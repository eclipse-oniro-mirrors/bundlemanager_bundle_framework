/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bundle_spm_manager.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <thread>

#include "access_token_error.h"
#include "account_helper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "bundle_verify_mgr.h"
#include "dual_mode_helper.h"
#include "inner_bundle_clone_common.h"
#include "installd_client.h"
#include "parameters.h"
#include "provision/provision_verify.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// SPM switch: default off; read once per process, changes take effect after restart.
constexpr const char* BMS_SPM_ENABLE_PARAM = "persist.bms.spm.enable";

// Retry policy for transient AT IPC failures: retry once after a short interval.
constexpr int32_t ATM_TRANSIENT_RETRY_COUNT = 1;
constexpr int32_t ATM_TRANSIENT_RETRY_INTERVAL_MS = 100;

bool IsTransientAtmError(int32_t errCode)
{
    return errCode == Security::AccessToken::AccessTokenError::ERR_SERVICE_ABNORMAL ||
        errCode == Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED;
}

// Extracts the provision info from the trusted bundle info cached by the access
// token service: 1) parse the provision JSON, 2) overwrite with the extra fields
// AT already parsed, 3) deep-copy the profile block.
bool ParseTrustedBundleInfo(const Security::AccessToken::TrustedBundleInfo &tbi,
    Security::Verify::ProvisionInfo &provisionInfo)
{
    const auto &profileData = tbi.profileData;
    if (Security::Verify::ParseProvision(profileData.provisionRaw, provisionInfo) !=
        Security::Verify::AppProvisionVerifyResult::PROVISION_OK) {
        return false;
    }
    if (!profileData.appId.empty()) {
        provisionInfo.appId = profileData.appId;
    }
    if (!profileData.fingerprint.empty()) {
        provisionInfo.fingerprint = profileData.fingerprint;
    }
    if (!profileData.organization.empty()) {
        provisionInfo.organization = profileData.organization;
    }
    provisionInfo.isOpenHarmony = profileData.isOpenHarmony;
    provisionInfo.isEnterpriseResigned = profileData.isEnterpriseResigned;
    return BundleSpmManager::FillProvisionProfileBlock(profileData, provisionInfo);
}

// The hmdfs/sharefs config entries are keyed by bundleId: convert the
// AT-generated uid to its bundleId with the canonical derivation used by the
// OFF allocator (GetUserIdByUid + BASE_USER_RANGE), so a uid allocated by the
// access token service gets the fs config the local allocator would have
// produced (GenerateBundleId does this on the OFF path).
void MakeFsConfigForNewUid(int32_t uid, const std::string &bundleName)
{
    int32_t userId = BundleUtil::GetUserIdByUid(uid);
    int32_t bundleId = uid - userId * Constants::BASE_USER_RANGE;
    BundleUtil::MakeFsConfig(bundleName, bundleId, ServiceConstants::HMDFS_CONFIG_PATH);
    BundleUtil::MakeFsConfig(bundleName, bundleId, ServiceConstants::SHAREFS_CONFIG_PATH);
}

// The fs config directory key follows the OFF allocator / boot restore
// convention per identity type: the plain name for the main identity, the
// dual-mode prefixed name, the clone/CLI composite "<N>clone_<name>" and the
// DLP sandbox composite "<N>_<name>". Writing a derived identity's bundleId
// under the MAIN name would clobber the main app's config until the next
// restore.
std::string GetFsConfigName(const InnerBundleInfo &info, int32_t dlpType, int32_t appIndex)
{
    const std::string &bundleName = info.GetBundleName();
    if (info.IsDualModeCloneApp()) {
        return DualModeHelper::GetDualModeBundleName(bundleName);
    }
    if (appIndex == 0) {
        return bundleName;
    }
    if (dlpType != 0) {
        return std::to_string(appIndex) + Constants::FILE_UNDERLINE + bundleName;
    }
    return BundleCloneCommonHelper::GetCloneBundleIdKey(bundleName, appIndex);
}
} // namespace

bool BundleSpmManager::FillProvisionProfileBlock(const Security::AccessToken::ProfileData &profileData,
    Security::Verify::ProvisionInfo &provisionInfo)
{
    // The profile block vector is the single source of truth: the separate length
    // field comes from another process and must not be trusted to match the vector
    // size (an inconsistent claimed length would cause an out-of-bound read when
    // the block is copied downstream).
    if (profileData.profileBlock.size() >=
        static_cast<size_t>(ServiceConstants::MAX_PROFILE_BLOCK_LENGTH)) {
        // An AT-side block beyond the cap is a contract anomaly: fail the parse
        // BEFORE the allocation (the length stays the single source of truth).
        return false;
    }
    provisionInfo.profileBlockLength = static_cast<int32_t>(profileData.profileBlock.size());
    if (profileData.profileBlock.empty()) {
        return true;
    }
    provisionInfo.profileBlock.reset(new (std::nothrow) unsigned char[profileData.profileBlock.size()]);
    if (provisionInfo.profileBlock == nullptr) {
        return false;
    }
    std::copy(profileData.profileBlock.begin(), profileData.profileBlock.end(),
        provisionInfo.profileBlock.get());
    return true;
}

BundleSpmManager &BundleSpmManager::GetInstance()
{
    static BundleSpmManager instance;
    return instance;
}

bool BundleSpmManager::IsEnabled()
{
    static bool enabled = OHOS::system::GetBoolParameter(BMS_SPM_ENABLE_PARAM, true);
    return enabled;
}

Security::AccessToken::BundlePolicy BundleSpmManager::CreateBundlePolicy(
    const InnerBundleInfo &innerBundleInfo, int32_t dlpType, bool isDebugGrant)
{
    Security::AccessToken::BundlePolicy policy;
    policy.dlpType = static_cast<Security::AccessToken::DlpType>(dlpType);
    policy.isDebugGrant = isDebugGrant;
    DefaultPermission permission;
    if (!BundlePermissionMgr::GetDefaultPermission(innerBundleInfo.GetBundleName(), permission)) {
        return policy;
    }
#ifdef USE_PRE_BUNDLE_PROFILE
    if (!BundlePermissionMgr::MatchSignature(permission, innerBundleInfo.GetCertificateFingerprint()) &&
        !BundlePermissionMgr::MatchSignature(permission, innerBundleInfo.GetAppId()) &&
        !BundlePermissionMgr::MatchSignature(permission, innerBundleInfo.GetAppIdentifier()) &&
        !BundlePermissionMgr::MatchSignature(permission, innerBundleInfo.GetOldAppIds())) {
        LOG_W(BMS_TAG_INSTALLER, "bundleName:%{public}s MatchSignature failed",
            innerBundleInfo.GetBundleName().c_str());
        return policy;
    }
#endif
    // All permissions of the matched default permission are pre-authorized: the
    // SPM policy does not depend on the request permissions of this particular
    // profile, so a profile that requests a subset still gets the full set.
    for (const auto &perm : permission.grantPermission) {
        Security::AccessToken::PreAuthorizationInfo preAuthorizationInfo;
        preAuthorizationInfo.permissionName = perm.name;
        preAuthorizationInfo.userCancelable = perm.userCancellable;
        policy.preAuthorizationInfo.emplace_back(preAuthorizationInfo);
    }
    return policy;
}

int32_t BundleSpmManager::FinishHapInstall(int32_t sessionId, bool isSuccess,
    const std::map<std::string, std::string> &modulePathMap)
{
    if (sessionId == 0) {
        return ERR_OK;
    }
    // isSuccess maps to the isPersistent semantics of FinishInstall: true commits and
    // persists the session, false rolls it back without persistence.
    auto ret = Security::AccessToken::AccessTokenKit::FinishInstall(sessionId, isSuccess, modulePathMap);
    if (ret == Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED) {
        // Retry ONLY when the request provably never reached the AT side
        // (parcel write failed before the call): SERVICE_ABNORMAL and
        // READ_PARCEL_FAILED may mean the AT side already finished the session,
        // and a blind retry could double-apply or hit a finished session
        // (cross-process idempotency of FinishInstall is not guaranteed —
        // registered as a cross-repo confirmation item).
        ret = Security::AccessToken::AccessTokenKit::FinishInstall(sessionId, isSuccess, modulePathMap);
    }
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_E(BMS_TAG_INSTALLER, "FinishInstall failed, sessionId:%{public}d errCode:%{public}d",
            sessionId, ret);
        return ret;
    }
    InstalldClient::GetInstance()->ClearSessionProvisionCache(sessionId);
    return ERR_OK;
}

BundleSpmManager::InstallSession BundleSpmManager::InstallSession::CheckSignAndInitSession(int32_t userId,
    const std::vector<std::string> &bundlePaths, bool isPreInstallApp,
    BundleInstallChecker &checker, ErrCode &outErrCode, bool readFile, bool skipEnterpriseResign)
{
    InstallSession session;
    if (!IsEnabled()) {
        std::vector<Security::Verify::HapVerifyResult> results;
        outErrCode = checker.CheckMultipleHapsSignInfo(bundlePaths, results, readFile, userId,
            skipEnterpriseResign);
        if (outErrCode != ERR_OK) {
            return session;
        }
        session.hapVerifyResults_ = std::move(results);
        return session;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER,
        "InstallSession::CheckSignAndInitSession start, userId:%{public}d hapCount:%{public}d "
        "isPreInstallApp:%{public}d skipEnterpriseResign:%{public}d", userId,
        static_cast<int32_t>(bundlePaths.size()),
        static_cast<int32_t>(isPreInstallApp), static_cast<int32_t>(skipEnterpriseResign));
    // SPM ON: verify sign info in the access token service, which allocates the session id
    // and caches the trusted bundle info for later queries by BMS and installd.
    if (bundlePaths.empty()) {
        // Align with the OFF checker (CheckMultipleHapsSignInfo rejects an empty
        // path list): do not hand an empty hap list to the AT side.
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "check sign failed paths empty");
        outErrCode = ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
        return session;
    }
    Security::AccessToken::BundleHapList hapList;
    hapList.hapPaths = bundlePaths;
    hapList.isPreInstalled = isPreInstallApp;
    // The real (normalized) userId must ALWAYS be passed: the AT side locates
    // the enterprise resign cert dir from it — the SAME path as
    // BundleUtil::GetEnterpriseReSignatureCert — and verifies every hap
    // carrying an ENTERPRISE_RE_SIGN_BLOB against that dir. Never encode the
    // skip permission in this field: the AT side maps
    // userIdForEnterpriseSign == -1 to an EMPTY cert dir, and an empty dir
    // does NOT skip the resign block verification — a block-carrying hap then
    // fails VERIFY_ENTERPRISE_RESIGN_FAIL (8522695) because the block cert
    // chain has nothing to match against, so a permission holder would be
    // rejected where a normal caller passes. skipEnterpriseResign never
    // alters this field: its only effect is the BMS-side policy gate
    // (CheckEnterpriseResign) below.
    if (userId < Constants::DEFAULT_USERID) {
        userId = AccountHelper::GetUserIdByCallerType();
    }
    hapList.userIdForEnterpriseSign = userId;
    std::vector<Security::AccessToken::TrustedBundleInfo> trustedBundleInfos;
    Security::AccessToken::HapVerifyResultInfo resultInfo;
    int32_t ret = Security::AccessToken::AccessTokenKit::CheckHapSignInfo(hapList,
        Security::AccessToken::SignInfoQueryFlag::QUERY_PROFILE, session.sessionId_,
        trustedBundleInfos, resultInfo);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "CheckHapSignInfo failed, ret %{public}d errorCode %{public}d",
            ret, resultInfo.errorCode);
        outErrCode = BundleVerifyMgr::ConvertHapVerifyResultCode(resultInfo.errorCode, ret);
        return session;
    }
    if (trustedBundleInfos.size() != bundlePaths.size()) {
        // The AT side must return exactly one entry per hap; anything else would
        // make the downstream path-indexed accesses read out of bounds (fail closed).
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "CheckHapSignInfo returned %{public}d entries for %{public}d haps",
            static_cast<int32_t>(trustedBundleInfos.size()),
            static_cast<int32_t>(bundlePaths.size()));
        // The uncommitted session rides back with the return value: the
        // InstallSession destructor (or a retry's move-assignment) rolls it
        // back on the AT side — no explicit FinishHapInstall needed here.
        outErrCode = ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE;
        return session;
    }
    for (const auto &trustedBundleInfo : trustedBundleInfos) {
        Security::Verify::ProvisionInfo provisionInfo;
        if (!ParseTrustedBundleInfo(trustedBundleInfo, provisionInfo)) {
#ifndef X86_EMULATOR_MODE
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "ParseTrustedBundleInfo failed");
            outErrCode = ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE;
            return session;
#else
            // Mirror the OFF checker (BundleInstallChecker::CheckMultipleHapsSignInfo):
            // on the emulator an unsigned hap's verify failure must not block the
            // install — the OFF path tolerates verifyRes != ERR_OK and clears the
            // appId of an invalid provision, so continue with a default provision.
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "ParseTrustedBundleInfo failed, continue with default provision");
            provisionInfo = Security::Verify::ProvisionInfo();
#endif
        }
        Security::Verify::HapVerifyResult hapVerifyResult;
        hapVerifyResult.SetProvisionInfo(provisionInfo);
        session.hapVerifyResults_.emplace_back(std::move(hapVerifyResult));
    }
    if (session.hapVerifyResults_.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "no sign info in the all haps");
        outErrCode = ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
        return session;
    }
    // The policy gate the skip permission exempts: the BMS-side mandate "an
    // enterprise app on a cert-configured enterprise device must have been
    // re-signed". The AT-side crypto gate above always ran with the real
    // userId regardless of the permission (a matching re-signed hap passed
    // it and is marked isEnterpriseResigned).
    if (skipEnterpriseResign) {
        LOG_I(BMS_TAG_INSTALLER, "skip enterprise resign check for permission-granted caller");
    } else if (!checker.CheckEnterpriseResign(session.hapVerifyResults_[0].GetProvisionInfo(), userId)) {
        LOG_E(BMS_TAG_INSTALLER, "enterprise resign check failed");
        outErrCode = ERR_APPEXECFWK_INSTALL_FAILED_APP_SOURCE_NOT_TRUESTED;
        return session;
    }
    if (!checker.CheckProvisionInfoIsValid(session.hapVerifyResults_)) {
#ifndef X86_EMULATOR_MODE
        LOG_E(BMS_TAG_INSTALLER, "CheckProvisionInfoIsValid failed");
        outErrCode = ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
        return session;
#else
        // on emulator if check signature failed clear appid
        for (auto &verifyRes : session.hapVerifyResults_) {
            Security::Verify::ProvisionInfo provisionInfo = verifyRes.GetProvisionInfo();
            provisionInfo.appId = Constants::EMPTY_STRING;
            verifyRes.SetProvisionInfo(provisionInfo);
        }
#endif
    }
    outErrCode = ERR_OK;
    return session;
}

BundleSpmManager::InstallSession BundleSpmManager::InstallSession::CreateDeferred()
{
    return InstallSession();
}

BundleSpmManager::InstallSession::InstallSession(InstallSession &&other) noexcept
    : sessionId_(other.sessionId_), committed_(other.committed_),
      identityPrepared_(other.identityPrepared_),
      hapVerifyResults_(std::move(other.hapVerifyResults_))
{
    other.sessionId_ = 0;
    other.committed_ = false;
    other.identityPrepared_ = false;
}

BundleSpmManager::InstallSession &BundleSpmManager::InstallSession::operator=(
    InstallSession &&other) noexcept
{
    if (this != &other) {
        if (sessionId_ != 0 && !committed_) {
            BundleSpmManager::FinishHapInstall(sessionId_, false, {});
            ClearInstalldProvisionCache();
        }
        sessionId_ = other.sessionId_;
        committed_ = other.committed_;
        identityPrepared_ = other.identityPrepared_;
        hapVerifyResults_ = std::move(other.hapVerifyResults_);
        other.sessionId_ = 0;
        other.committed_ = false;
        other.identityPrepared_ = false;
    }
    return *this;
}

BundleSpmManager::InstallSession::~InstallSession()
{
    if (sessionId_ != 0 && !committed_) {
        BundleSpmManager::FinishHapInstall(sessionId_, false, {});
        ClearInstalldProvisionCache();
    }
}

int32_t BundleSpmManager::InstallSession::GetSessionId() const
{
    return sessionId_;
}

bool BundleSpmManager::InstallSession::IsActive() const
{
    return sessionId_ != 0;
}

bool BundleSpmManager::InstallSession::IsCommitted() const
{
    return committed_;
}

bool BundleSpmManager::InstallSession::HasPreparedIdentity() const
{
    return identityPrepared_;
}

bool BundleSpmManager::InstallSession::GetHapVerifyResults(
    std::vector<Security::Verify::HapVerifyResult> &out) const
{
    if (hapVerifyResults_.empty()) {
        return false;
    }
    out = hapVerifyResults_;
    return true;
}

int32_t BundleSpmManager::InstallSession::InitToken(InnerBundleInfo &info, int32_t userId,
    int32_t dlpType, Security::AccessToken::AccessTokenIDEx &tokenIdEx,
    Security::AccessToken::HapInfoCheckResult &checkResult, const std::string &caps,
    BundleDataMgr *dataMgr, bool isDebugGrant, int32_t *identityUid)
{
    if (!IsEnabled()) {
        int32_t ret;
        if (tokenIdEx.tokenIdExStruct.tokenID != 0) {
            ret = BundlePermissionMgr::UpdateHapToken(tokenIdEx, info, userId, checkResult, caps,
                false, isDebugGrant);
        } else {
            ret = BundlePermissionMgr::InitHapToken(info, userId, dlpType, tokenIdEx, checkResult,
                caps, isDebugGrant);
        }
        if (ret != ERR_OK) {
            return ret;
        }
        if (dataMgr != nullptr) {
            InnerBundleUserInfo bundleUserInfo;
            if (info.GetInnerBundleUserInfo(userId, bundleUserInfo)
                && bundleUserInfo.uid == Constants::INVALID_UID) {
                ret = dataMgr->GenerateUidAndGid(bundleUserInfo);
                if (ret != ERR_OK) {
                    return ret;
                }
                info.AddInnerBundleUserInfo(bundleUserInfo);
            }
        }
        return ERR_OK;
    }
    // Identity reuse for a fresh install (SPM ON): the plan covers two shapes —
    // the S2 live leftover of an interrupted install and the keep-data
    // reinstall whose AT-side ACTIVE data is absent. Both reuse the existing
    // identity through UpdateToken (the policy is refreshed to the new
    // version; the S2 shape keeps the token id and uid stable so data
    // directories possibly created before the interruption keep their owner;
    // the keep-data shape relies on the AT side restoring the reserved
    // identity on the update interface — AT-side support, tracked separately).
    // The session carries no prepared identity in this case: Commit persists
    // the policy through the updated-token map, which is the regular shape of
    // an update-only session.
    FreshInstallIdentityPlan identityPlan = CheckNewInstallIdentity(userId,
        info.GetBundleName(), info.GetAppIndex(), dataMgr);
    if (identityPlan.reuseTokenId != 0) {
        LOG_NOFUNC_I(BMS_TAG_INSTALLER,
            "reuse existing identity for install, bundleName:%{public}s userId:%{public}d "
            "tokenId:%{public}u keepData:%{public}d",
            info.GetBundleName().c_str(), userId, identityPlan.reuseTokenId,
            static_cast<int32_t>(identityPlan.keepDataReinstall));
        Security::AccessToken::AccessTokenIDEx reusedIdEx;
        reusedIdEx.tokenIdExStruct.tokenID = identityPlan.reuseTokenId;
        int32_t refreshedUid = 0;
        // Propagate dlpType and appIndex so the replayed policy keeps the DLP
        // classification and the fs-config key lands on the identity's OWN
        // composite name (a hardcoded 0 here would refresh a DLP sandbox token
        // with a non-DLP policy and clobber the MAIN app's fs config with a
        // derived identity's bundleId).
        int32_t updateRet = UpdateToken(reusedIdEx, info, userId, checkResult, caps,
            false, isDebugGrant, dlpType, info.GetAppIndex(), &refreshedUid);
        if (updateRet != ERR_OK) {
            return updateRet;
        }
        tokenIdEx.tokenIDEx = reusedIdEx.tokenIDEx;
        if (identityUid != nullptr) {
            *identityUid = refreshedUid;
        }
        // Clone/sandbox identity: the caller owns the uid handling (it builds
        // the derived info from the identity uid out-param); the user info of
        // `info` belongs to the main app and must not be touched — same guard
        // as the Prepare path below. The dual-mode clone keeps the main-app
        // handling (its uid lives in the MAIN user info).
        bool cloneInstall = info.GetAppIndex() != 0 &&
            info.GetAppIndex() != ServiceConstants::DUAL_MODE_CLONE_APP_INDEX;
        if (cloneInstall) {
            return ERR_OK;
        }
        if (refreshedUid > 0) {
            // Adopt the reused token's uid into the user info (fresh install:
            // no local uid yet — the AT value is the authority; UpdateToken
            // already staged the fs config and the reverse-lookup entry).
            InnerBundleUserInfo bundleUserInfo;
            if (!info.GetInnerBundleUserInfo(userId, bundleUserInfo)) {
                bundleUserInfo.bundleUserInfo.userId = userId;
                bundleUserInfo.bundleName = info.GetBundleName();
            }
            bundleUserInfo.uid = refreshedUid;
            bundleUserInfo.gids.clear();
            bundleUserInfo.gids.emplace_back(refreshedUid);
            info.AddInnerBundleUserInfo(bundleUserInfo);
        }
        return ERR_OK;
    }
    // SPM ON: prepare the hap identity (token id and uid) in the access token service.
    // Kept-data recovery is carried by the reserved identity on the AT side, which makes
    // PrepareHapIdentity return the original uid and token id for a re-install.
    Security::AccessToken::HapBaseInfo hapBaseInfo;
    hapBaseInfo.userID = userId;
    hapBaseInfo.bundleName = info.GetBundleName();
    hapBaseInfo.instIndex = info.GetAppIndex();
    Security::AccessToken::BundlePolicy policy = BundleSpmManager::CreateBundlePolicy(
        info, dlpType, isDebugGrant);
    // Desired identity: for the MAIN app (appIndex 0) an already allocated local
    // uid is adopted (update/reinstall never moves the uid the data directories
    // belong to). For a CLONE (appIndex > 0) no desired is passed: the AT token
    // query filters by instIndex, so the AT side allocates a FRESH uid for the
    // clone instead of deriving the main app uid from the bundle-id mapping.
    // Exception — the dual-mode clone (appIndex == DUAL_MODE_CLONE_APP_INDEX):
    // it is installed by the BASE installer and keeps its uid in the MAIN user
    // info (not the cloneInfos), so it must follow the main-app handling: adopt
    // the existing uid as desired on update, persist the AT uid on fresh
    // install. Treating it as a plain clone would leave the fresh install with
    // no uid at all (GenerateUidAndGid fails fast under SPM ON) and would drift
    // the update path to a freshly allocated uid while the app keeps running
    // under the old one.
    bool cloneInstall = info.GetAppIndex() != 0 &&
        info.GetAppIndex() != ServiceConstants::DUAL_MODE_CLONE_APP_INDEX;
    Security::AccessToken::Identity identity;
    if (!cloneInstall) {
        InnerBundleUserInfo existing;
        if (info.GetInnerBundleUserInfo(userId, existing) &&
            existing.uid != Constants::INVALID_UID) {
            identity.uid = existing.uid;
        }
    }
    int32_t ret = Security::AccessToken::AccessTokenKit::PrepareHapIdentity(sessionId_, hapBaseInfo,
        policy, identity);
    if (IsTransientAtmError(ret)) {
        // Transient AT IPC failure (service restarting / parcel corruption):
        // retry once after a short interval; the identity out params are
        // re-populated by a successful retry.
        LOG_NOFUNC_W(BMS_TAG_INSTALLER,
            "PrepareHapIdentity transient failure, retrying, bundleName:%{public}s errCode:%{public}d",
            info.GetBundleName().c_str(), ret);
        std::this_thread::sleep_for(std::chrono::milliseconds(ATM_TRANSIENT_RETRY_INTERVAL_MS));
        ret = Security::AccessToken::AccessTokenKit::PrepareHapIdentity(sessionId_, hapBaseInfo,
            policy, identity);
    }
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "PrepareHapIdentity failed, bundleName:%{public}s errCode:%{public}d",
            info.GetBundleName().c_str(), ret);
        return ret;
    }
    if (identity.tokenId == 0 || identity.uid <= 0) {
        // The identity returned by PrepareHapIdentity is incomplete — treat it
        // as a failed SPM interface call: a zero tokenId or a non-positive uid
        // flowing downstream would either fail the token creation or drift the
        // token-to-uid binding (an INVALID uid would hit the centralized
        // GenerateUidAndGid fail-fast later); fail here already. The output
        // params (tokenIdEx / identityUid) are deliberately not written on
        // this failure path (no partial handover).
        LOG_NOFUNC_E(BMS_TAG_INSTALLER,
            "PrepareHapIdentity invalid identity, bundleName:%{public}s tokenId:%{public}" PRIu64
            " uid:%{public}d",
            info.GetBundleName().c_str(), static_cast<uint64_t>(identity.tokenId), identity.uid);
        return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
    }
    if (BundleUtil::GetUserIdByUid(identity.uid) != userId) {
        // User-segment consistency check (no assumption about the AT-side
        // application-uid subrange): a uid the AT side binds to THIS user's
        // identity must fall inside this user's uid segment. A uid from
        // another user's segment is a cross-user drift — persisting it would
        // bind the token to a uid the app can never run under. Note this is
        // deliberately NOT the [BASE_APP_UID, MAX_APP_UID] range check that
        // was reverted on 2026-10-12 (that check assumed the BMS allocation
        // subrange and could reject legitimate AT-allocated uids).
        LOG_NOFUNC_E(BMS_TAG_INSTALLER,
            "PrepareHapIdentity uid outside the user segment, bundleName:%{public}s "
            "uid:%{public}d expected userId:%{public}d",
            info.GetBundleName().c_str(), identity.uid, userId);
        return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
    }
    tokenIdEx.tokenIDEx = identity.tokenId;
    if (identityUid != nullptr) {
        *identityUid = identity.uid;
    }
    // Mark that THIS session prepared the identity (fresh creation or reserved
    // adoption): the post-commit DB-failure undo may only delete tokens that
    // were created inside the session — an update-only session (UpdateToken)
    // keeps the pre-existing token and must never undo it.
    identityPrepared_ = true;
    LOG_NOFUNC_I(BMS_TAG_INSTALLER,
        "PrepareHapIdentity success, bundleName:%{public}s appIndex:%{public}d sessionId:%{public}d "
        "tokenId:%{public}u uid:%{public}d",
        info.GetBundleName().c_str(), info.GetAppIndex(), sessionId_,
        tokenIdEx.tokenIdExStruct.tokenID, identity.uid);
    // The uid is guaranteed positive by the check above: produce the fs config
    // for the newly generated uid (the data directory creation below consumes
    // it), keyed by the identity-type composite name so a derived identity
    // never clobbers the main app's config. The reverse-lookup map entry is NOT
    // touched here — it is inserted at the DB-persistence point of the install
    // (BundleDataMgr), so a failed or rolled-back install never pollutes the map.
    MakeFsConfigForNewUid(identity.uid, GetFsConfigName(info, dlpType, info.GetAppIndex()));
    if (cloneInstall) {
        // Clone: the caller owns the uid handling (it builds the clone info from
        // the identity uid / the recovered record itself); the user info of `info`
        // belongs to the main app and must not be touched.
        return ERR_OK;
    }
    // uid handling (dual authority, no drift):
    // - existing user info with a valid uid: pass it as the DESIRED identity so the
    //   AT side adopts the SAME uid (adopt-or-reallocate) — an update/reinstall must
    //   never move the uid the data directories already belong to;
    // - fresh user info: the AT side allocates the uid; persist it here so the later
    //   GenerateUidAndGid call (now idempotent) keeps it instead of re-allocating
    //   from the independent BMS counter.
    InnerBundleUserInfo bundleUserInfo;
    bool userExists = info.GetInnerBundleUserInfo(userId, bundleUserInfo);
    if (!userExists) {
        bundleUserInfo.bundleUserInfo.userId = userId;
        bundleUserInfo.bundleName = info.GetBundleName();
    }
    if (userExists && bundleUserInfo.uid != Constants::INVALID_UID &&
        bundleUserInfo.uid != identity.uid) {
        // The AT side did not adopt the desired local uid and reallocated a new
        // one: under SPM ON the AT uid is authoritative — adopt it and drop the
        // stale local uid (its gid is cleared so uid and gids[0] stay
        // consistent). The stale entry of the abandoned uid in the reverse-
        // lookup map is rejected by the query cross-check and dropped at the
        // next boot restore.
        LOG_NOFUNC_W(BMS_TAG_INSTALLER, "AT uid %{public}d differs from local uid %{public}d, adopt AT uid, "
            "bundleName:%{public}s", identity.uid, bundleUserInfo.uid, info.GetBundleName().c_str());
        // The fs config layout is a single content-keyed file per bundle
        // (<configPath>/<bundleName>/<BUNDLE_ID_FILE>): MakeFsConfigForNewUid
        // above has already overwritten its content with the new uid — no
        // per-uid file exists to remove (the boot restore rewrites it as well).
        bundleUserInfo.gids.clear();
    }
    bundleUserInfo.uid = identity.uid;
    if (std::find(bundleUserInfo.gids.begin(), bundleUserInfo.gids.end(), identity.uid) ==
        bundleUserInfo.gids.end()) {
        bundleUserInfo.gids.emplace_back(identity.uid);
    }
    info.AddInnerBundleUserInfo(bundleUserInfo);
    return ERR_OK;
}

int32_t BundleSpmManager::InstallSession::UpdateToken(
    Security::AccessToken::AccessTokenIDEx &tokenIdEx, const InnerBundleInfo &info, int32_t userId,
    Security::AccessToken::HapInfoCheckResult &checkResult, const std::string &caps,
    bool dataRefresh, bool isDebugGrant, int32_t dlpType, int32_t appIndex, int32_t *refreshedUid)
{
    if (!IsEnabled()) {
        return BundlePermissionMgr::UpdateHapToken(tokenIdEx, info, userId, checkResult, caps,
            dataRefresh, isDebugGrant);
    }
    // SPM ON: update the hap policy bound to the existing token inside the session.
    Security::AccessToken::BundlePolicy policy = BundleSpmManager::CreateBundlePolicy(
        info, dlpType, isDebugGrant);
    int32_t uidOut = Constants::INVALID_UID;
    // tokenIdEx is an in/out parameter since AT PR #5133: the low 32 bits locate
    // the token, and on success the AT side refreshes the high 32 bits (tokenAttr,
    // same source as the FinishInstall commit value) in place — handing the
    // caller's reference through keeps the refreshed attr on the caller's token
    // record (their normal save path persists it). The error path leaves the
    // input untouched (AT-side contract).
    int32_t ret = Security::AccessToken::AccessTokenKit::UpdateHapPolicy(sessionId_,
        tokenIdEx, policy, uidOut);
    if (IsTransientAtmError(ret)) {
        // Transient AT IPC failure: retry once after a short interval.
        LOG_NOFUNC_W(BMS_TAG_INSTALLER,
            "UpdateHapPolicy transient failure, retrying, bundleName:%{public}s userId:%{public}d "
            "errCode:%{public}d", info.GetBundleName().c_str(), userId, ret);
        std::this_thread::sleep_for(std::chrono::milliseconds(ATM_TRANSIENT_RETRY_INTERVAL_MS));
        ret = Security::AccessToken::AccessTokenKit::UpdateHapPolicy(sessionId_,
            tokenIdEx, policy, uidOut);
    }
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER,
            "UpdateHapPolicy failed, bundleName:%{public}s userId:%{public}d sessionId:%{public}d "
            "tokenId:%{public}u ret:%{public}d",
            info.GetBundleName().c_str(), userId, sessionId_,
            tokenIdEx.tokenIdExStruct.tokenID, ret);
        return ret;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER,
        "UpdateHapPolicy success, bundleName:%{public}s userId:%{public}d sessionId:%{public}d "
        "tokenId:%{public}u uid:%{public}d",
        info.GetBundleName().c_str(), userId, sessionId_,
        tokenIdEx.tokenIdExStruct.tokenID, uidOut);
    // The AT side ALWAYS reports the token-bound uid in uidOut on success, so a
    // bare "> 0" check would run the refresh handling on every single policy
    // update. Compare against the CURRENT uid first: the cache rewrite, the fs
    // config regeneration, the stale-entry eviction and the refreshedUid
    // handover only happen on an actual uid change (an unassigned/INVALID
    // current uid counts as a change — the cache entry must be created).
    // Negative uidOut values never pass the comparison against a valid uid and
    // are additionally excluded (an AT contract anomaly must never poison the
    // cache keys or the fs config files).
    int32_t currentUid = info.GetUid(userId, appIndex);
    if (uidOut > 0 && uidOut != currentUid) {
        if (BundleUtil::GetUserIdByUid(uidOut) != userId) {
            // Same user-segment consistency check as InitToken: a uid the AT side
            // binds to THIS user's identity must fall inside this user's uid
            // segment. A cross-user drift flowing into the reverse-lookup cache,
            // the fs config or the persisted user info would bind the token to a
            // uid the app can never run under — fail the install here already
            // (the session rollback reverts the policy update).
            LOG_NOFUNC_E(BMS_TAG_INSTALLER,
                "UpdateHapPolicy uid outside the user segment, bundleName:%{public}s "
                "uid:%{public}d expected userId:%{public}d",
                info.GetBundleName().c_str(), uidOut, userId);
            return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
        }
        // The uid bound to the token changed with the policy update: stage the
        // reverse-lookup cache rewrite and the stale-entry eviction — both are
        // applied only on a successful Commit, so a rolled-back update keeps the
        // old entry (the AT-side rollback restores the old uid binding). The
        // refreshed uid is still handed back through the optional out param so
        // callers with a writable info persist it (their normal save path then
        // writes the DB — otherwise the cache and the DB would split).
        LOG_NOFUNC_I(BMS_TAG_INSTALLER, "UpdateHapPolicy refreshed uid, bundleName:%{public}s "
            "old uid:%{public}d new uid:%{public}d",
            info.GetBundleName().c_str(), currentUid, uidOut);
        if (refreshedUid != nullptr) {
            *refreshedUid = uidOut;
        }
        // The reverse-lookup entry of the refreshed uid is inserted at the
        // DB-persistence point (the refreshed uid is persisted together with the
        // info); the stale entry of the abandoned old uid is rejected by the
        // query cross-check until the next restore drops it. The fs config key
        // follows the identity-type composite convention (see GetFsConfigName).
        MakeFsConfigForNewUid(uidOut, GetFsConfigName(info, dlpType, appIndex));
    }
    return ret;
}

int32_t BundleSpmManager::InstallSession::CheckPermissionInfo(
    Security::AccessToken::InstallTypeEnum installType,
    Security::AccessToken::HapInfoCheckResult &checkResult,
    Security::AccessToken::MultipleMode mode)
{
    if (!IsEnabled()) {
        return ERR_OK;
    }
    // SPM ON: pre-check app permissions inside the session (install/replace/merge).
    // The dual-mode identity of this install rides along — the AT side moved the
    // mode consumption from CheckHapSignInfo to this call (AT PR #5133), and the
    // caller decides it HERE because the effective dual-mode policy is only
    // resolved on the parsed bundle info by now (never at the sign-check session
    // creation, where a preinstall first pass is still UNSPECIFIED).
    int32_t ret = Security::AccessToken::AccessTokenKit::CheckHapPermissionInfo(sessionId_,
        installType, mode, checkResult);
    if (ret == Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        return ERR_OK;
    }
    LOG_NOFUNC_E(BMS_TAG_INSTALLER, "CheckPermissionInfo failed, sessionId:%{public}d ret:%{public}d",
        sessionId_, ret);
    // Map the AT code to a registered BMS install code (pre-SPM error contract):
    // a cross-hap consistency mismatch surfaces as the bundle/app-type code the
    // OFF path returns; everything else folds into the generic grant-request
    // failure so no unregistered AT code leaks through the facade boundary.
    switch (ret) {
        case Security::AccessToken::AccessTokenError::ERR_CHECK_MULTIPLE_HAP_BUNDLE_NAME_MISMATCH:
            return ERR_APPEXECFWK_INSTALL_BUNDLENAME_NOT_SAME;
        case Security::AccessToken::AccessTokenError::ERR_CHECK_MULTIPLE_HAP_APP_FEATURE_MISMATCH:
            return ERR_APPEXECFWK_INSTALL_APPTYPE_NOT_SAME;
        case Security::AccessToken::AccessTokenError::ERR_BUNDLE_ALREADY_EXIST:
            // The callers' TYPE_INSTALL→TYPE_REPLACE degrade retry keys on this
            // raw code — keep it un-wrapped so the leftover-identity recovery
            // still triggers.
            return ret;
        default:
            return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
    }
}

int32_t BundleSpmManager::InstallSession::VerifyPermission(const std::string &bundleName,
    const std::string &permission, int32_t userId)
{
    (void)userId;
    if (!IsEnabled()) {
        return BundlePermissionMgr::VerifyPermission(bundleName, permission, userId);
    }
    // SPM ON: query the policy cached in the session instead of the installed token.
    Security::AccessToken::BundlePolicyInfo policyInfo;
    int32_t ret = Security::AccessToken::AccessTokenKit::GetCachePolicyBySessionId(sessionId_,
        bundleName, policyInfo);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        // The session policy is unavailable (session gone / query failed): the
        // permission cannot be verified — deny with the registered code instead
        // of leaking a raw AT code through the facade boundary.
        LOG_NOFUNC_E(BMS_TAG_INSTALLER,
            "VerifyPermission session policy query failed, bundleName:%{public}s ret %{public}d",
            bundleName.c_str(), ret);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    for (const auto &reqPermission : policyInfo.reqPermissions) {
        if (reqPermission == permission) {
            return ERR_OK;
        }
    }
    // Not granted in this session's cached policy: a registered BMS error code
    // instead of a bare -1 (the ON-mode unit tests pin the code path, callers
    // see a diagnosable value).
    return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
}

int32_t BundleSpmManager::InstallSession::Commit(const std::map<std::string, std::string>
    &modulePathMap)
{
    if (!IsEnabled()) {
        return ERR_OK;
    }
    int32_t ret = BundleSpmManager::FinishHapInstall(sessionId_, true, modulePathMap);
    if (ret == ERR_OK) {
        committed_ = true;
        // FinishHapInstall already cleared the installd provision cache on its
        // success path — no second IPC here (the double clear was redundant).
        return ret;
    }
    // The session reached its end even on failure: drop the installd provision
    // cache so a failed commit does not leak session-scoped entries.
    ClearInstalldProvisionCache();
    return ret;
}

int32_t BundleSpmManager::InstallSession::Rollback()
{
    if (!IsEnabled() || committed_) {
        return ERR_OK;
    }
    int32_t ret = BundleSpmManager::FinishHapInstall(sessionId_, false, {});
    ClearInstalldProvisionCache();
    if (ret == ERR_OK) {
        // The session is closed on the AT side; clear the local id so neither the
        // destructor nor a move assignment rolls the same session back twice
        // (plugin/shared installers roll back explicitly on their success paths).
        sessionId_ = 0;
    }
    return ret;
}

void BundleSpmManager::InstallSession::FillCreateDirParam(CreateDirParam &param) const
{
    param.sessionId = sessionId_;
}

void BundleSpmManager::InstallSession::FillCodeSignatureParam(
    const Security::Verify::HapVerifyResult &hapVerifyResult, CodeSignatureParam &param) const
{
    param.sessionId = sessionId_;
}

void BundleSpmManager::InstallSession::FillInstallHnpParam(InstallHnpParam &param) const
{
    param.sessionId = sessionId_;
}

void BundleSpmManager::InstallSession::FillVerifyBinParam(VerifyBinParam &param) const
{
    param.sessionId = sessionId_;
}

ErrCode BundleSpmManager::InstallSession::DeliverySignProfile(const std::string &bundleName,
    int32_t profileBlockLength, const unsigned char *profileBlock) const
{
    return InstalldClient::GetInstance()->DeliverySignProfile(bundleName, profileBlockLength,
        profileBlock, sessionId_);
}

void BundleSpmManager::InstallSession::ClearInstalldProvisionCache()
{
    ErrCode ret = InstalldClient::GetInstance()->ClearSessionProvisionCache(sessionId_);
    if (ret != ERR_OK) {
        // Best-effort cleanup: a leftover cache entry is only a dead key for the
        // finished session (no functional impact), but log it so the retention in
        // the privileged installd process stays diagnosable.
        LOG_NOFUNC_E(BMS_TAG_INSTALLER,
            "clear installd provision cache failed, sessionId:%{public}d errCode:%{public}d",
            sessionId_, ret);
    }
}

int32_t BundleSpmManager::OnModuleUninstalled(const InnerBundleInfo &info, int32_t userId)
{
    if (!IsEnabled()) {
        return ERR_OK;
    }
    // Standalone session: verify the remaining haps, refresh the permission policy
    // (module set changed) and commit with the identity hap-path mapping.
    Security::AccessToken::BundleHapList hapList;
    hapList.hapPaths = info.GetAllHapPaths();
    hapList.isPreInstalled = info.IsPreInstallApp();
    hapList.userIdForEnterpriseSign = userId;
    if (hapList.hapPaths.empty()) {
        // Nothing left to re-sign (defensive: the last-module uninstall takes
        // the full-uninstall flow, this path only sees the remaining set).
        LOG_NOFUNC_W(BMS_TAG_INSTALLER, "OnModuleUninstall empty hap list, bundleName:%{public}s",
            info.GetBundleName().c_str());
        return ERR_OK;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "OnModuleUninstall begin, bundleName:%{public}s userId:%{public}d "
        "hapCount:%{public}d", info.GetBundleName().c_str(), userId,
        static_cast<int32_t>(hapList.hapPaths.size()));
    int32_t sessionId = 0;
    std::vector<Security::AccessToken::TrustedBundleInfo> trustedBundleInfos;
    Security::AccessToken::HapVerifyResultInfo resultInfo;
    int32_t ret = Security::AccessToken::AccessTokenKit::CheckHapSignInfo(hapList,
        Security::AccessToken::SignInfoQueryFlag::QUERY_PROFILE, sessionId,
        trustedBundleInfos, resultInfo);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "OnModuleUninstall verify failed, bundleName:%{public}s "
            "ret %{public}d errorCode %{public}d", info.GetBundleName().c_str(), ret, resultInfo.errorCode);
        return BundleVerifyMgr::ConvertHapVerifyResultCode(resultInfo.errorCode, ret);
    }
    Security::AccessToken::HapInfoCheckResult checkResult;
    // Same identity-based rule as the install path (dualModeBundleName_ there —
    // the installer derives it from this very flag via InitDualModeBundleName):
    // the remaining modules of a dual-mode clone app are re-signed against the
    // SUB-mode identity; every other bundle uses the default/main mode.
    Security::AccessToken::MultipleMode mode = info.IsDualModeCloneApp()
        ? Security::AccessToken::MultipleMode::SUB_MODE
        : Security::AccessToken::MultipleMode::DEFAULT_OR_MAIN_MODE;
    ret = Security::AccessToken::AccessTokenKit::CheckHapPermissionInfo(sessionId,
        Security::AccessToken::InstallTypeEnum::TYPE_REPLACE, mode, checkResult);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "OnModuleUninstall check permission failed, bundleName:%{public}s "
            "sessionId:%{public}d ret %{public}d", info.GetBundleName().c_str(), sessionId, ret);
        BundleSpmManager::FinishHapInstall(sessionId, false, {});
        return ret;
    }
    std::map<std::string, std::string> modulePathMap;
    for (const auto &hapPath : hapList.hapPaths) {
        modulePathMap[hapPath] = hapPath;
    }
    ret = BundleSpmManager::FinishHapInstall(sessionId, true, modulePathMap);
    if (ret != ERR_OK) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "OnModuleUninstall commit failed, bundleName:%{public}s "
            "sessionId:%{public}d errCode:%{public}d", info.GetBundleName().c_str(), sessionId, ret);
        // Best-effort rollback so the standalone session does not linger on the
        // AT side (mirrors the check-permission failure branch above); a failed
        // rollback keeps the leftover for the already-registered recovery.
        BundleSpmManager::FinishHapInstall(sessionId, false, {});
        return ret;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "OnModuleUninstall success, bundleName:%{public}s sessionId:%{public}d",
        info.GetBundleName().c_str(), sessionId);
    return ERR_OK;
}

bool BundleSpmManager::IsRecoverableSpmError(int32_t errCode)
{
    // Only the SPM session APIs produce these codes; keep the SPM OFF error-code
    // contract untouched (legacy failures stay wrapped in the BMS install codes).
    if (!IsEnabled()) {
        return false;
    }
    return errCode == Security::AccessToken::AccessTokenError::ERR_UID_NOT_EXIST ||
        errCode == Security::AccessToken::AccessTokenError::ERR_BUNDLE_ALREADY_EXIST;
}

ErrCode BundleSpmManager::WrapRecoverableSpmErrorCode(ErrCode errCode)
{
    // Install entries without an on-demand recovery chain (preinstall/recover/
    // shared/skills/appservicefwk, ...) call this before returning, so no
    // unregistered AT code leaks through the IPC boundary.
    return IsRecoverableSpmError(errCode) ?
        ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED : errCode;
}

bool BundleSpmManager::TryRecoverUidError(const std::string &bundleName, BundleDataMgr *dataMgr)
{
    if (!IsEnabled() || dataMgr == nullptr || bundleName.empty()) {
        return false;
    }
    InnerBundleInfo info;
    if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
        return false;
    }
    Security::AccessToken::MigratedInfo migratedInfo;
    migratedInfo.bundleName = bundleName;
    migratedInfo.pathList.hapPaths = info.GetAllHapPaths();
    migratedInfo.pathList.isPreInstalled = info.IsPreInstallApp();
    // Identity mode of the migration entry (same rule as the boot migration
    // builder): a dual-mode clone app migrates into the SUB mode.
    migratedInfo.mode = info.IsDualModeCloneApp()
        ? Security::AccessToken::MultipleMode::SUB_MODE
        : Security::AccessToken::MultipleMode::DEFAULT_OR_MAIN_MODE;
    for (const auto &userInfoPair : info.GetInnerBundleUserInfos()) {
        const auto &userInfo = userInfoPair.second;
        const auto &bundleUserInfo = userInfo.bundleUserInfo;
        Security::AccessToken::HapBaseInfo baseInfo;
        baseInfo.userID = bundleUserInfo.userId;
        baseInfo.bundleName = bundleName;
        // Filter invalid uids from the RDB records (OTA / corruption leftovers):
        // the AT side would register them as-is and the identity would be broken.
        // The MAIN identity's base info and uid must be staged TOGETHER — a
        // conditional uid with an unconditional base info would misalign the
        // parallel lists and bind every following clone identity to the wrong
        // uid — so a corrupt main record stages nothing for the main identity
        // while its valid clones below are still migrated. A uid outside the
        // record's own user segment is a cross-user drift and is skipped the
        // same way (same consistency check as InitToken).
        bool mainUidInSegment = userInfo.uid > 0 &&
            BundleUtil::GetUserIdByUid(userInfo.uid) == bundleUserInfo.userId;
        if (mainUidInSegment) {
            // main identity of this user (app index 0)
            baseInfo.instIndex = Constants::INITIAL_APP_INDEX;
            migratedInfo.hapBaseInfoList.emplace_back(baseInfo);
            migratedInfo.uidList.emplace_back(userInfo.uid);
            migratedInfo.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::NONE);
        }
        // clone identities of this user, keyed by app index
        for (const auto &clonePair : userInfo.cloneInfos) {
            if (clonePair.second.uid <= 0 ||
                BundleUtil::GetUserIdByUid(clonePair.second.uid) != clonePair.second.userId) {
                continue;
            }
            Security::AccessToken::HapBaseInfo cloneInfo = baseInfo;
            cloneInfo.instIndex = clonePair.second.appIndex;
            migratedInfo.hapBaseInfoList.emplace_back(cloneInfo);
            migratedInfo.uidList.emplace_back(clonePair.second.uid);
            migratedInfo.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::NONE);
        }
    }
    std::vector<Security::AccessToken::BundleMigrateResult> results;
    int32_t ret = Security::AccessToken::AccessTokenKit::MigrateInstalledBundles({migratedInfo}, results);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS &&
        ret != Security::AccessToken::AccessTokenError::ERR_MIGRATION_COMPLETED) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "on-demand migration of %{public}s failed, ret %{public}d",
            bundleName.c_str(), ret);
        return false;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "on-demand migration of %{public}s recovered", bundleName.c_str());
    return true;
}

bool BundleSpmManager::TryRecoverAlreadyExistError(const std::string &bundleName)
{
    if (!IsEnabled() || bundleName.empty()) {
        return false;
    }
    // A by-name delete (tokenId 0) wipes EVERY identity of the bundle on the AT
    // side. When the BMS records show a live identity (an installed user), the
    // wipe would destroy it along with the leftover — the app would stay
    // installed while its token is gone. Refuse the auto-recovery and surface
    // the ALREADY_EXIST error instead; a precise per-identity cleanup stays a
    // registered cross-repo item (AT-side delete by identity). The typical
    // leftover scenario (a crashed install left no BMS record) is unaffected.
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleInfo info;
    if (dataMgr != nullptr && dataMgr->FetchInnerBundleInfo(bundleName, info)) {
        for (const auto &userItem : info.GetInnerBundleUserInfos()) {
            const auto &userInfo = userItem.second;
            bool hasLiveIdentity = userInfo.uid > 0;
            for (const auto &cloneItem : userInfo.cloneInfos) {
                hasLiveIdentity = hasLiveIdentity || cloneItem.second.uid > 0;
            }
            for (const auto &sandboxItem : userInfo.sandboxInfos) {
                hasLiveIdentity = hasLiveIdentity || sandboxItem.second.uid > 0;
            }
            if (hasLiveIdentity) {
                LOG_NOFUNC_W(BMS_TAG_INSTALLER,
                    "leftover identity of %{public}s not auto-cleaned: the by-name delete would "
                    "destroy the live identity of user %{public}d",
                    bundleName.c_str(), userInfo.bundleUserInfo.userId);
                return false;
            }
        }
    }
    int32_t ret = Security::AccessToken::AccessTokenKit::DeleteIdentity(0, bundleName,
        Security::AccessToken::ReservedType::NONE);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "clean leftover identity of %{public}s failed, ret %{public}d",
            bundleName.c_str(), ret);
        return false;
    }
    // The AT side deletes EVERY identity of the bundle by name (tokenId 0).
    // Leftover reverse-lookup entries are rejected by the query cross-check
    // and dropped at the next boot restore.
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "cleaned leftover identity of %{public}s, retry install",
        bundleName.c_str());
    return true;
}

int32_t BundleSpmManager::DeleteToken(Security::AccessToken::AccessTokenID tokenId,
    const std::string &bundleName, TokenDeleteType type)
{
    if (!IsEnabled()) {
        switch (type) {
            case TokenDeleteType::RESERVED_IDENTITY:
                return BundlePermissionMgr::DeleteAccessTokenId(tokenId, true);
            case TokenDeleteType::RESERVED_DATA:
                // Legacy keep-data uninstall keeps the token active; nothing to delete.
                return ERR_OK;
            case TokenDeleteType::NONE:
            default:
                return BundlePermissionMgr::DeleteAccessTokenId(tokenId, false);
        }
    }
    if (tokenId == 0) {
        // A zero token id must NEVER reach the AT side: DeleteIdentity(0, bundleName,
        // NONE) deletes EVERY token of the bundle by name there, while the legacy
        // DeleteAccessTokenId(0) only failed harmlessly. Guards that fire before the
        // token was assigned would otherwise wipe the installed identities.
        LOG_NOFUNC_E(BMS_TAG_INSTALLER,
            "DeleteToken rejected zero tokenId, bundleName:%{public}s", bundleName.c_str());
        return Security::AccessToken::AccessTokenError::ERR_PARAM_INVALID;
    }
    // SPM ON: TokenDeleteType maps one-to-one to the AT ReservedType values (0/1/2).
    // A leftover reverse-lookup entry of the deleted identity is rejected by the
    // query cross-check and dropped at the next boot restore.
    return Security::AccessToken::AccessTokenKit::DeleteIdentity(tokenId, bundleName,
        static_cast<Security::AccessToken::ReservedType>(type));
}

BundleSpmManager::FreshInstallIdentityPlan BundleSpmManager::CheckNewInstallIdentity(
    int32_t userId, const std::string &bundleName, int32_t appIndex, BundleDataMgr *dataMgr)
{
    FreshInstallIdentityPlan plan;
    if (!IsEnabled() || bundleName.empty()) {
        return plan;
    }
    UninstallBundleInfo uninstallBundleInfo;
    bool hasKeepData = dataMgr != nullptr &&
        dataMgr->GetUninstallBundleInfo(bundleName, uninstallBundleInfo);
    Security::AccessToken::AccessTokenID atTokenId =
        Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appIndex);
    if (hasKeepData) {
        // Keep-data reinstall: the identity plan is decided by One signals —
        // 1) checkBySpm: whether the OTA migration successfully migrated this
        //    bundle's uid/identity to the AT side. false = migration did not
        //    cover this bundle (the abnormal shape).
        // Normal keep-data reinstall (checkBySpm=true): the AT side kept the
        // reserved identity — PrepareHapIdentity recognizes the reservation and
        // returns the same token id and uid (Prepare flow, empty plan).
        // Abnormal keep-data reinstall (checkBySpm=false AND AT side has no
        // identity): the reuse goes through the update interface with the
        // BMS-recorded token id — the AT side restores the reserved identity there.
        // A record of ANOTHER user does not affect this identity.
        if (!uninstallBundleInfo.checkBySpm) {
            auto it = uninstallBundleInfo.userInfos.find(std::to_string(userId));
            if (it != uninstallBundleInfo.userInfos.end() && it->second.accessTokenId != 0) {
                plan.reuseTokenId = it->second.accessTokenId;
                plan.keepDataReinstall = true;
                return plan;
            }
        }
        // checkBySpm=true (normal), checkBySpm=false but AT has the identity,
        // or no record of this user: fall through — a clean install for this
        // identity goes through Prepare.
        return plan;
    }
    if (atTokenId != 0) {
        // S2 split state: BMS has no data and no keep-data reservation, while
        // the AT side holds a live token of this identity — the residue of an
        // interrupted install. Reuse it through the update interface.
        plan.reuseTokenId = atTokenId;
    }
    return plan;
}

bool BundleSpmManager::HasAtIdentity(int32_t userId, const std::string &bundleName, int32_t appIndex)
{
    if (!IsEnabled() || bundleName.empty()) {
        return false;
    }
    return Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName,
        appIndex) != 0;
}
} // namespace AppExecFwk
} // namespace OHOS
