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

#include "access_token_error.h"
#include "app_log_tag_wrapper.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "bundle_verify_mgr.h"
#include "installd_client.h"
#include "parameters.h"
#include "provision/provision_verify.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// SPM switch: default off; read once per process, changes take effect after restart.
constexpr const char* BMS_SPM_ENABLE_PARAM = "persist.bms.spm.enable";

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
// OFF allocator (GetUserIdByUid + BASE_USER_RANGE, see IsValidAppUid), so a uid
// allocated by the access token service gets the fs config the local allocator
// would have produced (GenerateBundleId does this on the OFF path).
void MakeFsConfigForNewUid(int32_t uid, const std::string &bundleName)
{
    int32_t userId = BundleUtil::GetUserIdByUid(uid);
    int32_t bundleId = uid - userId * Constants::BASE_USER_RANGE;
    BundleUtil::MakeFsConfig(bundleName, bundleId, ServiceConstants::HMDFS_CONFIG_PATH);
    BundleUtil::MakeFsConfig(bundleName, bundleId, ServiceConstants::SHAREFS_CONFIG_PATH);
}
} // namespace

bool BundleSpmManager::FillProvisionProfileBlock(const Security::AccessToken::ProfileData &profileData,
    Security::Verify::ProvisionInfo &provisionInfo)
{
    // The profile block vector is the single source of truth: the separate length
    // field comes from another process and must not be trusted to match the vector
    // size (an inconsistent claimed length would cause an out-of-bound read when
    // the block is copied downstream).
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
    static bool enabled = OHOS::system::GetBoolParameter(BMS_SPM_ENABLE_PARAM, false);
    return enabled;
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
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "InstallSession::CheckSignAndInitSession start, userId:%{public}d hapCount:%{public}d "
        "isPreInstallApp:%{public}d skipEnterpriseResign:%{public}d", userId,
        static_cast<int32_t>(bundlePaths.size()),
        static_cast<int32_t>(isPreInstallApp), static_cast<int32_t>(skipEnterpriseResign));
    // SPM ON: verify sign info in the access token service, which allocates the session id
    // and caches the trusted bundle info for later queries by BMS and installd.
    Security::AccessToken::BundleHapList hapList;
    hapList.hapPaths = bundlePaths;
    hapList.isPreInstalled = isPreInstallApp;
    // Cross-process contract: userId -1 tells the AT side to skip the enterprise
    // resign verification (the caller holds SKIP_ENTERPRISE_RESIGN_VERIFY).
    hapList.userId = skipEnterpriseResign ? -1 : userId;
    std::vector<Security::AccessToken::TrustedBundleInfo> trustedBundleInfos;
    Security::AccessToken::HapVerifyResultInfo resultInfo;
    int32_t ret = Security::AccessToken::AccessTokenKit::CheckHapSignInfo(hapList,
        Security::AccessToken::SignInfoQueryFlag::QUERY_PROFILE, session.sessionId_,
        trustedBundleInfos, resultInfo);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "CheckHapSignInfo failed, ret %{public}d", ret);
        session.sessionId_ = 0;
        outErrCode = BundleVerifyMgr::ConvertHapVerifyResultCode(ret);
        return session;
    }
    if (trustedBundleInfos.size() != bundlePaths.size()) {
        // The AT side must return exactly one entry per hap; anything else would
        // make the downstream path-indexed accesses read out of bounds (fail closed).
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "CheckHapSignInfo returned %{public}d entries for %{public}d haps",
            static_cast<int32_t>(trustedBundleInfos.size()),
            static_cast<int32_t>(bundlePaths.size()));
        // The AT side allocated the session inside CheckHapSignInfo; finish it
        // before dropping the id, otherwise it leaks on the AT side.
        int32_t rollbackRet = BundlePermissionMgr::FinishHapInstall(session.sessionId_, false, {});
        if (rollbackRet != ERR_OK) {
            // Secondary failure: the AT session may leak, keep it observable.
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "rollback AT session failed, sessionId:%{public}d errCode:%{public}d",
                session.sessionId_, rollbackRet);
        }
        session.sessionId_ = 0;
        outErrCode = ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE;
        return session;
    }
    for (const auto &trustedBundleInfo : trustedBundleInfos) {
        Security::Verify::ProvisionInfo provisionInfo;
        if (!ParseTrustedBundleInfo(trustedBundleInfo, provisionInfo)) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "ParseTrustedBundleInfo failed");
            // Same as above: the session is already allocated on the AT side.
            int32_t rollbackRet = BundlePermissionMgr::FinishHapInstall(session.sessionId_, false, {});
            if (rollbackRet != ERR_OK) {
                LOG_NOFUNC_E(BMS_TAG_INSTALLER, "rollback AT session failed, sessionId:%{public}d errCode:%{public}d",
                    session.sessionId_, rollbackRet);
            }
            session.sessionId_ = 0;
            outErrCode = ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE;
            return session;
        }
        Security::Verify::HapVerifyResult hapVerifyResult;
        hapVerifyResult.SetProvisionInfo(provisionInfo);
        session.hapVerifyResults_.emplace_back(std::move(hapVerifyResult));
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
      hapVerifyResults_(std::move(other.hapVerifyResults_))
{
    other.sessionId_ = 0;
    other.committed_ = false;
}

BundleSpmManager::InstallSession &BundleSpmManager::InstallSession::operator=(
    InstallSession &&other) noexcept
{
    if (this != &other) {
        if (sessionId_ != 0 && !committed_) {
            BundlePermissionMgr::FinishHapInstall(sessionId_, false, {});
            ClearInstalldProvisionCache();
        }
        sessionId_ = other.sessionId_;
        committed_ = other.committed_;
        hapVerifyResults_ = std::move(other.hapVerifyResults_);
        other.sessionId_ = 0;
        other.committed_ = false;
    }
    return *this;
}

BundleSpmManager::InstallSession::~InstallSession()
{
    if (sessionId_ != 0 && !committed_) {
        BundlePermissionMgr::FinishHapInstall(sessionId_, false, {});
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
    // SPM ON: prepare the hap identity (token id and uid) in the access token service.
    // Kept-data recovery is carried by the reserved identity on the AT side, which makes
    // PrepareHapIdentity return the original uid and token id for a re-install.
    Security::AccessToken::HapBaseInfo hapBaseInfo;
    hapBaseInfo.userID = userId;
    hapBaseInfo.bundleName = info.GetBundleName();
    hapBaseInfo.instIndex = info.GetAppIndex();
    Security::AccessToken::BundlePolicy policy = BundlePermissionMgr::CreateBundlePolicy(
        info, dlpType, isDebugGrant);
    // Desired identity: for the MAIN app (appIndex 0) an already allocated local
    // uid is adopted (update/reinstall never moves the uid the data directories
    // belong to). For a CLONE (appIndex > 0) no desired is passed: the AT token
    // query filters by instIndex, so the AT side allocates a FRESH uid for the
    // clone instead of deriving the main app uid from the bundle-id mapping.
    Security::AccessToken::Identity identity;
    bool cloneInstall = info.GetAppIndex() != 0;
    if (!cloneInstall) {
        InnerBundleUserInfo existing;
        if (info.GetInnerBundleUserInfo(userId, existing) &&
            existing.uid != Constants::INVALID_UID) {
            identity.uid = existing.uid;
        }
    }
    int32_t ret = Security::AccessToken::AccessTokenKit::PrepareHapIdentity(sessionId_, hapBaseInfo,
        policy, identity);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "PrepareHapIdentity failed, bundleName:%{public}s errCode:%{public}d",
            info.GetBundleName().c_str(), ret);
        return ret;
    }
    if (identity.tokenId == 0) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "PrepareHapIdentity invalid tokenId, bundleName:%{public}s",
            info.GetBundleName().c_str());
        return Security::AccessToken::AccessTokenError::ERR_TOKENID_CREATE_FAILED;
    }
    tokenIdEx.tokenIDEx = identity.tokenId;
    if (identityUid != nullptr) {
        *identityUid = identity.uid;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER,
        "PrepareHapIdentity success, bundleName:%{public}s appIndex:%{public}d sessionId:%{public}d "
        "tokenId:%{public}u uid:%{public}d",
        info.GetBundleName().c_str(), info.GetAppIndex(), sessionId_,
        tokenIdEx.tokenIdExStruct.tokenID, identity.uid);
    if (identity.uid != 0) {
        // The AT side generated (or adopted) this uid: refresh the SPM ON
        // reverse-lookup cache so fresh installs are covered in-process too
        // (the boot restore only repopulates it after a restart), and produce
        // the fs config for the newly generated uid.
        auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr != nullptr) {
            dataMgr->UpdateUidIndexMap(identity.uid, info.GetBundleName(), info.GetAppIndex());
        }
        MakeFsConfigForNewUid(identity.uid, info.GetBundleName());
    }
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
    if (identity.uid != 0) {
        if (userExists && bundleUserInfo.uid != Constants::INVALID_UID &&
            bundleUserInfo.uid != identity.uid) {
            // The AT side did not adopt the desired uid (alloc failed and it picked
            // another one): keep the local uid — the data directories belong to it —
            // and leave a trace; the token/uid mismatch needs an AT-side fix.
            LOG_NOFUNC_W(BMS_TAG_INSTALLER, "AT uid %{public}d differs from local uid %{public}d, keep local, "
                "bundleName:%{public}s", identity.uid, bundleUserInfo.uid, info.GetBundleName().c_str());
            // The cache entry written above holds the AT uid, but the app actually
            // runs with the local uid: rewrite the entry and drop the AT one.
            auto cacheMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
            if (cacheMgr != nullptr) {
                cacheMgr->RemoveUidIndexMap(identity.uid);
                cacheMgr->UpdateUidIndexMap(bundleUserInfo.uid, info.GetBundleName(), info.GetAppIndex());
            }
        } else {
            bundleUserInfo.uid = identity.uid;
            if (std::find(bundleUserInfo.gids.begin(), bundleUserInfo.gids.end(), identity.uid) ==
                bundleUserInfo.gids.end()) {
                bundleUserInfo.gids.emplace_back(identity.uid);
            }
            info.AddInnerBundleUserInfo(bundleUserInfo);
        }
    } else if (!userExists) {
        // No uid from the AT side either: keep the bare placeholder; the later
        // GenerateUidAndGid call fills in the uid.
        info.AddInnerBundleUserInfo(bundleUserInfo);
    }
    return ERR_OK;
}

int32_t BundleSpmManager::InstallSession::UpdateToken(
    Security::AccessToken::AccessTokenIDEx &tokenIdEx, const InnerBundleInfo &info, int32_t userId,
    Security::AccessToken::HapInfoCheckResult &checkResult, const std::string &caps,
    bool dataRefresh, bool isDebugGrant)
{
    if (!IsEnabled()) {
        return BundlePermissionMgr::UpdateHapToken(tokenIdEx, info, userId, checkResult, caps,
            dataRefresh, isDebugGrant);
    }
    // SPM ON: update the hap policy bound to the existing token inside the session.
    Security::AccessToken::BundlePolicy policy = BundlePermissionMgr::CreateBundlePolicy(
        info, 0, isDebugGrant);
    int32_t uidOut = 0;
    int32_t ret = Security::AccessToken::AccessTokenKit::UpdateHapPolicy(sessionId_,
        tokenIdEx.tokenIdExStruct.tokenID, policy, uidOut);
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
    if (uidOut != 0) {
        // The AT side reports the uid bound to the token after the policy update:
        // the app's uid needs a refresh, so the reverse-lookup cache entry is
        // rewritten with it and the fs config is regenerated for the uid. A stale
        // entry under the previous uid is evicted so it cannot resolve to this
        // app if the AT side ever reuses the old uid.
        LOG_NOFUNC_I(BMS_TAG_INSTALLER, "UpdateHapPolicy refreshed uid, bundleName:%{public}s uid:%{public}d",
            info.GetBundleName().c_str(), uidOut);
        auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr != nullptr) {
            int32_t oldUid = info.GetUid(userId);
            if (oldUid != Constants::INVALID_UID && oldUid != 0 && oldUid != uidOut) {
                dataMgr->RemoveUidIndexMap(oldUid);
            }
            dataMgr->UpdateUidIndexMap(uidOut, info.GetBundleName(), info.GetAppIndex());
        }
        MakeFsConfigForNewUid(uidOut, info.GetBundleName());
    }
    return ret;
}

int32_t BundleSpmManager::InstallSession::CheckPermissionInfo(
    Security::AccessToken::InstallTypeEnum installType,
    Security::AccessToken::HapInfoCheckResult &checkResult)
{
    if (!IsEnabled()) {
        return ERR_OK;
    }
    // SPM ON: pre-check app permissions inside the session (install/replace/merge).
    return Security::AccessToken::AccessTokenKit::CheckHapPermissionInfo(sessionId_,
        installType, checkResult);
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
        return ret;
    }
    for (const auto &reqPermission : policyInfo.reqPermissions) {
        if (reqPermission == permission) {
            return ERR_OK;
        }
    }
    return -1;
}

int32_t BundleSpmManager::InstallSession::Commit(const std::map<std::string, std::string>
    &modulePathMap)
{
    if (!IsEnabled()) {
        return ERR_OK;
    }
    int32_t ret = BundlePermissionMgr::FinishHapInstall(sessionId_, true, modulePathMap);
    if (ret == ERR_OK) {
        committed_ = true;
    }
    // The session reached its end either way: drop the installd provision cache so
    // a failed commit does not leak session-scoped entries in the privileged process.
    ClearInstalldProvisionCache();
    return ret;
}

int32_t BundleSpmManager::InstallSession::Rollback()
{
    if (!IsEnabled() || committed_) {
        return ERR_OK;
    }
    int32_t ret = BundlePermissionMgr::FinishHapInstall(sessionId_, false, {});
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
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "clear installd provision cache failed, sessionId:%{public}d errCode:%{public}d",
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
    hapList.userId = userId;
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
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "OnModuleUninstall verify failed, bundleName:%{public}s ret %{public}d",
            info.GetBundleName().c_str(), ret);
        return ret;
    }
    Security::AccessToken::HapInfoCheckResult checkResult;
    ret = Security::AccessToken::AccessTokenKit::CheckHapPermissionInfo(sessionId,
        Security::AccessToken::InstallTypeEnum::TYPE_REPLACE, checkResult);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "OnModuleUninstall check permission failed, bundleName:%{public}s "
            "sessionId:%{public}d ret %{public}d", info.GetBundleName().c_str(), sessionId, ret);
        BundlePermissionMgr::FinishHapInstall(sessionId, false, {});
        return ret;
    }
    std::map<std::string, std::string> modulePathMap;
    for (const auto &hapPath : hapList.hapPaths) {
        modulePathMap[hapPath] = hapPath;
    }
    ret = BundlePermissionMgr::FinishHapInstall(sessionId, true, modulePathMap);
    if (ret != ERR_OK) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "OnModuleUninstall commit failed, bundleName:%{public}s "
            "sessionId:%{public}d errCode:%{public}d", info.GetBundleName().c_str(), sessionId, ret);
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
    for (const auto &userInfoPair : info.GetInnerBundleUserInfos()) {
        const auto &userInfo = userInfoPair.second;
        const auto &bundleUserInfo = userInfo.bundleUserInfo;
        Security::AccessToken::HapBaseInfo baseInfo;
        baseInfo.userID = bundleUserInfo.userId;
        baseInfo.bundleName = bundleName;
        // main identity of this user (app index 0)
        baseInfo.instIndex = Constants::INITIAL_APP_INDEX;
        migratedInfo.hapBaseInfoList.emplace_back(baseInfo);
        migratedInfo.uidList.emplace_back(userInfo.uid);
        migratedInfo.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::NONE);
        // clone identities of this user, keyed by app index
        for (const auto &clonePair : userInfo.cloneInfos) {
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
    int32_t ret = Security::AccessToken::AccessTokenKit::DeleteIdentity(0, bundleName,
        Security::AccessToken::ReservedType::NONE);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "clean leftover identity of %{public}s failed, ret %{public}d",
            bundleName.c_str(), ret);
        return false;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "cleaned leftover identity of %{public}s, retry install",
        bundleName.c_str());
    return true;
}

int32_t BundleSpmManager::DeleteToken(Security::AccessToken::AccessTokenID tokenId,
    const std::string &bundleName, TokenDeleteType type, int32_t uid)
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
    int32_t ret = Security::AccessToken::AccessTokenKit::DeleteIdentity(tokenId, bundleName,
        static_cast<Security::AccessToken::ReservedType>(type));
    if (ret == ERR_OK && uid != Constants::INVALID_UID && type == TokenDeleteType::NONE) {
        // Only the NONE semantics actually deletes the identity: the reserved types
        // keep it in the AT service, so the reverse-lookup cache entry stays with it.
        auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr != nullptr) {
            dataMgr->RemoveUidIndexMap(uid);
        }
    }
    return ret;
}
} // namespace AppExecFwk
} // namespace OHOS
