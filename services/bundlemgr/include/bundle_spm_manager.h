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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SPM_MANAGER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SPM_MANAGER_H

#include <map>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "appexecfwk_errors.h"
#include "bundle_install_checker.h"
#include "inner_bundle_info.h"
#include "ipc/code_signature_param.h"
#include "ipc/create_dir_param.h"
#include "ipc/install_hnp_param.h"
#include "ipc/verify_bin_param.h"

namespace OHOS {
namespace AppExecFwk {

class BundleDataMgr;

/**
 * @brief Facade collecting all SPM (Security Permission Manager) related logic used by
 *        installers. While SPM is disabled (IsEnabled() == false), every method degrades
 *        to a legacy passthrough wrapper or a no-op with zero behavior change and error
 *        codes passed through unchanged. SPM stage 3 will switch the internal branches
 *        to access token service calls without touching installer call sites.
 */
class BundleSpmManager {
public:
    static BundleSpmManager &GetInstance();

    /**
     * @brief Assemble the SPM BundlePolicy from the bundle info: the pre-authorization
     *        list (default permission source, signature matched) plus dlp type and
     *        debug grant flag. Permission defs/states are derived by the access token
     *        service from the session provision (deferred permission model).
     */
    static Security::AccessToken::BundlePolicy CreateBundlePolicy(const InnerBundleInfo &innerBundleInfo,
        int32_t dlpType, bool isDebugGrant);

    /**
     * @brief Finish the AT install session: isSuccess maps to the isPersistent
     *        semantics of FinishInstall (true commits and persists, false rolls
     *        back without persistence); a zero session id short-circuits and a
     *        transient AT error is retried once; on success the installd session
     *        provision cache is cleared.
     */
    static int32_t FinishHapInstall(int32_t sessionId, bool isSuccess,
        const std::map<std::string, std::string> &modulePathMap);

    /**
     * @brief Whether the SPM delayed permission model is enabled. Reads the
     *        system parameter persist.bms.spm.enable (default false, spec FR-19);
     *        the value is cached per process, so a change needs a restart.
     */
    static bool IsEnabled();

    /**
     * @brief RAII handle of one install-scoped SPM session, move-only.
     *
     * Lifecycle (SPM ON): CheckSignAndInitSession()/CreateDeferred() obtains the
     * session id; Commit()
     * submits it after bundle data is persisted; destruction rolls it back if not
     * committed (a failed commit fails the install, so the failure path rolls both
     * the business data and the session back consistently). Under SPM OFF the
     * session id is always 0, so every SPM side effect (session rollback, installd
     * provision cache cleanup) is skipped.
     */
    class InstallSession {
    public:
        // Default-constructs an empty session (session id 0, inert under SPM OFF);
        // equivalent to CreateDeferred(). Public so installers can hold it as a member.
        InstallSession() = default;
        InstallSession(InstallSession &&other) noexcept;
        InstallSession &operator=(InstallSession &&other) noexcept;
        ~InstallSession();
        InstallSession(const InstallSession &) = delete;
        InstallSession &operator=(const InstallSession &) = delete;

        /**
         * @brief Verify hap sign info and initialize the SPM install session.
         *        SPM OFF: passthrough of BundleInstallChecker::CheckMultipleHapsSignInfo
         *        with the same arguments (readFile/userId/skipEnterpriseResign must match
         *        the pre-facade call site to keep behavior unchanged). On success the
         *        cached results are available via GetHapVerifyResults().
         * @param userId Indicates the user id passed to sign verification.
         * @param bundlePaths Indicates the hap paths to verify.
         * @param isPreInstallApp Indicates whether the bundles are pre-installed; consumed
         *        by SPM stage 3 only.
         * @param checker Indicates the install checker owned by the caller installer.
         * @param outErrCode Outputs the raw error code of the underlying verification.
         * @param readFile Indicates whether to read the hap files during verification.
         * @param skipEnterpriseResign Indicates whether to skip enterprise resign check.
         * @return Returns an empty session (session id 0) on failure.
         */
        static InstallSession CheckSignAndInitSession(int32_t userId, const std::vector<std::string> &bundlePaths,
            bool isPreInstallApp, BundleInstallChecker &checker, ErrCode &outErrCode,
            bool readFile = true, bool skipEnterpriseResign = false);

        /**
         * @brief Create a session without sign verification, used by installers whose
         *        token is initialized later in the flow (clone/sandbox/multi-user).
         * @return Returns a deferred session (session id 0).
         */
        static InstallSession CreateDeferred();

        int32_t GetSessionId() const;
        bool IsActive() const;
        // Whether Commit already succeeded: a committed session's identity was
        // persisted by FinishInstall(true), so failure rollbacks still need the
        // explicit DeleteIdentity undo; an uncommitted session's freshly created
        // identity is discarded by the session rollback itself (never persisted).
        bool IsCommitted() const;
        // Whether InitToken prepared an identity inside this session (fresh
        // creation or reserved adoption). An update-only session (UpdateToken)
        // never sets it: its token predates the session, so the failure rollback
        // must never delete it.
        bool HasPreparedIdentity() const;
        bool GetHapVerifyResults(std::vector<Security::Verify::HapVerifyResult> &out) const;

        /**
         * @brief Initialize hap token and, for a fresh install user info, allocate uid/gid.
         *        SPM OFF: tokenID != 0 means keep-data recovery and updates the existing
         *        token, otherwise a new token is initialized; after success, uid is
         *        allocated via BundleDataMgr::GenerateUidAndGid when not done yet.
         *        SPM ON: PrepareHapIdentity prepares the identity — with session id 0
         *        the AT side allocates a session itself and writes the id back; uid
         *        handling follows the dual-authority rule (desired adoption / AT
         *        allocation persisted, GenerateUidAndGid stays idempotent).
         */
        int32_t InitToken(InnerBundleInfo &info, int32_t userId, int32_t dlpType,
            Security::AccessToken::AccessTokenIDEx &tokenIdEx,
            Security::AccessToken::HapInfoCheckResult &checkResult, const std::string &caps,
            BundleDataMgr *dataMgr, bool isDebugGrant = false,
            int32_t *identityUid = nullptr);
        // identityUid: optional out param carrying the uid of the prepared identity —
        // clone installers use it because under SPM ON they do not allocate the uid
        // locally (the AT side allocates a fresh one; the token query filters by
        // instIndex so the main app uid is never derived) and the clone uid handling
        // is owned by the caller (the user info of `info` stays untouched).

        // dlpType: the DLP type carried into the ON-path policy (0 = normal
        // token; the DLP sandbox flows use InitToken, which takes it as a
        // leading parameter). checkResult: filled by the SPM OFF passthrough
        // (UpdateHapToken); under SPM ON the policy update produces no
        // permission-check result — the failure is carried by the return code
        // and the facade log, GetCheckResultMsg returns empty.
        int32_t UpdateToken(Security::AccessToken::AccessTokenIDEx &tokenIdEx,
            const InnerBundleInfo &info, int32_t userId,
            Security::AccessToken::HapInfoCheckResult &checkResult, const std::string &caps,
            bool dataRefresh = false, bool isDebugGrant = false, int32_t dlpType = 0,
            int32_t appIndex = 0,
            // Optional out param: when the AT side refreshes the token-bound uid
            // (uidOut > 0), callers with a writable info persist it back into
            // the user info (the DB write happens through their normal save path).
            int32_t *refreshedUid = nullptr);

        /**
         * @brief Pre-check app permissions inside the session. Always returns ERR_OK
         *         under SPM OFF; installType carries the same InstallTypeEnum
         *         (TYPE_INSTALL/TYPE_REPLACE/TYPE_MERGE) consumed by
         *         AccessTokenKit::CheckHapPermissionInfo. The dual-mode identity
         *         (MultipleMode) of this install is passed HERE — not at the
         *         sign-check session creation, where the install's dual-mode
         *         identity is not settled yet — because the AT side consumes the
         *         mode through this call (moved from CheckHapSignInfo, AT PR
         *         #5133).
         * @param installType Indicates the install type (install/replace/merge).
         * @param checkResult Outputs the permission check result.
         * @param mode Indicates the dual-mode identity of this install on the AT
         *        side: an install running under the dual-mode clone name (the
         *        secondary variant, e.g. a non-empty dualModeBundleName_ in the
         *        base installer) uses SUB_MODE, every other install uses the
         *        default/main mode.
         */
        int32_t CheckPermissionInfo(Security::AccessToken::InstallTypeEnum installType,
            Security::AccessToken::HapInfoCheckResult &checkResult,
            Security::AccessToken::MultipleMode mode
                = Security::AccessToken::MultipleMode::DEFAULT_OR_MAIN_MODE);

        int32_t VerifyPermission(const std::string &bundleName, const std::string &permission,
            int32_t userId);

        /**
         * @brief Commit the session after bundle data is persisted. Always returns
         *         ERR_OK and triggers no IPC under SPM OFF. A failed commit must fail
         *         the install: the callers map it to a registered BMS error code, and
         *         the regular failure path rolls both the business data and the
         *         session (destructor rollback) back.
         */
        int32_t Commit(const std::map<std::string, std::string> &modulePathMap);

        int32_t Rollback();

        // Only set the session id of installd IPC params; other fields keep being
        // filled by installers (ProcessCodeSignatureParam stays at call sites).
        void FillCreateDirParam(CreateDirParam &param) const;
        void FillCodeSignatureParam(const Security::Verify::HapVerifyResult &hapVerifyResult,
            CodeSignatureParam &param) const;
        void FillInstallHnpParam(InstallHnpParam &param) const;
        void FillVerifyBinParam(VerifyBinParam &param) const;

        ErrCode DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
            const unsigned char *profileBlock) const;

    private:
        void ClearInstalldProvisionCache();

        int32_t sessionId_ = 0;
        bool committed_ = false;
        bool identityPrepared_ = false;
        std::vector<Security::Verify::HapVerifyResult> hapVerifyResults_;
    };

    enum class TokenDeleteType {
        NONE = 0,
        RESERVED_IDENTITY,
        RESERVED_DATA,
    };

    /**
     * @brief Re-sign the app permissions in a standalone SPM session after a module
     *        uninstall. No-op under SPM OFF; failures do not block the uninstall flow.
     * @param info Indicates the bundle info of the remaining app.
     * @param userId Indicates the user id.
     * @return Returns ERR_OK under SPM OFF or when the refresh succeeds.
     */
    static int32_t OnModuleUninstalled(const InnerBundleInfo &info, int32_t userId);

    /**
     * @brief Whether the error code returned by the access token service can be
     *        recovered on demand by TryRecoverUidError/TryRecoverAlreadyExistError
     *        (used by installers to decide whether to bubble the raw code up to
     *        the install entry for the recovery retry). Always false under SPM OFF,
     *        so the SPM OFF error-code contract is never affected.
     */
    static bool IsRecoverableSpmError(int32_t errCode);

    /**
     * @brief Wrap the raw AT recovery codes back into the registered BMS install
     *        error code. Install entries without an on-demand recovery chain must
     *        call this before returning to their callers, so no unregistered AT
     *        code leaks through the IPC boundary.
     */
    static ErrCode WrapRecoverableSpmErrorCode(ErrCode errCode);

    /**
     * @brief Normalize the provision profile block from the AT-side profile data:
     *        the block vector is the single source of truth for both the length
     *        and the content (the separate claimed length comes from another
     *        process and is never trusted).
     */
    static bool FillProvisionProfileBlock(const Security::AccessToken::ProfileData &profileData,
        Security::Verify::ProvisionInfo &provisionInfo);

    /**
     * @brief On-demand recovery when the access token service reports a missing uid
     *        (e.g. an OTA migration gap): re-register the identity of this single
     *        bundle via MigrateInstalledBundles. Always false under SPM OFF.
     */
    static bool TryRecoverUidError(const std::string &bundleName, BundleDataMgr *dataMgr);

    /**
     * @brief On-demand recovery when the access token service reports a leftover
     *        identity (crashed session): delete it by bundle name and retry.
     *        Always false under SPM OFF.
     */
    static bool TryRecoverAlreadyExistError(const std::string &bundleName);

    /**
     * @brief Delete a hap token with the reserved semantics.
     *        SPM OFF mapping: NONE -> DeleteAccessTokenId(tokenId, false);
     *        RESERVED_IDENTITY -> DeleteAccessTokenId(tokenId, true);
     *        RESERVED_DATA -> no-op (legacy keep-data keeps the token active).
     *        SPM ON: the identity is deleted through DeleteIdentity (the
     *        TokenDeleteType maps one-to-one to the AT ReservedType values).
     */
    static int32_t DeleteToken(Security::AccessToken::AccessTokenID tokenId,
        const std::string &bundleName, TokenDeleteType type = TokenDeleteType::NONE);

private:
    BundleSpmManager() = default;
    ~BundleSpmManager() = default;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SPM_MANAGER_H
