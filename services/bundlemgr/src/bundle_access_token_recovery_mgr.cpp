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

#include "bundle_access_token_recovery_mgr.h"

#include <chrono>
#include <thread>

#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "app_log_wrapper.h"
#include "app_provision_info_manager.h"
#include "appexecfwk_errors.h"
#include "bundle_permission_mgr.h"
#include "bundle_service_constants.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t RET_RECOVERY_INTERNAL_ERROR = -1;
// Retry rounds after the first pass; worst-case attempts per app stay 1 + 3 = 4.
constexpr int32_t MAX_RETRY_ROUNDS = 3;
// Wait before retry rounds 2 and 3, so a killed service gets restarted first.
constexpr int32_t RETRY_INTERVAL_MS = 500;

struct RecoveryResult {
    size_t successCount = 0;
    size_t alreadyExistCount = 0;
    size_t definitiveFailedCount = 0;
};

// Transient errors: the access token service is unreachable or its db is momentarily not
// operable; the app may still be recovered once the service comes back.
bool IsTransientError(int32_t ret)
{
    return ret == Security::AccessToken::AccessTokenError::ERR_SERVICE_ABNORMAL ||
        ret == Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED ||
        ret == Security::AccessToken::AccessTokenError::ERR_READ_PARCEL_FAILED ||
        ret == Security::AccessToken::AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
}

// Classify a non-transient result; ERR_TOKENID_HAS_EXISTED counts as done.
void CountFinalResult(const AccessTokenRestoreInfo &restoreInfo, int32_t ret, RecoveryResult &result)
{
    if (ret == ERR_OK) {
        ++result.successCount;
        return;
    }
    if (ret == Security::AccessToken::AccessTokenError::ERR_TOKENID_HAS_EXISTED) {
        ++result.alreadyExistCount;
        return;
    }
    ++result.definitiveFailedCount;
    APP_LOGE("RestoreHapToken restore finished with definitive failure, bundle:%{public}s "
        "userId:%{public}d appIndex:%{public}d ret:%{public}d", restoreInfo.bundleName.c_str(),
        restoreInfo.userId, restoreInfo.appIndex, ret);
}
} // namespace

void BundleAccessTokenRecoveryMgr::ProcessRecovery(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const char *mountPoint)
{
    if (!NeedRecovery()) {
        return;
    }
    APP_LOGI("RestoreHapToken recovery start, mount:%{public}s", mountPoint);
    if (dataMgr == nullptr) {
        // Abort without resetting the marker: nothing has been restored yet, next boot retries.
        APP_LOGE("RestoreHapToken recovery aborted, get data manager failed, mount:%{public}s",
            mountPoint);
        return;
    }
    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);
    APP_LOGI("RestoreHapToken recovery total:%{public}zu", restoreInfos.size());
    bool allRestored = RestoreAllApps(dataMgr, restoreInfos);
    if (!allRestored) {
        // Keep the marker set: pending apps need the next boot to re-enter recovery.
        APP_LOGE("RestoreHapToken recovery incomplete, keep dberror for next boot, "
            "mount:%{public}s", mountPoint);
        return;
    }
    // Safe to clear the marker; on reset failure the parameter stays set for the next boot.
    int32_t resetRet = Security::AccessToken::AccessTokenKit::ResetDatabaseRecoveryStatus();
    if (resetRet != ERR_OK) {
        APP_LOGE("RestoreHapToken reset recovery status failed, ret:%{public}d", resetRet);
        return;
    }
    APP_LOGI("RestoreHapToken reset recovery status success");
}

bool BundleAccessTokenRecoveryMgr::NeedRecovery()
{
    return OHOS::system::GetBoolParameter(ServiceConstants::ACCESS_TOKEN_DB_ERROR_PARAM, false);
}

bool BundleAccessTokenRecoveryMgr::RestoreAllApps(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::vector<AccessTokenRestoreInfo> &restoreInfos)
{
    RecoveryResult result;
    std::vector<AccessTokenRestoreInfo> failedInfos;
    // Phase 1: one attempt per app; only transient errors postpone an app to the retry phase.
    for (const auto &restoreInfo : restoreInfos) {
        int32_t ret = RestoreSingleApp(dataMgr, restoreInfo);
        if (IsTransientError(ret)) {
            failedInfos.push_back(restoreInfo);
            APP_LOGW("RestoreHapToken first pass transient failure, bundle:%{public}s "
                "userId:%{public}d appIndex:%{public}d ret:%{public}d",
                restoreInfo.bundleName.c_str(), restoreInfo.userId, restoreInfo.appIndex, ret);
            continue;
        }
        CountFinalResult(restoreInfo, ret, result);
    }
    // Phase 2: retry rounds; each round removes apps whose result is no longer transient.
    for (int32_t round = 1; round <= MAX_RETRY_ROUNDS && !failedInfos.empty(); ++round) {
        std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_INTERVAL_MS));
        std::vector<AccessTokenRestoreInfo> nextRound;
        for (const auto &restoreInfo : failedInfos) {
            int32_t ret = RestoreSingleApp(dataMgr, restoreInfo);
            if (IsTransientError(ret)) {
                nextRound.push_back(restoreInfo);
                APP_LOGW("RestoreHapToken retry round failed, bundle:%{public}s userId:%{public}d "
                    "appIndex:%{public}d ret:%{public}d round:%{public}d",
                    restoreInfo.bundleName.c_str(), restoreInfo.userId, restoreInfo.appIndex,
                    ret, round);
                continue;
            }
            CountFinalResult(restoreInfo, ret, result);
        }
        failedInfos.swap(nextRound);
    }
    APP_LOGI("RestoreHapToken recovery finish, total:%{public}zu success:%{public}zu "
        "alreadyExist:%{public}zu definitiveFailed:%{public}zu pending:%{public}zu",
        restoreInfos.size(), result.successCount, result.alreadyExistCount,
        result.definitiveFailedCount, failedInfos.size());
    for (const auto &pendingInfo : failedInfos) {
        APP_LOGE("RestoreHapToken recovery pending for next boot, bundle:%{public}s "
            "userId:%{public}d appIndex:%{public}d", pendingInfo.bundleName.c_str(),
            pendingInfo.userId, pendingInfo.appIndex);
    }
    return failedInfos.empty();
}

int32_t BundleAccessTokenRecoveryMgr::RestoreSingleApp(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const AccessTokenRestoreInfo &restoreInfo)
{
    InnerBundleInfo innerBundleInfo;
    if (!dataMgr->FetchInnerBundleInfo(restoreInfo.bundleName, innerBundleInfo)) {
        APP_LOGW("RestoreHapToken fetch inner bundle info failed, bundle:%{public}s",
            restoreInfo.bundleName.c_str());
        return RET_RECOVERY_INTERNAL_ERROR;
    }
    if (restoreInfo.appIndex != 0) {
        innerBundleInfo.SetAppIndex(restoreInfo.appIndex);
    }
    // tempBundleInfos_ (dual-mode, not launched yet) is intentionally out of scope.
    AppProvisionInfo appProvisionInfo;
    if (dataMgr->GetAppProvisionInfo(restoreInfo.bundleName, restoreInfo.userId, appProvisionInfo)
        != ERR_OK) {
        APP_LOGW("RestoreHapToken get app provision info failed, bundle:%{public}s",
            restoreInfo.bundleName.c_str());
    }
    Security::AccessToken::AccessTokenIDEx tokenIdeEx;
    tokenIdeEx.tokenIDEx = restoreInfo.accessTokenIdEx;
    Security::AccessToken::HapInfoCheckResult checkResult;
    return BundlePermissionMgr::RestoreHapToken(innerBundleInfo, restoreInfo.userId,
        tokenIdeEx, checkResult, appProvisionInfo.appServiceCapabilities);
}
} // namespace AppExecFwk
} // namespace OHOS
