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
// Max attempts (initial + 3 retries) to restore one app's token, per requirement "retry 3 times".
constexpr int32_t MAX_RESTORE_ATTEMPTS = 4;
constexpr int32_t RET_RECOVERY_INTERNAL_ERROR = -1;

struct RecoveryResult {
    size_t successCount = 0;
    size_t alreadyExistCount = 0;
    std::vector<std::string> failedList;
};
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
    RestoreAllApps(dataMgr, restoreInfos);
    // Clear the marker unconditionally after traversal even if some apps failed: each app was
    // already retried MAX_RESTORE_ATTEMPTS times, and a persist parameter that stays set would
    // rerun the full (mostly already-exist) pass on every boot. If the reset itself fails the
    // parameter stays set, so the next mount point or boot retries the whole pass idempotently.
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

void BundleAccessTokenRecoveryMgr::RestoreAllApps(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::vector<AccessTokenRestoreInfo> &restoreInfos)
{
    RecoveryResult result;
    for (const auto &restoreInfo : restoreInfos) {
        int32_t ret = RET_RECOVERY_INTERNAL_ERROR;
        bool alreadyExist = false;
        for (int32_t attempt = 1; attempt <= MAX_RESTORE_ATTEMPTS; ++attempt) {
            ret = RestoreSingleApp(dataMgr, restoreInfo, alreadyExist);
            if ((ret == ERR_OK) || alreadyExist) {
                break;
            }
            APP_LOGW("RestoreHapToken attempt failed, bundle:%{public}s userId:%{public}d "
                "appIndex:%{public}d ret:%{public}d attempt:%{public}d", restoreInfo.bundleName.c_str(),
                restoreInfo.userId, restoreInfo.appIndex, ret, attempt);
        }
        if (alreadyExist) {
            ++result.alreadyExistCount;
        } else if (ret == ERR_OK) {
            ++result.successCount;
        } else {
            result.failedList.push_back(restoreInfo.bundleName);
        }
    }
    APP_LOGI("RestoreHapToken recovery finish, total:%{public}zu success:%{public}zu "
        "alreadyExist:%{public}zu failed:%{public}zu", restoreInfos.size(), result.successCount,
        result.alreadyExistCount, result.failedList.size());
    for (const auto &failedBundle : result.failedList) {
        APP_LOGE("RestoreHapToken finally failed, bundle:%{public}s", failedBundle.c_str());
    }
}

int32_t BundleAccessTokenRecoveryMgr::RestoreSingleApp(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const AccessTokenRestoreInfo &restoreInfo, bool &alreadyExist)
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
    // tempBundleInfos_ (dual-mode, feature not launched yet; apps of the mode the user has not
    // chosen) is intentionally out of the recovery scope, aligned with the spike scope.
    AppProvisionInfo appProvisionInfo;
    if (dataMgr->GetAppProvisionInfo(restoreInfo.bundleName, restoreInfo.userId, appProvisionInfo)
        != ERR_OK) {
        APP_LOGW("RestoreHapToken get app provision info failed, bundle:%{public}s",
            restoreInfo.bundleName.c_str());
    }
    Security::AccessToken::AccessTokenIDEx tokenIdeEx;
    tokenIdeEx.tokenIDEx = restoreInfo.accessTokenIdEx;
    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t ret = BundlePermissionMgr::RestoreHapToken(innerBundleInfo, restoreInfo.userId,
        tokenIdeEx, checkResult, appProvisionInfo.appServiceCapabilities);
    alreadyExist = (ret == Security::AccessToken::AccessTokenError::ERR_TOKENID_HAS_EXISTED);
    return ret;
}
} // namespace AppExecFwk
} // namespace OHOS
