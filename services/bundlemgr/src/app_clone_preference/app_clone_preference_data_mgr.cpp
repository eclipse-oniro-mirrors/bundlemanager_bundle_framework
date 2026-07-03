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

#include "app_clone_preference_data_mgr.h"

#include <algorithm>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_file_util.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"

namespace OHOS {
namespace AppExecFwk {

AppClonePreferenceDataMgr::AppClonePreferenceDataMgr()
{
    APP_LOGD("create AppClonePreferenceDataMgr");
    storage_ = std::make_shared<AppClonePreferenceStorage>();
}

ErrCode AppClonePreferenceDataMgr::GetAppClonePreference(const std::string &bundleName, int32_t userId,
    AppClonePreference &preference)
{
    if (bundleName.empty()) {
        APP_LOGE_NOFUNC("GetAppClonePreference bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE_NOFUNC("GetAppClonePreference BundleDataMgr is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    if (!dataMgr->HasUserInstallInBundle(bundleName, userId)) {
        APP_LOGE_NOFUNC("GetAppClonePreference bundle %{public}s does not exist in userId %{public}d",
            bundleName.c_str(), userId);
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (storage_ == nullptr) {
        APP_LOGE_NOFUNC("GetAppClonePreference storage is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    if (!storage_->Query(bundleName, userId, preference)) {
        APP_LOGE_NOFUNC("GetAppClonePreference no record for bundle %{public}s userId %{public}d",
            bundleName.c_str(), userId);
        return ERR_BUNDLE_MANAGER_APP_CLONE_PREFERENCE_NOT_EXIST;
    }
    // Dirty data cleanup: CLONE preference but the clone no longer exists
    if (preference.mode == AppClonePreferenceMode::CLONE_APP) {
        auto existingAppIndexes = dataMgr->GetCloneAppIndexes(bundleName, userId);
        if (std::find(existingAppIndexes.begin(), existingAppIndexes.end(),
            preference.appIndex) == existingAppIndexes.end()) {
            APP_LOGW_NOFUNC("GetAppClonePreference preferred clone %{public}d no longer exists, delete dirty record",
                preference.appIndex);
            if (!storage_->Delete(bundleName, userId)) {
                APP_LOGE_NOFUNC("GetAppClonePreference storage Delete failed for bundle %{public}s userId %{public}d",
                    bundleName.c_str(), userId);
            }
            return ERR_BUNDLE_MANAGER_APP_CLONE_PREFERENCE_NOT_EXIST;
        }
    }
    return ERR_OK;
}

ErrCode AppClonePreferenceDataMgr::SetAppClonePreference(const std::string &bundleName, int32_t userId,
    const AppClonePreference &preference)
{
    if (bundleName.empty()) {
        APP_LOGE_NOFUNC("SetAppClonePreference bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY;
    }
    if (static_cast<int32_t>(preference.mode) < static_cast<int32_t>(AppClonePreferenceMode::ALWAYS_ASK) ||
        static_cast<int32_t>(preference.mode) > static_cast<int32_t>(AppClonePreferenceMode::CLONE_APP)) {
        APP_LOGE_NOFUNC("SetAppClonePreference invalid preference type %{public}d",
            static_cast<int32_t>(preference.mode));
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    if (preference.mode == AppClonePreferenceMode::CLONE_APP &&
        (preference.appIndex < ServiceConstants::CLONE_APP_INDEX_MIN ||
         preference.appIndex > BundleFileUtil::GetCloneMaxCount())) {
        APP_LOGE_NOFUNC("SetAppClonePreference invalid appIndex %{public}d for CLONE type", preference.appIndex);
        return ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE_NOFUNC("SetAppClonePreference BundleDataMgr is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    if (!dataMgr->HasUserInstallInBundle(bundleName, userId)) {
        APP_LOGE_NOFUNC("SetAppClonePreference bundle %{public}s does not exist in userId %{public}d",
            bundleName.c_str(), userId);
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto existingAppIndexes = dataMgr->GetCloneAppIndexes(bundleName, userId);
    if (existingAppIndexes.empty()) {
        APP_LOGE_NOFUNC("SetAppClonePreference bundle %{public}s has no clones", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_APP_CLONE_NOT_EXIST;
    }
    if (preference.mode == AppClonePreferenceMode::CLONE_APP &&
        std::find(existingAppIndexes.begin(), existingAppIndexes.end(),
            preference.appIndex) == existingAppIndexes.end()) {
        APP_LOGE_NOFUNC("SetAppClonePreference clone appIndex %{public}d not created", preference.appIndex);
        return ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST;
    }
    int32_t targetAppIndex = Constants::MAIN_APP_INDEX;
    if (preference.mode == AppClonePreferenceMode::CLONE_APP) {
        targetAppIndex = preference.appIndex;
    }
    if (preference.mode != AppClonePreferenceMode::ALWAYS_ASK) {
        bool isEnabled = false;
        auto enRet = dataMgr->IsApplicationEnabled(bundleName, targetAppIndex, isEnabled, userId);
        if (enRet != ERR_OK) {
            return ERR_BUNDLE_MANAGER_APPLICATION_DISABLED;
        }
        if (!isEnabled) {
            APP_LOGE_NOFUNC("SetAppClonePreference target appIndex %{public}d is disabled", targetAppIndex);
            return ERR_BUNDLE_MANAGER_APPLICATION_DISABLED;
        }
    }
    if (storage_ == nullptr) {
        APP_LOGE_NOFUNC("SetAppClonePreference storage is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    if (!storage_->InsertOrReplace(bundleName, userId, preference)) {
        APP_LOGE_NOFUNC("SetAppClonePreference storage InsertOrReplace failed");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppClonePreferenceDataMgr::DeleteAppClonePreference(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty()) {
        return ERR_OK;
    }
    if (storage_ == nullptr) {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    if (!storage_->Delete(bundleName, userId)) {
        APP_LOGW_NOFUNC("DeleteAppClonePreference storage Delete failed (may be no-op)");
    }
    return ERR_OK;
}

ErrCode AppClonePreferenceDataMgr::HandleAppCloneUninstalled(const std::string &bundleName,
    int32_t userId, int32_t uninstalledAppIndex)
{
    if (bundleName.empty()) {
        return ERR_OK;
    }
    if (storage_ == nullptr) {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    AppClonePreference current;
    if (!storage_->Query(bundleName, userId, current)) {
        APP_LOGD("HandleAppCloneUninstalled no preference record, nothing to do");
        return ERR_OK;
    }
    if (current.mode == AppClonePreferenceMode::CLONE_APP && current.appIndex == uninstalledAppIndex) {
        APP_LOGD("HandleAppCloneUninstalled preferred clone %{public}d uninstalled, switch to ALWAYS_ASK",
            uninstalledAppIndex);
        AppClonePreference alwaysAsk;
        if (!storage_->InsertOrReplace(bundleName, userId, alwaysAsk)) {
            APP_LOGE_NOFUNC("HandleAppCloneUninstalled storage InsertOrReplace failed for bundle %{public}s "
                "userId %{public}d", bundleName.c_str(), userId);
        }
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
