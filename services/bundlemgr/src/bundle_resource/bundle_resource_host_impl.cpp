/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_resource_host_impl.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_manager.h"

namespace OHOS {
namespace AppExecFwk {
ErrCode BundleResourceHostImpl::GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo, const int32_t appIndex)
{
    APP_LOGD("start, bundleName: %{public}s, flags: %{public}u", bundleName.c_str(), flags);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_GET_BUNDLE_RESOURCES)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if ((appIndex < 0) || (appIndex > ServiceConstants::CLONE_APP_INDEX_MAX)) {
        APP_LOGE("get fail, bundleName %{public}s %{public}d not in valid range",
            bundleName.c_str(), appIndex);
        return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager nullptr, bundleName %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!manager->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo, appIndex)) {
        APP_LOGE("get failed, bundleName %{public}s, flags %{public}u", bundleName.c_str(), flags);
        return CheckBundleNameValid(bundleName, appIndex);
    }
    return ERR_OK;
}

ErrCode BundleResourceHostImpl::GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo, const int32_t appIndex)
{
    APP_LOGD("start, bundleName: %{public}s, flags: %{public}u", bundleName.c_str(), flags);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_GET_BUNDLE_RESOURCES)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if ((appIndex < 0) || (appIndex > ServiceConstants::CLONE_APP_INDEX_MAX)) {
        APP_LOGE("get fail, bundleName %{public}s appIndex %{public}d not in valid range",
            bundleName.c_str(), appIndex);
        return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager nullptr, bundleName %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!manager->GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfo, appIndex)) {
        APP_LOGE("get failed, bundleName %{public}s, flags %{public}u", bundleName.c_str(), flags);
        return CheckBundleNameValid(bundleName, appIndex);
    }
    return ERR_OK;
}

ErrCode BundleResourceHostImpl::GetAllBundleResourceInfo(const uint32_t flags,
    std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    APP_LOGD("start");
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_GET_BUNDLE_RESOURCES)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager is nullptr");
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!manager->GetAllBundleResourceInfo(flags, bundleResourceInfos)) {
        APP_LOGE("get failed, flags %{public}u", flags);
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 1, 0);
    return ERR_OK;
}

ErrCode BundleResourceHostImpl::GetAllLauncherAbilityResourceInfo(const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    APP_LOGD("start");
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_GET_BUNDLE_RESOURCES)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager is nullptr");
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!manager->GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfos)) {
        APP_LOGE("get failed, flags %{public}u", flags);
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 1, 0);
    return ERR_OK;
}

ErrCode BundleResourceHostImpl::CheckBundleNameValid(const std::string &bundleName, int32_t appIndex)
{
    if (appIndex == 0) {
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager nullptr, bundleName %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    BundleResourceInfo bundleResourceInfo;
    if (!manager->GetBundleResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), bundleResourceInfo)) {
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    APP_LOGE("get failed, bundleName %{public}s appIndex %{public}d", bundleName.c_str(), appIndex);
    return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
}
} // AppExecFwk
} // OHOS
