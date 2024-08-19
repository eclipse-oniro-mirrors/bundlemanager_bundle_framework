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

#include "bms_extension_client.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_manager.h"
#include "bundle_mgr_service.h"

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
        APP_LOGE("get bundle resource Fail, bundleName: %{public}s appIndex: %{public}d not in valid range",
            bundleName.c_str(), appIndex);
        return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager nullptr, bundleName %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!manager->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo, appIndex)) {
        APP_LOGE_NOFUNC("get resource failed -n %{public}s -f %{public}u", bundleName.c_str(), flags);
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
        APP_LOGE("get bundle resource Fail, bundleName: %{public}s appIndex: %{public}d not in valid range",
            bundleName.c_str(), appIndex);
        return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager nullptr, bundleName %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!manager->GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfo, appIndex)) {
        APP_LOGE_NOFUNC("get resource failed -n %{public}s -f %{public}u", bundleName.c_str(), flags);
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
        APP_LOGE("get all resource failed, flags:%{public}u", flags);
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->GetAllBundleResourceInfo(flags, bundleResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGD("get all resource from ext failed, flags:%{public}u", flags);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) {
        APP_LOGD("need sort by label");
        std::sort(bundleResourceInfos.begin(), bundleResourceInfos.end(),
            [](BundleResourceInfo &resourceA, BundleResourceInfo &resourceB) {
                return resourceA.label < resourceB.label;
            });
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
        APP_LOGE("get all resource failed, flags:%{public}u", flags);
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGD("get all resource from ext failed, flags:%{public}u", flags);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) {
        APP_LOGD("need sort by label");
        std::sort(launcherAbilityResourceInfos.begin(), launcherAbilityResourceInfos.end(),
            [](LauncherAbilityResourceInfo &resourceA, LauncherAbilityResourceInfo &resourceB) {
                return resourceA.label < resourceB.label;
            });
    }
    BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 1, 0);
    return ERR_OK;
}

ErrCode BundleResourceHostImpl::AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId)
{
    APP_LOGD("start, bundleName:%{public}s userId:%{private}d", bundleName.c_str(), userId);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!dataMgr->HasUserId(userId)) {
        APP_LOGE("user id invalid");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_GET_BUNDLE_RESOURCES)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsBrokerServiceStarted()) {
        APP_LOGE("broker is not started");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->AddResourceInfoByBundleName(bundleName, userId);
    if (ret != ERR_OK) {
        APP_LOGE("bms extension client api add resource info by bundle name error:%{public}d", ret);
    }
    return ret;
}

ErrCode BundleResourceHostImpl::AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const int32_t userId)
{
    APP_LOGD("start, bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s userId:%{private}d",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str(), userId);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    if (moduleName.empty()) {
        APP_LOGE("moduleName is empty.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    if (abilityName.empty()) {
        APP_LOGE("abilityName is empty.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!dataMgr->HasUserId(userId)) {
        APP_LOGE("user id invalid");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_GET_BUNDLE_RESOURCES)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsBrokerServiceStarted()) {
        APP_LOGE("broker is not started");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    if (ret != ERR_OK) {
        APP_LOGE("bms extension client api add resource info by ability name error:%{public}d", ret);
    }
    return ret;
}

ErrCode BundleResourceHostImpl::DeleteResourceInfo(const std::string &key)
{
    APP_LOGD("start, key:%{private}s", key.c_str());
    if (key.empty()) {
        APP_LOGE("key is empty.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_GET_BUNDLE_RESOURCES)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsBrokerServiceStarted()) {
        APP_LOGE("broker is not started");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->DeleteResourceInfo(key);
    if (ret != ERR_OK) {
        APP_LOGE("bms extension client api delete by key error:%{public}d", ret);
    }
    return ret;
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
    APP_LOGE("get failed, bundleName:%{public}s appIndex:%{public}d", bundleName.c_str(), appIndex);
    return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
}
} // AppExecFwk
} // OHOS
