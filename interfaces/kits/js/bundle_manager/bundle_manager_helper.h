/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_HELPER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_HELPER_H

#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "clean_cache_callback.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
class BundleManagerHelper {
public:
    static ErrCode InnerBatchQueryAbilityInfos(const std::vector<OHOS::AAFwk::Want>& wants, int32_t flags,
        int32_t userId, std::vector<AbilityInfo>& abilityInfos);
    static ErrCode InnerGetDynamicIcon(const std::string& bundleName, std::string& moduleName);
    static ErrCode InnerIsAbilityEnabled(const AbilityInfo& abilityInfo, bool& isEnable, int32_t appIndex);
    static ErrCode InnerSetAbilityEnabled(const AbilityInfo& abilityInfo, bool& isEnable, int32_t appIndex);
    static ErrCode InnerSetApplicationEnabled(const std::string& bundleName, bool& isEnable, int32_t appIndex);
    static ErrCode InnerEnableDynamicIcon(
        const std::string& bundleName, const std::string& moduleName, int32_t appIndex, int32_t userId, bool isDefault);
    static ErrCode InnerGetAppCloneIdentity(int32_t uid, std::string& bundleName, int32_t& appIndex);
    static ErrCode InnerGetBundleArchiveInfo(std::string& hapFilePath, int32_t flags, BundleInfo& bundleInfo);
    static ErrCode GetAbilityFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
        const std::string& moduleName, AbilityInfo& targetAbilityInfo);
    static ErrCode GetExtensionFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
        const std::string& moduleName, ExtensionAbilityInfo& targetExtensionInfo);
    static ErrCode InnerGetPermissionDef(const std::string& permissionName, PermissionDef& permissionDef);
    static ErrCode InnerCleanBundleCacheCallback(
        const std::string &bundleName, int32_t appIndex, const OHOS::sptr<CleanCacheCallback> cleanCacheCallback);
    static ErrCode InnerGetAppProvisionInfo(
        const std::string& bundleName, int32_t userId, AppProvisionInfo& appProvisionInfo);
    static ErrCode InnerGetAllAppProvisionInfo(const int32_t userId, std::vector<AppProvisionInfo>& appProvisionInfos);
    static ErrCode InnerGetAllAppInstallExtendedInfo(std::vector<AppInstallExtendedInfo>& appInstallExtendedInfos);
    static ErrCode InnerGetAllPreinstalledApplicationInfos(
        std::vector<PreinstalledApplicationInfo>& preinstalledApplicationInfos);
    static ErrCode InnerGetAllAppCloneBundleInfo(
        const std::string& bundleName, int32_t bundleFlags, int32_t userId, std::vector<BundleInfo>& bundleInfos);
    static ErrCode InnerGetAllSharedBundleInfo(std::vector<SharedBundleInfo>& sharedBundles);
    static ErrCode InnerGetSharedBundleInfo(
        const std::string& bundleName, const std::string& moduleName, std::vector<SharedBundleInfo>& sharedBundles);
    static ErrCode InnerGetExtResource(const std::string& bundleName, std::vector<std::string>& moduleNames);
    static ErrCode InnerDisableDynamicIcon(
        const std::string& bundleName, int32_t appIndex, int32_t userId, bool isDefault);
    static ErrCode InnerGetDynamicIconInfo(
        const std::string& bundleName, std::vector<DynamicIconInfo>& dynamicIconInfos);
    static ErrCode InnerGetAllDynamicIconInfo(const int32_t userId, std::vector<DynamicIconInfo>& dynamicIconInfos);
    static ErrCode InnerVerify(const std::vector<std::string>& abcPaths, bool flag);
    static ErrCode InnerDeleteAbc(const std::string& path);
    static ErrCode InnerGetRecoverableApplicationInfo(std::vector<RecoverableApplicationInfo>& recoverableApplications);
    static ErrCode InnerGetAllPluginInfo(
        std::string& hostBundleName, int32_t userId, std::vector<PluginBundleInfo>& pluginBundleInfos);
    static ErrCode InnerSetAbilityFileTypesForSelf(
        const std::string& moduleName, const std::string& abilityName, const std::vector<std::string>& fileTypes);
    static ErrCode InnerGetAbilityInfos(const std::string& uri, uint32_t flags, std::vector<AbilityInfo>& abilityInfos);
    static ErrCode InnerCleanBundleCacheForSelfCallback(const OHOS::sptr<CleanCacheCallback> cleanCacheCallback);
    static ErrCode InnerGetPluginBundlePathForSelf(const std::string &pluginBundleName, std::string &codePath);
    static ErrCode InnerGetBundleInstallStatus(const std::string &bundleName, BundleInstallStatus &bundleInstallStatus);
};
} // AppExecFwk
} // OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_HELPER_H