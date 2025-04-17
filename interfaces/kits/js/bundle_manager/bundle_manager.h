/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_H

#include "ability_info.h"
#include "app_provision_info.h"
#include "base_cb_info.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "clean_cache_callback.h"
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "dynamic_icon_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "plugin/plugin_bundle_info.h"
#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
#include "pixel_map.h"
#endif
#include "preinstalled_application_info.h"
#include "process_cache_callback_host.h"
#include "recoverable_application_info.h"
#include "shared/shared_bundle_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class ClearCacheListener final : public EventFwk::CommonEventSubscriber {
public:
    explicit ClearCacheListener(const EventFwk::CommonEventSubscribeInfo &subscribeInfo);
    virtual ~ClearCacheListener() = default;
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
    static void HandleCleanEnv(void *data);
};
struct GetBundleArchiveInfoCallbackInfo : public BaseCallbackInfo {
    explicit GetBundleArchiveInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    int32_t flags = 0;
    std::string hapFilePath;
    BundleInfo bundleInfo;
};
struct GetBundleNameByUidCallbackInfo : public BaseCallbackInfo {
    explicit GetBundleNameByUidCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    int32_t uid = 0;
    std::string bundleName;
};
struct GetAppCloneIdentityCallbackInfo : public GetBundleNameByUidCallbackInfo {
    explicit GetAppCloneIdentityCallbackInfo(napi_env env) : GetBundleNameByUidCallbackInfo(env) {}

    int32_t appIndex = 0;
};
struct AbilityCallbackInfo : public BaseCallbackInfo {
    explicit AbilityCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    bool isSavedInCache = false;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<AbilityInfo> abilityInfos;
    OHOS::AAFwk::Want want;
};

struct BatchAbilityCallbackInfo : public BaseCallbackInfo {
    explicit BatchAbilityCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    bool isSavedInCache = false;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<OHOS::AAFwk::Want> wants;
};

struct ExtensionCallbackInfo : public BaseCallbackInfo {
    explicit ExtensionCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    bool isSavedInCache = false;
    int32_t extensionAbilityType = static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED);
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    OHOS::AAFwk::Want want;
};

struct CleanBundleCacheCallbackInfo : public BaseCallbackInfo {
    explicit CleanBundleCacheCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    int32_t appIndex = 0;
    OHOS::sptr<CleanCacheCallback> cleanCacheCallback;
};

struct GetAllBundleCacheCallbackInfo : public BaseCallbackInfo {
    explicit GetAllBundleCacheCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    uint64_t cacheSize = 0;
    OHOS::sptr<ProcessCacheCallbackHost> cacheCallback;
};

struct CleanAllBundleCacheCallbackInfo : public BaseCallbackInfo {
    explicit CleanAllBundleCacheCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    OHOS::sptr<ProcessCacheCallbackHost> cacheCallback;
};

struct AbilityIconCallbackInfo : public BaseCallbackInfo {
    explicit AbilityIconCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
#endif
};

struct AbilityLabelCallbackInfo : public BaseCallbackInfo {
    explicit AbilityLabelCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string abilityLabel;
};

struct ApplicationEnableCallbackInfo : public BaseCallbackInfo {
    explicit ApplicationEnableCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    bool isEnable = false;
    int32_t appIndex = 0;
    std::string bundleName;
};

struct LaunchWantCallbackInfo : public BaseCallbackInfo {
    explicit LaunchWantCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::string bundleName;
    OHOS::AAFwk::Want want;
};

struct VerifyCallbackInfo : public BaseCallbackInfo {
    explicit VerifyCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    bool flag = false;
    std::string deletePath;
    std::vector<std::string> abcPaths;
};

struct BundleOption {
    int32_t userId = Constants::UNSPECIFIED_USERID;
    int32_t appIndex = Constants::DEFAULT_APP_INDEX;
    bool isDefault = true;
};

struct DynamicIconCallbackInfo : public BaseCallbackInfo {
    explicit DynamicIconCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    std::string bundleName;
    std::string moduleName;
    std::vector<std::string> moduleNames;
    BundleOption option;
};

struct DynamicIconInfoCallbackInfo : public BaseCallbackInfo {
    explicit DynamicIconInfoCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<DynamicIconInfo> dynamicIconInfos;
};

enum AbilityProfileType : uint32_t {
    ABILITY_PROFILE = 0,
    EXTENSION_PROFILE,
    UNKNOWN_PROFILE
};

struct GetProfileCallbackInfo : public BaseCallbackInfo {
    explicit GetProfileCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    AbilityProfileType type = AbilityProfileType::UNKNOWN_PROFILE;
    std::string moduleName;
    std::string abilityName;
    std::string metadataName;
    std::vector<std::string> profileVec;
};

struct AbilityEnableCallbackInfo : public BaseCallbackInfo {
    explicit AbilityEnableCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    bool isEnable = false;
    int32_t appIndex = 0;
    AbilityInfo abilityInfo;
};

struct ApplicationInfoCallbackInfo : public BaseCallbackInfo {
    explicit ApplicationInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::string bundleName;
    ApplicationInfo appInfo;
};

struct ApplicationInfosCallbackInfo : public BaseCallbackInfo {
    explicit ApplicationInfosCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}

    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<ApplicationInfo> appInfos;
};

struct AsyncPermissionDefineCallbackInfo : public BaseCallbackInfo {
    explicit AsyncPermissionDefineCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    std::string permissionName;
    OHOS::AppExecFwk::PermissionDef permissionDef;
};

struct MigrateDataCallbackInfo : public BaseCallbackInfo {
    explicit MigrateDataCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::vector<std::string> sourcePaths;
    std::string destinationPath;
};

struct Query {
    std::string bundleName_;
    std::string interfaceType_;
    int32_t flags_ = 0;
    int32_t userId_ = Constants::UNSPECIFIED_USERID;
    napi_env env_;
    Query(const std::string &bundleName, const std::string &interfaceType, int32_t flags, int32_t userId, napi_env env)
        : bundleName_(bundleName), interfaceType_(interfaceType), flags_(flags), userId_(userId), env_(env) {}

    bool operator==(const Query &query) const
    {
        return bundleName_ == query.bundleName_ && interfaceType_ == query.interfaceType_ &&
            flags_ == query.flags_ && userId_ == query.userId_ && env_ == query.env_;
    }
};

struct QueryHash  {
    size_t operator()(const Query &query) const
    {
        return std::hash<std::string>()(query.bundleName_) ^ std::hash<std::string>()(query.interfaceType_) ^
            std::hash<int32_t>()(query.flags_) ^ std::hash<int32_t>()(query.userId_) ^
            std::hash<napi_env>()(query.env_);
    }
};

struct BundleInfosCallbackInfo : public BaseCallbackInfo {
    explicit BundleInfosCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}

    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<BundleInfo> bundleInfos;
};

struct BundleInfoCallbackInfo : public BaseCallbackInfo {
    explicit BundleInfoCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    bool isSavedInCache = false;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    int32_t uid = 0;
    std::string bundleName;
    BundleInfo bundleInfo;
};

struct BatchBundleInfoCallbackInfo : public BaseCallbackInfo {
    explicit BatchBundleInfoCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    bool isSavedInCache = false;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    int32_t uid = 0;
    std::vector<std::string> bundleNames;
    std::vector<BundleInfo> bundleInfos;
};

struct PluginCallbackInfo : public BaseCallbackInfo {
    explicit PluginCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::string hostBundleName;
    std::vector<PluginBundleInfo> pluginBundleInfos;
};

struct SharedBundleCallbackInfo : public BaseCallbackInfo {
    explicit SharedBundleCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}

    std::string bundleName;
    std::string moduleName;
    std::vector<SharedBundleInfo> sharedBundles;
};

struct AppProvisionInfoCallbackInfo : public BaseCallbackInfo {
    explicit AppProvisionInfoCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::string bundleName;
    AppProvisionInfo appProvisionInfo;
};

struct RecoverableApplicationCallbackInfo : public BaseCallbackInfo {
    explicit RecoverableApplicationCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}

    std::vector<RecoverableApplicationInfo> recoverableApplicationInfos;
};

struct PreinstalledApplicationInfosCallbackInfo : public BaseCallbackInfo {
    explicit PreinstalledApplicationInfosCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    std::vector<PreinstalledApplicationInfo> preinstalledApplicationInfos;
};

struct CloneAppBundleInfoCallbackInfo : public BaseCallbackInfo {
    explicit CloneAppBundleInfoCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}

    int32_t appIndex = 0;
    int32_t bundleFlags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::string bundleName;
    BundleInfo bundleInfo;
};

struct CloneAppBundleInfosCallbackInfo : public BaseCallbackInfo {
    explicit CloneAppBundleInfosCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}

    int32_t bundleFlags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::string bundleName;
    std::vector<BundleInfo> bundleInfos;
};

napi_value GetBundleArchiveInfo(napi_env env, napi_callback_info info);
napi_value GetBundleNameByUid(napi_env env, napi_callback_info info);
napi_value SetApplicationEnabled(napi_env env, napi_callback_info info);
napi_value SetAbilityEnabled(napi_env env, napi_callback_info info);
napi_value IsApplicationEnabled(napi_env env, napi_callback_info info);
napi_value IsAbilityEnabled(napi_env env, napi_callback_info info);
napi_value QueryAbilityInfos(napi_env env, napi_callback_info info);
napi_value BatchQueryAbilityInfos(napi_env env, napi_callback_info info);
napi_value QueryAbilityInfosSync(napi_env env, napi_callback_info info);
napi_value QueryExtensionInfos(napi_env env, napi_callback_info info);
napi_value GetAbilityLabel(napi_env env, napi_callback_info info);
napi_value GetAbilityIcon(napi_env env, napi_callback_info info);
napi_value CleanBundleCacheFiles(napi_env env, napi_callback_info info);
napi_value GetPermissionDef(napi_env env, napi_callback_info info);
napi_value GetLaunchWantForBundle(napi_env env, napi_callback_info info);
napi_value GetProfile(napi_env env, napi_callback_info info, const AbilityProfileType &profileType);
napi_value GetProfileByAbility(napi_env env, napi_callback_info info);
napi_value GetProfileByExAbility(napi_env env, napi_callback_info info);
napi_value GetApplicationInfo(napi_env env, napi_callback_info info);
napi_value GetApplicationInfos(napi_env env, napi_callback_info info);
napi_value GetBundleInfos(napi_env env, napi_callback_info info);
napi_value GetBundleInfo(napi_env env, napi_callback_info info);
napi_value GetApplicationInfoSync(napi_env env, napi_callback_info info);
napi_value GetBundleInfoSync(napi_env env, napi_callback_info info);
napi_value GetBundleInfoForSelf(napi_env env, napi_callback_info info);
napi_value GetAllSharedBundleInfo(napi_env env, napi_callback_info info);
napi_value GetSharedBundleInfo(napi_env env, napi_callback_info info);
napi_value GetAppProvisionInfo(napi_env env, napi_callback_info info);
napi_value GetSpecifiedDistributionType(napi_env env, napi_callback_info info);
napi_value GetAdditionalInfo(napi_env env, napi_callback_info info);
napi_value GetBundleInfoForSelfSync(napi_env env, napi_callback_info info);
napi_value VerifyAbc(napi_env env, napi_callback_info info);
napi_value DeleteAbc(napi_env env, napi_callback_info info);
napi_value GetExtResource(napi_env env, napi_callback_info info);
napi_value EnableDynamicIcon(napi_env env, napi_callback_info info);
napi_value DisableDynamicIcon(napi_env env, napi_callback_info info);
napi_value GetDynamicIcon(napi_env env, napi_callback_info info);
napi_value GetJsonProfile(napi_env env, napi_callback_info info);
napi_value GetRecoverableApplicationInfo(napi_env env, napi_callback_info info);
napi_value SetAdditionalInfo(napi_env env, napi_callback_info info);
napi_value CanOpenLink(napi_env env, napi_callback_info info);
napi_value GetAllPreinstalledApplicationInfos(napi_env env, napi_callback_info info);
napi_value GetAllBundleInfoByDeveloperId(napi_env env, napi_callback_info info);
napi_value GetDeveloperIds(napi_env env, napi_callback_info info);
napi_value SwitchUninstallState(napi_env env, napi_callback_info info);
napi_value GetAppCloneBundleInfo(napi_env env, napi_callback_info info);
napi_value GetAllAppCloneBundleInfo(napi_env env, napi_callback_info info);
napi_value GetAppCloneIdentity(napi_env env, napi_callback_info info);
napi_value GetAllPluginInfo(napi_env env, napi_callback_info info);
napi_value GetAllBundleCacheSize(napi_env env, napi_callback_info info);
napi_value CleanAllBundleCache(napi_env env, napi_callback_info info);
napi_value GetLaunchWant(napi_env env, napi_callback_info info);
napi_value MigrateData(napi_env env, napi_callback_info info);
napi_value GetAllDynamicIconInfo(napi_env env, napi_callback_info info);
void CreateApplicationFlagObject(napi_env env, napi_value value);
void CreateAbilityFlagObject(napi_env env, napi_value value);
void CreateExtensionAbilityFlagObject(napi_env env, napi_value value);
void CreateExtensionAbilityTypeObject(napi_env env, napi_value value);
void CreateBundleFlagObject(napi_env env, napi_value value);
void CreatePermissionGrantStateObject(napi_env env, napi_value value);
void CreateAbilityTypeObject(napi_env env, napi_value value);
void CreateDisplayOrientationObject(napi_env env, napi_value value);
void CreateOrientationRelatedToSensor(napi_env env, napi_value value);
void CreateLaunchTypeObject(napi_env env, napi_value value);
void CreateSupportWindowModesObject(napi_env env, napi_value value);
void CreateModuleTypeObject(napi_env env, napi_value value);
void CreateBundleTypeObject(napi_env env, napi_value value);
void CreateCompatiblePolicyObject(napi_env env, napi_value value);
void CreateProfileTypeObject(napi_env env, napi_value value);
void CreateAppDistributionTypeObject(napi_env env, napi_value value);
void RegisterClearCacheListener();
void CreateMultiAppModeTypeObject(napi_env env, napi_value value);
void CreateApplicationInfoFlagObject(napi_env env, napi_value value);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_H
