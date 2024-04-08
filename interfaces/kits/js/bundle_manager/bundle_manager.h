/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
#include "pixel_map.h"
#endif
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
};
struct GetBundleArchiveInfoCallbackInfo : public BaseCallbackInfo {
    explicit GetBundleArchiveInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    std::string hapFilePath;
    int32_t flags = 0;
    BundleInfo bundleInfo;
};
struct GetBundleNameByUidCallbackInfo : public BaseCallbackInfo {
    explicit GetBundleNameByUidCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    int32_t uid = 0;
    std::string bundleName;
};
struct AbilityCallbackInfo : public BaseCallbackInfo {
    explicit AbilityCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    OHOS::AAFwk::Want want;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    bool isSavedInCache = false;
    std::vector<AbilityInfo> abilityInfos;
};

struct ExtensionCallbackInfo : public BaseCallbackInfo {
    explicit ExtensionCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    OHOS::AAFwk::Want want;
    int32_t extensionAbilityType = static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED);
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    bool isSavedInCache = false;
    std::vector<ExtensionAbilityInfo> extensionInfos;
};

struct CleanBundleCacheCallbackInfo : public BaseCallbackInfo {
    explicit CleanBundleCacheCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    OHOS::sptr<CleanCacheCallback> cleanCacheCallback;
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
    std::string bundleName;
    bool isEnable = false;
};

struct LaunchWantCallbackInfo : public BaseCallbackInfo {
    explicit LaunchWantCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    OHOS::AAFwk::Want want;
};

struct VerifyCallbackInfo : public BaseCallbackInfo {
    explicit VerifyCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::vector<std::string> abcPaths;
    bool flag = false;
    std::string deletePath;
};

struct DynamicIconCallbackInfo : public BaseCallbackInfo {
    explicit DynamicIconCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    std::string bundleName;
    std::string moduleName;
    std::vector<std::string> moduleNames;
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
    AbilityInfo abilityInfo;
    bool isEnable = false;
};

struct ApplicationInfoCallbackInfo : public BaseCallbackInfo {
    explicit ApplicationInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
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
            std::hash<int32_t>()(query.flags_) ^ std::hash<int32_t>()(query.userId_);
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
    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    bool isSavedInCache = false;
    int32_t uid = 0;
    BundleInfo bundleInfo;
};

struct SharedBundleCallbackInfo : public BaseCallbackInfo {
    explicit SharedBundleCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}

    std::string bundleName;
    std::string moduleName;
    std::vector<SharedBundleInfo> sharedBundles;
};

struct AppProvisionInfoCallbackInfo : public BaseCallbackInfo {
    explicit AppProvisionInfoCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    std::string bundleName;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    AppProvisionInfo appProvisionInfo;
};

struct RecoverableApplicationCallbackInfo : public BaseCallbackInfo {
    explicit RecoverableApplicationCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}

    std::vector<RecoverableApplicationInfo> recoverableApplicationInfos;
};

napi_value GetBundleArchiveInfo(napi_env env, napi_callback_info info);
napi_value GetBundleNameByUid(napi_env env, napi_callback_info info);
napi_value SetApplicationEnabled(napi_env env, napi_callback_info info);
napi_value SetAbilityEnabled(napi_env env, napi_callback_info info);
napi_value IsApplicationEnabled(napi_env env, napi_callback_info info);
napi_value IsAbilityEnabled(napi_env env, napi_callback_info info);
napi_value QueryAbilityInfos(napi_env env, napi_callback_info info);
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
napi_value GetAllBundleInfoByDeveloperId(napi_env env, napi_callback_info info);
napi_value GetDeveloperIds(napi_env env, napi_callback_info info);
napi_value SwitchUninstallState(napi_env env, napi_callback_info info);
void CreateApplicationFlagObject(napi_env env, napi_value value);
void CreateAbilityFlagObject(napi_env env, napi_value value);
void CreateExtensionAbilityFlagObject(napi_env env, napi_value value);
void CreateExtensionAbilityTypeObject(napi_env env, napi_value value);
void CreateBundleFlagObject(napi_env env, napi_value value);
void CreatePermissionGrantStateObject(napi_env env, napi_value value);
void CreateAbilityTypeObject(napi_env env, napi_value value);
void CreateDisplayOrientationObject(napi_env env, napi_value value);
void CreateLaunchTypeObject(napi_env env, napi_value value);
void CreateSupportWindowModesObject(napi_env env, napi_value value);
void CreateModuleTypeObject(napi_env env, napi_value value);
void CreateBundleTypeObject(napi_env env, napi_value value);
void CreateCompatiblePolicyObject(napi_env env, napi_value value);
void CreateProfileTypeObject(napi_env env, napi_value value);
void CreateAppDistributionTypeObject(napi_env env, napi_value value);
void RegisterClearCacheListener();
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_H
