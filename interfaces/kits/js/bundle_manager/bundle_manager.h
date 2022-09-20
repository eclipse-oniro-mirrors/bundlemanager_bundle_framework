/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "base_cb_info.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "clean_cache_callback.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
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
    std::vector<AbilityInfo> abilityInfos;
};

struct ExtensionCallbackInfo : public BaseCallbackInfo {
    explicit ExtensionCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    OHOS::AAFwk::Want want;
    int32_t extensionAbilityType = static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED);
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<ExtensionAbilityInfo> extensionInfos;
};

struct CleanBundleCacheCallbackInfo : public BaseCallbackInfo {
    explicit CleanBundleCacheCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    OHOS::sptr<CleanCacheCallback> cleanCacheCallback;
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

struct AbilityEnableCallbackInfo : public BaseCallbackInfo {
    explicit AbilityEnableCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    AbilityInfo abilityInfo;
    bool isEnable = false;
};

struct AsyncPermissionDefineCallbackInfo : public BaseCallbackInfo {
    explicit AsyncPermissionDefineCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    std::string permissionName;
    OHOS::AppExecFwk::PermissionDef permissionDef;
};

napi_value GetBundleArchiveInfo(napi_env env, napi_callback_info info);
napi_value GetBundleNameByUid(napi_env env, napi_callback_info info);
napi_value SetApplicationEnabled(napi_env env, napi_callback_info info);
napi_value SetAbilityEnabled(napi_env env, napi_callback_info info);
napi_value IsApplicationEnabled(napi_env env, napi_callback_info info);
napi_value IsAbilityEnabled(napi_env env, napi_callback_info info);
napi_value QueryAbilityInfos(napi_env env, napi_callback_info info);
napi_value QueryExtensionInfos(napi_env env, napi_callback_info info);
napi_value CleanBundleCacheFiles(napi_env env, napi_callback_info info);
napi_value GetPermissionDef(napi_env env, napi_callback_info info);
napi_value GetLaunchWantForBundle(napi_env env, napi_callback_info info);
void CreateAbilityFlagObject(napi_env env, napi_value value);
void CreateExtensionAbilityFlagObject(napi_env env, napi_value value);
void CreateExtensionAbilityTypeObject(napi_env env, napi_value value);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_H
