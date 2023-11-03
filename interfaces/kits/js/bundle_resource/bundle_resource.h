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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_BUNDLE_RESOURCE_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_BUNDLE_RESOURCE_H

#include "base_cb_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_resource_info.h"
#include "launcher_ability_resource_info.h"
#endif

namespace OHOS {
namespace AppExecFwk {
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
struct AllBundleResourceInfoCallback : public BaseCallbackInfo {
    explicit AllBundleResourceInfoCallback(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    std::vector<BundleResourceInfo> bundleResourceInfos;
};

struct AllLauncherAbilityResourceInfoCallback : public BaseCallbackInfo {
    explicit AllLauncherAbilityResourceInfoCallback(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
};
#endif
napi_value GetBundleResourceInfo(napi_env env, napi_callback_info info);
napi_value GetLauncherAbilityResourceInfo(napi_env env, napi_callback_info info);
napi_value GetAllBundleResourceInfo(napi_env env, napi_callback_info info);
napi_value GetAllLauncherAbilityResourceInfo(napi_env env, napi_callback_info info);
void CreateBundleResourceFlagObject(napi_env env, napi_value value);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_BUNDLE_RESOURCE_H