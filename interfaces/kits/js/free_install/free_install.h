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

#ifndef BUNDLE_FRAMEWORK_KITS_JS_FREE_INSTALL_FREE_INSTALL_H
#define BUNDLE_FRAMEWORK_KITS_JS_FREE_INSTALL_FREE_INSTALL_H

#include "base_cb_info.h"
#include "bundle_pack_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
struct HapModuleRemovableCallbackInfo : public BaseCallbackInfo {
    explicit HapModuleRemovableCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    bool result = false;
    std::string bundleName;
    std::string moduleName;
};

struct SetHapModuleUpgradeFlagCallbackInfo : public BaseCallbackInfo {
    explicit SetHapModuleUpgradeFlagCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    int32_t upgradeFlag = 0;
    std::string bundleName;
    std::string moduleName;
};

struct GetBundlePackInfoCallbackInfo : public BaseCallbackInfo {
    explicit GetBundlePackInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    int32_t bundlePackFlag = 0;
    std::string bundleName;
    BundlePackInfo bundlePackInfo;
};

struct GetDispatchInfoCallbackInfo : public BaseCallbackInfo {
    explicit GetDispatchInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string version;
    std::string dispatchAPI;
};

napi_value IsHapModuleRemovable(napi_env env, napi_callback_info info);
napi_value SetHapModuleUpgradeFlag(napi_env env, napi_callback_info info);
napi_value GetBundlePackInfo(napi_env env, napi_callback_info info);
napi_value GetDispatchInfo(napi_env env, napi_callback_info info);

void CreateUpgradeFlagObject(napi_env env, napi_value value);
void CreateBundlePackFlagObject(napi_env env, napi_value value);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // BUNDLE_FRAMEWORK_KITS_JS_FREE_INSTALL_FREE_INSTALL_H