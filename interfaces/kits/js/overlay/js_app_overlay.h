/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef JS_APP_CONTROL_H
#define JS_APP_CONTROL_H

#include "base_cb_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "overlay_module_info.h"

namespace OHOS {
namespace AppExecFwk {
enum OverlayOption : uint32_t {
    OPTION_SET_OVERLAY_ENABLED,
    OPTION_SET_OVERLAY_ENABLED_BY_BUNDLE,
    OPTION_GET_OVERLAY_MODULE_INFO,
    OPTION_GET_OVERLAY_TARGET_MODULE_INFO,
    OPTION_GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME,
    OPTION_GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME,
    INVALID_OPTION,
};

struct OverlayCallbackInfo : public BaseCallbackInfo {
    explicit OverlayCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    bool isEnabled = true;
    OverlayOption option = INVALID_OPTION;
    std::string bundleName;
    std::string moduleName;
    std::string targetModuleName;
    std::string targetBundleName;
    std::vector<OverlayModuleInfo> infoVec;
    OverlayModuleInfo overlayModuleInfo;
};

napi_value SetOverlayEnabled(napi_env env, napi_callback_info info);
napi_value SetOverlayEnabledByBundleName(napi_env env, napi_callback_info info);
napi_value GetOverlayModuleInfo(napi_env env, napi_callback_info info);
napi_value GetTargetOverlayModuleInfos(napi_env env, napi_callback_info info);
napi_value GetOverlayModuleInfoByBundleName(napi_env env, napi_callback_info info);
napi_value GetTargetOverlayModuleInfosByBundleName(napi_env env, napi_callback_info info);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif /* JS_APP_CONTROL_H */