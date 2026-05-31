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

#ifndef FOUNDATION_BUNDLEMGR_SERVICES_KITS_INCLUDE_PLUGIN_MANAGER_H
#define FOUNDATION_BUNDLEMGR_SERVICES_KITS_INCLUDE_PLUGIN_MANAGER_H

#include <string>
#include <vector>

#include "base_cb_info.h"
#include "installer_helper.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
struct InstallLocalPluginCallbackInfo : public BaseCallbackInfo {
    explicit InstallLocalPluginCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::vector<std::string> pluginFilePaths;
    InstallResult installResult;
};

struct UninstallLocalPluginCallbackInfo : public BaseCallbackInfo {
    explicit UninstallLocalPluginCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string pluginBundleName;
    InstallResult installResult;
};

napi_value InstallLocalPlugin(napi_env env, napi_callback_info info);
napi_value UninstallLocalPlugin(napi_env env, napi_callback_info info);
} // namespace AppExecFwk
} // namespace OHOS

#endif // FOUNDATION_BUNDLEMGR_SERVICES_KITS_INCLUDE_PLUGIN_MANAGER_H
