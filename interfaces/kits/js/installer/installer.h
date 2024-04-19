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

#ifndef FOUNDATION_BUNDLEMGR_SERVICES_KITS_INCLUDE_INSTALLER_H
#define FOUNDATION_BUNDLEMGR_SERVICES_KITS_INCLUDE_INSTALLER_H

#include "base_cb_info.h"
#include "install_param.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
extern thread_local napi_ref g_classBundleInstaller;

struct InstallResult {
    int32_t resultCode = 0;
    std::string resultMsg;
};

enum class InstallOption {
    INSTALL = 0,
    RECOVER = 1,
    UNINSTALL = 2,
    UPDATE_BUNDLE_FOR_SELF = 3,
    UNKNOWN = 4,
    UNINSTALL_AND_RECOVER = 5,
};

struct AsyncInstallCallbackInfo {
    explicit AsyncInstallCallbackInfo(napi_env napiEnv) : env(napiEnv) {}
    ~AsyncInstallCallbackInfo();

    std::vector<std::string> hapFiles;
    std::string bundleName;
    std::string param;
    OHOS::AppExecFwk::InstallParam installParam;
    OHOS::AppExecFwk::UninstallParam uninstallParam;
    InstallResult installResult;
    int32_t err = 0;
    InstallOption option = InstallOption::UNKNOWN;

    napi_env env;
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
};

struct AsyncGetBundleInstallerCallbackInfo {
    explicit AsyncGetBundleInstallerCallbackInfo(napi_env napiEnv) : env(napiEnv) {}
    ~AsyncGetBundleInstallerCallbackInfo();

    napi_env env;
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
};

struct ExtResourceCallbackInfo : public BaseCallbackInfo {
    explicit ExtResourceCallbackInfo(napi_env env) : BaseCallbackInfo(env) {}
    std::string bundleName;
    std::vector<std::string> moduleNames;
    std::vector<std::string> filePaths;
};

struct InstallCloneAppCallbackInfo : public BaseCallbackInfo {
    explicit InstallCloneAppCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    int32_t userId = 0;
    int32_t appIndex = 0;
};

napi_value GetBundleInstaller(napi_env env, napi_callback_info info);
napi_value GetBundleInstallerSync(napi_env env, napi_callback_info info);
napi_value Install(napi_env env, napi_callback_info info);
napi_value Recover(napi_env env, napi_callback_info info);
napi_value Uninstall(napi_env env, napi_callback_info info);
napi_value BundleInstallerConstructor(napi_env env, napi_callback_info info);
napi_value UpdateBundleForSelf(napi_env env, napi_callback_info info);
napi_value AddExtResource(napi_env env, napi_callback_info info);
napi_value RemoveExtResource(napi_env env, napi_callback_info info);
napi_value UninstallAndRecover(napi_env env, napi_callback_info info);
napi_value InstallCloneApp(napi_env env, napi_callback_info info);
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMGR_SERVICES_KITS_INCLUDE_INSTALLER_H