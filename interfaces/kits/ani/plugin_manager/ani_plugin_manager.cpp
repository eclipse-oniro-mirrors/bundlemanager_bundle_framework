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

#include <ani_signature_builder.h>

#include <array>
#include <string>
#include <vector>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_death_recipient.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "installer_callback.h"
#include "installer_helper.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_PLUGIN_BUNDLE_MANAGER = "@ohos.bundle.pluginBundleManager.pluginBundleManager";
}

static void ExecuteInstallLocalPlugin(const std::vector<std::string>& pluginFilePaths, InstallResult& installResult)
{
    if (pluginFilePaths.empty()) {
        installResult.resultCode = ERR_APPEXECFWK_PLUGIN_INSTALL_FILEPATH_INVALID;
        return;
    }

    sptr<IBundleMgr> iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr || iBundleMgr->AsObject() == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        installResult.resultCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        return;
    }
    sptr<ILocalPluginInstaller> localPluginInstaller = iBundleMgr->GetLocalPluginInstaller();
    if (localPluginInstaller == nullptr || localPluginInstaller->AsObject() == nullptr) {
        APP_LOGE("can not get localPluginInstaller");
        installResult.resultCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        return;
    }
    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    if (callback == nullptr || recipient == nullptr) {
        APP_LOGE("callback or death recipient is nullptr");
        installResult.resultCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        return;
    }
    localPluginInstaller->AsObject()->AddDeathRecipient(recipient);

    ErrCode res = localPluginInstaller->Install(pluginFilePaths, callback);
    if (res != ERR_OK) {
        APP_LOGE("InstallLocalPlugin failed due to %{public}d", res);
        installResult.resultCode = res;
        return;
    }

    installResult.resultCode = callback->GetInnerCode();
}

static void AniInstallLocalPlugin(ani_env* env, ani_object aniPluginFilePaths)
{
    APP_LOGD("ani InstallLocalPlugin called");
    std::vector<std::string> pluginFilePaths;
    if (aniPluginFilePaths == nullptr || !CommonFunAni::ParseStrArray(env, aniPluginFilePaths, pluginFilePaths)) {
        APP_LOGE("pluginFilePaths parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, FILE_PATH, TYPE_ARRAY);
        return;
    }

    InstallResult installResult;
    ExecuteInstallLocalPlugin(pluginFilePaths, installResult);
    ErrCode result = CommonFunc::ConvertErrCode(installResult.resultCode);
    if (result != SUCCESS) {
        BusinessErrorAni::ThrowCommonError(env, result,
            RESOURCE_NAME_OF_INSTALL_LOCAL_PLUGIN, PERMISSION_SUPPORT_LOCAL_PLUGIN);
    }
}

static void ExecuteUninstallLocalPlugin(const std::string& pluginBundleName, InstallResult& installResult)
{
    if (pluginBundleName.empty()) {
        installResult.resultCode = ERR_APPEXECFWK_PLUGIN_NOT_FOUND;
        return;
    }

    sptr<IBundleMgr> iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr || iBundleMgr->AsObject() == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        installResult.resultCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        return;
    }
    sptr<ILocalPluginInstaller> localPluginInstaller = iBundleMgr->GetLocalPluginInstaller();
    if (localPluginInstaller == nullptr || localPluginInstaller->AsObject() == nullptr) {
        APP_LOGE("can not get localPluginInstaller");
        installResult.resultCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        return;
    }
    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    if (callback == nullptr || recipient == nullptr) {
        APP_LOGE("callback or death recipient is nullptr");
        installResult.resultCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        return;
    }
    localPluginInstaller->AsObject()->AddDeathRecipient(recipient);

    ErrCode res = localPluginInstaller->Uninstall(pluginBundleName, callback);
    if (res != ERR_OK) {
        APP_LOGE("UninstallLocalPlugin failed due to %{public}d", res);
        installResult.resultCode = res;
        return;
    }

    installResult.resultCode = callback->GetInnerCode();
}

static void AniUninstallLocalPlugin(ani_env* env, ani_string aniPluginBundleName)
{
    APP_LOGD("ani UninstallLocalPlugin called");
    std::string pluginBundleName;
    if (aniPluginBundleName == nullptr || !CommonFunAni::ParseString(env, aniPluginBundleName, pluginBundleName)) {
        APP_LOGE("pluginBundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PLUGIN_BUNDLE_NAME, TYPE_STRING);
        return;
    }

    InstallResult installResult;
    ExecuteUninstallLocalPlugin(pluginBundleName, installResult);
    ErrCode result = CommonFunc::ConvertErrCode(installResult.resultCode);
    if (result != SUCCESS) {
        BusinessErrorAni::ThrowCommonError(env, result,
            RESOURCE_NAME_OF_UNINSTALL_LOCAL_PLUGIN, PERMISSION_SUPPORT_LOCAL_PLUGIN);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("plugin_manager ANI_Constructor called");
    ani_env* env = nullptr;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace ns = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_PLUGIN_BUNDLE_MANAGER);
    ani_namespace kitNs = nullptr;
    res = env->FindNamespace(ns.Descriptor().c_str(), &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Not found namespace of @ohos.bundle.pluginBundleManager.pluginBundleManager");

    std::array methods = {
        ani_native_function { "installLocalPluginNative", nullptr, reinterpret_cast<void*>(AniInstallLocalPlugin) },
        ani_native_function { "uninstallLocalPluginNative", nullptr,
            reinterpret_cast<void*>(AniUninstallLocalPlugin) },
    };
    res = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods");

    *result = ANI_VERSION_1;
    APP_LOGI("plugin_manager ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AppExecFwk
} // namespace OHOS
