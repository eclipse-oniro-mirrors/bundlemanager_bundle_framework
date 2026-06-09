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

#include "plugin_manager.h"

#include <memory>
#include <string>
#include <vector>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_death_recipient.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "common_func.h"
#include "installer_callback.h"
#include "installer_helper.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {

void InstallLocalPluginExec(napi_env env, void *data)
{
    InstallLocalPluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<InstallLocalPluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    InstallResult &installResult = asyncCallbackInfo->installResult;
    if (asyncCallbackInfo->pluginFilePaths.empty()) {
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

    ErrCode res = localPluginInstaller->Install(asyncCallbackInfo->pluginFilePaths, callback);
    if (res != ERR_OK) {
        APP_LOGE("InstallLocalPlugin failed due to %{public}d", res);
        installResult.resultCode = res;
        return;
    }

    installResult.resultCode = callback->GetInnerCode();
}

void InstallLocalPluginComplete(napi_env env, napi_status status, void *data)
{
    InstallLocalPluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<InstallLocalPluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<InstallLocalPluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_ONE] = {0};
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->installResult.resultCode);
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env,
            asyncCallbackInfo->err, RESOURCE_NAME_OF_INSTALL_LOCAL_PLUGIN, PERMISSION_SUPPORT_LOCAL_PLUGIN);
    }

    CommonFunc::NapiReturnDeferred<InstallLocalPluginCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value InstallLocalPlugin(napi_env env, napi_callback_info info)
{
    APP_LOGD("InstallLocalPlugin called");
    NapiArg args(env, info);
    InstallLocalPluginCallbackInfo *asyncCallbackInfo = new (std::nothrow) InstallLocalPluginCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<InstallLocalPluginCallbackInfo> callbackPtr {asyncCallbackInfo};

    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (!CommonFunc::ParseStringArray(env, asyncCallbackInfo->pluginFilePaths, args[ARGS_POS_ZERO])) {
        APP_LOGE("pluginFilePaths parse failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, FILE_PATH, TYPE_ARRAY);
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<InstallLocalPluginCallbackInfo>(env, asyncCallbackInfo,
        RESOURCE_NAME_OF_INSTALL_LOCAL_PLUGIN, InstallLocalPluginExec, InstallLocalPluginComplete);
    callbackPtr.release();
    APP_LOGD("InstallLocalPlugin done");
    return promise;
}

void UninstallLocalPluginExec(napi_env env, void *data)
{
    UninstallLocalPluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<UninstallLocalPluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->pluginBundleName.empty()) {
        asyncCallbackInfo->installResult.resultCode = ERR_APPEXECFWK_PLUGIN_NOT_FOUND;
        return;
    }

    sptr<IBundleMgr> iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr || iBundleMgr->AsObject() == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        asyncCallbackInfo->installResult.resultCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        return;
    }
    sptr<ILocalPluginInstaller> localPluginInstaller = iBundleMgr->GetLocalPluginInstaller();
    if (localPluginInstaller == nullptr || localPluginInstaller->AsObject() == nullptr) {
        APP_LOGE("can not get localPluginInstaller");
        asyncCallbackInfo->installResult.resultCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        return;
    }

    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    if (callback == nullptr || recipient == nullptr) {
        APP_LOGE("callback or death recipient is nullptr");
        asyncCallbackInfo->installResult.resultCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        return;
    }
    localPluginInstaller->AsObject()->AddDeathRecipient(recipient);

    ErrCode res = localPluginInstaller->Uninstall(asyncCallbackInfo->pluginBundleName, callback);
    if (res != ERR_OK) {
        APP_LOGE("UninstallLocalPlugin failed due to %{public}d", res);
        asyncCallbackInfo->installResult.resultCode = res;
        return;
    }

    asyncCallbackInfo->installResult.resultCode = callback->GetInnerCode();
}

void UninstallLocalPluginComplete(napi_env env, napi_status status, void *data)
{
    UninstallLocalPluginCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<UninstallLocalPluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<UninstallLocalPluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_ONE] = {0};
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->installResult.resultCode);
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env,
            asyncCallbackInfo->err, RESOURCE_NAME_OF_UNINSTALL_LOCAL_PLUGIN, PERMISSION_SUPPORT_LOCAL_PLUGIN);
    }

    CommonFunc::NapiReturnDeferred<UninstallLocalPluginCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value UninstallLocalPlugin(napi_env env, napi_callback_info info)
{
    APP_LOGD("UninstallLocalPlugin called");
    NapiArg args(env, info);
    UninstallLocalPluginCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) UninstallLocalPluginCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<UninstallLocalPluginCallbackInfo> callbackPtr {asyncCallbackInfo};

    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->pluginBundleName)) {
        APP_LOGE("pluginBundleName parse failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PLUGIN_BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<UninstallLocalPluginCallbackInfo>(env, asyncCallbackInfo,
        RESOURCE_NAME_OF_UNINSTALL_LOCAL_PLUGIN, UninstallLocalPluginExec, UninstallLocalPluginComplete);
    callbackPtr.release();
    APP_LOGD("UninstallLocalPlugin done");
    return promise;
}

static void ProcessPluginInfos(
    napi_env env, napi_value result, const std::vector<PluginBundleInfo> &pluginBundleInfos)
{
    if (pluginBundleInfos.empty()) {
        APP_LOGD("pluginBundleInfos is null");
        return;
    }
    size_t index = 0;
    for (const auto &item : pluginBundleInfos) {
        napi_value objPluginInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objPluginInfo));
        CommonFunc::ConvertPluginBundleInfo(env, item, objPluginInfo);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, objPluginInfo));
        index++;
    }
}

static ErrCode InnerGetAllLocalPluginInfoForSelf(std::vector<PluginBundleInfo>& pluginBundleInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAllLocalPluginInfoForSelf(pluginBundleInfos);
    APP_LOGD("GetAllLocalPluginInfoForSelf ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

void GetAllLocalPluginInfoForSelfExec(napi_env env, void *data)
{
    GetAllLocalPluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetAllLocalPluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetAllLocalPluginInfoForSelf(asyncCallbackInfo->pluginBundleInfos);
}

void GetAllLocalPluginInfoForSelfComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGI("GetAllLocalPluginInfoForSelfComplete begin");
    GetAllLocalPluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetAllLocalPluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetAllLocalPluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        ProcessPluginInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->pluginBundleInfos);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_LOCAL_PLUGIN_INFO_FOR_SELF, PERMISSION_SUPPORT_LOCAL_PLUGIN);
    }
    CommonFunc::NapiReturnDeferred<GetAllLocalPluginCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllLocalPluginInfoForSelf(napi_env env, napi_callback_info info)
{
    APP_LOGI("napi GetAllLocalPluginInfoForSelf begin");
    NapiArg args(env, info);
    GetAllLocalPluginCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetAllLocalPluginCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetAllLocalPluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ZERO, ARGS_SIZE_ZERO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetAllLocalPluginCallbackInfo>(env, asyncCallbackInfo,
        GET_ALL_LOCAL_PLUGIN_INFO_FOR_SELF, GetAllLocalPluginInfoForSelfExec, GetAllLocalPluginInfoForSelfComplete);
    callbackPtr.release();
    APP_LOGI_NOFUNC("napi GetAllLocalPluginInfoForSelf end");
    return promise;
}
} // namespace AppExecFwk
} // namespace OHOS
