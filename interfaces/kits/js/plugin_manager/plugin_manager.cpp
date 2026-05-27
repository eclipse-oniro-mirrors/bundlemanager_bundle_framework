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
#include "business_error.h"
#include "common_func.h"
#include "installer_helper.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {

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
    LocalPluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<LocalPluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetAllLocalPluginInfoForSelf(asyncCallbackInfo->pluginBundleInfos);
}

void GetAllLocalPluginInfoForSelfComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGI("GetAllLocalPluginInfoForSelfComplete begin");
    LocalPluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<LocalPluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<LocalPluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        ProcessPluginInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->pluginBundleInfos);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_LOCAL_PLUGIN_INFO_FOR_SELF, ServiceConstants::PERMISSION_SUPPORT_LOCAL_PLUGIN);
    }
    CommonFunc::NapiReturnDeferred<LocalPluginCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllLocalPluginInfoForSelf(napi_env env, napi_callback_info info)
{
    APP_LOGI("napi GetAllLocalPluginInfoForSelf begin");
    NapiArg args(env, info);
    LocalPluginCallbackInfo *asyncCallbackInfo = new (std::nothrow) LocalPluginCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<LocalPluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ZERO, ARGS_SIZE_ZERO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<LocalPluginCallbackInfo>(env, asyncCallbackInfo,
        GET_ALL_LOCAL_PLUGIN_INFO_FOR_SELF, GetAllLocalPluginInfoForSelfExec, GetAllLocalPluginInfoForSelfComplete);
    callbackPtr.release();
    APP_LOGI_NOFUNC("napi GetAllLocalPluginInfoForSelf end");
    return promise;
}
} // namespace AppExecFwk
} // namespace OHOS
