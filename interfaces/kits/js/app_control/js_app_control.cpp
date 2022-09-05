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
#include "js_app_control.h"

#include <string>

#include "app_log_wrapper.h"
#include "app_control_interface.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "napi_arg.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;

namespace {
constexpr int32_t NO_ERROR = 0;
constexpr int32_t PARAM_TYPE_ERROR = 401;
constexpr int32_t SYSTEM_ABILITY_ERROR = 600101;

constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;

constexpr size_t ARGS_POS_ZERO = 0;
constexpr size_t ARGS_POS_ONE = 1;
constexpr size_t ARGS_POS_TWO = 2;

constexpr int32_t NAPI_RETURN_ONE = 1;
}

static OHOS::sptr<OHOS::AppExecFwk::IAppControlMgr> GetAppControlProxy()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("systemAbilityManager is null.");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        APP_LOGE("bundleMgrSa is null.");
        return nullptr;
    }
    auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
    if (bundleMgr == nullptr) {
        APP_LOGE("iface_cast failed.");
        return nullptr;
    }
    auto appControlProxy = bundleMgr->GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("GetAppControlProxy failed.");
        return nullptr;
    }
    return appControlProxy;
}

static napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static ErrCode InnerGetDisposedStatus(napi_env, const std::string& appId, Want& disposedWant)
{
    auto AppControlProxy = GetAppControlProxy();
    if (AppControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        return SYSTEM_ABILITY_ERROR;
    }
    return AppControlProxy->GetDisposedStatus(appId, disposedWant);
}

static ErrCode InnerSetDisposedStatus(napi_env, const std::string& appId, Want& disposedWant)
{
    auto AppControlProxy = GetAppControlProxy();
    if (AppControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        return SYSTEM_ABILITY_ERROR;
    }
    return AppControlProxy->SetDisposedStatus(appId, disposedWant);
}

static ErrCode InnerDeleteDisposedStatus(napi_env, const std::string& appId)
{
    auto AppControlProxy = GetAppControlProxy();
    if (AppControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        return SYSTEM_ABILITY_ERROR;
    }
    return AppControlProxy->DeleteDisposedStatus(appId);
}

void SetDisposedStatusExec(napi_env env, void *data)
{
    DisposedStatus *asyncCallbackInfo = static_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerSetDisposedStatus(env, asyncCallbackInfo->appId,
            asyncCallbackInfo->want);
    }
    return;
}

void SetDisposedStatusComplete(napi_env env, napi_status status, void *data)
{
    DisposedStatus *asyncCallbackInfo = static_cast<DisposedStatus *>(data);
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("SetDisposedStatus err = %{public}d", asyncCallbackInfo->err);
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->err),
            &result[0]));
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err != NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[0]));
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[0]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[0]), result, &placeHolder));
    }
}

napi_value SetDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to SetDisposedStatus");
    NapiArg args(env, info);
    DisposedStatus *asyncCallbackInfo = new (std::nothrow) DisposedStatus(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return WrapVoidToJS(env);
    }
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Napi func init failed");
        asyncCallbackInfo->err = PARAM_TYPE_ERROR;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->appId);
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_object)) {
            CommonFunc::ParseElementName(env, args[i], asyncCallbackInfo->want);
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            APP_LOGE("SetDisposedStatus arg err! pos:%{public}u, type:%{public}d", i, valueType);
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
        }
    }
    if (asyncCallbackInfo->err == PARAM_TYPE_ERROR) {
        napi_throw_type_error(env, std::to_string(PARAM_TYPE_ERROR).c_str(), "param type error!");
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DisposedStatus>(
        env, asyncCallbackInfo, "SetDisposedStatus", SetDisposedStatusExec, SetDisposedStatusComplete);
    callbackPtr.release();
    APP_LOGI("call SetDisposedStatus done.");
    return promise;
}

void DeleteDisposedStatusExec(napi_env env, void *data)
{
    DisposedStatus *asyncCallbackInfo = static_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerDeleteDisposedStatus(env, asyncCallbackInfo->appId);
    }
}

void DeleteDisposedStatusComplete(napi_env env, napi_status, void *data)
{
    DisposedStatus *asyncCallbackInfo = static_cast<DisposedStatus *>(data);
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("DeleteDisposedStatus err = %{public}d", asyncCallbackInfo->err);
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->err),
            &result[0]));
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[0]));
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[0]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[0]), result, &placeHolder));
    }
}

napi_value DeleteDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to DeleteDisposedStatus.");
    NapiArg args(env, info);
    DisposedStatus *asyncCallbackInfo = new (std::nothrow) DisposedStatus(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return WrapVoidToJS(env);
    }
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        asyncCallbackInfo->err = PARAM_TYPE_ERROR;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->appId);
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            APP_LOGE("DeleteDisposedStatus arg err! pos:%{public}u, type:%{public}d", i, valueType);
        }
    }
    if (asyncCallbackInfo->err == PARAM_TYPE_ERROR) {
        napi_throw_type_error(env, std::to_string(PARAM_TYPE_ERROR).c_str(), "param type error!");
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DisposedStatus>(
        env, asyncCallbackInfo, "DeleteDisposedStatus", DeleteDisposedStatusExec, DeleteDisposedStatusComplete);
    callbackPtr.release();
    APP_LOGI("call DeleteDisposedStatus done.");
    return promise;
}

void GetDisposedStatusExec(napi_env env, void *data)
{
    DisposedStatus *asyncCallbackInfo = static_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerGetDisposedStatus(env, asyncCallbackInfo->appId,
            asyncCallbackInfo->want);
    }
}

void GetDisposedStatusComplete(napi_env env, napi_status status, void *data)
{
    DisposedStatus *asyncCallbackInfo = static_cast<DisposedStatus *>(data);
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err != NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->err),
            &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, "failed to get disposed data",
            NAPI_AUTO_LENGTH, &result[1]));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        CommonFunc::ConvertWantInfo(env, result[1], asyncCallbackInfo->want);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[0]), result, &placeHolder));
    }
}

napi_value GetDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetDisposedStatus called");
    NapiArg args(env, info);
    DisposedStatus *asyncCallbackInfo = new (std::nothrow) DisposedStatus(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return WrapVoidToJS(env);
    }
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        asyncCallbackInfo->err = PARAM_TYPE_ERROR;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < args.GetArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->appId);
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            APP_LOGE("GetDisposedStatus arg err! pos:%{public}u, type:%{public}d", i, valueType);
        }
    }
    if (asyncCallbackInfo->err == PARAM_TYPE_ERROR) {
        napi_throw_type_error(env, std::to_string(PARAM_TYPE_ERROR).c_str(), "param type error!");
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DisposedStatus>(
        env, asyncCallbackInfo, "GetDisposedStatus", GetDisposedStatusExec, GetDisposedStatusComplete);
    callbackPtr.release();
    APP_LOGI("call GetDisposedStatus done.");
    return promise;
}
}
}