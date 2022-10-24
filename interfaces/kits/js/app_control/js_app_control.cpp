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
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
namespace {
const std::string PARAM_TYPE_CHECK_ERROR = "param type check error";
const std::string TYPE_WANT = "want";
const std::string PERMISSION_DISPOSED_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
const std::string SET_DISPOSED_STATUS = "SetDisposedStatus";
const std::string GET_DISPOSED_STATUS = "GetDisposedStatus";
const std::string DELETE_DISPOSED_STATUS = "DeleteDisposedStatus";
const std::string APP_ID = "appId";
const std::string DISPOSED_WANT = "disposedWant";
}
static OHOS::sptr<OHOS::AppExecFwk::IAppControlMgr> GetAppControlProxy()
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed.");
        return nullptr;
    }
    auto appControlProxy = bundleMgr->GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("GetAppControlProxy failed.");
        return nullptr;
    }
    return appControlProxy;
}

static ErrCode InnerGetDisposedStatus(napi_env, const std::string& appId, Want& disposedWant)
{
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    ErrCode ret = appControlProxy->GetDisposedStatus(appId, disposedWant);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerSetDisposedStatus(napi_env, const std::string& appId, Want& disposedWant)
{
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    ErrCode ret = appControlProxy->SetDisposedStatus(appId, disposedWant);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerDeleteDisposedStatus(napi_env, const std::string& appId)
{
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    ErrCode ret = appControlProxy->DeleteDisposedStatus(appId);
    return CommonFunc::ConvertErrCode(ret);
}

void SetDisposedStatusExec(napi_env env, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerSetDisposedStatus(env, asyncCallbackInfo->appId,
            asyncCallbackInfo->want);
    }
}

void SetDisposedStatusComplete(napi_env env, napi_status status, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("SetDisposedStatus err = %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, SET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
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
    APP_LOGD("begin to SetDisposedStatus");
    NapiArg args(env, info);
    DisposedStatus *asyncCallbackInfo = new (std::nothrow) DisposedStatus(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->appId)) {
                APP_LOGE("appId invalid!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
                return nullptr;
            }
            asyncCallbackInfo->err = asyncCallbackInfo->appId.size() == 0 ? ERROR_INVALID_APPID : NO_ERROR;
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseWantWithoutVerification(env, args[i], asyncCallbackInfo->want)) {
                APP_LOGE("disposed want invalid!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, DISPOSED_WANT, TYPE_WANT);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("SetDisposedStatus extra arg ignored");
            }
        } else {
            APP_LOGE("SetDisposedStatus arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DisposedStatus>(
        env, asyncCallbackInfo, "SetDisposedStatus", SetDisposedStatusExec, SetDisposedStatusComplete);
    callbackPtr.release();
    APP_LOGD("call SetDisposedStatus done.");
    return promise;
}

void DeleteDisposedStatusExec(napi_env env, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerDeleteDisposedStatus(env, asyncCallbackInfo->appId);
    }
}

void DeleteDisposedStatusComplete(napi_env env, napi_status, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("DeleteDisposedStatus err = %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, DELETE_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
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
    APP_LOGD("begin to DeleteDisposedStatus.");
    NapiArg args(env, info);
    DisposedStatus *asyncCallbackInfo = new (std::nothrow) DisposedStatus(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->appId)) {
                APP_LOGE("appId invalid!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
                return nullptr;
            }
            if (asyncCallbackInfo->appId.size() == 0) {
                asyncCallbackInfo->err = ERROR_INVALID_APPID;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("DeleteDisposedStatus extra arg ignored");
            }
        } else {
            APP_LOGE("DeleteDisposedStatus arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DisposedStatus>(
        env, asyncCallbackInfo, "DeleteDisposedStatus", DeleteDisposedStatusExec, DeleteDisposedStatusComplete);
    callbackPtr.release();
    APP_LOGD("call DeleteDisposedStatus done.");
    return promise;
}

void GetDisposedStatusExec(napi_env env, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerGetDisposedStatus(env, asyncCallbackInfo->appId,
            asyncCallbackInfo->want);
    }
}

void GetDisposedStatusComplete(napi_env env, napi_status status, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        CommonFunc::ConvertWantInfo(env, result[1], asyncCallbackInfo->want);
    } else {
        APP_LOGE("GetDisposedStatus err = %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, GET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
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
        return nullptr;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->appId)) {
                APP_LOGE("appId %{public}s invalid!", asyncCallbackInfo->appId.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
                return nullptr;
            }
            if (asyncCallbackInfo->appId.size() == 0) {
                asyncCallbackInfo->err = ERROR_INVALID_APPID;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("GetDisposedStatus extra arg ignored");
            }
        } else {
            APP_LOGE("GetDisposedStatus arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DisposedStatus>(
        env, asyncCallbackInfo, "GetDisposedStatus", GetDisposedStatusExec, GetDisposedStatusComplete);
    callbackPtr.release();
    APP_LOGD("call GetDisposedStatus done.");
    return promise;
}
}
}