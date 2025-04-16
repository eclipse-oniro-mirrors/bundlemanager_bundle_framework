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
#include "js_app_overlay.h"

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
const std::string MODULE_NAME = "moduleName";
const std::string BUNDLE_NAME = "bundleName";
const std::string TARGET_MODULE_NAME = "targetModuleName";
const std::string TARGET_BUNDLE_NAME = "targetBundleName";
const std::string IS_ENABLED = "isEnabled";
const std::string SET_OVERLAY_ENABLED = "SetOverlayEnabled";
const std::string SET_OVERLAY_ENABLED_BY_BUNDLE_NAME = "SetOverlayEnabledByBundleName";
const std::string GET_OVERLAY_MODULE_INFO = "GetOverlayModuleInfo";
const std::string GET_TARGET_OVERLAY_MODULE_INFOS = "GetTargetOverlayModuleInfos";
const std::string GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME = "GetOverlayModuleInfoByBundleName";
const std::string GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME = "GetTargetOverlayModuleInfosByBundleName";
} // namespace

static OHOS::sptr<OHOS::AppExecFwk::IOverlayManager> GetOverlayMgrProxy()
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return nullptr;
    }
    auto overlayMgrProxy = bundleMgr->GetOverlayManagerProxy();
    if (overlayMgrProxy == nullptr) {
        APP_LOGE("GetOverlayManagerProxy failed");
        return nullptr;
    }
    return overlayMgrProxy;
}


static ErrCode InnerSetOverlayEnabledExec(napi_env, OverlayCallbackInfo *callback)
{
    auto overlayMgrProxy = GetOverlayMgrProxy();
    if (overlayMgrProxy == nullptr) {
        APP_LOGE("overlayMgrProxy is null");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    ErrCode ret = ERR_OK;
    if (callback->option == OverlayOption::OPTION_SET_OVERLAY_ENABLED_BY_BUNDLE) {
        ret = overlayMgrProxy->SetOverlayEnabled(callback->bundleName, callback->moduleName, callback->isEnabled);
    } else {
        ret = overlayMgrProxy->SetOverlayEnabledForSelf(callback->moduleName, callback->isEnabled);
    }
    return CommonFunc::ConvertErrCode(ret);
}

void SetOverlayEnabledExec(napi_env env, void *data)
{
    OverlayCallbackInfo *overlayCallbackInfo = reinterpret_cast<OverlayCallbackInfo *>(data);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return;
    }
    if (overlayCallbackInfo->err == NO_ERROR) {
        overlayCallbackInfo->err = InnerSetOverlayEnabledExec(env, overlayCallbackInfo);
    }
}

void SetOverlayEnabledComplete(napi_env env, napi_status status, void *data)
{
    OverlayCallbackInfo *overlayCallbackInfo = reinterpret_cast<OverlayCallbackInfo *>(data);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return;
    }
    std::unique_ptr<OverlayCallbackInfo> callbackPtr {overlayCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (overlayCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("SetOverlayEnabledComplete err = %{public}d", overlayCallbackInfo->err);
        result[0] = BusinessError::CreateCommonError(env, overlayCallbackInfo->err,
            SET_OVERLAY_ENABLED_BY_BUNDLE_NAME, Constants::PERMISSION_CHANGE_OVERLAY_ENABLED_STATE);
    }
    CommonFunc::NapiReturnDeferred<OverlayCallbackInfo>(env, overlayCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value SetOverlayEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI SetOverlayEnabled called");
    NapiArg args(env, info);
    OverlayCallbackInfo *overlayCallbackInfo = new (std::nothrow) OverlayCallbackInfo(env);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<OverlayCallbackInfo> callbackPtr {overlayCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], overlayCallbackInfo->moduleName) ||
                overlayCallbackInfo->moduleName.empty()) {
                APP_LOGE("moduleName %{public}s invalid", overlayCallbackInfo->moduleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseBool(env, args[ARGS_POS_ONE], overlayCallbackInfo->isEnabled)) {
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLED, TYPE_BOOLEAN);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &overlayCallbackInfo->callback));
            } else {
                APP_LOGD("SetOverlayEnabled extra arg ignored");
            }
        } else {
            APP_LOGE("SetOverlayEnabled arg err");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }

    overlayCallbackInfo->option = OverlayOption::OPTION_SET_OVERLAY_ENABLED;
    auto promise = CommonFunc::AsyncCallNativeMethod<OverlayCallbackInfo>(
        env, overlayCallbackInfo, SET_OVERLAY_ENABLED, SetOverlayEnabledExec, SetOverlayEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call SetOverlayEnabled done");
    return promise;
}

napi_value SetOverlayEnabledByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI SetOverlayEnabledByBundleName called");
    NapiArg args(env, info);
    OverlayCallbackInfo *overlayCallbackInfo = new (std::nothrow) OverlayCallbackInfo(env);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<OverlayCallbackInfo> callbackPtr {overlayCallbackInfo};
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], overlayCallbackInfo->bundleName) ||
                overlayCallbackInfo->bundleName.empty()) {
                APP_LOGE("bundleName %{public}s invalid", overlayCallbackInfo->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseString(env, args[i], overlayCallbackInfo->moduleName) ||
                overlayCallbackInfo->moduleName.empty()) {
                APP_LOGE("moduleName %{public}s invalid", overlayCallbackInfo->moduleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (!CommonFunc::ParseBool(env, args[i], overlayCallbackInfo->isEnabled)) {
                APP_LOGE("isEnabled is %{public}d invalid", overlayCallbackInfo->isEnabled);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLED, TYPE_BOOLEAN);
                return nullptr;
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &overlayCallbackInfo->callback));
            } else {
                APP_LOGD("SetOverlayEnabledByBundleName extra arg ignored");
            }
        } else {
            APP_LOGE("SetOverlayEnabledByBundleName arg err");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }

    overlayCallbackInfo->option = OverlayOption::OPTION_SET_OVERLAY_ENABLED_BY_BUNDLE;
    auto promise = CommonFunc::AsyncCallNativeMethod<OverlayCallbackInfo>(
        env, overlayCallbackInfo, SET_OVERLAY_ENABLED_BY_BUNDLE_NAME, SetOverlayEnabledExec,
            SetOverlayEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call SetOverlayEnabledByBundleName done");
    return promise;
}

static ErrCode InnerGetOverlayModuleInfoExec(napi_env, OverlayCallbackInfo *overlayCbInfo)
{
    std::string bundleName = CommonFunc::ObtainCallingBundleName();
    if (bundleName.empty()) {
        APP_LOGE("obtain calling bundleName failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    auto overlayMgrProxy = GetOverlayMgrProxy();
    if (overlayMgrProxy == nullptr) {
        APP_LOGE("overlayMgrProxy is null");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }

    ErrCode ret = ERR_OK;
    if (overlayCbInfo->option == OverlayOption::OPTION_GET_OVERLAY_MODULE_INFO) {
        ret = overlayMgrProxy->GetOverlayModuleInfo(overlayCbInfo->moduleName,
            overlayCbInfo->overlayModuleInfo);
    } else if (overlayCbInfo->option == OverlayOption::OPTION_GET_OVERLAY_TARGET_MODULE_INFO) {
        ret = overlayMgrProxy->GetTargetOverlayModuleInfo(overlayCbInfo->targetModuleName,
            overlayCbInfo->infoVec);
    } else if (overlayCbInfo->option == OverlayOption::OPTION_GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME) {
        ret = overlayMgrProxy->GetOverlayModuleInfoByBundleName(overlayCbInfo->bundleName, overlayCbInfo->moduleName,
            overlayCbInfo->infoVec);
    } else if (overlayCbInfo->option == OverlayOption::OPTION_GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME) {
        ret = overlayMgrProxy->GetOverlayModuleInfoForTarget(overlayCbInfo->targetBundleName,
            overlayCbInfo->moduleName, overlayCbInfo->infoVec);
    } else {
        APP_LOGE("invalid overlay option");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    return CommonFunc::ConvertErrCode(ret);
}

void GetOverlayModuleInfoExec(napi_env env, void *data)
{
    OverlayCallbackInfo *overlayCbInfo = reinterpret_cast<OverlayCallbackInfo *>(data);
    if (overlayCbInfo == nullptr) {
        APP_LOGE("overlayCbInfo is null");
        return;
    }
    if (overlayCbInfo->err == NO_ERROR) {
        overlayCbInfo->err = InnerGetOverlayModuleInfoExec(env, overlayCbInfo);
        return;
    }
}

void GetOverlayModuleInfoComplete(napi_env env, napi_status status, void *data)
{
    OverlayCallbackInfo *overlayCallbackInfo = reinterpret_cast<OverlayCallbackInfo *>(data);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return;
    }
    std::unique_ptr<OverlayCallbackInfo> callbackPtr {overlayCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (overlayCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        if (overlayCallbackInfo->option == OverlayOption::OPTION_GET_OVERLAY_MODULE_INFO) {
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
            CommonFunc::ConvertOverlayModuleInfo(env, overlayCallbackInfo->overlayModuleInfo, result[ARGS_POS_ONE]);
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
            CommonFunc::ConvertOverlayModuleInfos(env, overlayCallbackInfo->infoVec, result[ARGS_POS_ONE]);
        }
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, overlayCallbackInfo->err,
            GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<OverlayCallbackInfo>(env, overlayCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetOverlayModuleInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetOverlayModuleInfo called");
    NapiArg args(env, info);
    OverlayCallbackInfo *overlayCallbackInfo = new (std::nothrow) OverlayCallbackInfo(env);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return nullptr;
    }
    overlayCallbackInfo->option = OverlayOption::OPTION_GET_OVERLAY_MODULE_INFO;
    std::unique_ptr<OverlayCallbackInfo> callbackPtr {overlayCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], overlayCallbackInfo->moduleName) ||
                overlayCallbackInfo->moduleName.empty()) {
                APP_LOGE("moduleName %{public}s invalid", overlayCallbackInfo->moduleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &overlayCallbackInfo->callback));
            } else {
                APP_LOGD("GetOverlayModuleInfo extra arg ignored");
            }
        } else {
            APP_LOGE("GetOverlayModuleInfo arg err");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<OverlayCallbackInfo>(
        env, overlayCallbackInfo, GET_OVERLAY_MODULE_INFO, GetOverlayModuleInfoExec, GetOverlayModuleInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetOverlayModuleInfo done");
    return promise;
}

void GetTargetOverlayModuleInfosComplete(napi_env env, napi_status status, void *data)
{
    OverlayCallbackInfo *overlayCallbackInfo = reinterpret_cast<OverlayCallbackInfo *>(data);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return;
    }
    std::unique_ptr<OverlayCallbackInfo> callbackPtr {overlayCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (overlayCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertOverlayModuleInfos(env, overlayCallbackInfo->infoVec, result[ARGS_POS_ONE]);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, overlayCallbackInfo->err,
            GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<OverlayCallbackInfo>(env, overlayCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetTargetOverlayModuleInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetTargetOverlayModuleInfos called");
    NapiArg args(env, info);
    OverlayCallbackInfo *overlayCallbackInfo = new (std::nothrow) OverlayCallbackInfo(env);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return nullptr;
    }
    overlayCallbackInfo->option = OverlayOption::OPTION_GET_OVERLAY_TARGET_MODULE_INFO;
    std::unique_ptr<OverlayCallbackInfo> callbackPtr {overlayCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], overlayCallbackInfo->targetModuleName) ||
                overlayCallbackInfo->targetModuleName.empty()) {
                APP_LOGE("targetModuleName %{public}s invalid", overlayCallbackInfo->targetModuleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, TARGET_MODULE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &overlayCallbackInfo->callback));
            } else {
                APP_LOGD("GetTargetOverlayModuleInfos extra arg ignored");
            }
        } else {
            APP_LOGE("GetTargetOverlayModuleInfos arg err");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<OverlayCallbackInfo>(
        env, overlayCallbackInfo, GET_TARGET_OVERLAY_MODULE_INFOS, GetOverlayModuleInfoExec,
        GetTargetOverlayModuleInfosComplete);
    callbackPtr.release();
    APP_LOGD("call GetTargetOverlayModuleInfos done");
    return promise;
}

napi_value GetOverlayModuleInfoByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetOverlayModuleInfoByBundleName called");
    NapiArg args(env, info);
    OverlayCallbackInfo *overlayCallbackInfo = new (std::nothrow) OverlayCallbackInfo(env);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return nullptr;
    }
    overlayCallbackInfo->option = OverlayOption::OPTION_GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME;
    std::unique_ptr<OverlayCallbackInfo> callbackPtr {overlayCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], overlayCallbackInfo->bundleName) ||
                overlayCallbackInfo->bundleName.empty()) {
                APP_LOGE("bundleName %{public}s invalid", overlayCallbackInfo->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &overlayCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseString(env, args[i], overlayCallbackInfo->moduleName)) {
                APP_LOGW("Parse moduleName error, default query for all module OverlayModuleInfo");
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &overlayCallbackInfo->callback));
                break;
            }
        } else {
            APP_LOGE("GetOverlayModuleInfoByBundleName arg err");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<OverlayCallbackInfo>(
        env, overlayCallbackInfo, GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME, GetOverlayModuleInfoExec,
        GetOverlayModuleInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetOverlayModuleInfoByBundleName done");
    return promise;
}

napi_value GetTargetOverlayModuleInfosByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetTargetOverlayModuleInfosByBundleName called");
    NapiArg args(env, info);
    OverlayCallbackInfo *overlayCallbackInfo = new (std::nothrow) OverlayCallbackInfo(env);
    if (overlayCallbackInfo == nullptr) {
        APP_LOGE("overlayCallbackInfo is null");
        return nullptr;
    }
    overlayCallbackInfo->option = OverlayOption::OPTION_GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME;
    std::unique_ptr<OverlayCallbackInfo> callbackPtr {overlayCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], overlayCallbackInfo->targetBundleName) ||
                overlayCallbackInfo->targetBundleName.empty()) {
                APP_LOGE("targetBundleName %{public}s invalid", overlayCallbackInfo->targetBundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, TARGET_BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &overlayCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseString(env, args[i], overlayCallbackInfo->moduleName)) {
                APP_LOGW("Parse moduleName error, default query for all module OverlayModuleInfo");
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &overlayCallbackInfo->callback));
                break;
            }
        } else {
            APP_LOGE("GetTargetOverlayModuleInfosByBundleName arg err");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<OverlayCallbackInfo>(
        env, overlayCallbackInfo, GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME, GetOverlayModuleInfoExec,
        GetTargetOverlayModuleInfosComplete);
    callbackPtr.release();
    APP_LOGD("call GetTargetOverlayModuleInfosByBundleName done");
    return promise;
}
} // AppExecFwk
} // OHOS