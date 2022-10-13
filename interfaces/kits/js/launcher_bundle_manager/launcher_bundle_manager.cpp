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

#include "launcher_bundle_manager.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "js_launcher_service.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {

static OHOS::sptr<OHOS::AppExecFwk::LauncherService> GetLauncherService()
{
    return OHOS::AppExecFwk::JSLauncherService::GetLauncherService();
}

static ErrCode InnerGetLauncherAbilityInfo(const std::string &bundleName, int32_t userId,
    std::vector<OHOS::AppExecFwk::LauncherAbilityInfo>& launcherAbilityInfos)
{
    auto launcherService = GetLauncherService();
    if (launcherService == nullptr) {
        return ERROR_ENVORINMENT_INIT_FAILED;
    }
    return launcherService->GetLauncherAbilityByBundleName(bundleName, userId, launcherAbilityInfos);
}

void GetLauncherAbilityInfoExec(napi_env env, void *data)
{
    GetLauncherAbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetLauncherAbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetLauncherAbilityInfo(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->userId, asyncCallbackInfo->launcherAbilityInfos);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void GetLauncherAbilityInfoComplete(napi_env env, napi_status status, void *data)
{
    GetLauncherAbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetLauncherAbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<GetLauncherAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertLauncherAbilityInfos(env, asyncCallbackInfo->launcherAbilityInfos, result[ARGS_POS_ONE]);
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
        napi_get_undefined(env, &result[ARGS_POS_ONE]);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == SUCCESS) {
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

napi_value GetLauncherAbilityInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to GetLauncherAbilityInfo");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetLauncherAbilityCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetLauncherAbilityCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<GetLauncherAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)
                || asyncCallbackInfo->bundleName.empty()) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId);
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetLauncherAbilityCallbackInfo>(
        env, asyncCallbackInfo, "GetLauncherAbilityInfo", GetLauncherAbilityInfoExec, GetLauncherAbilityInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetLauncherAbilityInfo done");
    return promise;
}

static ErrCode InnerGetAllLauncherAbilityInfo(int32_t userId,
    std::vector<OHOS::AppExecFwk::LauncherAbilityInfo>& launcherAbilityInfos)
{
    auto launcherService = GetLauncherService();
    if (launcherService == nullptr) {
        return ERROR_ENVORINMENT_INIT_FAILED;
    }
    return launcherService->GetAllLauncherAbility(userId, launcherAbilityInfos);
}

void GetAllLauncherAbilityInfoExec(napi_env env, void *data)
{
    GetAllLauncherAbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetAllLauncherAbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetAllLauncherAbilityInfo(asyncCallbackInfo->userId,
        asyncCallbackInfo->launcherAbilityInfos);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void GetAllLauncherAbilityInfoComplete(napi_env env, napi_status status, void *data)
{
    GetAllLauncherAbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetAllLauncherAbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<GetAllLauncherAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertLauncherAbilityInfos(env, asyncCallbackInfo->launcherAbilityInfos, result[ARGS_POS_ONE]);
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
        napi_get_undefined(env, &result[ARGS_POS_ONE]);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == SUCCESS) {
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

napi_value GetAllLauncherAbilityInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to GetAllLauncherAbilityInfo");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetAllLauncherAbilityCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetAllLauncherAbilityCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<GetAllLauncherAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId);
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetAllLauncherAbilityCallbackInfo>(
        env, asyncCallbackInfo, "GetLauncherAbilityInfo",
        GetAllLauncherAbilityInfoExec, GetAllLauncherAbilityInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetAllLauncherAbilityInfo done");
    return promise;
}

static ErrCode InnerGetShortcutInfo(std::string &bundleName, std::vector<OHOS::AppExecFwk::ShortcutInfo> &shortcutInfos)
{
    auto launcherService = GetLauncherService();
    if (launcherService == nullptr) {
        return ERROR_ENVORINMENT_INIT_FAILED;
    }
    return launcherService->GetShortcutInfoV9(bundleName, shortcutInfos);
}

void GetShortcutInfoExec(napi_env env, void *data)
{
    GetShortcutInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetShortcutInfo(asyncCallbackInfo->bundleName, asyncCallbackInfo->shortcutInfos);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void GetShortcutInfoComplete(napi_env env, napi_status status, void *data)
{
    GetShortcutInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<GetShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertShortCutInfos(env, asyncCallbackInfo->shortcutInfos, result[ARGS_POS_ONE]);
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
        napi_get_undefined(env, &result[ARGS_POS_ONE]);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == SUCCESS) {
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

napi_value GetShortcutInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin GetShortcutInfo");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetShortcutInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetShortcutInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<GetShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)
                || asyncCallbackInfo->bundleName.empty()) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_function)) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetShortcutInfoCallbackInfo>(
        env, asyncCallbackInfo, "GetShortcutInfo", GetShortcutInfoExec, GetShortcutInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetShortcutInfo done");
    return promise;
}
}
}