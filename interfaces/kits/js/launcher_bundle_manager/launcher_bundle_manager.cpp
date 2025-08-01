/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "js_launcher_service.h"
#include "napi_arg.h"
#include "napi_common_start_options.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {

const std::map<int32_t, int32_t> START_SHORTCUT_RES_MAP = {
    {ERR_OK, ERR_OK},
    {ERR_PERMISSION_DENIED, ERR_BUNDLE_MANAGER_PERMISSION_DENIED},
    {ERR_NOT_SYSTEM_APP, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED}
};
}
static OHOS::sptr<OHOS::AppExecFwk::LauncherService> GetLauncherService()
{
    return OHOS::AppExecFwk::JSLauncherService::GetLauncherService();
}

static ErrCode InnerGetLauncherAbilityInfo(const std::string &bundleName, int32_t userId,
    std::vector<OHOS::AppExecFwk::LauncherAbilityInfo>& launcherAbilityInfos)
{
    auto launcherService = GetLauncherService();
    if (launcherService == nullptr) {
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
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
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetLauncherAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertLauncherAbilityInfos(env, asyncCallbackInfo->launcherAbilityInfos, result[ARGS_POS_ONE]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, GET_LAUNCHER_ABILITY_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_get_undefined(env, &result[ARGS_POS_ONE]);
    }
    CommonFunc::NapiReturnDeferred<GetLauncherAbilityCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetLauncherAbilityInfo(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi begin to GetLauncherAbilityInfo");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetLauncherAbilityCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetLauncherAbilityCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetLauncherAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], asyncCallbackInfo->userId)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_THREE) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_TWO], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_TWO],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        APP_LOGE("parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetLauncherAbilityCallbackInfo>(
        env, asyncCallbackInfo, "GetLauncherAbilityInfo", GetLauncherAbilityInfoExec, GetLauncherAbilityInfoComplete);
    callbackPtr.release();
    APP_LOGI_NOFUNC("call GetLauncherAbilityInfo done");
    return promise;
}

napi_value GetLauncherAbilityInfoSync(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi GetLauncherAbilityInfoSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], userId)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
        return nullptr;
    }
    auto launcherService = GetLauncherService();
    if (launcherService == nullptr) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_SERVICE_EXCEPTION, GET_LAUNCHER_ABILITY_INFO_SYNC,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    std::vector<OHOS::AppExecFwk::LauncherAbilityInfo> launcherAbilityInfos;
    ErrCode ret = CommonFunc::ConvertErrCode(launcherService->
        GetLauncherAbilityInfoSync(bundleName, userId, launcherAbilityInfos));
    if (ret != SUCCESS) {
        APP_LOGE("GetLauncherAbilityInfoSync failed, bundleName is %{public}s, userId is %{public}d",
            bundleName.c_str(), userId);
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_LAUNCHER_ABILITY_INFO_SYNC, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nLauncherAbilityInfos = nullptr;
    NAPI_CALL(env, napi_create_array(env, &nLauncherAbilityInfos));
    CommonFunc::ConvertLauncherAbilityInfos(env, launcherAbilityInfos, nLauncherAbilityInfos);
    APP_LOGI_NOFUNC("call GetLauncherAbilityInfoSync done");
    return nLauncherAbilityInfos;
}

static ErrCode InnerGetAllLauncherAbilityInfo(int32_t userId,
    std::vector<OHOS::AppExecFwk::LauncherAbilityInfo>& launcherAbilityInfos)
{
    auto launcherService = GetLauncherService();
    if (launcherService == nullptr) {
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
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
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetAllLauncherAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertLauncherAbilityInfos(env, asyncCallbackInfo->launcherAbilityInfos, result[ARGS_POS_ONE]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, GET_ALL_LAUNCHER_ABILITY_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_get_undefined(env, &result[ARGS_POS_ONE]);
    }
    CommonFunc::NapiReturnDeferred<GetAllLauncherAbilityCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllLauncherAbilityInfo(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi begin to GetAllLauncherAbilityInfo");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetAllLauncherAbilityCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetAllLauncherAbilityCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetAllLauncherAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetMaxArgc() >= ARGS_SIZE_ONE) {
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], asyncCallbackInfo->userId)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_TWO) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_ONE], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        APP_LOGE("parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetAllLauncherAbilityCallbackInfo>(
        env, asyncCallbackInfo, "GetLauncherAbilityInfo",
        GetAllLauncherAbilityInfoExec, GetAllLauncherAbilityInfoComplete);
    callbackPtr.release();
    APP_LOGI_NOFUNC("call GetAllLauncherAbilityInfo done");
    return promise;
}

static ErrCode InnerGetShortcutInfo(std::string &bundleName,
    std::vector<OHOS::AppExecFwk::ShortcutInfo> &shortcutInfos, int32_t userId)
{
    auto launcherService = GetLauncherService();
    if (launcherService == nullptr) {
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    return launcherService->GetShortcutInfoV9(bundleName, shortcutInfos, userId);
}

void GetShortcutInfoExec(napi_env env, void *data)
{
    GetShortcutInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetShortcutInfo(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->shortcutInfos, asyncCallbackInfo->userId);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void GetShortcutInfoComplete(napi_env env, napi_status status, void *data)
{
    GetShortcutInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertShortCutInfos(env, asyncCallbackInfo->shortcutInfos, result[ARGS_POS_ONE]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, GET_SHORTCUT_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_get_undefined(env, &result[ARGS_POS_ONE]);
    }
    CommonFunc::NapiReturnDeferred<GetShortcutInfoCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetShortcutInfo(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi begin GetShortcutInfo");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetShortcutInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetShortcutInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetMaxArgc() >= ARGS_SIZE_ONE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_TWO) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_ONE], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        APP_LOGE("parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetShortcutInfoCallbackInfo>(
        env, asyncCallbackInfo, "GetShortcutInfo", GetShortcutInfoExec, GetShortcutInfoComplete);
    callbackPtr.release();
    APP_LOGI_NOFUNC("call GetShortcutInfo done");
    return promise;
}

napi_value GetShortcutInfoSync(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi GetShortcutInfoSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;
    if (args.GetMaxArgc() == ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], userId)) {
            APP_LOGW("parse userId falied");
            userId = Constants::UNSPECIFIED_USERID;
        }
    }

    auto launcherService = GetLauncherService();
    if (launcherService == nullptr) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_SERVICE_EXCEPTION, GET_SHORTCUT_INFO_SYNC,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    std::vector<OHOS::AppExecFwk::ShortcutInfo> shortcutInfos;
    ErrCode ret = CommonFunc::ConvertErrCode(launcherService->GetShortcutInfoV9(bundleName, shortcutInfos, userId));
    if (ret != SUCCESS) {
        APP_LOGE("failed, ret %{public}d", ret);
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_SHORTCUT_INFO_SYNC, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nShortcutInfos = nullptr;
    NAPI_CALL(env, napi_create_array(env, &nShortcutInfos));
    CommonFunc::ConvertShortCutInfos(env, shortcutInfos, nShortcutInfos);
    APP_LOGI_NOFUNC("call GetShortcutInfoSync done");
    return nShortcutInfos;
}

bool ParseGetShortcutInfoAppIndex(napi_env env, napi_value args, int32_t &appIndex)
{
    if (!CommonFunc::ParseInt(env, args, appIndex)) {
        APP_LOGE("parse appIndex failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return false;
    }
    if (appIndex < Constants::MAIN_APP_INDEX || appIndex > Constants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("appIndex: %{public}d not in valid range", appIndex);
        BusinessError::ThrowParameterTypeError(env, ERROR_INVALID_APPINDEX, APP_INDEX, TYPE_NUMBER);
        return false;
    }
    return true;
}

napi_value GetShortcutInfoByAppIndex(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi GetShortcutInfoByAppIndex called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }

    int32_t appIndex = Constants::MAIN_APP_INDEX;
    if (!ParseGetShortcutInfoAppIndex(env, args[ARGS_POS_ONE], appIndex)) {
        return nullptr;
    }

    auto launcherService = GetLauncherService();
    if (launcherService == nullptr) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_SERVICE_EXCEPTION, GET_SHORTCUT_INFO_SYNC,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    std::vector<OHOS::AppExecFwk::ShortcutInfo> shortcutInfos;
    ErrCode ret = CommonFunc::ConvertErrCode(launcherService->
        GetShortcutInfoByAppIndex(bundleName, appIndex, shortcutInfos));
    if (ret != SUCCESS) {
        APP_LOGE("failed, ret %{public}d", ret);
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_SHORTCUT_INFO_BY_APPINDEX, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nShortcutInfos = nullptr;
    NAPI_CALL(env, napi_create_array(env, &nShortcutInfos));
    CommonFunc::ConvertShortCutInfos(env, shortcutInfos, nShortcutInfos);
    APP_LOGI_NOFUNC("call GetShortcutInfoByAppIndex done");
    return nShortcutInfos;
}

static ErrCode InnerStartShortcut(const OHOS::AppExecFwk::ShortcutInfo &shortcutInfo,
    const OHOS::AAFwk::StartOptions &startOptions)
{
    if (shortcutInfo.intents.empty()) {
        APP_LOGW("intents is empty");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    AAFwk::Want want;
    ElementName element;
    element.SetBundleName(shortcutInfo.intents[0].targetBundle);
    element.SetModuleName(shortcutInfo.intents[0].targetModule);
    element.SetAbilityName(shortcutInfo.intents[0].targetClass);
    want.SetElement(element);
    for (const auto &item : shortcutInfo.intents[0].parameters) {
        want.SetParam(item.first, item.second);
    }
    want.SetParam(AAFwk::Want::PARAM_APP_CLONE_INDEX_KEY, shortcutInfo.appIndex);
    auto res = AAFwk::AbilityManagerClient::GetInstance()->StartShortcut(want, startOptions);
    auto it = START_SHORTCUT_RES_MAP.find(res);
    if (it == START_SHORTCUT_RES_MAP.end()) {
        return ERR_BUNDLE_MANAGER_START_SHORTCUT_FAILED;
    }
    return it->second;
}

void StartShortcutExec(napi_env env, void *data)
{
    StartShortcutCallbackInfo *asyncCallbackInfo = reinterpret_cast<StartShortcutCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerStartShortcut(asyncCallbackInfo->shortcutInfo, asyncCallbackInfo->startOptions);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void StartShortcutComplete(napi_env env, napi_status status, void *data)
{
    StartShortcutCallbackInfo *asyncCallbackInfo = reinterpret_cast<StartShortcutCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<StartShortcutCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, START_SHORTCUT, Constants::PERMISSION_START_SHORTCUT);
    }

    CommonFunc::NapiReturnDeferred<StartShortcutCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value StartShortcut(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi begin StartShortcut");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    StartShortcutCallbackInfo *asyncCallbackInfo = new (std::nothrow) StartShortcutCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<StartShortcutCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[i], &valueType));
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseShortCutInfo(env, args[ARGS_POS_ZERO], asyncCallbackInfo->shortcutInfo)) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_SHORTCUT_INFO_FAILED);
                return nullptr;
            }
            if (asyncCallbackInfo->shortcutInfo.intents.empty()) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, ERROR_EMPTY_WANT);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if ((valueType == napi_object) &&
                (!AppExecFwk::UnwrapStartOptions(env, args[ARGS_POS_ONE], asyncCallbackInfo->startOptions))) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_START_OPTIONS_FAILED);
                return nullptr;
            }
        } else {
            APP_LOGE("parameter is invalid");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<StartShortcutCallbackInfo>(
        env, asyncCallbackInfo, "StartShortcut", StartShortcutExec, StartShortcutComplete);
    callbackPtr.release();
    APP_LOGI_NOFUNC("call StartShortcut done");
    return promise;
}

static ErrCode InnerStartShortcutWithReason(const OHOS::AppExecFwk::ShortcutInfo &shortcutInfo,
    std::string &startReason, const OHOS::AAFwk::StartOptions &startOptions)
{
    if (shortcutInfo.intents.empty()) {
        APP_LOGW("intents is empty");
        return ERR_BUNDLE_MANAGER_START_SHORTCUT_FAILED;
    }
    AAFwk::Want want;
    ElementName element;
    element.SetBundleName(shortcutInfo.intents[0].targetBundle);
    element.SetModuleName(shortcutInfo.intents[0].targetModule);
    element.SetAbilityName(shortcutInfo.intents[0].targetClass);
    want.SetElement(element);
    for (const auto &item : shortcutInfo.intents[0].parameters) {
        want.SetParam(item.first, item.second);
    }
    want.SetParam(AAFwk::Want::PARM_LAUNCH_REASON_MESSAGE, startReason);
    want.SetParam(AAFwk::Want::PARAM_APP_CLONE_INDEX_KEY, shortcutInfo.appIndex);
    auto res = AAFwk::AbilityManagerClient::GetInstance()->StartShortcut(want, startOptions);
    auto it = START_SHORTCUT_RES_MAP.find(res);
    if (it == START_SHORTCUT_RES_MAP.end()) {
        APP_LOGE("call AbilityManagerClient StartShortcut failed, res : %{public}d", res);
        return ERR_BUNDLE_MANAGER_START_SHORTCUT_FAILED;
    }
    return it->second;
}

void StartShortcutWithReasonExec(napi_env env, void *data)
{
    StartShortcutWithReasonCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<StartShortcutWithReasonCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerStartShortcutWithReason(asyncCallbackInfo->shortcutInfo,
        asyncCallbackInfo->reasonMessage, asyncCallbackInfo->startOptions);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void StartShortcutWithReasonComplete(napi_env env, napi_status status, void *data)
{
    StartShortcutWithReasonCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<StartShortcutWithReasonCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<StartShortcutWithReasonCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, START_SHORTCUT_WITH_REASON, Constants::PERMISSION_START_SHORTCUT);
    }

    CommonFunc::NapiReturnDeferred<StartShortcutWithReasonCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value StartShortcutWithReason(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi begin StartShortcutWithReason");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    StartShortcutWithReasonCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) StartShortcutWithReasonCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<StartShortcutWithReasonCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[i], &valueType));
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseShortCutInfo(env, args[ARGS_POS_ZERO], asyncCallbackInfo->shortcutInfo)) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_SHORTCUT_INFO_FAILED);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->reasonMessage)) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_REASON_MESSAGE);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if ((valueType == napi_object) &&
                (!AppExecFwk::UnwrapStartOptions(env, args[ARGS_POS_TWO], asyncCallbackInfo->startOptions))) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_START_OPTIONS_FAILED);
                return nullptr;
            }
        } else {
            APP_LOGE("parameter is invalid");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<StartShortcutWithReasonCallbackInfo>(
        env, asyncCallbackInfo, "StartShortcutWithReason",
        StartShortcutWithReasonExec, StartShortcutWithReasonComplete);
    callbackPtr.release();
    APP_LOGI_NOFUNC("call StartShortcutWithReason done");
    return promise;
}
}
}