/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "shortcut_manager.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* GET_ALL_DESKTOP_SHORTCUT_INFO = "GetAllDesktopShortcutInfo";
constexpr const char* ADD_DESKTOP_SHORTCUT_INFO = "AddDesktopShortcutInfo";
constexpr const char* PARSE_SHORTCUT_INFO = "ParseShortCutInfo";
constexpr const char* USER_ID = "userId";
}
static ErrCode InnerAddDesktopShortcutInfo(const OHOS::AppExecFwk::ShortcutInfo &shortcutInfo, int32_t userId)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return iBundleMgr->AddDesktopShortcutInfo(shortcutInfo, userId);
}

void AddDesktopShortcutInfoExec(napi_env env, void *data)
{
    AddDesktopShortcutInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<AddDesktopShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerAddDesktopShortcutInfo(asyncCallbackInfo->shortcutInfo, asyncCallbackInfo->userId);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void AddDesktopShortcutInfoComplete(napi_env env, napi_status status, void *data)
{
    AddDesktopShortcutInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<AddDesktopShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AddDesktopShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_ONE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, ADD_DESKTOP_SHORTCUT_INFO,
            Constants::PERMISSION_MANAGER_SHORTCUT);
    }
    CommonFunc::NapiReturnDeferred<AddDesktopShortcutInfoCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value AddDesktopShortcutInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("Napi begin AddDesktopShortcutInfo");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("Args init is error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    AddDesktopShortcutInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) AddDesktopShortcutInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AddDesktopShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetArgc() == ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseShortCutInfo(env, args[ARGS_POS_ZERO], asyncCallbackInfo->shortcutInfo) ||
            !CommonFunc::CheckShortcutInfo(asyncCallbackInfo->shortcutInfo)) {
            APP_LOGE("ParseShortCutInfo is error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_SHORTCUT_INFO);
            return nullptr;
        }
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], asyncCallbackInfo->userId)) {
            APP_LOGE("Parse userId is error");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
            return nullptr;
        }
    } else {
        APP_LOGE("Parameter is invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AddDesktopShortcutInfoCallbackInfo>(
        env, asyncCallbackInfo, "AddDesktopShortcutInfo", AddDesktopShortcutInfoExec, AddDesktopShortcutInfoComplete);
    callbackPtr.release();
    APP_LOGD("Call AddDesktopShortcutInfo done");
    return promise;
}

static ErrCode InnerDeleteDesktopShortcutInfo(const OHOS::AppExecFwk::ShortcutInfo &shortcutInfo, int32_t userId)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return iBundleMgr->DeleteDesktopShortcutInfo(shortcutInfo, userId);
}

void DeleteDesktopShortcutInfoExec(napi_env env, void *data)
{
    DeleteDesktopShortcutInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<DeleteDesktopShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerDeleteDesktopShortcutInfo(asyncCallbackInfo->shortcutInfo, asyncCallbackInfo->userId);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void DeleteDesktopShortcutInfoComplete(napi_env env, napi_status status, void *data)
{
    DeleteDesktopShortcutInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<DeleteDesktopShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<DeleteDesktopShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_ONE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, ADD_DESKTOP_SHORTCUT_INFO,
            Constants::PERMISSION_MANAGER_SHORTCUT);
    }
    CommonFunc::NapiReturnDeferred<DeleteDesktopShortcutInfoCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value DeleteDesktopShortcutInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("Napi begin DeleteDesktopShortcutInfo");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("Args init is error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    DeleteDesktopShortcutInfoCallbackInfo* asyncCallbackInfo =
        new (std::nothrow) DeleteDesktopShortcutInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<DeleteDesktopShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetArgc() == ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseShortCutInfo(env, args[ARGS_POS_ZERO], asyncCallbackInfo->shortcutInfo) ||
            !CommonFunc::CheckShortcutInfo(asyncCallbackInfo->shortcutInfo)) {
            APP_LOGE("ParseShortCutInfo is error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_SHORTCUT_INFO);
            return nullptr;
        }
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], asyncCallbackInfo->userId)) {
            APP_LOGE("Parse userId is error");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
            return nullptr;
        }
    } else {
        APP_LOGE("Parameter is invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DeleteDesktopShortcutInfoCallbackInfo>(env, asyncCallbackInfo,
        "DeleteDesktopShortcutInfo", DeleteDesktopShortcutInfoExec, DeleteDesktopShortcutInfoComplete);
    callbackPtr.release();
    APP_LOGD("Call DeleteDesktopShortcutInfo done");
    return promise;
}

static ErrCode InnerGetAllDesktopShortcutInfo(
    int32_t userId, std::vector<OHOS::AppExecFwk::ShortcutInfo> &shortcutInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return iBundleMgr->GetAllDesktopShortcutInfo(userId, shortcutInfos);
}

void GetAllDesktopShortcutInfoExec(napi_env env, void *data)
{
    GetAllDesktopShortcutInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<GetAllDesktopShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err =
        InnerGetAllDesktopShortcutInfo(asyncCallbackInfo->userId, asyncCallbackInfo->shortcutInfos);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void GetAllDesktopShortcutInfoComplete(napi_env env, napi_status status, void *data)
{
    GetAllDesktopShortcutInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<GetAllDesktopShortcutInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetAllDesktopShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertShortCutInfos(env, asyncCallbackInfo->shortcutInfos, result[ARGS_POS_ONE]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, GET_ALL_DESKTOP_SHORTCUT_INFO,
            Constants::PERMISSION_MANAGER_SHORTCUT);
        napi_get_undefined(env, &result[ARGS_POS_ONE]);
    }
    CommonFunc::NapiReturnDeferred<GetAllDesktopShortcutInfoCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllDesktopShortcutInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("Napi begin GetAllDesktopShortcutInfo");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("Args init is error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetAllDesktopShortcutInfoCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) GetAllDesktopShortcutInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetAllDesktopShortcutInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetArgc() == ARGS_SIZE_ONE) {
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], asyncCallbackInfo->userId)) {
            APP_LOGE("Parse userId is error");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
            return nullptr;
        }
    } else {
        APP_LOGE("Parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetAllDesktopShortcutInfoCallbackInfo>(env, asyncCallbackInfo,
        "GetAllDesktopShortcutInfo", GetAllDesktopShortcutInfoExec, GetAllDesktopShortcutInfoComplete);
    callbackPtr.release();
    APP_LOGD("Call GetAllDesktopShortcutInfo done");
    return promise;
}
} // AppExecFwk
} // OHOS