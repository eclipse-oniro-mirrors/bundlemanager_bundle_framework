/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_SHORTCUT_INFO_ERROR);
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
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, DELETE_DESKTOP_SHORTCUT_INFO,
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
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_SHORTCUT_INFO_ERROR);
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

static ErrCode InnerSetShortcutVisibleForSelf(const std::string &shortcutId, bool visible)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return iBundleMgr->SetShortcutVisibleForSelf(shortcutId, visible);
}

void SetShortcutVisibleForSelfExec(napi_env env, void *data)
{
    SetShortcutVisibleForSelfCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SetShortcutVisibleForSelfCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err =
        InnerSetShortcutVisibleForSelf(asyncCallbackInfo->shortcutId, asyncCallbackInfo->visible);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void SetShortcutVisibleForSelfComplete(napi_env env, napi_status status, void *data)
{
    SetShortcutVisibleForSelfCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SetShortcutVisibleForSelfCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<SetShortcutVisibleForSelfCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ONE]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, SET_SHORTCUT_VISIBLE);
    }
    CommonFunc::NapiReturnDeferred<SetShortcutVisibleForSelfCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value SetShortcutVisibleForSelf(napi_env env, napi_callback_info info)
{
    APP_LOGD("Napi begin SetShortcutVisibleForSelf");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("Args init is error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    SetShortcutVisibleForSelfCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) SetShortcutVisibleForSelfCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<SetShortcutVisibleForSelfCallbackInfo> callbackPtr {asyncCallbackInfo};

    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->shortcutId)) {
        APP_LOGE("Parse shortcutId is error");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, "shortcutId", TYPE_STRING);
        return nullptr;
    }

    if (!CommonFunc::ParseBool(env, args[ARGS_SIZE_ONE], asyncCallbackInfo->visible)) {
        APP_LOGE("Parse visible is error");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, "visible", TYPE_BOOLEAN);
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<SetShortcutVisibleForSelfCallbackInfo>(env, asyncCallbackInfo,
        "SetShortcutVisibleForSelf", SetShortcutVisibleForSelfExec, SetShortcutVisibleForSelfComplete);
    callbackPtr.release();
    APP_LOGD("Call SetShortcutVisibleForSelf done");
    return promise;
}

static ErrCode InnerGetAllShortcutInfoForSelf(std::vector<OHOS::AppExecFwk::ShortcutInfo> &shortcutInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    return iBundleMgr->GetAllShortcutInfoForSelf(shortcutInfos);
}

void GetAllShortcutInfoForSelfExec(napi_env env, void *data)
{
    GetAllShortcutInfoForSelfCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<GetAllShortcutInfoForSelfCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(
        InnerGetAllShortcutInfoForSelf(asyncCallbackInfo->shortcutInfos));
}

void GetAllShortcutInfoForSelfComplete(napi_env env, napi_status status, void *data)
{
    GetAllShortcutInfoForSelfCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<GetAllShortcutInfoForSelfCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetAllShortcutInfoForSelfCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertShortCutInfos(env, asyncCallbackInfo->shortcutInfos, result[ARGS_POS_ONE]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, GET_ALL_SHORTCUT_INFO_FOR_SELF);
    }
    CommonFunc::NapiReturnDeferred<GetAllShortcutInfoForSelfCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllShortcutInfoForSelf(napi_env env, napi_callback_info info)
{
    APP_LOGD("Napi begin GetAllShortcutInfoForSelf");
    GetAllShortcutInfoForSelfCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) GetAllShortcutInfoForSelfCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetAllShortcutInfoForSelfCallbackInfo> callbackPtr {asyncCallbackInfo};

    auto promise = CommonFunc::AsyncCallNativeMethod<GetAllShortcutInfoForSelfCallbackInfo>(env, asyncCallbackInfo,
        "GetAllShortcutInfoForSelf", GetAllShortcutInfoForSelfExec, GetAllShortcutInfoForSelfComplete);
    callbackPtr.release();
    APP_LOGD("Call GetAllShortcutInfoForSelf done");
    return promise;
}

#ifdef BUNDLE_FRAMEWORK_LAUNCHER
static bool CheckShortcutInfo(napi_env env, const std::string &referenceBundleName, const int32_t referenceAppIndex,
    std::unordered_set<std::string> &shortcutIds, ShortcutInfo &shortcutInfo)
{
    if (shortcutInfo.id.empty() || !shortcutIds.insert(shortcutInfo.id).second) {
        APP_LOGE("ShortcutId is illegal");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_SHORTCUT_ID_ILLEGAL_ERROR, ADD_DYNAMIC_SHORTCUT_INFOS, PERMISSION_DYNAMIC_SHORTCUT_INFO);
        napi_throw(env, businessError);
        return false;
    }
    if (shortcutInfo.appIndex < Constants::MAIN_APP_INDEX || shortcutInfo.appIndex > Constants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("appIndex: %{public}d not in valid range", shortcutInfo.appIndex);
        BusinessError::ThrowParameterTypeError(env, ERROR_INVALID_APPINDEX, APP_INDEX, TYPE_NUMBER);
        return false;
    }
    if (shortcutInfo.sourceType < Constants::ShortcutSourceType::DEFAULT_SHORTCUT ||
        shortcutInfo.sourceType > Constants::ShortcutSourceType::DYNAMIC_SHORTCUT) {
        APP_LOGE("sourceType is invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return false;
    }
    if (shortcutInfo.sourceType != Constants::ShortcutSourceType::DYNAMIC_SHORTCUT) {
        shortcutInfo.sourceType = Constants::ShortcutSourceType::DYNAMIC_SHORTCUT;
    }
    if (shortcutInfo.bundleName != referenceBundleName || shortcutInfo.appIndex != referenceAppIndex) {
        APP_LOGE("bundleName or appIndex is not unique");
        BusinessError::ThrowError(env, ERROR_BUNDLENAME_APPINDEX_NOT_UNIQUE, BUNDLENAME_APPINDEX_NOT_UNIQUE);
        return false;
    }
    return true;
}

static bool ParseShortcutInfos(napi_env env, napi_value nShortcutInfos, std::vector<ShortcutInfo> &shortcutInfos,
    bool isRelative)
{
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, nShortcutInfos, &isArray), false);
    if (!isArray) {
        APP_LOGE("nShortcutInfos is not of array type");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return false;
    }
    uint32_t arrayLength = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, nShortcutInfos, &arrayLength), false);
    if (arrayLength <= 0 || arrayLength > MAX_SHORTCUT_INFO_SIZE) {
        APP_LOGE("ShortcutInfo array length invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, SHORTCUT_INFO_LENGTH_ERROR);
        return false;
    }
    std::string referenceBundleName;
    int32_t referenceAppIndex = -1;
    std::unordered_set<std::string> shortcutIds;
    shortcutIds.reserve(arrayLength);
    for (uint32_t i = 0; i < arrayLength; ++i) {
        napi_value value = nullptr;
        NAPI_CALL_BASE(env, napi_get_element(env, nShortcutInfos, i, &value), false);
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
        if (valueType != napi_object) {
            APP_LOGE("shortcutInfo not object");
            shortcutInfos.clear();
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return false;
        }
        ShortcutInfo shortcutInfo;
        if (!CommonFunc::ParseShortCutInfo(env, value, shortcutInfo)) {
            APP_LOGE("ParseShortCutInfo failed");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return false;
        }
        if (isRelative) {
            if (i == 0) {
                referenceBundleName = shortcutInfo.bundleName;
                referenceAppIndex = shortcutInfo.appIndex;
            }
            if (!CheckShortcutInfo(env, referenceBundleName, referenceAppIndex, shortcutIds, shortcutInfo)) {
                APP_LOGE("CheckShortcutInfo failed");
                return false;
            }
        }
        shortcutInfos.push_back(shortcutInfo);
    }
    return true;
}

static ErrCode InnerAddDynamicShortcutInfos(const std::vector<ShortcutInfo> &shortcutInfos, int32_t userId)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return iBundleMgr->AddDynamicShortcutInfos(shortcutInfos, userId);
}

void AddDynamicShortcutInfosExec(napi_env env, void *data)
{
    AddDynamicShortcutInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<AddDynamicShortcutInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err =
        InnerAddDynamicShortcutInfos(asyncCallbackInfo->shortcutInfos, asyncCallbackInfo->userId);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void AddDynamicShortcutInfosComplete(napi_env env, napi_status status, void *data)
{
    AddDynamicShortcutInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<AddDynamicShortcutInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AddDynamicShortcutInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_ONE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, ADD_DYNAMIC_SHORTCUT_INFOS, PERMISSION_DYNAMIC_SHORTCUT_INFO);
    }
    CommonFunc::NapiReturnDeferred<AddDynamicShortcutInfosCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_POS_ONE);
}
#endif

napi_value AddDynamicShortcutInfos(napi_env env, napi_callback_info info)
{
#ifdef BUNDLE_FRAMEWORK_LAUNCHER
    APP_LOGD("Napi begin AddDynamicShortcutInfos");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("Args init is error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    AddDynamicShortcutInfosCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) AddDynamicShortcutInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AddDynamicShortcutInfosCallbackInfo> callbackPtr {asyncCallbackInfo};

    if (args.GetArgc() == ARGS_SIZE_TWO) {
        if (!ParseShortcutInfos(env, args[ARGS_POS_ZERO], asyncCallbackInfo->shortcutInfos, true)) {
            APP_LOGE("shortcutInfos invalid");
            return nullptr;
        }
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], asyncCallbackInfo->userId)) {
            APP_LOGE("Parse userId is error");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
            return nullptr;
        }
    } else {
        APP_LOGE("Parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<AddDynamicShortcutInfosCallbackInfo>(env, asyncCallbackInfo,
        ADD_DYNAMIC_SHORTCUT_INFOS, AddDynamicShortcutInfosExec, AddDynamicShortcutInfosComplete);
    callbackPtr.release();
    APP_LOGD("Call AddDynamicShortcutInfos done");
    return promise;
#else
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        ADD_DYNAMIC_SHORTCUT_INFOS);
    napi_throw(env, error);
    return nullptr;
#endif
}

#ifdef BUNDLE_FRAMEWORK_LAUNCHER
static ErrCode InnerSetShortcutsEnabled(const std::vector<ShortcutInfo> &shortcutInfos, bool isEnabled)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return iBundleMgr->SetShortcutsEnabled(shortcutInfos, isEnabled);
}

void SetShortcutsEnabledExec(napi_env env, void *data)
{
    SetShortcutsEnabledCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SetShortcutsEnabledCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerSetShortcutsEnabled(asyncCallbackInfo->shortcutInfos, asyncCallbackInfo->isEnabled);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void SetShortcutsEnabledComplete(napi_env env, napi_status status, void *data)
{
    SetShortcutsEnabledCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SetShortcutsEnabledCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<SetShortcutsEnabledCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_ONE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, SET_SHORTCUTS_ENABLED);
    }
    CommonFunc::NapiReturnDeferred<SetShortcutsEnabledCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_POS_ONE);
}
#endif

napi_value SetShortcutsEnabled(napi_env env, napi_callback_info info)
{
#ifdef BUNDLE_FRAMEWORK_LAUNCHER
    APP_LOGD("Napi begin SetShortcutsEnabled");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("Args init is error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    SetShortcutsEnabledCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) SetShortcutsEnabledCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<SetShortcutsEnabledCallbackInfo> callbackPtr {asyncCallbackInfo};

    if (args.GetArgc() == ARGS_SIZE_TWO) {
        if (!ParseShortcutInfos(env, args[ARGS_POS_ZERO], asyncCallbackInfo->shortcutInfos, false)) {
            APP_LOGE("shortcutInfos invalid");
            return nullptr;
        }
        if (!CommonFunc::ParseBool(env, args[ARGS_SIZE_ONE], asyncCallbackInfo->isEnabled)) {
            APP_LOGE("Parse isEnabled is error");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, "isEnabled", TYPE_BOOLEAN);
            return nullptr;
        }
    } else {
        APP_LOGE("Parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<SetShortcutsEnabledCallbackInfo>(env, asyncCallbackInfo,
        SET_SHORTCUTS_ENABLED, SetShortcutsEnabledExec, SetShortcutsEnabledComplete);
    callbackPtr.release();
    APP_LOGD("Call SetShortcutsEnabled done");
    return promise;
#else
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "SetShortcutsEnabled");
    napi_throw(env, error);
    return nullptr;
#endif
}

#ifdef BUNDLE_FRAMEWORK_LAUNCHER
static ErrCode InnerDeleteDynamicShortcutInfos(const std::string &bundleName, const int32_t appIndex,
    const int32_t userId, const std::vector<std::string> &ids)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return iBundleMgr->DeleteDynamicShortcutInfos(bundleName, appIndex, userId, ids);
}

void DeleteDynamicShortcutInfosExec(napi_env env, void *data)
{
    DeleteDynamicShortcutInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<DeleteDynamicShortcutInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    asyncCallbackInfo->err = InnerDeleteDynamicShortcutInfos(asyncCallbackInfo->bundleName, asyncCallbackInfo->appIndex,
        asyncCallbackInfo->userId, asyncCallbackInfo->shortcutIds);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
}

void DeleteDynamicShortcutInfosComplete(napi_env env, napi_status status, void *data)
{
    DeleteDynamicShortcutInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<DeleteDynamicShortcutInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<DeleteDynamicShortcutInfosCallbackInfo> callbackPtr {asyncCallbackInfo};

    napi_value result[ARGS_SIZE_ONE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, DELETE_DYNAMIC_SHORTCUT_INFOS,
            PERMISSION_DYNAMIC_SHORTCUT_INFO);
    }
    CommonFunc::NapiReturnDeferred<DeleteDynamicShortcutInfosCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

static bool ParseShortcutIds(napi_env env, std::vector<std::string> &shortcutIds, napi_value args)
{
    if (!CommonFunc::ParseStringArray(env, shortcutIds, args)) {
        APP_LOGE("ParseStringArray invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, SHORTCUT_IDS, TYPE_ARRAY);
        return false;
    }
    if (shortcutIds.size() > MAX_SHORTCUT_INFO_SIZE) {
        APP_LOGE("Shortcut ids length invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, SHORTCUT_IDS_LENGTH_ERROR);
        return false;
    }
    std::unordered_set<std::string> shortcutIdsSet;
    shortcutIdsSet.reserve(shortcutIds.size());
    for (const auto& id : shortcutIds) {
        if (id.empty() || !shortcutIdsSet.insert(id).second) {
            APP_LOGE("ShortcutId is illegal");
            napi_value businessError = BusinessError::CreateCommonError(
                env, ERROR_SHORTCUT_ID_ILLEGAL_ERROR, DELETE_DYNAMIC_SHORTCUT_INFOS, PERMISSION_DYNAMIC_SHORTCUT_INFO);
            napi_throw(env, businessError);
            return false;
        }
    }
    return true;
}

static bool ParseDeleteDynamicParam(
    napi_env env, napi_callback_info info, DeleteDynamicShortcutInfosCallbackInfo& callbackInfo)
{
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("Args init is error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return false;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], callbackInfo.bundleName)) {
        APP_LOGE("Parse bundleName error");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return false;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], callbackInfo.appIndex)) {
        APP_LOGE("Parse appIndex error");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return false;
    }
    if (callbackInfo.appIndex < Constants::MAIN_APP_INDEX ||
        callbackInfo.appIndex > Constants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("appIndex:%{public}d not in valid range", callbackInfo.appIndex);
        BusinessError::ThrowParameterTypeError(env, ERROR_INVALID_APPINDEX, APP_INDEX, TYPE_NUMBER);
        return false;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_TWO], callbackInfo.userId)) {
        APP_LOGE("Parse userId is error");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
        return false;
    }
    if (args.GetArgc() == ARGS_SIZE_FOUR &&
        !ParseShortcutIds(env, callbackInfo.shortcutIds, args[ARGS_POS_THREE])) {
        APP_LOGE("ParseShortcutIds failed");
        return false;
    }

    return true;
}
#endif

napi_value DeleteDynamicShortcutInfos(napi_env env, napi_callback_info info)
{
#ifdef BUNDLE_FRAMEWORK_LAUNCHER
    APP_LOGD("Napi begin DeleteDynamicShortcutInfos");

    DeleteDynamicShortcutInfosCallbackInfo* asyncCallbackInfo =
        new (std::nothrow) DeleteDynamicShortcutInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<DeleteDynamicShortcutInfosCallbackInfo> callbackPtr {asyncCallbackInfo};

    if (!ParseDeleteDynamicParam(env, info, *asyncCallbackInfo)) {
        APP_LOGE("ParseDeleteDynamicParam failed");
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<DeleteDynamicShortcutInfosCallbackInfo>(
        env, asyncCallbackInfo, DELETE_DYNAMIC_SHORTCUT_INFOS,
        DeleteDynamicShortcutInfosExec, DeleteDynamicShortcutInfosComplete);

    callbackPtr.release();
    APP_LOGD("Call DeleteDynamicShortcutInfos done");
    return promise;
#else
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        DELETE_DYNAMIC_SHORTCUT_INFOS);
    napi_throw(env, error);
    return nullptr;
#endif
}
} // AppExecFwk
} // OHOS