/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "bundle_manager.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "bundle_constants.h"
#include "common_func.h"
#include "hap_module_info.h"
#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
#include "image_source.h"
#include "pixel_map_napi.h"
#endif
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* METADATA_NAME = "metadataName";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* ABILITY_INFO = "abilityInfo";
constexpr const char* IS_ENABLE = "isEnable";
constexpr const char* USER_ID = "userId";
constexpr const char* BUNDLE_FLAGS = "bundleFlags";
constexpr const char* APP_FLAGS = "appFlags";
constexpr const char* CALLBACK = "callback";
constexpr const char* STRING_TYPE = "napi_string";
constexpr const char* FUNCTION_TYPE = "napi_function";
constexpr const char* NUMBER_TYPE = "napi_number";
constexpr const char* WRONG_PARAM_TYPE = "BusinessError 401: Wrong param type";
constexpr const char* GET_LAUNCH_WANT_FOR_BUNDLE = "GetLaunchWantForBundle";
const std::string GET_BUNDLE_ARCHIVE_INFO = "GetBundleArchiveInfo";
const std::string GET_BUNDLE_NAME_BY_UID = "GetBundleNameByUid";
const std::string QUERY_ABILITY_INFOS = "QueryAbilityInfos";
const std::string QUERY_EXTENSION_INFOS = "QueryExtensionInfos";
const std::string GET_BUNDLE_INFO = "GetBundleInfo";
const std::string GET_BUNDLE_INFOS = "GetBundleInfos";
const std::string GET_APPLICATION_INFO = "GetApplicationInfo";
const std::string GET_APPLICATION_INFOS = "GetApplicationInfos";
const std::string GET_PERMISSION_DEF = "GetPermissionDef";
const std::string PERMISSION_NAME = "permissionName";
const std::string BUNDLE_PERMISSIONS = "ohos.permission.GET_BUNDLE_INFO or ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
const std::string PARAM_TYPE_CHECK_ERROR = "param type check error";
const std::string PARAM_TYPE_CHECK_ERROR_WITH_POS = "param type check error, error position : ";
const std::string GET_BUNDLE_INFO_SYNC = "GetBundleInfoSync";
const std::string GET_APPLICATION_INFO_SYNC = "GetApplicationInfoSync";
const std::string INVALID_WANT_ERROR =
    "implicit query condition, at least one query param(action entities uri type) non-empty.";
} // namespace
using namespace OHOS::AAFwk;
static std::unordered_map<Query, napi_ref, QueryHash> cache;
namespace {
const std::string PARAMETER_BUNDLE_NAME = "bundleName";
}

static ErrCode InnerGetBundleArchiveInfo(std::string &hapFilePath, int32_t flags, BundleInfo &bundleInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetBundleArchiveInfoV9(hapFilePath, flags, bundleInfo);
    APP_LOGD("GetBundleArchiveInfoV9 ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

void GetBundleArchiveInfoExec(napi_env env, void *data)
{
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleArchiveInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetBundleArchiveInfo(
        asyncCallbackInfo->hapFilePath, asyncCallbackInfo->flags, asyncCallbackInfo->bundleInfo);
}

void GetBundleArchiveInfoComplete(napi_env env, napi_status status, void *data)
{
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleArchiveInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<GetBundleArchiveInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertBundleInfo(env,
            asyncCallbackInfo->bundleInfo, result[ARGS_POS_ONE], asyncCallbackInfo->flags);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_BUNDLE_ARCHIVE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ONE]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ZERO]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[ARGS_POS_ZERO]), result, &placeHolder));
    }
}

napi_value GetBundleArchiveInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetBundleArchiveInfo");
    NapiArg args(env, info);
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetBundleArchiveInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetBundleArchiveInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->hapFilePath)) {
                APP_LOGE("hapFilePath %{public}s invalid!", asyncCallbackInfo->hapFilePath.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags);
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetBundleArchiveInfoCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_ARCHIVE_INFO, GetBundleArchiveInfoExec, GetBundleArchiveInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetBundleArchiveInfo done");
    return promise;
}

static ErrCode InnerGetBundleNameByUid(int32_t uid, std::string &bundleName)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetNameForUid(uid, bundleName);
    APP_LOGD("GetNameForUid ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerGetApplicationInfo(const std::string &bundleName, int32_t flags,
    int32_t userId, ApplicationInfo &appInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetApplicationInfoV9(bundleName, flags, userId, appInfo);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerGetApplicationInfos(int32_t flags,
    int32_t userId, std::vector<ApplicationInfo> &appInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetApplicationInfosV9(flags, userId, appInfos);
    return CommonFunc::ConvertErrCode(ret);
}

static void ProcessApplicationInfos(
    napi_env env, napi_value result, const std::vector<ApplicationInfo> &appInfos)
{
    if (appInfos.size() == 0) {
        APP_LOGD("appInfos is null");
        return;
    }
    size_t index = 0;
    for (const auto &item : appInfos) {
        APP_LOGD("name{%s}, bundleName{%s} ", item.name.c_str(), item.bundleName.c_str());
        napi_value objAppInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objAppInfo));
        CommonFunc::ConvertApplicationInfo(env, objAppInfo, item);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, objAppInfo));
        index++;
    }
}

void GetBundleNameByUidExec(napi_env env, void *data)
{
    GetBundleNameByUidCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleNameByUidCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetBundleNameByUid(asyncCallbackInfo->uid, asyncCallbackInfo->bundleName);
}

void GetBundleNameByUidComplete(napi_env env, napi_status status, void *data)
{
    GetBundleNameByUidCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleNameByUidCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<GetBundleNameByUidCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(env, asyncCallbackInfo->bundleName.c_str(), NAPI_AUTO_LENGTH, &result[1]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_BUNDLE_NAME_BY_UID, BUNDLE_PERMISSIONS);
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

void GetApplicationInfoComplete(napi_env env, napi_status status, void *data)
{
    ApplicationInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<ApplicationInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<ApplicationInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertApplicationInfo(env, result[ARGS_POS_ONE], asyncCallbackInfo->appInfo);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_APPLICATION_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ONE]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ZERO]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[ARGS_POS_ZERO]), result, &placeHolder));
    }
}

void GetApplicationInfosComplete(napi_env env, napi_status status, void *data)
{
    ApplicationInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<ApplicationInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<ApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        ProcessApplicationInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->appInfos);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_APPLICATION_INFOS, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ONE]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ZERO]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[ARGS_POS_ZERO]), result, &placeHolder));
    }
}

void GetApplicationInfoExec(napi_env env, void *data)
{
    ApplicationInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerGetApplicationInfo(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->flags, asyncCallbackInfo->userId, asyncCallbackInfo->appInfo);
}

void GetApplicationInfosExec(napi_env env, void *data)
{
    ApplicationInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerGetApplicationInfos(asyncCallbackInfo->flags,
        asyncCallbackInfo->userId, asyncCallbackInfo->appInfos);
}

napi_value GetBundleNameByUid(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetBundleNameByUid");
    NapiArg args(env, info);
    GetBundleNameByUidCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetBundleNameByUidCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetBundleNameByUidCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->uid);
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetBundleNameByUidCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_NAME_BY_UID, GetBundleNameByUidExec, GetBundleNameByUidComplete);
    callbackPtr.release();
    APP_LOGD("call GetBundleNameByUid done");
    return promise;
}

napi_value GetApplicationInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetApplicationInfo called");
    NapiArg args(env, info);
    ApplicationInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<ApplicationInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() < ARGS_SIZE_TWO) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("appId %{public}s invalid!", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags %{public}d invalid!", asyncCallbackInfo->flags);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGE("userId %{public}d invalid!", asyncCallbackInfo->userId);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationInfoCallbackInfo>(
        env, asyncCallbackInfo, GET_APPLICATION_INFO, GetApplicationInfoExec, GetApplicationInfoComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetApplicationInfo done.");
    return promise;
}

napi_value GetApplicationInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetApplicationInfos called");
    NapiArg args(env, info);
    ApplicationInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<ApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() < ARGS_SIZE_ONE) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags %{public}d invalid!", asyncCallbackInfo->flags);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGE("userId %{public}d invalid!", asyncCallbackInfo->userId);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationInfosCallbackInfo>(
        env, asyncCallbackInfo, GET_APPLICATION_INFOS, GetApplicationInfosExec, GetApplicationInfosComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetApplicationInfos done.");
    return promise;
}

static ErrCode InnerQueryAbilityInfos(const Want &want,
    int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->QueryAbilityInfosV9(want, flags, userId, abilityInfos);
    APP_LOGD("QueryAbilityInfosV9 ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerSetApplicationEnabled(const std::string &bundleName, bool &isEnable)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed.");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = bundleMgr->SetApplicationEnabled(bundleName, isEnable);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerIsApplicationEnabled(const std::string &bundleName, bool &isEnable)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed.");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = bundleMgr->IsApplicationEnabled(bundleName, isEnable);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerSetAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed.");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = bundleMgr->SetAbilityEnabled(abilityInfo, isEnable);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerIsAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed.");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = bundleMgr->IsAbilityEnabled(abilityInfo, isEnable);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerGetAbilityLabel(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::string &abilityLabel)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed.");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    ErrCode ret = bundleMgr->GetAbilityLabel(bundleName, moduleName, abilityName, abilityLabel);
    return CommonFunc::ConvertErrCode(ret);
}

#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
static std::shared_ptr<Media::PixelMap> LoadImageFile(const uint8_t *data, size_t len)
{
    APP_LOGD("begin LoadImageFile");
    uint32_t errorCode = 0;
    Media::SourceOptions opts;
    std::unique_ptr<Media::ImageSource> imageSource = Media::ImageSource::CreateImageSource(data, len, opts, errorCode);
    if (errorCode != 0) {
        APP_LOGE("failed to create image source err is %{public}d", errorCode);
        return nullptr;
    }

    Media::DecodeOptions decodeOpts;
    auto pixelMapPtr = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != 0) {
        APP_LOGE("failed to create pixelmap err %{public}d", errorCode);
        return nullptr;
    }
    APP_LOGD("LoadImageFile finish");
    return std::shared_ptr<Media::PixelMap>(std::move(pixelMapPtr));
}

static ErrCode InnerGetAbilityIcon(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::shared_ptr<Media::PixelMap> &pixelMap)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed.");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGE("GetAbilityIcon check param failed.");
        return ERROR_PARAM_CHECK_ERROR;
    }
    std::unique_ptr<uint8_t[]> mediaDataPtr = nullptr;
    size_t len = 0;
    ErrCode ret = bundleMgr->GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, len);
    if (ret != ERR_OK) {
        APP_LOGE("get media data failed");
        return CommonFunc::ConvertErrCode(ret);
    }
    if (mediaDataPtr == nullptr || len == 0) {
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto pixelMapPtr = LoadImageFile(mediaDataPtr.get(), len);
    if (pixelMapPtr == nullptr) {
        APP_LOGE("loadImageFile failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    pixelMap = std::move(pixelMapPtr);
    return SUCCESS;
}
#endif

static void CheckAbilityInfoCache(
    napi_env env, const Query &query, const AbilityCallbackInfo *info, napi_value jsObject)
{
    if (info == nullptr) {
        return;
    }

    ElementName element = info->want.GetElement();
    if (element.GetBundleName().empty() || element.GetAbilityName().empty()) {
        return;
    }

    uint32_t explicitQueryResultLen = 1;
    if (info->abilityInfos.size() != explicitQueryResultLen ||
        info->abilityInfos[0].uid != IPCSkeleton::GetCallingUid()) {
        return;
    }

    napi_ref cacheAbilityInfo = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, jsObject, NAPI_RETURN_ONE, &cacheAbilityInfo));
    cache[query] = cacheAbilityInfo;
}

void QueryAbilityInfosExec(napi_env env, void *data)
{
    AbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    auto item = cache.find(Query(asyncCallbackInfo->want.ToString(),
        QUERY_ABILITY_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
    if (item != cache.end()) {
        asyncCallbackInfo->isSavedInCache = true;
        APP_LOGD("has cache, no need to query from host.");
        return;
    }

    asyncCallbackInfo->err = InnerQueryAbilityInfos(asyncCallbackInfo->want, asyncCallbackInfo->flags,
        asyncCallbackInfo->userId, asyncCallbackInfo->abilityInfos);
}

void QueryAbilityInfosComplete(napi_env env, napi_status status, void *data)
{
    AbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<AbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        if (asyncCallbackInfo->isSavedInCache) {
            auto item = cache.find(Query(asyncCallbackInfo->want.ToString(),
                QUERY_ABILITY_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
            if (item == cache.end()) {
                APP_LOGE("cannot find result in cache in %{public}s", __func__);
                return;
            }
            NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, item->second, &result[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
            CommonFunc::ConvertAbilityInfos(env, asyncCallbackInfo->abilityInfos, result[1]);
            Query query(asyncCallbackInfo->want.ToString(),
                QUERY_ABILITY_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env);
            CheckAbilityInfoCache(env, query, asyncCallbackInfo, result[1]);
        }
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            QUERY_ABILITY_INFOS, BUNDLE_PERMISSIONS);
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

napi_value QueryAbilityInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to QueryAbilityInfos");
    NapiArg args(env, info);
    AbilityCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    std::unique_ptr<AbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            if (!CommonFunc::ParseWantPerformance(env, args[i], asyncCallbackInfo->want)) {
                APP_LOGE("invalid want");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_WANT_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags);
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_number) {
                CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId);
            } else if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            } else {
                APP_LOGE("param check error");
                std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
                return nullptr;
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityCallbackInfo>(
        env, asyncCallbackInfo, QUERY_ABILITY_INFOS, QueryAbilityInfosExec, QueryAbilityInfosComplete);
    callbackPtr.release();
    APP_LOGD("call QueryAbilityInfos done");
    return promise;
}

static ErrCode InnerQueryExtensionInfos(ExtensionCallbackInfo *info)
{
    if (info == nullptr) {
        APP_LOGE("ExtensionCallbackInfo is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (info->extensionAbilityType == static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED)) {
        APP_LOGD("query extensionAbilityInfo without type");
        ret = iBundleMgr->QueryExtensionAbilityInfosV9(info->want, info->flags, info->userId, info->extensionInfos);
    } else {
        ExtensionAbilityType type = static_cast<ExtensionAbilityType>(info->extensionAbilityType);
        APP_LOGD("query extensionAbilityInfo with type %{public}d", info->extensionAbilityType);
        ret = iBundleMgr->QueryExtensionAbilityInfosV9(
            info->want, type, info->flags, info->userId, info->extensionInfos);
    }
    APP_LOGD("QueryExtensionAbilityInfosV9 ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

void QueryExtensionInfosExec(napi_env env, void *data)
{
    ExtensionCallbackInfo *asyncCallbackInfo = reinterpret_cast<ExtensionCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerQueryExtensionInfos(asyncCallbackInfo);
}

void QueryExtensionInfosComplete(napi_env env, napi_status status, void *data)
{
    ExtensionCallbackInfo *asyncCallbackInfo = reinterpret_cast<ExtensionCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<ExtensionCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        CommonFunc::ConvertExtensionInfos(env, asyncCallbackInfo->extensionInfos, result[1]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            QUERY_EXTENSION_INFOS, BUNDLE_PERMISSIONS);
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

napi_value QueryExtensionInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to QueryExtensionInfos");
    NapiArg args(env, info);
    ExtensionCallbackInfo *asyncCallbackInfo = new (std::nothrow) ExtensionCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    std::unique_ptr<ExtensionCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FIVE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            if (!CommonFunc::ParseWant(env, args[i], asyncCallbackInfo->want)) {
                APP_LOGE("invalid want");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_WANT_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->extensionAbilityType);
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags);
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_number) {
                CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId);
            } else if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            } else {
                APP_LOGE("param check error");
                std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
                return nullptr;
            }
        } else if (i == ARGS_POS_FOUR) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ExtensionCallbackInfo>(
        env, asyncCallbackInfo, QUERY_EXTENSION_INFOS, QueryExtensionInfosExec, QueryExtensionInfosComplete);
    callbackPtr.release();
    APP_LOGD("call QueryExtensionInfos done");
    return promise;
}

void CreateAbilityFlagObject(napi_env env, napi_value value)
{
    napi_value nGetAbilityInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), &nGetAbilityInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_DEFAULT",
        nGetAbilityInfoDefault));

    napi_value nGetAbilityInfoWithPermission;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION), &nGetAbilityInfoWithPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_PERMISSION",
        nGetAbilityInfoWithPermission));

    napi_value nGetAbilityInfoWithApplication;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION), &nGetAbilityInfoWithApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_APPLICATION",
        nGetAbilityInfoWithApplication));

    napi_value nGetAbilityInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA), &nGetAbilityInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_METADATA",
        nGetAbilityInfoWithMetadata));

    napi_value nGetAbilityInfoWithDisabled;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE), &nGetAbilityInfoWithDisabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_DISABLE",
        nGetAbilityInfoWithDisabled));

    napi_value nGetAbilityInfOnlySystemApp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP), &nGetAbilityInfOnlySystemApp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_ONLY_SYSTEM_APP",
        nGetAbilityInfOnlySystemApp));
}


void GetAbilityLabelExec(napi_env env, void *data)
{
    AbilityLabelCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityLabelCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerGetAbilityLabel(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->abilityName, asyncCallbackInfo->abilityLabel);
}

void GetAbilityLabelComplete(napi_env env, napi_status status, void *data)
{
    AbilityLabelCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityLabelCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<AbilityLabelCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->abilityLabel.c_str(),
            NAPI_AUTO_LENGTH, &result[1]));
    } else {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, "GetAbilityLabel", Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
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

napi_value GetAbilityLabel(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetAbilityLabel");
#ifdef GLOBAL_RESMGR_ENABLE
    NapiArg args(env, info);
    AbilityLabelCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityLabelCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<AbilityLabelCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("Napi func init failed");
        return nullptr;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->moduleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_TWO], asyncCallbackInfo->abilityName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_NAME, TYPE_STRING);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_FOUR) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_THREE], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_THREE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityLabelCallbackInfo>(
        env, asyncCallbackInfo, "GetAbilityLabel", GetAbilityLabelExec, GetAbilityLabelComplete);
    callbackPtr.release();
    APP_LOGD("call GetAbilityLabel done.");
    return promise;
#else
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "getAbilityLabel");
    napi_throw(env, error);
    return nullptr;
#endif
}

#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
void GetAbilityIconExec(napi_env env, void *data)
{
    AbilityIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerGetAbilityIcon(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->abilityName, asyncCallbackInfo->pixelMap);
}

void GetAbilityIconComplete(napi_env env, napi_status status, void *data)
{
    AbilityIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<AbilityIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        napi_value exports = nullptr;
        Media::PixelMapNapi::Init(env, exports);
        result[1] = Media::PixelMapNapi::CreatePixelMap(env, asyncCallbackInfo->pixelMap);
    } else {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, "GetAbilityIcon", Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
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
#endif

napi_value GetAbilityIcon(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetAbilityIcon");
#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
    NapiArg args(env, info);
    AbilityIconCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityIconCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<AbilityIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("Napi func init failed");
        return nullptr;
    }

    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->moduleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_TWO], asyncCallbackInfo->abilityName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_NAME, TYPE_STRING);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_FOUR) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_THREE], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_THREE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityIconCallbackInfo>(
        env, asyncCallbackInfo, "GetAbilityIcon", GetAbilityIconExec, GetAbilityIconComplete);
    callbackPtr.release();
    APP_LOGD("call GetAbilityIcon done.");
    return promise;
#else
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "getAbilityIcon");
    napi_throw(env, error);
    return nullptr;
#endif
}

void SetApplicationEnabledExec(napi_env env, void *data)
{
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerSetApplicationEnabled(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->isEnable);
}

void SetApplicationEnabledComplete(napi_env env, napi_status status, void *data)
{
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, "SetApplicationEnabled", Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
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

napi_value SetApplicationEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to SetApplicationEnabled");
    NapiArg args(env, info);
    ApplicationEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Napi func init failed");
        return nullptr;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseBool(env, args[ARGS_POS_ONE], asyncCallbackInfo->isEnable)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
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
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationEnableCallbackInfo>(
        env, asyncCallbackInfo, "SetApplicationEnabled", SetApplicationEnabledExec, SetApplicationEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call SetApplicationEnabled done.");
    return promise;
}

void SetAbilityEnabledExec(napi_env env, void *data)
{
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerSetAbilityEnabled(asyncCallbackInfo->abilityInfo,
        asyncCallbackInfo->isEnable);
}

void SetAbilityEnabledComplete(napi_env env, napi_status status, void *data)
{
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, "SetAbilityEnabled", Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
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

napi_value SetAbilityEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to SetAbilityEnabled");
    NapiArg args(env, info);
    AbilityEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseAbilityInfo(env, args[ARGS_POS_ZERO], asyncCallbackInfo->abilityInfo)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
            return nullptr;
        }
        if (!CommonFunc::ParseBool(env, args[ARGS_POS_ONE], asyncCallbackInfo->isEnable)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
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
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityEnableCallbackInfo>(
        env, asyncCallbackInfo, "SetAbilityEnabled", SetAbilityEnabledExec, SetAbilityEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call SetAbilityEnabled done.");
    return promise;
}

void IsApplicationEnabledExec(napi_env env, void *data)
{
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerIsApplicationEnabled(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->isEnable);
}

void IsApplicationEnabledComplete(napi_env env, napi_status status, void *data)
{
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->isEnable, &result[ARGS_POS_ONE]));
    } else {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, "", "");
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ONE]));
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

napi_value IsApplicationEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to IsApplicationEnabled");
    NapiArg args(env, info);
    ApplicationEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_ONE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_POS_TWO) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_ONE], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationEnableCallbackInfo>(
        env, asyncCallbackInfo, "IsSetApplicationEnabled", IsApplicationEnabledExec, IsApplicationEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call IsSetApplicationEnabled done.");
    return promise;
}

void IsAbilityEnabledExec(napi_env env, void *data)
{
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerIsAbilityEnabled(asyncCallbackInfo->abilityInfo,
        asyncCallbackInfo->isEnable);
}

void IsAbilityEnabledComplete(napi_env env, napi_status status, void *data)
{
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->isEnable, &result[ARGS_POS_ONE]));
    } else {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, "", "");
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ONE]));
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

napi_value IsAbilityEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to IsAbilityEnabled");
    NapiArg args(env, info);
    AbilityEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_ONE) {
        if (!CommonFunc::ParseAbilityInfo(env, args[ARGS_POS_ZERO], asyncCallbackInfo->abilityInfo)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
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
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityEnableCallbackInfo>(
        env, asyncCallbackInfo, "IsAbilityEnabled", IsAbilityEnabledExec, IsAbilityEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call SetAbilityEnabled done.");
    return promise;
}

static ErrCode InnerCleanBundleCacheCallback(
    const std::string& bundleName, const OHOS::sptr<CleanCacheCallback>& cleanCacheCallback)
{
    if (cleanCacheCallback == nullptr) {
        APP_LOGE("callback nullptr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode result = iBundleMgr->CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId);
    if (result != ERR_OK) {
        APP_LOGE("CleanBundleDataFiles call error");
    }
    return CommonFunc::ConvertErrCode(result);
}

void CleanBundleCacheFilesExec(napi_env env, void *data)
{
    CleanBundleCacheCallbackInfo* asyncCallbackInfo = reinterpret_cast<CleanBundleCacheCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("error CleanBundleCacheCallbackInfo is nullptr");
        return;
    }
    if (asyncCallbackInfo->cleanCacheCallback == nullptr) {
        asyncCallbackInfo->cleanCacheCallback = new (std::nothrow) CleanCacheCallback();
    }
    asyncCallbackInfo->err =
        InnerCleanBundleCacheCallback(asyncCallbackInfo->bundleName, asyncCallbackInfo->cleanCacheCallback);
}

void CleanBundleCacheFilesComplete(napi_env env, napi_status status, void *data)
{
    CleanBundleCacheCallbackInfo* asyncCallbackInfo = reinterpret_cast<CleanBundleCacheCallbackInfo*>(data);
    std::unique_ptr<CleanBundleCacheCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = { 0 };
    if ((asyncCallbackInfo->err == NO_ERROR) && (asyncCallbackInfo->cleanCacheCallback != nullptr)) {
        // wait for OnCleanCacheFinished
        uv_sem_wait(&(asyncCallbackInfo->cleanCacheCallback->uvSem_));
        asyncCallbackInfo->err = asyncCallbackInfo->cleanCacheCallback->GetErr() ?
            NO_ERROR : ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    // implement callback or promise
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            "CleanBundleCacheFiles", Constants::PERMISSION_REMOVECACHEFILE);
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

napi_value CleanBundleCacheFiles(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to CleanBundleCacheFiles");
    NapiArg args(env, info);
    CleanBundleCacheCallbackInfo *asyncCallbackInfo = new (std::nothrow) CleanBundleCacheCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("CleanBundleCacheFiles asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<CleanBundleCacheCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("CleanBundleCacheFiles napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    if (maxArgc >= ARGS_SIZE_ONE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            APP_LOGE("CleanBundleCacheFiles bundleName is not a string!");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETER_BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (maxArgc >= ARGS_SIZE_TWO) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_ONE], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        APP_LOGE("param error.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<CleanBundleCacheCallbackInfo>(
        env, asyncCallbackInfo, "CleanBundleCacheFiles", CleanBundleCacheFilesExec, CleanBundleCacheFilesComplete);
    callbackPtr.release();
    APP_LOGD("napi call CleanBundleCacheFiles done");
    return promise;
}

static ErrCode InnerGetLaunchWantForBundleExec(
    const std::string& bundleName, Want &want, int32_t userId)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode result = iBundleMgr->GetLaunchWantForBundle(bundleName, want, userId);
    if (result != ERR_OK) {
        APP_LOGE("GetLaunchWantForBundle call error");
    }

    return CommonFunc::ConvertErrCode(result);
}

void GetLaunchWantForBundleExec(napi_env env, void *data)
{
    LaunchWantCallbackInfo* asyncCallbackInfo = reinterpret_cast<LaunchWantCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("error LaunchWantCallbackInfo is nullptr");
        return;
    }

    asyncCallbackInfo->err = InnerGetLaunchWantForBundleExec(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->want, asyncCallbackInfo->userId);
}

void GetLaunchWantForBundleComplete(napi_env env, napi_status status, void *data)
{
    LaunchWantCallbackInfo *asyncCallbackInfo = reinterpret_cast<LaunchWantCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }

    std::unique_ptr<LaunchWantCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        CommonFunc::ConvertWantInfo(env, result[1], asyncCallbackInfo->want);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, GET_LAUNCH_WANT_FOR_BUNDLE,
            BUNDLE_PERMISSIONS);
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

napi_value GetLaunchWantForBundle(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to GetLaunchWantForBundle");
    NapiArg args(env, info);
    LaunchWantCallbackInfo *asyncCallbackInfo = new (std::nothrow) LaunchWantCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("GetLaunchWantForBundle asyncCallbackInfo is null.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    std::unique_ptr<LaunchWantCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("GetLaunchWantForBundle napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    for (size_t i = 0; i < maxArgc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (valueType != napi_string) {
                APP_LOGE("GetLaunchWantForBundle bundleName is not a string!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, STRING_TYPE);
                return nullptr;
            }
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName);
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_number) {
                if (CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId) == nullptr) {
                    BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, NUMBER_TYPE);
                    return nullptr;
                }
            } else if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGE("GetLaunchWantForBundle param check error");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, WRONG_PARAM_TYPE);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGE("GetLaunchWantForBundle param check error");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, CALLBACK, FUNCTION_TYPE);
                return nullptr;
            }
        } else {
            APP_LOGE("GetLaunchWantForBundle arg err!");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<LaunchWantCallbackInfo>(
        env, asyncCallbackInfo, "GetLaunchWantForBundle", GetLaunchWantForBundleExec, GetLaunchWantForBundleComplete);
    callbackPtr.release();
    APP_LOGD("napi call GetLaunchWantForBundle done");
    return promise;
}

ErrCode GetAbilityFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, AbilityInfo& targetAbilityInfo)
{
    bool ifExists = false;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        auto it = find_if(std::begin(hapModuleInfo.abilityInfos),
            std::end(hapModuleInfo.abilityInfos), [abilityName, moduleName](AbilityInfo abilityInfo) {
                return abilityInfo.name == abilityName && abilityInfo.moduleName == moduleName;
            });
        if (it != hapModuleInfo.abilityInfos.end()) {
            ifExists = true;
            targetAbilityInfo = *it;
            break;
        }
        if (ifExists) {
            break;
        }
    }
    if (!ifExists) {
        APP_LOGE("ability not exist");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode GetExtensionFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, ExtensionAbilityInfo& targetExtensionInfo)
{
    bool ifExists = false;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        auto it = find_if(std::begin(hapModuleInfo.extensionInfos),
            std::end(hapModuleInfo.extensionInfos), [abilityName, moduleName](ExtensionAbilityInfo extensionInfo) {
                return extensionInfo.name == abilityName && extensionInfo.moduleName == moduleName;
            });
        if (it != hapModuleInfo.extensionInfos.end()) {
            ifExists = true;
            targetExtensionInfo = *it;
            break;
        }
        if (ifExists) {
            break;
        }
    }
    if (!ifExists) {
        APP_LOGE("ability not exist");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

static ErrCode InnerGetProfile(GetProfileCallbackInfo &info)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    if (info.abilityName.empty()) {
        APP_LOGE("InnerGetProfile failed due to empty abilityName");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }

    if (info.moduleName.empty()) {
        APP_LOGE("InnerGetProfile failed due to empty moduleName");
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA);
    ErrCode result;
    BundleMgrClient client;
    BundleInfo bundleInfo;
    if (info.type == ProfileType::ABILITY_PROFILE) {
        auto getAbilityFlag = baseFlag +
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
        result = iBundleMgr->GetBundleInfoForSelf(getAbilityFlag, bundleInfo);
        if (result != ERR_OK) {
            APP_LOGE("GetBundleInfoForSelf failed");
            return result;
        }
        AbilityInfo targetAbilityInfo;
        result = GetAbilityFromBundleInfo(
            bundleInfo, info.abilityName, info.moduleName, targetAbilityInfo);
        if (result != ERR_OK) {
            return result;
        }
        if (!client.GetProfileFromAbility(targetAbilityInfo, info.metadataName, info.profileVec)) {
            APP_LOGE("GetProfileFromExtension failed");
            return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST;
        }
        return ERR_OK;
    }

    if (info.type == ProfileType::EXTENSION_PROFILE) {
        auto getExtensionFlag = baseFlag +
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY);
        result = iBundleMgr->GetBundleInfoForSelf(getExtensionFlag, bundleInfo);
        if (result != ERR_OK) {
            APP_LOGE("GetBundleInfoForSelf failed");
            return result;
        }

        ExtensionAbilityInfo targetExtensionInfo;
        result = GetExtensionFromBundleInfo(
            bundleInfo, info.abilityName, info.moduleName, targetExtensionInfo);
        if (result != ERR_OK) {
            return result;
        }
        if (!client.GetProfileFromExtension(targetExtensionInfo, info.metadataName, info.profileVec)) {
            APP_LOGE("GetProfileFromExtension failed");
            return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST;
        }
        return ERR_OK;
    }

    APP_LOGE("InnerGetProfile failed due to type is invalid");
    return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
}

void GetProfileExec(napi_env env, void *data)
{
    GetProfileCallbackInfo* asyncCallbackInfo = reinterpret_cast<GetProfileCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("error GetProfileCallbackInfo is nullptr");
        return;
    }

    ErrCode result = InnerGetProfile(*asyncCallbackInfo);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(result);
}

void GetProfileComplete(napi_env env, napi_status status, void *data)
{
    GetProfileCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetProfileCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }

    std::unique_ptr<GetProfileCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        CommonFunc::ConvertStringArrays(env, asyncCallbackInfo->profileVec, result[1]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, "", "");
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

napi_value GetProfile(napi_env env, napi_callback_info info, const ProfileType &profileType)
{
    APP_LOGD("napi begin to GetProfile");
    NapiArg args(env, info);
    GetProfileCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetProfileCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("GetProfile asyncCallbackInfo is null.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    asyncCallbackInfo->type = profileType;
    std::unique_ptr<GetProfileCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_POS_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("GetProfile napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    for (size_t i = 0; i < maxArgc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (valueType != napi_string) {
                APP_LOGE("GetProfile moduleName is not a string!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, STRING_TYPE);
                return nullptr;
            }
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->moduleName);
        } else if (i == ARGS_POS_ONE) {
            if (valueType != napi_string) {
                APP_LOGE("GetProfile abilityName is not a string!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_NAME, STRING_TYPE);
                return nullptr;
            }
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->abilityName);
        } else if (i == ARGS_POS_TWO) {
            if (valueType != napi_string) {
                APP_LOGE("GetProfile metaData name is not a string!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, METADATA_NAME, STRING_TYPE);
                return nullptr;
            }
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->metadataName);
        } else if (i == ARGS_POS_THREE) {
            if (valueType != napi_function) {
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, CALLBACK, FUNCTION_TYPE);
                return nullptr;
            }
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else {
            APP_LOGE("GetProfile arg err!");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetProfileCallbackInfo>(
        env, asyncCallbackInfo, "GetProfile", GetProfileExec, GetProfileComplete);
    callbackPtr.release();
    APP_LOGD("napi call GetProfile done");
    return promise;
}

napi_value GetProfileByAbility(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to GetProfileByAbility");
    return GetProfile(env, info, ProfileType::ABILITY_PROFILE);
}

napi_value GetProfileByExAbility(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to GetProfileByExAbility");
    return GetProfile(env, info, ProfileType::EXTENSION_PROFILE);
}

void CreateExtensionAbilityFlagObject(napi_env env, napi_value value)
{
    napi_value nGetExtensionAbilityInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT), &nGetExtensionAbilityInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_DEFAULT",
        nGetExtensionAbilityInfoDefault));

    napi_value nGetExtensionAbilityInfoWithPermission;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(
            GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION),
            &nGetExtensionAbilityInfoWithPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION",
        nGetExtensionAbilityInfoWithPermission));

    napi_value nGetExtensionAbilityInfoWithApplication;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(
            GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION),
            &nGetExtensionAbilityInfoWithApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION",
        nGetExtensionAbilityInfoWithApplication));

    napi_value nGetExtensionAbilityInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(
            GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA),
            &nGetExtensionAbilityInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_WITH_METADATA",
        nGetExtensionAbilityInfoWithMetadata));
}

void CreateExtensionAbilityTypeObject(napi_env env, napi_value value)
{
    napi_value nForm;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::FORM), &nForm));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FORM", nForm));

    napi_value nWorkSchedule;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::WORK_SCHEDULER), &nWorkSchedule));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WORK_SCHEDULER", nWorkSchedule));

    napi_value nInputMethod;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD), &nInputMethod));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "INPUT_METHOD", nInputMethod));

    napi_value nService;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::SERVICE), &nService));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SERVICE", nService));

    napi_value nAccessibility;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::ACCESSIBILITY), &nAccessibility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ACCESSIBILITY", nAccessibility));

    napi_value nDataShare;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::DATASHARE), &nDataShare));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DATA_SHARE", nDataShare));

    napi_value nFileShare;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::FILESHARE), &nFileShare));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FILE_SHARE", nFileShare));

    napi_value nStaticSubscriber;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::STATICSUBSCRIBER), &nStaticSubscriber));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STATIC_SUBSCRIBER", nStaticSubscriber));

    napi_value nWallpaper;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::WALLPAPER), &nWallpaper));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WALLPAPER", nWallpaper));

    napi_value nBackup;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::BACKUP), &nBackup));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "BACKUP", nBackup));

    napi_value nWindow;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::WINDOW), &nWindow));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WINDOW", nWindow));

    napi_value nEnterpriseAdmin;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::ENTERPRISE_ADMIN), &nEnterpriseAdmin));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ENTERPRISE_ADMIN", nEnterpriseAdmin));

    napi_value nTHUMBNAIL;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::THUMBNAIL), &nTHUMBNAIL));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "THUMBNAIL", nTHUMBNAIL));

    napi_value nPREVIEW;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::PREVIEW), &nPREVIEW));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PREVIEW", nPREVIEW));

    napi_value nUnspecified;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED), &nUnspecified));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNSPECIFIED", nUnspecified));
}

void CreateApplicationFlagObject(napi_env env, napi_value value)
{
    napi_value nGetApplicationInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), &nGetApplicationInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_DEFAULT",
        nGetApplicationInfoDefault));

    napi_value nGetApplicationInfoWithPermission;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION), &nGetApplicationInfoWithPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_WITH_PERMISSION",
        nGetApplicationInfoWithPermission));

    napi_value nGetApplicationInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA), &nGetApplicationInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_WITH_METADATA",
        nGetApplicationInfoWithMetadata));

    napi_value nGetApplicationInfoWithDisable;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), &nGetApplicationInfoWithDisable));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_WITH_DISABLE",
        nGetApplicationInfoWithDisable));
}

static ErrCode InnerGetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetPermissionDef(permissionName, permissionDef);
    return CommonFunc::ConvertErrCode(ret);
}

void GetPermissionDefExec(napi_env env, void *data)
{
    AsyncPermissionDefineCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncPermissionDefineCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerGetPermissionDef(asyncCallbackInfo->permissionName,
            asyncCallbackInfo->permissionDef);
    }
}

void GetPermissionDefComplete(napi_env env, napi_status status, void *data)
{
    AsyncPermissionDefineCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncPermissionDefineCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<AsyncPermissionDefineCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertPermissionDef(env, result[ARGS_POS_ONE], asyncCallbackInfo->permissionDef);
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, GET_PERMISSION_DEF, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ONE]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ZERO]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[ARGS_POS_ZERO]), result, &placeHolder));
    }
}

/**
 * Promise and async callback
 */
napi_value GetPermissionDef(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetPermissionDef called");
    NapiArg args(env, info);
    AsyncPermissionDefineCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncPermissionDefineCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<AsyncPermissionDefineCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[i], &valuetype));
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->permissionName)) {
                APP_LOGE("permissionName invalid!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PERMISSION_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valuetype == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("GetPermissionDef extra arg ignored");
            }
        } else {
            APP_LOGE("GetPermissionDef arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<AsyncPermissionDefineCallbackInfo>(
        env, asyncCallbackInfo, "GetPermissionDef", GetPermissionDefExec, GetPermissionDefComplete);
    callbackPtr.release();
    return promise;
}

static void CheckToCache(napi_env env, int32_t uid, int32_t callingUid, const Query &query, napi_value jsObject)
{
    if (uid != callingUid) {
        APP_LOGE("uid %{public}d and callingUid %{public}d not equal", uid, callingUid);
        return;
    }
    APP_LOGD("put applicationInfo to cache");
    napi_ref cacheApplicationInfo = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, jsObject, NAPI_RETURN_ONE, &cacheApplicationInfo));
    cache[query] = cacheApplicationInfo;
}

napi_value GetApplicationInfoSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetApplicationInfoSync call");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], bundleName)) {
                APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], flags)) {
                APP_LOGE("parseInt failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (!CommonFunc::ParseInt(env, args[i], userId)) {
                APP_LOGE("parseInt failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
                return nullptr;
            }
        } else {
            APP_LOGE("parameter is invalid");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    if (bundleName.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_NOT_EXIST, GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    napi_value nApplicationInfo = nullptr;
    auto item = cache.find(Query(bundleName, GET_APPLICATION_INFO, flags, userId, env));
    if (item != cache.end()) {
        APP_LOGD("getApplicationInfo param from cache");
        NAPI_CALL(env,
            napi_get_reference_value(env, item->second, &nApplicationInfo));
        return nApplicationInfo;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return nullptr;
    }
    AppExecFwk::ApplicationInfo appInfo;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetApplicationInfoV9(bundleName, flags, userId, appInfo));
    if (ret != NO_ERROR) {
        APP_LOGE("GetApplicationInfo failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    NAPI_CALL(env, napi_create_object(env, &nApplicationInfo));
    CommonFunc::ConvertApplicationInfo(env, nApplicationInfo, appInfo);
    Query query(bundleName, GET_APPLICATION_INFO, flags, userId, env);
    CheckToCache(env, appInfo.uid, IPCSkeleton::GetCallingUid(), query, nApplicationInfo);
    return nApplicationInfo;
}

napi_value GetBundleInfoSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetBundleInfoSync call");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[i], &valueType));
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], bundleName)) {
                APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], flags)) {
                APP_LOGE("parseInt failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if ((valueType == napi_number) && (!CommonFunc::ParseInt(env, args[i], userId))) {
                APP_LOGE("parseInt failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
                return nullptr;
            }
        } else {
            APP_LOGE("parameter is invalid");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    if (bundleName.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_NOT_EXIST, GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    napi_value nBundleInfo = nullptr;
    auto item = cache.find(Query(bundleName, GET_BUNDLE_INFO, flags, userId, env));
    if (item != cache.end()) {
        APP_LOGD("GetBundleInfo param from cache");
        NAPI_CALL(env,
            napi_get_reference_value(env, item->second, &nBundleInfo));
        return nBundleInfo;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("BundleMgr is null");
        return nullptr;
    }
    BundleInfo bundleInfo;
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->GetBundleInfoV9(bundleName, flags, bundleInfo, userId));
    if (ret != NO_ERROR) {
        APP_LOGE("GetBundleInfo failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    NAPI_CALL(env, napi_create_object(env,  &nBundleInfo));
    CommonFunc::ConvertBundleInfo(env, bundleInfo, nBundleInfo, flags);
    Query query(bundleName, GET_BUNDLE_INFO, flags, userId, env);
    CheckToCache(env, bundleInfo.uid, IPCSkeleton::GetCallingUid(), query, nBundleInfo);
    return nBundleInfo;
}

static ErrCode InnerGetBundleInfos(int32_t flags,
    int32_t userId, std::vector<BundleInfo> &bundleInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetBundleInfosV9(flags, bundleInfos, userId);
    return CommonFunc::ConvertErrCode(ret);
}

void CreateBundleFlagObject(napi_env env, napi_value value)
{
    napi_value nBundleInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT),
        &nBundleInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_DEFAULT",
        nBundleInfoDefault));

    napi_value nGetBundleInfoWithApplication;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION), &nGetBundleInfoWithApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_APPLICATION",
        nGetBundleInfoWithApplication));

    napi_value nGetBundleInfoWithHapModule;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE), &nGetBundleInfoWithHapModule));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_HAP_MODULE",
        nGetBundleInfoWithHapModule));

    napi_value nGetBundleInfoWithAbility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY), &nGetBundleInfoWithAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_ABILITY",
        nGetBundleInfoWithAbility));

    napi_value nGetBundleInfoWithExtensionAbility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY), &nGetBundleInfoWithExtensionAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY",
        nGetBundleInfoWithExtensionAbility));

    napi_value nGetBundleInfoWithRequestedPermission;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION), &nGetBundleInfoWithRequestedPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION",
        nGetBundleInfoWithRequestedPermission));

    napi_value nGetBundleInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), &nGetBundleInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_METADATA",
        nGetBundleInfoWithMetadata));

    napi_value nGetBundleInfoWithDisable;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), &nGetBundleInfoWithDisable));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_DISABLE",
        nGetBundleInfoWithDisable));

    napi_value nGetBundleInfoWithSignatureInfo;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), &nGetBundleInfoWithSignatureInfo));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_SIGNATURE_INFO",
        nGetBundleInfoWithSignatureInfo));
}

static ErrCode InnerGetBundleInfo(const std::string &bundleName, int32_t flags,
    int32_t userId, BundleInfo &bundleInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetBundleInfoV9(bundleName, flags, bundleInfo, userId);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerGetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetBundleInfoForSelf(flags, bundleInfo);
    return CommonFunc::ConvertErrCode(ret);
}

static void ProcessBundleInfos(
    napi_env env, napi_value result, const std::vector<BundleInfo> &bundleInfos, int32_t flags)
{
    if (bundleInfos.size() == 0) {
        APP_LOGD("bundleInfos is null");
        return;
    }
    size_t index = 0;
    for (const auto &item : bundleInfos) {
        APP_LOGD("name{%s}, bundleName{%s} ", item.name.c_str(), item.name.c_str());
        napi_value objBundleInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objBundleInfo));
        CommonFunc::ConvertBundleInfo(env, item, objBundleInfo, flags);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, objBundleInfo));
        index++;
    }
}

void GetBundleInfosComplete(napi_env env, napi_status status, void *data)
{
    BundleInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<BundleInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<BundleInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        ProcessBundleInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->bundleInfos, asyncCallbackInfo->flags);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_BUNDLE_INFOS, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
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
            sizeof(result) / sizeof(result[ARGS_POS_ZERO]), result, &placeHolder));
    }
}

void GetBundleInfoComplete(napi_env env, napi_status status, void *data)
{
    BundleInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<BundleInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<BundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertBundleInfo(env,
            asyncCallbackInfo->bundleInfo, result[ARGS_POS_ONE], asyncCallbackInfo->flags);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
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
            sizeof(result) / sizeof(result[ARGS_POS_ZERO]), result, &placeHolder));
    }
}

void GetBundleInfoExec(napi_env env, void *data)
{
    BundleInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<BundleInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerGetBundleInfo(asyncCallbackInfo->bundleName,
            asyncCallbackInfo->flags, asyncCallbackInfo->userId, asyncCallbackInfo->bundleInfo);
    }
}

void GetBundleInfoForSelfExec(napi_env env, void *data)
{
    BundleInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<BundleInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerGetBundleInfoForSelf(
            asyncCallbackInfo->flags, asyncCallbackInfo->bundleInfo);
    }
}

napi_value GetBundleInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetBundleInfo called");
    NapiArg args(env, info);
    BundleInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) BundleInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<BundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() < ARGS_SIZE_TWO) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("appId %{public}s invalid!", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags %{public}d invalid!", asyncCallbackInfo->flags);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGE("userId %{public}d invalid!", asyncCallbackInfo->userId);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<BundleInfoCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_INFO, GetBundleInfoExec, GetBundleInfoComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetBundleInfo done.");
    return promise;
}

void GetBundleInfosExec(napi_env env, void *data)
{
    BundleInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<BundleInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerGetBundleInfos(asyncCallbackInfo->flags,
        asyncCallbackInfo->userId, asyncCallbackInfo->bundleInfos);
}

napi_value GetBundleInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetBundleInfos called");
    NapiArg args(env, info);
    BundleInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) BundleInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<BundleInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() < ARGS_SIZE_ONE) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags %{public}d invalid!", asyncCallbackInfo->flags);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGE("userId %{public}d invalid!", asyncCallbackInfo->userId);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
                return nullptr;
            }
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<BundleInfosCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_INFOS, GetBundleInfosExec, GetBundleInfosComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetBundleInfos done.");
    return promise;
}

napi_value GetBundleInfoForSelf(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetBundleInfoForSelf called");
    NapiArg args(env, info);
    BundleInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) BundleInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<BundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags invalid!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<BundleInfoCallbackInfo>(
        env, asyncCallbackInfo, "GetBundleInfoForSelf", GetBundleInfoForSelfExec, GetBundleInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetBundleInfoForSelf done.");
    return promise;
}

void CreatePermissionGrantStateObject(napi_env env, napi_value value)
{
    napi_value nPermissionDenied;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, -1, &nPermissionDenied));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PERMISSION_DENIED",
        nPermissionDenied));

    napi_value nPermissionGranted;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &nPermissionGranted));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PERMISSION_GRANTED",
        nPermissionGranted));
}

void CreateAbilityTypeObject(napi_env env, napi_value value)
{
    napi_value nUnknow;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::UNKNOWN), &nUnknow));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNKNOWN", nUnknow));
    napi_value nPage;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::PAGE), &nPage));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PAGE", nPage));
    napi_value nService;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::SERVICE), &nService));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SERVICE", nService));
    napi_value nData;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::DATA), &nData));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DATA", nData));
}

void CreateBundleTypeObject(napi_env env, napi_value value)
{
    napi_value nApp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(BundleType::APP), &nApp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "APP", nApp));
    napi_value nAtomicService;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(BundleType::ATOMIC_SERVICE), &nAtomicService));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ATOMIC_SERVICE", nAtomicService));
}

void CreateDisplayOrientationObject(napi_env env, napi_value value)
{
    napi_value nUnspecified;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::UNSPECIFIED), &nUnspecified));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNSPECIFIED", nUnspecified));
    napi_value nLandscape;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::LANDSCAPE), &nLandscape));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "LANDSCAPE", nLandscape));
    napi_value nPortrait;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::PORTRAIT), &nPortrait));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PORTRAIT", nPortrait));
    napi_value nFollowrecent;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::FOLLOWRECENT), &nFollowrecent));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FOLLOW_RECENT", nFollowrecent));
    napi_value nReverseLandscape;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::LANDSCAPE_INVERTED), &nReverseLandscape));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "LANDSCAPE_INVERTED", nReverseLandscape));
    napi_value nReversePortrait;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::PORTRAIT_INVERTED), &nReversePortrait));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PORTRAIT_INVERTED", nReversePortrait));
    napi_value nAutoRotation;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION), &nAutoRotation));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION", nAutoRotation));
    napi_value nAutoRotationLandscape;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_LANDSCAPE),
            &nAutoRotationLandscape));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION_LANDSCAPE", nAutoRotationLandscape));
    napi_value nAutoRotationPortrait;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_PORTRAIT),
            &nAutoRotationPortrait));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION_PORTRAIT", nAutoRotationPortrait));
    napi_value nAutoRotationRestricted;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_RESTRICTED),
            &nAutoRotationRestricted));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION_RESTRICTED",
        nAutoRotationRestricted));
    napi_value nAutoRotationLandscapeRestricted;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_LANDSCAPE_RESTRICTED),
            &nAutoRotationLandscapeRestricted));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, value, "AUTO_ROTATION_LANDSCAPE_RESTRICTED", nAutoRotationLandscapeRestricted));
    napi_value nAutoRotationPortraitRestricted;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_PORTRAIT_RESTRICTED),
            &nAutoRotationPortraitRestricted));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION_PORTRAIT_RESTRICTED",
        nAutoRotationPortraitRestricted));
    napi_value nLocked;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::LOCKED), &nLocked));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "LOCKED", nLocked));
}

void CreateLaunchTypeObject(napi_env env, napi_value value)
{
    napi_value nSingleton;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::SINGLETON), &nSingleton));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SINGLETON", nSingleton));
    napi_value nStandard;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::STANDARD), &nStandard));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STANDARD", nStandard));
    napi_value nMultiton;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::STANDARD), &nMultiton));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MULTITON", nMultiton));
    napi_value nSpecified;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::SPECIFIED), &nSpecified));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SPECIFIED", nSpecified));
}

void CreateSupportWindowModesObject(napi_env env, napi_value value)
{
    napi_value nFullscreen;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(SupportWindowMode::FULLSCREEN), &nFullscreen));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FULL_SCREEN", nFullscreen));

    napi_value nSplit;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SupportWindowMode::SPLIT), &nSplit));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SPLIT", nSplit));

    napi_value nFloat;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SupportWindowMode::FLOATING), &nFloat));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FLOATING", nFloat));
}

void CreateModuleTypeObject(napi_env env, napi_value value)
{
    napi_value nUnknown;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ModuleType::UNKNOWN), &nUnknown));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNKNOWN", nUnknown));

    napi_value nEntry;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ModuleType::ENTRY), &nEntry));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ENTRY", nEntry));

    napi_value nFeature;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ModuleType::FEATURE), &nFeature));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FEATURE", nFeature));

    napi_value nShared;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ModuleType::SHARED), &nShared));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SHARED", nShared));
}
}
}