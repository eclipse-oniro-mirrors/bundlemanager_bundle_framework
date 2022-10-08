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
#include "bundle_manager.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "common_func.h"
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include "image_source.h"
#include "pixel_map_napi.h"
#endif
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;

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
        result[ARGS_POS_ZERO] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<GetBundleArchiveInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->hapFilePath)) {
                APP_LOGE("hapFilePath %{public}s invalid!", asyncCallbackInfo->hapFilePath.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
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
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetBundleArchiveInfoCallbackInfo>(
        env, asyncCallbackInfo, "GetBundleArchiveInfo", GetBundleArchiveInfoExec, GetBundleArchiveInfoComplete);
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        CommonFunc::ConvertApplicationInfo(env, result[1], asyncCallbackInfo->appInfo);
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        ProcessApplicationInfos(env, result[1], asyncCallbackInfo->appInfos);
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<GetBundleNameByUidCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
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
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetBundleNameByUidCallbackInfo>(
        env, asyncCallbackInfo, "GetBundleNameByUid", GetBundleNameByUidExec, GetBundleNameByUidComplete);
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<ApplicationInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    int defaultUserId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("appId %{public}s invalid!", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_ONE) {
            if (valueType == napi_number) {
                if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                    APP_LOGE("Falgs %{public}d invalid!", asyncCallbackInfo->flags);
                    BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                }
                if (args.GetArgc() == ARGS_SIZE_TWO) {
                    asyncCallbackInfo->userId = defaultUserId;
                }
            } else {
                APP_LOGE("param check error");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_TWO) {
            if (valueType == napi_number) {
                if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                    APP_LOGE("userId %{public}d invalid!", asyncCallbackInfo->userId);
                    BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                }
            } else if (valueType == napi_function) {
                asyncCallbackInfo->userId = defaultUserId;
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGE("param check error");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_THREE) {
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
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationInfoCallbackInfo>(
        env, asyncCallbackInfo, "GetApplicationInfo", GetApplicationInfoExec, GetApplicationInfoComplete);
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<ApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    int32_t defaultUserId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_number)) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Falgs %{public}d invalid!", asyncCallbackInfo->flags);
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
            if (args.GetArgc() == ARGS_SIZE_ONE) {
                asyncCallbackInfo->userId = defaultUserId;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_number && !CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGE("userId %{public}d invalid!", asyncCallbackInfo->userId);
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            } else if (valueType == napi_function) {
                asyncCallbackInfo->userId = defaultUserId;
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGE("param check error");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
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
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationInfosCallbackInfo>(
        env, asyncCallbackInfo, "GetApplicationInfos", GetApplicationInfosExec, GetApplicationInfosComplete);
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

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
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
    std::unique_ptr<uint8_t[]> mediaDataPtr = nullptr;
    size_t len = 0;
    ErrCode ret = bundleMgr->GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, len);
    if (ret != ERR_OK) {
        APP_LOGE("get media data failed");
        return CommonFunc::ConvertErrCode(ret);
    }
    if (mediaDataPtr == nullptr || len == 0) {
        return ERROR_SYSTEM_IO_OPERATION;
    }
    auto pixelMapPtr = LoadImageFile(mediaDataPtr.get(), len);
    if (pixelMapPtr == nullptr) {
        APP_LOGE("loadImageFile failed");
        return ERROR_SYSTEM_IO_OPERATION;
    }
    pixelMap = std::move(pixelMapPtr);
    return SUCCESS;
}
#endif

void QueryAbilityInfosExec(napi_env env, void *data)
{
    AbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
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
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        CommonFunc::ConvertAbilityInfos(env, asyncCallbackInfo->abilityInfos, result[1]);
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    std::unique_ptr<AbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            if (!CommonFunc::ParseWant(env, args[i], asyncCallbackInfo->want)) {
                APP_LOGE("invalid want");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
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
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_POS_THREE) {
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
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityCallbackInfo>(
        env, asyncCallbackInfo, "QueryAbilityInfos", QueryAbilityInfosExec, QueryAbilityInfosComplete);
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    std::unique_ptr<ExtensionCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            if (!CommonFunc::ParseWant(env, args[i], asyncCallbackInfo->want)) {
                APP_LOGE("invalid want");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
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
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_POS_FOUR) {
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
    auto promise = CommonFunc::AsyncCallNativeMethod<ExtensionCallbackInfo>(
        env, asyncCallbackInfo, "QueryExtensionInfos", QueryExtensionInfosExec, QueryExtensionInfosComplete);
    callbackPtr.release();
    APP_LOGD("call QueryExtensionInfos done");
    return promise;
}

void CreateAbilityFlagObject(napi_env env, napi_value value)
{
    napi_value nGetAbilityInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_ABILITY_INFO_DEFAULT_V9),
        &nGetAbilityInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_DEFAULT",
        nGetAbilityInfoDefault));

    napi_value nGetAbilityInfoWithPermission;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_ABILITY_INFO_WITH_PERMISSION_V9),
        &nGetAbilityInfoWithPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_PERMISSION",
        nGetAbilityInfoWithPermission));

    napi_value nGetAbilityInfoWithApplication;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_ABILITY_INFO_WITH_APPLICATION_V9),
        &nGetAbilityInfoWithApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_APPLICATION",
        nGetAbilityInfoWithApplication));

    napi_value nGetAbilityInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_ABILITY_INFO_WITH_METADATA_V9),
        &nGetAbilityInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_METADATA",
        nGetAbilityInfoWithMetadata));

    napi_value nGetAbilityInfoWithDisabled;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_ABILITY_INFO_WITH_DISABLE_V9),
        &nGetAbilityInfoWithDisabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_DISABLE",
        nGetAbilityInfoWithDisabled));

    napi_value nGetAbilityInfOnlySystemApp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_ABILITY_INFO_ONLY_SYSTEM_APP_V9),
        &nGetAbilityInfOnlySystemApp));
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
    NapiArg args(env, info);
    AbilityLabelCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityLabelCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<AbilityLabelCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("bundleName %{public}s invalid!", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->moduleName)) {
                APP_LOGE("moduleName %{public}s invalid!", asyncCallbackInfo->moduleName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->abilityName)) {
                APP_LOGE("abilityName %{public}s invalid!", asyncCallbackInfo->abilityName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("GetAbilityLabel arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityLabelCallbackInfo>(
        env, asyncCallbackInfo, "GetAbilityLabel", GetAbilityLabelExec, GetAbilityLabelComplete);
    callbackPtr.release();
    APP_LOGD("call GetAbilityLabel done.");
    return promise;
}

void GetAbilityIconExec(napi_env env, void *data)
{
    AbilityIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    asyncCallbackInfo->err = InnerGetAbilityIcon(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->abilityName, asyncCallbackInfo->pixelMap);
#else
    asyncCallbackInfo->err = ERROR_SYSTEM_ABILITY_NOT_FOUND;
#endif
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
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
        napi_value exports = nullptr;
        Media::PixelMapNapi::Init(env, exports);
        result[1] = Media::PixelMapNapi::CreatePixelMap(env, asyncCallbackInfo->pixelMap);
#endif
    } else {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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

napi_value GetAbilityIcon(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetAbilityIcon");
    NapiArg args(env, info);
    AbilityIconCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityIconCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<AbilityIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("bundleName %{public}s invalid!", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->moduleName)) {
                APP_LOGE("moduleName %{public}s invalid!", asyncCallbackInfo->moduleName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->abilityName)) {
                APP_LOGE("abilityName %{public}s invalid!", asyncCallbackInfo->abilityName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("GetAbilityIcon arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityIconCallbackInfo>(
        env, asyncCallbackInfo, "GetAbilityIcon", GetAbilityIconExec, GetAbilityIconComplete);
    callbackPtr.release();
    APP_LOGD("call GetAbilityIcon done.");
    return promise;
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("bundleName %{public}s invalid!", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_boolean)) {
            NAPI_CALL(env, napi_get_value_bool(env, args[i], &asyncCallbackInfo->isEnable));
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            APP_LOGE("SetApplicationEnabled arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            if (!CommonFunc::ParseAbilityInfo(env, args[i], asyncCallbackInfo->abilityInfo)) {
                APP_LOGE("SetAbilityEnabled arg err!");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_boolean)) {
            NAPI_CALL(env, napi_get_value_bool(env, args[i], &asyncCallbackInfo->isEnable));
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            APP_LOGE("SetAbilityEnabled arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
    APP_LOGI("begin to IsSetApplicationEnabled");
    NapiArg args(env, info);
    ApplicationEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("bundleName %{public}s invalid!", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            APP_LOGE("IsSetApplicationEnabled arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            if (!CommonFunc::ParseAbilityInfo(env, args[i], asyncCallbackInfo->abilityInfo)) {
                APP_LOGE("IsAbilityEnabled arg err!");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            APP_LOGE("IsAbilityEnabled arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
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
        asyncCallbackInfo->err = asyncCallbackInfo->cleanCacheCallback->GetErr() ? NO_ERROR : ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    // implement callback or promise
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<CleanBundleCacheCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("CleanBundleCacheFiles napi func init failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    for (size_t i = 0; i < maxArgc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("CleanBundleCacheFiles bundleName is not a string!");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("CleanBundleCacheFiles extra arg ignored");
            }
        } else {
            APP_LOGE("CleanBundleCacheFiles arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }

    std::unique_ptr<LaunchWantCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("GetLaunchWantForBundle napi func init failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    for (size_t i = 0; i < maxArgc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("GetLaunchWantForBundle bundleName is not a string!");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_number) {
                CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId);
            } else if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            } else {
                APP_LOGE("GetLaunchWantForBundle param check error");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGE("GetLaunchWantForBundle param check error");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
            break;
        } else {
            APP_LOGE("GetLaunchWantForBundle arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<LaunchWantCallbackInfo>(
        env, asyncCallbackInfo, "GetLaunchWantForBundle", GetLaunchWantForBundleExec, GetLaunchWantForBundleComplete);
    callbackPtr.release();
    APP_LOGD("napi call GetLaunchWantForBundle done");
    return promise;
}

static ErrCode InnerGetProfile(GetProfileCallbackInfo &info)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    std::string bundleName;
    if (!iBundleMgr->ObtainCallingBundleName(bundleName)) {
        APP_LOGE("InnerGetProfile failed when obtain calling bundelName");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    if (info.abilityName.empty() || info.moduleName.empty()) {
        APP_LOGE("InnerGetProfile failed due to empty abilityName or moduleName");
        return ERROR_PARAM_CHECK_ERROR;
    }

    ErrCode result;
    Want want;
    ElementName elementName("", bundleName, info.abilityName, info.moduleName);
    want.SetElement(elementName);
    BundleMgrClient client;
    if (info.type == ProfileType::ABILITY_PROFILE) {
        std::vector<AbilityInfo> abilityInfos;
        result = iBundleMgr->QueryAbilityInfosV9(
            want, AbilityInfoFlagV9::GET_ABILITY_INFO_WITH_METADATA_V9,
            Constants::UNSPECIFIED_USERID, abilityInfos);
        if (result != ERR_OK) {
            APP_LOGE("QueryExtensionAbilityInfosV9 failed");
            return result;
        }

        if (abilityInfos.empty()) {
            APP_LOGE("extensionInfos empty");
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }

        if (!client.GetProfileFromAbility(abilityInfos[0], info.metadataName, info.profileVec)) {
            APP_LOGE("GetProfileFromExtension failed");
            return ERR_BUNDLE_MANAGER__PROFILE_NOT_EXIST;
        }

        return ERR_OK;
    }

    if (info.type == ProfileType::EXTENSION_PROFILE) {
        std::vector<ExtensionAbilityInfo> extensionInfos;
        result = iBundleMgr->QueryExtensionAbilityInfosV9(want,
            ExtensionAbilityInfoFlagV9::GET_EXTENSION_ABILITY_INFO_WITH_METADATA_V9,
            Constants::UNSPECIFIED_USERID, extensionInfos);
        if (result != ERR_OK) {
            APP_LOGE("QueryExtensionAbilityInfosV9 failed");
            return result;
        }

        if (extensionInfos.empty()) {
            APP_LOGE("extensionInfos empty");
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }

        if (!client.GetProfileFromExtension(extensionInfos[0], info.metadataName, info.profileVec)) {
            APP_LOGE("GetProfileFromExtension failed");
            return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }

    asyncCallbackInfo->type = profileType;
    std::unique_ptr<GetProfileCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_POS_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("GetProfile napi func init failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    for (size_t i = 0; i < maxArgc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->moduleName)) {
                APP_LOGE("GetProfile moduleName is not a string!");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->abilityName)) {
                APP_LOGE("GetProfile abilityName is not a string!");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->metadataName)) {
                APP_LOGE("GetProfile metadataName is not a string!");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else  if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("GetProfile arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
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
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_EXTENSION_ABILITY_INFO_DEFAULT_V9),
        &nGetExtensionAbilityInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_DEFAULT",
        nGetExtensionAbilityInfoDefault));

    napi_value nGetExtensionAbilityInfoWithPermission;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION_V9),
        &nGetExtensionAbilityInfoWithPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION",
        nGetExtensionAbilityInfoWithPermission));

    napi_value nGetExtensionAbilityInfoWithApplication;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION_V9),
        &nGetExtensionAbilityInfoWithApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION",
        nGetExtensionAbilityInfoWithApplication));

    napi_value nGetExtensionAbilityInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(GET_EXTENSION_ABILITY_INFO_WITH_METADATA_V9),
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
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_APPLICATION_INFO_DEFAULT_V9),
        &nGetApplicationInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_DEFAULT",
        nGetApplicationInfoDefault));

    napi_value nGetApplicationInfoWithPermission;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_APPLICATION_INFO_WITH_PERMISSION_V9),
        &nGetApplicationInfoWithPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_WITH_PERMISSION",
        nGetApplicationInfoWithPermission));

    napi_value nGetApplicationInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_APPLICATION_INFO_WITH_METADATA_V9),
        &nGetApplicationInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_WITH_METADATA",
        nGetApplicationInfoWithMetadata));

    napi_value nGetApplicationInfoWithDisable;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_APPLICATION_INFO_WITH_DISABLE_V9),
        &nGetApplicationInfoWithDisable));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_WITH_DISABLE",
        nGetApplicationInfoWithDisable));

    napi_value nGetAllApplicationInfo;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_ALL_APPLICATION_INFO_V9),
        &nGetAllApplicationInfo));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ALL_APPLICATION_INFO",
        nGetAllApplicationInfo));
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
    asyncCallbackInfo->err = InnerGetPermissionDef(asyncCallbackInfo->permissionName,
        asyncCallbackInfo->permissionDef);
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
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<AsyncPermissionDefineCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[i], &valuetype));
        if ((i == ARGS_POS_ZERO) && (valuetype == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->permissionName)) {
                APP_LOGE("permissionName %{public}s invalid!", asyncCallbackInfo->permissionName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
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

void CreateBundleFlagObject(napi_env env, napi_value value)
{
    napi_value nBundleInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_BUNDLE_INFO_DEFAULT_V9),
        &nBundleInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_DEFAULT",
        nBundleInfoDefault));

    napi_value nGetBundleInfoWithApplication;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_BUNDLE_INFO_WITH_APPLICATION_V9),
        &nGetBundleInfoWithApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_APPLICATION",
        nGetBundleInfoWithApplication));

    napi_value nGetBundleInfoWithHapModule;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_BUNDLE_INFO_WITH_HAP_MODULE_V9),
        &nGetBundleInfoWithHapModule));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_HAP_MODULE",
        nGetBundleInfoWithHapModule));

    napi_value nGetBundleInfoWithAbility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_BUNDLE_INFO_WITH_ABILITY_V9),
        &nGetBundleInfoWithAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_ABILITY",
        nGetBundleInfoWithAbility));

    napi_value nGetBundleInfoWithExtensionAbility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY_V9),
        &nGetBundleInfoWithExtensionAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY",
        nGetBundleInfoWithExtensionAbility));

    napi_value nGetBundleInfoWithRequestedPermission;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION_V9), &nGetBundleInfoWithRequestedPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION",
        nGetBundleInfoWithRequestedPermission));

    napi_value nGetBundleInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_BUNDLE_INFO_WITH_METADATA_V9),
        &nGetBundleInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_METADATA",
        nGetBundleInfoWithMetadata));

    napi_value nGetBundleInfoWithDisable;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_BUNDLE_INFO_WITH_DISABLE_V9),
        &nGetBundleInfoWithDisable));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_DISABLE",
        nGetBundleInfoWithDisable));

    napi_value nGetBundleInfoWithSignatureInfo;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GET_BUNDLE_INFO_WITH_SIGNATURE_INFO_V9),
        &nGetBundleInfoWithSignatureInfo));
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
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        CommonFunc::ConvertBundleInfo(env, asyncCallbackInfo->bundleInfo, result[1], asyncCallbackInfo->flags);
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
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

void GetBundleInfoExec(napi_env env, void *data)
{
    BundleInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<BundleInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerGetBundleInfo(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->flags, asyncCallbackInfo->userId, asyncCallbackInfo->bundleInfo);
}

napi_value GetBundleInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetBundleInfo called");
    NapiArg args(env, info);
    BundleInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) BundleInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        BusinessError::ThrowError(env, ERROR_OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<BundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    int defaultUserId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("appId %{public}s invalid!", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_ONE && valueType == napi_number) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Falgs %{public}d invalid!", asyncCallbackInfo->flags);
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            }
            if (args.GetArgc() == ARGS_SIZE_TWO) {
                asyncCallbackInfo->userId = defaultUserId;
            }
        } else if (i == ARGS_SIZE_TWO && valueType == napi_number) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGE("userId %{public}d invalid!", asyncCallbackInfo->userId);
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            }
        } else if (i == ARGS_SIZE_TWO && valueType == napi_function) {
            asyncCallbackInfo->userId = defaultUserId;
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else if (i == ARGS_SIZE_THREE) {
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
    auto promise = CommonFunc::AsyncCallNativeMethod<BundleInfoCallbackInfo>(
        env, asyncCallbackInfo, "GetBundleInfo", GetBundleInfoExec, GetBundleInfoComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetBundleInfo done.");
    return promise;
}
}
}