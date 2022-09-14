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
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;

static ErrCode InnerQueryAbilityInfos(napi_env env, const Want &want,
    int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return INTERNAL_ERROR;
    }
    ErrCode ret = iBundleMgr->QueryAbilityInfosV9(want, flags, userId, abilityInfos);
    return CommonFunc::ConvertErrCode(ret);
}

void QueryAbilityInfosExec(napi_env env, void *data)
{
    AbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerQueryAbilityInfos(env, asyncCallbackInfo->want, asyncCallbackInfo->flags,
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
        BusinessError::ThrowError(env, OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    std::unique_ptr<AbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            if (!CommonFunc::ParseWant(env, args[i], asyncCallbackInfo->want)) {
                APP_LOGE("invalid want");
                BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, asyncCallbackInfo->flags, args[i]);
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_number) {
                CommonFunc::ParseInt(env, asyncCallbackInfo->userId, args[i]);
            } else if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            } else {
                APP_LOGE("param check error");
                BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_THREE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityCallbackInfo>(
        env, asyncCallbackInfo, "QueryAbilityInfos", QueryAbilityInfosExec, QueryAbilityInfosComplete);
    callbackPtr.release();
    APP_LOGD("call QueryAbilityInfos done");
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

static ErrCode InnerCleanBundleCacheCallback(
    const std::string& bundleName, const OHOS::sptr<CleanCacheCallback>& cleanCacheCallback)
{
    if (cleanCacheCallback == nullptr) {
        APP_LOGE("callback nullptr");
        return INTERNAL_ERROR;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return INTERNAL_ERROR;
    }
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode result = iBundleMgr->CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId);
    if (result != ERR_OK) {
        APP_LOGE("CleanBundleDataFiles call error");
        return result;
    }
    return ERR_OK;
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
        asyncCallbackInfo->err = asyncCallbackInfo->cleanCacheCallback->GetErr() ? NO_ERROR : INTERNAL_ERROR;
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
    APP_LOGI("napi begin to CleanBundleCacheFiles");
    NapiArg args(env, info);
    CleanBundleCacheCallbackInfo *asyncCallbackInfo = new (std::nothrow) CleanBundleCacheCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("CleanBundleCacheFiles asyncCallbackInfo is null.");
        BusinessError::ThrowError(env, OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<CleanBundleCacheCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("CleanBundleCacheFiles napi func init failed");
        BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    for (size_t i = 0; i < maxArgc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("CleanBundleCacheFiles bundleName is not a string!");
                BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
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
            BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<CleanBundleCacheCallbackInfo>(
        env, asyncCallbackInfo, "CleanBundleCacheFiles", CleanBundleCacheFilesExec, CleanBundleCacheFilesComplete);
    callbackPtr.release();
    APP_LOGI("napi call CleanBundleCacheFiles done");
    return promise;
}
}
}