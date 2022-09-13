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

void QueryAbilityInfosExec(napi_env env, void *data)
{}

void QueryAbilityInfosComplete(napi_env env, napi_status status, void *data)
{}

napi_value QueryAbilityInfos(napi_env env, napi_callback_info info)
{
    return nullptr;
}

static void ConvertPermissionDef(napi_env env, napi_value result, const PermissionDef &permissionDef)
{
    napi_value nPermissionName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, permissionDef.permissionName.c_str(), NAPI_AUTO_LENGTH, &nPermissionName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "permissionName", nPermissionName));

    napi_value nGrantMode;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, permissionDef.grantMode, &nGrantMode));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "grantMode", nGrantMode));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, permissionDef.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "labelId", nLabelId));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, permissionDef.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "descriptionId", nDescriptionId));
}

static ErrCode InnerGetPermissionDef(napi_env env, const std::string &permissionName, PermissionDef &permissionDef)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    };
    return iBundleMgr->GetPermissionDef(permissionName, permissionDef);
}

void GetPermissionDefExec(napi_env env, void *data)
{
    AsyncPermissionDefineCallbackInfo *asyncCallbackInfo = static_cast<AsyncPermissionDefineCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    if (!asyncCallbackInfo->err) {
        asyncCallbackInfo->err = InnerGetPermissionDef(env, asyncCallbackInfo->permissionName,
            asyncCallbackInfo->permissionDef);
    }
}

void GetPermissionDefComplete(napi_env env, napi_status status, void *data)
{
    AsyncPermissionDefineCallbackInfo *asyncCallbackInfo = static_cast<AsyncPermissionDefineCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<AsyncPermissionDefineCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, CODE_SUCCESS, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        ConvertPermissionDef(env, result[ARGS_POS_ONE], asyncCallbackInfo->permissionDef);
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == ERR_OK) {
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
        BusinessError::ThrowError(env, OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<AsyncPermissionDefineCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[i], &valuetype));
        if ((i == ARGS_POS_ZERO) && (valuetype == napi_string)) {
            if(!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->permissionName)) {
                APP_LOGE("permissionName %{public}s invalid!", asyncCallbackInfo->permissionName.c_str());
                BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
                return nullptr;                
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("GetDisposedStatus extra arg ignored");
            }
        } else {
            APP_LOGE("GetDisposedStatus arg err!");
            BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
            return nullptr;
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<AsyncPermissionDefineCallbackInfo>(
        env, asyncCallbackInfo, "GetPermissionDef", GetPermissionDefExec, GetPermissionDefComplete);
    callbackPtr.release();
    return promise;
}
}
}