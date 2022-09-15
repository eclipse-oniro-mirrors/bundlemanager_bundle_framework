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
#include "free_install.h"

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
enum class UpgradeFlag {
    NOT_UPGRADE = 0,
    SINGLE_UPGRADE = 1,
    RELATION_UPGRADE = 2,
};
const std::string RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE = "isHapModuleRemovable";
const std::string RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG = "setHapModuleUpgradeFlag";

}

static ErrCode InnerIsHapModuleRemovable(const std::string &bundleName,
    const std::string &moduleName, bool &isRemovable)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return INTERNAL_ERROR;
    }
    auto result = iBundleMgr->IsModuleRemovable(bundleName, moduleName, isRemovable);
    if (result != ERR_OK) {
        APP_LOGE("InnerIsHapModuleRemovable::IsModuleRemovable failed");
    }
    return result;
}

void IsHapModuleRemovableExec(napi_env env, void *data)
{
    HapModuleRemovableCallbackInfo *asyncCallbackInfo = reinterpret_cast<HapModuleRemovableCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerIsHapModuleRemovable(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->result);
}

void IsHapModuleRemovableComplete(napi_env env, napi_status status, void *data)
{
    HapModuleRemovableCallbackInfo *asyncCallbackInfo = reinterpret_cast<HapModuleRemovableCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<HapModuleRemovableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->result, &result[1]));
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

napi_value IsHapModuleRemovable(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_IsHapModuleRemovable start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    HapModuleRemovableCallbackInfo *asyncCallbackInfo = new (std::nothrow) HapModuleRemovableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        BusinessError::ThrowError(env, OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<HapModuleRemovableCallbackInfo> callbackPtr {asyncCallbackInfo};
    size_t size = args.GetMaxArgc();
    for (size_t i = 0; i < size; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->moduleName)) {
                BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<HapModuleRemovableCallbackInfo>(
        env, asyncCallbackInfo, RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE,
        IsHapModuleRemovableExec, IsHapModuleRemovableComplete);
    callbackPtr.release();
    APP_LOGD("call IsHapModuleRemovable done");
    return promise;
}

static ErrCode InnerSetHapModuleUpgradeFlag(const std::string &bundleName,
    const std::string &moduleName, int32_t upgradeFlag)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return INTERNAL_ERROR;
    }
    auto result = iBundleMgr->SetModuleUpgradeFlag(bundleName, moduleName, upgradeFlag);
    if (result != ERR_OK) {
        APP_LOGE("InnerSetHapModuleUpgradeFlag::SetModuleUpgradeFlag failed");
    }
    return result;
}

void SetHapModuleUpgradeFlagExec(napi_env env, void *data)
{
    SetHapModuleUpgradeFlagCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SetHapModuleUpgradeFlagCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerSetHapModuleUpgradeFlag(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->upgradeFlag);
}

void SetHapModuleUpgradeFlagComplete(napi_env env, napi_status status, void *data)
{
    SetHapModuleUpgradeFlagCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SetHapModuleUpgradeFlagCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<SetHapModuleUpgradeFlagCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
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

napi_value SetHapModuleUpgradeFlag(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_SetHapModuleUpgradeFlag start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    SetHapModuleUpgradeFlagCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) SetHapModuleUpgradeFlagCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        BusinessError::ThrowError(env, OUT_OF_MEMORY_ERROR);
        return nullptr;
    }
    std::unique_ptr<SetHapModuleUpgradeFlagCallbackInfo> callbackPtr {asyncCallbackInfo};
    size_t size = args.GetMaxArgc();
    for (size_t i = 0; i < size; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->moduleName)) {
                BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_number)) {
            if (!CommonFunc::ParseInt(env, asyncCallbackInfo->upgradeFlag, args[i])) {
                BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<SetHapModuleUpgradeFlagCallbackInfo>(
        env, asyncCallbackInfo, RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG,
        SetHapModuleUpgradeFlagExec, SetHapModuleUpgradeFlagComplete);
    callbackPtr.release();
    APP_LOGD("call SetHapModuleUpgradeFlag done");
    return promise;
}

void CreateUpgradeFlagObject(napi_env env, napi_value value)
{
    napi_value nNotUpgrade;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(UpgradeFlag::NOT_UPGRADE), &nNotUpgrade));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "NOT_UPGRADE", nNotUpgrade));

    napi_value nSingleUpgrade;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(UpgradeFlag::SINGLE_UPGRADE), &nSingleUpgrade));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SINGLE_UPGRADE", nSingleUpgrade));

    napi_value nRelationUpgrade;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(UpgradeFlag::RELATION_UPGRADE), &nRelationUpgrade));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "RELATION_UPGRADE", nRelationUpgrade));
}
} // AppExecFwk
} // OHOS