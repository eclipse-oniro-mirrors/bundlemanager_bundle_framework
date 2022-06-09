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

#include "js_default_app.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t NO_ERROR = 0;
constexpr int32_t PARAM_TYPE_ERROR = 1;

constexpr size_t ARGS_SIZE_ZERO = 0;
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;

constexpr int32_t NAPI_RETURN_ZERO = 0;
constexpr int32_t NAPI_RETURN_ONE = 1;
}

DefaultAppInfo::DefaultAppInfo(napi_env napiEnv)
{
    env = napiEnv;
}

DefaultAppInfo::~DefaultAppInfo()
{
    if (callback) {
        napi_delete_reference(env, callback);
        callback = nullptr;
    }
    if (asyncWork) {
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }
}

static OHOS::sptr<OHOS::AppExecFwk::IDefaultApp> GetDefaultAppProxy()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("systemAbilityManager is null.");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        APP_LOGE("bundleMgrSa is null.");
        return nullptr;
    }
    auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
    if (bundleMgr == nullptr) {
        APP_LOGE("iface_cast failed.");
        return nullptr;
    }
    auto defaultAppProxy = bundleMgr->GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("GetDefaultAppProxy failed.");
        return nullptr;
    }
    return defaultAppProxy;
}


static void ParseString(napi_env env, napi_value value, std::string& result)
{
    size_t size = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        APP_LOGE("napi_get_value_string_utf8 error.");
        return;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + 1), &size) != napi_ok) {
        APP_LOGE("napi_get_value_string_utf8 error");
    }
}

static napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static bool InnerIsDefaultApplication(napi_env env, const std::string& type)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is null.");
        return false;
    }
    return defaultAppProxy->IsDefaultApplication(type);
}

napi_value IsDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to call NAPI IsDefaultApplication.");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGD("argc = [%{public}zu]", argc);
    if (argc > ARGS_SIZE_TWO) {
        APP_LOGE("param count invalid.");
        return WrapVoidToJS(env);
    }
    DefaultAppInfo *asyncCallbackInfo = new (std::nothrow) DefaultAppInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return WrapVoidToJS(env);
    }
    std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};

    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == ARGS_SIZE_ZERO) && (valueType == napi_string)) {
            ParseString(env, argv[i], asyncCallbackInfo->type);
        } else if ((i == ARGS_SIZE_ONE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
        }
    }
    if (argc == ARGS_SIZE_ZERO) {
        APP_LOGE("param is zero.");
        asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env,  &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "IsDefaultApplication", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            if (asyncCallbackInfo->errCode == NO_ERROR) {
                asyncCallbackInfo->result = InnerIsDefaultApplication(env, asyncCallbackInfo->type);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};
            napi_value result[2] = { 0 };
            if (asyncCallbackInfo->errCode != NO_ERROR) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->errCode),
                    &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, "type mismatch",
                    NAPI_AUTO_LENGTH, &result[1]));
            } else {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->result, &result[1]));
            }
            if (asyncCallbackInfo->deferred) {
                if (asyncCallbackInfo->errCode == NO_ERROR) {
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
        },
        (void*)asyncCallbackInfo, &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    APP_LOGD("call IsDefaultApplication done.");
    return promise;
}

napi_value GetDefaultApplication(napi_env env, napi_callback_info info)
{
    return WrapVoidToJS(env);
}

napi_value SetDefaultApplication(napi_env env, napi_callback_info info)
{
    return WrapVoidToJS(env);
}

napi_value ResetDefaultApplication(napi_env env, napi_callback_info info)
{
    return WrapVoidToJS(env);
}
}
}
