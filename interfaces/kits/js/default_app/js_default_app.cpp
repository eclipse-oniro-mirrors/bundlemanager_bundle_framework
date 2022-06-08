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
constexpr size_t NAPI_ERR_NO_ERROR = 0;
constexpr int32_t INVALID_PARAM = 2;

constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;

constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;

constexpr size_t ARGS_ASYNC_COUNT = 1;
constexpr size_t ARGS_MAX_COUNT = 10;

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

static napi_value WrapUndefinedToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
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

static void IsDefaultApplicationExecute(napi_env env, void* data)
{
    APP_LOGD("NAPI IsDefaultApplicationExecute, worker pool thread execute.");
    DefaultAppInfo* defaultAppInfo = static_cast<DefaultAppInfo*>(data);
    if (defaultAppInfo == nullptr) {
        APP_LOGE("defaultAppInfo is null.");
        return;
    }
    defaultAppInfo->result = InnerIsDefaultApplication(env, defaultAppInfo->type);
}

static void IsDefaultApplicationPromiseComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI IsDefaultApplicationPromiseComplete, main event thread complete.");
    DefaultAppInfo* defaultAppInfo = static_cast<DefaultAppInfo*>(data);
    std::unique_ptr<DefaultAppInfo> callbackPtr {defaultAppInfo};
    napi_value result = nullptr;
    if (defaultAppInfo->errCode == NAPI_ERR_NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, defaultAppInfo->result, &result));
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, defaultAppInfo->deferred, result));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, defaultAppInfo->errCode, &result));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, defaultAppInfo->deferred, result));
    }
    APP_LOGD("NAPI IsDefaultApplicationPromiseComplete, main event thread complete end.");
}

static napi_value IsDefaultApplicationPromise(napi_env env, DefaultAppInfo* defaultAppInfo)
{
    APP_LOGD("%{public}s, promise.", __func__);
    if (defaultAppInfo == nullptr) {
        APP_LOGE("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    defaultAppInfo->deferred = deferred;

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, IsDefaultApplicationExecute,
                       IsDefaultApplicationPromiseComplete, (void *)defaultAppInfo, &defaultAppInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, defaultAppInfo->asyncWork));
    APP_LOGD("%{public}s, promise end.", __func__);
    return promise;
}

static void IsDefaultApplicationAsyncComplete(napi_env env, napi_status status, void* data)
{
    APP_LOGD("NAPI IsDefaultApplicationAsyncComplete, main event thread complete.");
    DefaultAppInfo* defaultAppInfo = static_cast<DefaultAppInfo*>(data);
    std::unique_ptr<DefaultAppInfo> callbackPtr {defaultAppInfo};
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_SIZE_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    if (defaultAppInfo->errCode) {
        napi_create_int32(env, defaultAppInfo->errCode, &result[PARAM0]);
    }

    if (defaultAppInfo->errCode == NAPI_ERR_NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, defaultAppInfo->result, &result[PARAM1]));
    } else {
        result[PARAM1] = WrapUndefinedToJS(env);
    }

    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, defaultAppInfo->callback, &callback));
    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, undefined, callback, sizeof(result) / sizeof(result[PARAM0]), result, &callResult));
    APP_LOGD("NAPI IsDefaultApplicationAsyncComplete, main event thread complete end.");
}

static napi_value IsDefaultApplicationAsync(
    napi_env env, napi_value *args, const size_t argCallback, DefaultAppInfo* defaultAppInfo)
{
    APP_LOGD("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || defaultAppInfo == nullptr) {
        APP_LOGE("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], NAPI_RETURN_ONE, &defaultAppInfo->callback));
    } else {
        return nullptr;
    }

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, IsDefaultApplicationExecute,
                       IsDefaultApplicationAsyncComplete, (void *)defaultAppInfo, &defaultAppInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, defaultAppInfo->asyncWork));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    APP_LOGD("%{public}s, asyncCallback end.", __func__);
    return result;
}

static napi_value IsDefaultApplicationWrap(napi_env env, napi_callback_info info, DefaultAppInfo* defaultAppInfo)
{
    APP_LOGD("%{public}s, IsDefaultApplicationWrap begin.", __func__);
    if (defaultAppInfo == nullptr) {
        APP_LOGE("%{public}s, defaultAppInfo == nullptr.", __func__);
        return nullptr;
    }
    size_t argcAsync = ARGS_SIZE_TWO;
    const size_t argcPromise = ARGS_SIZE_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        APP_LOGE("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, args[PARAM0], &valueType);
    if (valueType == napi_string) {
        ParseString(env, args[PARAM0], defaultAppInfo->type);
    } else {
        defaultAppInfo->errCode = INVALID_PARAM;
        defaultAppInfo->errMsg = "type misMatch";
    }

    if (argcAsync > argcPromise) {
        ret = IsDefaultApplicationAsync(env, args, argcAsync - 1, defaultAppInfo);
    } else {
        ret = IsDefaultApplicationPromise(env, defaultAppInfo);
    }
    APP_LOGD("%{public}s, IsDefaultApplicationWrap end.", __func__);
    return ret;
}

napi_value IsDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to call NAPI IsDefaultApplication.");
    DefaultAppInfo* defaultAppInfo = new (std::nothrow) DefaultAppInfo(env);
    if (defaultAppInfo == nullptr) {
        APP_LOGE("defaultAppInfo is null.");
        return WrapVoidToJS(env);
    }
    std::unique_ptr<DefaultAppInfo> callbackPtr {defaultAppInfo};
    napi_value ret = IsDefaultApplicationWrap(env, info, defaultAppInfo);

    if (ret == nullptr) {
        APP_LOGE("ret is null.");
        ret = WrapVoidToJS(env);
    } else {
        callbackPtr.release();
    }
    APP_LOGD("call IsDefaultApplication done.");
    return ret;
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