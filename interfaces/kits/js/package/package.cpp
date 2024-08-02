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
#include "package.h"
#include <string>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_host.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "securec.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
namespace {
constexpr int8_t NAPI_RETURN_ZERO = 0;
constexpr uint8_t ARGS_SIZE_ONE = 1;
constexpr uint8_t ARGS_SIZE_TWO = 2;
constexpr int32_t PARAM0 = 0;
constexpr int8_t PARAM1 = 1;
constexpr int8_t NAPI_RETURN_ONE = 1;
constexpr int8_t INVALID_PARAM = 2;
constexpr int16_t INVALID_NUMBER = 202;
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* COMPLETE = "complete";
constexpr const char* FAIL = "fail";
constexpr const char* SUCCESS = "success";
}

CheckPackageHasInstalledOptions::~CheckPackageHasInstalledOptions()
{
    if (successRef) {
        APP_LOGD("CheckPackageHasInstalledOptions::~CheckPackageHasInstalledOptions delete successRef");
        napi_delete_reference(env, successRef);
        successRef = nullptr;
    }
    if (failRef) {
        APP_LOGD("CheckPackageHasInstalledOptions::~CheckPackageHasInstalledOptions delete failRef");
        napi_delete_reference(env, failRef);
        failRef = nullptr;
    }
    if (completeRef) {
        APP_LOGD("CheckPackageHasInstalledOptions::~CheckPackageHasInstalledOptions delete completeRef");
        napi_delete_reference(env, completeRef);
        completeRef = nullptr;
    }
    if (asyncWork) {
        APP_LOGD("CheckPackageHasInstalledOptions::~CheckPackageHasInstalledOptions delete callbackRef");
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }
}

static OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgr()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("GetBundleMgr GetSystemAbilityManager is null");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        APP_LOGE("GetBundleMgr GetSystemAbility is null");
        return nullptr;
    }
    auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
    if (bundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr iface_cast get null");
    }
    return bundleMgr;
}

static std::string GetStringFromNAPI(napi_env env, napi_value value)
{
    std::string result;
    size_t size = 0;

    if (napi_get_value_string_utf8(env, value, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        APP_LOGE("can not get string size");
        return "";
    }
    result.reserve(size + NAPI_RETURN_ONE);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + NAPI_RETURN_ONE), &size) != napi_ok) {
        APP_LOGE("can not get string value");
        return "";
    }
    return result;
}

static void ParseCheckPackageHasInstalledOptions(napi_env env, napi_value param,
    OHOS::AppExecFwk::CheckPackageHasInstalledOptions *hasInstalledOptions)
{
    if (hasInstalledOptions == nullptr) {
        APP_LOGW("hasInstalledOptions is nullptr");
        return;
    }
    napi_valuetype valueType;
    napi_value prop = nullptr;
    // parse bundleName
    napi_get_named_property(env, param, BUNDLE_NAME, &prop);
    napi_typeof(env, prop, &valueType);
    hasInstalledOptions->isString = false;
    if (valueType == napi_string) {
        hasInstalledOptions->bundleName = GetStringFromNAPI(env, prop);
        hasInstalledOptions->isString = true;
    }
    // parse success function
    napi_value jsFunc = nullptr;
    napi_ref jsFuncRef = nullptr;
    napi_get_named_property(env, param, SUCCESS, &jsFunc);
    napi_typeof(env, jsFunc, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, jsFunc, NAPI_RETURN_ONE, &jsFuncRef);
        hasInstalledOptions->successRef = jsFuncRef;
    }
    // parse fail function
    napi_get_named_property(env, param, FAIL, &jsFunc);
    napi_typeof(env, jsFunc, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, jsFunc, NAPI_RETURN_ONE, &jsFuncRef);
        hasInstalledOptions->failRef = jsFuncRef;
    }
    // parse complete function
    napi_get_named_property(env, param, COMPLETE, &jsFunc);
    napi_typeof(env, jsFunc, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, jsFunc, NAPI_RETURN_ONE, &jsFuncRef);
        hasInstalledOptions->completeRef = jsFuncRef;
    }
}

static bool InnerHasInstalled(std::string bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("bundleName is invalid param");
        return false;
    }
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    BundleInfo bundleInfo;
    bool ret = iBundleMgr->GetBundleInfo(bundleName, 0, bundleInfo);
    if (!ret) {
        APP_LOGE("bundleInfo is not find, bundleName=%{public}s", bundleName.c_str());
    }
    return ret;
}

static void ConvertCheckPackageHasInstalledResponse(napi_env env, napi_value hasInstalledResponseObj,
    const OHOS::AppExecFwk::CheckPackageHasInstalledResponse &response)
{
    APP_LOGD("convert CheckPackageHasInstalledResponse start");
    napi_value nResult;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, response.result, &nResult));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, hasInstalledResponseObj, "result", nResult));
}

static void HasInstalledExecute(napi_env env, void *data)
{
    APP_LOGD("NAPI_HasInstalled, worker pool thread execute");
    CheckPackageHasInstalledOptions *asyncCallbackInfo = static_cast<CheckPackageHasInstalledOptions *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("NAPI_HasInstalled, asyncCallbackInfo == nullptr");
        return;
    }
    if (!asyncCallbackInfo->errCode && asyncCallbackInfo->isString && asyncCallbackInfo->successRef) {
        asyncCallbackInfo->response.result = InnerHasInstalled(asyncCallbackInfo->bundleName);
    }
    APP_LOGD("NAPI_HasInstalled, worker pool thread execute end");
}

static void HasInstalledAsyncComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI_HasInstalled, main event thread complete");
    CheckPackageHasInstalledOptions *asyncCallbackInfo = static_cast<CheckPackageHasInstalledOptions *>(data);
    std::unique_ptr<CheckPackageHasInstalledOptions> callbackPtr {asyncCallbackInfo};
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("NAPI_HasInstalled, asyncCallbackInfo == nullptr");
        return;
    }
    napi_value callback = nullptr;
    napi_value placeHolder = nullptr;
    if (!asyncCallbackInfo->isString) {
        if (asyncCallbackInfo->failRef) {
            napi_value result[ARGS_SIZE_TWO] = { 0 };
            NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, "value is not an available number",
                NAPI_AUTO_LENGTH, &result[PARAM0]));
            NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, INVALID_NUMBER, &result[PARAM1]));
            NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->failRef, &callback));
            napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, result, &placeHolder);
        }
    } else {
        if (asyncCallbackInfo->successRef) {
            napi_value result[ARGS_SIZE_ONE] = { 0 };
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[PARAM0]));
            ConvertCheckPackageHasInstalledResponse(env, result[PARAM0], asyncCallbackInfo->response);
            NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->successRef, &callback));
            napi_call_function(env, nullptr, callback, ARGS_SIZE_ONE, result, &placeHolder);
        }
    }
    if (asyncCallbackInfo->completeRef) {
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->completeRef, &callback));
        napi_call_function(env, nullptr, callback, 0, nullptr, &placeHolder);
    }
    APP_LOGD("NAPI_HasInstalled, main event thread complete end");
}

napi_value HasInstalled(napi_env env, napi_callback_info info)
{
    APP_LOGD("asyncCallback");
    size_t requireArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    if (argc != requireArgc) {
        APP_LOGW("requires 1 parameter");
        return nullptr;
    }

    CheckPackageHasInstalledOptions *asyncCallbackInfo = new (std::nothrow) CheckPackageHasInstalledOptions();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<CheckPackageHasInstalledOptions> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->env = env;
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valueType));
    if (valueType == napi_object) {
        ParseCheckPackageHasInstalledOptions(env, argv[PARAM0], asyncCallbackInfo);
    } else {
        asyncCallbackInfo->errCode = INVALID_PARAM;
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "JSHasInstalled", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, HasInstalledExecute,
                       HasInstalledAsyncComplete, (void *)asyncCallbackInfo, &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    return nullptr;
}
}  // namespace AppExecFwk
}  // namespace OHOS
