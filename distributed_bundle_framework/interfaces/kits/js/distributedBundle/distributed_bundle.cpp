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
#include "distributed_bundle.h"

#include <mutex>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "distributed_bms_interface.h"
#include "distributed_bms_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "securec.h"
#include "system_ability_definition.h"


namespace OHOS {
namespace AppExecFwk {
namespace {
static ErrCode ConvertErrCode(ErrCode nativeErrCode)
{
    switch (nativeErrCode) {
        case ERR_OK:
            return SUCCESS;
        case ERR_BUNDLE_MANAGER_INVALID_USER_ID:
            return ERROR_INVALID_USER_ID;
        case ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST:
            return ERROR_BUNDLE_NOT_EXIST;
        case ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST:
            return ERROR_MODULE_NOT_EXIST;
        case ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST:
            return ERROR_ABILITY_NOT_EXIST;
        case ERR_BUNDLE_MANAGER_PERMISSION_DENIED:
            return ERROR_PERMISSION_DENIED_ERROR;
        default:
            return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
}

static bool ParseString(napi_env env, napi_value value, std::string& result)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_string) {
        APP_LOGE("ParseString type mismatch!");
        return false;
    }
    size_t size = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        APP_LOGE("napi_get_value_string_utf8 error.");
        return false;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + 1), &size) != napi_ok) {
        APP_LOGE("napi_get_value_string_utf8 error");
        return false;
    }
    return true;
}
static std::mutex distributeBundleMgrMutex;
static OHOS::sptr<OHOS::AppExecFwk::IDistributedBms> GetDistributedBundleMgr()
{
    APP_LOGD("GetDistributedBundleMgr start");
    static sptr<OHOS::AppExecFwk::IDistributedBms> distributeBundleMgr;
    if (distributeBundleMgr == nullptr) {
        std::lock_guard<std::mutex> lock(distributeBundleMgrMutex);
        auto samgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr == nullptr) {
            APP_LOGE("GetDistributedBundleMgr samgr is nullptr");
            return distributeBundleMgr;
        }
        auto remoteObject = samgr->GetSystemAbility(OHOS::DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (remoteObject == nullptr) {
            APP_LOGE("GetDistributedBundleMgr remoteObject is nullptr");
            return distributeBundleMgr;
        }
        distributeBundleMgr = OHOS::iface_cast<IDistributedBms>(remoteObject);
    }
    return distributeBundleMgr;
}

// 570281 参数不匹配
static void ConvertElementName(napi_env env, napi_value objElementName, const ElementName &elementName)
{
    napi_value nDeviceId;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetDeviceID().c_str(), NAPI_AUTO_LENGTH, &nDeviceId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objElementName, "deviceId", nDeviceId));

    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetBundleName().c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objElementName, "bundleName", nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetModuleName().c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objElementName, "moduleName", nModuleName));

    napi_value nAbilityName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetAbilityName().c_str(), NAPI_AUTO_LENGTH, &nAbilityName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objElementName, "abilityName", nAbilityName));
}

static void ConvertRemoteAbilityInfo(
    napi_env env, const RemoteAbilityInfo &remoteAbilityInfo, napi_value objRemoteAbilityInfo)
{
    napi_value objElementName;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objElementName));
    ConvertElementName(env, objElementName, remoteAbilityInfo.elementName);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objRemoteAbilityInfo, "elementName", objElementName));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, remoteAbilityInfo.label.c_str(), NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objRemoteAbilityInfo, "label", nLabel));

    napi_value nIcon;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, remoteAbilityInfo.icon.c_str(), NAPI_AUTO_LENGTH, &nIcon));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objRemoteAbilityInfo, "icon", nIcon));
}

static void ConvertRemoteAbilityInfos(
    napi_env env, const std::vector<RemoteAbilityInfo> &remoteAbilityInfos, napi_value objRemoteAbilityInfos)
{
    if (remoteAbilityInfos.size() == 0) {
        APP_LOGE("ConvertRemoteAbilityInfos remoteAbilityInfos is empty");
        return;
    }
    size_t index = 0;
    for (const auto &remoteAbilityInfo : remoteAbilityInfos) {
        APP_LOGD("remoteAbilityInfo bundleName:%{public}s, abilityName:%{public}s, label:%{public}s",
                 remoteAbilityInfo.elementName.GetBundleName().c_str(),
                 remoteAbilityInfo.elementName.GetAbilityName().c_str(),
                 remoteAbilityInfo.label.c_str());
        napi_value objRemoteAbilityInfo = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objRemoteAbilityInfo));
        ConvertRemoteAbilityInfo(env, objRemoteAbilityInfo, remoteAbilityInfo);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, objRemoteAbilityInfos, index, objRemoteAbilityInfo));
        index++;
    }
}

static bool ParseValueIfExist(napi_env env, napi_value args, const std::string &key, std::string &value)
{
    napi_value prop = nullptr;
    bool hasKey = false;
    napi_has_named_property(env, args, key.c_str(), &hasKey);
    if (hasKey) {
        napi_status status = napi_get_named_property(env, args, key.c_str(), &prop);
        if ((status != napi_ok) || !ParseString(env, prop, value)) {
            APP_LOGE("begin to parse ElementName moduleName failed");
            return false;
        }
    }
    return true;
}

static bool ParseElementName(napi_env env,, napi_value args, OHOS::AppExecFwk::ElementName &elementName)
{
    APP_LOGD("begin to parse ElementName");
    napi_valuetype valueType;
    napi_status status = napi_typeof(env, args, &valueType);
    if ((status != napi_ok)|| (valueType != napi_object)) {
        APP_LOGE("args not object type");
        return false;
    }
    std::string deviceId;
    if (!ParseValueIfExist(env, args, "deviceId", deviceId)) {
        APP_LOGE("begin to parse ElementName deviceId failed");
        return false;
    }
    elementName.SetDeviceID(deviceId);

    napi_value prop = nullptr;
    std::string bundleName;
    status = napi_get_named_property(env, args, "bundleName", &prop);
    if ((status != napi_ok) || !ParseString(env, args, bundleName)) {
        APP_LOGE("begin to parse ElementName bundleName failed");
        return false;
    }
    elementName.SetBundleName(bundleName);

    prop = nullptr;
    status = napi_get_named_property(env, args, "abilityName", &prop);
    std::string abilityName;
    if ((status != napi_ok) || !ParseString(env, args, abilityName)) {
        APP_LOGE("begin to parse ElementName abilityName failed");
        return false;
    }
    elementName.SetAbilityName(abilityName);

    std::string moduleName;
    if (!ParseModuleName(env, args, moduleName)) {
        return false;
    }
    elementName.SetModuleName(moduleName);
    APP_LOGD("parse ElementName end");
    return true;
}

static bool ParseElementNames(napi_env env, napi_value args, std::vector<ElementName> &elementNames)
{
    APP_LOGD("begin to parse ElementNames");
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, args, &isArray), false);
    if (!isArray) {
        APP_LOGE("parseElementNames args not array");
        return false;
    }
    uint32_t arrayLength = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, args, &arrayLength), false);
    APP_LOGD("arrayLength:%{public}d", arrayLength);
    for (uint32_t i = 0; i < arrayLength; i++) {
        napi_value value = nullptr;
        NAPI_CALL_BASE(env, napi_get_element(env, args, i, &value), false);
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
        if (valueType != napi_object) {
            APP_LOGE("array inside not object type");
            elementNames.clear();
            return false;
        }
        ElementName elementName;
        if (!ParseElementName(env, value, elementName)) {
            APP_LOGE("elementNames parse elementName failed");
            return false;
        }
        elementNames.push_back(elementName);
    }
    return true;
}
}

GetRemoteAbilityInfoCallbackInfo::~GetRemoteAbilityInfoCallbackInfo()
{
    if (callbackRef) {
        APP_LOGD("GetRemoteAbilityInfoCallbackInfo::~GetRemoteAbilityInfoCallbackInfo delete callbackRef");
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
    if (asyncWork) {
        APP_LOGD("GetRemoteAbilityInfoCallbackInfo::~GetRemoteAbilityInfoCallbackInfo delete asyncWork");
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }
}

int32_t InnerGetRemoteAbilityInfo(const std::vector<ElementName> &elementNames, const std::string &locale,
    bool isArray, std::vector<RemoteAbilityInfo> &remoteAbilityInfos)
{
    if (elementNames.size() == 0) {
        APP_LOGE("InnerGetRemoteAbilityInfos elementNames is empty");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iDistBundleMgr = GetDistributedBundleMgr();
    if (iDistBundleMgr == nullptr) {
        APP_LOGE("can not get iDistBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    int32_t result;
    if (isArray) {
        result = iDistBundleMgr->GetRemoteAbilityInfos(elementNames, locale, remoteAbilityInfos);
    } else {
        RemoteAbilityInfo remoteAbilityInfo;
        result = iDistBundleMgr->GetRemoteAbilityInfo(elementNames[0], locale, remoteAbilityInfo);
        remoteAbilityInfos.push_back(remoteAbilityInfo);
    }
    if (result != 0) {
        APP_LOGE("InnerGetRemoteAbilityInfo failed");
    }
    return ConvertErrCode(result);
}

void GetRemoteAbilityInfoExec(napi_env env, void *data)
{
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetRemoteAbilityInfoCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetRemoteAbilityInfo(asyncCallbackInfo->elementNames,
        asyncCallbackInfo->local, asyncCallbackInfo->isArray, asyncCallbackInfo->remoteAbilityInfos);
}

void GetRemoteAbilityInfoComplete(napi_env env, napi_status status, void *data)
{
    GetRemoteAbilityInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetRemoteAbilityInfoCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<GetRemoteAbilityInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO];
    if ((asyncCallbackInfo->err == SUCCESS) && !asyncCallbackInfo->remoteAbilityInfos.empty()) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        if (callbackPtr->isArray) {
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_SIZE_ONE]));
            ConvertRemoteAbilityInfos(env, asyncCallbackInfo->remoteAbilityInfos, result[ARGS_SIZE_ONE]);
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_SIZE_ONE]));
            ConvertRemoteAbilityInfo(env, asyncCallbackInfo->remoteAbilityInfos[0], result[ARGS_SIZE_ONE]);
        }
    } else {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == SUCCESS) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_SIZE_ONE]));
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

static napi_value GetRemoteAbilityInfoMethod(napi_env env, GetRemoteAbilityInfoCallbackInfo *asyncCallbackInfo,
    std::string methodName, void (*execFunc)(napi_env, void *), void (*completeFunc)(napi_env, napi_status, void *))
{
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, methodName.c_str(), NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, execFunc, completeFunc,
        (void*)asyncCallbackInfo, &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return promise;
}

static bool ParseElementNames(napi_env env, napi_env argv, GetRemoteAbilityInfoCallbackInfo *asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return false;
    }
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, args, &isArray), false);
    asyncCallbackInfo->isArray = isArray;
    if (isArray) {
        if (ParseElementNames(env, argv, asyncCallbackInfo->elementNames)) {
            return true;
        }
    } else {
        ElementName elementName;
        if (ParseElementName(env, argv, elementName)) {
            asyncCallbackInfo->elementNames.push_back(elementName);
            return true;
        }
    }
    return false;
}

napi_value GetRemoteAbilityInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetRemoteAbilityInfo");
    NapiArg args(env, info);
    GetRemoteAbilityInfoCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) GetRemoteAbilityInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::unique_ptr<GetRemoteAbilityInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            if (!ParseElementNames(env, args[i], asyncCallbackInfo)) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_string)) {
            if (!ParseString(env, asyncCallbackInfo->locale, args[i])) {
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE || i == ARGS_POS_TWO) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callbackRef));
            break;
        } else {
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = GetRemoteAbilityInfoMethod(env, asyncCallbackInfo, "GetRemoteAbilityInfo",
        GetRemoteAbilityInfoExec, GetRemoteAbilityInfoComplete);
    callbackPtr.release();
    APP_LOGD("GetRemoteAbilityInfo end");
    return promise;
}
}  // namespace AppExecFwk
}  // namespace OHOS
