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
#include "js_app_control.h"

#include <string>

#include "app_log_wrapper.h"
#include "app_control_interface.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"
#include "disposed_rule.h"
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_common_want.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
namespace {
const std::string PARAM_TYPE_CHECK_ERROR = "param type check error";
const std::string TYPE_WANT = "want";
const std::string PERMISSION_DISPOSED_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
const std::string SET_DISPOSED_STATUS = "SetDisposedStatus";
const std::string GET_DISPOSED_STATUS = "GetDisposedStatus";
const std::string DELETE_DISPOSED_STATUS = "DeleteDisposedStatus";
const std::string SET_DISPOSED_STATUS_SYNC = "SetDisposedStatusSync";
const std::string DELETE_DISPOSED_STATUS_SYNC = "DeleteDisposedStatusSync";
const std::string GET_DISPOSED_STATUS_SYNC = "GetDisposedStatusSync";
const std::string APP_ID = "appId";
const std::string DISPOSED_WANT = "disposedWant";
const std::string DISPOSED_RULE = "disposedRule";
const std::string DISPOSED_RULE_TYPE = "DisposedRule";
}
static OHOS::sptr<OHOS::AppExecFwk::IAppControlMgr> GetAppControlProxy()
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed.");
        return nullptr;
    }
    auto appControlProxy = bundleMgr->GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("GetAppControlProxy failed.");
        return nullptr;
    }
    return appControlProxy;
}

static ErrCode InnerGetDisposedStatus(napi_env, const std::string& appId, Want& disposedWant)
{
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    ErrCode ret = appControlProxy->GetDisposedStatus(appId, disposedWant);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerSetDisposedStatus(napi_env, const std::string& appId, Want& disposedWant)
{
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    ErrCode ret = appControlProxy->SetDisposedStatus(appId, disposedWant);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerDeleteDisposedStatus(napi_env, const std::string& appId)
{
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    ErrCode ret = appControlProxy->DeleteDisposedStatus(appId);
    return CommonFunc::ConvertErrCode(ret);
}

void SetDisposedStatusExec(napi_env env, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerSetDisposedStatus(env, asyncCallbackInfo->appId,
            asyncCallbackInfo->want);
    }
}

void SetDisposedStatusComplete(napi_env env, napi_status status, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("SetDisposedStatus err = %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, SET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
    CommonFunc::NapiReturnDeferred<DisposedStatus>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value SetDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to SetDisposedStatus");
    NapiArg args(env, info);
    DisposedStatus *asyncCallbackInfo = new (std::nothrow) DisposedStatus(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->appId)) {
                APP_LOGE("appId invalid!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
                return nullptr;
            }
            asyncCallbackInfo->err = asyncCallbackInfo->appId.size() == 0 ? ERROR_INVALID_APPID : NO_ERROR;
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseWantWithoutVerification(env, args[i], asyncCallbackInfo->want)) {
                APP_LOGE("disposed want invalid!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, DISPOSED_WANT, TYPE_WANT);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("SetDisposedStatus extra arg ignored");
            }
        } else {
            APP_LOGE("SetDisposedStatus arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DisposedStatus>(
        env, asyncCallbackInfo, "SetDisposedStatus", SetDisposedStatusExec, SetDisposedStatusComplete);
    callbackPtr.release();
    APP_LOGD("call SetDisposedStatus done.");
    return promise;
}

napi_value SetDisposedStatusSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to SetDisposedStatusSync");
    NapiArg args(env, info);
    napi_value nRet;
    napi_get_undefined(env, &nRet);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nRet;
    }
    std::string appId;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], appId)) {
        APP_LOGE("appId %{public}s invalid!", appId.c_str());
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return nRet;
    }
    if (appId.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_INVALID_APPID, SET_DISPOSED_STATUS_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    OHOS::AAFwk::Want want;
    if (!CommonFunc::ParseWantWithoutVerification(env, args[ARGS_POS_ONE], want)) {
        APP_LOGE("want invalid!");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, DISPOSED_WANT, TYPE_WANT);
        return nRet;
    }
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            SET_DISPOSED_STATUS_SYNC);
        napi_throw(env, error);
        return nRet;
    }
    ErrCode ret = appControlProxy->SetDisposedStatus(appId, want);
    ret = CommonFunc::ConvertErrCode(ret);
    if (ret != NO_ERROR) {
        APP_LOGE("SetDisposedStatusSync err = %{public}d", ret);
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, SET_DISPOSED_STATUS_SYNC, PERMISSION_DISPOSED_STATUS);
        napi_throw(env, businessError);
    }
    APP_LOGD("call SetDisposedStatusSync done.");
    return nRet;
}

void DeleteDisposedStatusExec(napi_env env, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerDeleteDisposedStatus(env, asyncCallbackInfo->appId);
    }
}

void DeleteDisposedStatusComplete(napi_env env, napi_status, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("DeleteDisposedStatus err = %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, DELETE_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
    CommonFunc::NapiReturnDeferred<DisposedStatus>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value DeleteDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to DeleteDisposedStatus.");
    NapiArg args(env, info);
    DisposedStatus *asyncCallbackInfo = new (std::nothrow) DisposedStatus(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->appId)) {
                APP_LOGE("appId invalid!");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
                return nullptr;
            }
            if (asyncCallbackInfo->appId.size() == 0) {
                asyncCallbackInfo->err = ERROR_INVALID_APPID;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("DeleteDisposedStatus extra arg ignored");
            }
        } else {
            APP_LOGE("DeleteDisposedStatus arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DisposedStatus>(
        env, asyncCallbackInfo, "DeleteDisposedStatus", DeleteDisposedStatusExec, DeleteDisposedStatusComplete);
    callbackPtr.release();
    APP_LOGD("call DeleteDisposedStatus done.");
    return promise;
}

napi_value DeleteDisposedStatusSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to DeleteDisposedStatusSync.");
    NapiArg args(env, info);
    napi_value nRet;
    napi_get_undefined(env, &nRet);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nRet;
    }
    std::string appId;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], appId)) {
        APP_LOGE("appId %{public}s invalid!", appId.c_str());
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return nRet;
    }
    if (appId.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_INVALID_APPID, DELETE_DISPOSED_STATUS_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            DELETE_DISPOSED_STATUS_SYNC);
        napi_throw(env, error);
        return nRet;
    }
    ErrCode ret = appControlProxy->DeleteDisposedStatus(appId);
    ret = CommonFunc::ConvertErrCode(ret);
    if (ret != NO_ERROR) {
        APP_LOGE("DeleteDisposedStatusSync err = %{public}d", ret);
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, DELETE_DISPOSED_STATUS_SYNC, PERMISSION_DISPOSED_STATUS);
        napi_throw(env, businessError);
    }
    APP_LOGD("call DeleteDisposedStatusSync done.");
    return nRet;
}

void GetDisposedStatusExec(napi_env env, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerGetDisposedStatus(env, asyncCallbackInfo->appId,
            asyncCallbackInfo->want);
    }
}

void GetDisposedStatusComplete(napi_env env, napi_status status, void *data)
{
    DisposedStatus *asyncCallbackInfo = reinterpret_cast<DisposedStatus *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        CommonFunc::ConvertWantInfo(env, result[1], asyncCallbackInfo->want);
    } else {
        APP_LOGE("GetDisposedStatus err = %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, GET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
    CommonFunc::NapiReturnDeferred<DisposedStatus>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetDisposedStatus called");
    NapiArg args(env, info);
    DisposedStatus *asyncCallbackInfo = new (std::nothrow) DisposedStatus(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return nullptr;
    }
    std::unique_ptr<DisposedStatus> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->appId)) {
                APP_LOGE("appId %{public}s invalid!", asyncCallbackInfo->appId.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
                return nullptr;
            }
            if (asyncCallbackInfo->appId.size() == 0) {
                asyncCallbackInfo->err = ERROR_INVALID_APPID;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("GetDisposedStatus extra arg ignored");
            }
        } else {
            APP_LOGE("GetDisposedStatus arg err!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DisposedStatus>(
        env, asyncCallbackInfo, "GetDisposedStatus", GetDisposedStatusExec, GetDisposedStatusComplete);
    callbackPtr.release();
    APP_LOGD("call GetDisposedStatus done.");
    return promise;
}

napi_value GetDisposedStatusSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetDisposedStatusSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string appId;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], appId)) {
        APP_LOGE("appId %{public}s invalid!", appId.c_str());
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return nullptr;
    }
    if (appId.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_INVALID_APPID, GET_DISPOSED_STATUS_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            GET_DISPOSED_STATUS_SYNC);
        napi_throw(env, error);
        return nullptr;
    }
    OHOS::AAFwk::Want disposedWant;
    ErrCode ret = appControlProxy->GetDisposedStatus(appId, disposedWant);
    ret = CommonFunc::ConvertErrCode(ret);
    if (ret != ERR_OK) {
        APP_LOGE("GetDisposedStatusSync failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_DISPOSED_STATUS_SYNC, PERMISSION_DISPOSED_STATUS);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nWant = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nWant));
    CommonFunc::ConvertWantInfo(env, nWant, disposedWant);
    APP_LOGD("call GetDisposedStatusSync done.");
    return nWant;
}

void ConvertRuleInfo(napi_env env, napi_value nRule, const DisposedRule &rule)
{
    napi_value nWant = nullptr;
    if (rule.want != nullptr) {
        nWant = CreateJsWant(env, *rule.want);
    } else {
        napi_create_object(env, &nWant);
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, nRule, "want", nWant));
    napi_value nComponentType;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<int32_t>(rule.componentType), &nComponentType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, nRule, "componentType", nComponentType));
    napi_value nDisposedType;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<int32_t>(rule.disposedType), &nDisposedType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, nRule, "disposedType", nDisposedType));
    napi_value nControlType;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<int32_t>(rule.controlType), &nControlType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, nRule, "controlType", nControlType));

    napi_value nElementList;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nElementList));
    for (size_t idx = 0; idx < rule.elementList.size(); idx++) {
        napi_value nElementName;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nElementName));
        CommonFunc::ConvertElementName(env, nElementName, rule.elementList[idx]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nElementList, idx, nElementName));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, nRule, "elementList", nElementList));
    napi_value nPriority;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, rule.priority, &nPriority));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, nRule, "priority", nPriority));
}

bool ParseDiposedRule(napi_env env, napi_value nRule, DisposedRule &rule)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, nRule, &valueType), false);
    if (valueType != napi_object) {
        APP_LOGW("nRule not object type");
        return false;
    }
    napi_value prop = nullptr;
    napi_get_named_property(env, nRule, TYPE_WANT.c_str(), &prop);
    AAFwk::Want want;
    if (!UnwrapWant(env, prop, want)) {
        APP_LOGW("parse want failed");
        return false;
    }
    rule.want = std::make_shared<AAFwk::Want>(want);
    napi_get_named_property(env, nRule, "componentType", &prop);
    int32_t componentType;
    if (!CommonFunc::ParseInt(env, prop, componentType)) {
        APP_LOGW("componentType parseInt failed");
        return false;
    }
    if (componentType > static_cast<int32_t>(ComponentType::UI_EXTENSION) ||
        componentType < static_cast<int32_t>(ComponentType::UI_ABILITY)) {
        APP_LOGW("componentType not valid");
        return false;
    }
    rule.componentType = static_cast<ComponentType>(componentType);
    napi_get_named_property(env, nRule, "disposedType", &prop);
    int32_t disposedType;
    if (!CommonFunc::ParseInt(env, prop, disposedType)) {
        APP_LOGW("disposedType parseInt failed");
        return false;
    }
    if (disposedType > static_cast<int32_t>(DisposedType::NON_BLOCK) ||
        disposedType < static_cast<int32_t>(DisposedType::BLOCK_APPLICATION)) {
        APP_LOGW("disposedType not valid");
        return false;
    }
    rule.disposedType = static_cast<DisposedType>(disposedType);
    napi_get_named_property(env, nRule, "controlType", &prop);
    int32_t controlType;
    if (!CommonFunc::ParseInt(env, prop, controlType)) {
        APP_LOGW("disposedType parseInt failed");
        return false;
    }
    if (controlType > static_cast<int32_t>(ControlType::DISALLOWED_LIST) ||
        controlType < static_cast<int32_t>(ControlType::ALLOWED_LIST)) {
        APP_LOGW("ControlType not valid");
        return false;
    }
    rule.controlType = static_cast<ControlType>(controlType);

    napi_value nElementList = nullptr;
    napi_get_named_property(env, nRule, "elementList", &nElementList);
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, nElementList, &isArray), false);
    if (!isArray) {
        APP_LOGW("nElementList not array");
        return false;
    }
    uint32_t arrayLength = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, nElementList, &arrayLength), false);
    for (uint32_t j = 0; j < arrayLength; j++) {
        napi_value value = nullptr;
        NAPI_CALL_BASE(env, napi_get_element(env, nElementList, j, &value), false);
        ElementName name;
        if (!CommonFunc::ParseElementName(env, value, name)) {
            APP_LOGW("parse element name failed");
            return false;
        }
        rule.elementList.push_back(name);
    }
    napi_get_named_property(env, nRule, "priority", &prop);
    if (!CommonFunc::ParseInt(env, prop, rule.priority)) {
        APP_LOGW("priority parseInt failed");
        return false;
    }
    return true;
}

napi_value GetDisposedRule(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetDisposedRule called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string appId;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], appId)) {
        APP_LOGE("appId %{public}s invalid!", appId.c_str());
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return nullptr;
    }
    if (appId.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_INVALID_APPID, GET_DISPOSED_STATUS_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            GET_DISPOSED_STATUS_SYNC);
        napi_throw(env, error);
        return nullptr;
    }
    DisposedRule disposedRule;
    ErrCode ret = appControlProxy->GetDisposedRule(appId, disposedRule);
    ret = CommonFunc::ConvertErrCode(ret);
    if (ret != ERR_OK) {
        APP_LOGE("GetDisposedStatusSync failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_DISPOSED_STATUS_SYNC, PERMISSION_DISPOSED_STATUS);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nRule = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nRule));
    ConvertRuleInfo(env, nRule, disposedRule);
    return nRule;
}

napi_value SetDisposedRule(napi_env env, napi_callback_info info)
{
    NapiArg args(env, info);
    napi_value nRet;
    napi_get_undefined(env, &nRet);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nRet;
    }
    std::string appId;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], appId)) {
        APP_LOGE("appId %{public}s invalid!", appId.c_str());
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return nRet;
    }
    if (appId.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_INVALID_APPID, SET_DISPOSED_STATUS_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    DisposedRule rule;
    if (!ParseDiposedRule(env, args[ARGS_POS_ONE], rule)) {
        APP_LOGE("rule invalid!");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, DISPOSED_RULE, DISPOSED_RULE_TYPE);
        return nRet;
    }
    auto appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null.");
        napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            SET_DISPOSED_STATUS_SYNC);
        napi_throw(env, error);
        return nRet;
    }
    ErrCode ret = appControlProxy->SetDisposedRule(appId, rule);
    ret = CommonFunc::ConvertErrCode(ret);
    if (ret != NO_ERROR) {
        APP_LOGE("SetDisposedStatusSync err = %{public}d", ret);
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, SET_DISPOSED_STATUS_SYNC, PERMISSION_DISPOSED_STATUS);
        napi_throw(env, businessError);
    }
    return nRet;
}

void CreateComponentType(napi_env env, napi_value value)
{
    napi_value nUiAbilityType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ComponentType::UI_ABILITY),
        &nUiAbilityType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UI_ABILITY",
        nUiAbilityType));
    napi_value nExtensionAbilityType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ComponentType::UI_EXTENSION),
        &nExtensionAbilityType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UI_EXTENSION",
        nExtensionAbilityType));
}

void CreateDisposedType(napi_env env, napi_value value)
{
    napi_value nBlockApplication;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(DisposedType::BLOCK_APPLICATION),
        &nBlockApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "BLOCK_APPLICATION",
        nBlockApplication));
    napi_value nBlockAbility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(DisposedType::BLOCK_ABILITY),
        &nBlockAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "BLOCK_ABILITY",
        nBlockApplication));
    napi_value nNonBlock;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(DisposedType::NON_BLOCK),
        &nNonBlock));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "NON_BLOCK",
        nNonBlock));
}

void CreateControlType(napi_env env, napi_value value)
{
    napi_value nAllowedList;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ControlType::ALLOWED_LIST),
        &nAllowedList));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ALLOWED_LIST",
        nAllowedList));
    napi_value nDisAllowedList;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ControlType::DISALLOWED_LIST),
        &nDisAllowedList));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DISALLOWED_LIST",
        nDisAllowedList));
}
}
}