/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "service_router_mgr.h"

#include <string>

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "common_func.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "service_router_mgr_helper.h"
#include "service_router_mgr_interface.h"
#include "service_router_mgr_proxy.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
namespace {
const std::string PARAM_TYPE_CHECK_ERROR = "param type check error";
const std::string TYPE_BUSINESS_AIBILITY_FILTER = "businessAbilityFilter";
const std::string QUERY_BUSINESS_ABILITY_INFO = "queryBusinessAbilityInfo";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* NAME = "name";
constexpr const char* BUSINESS_TYPE = "businessType";
constexpr const char* MIME_TYPE = "mimeType";
constexpr const char* URI = "uri";
constexpr const char* LABEL_ID = "labelId";
constexpr const char* DESCRIPTION_ID = "descriptionId";
constexpr const char* ICON_ID = "iconId";
constexpr const char* APPLICATION_INFO = "applicationInfo";
}

static void ConvertAppInfo(napi_env env, napi_value objAppInfo, const AppInfo &appInfo)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, NAME, nName));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, appInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, DESCRIPTION_ID, nDescriptionId));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, appInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, LABEL_ID, nLabelId));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, appInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, ICON_ID, nIconId));
}

static void ConvertBusinessAbilityInfo(napi_env env, const BusinessAbilityInfo &businessAbilityInfo, napi_value objAbilityInfo)
{
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, businessAbilityInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, BUNDLE_NAME, nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, businessAbilityInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, MODULE_NAME, nModuleName));

    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, businessAbilityInfo.abilityName.c_str(), NAPI_AUTO_LENGTH,
        &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, NAME, nName));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, businessAbilityInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, LABEL_ID, nLabelId));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, businessAbilityInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, DESCRIPTION_ID, nDescriptionId));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, businessAbilityInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, ICON_ID, nIconId));

    napi_value nBusinessType;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(businessAbilityInfo.businessType), &nBusinessType));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, objAbilityInfo, BUSINESS_TYPE, nBusinessType));

    napi_value nAppInfo;
    if (!businessAbilityInfo.appInfo.bundleName.empty()) {
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nAppInfo));
        ConvertAppInfo(env, nAppInfo, businessAbilityInfo.appInfo);
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &nAppInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, APPLICATION_INFO, nAppInfo));
}

static void ConvertBusinessAbilityInfos(napi_env env, const std::vector<BusinessAbilityInfo> &businessAbilityInfos,
    napi_value value)
{
    for (size_t index = 0; index < businessAbilityInfos.size(); ++index) {
        napi_value objAbilityInfo = nullptr;
        napi_create_object(env, &objAbilityInfo);
        ConvertBusinessAbilityInfo(env, businessAbilityInfos[index], objAbilityInfo);
        napi_set_element(env, value, index, objAbilityInfo);
    }
}

static ErrCode InnerQueryBusinessAbilityInfos(AbilityInfosCallbackInfo *info)
{
    if (info == nullptr) {
        APP_LOGE("CallbackInfo is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    if (serviceRouterMgr == nullptr) {
        APP_LOGE("can not get serviceRouterMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    auto ret = serviceRouterMgr->QueryBusinessAbilityInfos(info->filter, info->businessAbilityInfos);
    APP_LOGI("InnerQueryBusinessAbilityInfos ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

void QueryBusinessAbilityInfosExec(napi_env env, void *data)
{
    APP_LOGD("QueryServiceInfosExec start");
    AbilityInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityInfosCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerQueryBusinessAbilityInfos(asyncCallbackInfo);
}

void QueryBusinessAbilityInfosComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("QueryBusinessAbilityInfosComplete start");
    AbilityInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityInfosCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<AbilityInfosCallbackInfo> callbackPtr{asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        ConvertBusinessAbilityInfos(env, asyncCallbackInfo->businessAbilityInfos, result[1]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            QUERY_BUSINESS_ABILITY_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
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

bool ParseBusinessAbilityInfo(napi_env env, napi_value args, BusinessAbilityFilter &filter)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        return false;
    }
    napi_value prop = nullptr;
    int32_t businessType = static_cast<int32_t>(BusinessType::UNSPECIFIED);
    napi_get_named_property(env, args, BUSINESS_TYPE, &prop);
    napi_typeof(env, prop, &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, prop, &businessType);
    }

    prop = nullptr;
    napi_get_named_property(env, args, MIME_TYPE, &prop);
    std::string mimeType = CommonFunc::GetStringFromNAPI(env, prop);
    prop = nullptr;
    napi_get_named_property(env, args, URI, &prop);
    std::string uri = CommonFunc::GetStringFromNAPI(env, prop);
    
    filter.businessType = static_cast<BusinessType>(businessType);
    filter.mimeType = mimeType;
    filter.uri = uri;
    return true;
}

napi_value QueryBusinessAbilityInfos(napi_env env, napi_callback_info info)
{
    APP_LOGI("NAPI_QueryServiceInfos start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    AbilityInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AbilityInfosCallbackInfo> callbackPtr{asyncCallbackInfo};
    if (args.GetMaxArgc() >= ARGS_SIZE_ONE) {
        if (!ParseBusinessAbilityInfo(env, args[ARGS_POS_ZERO], asyncCallbackInfo->filter)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, TYPE_BUSINESS_AIBILITY_FILTER, TYPE_STRING);
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
        APP_LOGE("parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityInfosCallbackInfo>(
        env, asyncCallbackInfo, QUERY_BUSINESS_ABILITY_INFO, QueryBusinessAbilityInfosExec, QueryBusinessAbilityInfosComplete);
    callbackPtr.release();
    return promise;
}
} // AppExecFwk
} // OHOS