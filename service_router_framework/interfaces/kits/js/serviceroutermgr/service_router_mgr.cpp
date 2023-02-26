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

#include "app_log_wrapper.h"
#include "service_router_mgr_interface.h"
#include "service_router_mgr_proxy.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "appexecfwk_errors.h"
#include "iservice_registry.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
namespace {
const std::string STRING_BUNDLE_NAME = "bundleName";
const std::string PARAM_TYPE_CHECK_ERROR = "param type check error";
const std::string TYPE_WANT = "want";
const std::string QUERY_SERVICE_FLAG = "ServiceInfosFlag";
const std::string QUERY_SERVICE_INFOS = "queryServiceInfos";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* NAME = "name";
constexpr const char* SERVICE_TYPE = "serviceType";
constexpr const char* PERMISSIONS = "permissions";
constexpr const char* LABEL_ID = "labelId";
constexpr const char* DESCRIPTION_ID = "descriptionId";
constexpr const char* ICON_ID = "iconId";
constexpr const char* APPLICATION_INFO = "applicationInfo";
}

static sptr<IServiceRouterManager> GetServiceRouterMgr()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("systemAbilityManager is null.");
        return nullptr;
    }
    auto serviceRouterMgrSa = systemAbilityManager->GetSystemAbility(OHOS::SERVICE_ROUTER_MGR_SERVICE_ID);
    if (serviceRouterMgrSa == nullptr) {
        APP_LOGE("serviceRouterMgrSa is null.");
        return nullptr;
    }
    auto serviceRouterMgr = OHOS::iface_cast<IServiceRouterManager>(serviceRouterMgrSa);
    if (serviceRouterMgr == nullptr) {
        APP_LOGE("iface_cast failed.");
        return nullptr;
    }
    return serviceRouterMgr;
}

static void ConvertAppInfo(napi_env env, napi_value objAppInfo, const AppInfo &appInfo)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
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

static void ConvertServiceInfo(napi_env env, const ServiceInfo &serviceInfo, napi_value objServiceInfo)
{
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, serviceInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objServiceInfo, BUNDLE_NAME, nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, serviceInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objServiceInfo, MODULE_NAME, nModuleName));

    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, serviceInfo.abilityName.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objServiceInfo, NAME, nName));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, serviceInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objServiceInfo, LABEL_ID, nLabelId));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, serviceInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objServiceInfo, DESCRIPTION_ID, nDescriptionId));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, serviceInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objServiceInfo, ICON_ID, nIconId));

    napi_value nServiceType;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(serviceInfo.serviceType), &nServiceType));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, objServiceInfo, SERVICE_TYPE, nServiceType));

    napi_value nPermissions;
    size_t size = serviceInfo.permissions.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nPermissions));
    for (size_t i = 0; i < size; ++i) {
        napi_value permission;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, serviceInfo.permissions[i].c_str(), NAPI_AUTO_LENGTH, &permission));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nPermissions, i, permission));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objServiceInfo, PERMISSIONS, nPermissions));

    napi_value nAppInfo;
    if (!serviceInfo.appInfo.name.empty()) {
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nAppInfo));
        ConvertAppInfo(env, nAppInfo, serviceInfo.appInfo);
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &nAppInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objServiceInfo, APPLICATION_INFO, nAppInfo));
}

static void ConvertServiceInfos(napi_env env, const std::vector<ServiceInfo> &serviceInfos,
    napi_value value)
{
    for (size_t index = 0; index < serviceInfos.size(); ++index) {
        napi_value objServiceInfo = nullptr;
        napi_create_object(env, &objServiceInfo);
        ConvertServiceInfo(env, serviceInfos[index], objServiceInfo);
        napi_set_element(env, value, index, objServiceInfo);
    }
}

static ErrCode InnerQueryServiceInfos(ServiceInfosCallbackInfo *info)
{
    if (info == nullptr) {
        APP_LOGE("ExtensionCallbackInfo is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto serviceRouterMgr = GetServiceRouterMgr();
    if (serviceRouterMgr == nullptr) {
        APP_LOGE("can not get serviceRouterMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ExtensionServiceType type = static_cast<ExtensionServiceType>(info->serviceType);
    auto ret = serviceRouterMgr->QueryServiceInfos(info->want, type, info->serviceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("InnerQueryServiceInfos failed");
    }
    APP_LOGI("InnerQueryServiceInfos ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

void QueryServiceInfosExec(napi_env env, void *data)
{
    APP_LOGE("QueryServiceInfosExec start");
    ServiceInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<ServiceInfosCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerQueryServiceInfos(asyncCallbackInfo);
}

void QueryServiceInfosComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGE("QueryServiceInfosComplete start");
    ServiceInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<ServiceInfosCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<ServiceInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        ConvertServiceInfos(env, asyncCallbackInfo->serviceInfos, result[1]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            QUERY_SERVICE_INFOS, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
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

napi_value QueryServiceInfos(napi_env env, napi_callback_info info)
{
    APP_LOGI("NAPI_QueryServiceInfos start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    ServiceInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) ServiceInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ServiceInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseWantWithoutVerification(env, args[ARGS_POS_ZERO], asyncCallbackInfo->want)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, STRING_BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], asyncCallbackInfo->serviceType)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, QUERY_SERVICE_FLAG, TYPE_NUMBER);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_THREE) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_TWO], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_TWO],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        APP_LOGE("parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ServiceInfosCallbackInfo>(
        env, asyncCallbackInfo, QUERY_SERVICE_INFOS, QueryServiceInfosExec, QueryServiceInfosComplete);
    callbackPtr.release();
    return promise;
}
} // AppExecFwk
} // OHOS