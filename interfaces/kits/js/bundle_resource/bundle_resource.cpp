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

#include "bundle_resource.h"

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_resource_client.h"
#include "business_error.h"
#include "common_func.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* LABEL = "label";
constexpr const char* ICON = "icon";
constexpr const char* PERMISSION_GET_BUNDLE_RESOURCES = "ohos.permission.GET_BUNDLE_RESOURCES";
constexpr const char* GET_BUNDLE_RESOURCE_INFO = "GetBundleResourceInfo";
constexpr const char* GET_LAUNCHER_ABILITY_RESOURCE_INFO = "GetLauncherAbilityResourceInfo";

static void ConvertBundleResourceInfo(
    napi_env env,
    const BundleResourceInfo &bundleResourceInfo,
    napi_value objBundleResourceInfo)
{
    APP_LOGD("start");
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, bundleResourceInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleResourceInfo, BUNDLE_NAME, nBundleName));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, bundleResourceInfo.label.c_str(),
        NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleResourceInfo, LABEL, nLabel));

    napi_value nIcon;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, bundleResourceInfo.icon.c_str(),
        NAPI_AUTO_LENGTH, &nIcon));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleResourceInfo, ICON, nIcon));
    APP_LOGD("end");
}

static void ConvertLauncherAbilityResourceInfo(
    napi_env env,
    const LauncherAbilityResourceInfo &launcherAbilityResourceInfo,
    napi_value objLauncherAbilityResourceInfo)
{
    APP_LOGD("start");
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, launcherAbilityResourceInfo.bundleName.c_str(),
        NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objLauncherAbilityResourceInfo,
        BUNDLE_NAME, nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, launcherAbilityResourceInfo.moduleName.c_str(),
        NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objLauncherAbilityResourceInfo,
        MODULE_NAME, nModuleName));

    napi_value nAbilityName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, launcherAbilityResourceInfo.abilityName.c_str(),
        NAPI_AUTO_LENGTH, &nAbilityName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objLauncherAbilityResourceInfo,
        ABILITY_NAME, nAbilityName));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, launcherAbilityResourceInfo.label.c_str(),
        NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objLauncherAbilityResourceInfo,
        LABEL, nLabel));

    napi_value nIcon;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, launcherAbilityResourceInfo.icon.c_str(),
        NAPI_AUTO_LENGTH, &nIcon));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objLauncherAbilityResourceInfo,
        ICON, nIcon));
    APP_LOGD("end");
}

static void ConvertLauncherAbilityResourceInfos(
    napi_env env,
    const std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos,
    napi_value objLauncherAbilityResourceInfos)
{
    for (size_t index = 0; index < launcherAbilityResourceInfos.size(); ++index) {
        napi_value objLauncherAbilityResourceInfo = nullptr;
        napi_create_object(env, &objLauncherAbilityResourceInfo);
        ConvertLauncherAbilityResourceInfo(env, launcherAbilityResourceInfos[index], objLauncherAbilityResourceInfo);
        napi_set_element(env, objLauncherAbilityResourceInfos, index, objLauncherAbilityResourceInfo);
    }
}
}

napi_value GetBundleResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t flags = 0;
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], flags)) {
            APP_LOGW("parse flags failed");
        }
    }
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }
    BundleResourceInfo resourceInfo;
    BundleResourceClient client;
    auto ret = CommonFunc::ConvertErrCode(client.GetBundleResourceInfo(bundleName, flags, resourceInfo));
    if (ret != ERR_OK) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_BUNDLE_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nBundleResourceInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nBundleResourceInfo));
    ConvertBundleResourceInfo(env, resourceInfo, nBundleResourceInfo);
    APP_LOGD("NAPI end");
    return nBundleResourceInfo;
}

napi_value GetLauncherAbilityResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t flags = 0;
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], flags)) {
            APP_LOGW("parse flags failed");
        }
    }
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    BundleResourceClient client;
    auto ret = CommonFunc::ConvertErrCode(client.GetLauncherAbilityResourceInfo(bundleName,
        flags, launcherAbilityResourceInfos));
    if (ret != ERR_OK) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_LAUNCHER_ABILITY_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nLauncherAbilityResourceInfos = nullptr;
    NAPI_CALL(env, napi_create_array(env, &nLauncherAbilityResourceInfos));
    ConvertLauncherAbilityResourceInfos(env, launcherAbilityResourceInfos, nLauncherAbilityResourceInfos);
    APP_LOGD("NAPI end");
    return nLauncherAbilityResourceInfos;
}
} // AppExecFwk
} // OHOS
