/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_resource_drawable_utils.h"
#include "business_error.h"
#include "common_func.h"
#include "iservice_registry.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "resource_helper.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* LABEL = "label";
constexpr const char* ICON = "icon";
constexpr const char* DRAWABLE_DESCRIPTOR = "drawableDescriptor";
constexpr const char* GET_RESOURCE_INFO_ALL = "GET_RESOURCE_INFO_ALL";
constexpr const char* GET_RESOURCE_INFO_WITH_LABEL = "GET_RESOURCE_INFO_WITH_LABEL";
constexpr const char* GET_RESOURCE_INFO_WITH_ICON = "GET_RESOURCE_INFO_WITH_ICON";
constexpr const char* GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL = "GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL";
constexpr const char* GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR = "GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR";
constexpr const char* GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY = "GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY";

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

    napi_value nDrawableDescriptor = BundleResourceDrawableUtils::ConvertToDrawableDescriptor(
        env, bundleResourceInfo.foreground, bundleResourceInfo.background);
    if (nDrawableDescriptor == nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &nDrawableDescriptor));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleResourceInfo,
        DRAWABLE_DESCRIPTOR, nDrawableDescriptor));

    napi_value nAppIndex;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, bundleResourceInfo.appIndex, &nAppIndex));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleResourceInfo, APP_INDEX, nAppIndex));
    APP_LOGD("end");
}

static void ConvertBundleResourceInfos(
    napi_env env,
    const std::vector<BundleResourceInfo> &bundleResourceInfos,
    napi_value objBundleResourceInfos)
{
    for (size_t index = 0; index < bundleResourceInfos.size(); ++index) {
        napi_value objBundleResourceInfo = nullptr;
        napi_create_object(env, &objBundleResourceInfo);
        ConvertBundleResourceInfo(env, bundleResourceInfos[index], objBundleResourceInfo);
        napi_set_element(env, objBundleResourceInfos, index, objBundleResourceInfo);
    }
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

    napi_value nDrawableDescriptor = BundleResourceDrawableUtils::ConvertToDrawableDescriptor(
        env, launcherAbilityResourceInfo.foreground, launcherAbilityResourceInfo.background);
    if (nDrawableDescriptor == nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &nDrawableDescriptor));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objLauncherAbilityResourceInfo,
        DRAWABLE_DESCRIPTOR, nDrawableDescriptor));

    napi_value nAppIndex;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, launcherAbilityResourceInfo.appIndex, &nAppIndex));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objLauncherAbilityResourceInfo, APP_INDEX, nAppIndex));
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
    APP_LOGI("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName) || bundleName.empty()) {
        APP_LOGE("parse bundleName failed, bundleName is %{public}s", bundleName.c_str());
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
    int32_t appIndex = 0;
    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_TWO], appIndex)) {
            APP_LOGW("parse appIndex failed");
        }
    }
    BundleResourceInfo resourceInfo;
    auto ret = ResourceHelper::InnerGetBundleResourceInfo(bundleName, flags, appIndex, resourceInfo);
    if (ret != ERR_OK) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_BUNDLE_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nBundleResourceInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nBundleResourceInfo));
    ConvertBundleResourceInfo(env, resourceInfo, nBundleResourceInfo);
    APP_LOGI("NAPI end");
    return nBundleResourceInfo;
}

napi_value GetLauncherAbilityResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName) || bundleName.empty()) {
        APP_LOGE("parse bundleName failed, bundleName is %{public}s", bundleName.c_str());
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
    int32_t appIndex = 0;
    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_TWO], appIndex)) {
            APP_LOGW("parse appIndex failed");
        }
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    auto ret = ResourceHelper::InnerGetLauncherAbilityResourceInfo(
        bundleName, flags, appIndex, launcherAbilityResourceInfos);
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

void GetAllBundleResourceInfoExec(napi_env env, void *data)
{
    AllBundleResourceInfoCallback *asyncCallbackInfo = reinterpret_cast<AllBundleResourceInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = ResourceHelper::InnerGetAllBundleResourceInfo(asyncCallbackInfo->flags,
        asyncCallbackInfo->bundleResourceInfos);
}

void GetAllBundleResourceInfoComplete(napi_env env, napi_status status, void *data)
{
    AllBundleResourceInfoCallback *asyncCallbackInfo = reinterpret_cast<AllBundleResourceInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AllBundleResourceInfoCallback> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        ConvertBundleResourceInfos(env, asyncCallbackInfo->bundleResourceInfos, result[1]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_BUNDLE_RESOURCE_INFO, PERMISSION_GET_ALL_BUNDLE_RESOURCES);
    }
    CommonFunc::NapiReturnDeferred<AllBundleResourceInfoCallback>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllBundleResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    AllBundleResourceInfoCallback *asyncCallbackInfo = new (std::nothrow) AllBundleResourceInfoCallback(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AllBundleResourceInfoCallback> callbackPtr {asyncCallbackInfo};
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], flags)) {
        APP_LOGE("Flags %{public}d invalid", flags);
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }
    asyncCallbackInfo->flags = static_cast<uint32_t>(flags);
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_ONE], &valueType);
        if (valueType == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
                NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AllBundleResourceInfoCallback>(
        env, asyncCallbackInfo, GET_ALL_BUNDLE_RESOURCE_INFO, GetAllBundleResourceInfoExec,
        GetAllBundleResourceInfoComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void GetAllLauncherAbilityResourceInfoExec(napi_env env, void *data)
{
    AllLauncherAbilityResourceInfoCallback *asyncCallbackInfo =
        reinterpret_cast<AllLauncherAbilityResourceInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = ResourceHelper::InnerGetAllLauncherAbilityResourceInfo(
        asyncCallbackInfo->flags, asyncCallbackInfo->launcherAbilityResourceInfos);
}

void GetAllLauncherAbilityResourceInfoComplete(napi_env env, napi_status status, void *data)
{
    AllLauncherAbilityResourceInfoCallback *asyncCallbackInfo =
        reinterpret_cast<AllLauncherAbilityResourceInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AllLauncherAbilityResourceInfoCallback> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        ConvertLauncherAbilityResourceInfos(env, asyncCallbackInfo->launcherAbilityResourceInfos, result[1]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO, PERMISSION_GET_ALL_BUNDLE_RESOURCES);
    }
    CommonFunc::NapiReturnDeferred<AllLauncherAbilityResourceInfoCallback>(env, asyncCallbackInfo,
        result, ARGS_SIZE_TWO);
}

napi_value GetAllLauncherAbilityResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    AllLauncherAbilityResourceInfoCallback *asyncCallbackInfo =
        new (std::nothrow) AllLauncherAbilityResourceInfoCallback(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AllLauncherAbilityResourceInfoCallback> callbackPtr {asyncCallbackInfo};
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], flags)) {
        APP_LOGE("Flags %{public}d invalid", flags);
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }
    asyncCallbackInfo->flags = static_cast<uint32_t>(flags);
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_ONE], &valueType);
        if (valueType == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
                NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AllLauncherAbilityResourceInfoCallback>(
        env, asyncCallbackInfo, GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO, GetAllLauncherAbilityResourceInfoExec,
        GetAllLauncherAbilityResourceInfoComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void CreateBundleResourceFlagObject(napi_env env, napi_value value)
{
    napi_value nGetAll;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), &nGetAll));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, GET_RESOURCE_INFO_ALL, nGetAll));

    napi_value nGetLabel;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), &nGetLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, GET_RESOURCE_INFO_WITH_LABEL, nGetLabel));

    napi_value nGetIcon;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON), &nGetIcon));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, GET_RESOURCE_INFO_WITH_ICON, nGetIcon));

    napi_value nGetSortByLabel;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL), &nGetSortByLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value,
        GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL, nGetSortByLabel));

    napi_value nGetDrawable;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR), &nGetDrawable));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value,
        GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR, nGetDrawable));

    napi_value nGetMainAbility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY), &nGetMainAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value,
        GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY, nGetMainAbility));
}

napi_value GetExtensionAbilityResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetExtensionAbilityResourceInfo start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("parse bundleName failed, bundleName is %{public}s", bundleName.c_str());
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (bundleName.empty()) {
        APP_LOGE("invalid bundleName");
        napi_value businessError = BusinessError::CreateCommonError(env, ERROR_BUNDLE_NOT_EXIST,
            GET_EXTENSION_ABILITY_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        napi_throw(env, businessError);
        return nullptr;
    }
    int32_t extensionAbilityType = static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED);
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], extensionAbilityType)) {
        APP_LOGE("parse extensionAbilityType failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, EXTENSION_ABILITY_TYPE, TYPE_NUMBER);
        return nullptr;
    }
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_TWO], flags)) {
        APP_LOGE("parse flags failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }
    int32_t appIndex = 0;
    if (args.GetMaxArgc() >= ARGS_SIZE_FOUR) {
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_THREE], appIndex)) {
            APP_LOGW("parse appIndex failed");
        }
    }
    std::vector<LauncherAbilityResourceInfo> entensionAbilityResourceInfos;
    auto ret = ResourceHelper::InnerGetExtensionAbilityResourceInfo(bundleName,
        static_cast<ExtensionAbilityType>(extensionAbilityType), flags, appIndex, entensionAbilityResourceInfos);
    if (ret != ERR_OK) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_EXTENSION_ABILITY_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nExtensionAbilityResourceInfos = nullptr;
    NAPI_CALL(env, napi_create_array(env, &nExtensionAbilityResourceInfos));
    ConvertLauncherAbilityResourceInfos(env, entensionAbilityResourceInfos, nExtensionAbilityResourceInfos);
    APP_LOGD("GetExtensionAbilityResourceInfo end");
    return nExtensionAbilityResourceInfos;
}

void GetAllUninstallBundleResourceInfoExec(napi_env env, void *data)
{
    AllBundleResourceInfoCallback *asyncCallbackInfo = reinterpret_cast<AllBundleResourceInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = ResourceHelper::InnerGetAllUninstallBundleResourceInfo(asyncCallbackInfo->flags,
        asyncCallbackInfo->bundleResourceInfos);
}

void GetAllUninstallBundleResourceInfoComplete(napi_env env, napi_status status, void *data)
{
    AllBundleResourceInfoCallback *asyncCallbackInfo = reinterpret_cast<AllBundleResourceInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AllBundleResourceInfoCallback> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        ConvertBundleResourceInfos(env, asyncCallbackInfo->bundleResourceInfos, result[1]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_UNINSTALL_BUNDLE_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
    }
    CommonFunc::NapiReturnDeferred<AllBundleResourceInfoCallback>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllUninstallBundleResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    AllBundleResourceInfoCallback *asyncCallbackInfo = new (std::nothrow) AllBundleResourceInfoCallback(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AllBundleResourceInfoCallback> callbackPtr {asyncCallbackInfo};
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], flags)) {
        APP_LOGE("Flags %{public}d invalid", flags);
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }
    asyncCallbackInfo->flags = static_cast<uint32_t>(flags);
    auto promise = CommonFunc::AsyncCallNativeMethod<AllBundleResourceInfoCallback>(
        env, asyncCallbackInfo, GET_ALL_UNINSTALL_BUNDLE_RESOURCE_INFO, GetAllUninstallBundleResourceInfoExec,
        GetAllUninstallBundleResourceInfoComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}
} // AppExecFwk
} // OHOS
