/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <ani_signature_builder.h>

#include "ani_resource_manager_common.h"
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_resource_info.h"
#include "bundle_resource_interface.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "resource_helper.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
constexpr const char* NS_NAME_RESOURCEMANAGER = "@ohos.bundle.bundleResourceManager.bundleResourceManager";
constexpr const int32_t MAX_ARRAYLIST_SIZE = 1000;
}

static ani_object AniGetBundleResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_int aniResFlag, ani_int aniAppIndex)
{
    APP_LOGD("ani GetBundleResourceInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName) || bundleName.empty()) {
        APP_LOGE("parse bundleName %{public}s failed", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t flags = static_cast<int32_t>(aniResFlag);
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }

    BundleResourceInfo bundleResInfo;
    int32_t ret = ResourceHelper::InnerGetBundleResourceInfo(bundleName, flags, aniAppIndex, bundleResInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_BUNDLE_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }

    return AniResourceManagerCommon::ConvertBundleResourceInfo(env, bundleResInfo);
}

static ani_object AniGetLauncherAbilityResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_int aniResFlag, ani_int aniAppIndex)
{
    APP_LOGD("ani GetLauncherAbilityResourceInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName) || bundleName.empty()) {
        APP_LOGE("parse bundleName %{public}s failed", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t flags = static_cast<int32_t>(aniResFlag);
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    int32_t ret = ResourceHelper::InnerGetLauncherAbilityResourceInfo(
        bundleName, flags, aniAppIndex, launcherAbilityResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetLauncherAbilityResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret,
            GET_LAUNCHER_ABILITY_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_object launcherAbilityResourceInfosObject = CommonFunAni::ConvertAniArray(
        env, launcherAbilityResourceInfos, AniResourceManagerCommon::ConvertLauncherAbilityResourceInfo);
    if (launcherAbilityResourceInfosObject == nullptr) {
        APP_LOGE("nullptr launcherAbilityResourceInfosObject");
    }

    return launcherAbilityResourceInfosObject;
}

static ani_object AniGetAllBundleResourceInfo(ani_env* env, ani_int aniResFlag)
{
    APP_LOGD("ani GetAllBundleResourceInfo called");

    int32_t flags = static_cast<int32_t>(aniResFlag);
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }

    std::vector<BundleResourceInfo> bundleResourceInfos;
    int32_t ret = ResourceHelper::InnerGetAllBundleResourceInfo(static_cast<uint32_t>(flags), bundleResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetLauncherAbilityResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, GET_ALL_BUNDLE_RESOURCE_INFO, PERMISSION_GET_ALL_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_object bundleResourceInfosObject = CommonFunAni::ConvertAniArray(
        env, bundleResourceInfos, AniResourceManagerCommon::ConvertBundleResourceInfo);
    if (bundleResourceInfosObject == nullptr) {
        APP_LOGE("nullptr bundleResourceInfosObject");
    }

    return bundleResourceInfosObject;
}

static ani_object AniGetAllLauncherAbilityResourceInfo(ani_env* env, ani_int aniResFlag)
{
    APP_LOGD("ani GetAllLauncherAbilityResourceInfo called");

    int32_t flags = static_cast<int32_t>(aniResFlag);
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    int32_t ret = ResourceHelper::InnerGetAllLauncherAbilityResourceInfo(
        static_cast<uint32_t>(flags), launcherAbilityResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetLauncherAbilityResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret,
            GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO, PERMISSION_GET_ALL_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_object launcherAbilityResourceInfosObject = CommonFunAni::ConvertAniArray(
        env, launcherAbilityResourceInfos, AniResourceManagerCommon::ConvertLauncherAbilityResourceInfo);
    if (launcherAbilityResourceInfosObject == nullptr) {
        APP_LOGE("nullptr launcherAbilityResourceInfosObject");
    }

    return launcherAbilityResourceInfosObject;
}

static ani_object AniGetLauncherAbilityResourceInfoList(ani_env* env, ani_object aniOptionsList, ani_int aniResFlag)
{
    APP_LOGD("ani AniGetLauncherAbilityResourceInfoList called");

    int32_t flags = static_cast<int32_t>(aniResFlag);
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }
    std::vector<BundleOptionInfo> optionsList;
    if (!CommonFunAni::ParseAniArray(env, aniOptionsList, optionsList, CommonFunAni::ParseBundleOption)) {
        APP_LOGE("ParseBundleOption failed");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_OPTION, GET_LAUNCHER_ABILITY_RESOURCE_INFO_LIST);
        return nullptr;
    }
    if (optionsList.empty()) {
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_OPTION, PARAM_BUNDLE_OPTIONS_EMPTY_ERROR);
        return nullptr;
    }
    if (optionsList.size() > MAX_ARRAYLIST_SIZE) {
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_OPTION, PARAM_BUNDLE_OPTIONS_NUMBER_ERROR);
        return nullptr;
    }
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    int32_t ret = ResourceHelper::InnerGetLauncherAbilityResourceInfoList(optionsList,
        static_cast<uint32_t>(flags), launcherAbilityResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("AniGetLauncherAbilityResourceInfoList failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonNewError(env, ret,
            GET_LAUNCHER_ABILITY_RESOURCE_INFO_LIST, PERMISSION_GET_ALL_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_object launcherAbilityResourceInfosObject = CommonFunAni::ConvertAniArray(
        env, launcherAbilityResourceInfos, AniResourceManagerCommon::ConvertLauncherAbilityResourceInfo);
    if (launcherAbilityResourceInfosObject == nullptr) {
        APP_LOGE("nullptr launcherAbilityResourceInfosObject");
    }

    return launcherAbilityResourceInfosObject;
}

static ani_object GetExtensionAbilityResourceInfoNative(ani_env* env, ani_string aniBundleName,
    ani_enum_item aniExtensionAbilityType, ani_int aniResourceFlags, ani_int aniAppIndex)
{
    APP_LOGD("ani GetExtensionAbilityResourceInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName empty");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_BUNDLE_NOT_EXIST, GET_EXTENSION_ABILITY_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }
    ExtensionAbilityType extensionAbilityType = ExtensionAbilityType::UNSPECIFIED;
    if (!EnumUtils::EnumETSToNative(env, aniExtensionAbilityType, extensionAbilityType)) {
        APP_LOGE("Parse extensionAbilityType failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, EXTENSION_ABILITY_TYPE, TYPE_NUMBER);
        return nullptr;
    }

    int32_t flags = static_cast<int32_t>(aniResourceFlags);
    if (flags <= 0) {
        flags = static_cast<int32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    }

    std::vector<LauncherAbilityResourceInfo> extensionAbilityResourceInfos;
    ErrCode ret = ResourceHelper::InnerGetExtensionAbilityResourceInfo(
        bundleName, extensionAbilityType, flags, aniAppIndex, extensionAbilityResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("QueryExtensionAbilityInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_EXTENSION_ABILITY_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }
    ani_object launcherAbilityResourceInfosObject = CommonFunAni::ConvertAniArray(
        env, extensionAbilityResourceInfos, AniResourceManagerCommon::ConvertLauncherAbilityResourceInfo);
    if (launcherAbilityResourceInfosObject == nullptr) {
        APP_LOGE("nullptr launcherAbilityResourceInfosObject");
    }
    return launcherAbilityResourceInfosObject;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor resourceManager called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_RESOURCEMANAGER);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_RESOURCEMANAGER, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "getBundleResourceInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetBundleResourceInfo) },
        ani_native_function { "getLauncherAbilityResourceInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetLauncherAbilityResourceInfo) },
        ani_native_function { "getAllBundleResourceInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetAllBundleResourceInfo) },
        ani_native_function { "getAllLauncherAbilityResourceInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetAllLauncherAbilityResourceInfo) },
        ani_native_function { "getLauncherAbilityResourceInfoListNative", nullptr,
            reinterpret_cast<void*>(AniGetLauncherAbilityResourceInfoList) },
        ani_native_function { "getExtensionAbilityResourceInfoNative", nullptr,
            reinterpret_cast<void*>(GetExtensionAbilityResourceInfoNative) }
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_RESOURCEMANAGER, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS