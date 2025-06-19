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

#include "ani_resource_manager_convert.h"
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
constexpr int32_t INVALID_INT = -500;
constexpr int32_t DEFAULT_RES_FLAG = 1;
constexpr int32_t DEFAULT_IDX = 0;
constexpr const char* NS_NAME_RESOURCEMANAGER = "@ohos.bundle.bundleResourceManager.bundleResourceManager";
}

static ani_object AniGetBundleResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_double aniResFlag, ani_double aniAppIndex)
{
    APP_LOGD("ani GetBundleResourceInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName) || bundleName.empty()) {
        APP_LOGE("parse bundleName %{public}s failed", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t resFlag = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniResFlag, &resFlag)) {
        APP_LOGE("Cast aniResFlag failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return nullptr;
    }

    if (resFlag == INVALID_INT) {
        resFlag = DEFAULT_RES_FLAG;
    }

    if (appIndex == INVALID_INT) {
        appIndex = DEFAULT_IDX;
    }

    BundleResourceInfo bundleResInfo;
    int32_t ret = ResourceHelper::InnerGetBundleResourceInfo(bundleName, resFlag, appIndex, bundleResInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_BUNDLE_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }

    return AniResourceManagerConvert::ConvertBundleResourceInfo(env, bundleResInfo);
}

static ani_object AniGetLauncherAbilityResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_double aniResFlag, ani_double aniAppIndex)
{
    APP_LOGD("ani GetLauncherAbilityResourceInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName) || bundleName.empty()) {
        APP_LOGE("parse bundleName %{public}s failed", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t resFlag = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniResFlag, &resFlag)) {
        APP_LOGE("Cast aniResFlag failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return nullptr;
    }

    if (resFlag == INVALID_INT) {
        resFlag = DEFAULT_RES_FLAG;
    }

    if (appIndex == INVALID_INT) {
        appIndex = DEFAULT_IDX;
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    int32_t ret = ResourceHelper::InnerGetLauncherAbilityResourceInfo(
        bundleName, resFlag, appIndex, launcherAbilityResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetLauncherAbilityResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret,
            GET_LAUNCHER_ABILITY_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_object launcherAbilityResourceInfosObject = CommonFunAni::ConvertAniArray(
        env, launcherAbilityResourceInfos, AniResourceManagerConvert::ConvertLauncherAbilityResourceInfo);
    if (launcherAbilityResourceInfosObject == nullptr) {
        APP_LOGE("nullptr launcherAbilityResourceInfosObject");
    }

    return launcherAbilityResourceInfosObject;
}

static ani_object AniGetAllBundleResourceInfo(ani_env* env, ani_double aniResFlag)
{
    APP_LOGD("ani GetAllBundleResourceInfo called");
    int32_t resFlag = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniResFlag, &resFlag)) {
        APP_LOGE("Cast aniResFlag failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }

    std::vector<BundleResourceInfo> bundleResourceInfos;
    int32_t ret = ResourceHelper::InnerGetAllBundleResourceInfo(resFlag, bundleResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetLauncherAbilityResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, GET_ALL_BUNDLE_RESOURCE_INFO, PERMISSION_GET_ALL_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_object bundleResourceInfosObject = CommonFunAni::ConvertAniArray(
        env, bundleResourceInfos, AniResourceManagerConvert::ConvertBundleResourceInfo);
    if (bundleResourceInfosObject == nullptr) {
        APP_LOGE("nullptr bundleResourceInfosObject");
    }

    return bundleResourceInfosObject;
}

static ani_object AniGetAllLauncherAbilityResourceInfo(ani_env* env, ani_double aniResFlag)
{
    APP_LOGD("ani GetAllLauncherAbilityResourceInfo called");
    int32_t resFlag = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniResFlag, &resFlag)) {
        APP_LOGE("Cast aniResFlag failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    int32_t ret = ResourceHelper::InnerGetAllLauncherAbilityResourceInfo(resFlag, launcherAbilityResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetLauncherAbilityResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret,
            GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO, PERMISSION_GET_ALL_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_object launcherAbilityResourceInfosObject = CommonFunAni::ConvertAniArray(
        env, launcherAbilityResourceInfos, AniResourceManagerConvert::ConvertLauncherAbilityResourceInfo);
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
            reinterpret_cast<void*>(AniGetAllLauncherAbilityResourceInfo) }
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