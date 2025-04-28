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

namespace  {
    constexpr int32_t INVALID_INT = -500;
    constexpr int32_t DEFAULT_RES_FLAG = 1;
    constexpr int32_t DEFAULT_IDX = 0;
}

static ani_object GetBundleResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_double aniResFlag, ani_double aniAppIndex)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    int32_t resFlag = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniResFlag, &resFlag)) {
        APP_LOGE("Cast aniResFlag failed");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, CommonFunAniNS::TYPE_INT);
        return nullptr;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, CommonFunAniNS::TYPE_INT);
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

    return CommonFunAni::ConvertBundleResourceInfo(env, bundleResInfo);
}

static ani_ref GetLauncherAbilityResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_double aniResFlag, ani_double aniAppIndex)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    int32_t resFlag = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniResFlag, &resFlag)) {
        APP_LOGE("Cast aniResFlag failed");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, CommonFunAniNS::TYPE_INT);
        return nullptr;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, CommonFunAniNS::TYPE_INT);
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
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_LAUNCHER_ABILITY_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_ref launcherAbilityResourceInfosRef = CommonFunAni::ConvertAniArray(
        env, launcherAbilityResourceInfos, CommonFunAni::ConvertLauncherAbilityResourceInfo);
    if (launcherAbilityResourceInfosRef == nullptr) {
        APP_LOGE("nullptr launcherAbilityResourceInfosRef");
    }

    return launcherAbilityResourceInfosRef;
}

static ani_ref GetAllBundleResourceInfo(ani_env* env, ani_double aniResFlag)
{
    int32_t resFlag = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniResFlag, &resFlag)) {
        APP_LOGE("Cast aniResFlag failed");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, CommonFunAniNS::TYPE_INT);
        return nullptr;
    }

    std::vector<BundleResourceInfo> bundleResourceInfos;
    int32_t ret = ResourceHelper::InnerGetAllBundleResourceInfo(resFlag, bundleResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetLauncherAbilityResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_ALL_BUNDLE_RESOURCE_INFO, PERMISSION_GET_ALL_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_ref bundleResourceInfosRef = CommonFunAni::ConvertAniArray(
        env, bundleResourceInfos, CommonFunAni::ConvertBundleResourceInfo);
    if (bundleResourceInfosRef == nullptr) {
        APP_LOGE("nullptr bundleResourceInfosRef");
    }

    return bundleResourceInfosRef;
}

static ani_ref GetAllLauncherAbilityResourceInfo(ani_env* env, ani_double aniResFlag)
{
    int32_t resFlag = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniResFlag, &resFlag)) {
        APP_LOGE("Cast aniResFlag failed");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, RESOURCE_FLAGS, CommonFunAniNS::TYPE_INT);
        return nullptr;
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    int32_t ret = ResourceHelper::InnerGetAllLauncherAbilityResourceInfo(resFlag, launcherAbilityResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetLauncherAbilityResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO,
            PERMISSION_GET_ALL_BUNDLE_RESOURCES);
        return nullptr;
    }

    ani_ref launcherAbilityResourceInfosRef = CommonFunAni::ConvertAniArray(
        env, launcherAbilityResourceInfos, CommonFunAni::ConvertLauncherAbilityResourceInfo);
    if (launcherAbilityResourceInfosRef == nullptr) {
        APP_LOGE("nullptr launcherAbilityResourceInfosRef");
    }

    return launcherAbilityResourceInfosRef;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor resourceMgr called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    static const char* nsName = "L@ohos/bundle/bundleResourceManager/bundleResourceManager;";
    ani_namespace kitNs;
    res = env->FindNamespace(nsName, &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(
        res, "Not found nameSpace L@ohos/bundle/bundleResourceManager/bundleResourceManager;");

    std::array methods = {
        ani_native_function {
            "getBundleResourceInfoNative",
            nullptr,
            reinterpret_cast<void*>(GetBundleResourceInfo)
        },
        ani_native_function {
            "getLauncherAbilityResourceInfoNative",
            nullptr,
            reinterpret_cast<void*>(GetLauncherAbilityResourceInfo)
        },
        ani_native_function {
            "getAllBundleResourceInfoNative",
            nullptr,
            reinterpret_cast<void*>(GetAllBundleResourceInfo)
        },
        ani_native_function {
            "getAllLauncherAbilityResourceInfoNative",
            nullptr,
            reinterpret_cast<void*>(GetAllLauncherAbilityResourceInfo)
        }
    };

    res = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods");

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS