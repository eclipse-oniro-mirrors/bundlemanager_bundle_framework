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

namespace OHOS {
namespace AppExecFwk {

namespace  {
    constexpr int32_t INVALID_INT = -500;
    constexpr int32_t DEFAULT_RES_FLAG = 1;
    constexpr int32_t DEFAULT_IDX = 0;
    constexpr const char* APP_INDEX = "appIndex";
    constexpr const char* BUNDLE_RESOURCE_FLAG = "ResourceFlag";
    constexpr const char* GET_BUNDLE_RESOURCE_INFO = "GetBundleResourceInfo";
    constexpr const char* PERMISSION_GET_BUNDLE_RESOURCES = "ohos.permission.GET_BUNDLE_RESOURCES";
}

static ani_object GetBundleResourceInfo([[maybe_unused]] ani_env* env, ani_string aniBundleName,
    ani_double resFlag, ani_double appIdx)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    int32_t resFlagInt = 0;
    if (!CommonFunAni::TryCastDoubleTo(resFlag, &resFlagInt)) {
        APP_LOGE("Cast resFlag failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_RESOURCE_FLAG, CommonFunAniNS::TYPE_INT);
        return nullptr;
    }
    int32_t appIdxInt = 0;
    if (!CommonFunAni::TryCastDoubleTo(appIdx, &appIdxInt)) {
        APP_LOGE("Cast appIdx failed");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, CommonFunAniNS::TYPE_INT);
        return nullptr;
    }
    auto resourceMgr = ResourceHelper::GetBundleResourceMgr();
    if (resourceMgr == nullptr) {
        APP_LOGE("GetBundleResourceMgr failed");
        return nullptr;
    }

    if (resFlagInt == INVALID_INT) {
        resFlagInt = DEFAULT_RES_FLAG;
    }

    if (appIdxInt == INVALID_INT) {
        appIdxInt = DEFAULT_IDX;
    }

    BundleResourceInfo bundleResInfo;
    int32_t ret = resourceMgr->GetBundleResourceInfo(bundleName, resFlagInt, bundleResInfo, appIdxInt);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, ret, GET_BUNDLE_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }

    return CommonFunAni::ConvertBundleResourceInfo(env, bundleResInfo);
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor resourceMgr called");
    ani_env* env;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        APP_LOGE("Unsupported ANI_VERSION_1");
        return (ani_status)9;
    }

    static const char* nsName = "L@ohos/bundle/bundleResourceManager/bundleResourceManager;";
    ani_namespace kitNs;
    if (env->FindNamespace(nsName, &kitNs) != ANI_OK) {
        APP_LOGE("Not found nameSpace name: %{public}s", nsName);
        return (ani_status)2;
    }

    std::array methods = {
        ani_native_function {
            "getBundleResourceInfoNative",
            "Lstd/core/String;DD:LbundleManager/BundleResourceInfo/BundleResourceInfo;",
            reinterpret_cast<void*>(GetBundleResourceInfo)
        }
    };

    if (env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size()) != ANI_OK) {
        APP_LOGE("Cannot bind native methods to %{public}s", nsName);
        return (ani_status)3;
    };

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS