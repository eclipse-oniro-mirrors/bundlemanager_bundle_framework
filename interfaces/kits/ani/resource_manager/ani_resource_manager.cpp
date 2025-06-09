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
#include <ani_signature_builder.h>
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
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_RESOURCE_FLAG, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    auto resourceMgr = ResourceHelper::GetBundleResourceMgr();
    if (resourceMgr == nullptr) {
        APP_LOGE("GetBundleResourceMgr failed");
        return nullptr;
    }

    if (resFlag == INVALID_INT) {
        resFlag = DEFAULT_RES_FLAG;
    }

    if (appIndex == INVALID_INT) {
        appIndex = DEFAULT_IDX;
    }

    BundleResourceInfo bundleResInfo;
    int32_t ret = resourceMgr->GetBundleResourceInfo(bundleName, resFlag, bundleResInfo, appIndex);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleResourceInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret), GET_BUNDLE_RESOURCE_INFO, PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }

    return CommonFunAni::ConvertBundleResourceInfo(env, bundleResInfo);
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor resourceMgr called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    auto nsName = arkts::ani_signature::Builder::BuildNamespace(
        {"@ohos", "bundle", "bundleResourceManager", "bundleResourceManager"});
    ani_namespace kitNs;
    res = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(
        res, "Not found nameSpace L@ohos/bundle/bundleResourceManager/bundleResourceManager;");

    std::array methods = {
        ani_native_function {
            "getBundleResourceInfoNative",
            nullptr,
            reinterpret_cast<void*>(GetBundleResourceInfo)
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