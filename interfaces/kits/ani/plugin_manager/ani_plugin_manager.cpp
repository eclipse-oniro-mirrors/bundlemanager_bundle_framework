/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "napi_constants.h"


namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_PLUGIN_MANAGER = "@ohos.bundle.pluginManager.pluginManager";
}

static ani_object GetAllLocalPluginInfoForSelfNative(ani_env* env)
{
    APP_LOGD("ani GetAllLocalPluginInfoForSelfNative called");
    std::vector<PluginBundleInfo> pluginBundleInfos;
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    ErrCode ret = iBundleMgr->GetAllLocalPluginInfoForSelf(pluginBundleInfos);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetAllLocalPluginInfoForSelf failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), GET_ALL_LOCAL_PLUGIN_INFO_FOR_SELF,
            ServiceConstants::PERMISSION_SUPPORT_LOCAL_PLUGIN);
        return nullptr;
    }

    return CommonFunAni::ConvertAniArray(env, pluginBundleInfos, CommonFunAni::ConvertPluginBundleInfo);
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("plugin_manager ANI_Constructor called");
    ani_env* env = nullptr;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace ns = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_PLUGIN_MANAGER);
    ani_namespace kitNs = nullptr;
    res = env->FindNamespace(ns.Descriptor().c_str(), &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Not found namespace of @ohos.bundle.pluginManager.pluginManager");

    std::array methods = {
        ani_native_function { "getAllLocalPluginInfoForSelfNative", nullptr,
            reinterpret_cast<void*>(GetAllLocalPluginInfoForSelfNative) },
    };
    res = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods");

    *result = ANI_VERSION_1;
    APP_LOGI("plugin_manager ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AppExecFwk
} // namespace OHOS
