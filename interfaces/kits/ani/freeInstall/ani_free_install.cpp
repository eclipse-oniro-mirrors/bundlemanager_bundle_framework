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

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "enum_util.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_FREEINSTALL = "@ohos.bundle.freeInstall.freeInstall";
} // namespace

static void AniSetHapModuleUpgradeFlag(
    ani_env* env, ani_string aniBundleName, ani_string aniModuleName, ani_enum_item aniUpgradeFlag)
{
    APP_LOGD("ani SetHapModuleUpgradeFlag called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return;
    }

    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName)) {
        APP_LOGE("parse moduleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return;
    }

    int32_t upgradeFlag = 0;
    if (!EnumUtils::EnumETSToNative(env, aniUpgradeFlag, upgradeFlag)) {
        APP_LOGE("parse upgradeFlag failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, UPGRADE_FLAG, TYPE_NUMBER);
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG, Constants::PERMISSION_INSTALL_BUNDLE);
        return;
    }

    auto result = iBundleMgr->SetModuleUpgradeFlag(bundleName, moduleName, upgradeFlag);
    if (result != ERR_OK) {
        APP_LOGE("SetModuleUpgradeFlag failed, bundleName is %{public}s, moduleName is %{public}s", bundleName.c_str(),
            moduleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(result),
            RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG, Constants::PERMISSION_INSTALL_BUNDLE);
        return;
    }
}

static ani_boolean AniIsHapModuleRemovable(ani_env* env, ani_string aniBundleName, ani_string aniModuleName)
{
    APP_LOGD("ani IsHapModuleRemovable called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return false;
    }

    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName)) {
        APP_LOGE("parse moduleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return false;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return false;
    }
    bool isRemovable = false;
    auto result = iBundleMgr->IsModuleRemovable(bundleName, moduleName, isRemovable);
    if (result != ERR_OK) {
        APP_LOGE("IsModuleRemovable failed, bundleName is %{public}s, moduleName is %{public}s", bundleName.c_str(),
            moduleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(result),
            RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return false;
    }
    return CommonFunAni::BoolToAniBoolean(isRemovable);
}

static ani_object AniGetBundlePackInfo(ani_env* env, ani_string aniBundleName, ani_enum_item aniBundlePackFlag)
{
    APP_LOGD("ani GetBundlePackInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }

    BundlePackFlag bundlePackFlag = BundlePackFlag::GET_PACK_INFO_ALL;
    if (!EnumUtils::EnumETSToNative(env, aniBundlePackFlag, bundlePackFlag)) {
        APP_LOGE("parse upgradeFlag failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_PACK_FLAG, TYPE_NUMBER);
        return nullptr;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, RESOURCE_NAME_OF_GET_BUNDLE_PACK_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    BundlePackInfo bundlePackInfo;
    auto result = iBundleMgr->GetBundlePackInfo(bundleName, static_cast<int32_t>(bundlePackFlag), bundlePackInfo);
    if (result != ERR_OK) {
        APP_LOGE("GetBundlePackInfo failed, bundleName is %{public}s", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(result),
            RESOURCE_NAME_OF_GET_BUNDLE_PACK_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    return CommonFunAni::ConvertBundlePackInfo(env, bundlePackInfo, static_cast<uint32_t>(bundlePackFlag));
}

static ani_object AniGetDispatchInfo(ani_env* env)
{
    APP_LOGD("ani GetDispatchInfo called");
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, RESOURCE_NAME_OF_GET_DISPATCH_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    if (!iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        BusinessErrorAni::ThrowCommonError(env, ERROR_NOT_SYSTEM_APP, RESOURCE_NAME_OF_GET_DISPATCH_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    if (!iBundleMgr->VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("GetDispatchInfo failed due to permission denied");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PERMISSION_DENIED_ERROR, RESOURCE_NAME_OF_GET_DISPATCH_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    return CommonFunAni::CreateDispatchInfo(env, DISPATCH_INFO_VERSION, DISPATCH_INFO_DISPATCH_API);
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor freeInstall called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_FREEINSTALL);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_FREEINSTALL, status);
        return status;
    }
    std::array methods = {
        ani_native_function { "setHapModuleUpgradeFlagNative", nullptr,
            reinterpret_cast<void*>(AniSetHapModuleUpgradeFlag) },
        ani_native_function { "isHapModuleRemovableNative", nullptr, reinterpret_cast<void*>(AniIsHapModuleRemovable) },
        ani_native_function { "getBundlePackInfoNative", nullptr, reinterpret_cast<void*>(AniGetBundlePackInfo) },
        ani_native_function { "getDispatchInfoNative", nullptr, reinterpret_cast<void*>(AniGetDispatchInfo) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_FREEINSTALL, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // namespace AppExecFwk
} // namespace OHOS
