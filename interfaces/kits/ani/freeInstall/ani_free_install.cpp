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

static void SetHapModuleUpgradeFlagNative(
    ani_env* env, ani_string aniBundleName, ani_string aniModuleName, ani_enum_item aniUpgradeFlag)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return;
    }

    std::string moduleName = CommonFunAni::AniStrToString(env, aniModuleName);
    if (moduleName.empty()) {
        APP_LOGE("moduleName is empty");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::MODULE_NAME, CommonFunAniNS::TYPE_STRING);
        return;
    }

    int32_t upgradeFlag = 0;
    if (!EnumUtils::EnumETSToNative(env, aniUpgradeFlag, upgradeFlag)) {
        APP_LOGE("parse upgradeFlag failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, UPGRADE_FLAG, CommonFunAniNS::TYPE_NUMBER);
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

static ani_boolean IsHapModuleRemovableNative(ani_env* env, ani_string aniBundleName, ani_string aniModuleName)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return false;
    }

    std::string moduleName = CommonFunAni::AniStrToString(env, aniModuleName);
    if (moduleName.empty()) {
        APP_LOGE("moduleName is empty");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::MODULE_NAME, CommonFunAniNS::TYPE_STRING);
        return false;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
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

static ani_object GetBundlePackInfoNative(ani_env* env, ani_string aniBundleName, ani_enum_item aniBundlePackFlag)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }

    BundlePackFlag bundlePackFlag = BundlePackFlag::GET_PACK_INFO_ALL;
    if (!EnumUtils::EnumETSToNative(env, aniBundlePackFlag, bundlePackFlag)) {
        APP_LOGE("parse upgradeFlag failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_PACK_FLAG, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, RESOURCE_NAME_OF_GET_BUNDLE_PACK_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    BundlePackInfo bundlePackInfo;
    auto result = iBundleMgr->GetBundlePackInfo(bundleName, static_cast<int32_t>(bundlePackFlag), bundlePackInfo);
    if (result != ERR_OK) {
        APP_LOGE("GetBundlePackInfo failed, bundleName is %{public}s", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(result),
            RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    return CommonFunAni::ConvertBundlePackInfo(env, bundlePackInfo);
}

static ani_object GetDispatchInfoNative(ani_env* env)
{
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
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace freeInstallNS = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_FREEINSTALL);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(freeInstallNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_FREEINSTALL, status);
        return status;
    }
    std::array methods = {
        ani_native_function {
            "SetHapModuleUpgradeFlagNative", nullptr, reinterpret_cast<void*>(SetHapModuleUpgradeFlagNative) },
        ani_native_function {
            "IsHapModuleRemovableNative", nullptr, reinterpret_cast<void*>(IsHapModuleRemovableNative) },
        ani_native_function { "GetBundlePackInfoNative", nullptr, reinterpret_cast<void*>(GetBundlePackInfoNative) },
        ani_native_function { "GetDispatchInfoNative", nullptr, reinterpret_cast<void*>(GetDispatchInfoNative) },
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
