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
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "napi_constants.h"
#include "overlay_module_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_OVERLAY = "@ohos.bundle.overlay.overlay";
} // namespace

static void SetOverlayEnabled(ani_env *env, ani_string aniModuleName, ani_boolean aniIsEnabled)
{
    std::string moduleName = CommonFunAni::AniStrToString(env, aniModuleName);
    if (moduleName.empty()) {
        APP_LOGE("MoudleName is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, CommonFunAniNS::TYPE_STRING);
        return;
    }
    bool isEnabled = CommonFunAni::AniBooleanToBool(aniIsEnabled);

    auto overlayMgrProxy = CommonFunc::GetOverlayMgrProxy();
    if (overlayMgrProxy == nullptr) {
        APP_LOGE("overlayMgrProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            SET_OVERLAY_ENABLED, Constants::PERMISSION_CHANGE_OVERLAY_ENABLED_STATE);
        return;
    }

    ErrCode ret = overlayMgrProxy->SetOverlayEnabledForSelf(moduleName, isEnabled);
    if (ret != ERR_OK) {
        APP_LOGE("SetOverlayEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            SET_OVERLAY_ENABLED, Constants::PERMISSION_CHANGE_OVERLAY_ENABLED_STATE);
        return;
    }
}

static void SetOverlayEnabledByBundleName(ani_env *env,
    ani_string aniBundleName, ani_string aniModuleName, ani_boolean aniIsEnabled)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return;
    }
    std::string moduleName = CommonFunAni::AniStrToString(env, aniModuleName);
    if (moduleName.empty()) {
        APP_LOGE("MoudleName is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, CommonFunAniNS::TYPE_STRING);
        return;
    }
    bool isEnabled = CommonFunAni::AniBooleanToBool(aniIsEnabled);

    auto overlayMgrProxy = CommonFunc::GetOverlayMgrProxy();
    if (overlayMgrProxy == nullptr) {
        APP_LOGE("overlayMgrProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            SET_OVERLAY_ENABLED_BY_BUNDLE_NAME, Constants::PERMISSION_CHANGE_OVERLAY_ENABLED_STATE);
        return;
    }

    ErrCode ret = overlayMgrProxy->SetOverlayEnabled(bundleName, moduleName, isEnabled);
    if (ret != ERR_OK) {
        APP_LOGE("SetOverlayEnabledByBundleName failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            SET_OVERLAY_ENABLED_BY_BUNDLE_NAME, Constants::PERMISSION_CHANGE_OVERLAY_ENABLED_STATE);
        return;
    }
}

static ani_object GetOverlayModuleInfo(ani_env *env, ani_string aniModuleName)
{
    std::string moduleName = CommonFunAni::AniStrToString(env, aniModuleName);
    if (moduleName.empty()) {
        APP_LOGE("MoudleName is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }

    auto overlayMgrProxy = CommonFunc::GetOverlayMgrProxy();
    if (overlayMgrProxy == nullptr) {
        APP_LOGE("overlayMgrProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            GET_OVERLAY_MODULE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    OverlayModuleInfo overlayModuleInfo;

    ErrCode ret = overlayMgrProxy->GetOverlayModuleInfo(moduleName, overlayModuleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetOverlayModuleInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_OVERLAY_MODULE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    return CommonFunAni::ConvertOverlayModuleInfo(env, overlayModuleInfo);
}

static ani_object GetTargetOverlayModuleInfos(ani_env *env, ani_string aniTargetModuleName)
{
    std::string targetModuleName = CommonFunAni::AniStrToString(env, aniTargetModuleName);
    if (targetModuleName.empty()) {
        APP_LOGE("TargetModuleName is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR,
            TARGET_MODULE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }

    auto overlayMgrProxy = CommonFunc::GetOverlayMgrProxy();
    if (overlayMgrProxy == nullptr) {
        APP_LOGE("overlayMgrProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            GET_TARGET_OVERLAY_MODULE_INFOS, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    std::vector<OverlayModuleInfo> overlayModuleInfos;

    ErrCode ret = overlayMgrProxy->GetTargetOverlayModuleInfo(targetModuleName, overlayModuleInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetTargetOverlayModuleInfos failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_TARGET_OVERLAY_MODULE_INFOS, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    ani_object overlayModuleInfosObject = CommonFunAni::ConvertAniArray(
        env, overlayModuleInfos, CommonFunAni::ConvertOverlayModuleInfo);
    if (overlayModuleInfosObject == nullptr) {
        APP_LOGE("nullptr overlayModuleInfosObject");
    }

    return overlayModuleInfosObject;
}

static ani_object GetOverlayModuleInfoByBundleName(ani_env *env, ani_string aniBundleName, ani_string aniModuleName)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    std::string moduleName = CommonFunAni::AniStrToString(env, aniModuleName);
    if (moduleName.empty()) {
        APP_LOGI("MoudleName undefined, default query for all module OverlayModuleInfo");
    }

    auto overlayMgrProxy = CommonFunc::GetOverlayMgrProxy();
    if (overlayMgrProxy == nullptr) {
        APP_LOGE("overlayMgrProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    std::vector<OverlayModuleInfo> overlayModuleInfos;

    ErrCode ret = overlayMgrProxy->GetOverlayModuleInfoByBundleName(bundleName, moduleName, overlayModuleInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetOverlayModuleInfoByBundleName failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    ani_object overlayModuleInfosObject = CommonFunAni::ConvertAniArray(
        env, overlayModuleInfos, CommonFunAni::ConvertOverlayModuleInfo);
    if (overlayModuleInfosObject == nullptr) {
        APP_LOGE("nullptr overlayModuleInfosObject");
    }

    return overlayModuleInfosObject;
}

static ani_object GetTargetOverlayModuleInfosByBundleName(ani_env *env,
    ani_string aniTargetBundleName, ani_string aniModuleName)
{
    std::string targetBundleName = CommonFunAni::AniStrToString(env, aniTargetBundleName);
    if (targetBundleName.empty()) {
        APP_LOGE("TargetBundleName is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR,
            TARGET_BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    std::string moduleName = CommonFunAni::AniStrToString(env, aniModuleName);
    if (moduleName.empty()) {
        APP_LOGI("MoudleName undefined, default query for all module OverlayModuleInfo");
    }

    auto overlayMgrProxy = CommonFunc::GetOverlayMgrProxy();
    if (overlayMgrProxy == nullptr) {
        APP_LOGE("overlayMgrProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    std::vector<OverlayModuleInfo> overlayModuleInfos;

    ErrCode ret = overlayMgrProxy->GetOverlayModuleInfoForTarget(targetBundleName, moduleName, overlayModuleInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetTargetOverlayModuleInfosByBundleName failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    ani_object overlayModuleInfosObject = CommonFunAni::ConvertAniArray(
        env, overlayModuleInfos, CommonFunAni::ConvertOverlayModuleInfo);
    if (overlayModuleInfosObject == nullptr) {
        APP_LOGE("nullptr overlayModuleInfosObject");
    }

    return overlayModuleInfosObject;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor overlay called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace freeInstallNS = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_OVERLAY);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(freeInstallNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_OVERLAY, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "setOverlayEnabledNative", nullptr,
            reinterpret_cast<void*>(SetOverlayEnabled) },
        ani_native_function { "setOverlayEnabledByBundleNameNative", nullptr,
            reinterpret_cast<void*>(SetOverlayEnabledByBundleName) },
        ani_native_function { "getOverlayModuleInfoNative", nullptr,
            reinterpret_cast<void*>(GetOverlayModuleInfo) },
        ani_native_function { "getTargetOverlayModuleInfosNative", nullptr,
            reinterpret_cast<void*>(GetTargetOverlayModuleInfos) },
        ani_native_function { "getOverlayModuleInfoByBundleNameNative", nullptr,
            reinterpret_cast<void*>(GetOverlayModuleInfoByBundleName) },
        ani_native_function { "getTargetOverlayModuleInfosByBundleNameNative", nullptr,
            reinterpret_cast<void*>(GetTargetOverlayModuleInfosByBundleName) }
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_OVERLAY, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS