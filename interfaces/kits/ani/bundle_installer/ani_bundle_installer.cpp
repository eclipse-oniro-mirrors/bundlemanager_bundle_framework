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

#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "app_log_wrapper.h"
#include "base_cb_info.h"
#include "bundle_death_recipient.h"
#include "bundle_errors.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "install_param.h"
#include "installer_callback.h"
#include "installer_helper.h"
#include "ipc_skeleton.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr uint8_t INSTALLER_METHOD_COUNTS = 11;
constexpr int32_t SPECIFIED_DISTRIBUTION_TYPE_MAX_SIZE = 128;
constexpr int32_t ADDITIONAL_INFO_MAX_SIZE = 3000;
constexpr const char* RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER_SYNC = "GetBundleInstallerSync";
constexpr const char* RESOURCE_NAME_OF_INSTALL = "Install";
constexpr const char* RESOURCE_NAME_OF_UNINSTALL = "Uninstall";
constexpr const char* RESOURCE_NAME_OF_RECOVER = "Recover";
constexpr const char* RESOURCE_NAME_OF_UPDATE_BUNDLE_FOR_SELF = "UpdateBundleForSelf";
constexpr const char* RESOURCE_NAME_OF_UNINSTALL_AND_RECOVER = "UninstallAndRecover";
constexpr const char* INNERINSTALLER_CLASSNAME = "L@ohos/bundle/installerInner/BundleInstallerInner;";
constexpr const char* INSTALL_PERMISSION =
    "ohos.permission.INSTALL_BUNDLE or "
    "ohos.permission.INSTALL_ENTERPRISE_BUNDLE or "
    "ohos.permission.INSTALL_ENTERPRISE_MDM_BUNDLE or "
    "ohos.permission.INSTALL_ENTERPRISE_NORMAL_BUNDLE or "
    "ohos.permission.INSTALL_INTERNALTESTING_BUNDLE";
constexpr const char* UNINSTALL_PERMISSION = "ohos.permission.INSTALL_BUNDLE or ohos.permission.UNINSTALL_BUNDLE";
constexpr const char* RECOVER_PERMISSION = "ohos.permission.INSTALL_BUNDLE or ohos.permission.RECOVER_BUNDLE";
constexpr const char* INSTALL_SELF_PERMISSION = "ohos.permission.INSTALL_SELF_BUNDLE";
constexpr const char* PARAMETERS = "parameters";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* CREATE_APP_CLONE = "CreateAppClone";
constexpr const char* DESTROY_APP_CLONE = "destroyAppClone";
constexpr const char* CORRESPONDING_TYPE = "corresponding type";
constexpr const char* HAPS_FILE_NEEDED =
    "BusinessError 401: Parameter error. parameter hapFiles is needed for code signature";
} // namespace
static bool g_isSystemApp = false;

static bool GetNativeInstallerWithDeathRecpt(InstallResult& installResult,
    sptr<IBundleInstaller>& iBundleInstaller, sptr<InstallerCallback>& callback)
{
    iBundleInstaller = CommonFunc::GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return false;
    }
    callback = new (std::nothrow) InstallerCallback();
    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    if (callback == nullptr ||recipient == nullptr) {
        APP_LOGE("callback or recipient is nullptr");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return false;
    }
    iBundleInstaller->AsObject()->AddDeathRecipient(recipient);
    return true;
}

static bool ParseInstallParamWithLog(ani_env* env, ani_object& aniInstParam, InstallParam& installParam)
{
    if (!CommonFunAni::ParseInstallParam(env, aniInstParam, installParam)) {
        APP_LOGE("InstallParam parse invalid");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
        return false;
    }
    return true;
}

static bool CheckInstallParam(ani_env* env, InstallParam& installParam)
{
    if (installParam.specifiedDistributionType.size() > SPECIFIED_DISTRIBUTION_TYPE_MAX_SIZE) {
        APP_LOGE("Parse specifiedDistributionType size failed");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR,
            "BusinessError 401: The size of specifiedDistributionType is greater than 128");
        return false;
    }
    if (installParam.additionalInfo.size() > ADDITIONAL_INFO_MAX_SIZE) {
        APP_LOGE("Parse additionalInfo size failed");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR,
            "BusinessError 401: The size of additionalInfo is greater than 3000");
        return false;
    }
    return true;
}

static void ExecuteInstall(const std::vector<std::string>& hapFiles, InstallParam& installParam,
    InstallResult& installResult)
{
    if (hapFiles.empty() && installParam.sharedBundleDirPaths.empty()) {
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FILE_PATH_INVALID);
        return;
    }
    sptr<IBundleInstaller> iBundleInstaller;
    sptr<InstallerCallback> callback;
    if (!GetNativeInstallerWithDeathRecpt(installResult, iBundleInstaller, callback)) {
        return;
    }
    ErrCode res = iBundleInstaller->StreamInstall(hapFiles, installParam, callback);
    if (res == ERR_OK) {
        installResult.resultCode = callback->GetResultCode();
        APP_LOGD("InnerInstall resultCode %{public}d", installResult.resultCode);
        installResult.resultMsg = callback->GetResultMsg();
        APP_LOGD("InnerInstall resultMsg %{public}s", installResult.resultMsg.c_str());
        return;
    }
    APP_LOGE("install failed due to %{public}d", res);
    std::unordered_map<int32_t, int32_t> proxyErrCodeMap;
    InstallerHelper::CreateProxyErrCode(proxyErrCodeMap);
    if (proxyErrCodeMap.find(res) != proxyErrCodeMap.end()) {
        installResult.resultCode = proxyErrCodeMap.at(res);
    } else {
        installResult.resultCode = IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR;
    }
}

static void ProcessResult(ani_env* env, InstallResult& result, const InstallOption& option)
{
    InstallerHelper::ConvertInstallResult(result);
    if (result.resultCode != SUCCESS) {
        switch (option) {
            case InstallOption::INSTALL:
                BusinessErrorAni::ThrowParameterTypeError(env, result.resultCode,
                    RESOURCE_NAME_OF_INSTALL, INSTALL_PERMISSION);
                break;
            case InstallOption::RECOVER:
                BusinessErrorAni::ThrowParameterTypeError(env, result.resultCode,
                    RESOURCE_NAME_OF_RECOVER, RECOVER_PERMISSION);
                break;
            case InstallOption::UNINSTALL:
                BusinessErrorAni::ThrowParameterTypeError(env, result.resultCode,
                    RESOURCE_NAME_OF_UNINSTALL, UNINSTALL_PERMISSION);
                break;
            case InstallOption::UPDATE_BUNDLE_FOR_SELF:
                BusinessErrorAni::ThrowParameterTypeError(env, result.resultCode,
                    RESOURCE_NAME_OF_UPDATE_BUNDLE_FOR_SELF, INSTALL_SELF_PERMISSION);
                break;
            case InstallOption::UNINSTALL_AND_RECOVER:
                BusinessErrorAni::ThrowParameterTypeError(env, result.resultCode,
                    RESOURCE_NAME_OF_UNINSTALL_AND_RECOVER, UNINSTALL_PERMISSION);
                break;
            default:
                break;
        }
    }
}

static void UninstallOrRecoverExecuter(std::string& bundleName, InstallParam& installParam,
    InstallResult& installResult, InstallOption option)
{
    if (bundleName.empty()) {
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_RECOVER_INVALID_BUNDLE_NAME);
        return;
    }
    sptr<IBundleInstaller> iBundleInstaller;
    sptr<InstallerCallback> callback;
    if (!GetNativeInstallerWithDeathRecpt(installResult, iBundleInstaller, callback)) {
        return;
    }
    if (option == InstallOption::RECOVER) {
        iBundleInstaller->Recover(bundleName, installParam, callback);
    } else if (option == InstallOption::UNINSTALL) {
        iBundleInstaller->Uninstall(bundleName, installParam, callback);
    } else {
        APP_LOGE("error install option %{public}d", option);
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }
    installResult.resultMsg = callback->GetResultMsg();
    APP_LOGD("%{public}d resultMsg %{public}s", option, installResult.resultMsg.c_str());
    installResult.resultCode = callback->GetResultCode();
    APP_LOGD("%{public}d resultCode %{public}d", option, installResult.resultCode);
}

static void AniInstall(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_array arrayObj, ani_object aniInstParam)
{
    APP_LOGI("Install");
    std::vector<std::string> hapFiles;
    if (!CommonFunAni::ParseStrArray(env, arrayObj, hapFiles)) {
        APP_LOGE("hapFiles parse invalid");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
        return;
    }
    InstallParam installParam;
    if (!ParseInstallParamWithLog(env, aniInstParam, installParam)) {
        return;
    }
    if (!CheckInstallParam(env, installParam)) {
        return;
    }
    if (hapFiles.empty() && !installParam.verifyCodeParams.empty()) {
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, HAPS_FILE_NEEDED);
        return;
    }
    InstallResult result;
    ExecuteInstall(hapFiles, installParam, result);
    ProcessResult(env, result, InstallOption::INSTALL);
}

static bool ParseBundleNameAndInstallParam(ani_env* env, ani_string& aniBundleName, ani_object& aniInstParam,
    std::string& bundleName, InstallParam& installParam)
{
    bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("Bundle name is empty.");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, CORRESPONDING_TYPE);
        return false;
    }
    return ParseInstallParamWithLog(env, aniInstParam, installParam);
}

static void AniUninstall(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_object aniInstParam)
{
    APP_LOGI("Uninstall");
    std::string bundleName;
    InstallParam installParam;
    if (!ParseBundleNameAndInstallParam(env, aniBundleName, aniInstParam, bundleName, installParam)) {
        return;
    }
    InstallResult result;
    UninstallOrRecoverExecuter(bundleName, installParam, result, InstallOption::UNINSTALL);
    ProcessResult(env, result, InstallOption::UNINSTALL);
}

static void AniRecover(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_object aniInstParam)
{
    APP_LOGI("AniRecover");
    std::string bundleName;
    InstallParam installParam;
    if (!ParseBundleNameAndInstallParam(env, aniBundleName, aniInstParam, bundleName, installParam)) {
        return;
    }
    InstallResult result;
    UninstallOrRecoverExecuter(bundleName, installParam, result, InstallOption::RECOVER);
    ProcessResult(env, result, InstallOption::RECOVER);
}

static void ExeUninstallByUninstallParam(UninstallParam& uninstallParam, InstallResult& installResult)
{
    const std::string bundleName = uninstallParam.bundleName;
    if (bundleName.empty()) {
        installResult.resultCode =
            static_cast<int32_t>(IStatusReceiver::ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST);
        return;
    }
    sptr<IBundleInstaller> iBundleInstaller;
    sptr<InstallerCallback> callback;
    if (!GetNativeInstallerWithDeathRecpt(installResult, iBundleInstaller, callback)) {
        return;
    }
    iBundleInstaller->Uninstall(uninstallParam, callback);
    installResult.resultMsg = callback->GetResultMsg();
    installResult.resultCode = callback->GetResultCode();
}

static void AniUninstallByUninstallParam(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_object aniUnInstParam)
{
    APP_LOGI("UninstallByUninstallParam");
    UninstallParam uninstallParam;
    if (!CommonFunAni::ParseUninstallParam(env, aniUnInstParam, uninstallParam)) {
        APP_LOGE("InstallParam parse invalid");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
        return;
    }
    InstallResult result;
    ExeUninstallByUninstallParam(uninstallParam, result);
    ProcessResult(env, result, InstallOption::UNINSTALL);
}

static void AniUpdateBundleForSelf(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_array arrayObj, ani_object aniInstParam)
{
    APP_LOGI("UpdateBundleForSelf");
}

static void AniUninstallUpdates(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string bundleName, ani_object aniInstParam)
{
    APP_LOGI("UninstallUpdates");
}

static void AniAddExtResource(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string bundleName, ani_object filePaths)
{
    APP_LOGI("AddExtResource");
}

static void AniRemoveExtResource(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string bundleName, ani_object moduleNames)
{
    APP_LOGI("RemoveExtResource");
}

static ani_double AniCreateAppClone(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_object aniCrtAppCloneParam)
{
    APP_LOGI("CreateAppClone");
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("Bundle name is empty.");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, CORRESPONDING_TYPE);
        return (ani_double)Constants::INITIAL_APP_INDEX;
    }
    int32_t userId;
    int32_t appIdx;
    CommonFunAni::ParseCreateAppCloneParam(env, aniCrtAppCloneParam, userId, appIdx);
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    ErrCode res = CommonFunc::ConvertErrCode(InstallerHelper::InnerCreateAppClone(bundleName, userId, appIdx));
    if (res != SUCCESS) {
        BusinessErrorAni::ThrowParameterTypeError(env, res, CREATE_APP_CLONE,
            Constants::PERMISSION_INSTALL_CLONE_BUNDLE);
    }
    return (ani_double)appIdx;
}

static void AniDestroyAppClone(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_double aniAppIndex, ani_object aniDestroyAppCloneParam)
{
    APP_LOGI("DestroyAppClone");
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("Bundle name is empty.");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, CORRESPONDING_TYPE);
        return;
    }
    int32_t appIdx = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIdx)) {
        APP_LOGE("Cast appIdx failed");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return;
    }
    DestroyAppCloneParam destroyCloneParam;
    if (!CommonFunAni::ParseDestroyAppCloneParam(env, aniDestroyAppCloneParam, destroyCloneParam)) {
        APP_LOGE("DestroyAppCloneParam parse invalid");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
        return;
    }
    if (destroyCloneParam.userId == Constants::UNSPECIFIED_USERID) {
        destroyCloneParam.userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    ErrCode result = CommonFunc::ConvertErrCode(InstallerHelper::InnerDestroyAppClone(bundleName,
        destroyCloneParam.userId, appIdx, destroyCloneParam));
    if (result != SUCCESS) {
        BusinessErrorAni::ThrowParameterTypeError(env, result,
            DESTROY_APP_CLONE, Constants::PERMISSION_UNINSTALL_CLONE_BUNDLE);
    }
}

static void AniInstallPreexistingApp(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string bundleName, ani_double userId)
{
    APP_LOGI("InstallPreexistingApp");
}

static ani_object AniGetBundleInstallerSync(ani_env* env)
{
    APP_LOGI("GetBundleInstallerSync");
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return nullptr;
    }
    if (!g_isSystemApp && !iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_NOT_SYSTEM_APP,
            RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER_SYNC, INSTALL_PERMISSION);
        return nullptr;
    }
    g_isSystemApp = true;
    ani_class installerClz = CommonFunAni::CreateClassByName(env, INNERINSTALLER_CLASSNAME);
    RETURN_NULL_IF_NULL(installerClz);
    return CommonFunAni::CreateNewObjectByClass(env, installerClz);
}
 
static void GetInstallerMethods(std::array<ani_native_function, INSTALLER_METHOD_COUNTS> &installerMethods)
{
    installerMethods = {
        ani_native_function { "installNative",
            "Lescompat/Array;L@ohos/bundle/installer/installer/InstallParam;:V",
            reinterpret_cast<void*>(AniInstall) },
        ani_native_function { "uninstallNative",
            "Lstd/core/String;L@ohos/bundle/installer/installer/InstallParam;:V",
            reinterpret_cast<void*>(AniUninstall) },
        ani_native_function { "recoverNative",
            "Lstd/core/String;L@ohos/bundle/installer/installer/InstallParam;:V",
            reinterpret_cast<void*>(AniRecover) },
        ani_native_function { "uninstallByOwnParam",
            "L@ohos/bundle/installer/installer/UninstallParam;:V",
            reinterpret_cast<void*>(AniUninstallByUninstallParam) },
        ani_native_function { "updateBundleForSelfNative",
            "Lescompat/Array;L@ohos/bundle/installer/installer/InstallParam;:V",
            reinterpret_cast<void*>(AniUpdateBundleForSelf) },
        ani_native_function { "uninstallUpdatesNative",
            "Lstd/core/String;L@ohos/bundle/installer/installer/InstallParam;:V",
            reinterpret_cast<void*>(AniUninstallUpdates) },
        ani_native_function { "addExtResourceNative",
            "Lstd/core/String;Lescompat/Array;:V",
            reinterpret_cast<void*>(AniAddExtResource) },
        ani_native_function { "removeExtResourceNative",
            "Lstd/core/String;Lescompat/Array;:V",
            reinterpret_cast<void*>(AniRemoveExtResource) },
        ani_native_function { "createAppCloneNative",
            "Lstd/core/String;L@ohos/bundle/installer/installer/CreateAppCloneParam;:D",
            reinterpret_cast<void*>(AniCreateAppClone) },
        ani_native_function { "destroyAppCloneNative", nullptr,
            reinterpret_cast<void*>(AniDestroyAppClone) },
        ani_native_function { "installPreexistingAppNative",
            "Lstd/core/String;D:V",
            reinterpret_cast<void*>(AniInstallPreexistingApp) },
    };
}
 
extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("bundle_installer ANI_Constructor called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");
    static const char* nsName = "L@ohos/bundle/installer/installer;";
    ani_namespace kitNs;
    res = env->FindNamespace(nsName, &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Not found nameSpace L@ohos/bundle/installer/installer;");
    std::array methods = {
        ani_native_function { "getBundleInstallerSync", ":L@ohos/bundle/installer/installer/BundleInstaller;",
            reinterpret_cast<void*>(AniGetBundleInstallerSync) },
    };
    res = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods");
    APP_LOGI("BundleInstaller class binding..");
    ani_class installerClz;
    res = env->FindClass(INNERINSTALLER_CLASSNAME, &installerClz);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Not found clsName");
    std::array<ani_native_function, INSTALLER_METHOD_COUNTS> installerMethods;
    GetInstallerMethods(installerMethods);
    res = env->Class_BindNativeMethods(installerClz, installerMethods.data(), installerMethods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods to clsName");
    *result = ANI_VERSION_1;
    APP_LOGI("bundle_installer ANI_Constructor finished");
    return ANI_OK;
}
}

} // namespace AppExecFwk
} // namespace OHOS
 