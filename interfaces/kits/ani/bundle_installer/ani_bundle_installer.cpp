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
constexpr uint8_t INSTALLER_METHOD_COUNTS = 13;
constexpr const char* INNERINSTALLER_CLASSNAME = "@ohos.bundle.installerInner.BundleInstallerInner";
} // namespace
static bool g_isSystemApp = false;
using namespace arkts::ani_signature;
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
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
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
        installResult.innerCode = callback->GetInnerCode();
        return;
    }
    APP_LOGE("install failed due to %{public}d", res);
    std::unordered_map<int32_t, int32_t> proxyErrCodeMap;
    InstallerHelper::CreateProxyErrCode(proxyErrCodeMap);
    if (proxyErrCodeMap.find(res) != proxyErrCodeMap.end()) {
        installResult.resultCode = proxyErrCodeMap.at(res);
        // append inner error code to TS interface result message
        installResult.innerCode = res;
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
                BusinessErrorAni::ThrowInstallError(env, result.resultCode, result.innerCode,
                    RESOURCE_NAME_OF_INSTALL, INSTALL_PERMISSION);
                break;
            case InstallOption::RECOVER:
                BusinessErrorAni::ThrowCommonError(env, result.resultCode,
                    RESOURCE_NAME_OF_RECOVER, RECOVER_PERMISSION);
                break;
            case InstallOption::UNINSTALL:
                BusinessErrorAni::ThrowCommonError(env, result.resultCode,
                    RESOURCE_NAME_OF_UNINSTALL, UNINSTALL_PERMISSION);
                break;
            case InstallOption::UPDATE_BUNDLE_FOR_SELF:
                BusinessErrorAni::ThrowCommonError(env, result.resultCode,
                    RESOURCE_NAME_OF_UPDATE_BUNDLE_FOR_SELF, INSTALL_SELF_PERMISSION);
                break;
            case InstallOption::UNINSTALL_AND_RECOVER:
                BusinessErrorAni::ThrowCommonError(env, result.resultCode,
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
    } else if (option == InstallOption::UNINSTALL_AND_RECOVER) {
        iBundleInstaller->UninstallAndRecover(bundleName, installParam, callback);
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

static bool GetInstallParamForInstall(ani_env* env, ani_array arrayObj, ani_object aniInstParam,
    std::vector<std::string>& hapFiles, InstallParam& installParam)
{
    APP_LOGI("Install");
    if (!CommonFunAni::ParseStrArray(env, arrayObj, hapFiles)) {
        APP_LOGE("hapFiles parse invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
        return false;
    }
    if (!ParseInstallParamWithLog(env, aniInstParam, installParam)) {
        return false;
    }
    if (!CheckInstallParam(env, installParam)) {
        return false;
    }
    if (hapFiles.empty() && !installParam.verifyCodeParams.empty()) {
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_HAPS_FILE_EMPTY_ERROR);
        return false;
    }
    return true;
}

static void AniInstall(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_array arrayObj, ani_object aniInstParam)
{
    APP_LOGD("ani Install called");
    std::vector<std::string> hapFiles;
    InstallParam installParam;
    if (!GetInstallParamForInstall(env, arrayObj, aniInstParam, hapFiles, installParam)) {
        return;
    }
    if (installParam.installFlag == InstallFlag::NORMAL) {
        installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    }
    InstallResult result;
    ExecuteInstall(hapFiles, installParam, result);
    ProcessResult(env, result, InstallOption::INSTALL);
}

static bool ParseBundleNameAndInstallParam(ani_env* env, ani_string& aniBundleName, ani_object& aniInstParam,
    std::string& bundleName, InstallParam& installParam)
{
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return false;
    }
    return ParseInstallParamWithLog(env, aniInstParam, installParam);
}

static void AniUninstall(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_object aniInstParam)
{
    APP_LOGD("ani Uninstall called");
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
    APP_LOGD("ani Recover called");
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
    APP_LOGD("ani UninstallByUninstallParam called");
    UninstallParam uninstallParam;
    if (!CommonFunAni::ParseUninstallParam(env, aniUnInstParam, uninstallParam)) {
        APP_LOGE("InstallParam parse invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
        return;
    }
    InstallResult result;
    ExeUninstallByUninstallParam(uninstallParam, result);
    ProcessResult(env, result, InstallOption::UNINSTALL);
}

static void AniUpdateBundleForSelf(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_array arrayObj, ani_object aniInstParam)
{
    APP_LOGD("ani UpdateBundleForSelf called");
    std::vector<std::string> hapFiles;
    InstallParam installParam;
    if (!GetInstallParamForInstall(env, arrayObj, aniInstParam, hapFiles, installParam)) {
        return;
    }
    installParam.isSelfUpdate = true;
    InstallResult result;
    ExecuteInstall(hapFiles, installParam, result);
    ProcessResult(env, result, InstallOption::UPDATE_BUNDLE_FOR_SELF);
}

static void AniUninstallUpdates(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_object aniInstParam)
{
    APP_LOGD("ani UninstallUpdates called");
    std::string bundleName;
    InstallParam installParam;
    if (!ParseBundleNameAndInstallParam(env, aniBundleName, aniInstParam, bundleName, installParam)) {
        return;
    }
    InstallResult result;
    UninstallOrRecoverExecuter(bundleName, installParam, result, InstallOption::UNINSTALL_AND_RECOVER);
    ProcessResult(env, result, InstallOption::UNINSTALL_AND_RECOVER);
}

static bool ParseBundleNameAndFilePath(ani_env* env, ani_string aniBundleName, ani_object aniFilePaths,
    std::string& bundleName, std::vector<std::string>& filePaths)
{
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return false;
    }
    if (!CommonFunAni::ParseStrArray(env, aniFilePaths, filePaths)) {
        APP_LOGE("filePaths invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, FILE_PATH, TYPE_ARRAY);
        return false;
    }
    return true;
}

static void AniAddExtResource(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_object aniFilePaths)
{
    APP_LOGD("ani AddExtResource called");
    std::string bundleName;
    std::vector<std::string> filePaths;
    if (!ParseBundleNameAndFilePath(env, aniBundleName, aniFilePaths, bundleName, filePaths)) {
        return;
    }
    ErrCode err = InstallerHelper::InnerAddExtResource(bundleName, filePaths);
    if (err != NO_ERROR) {
        BusinessErrorAni::ThrowCommonError(
            env, err, ADD_EXT_RESOURCE, Constants::PERMISSION_INSTALL_BUNDLE);
    }
}

static void AniRemoveExtResource(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_object aniModuleNames)
{
    APP_LOGD("ani RemoveExtResource called");
    std::string bundleName;
    std::vector<std::string> moduleNames;
    if (!ParseBundleNameAndFilePath(env, aniBundleName, aniModuleNames, bundleName, moduleNames)) {
        return;
    }
    ErrCode err = InstallerHelper::InnerRemoveExtResource(bundleName, moduleNames);
    if (err != NO_ERROR) {
        BusinessErrorAni::ThrowCommonError(
            env, err, REMOVE_EXT_RESOURCE, UNINSTALL_PERMISSION);
    }
}

static ani_double AniCreateAppClone(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_object aniCrtAppCloneParam)
{
    APP_LOGD("ani CreateAppClone called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
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
        BusinessErrorAni::ThrowCommonError(env, res, CREATE_APP_CLONE, Constants::PERMISSION_INSTALL_CLONE_BUNDLE);
    }
    return (ani_double)appIdx;
}

static void AniDestroyAppClone(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_double aniAppIndex, ani_object aniDestroyAppCloneParam)
{
    APP_LOGD("ani DestroyAppClone called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return;
    }
    int32_t appIdx = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIdx)) {
        APP_LOGE("Cast appIdx failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return;
    }
    DestroyAppCloneParam destroyCloneParam;
    if (!CommonFunAni::ParseDestroyAppCloneParam(env, aniDestroyAppCloneParam, destroyCloneParam)) {
        APP_LOGE("DestroyAppCloneParam parse invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
        return;
    }
    if (destroyCloneParam.userId == Constants::UNSPECIFIED_USERID) {
        destroyCloneParam.userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    ErrCode result = CommonFunc::ConvertErrCode(InstallerHelper::InnerDestroyAppClone(bundleName,
        destroyCloneParam.userId, appIdx, destroyCloneParam));
    if (result != SUCCESS) {
        BusinessErrorAni::ThrowCommonError(env, result,
            DESTROY_APP_CLONE, Constants::PERMISSION_UNINSTALL_CLONE_BUNDLE);
    }
}

static void AniInstallPreexistingApp(ani_env* env, [[maybe_unused]] ani_object installerObj,
    ani_string aniBundleName, ani_double aniUserId)
{
    APP_LOGD("ani InstallPreexistingApp called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast appIdx failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    ErrCode result = CommonFunc::ConvertErrCode(InstallerHelper::InnerInstallPreexistingApp(bundleName, userId));
    if (result != SUCCESS) {
        BusinessErrorAni::ThrowCommonError(env, result,
            INSTALL_PREEXISTING_APP, Constants::PERMISSION_INSTALL_BUNDLE);
    }
}

static void AniInstallPlugin(ani_env* env, [[maybe_unused]] ani_object installerObj, ani_string aniHostBundleName,
    ani_object aniPluginFilePaths, ani_object aniPluginParam)
{
    APP_LOGD("ani InstallPlugin called");

    std::string hostBundleName;
    if (!CommonFunAni::ParseString(env, aniHostBundleName, hostBundleName)) {
        APP_LOGE("parse hostBundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return;
    }

    std::vector<std::string> pluginFilePaths;
    if (aniPluginFilePaths == nullptr || !CommonFunAni::ParseStrArray(env, aniPluginFilePaths, pluginFilePaths)) {
        APP_LOGE("pluginFilePaths parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, FILE_PATH, TYPE_ARRAY);
        return;
    }

    InstallPluginParam pluginParam;
    if (aniPluginParam == nullptr || !CommonFunAni::ParsePluginParam(env, aniPluginParam, pluginParam)) {
        APP_LOGE("pluginParam parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
        return;
    }
    if (pluginParam.userId == Constants::UNSPECIFIED_USERID) {
        pluginParam.userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }

    ErrCode result =
        CommonFunc::ConvertErrCode(InstallerHelper::InnerInstallPlugin(hostBundleName, pluginFilePaths, pluginParam));
    if (result != SUCCESS) {
        BusinessErrorAni::ThrowCommonError(env, result, INSTALL_PLUGIN, Constants::PERMISSION_INSTALL_PLUGIN);
    }
}

static void AniUninstallPlugin(ani_env* env, [[maybe_unused]] ani_object installerObj, ani_string aniHostBundleName,
    ani_string aniPluginBundleName, ani_object aniPluginParam)
{
    APP_LOGD("ani UninstallPlugin called");

    std::string hostBundleName;
    if (!CommonFunAni::ParseString(env, aniHostBundleName, hostBundleName)) {
        APP_LOGE("parse hostBundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return;
    }

    std::string pluginBundleName;
    if (!CommonFunAni::ParseString(env, aniPluginBundleName, pluginBundleName)) {
        APP_LOGW("parse pluginBundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PLUGIN_BUNDLE_NAME, TYPE_STRING);
        return;
    }

    InstallPluginParam pluginParam;
    if (aniPluginParam == nullptr || !CommonFunAni::ParsePluginParam(env, aniPluginParam, pluginParam)) {
        APP_LOGE("pluginParam parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
        return;
    }
    if (pluginParam.userId == Constants::UNSPECIFIED_USERID) {
        pluginParam.userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }

    ErrCode result = CommonFunc::ConvertErrCode(
        InstallerHelper::InnerUninstallPlugin(hostBundleName, pluginBundleName, pluginParam));
    if (result != SUCCESS) {
        BusinessErrorAni::ThrowCommonError(env, result, UNINSTALL_PLUGIN, Constants::PERMISSION_UNINSTALL_PLUGIN);
    }
}

static ani_object AniGetBundleInstaller(ani_env* env, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetBundleInstaller called");
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return nullptr;
    }
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (!g_isSystemApp && !iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        BusinessErrorAni::ThrowCommonError(env, ERROR_NOT_SYSTEM_APP,
            isSync ? RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER_SYNC : RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER,
            INSTALL_PERMISSION);
        return nullptr;
    }
    g_isSystemApp = true;
    ani_class installerClz = CommonFunAni::CreateClassByName(env,
        Builder::BuildClass(INNERINSTALLER_CLASSNAME).Descriptor());
    RETURN_NULL_IF_NULL(installerClz);
    return CommonFunAni::CreateNewObjectByClass(env, installerClz);
}
 
static void GetInstallerMethods(std::array<ani_native_function, INSTALLER_METHOD_COUNTS> &installerMethods)
{
    installerMethods = {
        ani_native_function { "installNative", nullptr, reinterpret_cast<void*>(AniInstall) },
        ani_native_function { "uninstallNative", nullptr, reinterpret_cast<void*>(AniUninstall) },
        ani_native_function { "recoverNative", nullptr, reinterpret_cast<void*>(AniRecover) },
        ani_native_function { "uninstallByOwnParamNative", nullptr,
            reinterpret_cast<void*>(AniUninstallByUninstallParam) },
        ani_native_function { "updateBundleForSelfNative", nullptr, reinterpret_cast<void*>(AniUpdateBundleForSelf) },
        ani_native_function { "uninstallUpdatesNative", nullptr, reinterpret_cast<void*>(AniUninstallUpdates) },
        ani_native_function { "addExtResourceNative", nullptr, reinterpret_cast<void*>(AniAddExtResource) },
        ani_native_function { "removeExtResourceNative", nullptr, reinterpret_cast<void*>(AniRemoveExtResource) },
        ani_native_function { "createAppCloneNative", nullptr, reinterpret_cast<void*>(AniCreateAppClone) },
        ani_native_function { "destroyAppCloneNative", nullptr, reinterpret_cast<void*>(AniDestroyAppClone) },
        ani_native_function { "installPreexistingAppNative", nullptr,
            reinterpret_cast<void*>(AniInstallPreexistingApp) },
        ani_native_function { "installPluginNative", nullptr, reinterpret_cast<void*>(AniInstallPlugin) },
        ani_native_function { "uninstallPluginNative", nullptr, reinterpret_cast<void*>(AniUninstallPlugin) },
    };
}
 
extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("bundle_installer ANI_Constructor called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");
    Namespace installerNs = Builder::BuildNamespace("@ohos.bundle.installer.installer");
    ani_namespace kitNs;
    res = env->FindNamespace(installerNs.Descriptor().c_str(), &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Not found nameSpace of @ohos.bundle.installer.installer");

    std::array methods = {
        ani_native_function { "getBundleInstallerNative", nullptr, reinterpret_cast<void*>(AniGetBundleInstaller) }
    };
    res = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods");
    APP_LOGI("BundleInstaller class binding");
    ani_class installerClz;
    res = env->FindClass(Builder::BuildClass(INNERINSTALLER_CLASSNAME).Descriptor().c_str(), &installerClz);
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
 