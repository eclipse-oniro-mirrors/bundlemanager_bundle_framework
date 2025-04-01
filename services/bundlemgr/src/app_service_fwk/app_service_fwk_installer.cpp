/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "app_service_fwk_installer.h"

#include "app_provision_info_manager.h"
#include "bundle_mgr_service.h"
#include "inner_patch_info.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "patch_data_mgr.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* HSP_VERSION_PREFIX = "v";
constexpr const char* HSP_PATH = ", path: ";
constexpr const char* SHARED_MODULE_TYPE = "shared";
constexpr const char* COMPILE_SDK_TYPE_OPEN_HARMONY = "OpenHarmony";
constexpr const char* DEBUG_APP_IDENTIFIER = "DEBUG_LIB_ID";
constexpr const char* APP_INSTALL_PATH = "/data/app/el1/bundle";
constexpr const int64_t FIVE_MB = 1024 * 1024 * 5; // 5MB
}

std::string ObtainTempSoPath(
    const std::string &moduleName, const std::string &nativeLibPath)
{
    std::string tempSoPath;
    if (nativeLibPath.empty()) {
        APP_LOGE("invalid native libs path");
        return tempSoPath;
    }
    tempSoPath = nativeLibPath;
    auto pos = tempSoPath.find(moduleName);
    if (pos == std::string::npos) {
        tempSoPath = moduleName + AppExecFwk::ServiceConstants::TMP_SUFFIX
            + AppExecFwk::ServiceConstants::PATH_SEPARATOR + tempSoPath;
    } else {
        std::string innerTempStr = moduleName + AppExecFwk::ServiceConstants::TMP_SUFFIX;
        tempSoPath.replace(pos, moduleName.length(), innerTempStr);
    }
    return tempSoPath + AppExecFwk::ServiceConstants::PATH_SEPARATOR;
};

void BuildCheckParam(
    const InstallParam &installParam, InstallCheckParam &checkParam)
{
    checkParam.isPreInstallApp = installParam.isPreInstallApp;
    checkParam.crowdtestDeadline = installParam.crowdtestDeadline;
    checkParam.appType = AppExecFwk::Constants::AppType::SYSTEM_APP;
    checkParam.removable = installParam.removable;
    checkParam.installBundlePermissionStatus = installParam.installBundlePermissionStatus;
    checkParam.installEnterpriseBundlePermissionStatus = installParam.installEnterpriseBundlePermissionStatus;
    checkParam.installEtpNormalBundlePermissionStatus = installParam.installEtpNormalBundlePermissionStatus;
    checkParam.installEtpMdmBundlePermissionStatus = installParam.installEtpMdmBundlePermissionStatus;
    checkParam.isCallByShell = installParam.isCallByShell;
    checkParam.needSendEvent = installParam.needSendEvent;
    checkParam.specifiedDistributionType = installParam.specifiedDistributionType;
};

AppServiceFwkInstaller::AppServiceFwkInstaller()
    : bundleInstallChecker_(std::make_unique<BundleInstallChecker>())
{
    APP_LOGI_NOFUNC("AppServiceFwk installer instance created");
}

AppServiceFwkInstaller::~AppServiceFwkInstaller()
{
    APP_LOGI_NOFUNC("AppServiceFwk installer instance destroyed");
}

ErrCode AppServiceFwkInstaller::Install(
    const std::vector<std::string> &hspPaths, InstallParam &installParam)
{
    ErrCode result = BeforeInstall(hspPaths, installParam);
    CHECK_RESULT(result, "BeforeInstall check failed %{public}d");
    result = ProcessInstall(hspPaths, installParam);
    APP_LOGI("%{public}s %{public}s result %{public}d first time", hspPaths[0].c_str(), bundleName_.c_str(), result);
    if (result != ERR_OK && installParam.copyHapToInstallPath) {
        PreInstallBundleInfo preInstallBundleInfo;
        if (!dataMgr_->GetPreInstallBundleInfo(bundleName_, preInstallBundleInfo) ||
            preInstallBundleInfo.GetBundlePaths().empty()) {
            APP_LOGE("get preInstallBundleInfo failed");
            return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
        }
        ResetProperties();
        auto uninstallRes = UnInstall(bundleName_, true);
        ResetProperties();
        InstallParam reinstallParam;
        reinstallParam.isPreInstallApp = true;
        reinstallParam.removable = false;
        reinstallParam.copyHapToInstallPath = false;
        reinstallParam.needSavePreInstallInfo = true;
        result = ProcessInstall(preInstallBundleInfo.GetBundlePaths(), reinstallParam);
        APP_LOGI("uninstallRes %{public}d installRes second time %{public}d", uninstallRes, result);
    } else if (result != ERR_OK && installParam.isOTA) {
        ResetProperties();
        auto uninstallRes = UnInstall(bundleName_, true);
        ResetProperties();
        result = ProcessInstall(hspPaths, installParam);
        APP_LOGI("uninstallRes %{public}d installRes second time %{public}d", uninstallRes, result);
    }
    SendBundleSystemEvent(
        hspPaths,
        BundleEventType::INSTALL,
        installParam,
        (installParam.isOTA ? InstallScene::REBOOT : InstallScene::BOOT),
        result);
    return result;
}

ErrCode AppServiceFwkInstaller::UnInstall(const std::string &bundleName, bool isKeepData)
{
    APP_LOGI("Uninstall bundle %{public}s", bundleName.c_str());
    if (BeforeUninstall(bundleName) != ERR_OK) {
        APP_LOGE("check bundleType failed for bundle %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_UNINSTALL_PARAM_ERROR;
    }
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START)) {
        APP_LOGE("uninstall already start");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS)) {
        APP_LOGE("delete inner info failed for bundle %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }
    PreInstallBundleInfo preInstallBundleInfo;
    if (dataMgr_->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        dataMgr_->DeletePreInstallBundleInfo(bundleName, preInstallBundleInfo);
    }
    std::string bundleDir =
        std::string(AppExecFwk::Constants::BUNDLE_CODE_DIR) +
        AppExecFwk::ServiceConstants::PATH_SEPARATOR + bundleName;
    APP_LOGI("start to remove bundle dir: %{public}s", bundleDir.c_str());
    if (InstalldClient::GetInstance()->RemoveDir(bundleDir) != ERR_OK) {
        APP_LOGW("remove bundle dir %{public}s failed", bundleDir.c_str());
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    if (!isKeepData) {
        InstalldClient::GetInstance()->RemoveBundleDataDir(bundleName, 0, false);
    }
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::UnInstall(
    const std::string &bundleName, const std::string &moduleName)
{
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("bundleName or moduleName is empty, param error");
        return ERR_APPEXECFWK_UNINSTALL_PARAM_ERROR;
    }
    APP_LOGI("bundle %{public}s module %{public}s need to be unstalled", bundleName.c_str(), moduleName.c_str());
    if (BeforeUninstall(bundleName) != ERR_OK) {
        APP_LOGE("check bundleType failed");
        return ERR_APPEXECFWK_UNINSTALL_PARAM_ERROR;
    }
    InnerBundleInfo info;
    if (!dataMgr_->GetInnerBundleInfoWithDisable(bundleName, info)) {
        APP_LOGE("get bundle info for %{public}s failed", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    if (CheckNeedUninstallBundle(moduleName, info)) {
        APP_LOGI("need uninstall bundle %{public}s", bundleName.c_str());
        return UnInstall(bundleName);
    }
    ScopeGuard enableGuard([&] { dataMgr_->EnableBundle(bundleName); });
    std::vector<std::string> installedModules;
    info.GetModuleNames(installedModules);
    if (std::find(installedModules.begin(), installedModules.end(), moduleName) == installedModules.end()) {
        APP_LOGE("Error: module %{public}s is not found in installedModules", moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }

    if (installedModules.size() == 1) {
        APP_LOGE("can not uninstall only one module");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START)) {
        APP_LOGE("uninstall already start");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }
    ScopeGuard stateGuard([&] { dataMgr_->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS); });
    auto result = UnInstall(bundleName, moduleName, info);
    if (result != ERR_OK) {
        APP_LOGE("uninstall failed, module %{public}s bundle %{public}s", moduleName.c_str(), bundleName.c_str());
        return result;
    }
    return ERR_OK;
}

void AppServiceFwkInstaller::ResetProperties()
{
    bundleMsg_ = "";
    uninstallModuleVec_.clear();
    versionUpgrade_ = false;
    moduleUpdate_ = false;
    deleteBundlePath_.clear();
    versionCode_ = 0;
    newInnerBundleInfo_ = InnerBundleInfo();
    isEnterpriseBundle_ = false;
    appIdentifier_ = "";
    compileSdkType_ = "";
    cpuAbi_ = "";
    nativeLibraryPath_ = "";
}

bool AppServiceFwkInstaller::CheckNeedUninstallBundle(const std::string &moduleName, const InnerBundleInfo &info)
{
    for (const auto &item : info.GetInnerModuleInfos()) {
        if (item.second.distro.moduleType == "shared" && item.second.moduleName != moduleName) {
            return false;
        }
    }
    return true;
}

ErrCode AppServiceFwkInstaller::UnInstall(
    const std::string &bundleName, const std::string &moduleName, InnerBundleInfo &oldInfo)
{
    // remove info & remove dir under el1
    APP_LOGI("start to remove module info of %{public}s in %{public}s ", moduleName.c_str(), bundleName.c_str());
    if (!dataMgr_->RemoveModuleInfo(bundleName, moduleName, oldInfo)) {
        APP_LOGE("RemoveModuleInfo failed");
        return ERR_APPEXECFWK_RMV_MODULE_ERROR;
    }
    RemoveModuleDataDir(bundleName, moduleName, oldInfo);
    return ERR_OK;
}

void AppServiceFwkInstaller::RemoveModuleDataDir(
    const std::string &bundleName, const std::string &moduleName, const InnerBundleInfo &oldInfo)
{
    APP_LOGI("start to remove module info of %{public}s in %{public}s ", moduleName.c_str(), bundleName.c_str());
    std::string moduleDir =
        std::string(AppExecFwk::Constants::BUNDLE_CODE_DIR) +
        AppExecFwk::ServiceConstants::PATH_SEPARATOR + bundleName +
        AppExecFwk::ServiceConstants::PATH_SEPARATOR + HSP_VERSION_PREFIX + std::to_string(oldInfo.GetVersionCode()) +
        AppExecFwk::ServiceConstants::PATH_SEPARATOR + moduleName;
    APP_LOGI("start to remove module dir: %{public}s", moduleDir.c_str());
    if (InstalldClient::GetInstance()->RemoveDir(moduleDir) != ERR_OK) {
        APP_LOGW("remove module dir %{public}s failed", moduleDir.c_str());
    }
}

ErrCode AppServiceFwkInstaller::BeforeInstall(
    const std::vector<std::string> &hspPaths, InstallParam &installParam)
{
    if (hspPaths.empty()) {
        APP_LOGE("HspPaths is empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr_ == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::BeforeUninstall(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr_ == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    BundleType type;
    if (!dataMgr_->GetBundleType(bundleName, type)) {
        APP_LOGE("get bundle type for %{public}s failed", bundleName.c_str());
        return ERR_APPEXECFWK_UNINSTALL_PARAM_ERROR;
    }
    return type == BundleType::APP_SERVICE_FWK ? ERR_OK : ERR_APPEXECFWK_UNINSTALL_PARAM_ERROR;
}

ErrCode AppServiceFwkInstaller::ProcessInstall(
    const std::vector<std::string> &hspPaths, InstallParam &installParam)
{
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    ErrCode result = CheckAndParseFiles(hspPaths, installParam, newInfos);
    CHECK_RESULT(result, "CheckAndParseFiles failed %{public}d");

    InnerBundleInfo oldInfo;
    bool isDowngrade = false;
    if (!CheckNeedInstall(newInfos, oldInfo, isDowngrade)) {
        if (isDowngrade) {
            APP_LOGE("version down grade install");
            return ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE;
        }
        APP_LOGI_NOFUNC("fwk not need install");
        return ERR_OK;
    }
    ScopeGuard stateGuard([&] {
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_SUCCESS);
        dataMgr_->EnableBundle(bundleName_);
    });

    if (versionUpgrade_ || moduleUpdate_) {
        result = UpdateAppService(oldInfo, newInfos, installParam);
        CHECK_RESULT(result, "UpdateAppService failed %{public}d");
    } else {
        result = InnerProcessInstall(newInfos, installParam);
        if (result != ERR_OK) {
            APP_LOGE("InnerProcessInstall failed %{public}d", result);
            RollBack();
            return result;
        }
    }
    SavePreInstallBundleInfo(result, newInfos, installParam);
    PatchDataMgr::GetInstance().ProcessPatchInfo(bundleName_, hspPaths,
        newInfos.begin()->second.GetVersionCode(), AppPatchType::SERVICE_FWK, installParam.isPatch);
    // check mark install finish
    result = MarkInstallFinish();
    if (result != ERR_OK) {
        APP_LOGE("mark install finish failed %{public}d", result);
        if (!versionUpgrade_ && !moduleUpdate_) {
            RollBack();
        }
        PatchDataMgr::GetInstance().DeleteInnerPatchInfo(bundleName_);
        return result;
    }
    return result;
}

void AppServiceFwkInstaller::SavePreInstallBundleInfo(ErrCode installResult,
    const std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InstallParam &installParam)
{
    if (installResult != ERR_OK) {
        APP_LOGW("install bundle %{public}s failed for %{public}d", bundleName_.c_str(), installResult);
        return;
    }
    if (!installParam.needSavePreInstallInfo) {
        APP_LOGI("no need to save pre info");
        return;
    }
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName_);
    dataMgr_->GetPreInstallBundleInfo(bundleName_, preInstallBundleInfo);
    preInstallBundleInfo.SetAppType(Constants::AppType::SYSTEM_APP);
    preInstallBundleInfo.SetVersionCode(versionCode_);
    preInstallBundleInfo.SetIsUninstalled(false);
    for (const std::string &bundlePath : deleteBundlePath_) {
        APP_LOGI_NOFUNC("preInstallBundleInfo delete path %{public}s", bundlePath.c_str());
        preInstallBundleInfo.DeleteBundlePath(bundlePath);
    }
    for (const auto &item : newInfos) {
        preInstallBundleInfo.AddBundlePath(item.first);
    }
    preInstallBundleInfo.SetRemovable(false);

    for (const auto &innerBundleInfo : newInfos) {
        auto applicationInfo = innerBundleInfo.second.GetBaseApplicationInfo();
        innerBundleInfo.second.AdaptMainLauncherResourceInfo(applicationInfo);
        preInstallBundleInfo.SetLabelId(applicationInfo.labelResource.id);
        preInstallBundleInfo.SetIconId(applicationInfo.iconResource.id);
        preInstallBundleInfo.SetModuleName(applicationInfo.labelResource.moduleName);
        preInstallBundleInfo.SetSystemApp(applicationInfo.isSystemApp);
        preInstallBundleInfo.SetBundleType(BundleType::APP_SERVICE_FWK);
        auto innerModuleInfos = innerBundleInfo.second.GetInnerModuleInfos();
        if (!innerModuleInfos.empty() &&
            innerModuleInfos.begin()->second.distro.moduleType == Profile::MODULE_TYPE_ENTRY) {
            break;
        }
    }
    if (!dataMgr_->SavePreInstallBundleInfo(bundleName_, preInstallBundleInfo)) {
        APP_LOGE("SavePreInstallBundleInfo for bundleName_ failed");
    }
}

ErrCode AppServiceFwkInstaller::CheckAndParseFiles(
    const std::vector<std::string> &hspPaths, InstallParam &installParam,
    std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    InstallCheckParam checkParam;
    BuildCheckParam(installParam, checkParam);

    std::vector<std::string> checkedHspPaths;
    // check hsp paths
    ErrCode result = BundleUtil::CheckFilePath(hspPaths, checkedHspPaths);
    CHECK_RESULT(result, "Hsp file check failed %{public}d");

    // check file type
    result = CheckFileType(checkedHspPaths);
    CHECK_RESULT(result, "Hsp suffix check failed %{public}d");

    // check syscap
    result = bundleInstallChecker_->CheckSysCap(checkedHspPaths);
    bool isSysCapValid = (result == ERR_OK);
    if (!isSysCapValid) {
        APP_LOGI("Hsp syscap check failed %{public}d", result);
    }

    // verify signature info for all haps
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    result = bundleInstallChecker_->CheckMultipleHapsSignInfo(
        checkedHspPaths, hapVerifyResults);
    CHECK_RESULT(result, "Hsp files check signature info failed %{public}d");

    result = bundleInstallChecker_->ParseHapFiles(
        checkedHspPaths, checkParam, hapVerifyResults, newInfos);
    CHECK_RESULT(result, "Parse hsps file failed %{public}d");

    // check install permission
    result = bundleInstallChecker_->CheckInstallPermission(checkParam, hapVerifyResults);
    CHECK_RESULT(result, "Check install permission failed %{public}d");

    // check hsp install condition
    result = bundleInstallChecker_->CheckHspInstallCondition(hapVerifyResults, IPCSkeleton::GetCallingUid());
    CHECK_RESULT(result, "Check hsp install condition failed %{public}d");

    // check device type
    if (!isSysCapValid) {
        result = bundleInstallChecker_->CheckDeviceType(newInfos);
        if (result != ERR_OK) {
            APP_LOGE("Check device type failed : %{public}d", result);
            return ERR_APPEXECFWK_INSTALL_SYSCAP_FAILED_AND_DEVICE_TYPE_ERROR;
        }
    }

    result = CheckAppLabelInfo(newInfos);
    CHECK_RESULT(result, "Check app label failed %{public}d");

    // delivery sign profile to code signature
    result = DeliveryProfileToCodeSign(hapVerifyResults);
    CHECK_RESULT(result, "delivery sign profile failed %{public}d");

    // check native file
    result = bundleInstallChecker_->CheckMultiNativeFile(newInfos);
    CHECK_RESULT(result, "Native so is incompatible in all hsps %{public}d");

    isEnterpriseBundle_ = bundleInstallChecker_->CheckEnterpriseBundle(hapVerifyResults[0]);
    appIdentifier_ = (hapVerifyResults[0].GetProvisionInfo().type == Security::Verify::ProvisionType::DEBUG) ?
        DEBUG_APP_IDENTIFIER : hapVerifyResults[0].GetProvisionInfo().bundleInfo.appIdentifier;
    compileSdkType_ = newInfos.empty() ? COMPILE_SDK_TYPE_OPEN_HARMONY :
        (newInfos.begin()->second).GetBaseApplicationInfo().compileSdkType;

    GenerateOdid(newInfos, hapVerifyResults);
    AddAppProvisionInfo(bundleName_, hapVerifyResults[0].GetProvisionInfo(), installParam);
    return result;
}

void AppServiceFwkInstaller::GenerateOdid(
    std::unordered_map<std::string, InnerBundleInfo> &infos,
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const
{
    if (hapVerifyRes.size() < infos.size() || infos.empty()) {
        APP_LOGE("hapVerifyRes size less than infos size or infos is empty");
        return;
    }

    std::string developerId = hapVerifyRes[0].GetProvisionInfo().bundleInfo.developerId;
    if (developerId.empty()) {
        developerId = hapVerifyRes[0].GetProvisionInfo().bundleInfo.bundleName;
    }
    std::string odid;
    dataMgr_->GenerateOdid(developerId, odid);

    for (auto &item : infos) {
        item.second.UpdateOdid(developerId, odid);
    }
}

ErrCode AppServiceFwkInstaller::CheckFileType(const std::vector<std::string> &bundlePaths)
{
    if (bundlePaths.empty()) {
        APP_LOGE("check hsp suffix failed due to empty bundlePaths");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    for (const auto &bundlePath : bundlePaths) {
        if (!BundleUtil::CheckFileType(bundlePath, ServiceConstants::HSP_FILE_SUFFIX)) {
            APP_LOGE("Hsp %{public}s suffix check failed", bundlePath.c_str());
            return ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME;
        }
    }

    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::CheckAppLabelInfo(
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    for (const auto &info : infos) {
        if (info.second.GetApplicationBundleType() != BundleType::APP_SERVICE_FWK) {
            APP_LOGE("App BundleType is not AppService");
            return ERR_APP_SERVICE_FWK_INSTALL_TYPE_FAILED;
        }

        auto moduleInfo = info.second.GetInnerModuleInfoByModuleName(info.second.GetCurModuleName());
        if (moduleInfo && moduleInfo->bundleType != BundleType::SHARED) {
            APP_LOGE("Module BundleType is not Shared");
            return ERR_APP_SERVICE_FWK_INSTALL_TYPE_FAILED;
        }
    }

    ErrCode ret = bundleInstallChecker_->CheckAppLabelInfo(infos);
    if (ret != ERR_OK) {
        APP_LOGE("CheckAppLabelInfo failed, ret %{public}d", ret);
        return ret;
    }

    bundleName_ = (infos.begin()->second).GetBundleName();
    versionCode_ = (infos.begin()->second).GetVersionCode();
    return ERR_OK;
}

void AppServiceFwkInstaller::AddAppProvisionInfo(
    const std::string &bundleName,
    const Security::Verify::ProvisionInfo &provisionInfo,
    const InstallParam &installParam) const
{
    AppProvisionInfo appProvisionInfo = bundleInstallChecker_->ConvertToAppProvisionInfo(provisionInfo);
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        bundleName, appProvisionInfo)) {
        APP_LOGW("BundleName %{public}s add appProvisionInfo failed", bundleName.c_str());
    }

    if (!installParam.specifiedDistributionType.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetSpecifiedDistributionType(
            bundleName, installParam.specifiedDistributionType)) {
            APP_LOGW("BundleName %{public}s SetSpecifiedDistributionType failed", bundleName.c_str());
        }
    }

    if (!installParam.additionalInfo.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetAdditionalInfo(
            bundleName, installParam.additionalInfo)) {
            APP_LOGW("BundleName %{public}s SetAdditionalInfo failed", bundleName.c_str());
        }
    }
}

ErrCode AppServiceFwkInstaller::InnerProcessInstall(
    std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InstallParam &installParam)
{
    APP_LOGI("start -n %{public}s, size: %{public}zu",
        bundleName_.c_str(), newInfos.size());
    ErrCode result = ERR_OK;
    for (auto it = newInfos.begin(); it != newInfos.end(); ++it) {
        InnerBundleInfo &newInfo = it->second;
        APP_LOGD("InnerProcessInstall module %{public}s",
            newInfo.GetCurrentModulePackage().c_str());
        result = ExtractModule(newInfo, it->first, installParam.copyHapToInstallPath);
        if (result != ERR_OK) {
            return result;
        }
        newInfo.SetApplicationFlags(installParam.preinstallSourceFlag);
        MergeBundleInfos(newInfo);
    }

    return SaveBundleInfoToStorage();
}

ErrCode AppServiceFwkInstaller::ExtractModule(
    InnerBundleInfo &newInfo, const std::string &bundlePath, bool copyHapToInstallPath)
{
    APP_LOGI_NOFUNC("begin ExtractModule with %{public}s bundlePath %{public}s",
        newInfo.GetCurrentModulePackage().c_str(), bundlePath.c_str());
    ErrCode result = ERR_OK;
    std::string bundleDir =
        std::string(AppExecFwk::Constants::BUNDLE_CODE_DIR) +
        AppExecFwk::ServiceConstants::PATH_SEPARATOR + bundleName_;
    result = MkdirIfNotExist(bundleDir);
    CHECK_RESULT(result, "Check bundle dir failed %{public}d");

    newInfo.SetAppCodePath(bundleDir);
    uint32_t versionCode = newInfo.GetVersionCode();
    std::string versionDir = bundleDir
        + AppExecFwk::ServiceConstants::PATH_SEPARATOR + HSP_VERSION_PREFIX + std::to_string(versionCode);
    result = MkdirIfNotExist(versionDir);
    CHECK_RESULT(result, "Check version dir failed %{public}d");

    auto &moduleName = newInfo.GetInnerModuleInfos().begin()->second.moduleName;
    std::string moduleDir = versionDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR + moduleName;
    result = MkdirIfNotExist(moduleDir);
    CHECK_RESULT(result, "Check module dir failed %{public}d");

    result = ProcessNativeLibrary(bundlePath, moduleDir, moduleName, versionDir, newInfo, copyHapToInstallPath);
    CHECK_RESULT(result, "ProcessNativeLibrary failed %{public}d");

    // preInstallHsp does not need to copy
    newInfo.SetModuleHapPath(bundlePath);
    newInfo.AddModuleSrcDir(moduleDir);
    newInfo.AddModuleResPath(moduleDir);

    if (copyHapToInstallPath) {
        std::string realHspPath = moduleDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR +
            moduleName + ServiceConstants::HSP_FILE_SUFFIX;
        result = InstalldClient::GetInstance()->CopyFile(bundlePath, realHspPath);
        newInfo.SetModuleHapPath(realHspPath);
        CHECK_RESULT(result, "move hsp to install dir failed %{public}d");

        std::string realSoPath = versionDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR +
            nativeLibraryPath_;
        result = VerifyCodeSignatureForHsp(realHspPath, realSoPath);
        CHECK_RESULT(result, "verify code sign failed %{public}d");
    }
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::VerifyCodeSignatureForHsp(
    const std::string &realHspPath, const std::string &realSoPath) const
{
    APP_LOGI("begin to verify code sign for hsp");
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = realHspPath;
    codeSignatureParam.targetSoPath = realSoPath;
    codeSignatureParam.cpuAbi = cpuAbi_;
    codeSignatureParam.appIdentifier = appIdentifier_;
    codeSignatureParam.signatureFileDir = "";
    codeSignatureParam.isEnterpriseBundle = isEnterpriseBundle_;
    codeSignatureParam.isCompileSdkOpenHarmony = (compileSdkType_ == COMPILE_SDK_TYPE_OPEN_HARMONY);
    codeSignatureParam.isPreInstalledBundle = false;
    codeSignatureParam.isCompressNativeLibrary = isCompressNativeLibs_;
    return InstalldClient::GetInstance()->VerifyCodeSignatureForHap(codeSignatureParam);
}

ErrCode AppServiceFwkInstaller::ExtractModule(InnerBundleInfo &oldInfo,
    InnerBundleInfo &newInfo, const std::string &bundlePath)
{
    ErrCode result = ERR_OK;
    std::string bundleDir =
        std::string(AppExecFwk::Constants::BUNDLE_CODE_DIR) +
        AppExecFwk::ServiceConstants::PATH_SEPARATOR + bundleName_;
    result = MkdirIfNotExist(bundleDir);
    CHECK_RESULT(result, "Check bundle dir failed %{public}d");

    oldInfo.SetAppCodePath(bundleDir);
    uint32_t versionCode = newInfo.GetVersionCode();
    std::string versionDir = bundleDir
        + AppExecFwk::ServiceConstants::PATH_SEPARATOR + HSP_VERSION_PREFIX + std::to_string(versionCode);
    result = MkdirIfNotExist(versionDir);
    CHECK_RESULT(result, "Check version dir failed %{public}d");

    auto &moduleName = newInfo.GetInnerModuleInfos().begin()->second.moduleName;
    std::string moduleDir = versionDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR + moduleName;
    result = MkdirIfNotExist(moduleDir);
    CHECK_RESULT(result, "Check module dir failed %{public}d");

    result = ProcessNativeLibrary(bundlePath, moduleDir, moduleName, versionDir, newInfo);
    CHECK_RESULT(result, "ProcessNativeLibrary failed %{public}d");

    // preInstallHsp does not need to copy
    oldInfo.SetModuleHapPath(bundlePath);
    oldInfo.AddModuleSrcDir(moduleDir);
    oldInfo.AddModuleResPath(moduleDir);
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::MkdirIfNotExist(const std::string &dir)
{
    bool isDirExist = false;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(dir, isDirExist);
    CHECK_RESULT(result, "Check if dir exist failed %{public}d");

    if (!isDirExist) {
        result = InstalldClient::GetInstance()->CreateBundleDir(dir);
        CHECK_RESULT(result, "Create dir failed %{public}d");
    }
    return result;
}

ErrCode AppServiceFwkInstaller::ProcessNativeLibrary(
    const std::string &bundlePath,
    const std::string &moduleDir,
    const std::string &moduleName,
    const std::string &versionDir,
    InnerBundleInfo &newInfo,
    bool copyHapToInstallPath)
{
    APP_LOGI_NOFUNC("ProcessNativeLibrary %{public}s %{public}s", bundlePath.c_str(), moduleDir.c_str());
    if (!newInfo.FetchNativeSoAttrs(moduleName, cpuAbi_, nativeLibraryPath_)) {
        return ERR_OK;
    }
    isCompressNativeLibs_ = newInfo.IsCompressNativeLibs(moduleName);
    if (isCompressNativeLibs_) {
        std::string tempNativeLibraryPath = ObtainTempSoPath(moduleName, nativeLibraryPath_);
        if (tempNativeLibraryPath.empty()) {
            APP_LOGE("tempNativeLibraryPath is empty");
            return ERR_APPEXECFWK_INSTALLD_EXTRACT_FILES_FAILED;
        }

        std::string tempSoPath =
            versionDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR + tempNativeLibraryPath;
        APP_LOGI_NOFUNC("TempSoPath %{public}s cpuAbi %{public}s", tempSoPath.c_str(), cpuAbi_.c_str());
        auto result = InstalldClient::GetInstance()->ExtractModuleFiles(
            bundlePath, moduleDir, tempSoPath, cpuAbi_);
        CHECK_RESULT(result, "Extract module files failed %{public}d");
        if (!copyHapToInstallPath) {
            // verify hap or hsp code signature for compressed so files
            result = VerifyCodeSignatureForNativeFiles(bundlePath, cpuAbi_, tempSoPath);
            CHECK_RESULT(result, "fail to VerifyCodeSignature, error is %{public}d");
        }
        // move so to real path
        result = MoveSoToRealPath(moduleName, versionDir, nativeLibraryPath_);
        CHECK_RESULT(result, "Move so to real path failed %{public}d");
    } else {
        std::vector<std::string> fileNames;
        auto result = InstalldClient::GetInstance()->GetNativeLibraryFileNames(
            bundlePath, cpuAbi_, fileNames);
        CHECK_RESULT(result, "Fail to GetNativeLibraryFileNames, error is %{public}d");
        newInfo.SetNativeLibraryFileNames(moduleName, fileNames);
    }
    return ERR_OK;
}

void AppServiceFwkInstaller::MergeBundleInfos(InnerBundleInfo &info)
{
    if (newInnerBundleInfo_.GetBundleName().empty()) {
        newInnerBundleInfo_ = info;
        return;
    }

    newInnerBundleInfo_.AddModuleInfo(info);
}

ErrCode AppServiceFwkInstaller::SaveBundleInfoToStorage()
{
    newInnerBundleInfo_.SetInstallMark(bundleName_, newInnerBundleInfo_.GetCurModuleName(),
        InstallExceptionStatus::INSTALL_START);
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_START)) {
        APP_LOGE("UpdateBundleInstallState failed");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }

    if (!dataMgr_->AddInnerBundleInfo(bundleName_, newInnerBundleInfo_)) {
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_START);
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_SUCCESS);
        APP_LOGE("Save bundle failed %{public}s", bundleName_.c_str());
        return ERR_APPEXECFWK_ADD_BUNDLE_ERROR;
    }

    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::MoveSoToRealPath(
    const std::string &moduleName, const std::string &versionDir,
    const std::string &nativeLibraryPath)
{
    // 1. move so files to real installation dir
    std::string realSoPath = versionDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR
        + nativeLibraryPath + AppExecFwk::ServiceConstants::PATH_SEPARATOR;
    ErrCode result = MkdirIfNotExist(realSoPath);
    CHECK_RESULT(result, "Check module dir failed %{public}d");
    std::string tempNativeLibraryPath = ObtainTempSoPath(moduleName, nativeLibraryPath);
    if (tempNativeLibraryPath.empty()) {
        APP_LOGI("No so libs existed");
        return ERR_OK;
    }

    std::string tempSoPath =
        versionDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR + tempNativeLibraryPath;
    APP_LOGD("Move so files from path %{public}s to path %{public}s",
        tempSoPath.c_str(), realSoPath.c_str());
    bool isDirExist = false;
    result = InstalldClient::GetInstance()->IsExistDir(tempSoPath, isDirExist);
    CHECK_RESULT(result, "Check temp so dir failed %{public}d");
    if (!isDirExist) {
        APP_LOGI("temp so dir not exist");
        return ERR_OK;
    }
    result = InstalldClient::GetInstance()->MoveFiles(tempSoPath, realSoPath);
    if (result != ERR_OK) {
        APP_LOGE("Move to real path failed %{public}d", result);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }

    // 2. remove so temp dir
    std::string deleteTempDir = versionDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR
        + moduleName + AppExecFwk::ServiceConstants::TMP_SUFFIX;
    result = InstalldClient::GetInstance()->RemoveDir(deleteTempDir);
    if (result != ERR_OK) {
        APP_LOGW("Remove temp dir %{public}s failed %{public}d",
            deleteTempDir.c_str(), result);
    }
    return ERR_OK;
}

void AppServiceFwkInstaller::RollBack()
{
    APP_LOGI("RollBack: %{public}s", bundleName_.c_str());
    if (newInnerBundleInfo_.IsPreInstallApp() && !BundleUtil::CheckSystemFreeSize(APP_INSTALL_PATH, FIVE_MB)) {
        APP_LOGW("pre bundle: %{public}s no rollback due to no space", bundleName_.c_str());
        return;
    }

    // RemoveCache
    RemoveInfo(bundleName_);
}

ErrCode AppServiceFwkInstaller::UpdateAppService(
    InnerBundleInfo &oldInfo,
    std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InstallParam &installParam)
{
    APP_LOGI_NOFUNC("UpdateAppService for bundle %{public}s", oldInfo.GetBundleName().c_str());
    auto oldVersionCode = oldInfo.GetVersionCode();
    // update
    ErrCode result = ERR_OK;
    for (auto &item : newInfos) {
        if ((result = ProcessBundleUpdateStatus(oldInfo, item.second, item.first, installParam)) != ERR_OK) {
            APP_LOGE("ProcessBundleUpdateStatus failed %{public}d", result);
            return result;
        }
    }
    if (!uninstallModuleVec_.empty()) {
        result = UninstallLowerVersion(uninstallModuleVec_);
        if (result != ERR_OK) {
            APP_LOGE("UninstallLowerVersion failed %{public}d", result);
            return result;
        }
    }
    if (oldVersionCode < versionCode_) {
        RemoveLowerVersionSoDir(oldVersionCode);
    }

    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::ProcessBundleUpdateStatus(InnerBundleInfo &oldInfo,
    InnerBundleInfo &newInfo, const std::string &hspPath, const InstallParam &installParam)
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    APP_LOGI_NOFUNC("ProcessBundleUpdateStatus for module %{public}s", moduleName.c_str());
    if (moduleName.empty()) {
        APP_LOGE("get current package failed");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }
    if (versionUpgrade_) {
        APP_LOGI_NOFUNC("uninstallModuleVec_ insert module %{public}s", moduleName.c_str());
        uninstallModuleVec_.emplace_back(moduleName);
    }
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_START)) {
        APP_LOGE("update already start");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }
    // 1. bundle exist, module exist, update module
    // 2. bundle exist, install new hsp
    bool isModuleExist = oldInfo.FindModule(moduleName);
    APP_LOGI("module %{public}s isModuleExist %{public}d", moduleName.c_str(), isModuleExist);

    auto result = isModuleExist ? ProcessModuleUpdate(newInfo, oldInfo, hspPath, installParam) :
        ProcessNewModuleInstall(newInfo, oldInfo, hspPath, installParam);
    if (result != ERR_OK) {
        APP_LOGE("install module failed %{public}d", result);
        return result;
    }
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::ProcessModuleUpdate(InnerBundleInfo &newInfo,
    InnerBundleInfo &oldInfo, const std::string &hspPath, const InstallParam &installParam)
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    APP_LOGD("ProcessModuleUpdate, bundleName : %{public}s, moduleName : %{public}s",
        newInfo.GetBundleName().c_str(), moduleName.c_str());
    if (oldInfo.GetModuleTypeByPackage(moduleName) != SHARED_MODULE_TYPE) {
        APP_LOGE("moduleName is inconsistent in the updating hap");
        return ERR_APPEXECFWK_INSTALL_INCONSISTENT_MODULE_NAME;
    }
    oldInfo.SetInstallMark(bundleName_, moduleName, InstallExceptionStatus::UPDATING_EXISTED_START);

    std::string oldHspPath = oldInfo.GetModuleHapPath(moduleName);
    if (!oldHspPath.empty()) {
        APP_LOGI_NOFUNC("deleteBundlePath_ insert path %{public}s", oldHspPath.c_str());
        deleteBundlePath_.emplace_back(oldHspPath);
    }

    auto result = ExtractModule(newInfo, hspPath, installParam.copyHapToInstallPath);
    CHECK_RESULT(result, "ExtractModule failed %{public}d");

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
        APP_LOGE("old module update state failed");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }

    oldInfo.SetBundleUpdateTime(BundleUtil::GetCurrentTimeMs(), Constants::DEFAULT_USERID);
    if (!dataMgr_->UpdateInnerBundleInfo(bundleName_, newInfo, oldInfo)) {
        APP_LOGE("update innerBundleInfo %{public}s failed", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::ProcessNewModuleInstall(InnerBundleInfo &newInfo,
    InnerBundleInfo &oldInfo, const std::string &hspPath, const InstallParam &installParam)
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    APP_LOGD("ProcessNewModuleInstall, bundleName : %{public}s, moduleName : %{public}s",
        newInfo.GetBundleName().c_str(), moduleName.c_str());
    if (bundleInstallChecker_->IsContainModuleName(newInfo, oldInfo)) {
        APP_LOGE("moduleName is already existed");
        return ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME;
    }

    oldInfo.SetInstallMark(bundleName_, moduleName, InstallExceptionStatus::UPDATING_NEW_START);

    auto result = ExtractModule(newInfo, hspPath, installParam.copyHapToInstallPath);
    if (result != ERR_OK) {
        APP_LOGE("extract module and rename failed");
        return result;
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
        APP_LOGE("new moduleupdate state failed");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }

    oldInfo.SetBundleUpdateTime(BundleUtil::GetCurrentTimeMs(), Constants::DEFAULT_USERID);
    if (!dataMgr_->AddNewModuleInfo(bundleName_, newInfo, oldInfo)) {
        APP_LOGE(
            "add module %{public}s to innerBundleInfo %{public}s failed", moduleName.c_str(), bundleName_.c_str());
        return ERR_APPEXECFWK_ADD_MODULE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::UninstallLowerVersion(const std::vector<std::string> &moduleNameList)
{
    APP_LOGI_NOFUNC("start to uninstall lower version module");
    InnerBundleInfo info;
    bool isExist = false;
    if (!GetInnerBundleInfoWithDisable(info, isExist) || !isExist) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_START)) {
        APP_LOGE("uninstall already start");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }

    std::vector<std::string> moduleVec = info.GetModuleNameVec();
    InnerBundleInfo oldInfo = info;
    for (const auto &package : moduleVec) {
        if (find(moduleNameList.begin(), moduleNameList.end(), package) == moduleNameList.end()) {
            APP_LOGI("uninstall package %{public}s", package.c_str());
            if (!dataMgr_->RemoveModuleInfo(bundleName_, package, info)) {
                APP_LOGE("RemoveModuleInfo failed");
                return ERR_APPEXECFWK_RMV_MODULE_ERROR;
            }
        }
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_SUCCESS)) {
        APP_LOGE("uninstall already start");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }
    return ERR_OK;
}

bool AppServiceFwkInstaller::GetInnerBundleInfoWithDisable(InnerBundleInfo &info, bool &isAppExist)
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            APP_LOGE("Get dataMgr shared_ptr nullptr");
            return false;
        }
    }
    isAppExist = dataMgr_->GetInnerBundleInfoWithDisable(bundleName_, info);
    return true;
}

void AppServiceFwkInstaller::RemoveInfo(const std::string &bundleName)
{
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS)) {
        APP_LOGE("Delete inner info failed");
    }
}

void AppServiceFwkInstaller::SendBundleSystemEvent(
    const std::vector<std::string> &hspPaths, BundleEventType bundleEventType,
    const InstallParam &installParam, InstallScene preBundleScene, ErrCode errCode)
{
    EventInfo sysEventInfo;
    sysEventInfo.bundleName = bundleName_;
    sysEventInfo.isPreInstallApp = installParam.isPreInstallApp;
    sysEventInfo.errCode = errCode;
    sysEventInfo.userId = Constants::ALL_USERID;
    sysEventInfo.versionCode = versionCode_;
    sysEventInfo.preBundleScene = preBundleScene;
    sysEventInfo.filePath = hspPaths;
    sysEventInfo.callingUid = IPCSkeleton::GetCallingUid();
    EventReport::SendBundleSystemEvent(bundleEventType, sysEventInfo);
}

bool AppServiceFwkInstaller::CheckNeedInstall(const std::unordered_map<std::string, InnerBundleInfo> &infos,
    InnerBundleInfo &oldInfo, bool &isDowngrade)
{
    if (infos.empty()) {
        APP_LOGW("innerbundleinfos is empty");
        return false;
    }
    if (!(dataMgr_->FetchInnerBundleInfo(bundleName_, oldInfo))) {
        APP_LOGD("bundleName %{public}s not existed local", bundleName_.c_str());
        return true;
    }
    APP_LOGI_NOFUNC("%{public}s old version:%{public}d, new version:%{public}d",
        bundleName_.c_str(), oldInfo.GetVersionCode(), versionCode_);

    if ((oldInfo.GetVersionCode() == versionCode_) &&
        oldInfo.GetApplicationBundleType() != BundleType::APP_SERVICE_FWK) {
        APP_LOGW("bundle %{public}s type is not same, existing type is %{public}d",
            bundleName_.c_str(), oldInfo.GetApplicationBundleType());
        return false;
    }
    if (oldInfo.GetVersionCode() > versionCode_) {
        isDowngrade = true;
        APP_LOGW("version code is lower than current app service");
        return false;
    }

    for (const auto &item : infos) {
        if (CheckNeedUpdate(item.second, oldInfo)) {
            return true;
        }
    }
    return false;
}

bool AppServiceFwkInstaller::CheckNeedUpdate(const InnerBundleInfo &newInfo, const InnerBundleInfo &oldInfo)
{
    auto oldVersionCode = oldInfo.GetVersionCode();
    if (oldVersionCode > versionCode_) {
        APP_LOGW_NOFUNC("fwk new version code is lower than current");
        return false;
    } else if (oldVersionCode < versionCode_) {
        APP_LOGW_NOFUNC("fwk upgrade old version:%{public}d new version: %{public}d", oldVersionCode, versionCode_);
        versionUpgrade_ = true;
        return true;
    }
    std::string moduleName { newInfo.GetCurModuleName() };
    std::string buildHashOld;
    if (!oldInfo.GetModuleBuildHash(moduleName, buildHashOld)) {
        APP_LOGD("module %{public}s is a new module", moduleName.c_str());
        moduleUpdate_ = true;
        return true;
    }
    std::string buildHashNew;
    if (!newInfo.GetModuleBuildHash(moduleName, buildHashNew)) {
        APP_LOGD("GetModuleBuildHash from module %{public}s failed", moduleName.c_str());
        return false;
    }
    if (buildHashOld != buildHashNew) {
        APP_LOGD("module %{public}s buildHash has changed", moduleName.c_str());
        moduleUpdate_ = true;
        return true;
    }
    return false;
}

ErrCode AppServiceFwkInstaller::RemoveLowerVersionSoDir(uint32_t versionCode)
{
    if (!versionUpgrade_) {
        APP_LOGW("versionCode is not upgraded, so there is no need to delete the so dir");
        return ERR_OK;
    }
    std::string bundleDir =
        std::string(AppExecFwk::Constants::BUNDLE_CODE_DIR) +
        AppExecFwk::ServiceConstants::PATH_SEPARATOR + bundleName_;
    std::string versionDir = bundleDir
        + AppExecFwk::ServiceConstants::PATH_SEPARATOR + HSP_VERSION_PREFIX + std::to_string(versionCode);
    APP_LOGI_NOFUNC("RemoveLowerVersionSoDir %{public}s", versionDir.c_str());
    return InstalldClient::GetInstance()->RemoveDir(versionDir);
}

ErrCode AppServiceFwkInstaller::VerifyCodeSignatureForNativeFiles(const std::string &bundlePath,
    const std::string &cpuAbi, const std::string &targetSoPath) const
{
    APP_LOGD("begin to verify code signature for hsp native files");
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = bundlePath;
    codeSignatureParam.cpuAbi = cpuAbi;
    codeSignatureParam.targetSoPath = targetSoPath;
    codeSignatureParam.signatureFileDir = "";
    codeSignatureParam.isEnterpriseBundle = isEnterpriseBundle_;
    codeSignatureParam.appIdentifier = appIdentifier_;
    codeSignatureParam.isCompileSdkOpenHarmony = (compileSdkType_ == COMPILE_SDK_TYPE_OPEN_HARMONY);
    codeSignatureParam.isPreInstalledBundle = true;
    return InstalldClient::GetInstance()->VerifyCodeSignature(codeSignatureParam);
}

ErrCode AppServiceFwkInstaller::DeliveryProfileToCodeSign(
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults) const
{
    InnerBundleInfo oldInfo;
    if (dataMgr_->FetchInnerBundleInfo(bundleName_, oldInfo)) {
        APP_LOGD("shared bundle %{public}s has been installed and unnecessary to delivery sign profile",
            bundleName_.c_str());
        return ERR_OK;
    }
    if (hapVerifyResults.empty()) {
        APP_LOGE("no sign info in the all haps");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }

    Security::Verify::ProvisionInfo provisionInfo = hapVerifyResults[0].GetProvisionInfo();
    if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM ||
        provisionInfo.type == Security::Verify::ProvisionType::DEBUG) {
        if (provisionInfo.profileBlockLength == 0 || provisionInfo.profileBlock == nullptr) {
            APP_LOGE("invalid sign profile");
            return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
        }
        return InstalldClient::GetInstance()->DeliverySignProfile(provisionInfo.bundleInfo.bundleName,
            provisionInfo.profileBlockLength, provisionInfo.profileBlock.get());
    }
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::MarkInstallFinish()
{
    if (dataMgr_ == nullptr) {
        APP_LOGE("dataMgr_ is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    InnerBundleInfo info;
    if (!dataMgr_->FetchInnerBundleInfo(bundleName_, info)) {
        APP_LOGE("mark finish failed, -n %{public}s not exist", bundleName_.c_str());
        return ERR_APPEXECFWK_FETCH_BUNDLE_ERROR;
    }
    info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    info.SetInstallMark(bundleName_, info.GetCurModuleName(), InstallExceptionStatus::INSTALL_FINISH);
    if (!dataMgr_->UpdateInnerBundleInfo(info, true)) {
        if (!dataMgr_->UpdateInnerBundleInfo(info, true)) {
            APP_LOGE("save mark failed, -n %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_UPDATE_BUNDLE_ERROR;
        }
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
