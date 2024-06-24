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

#include "app_log_wrapper.h"
#include "app_provision_info_manager.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "preinstalled_application_info.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string HSP_VERSION_PREFIX = "v";
const std::string HSP_PATH = ", path: ";
const std::string SHARED_MODULE_TYPE = "shared";
const std::string COMPILE_SDK_TYPE_OPEN_HARMONY = "OpenHarmony";
const std::string DEBUG_APP_IDENTIFIER = "DEBUG_LIB_ID";

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
}

AppServiceFwkInstaller::AppServiceFwkInstaller()
    : bundleInstallChecker_(std::make_unique<BundleInstallChecker>())
{
    APP_LOGI("AppServiceFwk installer instance is created");
}

AppServiceFwkInstaller::~AppServiceFwkInstaller()
{
    APP_LOGI("AppServiceFwk installer instance is destroyed");
}

ErrCode AppServiceFwkInstaller::Install(
    const std::vector<std::string> &hspPaths, InstallParam &installParam)
{
    ErrCode result = BeforeInstall(hspPaths, installParam);
    CHECK_RESULT(result, "BeforeInstall check failed %{public}d");
    result = ProcessInstall(hspPaths, installParam);
    APP_LOGI("install result %{public}d", result);
    SendBundleSystemEvent(
        hspPaths,
        BundleEventType::INSTALL,
        installParam,
        InstallScene::BOOT,
        result);
    return result;
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
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    if (!installParam.isPreInstallApp) {
        return ERR_APP_SERVICE_FWK_INSTALL_NOT_PREINSTALL;
    }

    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::ProcessInstall(
    const std::vector<std::string> &hspPaths, InstallParam &installParam)
{
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    ErrCode result = CheckAndParseFiles(hspPaths, installParam, newInfos);
    CHECK_RESULT(result, "CheckAndParseFiles failed %{public}d");

    InnerBundleInfo oldInfo;
    if (!CheckNeedInstall(newInfos, oldInfo)) {
        APP_LOGI("need not to install");
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
        }
    }
    SavePreInstallBundleInfo(result, newInfos);
    return result;
}

void AppServiceFwkInstaller::SavePreInstallBundleInfo(
    ErrCode installResult, const std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    if (installResult != ERR_OK) {
        APP_LOGW("install bundle %{public}s failed for %{public}d", bundleName_.c_str(), installResult);
        return;
    }
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName_);
    dataMgr_->GetPreInstallBundleInfo(bundleName_, preInstallBundleInfo);
    preInstallBundleInfo.SetAppType(Constants::AppType::SYSTEM_APP);
    preInstallBundleInfo.SetVersionCode(versionCode_);
    preInstallBundleInfo.SetIsUninstalled(false);
    for (const std::string &bundlePath : deleteBundlePath_) {
        APP_LOGI("preInstallBundleInfo delete path %{public}s", bundlePath.c_str());
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
        auto bundleInfo = innerBundleInfo.second.GetBaseBundleInfo();
        if (!bundleInfo.hapModuleInfos.empty() &&
            bundleInfo.hapModuleInfos[0].moduleType == ModuleType::ENTRY) {
            break;
        }
    }
    if (!dataMgr_->SavePreInstallBundleInfo(bundleName_, preInstallBundleInfo)) {
        APP_LOGE("SavePreInstallBundleInfo for bundleName_ failed.");
    }
}

ErrCode AppServiceFwkInstaller::CheckAndParseFiles(
    const std::vector<std::string> &hspPaths, InstallParam &installParam,
    std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    APP_LOGI("CheckAndParseFiles Start");
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
    CHECK_RESULT(result, "Hsp syscap check failed %{public}d");

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
    result = bundleInstallChecker_->CheckHspInstallCondition(hapVerifyResults);
    CHECK_RESULT(result, "Check hsp install condition failed %{public}d");

    // check device type
    result = bundleInstallChecker_->CheckDeviceType(newInfos);
    CHECK_RESULT(result, "Check device type failed %{public}d");

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
    APP_LOGI("CheckAndParseFiles End, newInfos size: %{public}zu", newInfos.size());
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
        APP_LOGE("CheckAppLabelInfo failed, result: %{public}d", ret);
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
        APP_LOGW("BundleName: %{public}s add appProvisionInfo failed.", bundleName.c_str());
    }

    if (!installParam.specifiedDistributionType.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetSpecifiedDistributionType(
            bundleName, installParam.specifiedDistributionType)) {
            APP_LOGW("BundleName: %{public}s SetSpecifiedDistributionType failed.", bundleName.c_str());
        }
    }

    if (!installParam.additionalInfo.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetAdditionalInfo(
            bundleName, installParam.additionalInfo)) {
            APP_LOGW("BundleName: %{public}s SetAdditionalInfo failed.", bundleName.c_str());
        }
    }
}

ErrCode AppServiceFwkInstaller::InnerProcessInstall(
    std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InstallParam &installParam)
{
    APP_LOGI("InnerProcessInstall start bundleName: %{public}s, size: %{public}zu",
        bundleName_.c_str(), newInfos.size());
    ErrCode result = ERR_OK;
    for (auto it = newInfos.begin(); it != newInfos.end(); ++it) {
        InnerBundleInfo &newInfo = it->second;
        APP_LOGD("InnerProcessInstall module %{public}s",
            newInfo.GetCurrentModulePackage().c_str());
        result = ExtractModule(newInfo, it->first);
        if (result != ERR_OK) {
            return result;
        }

        MergeBundleInfos(newInfo);
    }

    return SaveBundleInfoToStorage();
}

ErrCode AppServiceFwkInstaller::ExtractModule(
    InnerBundleInfo &newInfo, const std::string &bundlePath)
{
    APP_LOGI("begin to ExtractModule with %{public}s bundlePath %{public}s",
        newInfo.GetCurrentModulePackage().c_str(), bundlePath.c_str());
    ErrCode result = ERR_OK;
    std::string bundleDir =
        AppExecFwk::Constants::BUNDLE_CODE_DIR + AppExecFwk::ServiceConstants::PATH_SEPARATOR + bundleName_;
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

    result = ProcessNativeLibrary(bundlePath, moduleDir, moduleName, versionDir, newInfo);
    CHECK_RESULT(result, "ProcessNativeLibrary failed %{public}d");

    // preInstallHsp does not need to copy
    newInfo.SetModuleHapPath(bundlePath);
    newInfo.AddModuleSrcDir(moduleDir);
    newInfo.AddModuleResPath(moduleDir);
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::ExtractModule(InnerBundleInfo &oldInfo,
    InnerBundleInfo &newInfo, const std::string &bundlePath)
{
    ErrCode result = ERR_OK;
    std::string bundleDir =
        AppExecFwk::Constants::BUNDLE_CODE_DIR + AppExecFwk::ServiceConstants::PATH_SEPARATOR + bundleName_;
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
    APP_LOGI("mkdir for dir: %{public}s", dir.c_str());
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
    InnerBundleInfo &newInfo)
{
    APP_LOGI("ProcessNativeLibrary param %{public}s  %{public}s %{public}s %{public}s",
        bundlePath.c_str(), moduleDir.c_str(), moduleName.c_str(), versionDir.c_str());
    std::string cpuAbi;
    std::string nativeLibraryPath;
    if (!newInfo.FetchNativeSoAttrs(moduleName, cpuAbi, nativeLibraryPath)) {
        return ERR_OK;
    }
    APP_LOGI("FetchNativeSoAttrs sucess with cpuAbi %{public}s nativeLibraryPath %{public}s",
        cpuAbi.c_str(), nativeLibraryPath.c_str());
    if (newInfo.IsCompressNativeLibs(moduleName)) {
        std::string tempNativeLibraryPath = ObtainTempSoPath(moduleName, nativeLibraryPath);
        if (tempNativeLibraryPath.empty()) {
            APP_LOGE("tempNativeLibraryPath is empty");
            return ERR_APPEXECFWK_INSTALLD_EXTRACT_FILES_FAILED;
        }

        std::string tempSoPath =
            versionDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR + tempNativeLibraryPath;
        APP_LOGI("TempSoPath=%{public}s,cpuAbi=%{public}s, bundlePath=%{public}s",
            tempSoPath.c_str(), cpuAbi.c_str(), bundlePath.c_str());
        auto result = InstalldClient::GetInstance()->ExtractModuleFiles(
            bundlePath, moduleDir, tempSoPath, cpuAbi);
        CHECK_RESULT(result, "Extract module files failed %{public}d");
        // verify hap or hsp code signature for compressed so files
        result = VerifyCodeSignatureForNativeFiles(bundlePath, cpuAbi, tempSoPath);
        CHECK_RESULT(result, "fail to VerifyCodeSignature, error is %{public}d");
        // move so to real path
        result = MoveSoToRealPath(moduleName, versionDir, nativeLibraryPath);
        CHECK_RESULT(result, "Move so to real path failed %{public}d");
    } else {
        std::vector<std::string> fileNames;
        auto result = InstalldClient::GetInstance()->GetNativeLibraryFileNames(
            bundlePath, cpuAbi, fileNames);
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
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_START)) {
        APP_LOGE("UpdateBundleInstallState failed");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }

    if (!dataMgr_->AddInnerBundleInfo(bundleName_, newInnerBundleInfo_)) {
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_START);
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_SUCCESS);
        APP_LOGE("Save bundle failed : %{public}s", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
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
        APP_LOGE("Move file to real path failed %{public}d", result);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }

    // 2. remove so temp dir
    std::string deleteTempDir = versionDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR
        + moduleName + AppExecFwk::ServiceConstants::TMP_SUFFIX;
    result = InstalldClient::GetInstance()->RemoveDir(deleteTempDir);
    if (result != ERR_OK) {
        APP_LOGW("Remove hsp temp so dir %{public}s failed, error is %{public}d",
            deleteTempDir.c_str(), result);
    }
    return ERR_OK;
}

void AppServiceFwkInstaller::RollBack()
{
    APP_LOGI("RollBack: %{public}s", bundleName_.c_str());
    // 1.RemoveBundleDir
    RemoveBundleCodeDir(newInnerBundleInfo_);

    // 2.RemoveCache
    RemoveInfo(bundleName_);
}

ErrCode AppServiceFwkInstaller::UpdateAppService(
    InnerBundleInfo &oldInfo,
    std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InstallParam &installParam)
{
    APP_LOGI("UpdateAppService for bundle %{public}s", oldInfo.GetBundleName().c_str());
    auto oldVersionCode = oldInfo.GetVersionCode();
    // update
    ErrCode result = ERR_OK;
    for (auto &item : newInfos) {
        if ((result = ProcessBundleUpdateStatus(oldInfo, item.second, item.first)) != ERR_OK) {
            APP_LOGE("ProcessBundleUpdateStatus failed %{public}d", result);
            return result;
        }
    }
    if (!uninstallModuleVec_.empty()) {
        result = UninstallLowerVersion(uninstallModuleVec_);
    }
    if (oldVersionCode < versionCode_) {
        RemoveLowerVersionSoDir(oldVersionCode);
    }

    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::ProcessBundleUpdateStatus(InnerBundleInfo &oldInfo,
    InnerBundleInfo &newInfo, const std::string &hspPath)
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    APP_LOGI("ProcessBundleUpdateStatus for module %{public}s", moduleName.c_str());
    if (moduleName.empty()) {
        APP_LOGE("get current package failed");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }
    if (versionUpgrade_) {
        APP_LOGI("uninstallModuleVec_ insert module %{public}s", moduleName.c_str());
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

    auto result = isModuleExist ? ProcessModuleUpdate(newInfo, oldInfo,
        hspPath) : ProcessNewModuleInstall(newInfo, oldInfo, hspPath);
    if (result != ERR_OK) {
        APP_LOGE("install module failed %{public}d", result);
        return result;
    }
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::ProcessModuleUpdate(InnerBundleInfo &newInfo,
    InnerBundleInfo &oldInfo, const std::string &hspPath)
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    APP_LOGD("ProcessModuleUpdate, bundleName : %{public}s, moduleName : %{public}s",
        newInfo.GetBundleName().c_str(), moduleName.c_str());
    if (oldInfo.GetModuleTypeByPackage(moduleName) != SHARED_MODULE_TYPE) {
        APP_LOGE("moduleName is inconsistent in the updating hap");
        return ERR_APPEXECFWK_INSTALL_INCONSISTENT_MODULE_NAME;
    }
    oldInfo.SetInstallMark(bundleName_, moduleName, InstallExceptionStatus::UPDATING_EXISTED_START);
    if (!dataMgr_->SaveInnerBundleInfo(oldInfo)) {
        APP_LOGE("save install mark failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    std::string oldHspPath = oldInfo.GetModuleHapPath(moduleName);
    if (!oldHspPath.empty()) {
        APP_LOGI("deleteBundlePath_ insert path %{public}s", oldHspPath.c_str());
        deleteBundlePath_.emplace_back(oldHspPath);
    }

    auto result = ExtractModule(newInfo, hspPath);
    CHECK_RESULT(result, "ExtractModule failed %{public}d");

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
        APP_LOGE("old module update state failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    oldInfo.SetInstallMark(bundleName_, moduleName, InstallExceptionStatus::UPDATING_FINISH);
    oldInfo.SetBundleUpdateTime(BundleUtil::GetCurrentTimeMs(), Constants::DEFAULT_USERID);
    if (!dataMgr_->UpdateInnerBundleInfo(bundleName_, newInfo, oldInfo)) {
        APP_LOGE("update innerBundleInfo %{public}s failed", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::ProcessNewModuleInstall(InnerBundleInfo &newInfo,
    InnerBundleInfo &oldInfo, const std::string &hspPath)
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    APP_LOGD("ProcessNewModuleInstall, bundleName : %{public}s, moduleName : %{public}s",
        newInfo.GetBundleName().c_str(), moduleName.c_str());
    if (bundleInstallChecker_->IsContainModuleName(newInfo, oldInfo)) {
        APP_LOGE("moduleName is already existed");
        return ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME;
    }

    oldInfo.SetInstallMark(bundleName_, moduleName, InstallExceptionStatus::UPDATING_NEW_START);
    if (!dataMgr_->SaveInnerBundleInfo(oldInfo)) {
        APP_LOGE("save install mark failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    auto result = ExtractModule(newInfo, hspPath);
    if (result != ERR_OK) {
        APP_LOGE("extract module and rename failed");
        return result;
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
        APP_LOGE("new moduleupdate state failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    oldInfo.SetInstallMark(bundleName_, moduleName, InstallExceptionStatus::INSTALL_FINISH);
    oldInfo.SetBundleUpdateTime(BundleUtil::GetCurrentTimeMs(), Constants::DEFAULT_USERID);
    if (!dataMgr_->AddNewModuleInfo(bundleName_, newInfo, oldInfo)) {
        APP_LOGE(
            "add module %{public}s to innerBundleInfo %{public}s failed", moduleName.c_str(), bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::UninstallLowerVersion(const std::vector<std::string> &moduleNameList)
{
    APP_LOGI("start to uninstall lower version module");
    InnerBundleInfo info;
    bool isExist = false;
    if (!GetInnerBundleInfo(info, isExist) || !isExist) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_START)) {
        APP_LOGE("uninstall already start");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    std::vector<std::string> moduleVec = info.GetModuleNameVec();
    APP_LOGI("bundleName: %{public}s moduleVec size: %{public}zu", bundleName_.c_str(), moduleVec.size());
    InnerBundleInfo oldInfo = info;
    for (const auto &package : moduleVec) {
        if (find(moduleNameList.begin(), moduleNameList.end(), package) == moduleNameList.end()) {
            APP_LOGI("uninstall package %{public}s", package.c_str());
            if (!dataMgr_->RemoveModuleInfo(bundleName_, package, info)) {
                APP_LOGE("RemoveModuleInfo failed");
                return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
            }
        }
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_SUCCESS)) {
        APP_LOGE("uninstall already start");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    return ERR_OK;
}

bool AppServiceFwkInstaller::GetInnerBundleInfo(InnerBundleInfo &info, bool &isAppExist)
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            APP_LOGE("Get dataMgr shared_ptr nullptr");
            return false;
        }
    }
    isAppExist = dataMgr_->GetInnerBundleInfo(bundleName_, info);
    return true;
}

ErrCode AppServiceFwkInstaller::RemoveBundleCodeDir(const InnerBundleInfo &info) const
{
    auto result = InstalldClient::GetInstance()->RemoveDir(info.GetAppCodePath());
    if (result != ERR_OK) {
        APP_LOGE("Fail to remove bundle code dir %{public}s, error is %{public}d",
            info.GetAppCodePath().c_str(), result);
    }
    return result;
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
    EventReport::SendBundleSystemEvent(bundleEventType, sysEventInfo);
}

bool AppServiceFwkInstaller::CheckNeedInstall(const std::unordered_map<std::string, InnerBundleInfo> &infos,
    InnerBundleInfo &oldInfo)
{
    if (infos.empty()) {
        APP_LOGW("innerbundleinfos is empty");
        return false;
    }
    if (!(dataMgr_->FetchInnerBundleInfo(bundleName_, oldInfo))) {
        APP_LOGD("bundleName %{public}s not existed local", bundleName_.c_str());
        return true;
    }
    APP_LOGI("oldVersionCode: %{public}d, new version Code: %{public}d", oldInfo.GetVersionCode(), versionCode_);

    if ((oldInfo.GetVersionCode() == versionCode_) &&
        oldInfo.GetApplicationBundleType() != BundleType::APP_SERVICE_FWK) {
        APP_LOGW("bundle %{public}s type is not same, existing bundle type is %{public}d",
            bundleName_.c_str(), oldInfo.GetApplicationBundleType());
        return false;
    }
    if (oldInfo.GetVersionCode() > versionCode_) {
        APP_LOGW("version code is lower than current app service.");
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
        APP_LOGW("version code is lower than current app service.");
        return false;
    } else if (oldVersionCode < versionCode_) {
        APP_LOGW("upgrade, old version is %{public}d, new version is %{public}d", oldVersionCode, versionCode_);
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
        AppExecFwk::Constants::BUNDLE_CODE_DIR + AppExecFwk::ServiceConstants::PATH_SEPARATOR + bundleName_;
    std::string versionDir = bundleDir
        + AppExecFwk::ServiceConstants::PATH_SEPARATOR + HSP_VERSION_PREFIX + std::to_string(versionCode);
    APP_LOGI("RemoveDir %{public}s", versionDir.c_str());
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
        APP_LOGE("no sign info in the all haps!");
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
}  // namespace AppExecFwk
}  // namespace OHOS
