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
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string HSP_VERSION_PREFIX = "v";

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
        tempSoPath = moduleName + AppExecFwk::Constants::TMP_SUFFIX
            + AppExecFwk::Constants::PATH_SEPARATOR + tempSoPath;
    } else {
        std::string innerTempStr = moduleName + AppExecFwk::Constants::TMP_SUFFIX;
        tempSoPath.replace(pos, moduleName.length(), innerTempStr);
    }
    return tempSoPath + AppExecFwk::Constants::PATH_SEPARATOR;
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
    return ProcessInstall(hspPaths, installParam);
}

ErrCode AppServiceFwkInstaller::BeforeInstall(
    const std::vector<std::string> &hspPaths, InstallParam &installParam)
{
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

    ScopeGuard stateGuard([&] {
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_SUCCESS);
        dataMgr_->EnableBundle(bundleName_);
    });
    result = InnerProcessInstall(newInfos, installParam);
    if (result != ERR_OK) {
        APP_LOGE("InnerProcessInstall failed %{public}d", result);
        RollBack();
    }
    return result;
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

    // check native file
    result = bundleInstallChecker_->CheckMultiNativeFile(newInfos);
    CHECK_RESULT(result, "Native so is incompatible in all hsps %{public}d");

    AddAppProvisionInfo(bundleName_, hapVerifyResults[0].GetProvisionInfo(), installParam);
    APP_LOGI("CheckAndParseFiles End");
    return result;
}

ErrCode AppServiceFwkInstaller::CheckAppLabelInfo(
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    for (const auto &info : infos) {
        if (info.second.GetApplicationBundleType() != BundleType::APP_SERVICE_FWK) {
            APP_LOGE("BundleType is not AppServiceFwk");
            return ERR_APP_SERVICE_FWK_INSTALL_TYPE_FAILED;
        }
    }

    ErrCode ret = bundleInstallChecker_->CheckAppLabelInfo(infos);
    if (ret != ERR_OK) {
        return ret;
    }

    bundleName_ = (infos.begin()->second).GetBundleName();
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
    ErrCode result = ERR_OK;
    std::string bundleDir =
        AppExecFwk::Constants::BUNDLE_CODE_DIR + AppExecFwk::Constants::PATH_SEPARATOR + bundleName_;
    result = MkdirIfNotExist(bundleDir);
    CHECK_RESULT(result, "Check bundle dir failed %{public}d");

    newInfo.SetAppCodePath(bundleDir);
    uint32_t versionCode = newInfo.GetVersionCode();
    std::string versionDir = bundleDir
        + AppExecFwk::Constants::PATH_SEPARATOR + HSP_VERSION_PREFIX + std::to_string(versionCode);
    result = MkdirIfNotExist(versionDir);
    CHECK_RESULT(result, "Check version dir failed %{public}d");

    auto &moduleName = newInfo.GetInnerModuleInfos().begin()->second.moduleName;
    std::string moduleDir = versionDir + AppExecFwk::Constants::PATH_SEPARATOR + moduleName;
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
    InnerBundleInfo &newInfo)
{
    std::string cpuAbi;
    std::string nativeLibraryPath;
    if (!newInfo.FetchNativeSoAttrs(moduleName, cpuAbi, nativeLibraryPath)) {
        return ERR_OK;
    }

    if (newInfo.IsCompressNativeLibs(moduleName)) {
        std::string tempNativeLibraryPath = ObtainTempSoPath(moduleName, nativeLibraryPath);
        if (tempNativeLibraryPath.empty()) {
            return ERR_APPEXECFWK_INSTALLD_EXTRACT_FILES_FAILED;
        }

        std::string tempSoPath =
            versionDir + AppExecFwk::Constants::PATH_SEPARATOR + tempNativeLibraryPath;
        APP_LOGD("TempSoPath=%{public}s,cpuAbi=%{public}s, bundlePath=%{public}s",
            tempSoPath.c_str(), cpuAbi.c_str(), bundlePath.c_str());
        auto result = InstalldClient::GetInstance()->ExtractModuleFiles(
            bundlePath, moduleDir, tempSoPath, cpuAbi);
        CHECK_RESULT(result, "Extract module files failed %{public}d");
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
    std::string realSoPath = versionDir + AppExecFwk::Constants::PATH_SEPARATOR
        + nativeLibraryPath + AppExecFwk::Constants::PATH_SEPARATOR;
    ErrCode result = MkdirIfNotExist(realSoPath);
    CHECK_RESULT(result, "Check module dir failed %{public}d");
    std::string tempNativeLibraryPath = ObtainTempSoPath(moduleName, nativeLibraryPath);
    if (tempNativeLibraryPath.empty()) {
        APP_LOGI("No so libs existed");
        return ERR_OK;
    }

    std::string tempSoPath =
        versionDir + AppExecFwk::Constants::PATH_SEPARATOR + tempNativeLibraryPath;
    APP_LOGD("Move so files from path %{public}s to path %{public}s",
        tempSoPath.c_str(), realSoPath.c_str());
    result = InstalldClient::GetInstance()->MoveFiles(tempSoPath, realSoPath);
    if (result != ERR_OK) {
        APP_LOGE("Move file to real path failed %{public}d", result);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }

    // 2. remove so temp dir
    std::string deleteTempDir = versionDir + AppExecFwk::Constants::PATH_SEPARATOR
        + moduleName + AppExecFwk::Constants::TMP_SUFFIX;
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
}  // namespace AppExecFwk
}  // namespace OHOS
