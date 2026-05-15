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

#include "independent_skills_installer.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "app_provision_info_manager.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "inner_patch_info.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "patch_data_mgr.h"
#include "scope_guard.h"
#include "skills_description_manager.h"
#include "skills_installer_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* COMPILE_SDK_TYPE_OPEN_HARMONY = "OpenHarmony";
constexpr const char* DEBUG_APP_IDENTIFIER = "DEBUG_LIB_ID";
constexpr const int64_t FIVE_MB = 1024 * 1024 * 5; // 5MB
constexpr const char* TEMP_PATH = "+temp";
constexpr const char* BASE_SKILL_DIR = "/data/app/el1/skills/public";

void BuildCheckParam(
    const InstallParam &installParam, InstallCheckParam &checkParam)
{
    checkParam.isPreInstallApp = installParam.isPreInstallApp;
    checkParam.crowdtestDeadline = installParam.crowdtestDeadline;
    checkParam.appType = Constants::AppType::SYSTEM_APP;
    checkParam.removable = installParam.removable;
    checkParam.installBundlePermissionStatus = installParam.installBundlePermissionStatus;
    checkParam.installEnterpriseBundlePermissionStatus = installParam.installEnterpriseBundlePermissionStatus;
    checkParam.installEtpNormalBundlePermissionStatus = installParam.installEtpNormalBundlePermissionStatus;
    checkParam.installEtpMdmBundlePermissionStatus = installParam.installEtpMdmBundlePermissionStatus;
    checkParam.isCallByShell = installParam.isCallByShell;
    checkParam.needSendEvent = installParam.needSendEvent;
    checkParam.specifiedDistributionType = installParam.specifiedDistributionType;
}
} // namespace

IndependentSkillsInstaller::IndependentSkillsInstaller()
    : bundleInstallChecker_(std::make_unique<BundleInstallChecker>())
{
    LOG_D(BMS_TAG_INSTALLER, "IndependentSkillsInstaller instance created");
}

IndependentSkillsInstaller::~IndependentSkillsInstaller()
{
    LOG_D(BMS_TAG_INSTALLER, "IndependentSkillsInstaller instance destroyed");
}

ErrCode IndependentSkillsInstaller::Install(
    const std::vector<std::string> &hspPaths, const InstallParam &installParam)
{
    LOG_I(BMS_TAG_INSTALLER, "Install skills bundle userId %{public}d start", installParam.userId);
    startTime_ = BundleUtil::GetCurrentTimeMs();
    ErrCode result = ProcessInstall(hspPaths, installParam);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "install skills failed -n %{public}s result %{public}d", bundleName_.c_str(), result);
    } else {
        LOG_I(BMS_TAG_INSTALLER, "install skills succeed -n %{public}s -u %{public}d", bundleName_.c_str(), userId_);
    }
    // normal install need to NotifyBundleStatus, preInstall no need to NotifyBundleStatus.
    if (!hspPaths.empty()) {
        SendBundleSystemEvent(
            bundleName_.empty() ? hspPaths[0] : bundleName_,
            installParam,
            (moduleUpdate_ || versionUpgrade_) ? BundleEventType::UPDATE : BundleEventType::INSTALL,
            result);
    }
    return result;
}

ErrCode IndependentSkillsInstaller::InstallBundleByBundleName(
    const std::string &bundleName, const InstallParam &installParam)
{
    LOG_I(BMS_TAG_INSTALLER, "InstallBundleByBundleName skills bundle %{public}s userId %{public}d",
        bundleName.c_str(), installParam.userId);
    startTime_ = BundleUtil::GetCurrentTimeMs();
    ErrCode result = ProcessInstallBundleByBundleName(bundleName, installParam);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "skills bundle %{public}s userId %{public}d install by name failed",
            bundleName.c_str(), installParam.userId);
    } else {
        LOG_I(BMS_TAG_INSTALLER, "skills bundle %{public}s userId %{public}d install by name succeed",
            bundleName.c_str(), installParam.userId);
    }
    // normal unInstall need to NotifyBundleStatus, preUninstall no need to NotifyBundleStatus.
    SendBundleSystemEvent(
        bundleName, installParam,
        (moduleUpdate_ || versionUpgrade_) ? BundleEventType::UPDATE : BundleEventType::INSTALL,
        result);
    return result;
}

ErrCode IndependentSkillsInstaller::Uninstall(const std::string &bundleName, const InstallParam &installParam)
{
    LOG_I(BMS_TAG_INSTALLER, "Uninstall skills bundle %{public}s userId %{public}d",
        bundleName.c_str(), installParam.userId);
    startTime_ = BundleUtil::GetCurrentTimeMs();
    ErrCode result = ProcessUninstall(bundleName, installParam);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "skills bundle %{public}s userId %{public}d uninstall failed",
            bundleName.c_str(), installParam.userId);
    } else {
        LOG_I(BMS_TAG_INSTALLER, "skills bundle %{public}s userId %{public}d uninstall succeed",
            bundleName.c_str(), installParam.userId);
    }
    // normal unInstall need to NotifyBundleStatus, preUninstall no need to NotifyBundleStatus.
    SendBundleSystemEvent(bundleName, installParam, BundleEventType::UNINSTALL, result);
    return result;
}

ErrCode IndependentSkillsInstaller::ProcessInstall(
    const std::vector<std::string> &hspPaths, const InstallParam &installParam)
{
    ErrCode result = BeforeInstall(hspPaths, installParam);
    CHECK_SKILLS_RESULT(result, "BeforeInstall check failed %{public}d");
    if (dataMgr_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    // check user
    if (!dataMgr_->HasUserId(installParam.userId)) {
        LOG_E(BMS_TAG_INSTALLER, "userId %{public}d not exist", installParam.userId);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    result = CheckAndParseFiles(hspPaths, installParam, newInfos);
    CHECK_SKILLS_RESULT(result, "CheckAndParseFiles failed %{public}d");
    auto &mtx = dataMgr_->GetBundleMutex(bundleName_);
    std::lock_guard lock {mtx};
    InnerBundleInfo oldInfo;
    bool isDowngrade = false;
    if (!CheckNeedInstall(newInfos, oldInfo, isDowngrade)) {
        if (isDowngrade) {
            LOG_E(BMS_TAG_INSTALLER, "version down grade install");
            return ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE;
        }
        LOG_I(BMS_TAG_INSTALLER, "skills not need install");
        return ERR_OK;
    }

    ScopeGuard stateGuard([&] {
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_SUCCESS);
        dataMgr_->EnableBundle(bundleName_);
    });

    if (versionUpgrade_ || moduleUpdate_) {
        result = UpdateSkillsPackage(oldInfo, newInfos, installParam);
        // need rollback
        if (result != ERR_OK) {
            RollBack(newInfos, result);
            LOG_E(BMS_TAG_INSTALLER, "skills -n %{public}s -u %{public}d update failed %{public}d",
                bundleName_.c_str(), userId_, result);
            return result;
        }
        CHECK_SKILLS_RESULT(result, "UpdateSkillsPackage failed %{public}d");
    } else {
        result = InnerProcessInstall(newInfos, installParam);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLER, "InnerProcessInstall failed %{public}d", result);
            RollBack();
            return result;
        }
    }
    PatchDataMgr::GetInstance().ProcessPatchInfo(bundleName_, hspPaths,
        newInfos.begin()->second.GetVersionCode(), AppPatchType::SERVICE_FWK, installParam.isPatch);
    // check mark install finish
    result = MarkInstallFinish();
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "mark install finish failed %{public}d", result);
        if (!versionUpgrade_ && !moduleUpdate_) {
            RollBack();
        }
        PatchDataMgr::GetInstance().DeleteInnerPatchInfo(bundleName_);
        return result;
    }
    RemoveOldSkillsPath();
    return result;
}

ErrCode IndependentSkillsInstaller::CheckUserId(const int32_t userId)
{
    if (dataMgr_ == nullptr) {
        return ERR_APPEXECFWK_NULL_PTR;
    }

    if (!dataMgr_->HasUserId(userId)) {
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }
    if ((userId == Constants::DEFAULT_USERID) || (userId == Constants::U1)) {
        LOG_E(BMS_TAG_INSTALLER, "-n %{public}s not support install in -u %{public}d ", bundleName_.c_str(), userId);
        return ERR_SKILLS_NOT_SUPPORT_SINGLETON_AND_U1;
    }
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::BeforeInstall(
    const std::vector<std::string> &hspPaths, const InstallParam &installParam)
{
    if (hspPaths.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "HspPaths is empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::CopyHspToSecurityDir(std::vector<std::string> &bundlePaths)
{
    for (size_t index = 0; index < bundlePaths.size(); ++index) {
        auto destination = BundleUtil::CopyFileToSecurityDir(bundlePaths[index], DirType::STREAM_INSTALL_DIR,
            toDeleteTempHspPath_);
        if (destination.empty()) {
            LOG_E(BMS_TAG_INSTALLER, "copy file %{public}s to security dir failed", bundlePaths[index].c_str());
            return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
        }
        bundlePaths[index] = destination;
    }
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::CheckAndParseFiles(
    const std::vector<std::string> &hspPaths, const InstallParam &installParam,
    std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    InstallCheckParam checkParam;
    BuildCheckParam(installParam, checkParam);

    std::vector<std::string> checkedHspPaths;
    // check hsp paths
    ErrCode result = BundleUtil::CheckFilePath(hspPaths, checkedHspPaths);
    CHECK_SKILLS_RESULT(result, "Hsp file check failed %{public}d");

    // check file type
    result = CheckFileType(checkedHspPaths);
    CHECK_SKILLS_RESULT(result, "Hsp suffix check failed %{public}d");

    if (!checkParam.isPreInstallApp) {
        // copy the haps to the dir which cannot be accessed from caller
        result = CopyHspToSecurityDir(checkedHspPaths);
        CHECK_SKILLS_RESULT(result, "copy file failed %{public}d");
    }

    // check syscap
    ErrCode checkSysCapRes = bundleInstallChecker_->CheckSysCap(checkedHspPaths);
    if (checkSysCapRes != ERR_OK) {
        LOG_I(BMS_TAG_INSTALLER, "Hsp syscap check failed %{public}d", result);
    }

    // verify signature info for all haps
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    result = bundleInstallChecker_->CheckMultipleHapsSignInfo(
        checkedHspPaths, hapVerifyResults);
    CHECK_SKILLS_RESULT(result, "Hsp files check signature info failed %{public}d");

    result = bundleInstallChecker_->ParseHapFiles(
        checkedHspPaths, checkParam, hapVerifyResults, newInfos);
    CHECK_SKILLS_RESULT(result, "Parse hsps file failed %{public}d");

    // check install permission
    result = bundleInstallChecker_->CheckInstallPermission(checkParam, hapVerifyResults);
    CHECK_SKILLS_RESULT(result, "Check install permission failed %{public}d");

    // check hsp install condition
    result = bundleInstallChecker_->CheckHspInstallCondition(hapVerifyResults);
    CHECK_SKILLS_RESULT(result, "Check hsp install condition failed %{public}d");

    // check device type
    if (checkSysCapRes != ERR_OK) {
        result = bundleInstallChecker_->CheckDeviceType(newInfos, checkSysCapRes);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLER, "Check device type failed : %{public}d", result);
            return ERR_APPEXECFWK_INSTALL_SYSCAP_FAILED_AND_DEVICE_TYPE_ERROR;
        }
    }
    result = CheckAppLabelInfo(newInfos);
    CHECK_SKILLS_RESULT(result, "Check app label failed %{public}d");
    if (installParam.needSavePreInstallInfo) {
        SavePreInstallBundleInfo(newInfos, installParam);
    }
    userId_ = installParam.userId;
    // check user
    result = CheckUserId(userId_);
    CHECK_SKILLS_RESULT(result, "Check userId failed %{public}d");
    // check singleton
    result = CheckSingletonAndU1Enable(newInfos);
    CHECK_SKILLS_RESULT(result, "Check u1enable or singleton failed %{public}d");
    // delivery sign profile to code signature
    result = DeliveryProfileToCodeSign(hapVerifyResults);
    CHECK_SKILLS_RESULT(result, "delivery sign profile failed %{public}d");

    verifyRes_ = hapVerifyResults[0];
    isEnterpriseBundle_ = bundleInstallChecker_->CheckEnterpriseBundle(hapVerifyResults[0]);
    appIdentifier_ = (hapVerifyResults[0].GetProvisionInfo().type == Security::Verify::ProvisionType::DEBUG) ?
        DEBUG_APP_IDENTIFIER : hapVerifyResults[0].GetProvisionInfo().bundleInfo.appIdentifier;
    compileSdkType_ = newInfos.empty() ? COMPILE_SDK_TYPE_OPEN_HARMONY :
        (newInfos.begin()->second).GetBaseApplicationInfo().compileSdkType;
    UpdateDeveloperId(newInfos, hapVerifyResults);
    AddAppProvisionInfo(bundleName_, hapVerifyResults[0].GetProvisionInfo(), installParam);
    return result;
}

bool IndependentSkillsInstaller::RemoveModuleDir(
    const std::string &bundleName, const std::string &moduleName)
{
    if (bundleName.empty() || moduleName.empty()) {
        LOG_W(BMS_TAG_INSTALLER, "bundle or module is empty, no need to process");
        return false;
    }
    std::string moduleDir =
        std::string(BASE_SKILL_DIR) + AppExecFwk::ServiceConstants::PATH_SEPARATOR +
        bundleName + AppExecFwk::ServiceConstants::PATH_SEPARATOR + moduleName;
    LOG_I(BMS_TAG_INSTALLER, "start to remove module dir: %{public}s", moduleDir.c_str());
    if (InstalldClient::GetInstance()->RemoveDir(moduleDir, BundleDirScene::REMOVE_SKILL_MODULE_DIR, bundleName) !=
        ERR_OK) {
        LOG_W(BMS_TAG_INSTALLER, "remove module dir %{public}s failed", moduleDir.c_str());
        return false;
    }
    return true;
}

bool IndependentSkillsInstaller::RemoveSkillDir(
    const std::string &bundleName, const std::string &moduleName, const std::string &skillsName)
{
    if (bundleName.empty() || moduleName.empty() || skillsName.empty()) {
        LOG_W(BMS_TAG_INSTALLER, "bundle or module or skillsName is empty, no need to process");
        return false;
    }
    std::string moduleDir =
        std::string(BASE_SKILL_DIR) + AppExecFwk::ServiceConstants::PATH_SEPARATOR +
        bundleName + AppExecFwk::ServiceConstants::PATH_SEPARATOR + moduleName +
        AppExecFwk::ServiceConstants::PATH_SEPARATOR + skillsName;
    LOG_I(BMS_TAG_INSTALLER, "start to remove skill dir: %{public}s", moduleDir.c_str());
    if (InstalldClient::GetInstance()->RemoveDir(moduleDir, BundleDirScene::REMOVE_SKILL_MODULE_DIR, bundleName) !=
        ERR_OK) {
        LOG_W(BMS_TAG_INSTALLER, "remove module dir %{public}s failed", moduleDir.c_str());
        return false;
    }
    return true;
}

bool IndependentSkillsInstaller::UpdateDeveloperId(
    std::unordered_map<std::string, InnerBundleInfo> &infos,
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const
{
    if (hapVerifyRes.size() < infos.size() || infos.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "hapVerifyRes size less than infos size or infos is empty");
        return false;
    }

    std::string developerId = hapVerifyRes[0].GetProvisionInfo().bundleInfo.developerId;
    if (developerId.empty()) {
        developerId = hapVerifyRes[0].GetProvisionInfo().bundleInfo.bundleName;
    }

    for (auto &item : infos) {
        item.second.UpdateDeveloperId(developerId);
    }
    return true;
}

ErrCode IndependentSkillsInstaller::CheckFileType(const std::vector<std::string> &bundlePaths)
{
    if (bundlePaths.size() != 1) {
        LOG_E(BMS_TAG_INSTALLER, "check hsp suffix failed due to invalid bundlePaths");
        return ERR_SKILLS_ONLY_ALLOW_ONE_MODULE;
    }
    if (!BundleUtil::CheckFileType(bundlePaths[0], ServiceConstants::HSP_FILE_SUFFIX)) {
        LOG_E(BMS_TAG_INSTALLER, "Hsp %{public}s suffix check failed", bundlePaths[0].c_str());
        return ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME;
    }

    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::CheckAppLabelInfo(
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    if (infos.empty()) {
        return ERR_SKILLS_HAS_NO_MODULE;
    }
    for (const auto &info : infos) {
        if (info.second.GetApplicationBundleType() != BundleType::SKILL) {
            LOG_E(BMS_TAG_INSTALLER, "App BundleType is not skills");
            return ERR_SKILLS_INSTALL_TYPE_FAILED;
        }

        auto moduleInfo = info.second.GetInnerModuleInfoByModuleName(info.second.GetCurModuleName());
        if (moduleInfo && moduleInfo->distro.moduleType != Profile::MODULE_TYPE_SKILLS) {
            LOG_E(BMS_TAG_INSTALLER, "App ModuleType is not skill");
            return ERR_SKILLS_INSTALL_TYPE_FAILED;
        }
        // skills only has 1 skillProfiles
        if (moduleInfo && (moduleInfo->skillProfiles.size() != 1)) {
            LOG_E(BMS_TAG_INSTALLER, "App skillProfiles size %{public}zu error", moduleInfo->skillProfiles.size());
            return ERR_SKILLS_ONLY_ALLOW_ONE_SKILLS_AGENT;
        }
    }

    ErrCode ret = bundleInstallChecker_->CheckAppLabelInfo(infos);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "CheckAppLabelInfo failed, ret %{public}d", ret);
        return ret;
    }

    bundleName_ = (infos.begin()->second).GetBundleName();
    versionCode_ = (infos.begin()->second).GetVersionCode();
    return ERR_OK;
}

bool IndependentSkillsInstaller::SavePreInstallBundleInfo(
    const std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InstallParam &installParam)
{
    if (newInfos.empty()) {
        return false;
    }
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName_);
    dataMgr_->GetPreInstallBundleInfo(bundleName_, preInstallBundleInfo);
    preInstallBundleInfo.SetAppType(newInfos.begin()->second.GetAppType());
    preInstallBundleInfo.SetVersionCode(versionCode_);
    preInstallBundleInfo.SetIsUninstalled(false);
    for (const std::string &bundlePath : deleteBundlePath_) {
        LOG_I(BMS_TAG_INSTALLER, "preInstallBundleInfo delete path %{public}s", bundlePath.c_str());
        preInstallBundleInfo.DeleteBundlePath(bundlePath);
    }
    for (const auto &item : newInfos) {
        preInstallBundleInfo.AddBundlePath(item.first);
    }
    preInstallBundleInfo.SetRemovable(newInfos.begin()->second.IsRemovable());

    for (const auto &innerBundleInfo : newInfos) {
        auto applicationInfo = innerBundleInfo.second.GetBaseApplicationInfo();
        innerBundleInfo.second.AdaptMainLauncherResourceInfo(applicationInfo);
        preInstallBundleInfo.SetLabelId(applicationInfo.labelResource.id);
        preInstallBundleInfo.SetIconId(applicationInfo.iconResource.id);
        preInstallBundleInfo.SetDescriptionId(applicationInfo.descriptionId);
        preInstallBundleInfo.SetModuleName(applicationInfo.labelResource.moduleName);
        preInstallBundleInfo.SetSystemApp(applicationInfo.isSystemApp);
        preInstallBundleInfo.SetBundleType(BundleType::SKILL);
        break;
    }
    if (!dataMgr_->SavePreInstallBundleInfo(bundleName_, preInstallBundleInfo)) {
        LOG_E(BMS_TAG_INSTALLER, "SavePreInstallBundleInfo for bundleName_ failed");
        return false;
    }
    return true;
}

void IndependentSkillsInstaller::AddAppProvisionInfo(
    const std::string &bundleName,
    const Security::Verify::ProvisionInfo &provisionInfo,
    const InstallParam &installParam) const
{
    AppProvisionInfo appProvisionInfo = bundleInstallChecker_->ConvertToAppProvisionInfo(provisionInfo);
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        bundleName, appProvisionInfo)) {
        LOG_W(BMS_TAG_INSTALLER, "BundleName %{public}s add appProvisionInfo failed", bundleName.c_str());
    }

    if (!installParam.specifiedDistributionType.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetSpecifiedDistributionType(
            bundleName, installParam.specifiedDistributionType)) {
            LOG_W(BMS_TAG_INSTALLER, "BundleName %{public}s SetSpecifiedDistributionType failed", bundleName.c_str());
        }
    }

    if (!installParam.additionalInfo.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetAdditionalInfo(
            bundleName, installParam.additionalInfo)) {
            LOG_W(BMS_TAG_INSTALLER, "BundleName %{public}s SetAdditionalInfo failed", bundleName.c_str());
        }
    }
}

ErrCode IndependentSkillsInstaller::InnerProcessInstall(
    std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    const InstallParam &installParam)
{
    LOG_I(BMS_TAG_INSTALLER, "start install skills -n %{public}s, size: %{public}zu",
        bundleName_.c_str(), newInfos.size());
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = userId_;
    innerBundleUserInfo.bundleName = bundleName_;
    ErrCode result = ERR_OK;
    for (auto it = newInfos.begin(); it != newInfos.end(); ++it) {
        InnerBundleInfo &newInfo = it->second;
        const std::string &hspPath = it->first;
        result = ExtractModule(newInfo, hspPath, installParam.copyHapToInstallPath, false);
        CHECK_SKILLS_RESULT(result, "ExtractModule failed %{public}d");
        newInfo.SetApplicationFlags(installParam.preinstallSourceFlag);
        newInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
        MergeBundleInfos(newInfo);
    }

    return SaveBundleInfoToStorage();
}

void IndependentSkillsInstaller::MergeBundleInfos(InnerBundleInfo &info)
{
    if (newInnerBundleInfo_.GetBundleName().empty()) {
        newInnerBundleInfo_ = info;
        return;
    }

    newInnerBundleInfo_.AddModuleInfo(info);
}

ErrCode IndependentSkillsInstaller::SaveBundleInfoToStorage()
{
    newInnerBundleInfo_.SetInstallMark(bundleName_, newInnerBundleInfo_.GetCurModuleName(),
        InstallExceptionStatus::INSTALL_START);
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_START)) {
        LOG_E(BMS_TAG_INSTALLER, "UpdateBundleInstallState failed");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }
    // init hapToken
    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    Security::AccessToken::HapInfoCheckResult checkResult;
    ErrCode result = BundlePermissionMgr::InitHapToken(newInnerBundleInfo_, userId_, 0, accessTokenIdEx, checkResult,
        verifyRes_.GetProvisionInfo().appServiceCapabilities, false);
    if (result != ERR_OK) {
        auto msg = BundlePermissionMgr::GetCheckResultMsg(checkResult);
        LOG_E(BMS_TAG_INSTALLER, "skills %{public}s init hapToken failed msg %{public}s, err %{public}d",
            bundleName_.c_str(), msg.c_str(), result);
        return result;
    }

    newInnerBundleInfo_.SetBundleInstallTime(BundleUtil::GetCurrentTimeMs(), userId_);
    if (!dataMgr_->AddInnerBundleInfo(bundleName_, newInnerBundleInfo_)) {
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_START);
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_SUCCESS);
        LOG_E(BMS_TAG_INSTALLER, "Save bundle failed %{public}s", bundleName_.c_str());
        return ERR_APPEXECFWK_ADD_BUNDLE_ERROR;
    }

    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::VerifyCodeSignatureForHsp(
    const std::string &realHspPath) const
{
    LOG_I(BMS_TAG_INSTALLER, "begin to verify code sign for hsp");
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = realHspPath;
    codeSignatureParam.bundleName = bundleName_;
    codeSignatureParam.targetSoPath = "";
    codeSignatureParam.cpuAbi = "";
    codeSignatureParam.appIdentifier = (verifyRes_.GetProvisionInfo().type ==
        Security::Verify::ProvisionType::DEBUG) ? DEBUG_APP_IDENTIFIER : appIdentifier_;
    codeSignatureParam.signatureFileDir = "";
    codeSignatureParam.isEnterpriseBundle = isEnterpriseBundle_;
    codeSignatureParam.isCompileSdkOpenHarmony = (compileSdkType_ == COMPILE_SDK_TYPE_OPEN_HARMONY);
    codeSignatureParam.isPreInstalledBundle = false;
    bundleInstallChecker_->ProcessCodeSignatureParam(verifyRes_, codeSignatureParam);
    return InstalldClient::GetInstance()->VerifyCodeSignatureForHap(codeSignatureParam);
}

ErrCode IndependentSkillsInstaller::MkdirIfNotExist(const std::string &dir)
{
    bool isDirExist = false;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(dir, isDirExist);
    CHECK_SKILLS_RESULT(result, "Check if dir exist failed %{public}d");

    if (!isDirExist) {
        result = InstalldClient::GetInstance()->CreateBundleDir(bundleName_, BundleDirScene::BASE_SKILL_DIR, dir);
        CHECK_SKILLS_RESULT(result, "Create dir failed %{public}d");
    }
    return result;
}

ErrCode IndependentSkillsInstaller::UpdateSkillsPackage(
    InnerBundleInfo &oldInfo,
    std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    const InstallParam &installParam)
{
    LOG_I(BMS_TAG_INSTALLER, "UpdateSkillsPackage for bundle %{public}s", oldInfo.GetBundleName().c_str());
    ErrCode result = ERR_OK;
    for (auto &item : newInfos) {
        if ((result = ProcessBundleUpdateStatus(oldInfo, item.second, item.first, installParam)) != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLER, "ProcessBundleUpdateStatus failed %{public}d", result);
            return result;
        }
    }
    if (!uninstallModuleVec_.empty()) {
        result = UninstallLowerVersion(uninstallModuleVec_);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLER, "UninstallLowerVersion failed %{public}d, can not rollback", result);
        }
    }
    // update hapToken
    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    Security::AccessToken::HapInfoCheckResult checkResult;
    result = BundlePermissionMgr::UpdateHapToken(accessTokenIdEx, oldInfo, userId_, checkResult,
        verifyRes_.GetProvisionInfo().appServiceCapabilities, false, false);
    if (result != ERR_OK) {
        auto msg = BundlePermissionMgr::GetCheckResultMsg(checkResult);
        LOG_E(BMS_TAG_INSTALLER, "skills %{public}s update hapToken failed msg %{public}s, err %{public}d",
            bundleName_.c_str(), msg.c_str(), result);
        return result;
    }
    InnerProcessNeedDeleteSkillPackage(oldInfo);
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::ProcessBundleUpdateStatus(InnerBundleInfo &oldInfo,
    InnerBundleInfo &newInfo, const std::string &hspPath, const InstallParam &installParam)
{
    // check appId or appIdentifier
    if (!CheckAppIdentifier(oldInfo.GetAppIdentifier(), newInfo.GetAppIdentifier(),
        oldInfo.GetProvisionId(), newInfo.GetProvisionId())) {
        return ERR_APPEXECFWK_INSTALL_FAILED_INCONSISTENT_SIGNATURE;
    }
    // check bundleType
    if (oldInfo.GetApplicationBundleType() != newInfo.GetApplicationBundleType()) {
        return ERR_SKILLS_INSTALL_TYPE_NOT_SAME;
    }
    std::string moduleName = newInfo.GetCurrentModulePackage();
    LOG_I(BMS_TAG_INSTALLER, "ProcessBundleUpdateStatus for module %{public}s", moduleName.c_str());
    if (moduleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "get current package failed");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }
    if (versionUpgrade_) {
        LOG_I(BMS_TAG_INSTALLER, "uninstallModuleVec_ insert module %{public}s", moduleName.c_str());
        uninstallModuleVec_.emplace_back(moduleName);
    }
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_START)) {
        LOG_E(BMS_TAG_INSTALLER, "update already start");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }
    // 1. bundle exist, module exist, update module
    // 2. bundle exist, install new hsp
    bool isModuleExist = oldInfo.FindModule(moduleName);
    LOG_I(BMS_TAG_INSTALLER, "skills module %{public}s isModuleExist %{public}d", moduleName.c_str(), isModuleExist);
    if (!isModuleExist && moduleUpdate_) {
        return ERR_SKILLS_MODULE_NAME_NOT_SAME;
    }
    if (!hasInstalledInUser_) {
        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleUserInfo.bundleUserInfo.userId = userId_;
        innerBundleUserInfo.bundleName = bundleName_;
        oldInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
        oldInfo.SetBundleInstallTime(BundleUtil::GetCurrentTimeMs(), userId_);
    }
    auto result = isModuleExist ? ProcessModuleUpdate(newInfo, oldInfo, hspPath, installParam) :
        ProcessNewModuleInstall(newInfo, oldInfo, hspPath, installParam);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "install module failed %{public}d", result);
        return result;
    }
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::ProcessModuleUpdate(InnerBundleInfo &newInfo,
    InnerBundleInfo &oldInfo, const std::string &hspPath, const InstallParam &installParam)
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    LOG_D(BMS_TAG_INSTALLER, "ProcessModuleUpdate, bundleName : %{public}s, moduleName : %{public}s",
        newInfo.GetBundleName().c_str(), moduleName.c_str());
    oldInfo.SetInstallMark(bundleName_, moduleName, InstallExceptionStatus::UPDATING_EXISTED_START);

    std::string oldHspPath = oldInfo.GetModuleHapPath(moduleName);
    if (!oldHspPath.empty()) {
        LOG_I(BMS_TAG_INSTALLER, "deleteBundlePath_ insert path %{public}s", oldHspPath.c_str());
        deleteBundlePath_.emplace_back(oldHspPath);
    }

    auto result = ExtractModule(newInfo, hspPath, installParam.copyHapToInstallPath, true);
    CHECK_SKILLS_RESULT(result, "ExtractModule failed %{public}d");
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
        LOG_E(BMS_TAG_INSTALLER, "old module update state failed");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }
    oldInfo.SetBundleUpdateTimeForAllUser(BundleUtil::GetCurrentTimeMs());
    if (!dataMgr_->UpdateInnerBundleInfo(bundleName_, newInfo, oldInfo)) {
        LOG_E(BMS_TAG_INSTALLER, "update innerBundleInfo %{public}s failed", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::ProcessNewModuleInstall(InnerBundleInfo &newInfo,
    InnerBundleInfo &oldInfo, const std::string &hspPath, const InstallParam &installParam)
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    LOG_D(BMS_TAG_INSTALLER, "ProcessNewModuleInstall, bundleName : %{public}s, moduleName : %{public}s",
        newInfo.GetBundleName().c_str(), moduleName.c_str());
    if (bundleInstallChecker_->IsContainModuleName(newInfo, oldInfo)) {
        LOG_E(BMS_TAG_INSTALLER, "moduleName is already existed");
        return ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME;
    }

    oldInfo.SetInstallMark(bundleName_, moduleName, InstallExceptionStatus::UPDATING_NEW_START);

    auto result = ExtractModule(newInfo, hspPath, installParam.copyHapToInstallPath, false);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "extract module and rename failed");
        return result;
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
        LOG_E(BMS_TAG_INSTALLER, "new moduleupdate state failed");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }
    oldInfo.SetBundleUpdateTimeForAllUser(BundleUtil::GetCurrentTimeMs());
    if (!dataMgr_->AddNewModuleInfo(bundleName_, newInfo, oldInfo)) {
        LOG_E(BMS_TAG_INSTALLER, "add module %{public}s to %{public}s failed", moduleName.c_str(), bundleName_.c_str());
        return ERR_APPEXECFWK_ADD_MODULE_ERROR;
    }
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::ExtractModule(
    InnerBundleInfo &newInfo, const std::string &bundlePath,
    bool copyHapToInstallPath, bool isModuleExist)
{
    ErrCode result = ERR_OK;
    auto moduleInfos = newInfo.GetInnerModuleInfos();
    if (moduleInfos.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "skills %{public}s has no module", bundleName_.c_str());
        return ERR_SKILLS_HAS_NO_MODULE;
    }
    std::string bundleDir = std::string(BASE_SKILL_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName_;
    result = MkdirIfNotExist(bundleDir);
    CHECK_SKILLS_RESULT(result, "Check bundle dir failed %{public}d");
    newInfo.SetAppCodePath(bundleDir);
    std::string moduleName = moduleInfos.begin()->second.moduleName;
    std::string tempModuleName = moduleName;
    if (isModuleExist) {
        tempModuleName += TEMP_PATH;
    }
    std::string moduleDir = bundleDir + ServiceConstants::PATH_SEPARATOR + tempModuleName;
    result = MkdirIfNotExist(moduleDir);
    CHECK_SKILLS_RESULT(result, "Check module dir failed %{public}d");
    result = ExtractSkills(newInfo, moduleInfos.begin()->second, bundlePath, isModuleExist);
    CHECK_SKILLS_RESULT(result, "extract skill failed %{public}d");
    // preInstallHsp does not need to copy
    if (copyHapToInstallPath) {
        std::string tempHspPath = moduleDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR +
            tempModuleName + ServiceConstants::HSP_FILE_SUFFIX;
        result = InstalldClient::GetInstance()->CopyFile(bundlePath, tempHspPath, BundleDirScene::COPY_SKILL_HSP);
        std::string realHspPath = moduleDir + AppExecFwk::ServiceConstants::PATH_SEPARATOR +
            moduleName + ServiceConstants::HSP_FILE_SUFFIX;
        newInfo.SetModuleHapPath(realHspPath);
        CHECK_SKILLS_RESULT(result, "move hsp to install dir failed %{public}d");
        result = VerifyCodeSignatureForHsp(tempHspPath);
        CHECK_SKILLS_RESULT(result, "verify code sign failed %{public}d");
    } else {
        newInfo.SetModuleHapPath(bundlePath);
    }
    std::string realModuleDir = bundleDir + ServiceConstants::PATH_SEPARATOR + moduleName;
    // rename +temp
    if (isModuleExist) {
        result = InstalldClient::GetInstance()->RenameModuleDir(moduleDir, realModuleDir,
            bundleName_, BundleDirScene::BASE_SKILL_DIR);
        CHECK_SKILLS_RESULT(result, "rename +temp path failed %{public}d");
    }
    // save killName and description
    newInfo.AddModuleSrcDir(realModuleDir);
    newInfo.AddModuleResPath(realModuleDir);
    newInfo.SetHideDesktopIcon(true);
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::ExtractSkills(
    InnerBundleInfo &newInfo, const InnerModuleInfo &moduleInfo, const std::string &bundlePath, bool isModuleExist)
{
    std::vector<std::string> skillsNameList;
    for (const auto &skills : moduleInfo.skillProfiles) {
        // not allow ../ in name
        if (skills.name.find(ServiceConstants::RELATIVE_PATH) == std::string::npos) {
            skillsNameList.emplace_back(skills.name);
        }
    }
    if (skillsNameList.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "skills %{public}s has no skillProfiles", bundleName_.c_str());
        return ERR_SKILLS_HAS_NO_SKILLS_AGENT;
    }
    std::string moduleName = moduleInfo.moduleName;
    std::string tempModuleName = moduleName;
    if (isModuleExist) {
        tempModuleName += TEMP_PATH;
    }
    std::vector<SkillsPackageInfo> validSkillInfoList;
    ErrCode result = SkillsInstallerUtil::ExtractSkillsPackage(bundleName_, moduleName, tempModuleName,
        bundlePath, skillsNameList, validSkillInfoList);
    CHECK_SKILLS_RESULT(result, "ExtractSkillsPackage failed %{public}d");
    if (validSkillInfoList.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "skills %{public}s has no validSkillInfoList", bundleName_.c_str());
        return ERR_SKILLS_HAS_NO_SKILLS_AGENT;
    }
    if (isModuleExist) {
        for (auto &info : validSkillInfoList) {
            info.moduleName = moduleName;
        }
    }
    result = SkillsInstallerUtil::RemoveInvalidSkillProfiles(validSkillInfoList, newInfo);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "skills %{public}s remove skill failed %{public}d", bundleName_.c_str(), result);
        return result;
    }
    result = SkillsDescriptionManager::GetInstance()->AddSkillDescriptions(validSkillInfoList);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "skills %{public}s add description failed %{public}d", bundleName_.c_str(), result);
        return result;
    }
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::UninstallLowerVersion(const std::vector<std::string> &moduleNameList)
{
    LOG_I(BMS_TAG_INSTALLER, "start to uninstall lower version module");
    InnerBundleInfo info;
    bool isExist = false;
    if (!FetchInnerBundleInfo(info, isExist) || !isExist) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_START)) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall already start");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }

    std::vector<std::string> moduleVec = info.GetModuleNameVec();
    InnerBundleInfo oldInfo = info;
    for (const auto &package : moduleVec) {
        if (find(moduleNameList.begin(), moduleNameList.end(), package) == moduleNameList.end()) {
            LOG_I(BMS_TAG_INSTALLER, "uninstall package %{public}s", package.c_str());
            if (!dataMgr_->RemoveModuleInfo(bundleName_, package, info)) {
                LOG_E(BMS_TAG_INSTALLER, "RemoveModuleInfo failed");
                return ERR_APPEXECFWK_RMV_MODULE_ERROR;
            }
            // After successfully saving the bundleInfo, delete the path
            SkillsPackageInfo packageInfo;
            packageInfo.bundleName = bundleName_;
            packageInfo.moduleName = package;
            needDeleteSkillsPackageInfo_.emplace_back(packageInfo);
        }
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_SUCCESS)) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall already start");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }
    return ERR_OK;
}

bool IndependentSkillsInstaller::FetchInnerBundleInfo(InnerBundleInfo &info, bool &isAppExist)
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            LOG_E(BMS_TAG_INSTALLER, "Get dataMgr shared_ptr nullptr");
            return false;
        }
    }
    isAppExist = dataMgr_->FetchInnerBundleInfo(bundleName_, info);
    return true;
}

bool IndependentSkillsInstaller::RemoveInfo(const std::string &bundleName)
{
    if (dataMgr_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "DataMgr is nullptr");
        return false;
    }
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS)) {
        LOG_E(BMS_TAG_INSTALLER, "Delete inner info failed");
        return false;
    }
    return true;
}

bool IndependentSkillsInstaller::CheckNeedInstall(const std::unordered_map<std::string, InnerBundleInfo> &infos,
    InnerBundleInfo &oldInfo, bool &isDowngrade)
{
    if (infos.empty()) {
        LOG_W(BMS_TAG_INSTALLER, "innerbundleinfos is empty");
        return false;
    }
    if (!(dataMgr_->FetchInnerBundleInfo(bundleName_, oldInfo))) {
        LOG_D(BMS_TAG_INSTALLER, "bundleName %{public}s not existed local", bundleName_.c_str());
        return true;
    }
    // used to rollback when update failed
    oldInnerBundleInfo_ = oldInfo;
    hasInstalledInUser_ = oldInfo.HasInnerBundleUserInfo(userId_);
    LOG_I(BMS_TAG_INSTALLER, "%{public}s old version:%{public}d, new version:%{public}d",
        bundleName_.c_str(), oldInfo.GetVersionCode(), versionCode_);
    if (oldInfo.GetVersionCode() == versionCode_) {
        moduleUpdate_ = true;
        return true;
    } else if (oldInfo.GetVersionCode() > versionCode_) {
        isDowngrade = true;
        LOG_W(BMS_TAG_INSTALLER, "version code is lower than current app service");
        return false;
    }
    LOG_I(BMS_TAG_INSTALLER, "%{public}s version code is upgraded", bundleName_.c_str());
    versionUpgrade_ = true;
    return true;
}

ErrCode IndependentSkillsInstaller::CheckSingletonAndU1Enable(
    const std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    for (const auto &newInfo : newInfos) {
        if (newInfo.second.IsSingleton() || newInfo.second.IsU1Enable()) {
            return ERR_SKILLS_NOT_SUPPORT_SINGLETON_AND_U1;
        }
    }
    return ERR_OK;
}

bool IndependentSkillsInstaller::CheckAppIdentifier(
    const std::string &oldAppIdentifier, const std::string &newAppIdentifier,
    const std::string &oldAppId, const std::string &newAppId)
{
    if (!oldAppIdentifier.empty() && !newAppIdentifier.empty() &&
        (oldAppIdentifier == newAppIdentifier)) {
        return true;
    }
    if (oldAppId == newAppId) {
        return true;
    }
    LOG_E(BMS_TAG_INSTALLER, "the appIdentifier or appId of the new bundle is not the same as old one");
    return false;
}

ErrCode IndependentSkillsInstaller::DeliveryProfileToCodeSign(
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults) const
{
    if (hapVerifyResults.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "no sign info in the all haps");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }

    Security::Verify::ProvisionInfo provisionInfo = hapVerifyResults[0].GetProvisionInfo();
    if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM ||
        provisionInfo.type == Security::Verify::ProvisionType::DEBUG) {
        if (provisionInfo.profileBlockLength == 0 || provisionInfo.profileBlock == nullptr) {
            LOG_E(BMS_TAG_INSTALLER, "invalid sign profile");
            return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
        }
        return InstalldClient::GetInstance()->DeliverySignProfile(provisionInfo.bundleInfo.bundleName,
            provisionInfo.profileBlockLength, provisionInfo.profileBlock.get());
    }
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::MarkInstallFinish()
{
    if (dataMgr_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "dataMgr_ is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    InnerBundleInfo info;
    if (!dataMgr_->FetchInnerBundleInfo(bundleName_, info)) {
        LOG_E(BMS_TAG_INSTALLER, "mark finish failed, -n %{public}s not exist", bundleName_.c_str());
        return ERR_APPEXECFWK_FETCH_BUNDLE_ERROR;
    }
    info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    info.SetInstallMark(bundleName_, info.GetCurModuleName(), InstallExceptionStatus::INSTALL_FINISH);
    if (!dataMgr_->UpdateInnerBundleInfo(info, true)) {
        if (!dataMgr_->UpdateInnerBundleInfo(info, true)) {
            LOG_E(BMS_TAG_INSTALLER, "save mark failed, -n %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_UPDATE_BUNDLE_ERROR;
        }
    }
    return ERR_OK;
}

void IndependentSkillsInstaller::SendBundleSystemEvent(
    const std::string &bundleName, const InstallParam &installParam,
    BundleEventType bundleEventType, ErrCode errCode)
{
    EventInfo sysEventInfo;
    sysEventInfo.bundleName = bundleName;
    sysEventInfo.isPreInstallApp = installParam.isPreInstallApp;
    sysEventInfo.errCode = errCode;
    sysEventInfo.userId = installParam.userId;
    sysEventInfo.versionCode = versionCode_;
    InstallScene preBundleScene = installParam.isOTA ? InstallScene::REBOOT : InstallScene::BOOT;
    if (!installParam.isPreInstallApp) {
        preBundleScene = InstallScene::NORMAL;
    }
    if (installParam.isCreateUser) {
        preBundleScene = InstallScene::CREATE_USER;
    }
    if (installParam.isRemoveUser) {
        preBundleScene = InstallScene::REMOVE_USER;
    }
    sysEventInfo.preBundleScene = preBundleScene;
    sysEventInfo.callingUid = IPCSkeleton::GetCallingUid();
    sysEventInfo.startTime = startTime_;
    sysEventInfo.endTime = BundleUtil::GetCurrentTimeMs();
    if (dataMgr_ != nullptr) {
        dataMgr_->GetOdidByBundleName(bundleName, sysEventInfo.odid);
    }
    if ((errCode == ERR_OK) && ((bundleEventType == BundleEventType::INSTALL) ||
        (bundleEventType == BundleEventType::UPDATE))) {
        GetInstallEventInfo(sysEventInfo);
    }
    EventReport::SendBundleSystemEvent(bundleEventType, sysEventInfo);
}

void IndependentSkillsInstaller::GetInstallEventInfo(EventInfo &eventInfo)
{
    APP_LOGD("GetInstallEventInfo start, bundleName:%{public}s", bundleName_.c_str());
    InnerBundleInfo bundleInfo;
    bool isExist = false;
    if (!FetchInnerBundleInfo(bundleInfo, isExist) || !isExist) {
        LOG_E(BMS_TAG_INSTALLER, "fetch -n %{public}s failed, may not exist", bundleName_.c_str());
        return;
    }
    eventInfo.fingerprint = bundleInfo.GetCertificateFingerprint();
    eventInfo.appDistributionType = bundleInfo.GetAppDistributionType();
    eventInfo.hideDesktopIcon = bundleInfo.IsHideDesktopIconForEvent();
    eventInfo.timeStamp = bundleInfo.GetBundleUpdateTime(userId_);
    eventInfo.isAbcCompressed = bundleInstallChecker_->GetIsAbcCompressed();
    eventInfo.minAPIVersion = bundleInfo.GetBaseApplicationInfo().apiCompatibleVersion;
    eventInfo.targetAPIVersion = bundleInfo.GetBaseApplicationInfo().apiTargetVersion;
    eventInfo.compileSdkVersion = bundleInfo.GetBaseApplicationInfo().compileSdkVersion;
    // report hapPath and hashValue
    for (const auto &innerModuleInfo : bundleInfo.GetInnerModuleInfos()) {
        eventInfo.filePath.push_back(innerModuleInfo.second.hapPath);
        eventInfo.hashValue.push_back(innerModuleInfo.second.hashValue);
    }
}

void IndependentSkillsInstaller::RollBack()
{
    LOG_I(BMS_TAG_INSTALLER, "RollBack: %{public}s", bundleName_.c_str());
    if (newInnerBundleInfo_.IsPreInstallApp() && !BundleUtil::CheckSystemFreeSize(BASE_SKILL_DIR, FIVE_MB)) {
        LOG_W(BMS_TAG_INSTALLER, "pre bundle: %{public}s no rollback due to no space", bundleName_.c_str());
        return;
    }
    // RemoveCache
    RemoveInfo(bundleName_);
    // delete code
    std::string bundleDir = std::string(BASE_SKILL_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName_;
    ErrCode result =
        InstalldClient::GetInstance()->RemoveDir(bundleDir, BundleDirScene::REMOVE_SKILL_BUNDLE_DIR, bundleName_);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "remove bundle dir %{public}s failed", bundleDir.c_str());
    }
    result = SkillsDescriptionManager::GetInstance()->DeleteSkillDescriptions(bundleName_);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "delete skill descriptions %{public}s -u %{public}d failed",
            bundleName_.c_str(), userId_);
    }
}

void IndependentSkillsInstaller::RollBack(
    const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    const ErrCode result)
{
    if ((result == ERR_APPEXECFWK_INSTALL_FAILED_INCONSISTENT_SIGNATURE) ||
        (result == ERR_SKILLS_INSTALL_TYPE_NOT_SAME) ||
        (result == ERR_APPEXECFWK_INSTALL_PARAM_ERROR) ||
        (result == ERR_SKILLS_MODULE_NAME_NOT_SAME)) {
        return;
    }
    auto oldmoduleInfos = oldInnerBundleInfo_.GetInnerModuleInfos();
    // delete new path
    for (const auto &item : newInfos) {
        std::string moduleName = item.second.GetCurrentModulePackage();
        if (oldmoduleInfos.find(moduleName) == oldmoduleInfos.end()) {
            RemoveModuleDir(bundleName_, moduleName);
        } else {
            RemoveModuleDir(bundleName_, moduleName + TEMP_PATH);
        }
    }
    if (dataMgr_ != nullptr) {
        if (!dataMgr_->UpdateInnerBundleInfo(oldInnerBundleInfo_, false)) {
            LOG_E(BMS_TAG_INSTALLER, "Rollback failed -n %{public}s", bundleName_.c_str());
        } else {
            LOG_I(BMS_TAG_INSTALLER, "Rollback succeed -n %{public}s", bundleName_.c_str());
        }
    }
}

ErrCode IndependentSkillsInstaller::ProcessInstallBundleByBundleName(
    const std::string &bundleName, const InstallParam &installParam)
{
    if (bundleName.empty()) {
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    ErrCode result = CheckUserId(installParam.userId);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "bundle %{public}s userId %{public}d type error", bundleName.c_str(),
            installParam.userId);
        return result;
    }
    {
        auto &mtx = dataMgr_->GetBundleMutex(bundleName);
        std::lock_guard lock {mtx};
        bundleName_ = bundleName;
        userId_ = installParam.userId;
        bool isAppExist = dataMgr_->FetchInnerBundleInfo(bundleName, oldInnerBundleInfo_);
        if (isAppExist) {
            versionCode_ = oldInnerBundleInfo_.GetVersionCode();
            if (oldInnerBundleInfo_.GetApplicationBundleType() != BundleType::SKILL) {
                LOG_E(BMS_TAG_INSTALLER, "bundle %{public}s userId %{public}d type error", bundleName.c_str(), userId_);
                return ERR_SKILLS_INSTALL_TYPE_FAILED;
            }
            if (oldInnerBundleInfo_.HasInnerBundleUserInfo(userId_)) {
                LOG_E(BMS_TAG_INSTALLER, "bundle %{public}s userId %{public}d already exist",
                    bundleName.c_str(), userId_);
                return ERR_SKILLS_INSTALL_USER_ALREADY_EXIST;
            }
            InnerBundleUserInfo innerBundleUserInfo;
            innerBundleUserInfo.bundleUserInfo.userId = userId_;
            innerBundleUserInfo.bundleName = bundleName;
            innerBundleUserInfo.installTime = BundleUtil::GetCurrentTimeMs();
            innerBundleUserInfo.updateTime = innerBundleUserInfo.installTime;
            result = dataMgr_->AddInnerBundleUserInfo(bundleName, innerBundleUserInfo);
            if (result != ERR_OK) {
                LOG_E(BMS_TAG_INSTALLER, "bundle %{public}s userId %{public}d add failed %{public}d",
                    bundleName.c_str(), userId_, result);
                return result;
            }
            return ERR_OK;
        }
    }
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName);
    if (!dataMgr_->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto innerInstallParam = installParam;
    innerInstallParam.isPreInstallApp = true;
    innerInstallParam.removable = preInstallBundleInfo.IsRemovable();
    innerInstallParam.copyHapToInstallPath = false;
    return ProcessInstall(preInstallBundleInfo.GetBundlePaths(), innerInstallParam);
}

void IndependentSkillsInstaller::MarkPreInstallState(const std::string &bundleName, bool isUninstalled)
{
    LOG_I(BMS_TAG_INSTALLER, "bundle: %{public}s isUninstalled: %{public}d", bundleName.c_str(), isUninstalled);
    if (!dataMgr_) {
        LOG_E(BMS_TAG_INSTALLER, "dataMgr is nullptr");
        return;
    }

    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName);
    if (!dataMgr_->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        LOG_I(BMS_TAG_INSTALLER, "No PreInstallBundleInfo(%{public}s) in db", bundleName.c_str());
        return;
    }

    preInstallBundleInfo.SetIsUninstalled(isUninstalled);
    dataMgr_->SavePreInstallBundleInfo(bundleName, preInstallBundleInfo);
}

void IndependentSkillsInstaller::ResetProperties()
{
    uninstallModuleVec_.clear();
    versionUpgrade_ = false;
    moduleUpdate_ = false;
    deleteBundlePath_.clear();
    versionCode_ = 0;
    newInnerBundleInfo_ = InnerBundleInfo();
    isEnterpriseBundle_ = false;
    appIdentifier_ = "";
    compileSdkType_ = "";
    hasInstalledInUser_ = false;
    userId_ = -1;
    bundleName_ = "";
    needDeleteSkillsPackageInfo_.clear();
}

void IndependentSkillsInstaller::RemoveOldSkillsPath()
{
    if (needDeleteSkillsPackageInfo_.empty()) {
        return;
    }
    auto manager = SkillsDescriptionManager::GetInstance();
    if (manager == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "bundle %{public}s remove old failed, manager is nullptr", bundleName_.c_str());
        return;
    }
    std::string bundlePath = std::string(BASE_SKILL_DIR);
    for (const auto &packageInfo : needDeleteSkillsPackageInfo_) {
        if (packageInfo.skillsName.empty()) {
            // delete module
            RemoveModuleDir(packageInfo.bundleName, packageInfo.moduleName);
            auto result = manager->DeleteSkillDescriptions(packageInfo.bundleName, packageInfo.moduleName);
            if (result != ERR_OK) {
                LOG_E(BMS_TAG_INSTALLER, "delete skill failed -n %{public}s -m %{public}s %{public}d",
                    packageInfo.bundleName.c_str(), packageInfo.moduleName.c_str(), result);
            }
        } else {
            // delete skill
            RemoveSkillDir(packageInfo.bundleName, packageInfo.moduleName, packageInfo.skillsName);
            auto result = manager->DeleteSkillDescriptions(packageInfo.bundleName, packageInfo.moduleName,
                packageInfo.skillsName);
            if (result != ERR_OK) {
                LOG_E(BMS_TAG_INSTALLER, "delete skill failed -n %{public}s -m %{public}s -s %{public}s %{public}d",
                    packageInfo.bundleName.c_str(), packageInfo.moduleName.c_str(), packageInfo.skillsName.c_str(),
                    result);
            }
        }
    }
}

ErrCode IndependentSkillsInstaller::ProcessUninstall(const std::string &bundleName, const InstallParam &installParam)
{
    ErrCode result = BeforeUninstall(bundleName, installParam.userId);
    CHECK_SKILLS_RESULT(result, "BeforeUninstallInstall check failed %{public}d");
    if (dataMgr_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (!oldInnerBundleInfo_.IsRemovable()) {
        if (installParam.GetKillProcess() && !installParam.GetForceExecuted()) {
            LOG_E(BMS_TAG_INSTALLER, "skills -n %{public}s system app not support uninstall", bundleName.c_str());
            return ERR_APPEXECFWK_UNINSTALL_SYSTEM_APP_ERROR;
        }
    }
    auto &mtx = dataMgr_->GetBundleMutex(bundleName);
    std::lock_guard lock {mtx};
    // multi-user only remove userInfo
    if (oldInnerBundleInfo_.GetInnerBundleUserInfos().size() > 1) {
        if (!dataMgr_->RemoveInnerBundleUserInfo(bundleName, installParam.userId)) {
            LOG_E(BMS_TAG_INSTALLER, "bundle %{public}s delete userInfo %{public}d failed", bundleName.c_str(),
                installParam.userId);
            return ERR_APPEXECFWK_RMV_USERINFO_ERROR;
        }
        return ERR_OK;
    }
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START)) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall already start");
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS)) {
        LOG_E(BMS_TAG_INSTALLER, "delete inner info failed for bundle %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }
    MarkPreInstallState(bundleName, true);
    result = SkillsDescriptionManager::GetInstance()->DeleteSkillDescriptions(bundleName);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "delete skill desc -n %{public}s failed %{public}d", bundleName.c_str(), result);
    }
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName)) {
        LOG_E(BMS_TAG_INSTALLER, "bundleName: %{public}s delete appProvisionInfo failed", bundleName.c_str());
    }
    std::string bundleDir =
        std::string(BASE_SKILL_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName;
    LOG_I(BMS_TAG_INSTALLER, "start to remove bundle dir: %{public}s", bundleDir.c_str());
    if (InstalldClient::GetInstance()->RemoveDir(bundleDir, BundleDirScene::REMOVE_SKILL_BUNDLE_DIR, bundleName) !=
        ERR_OK) {
        LOG_W(BMS_TAG_INSTALLER, "remove bundle dir %{public}s failed", bundleDir.c_str());
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    return ERR_OK;
}

ErrCode IndependentSkillsInstaller::BeforeUninstall(const std::string &bundleName,
    const int32_t userId)
{
    userId_ = userId;
    bundleName_ = bundleName;
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "bundleName is empty");
        return ERR_SKILLS_UNINSTALL_BUNDLENAME_NOT_EXIST;
    }

    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (!dataMgr_->HasUserId(userId)) {
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    if (!dataMgr_->FetchInnerBundleInfo(bundleName, oldInnerBundleInfo_)) {
        LOG_E(BMS_TAG_INSTALLER, "bundle %{public}s not exist", bundleName.c_str());
        return ERR_SKILLS_UNINSTALL_BUNDLENAME_NOT_EXIST;
    }
    if (oldInnerBundleInfo_.GetApplicationBundleType() != BundleType::SKILL) {
        LOG_E(BMS_TAG_INSTALLER, "bundle %{public}s type error, not skills", bundleName.c_str());
        return ERR_SKILLS_UNINSTALL_WRONG_BUNDLE_TYPE;
    }
    if (!oldInnerBundleInfo_.HasInnerBundleUserInfo(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "bundle %{public}s get user %{public}d failed", bundleName.c_str(), userId);
        return ERR_APPEXECFWK_USER_NOT_INSTALL_HAP;
    }
    return ERR_OK;
}

void IndependentSkillsInstaller::InnerProcessNeedDeleteSkillPackage(const InnerBundleInfo &currentBundleInfo)
{
    // Compare skillProfiles between currentBundleInfo and oldInnerBundleInfo_ to identify deleted skills
    auto oldModuleInfos = oldInnerBundleInfo_.GetInnerModuleInfos();
    auto currentModuleInfos = currentBundleInfo.GetInnerModuleInfos();

    for (const auto &oldModulePair : oldModuleInfos) {
        const std::string &moduleName = oldModulePair.first;
        const InnerModuleInfo &oldModuleInfo = oldModulePair.second;
        // Check if module exists in current info, already process in UninstallLowerVersion
        auto currentModuleIter = currentModuleInfos.find(moduleName);
        if (currentModuleIter == currentModuleInfos.end()) {
            continue;
        }

        // Module exists, compare skillProfiles
        const InnerModuleInfo &currentModuleInfo = currentModuleIter->second;
        // Create a set of current skill names for quick lookup
        std::set<std::string> currentskillsNames;
        for (const auto &skillProfile : currentModuleInfo.skillProfiles) {
            currentskillsNames.insert(skillProfile.name);
        }
        // Find skillProfiles that exist in oldModuleInfo but not in currentModuleInfo
        for (const auto &skillProfile : oldModuleInfo.skillProfiles) {
            if (currentskillsNames.find(skillProfile.name) == currentskillsNames.end()) {
                // This skillProfile was deleted
                SkillsPackageInfo packageInfo;
                packageInfo.bundleName = bundleName_;
                packageInfo.moduleName = moduleName;
                packageInfo.skillsName = skillProfile.name;
                needDeleteSkillsPackageInfo_.emplace_back(packageInfo);
                LOG_I(BMS_TAG_INSTALLER, "Skill %{public}s in module %{public}s deleted, added to delete list",
                    skillProfile.name.c_str(), moduleName.c_str());
            }
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
