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

#include "inner_shared_bundle_installer.h"

#include "app_log_wrapper.h"
#include "app_provision_info_manager.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "shared/base_shared_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::Security;
namespace {
const std::string HSP_VERSION_PREFIX = "v";
}

InnerSharedBundleInstaller::InnerSharedBundleInstaller(const std::string &path)
    : sharedBundlePath_(path), bundleInstallChecker_(std::make_unique<BundleInstallChecker>())
{
    APP_LOGI("inner shared bundle installer instance is created");
}

InnerSharedBundleInstaller::~InnerSharedBundleInstaller()
{
    APP_LOGI("inner shared bundle installer instance is destroyed");
}

ErrCode InnerSharedBundleInstaller::ParseFiles(const InstallCheckParam &checkParam)
{
    APP_LOGD("parsing shared bundle files, path : %{private}s", sharedBundlePath_.c_str());
    ErrCode result = ERR_OK;

    // check file paths
    std::vector<std::string> bundlePaths;
    result = BundleUtil::CheckFilePath({sharedBundlePath_}, bundlePaths);
    CHECK_RESULT(result, "hsp files check failed %{public}d");

    // check syscap
    result = bundleInstallChecker_->CheckSysCap(bundlePaths);
    CHECK_RESULT(result, "hap syscap check failed %{public}d");

    // verify signature info for all haps
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    result = bundleInstallChecker_->CheckMultipleHapsSignInfo(bundlePaths, hapVerifyResults);
    CHECK_RESULT(result, "hap files check signature info failed %{public}d");

    // parse bundle infos
    result = bundleInstallChecker_->ParseHapFiles(bundlePaths, checkParam, hapVerifyResults, parsedBundles_);
    CHECK_RESULT(result, "parse haps file failed %{public}d");

    // check device type
    result = bundleInstallChecker_->CheckDeviceType(parsedBundles_);
    CHECK_RESULT(result, "check device type failed %{public}d");

    // check label info
    result = CheckAppLabelInfo();
    CHECK_RESULT(result, "check label info failed %{public}d");

    // check native file
    result = bundleInstallChecker_->CheckMultiNativeFile(parsedBundles_);
    CHECK_RESULT(result, "native so is incompatible in all haps %{public}d");

    AddAppProvisionInfo(bundleName_, hapVerifyResults[0].GetProvisionInfo());
    return result;
}

ErrCode InnerSharedBundleInstaller::Install(const InstallParam &installParam)
{
    if (parsedBundles_.empty()) {
        APP_LOGD("no bundle to install");
        return ERR_OK;
    }

    ErrCode result = ERR_OK;
    for (auto &item : parsedBundles_) {
        result = ExtractSharedBundles(item.first, item.second);
        CHECK_RESULT(result, "extract shared bundles failed %{public}d");
    }

    MergeBundleInfos();

    result = SavePreInstallInfo(installParam);
    CHECK_RESULT(result, "save pre install info failed %{public}d");

    result = SaveBundleInfoToStorage();
    CHECK_RESULT(result, "save bundle info to storage failed %{public}d");

    APP_LOGD("install shared bundle successfully: %{public}s", bundleName_.c_str());
    return result;
}

void InnerSharedBundleInstaller::RollBack()
{
    // delete created directories
    for (auto iter = createdDirs_.crbegin(); iter != createdDirs_.crend(); ++iter) {
        ErrCode err = InstalldClient::GetInstance()->RemoveDir(*iter);
        if (err != ERR_OK) {
            APP_LOGE("clean dir of %{public}s failed: %{public}s", bundleName_.c_str(), iter->c_str());
        }
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("get dataMgr failed");
        return;
    }

    // rollback database
    if (!isBundleExist_) {
        if (dataMgr->DeleteSharedBundleInfo(bundleName_)) {
            APP_LOGE("rollback new bundle failed : %{public}s", bundleName_.c_str());
        }
        DeleteAppProvisionInfo(bundleName_);
        return;
    }

    if (dataMgr->UpdateInnerBundleInfo(oldBundleInfo_)) {
        APP_LOGE("rollback old bundle failed : %{public}s", bundleName_.c_str());
    }
}

bool InnerSharedBundleInstaller::CheckDependency(const Dependency &dependency) const
{
    if (dependency.bundleName != bundleName_) {
        APP_LOGE("bundle name not match : %{public}s, %{public}s", bundleName_.c_str(), dependency.bundleName.c_str());
        return false;
    }

    for (const auto &item : parsedBundles_) {
        const auto bundleInfo = item.second;
        BaseSharedBundleInfo sharedBundle;
        bool isModuleExist = bundleInfo.GetMaxVerBaseSharedBundleInfo(dependency.moduleName, sharedBundle);
        if (isModuleExist && dependency.versionCode <= sharedBundle.versionCode) {
            return true;
        }
    }

    APP_LOGE("dependency not match");
    return false;
}

void InnerSharedBundleInstaller::SendBundleSystemEvent(const EventInfo &eventTemplate) const
{
    EventInfo eventInfo = eventTemplate;
    eventInfo.bundleName = bundleName_;
    eventInfo.versionCode = newBundleInfo_.GetBaseBundleInfo().versionCode;
    GetInstallEventInfo(eventInfo);

    BundleEventType eventType = isBundleExist_ ? BundleEventType::UPDATE : BundleEventType::INSTALL;
    EventReport::SendBundleSystemEvent(eventType, eventInfo);
}

ErrCode InnerSharedBundleInstaller::CheckAppLabelInfo()
{
    if (parsedBundles_.empty()) {
        return ERR_OK;
    }
    bundleName_ = parsedBundles_.begin()->second.GetBundleName();

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    isBundleExist_ = dataMgr->FetchInnerBundleInfo(bundleName_, oldBundleInfo_);
    if (isBundleExist_) {
        ErrCode ret = CheckCompatiblePolicyWithInstalledVersion();
        CHECK_RESULT(ret, "check compatible policy with installed version failed %{public}d");

        // check old InnerBundleInfo together
        parsedBundles_.emplace(bundleName_, oldBundleInfo_);
    } else {
        if (parsedBundles_.begin()->second.GetCompatiblePolicy() == CompatiblePolicy::NORMAL) {
            APP_LOGE("installing bundle is not hsp");
            return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
        }
    }

    // check compatible policy between all parsed bundles
    CompatiblePolicy firstPolicy = parsedBundles_.begin()->second.GetCompatiblePolicy();
    for (const auto &item : parsedBundles_) {
        if (item.second.GetCompatiblePolicy() != firstPolicy) {
            APP_LOGE("compatiblePolicy not same");
            return ERR_APPEXECFWK_INSTALL_COMPATIBLE_POLICY_NOT_SAME;
        }
    }

    ErrCode result = bundleInstallChecker_->CheckAppLabelInfo(parsedBundles_);
    if (isBundleExist_) {
        parsedBundles_.erase(bundleName_);
    }
    return result;
}

ErrCode InnerSharedBundleInstaller::CheckCompatiblePolicyWithInstalledVersion()
{
    if (oldBundleInfo_.GetCompatiblePolicy() == CompatiblePolicy::NORMAL) {
        APP_LOGE("old bundle is not shared");
        return ERR_APPEXECFWK_INSTALL_COMPATIBLE_POLICY_NOT_SAME;
    }

    if (oldBundleInfo_.GetCompatiblePolicy() != CompatiblePolicy::BACK_COMPATIBLE) {
        APP_LOGD("not back compatible shared bundle, do not check compatible policy");
        return ERR_OK;
    }

    for (const auto &item : parsedBundles_) {
        auto& sharedModules = item.second.GetInnerSharedModuleInfos();
        if (sharedModules.empty() || sharedModules.begin()->second.empty()) {
            APP_LOGW("inner shared module infos not found (%{public}s)", item.second.GetBundleName().c_str());
            continue;
        }

        auto& sharedModule = sharedModules.begin()->second.front();
        BaseSharedBundleInfo installedSharedModule;
        if (oldBundleInfo_.GetMaxVerBaseSharedBundleInfo(sharedModule.moduleName, installedSharedModule) &&
            installedSharedModule.versionCode > sharedModule.versionCode) {
            APP_LOGE("installing lower version shared package");
            return ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE;
        }
    }
    return ERR_OK;
}

ErrCode InnerSharedBundleInstaller::MkdirIfNotExist(const std::string &dir)
{
    bool isDirExist = false;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(dir, isDirExist);
    CHECK_RESULT(result, "check if dir exist failed %{public}d");
    if (!isDirExist) {
        result = InstalldClient::GetInstance()->CreateBundleDir(dir);
        CHECK_RESULT(result, "create dir failed %{public}d");
        createdDirs_.emplace_back(dir);
    }
    return result;
}

ErrCode InnerSharedBundleInstaller::ExtractSharedBundles(const std::string &bundlePath, InnerBundleInfo &newInfo)
{
    ErrCode result = ERR_OK;
    std::string bundleDir = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName_;
    result = MkdirIfNotExist(bundleDir);
    CHECK_RESULT(result, "check bundle dir failed %{public}d");
    newInfo.SetAppCodePath(bundleDir);

    uint32_t versionCode = newInfo.GetVersionCode();
    std::string versionDir = bundleDir + Constants::PATH_SEPARATOR + HSP_VERSION_PREFIX + std::to_string(versionCode);
    result = MkdirIfNotExist(versionDir);
    CHECK_RESULT(result, "check version dir failed %{public}d");

    auto &moduleName = newInfo.GetInnerModuleInfos().begin()->second.moduleName;
    std::string moduleDir = versionDir + Constants::PATH_SEPARATOR + moduleName;
    result = MkdirIfNotExist(moduleDir);
    CHECK_RESULT(result, "check module dir failed %{public}d");

    std::string cpuAbi;
    std::string nativeLibraryPath;
    newInfo.FetchNativeSoAttrs(moduleName, cpuAbi, nativeLibraryPath);
    std::string targetSoPath = versionDir + Constants::PATH_SEPARATOR + nativeLibraryPath + Constants::PATH_SEPARATOR;
    APP_LOGD("targetSoPath=%{public}s,cpuAbi=%{public}s, bundlePath=%{public}s",
        targetSoPath.c_str(), cpuAbi.c_str(), bundlePath.c_str());

    result = InstalldClient::GetInstance()->ExtractModuleFiles(bundlePath, moduleDir, targetSoPath, cpuAbi);
    CHECK_RESULT(result, "extract module files failed %{public}d");

    std::string hspPath = moduleDir + Constants::PATH_SEPARATOR + moduleName + Constants::INSTALL_SHARED_FILE_SUFFIX;
    result = InstalldClient::GetInstance()->CopyFile(bundlePath, hspPath);
    CHECK_RESULT(result, "copy hsp to install dir failed %{public}d");

    newInfo.SetModuleHapPath(hspPath);
    newInfo.AddModuleSrcDir(moduleDir);
    newInfo.AddModuleResPath(moduleDir);
    return ERR_OK;
}

void InnerSharedBundleInstaller::MergeBundleInfos()
{
    auto iter = parsedBundles_.begin();
    if (isBundleExist_) {
        newBundleInfo_ = oldBundleInfo_;
    } else {
        newBundleInfo_ = iter->second;
        ++iter;
    }

    for (; iter != parsedBundles_.end(); ++iter) {
        const auto &currentBundle = iter->second;
        const auto& infos = currentBundle.GetInnerSharedModuleInfos();
        if (infos.empty()) {
            continue;
        }

        const auto& innerModuleInfos = infos.begin()->second;
        if (!innerModuleInfos.empty()) {
            const auto& innerModuleInfo = innerModuleInfos.front();
            newBundleInfo_.InsertInnerSharedModuleInfo(innerModuleInfo.modulePackage, innerModuleInfo);
        }
        // update version
        if (newBundleInfo_.GetBaseBundleInfo().versionCode < currentBundle.GetBaseBundleInfo().versionCode) {
            newBundleInfo_.UpdateBaseBundleInfo(currentBundle.GetBaseBundleInfo(), false);
            newBundleInfo_.UpdateBaseApplicationInfo(currentBundle.GetBaseApplicationInfo());
        }
    }

    newBundleInfo_.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    newBundleInfo_.SetHideDesktopIcon(true);
}

ErrCode InnerSharedBundleInstaller::SavePreInstallInfo(const InstallParam &installParam)
{
    if (!installParam.needSavePreInstallInfo) {
        APP_LOGD("no need to save pre install info");
        return ERR_OK;
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("get dataMgr failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    PreInstallBundleInfo preInstallBundleInfo;
    dataMgr->GetPreInstallBundleInfo(bundleName_, preInstallBundleInfo);
    preInstallBundleInfo.SetVersionCode(newBundleInfo_.GetBaseBundleInfo().versionCode);
    for (const auto &item : parsedBundles_) {
        preInstallBundleInfo.AddBundlePath(item.first);
    }
#ifdef USE_PRE_BUNDLE_PROFILE
    preInstallBundleInfo.SetRemovable(installParam.removable);
#else
    preInstallBundleInfo.SetRemovable(newBundleInfo_.IsRemovable());
#endif
    dataMgr->SavePreInstallBundleInfo(bundleName_, preInstallBundleInfo);

    return ERR_OK;
}

ErrCode InnerSharedBundleInstaller::SaveBundleInfoToStorage()
{
    // update install mark
    std::string packageName;
    newBundleInfo_.SetInstallMark(bundleName_, packageName, InstallExceptionStatus::INSTALL_FINISH);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("get dataMgr failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    if (isBundleExist_) {
        if (!dataMgr->UpdateInnerBundleInfo(newBundleInfo_)) {
            APP_LOGE("save bundle failed : %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        return ERR_OK;
    }

    dataMgr->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_START);
    if (!dataMgr->AddInnerBundleInfo(bundleName_, newBundleInfo_)) {
        dataMgr->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_FAIL);
        APP_LOGE("save bundle failed : %{public}s", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    dataMgr->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_SUCCESS);
    return ERR_OK;
}

void InnerSharedBundleInstaller::GetInstallEventInfo(EventInfo &eventInfo) const
{
    APP_LOGD("GetInstallEventInfo start, bundleName:%{public}s", bundleName_.c_str());
    eventInfo.fingerprint = newBundleInfo_.GetCertificateFingerprint();
    eventInfo.appDistributionType = newBundleInfo_.GetAppDistributionType();
    eventInfo.hideDesktopIcon = newBundleInfo_.IsHideDesktopIcon();
    eventInfo.timeStamp = BundleUtil::GetCurrentTimeMs();

    // report hapPath and hashValue
    for (const auto &info : parsedBundles_) {
        for (const auto &innerModuleInfo : info.second.GetInnerModuleInfos()) {
            eventInfo.filePath.push_back(innerModuleInfo.second.hapPath);
            eventInfo.hashValue.push_back(innerModuleInfo.second.hashValue);
        }
    }
}

bool InnerSharedBundleInstaller::AddAppProvisionInfo(const std::string &bundleName,
        const Security::Verify::ProvisionInfo &provisionInfo) const
{
    AppProvisionInfo appProvisionInfo = bundleInstallChecker_->ConvertToAppProvisionInfo(provisionInfo);
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        bundleName, appProvisionInfo)) {
        APP_LOGE("bundleName: %{public}s add appProvisionInfo failed.", bundleName.c_str());
        return false;
    }
    return true;
}

bool InnerSharedBundleInstaller::DeleteAppProvisionInfo(const std::string &bundleName) const
{
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName)) {
        APP_LOGE("bundleName: %{public}s delete appProvisionInfo failed.", bundleName.c_str());
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
