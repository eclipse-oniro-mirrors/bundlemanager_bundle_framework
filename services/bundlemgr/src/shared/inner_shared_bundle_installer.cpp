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

#include "app_provision_info_manager.h"
#include "bundle_mgr_service.h"
#include "installd_client.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::Security;
namespace {
const std::string HSP_VERSION_PREFIX = "v";
const int32_t MAX_FILE_NUMBER = 2;
const std::string COMPILE_SDK_TYPE_OPEN_HARMONY = "OpenHarmony";
const std::string DEBUG_APP_IDENTIFIER = "DEBUG_LIB_ID";
}

InnerSharedBundleInstaller::InnerSharedBundleInstaller(const std::string &path)
    : sharedBundlePath_(path), bundleInstallChecker_(std::make_unique<BundleInstallChecker>())
{
    APP_LOGI("inner shared bundle installer instance is created");
}

InnerSharedBundleInstaller::~InnerSharedBundleInstaller()
{
    APP_LOGI("inner shared bundle installer instance is destroyed");
    BundleUtil::DeleteTempDirs(toDeleteTempHspPath_);
}

ErrCode InnerSharedBundleInstaller::ParseFiles(const InstallCheckParam &checkParam)
{
    APP_LOGD("parsing shared bundle files, path : %{private}s", sharedBundlePath_.c_str());
    ErrCode result = ERR_OK;

    // check file paths
    std::vector<std::string> inBundlePaths;
    result = BundleUtil::CheckFilePath({sharedBundlePath_}, inBundlePaths);
    CHECK_RESULT(result, "hsp files check failed %{public}d");

    if (!checkParam.isPreInstallApp) {
        // copy the haps to the dir which cannot be accessed from caller
        result = CopyHspToSecurityDir(inBundlePaths);
        CHECK_RESULT(result, "copy file failed %{public}d");
    }

    // check number and type of the hsp and sig files
    std::vector<std::string> bundlePaths;
    result = ObtainHspFileAndSignatureFilePath(inBundlePaths, bundlePaths, signatureFileDir_);
    CHECK_RESULT(result, "obtain hsp file path or signature file path failed due to %{public}d");

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

    // check install permission
    result = bundleInstallChecker_->CheckInstallPermission(checkParam, hapVerifyResults);
    CHECK_RESULT(result, "check install permission failed %{public}d");

    // check hsp install condition
    result = bundleInstallChecker_->CheckHspInstallCondition(hapVerifyResults);
    CHECK_RESULT(result, "check hsp install condition failed %{public}d");

    // to send notify of start install shared application
    sendStartSharedBundleInstallNotify(checkParam, parsedBundles_);

    // check device type
    result = bundleInstallChecker_->CheckDeviceType(parsedBundles_);
    CHECK_RESULT(result, "check device type failed %{public}d");

    // check label info
    result = CheckAppLabelInfo();
    CHECK_RESULT(result, "check label info failed %{public}d");

    // delivery sign profile to code signature
    result = DeliveryProfileToCodeSign(hapVerifyResults);
    CHECK_RESULT(result, "delivery sign profile failed %{public}d");

    // check native file
    result = bundleInstallChecker_->CheckMultiNativeFile(parsedBundles_);
    CHECK_RESULT(result, "native so is incompatible in all haps %{public}d");

    // check enterprise bundle
    /* At this place, hapVerifyResults cannot be empty and unnecessary to check it */
    isEnterpriseBundle_ = bundleInstallChecker_->CheckEnterpriseBundle(hapVerifyResults[0]);
    appIdentifier_ = (hapVerifyResults[0].GetProvisionInfo().type == Security::Verify::ProvisionType::DEBUG) ?
        DEBUG_APP_IDENTIFIER : hapVerifyResults[0].GetProvisionInfo().bundleInfo.appIdentifier;
    compileSdkType_ = parsedBundles_.empty() ? COMPILE_SDK_TYPE_OPEN_HARMONY :
        (parsedBundles_.begin()->second).GetBaseApplicationInfo().compileSdkType;
    AddAppProvisionInfo(bundleName_, hapVerifyResults[0].GetProvisionInfo());
    return result;
}

void InnerSharedBundleInstaller::sendStartSharedBundleInstallNotify(const InstallCheckParam &installCheckParam,
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    if (!installCheckParam.needSendEvent) {
        APP_LOGW("sendStartSharedBundleInstallNotify needSendEvent is false");
        return;
    }
    for (auto item : infos) {
        APP_LOGD("sendStartSharedBundleInstallNotify %{public}s  %{public}s %{public}s %{public}s",
            item.second.GetBundleName().c_str(), item.second.GetCurModuleName().c_str(),
            item.second.GetAppId().c_str(), item.second.GetAppIdentifier().c_str());
        NotifyBundleEvents installRes = {
            .bundleName = item.second.GetBundleName(),
            .modulePackage = item.second.GetCurModuleName(),
            .type = NotifyType::START_INSTALL,
            .appId = item.second.GetAppId(),
            .appIdentifier = item.second.GetAppIdentifier()
        };
        if (NotifyBundleStatusOfShared(installRes) != ERR_OK) {
            APP_LOGW("notify status failed for start install");
        }
    }
}

ErrCode InnerSharedBundleInstaller::NotifyBundleStatusOfShared(const NotifyBundleEvents &installRes)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr);
    return ERR_OK;
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
        item.second.SetApplicationFlags(installParam.preinstallSourceFlag);
        CHECK_RESULT(result, "extract shared bundles failed %{public}d");
    }

    MergeBundleInfos();

    result = SavePreInstallInfo(installParam);
    CHECK_RESULT(result, "save pre install info failed %{public}d");

    result = SaveBundleInfoToStorage();
    CHECK_RESULT(result, "save bundle info to storage failed %{public}d");

    // save specifiedDistributionType and additionalInfo
    SaveInstallParamInfo(bundleName_, installParam);
    // check mark install finish
    result = MarkInstallFinish();
    if (result != ERR_OK) {
        APP_LOGE("mark install finish failed %{public}d", result);
        RollBack();
        return result;
    }
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
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName_)) {
            APP_LOGE("bundleName: %{public}s delete appProvisionInfo failed", bundleName_.c_str());
        }
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
    eventInfo.callingUid = IPCSkeleton::GetCallingUid();
    GetInstallEventInfo(eventInfo);

    BundleEventType eventType = isBundleExist_ ? BundleEventType::UPDATE : BundleEventType::INSTALL;
    EventReport::SendBundleSystemEvent(eventType, eventInfo);
}

ErrCode InnerSharedBundleInstaller::CheckAppLabelInfo()
{
    if (parsedBundles_.empty()) {
        APP_LOGE("parsedBundles is empty");
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
        ErrCode ret = CheckBundleTypeWithInstalledVersion();
        CHECK_RESULT(ret, "check bundle type with installed version failed %{public}d");

        // check old InnerBundleInfo together
        parsedBundles_.emplace(bundleName_, oldBundleInfo_);
    } else {
        if (parsedBundles_.begin()->second.GetApplicationBundleType() != BundleType::SHARED) {
            APP_LOGE("installing bundle is not hsp");
            return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
        }
    }

    if (isBundleExist_) {
        parsedBundles_.erase(bundleName_);
    }
    return ERR_OK;
}

ErrCode InnerSharedBundleInstaller::CheckBundleTypeWithInstalledVersion()
{
    if (oldBundleInfo_.GetApplicationBundleType() != BundleType::SHARED) {
        APP_LOGE("old bundle is not shared");
        return ERR_APPEXECFWK_INSTALL_COMPATIBLE_POLICY_NOT_SAME;
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
    std::string bundleDir = Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR + bundleName_;
    result = MkdirIfNotExist(bundleDir);
    CHECK_RESULT(result, "check bundle dir failed %{public}d");
    newInfo.SetAppCodePath(bundleDir);

    uint32_t versionCode = newInfo.GetVersionCode();
    std::string versionDir = bundleDir + ServiceConstants::PATH_SEPARATOR + HSP_VERSION_PREFIX
        + std::to_string(versionCode);
    result = MkdirIfNotExist(versionDir);
    CHECK_RESULT(result, "check version dir failed %{public}d");

    auto &moduleName = newInfo.GetInnerModuleInfos().begin()->second.moduleName;
    std::string moduleDir = versionDir + ServiceConstants::PATH_SEPARATOR + moduleName;
    result = MkdirIfNotExist(moduleDir);
    CHECK_RESULT(result, "check module dir failed %{public}d");

    result = ProcessNativeLibrary(bundlePath, moduleDir, moduleName, versionDir, newInfo);
    CHECK_RESULT(result, "ProcessNativeLibrary failed %{public}d");

    if (newInfo.IsPreInstallApp()) {
        // preInstallApp does not need to copy hsp
        newInfo.SetModuleHapPath(bundlePath);
    } else {
        // save hsp and so files to installation dir
        std::string realHspPath = moduleDir + ServiceConstants::PATH_SEPARATOR + moduleName +
            ServiceConstants::HSP_FILE_SUFFIX;
        result = SaveHspToRealInstallationDir(bundlePath, moduleDir, moduleName, realHspPath);
        CHECK_RESULT(result, "save hsp file failed %{public}d");
        newInfo.SetModuleHapPath(realHspPath);
    }
    if (newInfo.IsCompressNativeLibs(moduleName)) {
        // move so to real path
        result = MoveSoToRealPath(moduleName, versionDir);
        CHECK_RESULT(result, "move so to real path failed %{public}d");
    }
    newInfo.AddModuleSrcDir(moduleDir);
    newInfo.AddModuleResPath(moduleDir);
    newInfo.UpdateSharedModuleInfo();
    return ERR_OK;
}

void InnerSharedBundleInstaller::UpdateInnerModuleInfo(const std::string packageName,
    const InnerModuleInfo &innerModuleInfo)
{
    newBundleInfo_.ReplaceInnerModuleInfo(packageName, innerModuleInfo);
    std::string moduleDir = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName_ +
        ServiceConstants::PATH_SEPARATOR + HSP_VERSION_PREFIX + std::to_string(innerModuleInfo.versionCode) +
        ServiceConstants::PATH_SEPARATOR + innerModuleInfo.moduleName;
    bool isDirExist = false;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(moduleDir, isDirExist);
    if (isDirExist) {
        newBundleInfo_.SetCurrentModulePackage(packageName);
        newBundleInfo_.AddModuleSrcDir(moduleDir);
        newBundleInfo_.AddModuleResPath(moduleDir);
    } else {
        APP_LOGW("update path failed %{public}s %{public}d", moduleDir.c_str(), result);
    }
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
            UpdateInnerModuleInfo(innerModuleInfo.modulePackage, innerModuleInfo);
        }
        // update version
        if (newBundleInfo_.GetBaseBundleInfo().versionCode < currentBundle.GetBaseBundleInfo().versionCode) {
            newBundleInfo_.UpdateBaseBundleInfo(currentBundle.GetBaseBundleInfo(), false);
            newBundleInfo_.UpdateBaseApplicationInfo(currentBundle.GetBaseApplicationInfo(), false);
            newBundleInfo_.UpdateReleaseType(currentBundle);
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
    if (!dataMgr->GetPreInstallBundleInfo(bundleName_, preInstallBundleInfo)) {
        preInstallBundleInfo.SetBundleName(bundleName_);
    }
    preInstallBundleInfo.SetVersionCode(newBundleInfo_.GetBaseBundleInfo().versionCode);
    for (const auto &item : parsedBundles_) {
        preInstallBundleInfo.AddBundlePath(item.first);
    }
#ifdef USE_PRE_BUNDLE_PROFILE
    preInstallBundleInfo.SetRemovable(installParam.removable);
#else
    preInstallBundleInfo.SetRemovable(newBundleInfo_.IsRemovable());
#endif
    auto applicationInfo = newBundleInfo_.GetBaseApplicationInfo();
    newBundleInfo_.AdaptMainLauncherResourceInfo(applicationInfo);
    preInstallBundleInfo.SetLabelId(applicationInfo.labelResource.id);
    preInstallBundleInfo.SetIconId(applicationInfo.iconResource.id);
    preInstallBundleInfo.SetModuleName(applicationInfo.labelResource.moduleName);
    preInstallBundleInfo.SetSystemApp(applicationInfo.isSystemApp);
    preInstallBundleInfo.SetBundleType(BundleType::SHARED);
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
        if (!dataMgr->UpdateInnerBundleInfo(newBundleInfo_, false)) {
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

void InnerSharedBundleInstaller::AddAppProvisionInfo(const std::string &bundleName,
    const Security::Verify::ProvisionInfo &provisionInfo) const
{
    AppProvisionInfo appProvisionInfo = bundleInstallChecker_->ConvertToAppProvisionInfo(provisionInfo);
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        bundleName, appProvisionInfo)) {
        APP_LOGW("bundleName: %{public}s add appProvisionInfo failed", bundleName.c_str());
    }
}

void InnerSharedBundleInstaller::SaveInstallParamInfo(
    const std::string &bundleName, const InstallParam &installParam) const
{
    if (!installParam.specifiedDistributionType.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetSpecifiedDistributionType(
            bundleName, installParam.specifiedDistributionType)) {
            APP_LOGW("bundleName: %{public}s SetSpecifiedDistributionType failed", bundleName.c_str());
        }
    }
    if (!installParam.additionalInfo.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetAdditionalInfo(
            bundleName, installParam.additionalInfo)) {
            APP_LOGW("bundleName: %{public}s SetAdditionalInfo failed", bundleName.c_str());
        }
    }
}

ErrCode InnerSharedBundleInstaller::CopyHspToSecurityDir(std::vector<std::string> &bundlePaths)
{
    for (size_t index = 0; index < bundlePaths.size(); ++index) {
        auto destination = BundleUtil::CopyFileToSecurityDir(bundlePaths[index], DirType::STREAM_INSTALL_DIR,
            toDeleteTempHspPath_);
        if (destination.empty()) {
            APP_LOGE("copy file %{public}s to security dir failed", bundlePaths[index].c_str());
            return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
        }
        bundlePaths[index] = destination;
    }
    return ERR_OK;
}

ErrCode InnerSharedBundleInstaller::ObtainHspFileAndSignatureFilePath(const std::vector<std::string> &inBundlePaths,
    std::vector<std::string> &bundlePaths, std::string &signatureFilePath)
{
    if (inBundlePaths.empty() || inBundlePaths.size() > MAX_FILE_NUMBER) {
        APP_LOGE("number of files in single shared lib path is illegal");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    if (inBundlePaths.size() == 1) {
        if (!BundleUtil::EndWith(inBundlePaths[0], ServiceConstants::HSP_FILE_SUFFIX)) {
            APP_LOGE("invalid file in shared bundle dir");
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
        bundlePaths.emplace_back(inBundlePaths[0]);
        return ERR_OK;
    }
    int32_t numberOfHsp = 0;
    int32_t numberOfSignatureFile = 0;
    for (const auto &path : inBundlePaths) {
        if ((path.find(ServiceConstants::HSP_FILE_SUFFIX) == std::string::npos) &&
            (path.find(ServiceConstants::CODE_SIGNATURE_FILE_SUFFIX) == std::string::npos)) {
            APP_LOGE("only hsp or sig file can be contained in shared bundle dir");
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
        if (BundleUtil::EndWith(path, ServiceConstants::HSP_FILE_SUFFIX)) {
            numberOfHsp++;
            bundlePaths.emplace_back(path);
        }
        if (BundleUtil::EndWith(path, ServiceConstants::CODE_SIGNATURE_FILE_SUFFIX)) {
            numberOfSignatureFile++;
            signatureFilePath = path;
        }
        if ((numberOfHsp >= MAX_FILE_NUMBER) || (numberOfSignatureFile >= MAX_FILE_NUMBER)) {
            APP_LOGE("only one hsp and one signature file can be contained in a single shared bundle dir");
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
    }
    APP_LOGD("signatureFilePath is %{public}s", signatureFilePath.c_str());
    return ERR_OK;
}

ErrCode InnerSharedBundleInstaller::SaveHspToRealInstallationDir(const std::string &bundlePath,
    const std::string &moduleDir,
    const std::string &moduleName,
    const std::string &realHspPath)
{
    // 1. create temp dir
    ErrCode result = ERR_OK;
    std::string tempHspDir = moduleDir + ServiceConstants::PATH_SEPARATOR + moduleName;
    result = MkdirIfNotExist(tempHspDir);
    CHECK_RESULT(result, "create tempHspDir dir failed %{public}d");

    // 2. copy hsp to installation dir, and then to verify code signature of hsp
    std::string tempHspPath = tempHspDir + ServiceConstants::PATH_SEPARATOR + moduleName +
        ServiceConstants::HSP_FILE_SUFFIX;
    if (!signatureFileDir_.empty()) {
        result = InstalldClient::GetInstance()->CopyFile(bundlePath, tempHspPath, signatureFileDir_);
    } else {
        result = InstalldClient::GetInstance()->MoveHapToCodeDir(bundlePath, tempHspPath);
        CHECK_RESULT(result, "copy hsp to install dir failed %{public}d");
        bool isCompileSdkOpenHarmony = (compileSdkType_ == COMPILE_SDK_TYPE_OPEN_HARMONY);
        result = VerifyCodeSignatureForHsp(tempHspPath, appIdentifier_, isEnterpriseBundle_,
            isCompileSdkOpenHarmony, bundleName_);
    }
    CHECK_RESULT(result, "copy hsp to install dir failed %{public}d");

    // 3. move hsp to real installation dir
    APP_LOGD("move file from temp path %{public}s to real path %{public}s", tempHspPath.c_str(), realHspPath.c_str());
    result = InstalldClient::GetInstance()->MoveFile(tempHspPath, realHspPath);
    CHECK_RESULT(result, "move hsp to install dir failed %{public}d");

    // 4. remove temp dir
    result = InstalldClient::GetInstance()->RemoveDir(tempHspDir);
    if (result != ERR_OK) {
        APP_LOGW("remove temp hsp dir %{public}s failed, error is %{public}d", tempHspDir.c_str(), result);
    }
    return ERR_OK;
}

ErrCode InnerSharedBundleInstaller::MoveSoToRealPath(const std::string &moduleName, const std::string &versionDir)
{
    // 1. move so files to real installation dir
    std::string realSoPath = versionDir + ServiceConstants::PATH_SEPARATOR + nativeLibraryPath_ +
        ServiceConstants::PATH_SEPARATOR;
    ErrCode result = MkdirIfNotExist(realSoPath);
    CHECK_RESULT(result, "check module dir failed %{public}d");

    std::string tempNativeLibraryPath = ObtainTempSoPath(moduleName, nativeLibraryPath_);
    if (tempNativeLibraryPath.empty()) {
        APP_LOGI("no so libs existed");
        return ERR_OK;
    }
    std::string tempSoPath = versionDir + ServiceConstants::PATH_SEPARATOR + tempNativeLibraryPath;
    APP_LOGD("move so files from path %{public}s to path %{public}s", tempSoPath.c_str(), realSoPath.c_str());
    result = InstalldClient::GetInstance()->MoveFiles(tempSoPath, realSoPath);
    if (result != ERR_OK) {
        APP_LOGE("move file to real path failed %{public}d", result);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }

    // 2. remove so temp dir
    std::string deleteTempDir = versionDir + ServiceConstants::PATH_SEPARATOR + moduleName
        + ServiceConstants::TMP_SUFFIX;
    result = InstalldClient::GetInstance()->RemoveDir(deleteTempDir);
    if (result != ERR_OK) {
        APP_LOGW("remove hsp temp so dir %{public}s failed, error is %{public}d", deleteTempDir.c_str(), result);
    }
    return ERR_OK;
}

std::string InnerSharedBundleInstaller::ObtainTempSoPath(const std::string &moduleName,
    const std::string &nativeLibPath)
{
    std::string tempSoPath;
    if (nativeLibPath.empty()) {
        APP_LOGE("invalid native libs path");
        return tempSoPath;
    }
    tempSoPath = nativeLibPath;
    auto pos = tempSoPath.find(moduleName);
    if (pos == std::string::npos) {
        tempSoPath = moduleName + ServiceConstants::TMP_SUFFIX + ServiceConstants::PATH_SEPARATOR + tempSoPath;
    } else {
        std::string innerTempStr = moduleName + ServiceConstants::TMP_SUFFIX;
        tempSoPath.replace(pos, moduleName.length(), innerTempStr);
    }
    return tempSoPath + ServiceConstants::PATH_SEPARATOR;
}

ErrCode InnerSharedBundleInstaller::ProcessNativeLibrary(
    const std::string &bundlePath,
    const std::string &moduleDir,
    const std::string &moduleName,
    const std::string &versionDir,
    InnerBundleInfo &newInfo)
{
    std::string cpuAbi;
    if (!newInfo.FetchNativeSoAttrs(moduleName, cpuAbi, nativeLibraryPath_)) {
        return ERR_OK;
    }
    if (newInfo.IsCompressNativeLibs(moduleName)) {
        std::string tempNativeLibraryPath = ObtainTempSoPath(moduleName, nativeLibraryPath_);
        if (tempNativeLibraryPath.empty()) {
            APP_LOGE("tempNativeLibraryPath is empty");
            return ERR_APPEXECFWK_INSTALLD_EXTRACT_FILES_FAILED;
        }
        std::string tempSoPath = versionDir + ServiceConstants::PATH_SEPARATOR + tempNativeLibraryPath;
        APP_LOGD("tempSoPath=%{public}s,cpuAbi=%{public}s, bundlePath=%{public}s",
            tempSoPath.c_str(), cpuAbi.c_str(), bundlePath.c_str());
        auto result = InstalldClient::GetInstance()->ExtractModuleFiles(bundlePath, moduleDir, tempSoPath, cpuAbi);
        CHECK_RESULT(result, "extract module files failed %{public}d");
        // verify hap or hsp code signature for compressed so files
        result = VerifyCodeSignatureForNativeFiles(
            bundlePath, cpuAbi, tempSoPath, signatureFileDir_, newInfo.IsPreInstallApp());
        CHECK_RESULT(result, "fail to VerifyCodeSignature, error is %{public}d");
        cpuAbi_ = cpuAbi;
        tempSoPath_ = tempSoPath;
        isPreInstalledBundle_ = newInfo.IsPreInstallApp();
    } else {
        std::vector<std::string> fileNames;
        auto result = InstalldClient::GetInstance()->GetNativeLibraryFileNames(bundlePath, cpuAbi, fileNames);
        CHECK_RESULT(result, "fail to GetNativeLibraryFileNames, error is %{public}d");
        newInfo.SetNativeLibraryFileNames(moduleName, fileNames);
    }
    return ERR_OK;
}

ErrCode InnerSharedBundleInstaller::VerifyCodeSignatureForNativeFiles(const std::string &bundlePath,
    const std::string &cpuAbi, const std::string &targetSoPath, const std::string &signatureFileDir,
    bool isPreInstalledBundle) const
{
    if (!isPreInstalledBundle) {
        APP_LOGD("not pre-install app, skip verify code signature for native files");
        return ERR_OK;
    }
    APP_LOGD("begin to verify code signature for hsp native files");
    bool isCompileSdkOpenHarmony = (compileSdkType_ == COMPILE_SDK_TYPE_OPEN_HARMONY);
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = bundlePath;
    codeSignatureParam.cpuAbi = cpuAbi;
    codeSignatureParam.targetSoPath = targetSoPath;
    codeSignatureParam.signatureFileDir = signatureFileDir;
    codeSignatureParam.isEnterpriseBundle = isEnterpriseBundle_;
    codeSignatureParam.appIdentifier = appIdentifier_;
    codeSignatureParam.isCompileSdkOpenHarmony = isCompileSdkOpenHarmony;
    codeSignatureParam.isPreInstalledBundle = isPreInstalledBundle;
    return InstalldClient::GetInstance()->VerifyCodeSignature(codeSignatureParam);
}

ErrCode InnerSharedBundleInstaller::VerifyCodeSignatureForHsp(const std::string &tempHspPath,
    const std::string &appIdentifier, bool isEnterpriseBundle, bool isCompileSdkOpenHarmony,
    const std::string &bundleName) const
{
    APP_LOGD("begin to verify code signature for hsp");
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = tempHspPath;
    codeSignatureParam.cpuAbi = cpuAbi_;
    codeSignatureParam.targetSoPath = tempSoPath_;
    codeSignatureParam.appIdentifier = appIdentifier;
    codeSignatureParam.signatureFileDir = signatureFileDir_;
    codeSignatureParam.isEnterpriseBundle = isEnterpriseBundle;
    codeSignatureParam.isCompileSdkOpenHarmony = isCompileSdkOpenHarmony;
    codeSignatureParam.isPreInstalledBundle = isPreInstalledBundle_;
    return InstalldClient::GetInstance()->VerifyCodeSignatureForHap(codeSignatureParam);
}

ErrCode InnerSharedBundleInstaller::DeliveryProfileToCodeSign(
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults) const
{
    if (isBundleExist_) {
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

void InnerSharedBundleInstaller::SetCheckResultMsg(const std::string checkResultMsg) const
{
    bundleInstallChecker_->SetCheckResultMsg(checkResultMsg);
}

ErrCode InnerSharedBundleInstaller::MarkInstallFinish()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InnerBundleInfo info;
    if (!dataMgr->FetchInnerBundleInfo(bundleName_, info)) {
        APP_LOGE("mark finish failed, -n %{public}s not exist", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    info.SetInstallMark(bundleName_, info.GetCurModuleName(), InstallExceptionStatus::INSTALL_FINISH);
    if (!dataMgr->UpdateInnerBundleInfo(info, true)) {
        if (!dataMgr->UpdateInnerBundleInfo(info, true)) {
            APP_LOGE("save mark failed, -n %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
