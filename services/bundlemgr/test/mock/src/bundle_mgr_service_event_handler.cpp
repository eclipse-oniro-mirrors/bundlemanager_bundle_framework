/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "bundle_mgr_service_event_handler.h"

#include "account_helper.h"
#include "app_provision_info_manager.h"
#include "bundle_mgr_service.h"
#include "installd_client.h"
#include "user_unlocked_event_subscriber.h"
namespace OHOS {
namespace AppExecFwk {
const int32_t USERID = 100;
const std::string HSP_VERSION_PREFIX = "v";
BMSEventHandler::BMSEventHandler() {}

BMSEventHandler::~BMSEventHandler() {}

void BMSEventHandler::BmsStartEvent()
{
    BeforeBmsStart();
    OnBmsStarting();
    AfterBmsStart();
}

void BMSEventHandler::BeforeBmsStart()
{
    needNotifyBundleScanStatus_ = false;
}

void BMSEventHandler::OnBmsStarting()
{
    if (LoadInstallInfosFromDb()) {
        BundleRebootStartEvent();
        return;
    }

    if (!LoadAllPreInstallBundleInfos()) {
        needRebootOta_ = true;
    }
    ResultCode resultCode = GuardAgainstInstallInfosLossedStrategy();
    switch (resultCode) {
        case ResultCode::RECOVER_OK: {
            if (needRebootOta_) {
                BundleRebootStartEvent();
            } else {
                needNotifyBundleScanStatus_ = true;
            }

            break;
        }
        case ResultCode::REINSTALL_OK: {
            needNotifyBundleScanStatus_ = true;
            break;
        }
        case ResultCode::NO_INSTALLED_DATA: {
            BundleBootStartEvent();
            break;
        }
        default:
            break;
    }

    SaveSystemFingerprint();
}

void BMSEventHandler::AfterBmsStart()
{
    SetAllInstallFlag();
    HandleSceneBoard();
    ClearCache();
    ListeningUserUnlocked();
    RemoveUnreservedSandbox();
}

void BMSEventHandler::ClearCache()
{
    hapParseInfoMap_.clear();
    loadExistData_.clear();
    hasLoadAllPreInstallBundleInfosFromDb_ = false;
}

bool BMSEventHandler::LoadInstallInfosFromDb()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }

    return dataMgr->LoadDataFromPersistentStorage();
}

void BMSEventHandler::BundleBootStartEvent() {}

void BMSEventHandler::BundleRebootStartEvent()
{
#ifdef USE_PRE_BUNDLE_PROFILE
    if (LoadPreInstallProFile()) {
        UpdateAllPrivilegeCapability();
    }
#endif

    if (IsSystemUpgrade()) {
        OnBundleRebootStart();
        SaveSystemFingerprint();
    } else {
        HandlePreInstallException();
        CheckALLResourceInfo();
    }

    needNotifyBundleScanStatus_ = true;
}

ResultCode BMSEventHandler::GuardAgainstInstallInfosLossedStrategy()
{
    std::map<std::string, std::vector<InnerBundleUserInfo>> innerBundleUserInfoMaps;
    ScanResultCode scanResultCode = ScanAndAnalyzeUserDatas(innerBundleUserInfoMaps);
    if (scanResultCode == ScanResultCode::SCAN_NO_DATA) {
        return ResultCode::NO_INSTALLED_DATA;
    }

    if (scanResultCode == ScanResultCode::SCAN_HAS_DATA_PARSE_FAILED) {
        return ReInstallAllInstallDirApps();
    }

    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    ScanAndAnalyzeInstallInfos(installInfos);
    if (installInfos.empty()) {
        return ResultCode::SYSTEM_ERROR;
    }

    if (!CombineBundleInfoAndUserInfo(installInfos, innerBundleUserInfoMaps)) {
        return ResultCode::SYSTEM_ERROR;
    }

    return ResultCode::RECOVER_OK;
}

ScanResultCode BMSEventHandler::ScanAndAnalyzeUserDatas(
    std::map<std::string, std::vector<InnerBundleUserInfo>>& userMaps)
{
    ScanResultCode scanResultCode = ScanResultCode::SCAN_NO_DATA;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return scanResultCode;
    }
    dataMgr->AddUserId(USERID);
    scanResultCode = ScanResultCode::SCAN_HAS_DATA_PARSE_SUCCESS;
    return scanResultCode;
}

bool BMSEventHandler::AnalyzeUserData(int32_t userId, const std::string& userDataDir,
    const std::string& userDataBundleName, std::map<std::string, std::vector<InnerBundleUserInfo>>& userMaps)
{
    return false;
}

ResultCode BMSEventHandler::ReInstallAllInstallDirApps()
{
    return ResultCode::REINSTALL_OK;
}

void BMSEventHandler::ScanAndAnalyzeInstallInfos(std::map<std::string, std::vector<InnerBundleInfo>>& installInfos)
{
    std::map<std::string, std::vector<std::string>> hapPathsMap;
    ScanInstallDir(hapPathsMap);
    AnalyzeHaps(false, hapPathsMap, installInfos);

    std::vector<std::string> preInstallDirs;
    GetPreInstallDir(preInstallDirs);
    AnalyzeHaps(true, preInstallDirs, installInfos);
}

void BMSEventHandler::ScanInstallDir(std::map<std::string, std::vector<std::string>>& hapPathsMap)
{
    std::vector<std::string> bundleNameList;
    if (!ScanDir(Constants::BUNDLE_CODE_DIR, ScanMode::SUB_FILE_DIR, ResultMode::RELATIVE_PATH, bundleNameList)) {
        return;
    }

    for (const auto& bundleName : bundleNameList) {
        std::vector<std::string> hapPaths;
        auto appCodePath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName;
        if (!ScanDir(appCodePath, ScanMode::SUB_FILE_FILE, ResultMode::ABSOLUTE_PATH, hapPaths)) {
            continue;
        }

        if (hapPaths.empty()) {
            continue;
        }

        std::vector<std::string> checkHapPaths = CheckHapPaths(hapPaths);
        hapPathsMap.emplace(bundleName, checkHapPaths);
    }
}

std::vector<std::string> BMSEventHandler::CheckHapPaths(const std::vector<std::string>& hapPaths)
{
    std::vector<std::string> checkHapPaths;
    return checkHapPaths;
}

void BMSEventHandler::GetPreInstallRootDirList(std::vector<std::string>& rootDirList) {}

void BMSEventHandler::ClearPreInstallCache() {}

bool BMSEventHandler::LoadPreInstallProFile()
{
    return true;
}

bool BMSEventHandler::HasPreInstallProfile()
{
    return true;
}

void BMSEventHandler::ParsePreBundleProFile(const std::string& dir) {}

void BMSEventHandler::GetPreInstallDir(std::vector<std::string>& bundleDirs) {}

void BMSEventHandler::GetPreInstallDirFromLoadProFile(std::vector<std::string>& bundleDirs) {}

void BMSEventHandler::GetPreInstallDirFromScan(std::vector<std::string>& bundleDirs) {}

void BMSEventHandler::AnalyzeHaps(bool isPreInstallApp,
    const std::map<std::string, std::vector<std::string>>& hapPathsMap,
    std::map<std::string, std::vector<InnerBundleInfo>>& installInfos)
{
    for (const auto& hapPaths : hapPathsMap) {
        AnalyzeHaps(isPreInstallApp, hapPaths.second, installInfos);
    }
}

void BMSEventHandler::AnalyzeHaps(bool isPreInstallApp, const std::vector<std::string>& bundleDirs,
    std::map<std::string, std::vector<InnerBundleInfo>>& installInfos)
{
    for (const auto& bundleDir : bundleDirs) {
        std::unordered_map<std::string, InnerBundleInfo> hapInfos;
        if (!CheckAndParseHapFiles(bundleDir, isPreInstallApp, hapInfos) || hapInfos.empty()) {
            continue;
        }

        CollectInstallInfos(hapInfos, installInfos);
    }
}

void BMSEventHandler::CollectInstallInfos(const std::unordered_map<std::string, InnerBundleInfo>& hapInfos,
    std::map<std::string, std::vector<InnerBundleInfo>>& installInfos)
{
    for (const auto& hapInfoIter : hapInfos) {
        auto bundleName = hapInfoIter.second.GetBundleName();
        if (installInfos.find(bundleName) == installInfos.end()) {
            std::vector<InnerBundleInfo> innerBundleInfos { hapInfoIter.second };
            installInfos.emplace(bundleName, innerBundleInfos);
            continue;
        }

        installInfos.at(bundleName).emplace_back(hapInfoIter.second);
    }
}

bool BMSEventHandler::CombineBundleInfoAndUserInfo(
    const std::map<std::string, std::vector<InnerBundleInfo>>& installInfos,
    const std::map<std::string, std::vector<InnerBundleUserInfo>>& userInfoMaps)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }

    if (installInfos.empty() || userInfoMaps.empty()) {
        return false;
    }

    for (auto hasInstallInfo : installInfos) {
        auto bundleName = hasInstallInfo.first;
        auto userIter = userInfoMaps.find(bundleName);
        if (userIter == userInfoMaps.end()) {
            needRebootOta_ = true;
            continue;
        }

        for (auto& info : hasInstallInfo.second) {
            SaveInstallInfoToCache(info);
        }

        for (const auto& userInfo : userIter->second) {
            dataMgr->AddInnerBundleUserInfo(bundleName, userInfo);
        }
    }

    dataMgr->RestoreUidAndGid();
    dataMgr->LoadAllBundleStateDataFromJsonDb();
    return true;
}

void BMSEventHandler::SaveInstallInfoToCache(InnerBundleInfo& info)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }

    auto bundleName = info.GetBundleName();
    auto appCodePath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName;
    info.SetAppCodePath(appCodePath);

    std::string dataBaseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
                              ServiceConstants::DATABASE + bundleName;
    info.SetAppDataBaseDir(dataBaseDir);

    auto moduleDir = info.GetAppCodePath() + ServiceConstants::PATH_SEPARATOR + info.GetCurrentModulePackage();
    info.AddModuleSrcDir(moduleDir);
    info.AddModuleResPath(moduleDir);

    bool bundleExist = false;
    InnerBundleInfo dbInfo;
    {
        auto& mtx = dataMgr->GetBundleMutex(bundleName);
        std::lock_guard lock { mtx };
        bundleExist = dataMgr->FetchInnerBundleInfo(bundleName, dbInfo);
    }

    if (!bundleExist) {
        dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
        dataMgr->AddInnerBundleInfo(bundleName, info);
        dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS);
        return;
    }

    auto& hapModuleName = info.GetCurModuleName();
    std::vector<std::string> dbModuleNames;
    dbInfo.GetModuleNames(dbModuleNames);
    auto iter = std::find(dbModuleNames.begin(), dbModuleNames.end(), hapModuleName);
    if (iter != dbModuleNames.end()) {
        return;
    }

    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UPDATING_START);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UPDATING_SUCCESS);
    dataMgr->AddNewModuleInfo(bundleName, info, dbInfo);
}

bool BMSEventHandler::ScanDir(
    const std::string& dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string>& resultList)
{
    ErrCode result = InstalldClient::GetInstance()->ScanDir(dir, scanMode, resultMode, resultList);
    if (result != ERR_OK) {
        return false;
    }

    return true;
}

void BMSEventHandler::OnBundleBootStart(int32_t userId) {}

void BMSEventHandler::ProcessBootBundleInstallFromScan(int32_t userId) {}

void BMSEventHandler::GetBundleDirFromScan(std::list<std::string>& bundleDirs) {}

void BMSEventHandler::ProcessScanDir(const std::string& dir, std::list<std::string>& bundleDirs) {}

void BMSEventHandler::InnerProcessBootSystemHspInstall() {}

void BMSEventHandler::ProcessSystemHspInstall(const PreScanInfo& preScanInfo) {}

void BMSEventHandler::InnerProcessBootPreBundleProFileInstall(int32_t userId) {}

void BMSEventHandler::AddTasks(
    const std::map<int32_t, std::vector<PreScanInfo>, std::greater<int32_t>>& taskMap, int32_t userId)
{}

void BMSEventHandler::AddTaskParallel(int32_t taskPriority, const std::vector<PreScanInfo>& tasks, int32_t userId) {}

void BMSEventHandler::ProcessSystemBundleInstall(
    const PreScanInfo& preScanInfo, Constants::AppType appType, int32_t userId)
{}

void BMSEventHandler::ProcessSystemBundleInstall(
    const std::string& bundleDir, Constants::AppType appType, int32_t userId)
{}

void BMSEventHandler::ProcessSystemSharedBundleInstall(const std::string& sharedBundlePath, Constants::AppType appType)
{}

void BMSEventHandler::SetAllInstallFlag() const {}

void BMSEventHandler::OnBundleRebootStart() {}

void BMSEventHandler::ProcessRebootBundle() {}

bool BMSEventHandler::CheckOtaFlag(OTAFlag flag, bool& result)
{
    return true;
}

bool BMSEventHandler::UpdateOtaFlag(OTAFlag flag)
{
    return true;
}

void BMSEventHandler::ProcessCheckAppDataDir() {}

void BMSEventHandler::InnerProcessCheckAppDataDir() {}

void BMSEventHandler::ProcessCheckPreinstallData() {}

void BMSEventHandler::InnerProcessCheckPreinstallData() {}

void BMSEventHandler::ProcessCheckAppLogDir() {}

void BMSEventHandler::InnerProcessCheckAppLogDir() {}

void BMSEventHandler::ProcessCheckAppFileManagerDir() {}

void BMSEventHandler::InnerProcessCheckAppFileManagerDir() {}

void BMSEventHandler::ProcessCheckShaderCacheDir() {}

void BMSEventHandler::InnerProcessCheckShaderCacheDir() {}

void BMSEventHandler::ProcessCheckCloudShaderDir() {}

void BMSEventHandler::InnerProcessCheckCloudShaderDir() {}

void BMSEventHandler::ProcessNewBackupDir() {}

bool BMSEventHandler::LoadAllPreInstallBundleInfos()
{
    if (hasLoadAllPreInstallBundleInfosFromDb_) {
        return true;
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }

    std::vector<PreInstallBundleInfo> preInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    for (auto const & iter : preInstallBundleInfos) {
    }

    hasLoadAllPreInstallBundleInfosFromDb_ = true;
    return !preInstallBundleInfos.empty();
}

void BMSEventHandler::ProcessRebootBundleInstall() {}

void BMSEventHandler::ProcessReBootPreBundleProFileInstall() {}

void BMSEventHandler::ProcessRebootBundleInstallFromScan() {}

void BMSEventHandler::InnerProcessRebootBundleInstall(
    const std::list<std::string>& scanPathList, Constants::AppType appType)
{}

bool BMSEventHandler::UpdateModuleByHash(const BundleInfo& oldBundleInfo, const InnerBundleInfo& newInfo) const
{
    return true;
}

void BMSEventHandler::InnerProcessRebootSharedBundleInstall(
    const std::list<std::string>& scanPathList, Constants::AppType appType)
{}

void BMSEventHandler::InnerProcessRebootSystemHspInstall(const std::list<std::string>& scanPathList) {}

ErrCode BMSEventHandler::OTAInstallSystemHsp(const std::vector<std::string>& filePaths)
{
    return ERR_OK;
}

bool BMSEventHandler::IsNeedToUpdateSharedHspByHash(
    const InnerBundleInfo& oldInfo, const InnerBundleInfo& newInfo) const
{
    return true;
}

bool BMSEventHandler::IsNeedToUpdateSharedAppByHash(
    const InnerBundleInfo& oldInfo, const InnerBundleInfo& newInfo) const
{
    return true;
}

void BMSEventHandler::SaveSystemFingerprint() {}

bool BMSEventHandler::IsSystemUpgrade()
{
    return true;
}

bool BMSEventHandler::IsTestSystemUpgrade()
{
    return true;
}

bool BMSEventHandler::IsSystemFingerprintChanged()
{
    return true;
}

std::string BMSEventHandler::GetCurSystemFingerprint()
{
    return "";
}

bool BMSEventHandler::GetSystemParameter(const std::string& key, std::string& value)
{
    return true;
}

std::string BMSEventHandler::GetOldSystemFingerprint()
{
    return "";
}

void BMSEventHandler::AddParseInfosToMap(
    const std::string& bundleName, const std::unordered_map<std::string, InnerBundleInfo>& infos)
{}

void BMSEventHandler::ProcessRebootBundleUninstall() {}

bool BMSEventHandler::InnerProcessUninstallModule(
    const BundleInfo& bundleInfo, const std::unordered_map<std::string, InnerBundleInfo>& infos, bool &isDowngrade)
{
    return true;
}

void BMSEventHandler::DeletePreInfoInDb(const std::string& bundleName, const std::string& bundlePath, bool bundleLevel)
{}

bool BMSEventHandler::HasModuleSavedInPreInstalledDb(const std::string& bundleName, const std::string& bundlePath)
{
    return true;
}

void BMSEventHandler::SavePreInstallException(const std::string& bundleDir) {}

void BMSEventHandler::HandlePreInstallException() {}

bool BMSEventHandler::OTAInstallSystemBundle(
    const std::vector<std::string>& filePaths, Constants::AppType appType, bool removable)
{
    return true;
}

bool BMSEventHandler::OTAInstallSystemBundleNeedCheckUser(const std::vector<std::string>& filePaths,
    const std::string& bundleName, Constants::AppType appType, bool removable)
{
    return true;
}

bool BMSEventHandler::OTAInstallSystemSharedBundle(
    const std::vector<std::string>& filePaths, Constants::AppType appType, bool removable)
{
    return true;
}

bool BMSEventHandler::CheckAndParseHapFiles(
    const std::string& hapFilePath, bool isPreInstallApp, std::unordered_map<std::string, InnerBundleInfo>& infos)
{
    return true;
}

bool BMSEventHandler::ParseHapFiles(
    const std::string& hapFilePath, std::unordered_map<std::string, InnerBundleInfo>& infos)
{
    return true;
}

bool BMSEventHandler::IsPreInstallRemovable(const std::string& path)
{
    return true;
}

bool BMSEventHandler::GetPreInstallCapability(PreBundleConfigInfo& preBundleConfigInfo)
{
    return true;
}

bool BMSEventHandler::CheckExtensionTypeInConfig(const std::string& typeName)
{
    return true;
}

#ifdef USE_PRE_BUNDLE_PROFILE
void BMSEventHandler::UpdateRemovable(const std::string& bundleName, bool removable) {}

void BMSEventHandler::UpdateAllPrivilegeCapability() {}

void BMSEventHandler::UpdatePrivilegeCapability(const PreBundleConfigInfo& preBundleConfigInfo) {}

bool BMSEventHandler::MatchSignature(const PreBundleConfigInfo& configInfo, const std::string& signature)
{
    return true;
}

bool BMSEventHandler::MatchOldSignatures(
    const PreBundleConfigInfo& configInfo, const std::vector<std::string>& oldSignatures)
{
    return true;
}

void BMSEventHandler::UpdateTrustedPrivilegeCapability(const PreBundleConfigInfo& preBundleConfigInfo) {}
#endif

bool BMSEventHandler::FetchInnerBundleInfo(const std::string& bundleName, InnerBundleInfo& innerBundleInfo)
{
    return true;
}

void BMSEventHandler::ListeningUserUnlocked() const
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
    }
}

void BMSEventHandler::RemoveUnreservedSandbox() const {}

void BMSEventHandler::AddStockAppProvisionInfoByOTA(const std::string& bundleName, const std::string& filePath)
{
    Security::Verify::HapVerifyResult hapVerifyResult;
    auto ret = BundleVerifyMgr::ParseHapProfile(filePath, hapVerifyResult);
    if (ret != ERR_OK) {
        return;
    }

    std::unique_ptr<BundleInstallChecker> bundleInstallChecker = std::make_unique<BundleInstallChecker>();
    AppProvisionInfo appProvisionInfo =
        bundleInstallChecker->ConvertToAppProvisionInfo(hapVerifyResult.GetProvisionInfo());
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName, appProvisionInfo)) {
    }
}

void BMSEventHandler::UpdateAppDataSelinuxLabel(
    const std::string& bundleName, const std::string& apl, bool isPreInstall, bool debug)
{}

void BMSEventHandler::HandleSceneBoard() const {}

void BMSEventHandler::InnerProcessStockBundleProvisionInfo() {}

void BMSEventHandler::ProcessBundleProvisionInfo(const std::unordered_set<std::string>& allBundleNames)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    std::vector<BundleInfo> bundleInfos;
    if (dataMgr->GetBundleInfosV9(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE),
        bundleInfos, Constants::ALL_USERID) != ERR_OK) {
        return;
    }
    for (const auto& bundleInfo : bundleInfos) {
        if ((allBundleNames.find(bundleInfo.name) == allBundleNames.end()) && !bundleInfo.hapModuleInfos.empty()) {
            AddStockAppProvisionInfoByOTA(bundleInfo.name, bundleInfo.hapModuleInfos[0].hapPath);
        }
    }
}

void BMSEventHandler::ProcessSharedBundleProvisionInfo(const std::unordered_set<std::string>& allBundleNames)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    std::vector<SharedBundleInfo> shareBundleInfos;
    if (dataMgr->GetAllSharedBundleInfo(shareBundleInfos) != ERR_OK) {
        return;
    }
    for (const auto& sharedBundleInfo : shareBundleInfos) {
        if ((allBundleNames.find(sharedBundleInfo.name) == allBundleNames.end()) &&
            !sharedBundleInfo.sharedModuleInfos.empty()) {
            std::string hspPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
                                  sharedBundleInfo.name + ServiceConstants::PATH_SEPARATOR + HSP_VERSION_PREFIX +
                                  std::to_string(sharedBundleInfo.sharedModuleInfos[0].versionCode) +
                                  ServiceConstants::PATH_SEPARATOR + sharedBundleInfo.sharedModuleInfos[0].name +
                                  ServiceConstants::PATH_SEPARATOR + sharedBundleInfo.sharedModuleInfos[0].name +
                                  ServiceConstants::HSP_FILE_SUFFIX;
            AddStockAppProvisionInfoByOTA(sharedBundleInfo.name, hspPath);
        }
    }
}

void BMSEventHandler::ProcessRebootQuickFixBundleInstall(const std::string& path, bool isOta) {}

void BMSEventHandler::CheckALLResourceInfo() {}

void BMSEventHandler::ProcessBundleResourceInfo() {}

bool BMSEventHandler::IsHapPathExist(const BundleInfo &bundleInfo)
{
    return true;
}

bool BMSEventHandler::IsHspPathExist(const InnerBundleInfo &innerBundleInfo)
{
    return true;
}

void BMSEventHandler::SendBundleUpdateFailedEvent(const BundleInfo& bundleInfo) {}

bool BMSEventHandler::IsQuickfixFlagExsit(const BundleInfo& bundleInfo)
{
    return true;
}

bool BMSEventHandler::GetValueFromJson(nlohmann::json& jsonObject)
{
    return true;
}

void BMSEventHandler::ProcessRebootQuickFixUnInstallAndRecover(const std::string& path) {}

void BMSEventHandler::UpdatePreinstallDBForNotUpdatedBundle(
    const std::string& bundleName, const std::unordered_map<std::string, InnerBundleInfo>& innerBundleInfos)
{}

bool BMSEventHandler::InnerProcessUninstallForExistPreBundle(const BundleInfo &installedInfo)
{
    return false;
}
} // namespace AppExecFwk
} // namespace OHOS
