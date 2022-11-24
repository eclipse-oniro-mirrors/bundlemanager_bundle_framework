/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_MGR_SERVICE_EVENT_HANDLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_MGR_SERVICE_EVENT_HANDLER_H

#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "event_handler.h"
#include "pre_scan_info.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrService;
enum class ScanMode;
enum class ResultMode;

enum class ResultCode {
    RECOVER_OK = 0,
    REINSTALL_OK,
    NO_INSTALLED_DATA,
    SYSTEM_ERROR,
};

enum class ScanResultCode {
    SCAN_HAS_DATA_PARSE_SUCCESS,
    SCAN_HAS_DATA_PARSE_FAILED,
    SCAN_NO_DATA,
};

class BMSEventHandler : public EventHandler {
public:
    explicit BMSEventHandler(const std::shared_ptr<EventRunner> &runner);
    virtual ~BMSEventHandler() override;
    /**
     * @brief Process the event of install system bundles.
     * @param event Indicates the event to be processed.
     * @return
     */
    virtual void ProcessEvent(const InnerEvent::Pointer &event) override;

    /**
     * @brief Get preInstall root dir list,
     *        which the catalog of production has higher priority.
     * @param rootDirList Indicates the root dir list.
     * @return
     */
    static void GetPreInstallRootDirList(std::vector<std::string> &rootDirList);
    /**
     * @brief Load all preInstall infos from proFile.
     * @return Returns true if get the preInstall list successfully; returns false otherwise.
     */
    static bool LoadPreInstallProFile();
    /**
     * @brief Clear all preInstall infos cache.
     * @return
     */
    static void ClearPreInstallCache();
    /**
     * @brief Get the preInstall capability.
     * @param preBundleConfigInfo Indicates the preBundleConfigInfo.
     * @return Returns true if get the preInstall capability successfully; returns false otherwise.
     */
    static bool GetPreInstallCapability(PreBundleConfigInfo &preBundleConfigInfo);
    /**
     * @brief Has preInstall profile or not.
     * @return Returns result.
     */
    static bool HasPreInstallProfile();

    enum {
        BMS_START = 0,
    };

private:
    /**
     * @brief Bms start event.
     * @return
     */
    void BmsStartEvent();
    /**
     * @brief Before Bms start.
     * @return
     */
    void BeforeBmsStart();
    /**
     * @brief On Bms starting.
     * @return
     */
    void OnBmsStarting();
    /**
     * @brief After Bms start.
     * @return
     */
    void AfterBmsStart();
    /**
     * @brief Load install infos from db.
     * @return Returns true if load successfully; returns false otherwise.
     */
    bool LoadInstallInfosFromDb();
    /**
     * @brief Guard against install infos lossed strategy.
     * @return Returns ResultCode for recover install infos.
     */
    ResultCode GuardAgainstInstallInfosLossedStrategy();
    /**
     * @brief Scan and analyze install infos.
     * @param installInfos Indicates the install infos.
     * @return
     */
    void ScanAndAnalyzeInstallInfos(
        std::map<std::string, std::vector<InnerBundleInfo>> &installInfos);
    /**
     * @brief Scan and analyze common install dir.
     * @param installInfos Indicates the install infos.
     * @return
     */
    void ScanInstallDir(
        std::map<std::string, std::vector<std::string>> &hapPathsMap);
    /**
     * @brief Get preInstall haps.
     * @param bundleDirs Indicates preInstall hapPath.
     * @return
     */
    void GetPreInstallDir(std::vector<std::string> &bundleDirs);
    /**
     * @brief Analyze hap to InnerBundleInfo.
     * @param isPreInstallApp Indicates is preInstallApp or not.
     * @param hapPathsMap Indicates the hapPathsMap which will be analyzed.
     * @param installInfos Indicates the install infos.
     * @return
     */
    void AnalyzeHaps(
        bool isPreInstallApp,
        const std::map<std::string, std::vector<std::string>> &hapPathsMap,
        std::map<std::string, std::vector<InnerBundleInfo>> &installInfos);
    /**
     * @brief Analyze hap to InnerBundleInfo.
     * @param isPreInstallApp Indicates is preInstallApp or not.
     * @param bundleDirs Indicates the bundleDirs which will be analyzed.
     * @param installInfos Indicates the install infos.
     * @return
     */
    void AnalyzeHaps(
        bool isPreInstallApp,
        const std::vector<std::string> &bundleDirs,
        std::map<std::string, std::vector<InnerBundleInfo>> &installInfos);
    /**
     * @brief Get preBundle install dir.
     * @param bundleDirs Indicates the bundleDirs.
     * @return
     */
    void GetPreBundleDir(std::list<std::string> &bundleDirs);
    /**
     * @brief Check scaned hapPath whether end with .hap.
     * @param hapPaths Indicates the hapPaths.
     * @return Returns the checked hapPaths.
     */
    std::vector<std::string> CheckHapPaths(const std::vector<std::string> &hapPaths);
    /**
     * @brief Collect install infos from parse result.
     * @param hapInfos Indicates the parse result.
     * @param installInfos Indicates the saved installInfos.
     * @return.
     */
    void CollectInstallInfos(
        const std::unordered_map<std::string, InnerBundleInfo> &hapInfos,
        std::map<std::string, std::vector<InnerBundleInfo>> &installInfos);
    /**
     * @brief Scan and analyze userDatas.
     * @param userMaps Indicates the userMaps to save userInfo.
     * @return Returns ScanResultCode if Scan and analyze infos successfully; returns false otherwise.
     */
    ScanResultCode ScanAndAnalyzeUserDatas(
        std::map<std::string, std::vector<InnerBundleUserInfo>> &userMaps);
    /**
     * @brief Analyze userDatas.
     * @param userId Indicates the userId.
     * @param userDataDir Indicates the userDataDir.
     * @param userDataBundleName Indicates the userDataBundleName.
     * @param userMaps Indicates the userMaps to save userInfo.
     * @return Returns true if analyze infos successfully; returns false otherwise.
     */
    bool AnalyzeUserData(
        int32_t userId, const std::string &userDataDir, const std::string &userDataBundleName,
        std::map<std::string, std::vector<InnerBundleUserInfo>> &userMaps);
    /**
     * @brief ReInstall all Apps from installDir.
     * @return Returns the ResultCode indicates the result of this action.
     */
    ResultCode ReInstallAllInstallDirApps();
    /**
     * @brief Combine install infos and userInfos.
     * @param installInfos Indicates the installInfos.
     * @param userInfoMaps Indicates the userInfoMaps.
     * @return Returns true if combine infos successfully; returns false otherwise.
     */
    bool CombineBundleInfoAndUserInfo(
        const std::map<std::string, std::vector<InnerBundleInfo>> &installInfos,
        const std::map<std::string, std::vector<InnerBundleUserInfo>> &userInfoMaps);
    /**
     * @brief Save recover info to cache.
     * @param info Indicates the InnerBundleInfo.
     * @return
     */
    void SaveInstallInfoToCache(InnerBundleInfo &info);
    /**
     * @brief Scan dir by scanMode and resultMode, this function will perform
     *        scan through installd because installd has higher permissions.
     * @param scanMode Indicates the scanMode,
     *        which maybe SUB_FILE_ALL SUB_FILE_DIR or SUB_FILE_FILE.
     * @param resultMode Indicates the resultMode,
     *        which maybe ABSOLUTE_PATH or RELATIVE_PATH.
     * @param resultList Indicates the scan resultList.
     * @return Returns true if Scan successfully; returns false otherwise.
     */
    bool ScanDir(const std::string& dir, ScanMode scanMode,
        ResultMode resultMode, std::vector<std::string> &resultList);
    /**
     * @brief Bundle boot start event.
     * @return
     */
    void BundleBootStartEvent();
    /**
     * @brief Bundle reboot start event.
     * @return
     */
    void BundleRebootStartEvent();
    /**
     * @brief start boot scan.
     * @param userId Indicates the userId.
     * @return
     */
    void OnBundleBootStart(int32_t userId = Constants::UNSPECIFIED_USERID);
    /**
     * @brief Process boot bundle install from scan.
     * @param userId Indicates the userId.
     * @return
     */
    void ProcessBootBundleInstallFromScan(int32_t userId);
    /**
     * @brief Process bundle install by scanInfos.
     * @param userId Indicates the userId.
     * @return
     */
    void InnerProcessBootPreBundleProFileInstall(int32_t userId);
    /**
     * @brief Install bundles by scanDir.
     * @param scanDir Indicates the scanDir.
     * @param appType Indicates the bundle type.
     * @param userId Indicates userId.
     * @return
     */
    void ProcessSystemBundleInstall(
        const std::string &scanDir,
        Constants::AppType appType,
        int32_t userId = Constants::UNSPECIFIED_USERID);
    /**
     * @brief Install bundles by preScanInfo.
     * @param preScanInfo Indicates the preScanInfo.
     * @param appType Indicates the bundle type.
     * @param userId Indicates userId.
     * @return
     */
    void ProcessSystemBundleInstall(
        const PreScanInfo &preScanInfo,
        Constants::AppType appType,
        int32_t userId = Constants::UNSPECIFIED_USERID);
    /**
     * @brief start reboot scan.
     * @return
     */
    void OnBundleRebootStart();
    /**
     * @brief Process reboot bundle.
     * @return
     */
    void ProcessRebootBundle();
    /**
     * @brief Obtains the PreInstallBundleInfo objects.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool LoadAllPreInstallBundleInfos();
    /**
     * @brief Process reboot bundle install.
     * @return
     */
    void ProcessRebootBundleInstall();
    /**
     * @brief Process reboot bundle install by scanInfos.
     * @return
     */
    void ProcessReBootPreBundleProFileInstall();
    /**
     * @brief Process reboot bundle install from scan.
     * @return
     */
    void ProcessRebootBundleInstallFromScan();
    /**
     * @brief Process reboot install bundles by bundleList.
     * @param bundleList Indicates store bundle list.
     * @param appType Indicates the bundle type.
     * @return
     */
    void InnerProcessRebootBundleInstall(
        const std::list<std::string> &bundleList, Constants::AppType appType);
    /**
     * @brief Reboot uninstall system and system vendor bundles.
     * @return
     */
    void ProcessRebootBundleUninstall();
    /**
     * @brief Get bundle dir by scan.
     * @param bundleDirs Indicates the return bundleDirs.
     * @return
     */
    void GetBundleDirFromScan(std::list<std::string> &bundleDirs);
    /**
     * @brief Process scan dir.
     * @param dir Indicates the dir.
     * @param bundleDirs Indicates the return bundleDirs.
     * @return
     */
    void ProcessScanDir(const std::string &dir, std::list<std::string> &bundleDirs);
    /**
     * @brief Process parse pre bundle profile.
     * @param dir Indicates the dir.
     * @return
     */
    static void ParsePreBundleProFile(const std::string &dir);
    /**
     * @brief Set the flag indicates that all system and vendor applications installed.
     * @return
     */
    void SetAllInstallFlag() const;
    /**
     * @brief Check and parse hap.
     * @param hapFilePath Indicates the absolute file path of the HAP.
     * @param isPreInstallApp Indicates the hap is preInstallApp or not.
     * @param infos Indicates the obtained BundleInfo object.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    bool CheckAndParseHapFiles(const std::string &hapFilePath,
        bool isPreInstallApp, std::unordered_map<std::string, InnerBundleInfo> &infos);
    /**
     * @brief Parse hap.
     * @param hapFilePath Indicates the absolute file path of the HAP.
     * @param infos Indicates the obtained BundleInfo object.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    bool ParseHapFiles(
        const std::string &hapFilePath,
        std::unordered_map<std::string, InnerBundleInfo> &infos);
    /**
     * @brief OTA Install system app and system vendor bundles.
     * @param filePaths Indicates the filePaths.
     * @param appType Indicates the bundle type.
     * @param removable Indicates the bundle type.
     * @return Returns true if this function called successfully; returns false otherwise.
     */
    bool OTAInstallSystemBundle(
        const std::vector<std::string> &filePaths,
        Constants::AppType appType,
        bool removable);
    /**
     * @brief Used to determine whether the module has been installed. If the installation has
     *        been uninstalled, OTA install and upgrade will not be allowed.
     * @param bundleName Indicates the bundleName.
     * @param bundlePath Indicates the bundlePath.
     * @return Returns true if this function called successfully; returns false otherwise.
     */
    bool HasModuleSavedInPreInstalledDb(
        const std::string &bundleName, const std::string &bundlePath);
    /**
     * @brief Delete preInstallInfo to Db.
     * @param bundleName Indicates the bundleName.
     * @param bundlePath Indicates the bundlePath.
     */
    void DeletePreInfoInDb(
        const std::string &bundleName, const std::string &bundlePath, bool bundleLevel);
    /**
     * @brief Add parseInfos to map.
     * @param bundleName Indicates the bundleName.
     * @param infos Indicates the infos.
     */
    void AddParseInfosToMap(const std::string &bundleName,
        const std::unordered_map<std::string, InnerBundleInfo> &infos);
    /**
     * @brief Clear cache.
     */
    void ClearCache();
    /**
     * @brief Judge whether the preInstall app can be removable.
     * @param path Indicates the path.
     * @return Returns true if the preInstall is removable; returns false otherwise.
     */
    bool IsPreInstallRemovable(const std::string &path);
    /**
     * @brief Ota upgrade scenario, uninstall the hap application updated by the app hot patch and retain the data.
     * @param bundleName Indicates the bundleName.
     * @return Returns true if this function called successfully; returns false otherwise.
     */
    bool HotPatchAppProcessing(const std::string &bundleName);
    /**
     * @brief Save the current system version number to the bms database.
     */
    void SaveSystemVersion();
    /**
     * @brief Judge whether it is OTA upgradde.
     * @return Returns true if this function called successfully; returns false otherwise.
     */
    bool IsSystemUpgrade();
    /**
     * @brief Get current system version.
     * @param curSystemVersion Current system version.
     * @return Returns true if called successfully; returns false code otherwise.
     */
    bool GetCurSystemVersion(std::string &curSystemVersion);
    /**
     * @brief Get system version from db.
     * @param curSystemVersion Current system version.
     * @return Returns true if called successfully; returns false code otherwise.
     */
    bool GetOldSystemVersion(std::string &oldSystemVersion);
    /**
     * @brief Judge whether hot patch application.
     * @param bundleName Indicates the bundleName.
     * @return Returns true if called successfully; returns false code otherwise.
     */
    bool IsHotPatchApp(const std::string &bundleName);

    bool FetchInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &innerBundleInfo);

    void GetPreInstallDirFromLoadProFile(std::vector<std::string> &bundleDirs);
    void GetPreInstallDirFromScan(std::vector<std::string> &bundleDirs);
#ifdef USE_PRE_BUNDLE_PROFILE
    void UpdateRemovable(const std::string &bundleName, bool removable);
    void UpdateAllPrivilegeCapability();
    void UpdatePrivilegeCapability(const PreBundleConfigInfo &preBundleConfigInfo);
    bool MatchSignature(const PreBundleConfigInfo &configInfo, const std::string &signature);
    void UpdateTrustedPrivilegeCapability(const PreBundleConfigInfo &preBundleConfigInfo);
#endif

    // Used to save the information parsed by Hap in the scanned directory.
    std::map<std::string, std::unordered_map<std::string, InnerBundleInfo>> hapParseInfoMap_;
    // Used to save application information that already exists in the Db.
    std::map<std::string, PreInstallBundleInfo> loadExistData_;
    // Used to mark Whether trigger OTA check
    bool needRebootOta_ = false;
    // Used to notify bundle scan status
    bool needNotifyBundleScanStatus_ = false;

    bool hasLoadAllPreInstallBundleInfosFromDb_ = false;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_MGR_SERVICE_EVENT_HANDLER_H
