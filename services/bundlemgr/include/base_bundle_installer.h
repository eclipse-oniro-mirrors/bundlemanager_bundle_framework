/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BASE_BUNDLE_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BASE_BUNDLE_INSTALLER_H

#include <map>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <sys/stat.h>
#include "nocopyable.h"

#include "access_token.h"
#include "bundle_app_spawn_client.h"
#include "bundle_common_event_mgr.h"
#include "bundle_data_mgr.h"
#include "bundle_install_checker.h"
#include "event_report.h"
#include "install_param.h"
#include "installer_bundle_tmp_info.h"
#include "quick_fix/appqf_info.h"
#include "shared_bundle_installer.h"
#include "skills_installer/skills_package_info.h"

#ifdef APP_DOMAIN_VERIFY_ENABLED
#include "app_domain_verify_mgr_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
struct ArkStartupCache {
    BundleType bundleType;
    int32_t mode = (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    int32_t uid = 0;
    int32_t gid = 0;
    std::string bundleName;
    std::string cacheDir;
};
class BaseBundleInstaller {
public:
    BaseBundleInstaller();
    virtual ~BaseBundleInstaller();
    void SetCallingUid(int32_t callingUid);
    void SetCallingTokenId(const Security::AccessToken::AccessTokenID callerToken);

protected:
    bool otaInstall_ = false;
    enum class InstallerState : uint8_t {
        INSTALL_START,
        INSTALL_BUNDLE_CHECKED = 5,
        INSTALL_SYSCAP_CHECKED = 10,
        INSTALL_SIGNATURE_CHECKED = 15,
        INSTALL_PARSED = 20,
        INSTALL_HAP_HASH_PARAM_CHECKED = 25,
        INSTALL_OVERLAY_CHECKED = 30,
        INSTALL_VERSION_AND_BUNDLENAME_CHECKED = 35,
        INSTALL_NATIVE_SO_CHECKED = 40,
        INSTALL_PROXY_DATA_CHECKED = 45,
        INSTALL_REMOVE_SANDBOX_APP = 50,
        INSTALL_EXTRACTED = 60,
        INSTALL_INFO_SAVED = 80,
        INSTALL_RENAMED = 90,
        INSTALL_SUCCESS = 100,
        INSTALL_FAILED,
    };

    enum class NpapiPluginStatus : int32_t {
        STATUS_NOT_APPLICABLE = -1,
        STATUS_SUCCESS = 0,
        STATUS_EXTRACT_FAILED = 1,
        STATUS_REMOVE_FAILED = 2,
    };

    enum SingletonState {
        DEFAULT,
        SINGLETON_TO_NON = 1,
        NON_TO_SINGLETON = 2,
    };

    struct SharedBundleRollBackInfo {
        std::vector<std::string> newDirs; // record newly created directories, delete when rollback
        std::vector<std::string> newBundles; // record newly installed bundle, uninstall when rollback
        std::unordered_map<std::string, InnerBundleInfo> backupBundles; // record initial InnerBundleInfo
    };

    /**
     * @brief The main function for system and normal bundle install.
     * @param bundlePath Indicates the path for storing the HAP file of the application
     *                   to install or update.
     * @param installParam Indicates the install parameters.
     * @param appType Indicates the application type.
     * @return Returns ERR_OK if the application install successfully; returns error code otherwise.
     */
    ErrCode InstallBundle(
        const std::string &bundlePath, const InstallParam &installParam, const Constants::AppType appType);
    /**
     * @brief The main function for system and normal bundle install.
     * @param bundlePaths Indicates the paths for storing the HAP file sof the application
     *                   to install or update.
     * @param installParam Indicates the install parameters.
     * @param appType Indicates the application type.
     * @return Returns ERR_OK if the application install successfully; returns error code otherwise.
     */
    ErrCode InstallBundle(const std::vector<std::string> &bundlePaths, const InstallParam &installParam,
        const Constants::AppType appType);
    /**
     * @brief The main function for uninstall a bundle.
     * @param bundleName Indicates the bundle name of the application to uninstall.
     * @param installParam Indicates the uninstall parameters.
     * @return Returns ERR_OK if the application uninstall successfully; returns error code otherwise.
     */
    ErrCode UninstallBundle(const std::string &bundleName, const InstallParam &installParam);
    /**
     * @brief The main function for uninstall a module in a specific bundle.
     * @param bundleName Indicates the bundle name of the application to uninstall.
     * @param modulePackage Indicates the module package of the module to uninstall.
     * @param installParam Indicates the uninstall parameters.
     * @return Returns ERR_OK if the application uninstall successfully; returns error code otherwise.
     */
    ErrCode UninstallBundle(
        const std::string &bundleName, const std::string &modulePackage, const InstallParam &installParam);
    /**
     * @brief The main function for uninstall a bundle by uninstallParam.
     * @param uninstallParam Indicates the input of uninstallParam.
     * @return Returns ERR_OK if the application uninstall successfully; returns error code otherwise.
     */
    ErrCode CheckUninstallInnerBundleInfo(const InnerBundleInfo &info, const std::string &bundleName);
    ErrCode UninstallBundleByUninstallParam(const UninstallParam &uninstallParam);
    /**
     * @brief Update the installer state.
     * @attention This function changes the base class state only.
     * @param state Indicates the state to be updated to.
     * @return
     */
    virtual void UpdateInstallerState(const InstallerState state);
    /**
     * @brief Get the installer state.
     * @return The current state of the installer object.
     */
    inline InstallerState GetInstallerState()
    {
        return state_;
    }
    /**
     * @brief Get the installer state.
     * @param state Indicates the state to be updated to.
     * @return
     */
    inline void SetInstallerState(InstallerState state)
    {
        state_ = state;
    }

    std::string GetCurrentBundleName() const
    {
        return bundleName_;
    }
    /**
     * @brief The main function for bundle install by bundleName.
     * @param bundleName Indicates the bundleName of the application to install.
     * @param installParam Indicates the install parameters.
     * @return Returns ERR_OK if the application install successfully; returns error code otherwise.
     */
    ErrCode Recover(const std::string &bundleName, const InstallParam &installParam);
    /**
     * @brief The main function for bundle install by bundleName.
     * @param bundleName Indicates the bundleName of the application to install.
     * @param installParam Indicates the install parameters.
     * @return Returns ERR_OK if the application install successfully; returns error code otherwise.
     */
    ErrCode InstallBundleByBundleName(const std::string &bundleName, const InstallParam &installParam);
    /**
     * @brief Reset install properties.
     */
    void ResetInstallProperties();
    /**
     * @brief Reset install properties.
     * @param isBootScene Indicates the event occurs in the boot phase.
     */
    void MarkPreBundleSyeEventBootTag(bool isBootScene)
    {
        sysEventInfo_.preBundleScene =
            isBootScene ? InstallScene::BOOT : InstallScene::REBOOT;
    }

    bool NotifyAllBundleStatus();

    std::string GetCheckResultMsg() const;

    void SetCheckResultMsg(const std::string checkResultMsg) const;

    void SetVerifyPermissionResult(const Security::AccessToken::HapInfoCheckResult &checkResult);

    ErrCode RollbackHmpUserInfo(const std::string &bundleName);

    ErrCode RollbackHmpCommonInfo(const std::string &bundleName);

    bool IsDriverForAllUser(const std::string &bundleName);

    int32_t GetDriverInstallUser(const std::string &bundleName);

    bool IsEnterpriseForAllUser(const InstallParam &installParam, const std::string &bundleName);

private:
    // Delete the (bundleName, userId) preference row when the main app is uninstalled.
    // No-op when AppClonePreferenceDataMgr is unavailable (e.g. test env); logs the skip.
    void RemoveAppClonePreference(const std::string &bundleName, int32_t userId);
    /**
     * @brief The real procedure for system and normal bundle install.
     * @param bundlePath Indicates the path for storing the HAP file of the application
     *                   to install or update.
     * @param installParam Indicates the install parameters.
     * @param appType Indicates the application type.
     * @param uid Indicates the uid of the application.
     * @param isRecover Indicates whether this is a recovery scenario.
     * @return Returns ERR_OK if the bundle install successfully; returns error code otherwise.
     */
    ErrCode ProcessBundleInstall(const std::vector<std::string> &bundlePaths, const InstallParam &installParam,
        const Constants::AppType appType, int32_t &uid, bool isRecover = false);

    ErrCode InnerProcessBundleInstall(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        InnerBundleInfo &oldInfo, const InstallParam &installParam, int32_t &uid);

    bool CheckIsDebugGrant(const InstallParam &installParam, const std::string &appProvisionType);

    /**
     * @brief The real procedure function for uninstall a bundle.
     * @param bundleName Indicates the bundle name of the application to uninstall.
     * @param installParam Indicates the uninstall parameters.
     * @param uid Indicates the uid of the application.
     * @return Returns ERR_OK if the bundle uninstall successfully; returns error code otherwise.
     */
    ErrCode ProcessBundleUninstall(const std::string &bundleName, const InstallParam &installParam, int32_t &uid);
    /**
     * @brief The real procedure for uninstall a module in a specific bundle.
     * @param bundleName Indicates the bundle name of the application to uninstall.
     * @param modulePackage Indicates the module package of the module to uninstall.
     * @param installParam Indicates the uninstall parameters.
     * @param uid Indicates the uid of the application.
     * @return Returns ERR_OK if the module uninstall successfully; returns error code otherwise.
     */
    ErrCode ProcessBundleUninstall(const std::string &bundleName, const std::string &modulePackage,
        const InstallParam &installParam, int32_t &uid);
    /**
     * @brief The process of installing a new bundle.
     * @param info Indicates the InnerBundleInfo parsed from the config.json in the HAP package.
     * @param uid Indicates the uid of the application.
     * @return Returns ERR_OK if the new bundle install successfully; returns error code otherwise.
     */
    ErrCode ProcessBundleInstallStatus(InnerBundleInfo &info, int32_t &uid, const bool isDebugGrant = false);
    /**
     * @brief The process of installing a native bundle.
     * @param info Indicates the InnerBundleInfo parsed from the config.json in the HAP package.
     * @param uid Indicates the uid of the application.
     * @return Returns ERR_OK if the native bundle install successfully; returns error code otherwise.
     */
    ErrCode ProcessBundleInstallNative(const InnerBundleInfo &info, int32_t userId, bool removeDir = true);
    ErrCode ProcessBundleInstallNative(const InnerBundleInfo &info, const std::unordered_set<int32_t> &userIds);
    /**
     * @brief The process of uninstalling a native bundle.
     * @param info Indicates the InnerBundleInfo parsed from the config.json in the HAP package.
     * @param uid Indicates the uid of the application.
     * @param bundleName Indicates the bundleName of the application.
     * @return Returns ERR_OK if the native bundle uninstall successfully; returns error code otherwise.
     */
    ErrCode ProcessBundleUnInstallNative(const InnerBundleInfo &info, int32_t userId, const std::string &bundleName,
        const std::string &moduleName = "");
    ErrCode ProcessBundleUnInstallNative(const InnerBundleInfo &info, const std::unordered_set<int32_t> &userIds,
        const std::string &bundleName, const std::string &moduleName = "");
    /**
     * @brief The process of updating an exist bundle.
     * @param oldInfo Indicates the exist InnerBundleInfo object get from the database.
     * @param newInfo Indicates the InnerBundleInfo object parsed from the config.json in the HAP package.
     * @param isReplace Indicates whether there is the replace flag in the install flag.
     * @return Returns ERR_OK if the bundle updating successfully; returns error code otherwise.
     */
    ErrCode ProcessBundleUpdateStatus(InnerBundleInfo &oldInfo,
        InnerBundleInfo &newInfo, bool isReplace, bool killProcess = true);
    /**
     * @brief Remove a whole bundle.
     * @param info Indicates the InnerBundleInfo object of a bundle.
     * @param isKeepData Indicates that whether to save data.
     * @return Returns ERR_OK if the bundle removed successfully; returns error code otherwise.
     */
    ErrCode RemoveBundle(InnerBundleInfo &info, const InstallParam &installParam, const bool async = false);
    /**
     * @brief Create the code and data directories of a bundle.
     * @param info Indicates the InnerBundleInfo object of a bundle.
     * @return Returns ERR_OK if the bundle directories created successfully; returns error code otherwise.
     */
    ErrCode CreateBundleAndDataDir(InnerBundleInfo &info) const;
    /**
     * @brief Extract the code to temporilay directory and rename it.
     * @param info Indicates the InnerBundleInfo object of a bundle.
     * @param modulePath normal files decompression path.
     * @return Returns ERR_OK if the bundle extract and renamed successfully; returns error code otherwise.
     */
    ErrCode ExtractModule(InnerBundleInfo &info, const std::string &modulePath);
    /**
     * @brief Remove the code and data directories of a bundle.
     * @param info Indicates the InnerBundleInfo object of a bundle.
     * @param isKeepData Indicates that whether to save data.
     * @return Returns ERR_OK if the bundle directories removed successfully; returns error code otherwise.
     */
    ErrCode RemoveBundleAndDataDir(const InnerBundleInfo &info, bool isKeepData, const bool async = false);
    /**
     * @brief Remove the code and data directories of a module in a bundle.
     * @param info Indicates the InnerBundleInfo object of a bundle.
     * @param modulePackage Indicates the module to be removed.
     * @param userId Indicates the userId.
     * @param isKeepData Indicates that whether to save data.
     * @return Returns ERR_OK if the bundle directories removed successfully; returns error code otherwise.
     */
    ErrCode RemoveModuleAndDataDir(const InnerBundleInfo &info,
        const std::string &modulePackage, int32_t userId, bool isKeepData) const;
    /**
     * @brief Remove the current installing module directory.
     * @param info Indicates the InnerBundleInfo object of a bundle under installing.
     * @param bundleName Indicates the bundleName of the application.
     * @return Returns ERR_OK if the module directory removed successfully; returns error code otherwise.
     */
    ErrCode RemoveModuleDir(const std::string &modulePath, const std::string &bundleName) const;
    /**
     * @brief Extract files of the current installing module package.
     * @param info Indicates the InnerBundleInfo object of a bundle under installing.
     * @param modulePath normal files decompression path.
     * @param targetSoPath so files decompression path.
     * @param cpuAbi cpuAbi.
     * @return Returns ERR_OK if the module files extraced successfully; returns error code otherwise.
     */
    ErrCode ExtractModuleFiles(const InnerBundleInfo &info, const std::string &modulePath,
        const std::string &targetSoPath, const std::string &cpuAbi);
    /**
     * @brief Rename the directory of current installing module package.
     * @param info Indicates the InnerBundleInfo object of a bundle under installing.
     * @return Returns ERR_OK if the module directory renamed successfully; returns error code otherwise.
     */
    ErrCode RenameModuleDir(const InnerBundleInfo &info) const;
    /**
     * @brief The process of install a new module package.
     * @param newInfo Indicates the InnerBundleInfo object parsed from the config.json in the HAP package.
     * @param oldInfo Indicates the exist InnerBundleInfo object get from the database.
     * @return Returns ERR_OK if the new module install successfully; returns error code otherwise.
     */
    ErrCode ProcessNewModuleInstall(InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);
    /**
     * @brief The process of updating an exist module package.
     * @param newInfo Indicates the InnerBundleInfo object parsed from the config.json in the HAP package.
     * @param oldInfo Indicates the exist InnerBundleInfo object get from the database.
     * @return Returns ERR_OK if the module updating successfully; returns error code otherwise.
     */
    ErrCode ProcessModuleUpdate(InnerBundleInfo &newInfo,
        InnerBundleInfo &oldInfo, bool isReplace, bool killProcess = true);
    /**
     * @brief The real procedure for bundle install by bundleName.
     * @param bundleName Indicates the bundleName the application to install.
     * @param installParam Indicates the install parameters.
     * @param uid Indicates the uid of the application.
     * @return Returns ERR_OK if the bundle install successfully; returns error code otherwise.
     */
    ErrCode ProcessRecover(
        const std::string &bundleName, const InstallParam &installParam, int32_t &uid);
    /**
     * @brief The real procedure for bundle install by bundleName.
     * @param bundleName Indicates the bundleName the application to install.
     * @param installParam Indicates the install parameters.
     * @param uid Indicates the uid of the application.
     * @return Returns ERR_OK if the bundle install successfully; returns error code otherwise.
     */
    ErrCode ProcessInstallBundleByBundleName(
        const std::string &bundleName, const InstallParam &installParam, int32_t &uid);
    /**
     * @brief The real procedure for bundle install by bundleName.
     * @param bundleName Indicates the bundleName the application to install.
     * @param installParam Indicates the install parameters.
     * @param uid Indicates the uid of the application.
     * @return Returns ERR_OK if the bundle install successfully; returns error code otherwise.
     */
    ErrCode InnerProcessInstallByPreInstallInfo(
        const std::string &bundleName, const InstallParam &installParam, int32_t &uid);
    /**
     * @brief Check syscap.
     * @param bundlePaths Indicates the file paths of all HAP packages.
     * @return Returns ERR_OK if the syscap satisfy; returns error code otherwise.
     */
    ErrCode CheckSysCap(const std::vector<std::string> &bundlePaths);

    /**
     * @brief To parse hap files and to obtain innerBundleInfo of each hap.
     * @param bundlePaths Indicates the file paths of all HAP packages.
     * @param installParam Indicates the install parameters.
     * @param appType Indicates the app type of the hap.
     * @param hapVerifyRes Indicates all signature info of all haps.
     * @param infos Indicates the innerBundleinfo of each hap.
     * @return Returns ERR_OK if each hap is parsed successfully; returns error code otherwise.
     */
    ErrCode ParseHapFiles(
        const std::vector<std::string> &bundlePaths,
        const InstallParam &installParam,
        const Constants::AppType appType,
        std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
        std::unordered_map<std::string, InnerBundleInfo> &infos);

    ErrCode CheckShellInstall(std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);

    ErrCode CheckU1Enable(const InnerBundleInfo &info, const int32_t userId);

    ErrCode CheckEnterpriseResign(const InnerBundleInfo &oldInfo);

#ifdef X86_EMULATOR_MODE
    ErrCode CheckShellInstallForEmulator(std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);
#endif

    ErrCode CheckInstallCondition(std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
        std::unordered_map<std::string, InnerBundleInfo> &infos, ErrCode checkSysCapRes);

    ErrCode CheckHapBinInstallCondition(const std::unordered_map<std::string, InnerBundleInfo> &infos) const;

    std::vector<std::string> GetBinFilePaths(const InnerBundleInfo &info,
        const std::string &nativeLibraryPath) const;

    ErrCode ProcessBinFiles(const std::unordered_map<std::string, InnerBundleInfo> &infos) const;

    ErrCode CheckInstallPermission(const InstallParam &installParam,
        std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);
    /**
     * @brief To check dependency whether or not exists.
     * @param infos Indicates all innerBundleInfo for all haps need to be installed.
     * @param sharedBundleInstaller Cross-app shared bundle installer
     * @return Returns ERR_OK if haps checking successfully; returns error code otherwise.
     */
    ErrCode CheckDependency(std::unordered_map<std::string, InnerBundleInfo> &infos,
        const SharedBundleInstaller &sharedBundleInstaller);

    /**
     * @brief To check the hap hash param.
     * @param infos .Indicates all innerBundleInfo for all haps need to be installed.
     * @param hashParams .Indicates all hashParams in installParam.
     * @return Returns ERR_OK if haps checking successfully; returns error code otherwise.
     */
    ErrCode CheckHapHashParams(
        std::unordered_map<std::string, InnerBundleInfo> &infos,
        std::map<std::string, std::string> hashParams);
    /**
     * @brief To check the version code and bundleName in all haps.
     * @param infos .Indicates all innerBundleInfo for all haps need to be installed.
     * @return Returns ERR_OK if haps checking successfully; returns error code otherwise.
     */
    ErrCode CheckAppLabelInfo(const std::unordered_map<std::string, InnerBundleInfo> &infos);

    /**
     * @brief send notify to start install applicaiton
     * @param installParam Indicates the install parameters.
     * @param infos .Indicates all innerBundleInfo for all haps need to be installed.
    */
    void SendStartInstallNotify(const InstallParam &installParam,
        const std::unordered_map<std::string, InnerBundleInfo> &infos);

    ErrCode CheckSharedBundleLabelInfo(std::unordered_map<std::string, InnerBundleInfo> &infos);
    /**
     * @brief To check native file in all haps.
     * @param infos .Indicates all innerBundleInfo for all haps need to be installed.
     * @return Returns ERR_OK if haps checking successfully; returns error code otherwise.
     */
    ErrCode CheckMultiNativeFile(
        std::unordered_map<std::string, InnerBundleInfo> &infos);
    /**
     * @brief To roll back when the installation is failed.
     * @param infos .Indicates the innerBundleInfo needs to be roll back.
     * @param oldInfo Indicates the original innerBundleInfo of the bundle.
     * @return Returns ERR_OK if roll back successfully; returns error code otherwise.
     */
    void RollBack(const InnerBundleInfo &info, InnerBundleInfo &oldInfo);
    /**
     * @brief To check the version code and bundleName in all haps.
     * @param newInfos .Indicates all innerBundleInfo for all haps need to be rolled back.
     * @param oldInfo Indicates the original innerBundleInfo of the bundle.
     * @return Returns ERR_OK if roll back successfully; returns error code otherwise.
     */
    void RollBack(const std::unordered_map<std::string, InnerBundleInfo> &newInfos, InnerBundleInfo &oldInfo);
    /**
     * @brief To remove innerBundleInfo or moduleInfo of the corresponding haps.
     * @param bundleName Indicates the bundle name of the bundle which needs to be removed innerBundleInfo or
     *                   moudleInfo.
     * @param packageName Indicates the package name of the hap which needs to be removed the moduleInfo.
     * @return Returns ERR_OK if the removing is successful; returns error code otherwise.
     */
    void RemoveInfo(const std::string &bundleName, const std::string &packageName);
    /**
     * @brief To roll back the moduleInfo of the corresponding haps.
     * @param bundleName Indicates the bundle name of the bundle which needs to be rolled back the moudleInfo.
     * @param oldInfo Indicates the original innerBundleInfo of the bundle.
     * @return Returns ERR_OK if the rollback is successful; returns error code otherwise.
     */
    void RollBackModuleInfo(const std::string &bundleName, InnerBundleInfo &oldInfo);
    /**
     * @brief To obtain the innerBundleInfo of the corresponding hap.
     * @param info Indicates the innerBundleInfo obtained.
     * @param isAppExist Indicates if the innerBundleInfo is existed or not.
     * @return Returns ERR_OK if the innerBundleInfo is obtained successfully; returns error code otherwise.
     */
    bool FetchInnerBundleInfo(InnerBundleInfo &info, bool &isAppExist);
    /**
     * @brief To check whether the version code is compatible for application or not.
     * @param oldInfo Indicates the original innerBundleInfo of the bundle.
     * @return Returns ERR_OK if version code is checked successfully; returns error code otherwise.
     */
    ErrCode CheckVersionCompatibility(const InnerBundleInfo &oldInfo);
    /**
     * @brief To check whether the version code is compatible for application or not.
     * @param oldInfo Indicates the original innerBundleInfo of the bundle.
     * @return Returns ERR_OK if version code is checked successfully; returns error code otherwise.
     */
    ErrCode CheckVersionCompatibilityForApplication(const InnerBundleInfo &oldInfo);
    /**
     * @brief To check whether the version code is compatible for openharmony service or not.
     * @param info Indicates the original innerBundleInfo of the bundle.
     * @return Returns ERR_OK if version code is checked successfully; returns error code otherwise.
     */
    ErrCode CheckVersionCompatibilityForHmService(const InnerBundleInfo &oldInfo);
    /**
     * @brief To uninstall lower version feature haps.
     * @param info Indicates the innerBundleInfo of the bundle.
     * @param packageVec Indicates the array of package names of the high version entry or feature hap.
     * @return Returns ERR_OK if uninstall successfully; returns error code otherwise.
     */
    ErrCode UninstallLowerVersionFeature(const std::vector<std::string> &packageVec, bool killProcess = false);
    /**
     * @brief To get userId.
     * @param installParam Indicates the installParam of the bundle.
     * @return Returns userId.
     */
    int32_t GetUserId(const int32_t &userId) const;
    /**
     * @brief Remove bundle user data.
     * @param innerBundleInfo Indicates the innerBundleInfo of the bundle.
     * @param needRemoveData Indicates need remove data or not.
     * @return Returns BundleUserMgr.
     */
    ErrCode RemoveBundleUserData(
        InnerBundleInfo &innerBundleInfo, const InstallParam &installParam, const bool async = false);

    /**
     * @brief Create bundle user data.
     * @param innerBundleInfo Indicates the bundle type of the application.
     * @return Returns ERR_OK if result is ok; returns error code otherwise.
     */
    ErrCode CreateBundleUserData(InnerBundleInfo &innerBundleInfo);
    void AddBundleStatus(const NotifyBundleEvents &installRes);
    ErrCode CheckInstallationFree(const InnerBundleInfo &innerBundleInfo,
        const std::unordered_map<std::string, InnerBundleInfo> &infos) const;

    bool UninstallAppControl(const std::string &appId, const std::string &appIdentifier, int32_t userId);

    ErrCode InstallNormalAppControl(const std::string &installAppId,
        const std::string &appIdentifier, int32_t userId, bool isPreInstallApp = false);

    ErrCode CreateBundleCodeDir(InnerBundleInfo &info) const;
    ErrCode CreateBundleDataDir(InnerBundleInfo &info) const;
    ErrCode RemoveBundleCodeDir(const InnerBundleInfo &info, bool async) const;
    ErrCode RemoveBundleDataDir(
        const InnerBundleInfo &info, bool forException = false, const bool async = false);
    void RemoveEmptyDirs(const std::unordered_map<std::string, InnerBundleInfo> &infos,
        const bool isBundleUpdate = false) const;
    std::string GetModuleNames(const std::unordered_map<std::string, InnerBundleInfo> &infos) const;
    ErrCode UpdateHapToken(bool needUpdate, InnerBundleInfo &newInfo, const bool isDebugGrant = false);
    ErrCode SetDirApl(const InnerBundleInfo &info);
    ErrCode SetDirApl(const CreateDirParam &createDirParam, const std::string &CloneBundleName);
    /**
     * @brief Check to set isRemovable true when install.
     * @param newInfos Indicates all innerBundleInfo for all haps need to be installed.
     * @param oldInfo Indicates the original innerBundleInfo of the bundle.
     * @param userId Indicates the userId.
     * @param isFreeInstallFlag Indicates whether is FREE_INSTALL flag.
     * @param isAppExist Indicates whether app is exist.
     * @return
     */
    void CheckEnableRemovable(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        InnerBundleInfo &oldInfo, int32_t &userId, bool isFreeInstallFlag, bool isAppExist);
    /**
     * @brief Save oldInfo isRemovable to newInfo isRemovable.
     * @param newModuleInfo Indicates the old innerModuleInfo of the bundle..
     * @param oldInfo Indicates the old innerBundleInfo of the bundle.
     * @param existModule Indicates whether module is exist.
     * @return
     */
    void SaveOldRemovableInfo(InnerModuleInfo &newModuleInfo, InnerBundleInfo &oldInfo, bool existModule);
    /**
     * @brief Save hap path to records.
     * @param isPreInstallApp Indicates isPreInstallApp or not.
     * @param infos Indicates all innerBundleInfo for all haps need to be installed.
     * @return
     */
    void SaveHapPathToRecords(
        bool isPreInstallApp, const std::unordered_map<std::string, InnerBundleInfo> &infos);
    void OnSingletonChange(bool killProcess);
    void RestoreHaps(const std::vector<std::string> &bundlePaths, const InstallParam &installParam);
    bool AllowSingletonChange(const std::string &bundleName);
    void MarkPreInstallState(const std::string &bundleName, bool isUninstalled);
    ErrCode UninstallAllSandboxApps(const std::string &bundleName, int32_t userId = Constants::INVALID_USERID);
    ErrCode CheckAppLabel(const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo) const;
    bool CheckReleaseTypeIsCompatible(const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo) const;
    void SendBundleSystemEvent(const std::string &bundleName, BundleEventType bundleEventType,
        const InstallParam &installParam, InstallScene preBundleScene, ErrCode errCode);
    void SetAPIAndSdkVersions(int32_t targetAPIVersion, uint32_t minAPIVersion, const std::string &compileSdkVersion);
    void SetUid(int32_t uid);
    void StopRelable(const InnerBundleInfo &info);
    void SetIsAbcCompressed();
    ErrCode CheckNativeFileWithOldInfo(
        const InnerBundleInfo &oldInfo, std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    bool HasAllOldModuleUpdate(
        const InnerBundleInfo &oldInfo, const std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    ErrCode CheckArkNativeFileWithOldInfo(
        const InnerBundleInfo &oldInfo, std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    ErrCode CheckNativeSoWithOldInfo(
        const InnerBundleInfo &oldInfo, std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    ErrCode NotifyBundleStatus(const NotifyBundleEvents &installRes);
    void AddNotifyBundleEvents(const NotifyBundleEvents &notifyBundleEvents);
    void ProcessHqfInfo(const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo);
    ErrCode ProcessDiffFiles(const AppqfInfo &appQfInfo, const std::string &nativeLibraryPath,
        const std::string &cpuAbi) const;
    ErrCode ProcessDeployedHqfInfo(const std::string &nativeLibraryPath,
        const std::string &cpuAbi, const InnerBundleInfo &newInfo, const AppQuickFix &appQuickFix);
    ErrCode ProcessDeployingHqfInfo(
        const std::string &nativeLibraryPath, const std::string &cpuAbi, const InnerBundleInfo &newInfo) const;
    ErrCode UpdateLibAttrs(const InnerBundleInfo &newInfo,
        const std::string &cpuAbi, const std::string &nativeLibraryPath, AppqfInfo &appQfInfo) const;
    bool CheckHapLibsWithPatchLibs(
        const std::string &nativeLibraryPath, const std::string &hqfLibraryPath) const;
    ErrCode ExtractArkNativeFile(InnerBundleInfo &info, const std::string &modulePath);
    ErrCode DeleteOldArkNativeFile(const InnerBundleInfo &oldInfo);
    int32_t GetConfirmUserId(
        const int32_t &userId, std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    ErrCode CheckUserId(const int32_t &userId) const;
    ErrCode CreateArkProfile(
        const std::string &bundleName, int32_t userId, int32_t uid, int32_t gid) const;
    ErrCode DeleteArkProfile(const std::string &bundleName, int32_t userId) const;
    bool RemoveDataPreloadHapFiles(const std::string &bundleName) const;
    bool IsDataPreloadHap(const std::string &path) const;
    ErrCode ExtractArkProfileFile(const std::string &modulePath, const std::string &bundleName,
        int32_t userId) const;
    ErrCode ExtractAllArkProfileFile(const InnerBundleInfo &oldInfo, bool checkRepeat = false);
    ErrCode CopyPgoFileToArkProfileDir(const std::string &moduleName, const std::string &modulePath,
        const std::string &bundleName, int32_t userId);
    ErrCode CopyPgoFile(const std::string &moduleName, const std::string &pgoPath,
        const std::string &bundleName, int32_t userId) const;
    ErrCode CheckOverlayInstallation(std::unordered_map<std::string, InnerBundleInfo> &newInfos, int32_t userId);
    ErrCode CheckOverlayUpdate(const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo, int32_t userId) const;
    NotifyType GetNotifyType();
    void KillRelatedProcessIfArkWeb(bool isOta);
    ErrCode CheckAppService(
        const InnerBundleInfo &newInfo, const InnerBundleInfo &oldInfo, bool isAppExist);
    ErrCode CheckSingleton(const InnerBundleInfo &newInfo, const int32_t userId);
    void GetCallingEventInfo(EventInfo &eventInfo);
    void GetInstallEventInfo(EventInfo &eventInfo);
    void GetInstallEventInfo(const InnerBundleInfo &bundleInfo, EventInfo &eventInfo);
    ErrCode CheckArkProfileDir(const InnerBundleInfo &newInfo, const InnerBundleInfo &oldInfo) const;
    ErrCode ProcessAsanDirectory(InnerBundleInfo &info) const;
    ErrCode CleanAsanDirectory(InnerBundleInfo &info) const;
    void AddAppProvisionInfo(const std::string &bundleName,
        const Security::Verify::ProvisionInfo &provisionInfo, const InstallParam &installParam) const;
    void UpdateRouterInfo();
    void DeleteRouterInfo(const InnerBundleInfo &info, const std::string &moduleName = "");
    void DeleteRouterInfoForPlugin(const InnerBundleInfo &info);
    ErrCode UninstallHspBundle(std::string &uninstallDir, const std::string &bundleName);
    ErrCode UninstallHspVersion(std::string &uninstallDir, int32_t versionCode, InnerBundleInfo &info);
    ErrCode UninstallHspAndBundle(InnerBundleInfo &info, int32_t &versionCode,
        std::string &uninstallDir);
    ErrCode CheckProxyDatas(const std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    bool CheckDuplicateProxyData(const std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    bool CheckDuplicateProxyData(const InnerBundleInfo &newInfo, const InnerBundleInfo &oldInfo);
    bool CheckDuplicateProxyData(const std::vector<ProxyData> &proxyDatas);
    bool CheckApiInfo(const std::unordered_map<std::string, InnerBundleInfo> &infos);
    ErrCode InnerProcessNativeLibs(InnerBundleInfo &info, const std::string &modulePath);
    ErrCode CheckSoEncryption(InnerBundleInfo &info, const std::string &cpuAbi, const std::string &targetSoPath);
    bool ExtractSoFiles(const std::string &soPath, const std::string &cpuAbi) const;
    void ProcessOldNativeLibraryPath(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        uint32_t oldVersionCode, const std::string &oldNativeLibraryPath) const;
    void ProcessAOT(const InstallParam &installParam) const;
    void RemoveOldHapIfOTA(const InstallParam &installParam,
        const std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InnerBundleInfo &oldInfo);
    ErrCode CopyHapsToSecurityDir(const InstallParam &installParam, std::vector<std::string> &bundlePaths);
    ErrCode ParseHapPaths(const InstallParam &installParam, const std::vector<std::string> &inBundlePaths,
        std::vector<std::string> &parsedPaths);
    ErrCode RenameAllTempDir(const std::unordered_map<std::string, InnerBundleInfo> &newInfos) const;
    ErrCode FindSignatureFileDir(const std::string &moduleName, std::string &signatureFileDir);
    ErrCode MoveFileToRealInstallationDir(const std::unordered_map<std::string, InnerBundleInfo> &infos);
    std::string GetTempHapPath(const InnerBundleInfo &info);
    ErrCode SaveHapToInstallPath(const std::unordered_map<std::string, InnerBundleInfo> &infos,
        const InnerBundleInfo &oldInfo);
    ErrCode CheckHapEncryption(const std::unordered_map<std::string, InnerBundleInfo> &infos,
        const InnerBundleInfo &oldInfo, bool copyHapToInstallPath = true);
    void UpdateEncryptionStatus(const std::unordered_map<std::string, InnerBundleInfo> &infos,
        const InnerBundleInfo &oldInfo, InnerBundleInfo &newInfo);
    bool IsBundleEncrypted(const std::unordered_map<std::string, InnerBundleInfo> &infos,
        const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo);
    void UpdateAppInstallControlled(int32_t userId);
    void UpdateHasCloudkitConfig();
    ErrCode MoveSoFileToRealInstallationDir(const std::unordered_map<std::string, InnerBundleInfo> &infos,
        bool needDeleteOldLibraryPath, bool isBundleUpdate = false);
    ErrCode FinalProcessHapAndSoForBundleUpdate(const std::unordered_map<std::string, InnerBundleInfo> &infos,
        bool needCopyHapToInstallPath, bool needDeleteOldLibraryPath);
    void GetDataGroupIds(const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
        std::unordered_set<std::string> &groupIds);
    void GenerateNewUserDataGroupInfos(InnerBundleInfo &info) const;
    void RemoveOldGroupDirs(const InnerBundleInfo &oldInfo) const;
    ErrCode RemoveDataGroupDirs(const std::string &bundleName, int32_t userId, bool isKeepData = false) const;
    void DeleteGroupDirsForException(const InnerBundleInfo &oldInfo) const;
    ErrCode CreateDataGroupDirs(
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults, const InnerBundleInfo &oldInfo);
    bool NeedDeleteOldNativeLib(
        const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InnerBundleInfo &oldInfo);
    ErrCode UninstallBundleFromBmsExtension(const std::string &bundleName);
    ErrCode CheckBundleInBmsExtension(const std::string &bundleName, int32_t userId);
    ErrCode CheckMDMUpdateBundleForSelf(const InstallParam &installParam, InnerBundleInfo &oldInfo,
        const std::unordered_map<std::string, InnerBundleInfo> &newInfos, bool isAppExist);
    void ExtractResourceFiles(const InnerBundleInfo &info, const std::string &targetPath) const;
    void ExtractNPAPIPluginFiles(const std::string &modulePath);
    void RemoveNPAPIPluginDir();
    void RemoveTempSoDir(const std::string &tempSoDir, const std::string &bundleName);
    bool CheckAppIdentifier(const std::string &oldAppIdentifier, const std::string &newAppIdentifier,
        const std::string &oldAppId, const std::string &newAppId);
    ErrCode InstallEntryMoudleFirst(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        InnerBundleInfo &bundleInfo, const InnerBundleUserInfo &innerBundleUserInfo, const InstallParam &installParam);
    void ProcessQuickFixWhenInstallNewModule(const InstallParam &installParam,
        const std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    bool ExtractEncryptedSoFiles(const InnerBundleInfo &info, const std::string &tmpSoPath, int32_t uid) const;
    void SetOldAppIsEncrypted(const InnerBundleInfo &oldInfo);
    bool UpdateEncryptedStatus(const InnerBundleInfo &oldInfo);
    bool DeleteEncryptedStatus(const std::string &bundleName, int32_t uid);
    void ProcessEncryptedKeyExisted(int32_t res, uint32_t type,
        const std::vector<CodeProtectBundleInfo> &infos);
    ErrCode VerifyCodeSignatureForNativeFiles(InnerBundleInfo &info, const std::string &cpuAbi,
        const std::string &targetSoPath, const std::string &signatureFileDir) const;
    ErrCode VerifyCodeSignatureForHap(const std::unordered_map<std::string, InnerBundleInfo> &infos,
        const std::string &srcHapPath, const std::string &realHapPath);
    ErrCode DeliveryProfileToCodeSign() const;
    ErrCode RemoveProfileFromCodeSign(const std::string &bundleName) const;
    ErrCode ExtractResFileDir(const std::string &modulePath) const;
    ErrCode ProcessAppSkills(InnerBundleInfo &info);
    ErrCode FinalizeAppSkills(const InnerBundleInfo &info);
    ErrCode CommitAppSkills(const InnerBundleInfo &info);
    void PrepareAppSkillStatus(const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo,
        int32_t userId = Constants::INVALID_USERID);
    bool NotifyAppSkillStatus(const std::string &bundleName, const std::vector<std::string> &oldSkills,
        const std::vector<std::string> &newSkills, int32_t userId = Constants::INVALID_USERID) const;
    void RemoveAppSkillsDir(const std::string &bundleName) const;
    void RemoveAppSkillsDir(const std::string &bundleName, const std::string &moduleName,
        bool isTemp = false) const;
    /**
     * @brief The process of shareFiles configuration during bundle installation/update.
     * @param newInfos Indicates the parsed bundle infos (map of hapPath to InnerBundleInfo).
     * @param oldInfo Indicates the old bundle info for rollback (empty for new install).
     * @return Returns ERR_OK if processing succeeded; returns error code otherwise.
     */
    ErrCode ProcessBundleShareFiles(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InnerBundleInfo &oldInfo);

    /**
     * @brief Process shareFiles for a single module.
     * @param hapPath The HAP file path.
     * @param moduleInfo The module info.
     * @param bundleName The bundle name.
     * @param oldInfo The old bundle info for update.
     * @return Returns ERR_OK if processing succeeded; returns error code otherwise.
     */
    ErrCode ProcessModuleShareFiles(const std::string &hapPath,
        const InnerModuleInfo &moduleInfo, const std::string &bundleName,
        const InnerBundleInfo &oldInfo);

    /**
     * @brief Update shareFileInfo for all instances (multi-user, clone, sandbox).
     * @param shareFilesJson The JSON content.
     * @param bundleName The bundle name.
     * @param oldInfo The old bundle info containing all instance info.
     * @return Returns ERR_OK if operation succeeded; returns error code otherwise.
     */
    ErrCode UpdateShareFileInfoForAllInstances(const std::string &shareFilesJson,
        const std::string &bundleName, const InnerBundleInfo &oldInfo);

    /**
     * @brief Update all instances for a single user (main app + clones).
     * @param shareFilesJson The JSON content.
     * @param bundleName The bundle name.
     * @param userInfo The user bundle info.
     * @return Number of failed updates.
     */
    int32_t UpdateMultiUserInstances(const std::string &shareFilesJson,
        const std::string &bundleName, const InnerBundleUserInfo &userInfo);

    /**
     * @brief Process shareFiles cleanup during uninstall.
     * @param info The bundle info.
     * @param userId The user ID to cleanup.
     * @return Returns ERR_OK if processing succeeded; returns error code otherwise.
     */
    ErrCode ProcessUninstallShareFiles(const InnerBundleInfo &info, int32_t userId);

    /**
     * @brief Rollback shareFiles during install/update failure.
     * @details This function restores the previous shareFiles configuration:
     *          - For new install failure: unsets all shareFiles configuration
     *          - For update failure: restores the old shareFiles JSON saved before update
     * @param oldInfo Indicates the old bundle info for rollback (empty for new install).
     */
    void RollbackShareFiles(const InnerBundleInfo &oldInfo);

    /**
     * @brief Rollback shareFiles for new install failure.
     * @return Number of failed rollback operations.
     */
    int32_t RollbackShareFilesForNewInstall();

    /**
     * @brief Rollback shareFiles for update failure.
     * @param oldInfo The old bundle info.
     * @return Number of failed rollback operations.
     */
    int32_t RollbackShareFilesForUpdate(const InnerBundleInfo &oldInfo);

    /**
     * @brief Rollback shareFiles for a single user (main app + clones).
     * @param userInfo The user bundle info.
     * @param oldInfo The old bundle info.
     * @return Number of failed rollback operations.
     */
    int32_t RollbackUserInstances(const InnerBundleUserInfo &userInfo, const InnerBundleInfo &oldInfo);

    /**
     * @brief Save old shareFiles JSON config for rollback during update.
     * @param oldBundleInfo The old (installed) bundle info.
     * @return Returns ERR_OK if successfully saved; returns error code otherwise.
     */
    ErrCode SaveOldShareFilesForRollback(const InnerBundleInfo &oldBundleInfo);

    /**
     * @brief Check if the bundle info has shareFiles configured in entry module.
     * @param bundleInfo The bundle info to check.
     * @return Returns true if entry module has shareFiles configured; returns false otherwise.
     */
    static bool HasEntryShareFiles(const InnerBundleInfo &bundleInfo);

    /**
     * @brief Check if shareFiles processing is needed during install or update.
     * @param isAppExist Indicates whether this is an update scenario (true) or new install (false).
     * @param newInfos The new bundle infos to be installed.
     * @param oldInfo The old bundle info (used only in update scenario).
     * @return Returns true if shareFiles processing is needed; returns false otherwise.
     * @note For new install: returns true only if new version has shareFiles configured.
     * @note For update: returns true only if either old or new version has shareFiles configured.
     */
    static bool ShouldProcessShareFiles(bool isAppExist,
        const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InnerBundleInfo &oldInfo);

    ErrCode ExtractHnpFileDir(const std::string &cpuAbi, const std::map<std::string, std::string> &hnpPackageMap,
        const std::string &modulePath) const;
    void DeleteOldNativeLibraryPath() const;
    std::string GetRealSoPath(const std::string &bundleName, const std::string &nativeLibraryPath,
        bool isNeedDeleteOldPath) const;
    void RemoveTempPathOnlyUsedForSo(const InnerBundleInfo &innerBundleInfo, const bool isBundleUpdate = false) const;
    void UpdateDeveloperIdAndOdid(std::unordered_map<std::string, InnerBundleInfo> &infos,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const;
    void SetAppDistributionType(const std::unordered_map<std::string, InnerBundleInfo> &infos);
    ErrCode CreateShaderCache(const std::string &bundleName, int32_t uid, int32_t gid) const;
    ErrCode DeleteShaderCache(const std::string &bundleName) const;
    void DeleteUseLessSharefilesForDefaultUser(const std::string &bundleName, int32_t userId) const;
    ErrCode CleanShaderCache(const InnerBundleInfo &oldInfo, const std::string &bundleName, int32_t userId) const;
    ErrCode CleanArkStartupCache(const std::string &bundleName) const;
    void CreateCloudShader(const std::string &bundleName, int32_t uid, int32_t gid) const;
    ErrCode DeleteCloudShader(const std::string &bundleName) const;
    ErrCode DeleteEl1ShaderAndArkStartupCache(const InnerBundleInfo &oldInfo,
        const std::string &bundleName, int32_t userId) const;
    ArkStartupCache CreateArkStartupCacheParameter(const std::string &bundleName,
        int32_t userId, BundleType bundleType, int32_t uid);
    ErrCode CreateArkStartupCache(const ArkStartupCache &createArk) const;
    ErrCode DeleteArkStartupCache(const std::string &cacheDir, const std::string &bundleName, int32_t userId) const;
    bool VerifyActivationLock() const;
    std::vector<std::string> GenerateScreenLockProtectionDir(const std::string &bundleName) const;
    void CreateScreenLockProtectionDir(bool withOtherUsers = false);
    void CreateEl5AndSetPolicy(InnerBundleInfo &info, bool withOtherUsers);
    void DeleteScreenLockProtectionDir(const std::string bundleName) const;
    void DeleteEncryptionKeyId(const std::string &bundleName, bool existEl5Dir, bool isKeepData) const;
#ifdef APP_DOMAIN_VERIFY_ENABLED
    void PrepareSkillUri(const std::vector<Skill> &skills, std::vector<AppDomainVerify::SkillUri> &skillUris) const;
#endif
    void PrepareBundleDirQuota(const std::string &bundleName, const int32_t uid,
        const std::string &bundleDataDirPath, const int32_t limitSize) const;
    void ParseSizeFromProvision(const std::string &bundleName, const int32_t uid, int32_t &sizeMb) const;
    void VerifyDomain();
    void ClearDomainVerifyStatus(const std::string &appIdentifier, const std::string &bundleName) const;
    bool IsRdDevice() const;
    void SetAtomicServiceModuleUpgrade(const InnerBundleInfo &oldInfo);
    void UpdateExtensionSandboxInfo(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);
    void GetValidDataGroupIds(const std::vector<std::string> &extensionDataGroupIds,
        const std::vector<std::string> &bundleDataGroupIds, std::vector<std::string> &validGroupIds) const;
    void GetExtensionDirsChange(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InnerBundleInfo &oldInfo);
    void GetCreateExtensionDirs(std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    void GetRemoveExtensionDirs(
        std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InnerBundleInfo &oldInfo);
    void CreateExtensionDataDir(InnerBundleInfo &info) const;
    bool UpdateExtensionDirsApl(const std::vector<std::string> &updateExtensionDirs,
        const InnerBundleInfo &info) const;
    void RemoveCreatedExtensionDirsForException() const;
    void RemoveOldExtensionDirs() const;
    ErrCode InnerProcessUpdateHapToken(const bool isOldSystemApp, const bool isDebugGrant = false);
    bool InitDataMgr();
    std::string GetCloneInstallSource(const std::string &originalInstallSource,
        const std::string &callingBundleName) const;
    std::string GetInstallSource(const InstallParam &installParam) const;
    void SetApplicationFlagsAndInstallSource(std::unordered_map<std::string, InnerBundleInfo> &infos,
        const InstallParam &installParam) const;
    ErrCode CheckAppBlackList(const std::string &bundleName, const int32_t userId) const;
    bool CheckWhetherCanBeUninstalled(const std::string &bundleName, const std::string &appIdentifier) const;
    void CheckSystemFreeSizeAndClean() const;
    void CheckBundleNameAndStratAbility(const std::string &bundleName, const std::string &appIdentifier) const;
    void GetUninstallBundleInfo(bool isKeepData, int32_t userId,
        const InnerBundleInfo &oldInfo, UninstallBundleInfo &uninstallBundleInfo);
    bool CheckInstallOnKeepData(const std::string &bundleName, bool isOTA,
        const std::unordered_map<std::string, InnerBundleInfo> &infos);
    void SaveUninstallBundleInfo(const std::string bundleName, bool isKeepData,
        const UninstallBundleInfo &uninstallBundleInfo);
    void DeleteUninstallBundleInfo(const std::string &bundleName);
    bool DeleteUninstallBundleInfoFromDb(const std::string &bundleName);
    void SetFirstInstallTime(const std::string &bundleName, const int64_t &time, InnerBundleInfo &info);
    bool SaveFirstInstallBundleInfo(const std::string &bundleName, const int32_t userId,
        bool isPreInstallApp, const InnerBundleUserInfo &innerBundleUserInfo);
    void UpdateDynamicSkills();
    ErrCode MarkInstallFinish();
    bool IsArkWeb(const std::string &bundleName) const;
    bool IsShellOrDevAssistant() const;
    void UninstallDebugAppSandbox(const std::string &bundleName, const int32_t uid,
        const InnerBundleInfo& innerBundleInfo);
    ErrCode CheckAppDistributionType();
    ErrCode CheckSpaceIsolation(
        const InstallParam &installParam, const std::unordered_map<std::string, InnerBundleInfo> &newInfos) const;
    ErrCode CheckDriverIsolation(const Security::Verify::HapVerifyResult &hapVerifyResult, const int32_t userId,
        const std::unordered_map<std::string, InnerBundleInfo> &newInfos) const;
#ifdef WEBVIEW_ENABLE
    ErrCode VerifyArkWebInstall();
    void RestoreconForArkweb();
#endif

    bool SetDisposedRuleWhenBundleUpdateStart(const std::unordered_map<std::string, InnerBundleInfo> &infos,
        const InnerBundleInfo &oldBundleInfo, bool isPreInstallApp);

    bool DeleteDisposedRuleWhenBundleUpdateEnd(const InnerBundleInfo &oldBundleInfo);

    bool SetDisposedRuleWhenBundleUninstallStart(const std::string &bundleName,
        const std::string &appId, bool isMultiUser);
    bool DeleteDisposedRuleWhenBundleUninstallEnd(const std::string &bundleName,
        const std::string &appId, bool isMultiUser);
    bool AddAppGalleryHapToTempPath(const bool isPreInstallApp,
        const std::unordered_map<std::string, InnerBundleInfo> &infos);
    bool DeleteAppGalleryHapFromTempPath();
    void InnerProcessNewBundleDataDir(const bool isOta, const InnerBundleInfo &oldBundleInfo,
        const InnerBundleInfo &newBundleInfo);
    bool GetTempBundleInfo(InnerBundleInfo &info) const;
    bool InitTempBundleFromCache(InnerBundleInfo &info, bool &isAppExist, std::string bundleName = "");
    ErrCode UpdateAppEncryptedStatus(const std::string &bundleName, bool isExisted, int32_t appIndex);
    void CheckPreBundle(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InstallParam &installParam, bool isRecover);
    ErrCode CheckShellCanInstallPreApp(const std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    void CheckInstallAllowDowngrade(const InstallParam &installParam,
        const InnerBundleInfo &oldBundleInfo, ErrCode &result);

    bool RecoverHapToken(const std::string &bundleName, const int32_t userId,
        Security::AccessToken::AccessTokenIDEx& accessTokenIdEx, InnerBundleInfo &innerBundleInfo,
        const bool isDebugGrant = false);
    void UpdateKillApplicationProcess(const InnerBundleInfo &innerBundleInfo);
    std::string GetAssetAccessGroups(const std::string &bundleName);
    std::string GetDeveloperId(const std::string &bundleName);
    void GetModuleNames(const std::string &bundleName, std::vector<std::string> &moduleNames);
    ErrCode CheckPreAppAllowHdcInstall(const InstallParam &installParam,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);
    ErrCode CheckInstallGrantPermission(const InstallParam &installParam,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);
    void CheckPreBundleRecoverResult(ErrCode &result);

    bool IsAllowEnterPrise();
    void MarkIsForceUninstall(const std::string &bundleName, bool isForceUninstalled);
    bool CheckCanInstallPreBundle(const std::string &bundleName, const int32_t userId);
    void RemovePluginOnlyInCurrentUser(const InnerBundleInfo &info);
    std::string GetModulePath(const InnerBundleInfo &info, const bool isBundleUpdate, const bool isModuleUpdate);
    ErrCode ProcessBundleCodePath(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InnerBundleInfo &oldInfo, const std::string &bundleName,
        const bool isBundleUpdate, const bool needCopyHap);
    ErrCode InnerProcessCodePathCreateNewDir(const std::string &bundleName, const bool isBundleUpdate);
    ErrCode InnerProcessCodePathRealToOld(const std::string &bundleName, const uint32_t oldVersionCode);
    ErrCode InnerProcessCodePathNewToReal(const std::string &bundleName, const uint32_t oldVersionCode);
    void ProcessOldCodePath(const std::string &bundleName, const bool isBundleUpdate);
    void RollbackCodePath(const std::string &bundleName, bool isBundleUpdate);
    void InnerProcessTargetSoPath(const InnerBundleInfo &info, const bool isBundleUpdate,
        const std::string &modulePath, std::string &nativeLibraryPath, std::string &targetSoPath);
    ErrCode RecoverOnDemandInstallBundle(const std::string &bundleName,
        const InstallParam &installParam, int32_t &uid);
    void PrintStartWindowIconId(const InnerBundleInfo &info);
    bool ProcessExtProfile(const InstallParam &installParam);
    void SetHybridSpawn();
    ErrCode ProcessDynamicIconFileWhenUpdate(const InnerBundleInfo &oldInfo, const std::string &oldPath,
        const std::string &newPath);
    bool IsBundleCrossAppSharedConfig(const std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    bool CheckAddResultMsg(const InnerBundleInfo &info, bool isContainEntry);
    ErrCode CheckArkTSMode(const std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    bool AddInstallingBundleName(const InstallParam &installParam);
    bool DeleteInstallingBundleName(const InstallParam &installParam);
    void RollbackHnpInstall(const std::string &bundleName, const std::unordered_set<int32_t> &userIds);
    void VerifyDelayedAging(InnerBundleInfo &bundleInfo, int32_t uid);
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    ErrCode CheckInstallPermission(const std::string &appId, const std::string &appIdentifier,
        const std::vector<std::string> &allowedAppIds, const std::vector<std::string> &disallowedAppIds);
#endif
    ErrCode ProcessPluginFilesWhenUpdate(const InnerBundleInfo &oldInfo,
        const std::string &oldPath, const std::string &newPath);
    void ProcessUpdateShortcut();
    void NotifyBundleCallback(const NotifyType &type, int32_t uid);
    void ChangeFileStatByParsedPaths(const std::vector<std::string> &parsedPaths);

    bool isAppExist_ = false;
    bool isContainEntry_ = false;
    bool isAppService_ = false;
    // used for bundle update
    bool isFeatureNeedUninstall_ = false;
    // for quick fix
    bool needDeleteQuickFixInfo_ = false;
    bool hasInstalledInUser_ = false;
    bool isModuleUpdate_ = false;
    bool isEntryInstalled_ = false;
    bool isEnterpriseBundle_ = false;
    bool isInternaltestingBundle_ = false;
    // When it is true, it means that the same bundleName and same userId was uninstalled with keepData before
    bool existBeforeKeepDataApp_ = false;
    bool copyHapToInstallPath_ = false;
    bool needSetDisposeRule_ = false;
    bool needDeleteAppTempPath_ = false;
    bool isBundleExist_ = false;
    bool isBundleCrossAppSharedConfig_ = false;
    bool isHnpInstalled_ = false;
    bool isKeepTokenId_ = false;
    bool supportDataCloneInstall_ = false;
    bool hasShareFilesProcessed_ = false;
    bool hasOldShareFilesJsonSaved_ = false;
    InstallerState state_ = InstallerState::INSTALL_START;
    uint32_t versionCode_ = 0;
    uint32_t accessTokenId_ = 0;
    uint32_t oldApplicationReservedFlag_ = 0;

    int32_t userId_ = Constants::INVALID_USERID;
    int32_t sessionId_ = 0;
    bool sessionCommitted_ = false;
    std::map<std::string, std::string> modulePathMap_;
    int32_t overlayType_ = NON_OVERLAY_TYPE;
    int32_t atomicServiceModuleUpgrade_ = 0;
    SingletonState singletonState_ = SingletonState::DEFAULT;
    BundleType bundleType_ = BundleType::APP;
    Security::AccessToken::AccessTokenID callerToken_ = 0;
    std::string bundleName_;
    std::string modulePath_;
    std::string baseDataPath_;
    std::string modulePackage_;
    std::string mainAbility_;
    std::string moduleName_;
    std::string uninstallBundleAppId_;
    std::string entryModuleName_ = "";
    std::string appDistributionType_;
    std::string appIdentifier_ = "";
    std::string bundleAppIdentifier_ = "";
    std::string oldShareFilesJson_;
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker_ = nullptr;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;  // this pointer will get when public functions called
    // key is package name, value is boolean
    std::unordered_map<std::string, bool> installedModules_;
    std::vector<std::string> uninstallModuleVec_;
    std::map<std::string, std::string> hapPathRecords_;
    // utilizing for code-signature
    std::map<std::string, std::string> verifyCodeParams_;
    std::vector<std::string> toDeleteTempHapPath_;
    std::vector<NotifyBundleEvents> bundleEvents_;
    // key is the temp path of hap or hsp
    // value is the signature file path
    std::map<std::string, std::string> signatureFileMap_;
    std::vector<std::string> bundlePaths_;
    std::unordered_map<std::string, std::string> signatureFileTmpMap_;
    // utilize for install entry firstly from multi-installation
    std::map<std::string, std::string> pgoParams_;
    std::map<std::string, std::string> targetSoPathMap_;
    // indicates sandboxd dirs need to create by extension
    std::vector<std::string> newExtensionDirs_;
    // indicates sandboxd dirs need to create by extension
    std::vector<std::string> createExtensionDirs_;
    // indicates sandboxd dirs need to remove by extension
    std::vector<std::string> removeExtensionDirs_;
    // used to record system event infos
    EventInfo sysEventInfo_;
    NpapiPluginStatus npapiPluginStatus_ = NpapiPluginStatus::STATUS_NOT_APPLICABLE;
    Security::Verify::HapVerifyResult verifyRes_;
    std::vector<RequestPermission> aggregatedRequestPermissions_;
    InstallerBundleTempInfo tempInfo_;
    // indicates whether the application has been restored to the preinstall
    bool isPreBundleRecovered_ = false;
    std::vector<std::string> allowListenBundles_;
    std::unordered_map<std::string, std::vector<SkillsPackageInfo>> moduleSkillInfoMap_;
    std::unordered_set<std::string> appSkillProcessedModulePackages_;
    std::string appSkillNotifyBundleName_;
    std::vector<std::string> oldAppSkillNotifyItems_;
    std::vector<std::string> newAppSkillNotifyItems_;
    int32_t appSkillNotifyUserId_ = Constants::INVALID_USERID;

    DISALLOW_COPY_AND_MOVE(BaseBundleInstaller);

#define CHECK_RESULT(errcode, errmsg)                                              \
    do {                                                                           \
        if ((errcode) != ERR_OK) {                                                   \
            APP_LOGE(errmsg, errcode);                                             \
            return errcode;                                                        \
        }                                                                          \
    } while (0)

#define CHECK_RESULT_WITH_ROLLBACK(errcode, errmsg, newInfos, oldInfo)             \
    do {                                                                           \
        if ((errcode) == ERR_APPEXECFWK_INSTALL_SINGLETON_NOT_SAME ||              \
            (errcode) == ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON) {     \
            APP_LOGE(errmsg, errcode);                                             \
            return errcode;                                                        \
        }                                                                          \
                                                                                   \
        if ((errcode) != ERR_OK) {                                                   \
            APP_LOGE(errmsg, errcode);                                             \
            RollBack(newInfos, oldInfo);                                           \
            return errcode;                                                        \
        }                                                                          \
    } while (0)
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BASE_BUNDLE_INSTALLER_H
