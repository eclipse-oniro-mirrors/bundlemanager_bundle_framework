/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_DATA_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_DATA_MGR_H

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>

#include "bundle_dir.h"
#include "want.h"

#include "ability_info.h"
#include "aot/aot_args.h"
#include "application_info.h"
#include "app_provision_info.h"
#ifdef ABILITY_RUNTIME_ENABLE
#include "app_mgr_interface.h"
#include "running_process_info.h"
#endif
#include "bundle_data_storage_interface.h"
#include "bundle_event_callback_interface.h"
#include "bundle_promise.h"
#include "bundle_sandbox_app_helper.h"
#include "bundle_state_storage.h"
#include "bundle_status_callback_interface.h"
#include "bundle_storage_stats.h"
#include "common_event_data.h"
#include "dynamic_icon_info.h"
#include "ffrt.h"
#include "first_install_data_mgr_storage_rdb.h"
#include "inner_bundle_clone_info.h"
#include "inner_bundle_info.h"
#include "inner_bundle_user_info.h"
#include "ipc/create_dir_param.h"
#include "uninstall_data_mgr_storage_rdb.h"
#include "module_info.h"
#include "module_test_runner.h"
#include "preinstall_data_storage_interface.h"
#include "router_data_storage_interface.h"
#include "shortcut_data_storage_interface.h"
#include "shortcut_visible_data_storage_rdb.h"
#ifdef GLOBAL_RESMGR_ENABLE
#include "resource_manager.h"
#endif
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
#include "element.h"
#endif
#include "ohos_account_kits.h"

namespace OHOS {
namespace AppExecFwk {
enum class InstallState {
    INSTALL_START = 1,
    INSTALL_SUCCESS,
    INSTALL_FAIL,
    UNINSTALL_START,
    UNINSTALL_SUCCESS,
    UNINSTALL_FAIL,
    UPDATING_START,
    UPDATING_SUCCESS,
    UPDATING_FAIL,
    ROLL_BACK,
    USER_CHANGE,
};

class BundleDataMgr {
public:
    using Want = OHOS::AAFwk::Want;

    // init state transfer map data.
    BundleDataMgr();
    virtual ~BundleDataMgr();

    /**
     * @brief Boot query persistent storage.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool LoadDataFromPersistentStorage();
    /**
     * @brief Update internal state for whole bundle.
     * @param bundleName Indicates the bundle name.
     * @param state Indicates the install state to be set.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool UpdateBundleInstallState(const std::string &bundleName,
        const InstallState state, const bool isKeepData = false);
    /**
     * @brief Add new InnerBundleInfo.
     * @param bundleName Indicates the bundle name.
     * @param info Indicates the InnerBundleInfo object to be save.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool AddInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info, bool checkStatus = true);
    /**
     * @brief Add new module info to an exist InnerBundleInfo.
     * @param bundleName Indicates the bundle name.
     * @param newInfo Indicates the new InnerBundleInfo object.
     * @param oldInfo Indicates the old InnerBundleInfo object.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool AddNewModuleInfo(const std::string &bundleName, const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);
    bool AddNewModuleInfo(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);

    /**
     * @brief Remove module info from an exist InnerBundleInfo.
     * @param bundleName Indicates the bundle name.
     * @param modulePackage Indicates the module Package.
     * @param oldInfo Indicates the old InnerBundleInfo object.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool RemoveModuleInfo(const std::string &bundleName, const std::string &modulePackage, InnerBundleInfo &oldInfo,
        bool needSaveStorage = true);

    bool RemoveHspModuleByVersionCode(int32_t versionCode, InnerBundleInfo &info);
    /**
     * @brief Update module info of an exist module.
     * @param bundleName Indicates the bundle name.
     * @param newInfo Indicates the new InnerBundleInfo object.
     * @param oldInfo Indicates the old InnerBundleInfo object.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool UpdateInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);
    bool UpdateInnerBundleInfo(InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);
    void UpdateBaseBundleInfoIntoOld(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);
    bool UpdateInnerBundleInfo(const InnerBundleInfo &innerBundleInfo, bool needSaveStorage = true);
    bool UpdatePartialInnerBundleInfo(const InnerBundleInfo &info);
    bool UpdateEl5KeyId(const CreateDirParam &el5Param, const std::string keyId, bool needSaveStorage = true);
    /**
     * @brief Generate UID and GID for a bundle.
     * @param innerBundleUserInfo Indicates the InnerBundleUserInfo object.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GenerateUidAndGid(InnerBundleUserInfo &innerBundleUserInfo);
    /**
     * @brief Recycle uid and gid .
     * @param info Indicates the InnerBundleInfo object.
     */
    void RecycleUidAndGid(const InnerBundleInfo &info);
    /**
     * @brief Query the AbilityInfo by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    bool QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo,
        int32_t appIndex = 0) const;
    /**
     * @brief Query a AbilityInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param abilityInfos Indicates the obtained AbilityInfo of list.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    bool QueryAbilityInfos(
        const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const;
    /**
     * @brief Query a AbilityInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param abilityInfos Indicates the obtained AbilityInfo of list.
     * @return Returns ERR_OK if the AbilityInfo is successfully obtained; returns errCode otherwise.
     */
    ErrCode QueryAbilityInfosV9(
        const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const;
    /**
     * @brief Query a AbilityInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param abilityInfos Indicates the obtained AbilityInfo of list.
     * @return Returns ERR_OK if the AbilityInfo is successfully obtained; returns errCode otherwise.
     */
    ErrCode BatchQueryAbilityInfos(
        const std::vector<Want> &wants, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const;
    /**
     * @brief Query Launcher AbilityInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param userId Indicates the user ID.
     * @param abilityInfos Indicates the obtained AbilityInfo of list.
     * @return Returns ERR_OK if the AbilityInfo is successfully obtained; returns errCode otherwise.
     */
    ErrCode QueryLauncherAbilityInfos(
        const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const;
    /**
     * @brief Query Launcher AbilityInfo of list by the given Want.
     * @param bundleName Indicates the information of the ability.
     * @param userId Indicates the user ID.
     * @param abilityInfos Indicates the obtained AbilityInfo of list.
     * @return Returns ERR_OK if the AbilityInfo is successfully obtained; returns errCode otherwise.
     */
    ErrCode GetLauncherAbilityInfoSync(
        const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const;
    /**
     * @brief Query all match launcher ability infos by given wants.
     * @param want Indicates the match infomation for abilities.
     * @param info Indicates the bundleInfo.
     * @param abilityInfo Indicates the obtained AbilityInfo of list.
     * @param userId Indicates the user ID.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    void GetMatchLauncherAbilityInfos(const Want& want, const InnerBundleInfo& info,
        std::vector<AbilityInfo>& abilityInfos, int64_t installTime,
        int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Query the AbilityInfo by ability.uri in config.json.
     * @param abilityUri Indicates the uri of the ability.
     * @param abilityInfos Indicates the obtained AbilityInfos object.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    bool QueryAbilityInfosByUri(const std::string &abilityUri, std::vector<AbilityInfo> &abilityInfos);
    /**
     * @brief Query the AbilityInfo by ability.uri in config.json.
     * @param abilityUri Indicates the uri of the ability.
     * @param userId Indicates the user ID.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    bool QueryAbilityInfoByUri(
        const std::string &abilityUri, int32_t userId, AbilityInfo &abilityInfo) const;
    /**
     * @brief Obtains the ApplicationInfo based on a given bundle name.
     * @param appName Indicates the application bundle name to be queried.
     * @param flags Indicates the flag used to specify information contained
     *             in the ApplicationInfo object that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfo Indicates the obtained ApplicationInfo object.
     * @return Returns true if the application is successfully obtained; returns false otherwise.
     */
    bool GetApplicationInfo(
        const std::string &appName, int32_t flags, const int userId, ApplicationInfo &appInfo) const;
    /**
     * @brief Obtains the ApplicationInfo based on a given bundle name.
     * @param appName Indicates the application bundle name to be queried.
     * @param flags Indicates the flag used to specify information contained
     *             in the ApplicationInfo object that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfo Indicates the obtained ApplicationInfo object.
     * @return Returns ERR_OK if the application is successfully obtained; returns error code otherwise.
     */
    ErrCode GetApplicationInfoV9(
        const std::string &appName, int32_t flags, int32_t userId,
        ApplicationInfo &appInfo, const int32_t appIndex = 0) const;
    /**
     * @brief Obtains the ApplicationInfo based on a given bundle name.
     * @param appName Indicates the application bundle name to be queried.
     * @param flags Indicates the flag used to specify information contained
     *             in the ApplicationInfo object that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfo Indicates the obtained ApplicationInfo object.
     * @return Returns ERR_OK if the application is successfully obtained; returns error code otherwise.
     */
    ErrCode GetApplicationInfoWithResponseId(
        const std::string &appName, int32_t flags, int32_t &userId, ApplicationInfo &appInfo) const;
    /**
     * @brief Obtains information about all installed applications of a specified user.
     * @param flags Indicates the flag used to specify information contained
     *             in the ApplicationInfo objects that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfos Indicates all of the obtained ApplicationInfo objects.
     * @return Returns true if the application is successfully obtained; returns false otherwise.
     */
    bool GetApplicationInfos(
        int32_t flags, const int userId, std::vector<ApplicationInfo> &appInfos) const;
    /**
     * @brief Obtains information about all installed applications of a specified user.
     * @param flags Indicates the flag used to specify information contained
     *             in the ApplicationInfo objects that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfos Indicates all of the obtained ApplicationInfo objects.
     * @return Returns ERR_OK if the application is successfully obtained; returns error code otherwise.
     */
    ErrCode GetApplicationInfosV9(
        int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos) const;
    /**
     * @brief Obtains BundleInfo of all bundles available in the system.
     * @param flags Indicates the flag used to specify information contained in the BundleInfo that will be returned.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @param userId Indicates the user ID.
     * @return Returns true if the BundleInfos is successfully obtained; returns false otherwise.
     */
    bool GetBundleInfos(int32_t flags,
        std::vector<BundleInfo> &bundleInfos, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Obtains BundleInfo of all bundles available in the system.
     * @param flags Indicates the flag used to specify information contained in the BundleInfo that will be returned.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if the BundleInfos is successfully obtained; returns error code otherwise.
     */
    ErrCode GetBundleInfosV9(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId) const;
    /**
     * @brief Obtains the BundleInfo based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @param userId Indicates the user ID.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    bool GetBundleInfo(const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Obtains the BundleInfo based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @param userId Indicates the user ID.
     * @param appIndex Indicates the app index.
     * @return Returns ERR_OK if the BundleInfo is successfully obtained; returns error code otherwise.
     */
    ErrCode GetBundleInfoV9(const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const;
    /**
     * @brief Batch obtains the BundleInfos based on a given bundle name list.
     * @param bundleNames Indicates the application bundle name list to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfos Indicates the obtained BundleInfo list object.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if the BundleInfo is successfully obtained; returns error code otherwise.
     */
    void BatchGetBundleInfo(const std::vector<std::string> &bundleNames, int32_t flags,
        std::vector<BundleInfo> &bundleInfos, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Obtains the BundlePackInfo based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param BundlePackInfo Indicates the obtained BundlePackInfo object.
     * @return Returns ERR_OK if the BundlePackInfo is successfully obtained; returns other ErrCode otherwise.
     */
    ErrCode GetBundlePackInfo(const std::string &bundleName, int32_t flags, BundlePackInfo &bundleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Obtains the BundleInfo of application bundles based on the specified metaData.
     * @param metaData Indicates the metadata to get in the bundle.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @return Returns true if the BundleInfos is successfully obtained; returns false otherwise.
     */
    bool GetBundleInfosByMetaData(const std::string &metaData, std::vector<BundleInfo> &bundleInfos) const;
    /**
     * @brief Obtains the bundle name of a specified application based on the given UID.
     * @param uid Indicates the uid.
     * @param bundleName Indicates the obtained bundle name.
     * @return Returns true if the bundle name is successfully obtained; returns false otherwise.
     */
    bool GetBundleNameForUid(const int32_t uid, std::string &bundleName) const;
    /**
     * @brief Obtains all bundle names of a specified application based on the given application UID.
     * @param uid Indicates the uid.
     * @param bundleNames Indicates the obtained bundle names.
     * @return Returns true if the bundle names is successfully obtained; returns false otherwise.
     */
    bool GetBundlesForUid(const int uid, std::vector<std::string> &bundleNames) const;
    /**
     * @brief Obtains the formal name associated with the given UID.
     * @param uid Indicates the uid.
     * @param name Indicates the obtained formal name.
     * @return Returns ERR_OK if called successfully; returns error code otherwise.
     */
    ErrCode GetNameForUid(const int uid, std::string &name) const;
    /**
     * @brief Obtains the appIdentifier and appIndex with the given access tokenId.
     * @param accessTokenId Indicates the access tokenId of the application.
     * @param appIdentifier Indicates the app identifier of the application.
     * @param appIndex Indicates the app index of the application.
     * @return Returns ERR_OK if execute success; returns errCode otherwise.
     */
    ErrCode GetAppIdentifierAndAppIndex(const uint32_t accessTokenId,
        std::string &appIdentifier, int32_t &appIndex);
    /**
     * @brief Obtains an array of all group IDs associated with a specified bundle.
     * @param bundleName Indicates the bundle name.
     * @param gids Indicates the group IDs associated with the specified bundle.
     * @return Returns true if the gids is successfully obtained; returns false otherwise.
     */
    bool GetBundleGids(const std::string &bundleName, std::vector<int> &gids) const;
    /**
     * @brief Obtains an array of all group IDs associated with the given bundle name and UID.
     * @param bundleName Indicates the bundle name.
     * @param uid Indicates the uid.
     * @param gids Indicates the group IDs associated with the specified bundle.
     * @return Returns true if the gids is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleGidsByUid(const std::string &bundleName, const int &uid, std::vector<int> &gids) const;
    /**
     * @brief Obtains the BundleInfo of all keep-alive applications in the system.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @return Returns true if the BundleInfos is successfully obtained; returns false otherwise.
     */
    bool QueryKeepAliveBundleInfos(std::vector<BundleInfo> &bundleInfos) const;
    /**
     * @brief Obtains the label of a specified ability.
     * @param bundleName Indicates the bundle name.
     * @param moduleName Indicates the module name.
     * @param abilityName Indicates the ability name.
     * @param label Indicates the obtained label.
     * @return Returns ERR_OK if the ability label is successfully obtained; returns errCode otherwise.
     */
    ErrCode GetAbilityLabel(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, std::string &label) const;
    /**
     * @brief Obtains the Want for starting the main ability of an application based on the given bundle name.
     * @param bundleName Indicates the bundle name.
     * @param want Indicates the obtained launch Want object.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if this function is successfully called; returns errCode otherwise.
     */
    ErrCode GetLaunchWantForBundle(
        const std::string &bundleName, Want &want, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Obtain the HAP module info of a specific ability.
     * @param abilityInfo Indicates the ability.
     * @param userId Indicates the user ID.
     * @param hapModuleInfo Indicates the obtained HapModuleInfo object.
     * @return Returns true if the HapModuleInfo is successfully obtained; returns false otherwise.
     */
    bool GetHapModuleInfo(const AbilityInfo &abilityInfo,
        HapModuleInfo &hapModuleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Check whether the app is system app by it's UID.
     * @param uid Indicates the uid.
     * @return Returns true if the bundle is a system application; returns false otherwise.
     */
    bool CheckIsSystemAppByUid(const int uid) const;
    /**
     * @brief Obtains all bundle names installed.
     * @param bundleNames Indicates the bundle Names.
     * @param userId Indicates the user ID.
     * @return Returns true if have bundle installed; returns false otherwise.
     */
    bool GetBundleList(
        std::vector<std::string> &bundleNames, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Obtains debug bundle names installed.
     * @param bundleNames Indicates the debug bundle Names.
     * @param userId Indicates the user ID.
     * @return Returns true if have debug bundle installed; returns false otherwise.
     */
    bool GetDebugBundleList(
        std::vector<std::string> &bundleNames, int32_t userId) const;
    /**
     * @brief Set the bundle status disable.
     * @param bundleName Indicates the bundle name.
     * @return Returns true if the bundle status successfully set; returns false otherwise.
     */
    bool DisableBundle(const std::string &bundleName);
    /**
     * @brief Set the bundle status enable.
     * @param bundleName Indicates the bundle name.
     * @return Returns true if the bundle status successfully set; returns false otherwise.
     */
    bool EnableBundle(const std::string &bundleName);
    /**
     * @brief Get whether the application is a debug applicaiton.
     * @param bundleName Indicates the bundle name.
     * @param isDebuggable Indicates the application is a debug applicaiton.
     * @return Returns result of the operation.
     */
    ErrCode IsDebuggableApplication(const std::string &bundleName, bool &isDebuggable) const;
    /**
     * @brief Get whether the application status is enabled.
     * @param bundleName Indicates the bundle name.
     * @param isEnable Indicates the application status is enabled.
     * @return Returns result of the operation.
     */
    ErrCode IsApplicationEnabled(const std::string &bundleName,
        int32_t appIndex, bool &isEnable, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Set the application status.
     * @param bundleName Indicates the bundle name.
     * @param isEnable Indicates the status to set.
     * @param userId Indicates the user id.
     * @return Returns result of the operation.
     */
    ErrCode SetApplicationEnabled(const std::string &bundleName, int32_t appIndex, bool isEnable,
        const std::string &caller, int32_t userId = Constants::UNSPECIFIED_USERID);
    /**
     * @brief Sets whether to enable a specified ability through the proxy object.
     * @param abilityInfo Indicates information about the ability to check.
     * @param isEnable Indicates the ability status is enabled.
     * @return Returns result of the operation.
     */
    ErrCode IsAbilityEnabled(const AbilityInfo &abilityInfo, int32_t appIndex, bool &isEnable) const;
    /**
     * @brief Sets whether to enable a specified ability through the proxy object.
     * @param abilityInfo Indicates information about the ability.
     * @param isEnabled Specifies whether to enable the ability.
     *                 The value true means to enable it, and the value false means to disable it.
     * @param userId Indicates the user id.
     * @return Returns result of the operation.
     */
    ErrCode SetAbilityEnabled(const AbilityInfo &abilityInfo, int32_t appIndex, bool isEnabled,
        int32_t userId = Constants::UNSPECIFIED_USERID);
    /**
     * @brief Register the bundle status callback function.
     * @param bundleStatusCallback Indicates the callback object that using for notifing the bundle status.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool RegisterBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback);

    bool RegisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback);

    bool UnregisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback);
    /**
     * @brief Clear the specific bundle status callback.
     * @param bundleStatusCallback Indicates the callback to be cleared.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool ClearBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback);
    /**
     * @brief Unregister all the callbacks of status changed.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool UnregisterBundleStatusCallback();
    /**
     * @brief Get a mutex for locking by bundle name.
     * @param bundleName Indicates the bundle name.
     * @return Returns a reference of mutex that for locing by bundle name.
     */
    ffrt::mutex &GetBundleMutex(const std::string &bundleName);
    /**
     * @brief Obtains the provision Id based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param provisionId Indicates the provision Id to be returned.
     * @return Returns true if the provision Id is successfully obtained; returns false otherwise.
     */
    bool GetProvisionId(const std::string &bundleName, std::string &provisionId) const;
    /**
     * @brief Obtains the app feature based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param provisionId Indicates the app feature to be returned.
     * @return Returns true if the app feature is successfully obtained; returns false otherwise.
     */
    bool GetAppFeature(const std::string &bundleName, std::string &appFeature) const;
    /**
     * @brief Set the flag that indicates whether initial user create successfully.
     * @param flag Indicates the flag to be set.
     * @return
     */
    void SetInitialUserFlag(bool flag);
    /**
     * @brief Get a shared pointer to the IBundleDataStorage object.
     * @return Returns the pointer of IBundleDataStorage object.
     */
    std::shared_ptr<IBundleDataStorage> GetDataStorage() const;
    /**
     * @brief Obtains the FormInfo objects provided by all applications on the device.
     * @param formInfos List of FormInfo objects if obtained;
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetAllFormsInfo(std::vector<FormInfo> &formInfos) const;
    /**
     * @brief Obtains the FormInfo objects provided by a specified application on the device.
     * @param bundleName Indicates the bundle name of the  application.
     * @param formInfos List of FormInfo objects if obtained;
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos) const;
    /**
     * @brief Obtains the FormInfo objects provided by a specified module name.
     * @param formInfos List of FormInfo objects if obtained;
     * @param moduleName Indicates the module name of the application.
     * @param bundleName Indicates the bundle name of the application.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetFormsInfoByModule(
        const std::string &bundleName, const std::string &moduleName, std::vector<FormInfo> &formInfos) const;
    /**
     * @brief Obtains the ShortcutInfo objects provided by a specified application on the device.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user ID.
     * @param shortcutInfos List of ShortcutInfo objects if obtained.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetShortcutInfos(
        const std::string &bundleName, int32_t userId, std::vector<ShortcutInfo> &shortcutInfos) const;
    /**
     * @brief Obtains the ShortcutInfo objects provided by a specified application on the device.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user ID.
     * @param shortcutInfos List of ShortcutInfo objects if obtained.
     * @return Returns errcode of the result.
     */
    ErrCode GetShortcutInfoV9(
        const std::string &bundleName, int32_t userId, std::vector<ShortcutInfo> &shortcutInfos) const;
    /**
     * @brief Obtains the ShortcutInfo objects provided by a specified application on the device.
     * @param bundleName Indicates the bundle name of the application.
     * @param appIndex Indicates the app index of clone applications.
     * @param userId Indicates the user ID.
     * @param shortcutInfos List of ShortcutInfo objects if obtained.
     * @return Returns errcode of the result.
     */
    ErrCode GetShortcutInfoByAppIndex(const std::string &bundleName, const int32_t appIndex,
        std::vector<ShortcutInfo> &shortcutInfos) const;
    /**
     * @brief Obtains the CommonEventInfo objects provided by an event key on the device.
     * @param eventKey Indicates the event of the subscribe.
     * @param commonEventInfos List of CommonEventInfo objects if obtained.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetAllCommonEventInfo(const std::string &eventKey, std::vector<CommonEventInfo> &commonEventInfos) const;
    /**
     * @brief Obtains the PreInstallBundleInfo objects provided by bundleName.
     * @param bundleName Indicates the bundle name of the application.
     * @param preInstallBundleInfo Indicates information about the PreInstallBundleInfo.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetPreInstallBundleInfo(const std::string &bundleName, PreInstallBundleInfo &preInstallBundleInfo);
    /**
     * @brief Save new PreInstallBundleInfo.
     * @param bundleName Indicates the bundle name.
     * @param preInstallBundleInfo Indicates the PreInstallBundleInfo object to be save.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool SavePreInstallBundleInfo(const std::string &bundleName, const PreInstallBundleInfo &preInstallBundleInfo);
    /**
     * @brief Obtains the PreInstallBundleInfo objects provided by bundleName.
     * @param preInstallBundleInfo Indicates information about the PreInstallBundleInfo.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool LoadAllPreInstallBundleInfos(std::vector<PreInstallBundleInfo> &preInstallBundleInfos);
    /**
     * @brief Save new PreInstallBundleInfo.
     * @param bundleName Indicates the bundle name.
     * @param preInstallBundleInfo Indicates the PreInstallBundleInfo object to be save.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool DeletePreInstallBundleInfo(
        const std::string &bundleName, const PreInstallBundleInfo &preInstallBundleInfo);
    /**
     * @brief Save installation mark to datebase storage.
     * @param info Indicates the innerBundleInfo of the bundle which needs to save installation mark.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool SaveInnerBundleInfo(const InnerBundleInfo &info) const;
    /**
     * @brief GetInnerBundleUserInfoByUserId.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param userId Indicates the user ID.
     * @param innerBundleUserInfo Indicates the obtained InnerBundleUserInfo object.
     * @return Returns true if the application is successfully obtained; returns false otherwise.
     */
    bool GetInnerBundleUserInfoByUserId(
        const std::string &bundleName, int32_t userId, InnerBundleUserInfo &innerBundleUserInfo) const;
    /**
     * @brief save all created users.
     * @param userId Indicates the user ID.
     */
    void AddUserId(int32_t userId);
    /**
     * @brief remove userId.
     * @param userId Indicates the user ID.
     */
    void RemoveUserId(int32_t userId);
    /**
     * @brief query users.
     * @param userId Indicates the user ID.
     * @return Returns true when query user success; returns false otherwise.
     */
    bool HasUserId(int32_t userId) const;
    /**
     * @brief Get userId by calling uid.
     * @return Returns userId.
     */
    int32_t GetUserIdByCallingUid() const;
    /**
     * @brief Get all user.
     * @return Returns all userId.
     */
    std::set<int32_t> GetAllUser() const;
    /**
     * @brief Has initial user created.
     * @return Returns initial user flag.
     */
    bool HasInitialUserCreated() const
    {
        return initialUserFlag_;
    }
    /**
     * @brief Set bundlePromise.
     * @param bundlePromise Indicates the bundlePromise.
     */
    void SetBundlePromise(const std::shared_ptr<BundlePromise>& bundlePromise)
    {
        bundlePromise_ = bundlePromise;
    }
    /**
     * @brief Get bundleUserInfos by bundleName.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param innerBundleUserInfo Indicates the obtained InnerBundleUserInfo object.
     * @return Returns true if the application is successfully obtained; returns false otherwise.
     */
    bool GetInnerBundleUserInfos(
        const std::string &bundleName, std::vector<InnerBundleUserInfo> &innerBundleUserInfos) const;
    /**
     * @brief Get app privilege level.
     * @param bundleName Indicates the bundle name of the app privilege level.
     * @param userId Indicates the user id.
     * @return Returns app privilege level.
     */
    std::string GetAppPrivilegeLevel(
        const std::string &bundleName, int32_t userId = Constants::UNSPECIFIED_USERID);
    /**
     * @brief Query a ExtensionAbilityInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param extensionInfos Indicates the obtained ExtensionAbilityInfo of list.
     * @return Returns true if the ExtensionAbilityInfo is successfully obtained; returns false otherwise.
     */
    bool QueryExtensionAbilityInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex = 0) const;
    /**
     * @brief Query a ExtensionAbilityInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param extensionInfos Indicates the obtained ExtensionAbilityInfo of list.
     * @return Returns ERR_OK if the ExtensionAbilityInfo is successfully obtained; returns errCode otherwise.
     */
    ErrCode QueryExtensionAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex = 0) const;

    /**
     * @brief Query a ExtensionAbilityInfo without want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param extensionInfos Indicates the obtained ExtensionAbilityInfo of list.
     * @return Returns ERR_OK if the ExtensionAbilityInfo is successfully obtained; returns errCode otherwise.
     */
    ErrCode QueryExtensionAbilityInfos(uint32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex = 0) const;

    ErrCode QueryExtensionAbilityInfosByExtensionTypeName(const std::string &typeName, uint32_t flags,
        int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex = 0) const;
    /**
     * @brief Obtains the PreInstallBundleInfo objects in Cache.
     * @return Returns PreInstallBundleInfos.
     */
    const std::vector<PreInstallBundleInfo> GetAllPreInstallBundleInfos();
    /**
     * @brief Restore uid and gid .
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool RestoreUidAndGid();
    /**
     * @brief Load all bundle state data from jsonDb .
     * @return
     */
    void LoadAllBundleStateDataFromJsonDb();

    bool QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType, const int32_t &userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos) const;

    bool QueryExtensionAbilityInfoByUri(const std::string &uri, int32_t userId,
        ExtensionAbilityInfo &extensionAbilityInfo) const;

    ErrCode AddInnerBundleUserInfo(const std::string &bundleName, const InnerBundleUserInfo& newUserInfo);

    bool RemoveInnerBundleUserInfo(const std::string &bundleName, int32_t userId);

    bool ImplicitQueryInfoByPriority(const Want &want, int32_t flags, int32_t userId,
        AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionInfo) const;

    bool ImplicitQueryInfos(const Want &want, int32_t flags, int32_t userId, bool withDefault,
        std::vector<AbilityInfo> &abilityInfos, std::vector<ExtensionAbilityInfo> &extensionInfos,
        bool &findDefaultApp);
    bool UpateExtResources(const std::string &bundleName,
        const std::vector<ExtendResourceInfo> &extendResourceInfos);
    bool RemoveExtResources(const std::string &bundleName,
        const std::vector<std::string> &moduleNames);
    bool UpateCurDynamicIconModule(
        const std::string &bundleName, const std::string &moduleName,
        const int32_t userId = Constants::UNSPECIFIED_USERID, const int32_t appIndex = Constants::DEFAULT_APP_INDEX);
    void CreateAppInstallDir(int32_t userId);
    void RemoveAppInstallDir(int32_t userId);
    bool IsObtainAbilityInfo(const Want &want, int32_t userId, AbilityInfo &abilityInfo);
    ErrCode GetExtendResourceInfo(const std::string &bundleName, const std::string &moduleName,
        ExtendResourceInfo &extendResourceInfos);

    /**
     * @brief Sets whether to enable isRemovable based on given bundle name, module name and isEnable.
     * @param bundleName Indicates the bundleName.
     * @param moduleName Indicates the moduleName.
     * @param isEnable Set module isRemovable is enable.
     * @param userId Indicates the user ID.
     * @return Returns true if the module isRemovable is set success; returns false otherwise.
     */
    bool SetModuleRemovable(const std::string &bundleName, const std::string &moduleName, bool isEnable,
        int32_t userId);
    /**
     * @brief Get Module isRemovable by bundleName and moduleName.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param moduleName Indicates the moduleName.
     * @param isRemovable Indicates the module whether is removable.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if the module isRemovable is successfully obtained; returns other ErrCode otherwise.
     */
    ErrCode IsModuleRemovable(const std::string &bundleName, const std::string &moduleName, bool &isRemovable,
        int32_t userId) const;

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    int64_t GetBundleSpaceSize(const std::string &bundleName) const;
    int64_t GetBundleSpaceSize(const std::string &bundleName, int32_t userId) const;
    int64_t GetAllFreeInstallBundleSpaceSize() const;
    bool GetFreeInstallModules(
        std::map<std::string, std::vector<std::string>> &freeInstallModules) const;
#endif

#ifdef ABILITY_RUNTIME_ENABLE
    std::vector<int32_t> GetNoRunningBundleCloneIndexes(const sptr<IAppMgr> appMgrProxy, const std::string &bundleName,
        const std::vector<int32_t> &cloneAppIndexes) const;
#endif
    void GetBundleCacheInfos(
        const int32_t userId, std::vector<std::tuple<std::string, std::vector<std::string>,
        std::vector<int32_t>>> &validBundles, bool isClean = false) const;
    void GetBundleCacheInfo(
        std::function<std::vector<int32_t>(std::string&, std::vector<int32_t>&)> idxFilter,
        const InnerBundleInfo &info,
        std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<int32_t>>> &validBundles,
        const int32_t userId, bool isClean) const;
    bool GetBundleStats(const std::string &bundleName,
        const int32_t userId, std::vector<int64_t> &bundleStats,
        const int32_t appIndex = 0, const uint32_t statFlag = 0) const;
    ErrCode BatchGetBundleStats(const std::vector<std::string> &bundleNames, const int32_t userId,
        std::vector<BundleStorageStats> &bundleStats) const;
    void GetBundleModuleNames(const std::string &bundleName, std::vector<std::string> &moduleNameList) const;
    bool GetAllBundleStats(const int32_t userId, std::vector<int64_t> &bundleStats) const;
    bool HasUserInstallInBundle(const std::string &bundleName, const int32_t userId) const;
    bool GetAllDependentModuleNames(const std::string &bundleName, const std::string &moduleName,
        std::vector<std::string> &dependentModuleNames);
    ErrCode SetModuleUpgradeFlag(const std::string &bundleName, const std::string &moduleName, int32_t upgradeFlag);
    int32_t GetModuleUpgradeFlag(const std::string &bundleName, const std::string &moduleName) const;
    /**
     * @brief Get the Inner Bundle Info With Flags object
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param info Indicates the innerBundleInfo of the bundle.
     * @param userId Indicates the user ID.
     * @return Returns true if get inner bundle info is successfully obtained; returns false otherwise.
     */
    bool GetInnerBundleInfoWithFlags(const std::string &bundleName, const int32_t flags,
        InnerBundleInfo &info, int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const;
    bool GetInnerBundleInfoWithFlags(const std::string &bundleName, const int32_t flags,
        int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const;
    bool GetInnerBundleInfoWithBundleFlagsAndLock(const std::string &bundleName, int32_t flags,
        InnerBundleInfo &info, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    ErrCode GetInnerBundleInfoWithFlagsV9(const std::string &bundleName, int32_t flags,
        InnerBundleInfo &info, int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const;
    ErrCode GetInnerBundleInfoWithBundleFlagsV9(const std::string &bundleName, int32_t flags,
        InnerBundleInfo &info, int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const;
    std::shared_ptr<BundleSandboxAppHelper> GetSandboxAppHelper() const;
    ErrCode GetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo);

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    bool QueryInfoAndSkillsByElement(int32_t userId, const Element& element,
        AbilityInfo& abilityInfo, ExtensionAbilityInfo& extensionInfo, std::vector<Skill>& skills) const;

    bool GetElement(int32_t userId, const ElementName& elementName, Element& element) const;
#endif

    int32_t GetUserId(int32_t userId = Constants::UNSPECIFIED_USERID) const;

    ErrCode GetMediaData(const std::string &bundleName, const std::string &moduleName, const std::string &abilityName,
        std::unique_ptr<uint8_t[]> &mediaDataPtr, size_t &len, int32_t userId) const;

    ffrt::shared_mutex &GetStatusCallbackMutex();

    std::vector<sptr<IBundleStatusCallback>> GetCallBackList() const;

    std::string GetStringById(const std::string &bundleName, const std::string &moduleName,
        uint32_t resId, int32_t userId, const std::string &localeInfo);

    std::string GetIconById(
        const std::string &bundleName, const std::string &moduleName, uint32_t resId, uint32_t density, int32_t userId);
    void UpdateRemovable(const std::string &bundleName, bool removable);
    void UpdatePrivilegeCapability(
        const std::string &bundleName, const ApplicationInfo &appInfo);
    bool FetchInnerBundleInfo(
        const std::string &bundleName, InnerBundleInfo &innerBundleInfo);
    bool GetInnerBundleInfoUsers(const std::string &bundleName, std::set<int32_t> &userIds);
    bool IsSystemHsp(const std::string &bundleName);

    bool UpdateUninstallBundleInfo(const std::string &bundleName, const UninstallBundleInfo &uninstallBundleInfo);
    bool GetUninstallBundleInfo(const std::string &bundleName, UninstallBundleInfo &uninstallBundleInfo);
    bool DeleteUninstallBundleInfo(const std::string &bundleName, int32_t userId);
    bool GetAllUninstallBundleInfo(std::map<std::string, UninstallBundleInfo> &uninstallBundleInfos);

    bool AddFirstInstallBundleInfo(const std::string &bundleName, const int32_t userId,
        const FirstInstallBundleInfo &firstInstallBundleInfo);
    bool GetFirstInstallBundleInfo(const std::string &bundleName, const int32_t userId,
        FirstInstallBundleInfo &firstInstallBundleInfo);
    bool DeleteFirstInstallBundleInfo(int32_t userId);

    bool UpdateQuickFixInnerBundleInfo(const std::string &bundleName, const InnerBundleInfo &innerBundleInfo);

    void NotifyBundleEventCallback(const EventFwk::CommonEventData &eventData) const;

    const std::map<std::string, InnerBundleInfo> GetAllInnerBundleInfos() const
    {
        std::shared_lock<ffrt::shared_mutex> lock(bundleInfoMutex_);
        return bundleInfos_;
    }

    bool QueryOverlayInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info);

    void SaveOverlayInfo(const std::string &bundleName, InnerBundleInfo &innerBundleInfo);

    ErrCode GetAppProvisionInfo(const std::string &bundleName, int32_t userId,
        AppProvisionInfo &appProvisionInfo);

    virtual ErrCode GetProvisionMetadata(const std::string &bundleName, int32_t userId,
        std::vector<Metadata> &provisionMetadatas) const;

    ErrCode GetBaseSharedBundleInfos(const std::string &bundleName,
        std::vector<BaseSharedBundleInfo> &baseSharedBundleInfos,
        GetDependentBundleInfoFlag flag = GetDependentBundleInfoFlag::GET_APP_CROSS_HSP_BUNDLE_INFO) const;

    bool GetBaseSharedBundleInfo(const Dependency &dependency, BaseSharedBundleInfo &baseSharedBundleInfo) const;

    ErrCode GetAllSharedBundleInfo(std::vector<SharedBundleInfo> &sharedBundles) const;

    ErrCode GetSharedBundleInfo(const std::string &bundleName, const std::string &moduleName,
        std::vector<SharedBundleInfo> &sharedBundles);

    bool DeleteSharedBundleInfo(const std::string &bundleName);

    ErrCode GetSharedBundleInfoBySelf(const std::string &bundleName, SharedBundleInfo &sharedBundleInfo);

    ErrCode GetSharedDependencies(const std::string &bundleName, const std::string &moduleName,
        std::vector<Dependency> &dependencies);

    bool CheckHspVersionIsRelied(int32_t versionCode, const InnerBundleInfo &info) const;
    bool CheckHspBundleIsRelied(const std::string &hspBundleName) const;
    bool IsPreInstallApp(const std::string &bundleName);
    bool GetBundleType(const std::string &bundleName, BundleType &bundleType)const;

    ErrCode GetSharedBundleInfo(const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo);
    ErrCode GetSpecifiedDistributionType(const std::string &bundleName, std::string &specifiedDistributionType);
    ErrCode GetAdditionalInfo(const std::string &bundleName, std::string &additionalInfo);
    ErrCode GetAdditionalInfoForAllUser(const std::string &bundleName, std::string &additionalInfo);

    ErrCode GetProxyDataInfos(const std::string &bundleName, const std::string &moduleName, int32_t userId,
        std::vector<ProxyData> &proxyDatas) const;

    ErrCode GetAllProxyDataInfos(int32_t userId, std::vector<ProxyData> &proxyDatas) const;

    std::string GetBundleNameByAppId(const std::string &appId) const;

    void SetAOTCompileStatus(const std::string &bundleName, const std::string &moduleName,
        AOTCompileStatus aotCompileStatus, uint32_t versionCode);
    void ResetAOTFlags();
    void ResetAOTFlagsCommand(const std::string &bundleName);
    ErrCode ResetAOTCompileStatus(const std::string &bundleName, const std::string &moduleName,
        int32_t triggerMode);
    std::vector<std::string> GetAllBundleName() const;
    std::vector<std::string> GetAllSystemHspCodePaths() const;
    std::vector<std::string> GetAllExtensionBundleNames(const std::vector<ExtensionAbilityType> &types) const;
    /**
     * @brief Get lite bundleInfo of all bundles under the specified user
     * @param userId Indicates the user ID
     * @return Returns lite bundleInfo list, tuple format : {bundleName, uid, gid}
     */
    std::vector<std::tuple<std::string, int32_t, int32_t>> GetAllLiteBundleInfo(const int32_t userId) const;
    std::vector<std::string> GetBundleNamesForNewUser() const;
    bool IsBundleExist(const std::string &bundleName) const;
    bool QueryInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info) const;
    std::vector<int32_t> GetUserIds(const std::string &bundleName) const;
    ErrCode SetExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const std::string &extName, const std::string &mimeType);
    ErrCode DelExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const std::string &extName, const std::string &mimeType);
    bool QueryAppGalleryAbilityName(std::string &bundleName, std::string &abilityName);
    void ScanAllBundleGroupInfo();
    void HandleGroupIdAndIndex(const std::set<std::string> errorGroupIds,
        std::map<int32_t, std::string> &indexMap, std::map<std::string, int32_t> &groupIdMap);
    bool HandleErrorDataGroupInfos(
        const std::map<std::string, int32_t> &groupIdMap,
        const std::map<std::string, std::set<std::string>> &needProcessGroupInfoBundleNames);
    bool QueryDataGroupInfos(const std::string &bundleName, int32_t userId, std::vector<DataGroupInfo> &infos) const;
    bool GetGroupDir(const std::string &dataGroupId, std::string &dir, int32_t userId) const;
    void GenerateDataGroupUuidAndUid(DataGroupInfo &dataGroupInfo, int32_t userId,
        std::unordered_set<int32_t> &uniqueIdSet) const;
    void GenerateDataGroupInfos(const std::string &bundleName,
        const std::unordered_set<std::string> &dataGroupIdList, int32_t userId,
        bool needSaveStorage = false);
    bool CreateAppGroupDir(const std::string &bundleName, int32_t userId);
    void CreateAppEl5GroupDir(const std::string &bundleName, int32_t userId);
    void GetDataGroupIndexMap(std::map<std::string, std::pair<int32_t, std::string>> &dataGroupIndexMap,
        std::unordered_set<int32_t> &uniqueIdSet) const;
    bool IsShareDataGroupIdNoLock(const std::string &dataGroupId, int32_t userId) const;
    void GenerateNewUserDataGroupInfos(const std::string &bundleName, int32_t userId);
    void DeleteUserDataGroupInfos(const std::string &bundleName, int32_t userId, bool keepData);
    bool IsDataGroupIdExistNoLock(const std::string &dataGroupId, int32_t userId) const;
    void ProcessAllUserDataGroupInfosWhenBundleUpdate(InnerBundleInfo &innerBundleInfo);
    void DeleteGroupDirsForException(const InnerBundleInfo &oldInfo, int32_t userId) const;
    ErrCode GetJsonProfile(ProfileType profileType, const std::string &bundleName, const std::string &moduleName,
        std::string &profile, int32_t userId) const;
    ErrCode GetJsonProfileByExtractor(const std::string &hapPath, const std::string &profilePath,
        std::string &profile) const;
    bool GetOldAppIds(const std::string &bundleName, std::vector<std::string> &appIds) const;
    ErrCode GetInnerBundleInfoByUid(const int32_t uid, InnerBundleInfo &innerBundleInfo) const;
    ErrCode GetInnerBundleInfoAndIndexByUid(const int32_t uid, InnerBundleInfo &innerBundleInfo,
        int32_t &appIndex) const;
    std::string GetModuleNameByBundleAndAbility(const std::string& bundleName, const std::string& abilityName);
    const std::vector<PreInstallBundleInfo> GetRecoverablePreInstallBundleInfos(int32_t userId);
    ErrCode SetAdditionalInfo(const std::string& bundleName, const std::string& additionalInfo) const;
    ErrCode GetAppServiceHspBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo);
    ErrCode CreateBundleDataDir(int32_t userId);
    ErrCode CreateBundleDataDirWithEl(int32_t userId, DataDirEl dirEl);
    void GenerateOdid(const std::string &developerId, std::string &odid) const;
    ErrCode GetOdid(std::string &odid) const;
    ErrCode GetOdidByBundleName(const std::string &bundleName, std::string &odid) const;
    void UpdateRouterInfo(const std::string &bundleName);
    void UpdateRouterInfo(InnerBundleInfo &innerBundleInfo);
    void FindRouterHapPath(const InnerBundleInfo &innerBundleInfo,
        std::map<std::string, std::pair<std::string, std::string>> &hapPathMap);
    void UpdateRouterInfo(const std::string &bundleName,
        std::map<std::string, std::pair<std::string, std::string>> &hapPathMap);

    bool DeleteRouterInfo(const std::string &bundleName);
    bool DeleteRouterInfo(const std::string &bundleName, const std::string &moduleName);
    void GetAllBundleNames(std::set<std::string> &bundleNames);

    void UpdateIsPreInstallApp(const std::string &bundleName, bool isPreInstallApp);

    /**
     * @brief Check whether the link can be opened.
     * @param link Indicates the link to be opened.
     * @param canOpen Indicates whether the link can be opened.
     * @return  Returns result of the operation.
     */
    ErrCode CanOpenLink(
        const std::string &link, bool &canOpen) const;
    /**
    * @brief Obtains all bundle names of a specified user.
    * @param flags Indicates the flags to control the bundle list.
    * @param userId Indicates the user ID.
    * @param bundleNames Indicates the vector of the bundle names.
    * @return Returns ERR_OK if successfully obtained; returns error code otherwise.
    */
    ErrCode GetAllBundleNames(uint32_t flags, int32_t userId, std::vector<std::string> &bundleNames);
    ErrCode GetAllBundleInfoByDeveloperId(const std::string &developerId,
        std::vector<BundleInfo> &bundleInfos, int32_t userId);
    ErrCode GetDeveloperIds(const std::string &appDistributionType,
        std::vector<std::string> &developerIdList, int32_t userId);
    ErrCode SwitchUninstallState(const std::string &bundleName, const bool &state,
        const bool isNeedSendNotify, bool &stateChange);

    ErrCode AddCloneBundle(const std::string &bundleName, const InnerBundleCloneInfo &attr);
    ErrCode RemoveCloneBundle(const std::string &bundleName, const int32_t userId, int32_t appIndex);
    ErrCode QueryAbilityInfoByContinueType(const std::string &bundleName, const std::string &continueType,
        AbilityInfo &abilityInfo, int32_t userId, int32_t appIndex = 0) const;
    ErrCode GetBundleNameAndIndex(const int32_t uid, std::string &bundleName, int32_t &appIndex) const;
    ErrCode GetBundleNameAndIndexForUid(const int32_t uid, std::string &bundleName, int32_t &appIndex) const;

    ErrCode QueryCloneAbilityInfo(const ElementName &element, int32_t flags, int32_t userId,
        int32_t appIndex, AbilityInfo &abilityInfo) const;
    ErrCode GetCloneBundleInfo(const std::string &bundleName, int32_t flags, int32_t appIndex,
        BundleInfo &bundleInfo, int32_t userId) const;
    std::vector<int32_t> GetCloneAppIndexes(const std::string &bundleName, int32_t userId) const;
    std::set<int32_t> GetCloneAppIndexes(const std::string &bundleName) const;

    ErrCode ExplicitQueryExtensionInfoV9(const Want &want, int32_t flags, int32_t userId,
        ExtensionAbilityInfo &extensionInfo, int32_t appIndex = 0) const;

    void QueryAllCloneExtensionInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &infos) const;
    void QueryAllCloneExtensionInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &infos) const;

    ErrCode GetAppIdByBundleName(const std::string &bundleName, std::string &appId) const;

    ErrCode GetAppIdAndAppIdentifierByBundleName(const std::string &bundleName, std::string &appId,
        std::string &appIdentifier) const;

    std::string AppIdAndAppIdentifierTransform(const std::string appIdOrAppIdentifier) const;

    ErrCode GetSignatureInfoByBundleName(const std::string &bundleName, SignatureInfo &signatureInfo) const;

    ErrCode GetSignatureInfoByUid(const int32_t uid, SignatureInfo &signatureInfo) const;

    ErrCode GetInnerBundleInfoWithSandboxByUid(const int uid, InnerBundleInfo &innerBundleInfo) const;

    ErrCode UpdateAppEncryptedStatus(const std::string &bundleName, bool isExisted,
        int32_t appIndex = 0, bool needSaveStorage = true);

    ErrCode AddDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId);
    ErrCode DeleteDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId);
    ErrCode GetAllDesktopShortcutInfo(int32_t userId, std::vector<ShortcutInfo> &shortcutInfos);
    ErrCode DeleteDesktopShortcutInfo(const std::string &bundleName);
    ErrCode DeleteDesktopShortcutInfo(const std::string &bundleName, int32_t userId, int32_t appIndex);

    void GetBundleInfosForContinuation(std::vector<BundleInfo> &bundleInfos) const;

    /**
     * @brief Get a list of application package names that continue the specified package name.
     * @param continueBundleName The package name that is being continued.
     * @param bundleNames Continue the list of specified package names.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if successfully obtained; returns error code otherwise.
     */
    ErrCode GetContinueBundleNames(
        const std::string &continueBundleName, std::vector<std::string> &bundleNames, int32_t userId);
    void HandleOTACodeEncryption();
    bool HasAppOrAtomicServiceInUser(const std::string &bundleName, int32_t userId) const;
    bool GetAllAppAndAtomicServiceInUser(int32_t userId, std::vector<std::string> &bundleList) const;

    ErrCode IsBundleInstalled(const std::string &bundleName, int32_t userId, int32_t appIndex, bool &isInstalled);
    void CreateEl5Dir(const std::vector<CreateDirParam> &el5Params, bool needSaveStorage = false);
    void CreateEl5DirNoCache(const std::vector<CreateDirParam> &el5Params, InnerBundleInfo &info);
    int32_t GetUidByBundleName(const std::string &bundleName, int32_t userId, int32_t appIndex) const;
    ErrCode GetBundleNameByAppId(const std::string &appId, std::string &bundleName);
    ErrCode GetAllPluginInfo(const std::string &hostBundleName, int32_t userId,
        std::vector<PluginBundleInfo> &pluginBundleInfos) const;
    ErrCode GetDirForAtomicService(const std::string &bundleName, std::string &dataDir) const;
    ErrCode GetDirForAtomicServiceByUserId(const std::string &bundleName, int32_t userId,
        AccountSA::OhosAccountInfo &accountInfo, std::string &dataDir) const;
    std::string GetDirForApp(const std::string &bundleName, const int32_t appIndex) const;
    ErrCode GetDirByBundleNameAndAppIndex(const std::string &bundleName, const int32_t appIndex,
        std::string &dataDir);
    std::vector<int32_t> GetCloneAppIndexesByInnerBundleInfo(const InnerBundleInfo &innerBundleInfo,
        int32_t userId) const;
    ErrCode GetBundleDir(int32_t userId, BundleType type, AccountSA::OhosAccountInfo &accountInfo,
        BundleDir &bundleDir) const;
    ErrCode GetAllBundleDirs(int32_t userId, std::vector<BundleDir> &bundleDirs) const;
    ErrCode GetAssetAccessGroups(const std::string &bundleName, std::vector<std::string> &assetAccessGroups) const;
    ErrCode GetDeveloperId(const std::string &bundleName, std::string &developerId) const;
    ErrCode AddPluginInfo(const std::string &bundleName, const PluginBundleInfo &pluginBundleInfo,
        const int32_t userId);
    ErrCode RemovePluginInfo(const std::string &bundleName, const std::string &pluginBundleName,
        const int32_t userId);
    bool GetPluginBundleInfo(const std::string &hostBundleName, const std::string &pluginBundleName,
        const int32_t userId, PluginBundleInfo &pluginBundleInfo);
    bool FetchPluginBundleInfo(const std::string &hostBundleName, const std::string &pluginBundleName,
        PluginBundleInfo &pluginBundleInfo);
    ErrCode UpdatePluginBundleInfo(const std::string &hostBundleName, const PluginBundleInfo &pluginBundleInfo);
    ErrCode RemovePluginFromUserInfo(const std::string &hostBundleName, const std::string &pluginBundleName,
        const int32_t userId);
    ErrCode GetPluginAbilityInfo(const std::string &hostBundleName, const std::string &pluginBundleName,
        const std::string &pluginModuleName, const std::string &pluginAbilityName,
        const int32_t userId, AbilityInfo &abilityInfo);
    ErrCode GetPluginHapModuleInfo(const std::string &hostBundleName, const std::string &pluginBundleName,
        const std::string &pluginModuleName, const int32_t userId, HapModuleInfo &hapModuleInfo);
    ErrCode RegisterPluginEventCallback(const sptr<IBundleEventCallback> &pluginEventCallback);
    ErrCode UnregisterPluginEventCallback(const sptr<IBundleEventCallback> &pluginEventCallback);
    void NotifyPluginEventCallback(const EventFwk::CommonEventData &eventData);
    ErrCode GetDynamicIconInfo(const std::string &bundleName, std::vector<DynamicIconInfo> &dynamicIconInfos);
    void ProcessDynamicIconForOta();
    ErrCode GetAllDynamicIconInfo(const int32_t userId, std::vector<DynamicIconInfo> &dynamicIconInfos);
    std::string GetCurDynamicIconModule(const std::string &bundleName, const int32_t userId, const int32_t appIndex);
    ErrCode SetShortcutVisibleForSelf(const std::string &shortcutId, bool visible);
    ErrCode DeleteShortcutVisibleInfo(const std::string &bundleName, int32_t userId, int32_t appIndex);
    ErrCode GetAllShortcutInfoForSelf(std::vector<ShortcutInfo> &shortcutInfos);
    bool GreatOrEqualTargetAPIVersion(const int32_t platformVersion, const int32_t minorVersion,
        const int32_t patchVersion);
    ErrCode GetAllCloneAppIndexesAndUidsByInnerBundleInfo(const int32_t userId, std::unordered_map<std::string,
        std::vector<std::pair<int32_t, int32_t>>> &cloneInfos) const;
    void FilterShortcutJson(nlohmann::json &jsonResult);
    ErrCode IsSystemApp(const std::string &bundleName, bool &isSystemApp);
    void UpdateDesktopShortcutInfo(const std::string &bundleName);
    ErrCode GetPluginInfo(const std::string &hostBundleName, const std::string &pluginBundleName,
        const int32_t userId, PluginBundleInfo &pluginBundleInfo);
    bool SetBundleUserInfoRemovable(const std::string bundleName, int32_t userId, bool removable);
    ErrCode GetTestRunner(const std::string &bundleName, const std::string &moduleName, ModuleTestRunner &testRunner);
    ErrCode ImplicitQueryAbilityInfosWithDefault(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, AbilityInfo &defaultAbilityInfo, bool &findDefaultApp);
    void AddOtaNewInstallBundleName(const std::string &bundleName);
    std::set<std::string> GetOtaNewInstallBundleNames();
    void ClearOtaNewInstallBundleNames();

private:
    /**
     * @brief Init transferStates.
     * @return
     */
    void InitStateTransferMap();
    /**
     * @brief Determine whether to delete the data status.
     * @param state Indicates the InstallState object.
     * @return Returns true if state is INSTALL_FAIL，UNINSTALL_FAIL，UNINSTALL_SUCCESS，or UPDATING_FAIL; returns false
     * otherwise.
     */
    bool IsDeleteDataState(const InstallState state) const;
    /**
     * @brief Determine whether it is disable.
     * @param state Indicates the InstallState object.
     * @return Returns true if install state is UPDATING_START or UNINSTALL_START; returns false otherwise.
     */
    bool IsDisableState(const InstallState state) const;
    /**
     * @brief Delete bundle info if InstallState is not INSTALL_FAIL.
     * @param bundleName Indicates the bundle Names.
     * @param state Indicates the InstallState object.
     * @return Returns true if install state is UPDATING_START or UNINSTALL_START; returns false otherwise.
     */
    void DeleteBundleInfo(const std::string &bundleName, const InstallState state, const bool isKeepData = false);
    /**
     * @brief Implicit query abilityInfos by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param abilityInfos Indicates the obtained AbilityInfo of list.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    bool ImplicitQueryAbilityInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, int32_t appIndex = 0) const;
    ErrCode ImplicitQueryAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, int32_t appIndex = 0) const;
    bool CheckAbilityInfoFlagExist(int32_t flags, AbilityInfoFlag abilityInfoFlag) const;
    void GetMatchAbilityInfos(const Want &want, int32_t flags, const InnerBundleInfo &info,
        int32_t userId, std::vector<AbilityInfo> &abilityInfos,
        const std::vector<std::string> &paramMimeTypes, int32_t appIndex = 0) const;
    void AddSkillUrisInfo(const std::vector<Skill> &skills, std::vector<SkillUriForAbilityAndExtension> &skillUris,
        std::optional<size_t> matchSkillIndex, std::optional<size_t> matchUriIndex) const;
    void GetMatchAbilityInfosV9(const Want &want, int32_t flags, const InnerBundleInfo &info,
        int32_t userId, std::vector<AbilityInfo> &abilityInfos,
        const std::vector<std::string> &paramMimeTypes, int32_t appIndex = 0) const;
    bool ExplicitQueryAbilityInfo(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo,
        int32_t appIndex = 0) const;
    ErrCode ExplicitQueryAbilityInfoV9(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo,
        int32_t appIndex = 0) const;
    bool GenerateBundleId(const std::string &bundleName, int32_t &bundleId);
    int32_t GetUserIdByUid(int32_t uid) const;
    bool GetAllBundleInfos(int32_t flags, std::vector<BundleInfo> &bundleInfos) const;
    ErrCode GetAllBundleInfosV9(int32_t flags, std::vector<BundleInfo> &bundleInfos) const;
    bool ExplicitQueryExtensionInfo(const Want &want, int32_t flags, int32_t userId,
        ExtensionAbilityInfo &extensionInfo, int32_t appIndex = 0) const;
    bool ImplicitQueryExtensionInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex = 0) const;
    ErrCode ImplicitQueryExtensionInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex = 0) const;
    void GetMatchExtensionInfos(const Want &want, int32_t flags, const int32_t &userId, const InnerBundleInfo &info,
        std::vector<ExtensionAbilityInfo> &einfos, int32_t appIndex = 0) const;
    void GetMatchExtensionInfosV9(const Want &want, int32_t flags, int32_t userId, const InnerBundleInfo &info,
        std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex = 0) const;
    void GetAllExtensionInfos(uint32_t flags, int32_t userId, const InnerBundleInfo &info,
        std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex = 0) const;
    void GetOneExtensionInfosByExtensionTypeName(const std::string &typeName, uint32_t flags, int32_t userId,
        const InnerBundleInfo &info, std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex = 0) const;
    bool MatchUtd(Skill &skill, const std::string &utd, int32_t count) const;
    bool MatchUtd(const std::string &skillUtd, const std::string &wantUtd) const;
    bool MatchTypeWithUtd(const std::string &mimeType, const std::string &wantUtd) const;
    std::vector<int32_t> GetCloneAppIndexesNoLock(const std::string &bundleName, int32_t userId) const;
    void GetCloneAppInfo(const InnerBundleInfo &info, int32_t userId, int32_t flags,
        std::vector<ApplicationInfo> &appInfos) const;
    void GetCloneAppInfoV9(const InnerBundleInfo &info, int32_t userId, int32_t flags,
        std::vector<ApplicationInfo> &appInfos) const;
#ifdef GLOBAL_RESMGR_ENABLE
    std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager(const std::string &bundleName,
        const std::string &moduleName, int32_t userId, const std::string &localeInfo = Constants::EMPTY_STRING) const;
    std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager(const std::string &hapPath) const;
#endif

    void FilterAbilityInfosByModuleName(const std::string &moduleName, std::vector<AbilityInfo> &abilityInfos) const;
    void InnerCreateEl5Dir(const CreateDirParam &el5Param);
    void SetEl5DirPolicy(const CreateDirParam &el5Param, bool needSaveStorage);
    void SetEl5DirPolicy(const CreateDirParam &el5Param, InnerBundleInfo &info, std::string &keyId);

    void FilterExtensionAbilityInfosByModuleName(const std::string &moduleName,
        std::vector<ExtensionAbilityInfo> &extensionInfos) const;
    void CompatibleOldBundleStateInKvDb();
    void ResetBundleStateData();
    bool QueryAbilityInfoWithFlags(const std::optional<AbilityInfo> &option, int32_t flags, int32_t userId,
        const InnerBundleInfo &innerBundleInfo, AbilityInfo &info, int32_t appIndex = 0) const;
    ErrCode QueryAbilityInfoWithFlagsV9(const std::optional<AbilityInfo> &option, int32_t flags, int32_t userId,
        const InnerBundleInfo &innerBundleInfo, AbilityInfo &info,
        int32_t appIndex = 0) const;
    bool ImplicitQueryCurAbilityInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const;
    ErrCode ImplicitQueryCurAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const;
    void ImplicitQueryAllAbilityInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const;
    void ImplicitQueryAllAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const;
    bool ImplicitQueryCurExtensionInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const;
    ErrCode ImplicitQueryCurExtensionInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const;
    void ImplicitQueryAllExtensionInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const;
    void ImplicitQueryAllExtensionInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const;
    ErrCode ImplicitQueryAllExtensionInfos(uint32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex, const std::string &typeName = "") const;
    void GetMatchLauncherAbilityInfosForCloneInfos(const InnerBundleInfo& info, const AbilityInfo &abilityInfo,
        const InnerBundleUserInfo &bundleUserInfo, std::vector<AbilityInfo>& abilityInfos) const;
    void ModifyApplicationInfoByCloneInfo(const InnerBundleCloneInfo &cloneInfo,
        ApplicationInfo &applicationInfo) const;
    void ModifyBundleInfoByCloneInfo(const InnerBundleCloneInfo &cloneInfo, BundleInfo &bundleInfo) const;
    void GetCloneBundleInfos(const InnerBundleInfo& info, int32_t flags, int32_t userId,
        BundleInfo &bundleInfo, std::vector<BundleInfo> &bundleInfos) const;
    void GetBundleNameAndIndexByName(const std::string &keyName, std::string &bundleName, int32_t &appIndex) const;
    void GetCloneAbilityInfos(std::vector<AbilityInfo> &abilityInfos,
        const ElementName &element, int32_t flags, int32_t userId) const;
    void GetCloneAbilityInfosV9(std::vector<AbilityInfo> &abilityInfos,
        const ElementName &element, int32_t flags, int32_t userId) const;
    ErrCode ExplicitQueryCloneAbilityInfo(const ElementName &element, int32_t flags, int32_t userId,
        int32_t appIndex, AbilityInfo &abilityInfo) const;
    ErrCode ExplicitQueryCloneAbilityInfoV9(const ElementName &element, int32_t flags, int32_t userId,
        int32_t appIndex, AbilityInfo &abilityInfo) const;
    void ImplicitQueryCloneAbilityInfos(
        const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const;
    bool ImplicitQueryCurCloneAbilityInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos) const;
    void ImplicitQueryAllCloneAbilityInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos) const;
    void ImplicitQueryCloneAbilityInfosV9(
        const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const;
    bool ImplicitQueryCurCloneAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos) const;
    void ImplicitQueryAllCloneAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos) const;
    bool ImplicitQueryCurCloneExtensionAbilityInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &abilityInfos) const;
    ErrCode ImplicitQueryCurCloneExtensionAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &abilityInfos) const;
    bool ImplicitQueryAllCloneExtensionAbilityInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &infos) const;
    ErrCode ImplicitQueryAllCloneExtensionAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &abilityInfos) const;
    ErrCode CheckInnerBundleInfoWithFlags(
        const InnerBundleInfo &innerBundleInfo, const int32_t flags, int32_t userId, int32_t appIndex = 0) const;
    ErrCode CheckInnerBundleInfoWithFlagsV9(
        const InnerBundleInfo &innerBundleInfo, const int32_t flags, int32_t userId, int32_t appIndex = 0) const;
    ErrCode CheckBundleAndAbilityDisabled(const InnerBundleInfo &info, int32_t flags, int32_t userId) const;
    void AddAppDetailAbilityInfo(InnerBundleInfo &info) const;
    void GetAllLauncherAbility(const Want &want, std::vector<AbilityInfo> &abilityInfos,
        const int32_t userId, const int32_t requestUserId) const;
    ErrCode GetLauncherAbilityByBundleName(const Want &want, std::vector<AbilityInfo> &abilityInfos,
        const int32_t userId, const int32_t requestUserId) const;
    void ModifyLauncherAbilityInfo(bool isStage, AbilityInfo &abilityInfo) const;
    bool MatchPrivateType(const Want &want, const std::vector<std::string> &supportExtNames,
        const std::vector<std::string> &supportMimeTypes, const std::vector<std::string> &paramMimeTypes) const;
    bool UpdateOverlayInfo(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);
    void ResetExternalOverlayModuleState(const std::string &bundleName, const std::string &modulePackage);
    void BuildExternalOverlayConnection(const std::string &moduleName, InnerBundleInfo &oldInfo, int32_t userId);
    void RemoveOverlayInfoAndConnection(const InnerBundleInfo &innerBundleInfo, const std::string &bundleName);
    ErrCode FindAbilityInfoInBundleInfo(const InnerBundleInfo &innerBundleInfo, const std::string &moduleName,
        const std::string &abilityName, AbilityInfo &abilityInfo) const;
    void RestoreSandboxUidAndGid(std::map<int32_t, std::string> &bundleIdMap);
    bool IsUpdateInnerBundleInfoSatisified(const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo) const;
    ErrCode ProcessBundleMenu(BundleInfo& bundleInfo, int32_t flag, bool clearData) const;
    bool MatchShare(const Want &want, const std::vector<Skill> &skills) const;
    std::vector<Skill> FindSkillsContainShareAction(const std::vector<Skill> &skills) const;
    void EmplaceExtensionInfo(const InnerBundleInfo &info, const std::vector<Skill> &skills,
        ExtensionAbilityInfo &extensionInfo, int32_t flags, int32_t userId, std::vector<ExtensionAbilityInfo> &infos,
        std::optional<size_t> matchSkillIndex, std::optional<size_t> matchUriIndex, int32_t appIndex = 0) const;
    void EmplaceAbilityInfo(const InnerBundleInfo &info, const std::vector<Skill> &skills, AbilityInfo &abilityInfo,
        int32_t flags, int32_t userId, std::vector<AbilityInfo> &infos,
        std::optional<size_t> matchSkillIndex, std::optional<size_t> matchUriIndex, int32_t appIndex = 0) const;
    void AddAppHspBundleName(const BundleType type, const std::string &bundleName);
    void ConvertServiceHspToSharedBundleInfo(const InnerBundleInfo &innerBundleInfo,
        std::vector<BaseSharedBundleInfo> &baseSharedBundleInfos) const;
    void ProcessBundleRouterMap(BundleInfo& bundleInfo, int32_t flag) const;
    void ProcessAllowedAcls(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo) const;
    void ProcessCertificate(BundleInfo& bundleInfo, const std::string &bundleName, int32_t flags) const;
    void FilterAbilityInfosByAppLinking(const Want &want, int32_t flags,
        std::vector<AbilityInfo> &abilityInfos) const;
    void GetMultiLauncherAbilityInfo(const Want& want,
        const InnerBundleInfo& info, const InnerBundleUserInfo &bundleUserInfo,
        int64_t installTime, std::vector<AbilityInfo>& abilityInfos) const;
    void CreateNewDataGroupInfo(const std::string &groupId, const int32_t userId,
        const DataGroupInfo &oldDataGroupInfo, DataGroupInfo &newDataGroupInfo);
    ErrCode CreateEl5GroupDirs(const std::vector<DataGroupInfo> &dataGroupInfos, int32_t userId);
    ErrCode CreateGroupDirs(const std::vector<DataGroupInfo> &dataGroupInfos, int32_t userId,
        bool needCreateEl5Dir);
    bool CreateAppGroupDir(const InnerBundleInfo &info, int32_t userId);

    void PreProcessAnyUserFlag(const std::string &bundleName, int32_t& flags, int32_t &userId) const;
    void PostProcessAnyUserFlags(int32_t flags, int32_t userId,
        int32_t originalUserId, BundleInfo &bundleInfo, const InnerBundleInfo &innerBundleInfo) const;
    void GetExtensionAbilityInfoByTypeName(uint32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &infos, const std::string &typeName) const;
    bool GetShortcutInfosByInnerBundleInfo(
        const InnerBundleInfo &info, std::vector<ShortcutInfo> &shortcutInfos) const;
    std::string TryGetRawDataByExtractor(const std::string &hapPath, const std::string &profileName,
        const AbilityInfo &abilityInfo) const;
    void RestoreUidAndGidFromUninstallInfo();
    std::string GenerateUuid() const;
    std::string GenerateUuidByKey(const std::string &key) const;
    bool CheckUpdateTimeWithBmsParam(const int64_t updateTime) const;
    bool InnerProcessShortcutId(const int64_t updateTime, const std::string &hapPath,
        std::vector<ShortcutInfo> &shortcutInfos) const;
    void GetPreBundleSize(const std::string &name, std::vector<BundleStorageStats> &bundleStats) const;
    bool GetAdaptBaseShareBundleInfo(const InnerBundleInfo &innerBundleInfo, const Dependency &dependency,
        BaseSharedBundleInfo &baseSharedBundleInfo) const;

private:
    bool initialUserFlag_ = false;
    int32_t baseAppUid_ = Constants::BASE_APP_UID;
    mutable ffrt::mutex stateMutex_;
    mutable ffrt::mutex multiUserIdSetMutex_;
    mutable ffrt::mutex hspBundleNameMutex_;
    mutable ffrt::mutex pluginCallbackMutex_;
    mutable ffrt::mutex eventCallbackMutex_;
    mutable ffrt::shared_mutex bundleInfoMutex_;
    mutable ffrt::shared_mutex bundleIdMapMutex_;
    mutable ffrt::shared_mutex callbackMutex_;
    mutable ffrt::shared_mutex bundleMutex_;
    mutable ffrt::shared_mutex otaNewInstallMutex_;
    std::shared_ptr<IBundleDataStorage> dataStorage_;
    std::shared_ptr<IPreInstallDataStorage> preInstallDataStorage_;
    std::shared_ptr<BundleStateStorage> bundleStateStorage_;
    std::shared_ptr<BundlePromise> bundlePromise_ = nullptr;
    std::shared_ptr<BundleSandboxAppHelper> sandboxAppHelper_;
    std::shared_ptr<IShortcutDataStorage> shortcutStorage_;
    std::shared_ptr<IRouterDataStorage> routerStorage_;
    std::shared_ptr<UninstallDataMgrStorageRdb> uninstallDataMgr_;
    std::shared_ptr<FirstInstallDataMgrStorageRdb> firstInstallDataMgr_;
    std::shared_ptr<ShortcutVisibleDataStorageRdb> shortcutVisibleStorage_;
    // use vector because these functions using for IPC, the bundleName may duplicate
    std::vector<sptr<IBundleStatusCallback>> callbackList_;
    // common event callback
    std::vector<sptr<IBundleEventCallback>> eventCallbackList_;
    // using for locking by bundleName
    std::unordered_map<std::string, ffrt::mutex> bundleMutexMap_;
    // using for generating bundleId
    // key:bundleId
    // value:bundleName
    std::map<int32_t, std::string> bundleIdMap_;
    // all installed bundles
    // key:bundleName
    // value:innerbundleInfo
    std::map<std::string, InnerBundleInfo> bundleInfos_;
    // key:bundle name
    std::map<std::string, InstallState> installStates_;
    // current-status:previous-statue pair
    std::multimap<InstallState, InstallState> transferStates_;
    // save all created users.
    std::set<int32_t> multiUserIdsSet_;
    std::set<std::string> appServiceHspBundleName_;
    // using for plugin event callback
    std::vector<sptr<IBundleEventCallback>> pluginCallbackList_;
    std::set<std::string> otaNewInstallBundleNames_;

    static bool HasAppLinkingFlag(uint32_t flags);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_DATA_MGR_H
