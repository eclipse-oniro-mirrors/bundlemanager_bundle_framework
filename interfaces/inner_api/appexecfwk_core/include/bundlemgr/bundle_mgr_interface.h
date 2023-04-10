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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_INTERFACE_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_INTERFACE_H

#include "ability_info.h"
#include "appexecfwk_errors.h"
#include "application_info.h"
#include "bundle_constants.h"
#include "bundle_event_callback_interface.h"
#include "bundle_info.h"
#include "bundle_pack_info.h"
#include "bundle_installer_interface.h"
#include "bundle_status_callback_interface.h"
#include "bundle_user_mgr_interface.h"
#include "clean_cache_callback_interface.h"
#include "common_event_info.h"
#include "../app_control/app_control_interface.h"
#include "../default_app/default_app_interface.h"
#include "../quick_fix/quick_fix_manager_interface.h"
#include "distributed_bundle_info.h"
#include "form_info.h"
#include "hap_module_info.h"
#include "module_usage_record.h"
#include "permission_define.h"
#include "shortcut_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
enum class DumpFlag {
    DUMP_BUNDLE_LIST = 1,  // corresponse to option "-bundle-list"
    DUMP_BUNDLE_INFO,      // corresponse to option "-bundle [name]"
    DUMP_SHORTCUT_INFO,    // corresponse to option "-bundle [name] -shortcut-info"
};

class IBundleMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.BundleMgr");

    using Want = OHOS::AAFwk::Want;
    /**
     * @brief Obtains the ApplicationInfo based on a given bundle name.
     * @param appName Indicates the application bundle name to be queried.
     * @param flag Indicates the flag used to specify information contained
     *             in the ApplicationInfo object that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfo Indicates the obtained ApplicationInfo object.
     * @return Returns true if the application is successfully obtained; returns false otherwise.
     */
    virtual bool GetApplicationInfo(
        const std::string &appName, const ApplicationFlag flag, const int userId, ApplicationInfo &appInfo)
    {
        return false;
    }
    /**
     * @brief Obtains the ApplicationInfo based on a given bundle name.
     * @param appName Indicates the application bundle name to be queried.
     * @param flags Indicates the flag used to specify information contained
     *             in the ApplicationInfo object that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfo Indicates the obtained ApplicationInfo object.
     * @return Returns true if the application is successfully obtained; returns false otherwise.
     */
    virtual bool GetApplicationInfo(
        const std::string &appName, int32_t flags, int32_t userId, ApplicationInfo &appInfo)
    {
        return false;
    }
    /**
     * @brief Obtains the ApplicationInfo based on a given bundle name.
     * @param appName Indicates the application bundle name to be queried.
     * @param flag Indicates the flag used to specify information contained
     *             in the ApplicationInfo object that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfo Indicates the obtained ApplicationInfo object.
     * @return Returns ERR_OK if the application is successfully obtained; returns error code otherwise.
     */
    virtual ErrCode GetApplicationInfoV9(
        const std::string &appName, int32_t flag, int32_t userId, ApplicationInfo &appInfo)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Obtains information about all installed applications of a specified user.
     * @param flag Indicates the flag used to specify information contained
     *             in the ApplicationInfo objects that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfos Indicates all of the obtained ApplicationInfo objects.
     * @return Returns true if the application is successfully obtained; returns false otherwise.
     */
    virtual bool GetApplicationInfos(
        const ApplicationFlag flag, int userId, std::vector<ApplicationInfo> &appInfos)
    {
        return false;
    }
    /**
     * @brief Obtains information about all installed applications of a specified user.
     * @param flags Indicates the flag used to specify information contained
     *             in the ApplicationInfo objects that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfos Indicates all of the obtained ApplicationInfo objects.
     * @return Returns true if the application is successfully obtained; returns false otherwise.
     */
    virtual bool GetApplicationInfos(
        int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos)
    {
        return false;
    }
    /**
     * @brief Obtains information about all installed applications of a specified user.
     * @param flags Indicates the flag used to specify information contained
     *             in the ApplicationInfo objects that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfos Indicates all of the obtained ApplicationInfo objects.
     * @return Returns ERR_OK if the application is successfully obtained; returns error code otherwise.
     */
    virtual ErrCode GetApplicationInfosV9(
        int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Obtains the BundleInfo based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flag Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @param userId Indicates the user ID.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleInfo(const std::string &bundleName, const BundleFlag flag,
        BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return false;
    }
    /**
     * @brief Obtains the BundleInfo based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @param userId Indicates the user ID.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleInfo(const std::string &bundleName, int32_t flags,
        BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return false;
    }
    /**
     * @brief Obtains the BundleInfo based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if the BundleInfo is successfully obtained; returns error code otherwise.
     */
    virtual ErrCode GetBundleInfoV9(const std::string &bundleName, int32_t flags,
        BundleInfo &bundleInfo, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Obtains the BundleInfo for the calling app.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if the BundleInfo is successfully obtained; returns error code otherwise.
     */
    virtual ErrCode GetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Obtains the BundlePackInfo based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param BundlePackInfo Indicates the obtained BundlePackInfo object.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if the BundlePackInfo is successfully obtained; returns other ErrCode otherwise.
     */
    virtual ErrCode GetBundlePackInfo(const std::string &bundleName, const BundlePackFlag flag,
        BundlePackInfo &bundlePackInfo, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    /**
     * @brief Obtains the BundlePackInfo based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param BundlePackInfo Indicates the obtained BundlePackInfo object.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if the BundlePackInfo is successfully obtained; returns other ErrCode otherwise.
     */
    virtual ErrCode GetBundlePackInfo(const std::string &bundleName, int32_t flags,
        BundlePackInfo &bundlePackInfo, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    /**
     * @brief Obtains BundleInfo of all bundles available in the system.
     * @param flag Indicates the flag used to specify information contained in the BundleInfo that will be returned.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @param userId Indicates the user ID.
     * @return Returns true if the BundleInfos is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleInfos(const BundleFlag flag,
        std::vector<BundleInfo> &bundleInfos, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return false;
    }
    /**
     * @brief Obtains BundleInfo of all bundles available in the system.
     * @param flags Indicates the flag used to specify information contained in the BundleInfo that will be returned.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @param userId Indicates the user ID.
     * @return Returns true if the BundleInfos is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleInfos(int32_t flags,
        std::vector<BundleInfo> &bundleInfos, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return false;
    }
    /**
     * @brief Obtains BundleInfo of all bundles available in the system.
     * @param flags Indicates the flag used to specify information contained in the BundleInfo that will be returned.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if the BundleInfos is successfully obtained; returns error code otherwise.
     */
    virtual ErrCode GetBundleInfosV9(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Obtains the application UID based on the given bundle name and user ID.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user ID.
     * @return Returns the uid if successfully obtained; returns -1 otherwise.
     */
    virtual int GetUidByBundleName(const std::string &bundleName, const int userId)
    {
        return Constants::INVALID_UID;
    }
    /**
     * @brief Obtains the debug application UID based on the given bundle name and user ID.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user ID.
     * @return Returns the uid if successfully obtained; returns -1 otherwise.
     */
    virtual int GetUidByDebugBundleName(const std::string &bundleName, const int userId)
    {
        return Constants::INVALID_UID;
    }
    /**
     * @brief Obtains the application ID based on the given bundle name and user ID.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user ID.
     * @return Returns the application ID if successfully obtained; returns empty string otherwise.
     */
    virtual std::string GetAppIdByBundleName(const std::string &bundleName, const int userId)
    {
        return Constants::EMPTY_STRING;
    }
    /**
     * @brief Obtains the bundle name of a specified application based on the given UID.
     * @param uid Indicates the uid.
     * @param bundleName Indicates the obtained bundle name.
     * @return Returns true if the bundle name is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleNameForUid(const int uid, std::string &bundleName)
    {
        return false;
    }
    /**
     * @brief Obtains all bundle names of a specified application based on the given application UID.
     * @param uid Indicates the uid.
     * @param bundleNames Indicates the obtained bundle names.
     * @return Returns true if the bundle names is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundlesForUid(const int uid, std::vector<std::string> &bundleNames)
    {
        return false;
    }
    /**
     * @brief Obtains the formal name associated with the given UID.
     * @param uid Indicates the uid.
     * @param name Indicates the obtained formal name.
     * @return Returns ERR_OK if execute success; returns errCode otherwise.
     */
    virtual ErrCode GetNameForUid(const int uid, std::string &name)
    {
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    /**
     * @brief Obtains an array of all group IDs associated with a specified bundle.
     * @param bundleName Indicates the bundle name.
     * @param gids Indicates the group IDs associated with the specified bundle.
     * @return Returns true if the gids is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleGids(const std::string &bundleName, std::vector<int> &gids)
    {
        return false;
    }
    /**
     * @brief Obtains an array of all group IDs associated with the given bundle name and UID.
     * @param bundleName Indicates the bundle name.
     * @param uid Indicates the uid.
     * @param gids Indicates the group IDs associated with the specified bundle.
     * @return Returns true if the gids is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleGidsByUid(const std::string &bundleName, const int &uid, std::vector<int> &gids)
    {
        return false;
    }
    /**
     * @brief Obtains the type of a specified application based on the given bundle name.
     * @param bundleName Indicates the bundle name.
     * @return Returns "system" if the bundle is a system application; returns "third-party" otherwise.
     */
    virtual std::string GetAppType(const std::string &bundleName)
    {
        return Constants::EMPTY_STRING;
    }
    /**
     * @brief Check whether the app is system app by it's UID.
     * @param uid Indicates the uid.
     * @return Returns true if the bundle is a system application; returns false otherwise.
     */
    virtual bool CheckIsSystemAppByUid(const int uid)
    {
        return false;
    }
    /**
     * @brief Obtains the BundleInfo of application bundles based on the specified metaData.
     * @param metaData Indicates the metadata to get in the bundle.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @return Returns true if the BundleInfos is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleInfosByMetaData(const std::string &metaData, std::vector<BundleInfo> &bundleInfos)
    {
        return false;
    }
    /**
     * @brief Query the AbilityInfo by the given Want.
     * @param want Indicates the information of the ability.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    virtual bool QueryAbilityInfo(const Want &want, AbilityInfo &abilityInfo)
    {
        return false;
    }
    /**
     * @brief Query the AbilityInfo by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @param callBack Indicates the callback to be invoked for return ability manager service the operation result.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    virtual bool QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo,
        const sptr<IRemoteObject> &callBack)
    {
        return false;
    }
    /**
     * @brief Silent install by the given Want.
     * @param want Indicates the information of the want.
     * @param userId Indicates the user ID.
     * @param callBack Indicates the callback to be invoked for return the operation result.
     * @return Returns true if silent install successfully; returns false otherwise.
     */
    virtual bool SilentInstall(const Want &want, int32_t userId, const sptr<IRemoteObject> &callBack)
    {
        return false;
    }
    /**
     * @brief Upgrade atomic service
     * @param want Indicates the information of the ability.
     * @param userId Indicates the user ID.
     */
    virtual void UpgradeAtomicService(const Want &want, int32_t userId)
    {
        return;
    }
    /**
     * @brief Query the AbilityInfo by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    virtual bool QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo)
    {
        return false;
    }
    /**
     * @brief Query the AbilityInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param abilityInfos Indicates the obtained AbilityInfos object.
     * @return Returns true if the AbilityInfos is successfully obtained; returns false otherwise.
     */
    virtual bool QueryAbilityInfos(const Want &want, std::vector<AbilityInfo> &abilityInfos)
    {
        return false;
    }
    /**
     * @brief Query the AbilityInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param abilityInfos Indicates the obtained AbilityInfos object.
     * @return Returns true if the AbilityInfos is successfully obtained; returns false otherwise.
     */
    virtual bool QueryAbilityInfos(
        const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
    {
        return false;
    }
    /**
     * @brief Query the AbilityInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param flags Indicates the information contained in the AbilityInfo object to be returned.
     * @param userId Indicates the user ID.
     * @param abilityInfos Indicates the obtained AbilityInfos object.
     * @return Returns ERR_OK if the AbilityInfos is successfully obtained; returns errCode otherwise.
     */
    virtual ErrCode QueryAbilityInfosV9(
        const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
    {
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    /**
     * @brief Query the AllAbilityInfos of list by the given userId.
     * @param userId Indicates the information of the user.
     * @param abilityInfos Indicates the obtained AbilityInfos object.
     * @return Returns true if the AbilityInfos is successfully obtained; returns false otherwise.
     */
    virtual bool QueryAllAbilityInfos(const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
    {
        return false;
    }
    /**
     * @brief Query the AbilityInfo by ability.uri in config.json.
     * @param abilityUri Indicates the uri of the ability.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    virtual bool QueryAbilityInfoByUri(const std::string &abilityUri, AbilityInfo &abilityInfo)
    {
        return false;
    }
    /**
     * @brief Query the AbilityInfo by ability.uri in config.json.
     * @param abilityUri Indicates the uri of the ability.
     * @param userId Indicates the user ID.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    virtual bool QueryAbilityInfoByUri(const std::string &abilityUri, int32_t userId, AbilityInfo &abilityInfo)
    {
        return true;
    };
    /**
     * @brief Query the AbilityInfo by ability.uri in config.json.
     * @param abilityUri Indicates the uri of the ability.
     * @param abilityInfos Indicates the obtained AbilityInfos object.
     * @return Returns true if the AbilityInfo is successfully obtained; returns false otherwise.
     */
    virtual bool QueryAbilityInfosByUri(const std::string &abilityUri, std::vector<AbilityInfo> &abilityInfos)
    {
        return false;
    }
    /**
     * @brief Obtains the BundleInfo of all keep-alive applications in the system.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @return Returns true if the BundleInfos is successfully obtained; returns false otherwise.
     */
    virtual bool QueryKeepAliveBundleInfos(std::vector<BundleInfo> &bundleInfos)
    {
        return false;
    }
    /**
     * @brief Obtains the label of a specified ability.
     * @param bundleName Indicates the bundle name.
     * @param abilityName Indicates the ability name.
     * @return Returns the label of the ability if exist; returns empty string otherwise.
     */
    virtual std::string GetAbilityLabel(const std::string &bundleName, const std::string &abilityName)
    {
        return Constants::EMPTY_STRING;
    }
    /**
     * @brief Obtains the label of a specified ability.
     * @param bundleName Indicates the bundle name.
     * @param moduleName Indicates the module name.
     * @param abilityName Indicates the ability name.
     * @param label Indicates the obtained label.
     * @return Returns ERR_OK if called successfully; returns error code otherwise.
     */
    virtual ErrCode GetAbilityLabel(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, std::string &label)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Obtains information about an application bundle contained in an ohos Ability Package (HAP).
     * @param hapFilePath Indicates the absolute file path of the HAP.
     * @param flag Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleArchiveInfo(
        const std::string &hapFilePath, const BundleFlag flag, BundleInfo &bundleInfo)
    {
        return false;
    }
    /**
     * @brief Obtains information about an application bundle contained in an ohos Ability Package (HAP).
     * @param hapFilePath Indicates the absolute file path of the HAP.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    virtual bool GetBundleArchiveInfo(
        const std::string &hapFilePath, int32_t flags, BundleInfo &bundleInfo)
    {
        return false;
    }
    /**
     * @brief Obtains information about an application bundle contained in an ohos Ability Package (HAP).
     * @param hapFilePath Indicates the absolute file path of the HAP.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @return Returns ERR_OK if this function is successfully called; returns errCode otherwise.
     */
    virtual ErrCode GetBundleArchiveInfoV9(
        const std::string &hapFilePath, int32_t flags, BundleInfo &bundleInfo)
    {
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    /**
     * @brief Obtain the HAP module info of a specific ability.
     * @param abilityInfo Indicates the ability.
     * @param hapModuleInfo Indicates the obtained HapModuleInfo object.
     * @return Returns true if the HapModuleInfo is successfully obtained; returns false otherwise.
     */
    virtual bool GetHapModuleInfo(const AbilityInfo &abilityInfo, HapModuleInfo &hapModuleInfo)
    {
        return false;
    }
    /**
     * @brief Obtain the HAP module info of a specific ability.
     * @param abilityInfo Indicates the ability.
     * @param userId Indicates the userId.
     * @param hapModuleInfo Indicates the obtained HapModuleInfo object.
     * @return Returns true if the HapModuleInfo is successfully obtained; returns false otherwise.
     */
    virtual bool GetHapModuleInfo(const AbilityInfo &abilityInfo, int32_t userId, HapModuleInfo &hapModuleInfo)
    {
        return false;
    }
    /**
     * @brief Obtains the Want for starting the main ability of an application based on the given bundle name.
     * @param bundleName Indicates the bundle name.
     * @param want Indicates the obtained launch Want object.
     * @param userId Indicates the userId.
     * @return Returns ERR_OK if this function is successfully called; returns errCode otherwise.
     */
    virtual ErrCode GetLaunchWantForBundle(
        const std::string &bundleName, Want &want, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Checks whether the publickeys of two bundles are the same.
     * @param firstBundleName Indicates the first bundle name.
     * @param secondBundleName Indicates the second bundle name.
     * @return Returns SIGNATURE_UNKNOWN_BUNDLE if at least one of the given bundles is not found;
     *         returns SIGNATURE_NOT_MATCHED if their publickeys are different;
     *         returns SIGNATURE_MATCHED if their publickeys are the same.
     */
    virtual int CheckPublicKeys(const std::string &firstBundleName, const std::string &secondBundleName)
    {
        return Constants::SIGNATURE_UNKNOWN_BUNDLE;
    }
    /**
     * @brief Obtains detailed information about a specified permission.
     * @param permissionName Indicates the name of the ohos permission.
     * @param permissionDef Indicates the object containing detailed information about the given ohos permission.
     * @return Returns ERR_OK if the PermissionDef object is successfully obtained; returns other ErrCode otherwise.
     */
    virtual ErrCode GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
    {
        return ERR_OK;
    }
    /**
     * @brief Checks whether the system has a specified capability.
     * @param capName Indicates the name of the system feature to check.
     * @return Returns true if the given feature specified by name is available in the system; returns false otherwise.
     */
    virtual bool HasSystemCapability(const std::string &capName)
    {
        return false;
    }
    /**
     * @brief Obtains the capabilities that are available in the system.
     * @param systemCaps Indicates the list of capabilities available in the system.
     * @return Returns true if capabilities in the system are successfully obtained; returns false otherwise.
     */
    virtual bool GetSystemAvailableCapabilities(std::vector<std::string> &systemCaps)
    {
        return false;
    }
    /**
     * @brief Checks whether the current device has been started in safe mode.
     * @return Returns true if the device is in safe mode; returns false otherwise.
     */
    virtual bool IsSafeMode()
    {
        return false;
    }
    /**
     * @brief Clears cache data of a specified application.
     * @param bundleName Indicates the bundle name of the application whose cache data is to be cleared.
     * @param cleanCacheCallback Indicates the callback to be invoked for returning the operation result.
     * @param userId description the user id.
     * @return Returns ERR_OK if this function is successfully called; returns other ErrCode otherwise.
     */
    virtual ErrCode CleanBundleCacheFiles(
        const std::string &bundleName, const sptr<ICleanCacheCallback> &cleanCacheCallback,
        int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Clears application running data of a specified application.
     * @param bundleName Indicates the bundle name of the application whose data is to be cleared.
     * @param userId Indicates the user id.
     * @return Returns true if the data cleared successfully; returns false otherwise.
     */
    virtual bool CleanBundleDataFiles(const std::string &bundleName, const int userId = 0)
    {
        return false;
    }
    /**
     * @brief Register the specific bundle status callback.
     * @param bundleStatusCallback Indicates the callback to be invoked for returning the bundle status changed result.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool RegisterBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
    {
        return false;
    }

    virtual bool RegisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback)
    {
        return false;
    }

    virtual bool UnregisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback)
    {
        return false;
    }
    /**
     * @brief Clear the specific bundle status callback.
     * @param bundleStatusCallback Indicates the callback to be cleared.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool ClearBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
    {
        return false;
    }
    /**
     * @brief Unregister all the callbacks of status changed.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool UnregisterBundleStatusCallback()
    {
        return false;
    }

    /**
     * @brief Obtains the value of isRemovable based on a given bundle name and module name.
     * @param bundleName Indicates the bundle name to be queried.
     * @param moduleName Indicates the module name to be queried.
     * @param isRemovable Indicates the module whether is removable.
     * @return Returns ERR_OK if the isRemovable is successfully obtained; returns other ErrCode otherwise.
     */
    virtual ErrCode IsModuleRemovable(const std::string &bundleName, const std::string &moduleName, bool &isRemovable)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Sets whether to enable isRemovable based on a given bundle name and module name.
     * @param bundleName Indicates the bundle name to be queried.
     * @param moduleName Indicates the module name to be queried.
     * @param isEnable Specifies whether to enable the isRemovable of InnerModuleInfo.
     *                 The value true means to enable it, and the value false means to disable it
     * @return Returns true if the isRemovable is successfully obtained; returns false otherwise.
     */
    virtual bool SetModuleRemovable(
        const std::string &bundleName, const std::string &moduleName, bool isEnable)
    {
        return false;
    }

    /**
     * @brief Dump the bundle informations with specific flags.
     * @param flag Indicates the information contained in the dump result.
     * @param bundleName Indicates the bundle name if needed.
     * @param userId Indicates the user ID.
     * @param result Indicates the dump information result.
     * @return Returns true if the dump result is successfully obtained; returns false otherwise.
     */
    virtual bool DumpInfos(
        const DumpFlag flag, const std::string &bundleName, int32_t userId, std::string &result)
    {
        return false;
    }
    /**
     * @brief Checks whether a specified application is enabled.
     * @param bundleName Indicates the bundle name of the application.
     * @param isEnable Indicates the application status is enabled.
     * @return Returns result of the operation.
     */
    virtual ErrCode IsApplicationEnabled(const std::string &bundleName, bool &isEnable)
    {
        return ERR_OK;
    }
    /**
     * @brief Sets whether to enable a specified application.
     * @param bundleName Indicates the bundle name of the application.
     * @param isEnable Specifies whether to enable the application.
     *                 The value true means to enable it, and the value false means to disable it.
     * @param userId description the user id.
     * @return Returns result of the operation.
     */
    virtual ErrCode SetApplicationEnabled(const std::string &bundleName, bool isEnable,
        int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_OK;
    }
    /**
     * @brief Sets whether to enable a specified ability.
     * @param abilityInfo Indicates information about the ability to check.
     * @param isEnable Indicates the ability status is enabled.
     * @return Returns result of the operation.
     */
    virtual ErrCode IsAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable)
    {
        return ERR_OK;
    }
    /**
     * @brief Sets whether to enable a specified ability.
     * @param abilityInfo Indicates information about the ability.
     * @param isEnabled Specifies whether to enable the ability.
     *                 The value true means to enable it, and the value false means to disable it.
     * @param userId description the user id.
     * @return Returns result of the operation.
     */
    virtual ErrCode SetAbilityEnabled(const AbilityInfo &abilityInfo, bool isEnabled,
        int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_OK;
    }
    /**
     * @brief Obtains the FormInfo objects provided by all applications on the device.
     * @param formInfo list of FormInfo objects if obtained; returns an empty List if no FormInfo is available on the
     * device.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool GetAllFormsInfo(std::vector<FormInfo> &formInfos)
    {
        return false;
    }
    /**
     * @brief Obtains the FormInfo objects provided by a specified application on the device.
     * @param bundleName Indicates the bundle name of the application.
     * @param formInfo list of FormInfo objects if obtained; returns an empty List if no FormInfo is available on the
     * device.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos)
    {
        return false;
    }
    /**
     * @brief Obtains the FormInfo objects provided by a specified.
     * @param formInfo list of FormInfo objects if obtained; returns an empty List if no FormInfo is available on the
     * device.
     * @param moduleName Indicates the module name of the application.
     * @param bundleName Indicates the bundle name of the application.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool GetFormsInfoByModule(
        const std::string &bundleName, const std::string &moduleName, std::vector<FormInfo> &formInfos)
    {
        return false;
    }
    /**
     * @brief Obtains the ShortcutInfo objects provided by a specified application on the device.
     * @param bundleName Indicates the bundle name of the application.
     * @param shortcutInfos List of ShortcutInfo objects if obtained.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool GetShortcutInfos(const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfos)
    {
        return false;
    }

    virtual ErrCode GetShortcutInfoV9(const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfos)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    /**
     * @brief Obtains the CommonEventInfo objects provided by an event key on the device.
     * @param eventKey Indicates the event of the subscribe.
     * @param commonEventInfos List of CommonEventInfo objects if obtained.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool GetAllCommonEventInfo(const std::string &eventKey, std::vector<CommonEventInfo> &commonEventInfos)
    {
        return false;
    }
    /**
     * @brief Obtains the interface used to install and uninstall bundles.
     * @return Returns a pointer to IBundleInstaller class if exist; returns nullptr otherwise.
     */
    virtual sptr<IBundleInstaller> GetBundleInstaller()
    {
        return nullptr;
    }
    /**
     * @brief Obtains the interface used to create or delete user.
     * @return Returns a pointer to IBundleUserMgr class if exist; returns nullptr otherwise.
     */
    virtual sptr<IBundleUserMgr> GetBundleUserMgr()
    {
        return nullptr;
    }
    /**
     * @brief Obtains the DistributedBundleInfo based on a given bundle name and networkId.
     * @param networkId Indicates the networkId of remote device.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param distributedBundleInfo Indicates the obtained DistributedBundleInfo object.
     * @return Returns true if the DistributedBundleInfo is successfully obtained; returns false otherwise.
     */
    virtual bool GetDistributedBundleInfo(const std::string &networkId, const std::string &bundleName,
        DistributedBundleInfo &distributedBundleInfo)
    {
        return false;
    }
    /**
     * @brief Get app privilege level.
     * @param bundleName Indicates the bundle name of the app privilege level.
     * @param userId Indicates the user id.
     * @return Returns app privilege level.
     */
    virtual std::string GetAppPrivilegeLevel(
        const std::string &bundleName, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return Constants::EMPTY_STRING;
    }
    /**
     * @brief Query extension info.
     * @param Want Indicates the information of extension info.
     * @param flag Indicates the query flag which will fliter any specified stuff in the extension info.
     * @param userId Indicates the userId in the system.
     * @param extensionInfos Indicates the obtained extensions.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool QueryExtensionAbilityInfos(const Want &want, const int32_t &flag, const int32_t &userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos)
    {
        return true;
    }
    /**
     * @brief Query extension info.
     * @param Want Indicates the information of extension info.
     * @param flags Indicates the query flag which will filter any specified stuff in the extension info.
     * @param userId Indicates the userId in the system.
     * @param extensionInfos Indicates the obtained extensions.
     * @return Returns ERR_OK if this function is successfully called; returns errCode otherwise.
     */
    virtual ErrCode QueryExtensionAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos)
    {
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    /**
     * @brief Query extension info.
     * @param Want Indicates the information of extension info.
     * @param extensionType Indicates the type of the extension.
     * @param flag Indicates the query flag which will fliter any specified stuff in the extension info.
     * @param userId Indicates the userId in the system.
     * @param extensionInfos Indicates the obtained extensions.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool QueryExtensionAbilityInfos(const Want &want, const ExtensionAbilityType &extensionType,
        const int32_t &flag, const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
    {
        return true;
    }
    /**
     * @brief Query extension info.
     * @param Want Indicates the information of extension info.
     * @param extensionType Indicates the type of the extension.
     * @param flags Indicates the query flag which will filter any specified stuff in the extension info.
     * @param userId Indicates the userId in the system.
     * @param extensionInfos Indicates the obtained extensions.
     * @return Returns ERR_OK if this function is successfully called; returns errCode otherwise.
     */
    virtual ErrCode QueryExtensionAbilityInfosV9(const Want &want, const ExtensionAbilityType &extensionType,
        int32_t flags, int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
    {
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    virtual bool QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType, const int32_t &userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos)
    {
        return true;
    }

    virtual bool VerifyCallingPermission(const std::string &permission)
    {
        return true;
    }

    /**
     * @brief Verify whether the calling app is system app. Only for BMS usage.
     *
     * @param beginApiVersion Indicates version since this api became to be system api.
     * @param bundleName Indicates bundle name of the calling hap.
     * @return Returns true if the hap passes the verification; returns false otherwise.
     */
    virtual bool VerifySystemApi(int32_t beginApiVersion = Constants::INVALID_API_VERSION)
    {
        return true;
    }

    /**
     * @brief Obtains the dependent module names.
     *
     * @param bundleName Indicates the bundle name to be queried.
     * @param moduleName Indicates the module name to be queried.
     * @param dependentModuleNames Indicates the obtained dependent module names.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool GetAllDependentModuleNames(const std::string &bundleName, const std::string &moduleName,
        std::vector<std::string> &dependentModuleNames)
    {
        return false;
    }

    virtual bool SetDisposedStatus(const std::string &bundleName, int32_t status)
    {
        return false;
    }

    virtual int32_t GetDisposedStatus(const std::string &bundleName)
    {
        return 0;
    }

    virtual std::vector<std::string> GetAccessibleAppCodePaths(int32_t userId)
    {
        std::vector<std::string> vec;
        return vec;
    }

    virtual bool QueryExtensionAbilityInfoByUri(const std::string &uri, int32_t userId,
        ExtensionAbilityInfo &extensionAbilityInfo)
    {
        return false;
    }

    virtual bool ImplicitQueryInfoByPriority(const Want &want, int32_t flags, int32_t userId,
        AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionInfo)
    {
        return false;
    }

    virtual bool ImplicitQueryInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, std::vector<ExtensionAbilityInfo> &extensionInfos)
    {
        return false;
    }

    /**
     * @brief Obtains the AbilityInfo based on a given bundle name.
     * @param bundleName Indicates the bundle name to be queried.
     * @param abilityName Indicates the ability name to be queried.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @return Returns true if the abilityInfo is successfully obtained; returns false otherwise.
     */
    virtual bool GetAbilityInfo(
        const std::string &bundleName, const std::string &abilityName, AbilityInfo &abilityInfo)
    {
        return false;
    }
    /**
     * @brief Obtains the AbilityInfo based on a given bundle name.
     * @param bundleName Indicates the bundle name to be queried.
     * @param moduleName Indicates the module name to be queried.
     * @param abilityName Indicates the ability name to be queried.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @return Returns true if the abilityInfo is successfully obtained; returns false otherwise.
     */
    virtual bool GetAbilityInfo(
        const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, AbilityInfo &abilityInfo)
    {
        return false;
    }
    /**
     * @brief Obtain sandbox application bundleInfo.
     * @param bundleName Indicates the bundle name of the sandbox application to be install.
     * @param appIndex Indicates application index of the sandbox application.
     * @param userId Indicates the sandbox application is installed under which user id.
     * @return Returns ERR_OK if the get sandbox application budnelInfo successfully; returns errcode otherwise.
     */
    virtual ErrCode GetSandboxBundleInfo(
        const std::string &bundleName, int32_t appIndex, int32_t userId, BundleInfo &info)
    {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }

    /**
     * @brief Obtains the value of upgradeFlag based on a given bundle name and module name.
     * @param bundleName Indicates the bundle name to be queried.
     * @param moduleName Indicates the module name to be queried.
     * @return Returns true if the isRemovable is successfully obtained; returns false otherwise.
     */
    virtual bool GetModuleUpgradeFlag(const std::string &bundleName, const std::string &moduleName)
    {
        return false;
    }
    /**
     * @brief Sets whether to enable upgradeFlag based on a given bundle name and module name.
     * @param bundleName Indicates the bundle name to be queried.
     * @param moduleName Indicates the module name to be queried.
     * @param isEnable Specifies whether to enable the isRemovable of InnerModuleInfo.
     *                 The value true means to enable it, and the value false means to disable it
     * @return Returns ERR_OK if the isRemovable is successfully obtained; returns ErrCode otherwise.
     */
    virtual ErrCode SetModuleUpgradeFlag(
        const std::string &bundleName, const std::string &moduleName, int32_t upgradeFlag)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual bool CheckAbilityEnableInstall(
        const Want &want, int32_t missionId, int32_t userId, const sptr<IRemoteObject> &callback)
    {
        return false;
    }

    virtual bool ObtainCallingBundleName(std::string &bundleName)
    {
        return false;
    }

    virtual sptr<IDefaultApp> GetDefaultAppProxy()
    {
        return nullptr;
    }

    virtual sptr<IAppControlMgr> GetAppControlProxy()
    {
        return nullptr;
    }

    virtual bool GetBundleStats(const std::string &bundleName, int32_t userId, std::vector<int64_t> &bundleStats)
    {
        return false;
    }

    virtual ErrCode GetSandboxAbilityInfo(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
        AbilityInfo &info)
    {
        return ERR_APPEXECFWK_SANDBOX_QUERY_PARAM_ERROR;
    }

    virtual ErrCode GetSandboxExtAbilityInfos(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &einfos)
    {
        return ERR_APPEXECFWK_SANDBOX_QUERY_PARAM_ERROR;
    }

    virtual ErrCode GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
        HapModuleInfo &info)
    {
        return ERR_APPEXECFWK_SANDBOX_QUERY_PARAM_ERROR;
    }

    virtual ErrCode GetMediaData(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, std::unique_ptr<uint8_t[]> &mediaDataPtr, size_t &len,
        int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual sptr<IQuickFixManager> GetQuickFixManagerProxy()
    {
        return nullptr;
    }

    virtual std::string GetStringById(const std::string &bundleName, const std::string &moduleName, uint32_t resId,
        int32_t userId, const std::string &localeInfo = Constants::EMPTY_STRING)
    {
        return Constants::EMPTY_STRING;
    }

    virtual std::string GetIconById(
        const std::string &bundleName, const std::string &moduleName, uint32_t resId, uint32_t density, int32_t userId)
    {
        return Constants::EMPTY_STRING;
    }

    virtual int32_t GetUdidByNetworkId(const std::string &networkId, std::string &udid)
    {
        return 0;
    }

    virtual ErrCode SetDebugMode(bool isDebug)
    {
        return ERR_BUNDLEMANAGER_SET_DEBUG_MODE_INTERNAL_ERROR;
    }

    virtual bool ProcessPreload(const Want &want)
    {
        return false;
    }

    virtual ErrCode GetProvisionMetadata(const std::string &bundleName, int32_t userId,
        std::vector<Metadata> &provisionMetadatas)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    enum Message : uint32_t {
        GET_APPLICATION_INFO = 0,
        GET_APPLICATION_INFOS,
        GET_BUNDLE_INFO,
        GET_BUNDLE_PACK_INFO,
        GET_BUNDLE_INFOS,
        GET_UID_BY_BUNDLE_NAME,
        GET_APPID_BY_BUNDLE_NAME,
        GET_BUNDLE_NAME_FOR_UID,
        GET_BUNDLES_FOR_UID,
        GET_NAME_FOR_UID,
        GET_BUNDLE_GIDS,
        GET_BUNDLE_GIDS_BY_UID,
        GET_APP_TYPE,
        CHECK_IS_SYSTEM_APP_BY_UID,
        GET_BUNDLE_INFOS_BY_METADATA,
        QUERY_ABILITY_INFO,
        QUERY_ABILITY_INFOS,
        QUERY_ABILITY_INFO_BY_URI,
        QUERY_ABILITY_INFOS_BY_URI,
        QUERY_KEEPALIVE_BUNDLE_INFOS,
        GET_ABILITY_LABEL,
        GET_ABILITY_LABEL_WITH_MODULE_NAME,
        GET_BUNDLE_ARCHIVE_INFO,
        GET_HAP_MODULE_INFO,
        GET_LAUNCH_WANT_FOR_BUNDLE,
        CHECK_PUBLICKEYS,
        GET_PERMISSION_DEF,
        HAS_SYSTEM_CAPABILITY,
        GET_SYSTEM_AVAILABLE_CAPABILITIES,
        IS_SAFE_MODE,
        CLEAN_BUNDLE_CACHE_FILES,
        CLEAN_BUNDLE_DATA_FILES,
        REGISTER_BUNDLE_STATUS_CALLBACK,
        CLEAR_BUNDLE_STATUS_CALLBACK,
        UNREGISTER_BUNDLE_STATUS_CALLBACK,
        DUMP_INFOS,
        IS_APPLICATION_ENABLED,
        SET_APPLICATION_ENABLED,
        IS_ABILITY_ENABLED,
        SET_ABILITY_ENABLED,
        GET_ABILITY_INFO,
        GET_ABILITY_INFO_WITH_MODULE_NAME,
        GET_ALL_FORMS_INFO,
        GET_FORMS_INFO_BY_APP,
        GET_FORMS_INFO_BY_MODULE,
        GET_SHORTCUT_INFO,
        GET_ALL_COMMON_EVENT_INFO,
        GET_BUNDLE_INSTALLER,
        QUERY_ABILITY_INFO_MUTI_PARAM,
        QUERY_ABILITY_INFOS_MUTI_PARAM,
        QUERY_ALL_ABILITY_INFOS,
        GET_APPLICATION_INFO_WITH_INT_FLAGS,
        GET_APPLICATION_INFOS_WITH_INT_FLAGS,
        GET_BUNDLE_INFO_WITH_INT_FLAGS,
        GET_BUNDLE_PACK_INFO_WITH_INT_FLAGS,
        GET_BUNDLE_INFOS_WITH_INT_FLAGS,
        GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS,
        GET_BUNDLE_USER_MGR,
        GET_DISTRIBUTE_BUNDLE_INFO,
        QUERY_ABILITY_INFO_BY_URI_FOR_USERID,
        GET_APPLICATION_PRIVILEGE_LEVEL,
        QUERY_EXTENSION_INFO_WITHOUT_TYPE,
        QUERY_EXTENSION_INFO,
        QUERY_EXTENSION_INFO_BY_TYPE,
        VERIFY_CALLING_PERMISSION,
        GET_ACCESSIBLE_APP_CODE_PATH,
        QUERY_EXTENSION_ABILITY_INFO_BY_URI,
        IS_MODULE_REMOVABLE,
        SET_MODULE_REMOVABLE,
        QUERY_ABILITY_INFO_WITH_CALLBACK,
        UPGRADE_ATOMIC_SERVICE,
        IS_MODULE_NEED_UPDATE,
        SET_MODULE_NEED_UPDATE,
        GET_HAP_MODULE_INFO_WITH_USERID,
        IMPLICIT_QUERY_INFO_BY_PRIORITY,
        IMPLICIT_QUERY_INFOS,
        GET_ALL_DEPENDENT_MODULE_NAMES,
        GET_SANDBOX_APP_BUNDLE_INFO,
        SET_DISPOSED_STATUS,
        GET_DISPOSED_STATUS,
        QUERY_CALLING_BUNDLE_NAME,
        GET_DEFAULT_APP_PROXY,
        GET_BUNDLE_STATS,
        CHECK_ABILITY_ENABLE_INSTALL,
        GET_SANDBOX_APP_ABILITY_INFO,
        GET_SANDBOX_APP_EXTENSION_INFOS,
        GET_SANDBOX_MODULE_INFO,
        GET_MEDIA_DATA,
        GET_QUICK_FIX_MANAGER_PROXY,
        GET_STRING_BY_ID,
        GET_ICON_BY_ID,
        GET_UDID_BY_NETWORK_ID,
        GET_APP_CONTROL_PROXY,
        SET_DEBUG_MODE,
        QUERY_ABILITY_INFOS_V9,
        QUERY_EXTENSION_INFO_WITHOUT_TYPE_V9,
        QUERY_EXTENSION_INFO_V9,
        GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9,
        GET_APPLICATION_INFO_WITH_INT_FLAGS_V9,
        GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS_V9,
        GET_BUNDLE_INFO_WITH_INT_FLAGS_V9,
        GET_BUNDLE_INFOS_WITH_INT_FLAGS_V9,
        GET_SHORTCUT_INFO_V9,
        REGISTER_BUNDLE_EVENT_CALLBACK,
        UNREGISTER_BUNDLE_EVENT_CALLBACK,
        GET_BUNDLE_INFO_FOR_SELF,
        VERIFY_SYSTEM_API,
        PROCESS_PRELOAD,
        GET_PROVISION_METADATA,
        SILENT_INSTALL,
        GET_UID_BY_DEBUG_BUNDLE_NAME,
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_INTERFACE_H
