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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_CLIENT_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_CLIENT_H

#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_dir.h"
#include "bundle_info.h"
#include "bundle_pack_info.h"
#include "extension_ability_info.h"
#include "hap_module_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrClientImpl;
using Want = OHOS::AAFwk::Want;

class BundleMgrClient {
public:
    BundleMgrClient();
    virtual ~BundleMgrClient();

    ErrCode GetNameForUid(const int uid, std::string &name);
    bool GetBundleInfo(const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID);
    ErrCode GetBundlePackInfo(const std::string &bundleName, const BundlePackFlag flag, BundlePackInfo &bundlePackInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID);
    ErrCode CreateBundleDataDir(int32_t userId);
    ErrCode CreateBundleDataDirWithEl(int32_t userId, DataDirEl dirEl);

    /**
     * @brief Obtain the profile which are deploied in the Metadata in the bundle.
     * @param bundleName Indicates the bundle name of the bundle.
     * @param hapName Indicates the hap name of the bundle.
     * @param hapModuleInfo Indicates the information of the hap.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetHapModuleInfo(const std::string &bundleName, const std::string &hapName, HapModuleInfo &hapModuleInfo);
    /**
     * @brief Obtain the profile which are deploied in the Metadata in the bundle.
     * @param hapModuleInfo Indicates the information of a hap of this bundle.
     * @param MetadataName Indicates the name of the Metadata.
     * @param profileInfos Indicates the obtained profiles in json string.
     * @param includeSysRes whether include system resource.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetResConfigFile(const HapModuleInfo &hapModuleInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos, bool includeSysRes = true) const;
    /**
     * @brief Obtain the profile which are deploied in the Metadata in the bundle.
     * @param extensionInfo Indicates the information of the extension info of the bundle.
     * @param MetadataName Indicates the name of the Metadata.
     * @param includeSysRes whether include system resource.
     * @param profileInfos Indicates the obtained profiles in json string.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetResConfigFile(const ExtensionAbilityInfo &extensionInfo, const std::string &metadataName,
        std::vector<std::string> &profileInfos, bool includeSysRes = true) const;
    /**
     * @brief Obtain the profile which are deploied in the Metadata in the bundle.
     * @param abilityInfo Indicates the information of the ability info of the bundle.
     * @param MetadataName Indicates the name of the Metadata.
     * @param includeSysRes whether include system resource.
     * @param profileInfos Indicates the obtained profiles in json string.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetResConfigFile(const AbilityInfo &abilityInfo, const std::string &metadataName,
        std::vector<std::string> &profileInfos, bool includeSysRes = true) const;

    bool GetProfileFromExtension(const ExtensionAbilityInfo &extensionInfo, const std::string &metadataName,
        std::vector<std::string> &profileInfos, bool includeSysRes = true) const;
    bool GetProfileFromAbility(const AbilityInfo &abilityInfo, const std::string &metadataName,
        std::vector<std::string> &profileInfos, bool includeSysRes = true) const;
    bool GetProfileFromHap(const HapModuleInfo &hapModuleInfo, const std::string &metadataName,
        std::vector<std::string> &profileInfos, bool includeSysRes = true) const;
    bool GetProfileFromSharedHap(const HapModuleInfo &hapModuleInfo, const ExtensionAbilityInfo &extensionInfo,
        std::vector<std::string> &profileInfos, bool includeSysRes = true) const;
    /**
     * @brief Install sandbox application.
     * @param bundleName Indicates the bundle name of the sandbox application to be install.
     * @param dlpType Indicates type of the sandbox application.
     * @param userId Indicates the sandbox application will be installed under which user id.
     * @param appIndex Indicates the appIndex of the sandbox application installed under which user id.
     * @return Returns appIndex of sandbox application if successfully, otherwise returns 0.
     */
    ErrCode InstallSandboxApp(const std::string &bundleName, int32_t dlpType, int32_t userId, int32_t &appIndex);

    /**
     * @brief Uninstall sandbox application.
     * @param bundleName Indicates the bundle name of the sandbox application to be install.
     * @param appIndex Indicates application index of the sandbox application.
     * @param userId Indicates the sandbox application will be uninstall under which user id.
     * @return Returns true if the sandbox application is installed successfully; returns false otherwise.
     */
    ErrCode UninstallSandboxApp(const std::string &bundleName, int32_t appIndex, int32_t userId);

    ErrCode GetSandboxBundleInfo(const std::string &bundleName, int32_t appIndex, int32_t userId, BundleInfo &info);

    ErrCode GetSandboxAbilityInfo(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
        AbilityInfo &abilityInfo);
    ErrCode GetSandboxExtAbilityInfos(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
        std::vector<ExtensionAbilityInfo> &extensionInfos);
    ErrCode GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
        HapModuleInfo &hapModuleInfo);
    ErrCode GetDirByBundleNameAndAppIndex(const std::string &bundleName, const int32_t appIndex, std::string &dataDir);
    ErrCode GetAllBundleDirs(int32_t userId, std::vector<BundleDir> &bundleDirs);

private:
    static std::shared_ptr<BundleMgrClientImpl> impl_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_CLIENT_H
