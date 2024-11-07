/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_INSTALL_CHECKER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_INSTALL_CHECKER_H

#include <memory>
#include <string>
#include <vector>

#include "app_privilege_capability.h"
#include "app_provision_info.h"
#include "appexecfwk_errors.h"
#include "bundle_pack_info.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "install_param.h"

namespace OHOS {
namespace AppExecFwk {
struct InstallCheckParam {
    bool isPreInstallApp = false;
    bool removable = true;
    bool needSendEvent = true;
    // is shell token
    bool isCallByShell = false;
    // status of install bundle permission
    PermissionStatus installBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // status of install enterprise bundle permission
    PermissionStatus installEnterpriseBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // status of install enterprise normal bundle permission
    PermissionStatus installEtpNormalBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // status of install enterprise mdm bundle permission
    PermissionStatus installEtpMdmBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // status of install internaltesting bundle permission
    PermissionStatus installInternaltestingBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    
    Constants::AppType appType = Constants::AppType::THIRD_PARTY_APP;
    int64_t crowdtestDeadline = Constants::INVALID_CROWDTEST_DEADLINE; // for crowdtesting type hap
    std::string specifiedDistributionType;
};

class BundleInstallChecker {
public:
    /**
     * @brief Check syscap.
     * @param bundlePaths Indicates the file paths of all HAP packages.
     * @return Returns ERR_OK if the syscap satisfy; returns error code otherwise.
     */
    ErrCode CheckSysCap(const std::vector<std::string> &bundlePaths);

    /**
     * @brief Check signature info of multiple haps.
     * @param bundlePaths Indicates the file paths of all HAP packages.
     * @param hapVerifyRes Indicates the signature info.
     * @return Returns ERR_OK if the every hap has signature info and all haps have same signature info.
     */
    ErrCode CheckMultipleHapsSignInfo(
        const std::vector<std::string> &bundlePaths,
        std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);

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
     * @brief To check native file in all haps.
     * @param infos .Indicates all innerBundleInfo for all haps need to be installed.
     * @return Returns ERR_OK if haps checking successfully; returns error code otherwise.
     */
    ErrCode CheckMultiNativeFile(std::unordered_map<std::string, InnerBundleInfo> &infos);
    /**
     * @brief To check ark native file in all haps.
     * @param infos .Indicates all innerBundleInfo for all haps need to be installed.
     * @return Returns ERR_OK if haps checking successfully; returns error code otherwise.
     */
    ErrCode CheckMultiArkNativeFile(std::unordered_map<std::string, InnerBundleInfo> &infos);
    /**
     * @brief To check native so in all haps.
     * @param infos .Indicates all innerBundleInfo for all haps need to be installed.
     * @return Returns ERR_OK if haps checking successfully; returns error code otherwise.
     */
    ErrCode CheckMultiNativeSo(std::unordered_map<std::string, InnerBundleInfo> &infos);
    /**
     * @brief To parse hap files and to obtain innerBundleInfo of each hap.
     * @param bundlePaths Indicates the file paths of all HAP packages.
     * @param checkParam Indicates the install check parameters.
     * @param hapVerifyRes Indicates all signature info of all haps.
     * @param infos Indicates the innerBundleinfo of each hap.
     * @return Returns ERR_OK if each hap is parsed successfully; returns error code otherwise.
     */
    ErrCode ParseHapFiles(
        const std::vector<std::string> &bundlePaths,
        const InstallCheckParam &checkParam,
        std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
        std::unordered_map<std::string, InnerBundleInfo> &infos);
    /**
     * @brief To check dependency whether or not exists.
     * @param infos Indicates all innerBundleInfo for all haps need to be installed.
     * @return Returns ERR_OK if haps checking successfully; returns error code otherwise.
     */
    ErrCode CheckDependency(std::unordered_map<std::string, InnerBundleInfo> &infos);

    void ResetProperties();

    bool IsContainEntry()
    {
        return isContainEntry_;
    }

    ErrCode CheckHspInstallCondition(std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);

    ErrCode CheckInstallPermission(const InstallCheckParam &checkParam,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);

    bool VaildInstallPermission(const InstallParam &installParam,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);

    bool VaildEnterpriseInstallPermission(const InstallParam &installParam,
        const Security::Verify::ProvisionInfo &provisionInfo);

    bool VaildInstallPermissionForShare(const InstallCheckParam &checkParam,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);

    bool VaildEnterpriseInstallPermissionForShare(const InstallCheckParam &checkParam,
        const Security::Verify::ProvisionInfo &provisionInfo);

    ErrCode CheckModuleNameForMulitHaps(const std::unordered_map<std::string, InnerBundleInfo> &infos);

    bool IsExistedDistroModule(const InnerBundleInfo &newInfo, const InnerBundleInfo &info) const;

    bool IsContainModuleName(const InnerBundleInfo &newInfo, const InnerBundleInfo &info) const;

    ErrCode CheckDeviceType(std::unordered_map<std::string, InnerBundleInfo> &infos) const;

    AppProvisionInfo ConvertToAppProvisionInfo(const Security::Verify::ProvisionInfo &provisionInfo) const;

    ErrCode CheckProxyDatas(const InnerBundleInfo &info) const;

    ErrCode CheckIsolationMode(const std::unordered_map<std::string, InnerBundleInfo> &infos) const;

    ErrCode CheckSignatureFileDir(const std::string &signatureFileDir) const;

    ErrCode CheckDeveloperMode(const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const;

    ErrCode CheckAllowEnterpriseBundle(const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const;

    bool CheckEnterpriseBundle(Security::Verify::HapVerifyResult &hapVerifyRes) const;
    bool CheckInternaltestingBundle(Security::Verify::HapVerifyResult &hapVerifyRes) const;
    bool CheckSupportAppTypes(
        const std::unordered_map<std::string, InnerBundleInfo> &infos, const std::string &supportAppTypes) const;

    std::string GetCheckResultMsg() const;

    void SetCheckResultMsg(const std::string checkResultMsg);

    bool CheckProvisionInfoIsValid(const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);

private:

    ErrCode ParseBundleInfo(
        const std::string &bundleFilePath,
        InnerBundleInfo &info,
        BundlePackInfo &packInfo) const;

    ErrCode CheckSystemSize(
        const std::string &bundlePath,
        const Constants::AppType appType) const;

    void SetEntryInstallationFree(
        const BundlePackInfo &bundlePackInfo,
        InnerBundleInfo &innerBundleInfo);

    void SetPackInstallationFree(BundlePackInfo &bundlePackInfo, const InnerBundleInfo &innerBundleInfo) const;

    void CollectProvisionInfo(
        const Security::Verify::ProvisionInfo &provisionInfo,
        const AppPrivilegeCapability &appPrivilegeCapability,
        InnerBundleInfo &newInfo);

    void GetPrivilegeCapability(
        const InstallCheckParam &checkParam, InnerBundleInfo &newInfo);

    void ParseAppPrivilegeCapability(
        const Security::Verify::ProvisionInfo &provisionInfo,
        AppPrivilegeCapability &appPrivilegeCapability);

    ErrCode CheckMainElement(const InnerBundleInfo &info);

    ErrCode CheckBundleName(const std::string &provisionInfoBundleName, const std::string &bundleName);

    void FetchPrivilegeCapabilityFromPreConfig(
        const std::string &bundleName,
        const std::vector<std::string> &appSignatures,
        AppPrivilegeCapability &appPrivilegeCapability);

    bool MatchSignature(const std::vector<std::string> &appSignatures, const std::string &signature);

    bool GetPrivilegeCapabilityValue(const std::vector<std::string> &existInJson,
        const std::string &key, bool existInPreJson, bool existInProvision);

    ErrCode ProcessBundleInfoByPrivilegeCapability(const AppPrivilegeCapability &appPrivilegeCapability,
        InnerBundleInfo &innerBundleInfo);

    bool NeedCheckDependency(const Dependency &dependency, const InnerBundleInfo &info);

    bool FindModuleInInstallingPackage(
        const std::string &moduleName,
        const std::string &bundleName,
        const std::unordered_map<std::string, InnerBundleInfo> &infos);

    bool FindModuleInInstalledPackage(
        const std::string &moduleName,
        const std::string &bundleName,
        uint32_t versionCode);

    bool isContainEntry_ = false;

    void SetAppProvisionMetadata(const std::vector<Security::Verify::Metadata> &provisionMetadatas,
        InnerBundleInfo &newInfo);

    bool CheckProxyPermissionLevel(const std::string &permissionName) const;
    bool MatchOldSignatures(const std::string &bundleName, const std::vector<std::string> &appSignatures);
    std::tuple<bool, std::string, std::string> GetValidReleaseType(
        const std::unordered_map<std::string, InnerBundleInfo> &infos);
    void DetermineCloneNum(InnerBundleInfo &innerBundleInfo);

    std::string checkResultMsg_ = "";
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_INSTALL_CHECKER_H