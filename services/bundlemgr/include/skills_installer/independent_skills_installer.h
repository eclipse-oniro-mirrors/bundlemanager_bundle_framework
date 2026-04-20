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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_INDEPENDENT_SKILLS_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_INDEPENDENT_SKILLS_INSTALLER_H

#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "app_log_tag_wrapper.h"
#include "bundle_data_mgr.h"
#include "bundle_install_checker.h"
#include "event_report.h"
#include "inner_bundle_info.h"
#include "install_param.h"
#include "nocopyable.h"
#include "skills_package_info.h"

namespace OHOS {
namespace AppExecFwk {
class IndependentSkillsInstaller {
public:
    IndependentSkillsInstaller();
    virtual ~IndependentSkillsInstaller();

    ErrCode Install(const std::vector<std::string> &hspPaths, const InstallParam &installParam);

    ErrCode InstallBundleByBundleName(const std::string &bundleName, const InstallParam &installParam);

    ErrCode Uninstall(const std::string &bundleName, const InstallParam &installParam);

private:
    ErrCode ProcessInstallBundleByBundleName(const std::string &bundleName, const InstallParam &installParam);
    void ResetProperties();
    ErrCode BeforeInstall(
        const std::vector<std::string> &hspPaths, const InstallParam &installParam);
    ErrCode CheckUserId(const int32_t userId);
    void RemoveModuleDir(const std::string &bundleName, const std::string &moduleName);
    ErrCode ProcessInstall(
        const std::vector<std::string> &hspPaths, const InstallParam &installParam);
    ErrCode CopyHspToSecurityDir(std::vector<std::string> &bundlePaths);
    ErrCode CheckAndParseFiles(
        const std::vector<std::string> &hspPaths, const InstallParam &installParam,
        std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    ErrCode InnerProcessInstall(
        std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InstallParam &installParam);
    ErrCode CheckSingletonAndU1Enable(const std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    ErrCode CheckAppLabelInfo(
        const std::unordered_map<std::string, InnerBundleInfo> &infos);
    bool CheckAppIdentifier(const std::string &oldAppIdentifier, const std::string &newAppIdentifier,
        const std::string &oldAppId, const std::string &newAppId);
    ErrCode CheckFileType(const std::vector<std::string> &bundlePaths);
    ErrCode ExtractModule(
        InnerBundleInfo &newInfo, const std::string &bundlePath, bool copyHapToInstallPath, bool isModuleExist);
    ErrCode MkdirIfNotExist(const std::string &dir);
    void MergeBundleInfos(InnerBundleInfo &info);
    ErrCode SaveBundleInfoToStorage();
    void AddAppProvisionInfo(
        const std::string &bundleName,
        const Security::Verify::ProvisionInfo &provisionInfo,
        const InstallParam &installParam) const;
    void RollBack();
    void RollBack(const std::unordered_map<std::string, InnerBundleInfo> &newInfos, const ErrCode result);
    void RemoveInfo(const std::string &bundleName);
    void SavePreInstallBundleInfo(
        const std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InstallParam &installParam);
    ErrCode UpdateSkillsPackage(InnerBundleInfo &oldInfo,
        std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InstallParam &installParam);
    ErrCode UninstallLowerVersion(const std::vector<std::string> &moduleNameList);
    bool FetchInnerBundleInfo(InnerBundleInfo &info, bool &isAppExist);
    bool CheckNeedInstall(const std::unordered_map<std::string, InnerBundleInfo> &infos, InnerBundleInfo &oldInfo,
        bool &isDowngrade);
    ErrCode ProcessBundleUpdateStatus(InnerBundleInfo &oldInfo, InnerBundleInfo &newInfo,
        const std::string &hspPath, const InstallParam &installParam);
    ErrCode ProcessNewModuleInstall(InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo,
        const std::string &hspPath, const InstallParam &installParam);
    ErrCode ProcessModuleUpdate(InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo,
        const std::string &hspPath, const InstallParam &installParam);
    ErrCode DeliveryProfileToCodeSign(std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults) const;
    void UpdateDeveloperId(std::unordered_map<std::string, InnerBundleInfo> &infos,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const;
    ErrCode VerifyCodeSignatureForHsp(const std::string &realHspPath) const;
    ErrCode MarkInstallFinish();
    void RemoveOldSkillsPath();
    void MarkPreInstallState(const std::string &bundleName, bool isUninstalled);
    ErrCode BeforeUninstall(const std::string &bundleName, const int32_t userId);
    ErrCode ProcessUninstall(const std::string &bundleName, const InstallParam &installParam);
    void InnerProcessNeedDeleteSkillPackage(const InnerBundleInfo &currentBundleInfo);
    void RemoveSkillDir(const std::string &bundleName, const std::string &moduleName, const std::string &skillsName);

    bool versionUpgrade_ = false;
    bool moduleUpdate_ = false;
    bool isEnterpriseBundle_ = false;
    bool hasInstalledInUser_ = false;
    uint32_t versionCode_ = 0;
    int32_t userId_ = -1;
    int64_t startTime_ = 0;
    std::string bundleName_;
    std::string appIdentifier_;
    std::string compileSdkType_;
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker_ = nullptr;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    std::vector<std::string> uninstallModuleVec_;
    std::vector<std::string> deleteBundlePath_;
    std::vector<SkillsPackageInfo> needDeleteSkillsPackageInfo_;
    std::vector<std::string> toDeleteTempHspPath_;
    InnerBundleInfo newInnerBundleInfo_;
    // used to rollback when update failed
    InnerBundleInfo oldInnerBundleInfo_;
    Security::Verify::HapVerifyResult verifyRes_;
    DISALLOW_COPY_AND_MOVE(IndependentSkillsInstaller);

#define CHECK_SKILLS_RESULT(errcode, errmsg)                                              \
    do {                                                                           \
        if ((errcode) != ERR_OK) {                                                   \
            LOG_E(BMS_TAG_INSTALLER, errmsg, errcode);                             \
            return errcode;                                                        \
        }                                                                          \
    } while (0)
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_INDEPENDENT_SKILLS_INSTALLER_H
