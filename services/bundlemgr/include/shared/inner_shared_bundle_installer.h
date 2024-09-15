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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_SHARED_BUNDLE_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_SHARED_BUNDLE_INSTALLER_H

#include <string>
#include <unordered_map>
#include <vector>

#include "bundle_install_checker.h"
#include "bundle_common_event_mgr.h"
#include "event_report.h"
#include "inner_bundle_info.h"
#include "install_param.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class InnerSharedBundleInstaller {
public:
    /**
     * @brief Cross-app shared bundle installer for hsp files of same bundle.
     * @param path Indicates the real path or the parent directory of hsp files to be installed.
     */
    explicit InnerSharedBundleInstaller(const std::string &path);
    virtual ~InnerSharedBundleInstaller();

    /**
     * @brief Parse cross-app hsp files of same bundle.
     * @param checkParam Indicates the install check param.
     * @return Returns ERR_OK if the files are parsed successfully; returns error code otherwise.
     */
    ErrCode ParseFiles(const InstallCheckParam &checkParam);

    /**
     * @brief Get the bundle name of current shared bundle to be installed.
     * @return Returns the bundle name of current shared bundle to be installed.
     */
    inline std::string GetBundleName() const
    {
        return bundleName_;
    }

    /**
     * @brief Install cross-app shared bundles of same bundle.
     * @param installParam Indicates the install param.
     * @return Returns ERR_OK if the files are installed successfully; returns error code otherwise.
     */
    ErrCode Install(const InstallParam &installParam);

    /**
     * @brief Roll back the install action.
    */
    void RollBack();

    /**
     * @brief Checks whether the dependency is satisfied by current installing shared bundle.
     * @param dependency Indicates the dependency to be checked.
     * @return Returns true if the dependency is satisfied; returns false otherwise.
     */
    bool CheckDependency(const Dependency &dependency) const;

    void SetCheckResultMsg(const std::string checkResultMsg) const;

    /**
     * @brief Send bundle system event.
     * @param eventTemplate Indicates the template of EventInfo to send after installation.
     */
    void SendBundleSystemEvent(const EventInfo &eventTemplate) const;

    /**
     * @brief send notify to start install applicaiton
     * @param installParam Indicates the install parameters.
     * @param infos .Indicates all innerBundleInfo for all haps need to be installed.
    */
    void sendStartSharedBundleInstallNotify(const InstallCheckParam &installCheckParam,
        const std::unordered_map<std::string, InnerBundleInfo> &infos);
    
    ErrCode NotifyBundleStatusOfShared(const NotifyBundleEvents &installRes);

    ErrCode DeliveryProfileToCodeSign(std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults) const;

private:
    ErrCode CheckAppLabelInfo();
    ErrCode CheckBundleTypeWithInstalledVersion();
    ErrCode ExtractSharedBundles(const std::string &bundlePath, InnerBundleInfo &newInfo);
    ErrCode MkdirIfNotExist(const std::string &dir);
    void MergeBundleInfos();
    ErrCode SavePreInstallInfo(const InstallParam &installParam);
    ErrCode SaveBundleInfoToStorage();
    void GetInstallEventInfo(EventInfo &eventInfo) const;
    void AddAppProvisionInfo(const std::string &bundleName,
        const Security::Verify::ProvisionInfo &provisionInfo) const;
    void SaveInstallParamInfo(const std::string &bundleName, const InstallParam &installParam) const;
    ErrCode CopyHspToSecurityDir(std::vector<std::string> &bundlePaths);
    ErrCode ObtainHspFileAndSignatureFilePath(const std::vector<std::string> &inBundlePaths,
        std::vector<std::string> &bundlePaths, std::string &signatureFilePath);
    ErrCode SaveHspToRealInstallationDir(const std::string &bundlePath, const std::string &moduleDir,
        const std::string &moduleName, const std::string &realHspPath);
    std::string ObtainTempSoPath(const std::string &moduleName, const std::string &nativeLibPath);
    ErrCode MoveSoToRealPath(const std::string &moduleName, const std::string &versionDir);
    ErrCode ProcessNativeLibrary(const std::string &bundlePath,
        const std::string &moduleDir, const std::string &moduleName, const std::string &versionDir,
        InnerBundleInfo &newInfo);
    ErrCode VerifyCodeSignatureForNativeFiles(const std::string &bundlePath, const std::string &cpuAbi,
        const std::string &targetSoPath, const std::string &signatureFileDir, bool isPreInstalledBundle) const;
    ErrCode VerifyCodeSignatureForHsp(const std::string &tempHspPath, const std::string &appIdentifier,
        bool isEnterpriseBundle, bool isCompileSdkOpenHarmony, const std::string &bundleName) const;
    void UpdateInnerModuleInfo(const std::string packageName, const InnerModuleInfo &innerModuleInfo);

    // the real path or the parent directory of hsp files to be installed.
    std::string sharedBundlePath_;
    std::string bundleName_;
    std::string signatureFileDir_;
    std::vector<std::string> toDeleteTempHspPath_;
    // the key is the real path of each hsp file
    std::unordered_map<std::string, InnerBundleInfo> parsedBundles_;
    // created directories during installation, will be deleted when rollback.
    std::vector<std::string> createdDirs_;
    bool isBundleExist_ = false;
    InnerBundleInfo oldBundleInfo_;
    InnerBundleInfo newBundleInfo_;
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker_ = nullptr;
    std::string nativeLibraryPath_;
    bool isEnterpriseBundle_ = false;
    std::string appIdentifier_;
    std::string compileSdkType_;
    std::string cpuAbi_;
    std::string tempSoPath_;
    bool isPreInstalledBundle_ = false;

    DISALLOW_COPY_AND_MOVE(InnerSharedBundleInstaller);

#define CHECK_RESULT(errcode, errmsg)                                              \
    do {                                                                           \
        if ((errcode) != ERR_OK) {                                                   \
            APP_LOGE(errmsg, errcode);                                             \
            return errcode;                                                        \
        }                                                                          \
    } while (0)
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_SHARED_BUNDLE_INSTALLER_H