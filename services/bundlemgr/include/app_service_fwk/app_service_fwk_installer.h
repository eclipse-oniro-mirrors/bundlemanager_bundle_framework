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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_SERVICE_FWK_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_SERVICE_FWK_INSTALLER_H

#include <memory>
#include <string>
#include <unordered_map>

#include "bundle_data_mgr.h"
#include "bundle_install_checker.h"
#include "event_report.h"
#include "inner_bundle_info.h"
#include "install_param.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class AppServiceFwkInstaller {
public:
    AppServiceFwkInstaller();
    virtual ~AppServiceFwkInstaller();

    ErrCode Install(
        const std::vector<std::string> &hspPaths, InstallParam &installParam);
    ErrCode UnInstall(const std::string &bundleName, bool isKeepData = false);
private:
    void ResetProperties();
    ErrCode BeforeInstall(
        const std::vector<std::string> &hspPaths, InstallParam &installParam);
    ErrCode BeforeUninstall(const std::string &bundleName);
    ErrCode ProcessInstall(
        const std::vector<std::string> &hspPaths, InstallParam &installParam);
    ErrCode CheckAndParseFiles(
        const std::vector<std::string> &hspPaths, InstallParam &installParam,
        std::unordered_map<std::string, InnerBundleInfo> &newInfos);
    ErrCode InnerProcessInstall(
        std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        InstallParam &installParam);
    ErrCode CheckAppLabelInfo(
        const std::unordered_map<std::string, InnerBundleInfo> &infos);
    ErrCode CheckFileType(const std::vector<std::string> &bundlePaths);
    void SendBundleSystemEvent(
        const std::vector<std::string> &hspPaths, BundleEventType bundleEventType,
        const InstallParam &installParam, InstallScene preBundleScene, ErrCode errCode);
    ErrCode ExtractModule(
        InnerBundleInfo &newInfo, const std::string &bundlePath, bool copyHapToInstallPath = false);
    ErrCode ExtractModule(InnerBundleInfo &oldInfo, InnerBundleInfo &newInfo, const std::string &bundlePath);
    ErrCode MkdirIfNotExist(const std::string &dir);
    ErrCode ProcessNativeLibrary(
        const std::string &bundlePath,
        const std::string &moduleDir,
        const std::string &moduleName,
        const std::string &versionDir,
        InnerBundleInfo &newInfo,
        bool copyHapToInstallPath = false);
    ErrCode MoveSoToRealPath(
        const std::string &moduleName, const std::string &versionDir,
        const std::string &nativeLibraryPath);
    void MergeBundleInfos(InnerBundleInfo &info);
    ErrCode SaveBundleInfoToStorage();
    void AddAppProvisionInfo(
        const std::string &bundleName,
        const Security::Verify::ProvisionInfo &provisionInfo,
        const InstallParam &installParam) const;

    void RollBack();
    ErrCode RemoveBundleCodeDir(const InnerBundleInfo &info) const;
    void RemoveInfo(const std::string &bundleName);
    void SavePreInstallBundleInfo(ErrCode installResult,
        const std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InstallParam &installParam);
    ErrCode UpdateAppService(InnerBundleInfo &oldInfo,
        std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        InstallParam &installParam);
    ErrCode UninstallLowerVersion(const std::vector<std::string> &moduleNameList);
    bool GetInnerBundleInfo(InnerBundleInfo &info, bool &isAppExist);
    bool CheckNeedInstall(const std::unordered_map<std::string, InnerBundleInfo> &infos, InnerBundleInfo &oldInfo);
    bool CheckNeedUpdate(const InnerBundleInfo &newInfo, const InnerBundleInfo &oldInfo);
    ErrCode ProcessBundleUpdateStatus(InnerBundleInfo &oldInfo, InnerBundleInfo &newInfo,
        const std::string &hspPath, const InstallParam &installParam);
    ErrCode ProcessNewModuleInstall(InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo,
        const std::string &hspPath, const InstallParam &installParam);
    ErrCode ProcessModuleUpdate(InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo,
        const std::string &hspPath, const InstallParam &installParam);
    ErrCode RemoveLowerVersionSoDir(uint32_t versionCode);
    ErrCode VerifyCodeSignatureForNativeFiles(const std::string &bundlePath, const std::string &cpuAbi,
        const std::string &targetSoPath) const;
    ErrCode DeliveryProfileToCodeSign(std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults) const;
    void GenerateOdid(std::unordered_map<std::string, InnerBundleInfo> &infos,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const;
    ErrCode VerifyCodeSignatureForHsp(const std::string &realHspPath, const std::string &realSoPath) const;
    ErrCode MarkInstallFinish();

    std::unique_ptr<BundleInstallChecker> bundleInstallChecker_ = nullptr;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    std::string bundleName_;
    std::string bundleMsg_;
    std::vector<std::string> uninstallModuleVec_;
    bool versionUpgrade_ = false;
    bool moduleUpdate_ = false;
    std::vector<std::string> deleteBundlePath_;
    uint32_t versionCode_ = 0;
    InnerBundleInfo newInnerBundleInfo_;
    bool isEnterpriseBundle_ = false;
    std::string appIdentifier_;
    std::string compileSdkType_;
    std::string cpuAbi_;
    std::string nativeLibraryPath_;
    DISALLOW_COPY_AND_MOVE(AppServiceFwkInstaller);

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
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_SERVICE_FWK_INSTALLER_H