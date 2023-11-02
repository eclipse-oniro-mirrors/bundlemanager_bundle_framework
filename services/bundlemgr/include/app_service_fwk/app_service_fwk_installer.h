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
private:
    ErrCode BeforeInstall(
        const std::vector<std::string> &hspPaths, InstallParam &installParam);
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
    ErrCode ExtractModule(
        InnerBundleInfo &newInfo, const std::string &bundlePath);
    ErrCode MkdirIfNotExist(const std::string &dir);
    ErrCode ProcessNativeLibrary(
        const std::string &bundlePath,
        const std::string &moduleDir,
        const std::string &moduleName,
        const std::string &versionDir,
        InnerBundleInfo &newInfo);
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

    std::unique_ptr<BundleInstallChecker> bundleInstallChecker_ = nullptr;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    std::string bundleName_;
    InnerBundleInfo newInnerBundleInfo_;
    DISALLOW_COPY_AND_MOVE(AppServiceFwkInstaller);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_SERVICE_FWK_INSTALLER_H