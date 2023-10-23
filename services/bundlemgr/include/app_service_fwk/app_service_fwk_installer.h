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
    /**
     * @brief Cross-app shared bundle installer.
     * @param installParam Indicates the install param.
     * @param appType Indicates the type of the application.
     */
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

    std::unique_ptr<BundleInstallChecker> bundleInstallChecker_ = nullptr;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    DISALLOW_COPY_AND_MOVE(AppServiceFwkInstaller);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_SERVICE_FWK_INSTALLER_H