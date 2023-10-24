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

#include "app_service_fwk_installer.h"

#include "app_log_wrapper.h"
#include "app_provision_info_manager.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {

AppServiceFwkInstaller::AppServiceFwkInstaller()
    : bundleInstallChecker_(std::make_unique<BundleInstallChecker>())
{
    APP_LOGI("AppServiceFwk installer instance is created");
}

AppServiceFwkInstaller::~AppServiceFwkInstaller()
{
    APP_LOGI("AppServiceFwk installer instance is destroyed");
}

ErrCode AppServiceFwkInstaller::Install(
    const std::vector<std::string> &hspPaths, InstallParam &installParam)
{
    ErrCode result = BeforeInstall(hspPaths, installParam);
    CHECK_RESULT(result, "BeforeInstall check failed %{public}d");
    return ProcessInstall(hspPaths, installParam);
}

ErrCode AppServiceFwkInstaller::BeforeInstall(
    const std::vector<std::string> &hspPaths, InstallParam &installParam)
{
    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr_ == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    if (!installParam.isPreInstallApp) {
        return ERR_APP_SERVICE_FWK_INSTALL_NOT_PREINSTALL;
    }

    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::ProcessInstall(
    const std::vector<std::string> &hspPaths, InstallParam &installParam)
{
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    ErrCode result = CheckAndParseFiles(hspPaths, installParam, newInfos);
    CHECK_RESULT(result, "CheckAndParseFiles failed %{public}d");

    result = InnerProcessInstall(newInfos, installParam);
    CHECK_RESULT(result, "CheckAndParseFiles failed %{public}d");
    return result;
}

ErrCode AppServiceFwkInstaller::CheckAndParseFiles(
    const std::vector<std::string> &hspPaths, InstallParam &installParam,
    std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    return ERR_OK;
}

ErrCode AppServiceFwkInstaller::InnerProcessInstall(
    std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InstallParam &installParam)
{
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
