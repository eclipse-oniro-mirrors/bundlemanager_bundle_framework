/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "on_demand_install_data_mgr.h"

#include "bundle_constants.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_parser.h"
#include "bundle_service_constants.h"
#include "pre_scan_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* ON_DEMAND_INSTALL = "ohos.bms.param.on.demand.install";
constexpr const char* BMS_TRUE = "true";
}
OnDemandInstallDataMgr::OnDemandInstallDataMgr()
{
    onDemandDataStorage_ = std::make_shared<OnDemandInstallDataStorageRdb>();
    APP_LOGI("OnDemandInstallDataMgr instance is created");
}

OnDemandInstallDataMgr::~OnDemandInstallDataMgr()
{
    APP_LOGI("OnDemandInstallDataMgr instance is destroyed");
}

OnDemandInstallDataMgr& OnDemandInstallDataMgr::GetInstance()
{
    static OnDemandInstallDataMgr OnDemandInstallDataMgr;
    return OnDemandInstallDataMgr;
}

bool OnDemandInstallDataMgr::SaveOnDemandInstallBundleInfo(
    const std::string &bundleName, const PreInstallBundleInfo &preInstallBundleInfo)
{
    if (!onDemandDataStorage_->SaveOnDemandInstallBundleInfo(preInstallBundleInfo)) {
        APP_LOGE("save onDemandInstall bundle failed bundle:%{public}s", bundleName.c_str());
        return false;
    }
    return true;
}
 
bool OnDemandInstallDataMgr::DeleteOnDemandInstallBundleInfo(const std::string &bundleName)
{
    if (!onDemandDataStorage_->DeleteOnDemandInstallBundleInfo(bundleName)) {
        APP_LOGE("Delete onDemandInstall bundle failed bundle:%{public}s", bundleName.c_str());
        return false;
    }
    return true;
}
 
bool OnDemandInstallDataMgr::GetOnDemandInstallBundleInfo(
    const std::string &bundleName, PreInstallBundleInfo &preInstallBundleInfo)
{
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return false;
    }
    if (!onDemandDataStorage_->GetOnDemandInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        APP_LOGE("get onDemandInstall bundle failed -n: %{public}s", bundleName.c_str());
        return false;
    }
    return true;
}
 
bool OnDemandInstallDataMgr::GetAllOnDemandInstallBundleInfos(std::vector<PreInstallBundleInfo> &preInstallBundleInfos)
{
    if (!onDemandDataStorage_->GetAllOnDemandInstallBundleInfos(preInstallBundleInfos)) {
        APP_LOGE("get all onDemandInstall bundle failed");
        return false;
    }
    return true;
}

void OnDemandInstallDataMgr::DeleteNoDataPreloadBundleInfos()
{
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    GetAllOnDemandInstallBundleInfos(preInstallBundleInfos);
    for (auto &preInstallBundleInfo : preInstallBundleInfos) {
        std::vector<std::string> bundlePaths = preInstallBundleInfo.GetBundlePaths();
        if (!bundlePaths.empty() && bundlePaths[0].rfind(ServiceConstants::DATA_PRELOAD_APP, 0) != 0) {
            DeleteOnDemandInstallBundleInfo(preInstallBundleInfo.GetBundleName());
        }
    }
}

bool OnDemandInstallDataMgr::IsOnDemandInstall(const InstallParam &installParam)
{
    auto iter = installParam.parameters.find(ON_DEMAND_INSTALL);
    return iter != installParam.parameters.end() && iter->second == BMS_TRUE;
}

std::string OnDemandInstallDataMgr::GetAppidentifier(const std::string &bundlePath)
{
    std::string appIdentifier;
    std::vector<std::string> rootDirList;
    BMSEventHandler::GetPreInstallRootDirList(rootDirList);
    if (rootDirList.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "dirList is empty");
        return appIdentifier;
    }

    BundleParser bundleParser;
    std::set<PreScanInfo> installList;
    std::set<PreScanInfo> onDemandInstallList;
    for (const auto &rootDir : rootDirList) {
        std::string dir = rootDir + ServiceConstants::PRODUCT_SUFFIX;
        if (!BundleUtil::IsExistDirNoLog(dir)) {
            LOG_W(BMS_TAG_DEFAULT, "parse dir %{public}s not exist", dir.c_str());
            continue;
        }
        bundleParser.ParsePreAppListConfig(dir + ServiceConstants::DEFAULT_DATA_PRE_BUNDLE_DIR,
            installList, onDemandInstallList);
    }
    for (const PreScanInfo &preScanInfo : onDemandInstallList) {
        if (bundlePath.rfind(preScanInfo.bundleDir, 0) == 0) {
            return preScanInfo.appIdentifier;
        }
    }
    return appIdentifier;
}
}  // namespace AppExecFwk
}  // namespace OHOS