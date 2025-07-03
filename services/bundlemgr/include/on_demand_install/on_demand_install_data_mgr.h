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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_ON_DEMAND_INSTALL_DATA_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_ON_DEMAND_INSTALL_DATA_MGR_H
 
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

#include "install_param.h"
#include "on_demand_install_data_storage_rdb.h"
#include "pre_install_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
 
class OnDemandInstallDataMgr {
public:
    virtual ~OnDemandInstallDataMgr();
    
    static OnDemandInstallDataMgr &GetInstance();

    /**
     * @brief Save new OnDemandInstallBundleInfo.
     * @param bundleName Indicates the bundle name.
     * @param preInstallBundleInfo Indicates the PreInstallBundleInfo object to be save.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool SaveOnDemandInstallBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo);
    /**
     * @brief Delete OnDemandInstallBundleInfo.
     * @param bundleName Indicates the bundle name of the application.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool DeleteOnDemandInstallBundleInfo(const std::string &bundleName);
    /**
     * @brief Obtains the OnDemandInstallBundleInfo objects provided by bundleName.
     * @param bundleName Indicates the bundle name of the application.
     * @param preInstallBundleInfo Indicates information about the PreInstallBundleInfo.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetOnDemandInstallBundleInfo(const std::string &bundleName, PreInstallBundleInfo &preInstallBundleInfo);
    /**
     * @brief Obtains the all OnDemandInstallBundleInfo.
     * @param preInstallBundleInfos Indicates information about the PreInstallBundleInfos.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetAllOnDemandInstallBundleInfos(std::vector<PreInstallBundleInfo> &preInstallBundleInfos);

    void DeleteNoDataPreloadBundleInfos();

    bool IsOnDemandInstall(const InstallParam &installParam);

    std::string GetAppidentifier(const std::string &bundlePath);

private:
    OnDemandInstallDataMgr();
    std::shared_ptr<OnDemandInstallDataStorageRdb> onDemandDataStorage_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_ON_DEMAND_INSTALL_DATA_MGR_H