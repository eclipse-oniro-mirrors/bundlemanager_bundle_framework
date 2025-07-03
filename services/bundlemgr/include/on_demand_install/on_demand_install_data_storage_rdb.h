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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ON_DEMAND_INSTALL_DATA_STORAGE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ON_DEMAND_INSTALL_DATA_STORAGE_RDB_H

#include "pre_install_bundle_info.h"
#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class OnDemandInstallDataStorageRdb : public std::enable_shared_from_this<OnDemandInstallDataStorageRdb>  {
public:
    OnDemandInstallDataStorageRdb();
    ~OnDemandInstallDataStorageRdb();

    bool SaveOnDemandInstallBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo);

    bool DeleteOnDemandInstallBundleInfo(const std::string &bundleName);

    bool GetOnDemandInstallBundleInfo(const std::string &bundleName,
        PreInstallBundleInfo &preInstallBundleInfo);

    bool GetAllOnDemandInstallBundleInfos(std::vector<PreInstallBundleInfo> &preInstallBundleInfos);

private:
    void TransformStrToInfo(
        const std::map<std::string, std::string> &datas,
        std::vector<PreInstallBundleInfo> &preInstallBundleInfos);

    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ON_DEMAND_INSTALL_DATA_STORAGE_RDB_H