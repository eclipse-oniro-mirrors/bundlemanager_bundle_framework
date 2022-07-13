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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_INSTALL_DATA_STORAGE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_INSTALL_DATA_STORAGE_RDB_H

#include "bundle_constants.h"
#include "preinstall_data_storage_interface.h"
#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class PreInstallDataStorageRdb :
    public IPreInstallDataStorage, public std::enable_shared_from_this<PreInstallDataStorageRdb>  {
public:
    PreInstallDataStorageRdb();
    ~PreInstallDataStorageRdb();

    bool SavePreInstallStorageBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo) override;
    bool LoadAllPreInstallBundleInfos(std::vector<PreInstallBundleInfo> &preInstallBundleInfos) override;
    bool DeletePreInstallStorageBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo) override;

private:
    void TransformStrToInfo(
        const std::map<std::string, std::string> &datas,
        std::vector<PreInstallBundleInfo> &preInstallBundleInfos);
    void UpdateDataBase(std::map<std::string, PreInstallBundleInfo> &infos);

    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_INSTALL_DATA_STORAGE_RDB_H
