/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_INSTALL_DATA_STORAGE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_INSTALL_DATA_STORAGE_H

#include <mutex>

#include "bundle_constants.h"
#include "distributed_kv_data_manager.h"
#include "preinstall_data_storage_interface.h"

namespace OHOS {
namespace AppExecFwk {
class PreInstallDataStorage :
    public IPreInstallDataStorage, public std::enable_shared_from_this<PreInstallDataStorage>  {
public:
    PreInstallDataStorage();
    ~PreInstallDataStorage();

    bool SavePreInstallStorageBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo) override;
    bool LoadAllPreInstallBundleInfos(std::vector<PreInstallBundleInfo> &preInstallBundleInfos) override;
    bool DeletePreInstallStorageBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo) override;

private:
    void TryTwice(const std::function<DistributedKv::Status()>& func) const;
    bool CheckKvStore();
    DistributedKv::Status GetKvStore();
    bool ResetKvStore();
    DistributedKv::Status GetEntries(std::vector<DistributedKv::Entry> &allEntries) const;
    void SaveEntries(const std::vector<DistributedKv::Entry> &allEntries,
        std::vector<PreInstallBundleInfo> &preInstallBundleInfos);
    void UpdateDataBase(std::map<std::string, PreInstallBundleInfo>& infos);
    void DeleteOldBundleInfo(const std::string& oldKey);

private:
    const DistributedKv::AppId appId_ { Constants::APP_ID };
    const DistributedKv::StoreId storeId_ { Constants::PRE_INSTALL_DATA_STORE_ID };
    DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
    mutable std::mutex kvStorePtrMutex_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_INSTALL_DATA_STORAGE_H
