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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_DATA_STORAGE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_DATA_STORAGE_RDB_H

#include "bundle_constants.h"
#include "bundle_data_storage_interface.h"
#include "inner_bundle_info.h"
#include "rdb_data_manager.h"
#include "single_delayed_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {
class BundleDataStorageRdb :
    public IBundleDataStorage, public std::enable_shared_from_this<BundleDataStorageRdb> {
public:
    BundleDataStorageRdb();
    ~BundleDataStorageRdb();

    bool LoadAllData(std::map<std::string, InnerBundleInfo> &infos) override;
    bool SaveStorageBundleInfo(const InnerBundleInfo &innerBundleInfo) override;
    bool DeleteStorageBundleInfo(const InnerBundleInfo &innerBundleInfo) override;
    virtual bool ResetKvStore() override;

private:
    void TransformStrToInfo(
        const std::map<std::string, std::string> &datas,
        std::map<std::string, InnerBundleInfo> &infos);
    void UpdateDataBase(std::map<std::string, InnerBundleInfo> &infos);

    void BackupRdb();

    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
    std::shared_ptr<SingleDelayedTaskMgr> delayedTaskMgr_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_DATA_STORAGE_RDB_H
