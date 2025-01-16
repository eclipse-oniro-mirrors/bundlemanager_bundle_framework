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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FIRST_INSTALL_DATA_MGR_STORAGE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FIRST_INSTALL_DATA_MGR_STORAGE_RDB_H

#include "first_install_bundle_info.h"
#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class FirstInstallDataMgrStorageRdb : public std::enable_shared_from_this<FirstInstallDataMgrStorageRdb> {
public:
    FirstInstallDataMgrStorageRdb();
    ~FirstInstallDataMgrStorageRdb();
    bool IsExistFirstInstallBundleInfo(const std::string &bundleName, int32_t userId);
    bool AddFirstInstallBundleInfo(const std::string &bundleName, int32_t userId,
        const FirstInstallBundleInfo &firstInstallBundleInfo);
    bool GetFirstInstallBundleInfo(const std::string &bundleName, int32_t userId,
        FirstInstallBundleInfo &firstInstallBundleInfo);
    bool DeleteFirstInstallBundleInfo(int32_t userId);

private:
    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FIRST_INSTALL_DATA_MGR_STORAGE_RDB_H