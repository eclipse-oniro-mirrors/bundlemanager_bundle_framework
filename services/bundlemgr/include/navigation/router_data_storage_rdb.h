/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ROUTER_DATA_STORAGE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ROUTER_DATA_STORAGE_RDB_H

#include "rdb_data_manager.h"
#include "router_data_storage_interface.h"

namespace OHOS {
namespace AppExecFwk {
class RouterDataStorageRdb :
    public IRouterDataStorage, public std::enable_shared_from_this<RouterDataStorageRdb>  {
public:
    RouterDataStorageRdb();
    ~RouterDataStorageRdb();
    bool UpdateRouterInfo(const std::string &bundleName,
        const std::map<std::string, std::string> &routerInfoMap, const uint32_t versionCode);
    bool GetRouterInfo(const std::string &bundleName, const std::string &moduleName,
        const uint32_t versionCode, std::vector<RouterItem> &routerInfos);
    void GetAllBundleNames(std::set<std::string> &bundleNames);
    bool DeleteRouterInfo(const std::string &bundleName);
    bool DeleteRouterInfo(const std::string &bundleName, const std::string &moduleName);
    bool DeleteRouterInfo(const std::string &bundleName,
        const std::string &moduleName, const uint32_t versionCode);
    bool UpdateDB();
    bool InsertRouterInfo(const std::string &bundleName,
        const std::map<std::string, std::string> &routerInfoMap, const uint32_t versionCode);
    bool GetRouterInfoFromOldDB(const std::string &bundleName,
        const std::string &moduleName, std::vector<RouterItem> &routerInfos);
private:
    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ROUTER_DATA_STORAGE_RDB_H