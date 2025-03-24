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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_UNINSTALL_DATA_MGR_STORAGE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_UNINSTALL_DATA_MGR_STORAGE_RDB_H

#include "rdb_data_manager.h"
#include "uninstall_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class UninstallDataMgrStorageRdb : public std::enable_shared_from_this<UninstallDataMgrStorageRdb> {
public:
    UninstallDataMgrStorageRdb();
    ~UninstallDataMgrStorageRdb();
    bool UpdateUninstallBundleInfo(const std::string &bundleName, const UninstallBundleInfo &uninstallBundleInfo);
    bool GetUninstallBundleInfo(const std::string &bundleName, UninstallBundleInfo &uninstallBundleInfo);
    bool DeleteUninstallBundleInfo(const std::string &bundleName);
    bool GetAllUninstallBundleInfo(std::map<std::string, UninstallBundleInfo> &uninstallBundleInfos);
private:
    void TransformStrToInfo(const std::map<std::string, std::string> &datas,
        std::map<std::string, UninstallBundleInfo> &uninstallBundleInfos);
    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_UNINSTALL_DATA_MGR_STORAGE_RDB_H
