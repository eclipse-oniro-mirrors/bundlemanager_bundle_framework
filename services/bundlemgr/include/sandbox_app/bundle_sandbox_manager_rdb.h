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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_SANDBOX_MANAGER_RDB_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_SANDBOX_MANAGER_RDB_H

#include "bundle_sandbox_manager_db_interface.h"
#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class SandboxManagerRdb final :
    public ISandboxManagerDb,
    public std::enable_shared_from_this<SandboxManagerRdb> {
public:
    SandboxManagerRdb();
    ~SandboxManagerRdb();

    bool QueryAllSandboxInnerBundleInfo(std::unordered_map<std::string, InnerBundleInfo> &innerBundleInfos) override;
    bool QuerySandboxInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &innerBundleInfos) override;
    bool SaveSandboxInnerBundleInfo(const std::string &bundleName, const InnerBundleInfo &innerBundleInfos) override;
    bool DeleteSandboxInnerBundleInfo(const std::string &bundleName) override;

private:
    bool GetAllDataFromDb(std::unordered_map<std::string, InnerBundleInfo> &innerBundleInfos);
    bool GetDataFromDb(const std::string &bundleName, InnerBundleInfo &innerBundleInfo);
    bool SaveDataToDb(const std::string &bundleName, const InnerBundleInfo &innerBundleInfo);
    bool DeleteDataFromDb(const std::string &bundleName);

    std::shared_ptr<RdbDataManager> rdbDataManager_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_SANDBOX_MANAGER_RDB_H
