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
#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_PROVISION_INFO_MANAGER_RDB_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_PROVISION_INFO_MANAGER_RDB_H

#include <string>
#include <unordered_set>

#include "appexecfwk_errors.h"
#include "app_provision_info.h"
#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class AppProvisionInfoManagerRdb {
public:
    AppProvisionInfoManagerRdb();
    ~AppProvisionInfoManagerRdb();
    bool AddAppProvisionInfo(const std::string &bundleName, const AppProvisionInfo &appProvisionInfo);
    bool DeleteAppProvisionInfo(const std::string &bundleName);
    bool GetAppProvisionInfo(const std::string &bundleName, AppProvisionInfo &appProvisionInfo);
    bool GetAllAppProvisionInfoBundleName(std::unordered_set<std::string> &bundleNames);

    bool SetSpecifiedDistributionType(const std::string &bundleName, const std::string &specifiedDistributionType);
    bool GetSpecifiedDistributionType(const std::string &bundleName, std::string &specifiedDistributionType);
    bool SetAdditionalInfo(const std::string &bundleName, const std::string &additionalInfo);
    bool GetAdditionalInfo(const std::string &bundleName, std::string &additionalInfo);

private:
    bool ConvertToAppProvision(const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet,
        AppProvisionInfo &appProvisionInfo);
    std::shared_ptr<RdbDataManager> rdbDataManager_;

#define CHECK_RDB_RESULT_RETURN_IF_FAIL(errcode, errmsg)                           \
    do {                                                                           \
        if ((errcode) != NativeRdb::E_OK) {                                          \
            APP_LOGE(errmsg, errcode);                                             \
            return false;                                                          \
        }                                                                          \
    } while (0)
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_PROVISION_INFO_MANAGER_RDB_H
