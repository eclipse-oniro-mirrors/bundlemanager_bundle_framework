/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_RDB_CONFIG_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_RDB_CONFIG_H

#include <string>
#include <vector>

#include "bundle_constants.h"
#include "bundle_service_constants.h"

namespace OHOS {
namespace AppExecFwk {
struct BmsRdbConfig {
    int32_t version { ServiceConstants::BUNDLE_RDB_VERSION };
    std::string dbPath { ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH };
    std::string dbName;
    std::string tableName;
    std::string createTableSql;
    std::vector<std::string> insertColumnSql;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_RDB_CONFIG_H
