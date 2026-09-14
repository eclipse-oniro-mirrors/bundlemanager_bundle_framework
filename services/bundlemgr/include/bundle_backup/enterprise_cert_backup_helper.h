/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ENTERPRISE_CERT_BACKUP_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ENTERPRISE_CERT_BACKUP_HELPER_H

#include <set>
#include <string>

#include "appexecfwk_errors.h"
#include "bundle_service_constants.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {

class EnterpriseCertBackupHelper {
public:
    // Scan <certRootDir>/<userId>/*.cer for each given userId (the caller scopes this
    // to the current active user), append base64 items to certsArray; a missing user
    // dir is skipped (not an error). certRootDir is injectable for tests.
    static ErrCode BackupToJson(nlohmann::json &certsArray, const std::set<int32_t> &userIds,
        const std::string &certRootDir = std::string(ServiceConstants::HAP_COPY_PATH) +
            ServiceConstants::ENTERPRISE_CERT_PATH);

    // Validate, clear local certs of the users present in the backup, reinstall each
    // via AddCertAndEnableKey, roll back on failure.
    static ErrCode RestoreFromJson(const nlohmann::json &certsArray,
        const std::string &certRootDir = std::string(ServiceConstants::HAP_COPY_PATH) +
            ServiceConstants::ENTERPRISE_CERT_PATH);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ENTERPRISE_CERT_BACKUP_HELPER_H
