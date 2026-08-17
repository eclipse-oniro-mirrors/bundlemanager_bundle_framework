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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_ACCESS_TOKEN_RECOVERY_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_ACCESS_TOKEN_RECOVERY_MGR_H

#include <memory>
#include <vector>

#include "bundle_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
class BundleAccessTokenRecoveryMgr final {
public:
    // Restore every hap token recorded by BMS into the access token service when the access token
    // database is detected lost (persistable system parameter persist.accesstoken.permission.dberror
    // is set by ATM and stays set across boots until BMS finishes the recovery).
    // Called during BMS startup before the service reports ready, from two mount points
    // (OnBmsStarting db-loaded path and AfterBmsStart); mountPoint tells them apart in logs.
    // Idempotent across mount points: the reset call clears the parameter. Single-threaded by design.
    static void ProcessRecovery(const std::shared_ptr<BundleDataMgr> &dataMgr, const char *mountPoint);

private:
    static bool NeedRecovery();
    static void RestoreAllApps(const std::shared_ptr<BundleDataMgr> &dataMgr,
        const std::vector<AccessTokenRestoreInfo> &restoreInfos);
    static int32_t RestoreSingleApp(const std::shared_ptr<BundleDataMgr> &dataMgr,
        const AccessTokenRestoreInfo &restoreInfo, bool &alreadyExist);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_ACCESS_TOKEN_RECOVERY_MGR_H
