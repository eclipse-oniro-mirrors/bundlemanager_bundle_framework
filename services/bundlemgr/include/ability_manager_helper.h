/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ABILITY_MANAGER_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ABILITY_MANAGER_HELPER_H

#include <string>

namespace OHOS {
namespace AppExecFwk {
class AbilityManagerHelper {
public:
    enum IsRunningResult : int8_t {
        FAILED = -1,
        NOT_RUNNING = 0,
        RUNNING = 1,
    };

    static bool UninstallApplicationProcesses(
        const std::string &bundleName, const int uid, bool isUpgradeApp = false, int32_t appIndex = 0);
    static int32_t IsRunning(const std::string &bundleName);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ABILITY_MANAGER_HELPER_H
