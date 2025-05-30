/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SYSTEM_ABILITY_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SYSTEM_ABILITY_HELPER_H

#include <string>

#include "iremote_object.h"
#ifdef ABILITY_RUNTIME_ENABLE
#include "app_mgr_interface.h"
#include "running_process_info.h"
#endif

namespace OHOS {
namespace AppExecFwk {
class SystemAbilityHelper {
public:
    /**
     * @brief Get a pointer to a IRemoteObject object from system ability service.
     * @param systemAbilityId Indicates the system ability ID to be got.
     * @return Returns a pointer to the IRemoteObject object.
     */
    static sptr<IRemoteObject> GetSystemAbility(const int32_t systemAbilityId);
    /**
     * @brief Register a service to the system ability service.
     * @param systemAbilityId Indicates the system ability ID to be registered.
     * @param systemAbility Indicates the IRemoteObject pointer to be registered.
     * @return Returns true if the pointer registered successfully; returns false otherwise.
     */
    static bool AddSystemAbility(const int32_t systemAbilityId, const sptr<IRemoteObject> &systemAbility);
    /**
     * @brief Unregister a service from the system ability service.
     * @param systemAbilityId Indicates the system ability ID to be unregistered.
     * @return Returns true if the service unregistered successfully; returns false otherwise.
     */
    static bool RemoveSystemAbility(const int32_t systemAbilityId);

    /**
     * Uninstall app
     *
     * @param bundleName bundle name of uninstalling app.
     * @param uid uid of bundle.
     * @return Returns ERR_OK on success, others on failure.
     */
    static int UninstallApp(const std::string &bundleName, int32_t uid, int32_t appIndex);

    static int UpgradeApp(const std::string &bundleName, int32_t uid, int32_t appIndex);

    static bool UnloadSystemAbility(const int32_t systemAbilityId);
#ifdef ABILITY_RUNTIME_ENABLE
    static bool IsAppRunning(const sptr<IAppMgr> appMgrProxy,
        const std::string &bundleName, int32_t appCloneIndex);
#endif
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SYSTEM_ABILITY_HELPER_H