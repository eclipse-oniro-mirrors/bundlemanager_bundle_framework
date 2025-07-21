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

#include "ability_manager_helper.h"

#include "bundle_mgr_service.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"

#include "app_log_tag_wrapper.h"
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
#include "ability_manager_client.h"
#include "app_mgr_interface.h"
#include "running_process_info.h"
#endif

namespace OHOS {
namespace AppExecFwk {
bool AbilityManagerHelper::UninstallApplicationProcesses(
    const std::string &bundleName, const int uid, bool isUpgradeApp, int32_t appIndex)
{
#ifdef ABILITY_RUNTIME_ENABLE
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "begin UninstallApplicationProcesses -n %{public}s, -up %{public}d, -u %{public}d,"
        "-i %{public}d", bundleName.c_str(), isUpgradeApp, uid, appIndex);
    int ret = 0;
    if (isUpgradeApp) {
        ret = SystemAbilityHelper::UpgradeApp(bundleName, uid, appIndex);
    } else {
        ret = SystemAbilityHelper::UninstallApp(bundleName, uid, appIndex);
    }
    if (ret != 0) {
        APP_LOGE("kill application process failed uid: %{public}d, appIndex: %{public}d", uid, appIndex);
        return false;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "UninstallApplicationProcesses end");
    return true;
#else
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "ABILITY_RUNTIME_ENABLE is false");
    return true;
#endif
}

int32_t AbilityManagerHelper::IsRunning(const std::string &bundleName)
{
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "IsRunning check %{public}s", bundleName.c_str());
    sptr<IAppMgr> appMgrProxy =
        iface_cast<IAppMgr>(SystemAbilityHelper::GetSystemAbility(APP_MGR_SERVICE_ID));
    if (appMgrProxy == nullptr) {
        APP_LOGE("fail to find the app mgr service to check app is running");
        return FAILED;
    }

    std::vector<RunningProcessInfo> runningList;
    int result = appMgrProxy->GetAllRunningProcesses(runningList);
    if (result != ERR_OK) {
        APP_LOGE("GetAllRunningProcesses failed");
        return FAILED;
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "size %{public}zu", runningList.size());

    for (const auto &info : runningList) {
        auto res = std::any_of(info.bundleNames.begin(), info.bundleNames.end(),
            [bundleName](const auto &bundleNameInRunningProcessInfo) {
                return bundleNameInRunningProcessInfo == bundleName;
            });
        if (res) {
            return RUNNING;
        }
    }

    return NOT_RUNNING;
#else
APP_LOGI("BUNDLE_FRAMEWORK_FREE_INSTALL is false");
    return FAILED;
#endif
}

int32_t AbilityManagerHelper::QueryRunningSharedBundles(
    const pid_t pid, std::map<std::string, uint32_t> &shareBundles)
{
#ifdef ABILITY_RUNTIME_ENABLE
    sptr<IAppMgr> appMgrProxy =
        iface_cast<IAppMgr>(SystemAbilityHelper::GetSystemAbility(APP_MGR_SERVICE_ID));
    if (appMgrProxy == nullptr) {
        APP_LOGE("fail to find the app mgr service");
        return FAILED;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    // int32_t ret = appMgrProxy->QueryRunningSharedBundles(pid, shareBundles);
    IPCSkeleton::SetCallingIdentity(identity);
    return 0;
#else
    APP_LOGI("ABILITY_RUNTIME_ENABLE is false");
    return FAILED;
#endif
}
}  // namespace AppExecFwk
}  // namespace OHOS
