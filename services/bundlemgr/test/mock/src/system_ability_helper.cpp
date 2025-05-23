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

#include "system_ability_helper.h"

#include <map>

#include "system_ability_definition.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
std::map<int32_t, sptr<IRemoteObject>> g_abilities;
}  // namespace

sptr<IRemoteObject> SystemAbilityHelper::GetSystemAbility(const int32_t systemAbilityId)
{
    APP_LOGD("mock system ability helper get %{public}d system ability", systemAbilityId);
    auto iter = g_abilities.find(systemAbilityId);
    if (iter != g_abilities.end()) {
        return iter->second;
    }
    return nullptr;
}

bool SystemAbilityHelper::AddSystemAbility(const int32_t systemAbilityId, const sptr<IRemoteObject> &systemAbility)
{
    if (g_abilities.erase(systemAbilityId) > 0) {
        APP_LOGD("mock system ability helper add system ability erase exist key");
    }
    APP_LOGD("mock system ability helper emplace %{public}d system ability", systemAbilityId);
    g_abilities.emplace(systemAbilityId, systemAbility);
    // mock helper always return true.
    return true;
}

bool SystemAbilityHelper::RemoveSystemAbility(const int32_t systemAbilityId)
{
    APP_LOGD("mock system ability helper remove system ability");
    if (g_abilities.erase(systemAbilityId) > 0) {
        APP_LOGD("mock system ability helper remove %{public}d system ability erase exist key", systemAbilityId);
    }
    // mock helper always return true.
    return true;
}

int SystemAbilityHelper::UninstallApp(const std::string &bundleName, int32_t uid, int32_t appIndex)
{
    return 0;
}

int SystemAbilityHelper::UpgradeApp(const std::string &bundleName, int32_t uid, int32_t appIndex)
{
    return 0;
}

bool SystemAbilityHelper::UnloadSystemAbility(const int32_t systemAbilityId)
{
    APP_LOGD("mock system ability helper unload system ability");
    if (g_abilities.erase(systemAbilityId) > 0) {
        APP_LOGD("mock system ability helper unload %{public}d system ability erase exist key", systemAbilityId);
    }
    // mock helper always return true.
    return true;
}

#ifdef ABILITY_RUNTIME_ENABLE
bool SystemAbilityHelper::IsAppRunning(const sptr<IAppMgr> appMgrProxy,
    const std::string &bundleName, int32_t appCloneIndex)
{
    return false;
}
#endif
}  // namespace AppExecFwk
}  // namespace OHOS