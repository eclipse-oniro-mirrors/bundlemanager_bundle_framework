/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "aging/aging_bundle_state.h"

namespace OHOS {
namespace AppExecFwk {
AgingBundleState::AgingBundleState(const std::string &bundleName, int32_t totalModuleNum)
    : bundleName_(bundleName), cacheNum_(totalModuleNum) {}

void AgingBundleState::ChangeModuleCacheState(const std::string &moduleName, bool state)
{
    auto item = moduleCache_.find(moduleName);
    if (item == moduleCache_.end()) {
        moduleCache_.emplace(moduleName, state);
        return;
    }

    item->second = state;
    if (!state) {
        cacheNum_--;
    }
}

bool AgingBundleState::GetCacheState(const std::string &moduleName, bool &state) const
{
    auto item = moduleCache_.find(moduleName);
    if (item == moduleCache_.end()) {
        return false;
    }

    state = item->second;
    return true;
}

bool AgingBundleState::CanClearBundleCache() const
{
    return cacheNum_ == 0;
}

void AgingBundleState::Clear()
{
    moduleCache_.clear();
}
}  //  namespace AppExecFwk
}  //  namespace OHOS