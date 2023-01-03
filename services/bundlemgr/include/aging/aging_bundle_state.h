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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_AGING_BUNDLE_STATE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_AGING_BUNDLE_STATE_H

#include <map>
#include <string>

namespace OHOS {
namespace AppExecFwk {
class AgingBundleState {
public:
    AgingBundleState() = default;
    AgingBundleState(const std::string &bundleName, int32_t totalModuleNum);
    virtual ~AgingBundleState() = default;

    bool operator == (const AgingBundleState &agingBundleState) const
    {
        return bundleName_ == agingBundleState.GetBundleName();
    }

    const std::string &GetBundleName() const
    {
        return bundleName_;
    };

    void ChangeModuleCacheState(const std::string &moduleName, bool state);

    bool GetCacheState(const std::string &moduleName, bool &state) const;;

    bool CanClearBundleCache() const;;

    void Clear();

private:
    std::string bundleName_;
    // used to record how many module cache of the bundle have not been cleared,
    // and the bundle cache can be cleared When cacheNum is zero.
    int32_t cacheNum_;
    // all module cache states
    // key : removable moduleName
    // value : cache states
    std::map<std::string, bool> moduleCache_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_AGING_BUNDLE_STATE_H