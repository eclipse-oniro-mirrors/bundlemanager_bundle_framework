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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_AGING_MODULE_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_AGING_MODULE_INFO_H

#include <iostream>
#include <string>

namespace OHOS {
namespace AppExecFwk {
class AgingModuleInfo {
public:
    AgingModuleInfo() = default;
    AgingModuleInfo(const std::string &bundleName, const std::string &moduleName, int64_t time)
        : bundleName_(bundleName), moduleName_(moduleName), recentlyUsedTime_(time) {};
    virtual ~AgingModuleInfo() = default;

    bool operator < (const AgingModuleInfo &agingModuleInfo) const
    {
        if (bundleName_ == agingModuleInfo.GetBundleName() &&
            moduleName_ == agingModuleInfo.GetModuleName()) {
            return false;
        }

        return recentlyUsedTime_ <= agingModuleInfo.GetRecentlyUsedTime();
    }

    const std::string &GetBundleName() const
    {
        return bundleName_;
    };

    const std::string &GetModuleName() const
    {
        return moduleName_;
    };

    int64_t GetRecentlyUsedTime() const
    {
        return recentlyUsedTime_;
    };

    std::string ToString() const
    {
        return "[ bundleName = " + bundleName_
            + ", moduleName = " + moduleName_
            + ", recentlyUsedTime = " + std::to_string(recentlyUsedTime_) + "]";
    }

private:
    std::string bundleName_;
    std::string moduleName_;
    int64_t recentlyUsedTime_ = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_AGING_MODULE_INFO_H