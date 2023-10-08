/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_RESOURCE_SYSTEM_STATE_H
#define FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_RESOURCE_SYSTEM_STATE_H

#include <shared_mutex>
#include <string>

namespace OHOS {
namespace AppExecFwk {
class BundleSystemState {
public:
    ~BundleSystemState();

    static BundleSystemState &GetInstance();

    void SetSystemLanguage(const std::string &language);

    std::string GetSystemLanguage();

    void SetSystemColorMode(const std::string &colorMode);

    std::string GetSystemColorMode();

    std::string ToString();

    bool FromString(const std::string &systemState);

private:
    BundleSystemState();
    std::shared_mutex stateMutex_;
    // system language
    std::string language_;
    // colorMode : light dark
    std::string colorMode_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_RESOURCE_SYSTEM_STATE_H
