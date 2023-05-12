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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_SANDBOX_MANAGER_DB_INTERFACE_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_SANDBOX_MANAGER_DB_INTERFACE_H

#include <map>
#include <string>
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class ISandboxManagerDb {
public:
    ISandboxManagerDb() = default;
    virtual ~ISandboxManagerDb() = default;

    virtual bool QueryAllSandboxInnerBundleInfo(
        std::unordered_map<std::string, InnerBundleInfo> &innerBundleInfos) = 0;

    virtual bool QuerySandboxInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &innerBundleInfo) = 0;

    virtual bool SaveSandboxInnerBundleInfo(const std::string &bundleName, const InnerBundleInfo &innerBundleInfo) = 0;

    virtual bool DeleteSandboxInnerBundleInfo(const std::string &bundleName) = 0;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_SANDBOX_MANAGER_DB_INTERFACE_H
