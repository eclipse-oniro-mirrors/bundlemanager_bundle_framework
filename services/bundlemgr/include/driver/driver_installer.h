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

#include <unordered_map>

#include "application_info.h"
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class DriverInstaller {
public:
    DriverInstaller() = default;
    ~DriverInstaller() = default;

    ErrCode CopyDriverSoFile(const InnerBundleInfo &info, const std::string &srcPath) const;

    ErrCode FilterDriverSoFile(const InnerBundleInfo &info, const Metadata &meta,
        std::unordered_multimap<std::string, std::string> &dirMap) const;

    void RemoveDriverSoFile(const InnerBundleInfo &info, const std::string &moduleName = std::string()) const;

    std::string CreateDriverSoDestinedDir(const std::string &bundleName, const std::string &moduleName,
        const std::string &fileName, const std::string &destinedDir) const;
};
} // AppExecFwk
} // OHOS
