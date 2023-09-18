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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_HANDLER
#define FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_HANDLER

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "aot/aot_args.h"
#include "inner_bundle_info.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class AOTHandler final {
public:
    static AOTHandler& GetInstance();
    void HandleInstall(const std::unordered_map<std::string, InnerBundleInfo> &infos) const;
    void HandleOTA() const;
    void HandleIdle() const;
private:
    AOTHandler() = default;
    ~AOTHandler() = default;
    DISALLOW_COPY_AND_MOVE(AOTHandler);

    bool IsSupportARM64() const;
    std::string GetArkProfilePath(const std::string &bundleName, const std::string &moduleName) const;
    std::optional<AOTArgs> BuildAOTArgs(
        const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const;
    void HandleInstallWithSingleHap(const InnerBundleInfo &info, const std::string &compileMode) const;
    void ClearArkCacheDir() const;
    void ResetAOTFlags() const;
    void HandleIdleWithSingleHap(
        const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const;
    bool CheckDeviceState() const;
    void AOTInternal(std::optional<AOTArgs> aotArgs, uint32_t versionCode) const;
private:
    mutable std::mutex executeMutex_;
    mutable std::mutex idleMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_HANDLER
