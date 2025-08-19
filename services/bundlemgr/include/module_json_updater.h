/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_MODULE_JSON_UPDATER_H
#define FOUNDATION_BUNDLE_FRAMEWORK_MODULE_JSON_UPDATER_H

#include <map>
#include <mutex>
#include <set>
#include <string>

#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class ModuleJsonUpdater final {
public:
    static void UpdateModuleJsonAsync();
    static void SetIgnoreBundleNames(const std::set<std::string> &bundles);
private:
    static void UpdateModuleJson();
    static bool ParseBundleModuleJson(const InnerBundleInfo &curInfo, std::map<std::string, InnerBundleInfo> &moduleJsonMap);
    static bool ParseHapModuleJson(const std::string &hapPath, InnerBundleInfo &jsonInfo);
    static bool MergeInnerBundleInfo(const std::map<std::string, InnerBundleInfo> &moduleJsonMap, InnerBundleInfo &mergedInfo);
    static void UpdateExtensionType(const InnerBundleInfo &curInfo, InnerBundleInfo &mergedInfo);
    static bool CanUsePrivilegeExtension(const std::string &hapPath, const std::string &bundleName);
    static std::set<std::string> GetIgnoreBundleNames();
    static void ClearIgnoreBundleNames();
private:
    static std::set<std::string> ignoreBundleNames_;
    static std::mutex mutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_MODULE_JSON_UPDATER_H
