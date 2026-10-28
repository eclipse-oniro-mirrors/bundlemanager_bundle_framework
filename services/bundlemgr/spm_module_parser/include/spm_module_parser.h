/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SPM_MODULE_PARSER_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SPM_MODULE_PARSER_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
namespace Spm {

enum class BundleType : int32_t {
    APP = 0,
    ATOMIC_SERVICE = 1,
    SHARED = 2,
    APP_SERVICE_FWK = 3,
    APP_PLUGIN = 4,
    SKILL = 5,
};

struct DefinePermission {
    bool provisionEnable = true;
    bool distributedSceneEnable = false;
    bool isKernelEffect = false;
    bool hasValue = false;
    uint32_t labelId = 0;
    uint32_t descriptionId = 0;
    std::string name;
    std::string grantMode;
    std::string availableLevel;
    std::string label;
    std::string description;
    std::string availableType;
};

struct RequestPermission {
    uint32_t reasonId = 0;
    std::string name;
    std::string moduleName;
    std::string reason;
    std::string requiredFeature;
};

struct InnerModuleInfoForSpm {
    BundleType bundleType = BundleType::APP;
    std::vector<std::string> skillName;
    std::string bundleName;
    std::string moduleName;
    int32_t apiTargetVersion = 0;
    std::vector<DefinePermission> definePermission;
    std::vector<RequestPermission> requestPermission;
    bool allowAutoControlIntent = false;
    std::string moduleType;
};

/**
 * @brief Parse module.json content and extract fields needed by Spm.
 * @param moduleJson The raw JSON string of module.json.
 * @param moduleInfo Output struct populated with parsed data.
 * @return true if parsing succeeded, false otherwise.
 */
bool ParseSpmModule(const std::string &moduleJson, InnerModuleInfoForSpm &moduleInfo);

/**
 * @brief Compute the sandbox data directory name locally without IPC or file access.
 * @param bundleName The original bundle name.
 * @param appIndex The application instance index.
 * @return The original bundle name if appIndex <= 0; otherwise, "+clone-{appIndex}+{bundleName}".
 * @note Inputs are not validated. The same naming rule applies to all application types.
 */
std::string GetSandboxDataDirName(const std::string &bundleName, int32_t appIndex);

}  // namespace Spm
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_BUNDLE_FRAMEWORK_SPM_MODULE_PARSER_H
