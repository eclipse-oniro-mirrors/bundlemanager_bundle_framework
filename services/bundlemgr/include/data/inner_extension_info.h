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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_INNER_EXTENSION_INFO_H
#define FOUNDATION_BUNDLE_FRAMEWORK_INNER_EXTENSION_INFO_H

#include "extension_ability_info.h"

namespace OHOS {
namespace AppExecFwk {
struct InnerExtensionInfo {
    bool visible = false;
    bool enabled = true;
    bool needCreateSandbox = false;
    bool isolationProcess = false;
    uint32_t iconId = 0;
    uint32_t labelId = 0;
    uint32_t descriptionId = 0;
    int32_t priority = 0;
    int32_t uid = -1;
    int32_t appIndex = 0;
    ExtensionAbilityType type = ExtensionAbilityType::UNSPECIFIED;
    CompileMode compileMode = CompileMode::JS_BUNDLE;
    ExtensionProcessMode extensionProcessMode = ExtensionProcessMode::UNDEFINED;
    std::string bundleName;
    std::string moduleName;
    std::string name;
    std::string srcEntrance;
    std::string icon;
    std::string label;
    std::string description;
    std::string readPermission;
    std::string writePermission;
    std::string uri;
    std::string extensionTypeName;
    std::string resourcePath;
    std::string hapPath;
    std::string process;
    std::string customProcess;
    std::string arkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    std::vector<std::string> permissions;
    std::vector<std::string> appIdentifierAllowList;
    std::vector<Metadata> metadata;
    std::vector<SkillUriForAbilityAndExtension> skillUri;
    std::vector<Skill> skills;
    std::vector<std::string> dataGroupIds;
    std::vector<std::string> validDataGroupIds;

    static ExtensionAbilityInfo ConvertToExtensionInfo(const InnerExtensionInfo &innerExtensionInfo);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_INNER_EXTENSION_INFO_H
