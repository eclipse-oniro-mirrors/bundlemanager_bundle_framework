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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_INNER_ABILITY_INFO_H
#define FOUNDATION_BUNDLE_FRAMEWORK_INNER_ABILITY_INFO_H

#include "ability_info.h"

namespace OHOS {
namespace AppExecFwk {
struct InnerAbilityInfo {
    bool visible = false;
    bool isLauncherAbility = false;
    bool isNativeAbility = false;
    bool enabled = false;
    bool supportPipMode = false;
    bool formEnabled = false;
    bool removeMissionAfterTerminate = false;
    bool isModuleJson = false;
    bool isStageBasedModel = false;
    bool continuable = false;
    bool excludeFromMissions = false;
    bool unclearableMission = false;
    bool excludeFromDock = false;
    bool recoverable = false;
    bool isolationProcess = false;
    bool multiUserShared = false;
    bool grantPermission = false;
    bool directLaunch = true;
    LinkType linkType = LinkType::DEEP_LINK;
    uint32_t labelId = 0;
    uint32_t descriptionId = 0;
    uint32_t iconId = 0;
    uint32_t orientationId = 0;
    uint32_t formEntity = 0;
    uint32_t backgroundModes = 0;
    uint32_t startWindowId = 0;
    uint32_t startWindowIconId = 0;
    uint32_t startWindowBackgroundId = 0;
    uint32_t maxWindowWidth = 0;
    uint32_t minWindowWidth = 0;
    uint32_t maxWindowHeight = 0;
    uint32_t minWindowHeight = 0;
    uint32_t packageSize = 0;
    int32_t minFormHeight = 0;
    int32_t defaultFormHeight = 0;
    int32_t minFormWidth = 0;
    int32_t defaultFormWidth = 0;
    int32_t priority = 0;
    int32_t appIndex = 0;
    int32_t uid = -1;
    AbilityType type = AbilityType::UNKNOWN;
    ExtensionAbilityType extensionAbilityType = ExtensionAbilityType::UNSPECIFIED;
    DisplayOrientation orientation = DisplayOrientation::UNSPECIFIED;
    LaunchMode launchMode = LaunchMode::SINGLETON;
    CompileMode compileMode = CompileMode::JS_BUNDLE;
    AbilitySubType subType = AbilitySubType::UNSPECIFIED;
    int64_t installTime = 0;
    double maxWindowRatio = 0;
    double minWindowRatio = 0;
    std::string name;
    std::string label;
    std::string description;
    std::string iconPath;
    std::string theme;
    std::string kind;
    std::string extensionTypeName;
    std::string srcPath;
    std::string srcLanguage = Constants::SRC_LANGUAGE_JS;
    std::string arkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    std::string process;
    std::string uri;
    std::string targetAbility;
    std::string readPermission;
    std::string writePermission;
    std::string package;
    std::string bundleName;
    std::string moduleName;
    std::string applicationName;
    std::string codePath;
    std::string resourcePath;
    std::string hapPath;
    std::string srcEntrance;
    std::string startWindow;
    std::string startWindowIcon;
    std::string startWindowBackground;
    std::string preferMultiWindowOrientation = Constants::PREFER_MULTI_WINDOW_ORIENTATION_DEFAULT;
    std::string originalBundleName;
    std::string appName;
    std::string privacyUrl;
    std::string privacyName;
    std::string downloadUrl;
    std::string versionName;
    std::string className;
    std::string originalClassName;
    std::string uriPermissionMode;
    std::string uriPermissionPath;
    std::string libPath;
    std::string deviceId;
    std::vector<std::string> permissions;
    std::vector<std::string> deviceTypes;
    std::vector<std::string> deviceCapabilities;
    std::vector<std::string> configChanges;
    std::vector<SkillUriForAbilityAndExtension> skillUri;
    std::vector<Skill> skills;
    std::vector<Metadata> metadata;
    std::vector<SupportWindowMode> windowModes;
    std::vector<std::string> supportExtNames;
    std::vector<std::string> supportMimeTypes;
    std::vector<std::string> continueType;
    MetaData metaData;
    std::unordered_set<std::string> continueBundleNames;
    StartWindowResource startWindowResource;

    static AbilityInfo ConvertToAbilityInfo(const InnerAbilityInfo &innerAbilityInfo);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_INNER_ABILITY_INFO_H
