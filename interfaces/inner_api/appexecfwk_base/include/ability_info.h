/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_ABILITY_INFO_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_ABILITY_INFO_H

#include <string>
#include <unordered_set>

#include "parcel.h"
#include "application_info.h"
#include "extension_ability_info.h"

namespace OHOS {
namespace AppExecFwk {
enum AbilityInfoFlag : uint16_t {
    GET_ABILITY_INFO_DEFAULT = 0x00000000,
    GET_ABILITY_INFO_WITH_PERMISSION = 0x00000002,
    GET_ABILITY_INFO_WITH_APPLICATION = 0x00000004,
    GET_ABILITY_INFO_WITH_METADATA = 0x00000020,
    GET_ABILITY_INFO_SYSTEMAPP_ONLY = 0x00000080,
    GET_ABILITY_INFO_WITH_DISABLE = 0x00000100,
    GET_ABILITY_INFO_WITH_SKILL_URI = 0x00000200,
    GET_ABILITY_INFO_WITH_SKILL = 0x00000400
};

enum class GetAbilityInfoFlag : uint16_t {
    GET_ABILITY_INFO_DEFAULT = 0x00000000,
    GET_ABILITY_INFO_WITH_PERMISSION = 0x00000001,
    GET_ABILITY_INFO_WITH_APPLICATION = 0x00000002,
    GET_ABILITY_INFO_WITH_METADATA = 0x00000004,
    GET_ABILITY_INFO_WITH_DISABLE = 0x00000008,
    GET_ABILITY_INFO_ONLY_SYSTEM_APP = 0x00000010,
    GET_ABILITY_INFO_WITH_SKILL_URI = 0x00000020,
    GET_ABILITY_INFO_WITH_APP_LINKING = 0x00000040,
    GET_ABILITY_INFO_WITH_SKILL = 0x00000080
};

enum class AbilityType {
    UNKNOWN = 0,
    PAGE,
    SERVICE,
    DATA,
    FORM,
    EXTENSION,
};

enum class BackgroundMode {
    DEFAULT = 0,
    DATA_TRANSFER = 1 << 0,
    AUDIO_PLAYBACK = 1 << 1,
    AUDIO_RECORDING = 1 << 2,
    LOCATION = 1 << 3,
    BLUETOOTH_INTERACTION = 1 << 4,
    MULTI_DEVICE_CONNECTION = 1 << 5,
    WIFI_INTERACTION = 1 << 6,
    VOIP = 1 << 7,
    TASK_KEEPING = 1 << 8,
};

enum class AbilitySubType {
    UNSPECIFIED = 0,
    CA,
};

enum class DisplayOrientation {
    UNSPECIFIED = 0,
    LANDSCAPE,
    PORTRAIT,
    FOLLOWRECENT,
    LANDSCAPE_INVERTED,
    PORTRAIT_INVERTED,
    AUTO_ROTATION,
    AUTO_ROTATION_LANDSCAPE,
    AUTO_ROTATION_PORTRAIT,
    AUTO_ROTATION_RESTRICTED,
    AUTO_ROTATION_LANDSCAPE_RESTRICTED,
    AUTO_ROTATION_PORTRAIT_RESTRICTED,
    LOCKED,
    AUTO_ROTATION_UNSPECIFIED,
    FOLLOW_DESKTOP,
};

enum class LaunchMode {
    SINGLETON = 0,
    STANDARD,  // support more than one instance
    SPECIFIED,
};

enum class SupportWindowMode {
    FULLSCREEN = 0,
    SPLIT,
    FLOATING,
};

enum class LinkType : uint8_t {
    DEEP_LINK = 0,
    APP_LINK,
    DEFAULT_APP,
};

struct AbilityInfo;

/*
* According to Ability profile 1.0
*/
struct CompatibleAbilityInfo : public Parcelable {
    // deprecated: ability code class simple name, use 'className' instead.
    std::string package;
    std::string name;
    std::string label; // display name on screen.
    std::string description;
    std::string iconPath; // used as icon data (base64) for WEB Ability.
    std::string uri; // uri of ability.
    std::string moduleName; // indicates the name of the .hap package to which the capability belongs.
    std::string process;
    std::string targetAbility;
    std::string appName;
    std::string privacyUrl;
    std::string privacyName;
    std::string downloadUrl;
    std::string versionName;
    uint32_t backgroundModes = 0;
    uint32_t packageSize = 0; // The size of the package that AbilityInfo.uri points to.
    bool visible = false;
    bool formEnabled = false;
    bool multiUserShared = false;
    // deprecated: remove this field in new package format.
    AbilityType type = AbilityType::UNKNOWN;
    AbilitySubType subType = AbilitySubType::UNSPECIFIED;
    DisplayOrientation orientation = DisplayOrientation::UNSPECIFIED;
    LaunchMode launchMode = LaunchMode::SINGLETON;
    std::vector<std::string> permissions;
    std::vector<std::string> deviceTypes;
    std::vector<std::string> deviceCapabilities;
    bool supportPipMode = false;
    bool grantPermission = false;
    std::string readPermission;
    std::string writePermission;
    std::string uriPermissionMode;
    std::string uriPermissionPath;
    bool directLaunch = true;

    // set when install
    std::string bundleName; // bundle name which has this ability.
    std::string className;  // the ability full class name.
    std::string originalClassName; // the original ability full class name
    std::string deviceId; // device UDID information.
    CompatibleApplicationInfo applicationInfo;

    // form widget info
    uint32_t formEntity = 1; // where form can be displayed
    int32_t minFormHeight = 0; // minimum height of ability.
    int32_t defaultFormHeight = 0; // default height of ability.
    int32_t minFormWidth = 0; // minimum width of ability.
    int32_t defaultFormWidth = 0; // default width of ability.

    uint32_t iconId = 0;
    uint32_t labelId = 0;
    uint32_t descriptionId = 0;
    bool enabled = true;

    bool ReadFromParcel(Parcel& parcel);
    virtual bool Marshalling(Parcel& parcel) const override;
    static CompatibleAbilityInfo* Unmarshalling(Parcel& parcel);

    void ConvertToAbilityInfo(AbilityInfo& abilityInfo) const;
};

// configuration information about an ability
struct AbilityInfo : public Parcelable {
    std::string name;  // ability name, only the main class name
    std::string label;
    std::string description;
    std::string iconPath;
    uint32_t labelId = 0;
    uint32_t descriptionId = 0;
    uint32_t iconId = 0;
    std::string theme;
    bool visible = false;
    std::string kind;  // ability category
    AbilityType type = AbilityType::UNKNOWN;
    ExtensionAbilityType extensionAbilityType = ExtensionAbilityType::UNSPECIFIED;
    std::string extensionTypeName;
    DisplayOrientation orientation = DisplayOrientation::UNSPECIFIED;
    uint32_t orientationId = 0;
    LaunchMode launchMode = LaunchMode::SINGLETON;
    std::string srcPath;
    std::string srcLanguage = "js";
    std::string codeLanguage = Constants::CODE_LANGUAGE_1_1;
    std::vector<std::string> permissions;

    std::string process;
    std::vector<std::string> deviceTypes;
    std::vector<std::string> deviceCapabilities;
    std::string uri;
    std::string targetAbility;
    ApplicationInfo applicationInfo;
    bool isLauncherAbility = false;
    bool isNativeAbility = false;
    bool enabled = false;
    bool supportPipMode = false;
    bool formEnabled = false;
    bool removeMissionAfterTerminate = false;
    std::string readPermission;
    std::string writePermission;
    std::vector<std::string> configChanges;
    uint32_t formEntity = 0;
    int32_t minFormHeight = 0;
    int32_t defaultFormHeight = 0;
    int32_t minFormWidth = 0;
    int32_t defaultFormWidth = 0;
    MetaData metaData;
    uint32_t backgroundModes = 0;

    // for Check flags, add to abilityInfo and extensionAbilityInfo
    std::vector<SkillUriForAbilityAndExtension> skillUri;
    std::vector<Skill> skills;

    // set when install
    std::string package;  // the "module.package" in config.json
    std::string bundleName;
    std::string moduleName;       // the "module.name" in config.json
    std::string applicationName;  // the "bundlename" in config.json

    std::string codePath;         // ability main code path with name
    std::string resourcePath;     // resource path for resource init
    std::string hapPath;

    std::string srcEntrance;
    std::vector<Metadata> metadata;
    bool isModuleJson = false;
    bool isStageBasedModel = false;
    bool continuable = false;
    int32_t priority = 0;

    // configuration fields on startup page
    std::string startWindowIcon;
    uint32_t startWindowIconId = 0;
    std::string startWindowBackground;
    uint32_t startWindowBackgroundId = 0;
    // whether to display in the missions list
    bool excludeFromMissions = false;
    bool unclearableMission = false;
    bool excludeFromDock = false;
    std::string preferMultiWindowOrientation = "default";
    // whether to support recover UI interface
    bool recoverable = false;
    bool isolationProcess = false;

    // support windows mode
    std::vector<SupportWindowMode> windowModes;
    double maxWindowRatio = 0;
    double minWindowRatio = 0;
    uint32_t maxWindowWidth = 0;
    uint32_t minWindowWidth = 0;
    uint32_t maxWindowHeight = 0;
    uint32_t minWindowHeight = 0;
    // for NAPI, save self query cache
    int32_t uid = -1;
    CompileMode compileMode = CompileMode::JS_BUNDLE;
    int32_t appIndex = 0;

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
    uint32_t packageSize = 0;
    bool multiUserShared = false;
    bool grantPermission = false;
    bool directLaunch = true;
    AbilitySubType subType = AbilitySubType::UNSPECIFIED;
    std::string libPath;
    std::string deviceId;
    int64_t installTime = 0;
    std::vector<std::string> supportExtNames;
    std::vector<std::string> supportMimeTypes;
    std::vector<std::string> continueType;
    std::unordered_set<std::string> continueBundleNames;
    LinkType linkType = LinkType::DEEP_LINK;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static AbilityInfo *Unmarshalling(Parcel &parcel);
    void Dump(std::string prefix, int fd);
    void ConvertToCompatiableAbilityInfo(CompatibleAbilityInfo& compatibleAbilityInfo) const;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_ABILITY_INFO_H
