/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_EXTENSION_INFO_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_EXTENSION_INFO_H

#include <map>
#include <string>

#include "application_info.h"
#include "parcel.h"
#include "skill.h"

namespace OHOS {
namespace AppExecFwk {
enum ExtensionAbilityInfoFlag {
    GET_EXTENSION_INFO_DEFAULT = 0x00000000,
    GET_EXTENSION_INFO_WITH_PERMISSION = 0x00000002,
    GET_EXTENSION_INFO_WITH_APPLICATION = 0x00000004,
    GET_EXTENSION_INFO_WITH_METADATA = 0x00000020,
    GET_EXTENSION_INFO_WITH_SKILL_URI = 0x00000200,
    GET_EXTENSION_INFO_WITH_SKILL = 0x00000400,
};

enum class GetExtensionAbilityInfoFlag {
    GET_EXTENSION_ABILITY_INFO_DEFAULT = 0x00000000,
    GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION = 0x00000001,
    GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION = 0x00000002,
    GET_EXTENSION_ABILITY_INFO_WITH_METADATA = 0x00000004,
    GET_EXTENSION_ABILITY_INFO_WITH_SKILL_URI = 0x00000008,
    GET_EXTENSION_ABILITY_INFO_WITH_SKILL = 0x00000010,
};

enum class ExtensionAbilityType {
    FORM = 0,
    WORK_SCHEDULER = 1,
    INPUTMETHOD = 2,
    SERVICE = 3,
    ACCESSIBILITY = 4,
    DATASHARE = 5,
    FILESHARE = 6,
    STATICSUBSCRIBER = 7,
    WALLPAPER = 8,
    BACKUP = 9,
    WINDOW = 10,
    ENTERPRISE_ADMIN = 11,
    FILEACCESS_EXTENSION = 12,
    THUMBNAIL = 13,
    PREVIEW = 14,
    PRINT = 15,
    SHARE = 16,
    PUSH = 17,
    DRIVER = 18,
    ACTION = 19,
    ADS_SERVICE = 20,
    EMBEDDED_UI = 21,
    INSIGHT_INTENT_UI = 22,
    PHOTO_EDITOR = 23,
    UNSPECIFIED = 255,
    UI = 256,
    HMS_ACCOUNT = 257,
    APP_ACCOUNT_AUTHORIZATION = 258,
    ADS = 259,
    REMOTE_NOTIFICATION = 260,
    REMOTE_LOCATION = 261,
    VOIP = 262,
    ACCOUNTLOGOUT = 263,
    STATUS_BAR_VIEW = 264,
    LIVEVIEW_LOCKSCREEN = 265,
    UI_SERVICE = 269,
    SYSDIALOG_USERAUTH = 300,
    SYSDIALOG_COMMON = 301,
    SYSDIALOG_ATOMICSERVICEPANEL = 302,
    SYSDIALOG_POWER = 303,
    SYSDIALOG_MEETIMECALL = 304,
    SYSDIALOG_MEETIMECONTACT = 305,
    SYSDIALOG_MEETIMEMESSAGE = 306,
    SYSDIALOG_PRINT = 307,
    SYSPICKER_MEDIACONTROL = 400,
    SYSPICKER_SHARE = 401,
    SYSPICKER_MEETIMECONTACT = 402,
    SYSPICKER_MEETIMECALLLOG = 403,
    SYSPICKER_PHOTOPICKER = 404,
    SYSPICKER_CAMERA = 405,
    SYSPICKER_NAVIGATION = 406,
    SYSPICKER_APPSELECTOR = 407,
    SYSPICKER_FILEPICKER = 408,
    SYSPICKER_AUDIOPICKER = 409,
    SYS_COMMON_UI = 500,
    AUTO_FILL_PASSWORD = 501,
    VPN = 502,
    AUTO_FILL_SMART = 503,
    SYSPICKER_PHOTOEDITOR = 504,
    SYS_VISUAL = 505,
    RECENT_PHOTO = 506
};

enum class CompileMode {
    JS_BUNDLE = 0,
    ES_MODULE,
};

enum class ExtensionProcessMode {
    UNDEFINED = -1,
    INSTANCE = 0,
    TYPE = 1,
    BUNDLE = 2,
    RUN_WITH_MAIN_PROCESS = 3,
};

struct SkillUriForAbilityAndExtension {
    std::string scheme;
    std::string host;
    std::string port;
    std::string path;
    std::string pathStartWith;
    std::string pathRegex;
    std::string type;
    std::string utd;
    std::string linkFeature;
    int32_t maxFileSupported = 0;
    bool isMatch = false;
};

struct ExtensionAbilityInfo : public Parcelable {
    std::string bundleName;
    std::string moduleName;
    std::string name;
    std::string srcEntrance;
    std::string icon;
    int32_t iconId = 0;
    int32_t labelId = 0;
    std::string label;
    std::string description;
    int32_t descriptionId = 0;
    int32_t priority = 0;
    std::vector<std::string> permissions;
    std::string readPermission;
    std::string writePermission;
    std::string uri;
    ExtensionAbilityType type = ExtensionAbilityType::UNSPECIFIED;
    std::string extensionTypeName;
    std::vector<Metadata> metadata;
    ApplicationInfo applicationInfo;
    ExtensionProcessMode extensionProcessMode = ExtensionProcessMode::UNDEFINED;
    bool visible = false;

    // set when install
    bool enabled = true;
    std::string resourcePath;
    std::string hapPath;
    std::string process;
    CompileMode compileMode = CompileMode::JS_BUNDLE;
    // for NAPI, save self query cache
    int32_t uid = -1;
    int32_t appIndex = 0;

    // for Check flags, add to abilityInfo and extensionAbilityInfo
    std::vector<SkillUriForAbilityAndExtension> skillUri;
    std::vector<Skill> skills;

    bool needCreateSandbox = false;
    std::vector<std::string> dataGroupIds;
    std::vector<std::string> validDataGroupIds;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static ExtensionAbilityInfo *Unmarshalling(Parcel &parcel);
    bool MarshallingSkillUri(Parcel &parcel, SkillUriForAbilityAndExtension uri) const;
    void UpdateNeedCreateSandbox();
};

ExtensionAbilityType ConvertToExtensionAbilityType(const std::string &type);
std::string ConvertToExtensionTypeName(ExtensionAbilityType type);
ExtensionProcessMode ConvertToExtensionProcessMode(const std::string &extensionProcessMode);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_EXTENSION_INFO_H
