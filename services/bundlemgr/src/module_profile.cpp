/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "module_profile.h"

#include <algorithm>
#include <mutex>
#include <sstream>

#include "app_log_wrapper.h"
#include "app_privilege_capability.h"
#include "bundle_constants.h"
#include "bundle_util.h"
#include "common_profile.h"
#include "parameter.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string COMPRESS_NATIVE_LIBS = "persist.bms.supportCompressNativeLibs";
const int32_t THRESHOLD_VAL_LEN = 40;
bool IsSupportCompressNativeLibs()
{
    char compressNativeLibs[THRESHOLD_VAL_LEN] = {0};
    int32_t ret = GetParameter(COMPRESS_NATIVE_LIBS.c_str(), "", compressNativeLibs, THRESHOLD_VAL_LEN);
    if (ret <= 0) {
        APP_LOGE("GetParameter %{public}s failed.", COMPRESS_NATIVE_LIBS.c_str());
        return false;
    }
    if (std::strcmp(compressNativeLibs, "true") == 0) {
        return true;
    }
    return false;
}
}

namespace Profile {
int32_t g_parseResult = ERR_OK;
std::mutex g_mutex;

const std::set<std::string> MODULE_TYPE_SET = {
    "entry",
    "feature",
    "shared"
};

const std::set<std::string> VIRTUAL_MACHINE_SET = {
    "ark",
    "default"
};

const std::map<std::string, uint32_t> BACKGROUND_MODES_MAP = {
    {ProfileReader::KEY_DATA_TRANSFER, ProfileReader::VALUE_DATA_TRANSFER},
    {ProfileReader::KEY_AUDIO_PLAYBACK, ProfileReader::VALUE_AUDIO_PLAYBACK},
    {ProfileReader::KEY_AUDIO_RECORDING, ProfileReader::VALUE_AUDIO_RECORDING},
    {ProfileReader::KEY_LOCATION, ProfileReader::VALUE_LOCATION},
    {ProfileReader::KEY_BLUETOOTH_INTERACTION, ProfileReader::VALUE_BLUETOOTH_INTERACTION},
    {ProfileReader::KEY_MULTI_DEVICE_CONNECTION, ProfileReader::VALUE_MULTI_DEVICE_CONNECTION},
    {ProfileReader::KEY_WIFI_INTERACTION, ProfileReader::VALUE_WIFI_INTERACTION},
    {ProfileReader::KEY_VOIP, ProfileReader::VALUE_VOIP},
    {ProfileReader::KEY_TASK_KEEPING, ProfileReader::VALUE_TASK_KEEPING},
    {ProfileReader::KEY_PICTURE_IN_PICTURE, ProfileReader::VALUE_PICTURE_IN_PICTURE},
    {ProfileReader::KEY_SCREEN_FETCH, ProfileReader::VALUE_SCREEN_FETCH}
};

const std::set<std::string> GRANT_MODE_SET = {
    "system_grant",
    "user_grant"
};

const std::set<std::string> AVAILABLE_LEVEL_SET = {
    "system_core",
    "system_basic",
    "normal"
};

const std::map<std::string, LaunchMode> LAUNCH_MODE_MAP = {
    {"singleton", LaunchMode::SINGLETON},
    {"standard", LaunchMode::STANDARD},
    {"multiton", LaunchMode::STANDARD},
    {"specified", LaunchMode::SPECIFIED}
};
const std::unordered_map<std::string, DisplayOrientation> DISPLAY_ORIENTATION_MAP = {
    {"unspecified", DisplayOrientation::UNSPECIFIED},
    {"landscape", DisplayOrientation::LANDSCAPE},
    {"portrait", DisplayOrientation::PORTRAIT},
    {"landscape_inverted", DisplayOrientation::LANDSCAPE_INVERTED},
    {"portrait_inverted", DisplayOrientation::PORTRAIT_INVERTED},
    {"auto_rotation", DisplayOrientation::AUTO_ROTATION},
    {"auto_rotation_landscape", DisplayOrientation::AUTO_ROTATION_LANDSCAPE},
    {"auto_rotation_portrait", DisplayOrientation::AUTO_ROTATION_PORTRAIT},
    {"auto_rotation_restricted", DisplayOrientation::AUTO_ROTATION_RESTRICTED},
    {"auto_rotation_landscape_restricted", DisplayOrientation::AUTO_ROTATION_LANDSCAPE_RESTRICTED},
    {"auto_rotation_portrait_restricted", DisplayOrientation::AUTO_ROTATION_PORTRAIT_RESTRICTED},
    {"locked", DisplayOrientation::LOCKED}
};
const std::unordered_map<std::string, SupportWindowMode> WINDOW_MODE_MAP = {
    {"fullscreen", SupportWindowMode::FULLSCREEN},
    {"split", SupportWindowMode::SPLIT},
    {"floating", SupportWindowMode::FLOATING}
};
const std::unordered_map<std::string, BundleType> BUNDLE_TYPE_MAP = {
    {"app", BundleType::APP},
    {"atomicService", BundleType::ATOMIC_SERVICE},
    {"shared", BundleType::SHARED},
    {"appService", BundleType::APP_SERVICE_FWK}
};
const size_t MAX_QUERYSCHEMES_LENGTH = 50;

struct DeviceConfig {
    // pair first : if exist in module.json then true, otherwise false
    // pair second : actual value
    std::pair<bool, int32_t> minAPIVersion = std::make_pair<>(false, 0);
    std::pair<bool, bool> keepAlive = std::make_pair<>(false, false);
    std::pair<bool, bool> removable = std::make_pair<>(false, true);
    std::pair<bool, bool> singleton = std::make_pair<>(false, false);
    std::pair<bool, bool> userDataClearable = std::make_pair<>(false, true);
    std::pair<bool, bool> accessible = std::make_pair<>(false, true);
};

struct Metadata {
    std::string name;
    std::string value;
    std::string resource;
};

struct Ability {
    std::string name;
    std::string srcEntrance;
    std::string launchType = ABILITY_LAUNCH_TYPE_DEFAULT_VALUE;
    std::string description;
    int32_t descriptionId = 0;
    std::string icon;
    int32_t iconId = 0;
    std::string label;
    int32_t labelId = 0;
    int32_t priority = 0;
    std::vector<std::string> permissions;
    std::vector<Metadata> metadata;
    bool visible = false;
    bool continuable = false;
    std::vector<Skill> skills;
    std::vector<std::string> backgroundModes;
    std::string startWindowIcon;
    int32_t startWindowIconId = 0;
    std::string startWindowBackground;
    int32_t startWindowBackgroundId = 0;
    bool removeMissionAfterTerminate = false;
    std::string orientation = "unspecified";
    std::vector<std::string> windowModes;
    double maxWindowRatio = 0;
    double minWindowRatio = 0;
    uint32_t maxWindowWidth = 0;
    uint32_t minWindowWidth = 0;
    uint32_t maxWindowHeight = 0;
    uint32_t minWindowHeight = 0;
    bool excludeFromMissions = false;
    bool recoverable = false;
    bool unclearableMission = false;
    bool excludeFromDock = false;
    std::string preferMultiWindowOrientation = "default";
    bool isolationProcess = false;
};

struct Extension {
    std::string name;
    std::string srcEntrance;
    std::string icon;
    int32_t iconId = 0;
    std::string label;
    int32_t labelId = 0;
    std::string description;
    int32_t descriptionId = 0;
    int32_t priority = 0;
    std::string type;
    std::string readPermission;
    std::string writePermission;
    std::string uri;
    std::vector<std::string> permissions;
    bool visible = false;
    std::vector<Skill> skills;
    std::vector<Metadata> metadata;
    std::string extensionProcessMode;
};

struct App {
    std::string bundleName;
    bool debug = false;
    std::string icon;
    int32_t iconId = 0;
    std::string label;
    int32_t labelId = 0;
    std::string description;
    int32_t descriptionId = 0;
    std::string vendor;
    int32_t versionCode = 0;
    std::string versionName;
    int32_t minCompatibleVersionCode = -1;
    uint32_t minAPIVersion = 0;
    int32_t targetAPIVersion = 0;
    std::string apiReleaseType = APP_API_RELEASETYPE_DEFAULT_VALUE;
    bool keepAlive = false;
    std::pair<bool, bool> removable = std::make_pair<>(false, true);
    bool singleton = false;
    bool userDataClearable = true;
    bool accessible = false;
    std::vector<std::string> targetBundleList;
    std::map<std::string, DeviceConfig> deviceConfigs;
    bool multiProjects = false;
    std::string targetBundle;
    int32_t targetPriority = 0;
    bool asanEnabled = false;
    std::string bundleType = Profile::BUNDLE_TYPE_APP;
    std::string compileSdkVersion;
    std::string compileSdkType = Profile::COMPILE_SDK_TYPE_OPEN_HARMONY;
    bool gwpAsanEnabled = false;
    bool tsanEnabled = false;
    std::vector<ApplicationEnvironment> appEnvironments;
};

struct Module {
    std::string name;
    std::string type;
    std::string srcEntrance;
    std::string description;
    int32_t descriptionId = 0;
    std::string process;
    std::string mainElement;
    std::vector<std::string> deviceTypes;
    bool deliveryWithInstall = false;
    bool installationFree = false;
    std::string virtualMachine = MODULE_VIRTUAL_MACHINE_DEFAULT_VALUE;
    std::string pages;
    std::vector<Metadata> metadata;
    std::vector<Ability> abilities;
    std::vector<Extension> extensionAbilities;
    std::vector<RequestPermission> requestPermissions;
    std::vector<DefinePermission> definePermissions;
    std::vector<Dependency> dependencies;
    std::string compileMode;
    bool isLibIsolated = false;
    std::string targetModule;
    int32_t targetPriority = 0;
    std::vector<ProxyData> proxyDatas;
    std::vector<ProxyData> proxyData;
    std::string buildHash;
    std::string isolationMode;
    bool compressNativeLibs = true;
    std::string fileContextMenu;
    std::vector<std::string> querySchemes;
    std::string routerMap;
    std::vector<AppEnvironment> appEnvironments;
    std::string packageName;
    std::string appStartup;
};

struct ModuleJson {
    App app;
    Module module;
};

void from_json(const nlohmann::json &jsonObject, Metadata &metadata)
{
    APP_LOGD("read metadata tag from module.json");
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        META_DATA_NAME,
        metadata.name,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        META_DATA_VALUE,
        metadata.value,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        META_DATA_RESOURCE,
        metadata.resource,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}

void from_json(const nlohmann::json &jsonObject, Ability &ability)
{
    APP_LOGD("read ability tag from module.json");
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ABILITY_NAME,
        ability.name,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    // both srcEntry and srcEntrance can be configured, but srcEntry has higher priority
    if (jsonObject.find(SRC_ENTRY) != jsonObject.end()) {
        GetValueIfFindKey<std::string>(jsonObject,
            jsonObjectEnd,
            SRC_ENTRY,
            ability.srcEntrance,
            JsonType::STRING,
            true,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    } else {
        GetValueIfFindKey<std::string>(jsonObject,
            jsonObjectEnd,
            SRC_ENTRANCE,
            ability.srcEntrance,
            JsonType::STRING,
            true,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ABILITY_LAUNCH_TYPE,
        ability.launchType,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION,
        ability.description,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION_ID,
        ability.descriptionId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ICON,
        ability.icon,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ICON_ID,
        ability.iconId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        LABEL,
        ability.label,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        LABEL_ID,
        ability.labelId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        PRIORITY,
        ability.priority,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        PERMISSIONS,
        ability.permissions,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        META_DATA,
        ability.metadata,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    // both exported and visible can be configured, but exported has higher priority
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        VISIBLE,
        ability.visible,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        EXPORTED,
        ability.visible,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ABILITY_CONTINUABLE,
        ability.continuable,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<Skill>>(jsonObject,
        jsonObjectEnd,
        SKILLS,
        ability.skills,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        ABILITY_BACKGROUNDMODES,
        ability.backgroundModes,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ABILITY_START_WINDOW_ICON,
        ability.startWindowIcon,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ABILITY_START_WINDOW_ICON_ID,
        ability.startWindowIconId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ABILITY_START_WINDOW_BACKGROUND,
        ability.startWindowBackground,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ABILITY_START_WINDOW_BACKGROUND_ID,
        ability.startWindowBackgroundId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ABILITY_REMOVE_MISSION_AFTER_TERMINATE,
        ability.removeMissionAfterTerminate,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ABILITY_ORIENTATION,
        ability.orientation,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        ABILITY_SUPPORT_WINDOW_MODE,
        ability.windowModes,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<double>(jsonObject,
        jsonObjectEnd,
        ABILITY_MAX_WINDOW_RATIO,
        ability.maxWindowRatio,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<double>(jsonObject,
        jsonObjectEnd,
        ABILITY_MIN_WINDOW_RATIO,
        ability.minWindowRatio,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        ABILITY_MAX_WINDOW_WIDTH,
        ability.maxWindowWidth,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        ABILITY_MIN_WINDOW_WIDTH,
        ability.minWindowWidth,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        ABILITY_MAX_WINDOW_HEIGHT,
        ability.maxWindowHeight,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        ABILITY_MIN_WINDOW_HEIGHT,
        ability.minWindowHeight,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ABILITY_EXCLUDE_FROM_MISSIONS,
        ability.excludeFromMissions,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ABILITY_RECOVERABLE,
        ability.recoverable,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ABILITY_UNCLEARABLE_MISSION,
        ability.unclearableMission,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ABILITY_EXCLUDEFROMDOCK_MISSION,
        ability.excludeFromDock,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ABILITY_PREFER_MULTI_WINDOW_ORIENTATION_MISSION,
        ability.preferMultiWindowOrientation,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ABILITY_ISOLATION_PROCESS,
        ability.isolationProcess,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}

void from_json(const nlohmann::json &jsonObject, Extension &extension)
{
    APP_LOGD("read extension tag from module.json");
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        EXTENSION_ABILITY_NAME,
        extension.name,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    // both srcEntry and srcEntrance can be configured, but srcEntry has higher priority
    if (jsonObject.find(SRC_ENTRY) != jsonObject.end()) {
        GetValueIfFindKey<std::string>(jsonObject,
            jsonObjectEnd,
            SRC_ENTRY,
            extension.srcEntrance,
            JsonType::STRING,
            true,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    } else {
        GetValueIfFindKey<std::string>(jsonObject,
            jsonObjectEnd,
            SRC_ENTRANCE,
            extension.srcEntrance,
            JsonType::STRING,
            true,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ICON,
        extension.icon,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ICON_ID,
        extension.iconId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        LABEL,
        extension.label,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        LABEL_ID,
        extension.labelId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION,
        extension.description,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION_ID,
        extension.descriptionId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        PRIORITY,
        extension.priority,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        EXTENSION_ABILITY_TYPE,
        extension.type,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        EXTENSION_ABILITY_READ_PERMISSION,
        extension.readPermission,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        EXTENSION_ABILITY_WRITE_PERMISSION,
        extension.writePermission,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        EXTENSION_URI,
        extension.uri,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        PERMISSIONS,
        extension.permissions,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    // both exported and visible can be configured, but exported has higher priority
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        VISIBLE,
        extension.visible,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        EXPORTED,
        extension.visible,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<Skill>>(jsonObject,
        jsonObjectEnd,
        SKILLS,
        extension.skills,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        META_DATA,
        extension.metadata,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        EXTENSION_PROCESS_MODE,
        extension.extensionProcessMode,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}

void from_json(const nlohmann::json &jsonObject, DeviceConfig &deviceConfig)
{
    const auto &jsonObjectEnd = jsonObject.end();
    if (jsonObject.find(MIN_API_VERSION) != jsonObjectEnd) {
        deviceConfig.minAPIVersion.first = true;
        GetValueIfFindKey<int32_t>(jsonObject,
            jsonObjectEnd,
            MIN_API_VERSION,
            deviceConfig.minAPIVersion.second,
            JsonType::NUMBER,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    if (jsonObject.find(DEVICE_CONFIG_KEEP_ALIVE) != jsonObjectEnd) {
        deviceConfig.keepAlive.first = true;
        GetValueIfFindKey<bool>(jsonObject,
            jsonObjectEnd,
            DEVICE_CONFIG_KEEP_ALIVE,
            deviceConfig.keepAlive.second,
            JsonType::BOOLEAN,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    if (jsonObject.find(DEVICE_CONFIG_REMOVABLE) != jsonObjectEnd) {
        deviceConfig.removable.first = true;
        GetValueIfFindKey<bool>(jsonObject,
            jsonObjectEnd,
            DEVICE_CONFIG_REMOVABLE,
            deviceConfig.removable.second,
            JsonType::BOOLEAN,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    if (jsonObject.find(DEVICE_CONFIG_SINGLETON) != jsonObjectEnd) {
        deviceConfig.singleton.first = true;
        GetValueIfFindKey<bool>(jsonObject,
            jsonObjectEnd,
            DEVICE_CONFIG_SINGLETON,
            deviceConfig.singleton.second,
            JsonType::BOOLEAN,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    if (jsonObject.find(DEVICE_CONFIG_USER_DATA_CLEARABLE) != jsonObjectEnd) {
        deviceConfig.userDataClearable.first = true;
        GetValueIfFindKey<bool>(jsonObject,
            jsonObjectEnd,
            DEVICE_CONFIG_USER_DATA_CLEARABLE,
            deviceConfig.userDataClearable.second,
            JsonType::BOOLEAN,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    if (jsonObject.find(DEVICE_CONFIG_ACCESSIBLE) != jsonObjectEnd) {
        deviceConfig.accessible.first = true;
        GetValueIfFindKey<bool>(jsonObject,
            jsonObjectEnd,
            DEVICE_CONFIG_ACCESSIBLE,
            deviceConfig.accessible.second,
            JsonType::BOOLEAN,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
}

void from_json(const nlohmann::json &jsonObject, App &app)
{
    APP_LOGD("read app tag from module.json");
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_BUNDLE_NAME,
        app.bundleName,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ICON,
        app.icon,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        LABEL,
        app.label,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APP_VERSION_CODE,
        app.versionCode,
        JsonType::NUMBER,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_VERSION_NAME,
        app.versionName,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        APP_MIN_API_VERSION,
        app.minAPIVersion,
        JsonType::NUMBER,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APP_TARGET_API_VERSION,
        app.targetAPIVersion,
        JsonType::NUMBER,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APP_DEBUG,
        app.debug,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ICON_ID,
        app.iconId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        LABEL_ID,
        app.labelId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION,
        app.description,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION_ID,
        app.descriptionId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_VENDOR,
        app.vendor,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APP_MIN_COMPATIBLE_VERSION_CODE,
        app.minCompatibleVersionCode,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_API_RELEASETYPE,
        app.apiReleaseType,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APP_KEEP_ALIVE,
        app.keepAlive,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        APP_TARGETBUNDLELIST,
        app.targetBundleList,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    if (jsonObject.find(APP_REMOVABLE) != jsonObject.end()) {
        app.removable.first = true;
        GetValueIfFindKey<bool>(jsonObject,
            jsonObjectEnd,
            APP_REMOVABLE,
            app.removable.second,
            JsonType::BOOLEAN,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APP_SINGLETON,
        app.singleton,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APP_USER_DATA_CLEARABLE,
        app.userDataClearable,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APP_ACCESSIBLE,
        app.accessible,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APP_ASAN_ENABLED,
        app.asanEnabled,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_TYPE,
        app.bundleType,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    if (jsonObject.find(APP_PHONE) != jsonObjectEnd) {
        DeviceConfig deviceConfig;
        GetValueIfFindKey<DeviceConfig>(jsonObject,
            jsonObjectEnd,
            APP_PHONE,
            deviceConfig,
            JsonType::OBJECT,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
        app.deviceConfigs[APP_PHONE] = deviceConfig;
    }
    if (jsonObject.find(APP_TABLET) != jsonObjectEnd) {
        DeviceConfig deviceConfig;
        GetValueIfFindKey<DeviceConfig>(jsonObject,
            jsonObjectEnd,
            APP_TABLET,
            deviceConfig,
            JsonType::OBJECT,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
        app.deviceConfigs[APP_TABLET] = deviceConfig;
    }
    if (jsonObject.find(APP_TV) != jsonObjectEnd) {
        DeviceConfig deviceConfig;
        GetValueIfFindKey<DeviceConfig>(jsonObject,
            jsonObjectEnd,
            APP_TV,
            deviceConfig,
            JsonType::OBJECT,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
        app.deviceConfigs[APP_TV] = deviceConfig;
    }
    if (jsonObject.find(APP_WEARABLE) != jsonObjectEnd) {
        DeviceConfig deviceConfig;
        GetValueIfFindKey<DeviceConfig>(jsonObject,
            jsonObjectEnd,
            APP_WEARABLE,
            deviceConfig,
            JsonType::OBJECT,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
        app.deviceConfigs[APP_WEARABLE] = deviceConfig;
    }
    if (jsonObject.find(APP_LITE_WEARABLE) != jsonObjectEnd) {
        DeviceConfig deviceConfig;
        GetValueIfFindKey<DeviceConfig>(jsonObject,
            jsonObjectEnd,
            APP_LITE_WEARABLE,
            deviceConfig,
            JsonType::OBJECT,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
        app.deviceConfigs[APP_LITE_WEARABLE] = deviceConfig;
    }
    if (jsonObject.find(APP_CAR) != jsonObjectEnd) {
        DeviceConfig deviceConfig;
        GetValueIfFindKey<DeviceConfig>(jsonObject,
            jsonObjectEnd,
            APP_CAR,
            deviceConfig,
            JsonType::OBJECT,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
        app.deviceConfigs[APP_CAR] = deviceConfig;
    }
    if (jsonObject.find(APP_SMART_VISION) != jsonObjectEnd) {
        DeviceConfig deviceConfig;
        GetValueIfFindKey<DeviceConfig>(jsonObject,
            jsonObjectEnd,
            APP_SMART_VISION,
            deviceConfig,
            JsonType::OBJECT,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
        app.deviceConfigs[APP_SMART_VISION] = deviceConfig;
    }
    if (jsonObject.find(APP_ROUTER) != jsonObjectEnd) {
        DeviceConfig deviceConfig;
        GetValueIfFindKey<DeviceConfig>(jsonObject,
            jsonObjectEnd,
            APP_ROUTER,
            deviceConfig,
            JsonType::OBJECT,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
        app.deviceConfigs[APP_ROUTER] = deviceConfig;
    }
    if (jsonObject.find(APP_TWO_IN_ONE) != jsonObjectEnd) {
        DeviceConfig deviceConfig;
        GetValueIfFindKey<DeviceConfig>(jsonObject,
            jsonObjectEnd,
            APP_TWO_IN_ONE,
            deviceConfig,
            JsonType::OBJECT,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
        app.deviceConfigs[APP_TWO_IN_ONE] = deviceConfig;
    }
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APP_MULTI_PROJECTS,
        app.multiProjects,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_TARGET_BUNDLE_NAME,
        app.targetBundle,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APP_TARGET_PRIORITY,
        app.targetPriority,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        COMPILE_SDK_VERSION,
        app.compileSdkVersion,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        COMPILE_SDK_TYPE,
        app.compileSdkType,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APP_GWP_ASAN_ENABLED,
        app.gwpAsanEnabled,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APP_TSAN_ENABLED,
        app.tsanEnabled,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ApplicationEnvironment>>(jsonObject,
        jsonObjectEnd,
        MODULE_APP_ENVIRONMENTS,
        app.appEnvironments,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
}

void from_json(const nlohmann::json &jsonObject, Module &module)
{
    APP_LOGD("read module tag from module.json");
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_NAME,
        module.name,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_TYPE,
        module.type,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_DEVICE_TYPES,
        module.deviceTypes,
        JsonType::ARRAY,
        true,
        g_parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_DELIVERY_WITH_INSTALL,
        module.deliveryWithInstall,
        JsonType::BOOLEAN,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_PAGES,
        module.pages,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    // both srcEntry and srcEntrance can be configured, but srcEntry has higher priority
    if (jsonObject.find(SRC_ENTRY) != jsonObject.end()) {
        GetValueIfFindKey<std::string>(jsonObject,
            jsonObjectEnd,
            SRC_ENTRY,
            module.srcEntrance,
            JsonType::STRING,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    } else {
        GetValueIfFindKey<std::string>(jsonObject,
            jsonObjectEnd,
            SRC_ENTRANCE,
            module.srcEntrance,
            JsonType::STRING,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION,
        module.description,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION_ID,
        module.descriptionId,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_PROCESS,
        module.process,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_MAIN_ELEMENT,
        module.mainElement,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_INSTALLATION_FREE,
        module.installationFree,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_VIRTUAL_MACHINE,
        module.virtualMachine,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        META_DATA,
        module.metadata,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<Ability>>(jsonObject,
        jsonObjectEnd,
        MODULE_ABILITIES,
        module.abilities,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<Extension>>(jsonObject,
        jsonObjectEnd,
        MODULE_EXTENSION_ABILITIES,
        module.extensionAbilities,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<RequestPermission>>(jsonObject,
        jsonObjectEnd,
        MODULE_REQUEST_PERMISSIONS,
        module.requestPermissions,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<DefinePermission>>(jsonObject,
        jsonObjectEnd,
        MODULE_DEFINE_PERMISSIONS,
        module.definePermissions,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<Dependency>>(jsonObject,
        jsonObjectEnd,
        MODULE_DEPENDENCIES,
        module.dependencies,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_COMPILE_MODE,
        module.compileMode,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_IS_LIB_ISOLATED,
        module.isLibIsolated,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_TARGET_MODULE_NAME,
        module.targetModule,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_TARGET_PRIORITY,
        module.targetPriority,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ProxyData>>(jsonObject,
        jsonObjectEnd,
        MODULE_PROXY_DATAS,
        module.proxyDatas,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<ProxyData>>(jsonObject,
        jsonObjectEnd,
        MODULE_PROXY_DATA,
        module.proxyData,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_BUILD_HASH,
        module.buildHash,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_ISOLATION_MODE,
        module.isolationMode,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    if (IsSupportCompressNativeLibs()) {
        GetValueIfFindKey<bool>(jsonObject,
            jsonObjectEnd,
            MODULE_COMPRESS_NATIVE_LIBS,
            module.compressNativeLibs,
            JsonType::BOOLEAN,
            false,
            g_parseResult,
            ArrayType::NOT_ARRAY);
    }
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_FILE_CONTEXT_MENU,
        module.fileContextMenu,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_QUERY_SCHEMES,
        module.querySchemes,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_ROUTER_MAP,
        module.routerMap,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<AppEnvironment>>(jsonObject,
        jsonObjectEnd,
        MODULE_APP_ENVIRONMENTS,
        module.appEnvironments,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_PACKAGE_NAME,
        module.packageName,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_APP_STARTUP,
        module.appStartup,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}

void from_json(const nlohmann::json &jsonObject, ModuleJson &moduleJson)
{
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<App>(jsonObject,
        jsonObjectEnd,
        APP,
        moduleJson.app,
        JsonType::OBJECT,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Module>(jsonObject,
        jsonObjectEnd,
        MODULE,
        moduleJson.module,
        JsonType::OBJECT,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}
} // namespace Profile

namespace {
struct TransformParam {
    bool isSystemApp = false;
    bool isPreInstallApp = false;
};

void GetMetadata(std::vector<Metadata> &metadata, const std::vector<Profile::Metadata> &profileMetadata)
{
    for (const Profile::Metadata &item : profileMetadata) {
        Metadata tmpMetadata;
        tmpMetadata.name = item.name;
        tmpMetadata.value = item.value;
        tmpMetadata.resource = item.resource;
        metadata.emplace_back(tmpMetadata);
    }
}

bool CheckBundleNameIsValid(const std::string &bundleName)
{
    if (bundleName.empty()) {
        return false;
    }
    if (bundleName.size() < Constants::MIN_BUNDLE_NAME || bundleName.size() > Constants::MAX_BUNDLE_NAME) {
        return false;
    }
    char head = bundleName.at(0);
    if (!isalpha(head)) {
        return false;
    }
    for (const auto &c : bundleName) {
        if (!isalnum(c) && (c != '.') && (c != '_')) {
            return false;
        }
    }
    return true;
}

bool CheckModuleNameIsValid(const std::string &moduleName)
{
    if (moduleName.empty()) {
        return false;
    }
    if (moduleName.size() > Constants::MAX_MODULE_NAME) {
        return false;
    }
    if (moduleName.find(Constants::RELATIVE_PATH) != std::string::npos) {
        return false;
    }
    if (moduleName.find(Constants::MODULE_NAME_SEPARATOR) != std::string::npos) {
        APP_LOGE("module name should not contain ,");
        return false;
    }
    return true;
}

void UpdateNativeSoAttrs(
    const std::string &cpuAbi,
    const std::string &soRelativePath,
    bool isLibIsolated,
    InnerBundleInfo &innerBundleInfo)
{
    APP_LOGD("cpuAbi %{public}s, soRelativePath : %{public}s, isLibIsolated : %{public}d",
        cpuAbi.c_str(), soRelativePath.c_str(), isLibIsolated);
    innerBundleInfo.SetCpuAbi(cpuAbi);
    if (!innerBundleInfo.IsCompressNativeLibs(innerBundleInfo.GetCurModuleName())) {
        APP_LOGD("UpdateNativeSoAttrs compressNativeLibs is false, no need to decompress so");
        if (!isLibIsolated) {
            innerBundleInfo.SetNativeLibraryPath(soRelativePath);
        }
        if (!soRelativePath.empty()) {
            innerBundleInfo.SetModuleNativeLibraryPath(Constants::LIBS + cpuAbi);
            innerBundleInfo.SetSharedModuleNativeLibraryPath(Constants::LIBS + cpuAbi);
        }
        innerBundleInfo.SetModuleCpuAbi(cpuAbi);
        return;
    }
    if (!isLibIsolated) {
        innerBundleInfo.SetNativeLibraryPath(soRelativePath);
        return;
    }

    innerBundleInfo.SetModuleNativeLibraryPath(
        innerBundleInfo.GetCurModuleName() + Constants::PATH_SEPARATOR + soRelativePath);
    innerBundleInfo.SetSharedModuleNativeLibraryPath(
        innerBundleInfo.GetCurModuleName() + Constants::PATH_SEPARATOR + soRelativePath);
    innerBundleInfo.SetModuleCpuAbi(cpuAbi);
}

bool ParserNativeSo(
    const Profile::ModuleJson &moduleJson,
    const BundleExtractor &bundleExtractor,
    InnerBundleInfo &innerBundleInfo)
{
    std::string abis = GetAbiList();
    std::vector<std::string> abiList;
    SplitStr(abis, Constants::ABI_SEPARATOR, abiList, false, false);
    if (abiList.empty()) {
        APP_LOGD("Abi is empty");
        return false;
    }

    bool isDefault =
        std::find(abiList.begin(), abiList.end(), Constants::ABI_DEFAULT) != abiList.end();
    bool isSystemLib64Exist = BundleUtil::IsExistDir(Constants::SYSTEM_LIB64);
    APP_LOGD("abi list : %{public}s, isDefault : %{public}d", abis.c_str(), isDefault);
    std::string cpuAbi;
    std::string soRelativePath;
    bool soExist = bundleExtractor.IsDirExist(Constants::LIBS);
    if (!soExist) {
        APP_LOGD("so not exist");
        if (isDefault) {
            cpuAbi = isSystemLib64Exist ? Constants::ARM64_V8A : Constants::ARM_EABI_V7A;
            UpdateNativeSoAttrs(cpuAbi, soRelativePath, false, innerBundleInfo);
            return true;
        }

        for (const auto &abi : abiList) {
            if (Constants::ABI_MAP.find(abi) != Constants::ABI_MAP.end()) {
                cpuAbi = abi;
                UpdateNativeSoAttrs(cpuAbi, soRelativePath, false, innerBundleInfo);
                return true;
            }
        }

        return false;
    }

    APP_LOGD("so exist");
    bool isLibIsolated = moduleJson.module.isLibIsolated;
    if (isDefault) {
        if (isSystemLib64Exist) {
            if (bundleExtractor.IsDirExist(Constants::LIBS + Constants::ARM64_V8A)) {
                cpuAbi = Constants::ARM64_V8A;
                soRelativePath = Constants::LIBS + Constants::ABI_MAP.at(Constants::ARM64_V8A);
                UpdateNativeSoAttrs(cpuAbi, soRelativePath, isLibIsolated, innerBundleInfo);
                return true;
            }

            return false;
        }

        if (bundleExtractor.IsDirExist(Constants::LIBS + Constants::ARM_EABI_V7A)) {
            cpuAbi = Constants::ARM_EABI_V7A;
            soRelativePath = Constants::LIBS + Constants::ABI_MAP.at(Constants::ARM_EABI_V7A);
            UpdateNativeSoAttrs(cpuAbi, soRelativePath, isLibIsolated, innerBundleInfo);
            return true;
        }

        if (bundleExtractor.IsDirExist(Constants::LIBS + Constants::ARM_EABI)) {
            cpuAbi = Constants::ARM_EABI;
            soRelativePath = Constants::LIBS + Constants::ABI_MAP.at(Constants::ARM_EABI);
            UpdateNativeSoAttrs(cpuAbi, soRelativePath, isLibIsolated, innerBundleInfo);
            return true;
        }

        return false;
    }

    for (const auto &abi : abiList) {
        std::string libsPath;
        libsPath.append(Constants::LIBS).append(abi).append(Constants::PATH_SEPARATOR);
        if (Constants::ABI_MAP.find(abi) != Constants::ABI_MAP.end() && bundleExtractor.IsDirExist(libsPath)) {
            cpuAbi = abi;
            soRelativePath = Constants::LIBS + Constants::ABI_MAP.at(abi);
            UpdateNativeSoAttrs(cpuAbi, soRelativePath, isLibIsolated, innerBundleInfo);
            return true;
        }
    }

    return false;
}

bool ParserAtomicModuleConfig(const nlohmann::json &jsonObject, InnerBundleInfo &innerBundleInfo)
{
    nlohmann::json moduleJson = jsonObject.at(Profile::MODULE);
    std::vector<std::string> preloads;
    std::string moduleName = moduleJson.at(Profile::MODULE_NAME);
    if (moduleJson.contains(Profile::MODULE_ATOMIC_SERVICE)) {
        nlohmann::json moduleAtomicObj = moduleJson.at(Profile::MODULE_ATOMIC_SERVICE);
        if (moduleAtomicObj.contains(Profile::MODULE_ATOMIC_SERVICE_PRELOADS)) {
            nlohmann::json preloadObj = moduleAtomicObj.at(Profile::MODULE_ATOMIC_SERVICE_PRELOADS);
            if (preloadObj.empty()) {
                return true;
            }
            if (preloadObj.size() > Constants::MAX_JSON_ARRAY_LENGTH) {
                APP_LOGE("preloads config in module.json is oversize!");
                return false;
            }
            for (const auto &preload : preloadObj) {
                if (preload.contains(Profile::PRELOADS_MODULE_NAME)) {
                    std::string preloadName = preload.at(Profile::PRELOADS_MODULE_NAME);
                    preloads.emplace_back(preloadName);
                } else {
                    APP_LOGE("preloads must have moduleName.");
                    return false;
                }
            }
        }
    }
    innerBundleInfo.SetInnerModuleAtomicPreload(moduleName, preloads);
    return true;
}

bool ParserAtomicConfig(const nlohmann::json &jsonObject, InnerBundleInfo &innerBundleInfo)
{
    if (!jsonObject.contains(Profile::MODULE) || !jsonObject.contains(Profile::APP)) {
        APP_LOGE("ParserAtomicConfig failed due to bad module.json");
        return false;
    }
    nlohmann::json appJson = jsonObject.at(Profile::APP);
    nlohmann::json moduleJson = jsonObject.at(Profile::MODULE);
    if (!moduleJson.is_object() || !appJson.is_object()) {
        APP_LOGE("module.json file lacks of invalid module or app properties");
        return false;
    }
    BundleType bundleType = BundleType::APP;
    if (appJson.contains(Profile::BUNDLE_TYPE)) {
        if (appJson.at(Profile::BUNDLE_TYPE) == Profile::BUNDLE_TYPE_ATOMIC_SERVICE) {
            bundleType = BundleType::ATOMIC_SERVICE;
        } else if (appJson.at(Profile::BUNDLE_TYPE) == Profile::BUNDLE_TYPE_SHARED) {
            bundleType = BundleType::SHARED;
        } else if (appJson.at(Profile::BUNDLE_TYPE) == Profile::BUNDLE_TYPE_APP_SERVICE_FWK) {
            bundleType = BundleType::APP_SERVICE_FWK;
        }
    }

    innerBundleInfo.SetApplicationBundleType(bundleType);
    if (!ParserAtomicModuleConfig(jsonObject, innerBundleInfo)) {
        APP_LOGE("parse module atomicService failed.");
        return false;
    }
    return true;
}

bool ParserArkNativeFilePath(
    const Profile::ModuleJson &moduleJson,
    const BundleExtractor &bundleExtractor,
    InnerBundleInfo &innerBundleInfo)
{
    std::string abis = GetAbiList();
    std::vector<std::string> abiList;
    SplitStr(abis, Constants::ABI_SEPARATOR, abiList, false, false);
    if (abiList.empty()) {
        APP_LOGD("Abi is empty");
        return false;
    }

    bool isDefault =
        std::find(abiList.begin(), abiList.end(), Constants::ABI_DEFAULT) != abiList.end();
    bool isSystemLib64Exist = BundleUtil::IsExistDir(Constants::SYSTEM_LIB64);
    APP_LOGD("abi list : %{public}s, isDefault : %{public}d", abis.c_str(), isDefault);
    bool anExist = bundleExtractor.IsDirExist(Constants::AN);
    if (!anExist) {
        APP_LOGD("an not exist");
        return true;
    }

    APP_LOGD("an exist");
    if (isDefault) {
        if (isSystemLib64Exist) {
            if (bundleExtractor.IsDirExist(Constants::AN + Constants::ARM64_V8A)) {
                innerBundleInfo.SetArkNativeFileAbi(Constants::ARM64_V8A);
                return true;
            }

            return false;
        }

        if (bundleExtractor.IsDirExist(Constants::AN + Constants::ARM_EABI_V7A)) {
            innerBundleInfo.SetArkNativeFileAbi(Constants::ARM_EABI_V7A);
            return true;
        }

        if (bundleExtractor.IsDirExist(Constants::AN + Constants::ARM_EABI)) {
            innerBundleInfo.SetArkNativeFileAbi(Constants::ARM_EABI);
            return true;
        }

        return false;
    }

    for (const auto &abi : abiList) {
        std::string libsPath;
        libsPath.append(Constants::AN).append(abi).append(Constants::PATH_SEPARATOR);
        if (Constants::ABI_MAP.find(abi) != Constants::ABI_MAP.end() && bundleExtractor.IsDirExist(libsPath)) {
            innerBundleInfo.SetArkNativeFileAbi(abi);
            return true;
        }
    }

    return false;
}

bool ToApplicationInfo(
    const Profile::ModuleJson &moduleJson,
    const BundleExtractor &bundleExtractor,
    const TransformParam &transformParam,
    ApplicationInfo &applicationInfo)
{
    APP_LOGD("transform ModuleJson to ApplicationInfo");
    auto app = moduleJson.app;
    applicationInfo.name = app.bundleName;
    applicationInfo.bundleName = app.bundleName;

    applicationInfo.versionCode = static_cast<uint32_t>(app.versionCode);
    applicationInfo.versionName = app.versionName;
    if (app.minCompatibleVersionCode != -1) {
        applicationInfo.minCompatibleVersionCode = app.minCompatibleVersionCode;
    } else {
        applicationInfo.minCompatibleVersionCode = static_cast<int32_t>(applicationInfo.versionCode);
    }

    applicationInfo.apiCompatibleVersion = app.minAPIVersion;
    applicationInfo.apiTargetVersion = app.targetAPIVersion;

    applicationInfo.iconPath = app.icon;
    applicationInfo.iconId = app.iconId;
    applicationInfo.label = app.label;
    applicationInfo.labelId = app.labelId;
    applicationInfo.description = app.description;
    applicationInfo.descriptionId = app.descriptionId;
    applicationInfo.iconResource =
        BundleUtil::GetResource(app.bundleName, moduleJson.module.name, app.iconId);
    applicationInfo.labelResource =
        BundleUtil::GetResource(app.bundleName, moduleJson.module.name, app.labelId);
    applicationInfo.descriptionResource =
        BundleUtil::GetResource(app.bundleName, moduleJson.module.name, app.descriptionId);
    applicationInfo.targetBundleList = app.targetBundleList;

    if (transformParam.isSystemApp && transformParam.isPreInstallApp) {
        applicationInfo.keepAlive = app.keepAlive;
        applicationInfo.singleton = app.singleton;
        applicationInfo.userDataClearable = app.userDataClearable;
        if (app.removable.first) {
            applicationInfo.removable = app.removable.second;
        } else {
            applicationInfo.removable = false;
        }
        applicationInfo.accessible = app.accessible;
    }

    applicationInfo.apiReleaseType = app.apiReleaseType;
    applicationInfo.debug = app.debug;
    applicationInfo.deviceId = Constants::CURRENT_DEVICE_ID;
    applicationInfo.distributedNotificationEnabled = true;
    applicationInfo.entityType = Profile::APP_ENTITY_TYPE_DEFAULT_VALUE;
    applicationInfo.vendor = app.vendor;
    applicationInfo.asanEnabled = app.asanEnabled;
    if (app.bundleType == Profile::BUNDLE_TYPE_ATOMIC_SERVICE) {
        applicationInfo.bundleType = BundleType::ATOMIC_SERVICE;
    }

    // device adapt
    std::string deviceType = GetDeviceType();
    APP_LOGD("deviceType : %{public}s", deviceType.c_str());
    if (app.deviceConfigs.find(deviceType) != app.deviceConfigs.end()) {
        Profile::DeviceConfig deviceConfig = app.deviceConfigs.at(deviceType);
        if (deviceConfig.minAPIVersion.first) {
            applicationInfo.apiCompatibleVersion = static_cast<uint32_t>(deviceConfig.minAPIVersion.second);
        }
        if (applicationInfo.isSystemApp && transformParam.isPreInstallApp) {
            if (deviceConfig.keepAlive.first) {
                applicationInfo.keepAlive = deviceConfig.keepAlive.second;
            }
            if (deviceConfig.singleton.first) {
                applicationInfo.singleton = deviceConfig.singleton.second;
            }
            if (deviceConfig.userDataClearable.first) {
                applicationInfo.userDataClearable = deviceConfig.userDataClearable.second;
            }
            if (deviceConfig.removable.first) {
                applicationInfo.removable = deviceConfig.removable.second;
            }
            if (deviceConfig.accessible.first) {
                applicationInfo.accessible = deviceConfig.accessible.second;
            }
        }
    }

    applicationInfo.enabled = true;
    applicationInfo.multiProjects = app.multiProjects;
    applicationInfo.process = app.bundleName;
    applicationInfo.targetBundleName = app.targetBundle;
    applicationInfo.targetPriority = app.targetPriority;

    auto iterBundleType = std::find_if(std::begin(Profile::BUNDLE_TYPE_MAP),
        std::end(Profile::BUNDLE_TYPE_MAP),
        [&app](const auto &item) { return item.first == app.bundleType; });
    if (iterBundleType != Profile::BUNDLE_TYPE_MAP.end()) {
        applicationInfo.bundleType = iterBundleType->second;
    }
    applicationInfo.compileSdkVersion = app.compileSdkVersion;
    applicationInfo.compileSdkType = app.compileSdkType;
    applicationInfo.gwpAsanEnabled = app.gwpAsanEnabled;
    applicationInfo.tsanEnabled = app.tsanEnabled;
    applicationInfo.appEnvironments = app.appEnvironments;
    return true;
}

bool ToBundleInfo(
    const ApplicationInfo &applicationInfo,
    const InnerModuleInfo &innerModuleInfo,
    const TransformParam &transformParam,
    BundleInfo &bundleInfo)
{
    bundleInfo.name = applicationInfo.bundleName;

    bundleInfo.versionCode = static_cast<uint32_t>(applicationInfo.versionCode);
    bundleInfo.versionName = applicationInfo.versionName;
    bundleInfo.minCompatibleVersionCode = static_cast<uint32_t>(applicationInfo.minCompatibleVersionCode);

    bundleInfo.compatibleVersion = static_cast<uint32_t>(applicationInfo.apiCompatibleVersion);
    bundleInfo.targetVersion = static_cast<uint32_t>(applicationInfo.apiTargetVersion);

    bundleInfo.isKeepAlive = applicationInfo.keepAlive;
    bundleInfo.singleton = applicationInfo.singleton;
    bundleInfo.isPreInstallApp = transformParam.isPreInstallApp;

    bundleInfo.vendor = applicationInfo.vendor;
    bundleInfo.releaseType = applicationInfo.apiReleaseType;
    bundleInfo.isNativeApp = false;

    if (innerModuleInfo.isEntry) {
        bundleInfo.mainEntry = innerModuleInfo.moduleName;
        bundleInfo.entryModuleName = innerModuleInfo.moduleName;
    }

    return true;
}

uint32_t GetBackgroundModes(const std::vector<std::string> &backgroundModes)
{
    uint32_t backgroundMode = 0;
    for (const std::string &item : backgroundModes) {
        if (Profile::BACKGROUND_MODES_MAP.find(item) != Profile::BACKGROUND_MODES_MAP.end()) {
            backgroundMode |= Profile::BACKGROUND_MODES_MAP.at(item);
        }
    }
    return backgroundMode;
}

inline CompileMode ConvertCompileMode(const std::string& compileMode)
{
    if (compileMode == Profile::COMPILE_MODE_ES_MODULE) {
        return CompileMode::ES_MODULE;
    } else {
        return CompileMode::JS_BUNDLE;
    }
}

std::set<SupportWindowMode> ConvertToAbilityWindowMode(const std::vector<std::string> &windowModes,
    const std::unordered_map<std::string, SupportWindowMode> &windowMap)
{
    std::set<SupportWindowMode> modes;
    for_each(windowModes.begin(), windowModes.end(),
        [&windowMap, &modes](const auto &mode)->decltype(auto) {
        if (windowMap.find(mode) != windowMap.end()) {
            modes.emplace(windowMap.at(mode));
        }
    });
    if (modes.empty()) {
        modes.insert(SupportWindowMode::FULLSCREEN);
        modes.insert(SupportWindowMode::SPLIT);
        modes.insert(SupportWindowMode::FLOATING);
    }
    return modes;
}

bool ToAbilityInfo(
    const Profile::ModuleJson &moduleJson,
    const Profile::Ability &ability,
    const TransformParam &transformParam,
    AbilityInfo &abilityInfo)
{
    APP_LOGD("transform ModuleJson to AbilityInfo");
    abilityInfo.name = ability.name;
    abilityInfo.srcEntrance = ability.srcEntrance;
    abilityInfo.description = ability.description;
    abilityInfo.descriptionId = ability.descriptionId;
    abilityInfo.iconPath = ability.icon;
    abilityInfo.iconId = ability.iconId;
    abilityInfo.label = ability.label;
    abilityInfo.labelId = ability.labelId;
    abilityInfo.priority = ability.priority;
    abilityInfo.excludeFromMissions = ability.excludeFromMissions;
    abilityInfo.unclearableMission = ability.unclearableMission;
    abilityInfo.excludeFromDock = ability.excludeFromDock;
    abilityInfo.preferMultiWindowOrientation = ability.preferMultiWindowOrientation;
    abilityInfo.recoverable = ability.recoverable;
    abilityInfo.permissions = ability.permissions;
    abilityInfo.visible = ability.visible;
    abilityInfo.continuable = ability.continuable;
    abilityInfo.isolationProcess = ability.isolationProcess;
    abilityInfo.backgroundModes = GetBackgroundModes(ability.backgroundModes);
    GetMetadata(abilityInfo.metadata, ability.metadata);
    abilityInfo.package = moduleJson.module.name;
    abilityInfo.bundleName = moduleJson.app.bundleName;
    abilityInfo.moduleName = moduleJson.module.name;
    abilityInfo.applicationName = moduleJson.app.bundleName;
    auto iterLaunch = std::find_if(std::begin(Profile::LAUNCH_MODE_MAP),
        std::end(Profile::LAUNCH_MODE_MAP),
        [&ability](const auto &item) { return item.first == ability.launchType; });
    if (iterLaunch != Profile::LAUNCH_MODE_MAP.end()) {
        abilityInfo.launchMode = iterLaunch->second;
    }
    abilityInfo.enabled = true;
    abilityInfo.isModuleJson = true;
    abilityInfo.isStageBasedModel = true;
    abilityInfo.type = AbilityType::PAGE;
    for (const std::string &deviceType : moduleJson.module.deviceTypes) {
        abilityInfo.deviceTypes.emplace_back(deviceType);
    }
    abilityInfo.startWindowIcon = ability.startWindowIcon;
    abilityInfo.startWindowIconId = ability.startWindowIconId;
    abilityInfo.startWindowBackground = ability.startWindowBackground;
    abilityInfo.startWindowBackgroundId = ability.startWindowBackgroundId;
    abilityInfo.removeMissionAfterTerminate = ability.removeMissionAfterTerminate;
    abilityInfo.compileMode = ConvertCompileMode(moduleJson.module.compileMode);
    auto iterOrientation = std::find_if(std::begin(Profile::DISPLAY_ORIENTATION_MAP),
        std::end(Profile::DISPLAY_ORIENTATION_MAP),
        [&ability](const auto &item) { return item.first == ability.orientation; });
    if (iterOrientation != Profile::DISPLAY_ORIENTATION_MAP.end()) {
        abilityInfo.orientation = iterOrientation->second;
    }

    auto modesSet = ConvertToAbilityWindowMode(ability.windowModes, Profile::WINDOW_MODE_MAP);
    abilityInfo.windowModes.assign(modesSet.begin(), modesSet.end());
    abilityInfo.maxWindowRatio = ability.maxWindowRatio;
    abilityInfo.minWindowRatio = ability.minWindowRatio;
    abilityInfo.maxWindowWidth = ability.maxWindowWidth;
    abilityInfo.minWindowWidth = ability.minWindowWidth;
    abilityInfo.maxWindowHeight = ability.maxWindowHeight;
    abilityInfo.minWindowHeight = ability.minWindowHeight;
    return true;
}

bool ToExtensionInfo(
    const Profile::ModuleJson &moduleJson,
    const Profile::Extension &extension,
    const TransformParam &transformParam,
    ExtensionAbilityInfo &extensionInfo)
{
    APP_LOGD("transform ModuleJson to ExtensionAbilityInfo");
    extensionInfo.type = ConvertToExtensionAbilityType(extension.type);
    extensionInfo.extensionTypeName = extension.type;
    extensionInfo.name = extension.name;
    extensionInfo.srcEntrance = extension.srcEntrance;
    extensionInfo.icon = extension.icon;
    extensionInfo.iconId = extension.iconId;
    extensionInfo.label = extension.label;
    extensionInfo.labelId = extension.labelId;
    extensionInfo.description = extension.description;
    extensionInfo.descriptionId = extension.descriptionId;
    if (transformParam.isSystemApp && transformParam.isPreInstallApp) {
        extensionInfo.readPermission = extension.readPermission;
        extensionInfo.writePermission = extension.writePermission;
    }
    extensionInfo.priority = extension.priority;
    extensionInfo.uri = extension.uri;
    extensionInfo.permissions = extension.permissions;
    extensionInfo.visible = extension.visible;
    GetMetadata(extensionInfo.metadata, extension.metadata);
    extensionInfo.bundleName = moduleJson.app.bundleName;
    extensionInfo.moduleName = moduleJson.module.name;

    if (extensionInfo.type != ExtensionAbilityType::SERVICE &&
        extensionInfo.type != ExtensionAbilityType::DATASHARE) {
        extensionInfo.process = extensionInfo.bundleName;
        extensionInfo.process.append(":");
        extensionInfo.process.append(extensionInfo.extensionTypeName);
    }

    extensionInfo.compileMode = ConvertCompileMode(moduleJson.module.compileMode);
    extensionInfo.extensionProcessMode = ConvertToExtensionProcessMode(extension.extensionProcessMode);

    return true;
}

bool GetPermissions(
    const Profile::ModuleJson &moduleJson,
    const TransformParam &transformParam,
    InnerModuleInfo &innerModuleInfo)
{
    if (moduleJson.app.bundleName == Profile::SYSTEM_RESOURCES_APP) {
        for (const DefinePermission &definePermission : moduleJson.module.definePermissions) {
            if (definePermission.name.empty()) {
                continue;
            }
            if (Profile::GRANT_MODE_SET.find(definePermission.grantMode) == Profile::GRANT_MODE_SET.end()) {
                continue;
            }
            if (Profile::AVAILABLE_LEVEL_SET.find(definePermission.availableLevel)
                == Profile::AVAILABLE_LEVEL_SET.end()) {
                continue;
            }
            if (!definePermission.availableType.empty() &&
                definePermission.availableType != Profile::DEFINEPERMISSION_AVAILABLE_TYPE_MDM) {
                APP_LOGE("availableType(%{public}s) is invalid", definePermission.availableType.c_str());
                return false;
            }
            innerModuleInfo.definePermissions.emplace_back(definePermission);
        }
    }
    for (const RequestPermission &requestPermission : moduleJson.module.requestPermissions) {
        if (requestPermission.name.empty()) {
            continue;
        }
        innerModuleInfo.requestPermissions.emplace_back(requestPermission);
    }
    return true;
}

bool ToInnerModuleInfo(
    const Profile::ModuleJson &moduleJson,
    const TransformParam &transformParam,
    const OverlayMsg &overlayMsg,
    InnerModuleInfo &innerModuleInfo)
{
    APP_LOGD("transform ModuleJson to InnerModuleInfo");
    innerModuleInfo.name = moduleJson.module.name;
    innerModuleInfo.modulePackage = moduleJson.module.name;
    innerModuleInfo.moduleName = moduleJson.module.name;
    innerModuleInfo.description = moduleJson.module.description;
    innerModuleInfo.descriptionId = moduleJson.module.descriptionId;
    GetMetadata(innerModuleInfo.metadata, moduleJson.module.metadata);
    innerModuleInfo.distro.deliveryWithInstall = moduleJson.module.deliveryWithInstall;
    innerModuleInfo.distro.installationFree = moduleJson.module.installationFree;
    innerModuleInfo.distro.moduleName = moduleJson.module.name;
    innerModuleInfo.installationFree = moduleJson.module.installationFree;
    if (Profile::MODULE_TYPE_SET.find(moduleJson.module.type) != Profile::MODULE_TYPE_SET.end()) {
        innerModuleInfo.distro.moduleType = moduleJson.module.type;
        if (moduleJson.module.type == Profile::MODULE_TYPE_ENTRY) {
            innerModuleInfo.isEntry = true;
        }
    }

    innerModuleInfo.mainAbility = moduleJson.module.mainElement;
    innerModuleInfo.srcEntrance = moduleJson.module.srcEntrance;
    innerModuleInfo.process = moduleJson.module.process;

    for (const std::string &deviceType : moduleJson.module.deviceTypes) {
        innerModuleInfo.deviceTypes.emplace_back(deviceType);
    }

    if (Profile::VIRTUAL_MACHINE_SET.find(moduleJson.module.virtualMachine) != Profile::VIRTUAL_MACHINE_SET.end()) {
        innerModuleInfo.virtualMachine = moduleJson.module.virtualMachine;
    }

    innerModuleInfo.uiSyntax = Profile::MODULE_UI_SYNTAX_DEFAULT_VALUE;
    innerModuleInfo.pages = moduleJson.module.pages;
    if (!GetPermissions(moduleJson, transformParam, innerModuleInfo)) {
        APP_LOGE("GetPermissions failed");
        return false;
    }
    innerModuleInfo.dependencies = moduleJson.module.dependencies;
    innerModuleInfo.compileMode = moduleJson.module.compileMode;
    innerModuleInfo.isModuleJson = true;
    innerModuleInfo.isStageBasedModel = true;
    innerModuleInfo.isLibIsolated = moduleJson.module.isLibIsolated;
    innerModuleInfo.targetModuleName = moduleJson.module.targetModule;
    if (overlayMsg.type != NON_OVERLAY_TYPE && !overlayMsg.isModulePriorityExisted) {
        innerModuleInfo.targetPriority = Constants::OVERLAY_MINIMUM_PRIORITY;
    } else {
        innerModuleInfo.targetPriority = moduleJson.module.targetPriority;
    }
    if (moduleJson.module.proxyDatas.empty()) {
        innerModuleInfo.proxyDatas = moduleJson.module.proxyData;
    } else {
        innerModuleInfo.proxyDatas = moduleJson.module.proxyDatas;
    }
    innerModuleInfo.buildHash = moduleJson.module.buildHash;
    innerModuleInfo.isolationMode = moduleJson.module.isolationMode;
    innerModuleInfo.compressNativeLibs = moduleJson.module.compressNativeLibs;
    innerModuleInfo.fileContextMenu = moduleJson.module.fileContextMenu;

    if (moduleJson.module.querySchemes.size() > Profile::MAX_QUERYSCHEMES_LENGTH) {
        APP_LOGE("The length of the querySchemes exceeds the limit");
        return false;
    }
    for (const std::string &queryScheme : moduleJson.module.querySchemes) {
        innerModuleInfo.querySchemes.emplace_back(queryScheme);
    }

    innerModuleInfo.routerMap = moduleJson.module.routerMap;
    // abilities and fileContextMenu store in InnerBundleInfo
    innerModuleInfo.appEnvironments = moduleJson.module.appEnvironments;
    innerModuleInfo.packageName = moduleJson.module.packageName;
    innerModuleInfo.appStartup = moduleJson.module.appStartup;
    return true;
}

void SetInstallationFree(InnerModuleInfo &innerModuleInfo, BundleType bundleType)
{
    if (bundleType == BundleType::ATOMIC_SERVICE) {
        innerModuleInfo.distro.installationFree = true;
        innerModuleInfo.installationFree = true;
    } else {
        innerModuleInfo.distro.installationFree = false;
        innerModuleInfo.installationFree = false;
    }
}

bool ToInnerBundleInfo(
    const Profile::ModuleJson &moduleJson,
    const BundleExtractor &bundleExtractor,
    const OverlayMsg &overlayMsg,
    InnerBundleInfo &innerBundleInfo)
{
    APP_LOGD("transform ModuleJson to InnerBundleInfo");
    if (!CheckBundleNameIsValid(moduleJson.app.bundleName) || !CheckModuleNameIsValid(moduleJson.module.name)) {
        APP_LOGE("bundle name or module name is invalid");
        return false;
    }

    if (overlayMsg.type != NON_OVERLAY_TYPE && !CheckModuleNameIsValid(moduleJson.module.targetModule)) {
        APP_LOGE("target moduleName is invalid");
    }

    if ((overlayMsg.type == OVERLAY_EXTERNAL_BUNDLE) && !CheckBundleNameIsValid(moduleJson.app.targetBundle)) {
        APP_LOGE("targetBundleName of the overlay hap is invalid");
        return false;
    }

    TransformParam transformParam;
    transformParam.isPreInstallApp = innerBundleInfo.GetIsPreInstallApp();

    ApplicationInfo applicationInfo;
    applicationInfo.isSystemApp = innerBundleInfo.GetAppType() == Constants::AppType::SYSTEM_APP;
    transformParam.isSystemApp = applicationInfo.isSystemApp;
    applicationInfo.isCompressNativeLibs = moduleJson.module.compressNativeLibs;
    if (!ToApplicationInfo(moduleJson, bundleExtractor, transformParam, applicationInfo)) {
        APP_LOGE("To applicationInfo failed");
        return false;
    }

    InnerModuleInfo innerModuleInfo;
    if (!ToInnerModuleInfo(moduleJson, transformParam, overlayMsg, innerModuleInfo)) {
        APP_LOGE("To innerModuleInfo failed");
        return false;
    }
    innerModuleInfo.asanEnabled = applicationInfo.asanEnabled;
    innerModuleInfo.gwpAsanEnabled = applicationInfo.gwpAsanEnabled;
    SetInstallationFree(innerModuleInfo, applicationInfo.bundleType);

    BundleInfo bundleInfo;
    ToBundleInfo(applicationInfo, innerModuleInfo, transformParam, bundleInfo);

    // handle abilities
    auto entryActionMatcher = [] (const std::string &action) {
        return action == Constants::ACTION_HOME || action == Constants::WANT_ACTION_HOME;
    };
    bool findEntry = false;
    for (const Profile::Ability &ability : moduleJson.module.abilities) {
        AbilityInfo abilityInfo;
        ToAbilityInfo(moduleJson, ability, transformParam, abilityInfo);
        if (innerModuleInfo.mainAbility == abilityInfo.name) {
            innerModuleInfo.icon = abilityInfo.iconPath;
            innerModuleInfo.iconId = abilityInfo.iconId;
            innerModuleInfo.label = abilityInfo.label;
            innerModuleInfo.labelId = abilityInfo.labelId;
        }
        std::string key;
        key.append(moduleJson.app.bundleName).append(".")
            .append(moduleJson.module.name).append(".").append(abilityInfo.name);
        innerModuleInfo.abilityKeys.emplace_back(key);
        innerModuleInfo.skillKeys.emplace_back(key);
        innerBundleInfo.InsertSkillInfo(key, ability.skills);
        innerBundleInfo.InsertAbilitiesInfo(key, abilityInfo);
        if (findEntry) {
            continue;
        }
        // get entry ability
        for (const auto &skill : ability.skills) {
            bool isEntryAction = std::find_if(skill.actions.begin(), skill.actions.end(),
                entryActionMatcher) != skill.actions.end();
            bool isEntryEntity = std::find(skill.entities.begin(), skill.entities.end(),
                Constants::ENTITY_HOME) != skill.entities.end();
            if (isEntryAction && isEntryEntity) {
                innerModuleInfo.entryAbilityKey = key;
                innerModuleInfo.label = ability.label;
                innerModuleInfo.labelId = ability.labelId;
                // get launcher application and ability
                bool isLauncherEntity = std::find(skill.entities.begin(), skill.entities.end(),
                    Constants::FLAG_HOME_INTENT_FROM_SYSTEM) != skill.entities.end();
                if (isLauncherEntity && transformParam.isPreInstallApp) {
                    applicationInfo.isLauncherApp = true;
                    abilityInfo.isLauncherAbility = true;
                }
                findEntry = true;
                break;
            }
        }
    }

    // handle extensionAbilities
    for (const Profile::Extension &extension : moduleJson.module.extensionAbilities) {
        ExtensionAbilityInfo extensionInfo;
        if (!ToExtensionInfo(moduleJson, extension, transformParam, extensionInfo)) {
            APP_LOGE("To extensionInfo failed");
            return false;
        }

        if (innerModuleInfo.mainAbility == extensionInfo.name) {
            innerModuleInfo.icon = extensionInfo.icon;
            innerModuleInfo.iconId = extensionInfo.iconId;
            innerModuleInfo.label = extensionInfo.label;
            innerModuleInfo.labelId = extensionInfo.labelId;
        }

        if (transformParam.isPreInstallApp && !applicationInfo.isLauncherApp) {
            for (const auto &skill : extension.skills) {
                bool isEntryAction = std::find_if(skill.actions.cbegin(), skill.actions.cend(),
                    entryActionMatcher) != skill.actions.cend();
                bool isEntryEntity = std::find(skill.entities.cbegin(), skill.entities.cend(),
                    Constants::ENTITY_HOME) != skill.entities.cend();
                bool isLauncherEntity = std::find(skill.entities.cbegin(), skill.entities.cend(),
                    Constants::FLAG_HOME_INTENT_FROM_SYSTEM) != skill.entities.cend();
                if (isEntryAction && isEntryEntity && isLauncherEntity) {
                    applicationInfo.isLauncherApp = true;
                    break;
                }
            }
        }

        std::string key;
        key.append(moduleJson.app.bundleName).append(".")
            .append(moduleJson.module.name).append(".").append(extension.name);
        innerModuleInfo.extensionKeys.emplace_back(key);
        innerModuleInfo.extensionSkillKeys.emplace_back(key);
        innerBundleInfo.InsertExtensionSkillInfo(key, extension.skills);
        innerBundleInfo.InsertExtensionInfo(key, extensionInfo);
    }
    if (!findEntry && !transformParam.isPreInstallApp) {
        applicationInfo.needAppDetail = true;
        if (BundleUtil::IsExistDir(Constants::SYSTEM_LIB64)) {
            applicationInfo.appDetailAbilityLibraryPath = Profile::APP_DETAIL_ABILITY_LIBRARY_PATH_64;
        } else {
            applicationInfo.appDetailAbilityLibraryPath = Profile::APP_DETAIL_ABILITY_LIBRARY_PATH;
        }
        if ((applicationInfo.labelId == 0) && (applicationInfo.label.empty())) {
            applicationInfo.label = applicationInfo.bundleName;
        }
    }
    innerBundleInfo.SetCurrentModulePackage(moduleJson.module.name);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    // Here also need verify module type is shared.
    if (applicationInfo.bundleType == BundleType::SHARED) {
        innerModuleInfo.bundleType = applicationInfo.bundleType;
        innerModuleInfo.versionCode = applicationInfo.versionCode;
        innerModuleInfo.versionName = applicationInfo.versionName;
        innerBundleInfo.InsertInnerSharedModuleInfo(moduleJson.module.name, innerModuleInfo);
    }

    innerBundleInfo.InsertInnerModuleInfo(moduleJson.module.name, innerModuleInfo);
    innerBundleInfo.SetOverlayType(overlayMsg.type);

    if (overlayMsg.type == OVERLAY_EXTERNAL_BUNDLE && !overlayMsg.isAppPriorityExisted) {
        innerBundleInfo.SetTargetPriority(Constants::OVERLAY_MINIMUM_PRIORITY);
    } else {
        innerBundleInfo.SetTargetPriority(moduleJson.app.targetPriority);
    }
    int32_t overlayState = overlayMsg.type == OVERLAY_EXTERNAL_BUNDLE ? Constants::DEFAULT_OVERLAY_ENABLE_STATUS :
        Constants::DEFAULT_OVERLAY_DISABLE_STATUS;
    innerBundleInfo.SetOverlayState(overlayState);
    return true;
}
}  // namespace

OverlayMsg ModuleProfile::ObtainOverlayType(const nlohmann::json &jsonObject) const
{
    APP_LOGD("check if overlay installation");
    OverlayMsg overlayMsg;
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    if (!jsonObject.contains(Profile::MODULE) || !jsonObject.contains(Profile::APP)) {
        APP_LOGE("ObtainOverlayType failed due to bad module.json");
        Profile::g_parseResult = ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL;
        return overlayMsg;
    }
    nlohmann::json moduleJson = jsonObject.at(Profile::MODULE);
    nlohmann::json appJson = jsonObject.at(Profile::APP);
    if (!moduleJson.is_object() || !appJson.is_object()) {
        APP_LOGE("module.json file lacks of invalid module or app properties");
        Profile::g_parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return overlayMsg;
    }

    auto isTargetBundleExisted = appJson.contains(Profile::APP_TARGET_BUNDLE_NAME);
    auto isAppPriorityExisted = appJson.contains(Profile::APP_TARGET_PRIORITY);
    auto isTargetModuleNameExisted = moduleJson.contains(Profile::MODULE_TARGET_MODULE_NAME);
    auto isModulePriorityExisted = moduleJson.contains(Profile::MODULE_TARGET_PRIORITY);
    if (!isTargetBundleExisted && !isAppPriorityExisted && !isTargetModuleNameExisted &&
        !isModulePriorityExisted) {
        APP_LOGW("current hap is not overlayed hap");
        return overlayMsg;
    }
    if (!isTargetModuleNameExisted) {
        Profile::g_parseResult = ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_NAME_MISSED;
        APP_LOGE("overlay hap with invalid configuration file");
        return overlayMsg;
    }
    if (!isTargetBundleExisted && isAppPriorityExisted) {
        Profile::g_parseResult = ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_MISSED;
        APP_LOGE("overlay hap with invalid configuration file");
        return overlayMsg;
    }

    APP_LOGI("overlay configuration file is about to parse");
    overlayMsg.type = isTargetBundleExisted ? OVERLAY_EXTERNAL_BUNDLE : OVERLAY_INTERNAL_BUNDLE;
    overlayMsg.isAppPriorityExisted = isAppPriorityExisted;
    overlayMsg.isModulePriorityExisted = isModulePriorityExisted;
    return overlayMsg;
#else
    return overlayMsg;
#endif
}

ErrCode ModuleProfile::TransformTo(
    const std::ostringstream &source,
    const BundleExtractor &bundleExtractor,
    InnerBundleInfo &innerBundleInfo) const
{
    APP_LOGD("transform module.json stream to InnerBundleInfo");
    nlohmann::json jsonObject = nlohmann::json::parse(source.str(), nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("bad profile");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }
    OverlayMsg overlayMsg;
    Profile::ModuleJson moduleJson;
    {
        std::lock_guard<std::mutex> lock(Profile::g_mutex);
        Profile::g_parseResult = ERR_OK;
        overlayMsg = ObtainOverlayType(jsonObject);
        if ((overlayMsg.type == NON_OVERLAY_TYPE) && (Profile::g_parseResult != ERR_OK)) {
            int32_t ret = Profile::g_parseResult;
            Profile::g_parseResult = ERR_OK;
            APP_LOGE("ObtainOverlayType g_parseResult is %{public}d", ret);
            return ret;
        }
        APP_LOGD("overlay type of the hap is %{public}d", overlayMsg.type);
        Profile::g_parseResult = ERR_OK;
        moduleJson = jsonObject.get<Profile::ModuleJson>();
        if (Profile::g_parseResult != ERR_OK) {
            APP_LOGE("g_parseResult is %{public}d", Profile::g_parseResult);
            int32_t ret = Profile::g_parseResult;
            // need recover parse result to ERR_OK
            Profile::g_parseResult = ERR_OK;
            return ret;
        }
    }
    if (!ToInnerBundleInfo(
        moduleJson, bundleExtractor, overlayMsg, innerBundleInfo)) {
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR;
    }
    if (!ParserAtomicConfig(jsonObject, innerBundleInfo)) {
        APP_LOGE("Parser atomicService config failed.");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR;
    }
    if (!ParserNativeSo(moduleJson, bundleExtractor, innerBundleInfo)) {
        APP_LOGE("Parser native so failed.");
        return ERR_APPEXECFWK_PARSE_NATIVE_SO_FAILED;
    }
    if (!ParserArkNativeFilePath(moduleJson, bundleExtractor, innerBundleInfo)) {
        APP_LOGE("Parser ark native file failed.");
        return ERR_APPEXECFWK_PARSE_AN_FAILED;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
