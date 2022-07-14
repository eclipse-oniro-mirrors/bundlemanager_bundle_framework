/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "common_profile.h"

namespace OHOS {
namespace AppExecFwk {
namespace ProfileReader {
// common tag
const char* PROFILE_KEY_NAME = "name";
const char* PROFILE_KEY_ORIGINAL_NAME = "originalName";
const char* PROFILE_KEY_LABEL = "label";
const char* PROFILE_KEY_ICON_ID = "iconId";
const char* PROFILE_KEY_LABEL_ID = "labelId";
const char* PROFILE_KEY_DESCRIPTION = "description";
const char* PROFILE_KEY_DESCRIPTION_ID = "descriptionId";
const char* PROFILE_KEY_TYPE = "type";
const char* PROFILE_KEY_SRCPATH = "srcPath";
const char* PROFILE_KEY_SRCLANGUAGE = "srcLanguage";
const char* PRIORITY = "priority";

// bundle profile tag
const char* BUNDLE_PROFILE_KEY_APP = "app";
const char* BUNDLE_PROFILE_KEY_DEVICE_CONFIG = "deviceConfig";
const char* BUNDLE_PROFILE_KEY_MODULE = "module";
// sub  BUNDLE_PROFILE_KEY_APP
const char* BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME = "bundleName";
const char* BUNDLE_APP_PROFILE_KEY_VENDOR = "vendor";
const char* BUNDLE_APP_PROFILE_KEY_VERSION = "version";
const char* BUNDLE_APP_PROFILE_KEY_API_VERSION = "apiVersion";
const char* BUNDLE_APP_PROFILE_KEY_SINGLETON = "singleton";
const char* BUNDLE_APP_PROFILE_KEY_REMOVABLE = "removable";
const char* BUNDLE_APP_PROFILE_KEY_USER_DATA_CLEARABLE = "userDataClearable";
const char* BUNDLE_APP_PROFILE_KEY_TARGETET_BUNDLE_LIST = "targetBundleList";
// sub BUNDLE_APP_PROFILE_KEY_VERSION
const char* BUNDLE_APP_PROFILE_KEY_CODE = "code";
const char* BUNDLE_APP_PROFILE_KEY_MIN_COMPATIBLE_VERSION_CODE = "minCompatibleVersionCode";
// sub BUNDLE_APP_PROFILE_KEY_API_VERSION
const char* BUNDLE_APP_PROFILE_KEY_COMPATIBLE = "compatible";
const char* BUNDLE_APP_PROFILE_KEY_TARGET = "target";
const char* BUNDLE_APP_PROFILE_KEY_RELEASE_TYPE = "releaseType";
const char* APP_RELEASE_TYPE_VALUE_RELEASE = "Release";
// sub  BUNDLE_PROFILE_KEY_DEVICE_CONFIG
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DEFAULT = "default";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_PHONE = "phone";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TABLET = "tablet";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TV = "tv";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_CAR = "car";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_WEARABLE = "wearable";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_LITE_WEARABLE = "liteWearable";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SMART_VISION = "smartVision";
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DEFAULT
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_JOINT_USER_ID = "jointUserId";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_PROCESS = "process";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_KEEP_ALIVE = "keepAlive";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_ARK = "ark";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DIRECT_LAUNCH = "directLaunch";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SUPPORT_BACKUP = "supportBackup";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DEBUG = "debug";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_COMPRESS_NATIVE_LIBS = "compressNativeLibs";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_NETWORK = "network";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_REQ_VERSION = "reqVersion";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_FLAG = "flag";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_COMPATIBLE = "compatible";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TARGET = "target";
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_NETWORK
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_USES_CLEAR_TEXT = "usesCleartext";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SECURITY_CONFIG = "securityConfig";
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SECURITY_CONFIG
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAIN_SETTINGS = "domainSettings";
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAIN_SETTINGS
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_CLEAR_TEXT_PERMITTED = "cleartextPermitted";
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAINS = "domains";
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAINS
const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SUB_DOMAINS = "subDomains";
// sub BUNDLE_PROFILE_KEY_MODULE
const char* BUNDLE_MODULE_PROFILE_KEY_PACKAGE = "package";
const char* BUNDLE_MODULE_PROFILE_KEY_SUPPORTED_MODES = "supportedModes";
const char* BUNDLE_MODULE_PROFILE_KEY_REQ_CAPABILITIES = "reqCapabilities";
const char* BUNDLE_MODULE_PROFILE_KEY_SUPPORTED_REQ_CAPABILITIES = "reqCapabilities";
const char* BUNDLE_MODULE_DEPENDENCIES = "dependencies";
const char* MODULE_SUPPORTED_MODES_VALUE_DRIVE = "drive";
const char* BUNDLE_MODULE_PROFILE_KEY_DEVICE_TYPE = "deviceType";
const char* BUNDLE_MODULE_PROFILE_KEY_COLOR_MODE = "colorMode";
const char* BUNDLE_MODULE_PROFILE_KEY_DISTRO = "distro";
const char* BUNDLE_MODULE_PROFILE_KEY_META_DATA = "metaData";
const char* BUNDLE_MODULE_PROFILE_KEY_ABILITIES = "abilities";
const char* BUNDLE_MODULE_PROFILE_KEY_JS = "js";
const char* BUNDLE_MODULE_PROFILE_KEY_COMMON_EVENTS = "commonEvents";
const char* BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS = "shortcuts";
const char* BUNDLE_MODULE_PROFILE_KEY_DEFINE_PERMISSIONS = "definePermissions";
const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS = "reqPermissions";
const char* BUNDLE_MODULE_PROFILE_KEY_REQUEST_PERMISSIONS = "requestPermissions";
const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_NAME = "name";
const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_REASON = "reason";
const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_USEDSCENE = "usedScene";
const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_ABILITY = "ability";
const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_WHEN = "when";
const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_WHEN_INUSE = "inuse";
const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_WHEN_ALWAYS = "always";
const char* BUNDLE_MODULE_PROFILE_KEY_CUSTOMIZE_DATA = "customizeData";
const char* BUNDLE_MODULE_PROFILE_KEY_MAIN_ABILITY = "mainAbility";
const char* BUNDLE_MODULE_PROFILE_KEY_SRC_PATH = "srcPath";
// sub BUNDLE_MODULE_PROFILE_KEY_DISTRO
const char* BUNDLE_MODULE_PROFILE_KEY_DELIVERY_WITH_INSTALL = "deliveryWithInstall";
const char* BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME = "moduleName";
const char* BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE = "moduleType";
const char* BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE = "installationFree";
// sub BUNDLE_MODULE_PROFILE_KEY_SKILLS
const char* BUNDLE_MODULE_PROFILE_KEY_ACTIONS = "actions";
const char* BUNDLE_MODULE_PROFILE_KEY_ENTITIES = "entities";
const char* BUNDLE_MODULE_PROFILE_KEY_URIS = "uris";
// sub BUNDLE_MODULE_PROFILE_KEY_URIS
const char* BUNDLE_MODULE_PROFILE_KEY_SCHEME = "scheme";
const char* BUNDLE_MODULE_PROFILE_KEY_HOST = "host";
const char* BUNDLE_MODULE_PROFILE_KEY_PORT = "port";
const char* BUNDLE_MODULE_PROFILE_KEY_PATH = "path";
const char* BUNDLE_MODULE_PROFILE_KEY_PATHSTARTWITH = "pathStartWith";
const char* BUNDLE_MODULE_PROFILE_KEY_PATHREGX = "pathRegx";
const char* BUNDLE_MODULE_PROFILE_KEY_PATHREGEX = "pathRegex";
const char* BUNDLE_MODULE_PROFILE_KEY_TYPE = "type";
// sub BUNDLE_MODULE_PROFILE_KEY_META_DATA
const char* BUNDLE_MODULE_META_KEY_CUSTOMIZE_DATA = "customizeData";
const char* BUNDLE_MODULE_META_KEY_NAME = "name";
const char* BUNDLE_MODULE_META_KEY_VALUE = "value";
const char* BUNDLE_MODULE_META_KEY_EXTRA = "extra";
// sub BUNDLE_MODULE_PROFILE_KEY_DISTRO_TYPE
const char* MODULE_DISTRO_MODULE_TYPE_VALUE_ENTRY = "entry";
const char* MODULE_DISTRO_MODULE_TYPE_VALUE_FEATURE = "feature";
const char* MODULE_DISTRO_MODULE_TYPE_VALUE_HAR = "har";
// sub BUNDLE_MODULE_PROFILE_KEY_ABILITIES
const char* BUNDLE_MODULE_PROFILE_KEY_ICON = "icon";
const char* BUNDLE_MODULE_PROFILE_KEY_ICON_ID = "iconId";
const char* BUNDLE_MODULE_PROFILE_KEY_URI = "uri";
const char* BUNDLE_MODULE_PROFILE_KEY_LAUNCH_TYPE = "launchType";
const char* BUNDLE_MODULE_PROFILE_KEY_LAUNCH_THEME = "theme";
const char* BUNDLE_MODULE_PROFILE_KEY_VISIBLE = "visible";
const char* BUNDLE_MODULE_PROFILE_KEY_CONTINUABLE = "continuable";
const char* BUNDLE_MODULE_PROFILE_KEY_PERMISSIONS = "permissions";
const char* BUNDLE_MODULE_PROFILE_KEY_SKILLS = "skills";
const char* BUNDLE_MODULE_PROFILE_KEY_PROCESS = "process";
const char* BUNDLE_MODULE_PROFILE_KEY_DEVICE_CAP_ABILITY = "deviceCapability";
const char* BUNDLE_MODULE_PROFILE_KEY_FORM_ENABLED = "formEnabled";
const char* BUNDLE_MODULE_PROFILE_KEY_FORM = "form";
const char* BUNDLE_MODULE_PROFILE_KEY_ORIENTATION = "orientation";
const char* BUNDLE_MODULE_PROFILE_KEY_BACKGROUND_MODES = "backgroundModes";
const char* BUNDLE_MODULE_PROFILE_KEY_GRANT_PERMISSION = "grantPermission";
const char* BUNDLE_MODULE_PROFILE_KEY_URI_PERMISSION = "uriPermission";
const char* BUNDLE_MODULE_PROFILE_KEY_READ_PERMISSION = "readPermission";
const char* BUNDLE_MODULE_PROFILE_KEY_WRITE_PERMISSION = "writePermission";
const char* BUNDLE_MODULE_PROFILE_KEY_DIRECT_LAUNCH = "directLaunch";
const char* BUNDLE_MODULE_PROFILE_KEY_CONFIG_CHANGES = "configChanges";
const char* BUNDLE_MODULE_PROFILE_KEY_MISSION = "mission";
const char* BUNDLE_MODULE_PROFILE_KEY_TARGET_ABILITY = "targetAbility";
const char* BUNDLE_MODULE_PROFILE_KEY_MULTIUSER_SHARED = "multiUserShared";
const char* BUNDLE_MODULE_PROFILE_KEY_SUPPORT_PIP_MODE = "supportPipMode";
const char* BUNDLE_MODULE_PROFILE_KEY_FORMS_ENABLED = "formsEnabled";
const char* BUNDLE_MODULE_PROFILE_KEY_FORMS = "forms";
const char* BUNDLE_MODULE_PROFILE_KEY_START_WINDOW_ICON = "startWindowIcon";
const char* BUNDLE_MODULE_PROFILE_KEY_START_WINDOW_ICON_ID = "startWindowIconId";
const char* BUNDLE_MODULE_PROFILE_KEY_START_WINDOW_BACKGROUND = "startWindowBackground";
const char* BUNDLE_MODULE_PROFILE_KEY_START_WINDOW_BACKGROUND_ID = "startWindowBackgroundId";
const char* BUNDLE_MODULE_PROFILE_KEY_REMOVE_MISSION_AFTER_TERMINATE = "removeMissionAfterTerminate";
// sub BUNDLE_MODULE_PROFILE_KEY_FORM
const char* BUNDLE_MODULE_PROFILE_KEY_MODE = "mode";
// sub BUNDLE_MODULE_PROFILE_KEY_FORM
const char* BUNDLE_MODULE_PROFILE_FORM_ENTITY = "formEntity";
const char* BUNDLE_MODULE_PROFILE_FORM_MIN_HEIGHT = "minHeight";
const char* BUNDLE_MODULE_PROFILE_FORM_DEFAULT_HEIGHT = "defaultHeight";
const char* BUNDLE_MODULE_PROFILE_FORM_MIN_WIDTH = "minWidth";
const char* BUNDLE_MODULE_PROFILE_FORM_DEFAULT_WIDTH = "defaultWidth";
// sub BUNDLE_MODULE_PROFILE_KEY_FORMS
const char* BUNDLE_MODULE_PROFILE_FORMS_IS_DEFAULT = "isDefault";
const char* BUNDLE_MODULE_PROFILE_FORMS_COLOR_MODE = "colorMode";
const char* BUNDLE_MODULE_PROFILE_FORMS_SUPPORT_DIMENSIONS = "supportDimensions";
const char* BUNDLE_MODULE_PROFILE_FORMS_DEFAULT_DIMENSION = "defaultDimension";
const char* BUNDLE_MODULE_PROFILE_FORMS_LANDSCAPE_LAYOUTS = "landscapeLayouts";
const char* BUNDLE_MODULE_PROFILE_FORMS_PORTRAIT_LAYOUTS = "portraitLayouts";
const char* BUNDLE_MODULE_PROFILE_FORMS_UPDATEENABLED = "updateEnabled";
const char* BUNDLE_MODULE_PROFILE_FORMS_SCHEDULED_UPDATE_TIME = "scheduledUpdateTime";
const char* BUNDLE_MODULE_PROFILE_FORMS_UPDATE_DURATION = "updateDuration";
const char* BUNDLE_MODULE_PROFILE_FORMS_DEEP_LINK = "deepLink";
const char* BUNDLE_MODULE_PROFILE_FORMS_JS_COMPONENT_NAME = "jsComponentName";
const char* BUNDLE_MODULE_PROFILE_FORMS_VALUE = "value";
const char* BUNDLE_MODULE_PROFILE_FORMS_FORM_CONFIG_ABILITY = "formConfigAbility";
const char* BUNDLE_MODULE_PROFILE_FORMS_FORM_VISIBLE_NOTIFY = "formVisibleNotify";
const char* BUNDLE_MODULE_PROFILE_FORMS_SRC = "src";
// sub BUNDLE_MODULE_PROFILE_KEY_JS
const char* BUNDLE_MODULE_PROFILE_KEY_PAGES = "pages";
const char* BUNDLE_MODULE_PROFILE_KEY_WINDOW = "window";
// sub BUNDLE_MODULE_PROFILE_KEY_COMMON_EVENTS
const char* BUNDLE_MODULE_PROFILE_KEY_PERMISSION = "permission";
const char* BUNDLE_MODULE_PROFILE_KEY_DATA = "data";
const char* BUNDLE_MODULE_PROFILE_KEY_EVENTS = "events";
const char* MODULE_ABILITY_JS_TYPE_VALUE_NORMAL = "normal";
const char* MODULE_ABILITY_JS_TYPE_VALUE_FORM = "form";
// sub BUNDLE_MODULE_PROFILE_KEY_WINDOW
const char* BUNDLE_MODULE_PROFILE_KEY_DESIGN_WIDTH = "designWidth";
const char* BUNDLE_MODULE_PROFILE_KEY_AUTO_DESIGN_WIDTH = "autoDesignWidth";
// sub BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS
const char* BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_ID = "shortcutId";
const char* BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_WANTS = "intents";
// sub BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_WANTS
const char* BUNDLE_MODULE_PROFILE_KEY_TARGET_CLASS = "targetClass";
const char* BUNDLE_MODULE_PROFILE_KEY_TARGET_BUNDLE = "targetBundle";
// sub BUNDLE_INSTALL_MARK
const char* BUNDLE_INSTALL_MARK_BUNDLE = "installMarkBundle";
const char* BUNDLE_INSTALL_MARK_PACKAGE = "installMarkPackage";
const char* BUNDLE_INSTALL_MARK_STATUS = "installMarkStatus";
// sub BUNDLE_SANDBOX_PERSISTENT_INFO
const char* BUNDLE_SANDBOX_PERSISTENT_ACCESS_TOKEN_ID = "accessTokenId";
const char* BUNDLE_SANDBOX_PERSISTENT_APP_INDEX = "appIndex";
const char* BUNDLE_SANDBOX_PERSISTENT_USER_ID = "userId";

const char* KEY_HOME_SCREEN = "homeScreen";
const char* KEY_SEARCHBOX = "searchbox";

const char* BUNDLE_MODULE_PROFILE_KEY_JS_TYPE_ETS = "ets";

const char* KEY_DATA_TRANSFER = "dataTransfer";
const char* KEY_AUDIO_PLAYBACK = "audioPlayback";
const char* KEY_AUDIO_RECORDING = "audioRecording";
const char* KEY_LOCATION = "location";
const char* KEY_BLUETOOTH_INTERACTION = "bluetoothInteraction";
const char* KEY_MULTI_DEVICE_CONNECTION = "multiDeviceConnection";
const char* KEY_WIFI_INTERACTION = "wifiInteraction";
const char* KEY_VOIP = "voip";
const char* KEY_TASK_KEEPING = "taskKeeping";
const char* KEY_PICTURE_IN_PICTURE = "pictureInPicture";
const char* KEY_SCREEN_FETCH = "screenFetch";
} // namespace ProfileReader

namespace Profile {
// common
const char* ICON = "icon";
const char* ICON_ID = "iconId";
const char* LABEL = "label";
const char* LABEL_ID = "labelId";
const char* DESCRIPTION = "description";
const char* DESCRIPTION_ID = "descriptionId";
const char* META_DATA = "metadata";
const char* SKILLS = "skills";
const char* SRC_ENTRANCE = "srcEntrance";
const char* PERMISSIONS = "permissions";
const char* VISIBLE = "visible";
const char* SRC_LANGUAGE = "srcLanguage";
const char* PRIORITY = "priority";
// module.json
const char* APP = "app";
const char* MODULE = "module";
// app
const char* APP_BUNDLE_NAME = "bundleName";
const char* APP_DEBUG = "debug";
const char* APP_VENDOR = "vendor";
const char* APP_VERSION_CODE = "versionCode";
const char* APP_VERSION_NAME = "versionName";
const char* APP_MIN_COMPATIBLE_VERSION_CODE = "minCompatibleVersionCode";
const char* APP_MIN_API_VERSION = "minAPIVersion";
const char* APP_TARGET_API_VERSION = "targetAPIVersion";
const char* APP_API_RELEASETYPE = "apiReleaseType";
const char* APP_API_RELEASETYPE_DEFAULT_VALUE = "Release";
const char* APP_DISTRIBUTED_NOTIFICATION_ENABLED = "distributedNotificationEnabled";
const char* APP_ENTITY_TYPE = "entityType";
const char* APP_ENTITY_TYPE_DEFAULT_VALUE = "unspecified";
const char* APP_KEEP_ALIVE = "keepAlive";
const char* APP_REMOVABLE = "removable";
const char* APP_SINGLETON = "singleton";
const char* APP_USER_DATA_CLEARABLE = "userDataClearable";
const char* APP_PHONE = "phone";
const char* APP_TABLET = "tablet";
const char* APP_TV = "tv";
const char* APP_WEARABLE = "wearable";
const char* APP_LITE_WEARABLE = "liteWearable";
const char* APP_CAR = "car";
const char* APP_SMART_VISION = "smartVision";
const char* APP_ROUTER = "router";
const char* APP_ACCESSIBLE = "accessible";
const char* APP_TARGETBUNDLELIST = "targetBundleList";
const char* APP_MULTI_PROJECTS = "multiProjects";
// module
const char* MODULE_NAME = "name";
const char* MODULE_TYPE = "type";
const char* MODULE_PROCESS = "process";
const char* MODULE_MAIN_ELEMENT = "mainElement";
const char* MODULE_DEVICE_TYPES = "deviceTypes";
const char* MODULE_DELIVERY_WITH_INSTALL = "deliveryWithInstall";
const char* MODULE_INSTALLATION_FREE = "installationFree";
const char* MODULE_VIRTUAL_MACHINE = "virtualMachine";
const char* MODULE_VIRTUAL_MACHINE_DEFAULT_VALUE = "default";
const char* MODULE_UI_SYNTAX = "uiSyntax";
const char* MODULE_UI_SYNTAX_DEFAULT_VALUE = "hml";
const char* MODULE_PAGES = "pages";
const char* MODULE_ABILITIES = "abilities";
const char* MODULE_EXTENSION_ABILITIES = "extensionAbilities";
const char* MODULE_REQUEST_PERMISSIONS = "requestPermissions";
const char* MODULE_DEFINE_PERMISSIONS = "definePermissions";
const char* MODULE_DEPENDENCIES = "dependencies";
const char* MODULE_COMPILE_MODE = "compileMode";
// module type
const char* MODULE_TYPE_ENTRY = "entry";
const char* MODULE_TYPE_FEATURE = "feature";
const char* MODULE_TYPE_HAR = "har";
// deviceConfig
const char* MIN_API_VERSION = "minAPIVersion";
const char* DEVICE_CONFIG_DISTRIBUTED_NOTIFICATION_ENABLED = "distributedNotificationEnabled";
const char* DEVICE_CONFIG_KEEP_ALIVE = "keepAlive";
const char* DEVICE_CONFIG_REMOVABLE = "removable";
const char* DEVICE_CONFIG_SINGLETON = "singleton";
const char* DEVICE_CONFIG_USER_DATA_CLEARABLE = "userDataClearable";
const char* DEVICE_CONFIG_ACCESSIBLE = "accessible";
// metadata
const char* META_DATA_NAME = "name";
const char* META_DATA_VALUE = "value";
const char* META_DATA_RESOURCE = "resource";
// metadata reserved
const char* META_DATA_FORM = "ohos.extension.form";
const char* META_DATA_SHORTCUTS = "ohos.ability.shortcuts";
const char* META_DATA_COMMON_EVENTS = "ohos.extension.staticSubscriber";
// ability
const char* ABILITY_NAME = "name";
const char* ABILITY_LAUNCH_TYPE = "launchType";
const char* ABILITY_LAUNCH_TYPE_DEFAULT_VALUE = "singleton";
const char* ABILITY_BACKGROUNDMODES = "backgroundModes";
const char* ABILITY_CONTINUABLE = "continuable";
const char* ABILITY_START_WINDOW_ICON = "startWindowIcon";
const char* ABILITY_START_WINDOW_ICON_ID = "startWindowIconId";
const char* ABILITY_START_WINDOW_BACKGROUND = "startWindowBackground";
const char* ABILITY_START_WINDOW_BACKGROUND_ID = "startWindowBackgroundId";
const char* ABILITY_REMOVE_MISSION_AFTER_TERMINATE = "removeMissionAfterTerminate";
const char* ABILITY_ORIENTATION = "orientation";
const char* ABILITY_SUPPORT_WINDOW_MODE = "supportWindowMode";
const char* ABILITY_MAX_WINDOW_RATIO = "maxWindowRatio";
const char* ABILITY_MIN_WINDOW_RATIO = "minWindowRatio";
const char* ABILITY_MAX_WINDOW_WIDTH = "maxWindowWidth";
const char* ABILITY_MIN_WINDOW_WIDTH = "minWindowWidth";
const char* ABILITY_MAX_WINDOW_HEIGHT = "maxWindowHeight";
const char* ABILITY_MIN_WINDOW_HEIGHT = "minWindowHeight";
const char* ABILITY_EXCLUDE_FROM_MISSIONS = "excludeFromMissions";
// extension ability
const char* EXTENSION_ABILITY_NAME = "name";
const char* EXTENSION_ABILITY_TYPE = "type";
const char* EXTENSION_URI = "uri";
const char* EXTENSION_ABILITY_READ_PERMISSION = "readPermission";
const char* EXTENSION_ABILITY_WRITE_PERMISSION = "writePermission";
// requestPermission
const char* REQUESTPERMISSION_NAME = "name";
const char* REQUESTPERMISSION_REASON = "reason";
const char* REQUESTPERMISSION_REASON_ID = "reasonId";
const char* REQUESTPERMISSION_USEDSCENE = "usedScene";
const char* REQUESTPERMISSION_ABILITIES = "abilities";
const char* REQUESTPERMISSION_WHEN = "when";
// definePermission
const char* DEFINEPERMISSION_NAME = "name";
const char* DEFINEPERMISSION_GRANT_MODE = "grantMode";
const char* DEFINEPERMISSION_AVAILABLE_LEVEL = "availableLevel";
const char* DEFINEPERMISSION_PROVISION_ENABLE = "provisionEnable";
const char* DEFINEPERMISSION_DISTRIBUTED_SCENE_ENABLE = "distributedSceneEnable";
const char* DEFINEPERMISSION_GRANT_MODE_SYSTEM_GRANT = "system_grant";
const char* DEFINEPERMISSION_AVAILABLE_LEVEL_DEFAULT_VALUE = "normal";
// apl
const char* AVAILABLELEVEL_NORMAL = "normal";
const char* AVAILABLELEVEL_SYSTEM_BASIC = "system_basic";
const char* AVAILABLELEVEL_SYSTEM_CORE = "system_core";
// compile mode
const char* COMPILE_MODE_JS_BUNDLE = "jsbundle";
const char* COMPILE_MODE_ES_MODULE = "esmodule";
} // namespace Profile
} // namespace AppExecFwk
} // namespace OHOS