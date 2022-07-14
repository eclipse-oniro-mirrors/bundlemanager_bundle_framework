/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_COMMON_PROFILE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_COMMON_PROFILE_H

#include <string>

#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
namespace ProfileReader {
// common tag
extern const char* PROFILE_KEY_NAME;
extern const char* PROFILE_KEY_ORIGINAL_NAME;
extern const char* PROFILE_KEY_LABEL;
extern const char* PROFILE_KEY_ICON_ID;
extern const char* PROFILE_KEY_LABEL_ID;
extern const char* PROFILE_KEY_DESCRIPTION;
extern const char* PROFILE_KEY_DESCRIPTION_ID;
extern const char* PROFILE_KEY_TYPE;
extern const char* PROFILE_KEY_SRCPATH;
extern const char* PROFILE_KEY_SRCLANGUAGE;
extern const char* PRIORITY;

// bundle profile tag
extern const char* BUNDLE_PROFILE_KEY_APP;
extern const char* BUNDLE_PROFILE_KEY_DEVICE_CONFIG;
extern const char* BUNDLE_PROFILE_KEY_MODULE;
// sub  BUNDLE_PROFILE_KEY_APP
extern const char* BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME;
extern const char* BUNDLE_APP_PROFILE_KEY_VENDOR;
extern const char* BUNDLE_APP_PROFILE_KEY_VERSION;
extern const char* BUNDLE_APP_PROFILE_KEY_API_VERSION;
extern const char* BUNDLE_APP_PROFILE_KEY_SINGLETON;
extern const char* BUNDLE_APP_PROFILE_KEY_REMOVABLE;
extern const char* BUNDLE_APP_PROFILE_KEY_USER_DATA_CLEARABLE;
extern const char* BUNDLE_APP_PROFILE_KEY_TARGETET_BUNDLE_LIST;
// sub BUNDLE_APP_PROFILE_KEY_VERSION
extern const char* BUNDLE_APP_PROFILE_KEY_CODE;
extern const char* BUNDLE_APP_PROFILE_KEY_MIN_COMPATIBLE_VERSION_CODE;
// sub BUNDLE_APP_PROFILE_KEY_API_VERSION
extern const char* BUNDLE_APP_PROFILE_KEY_COMPATIBLE;
extern const char* BUNDLE_APP_PROFILE_KEY_TARGET;
extern const char* BUNDLE_APP_PROFILE_KEY_RELEASE_TYPE;
extern const char* APP_RELEASE_TYPE_VALUE_RELEASE;
// sub  BUNDLE_PROFILE_KEY_DEVICE_CONFIG
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DEFAULT;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_PHONE;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TABLET;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TV;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_CAR;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_WEARABLE;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_LITE_WEARABLE;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SMART_VISION;
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DEFAULT
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_JOINT_USER_ID;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_PROCESS;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_KEEP_ALIVE;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_ARK;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DIRECT_LAUNCH;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SUPPORT_BACKUP;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DEBUG;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_COMPRESS_NATIVE_LIBS;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_NETWORK;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_REQ_VERSION;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_FLAG;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_COMPATIBLE;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TARGET;
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_NETWORK
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_USES_CLEAR_TEXT;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SECURITY_CONFIG;
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SECURITY_CONFIG
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAIN_SETTINGS;
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAIN_SETTINGS
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_CLEAR_TEXT_PERMITTED;
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAINS;
// sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAINS
extern const char* BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SUB_DOMAINS;
// sub BUNDLE_PROFILE_KEY_MODULE
extern const char* BUNDLE_MODULE_PROFILE_KEY_PACKAGE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_SUPPORTED_MODES;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQ_CAPABILITIES;
extern const char* BUNDLE_MODULE_PROFILE_KEY_SUPPORTED_REQ_CAPABILITIES;
extern const char* BUNDLE_MODULE_DEPENDENCIES;
extern const char* MODULE_SUPPORTED_MODES_VALUE_DRIVE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_DEVICE_TYPE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_COLOR_MODE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_DISTRO;
extern const char* BUNDLE_MODULE_PROFILE_KEY_META_DATA;
extern const char* BUNDLE_MODULE_PROFILE_KEY_ABILITIES;
extern const char* BUNDLE_MODULE_PROFILE_KEY_JS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_COMMON_EVENTS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_DEFINE_PERMISSIONS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQUEST_PERMISSIONS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_NAME;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_REASON;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_USEDSCENE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_ABILITY;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_WHEN;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_WHEN_INUSE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS_WHEN_ALWAYS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_CUSTOMIZE_DATA;
extern const char* BUNDLE_MODULE_PROFILE_KEY_MAIN_ABILITY;
extern const char* BUNDLE_MODULE_PROFILE_KEY_SRC_PATH;
// sub BUNDLE_MODULE_PROFILE_KEY_DISTRO
extern const char* BUNDLE_MODULE_PROFILE_KEY_DELIVERY_WITH_INSTALL;
extern const char* BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME;
extern const char* BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE;
// sub BUNDLE_MODULE_PROFILE_KEY_SKILLS
extern const char* BUNDLE_MODULE_PROFILE_KEY_ACTIONS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_ENTITIES;
extern const char* BUNDLE_MODULE_PROFILE_KEY_URIS;
// sub BUNDLE_MODULE_PROFILE_KEY_URIS
extern const char* BUNDLE_MODULE_PROFILE_KEY_SCHEME;
extern const char* BUNDLE_MODULE_PROFILE_KEY_HOST;
extern const char* BUNDLE_MODULE_PROFILE_KEY_PORT;
extern const char* BUNDLE_MODULE_PROFILE_KEY_PATH;
extern const char* BUNDLE_MODULE_PROFILE_KEY_PATHSTARTWITH;
extern const char* BUNDLE_MODULE_PROFILE_KEY_PATHREGX;
extern const char* BUNDLE_MODULE_PROFILE_KEY_PATHREGEX;
extern const char* BUNDLE_MODULE_PROFILE_KEY_TYPE;
// sub BUNDLE_MODULE_PROFILE_KEY_META_DATA
extern const char* BUNDLE_MODULE_META_KEY_CUSTOMIZE_DATA;
extern const char* BUNDLE_MODULE_META_KEY_NAME;
extern const char* BUNDLE_MODULE_META_KEY_VALUE;
extern const char* BUNDLE_MODULE_META_KEY_EXTRA;
// sub BUNDLE_MODULE_PROFILE_KEY_DISTRO_TYPE
extern const char* MODULE_DISTRO_MODULE_TYPE_VALUE_ENTRY;
extern const char* MODULE_DISTRO_MODULE_TYPE_VALUE_FEATURE;
extern const char* MODULE_DISTRO_MODULE_TYPE_VALUE_HAR;
// sub BUNDLE_MODULE_PROFILE_KEY_ABILITIES
extern const char* BUNDLE_MODULE_PROFILE_KEY_ICON;
extern const char* BUNDLE_MODULE_PROFILE_KEY_ICON_ID;
extern const char* BUNDLE_MODULE_PROFILE_KEY_URI;
extern const char* BUNDLE_MODULE_PROFILE_KEY_LAUNCH_TYPE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_LAUNCH_THEME;
extern const char* BUNDLE_MODULE_PROFILE_KEY_VISIBLE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_CONTINUABLE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_PERMISSIONS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_SKILLS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_PROCESS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_DEVICE_CAP_ABILITY;
extern const char* BUNDLE_MODULE_PROFILE_KEY_FORM_ENABLED;
extern const char* BUNDLE_MODULE_PROFILE_KEY_FORM;
extern const char* BUNDLE_MODULE_PROFILE_KEY_ORIENTATION;
extern const char* BUNDLE_MODULE_PROFILE_KEY_BACKGROUND_MODES;
extern const char* BUNDLE_MODULE_PROFILE_KEY_GRANT_PERMISSION;
extern const char* BUNDLE_MODULE_PROFILE_KEY_URI_PERMISSION;
extern const char* BUNDLE_MODULE_PROFILE_KEY_READ_PERMISSION;
extern const char* BUNDLE_MODULE_PROFILE_KEY_WRITE_PERMISSION;
extern const char* BUNDLE_MODULE_PROFILE_KEY_DIRECT_LAUNCH;
extern const char* BUNDLE_MODULE_PROFILE_KEY_CONFIG_CHANGES;
extern const char* BUNDLE_MODULE_PROFILE_KEY_MISSION;
extern const char* BUNDLE_MODULE_PROFILE_KEY_TARGET_ABILITY;
extern const char* BUNDLE_MODULE_PROFILE_KEY_MULTIUSER_SHARED;
extern const char* BUNDLE_MODULE_PROFILE_KEY_SUPPORT_PIP_MODE;
extern const char* BUNDLE_MODULE_PROFILE_KEY_FORMS_ENABLED;
extern const char* BUNDLE_MODULE_PROFILE_KEY_FORMS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_START_WINDOW_ICON;
extern const char* BUNDLE_MODULE_PROFILE_KEY_START_WINDOW_ICON_ID;
extern const char* BUNDLE_MODULE_PROFILE_KEY_START_WINDOW_BACKGROUND;
extern const char* BUNDLE_MODULE_PROFILE_KEY_START_WINDOW_BACKGROUND_ID;
extern const char* BUNDLE_MODULE_PROFILE_KEY_REMOVE_MISSION_AFTER_TERMINATE;
// sub BUNDLE_MODULE_PROFILE_KEY_FORM
extern const char* BUNDLE_MODULE_PROFILE_KEY_MODE;
// sub BUNDLE_MODULE_PROFILE_KEY_FORM
extern const char* BUNDLE_MODULE_PROFILE_FORM_ENTITY;
extern const char* BUNDLE_MODULE_PROFILE_FORM_MIN_HEIGHT;
extern const char* BUNDLE_MODULE_PROFILE_FORM_DEFAULT_HEIGHT;
extern const char* BUNDLE_MODULE_PROFILE_FORM_MIN_WIDTH;
extern const char* BUNDLE_MODULE_PROFILE_FORM_DEFAULT_WIDTH;
// sub BUNDLE_MODULE_PROFILE_KEY_FORMS
extern const char* BUNDLE_MODULE_PROFILE_FORMS_IS_DEFAULT;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_COLOR_MODE;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_SUPPORT_DIMENSIONS;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_DEFAULT_DIMENSION;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_LANDSCAPE_LAYOUTS;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_PORTRAIT_LAYOUTS;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_UPDATEENABLED;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_SCHEDULED_UPDATE_TIME;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_UPDATE_DURATION;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_DEEP_LINK;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_JS_COMPONENT_NAME;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_VALUE;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_FORM_CONFIG_ABILITY;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_FORM_VISIBLE_NOTIFY;
extern const char* BUNDLE_MODULE_PROFILE_FORMS_SRC;
// sub BUNDLE_MODULE_PROFILE_KEY_JS
extern const char* BUNDLE_MODULE_PROFILE_KEY_PAGES;
extern const char* BUNDLE_MODULE_PROFILE_KEY_WINDOW;
// sub BUNDLE_MODULE_PROFILE_KEY_COMMON_EVENTS
extern const char* BUNDLE_MODULE_PROFILE_KEY_PERMISSION;
extern const char* BUNDLE_MODULE_PROFILE_KEY_DATA;
extern const char* BUNDLE_MODULE_PROFILE_KEY_EVENTS;
extern const char* MODULE_ABILITY_JS_TYPE_VALUE_NORMAL;
extern const char* MODULE_ABILITY_JS_TYPE_VALUE_FORM;
// sub BUNDLE_MODULE_PROFILE_KEY_WINDOW
extern const char* BUNDLE_MODULE_PROFILE_KEY_DESIGN_WIDTH;
extern const char* BUNDLE_MODULE_PROFILE_KEY_AUTO_DESIGN_WIDTH;
// sub BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS
extern const char* BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_ID;
extern const char* BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_WANTS;
// sub BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_WANTS
extern const char* BUNDLE_MODULE_PROFILE_KEY_TARGET_CLASS;
extern const char* BUNDLE_MODULE_PROFILE_KEY_TARGET_BUNDLE;
// sub BUNDLE_INSTALL_MARK
extern const char* BUNDLE_INSTALL_MARK_BUNDLE;
extern const char* BUNDLE_INSTALL_MARK_PACKAGE;
extern const char* BUNDLE_INSTALL_MARK_STATUS;
// sub BUNDLE_SANDBOX_PERSISTENT_INFO
extern const char* BUNDLE_SANDBOX_PERSISTENT_ACCESS_TOKEN_ID;
extern const char* BUNDLE_SANDBOX_PERSISTENT_APP_INDEX;
extern const char* BUNDLE_SANDBOX_PERSISTENT_USER_ID;

const uint32_t VALUE_HOME_SCREEN = 1 << 0;
// 000010 represents supporting search box
const uint32_t VALUE_SEARCHBOX = 1 << 1;

extern const char* KEY_HOME_SCREEN;
extern const char* KEY_SEARCHBOX;

extern const char* BUNDLE_MODULE_PROFILE_KEY_JS_TYPE_ETS;

static std::map<std::string, uint32_t> formEntityMap;

extern thread_local int32_t parseResult;

// background modes
// different bits in the binary represent different services
// 0000001 represents data transmission services
constexpr uint32_t VALUE_DATA_TRANSFER = 1 << 0;

// 0000 0010 represents audio output service
constexpr uint32_t VALUE_AUDIO_PLAYBACK = 1 << 1;

// 0000 0100 represents audio input service
constexpr uint32_t VALUE_AUDIO_RECORDING = 1 << 2;

// 0000 1000 represents positioning navigation service
constexpr uint32_t VALUE_LOCATION = 1 << 3;

// 0001 0000 represents bluetooth scanning, connection, transmission service (wearing)
constexpr uint32_t VALUE_BLUETOOTH_INTERACTION = 1 << 4;

// 0010 0000 represents multi device connection services
constexpr uint32_t VALUE_MULTI_DEVICE_CONNECTION = 1 << 5;

// 0100 0000 represents WiFi scanning, connection, transmission services (multi-screen)
constexpr uint32_t VALUE_WIFI_INTERACTION = 1 << 6;

// 1000 0000 represents audio call,VOIP service
constexpr uint32_t VALUE_VOIP = 1 << 7;

// 1 0000 0000 represents task Keeping service
constexpr uint32_t VALUE_TASK_KEEPING = 1 << 8;

// 10 0000 0000 represents picture in picture service
constexpr uint32_t VALUE_PICTURE_IN_PICTURE = 1 << 9;

// 100 0000 0000 represents screen fetch service
constexpr uint32_t VALUE_SCREEN_FETCH = 1 << 10;

extern const char* KEY_DATA_TRANSFER;
extern const char* KEY_AUDIO_PLAYBACK;
extern const char* KEY_AUDIO_RECORDING;
extern const char* KEY_LOCATION;
extern const char* KEY_BLUETOOTH_INTERACTION;
extern const char* KEY_MULTI_DEVICE_CONNECTION;
extern const char* KEY_WIFI_INTERACTION;
extern const char* KEY_VOIP;
extern const char* KEY_TASK_KEEPING;
extern const char* KEY_PICTURE_IN_PICTURE;
extern const char* KEY_SCREEN_FETCH;
}  // namespace ProfileReader

namespace Profile {
// common
extern const char* ICON;
extern const char* ICON_ID;
extern const char* LABEL;
extern const char* LABEL_ID;
extern const char* DESCRIPTION;
extern const char* DESCRIPTION_ID;
extern const char* META_DATA;
extern const char* SKILLS;
extern const char* SRC_ENTRANCE;
extern const char* PERMISSIONS;
extern const char* VISIBLE;
extern const char* SRC_LANGUAGE;
extern const char* PRIORITY;
// module.json
extern const char* APP;
extern const char* MODULE;
// app
extern const char* APP_BUNDLE_NAME;
extern const char* APP_DEBUG;
extern const char* APP_VENDOR;
extern const char* APP_VERSION_CODE;
extern const char* APP_VERSION_NAME;
extern const char* APP_MIN_COMPATIBLE_VERSION_CODE;
extern const char* APP_MIN_API_VERSION;
extern const char* APP_TARGET_API_VERSION;
extern const char* APP_API_RELEASETYPE;
extern const char* APP_API_RELEASETYPE_DEFAULT_VALUE;
extern const char* APP_DISTRIBUTED_NOTIFICATION_ENABLED;
extern const char* APP_ENTITY_TYPE;
extern const char* APP_ENTITY_TYPE_DEFAULT_VALUE;
extern const char* APP_KEEP_ALIVE;
extern const char* APP_REMOVABLE;
extern const char* APP_SINGLETON;
extern const char* APP_USER_DATA_CLEARABLE;
extern const char* APP_PHONE;
extern const char* APP_TABLET;
extern const char* APP_TV;
extern const char* APP_WEARABLE;
extern const char* APP_LITE_WEARABLE;
extern const char* APP_CAR;
extern const char* APP_SMART_VISION;
extern const char* APP_ROUTER;
extern const char* APP_ACCESSIBLE;
extern const char* APP_TARGETBUNDLELIST;
extern const char* APP_MULTI_PROJECTS;
// module
extern const char* MODULE_NAME;
extern const char* MODULE_TYPE;
extern const char* MODULE_PROCESS;
extern const char* MODULE_MAIN_ELEMENT;
extern const char* MODULE_DEVICE_TYPES;
extern const char* MODULE_DELIVERY_WITH_INSTALL;
extern const char* MODULE_INSTALLATION_FREE;
extern const char* MODULE_VIRTUAL_MACHINE;
extern const char* MODULE_VIRTUAL_MACHINE_DEFAULT_VALUE;
extern const char* MODULE_UI_SYNTAX;
extern const char* MODULE_UI_SYNTAX_DEFAULT_VALUE;
extern const char* MODULE_PAGES;
extern const char* MODULE_ABILITIES;
extern const char* MODULE_EXTENSION_ABILITIES;
extern const char* MODULE_REQUEST_PERMISSIONS;
extern const char* MODULE_DEFINE_PERMISSIONS;
extern const char* MODULE_DEPENDENCIES;
extern const char* MODULE_COMPILE_MODE;
// module type
extern const char* MODULE_TYPE_ENTRY;
extern const char* MODULE_TYPE_FEATURE;
extern const char* MODULE_TYPE_HAR;
// deviceConfig
extern const char* MIN_API_VERSION;
extern const char* DEVICE_CONFIG_DISTRIBUTED_NOTIFICATION_ENABLED;
extern const char* DEVICE_CONFIG_KEEP_ALIVE;
extern const char* DEVICE_CONFIG_REMOVABLE;
extern const char* DEVICE_CONFIG_SINGLETON;
extern const char* DEVICE_CONFIG_USER_DATA_CLEARABLE;
extern const char* DEVICE_CONFIG_ACCESSIBLE;
// metadata
extern const char* META_DATA_NAME;
extern const char* META_DATA_VALUE;
extern const char* META_DATA_RESOURCE;
// metadata reserved
extern const char* META_DATA_FORM;
extern const char* META_DATA_SHORTCUTS;
extern const char* META_DATA_COMMON_EVENTS;
// ability
extern const char* ABILITY_NAME;
extern const char* ABILITY_LAUNCH_TYPE;
extern const char* ABILITY_LAUNCH_TYPE_DEFAULT_VALUE;
extern const char* ABILITY_BACKGROUNDMODES;
extern const char* ABILITY_CONTINUABLE;
extern const char* ABILITY_START_WINDOW_ICON;
extern const char* ABILITY_START_WINDOW_ICON_ID;
extern const char* ABILITY_START_WINDOW_BACKGROUND;
extern const char* ABILITY_START_WINDOW_BACKGROUND_ID;
extern const char* ABILITY_REMOVE_MISSION_AFTER_TERMINATE;
extern const char* ABILITY_ORIENTATION;
extern const char* ABILITY_SUPPORT_WINDOW_MODE;
extern const char* ABILITY_MAX_WINDOW_RATIO;
extern const char* ABILITY_MIN_WINDOW_RATIO;
extern const char* ABILITY_MAX_WINDOW_WIDTH;
extern const char* ABILITY_MIN_WINDOW_WIDTH;
extern const char* ABILITY_MAX_WINDOW_HEIGHT;
extern const char* ABILITY_MIN_WINDOW_HEIGHT;
extern const char* ABILITY_EXCLUDE_FROM_MISSIONS;
// extension ability
extern const char* EXTENSION_ABILITY_NAME;
extern const char* EXTENSION_ABILITY_TYPE;
extern const char* EXTENSION_URI;
extern const char* EXTENSION_ABILITY_READ_PERMISSION;
extern const char* EXTENSION_ABILITY_WRITE_PERMISSION;
// requestPermission
extern const char* REQUESTPERMISSION_NAME;
extern const char* REQUESTPERMISSION_REASON;
extern const char* REQUESTPERMISSION_REASON_ID;
extern const char* REQUESTPERMISSION_USEDSCENE;
extern const char* REQUESTPERMISSION_ABILITIES;
extern const char* REQUESTPERMISSION_WHEN;
// definePermission
extern const char* DEFINEPERMISSION_NAME;
extern const char* DEFINEPERMISSION_GRANT_MODE;
extern const char* DEFINEPERMISSION_AVAILABLE_LEVEL;
extern const char* DEFINEPERMISSION_PROVISION_ENABLE;
extern const char* DEFINEPERMISSION_DISTRIBUTED_SCENE_ENABLE;
extern const char* DEFINEPERMISSION_GRANT_MODE_SYSTEM_GRANT;
extern const char* DEFINEPERMISSION_AVAILABLE_LEVEL_DEFAULT_VALUE;
// apl
extern const char* AVAILABLELEVEL_NORMAL;
extern const char* AVAILABLELEVEL_SYSTEM_BASIC;
extern const char* AVAILABLELEVEL_SYSTEM_CORE;
// compile mode
extern const char* COMPILE_MODE_JS_BUNDLE;
extern const char* COMPILE_MODE_ES_MODULE;

extern thread_local int32_t parseResult;
}  // namespace Profile
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_COMMON_PROFILE_H