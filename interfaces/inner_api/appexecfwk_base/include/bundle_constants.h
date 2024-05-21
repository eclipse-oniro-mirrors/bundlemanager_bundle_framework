/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_CONSTANTS_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_CONSTANTS_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
namespace Constants {
constexpr const char* TYPE_ONLY_MATCH_WILDCARD = "reserved/wildcard";
const std::string EMPTY_STRING = "";
constexpr const char* FILE_UNDERLINE = "_";
constexpr const char* BUNDLE_CODE_DIR = "/data/app/el1/bundle/public";
constexpr const char* SCREEN_LOCK_FILE_DATA_PATH = "/data/app/el5";
constexpr const char* CACHE_DIR = "cache";
constexpr int START_USERID = 100;
constexpr int DEFAULT_USERID = 0;
constexpr int INVALID_USERID = -1;
constexpr int UNSPECIFIED_USERID = -2;
constexpr int ALL_USERID = -3;
constexpr int ANY_USERID = -4;
constexpr int NOT_EXIST_USERID = -5;
constexpr int PATH_MAX_SIZE = 256;
constexpr int PERMISSION_GRANTED = 0;
constexpr int PERMISSION_NOT_GRANTED = -1;
constexpr int DEFAULT_STREAM_FD = -1;
constexpr int DUMP_INDENT = 4;
constexpr int32_t INVALID_API_VERSION = -1;
constexpr int32_t API_VERSION_NINE = 9;
constexpr int32_t ALL_VERSIONCODE = -1;
constexpr int32_t INVALID_UDID = -1;
constexpr int32_t DEFAULT_INSTALLERID = -1;
constexpr int32_t BACKUP_DEFAULT_APP_KEY = -2;

// native so
constexpr const char* ABI_DEFAULT = "default";
constexpr const char* ABI_SEPARATOR = ",";
constexpr const char* MODULE_NAME_SEPARATOR = ",";
constexpr const char* AN_SUFFIX = ".an";
constexpr const char* AP_SUFFIX = ".ap";
constexpr const char* SYSTEM_LIB64 = "/system/lib64";
constexpr const char* PATCH_PATH = "patch_";
constexpr const char* HOT_RELOAD_PATH = "hotreload_";

// uid and gid
constexpr int32_t INVALID_UID = -1;
constexpr int32_t ROOT_UID = 0;
constexpr int32_t BMS_UID = 1000;
constexpr int32_t SHELL_UID = 2000;
constexpr int32_t BACKU_HOME_GID = 1089;
constexpr int32_t ACCOUNT_UID = 3058;
constexpr int32_t FOUNDATION_UID = 5523;
constexpr int32_t BMS_GID = 1000;
constexpr int32_t BASE_APP_UID = 10000;
constexpr int32_t BASE_USER_RANGE = 200000;
constexpr int32_t MAX_APP_UID = 65535;
constexpr int32_t DATABASE_DIR_GID = 3012;
constexpr int32_t DFS_GID = 1009;
constexpr int32_t LOG_DIR_GID = 1007;

// for render process
constexpr int32_t START_UID_FOR_RENDER_PROCESS = 1000000;
constexpr int32_t END_UID_FOR_RENDER_PROCESS = 1099999;

// permissions
constexpr const char* PERMISSION_INSTALL_BUNDLE = "ohos.permission.INSTALL_BUNDLE";
constexpr const char* PERMISSION_INSTALL_ENTERPRISE_BUNDLE = "ohos.permission.INSTALL_ENTERPRISE_BUNDLE";
constexpr const char* PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE = "ohos.permission.INSTALL_ENTERPRISE_NORMAL_BUNDLE";
constexpr const char* PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE = "ohos.permission.INSTALL_ENTERPRISE_MDM_BUNDLE";
constexpr const char* PERMISSION_UNINSTALL_CLONE_BUNDLE = "ohos.permission.UNINSTALL_CLONE_BUNDLE";
constexpr const char* PERMISSION_GET_BUNDLE_INFO = "ohos.permission.GET_BUNDLE_INFO";
constexpr const char* PERMISSION_GET_BUNDLE_INFO_PRIVILEGED = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* PERMISSION_CHANGE_ABILITY_ENABLED_STATE = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
constexpr const char* PERMISSION_REMOVECACHEFILE = "ohos.permission.REMOVE_CACHE_FILES";
constexpr const char* PERMISSION_MANAGE_DISPOSED_APP_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
constexpr const char* PERMISSION_GET_DEFAULT_APPLICATION = "ohos.permission.GET_DEFAULT_APPLICATION";
constexpr const char* PERMISSION_SET_DEFAULT_APPLICATION = "ohos.permission.SET_DEFAULT_APPLICATION";
constexpr const char* PERMISSION_GET_INSTALLED_BUNDLE_LIST = "ohos.permission.GET_INSTALLED_BUNDLE_LIST";
constexpr const char* PERMISSION_INSTALL_SELF_BUNDLE = "ohos.permission.INSTALL_SELF_BUNDLE";
constexpr const char* PERMISSION_UNINSTALL_BUNDLE = "ohos.permission.UNINSTALL_BUNDLE";
constexpr const char* PERMISSION_RECOVER_BUNDLE = "ohos.permission.RECOVER_BUNDLE";
constexpr const char* PERMISSION_GET_BUNDLE_RESOURCES = "ohos.permission.GET_BUNDLE_RESOURCES";
constexpr const char* PERMISSION_RUN_DYN_CODE = "ohos.permission.RUN_DYN_CODE";
constexpr const char* PERMISSION_ACCESS_DYNAMIC_ICON = "ohos.permission.ACCESS_DYNAMIC_ICON";
constexpr const char* PERMISSION_INSTALL_SANDBOX_BUNDLE = "ohos.permission.INSTALL_SANDBOX_BUNDLE";
constexpr const char* PERMISSION_UNINSTALL_SANDBOX_BUNDLE = "ohos.permission.UNINSTALL_SANDBOX_BUNDLE";
constexpr const char* PERMISSION_INSTALL_QUICK_FIX_BUNDLE = "ohos.permission.INSTALL_QUICK_FIX_BUNDLE";
constexpr const char* PERMISSION_UNINSTALL_QUICK_FIX_BUNDLE = "ohos.permission.UNINSTALL_QUICK_FIX_BUNDLE";
constexpr const char* PERMISSION_CHANGE_BUNDLE_UNINSTALL_STATE = "ohos.permission.CHANGE_BUNDLE_UNINSTALL_STATE";
constexpr const char* PERMISSION_START_SHORTCUT = "ohos.permission.START_SHORTCUT";
constexpr const char* PERMISSION_INSTALL_CLONE_BUNDLE = "ohos.permission.INSTALL_CLONE_BUNDLE";

enum class AppType {
    SYSTEM_APP = 0,
    THIRD_SYSTEM_APP,
    THIRD_PARTY_APP,
};

constexpr const char* ACTION_HOME = "action.system.home";
constexpr const char* WANT_ACTION_HOME = "ohos.want.action.home";
constexpr const char* ENTITY_HOME = "entity.system.home";
constexpr const char* FLAG_HOME_INTENT_FROM_SYSTEM = "flag.home.intent.from.system";

constexpr uint8_t MAX_BUNDLE_NAME = 128;
constexpr uint8_t MIN_BUNDLE_NAME = 7;
constexpr uint8_t MAX_JSON_ELEMENT_LENGTH = 255;
constexpr uint16_t MAX_JSON_ARRAY_LENGTH = 512;

// max number of haps under one direction
constexpr uint8_t MAX_HAP_NUMBER = 128;

constexpr uint16_t MAX_JSON_STRING_LENGTH = 4096;
constexpr const char* UID = "uid";
constexpr const char* USER_ID = "userId";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* HAP_PATH = "hapPath";
constexpr int32_t MAX_LIMIT_SIZE = 4;

constexpr const char* DATA_ABILITY_URI_PREFIX = "dataability://";
constexpr const char* PARAM_URI_SEPARATOR = ":///";
constexpr uint32_t PARAM_URI_SEPARATOR_LEN = 4;
constexpr const char* URI_SEPARATOR = "://";

// appFeature
constexpr const char* HOS_SYSTEM_APP = "hos_system_app";

// rdb
constexpr const char* BUNDLE_RDB_NAME = "/bmsdb.db";

// ipc
constexpr int32_t CAPACITY_SIZE = 1 * 1024 * 1000; // 1M
constexpr int32_t MAX_PARCEL_CAPACITY = 100 * 1024 * 1024; // 100M

// permission
constexpr const char* LISTEN_BUNDLE_CHANGE = "ohos.permission.LISTEN_BUNDLE_CHANGE";

// sandbox application
constexpr const char* SANDBOX_APP_INDEX = "sandbox_app_index";
constexpr int32_t INITIAL_APP_INDEX = 0;
constexpr int32_t INITIAL_SANDBOX_APP_INDEX = 1000;
constexpr int32_t MAX_APP_INDEX = 100;
constexpr int32_t MAX_SANDBOX_APP_INDEX = INITIAL_SANDBOX_APP_INDEX + 100;

// app-distribution-type
constexpr const char* APP_DISTRIBUTION_TYPE_NONE = "none";
constexpr const char* APP_DISTRIBUTION_TYPE_APP_GALLERY = "app_gallery";
constexpr const char* APP_DISTRIBUTION_TYPE_ENTERPRISE = "enterprise";
constexpr const char* APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
constexpr const char* APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
constexpr const char* APP_DISTRIBUTION_TYPE_OS_INTEGRATION = "os_integration";
constexpr const char* APP_DISTRIBUTION_TYPE_CROWDTESTING = "crowdtesting";
// app provision type
constexpr const char* APP_PROVISION_TYPE_DEBUG = "debug";
constexpr const char* APP_PROVISION_TYPE_RELEASE = "release";

// crowdtesting
constexpr int64_t INVALID_CROWDTEST_DEADLINE = -1;
constexpr int64_t INHERIT_CROWDTEST_DEADLINE = -2;

// thread pool
constexpr const char* RELATIVE_PATH = "../";

// app detail ability
constexpr const char* APP_DETAIL_ABILITY = "AppDetailAbility";

// overlay installation
constexpr int32_t DEFAULT_OVERLAY_ENABLE_STATUS = 1;
constexpr int32_t DEFAULT_OVERLAY_DISABLE_STATUS = 0;
constexpr int32_t OVERLAY_MINIMUM_PRIORITY = 1;
constexpr const char* OVERLAY_STATE = "overlayState";
constexpr const char* PERMISSION_CHANGE_OVERLAY_ENABLED_STATE = "ohos.permission.CHANGE_OVERLAY_ENABLED_STATE";

// ark compile mode
constexpr const char* COMPILE_PARTIAL = "partial";

constexpr const char* ARK_CACHE_PATH = "/data/local/ark-cache/";
constexpr const char* ARK_PROFILE_PATH = "/data/local/ark-profile/";

// code signature
constexpr const char* CODE_SIGNATURE_FILE_SUFFIX = ".sig";
constexpr const char* CODE_SIGNATURE_HAP = "Hap";
constexpr const char* SIGNATURE_FILE_PATH = "signature_files";
constexpr const char* SECURITY_SIGNATURE_FILE_PATH = "security_signature_files";

//pgo file
constexpr const char* PGO_FILE_SUFFIX = ".ap";

// system param
constexpr const char* ALLOW_ENTERPRISE_BUNDLE = "const.bms.allowenterprisebundle";
constexpr const char* IS_ENTERPRISE_DEVICE = "const.edm.is_enterprise_device";
constexpr const char* DEVELOPERMODE_STATE = "const.security.developermode.state";

//extResource
constexpr const char* EXT_RESOURCE_FILE_PATH = "ext_resource";

// hmdfs and sharefs config
constexpr const char* HMDFS_CONFIG_PATH = "/config/hmdfs/";
constexpr const char* SHAREFS_CONFIG_PATH = "/config/sharefs/";
constexpr const char* SYSTEM_SERVICE_DIR = "/data/service/el1/public";

constexpr const char* SYSTEM_UI_BUNDLE_NAME = "com.ohos.systemui";
constexpr const char* LAUNCHER_BUNDLE_NAME = "com.ohos.launcher";
constexpr const char* SCENE_BOARD_BUNDLE_NAME = "com.ohos.sceneboard";

// clone application
constexpr int32_t CLONE_APP_INDEX_MIN = 1;
constexpr int32_t CLONE_APP_INDEX_MAX = 5;

constexpr const char* SHADER_CACHE_PATH = "/data/local/shader_cache/local/";
constexpr const char* CLOUD_SHADER_PATH = "/data/local/shader_cache/cloud/";
constexpr const char* CLOUD_SHADER_OWNER = "const.appgallery.shaderowner.bundlename";
}  // namespace Constants
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_CONSTANTS_H