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
constexpr const char* EMPTY_STRING = "";
constexpr const char* FILE_UNDERLINE = "_";
constexpr const char* BUNDLE_CODE_DIR = "/data/app/el1/bundle/public";
constexpr const char* CACHE_DIR = "cache";
constexpr int8_t START_USERID = 100;
constexpr int8_t DEFAULT_USERID = 0;
constexpr int8_t INVALID_USERID = -1;
constexpr int8_t UNSPECIFIED_USERID = -2;
constexpr int8_t ALL_USERID = -3;
constexpr int8_t ANY_USERID = -4;
constexpr int8_t PERMISSION_GRANTED = 0;
constexpr int8_t PERMISSION_NOT_GRANTED = -1;
constexpr int8_t DEFAULT_STREAM_FD = -1;
constexpr int8_t DUMP_INDENT = 4;
constexpr int8_t INVALID_API_VERSION = -1;
constexpr int8_t ALL_VERSIONCODE = -1;
constexpr int8_t INVALID_UDID = -1;
constexpr int8_t DEFAULT_INSTALLERID = -1;
constexpr int8_t DEFAULT_APP_INDEX = 0;

// uid and gid
constexpr int32_t INVALID_UID = -1;
constexpr int32_t ROOT_UID = 0;
constexpr int32_t FOUNDATION_UID = 5523;
constexpr int32_t CODE_PROTECT_UID = 7666;
constexpr int32_t BASE_APP_UID = 10000;
constexpr int32_t BASE_USER_RANGE = 200000;
constexpr int32_t MAX_APP_UID = 65535;
constexpr int32_t STORAGE_MANAGER_UID = 1090;

// for render process
constexpr int32_t START_UID_FOR_RENDER_PROCESS = 1000000;
constexpr int32_t END_UID_FOR_RENDER_PROCESS = 1099999;

/*
all of cache path for bundle:
modulename max is 128
/data/app/el1~el5/userid/base/bundlename/cache;
/data/app/el2/userid/sharefiles/bundlename/cache;
/data/app/el1~el5/userid/base/bundlename/haps/modulename/cache;
/data/app/el2/userid/sharefiles/bundlename/haps/modulename/cache;
*/
constexpr int16_t MAX_CACHE_DIR_SIZE = 774;

// permissions
constexpr const char* PERMISSION_INSTALL_BUNDLE = "ohos.permission.INSTALL_BUNDLE";
constexpr const char* PERMISSION_UNINSTALL_CLONE_BUNDLE = "ohos.permission.UNINSTALL_CLONE_BUNDLE";
constexpr const char* PERMISSION_GET_BUNDLE_INFO = "ohos.permission.GET_BUNDLE_INFO";
constexpr const char* PERMISSION_GET_BUNDLE_INFO_PRIVILEGED = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* PERMISSION_CHANGE_ABILITY_ENABLED_STATE = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
constexpr const char* PERMISSION_REMOVECACHEFILE = "ohos.permission.REMOVE_CACHE_FILES";
constexpr const char* PERMISSION_GET_DEFAULT_APPLICATION = "ohos.permission.GET_DEFAULT_APPLICATION";
constexpr const char* PERMISSION_SET_DEFAULT_APPLICATION = "ohos.permission.SET_DEFAULT_APPLICATION";
constexpr const char* PERMISSION_GET_INSTALLED_BUNDLE_LIST = "ohos.permission.GET_INSTALLED_BUNDLE_LIST";
constexpr const char* PERMISSION_RUN_DYN_CODE = "ohos.permission.RUN_DYN_CODE";
constexpr const char* PERMISSION_ACCESS_DYNAMIC_ICON = "ohos.permission.ACCESS_DYNAMIC_ICON";
constexpr const char* PERMISSION_START_SHORTCUT = "ohos.permission.START_SHORTCUT";
constexpr const char* PERMISSION_INSTALL_CLONE_BUNDLE = "ohos.permission.INSTALL_CLONE_BUNDLE";
constexpr const char* PERMISSION_MANAGER_SHORTCUT = "ohos.permission.MANAGE_SHORTCUTS";
constexpr const char* PERMISSION_ACCESS_APP_INSTALL_DIR = "ohos.permission.ACCESS_APP_INSTALL_DIR";
constexpr const char* PERMISSION_GET_SIGNATURE_INFO = "ohos.permission.GET_SIGNATURE_INFO";
constexpr const char* PERMISSION_MIGRATE_DATA = "ohos.permission.MIGRATE_DATA";

enum class AppType {
    SYSTEM_APP = 0,
    THIRD_SYSTEM_APP,
    THIRD_PARTY_APP,
};

enum NoGetBundleStatsFlag : uint32_t {
    GET_BUNDLE_WITH_ALL_SIZE = 0x00000000,
    GET_BUNDLE_WITHOUT_INSTALL_SIZE = 0x00000001,
    GET_BUNDLE_WITHOUT_DATA_SIZE = 0x00000002,
    GET_BUNDLE_WITHOUT_CACHE_SIZE = 0x00000004,
};

constexpr const char* ACTION_HOME = "action.system.home";
constexpr const char* WANT_ACTION_HOME = "ohos.want.action.home";
constexpr const char* ENTITY_HOME = "entity.system.home";

constexpr uint8_t MAX_BUNDLE_NAME = 128;
constexpr uint8_t MIN_BUNDLE_NAME = 7;
constexpr uint8_t MAX_JSON_ELEMENT_LENGTH = 255;
constexpr uint16_t MAX_JSON_ARRAY_LENGTH = 1024;

constexpr uint16_t MAX_JSON_STRING_LENGTH = 4096;
constexpr const char* UID = "uid";
constexpr const char* USER_ID = "userId";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* HAP_PATH = "hapPath";
constexpr const char* APP_INDEX = "appIndex";
constexpr int8_t MAX_LIMIT_SIZE = 4;

constexpr const char* PARAM_URI_SEPARATOR = ":///";
constexpr uint8_t PARAM_URI_SEPARATOR_LEN = 4;
constexpr const char* URI_SEPARATOR = "://";

// ipc
constexpr int32_t CAPACITY_SIZE = 1 * 1024 * 1000; // 1M
constexpr int32_t MAX_PARCEL_CAPACITY = 100 * 1024 * 1024; // 100M

// permission
constexpr const char* LISTEN_BUNDLE_CHANGE = "ohos.permission.LISTEN_BUNDLE_CHANGE";

// sandbox application
constexpr const char* SANDBOX_APP_INDEX = "sandbox_app_index";
constexpr int16_t INITIAL_APP_INDEX = 0;
constexpr int16_t INITIAL_SANDBOX_APP_INDEX = 1000;
constexpr int16_t MAX_APP_INDEX = 100;
constexpr int16_t MAX_SANDBOX_APP_INDEX = INITIAL_SANDBOX_APP_INDEX + 100;

// app-distribution-type
constexpr const char* APP_DISTRIBUTION_TYPE_NONE = "none";
constexpr const char* APP_DISTRIBUTION_TYPE_APP_GALLERY = "app_gallery";
constexpr const char* APP_DISTRIBUTION_TYPE_ENTERPRISE = "enterprise";
constexpr const char* APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
constexpr const char* APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
constexpr const char* APP_DISTRIBUTION_TYPE_INTERNALTESTING = "internaltesting";
constexpr const char* APP_DISTRIBUTION_TYPE_OS_INTEGRATION = "os_integration";
constexpr const char* APP_DISTRIBUTION_TYPE_CROWDTESTING = "crowdtesting";
// app provision type
constexpr const char* APP_PROVISION_TYPE_DEBUG = "debug";
constexpr const char* APP_PROVISION_TYPE_RELEASE = "release";

// crowdtesting
constexpr int8_t INVALID_CROWDTEST_DEADLINE = -1;
constexpr int8_t INHERIT_CROWDTEST_DEADLINE = -2;

// overlay installation
constexpr const char* OVERLAY_STATE = "overlayState";
constexpr const char* PERMISSION_CHANGE_OVERLAY_ENABLED_STATE = "ohos.permission.CHANGE_OVERLAY_ENABLED_STATE";

constexpr const char* SCENE_BOARD_BUNDLE_NAME = "com.ohos.sceneboard";

// clone application
constexpr int32_t MAIN_APP_INDEX = 0;
constexpr int32_t CLONE_APP_INDEX_MAX = 5;

//param key-value
constexpr const char* VERIFY_UNINSTALL_RULE_KEY = "ohos.bms.param.verifyUninstallRule";
constexpr const char* VERIFY_UNINSTALL_RULE_VALUE = "true";

constexpr const char* SUPPORT_APP_TYPES_SEPARATOR = ",";
constexpr const char* APP_DISTRIBUTION_TYPE_WHITE_LIST = "appDistributionTypeWhiteList";
}  // namespace Constants
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_CONSTANTS_H