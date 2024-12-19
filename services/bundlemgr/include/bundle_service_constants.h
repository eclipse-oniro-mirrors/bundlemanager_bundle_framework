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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SERVICE_CONSTANTS_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SERVICE_CONSTANTS_H

#include <map>
#include <set>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
namespace ServiceConstants {
constexpr const char* ASSETS_DIR = "assets";
constexpr const char* RESOURCES_INDEX = "resources.index";
constexpr int8_t INVALID_GID = -1;
constexpr int8_t BUNDLE_RDB_VERSION = 1;
constexpr const char* PATH_SEPARATOR = "/";
constexpr const char* LIBS = "libs/";
constexpr const char* AN = "an/";
constexpr const char* RES_FILE_PATH = "resources/resfile/";
constexpr const char* HNPS_FILE_PATH = "hnp_tmp_extract_dir/";
constexpr const char* HNPS = "hnp/";
constexpr const char* DIR_EL1 = "el1";
constexpr const char* DIR_EL2 = "el2";
constexpr const char* DIR_EL3 = "el3";
constexpr const char* DIR_EL4 = "el4";
constexpr const char* DIR_EL5 = "el5";
const std::vector<std::string> BUNDLE_EL = {DIR_EL1, DIR_EL2, DIR_EL3, DIR_EL4};
const std::vector<std::string> FULL_BUNDLE_EL = {DIR_EL1, DIR_EL2, DIR_EL3, DIR_EL4, DIR_EL5};
constexpr const char* ARM_EABI = "armeabi";
constexpr const char* ARM_EABI_V7A = "armeabi-v7a";
constexpr const char* ARM64_V8A = "arm64-v8a";
constexpr const char* ARM64 = "arm64";
constexpr const char* X86 = "x86";
constexpr const char* X86_64 = "x86_64";
const std::map<std::string, std::string> ABI_MAP = {
    {ARM_EABI, "arm"},
    {ARM_EABI_V7A, "arm"},
    {ARM64_V8A, "arm64"},
    {X86, "x86"},
    {X86_64, "x86_64"},
};
constexpr const char* CLONE_BUNDLE_PREFIX = "clone_";
constexpr const char* UNINSTALL_TMP_PREFIX = "=uninstall_tmp_";
constexpr const char* INSTALL_FILE_SUFFIX = ".hap";
constexpr const char* HSP_FILE_SUFFIX = ".hsp";
constexpr const char* QUICK_FIX_FILE_SUFFIX = ".hqf";
const char FILE_SEPARATOR_CHAR = '/';
constexpr const char* CURRENT_DEVICE_ID = "PHONE-001";
constexpr const char* HAP_COPY_PATH = "/data/service/el1/public/bms/bundle_manager_service";
constexpr const char* TMP_SUFFIX = "_tmp";
constexpr const char* BUNDLE_APP_DATA_BASE_DIR = "/data/app/";
constexpr const char* BASE = "/base/";
constexpr const char* CLONE = "clone";
constexpr const char* PLUS_SIGN = "+";
constexpr const char* MINUS_SIGN = "-";
constexpr const char* DATABASE = "/database/";
constexpr const char* SHAREFILES = "/sharefiles/";
constexpr const char* LOG = "/log/";
constexpr const char* HAPS = "/haps/";
constexpr const char* EXTENSION_DIR = "+extension-";
constexpr const char* FILE_SEPARATOR_LINE = "-";
constexpr const char* FILE_SEPARATOR_PLUS = "+";
constexpr const char* BUNDLE_MANAGER_SERVICE_PATH = "/data/service/el1/public/bms/bundle_manager_service";
constexpr const char* SANDBOX_DATA_PATH = "/data/storage/el2/base";
constexpr const char* REAL_DATA_PATH = "/data/app/el2";
constexpr const char* DATA_GROUP_PATH = "/group/";
constexpr const char* STREAM_INSTALL_PATH = "stream_install";
constexpr const char* SECURITY_STREAM_INSTALL_PATH = "security_stream_install";
constexpr const char* QUICK_FIX_PATH = "quick_fix";
constexpr const char* SECURITY_QUICK_FIX_PATH = "security_quick_fix";
constexpr const char* BUNDLE_ASAN_LOG_DIR = "/data/local/app-logs";
constexpr const char* SCREEN_LOCK_FILE_DATA_PATH = "/data/app/el5";
constexpr const char* GALLERY_DOWNLOAD_PATH = "/app_install/";
constexpr int NOT_EXIST_USERID = -5;
constexpr int PATH_MAX_SIZE = 256;
constexpr int32_t API_VERSION_NINE = 9;
constexpr int32_t API_VERSION_TWELVE = 12;
constexpr int32_t API_VERSION_FIFTEEN = 15;
constexpr int32_t API_VERSION_MOD = 1000;
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
constexpr int32_t BMS_UID = 1000;
constexpr int32_t SHELL_UID = 2000;
constexpr int32_t BACKU_HOME_GID = 1089;
constexpr int32_t ACCOUNT_UID = 3058;
constexpr int32_t MODULE_UPDATE_UID = 6666;
constexpr int32_t BMS_GID = 1000;
constexpr int32_t DATABASE_DIR_GID = 3012;
constexpr int32_t DFS_GID = 1009;
constexpr int32_t LOG_DIR_GID = 1007;
constexpr int32_t APP_INSTALL_GID = 2002;
// permissions
constexpr const char* PERMISSION_INSTALL_ENTERPRISE_BUNDLE = "ohos.permission.INSTALL_ENTERPRISE_BUNDLE";
constexpr const char* PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE = "ohos.permission.INSTALL_ENTERPRISE_NORMAL_BUNDLE";
constexpr const char* PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE = "ohos.permission.INSTALL_ENTERPRISE_MDM_BUNDLE";
constexpr const char* PERMISSION_INSTALL_INTERNALTESTING_BUNDLE = "ohos.permission.INSTALL_INTERNALTESTING_BUNDLE";
constexpr const char* PERMISSION_MANAGE_DISPOSED_APP_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
constexpr const char* PERMISSION_INSTALL_SELF_BUNDLE = "ohos.permission.INSTALL_SELF_BUNDLE";
constexpr const char* PERMISSION_UNINSTALL_BUNDLE = "ohos.permission.UNINSTALL_BUNDLE";
constexpr const char* PERMISSION_RECOVER_BUNDLE = "ohos.permission.RECOVER_BUNDLE";
constexpr const char* PERMISSION_GET_BUNDLE_RESOURCES = "ohos.permission.GET_BUNDLE_RESOURCES";
constexpr const char* PERMISSION_INSTALL_SANDBOX_BUNDLE = "ohos.permission.INSTALL_SANDBOX_BUNDLE";
constexpr const char* PERMISSION_UNINSTALL_SANDBOX_BUNDLE = "ohos.permission.UNINSTALL_SANDBOX_BUNDLE";
constexpr const char* PERMISSION_INSTALL_QUICK_FIX_BUNDLE = "ohos.permission.INSTALL_QUICK_FIX_BUNDLE";
constexpr const char* PERMISSION_UNINSTALL_QUICK_FIX_BUNDLE = "ohos.permission.UNINSTALL_QUICK_FIX_BUNDLE";
constexpr const char* PERMISSION_CHANGE_BUNDLE_UNINSTALL_STATE = "ohos.permission.CHANGE_BUNDLE_UNINSTALL_STATE";
constexpr const char* PERMISSION_PROTECT_SCREEN_LOCK_DATA = "ohos.permission.PROTECT_SCREEN_LOCK_DATA";

constexpr const char* FLAG_HOME_INTENT_FROM_SYSTEM = "flag.home.intent.from.system";
// max number of haps under one direction
constexpr uint8_t MAX_HAP_NUMBER = 128;
constexpr const char* DATA_ABILITY_URI_PREFIX = "dataability://";
// appFeature
constexpr const char* HOS_SYSTEM_APP = "hos_system_app";
// rdb
constexpr const char* BUNDLE_RDB_NAME = "/bmsdb.db";
// thread pool
constexpr const char* RELATIVE_PATH = "../";
// app detail ability
constexpr const char* APP_DETAIL_ABILITY = "AppDetailAbility";
// overlay installation
constexpr int32_t DEFAULT_OVERLAY_ENABLE_STATUS = 1;
constexpr int32_t DEFAULT_OVERLAY_DISABLE_STATUS = 0;
constexpr int32_t OVERLAY_MINIMUM_PRIORITY = 1;
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
constexpr const char* BMS_DATA_PRELOAD = "persist.bms.data.preload";
//extResource
constexpr const char* EXT_RESOURCE_FILE_PATH = "ext_resource";
// hmdfs and sharefs config
constexpr const char* HMDFS_CONFIG_PATH = "/config/hmdfs/";
constexpr const char* SHAREFS_CONFIG_PATH = "/config/sharefs/";
constexpr const char* SYSTEM_SERVICE_DIR = "/data/service/el1/public";
constexpr const char* SYSTEM_UI_BUNDLE_NAME = "com.ohos.systemui";
constexpr const char* LAUNCHER_BUNDLE_NAME = "com.ohos.launcher";
// clone application
constexpr int32_t CLONE_APP_INDEX_MIN = 1;
constexpr int32_t CLONE_APP_INDEX_MAX = 5;
constexpr const char* CLONE_PREFIX = "+clone-";
// shader
constexpr const char* SHADER_CACHE_PATH = "/data/local/shader_cache/local/";
constexpr const char* CLOUD_SHADER_PATH = "/data/local/shader_cache/cloud/";
constexpr const char* CLOUD_SHADER_COMMON_PATH = "/data/local/shader_cache/cloud/common";
constexpr const char* CLOUD_SHADER_OWNER = "const.appgallery.shaderowner.bundlename";
// apiReleaseType
constexpr const char* API_RELEASE_TYPE_RELEASE = "Release";
constexpr const char* API_RELEASE_TYPE_BETA = "Beta";
constexpr const char* API_RELEASE_TYPE_CANARY = "Canary";
// allow multi icon bundle
const std::set<std::string> ALLOW_MULTI_ICON_BUNDLE = {
    "com.ohos.contacts"
};
constexpr const char* CALLER_NAME_BMS = "bms";
// allow singleton change
const std::set<std::string> SINGLETON_WHITE_LIST = {
    "com.ohos.formrenderservice",
    "com.ohos.sceneboard",
    "com.ohos.callui",
    "com.ohos.mms",
    "com.ohos.FusionSearch"
};
// group
constexpr int16_t DATA_GROUP_DIR_MODE = 02770;
}  // namespace ServiceConstants
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SERVICE_CONSTANTS_H