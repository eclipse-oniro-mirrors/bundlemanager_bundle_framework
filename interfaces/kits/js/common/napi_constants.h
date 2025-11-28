/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#ifndef NAPI_CONSTANTS_H
#define NAPI_CONSTANTS_H

#include <map>
#include <set>

#include "bundle_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t ARGS_SIZE_ZERO = 0;
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr size_t ARGS_SIZE_FOUR = 4;
constexpr size_t ARGS_SIZE_FIVE = 5;

constexpr size_t ARGS_POS_ZERO = 0;
constexpr size_t ARGS_POS_ONE = 1;
constexpr size_t ARGS_POS_TWO = 2;
constexpr size_t ARGS_POS_THREE = 3;
constexpr size_t ARGS_POS_FOUR = 4;

constexpr size_t NAPI_RETURN_ONE = 1;
constexpr size_t CALLBACK_PARAM_SIZE = 2;

constexpr int32_t SPECIFIED_DISTRIBUTION_TYPE_MAX_SIZE = 128;
constexpr int32_t ADDITIONAL_INFO_MAX_SIZE = 3000;
constexpr uint32_t EXPLICIT_QUERY_RESULT_LEN = 1;
constexpr int32_t EMPTY_USER_ID = -500;

constexpr int32_t ENUM_ONE = 1;
constexpr int32_t ENUM_TWO = 2;
constexpr int32_t ENUM_THREE = 3;
constexpr int32_t ENUM_FOUR = 4;
constexpr int32_t ENUM_FIVE = 5;
constexpr int32_t ENUM_SIX = 6;
constexpr int32_t ENUM_SEVEN = 7;

constexpr const char* TYPE_NUMBER = "number";
constexpr const char* TYPE_STRING = "string";
constexpr const char* TYPE_OBJECT = "object";
constexpr const char* TYPE_BOOLEAN = "boolean";
constexpr const char* TYPE_FUNCTION = "function";
constexpr const char* TYPE_ARRAY = "array";

constexpr const char* UID = "uid";
constexpr const char* USER_ID = "userId";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* PARAM_TYPE_CHECK_ERROR = "param type check error";

// bundle_manager
constexpr const char* BUNDLE_FLAGS = "bundleFlags";
constexpr const char* APP_FLAGS = "appFlags";
constexpr const char* ERR_MSG_BUNDLE_SERVICE_EXCEPTION = "Bundle manager service is excepted.";
constexpr const char* IS_APPLICATION_ENABLED_SYNC = "IsApplicationEnabledSync";
constexpr const char* GET_BUNDLE_INFO_FOR_SELF_SYNC = "GetBundleInfoForSelfSync";
constexpr const char* GET_BUNDLE_INFO_SYNC = "GetBundleInfoSync";
constexpr const char* GET_APPLICATION_INFO_SYNC = "GetApplicationInfoSync";
constexpr const char* BUNDLE_PERMISSIONS =
    "ohos.permission.GET_BUNDLE_INFO or ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* GET_BUNDLE_INFO = "GetBundleInfo";
constexpr const char* GET_APPLICATION_INFO = "GetApplicationInfo";
constexpr const char* FLAGS = "flags";
constexpr const char* ABILITY_FLAGS = "abilityFlags";
constexpr const char* ABILITY_INFO = "abilityInfo";
constexpr const char* LINK_FEATURE = "linkFeature";
constexpr const char* EXTENSION_TYPE_NAME = "extensionTypeName";
constexpr const char* EXTENSION_ABILITY_TYPE = "extensionAbilityType";
constexpr const char* PARAM_EXTENSION_ABILITY_TYPE_EMPTY_ERROR =
    "BusinessError 401: Parameter error.Parameter extensionAbilityType is empty.";
constexpr const char* INVALID_WANT_ERROR =
    "implicit query condition, at least one query param(action, entities, uri, type, or linkFeature) non-empty.";
constexpr const char* APP_CLONE_IDENTITY_PERMISSIONS = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* GET_BUNDLE_INFOS = "GetBundleInfos";
constexpr const char* GET_APPLICATION_INFOS = "GetApplicationInfos";
constexpr const char* IS_APPLICATION_ENABLED = "IsApplicationEnabled";
constexpr const char* QUERY_ABILITY_INFOS_SYNC = "QueryAbilityInfosSync";
constexpr const char* GET_APP_CLONE_IDENTITY = "getAppCloneIdentity";
constexpr const char* GET_ABILITY_LABEL = "GetAbilityLabel";
constexpr const char* QUERY_EXTENSION_INFOS_SYNC = "QueryExtensionInfosSync";
constexpr const char* GET_LAUNCH_WANT_FOR_BUNDLE_SYNC = "GetLaunchWantForBundleSync";
constexpr const char* IS_ABILITY_ENABLED_SYNC = "IsAbilityEnabledSync";
constexpr const char* SET_ABILITY_ENABLED_SYNC = "SetAbilityEnabledSync";
constexpr const char* SET_APPLICATION_ENABLED_SYNC = "SetApplicationEnabledSync";
constexpr const char* SET_ABILITY_FILE_TYPES_FOR_SELF_STRING = "setAbilityFileTypesForSelf";
constexpr const char* GET_APP_CLONE_BUNDLE_INFO = "GetAppCloneBundleInfo";
constexpr const char* GET_DYNAMIC_ICON = "GetDynamicIcon";
constexpr const char* RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE = "GetSpecifiedDistributionType";
constexpr const char* BATCH_QUERY_ABILITY_INFOS = "BatchQueryAbilityInfos";
constexpr const char* GET_BUNDLE_NAME_BY_UID = "GetBundleNameByUid";
constexpr const char* ENABLE_DYNAMIC_ICON = "EnableDynamicIcon";
constexpr const char* QUERY_ABILITY_INFOS = "QueryAbilityInfos";
constexpr const char* GET_ABILITY_LABEL_SYNC = "GetAbilityLabelSync";
constexpr const char* GET_LAUNCH_WANT_FOR_BUNDLE = "GetLaunchWantForBundle";
constexpr const char* GET_BUNDLE_NAME_BY_UID_SYNC = "GetBundleNameByUidSync";
constexpr const char* QUERY_EXTENSION_INFOS = "QueryExtensionInfos";
constexpr const char* SET_ABILITY_ENABLED = "SetAbilityEnabled";
constexpr const char* SET_APPLICATION_ENABLED = "SetApplicationEnabled";
constexpr const char* HAP_FILE_PATH = "hapFilePath";
constexpr const char* PERMISSION_NAME = "permissionName";
constexpr const char* PROFILE_TYPE = "profileType";
constexpr const char* ADDITIONAL_INFO = "additionalInfo";
constexpr const char* DEVELOPER_ID = "developerId";
constexpr const char* APP_DISTRIBUTION_TYPE = "appDistributionType";
constexpr const char* APP_DISTRIBUTION_TYPE_ENUM = "AppDistributionType";
constexpr const char* HOST_BUNDLE_NAME = "hostBundleName";
constexpr const char* SOURCE_PATHS = "sourcePaths";
constexpr const char* DESTINATION_PATH = "destinationPath";
constexpr const char* LINK = "link";
constexpr const char* URI = "uri";
constexpr const char* FILE_TYPES = "fileTypes";
constexpr const char* SANDBOX_DATA_DIR = "sandboxDataDir";
constexpr const char* ERR_MSG_LAUNCH_WANT_INVALID = "The launch want is not found.";
constexpr const char* PARAM_BUNDLENAME_EMPTY_ERROR =
    "BusinessError 401: Parameter error. parameter bundleName is empty";
constexpr const char* PARAM_MODULENAME_EMPTY_ERROR =
    "BusinessError 401: Parameter error. parameter moduleName is empty";
constexpr const char* PARAM_ABILITYNAME_EMPTY_ERROR =
    "BusinessError 401: Parameter error. parameter abilityName is empty";
constexpr const char* GET_SIGNATURE_INFO_PERMISSIONS = "ohos.permission.GET_SIGNATURE_INFO";
constexpr const char* PARAM_DEVELOPER_ID_EMPTY_ERROR =
    "BusinessError 401: Parameter error. parameter developerId is empty";
constexpr const char* BUNDLE_ENABLE_AND_DISABLE_ALL_DYNAMIC_PERMISSIONS =
    "ohos.permission.ACCESS_DYNAMIC_ICON and ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
constexpr const char* BUNDLE_GET_ALL_DYNAMIC_PERMISSIONS =
    "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED and ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
constexpr const char* GET_ABILITYINFO_PERMISSIONS = "ohos.permission.GET_ABILITY_INFO";
constexpr const char* GET_BUNDLE_ARCHIVE_INFO = "GetBundleArchiveInfo";
constexpr const char* GET_PERMISSION_DEF = "GetPermissionDef";
constexpr const char* CLEAN_BUNDLE_CACHE_FILES = "cleanBundleCacheFiles";
constexpr const char* CLEAN_BUNDLE_CACHE_FILES_FOR_SELF = "CleanBundleCacheFilesForSelf";
constexpr const char* GET_ALL_BUNDLE_CACHE_SIZE = "getAllBundleCacheSize";
constexpr const char* CLEAN_ALL_BUNDLE_CACHE = "cleanAllBundleCache";
constexpr const char* GET_APP_PROVISION_INFO = "GetAppProvisionInfo";
constexpr const char* GET_ALL_APP_PROVISION_INFO = "GetAllAppProvisionInfo";
constexpr const char* CAN_OPEN_LINK = "CanOpenLink";
constexpr const char* GET_ALL_PREINSTALLED_APP_INFOS = "GetAllPreinstalledApplicationInfos";
constexpr const char* GET_ALL_BUNDLE_INFO_BY_DEVELOPER_ID = "GetAllBundleInfoByDeveloperId";
constexpr const char* SWITCH_UNINSTALL_STATE = "SwitchUninstallState";
constexpr const char* GET_SIGNATURE_INFO = "GetSignatureInfo";
constexpr const char* GET_ALL_APP_CLONE_BUNDLE_INFO = "GetAllAppCloneBundleInfo";
constexpr const char* GET_BUNDLE_ARCHIVE_INFO_SYNC = "GetBundleArchiveInfoSync";
constexpr const char* GET_PROFILE_BY_EXTENSION_ABILITY_SYNC = "GetProfileByExtensionAbilitySync";
constexpr const char* GET_PROFILE_BY_ABILITY_SYNC = "GetProfileByAbilitySync";
constexpr const char* GET_PERMISSION_DEF_SYNC = "GetPermissionDefSync";
constexpr const char* GET_APP_PROVISION_INFO_SYNC = "GetAppProvisionInfoSync";
constexpr const char* GET_ALL_SHARED_BUNDLE_INFO = "GetAllSharedBundleInfo";
constexpr const char* GET_SHARED_BUNDLE_INFO = "GetSharedBundleInfo";
constexpr const char* GET_JSON_PROFILE = "GetJsonProfile";
constexpr const char* RESOURCE_NAME_OF_GET_ADDITIONAL_INFO = "GetAdditionalInfo";
constexpr const char* GET_EXT_RESOURCE = "GetExtResource";
constexpr const char* DISABLE_DYNAMIC_ICON = "DisableDynamicIcon";
constexpr const char* VERIFY_ABC = "VerifyAbc";
constexpr const char* DELETE_ABC = "DeleteAbc";
constexpr const char* GET_RECOVERABLE_APPLICATION_INFO = "GetRecoverableApplicationInfo";
constexpr const char* RESOURCE_NAME_OF_SET_ADDITIONAL_INFO = "SetAdditionalInfo";
constexpr const char* GET_DEVELOPER_IDS = "GetDeveloperIds";
constexpr const char* GET_ALL_PLUGIN_INFO = "GetAllPluginInfo";
constexpr const char* MIGRATE_DATA = "MigrateData";
constexpr const char* GET_ALL_DYNAMIC_ICON = "GetAllDynamicIconInfo";
constexpr const char* GET_SANDBOX_DATA_DIR_SYNC = "GetSandboxDataDirSync";
constexpr const char* GET_ABILITY_INFOS = "GetAbilityInfos";
constexpr const char* GET_DYNAMIC_ICON_INFO = "GetDynamicIconInfo";
constexpr const char* GET_PLUGIN_BUNDLE_PATH_FOR_SELF = "GetPluginBundlePathForSelf";
constexpr const char* RECOVER_BACKUP_BUNDLE_DATA = "RecoverBackupBundleData";
constexpr const char* REMOVE_BACKUP_BUNDLE_DATA = "RemoveBackupBundleData";
constexpr const char* GET_BUNDLE_INSTALL_STATUS = "GetBundleInstallStatus";

inline const std::set<int32_t> SUPPORTED_PROFILE_LIST = { 1 };
inline const std::set<int32_t> UNINSTALL_COMPONENT_TYPE_LIST = { 1, 2 };

inline std::map<int32_t, std::string> APP_DISTRIBUTION_TYPE_MAP = {
    { ENUM_ONE, Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY },
    { ENUM_TWO, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE },
    { ENUM_THREE, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL },
    { ENUM_FOUR, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM },
    { ENUM_FIVE, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION },
    { ENUM_SIX, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING },
    { ENUM_SEVEN, Constants::APP_DISTRIBUTION_TYPE_NONE },
};

// launcher_bundle_manager
constexpr const char* GET_SHORTCUT_INFO = "GetShortcutInfo";
constexpr const char* GET_SHORTCUT_INFO_SYNC = "GetShortcutInfoSync";
constexpr const char* GET_SHORTCUT_INFO_BY_APPINDEX = "GetShortcutInfoByAppIndex";
constexpr const char* ERROR_EMPTY_WANT = "want in ShortcutInfo cannot be empty";
constexpr const char* PARSE_SHORTCUT_INFO_FAILED = "parse ShortcutInfo failed";
constexpr const char* PARSE_START_OPTIONS_FAILED = "parse StartOptions failed";
constexpr const char* START_SHORTCUT = "StartShortcut";
constexpr const char* GET_LAUNCHER_ABILITY_INFO = "GetLauncherAbilityInfo";
constexpr const char* GET_LAUNCHER_ABILITY_INFO_SYNC = "GetLauncherAbilityInfoSync";
constexpr const char* GET_ALL_LAUNCHER_ABILITY_INFO = "GetAllLauncherAbilityInfo";
constexpr const char* PARSE_REASON_MESSAGE = "parse ReasonMessage failed";
constexpr const char* START_SHORTCUT_WITH_REASON = "StartShortcutWithReason";

// resource_manager
constexpr const char* PERMISSION_GET_BUNDLE_RESOURCES = "ohos.permission.GET_BUNDLE_RESOURCES";
constexpr const char* GET_BUNDLE_RESOURCE_INFO = "GetBundleResourceInfo";
constexpr const char* RESOURCE_FLAGS = "resourceFlags";
constexpr const char* PERMISSION_GET_ALL_BUNDLE_RESOURCES =
    "ohos.permission.GET_INSTALLED_BUNDLE_LIST and ohos.permission.GET_BUNDLE_RESOURCES";
constexpr const char* GET_LAUNCHER_ABILITY_RESOURCE_INFO = "GetLauncherAbilityResourceInfo";
constexpr const char* GET_ALL_BUNDLE_RESOURCE_INFO = "GetAllBundleResourceInfo";
constexpr const char* GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO = "GetAllLauncherAbilityResourceInfo";
constexpr const char* GET_EXTENSION_ABILITY_RESOURCE_INFO = "GetExtensionAbilityResourceInfo";
constexpr const char* GET_ALL_UNINSTALL_BUNDLE_RESOURCE_INFO = "GetAllUninstalledBundleResourceInfo";

// shortcut_manager
constexpr const char* ADD_DESKTOP_SHORTCUT_INFO = "AddDesktopShortcutInfo";
constexpr const char* DELETE_DESKTOP_SHORTCUT_INFO = "DeleteDesktopShortcutInfo";
constexpr const char* GET_ALL_DESKTOP_SHORTCUT_INFO = "GetAllDesktopShortcutInfo";
constexpr const char* SET_SHORTCUT_VISIBLE = "SetShortcutVisibleForSelf";
constexpr const char* GET_ALL_SHORTCUT_INFO_FOR_SELF = "GetAllShortcutInfoForSelf";
constexpr const char* SHORTCUT_ID = "shortcutId";
constexpr const char* INVALID_SHORTCUT_INFO_ERROR =
    "invalid ShortcutInfo: parameter type error, or appIndex is less than 0";

// free_install
constexpr const char* RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE = "isHapModuleRemovable";
constexpr const char* RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG = "setHapModuleUpgradeFlag";
constexpr const char* RESOURCE_NAME_OF_GET_BUNDLE_PACK_INFO = "getBundlePackInfo";
constexpr const char* RESOURCE_NAME_OF_GET_DISPATCH_INFO = "getDispatchInfo";
constexpr const char* DISPATCH_INFO_VERSION = "1";
constexpr const char* DISPATCH_INFO_DISPATCH_API = "1.0";
constexpr const char* UPGRADE_FLAG = "upgradeFlag";
constexpr const char* BUNDLE_PACK_FLAG = "bundlePackFlag";

// overlay
constexpr const char* TARGET_MODULE_NAME = "targetModuleName";
constexpr const char* TARGET_BUNDLE_NAME = "targetBundleName";
constexpr const char* IS_ENABLED = "isEnabled";
constexpr const char* SET_OVERLAY_ENABLED = "SetOverlayEnabled";
constexpr const char* SET_OVERLAY_ENABLED_BY_BUNDLE_NAME = "SetOverlayEnabledByBundleName";
constexpr const char* GET_OVERLAY_MODULE_INFO = "GetOverlayModuleInfo";
constexpr const char* GET_TARGET_OVERLAY_MODULE_INFOS = "GetTargetOverlayModuleInfos";
constexpr const char* GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME = "GetOverlayModuleInfoByBundleName";
constexpr const char* GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME = "GetTargetOverlayModuleInfosByBundleName";

// installer
constexpr const char* RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER = "GetBundleInstaller";
constexpr const char* RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER_SYNC = "GetBundleInstallerSync";
constexpr const char* RESOURCE_NAME_OF_INSTALL = "Install";
constexpr const char* RESOURCE_NAME_OF_UNINSTALL = "Uninstall";
constexpr const char* RESOURCE_NAME_OF_RECOVER = "Recover";
constexpr const char* RESOURCE_NAME_OF_UPDATE_BUNDLE_FOR_SELF = "UpdateBundleForSelf";
constexpr const char* RESOURCE_NAME_OF_UNINSTALL_AND_RECOVER = "UninstallUpdates";
constexpr const char* INSTALL_PERMISSION =
    "ohos.permission.INSTALL_BUNDLE or "
    "ohos.permission.INSTALL_ENTERPRISE_BUNDLE or "
    "ohos.permission.INSTALL_ENTERPRISE_MDM_BUNDLE or "
    "ohos.permission.INSTALL_ENTERPRISE_NORMAL_BUNDLE or "
    "ohos.permission.INSTALL_INTERNALTESTING_BUNDLE";
constexpr const char* UNINSTALL_PERMISSION = "ohos.permission.INSTALL_BUNDLE or ohos.permission.UNINSTALL_BUNDLE";
constexpr const char* RECOVER_PERMISSION = "ohos.permission.INSTALL_BUNDLE or ohos.permission.RECOVER_BUNDLE";
constexpr const char* INSTALL_SELF_PERMISSION = "ohos.permission.INSTALL_SELF_BUNDLE";
constexpr const char* PARAMETERS = "parameters";
constexpr const char* CORRESPONDING_TYPE = "corresponding type";
constexpr const char* FILE_PATH = "filePath";
constexpr const char* ADD_EXT_RESOURCE = "AddExtResource";
constexpr const char* REMOVE_EXT_RESOURCE = "RemoveExtResource";
constexpr const char* PARAM_HAPS_FILE_EMPTY_ERROR =
    "BusinessError 401: Parameter error. parameter hapFiles is needed for code signature";
constexpr const char* CREATE_APP_CLONE = "CreateAppClone";
constexpr const char* DESTROY_APP_CLONE = "destroyAppClone";
constexpr const char* INSTALL_PREEXISTING_APP = "installPreexistingApp";
constexpr const char* INSTALL_PLUGIN = "InstallPlugin";
constexpr const char* UNINSTALL_PLUGIN = "UninstallPlugin";
constexpr const char* PLUGIN_BUNDLE_NAME = "pluginBundleName";

// app_control
constexpr const char* TYPE_WANT = "want";
constexpr const char* PERMISSION_DISPOSED_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
constexpr const char* PERMISSION_DISPOSED_APP_STATUS =
    "ohos.permission.MANAGE_DISPOSED_APP_STATUS or ohos.permission.GET_DISPOSED_APP_STATUS";
constexpr const char* SET_DISPOSED_STATUS = "SetDisposedStatus";
constexpr const char* GET_DISPOSED_STATUS = "GetDisposedStatus";
constexpr const char* DELETE_DISPOSED_STATUS = "DeleteDisposedStatus";
constexpr const char* SET_DISPOSED_STATUS_SYNC = "SetDisposedStatusSync";
constexpr const char* DELETE_DISPOSED_STATUS_SYNC = "DeleteDisposedStatusSync";
constexpr const char* GET_DISPOSED_STATUS_SYNC = "GetDisposedStatusSync";
constexpr const char* GET_DISPOSED_RULE = "GetDisposedRule";
constexpr const char* GET_ALL_DISPOSED_RULES = "GetAllDisposedRules";
constexpr const char* APP_ID = "appId";
constexpr const char* APP_IDENTIFIER = "appIdentifier";
constexpr const char* DISPOSED_WANT = "disposedWant";
constexpr const char* DISPOSED_RULE = "disposedRule";
constexpr const char* DISPOSED_RULE_TYPE = "DisposedRule";
constexpr const char* UNINSTALL_DISPOSED_RULE = "uninstallDisposedRule";
constexpr const char* UNINSTALL_DISPOSED_RULE_TYPE = "UninstallDisposedRule";
constexpr const char* SET_UNINSTALL_DISPOSED_RULE = "SetUninstallDisposedRule";
constexpr const char* DELETE_UNINSTALL_DISPOSED_RULE = "DeleteUninstallDisposedRule";
constexpr const char* GET_UNINSTALL_DISPOSED_RULE = "GetUninstallDisposedRule";
constexpr const char* SET_DISPOSED_RULE = "SetDisposedRule";
constexpr const char* SET_DISPOSED_RULES = "SetDisposedRules";

// default_app_manager
constexpr const char* PERMISSION_SET_DEFAULT_APPLICATION_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS =
    "ohos.permission.SET_DEFAULT_APPLICATION and ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
const std::unordered_map<std::string, std::string> TYPE_MAPPING = {
    {"Web Browser", "BROWSER"},
    {"Image Gallery", "IMAGE"},
    {"Audio Player", "AUDIO"},
    {"Video Player", "VIDEO"},
    {"PDF Viewer", "PDF"},
    {"Word Viewer", "WORD"},
    {"Excel Viewer", "EXCEL"},
    {"PPT Viewer", "PPT"},
    {"Email", "EMAIL"}
};
constexpr const char* IS_DEFAULT_APPLICATION = "IsDefaultApplication";
constexpr const char* IS_DEFAULT_APPLICATION_SYNC = "IsDefaultApplicationSync";
constexpr const char* GET_DEFAULT_APPLICATION = "GetDefaultApplication";
constexpr const char* GET_DEFAULT_APPLICATION_SYNC = "GetDefaultApplicationSync";
constexpr const char* SET_DEFAULT_APPLICATION = "SetDefaultApplication";
constexpr const char* SET_DEFAULT_APPLICATION_SYNC = "SetDefaultApplicationSync";
constexpr const char* RESET_DEFAULT_APPLICATION = "ResetDefaultApplication";
constexpr const char* RESET_DEFAULT_APPLICATION_SYNC = "ResetDefaultApplicationSync";
constexpr const char* SET_DEFAULT_APPLICATION_FOR_APP_CLONE = "SetDefaultApplicationForAppClone";
constexpr const char* TYPE_CHECK = "type";
constexpr const char* WANT_CHECK = "want";
constexpr const char* ELEMENT_NAME = "ElementName";
}
}
}
#endif