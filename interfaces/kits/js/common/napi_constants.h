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
#ifndef NAPI_CONSTANTS_H
#define NAPI_CONSTANTS_H

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

constexpr const char* TYPE_NUMBER = "number";
constexpr const char* TYPE_STRING = "string";
constexpr const char* TYPE_OBJECT = "object";
constexpr const char* TYPE_BOOLEAN = "boolean";
constexpr const char* TYPE_FUNCTION = "function";
constexpr const char* TYPE_ARRAY = "array";
constexpr const char* FLAGS = "flags";
constexpr const char* BUNDLE_FLAGS = "bundleFlags";
constexpr const char* ABILITY_FLAGS = "abilityFlags";
constexpr const char* APP_FLAGS = "appFlags";
constexpr const char* ABILITY_INFO = "abilityInfo";
constexpr const char* LINK_FEATURE = "linkFeature";
constexpr const char* EXTENSION_TYPE_NAME = "extensionTypeName";
constexpr const char* EXTENSION_ABILITY_TYPE = "extensionAbilityType";
constexpr const char* ERR_MSG_BUNDLE_SERVICE_EXCEPTION = "Bundle manager service is excepted.";
constexpr const char*  PARAM_EXTENSION_ABILITY_TYPE_EMPTY_ERROR =
    "BusinessError 401: Parameter error.Parameter extensionAbilityType is empty.";
constexpr const char* BUNDLE_PERMISSIONS =
    "ohos.permission.GET_BUNDLE_INFO or ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* INVALID_WANT_ERROR =
    "implicit query condition, at least one query param(action, entities, uri, type, or linkFeature) non-empty.";
constexpr const char* PARAM_TYPE_CHECK_ERROR = "param type check error";
constexpr const char* APP_CLONE_IDENTITY_PERMISSIONS = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* IS_APPLICATION_ENABLED_SYNC = "IsApplicationEnabledSync";
constexpr const char* GET_BUNDLE_INFO_FOR_SELF_SYNC = "GetBundleInfoForSelfSync";
constexpr const char* GET_BUNDLE_INFO_SYNC = "GetBundleInfoSync";
constexpr const char* GET_APPLICATION_INFO_SYNC = "GetApplicationInfoSync";
constexpr const char* GET_BUNDLE_INFO = "GetBundleInfo";
constexpr const char* GET_BUNDLE_INFOS = "GetBundleInfos";
constexpr const char* GET_APPLICATION_INFOS = "GetApplicationInfos";
constexpr const char* IS_APPLICATION_ENABLED = "IsApplicationEnabled";
constexpr const char* QUERY_ABILITY_INFOS_SYNC = "QueryAbilityInfosSync";
constexpr const char* GET_APPLICATION_INFO = "GetApplicationInfo";
constexpr const char* GET_APP_CLONE_IDENTITY = "getAppCloneIdentity";
constexpr const char* GET_ABILITY_LABEL = "GetAbilityLabel";
constexpr const char* QUERY_EXTENSION_INFOS_SYNC = "QueryExtensionInfosSync";
constexpr const char* GET_LAUNCH_WANT_FOR_BUNDLE_SYNC = "GetLaunchWantForBundleSync";
constexpr const char* IS_ABILITY_ENABLED_SYNC = "IsAbilityEnabledSync";
constexpr const char* SET_ABILITY_ENABLED_SYNC = "SetAbilityEnabledSync";
constexpr const char* SET_APPLICATION_ENABLED_SYNC = "SetApplicationEnabledSync";
constexpr const char* GET_APP_CLONE_BUNDLE_INFO = "GetAppCloneBundleInfo";
constexpr const char* GET_DYNAMIC_ICON = "GetDynamicIcon";
constexpr const char* RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE = "GetSpecifiedDistributionType";
constexpr const char* BATCH_QUERY_ABILITY_INFOS = "BatchQueryAbilityInfos";
constexpr const char* GET_BUNDLE_NAME_BY_UID = "GetBundleNameByUid";
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* RESOURCE_FLAGS = "resourceFlags";
constexpr const char* PERMISSION_GET_BUNDLE_RESOURCES = "ohos.permission.GET_BUNDLE_RESOURCES";
constexpr const char* PERMISSION_GET_ALL_BUNDLE_RESOURCES =
    "ohos.permission.GET_INSTALLED_BUNDLE_LIST and ohos.permission.GET_BUNDLE_RESOURCES";
constexpr const char* PARSE_START_OPTIONS = "parse StartOptions failed";
constexpr const char* GET_BUNDLE_RESOURCE_INFO = "GetBundleResourceInfo";
constexpr const char* GET_LAUNCHER_ABILITY_RESOURCE_INFO = "GetLauncherAbilityResourceInfo";
constexpr const char* GET_ALL_BUNDLE_RESOURCE_INFO = "GetAllBundleResourceInfo";
constexpr const char* GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO = "GetAllLauncherAbilityResourceInfo";
constexpr const char* ENABLE_DYNAMIC_ICON = "EnableDynamicIcon";
constexpr const char* RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE = "isHapModuleRemovable";
constexpr const char* RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG = "setHapModuleUpgradeFlag";
constexpr const char* RESOURCE_NAME_OF_GET_BUNDLE_PACK_INFO = "getBundlePackInfo";
constexpr const char* RESOURCE_NAME_OF_GET_DISPATCH_INFO = "getDispatchInfo";
constexpr const char* DISPATCH_INFO_VERSION = "1";
constexpr const char* DISPATCH_INFO_DISPATCH_API = "1.0";
constexpr const char* UPGRADE_FLAG = "upgradeFlag";
constexpr const char* BUNDLE_PACK_FLAG = "bundlePackFlag";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* TARGET_MODULE_NAME = "targetModuleName";
constexpr const char* TARGET_BUNDLE_NAME = "targetBundleName";
constexpr const char* IS_ENABLED = "isEnabled";
constexpr const char* SET_OVERLAY_ENABLED = "SetOverlayEnabled";
constexpr const char* SET_OVERLAY_ENABLED_BY_BUNDLE_NAME = "SetOverlayEnabledByBundleName";
constexpr const char* GET_OVERLAY_MODULE_INFO = "GetOverlayModuleInfo";
constexpr const char* GET_TARGET_OVERLAY_MODULE_INFOS = "GetTargetOverlayModuleInfos";
constexpr const char* GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME = "GetOverlayModuleInfoByBundleName";
constexpr const char* GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME = "GetTargetOverlayModuleInfosByBundleName";
constexpr const char* GET_LAUNCHER_ABILITY_INFO = "GetLauncherAbilityInfo";
constexpr const char* GET_LAUNCHER_ABILITY_INFO_SYNC = "GetLauncherAbilityInfoSync";
constexpr const char* GET_ALL_LAUNCHER_ABILITY_INFO = "GetAllLauncherAbilityInfo";
constexpr const char* GET_SHORTCUT_INFO = "GetShortcutInfo";
constexpr const char* GET_SHORTCUT_INFO_SYNC = "GetShortcutInfoSync";
constexpr const char* USER_ID = "userId";
constexpr const char* ERROR_EMPTY_WANT = "want in ShortcutInfo cannot be empty";
constexpr const char* START_SHORTCUT = "StartShortcut";
constexpr const char* RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER = "GetBundleInstaller";
constexpr const char* RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER_SYNC = "GetBundleInstallerSync";
constexpr const char* RESOURCE_NAME_OF_INSTALL = "Install";
constexpr const char* RESOURCE_NAME_OF_UNINSTALL = "Uninstall";
constexpr const char* RESOURCE_NAME_OF_RECOVER = "Recover";
constexpr const char* RESOURCE_NAME_OF_UPDATE_BUNDLE_FOR_SELF = "UpdateBundleForSelf";
constexpr const char* RESOURCE_NAME_OF_UNINSTALL_AND_RECOVER = "UninstallAndRecover";
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
constexpr const char* HAPS_FILE_NEEDED =
    "BusinessError 401: Parameter error. parameter hapFiles is needed for code signature";
constexpr const char* CREATE_APP_CLONE = "CreateAppClone";
constexpr const char* DESTROY_APP_CLONE = "destroyAppClone";
constexpr const char* INSTALL_PREEXISTING_APP = "installPreexistingApp";
constexpr const char* INSTALL_PLUGIN = "InstallPlugin";
constexpr const char* UNINSTALL_PLUGIN = "UninstallPlugin";
constexpr const char* PLUGIN_BUNDLE_NAME = "pluginBundleName";
constexpr const char* GET_ALL_DESKTOP_SHORTCUT_INFO = "GetAllDesktopShortcutInfo";
constexpr const char* ADD_DESKTOP_SHORTCUT_INFO = "AddDesktopShortcutInfo";
constexpr const char* DELETE_DESKTOP_SHORTCUT_INFO = "DeleteDesktopShortcutInfo";
constexpr const char* QUERY_ABILITY_INFOS = "QueryAbilityInfos";
constexpr const char* GET_ABILITY_LABEL_SYNC = "GetAbilityLabelSync";
constexpr const char* GET_LAUNCH_WANT_FOR_BUNDLE = "GetLaunchWantForBundle";
constexpr const char* GET_BUNDLE_NAME_BY_UID_SYNC = "GetBundleNameByUidSync";
constexpr const char* QUERY_EXTENSION_INFOS = "QueryExtensionInfos";
constexpr const char* SET_ABILITY_ENABLED = "SetAbilityEnabled";
constexpr const char* SET_APPLICATION_ENABLED = "SetApplicationEnabled";
}
}
}
#endif