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

constexpr int32_t GET_REMOTE_ABILITY_INFO_MAX_SIZE = 10;

constexpr const char* TYPE_NUMBER = "number";
constexpr const char* TYPE_STRING = "string";
constexpr const char* TYPE_OBJECT = "object";
constexpr const char* TYPE_BOOLEAN = "boolean";
constexpr const char* TYPE_FUNCTION = "function";
constexpr const char* TYPE_ARRAY = "array";
constexpr const char* FLAGS = "flags";
constexpr const char* BUNDLE_FLAGS = "bundleFlags";
constexpr const char* ABILITY_FLAGS = "abilityFlags";
constexpr const char* APPLICATION_FLAGS = "applicationFlags";
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
constexpr const char* RESOURCE_NAME_GET_REMOTE_ABILITY_INFO = "GetRemoteAbilityInfo";
constexpr const char* PARAMETER_ELEMENT_NAME = "elementName";
constexpr const char* PARAMETER_LOCALE = "locale";
constexpr const char* TYPE_WANT = "want";
constexpr const char* PERMISSION_DISPOSED_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
constexpr const char* SET_DISPOSED_STATUS = "SetDisposedStatus";
constexpr const char* GET_DISPOSED_STATUS = "GetDisposedStatus";
constexpr const char* DELETE_DISPOSED_STATUS = "DeleteDisposedStatus";
constexpr const char* SET_DISPOSED_STATUS_SYNC = "SetDisposedStatusSync";
constexpr const char* DELETE_DISPOSED_STATUS_SYNC = "DeleteDisposedStatusSync";
constexpr const char* GET_DISPOSED_STATUS_SYNC = "GetDisposedStatusSync";
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
}
}
}
#endif