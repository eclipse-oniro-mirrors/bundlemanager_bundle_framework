/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "business_error_map.h"

#include <unordered_map>

#include "bundle_errors.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ERR_MSG_PERMISSION_DENIED_ERROR =
    "Permission denied. An attempt was made to $ forbidden by permission: $.";
constexpr const char* ERR_MSG_NOT_SYSTEM_APP =
    "Permission denied. Non-system APP calling system API";
constexpr const char* ERR_MSG_PARAM_TYPE_ERROR = "Parameter error. The type of $ must be $.";
constexpr const char* ERR_MSG_ABILITY_NOT_SUPPORTED =
    "Capability not supported. Function $ can not work correctly due to limited device capabilities.";
constexpr const char* ERR_MSG_BUNDLE_NOT_EXIST = "The specified bundle is not found.";
constexpr const char* ERR_MSG_MODULE_NOT_EXIST = "The specified module is not found.";
constexpr const char* ERR_MSG_ABILITY_NOT_EXIST = "The specified ability is not found.";
constexpr const char* ERR_MSG_INVALID_USER_ID = "The specified user id is not found.";
constexpr const char* ERR_MSG_APPID_NOT_EXIST = "The specified appId is an empty string.";
constexpr const char* ERR_MSG_APPIDENTIFIER_NOT_EXIST = "The specified appIdentifier is an empty string.";
constexpr const char* ERR_MSG_PERMISSION_NOT_EXIST = "The specified permission is not found.";
constexpr const char* ERR_MSG_DEVICE_ID_NOT_EXIST = "The specified deviceId is not found.";
constexpr const char* ERR_MSG_INVALID_APP_INDEX = "The specified app index is invalid.";
constexpr const char* ERR_MSG_INSTALL_PARSE_FAILED = "Failed to install the hap since the hap fails to be parsed.";
constexpr const char* ERR_MSG_INSTALL_VERIFY_SIGNATURE_FAILED =
    "Failed to install the hap since the hap signature fails to be verified.";
constexpr const char* ERR_MSG_INSTALL_HAP_FILEPATH_INVALID =
    "Failed to install the hap since the path of the hap is invalid or too large size.";
constexpr const char* ERR_MSG_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT =
    "Failed to install haps since the configuration information of multi haps is inconsistent.";
constexpr const char* ERR_MSG_INSTALL_NO_DISK_SPACE_LEFT =
    "Failed to install the hap since the system disk space is insufficient.";
constexpr const char* ERR_MSG_INSTALL_VERSION_DOWNGRADE =
    "Failed to install the hap since the version of the newly installed hap is too early.";
constexpr const char* ERR_MSG_INSTALL_DEPENDENT_MODULE_NOT_EXIST =
    "Failed to install the HAP or HSP because the dependent module does not exist.";
constexpr const char* ERR_MSG_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED =
    "Failed to install the HSP due to the lack of required permission.";
constexpr const char* ERR_MSG_UNINSTALL_PREINSTALL_APP_FAILED = "The preinstalled app cannot be uninstalled.";
constexpr const char* ERR_MSG_BUNDLE_NOT_PREINSTALLED =
    "Failed to uninstall updates because the HAP is not pre-installed.";
constexpr const char* ERR_ZLIB_SRC_FILE_INVALID_MSG = "The Input source file is invalid.";
constexpr const char* ERR_ZLIB_DEST_FILE_INVALID_MSG = "The Input destination file is invalid.";
constexpr const char* ERR_MSG_BUNDLE_SERVICE_EXCEPTION = "Bundle manager service is excepted.";
constexpr const char* ERROR_MSG_BUNDLE_IS_DISABLED = "The specified bundle is disabled.";
constexpr const char* ERROR_MSG_ABILITY_IS_DISABLED = "The specified ability is disabled.";
constexpr const char* ERROR_MSG_PROFILE_NOT_EXIST = "The specified profile is not found in the HAP.";
constexpr const char* ERROR_INVALID_UID_MSG = "The specified uid is invalid.";
constexpr const char* ERROR_INVALID_HAP_PATH_MSG = "The input source file is invalid.";
constexpr const char* ERROR_DEFAULT_APP_NOT_EXIST_MSG = "The specified default app does not exist.";
constexpr const char* ERROR_INVALID_TYPE_MSG = "The specified type is invalid.";
constexpr const char* ERROR_MSG_DISTRIBUTED_SERVICE_NOT_RUNNING = "The distributed service is not running.";
constexpr const char* ERROR_ABILITY_AND_TYPE_MISMATCH_MSG = "The specified ability and type do not match.";
constexpr const char* ERROR_MSG_CLEAR_CACHE_FILES_UNSUPPORTED =
    "The specified bundle does not support clearing cache files.";
constexpr const char* ERROR_MSG_INSTALL_HAP_OVERLAY_CHECK_FAILED =
    "Failed to install the HAP because the overlay check of the HAP failed.";
constexpr const char* ERROR_MSG_SPECIFIED_BUNDLE_NOT_OVERLAY_BUNDLE =
    "The specified bundleName is not overlay bundle.";
constexpr const char* ERROR_MSG_SPECIFIED_MODULE_NOT_OVERLAY_MODULE =
    "The specified moduleName is not overlay module.";
constexpr const char* ERROR_MSG_SPECIFIED_MODULE_IS_OVERLAY_MODULE =
    "The specified moduleName is overlay module.";
constexpr const char* ERROR_MSG_SPECIFIED_BUNDLE_IS_OVERLAY_BUNDLE =
    "The specified bundle is overlay bundle.";
constexpr const char* ERROR_MSG_SHARE_APP_LIBRARY_IS_RELIED =
    "The version of the shared bundle is dependent on other applications.";
constexpr const char* ERROR_MSG_SHARE_APP_LIBRARY_IS_NOT_EXIST =
    "The specified shared library is not exist";
constexpr const char* ERR_MSG_UNINSTALL_SHARED_LIBRARY =
    "The specified bundle is shared library";
constexpr const char* ERR_MSG_DISALLOW_INSTALL =
    "Failed to install the HAP because the installation is forbidden by enterprise device management.";
constexpr const char* ERR_MSG_WRONG_PROXY_DATA_URI =
    "The uri in data proxy is wrong";
constexpr const char* ERR_MSG_WRONG_PROXY_DATA_PERMISSION =
    "The apl of required permission in non-system data proxy should be system_basic or system_core";
constexpr const char* ERR_MSG_WRONG_MODE_ISOLATION =
    "Failed to install the HAP because the isolationMode configured is not supported";
constexpr const char* ERR_MSG_DISALLOW_UNINSTALL =
    "Failed to uninstall the HAP because the uninstall is forbidden by enterprise device management.";
constexpr const char* ERR_MSG_ALREADY_EXIST =
    "Failed to install the HAP because the VersionCode to be updated is not greater than the current VersionCode";
constexpr const char* ERR_ZLIB_SRC_FILE_FORMAT_ERROR_OR_DAMAGED_MSG =
    "The input source file is not in ZIP format or is damaged.";
constexpr const char* ERR_MSG_CODE_SIGNATURE_FAILED =
    "Failed to install the HAP because the code signature verification failed.";
constexpr const char* ERR_MSG_SELF_UPDATE_NOT_MDM =
    "Failed to install the HAP because the distribution type of the caller application is not enterprise_mdm.";
constexpr const char* ERR_MSG_SELF_UPDATE_BUNDLENAME_NOT_SAME =
    "Failed to install the HAP because the bundleName is different from the bundleName of the caller application.";
constexpr const char* ERR_MSG_ENTERPRISE_BUNDLE_NOT_ALLOWED =
    "Failed to install the HAP because an enterprise normal/MDM bundle cannot be installed on non-enterprise devices.";
constexpr const char* ERR_MSG_INSTALL_EXISTED_ENTERPRISE_BUNDLE_NOT_ALLOWED =
    "It is not allowed to install the enterprise bundle.";
constexpr const char* ERR_MSG_DEBUG_BUNDLE_NOT_ALLOWED =
    "Failed to install the HAP because a debug bundle can be installed only in developer mode.";
constexpr const char* ERR_MSG_ERROR_VERIFY_ABC = "Failed to verify the abc file.";
constexpr const char* ERR_MSG_ERROR_DELETE_ABC = "Failed to delete the abc file.";
constexpr const char* ERR_MSG_ERROR_EXT_RESOURCE_ADD_ERROR = "Failed to add extended resources.";
constexpr const char* ERR_MSG_ERROR_EXT_RESOURCE_REMOVE_ERROR = "Failed to remove extended resources.";
constexpr const char* ERR_MSG_ERROR_EXT_RESOURCE_GET_ERROR = "Failed to obtain extended resources.";
constexpr const char* ERR_MSG_ERROR_DYNAMIC_ICON_ENABLE_ERROR = "Failed to enable the dynamic icon.";
constexpr const char* ERR_MSG_ENABLE_DYNAMIC_ICON_DUE_TO_EXISTING_CUSTOM_THEMES =
    "Dynamic icons cannot take effect due to existing custom themes.";
constexpr const char* ERR_MSG_ERROR_DYNAMIC_ICON_DISABLE_ERROR = "Failed to disable the dynamic icon.";
constexpr const char* ERR_MSG_ERROR_DYNAMIC_ICON_GET_ERROR = "Failed to obtain the dynamic icon.";
constexpr const char* ERROR_MSG_NOT_APP_GALLERY_CALL = "The caller is not AppGallery.";
constexpr const char* ERROR_MSG_INSTALL_PERMISSION_CHECK_ERROR =
    "Failed to install the HAP because the HAP requests wrong permissions.";
constexpr const char* ERR_MSG_INVALID_LINK = "The specified link is invalid.";
constexpr const char* ERR_MSG_SCHEME_NOT_IN_QUERYSCHEMES =
    "The scheme of the specified link is not in the querySchemes.";
constexpr const char* ERR_MSG_INVALID_DEVELOPER_ID =
    "The specified developerId is invalid.";
constexpr const char* ERR_MSG_BUNDLE_CAN_NOT_BE_UNINSTALLED =
    "The specified application cannot be uninstalled.";
constexpr const char* ERR_MSG_START_SHORTCUT =
    "The ability specified by want in the ShortcutInfo struct cannot be started.";
constexpr const char* ERR_MSG_INSTALL_FAILED_CONTROLLED =
    "Failed to install the HAP because the device has been controlled.";
constexpr const char* ERR_MSG_NATIVE_INSTALL_FAILED =
    "Failed to install the HAP because installing the native package failed.";
constexpr const char* ERR_MSG_NATIVE_UNINSTALL_FAILED =
    "Failed to uninstall the HAP because uninstalling the native package failed.";
constexpr const char* ERR_MSG_INVALID_APPINDEX =
    "The appIndex is invalid.";
constexpr const char* ERROR_MSG_LOCKED_APPLICATION_UNINSTALL =
    "Failed to uninstall the app because the app is locked.";
constexpr const char* ERR_MSG_APP_NOT_SUPPORTED_MULTI_TYPE =
    "The app does not support the creation of an appClone instance.";
constexpr const char* ERR_MSG_SHORTCUT_ID_ILLEGAL =
    "The specified shortcut id is illegal.";
constexpr const char* ERR_MSG_INSTALL_FAILED_INCONSISTENT_SIGNATURE =
    "Failed to install the HAP because an application with the same bundle name "
    "but different signature information exists on the device.";
constexpr const char* ERR_MSG_INVALID_UNINSTALL_RULE =
    "The specified bundleName of want is not the same with caller.";
constexpr const char* ERR_MSG_APP_DISTRIBUTION_TYPE_NOT_ALLOW_INSTALL =
    "Failed to install the HAP or HSP because the app distribution type is not allowed.";
constexpr const char* ERR_MSG_INSTALL_FAILED_AND_RESTORE_TO_PREINSTALLED =
    "Failed to install the HAP and restore to preinstalled bundle.";
constexpr const char* ERR_MSG_PLUGIN_ID_CHECK_ERROR =
    "Failed to install the plugin because the plugin id fails to be verified.";
constexpr const char* ERR_MSG_CHECK_SUPPORT_PERMISSION =
    "Failed to install the plugin because the host application lacks ohos.permission.kernel.SUPPORT_PLUGIN.";
constexpr const char* ERROR_MSG_DEVICE_NOT_SUPPORT_PLUGIN =
    "Failed to install the plugin because the current device does not support plugin.";
constexpr const char* ERROR_MSG_PLUGIN_ID_PARSE_ERROR =
    "Failed to install the plugin because the plugin id fails to be parsed.";
constexpr const char* ERROR_MSG_PLUGIN_NOT_FOUND =
    "Failed to uninstall the plugin because the specified plugin is not found.";
constexpr const char* ERROR_MSG_PLUGIN_SAME_BUNDLE_NAME =
    "Failed to install the plugin because the plugin name is same as host bundle name.";
constexpr const char* ERROR_MSG_INSTALL_FILE_IS_SHARED_LIBRARY =
    "Failed to install because disallow install a shared bundle by hapFilePaths.";
constexpr const char* ERROR_MSG_SOURCE_PATHS_AREINVALID =
    "The source paths are invalid.";
constexpr const char* ERROR_MSG_DESTINATION_PATHS_AREINVALID =
    "The destination path is invalid.";
constexpr const char* ERROR_MSG_USER_AUTHENTICATION_FAILED =
    "User authentication failed.";
constexpr const char* ERROR_MSG_WAITING_FOR_USER_AUTHENTICATION_TIMEOUT =
    "Waiting for user authentication timeout.";
constexpr const char* ERROR_MSG_SOURCE_PATH_ACCESS_FAILED =
    "There are inaccessible path in the source paths.";
constexpr const char* ERROR_MSG_DESTINATION_PATH_ACCESS_FAILED =
    "The destination path cannot be accessed.";
constexpr const char* ERROR_MSG_DATA_MIGRATION_COPY_FAILED =
    "System error occurred during copy execution.";

static std::unordered_map<int32_t, const char*> ERR_MSG_MAP = {
    { ERROR_PERMISSION_DENIED_ERROR, ERR_MSG_PERMISSION_DENIED_ERROR },
    { ERROR_NOT_SYSTEM_APP, ERR_MSG_NOT_SYSTEM_APP },
    { ERROR_PARAM_CHECK_ERROR, ERR_MSG_PARAM_TYPE_ERROR },
    { ERROR_SYSTEM_ABILITY_NOT_FOUND, ERR_MSG_ABILITY_NOT_SUPPORTED },
    { ERROR_BUNDLE_NOT_EXIST, ERR_MSG_BUNDLE_NOT_EXIST },
    { ERROR_MODULE_NOT_EXIST, ERR_MSG_MODULE_NOT_EXIST },
    { ERROR_ABILITY_NOT_EXIST, ERR_MSG_ABILITY_NOT_EXIST },
    { ERROR_INVALID_USER_ID, ERR_MSG_INVALID_USER_ID },
    { ERROR_INVALID_APPID, ERR_MSG_APPID_NOT_EXIST },
    { ERROR_INVALID_APPIDENTIFIER, ERR_MSG_APPIDENTIFIER_NOT_EXIST },
    { ERROR_INVALID_APPINDEX, ERR_MSG_INVALID_APP_INDEX },
    { ERROR_PERMISSION_NOT_EXIST, ERR_MSG_PERMISSION_NOT_EXIST },
    { ERROR_DEVICE_ID_NOT_EXIST, ERR_MSG_DEVICE_ID_NOT_EXIST },
    { ERROR_INSTALL_PARSE_FAILED, ERR_MSG_INSTALL_PARSE_FAILED },
    { ERROR_INSTALL_VERIFY_SIGNATURE_FAILED, ERR_MSG_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERROR_INSTALL_HAP_FILEPATH_INVALID, ERR_MSG_INSTALL_HAP_FILEPATH_INVALID },
    { ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT, ERR_MSG_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERROR_INSTALL_NO_DISK_SPACE_LEFT, ERR_MSG_INSTALL_NO_DISK_SPACE_LEFT },
    { ERROR_INSTALL_VERSION_DOWNGRADE, ERR_MSG_INSTALL_VERSION_DOWNGRADE },
    { ERROR_INSTALL_DEPENDENT_MODULE_NOT_EXIST, ERR_MSG_INSTALL_DEPENDENT_MODULE_NOT_EXIST },
    { ERROR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED, ERR_MSG_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED },
    { ERROR_UNINSTALL_PREINSTALL_APP_FAILED, ERR_MSG_UNINSTALL_PREINSTALL_APP_FAILED },
    { ERROR_BUNDLE_NOT_PREINSTALLED, ERR_MSG_BUNDLE_NOT_PREINSTALLED },
    { ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION },
    { ERR_ZLIB_SRC_FILE_INVALID, ERR_ZLIB_SRC_FILE_INVALID_MSG },
    { ERR_ZLIB_DEST_FILE_INVALID, ERR_ZLIB_DEST_FILE_INVALID_MSG },
    { ERROR_BUNDLE_IS_DISABLED, ERROR_MSG_BUNDLE_IS_DISABLED },
    { ERROR_ABILITY_IS_DISABLED, ERROR_MSG_ABILITY_IS_DISABLED },
    { ERROR_PROFILE_NOT_EXIST, ERROR_MSG_PROFILE_NOT_EXIST },
    { ERROR_INVALID_UID, ERROR_INVALID_UID_MSG },
    { ERROR_INVALID_HAP_PATH, ERROR_INVALID_HAP_PATH_MSG },
    { ERROR_DEFAULT_APP_NOT_EXIST, ERROR_DEFAULT_APP_NOT_EXIST_MSG },
    { ERROR_INVALID_TYPE, ERROR_INVALID_TYPE_MSG },
    { ERROR_DISTRIBUTED_SERVICE_NOT_RUNNING, ERROR_MSG_DISTRIBUTED_SERVICE_NOT_RUNNING },
    { ERROR_ABILITY_AND_TYPE_MISMATCH, ERROR_ABILITY_AND_TYPE_MISMATCH_MSG },
    { ERROR_CLEAR_CACHE_FILES_UNSUPPORTED, ERROR_MSG_CLEAR_CACHE_FILES_UNSUPPORTED },
    { ERROR_INSTALL_HAP_OVERLAY_CHECK_FAILED, ERROR_MSG_INSTALL_HAP_OVERLAY_CHECK_FAILED },
    { ERROR_SPECIFIED_MODULE_NOT_OVERLAY_MODULE, ERROR_MSG_SPECIFIED_MODULE_NOT_OVERLAY_MODULE },
    { ERROR_SPECIFIED_BUNDLE_NOT_OVERLAY_BUNDLE, ERROR_MSG_SPECIFIED_BUNDLE_NOT_OVERLAY_BUNDLE },
    { ERROR_SPECIFIED_MODULE_IS_OVERLAY_MODULE, ERROR_MSG_SPECIFIED_MODULE_IS_OVERLAY_MODULE },
    { ERROR_SPECIFIED_BUNDLE_IS_OVERLAY_BUNDLE, ERROR_MSG_SPECIFIED_BUNDLE_IS_OVERLAY_BUNDLE },
    { ERROR_UNINSTALL_SHARE_APP_LIBRARY_IS_RELIED, ERROR_MSG_SHARE_APP_LIBRARY_IS_RELIED },
    { ERROR_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST, ERROR_MSG_SHARE_APP_LIBRARY_IS_NOT_EXIST },
    { ERROR_UNINSTALL_BUNDLE_IS_SHARED_BUNDLE, ERR_MSG_UNINSTALL_SHARED_LIBRARY },
    { ERROR_DISALLOW_INSTALL, ERR_MSG_DISALLOW_INSTALL },
    { ERROR_INSTALL_WRONG_DATA_PROXY_URI, ERR_MSG_WRONG_PROXY_DATA_URI },
    { ERROR_INSTALL_WRONG_DATA_PROXY_PERMISSION, ERR_MSG_WRONG_PROXY_DATA_PERMISSION },
    { ERROR_INSTALL_WRONG_MODE_ISOLATION, ERR_MSG_WRONG_MODE_ISOLATION },
    { ERROR_DISALLOW_UNINSTALL, ERR_MSG_DISALLOW_UNINSTALL },
    { ERROR_INSTALL_ALREADY_EXIST, ERR_MSG_ALREADY_EXIST },
    { ERR_ZLIB_SRC_FILE_FORMAT_ERROR_OR_DAMAGED, ERR_ZLIB_SRC_FILE_FORMAT_ERROR_OR_DAMAGED_MSG },
    { ERROR_INSTALL_CODE_SIGNATURE_FAILED, ERR_MSG_CODE_SIGNATURE_FAILED },
    { ERROR_INSTALL_SELF_UPDATE_NOT_MDM, ERR_MSG_SELF_UPDATE_NOT_MDM},
    { ERROR_INSTALL_SELF_UPDATE_BUNDLENAME_NOT_SAME, ERR_MSG_SELF_UPDATE_BUNDLENAME_NOT_SAME},
    { ERROR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED, ERR_MSG_ENTERPRISE_BUNDLE_NOT_ALLOWED },
    { ERROR_INSTALL_EXISTED_ENTERPRISE_NOT_ALLOWED_ERROR, ERR_MSG_INSTALL_EXISTED_ENTERPRISE_BUNDLE_NOT_ALLOWED },
    { ERROR_INSTALL_DEBUG_BUNDLE_NOT_ALLOWED, ERR_MSG_DEBUG_BUNDLE_NOT_ALLOWED},
    { ERROR_VERIFY_ABC, ERR_MSG_ERROR_VERIFY_ABC},
    { ERROR_NOT_APP_GALLERY_CALL, ERROR_MSG_NOT_APP_GALLERY_CALL},
    { ERROR_DELETE_ABC, ERR_MSG_ERROR_DELETE_ABC},
    { ERROR_ADD_EXTEND_RESOURCE, ERR_MSG_ERROR_EXT_RESOURCE_ADD_ERROR},
    { ERROR_REMOVE_EXTEND_RESOURCE, ERR_MSG_ERROR_EXT_RESOURCE_REMOVE_ERROR},
    { ERROR_GET_EXTEND_RESOURCE, ERR_MSG_ERROR_EXT_RESOURCE_GET_ERROR},
    { ERROR_ENABLE_DYNAMIC_ICON, ERR_MSG_ERROR_DYNAMIC_ICON_ENABLE_ERROR},
    { ERROR_ENABLE_DYNAMIC_ICON_DUE_TO_EXISTING_CUSTOM_THEMES,
        ERR_MSG_ENABLE_DYNAMIC_ICON_DUE_TO_EXISTING_CUSTOM_THEMES},
    { ERROR_DISABLE_DYNAMIC_ICON, ERR_MSG_ERROR_DYNAMIC_ICON_DISABLE_ERROR},
    { ERROR_GET_DYNAMIC_ICON, ERR_MSG_ERROR_DYNAMIC_ICON_GET_ERROR},
    { ERROR_INSTALL_PERMISSION_CHECK_ERROR, ERROR_MSG_INSTALL_PERMISSION_CHECK_ERROR},
    { ERROR_INVALID_LINK, ERR_MSG_INVALID_LINK },
    { ERROR_SCHEME_NOT_IN_QUERYSCHEMES, ERR_MSG_SCHEME_NOT_IN_QUERYSCHEMES },
    { ERROR_INVALID_DEVELOPERID, ERR_MSG_INVALID_DEVELOPER_ID },
    { ERROR_BUNDLE_CAN_NOT_BE_UNINSTALLED, ERR_MSG_BUNDLE_CAN_NOT_BE_UNINSTALLED },
    { ERROR_START_SHORTCUT_ERROR, ERR_MSG_START_SHORTCUT },
    { ERROR_INSTALL_FAILED_CONTROLLED, ERR_MSG_INSTALL_FAILED_CONTROLLED },
    { ERROR_INSTALL_NATIVE_FAILED, ERR_MSG_NATIVE_INSTALL_FAILED },
    { ERROR_UNINSTALL_NATIVE_FAILED, ERR_MSG_NATIVE_UNINSTALL_FAILED },
    { ERROR_INVALID_APPINDEX, ERR_MSG_INVALID_APPINDEX },
    { ERROR_APPLICATION_UNINSTALL, ERROR_MSG_LOCKED_APPLICATION_UNINSTALL },
    { ERROR_APP_NOT_SUPPORTED_MULTI_TYPE, ERR_MSG_APP_NOT_SUPPORTED_MULTI_TYPE },
    { ERROR_SHORTCUT_ID_ILLEGAL_ERROR, ERR_MSG_SHORTCUT_ID_ILLEGAL },
    { ERROR_INSTALL_FAILED_INCONSISTENT_SIGNATURE, ERR_MSG_INSTALL_FAILED_INCONSISTENT_SIGNATURE },
    { ERROR_INVALID_UNINSTALL_RULE, ERR_MSG_INVALID_UNINSTALL_RULE },
    { ERROR_APP_DISTRIBUTION_TYPE_NOT_ALLOW_INSTALL, ERR_MSG_APP_DISTRIBUTION_TYPE_NOT_ALLOW_INSTALL },
    { ERROR_INSTALL_FAILED_AND_RESTORE_TO_PREINSTALLED, ERR_MSG_INSTALL_FAILED_AND_RESTORE_TO_PREINSTALLED },
    { ERROR_PLUGIN_ID_CHECK_ERROR, ERR_MSG_PLUGIN_ID_CHECK_ERROR},
    { ERROR_CHECK_SUPPORT_PERMISSION, ERR_MSG_CHECK_SUPPORT_PERMISSION},
    { ERROR_DEVICE_NOT_SUPPORT_PLUGIN, ERROR_MSG_DEVICE_NOT_SUPPORT_PLUGIN},
    { ERROR_PLUGIN_ID_PARSE_ERROR, ERROR_MSG_PLUGIN_ID_PARSE_ERROR },
    { ERROR_PLUGIN_NOT_FOUND, ERROR_MSG_PLUGIN_NOT_FOUND },
    { ERROR_PLUGIN_SAME_BUNDLE_NAME, ERROR_MSG_PLUGIN_SAME_BUNDLE_NAME},
    { ERROR_INSTALL_FILE_IS_SHARED_LIBRARY, ERROR_MSG_INSTALL_FILE_IS_SHARED_LIBRARY},
    { ERROR_SOURCE_PATHS_AREINVALID, ERROR_MSG_SOURCE_PATHS_AREINVALID},
    { ERROR_DESTINATION_PATHS_AREINVALID, ERROR_MSG_DESTINATION_PATHS_AREINVALID},
    { ERROR_USER_AUTHENTICATION_FAILED, ERROR_MSG_USER_AUTHENTICATION_FAILED},
    { ERROR_WAITING_FOR_USER_AUTHENTICATION_TIMEOUT, ERROR_MSG_WAITING_FOR_USER_AUTHENTICATION_TIMEOUT},
    { ERROR_SOURCE_PATH_ACCESS_FAILED, ERROR_MSG_SOURCE_PATH_ACCESS_FAILED},
    { ERROR_DESTINATION_PATH_ACCESS_FAILED, ERROR_MSG_DESTINATION_PATH_ACCESS_FAILED},
    { ERROR_DATA_MIGRATION_COPY_FAILED, ERROR_MSG_DATA_MIGRATION_COPY_FAILED}
};
} // namespace
void BusinessErrorMap::GetErrMap(std::unordered_map<int32_t, const char*>& errMap)
{
    errMap = ERR_MSG_MAP;
}
}
}