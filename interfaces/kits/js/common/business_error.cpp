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

#include "business_error.h"

#include <unordered_map>

#include "bundle_errors.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ERR_MSG_BUSINESS_ERROR = "BusinessError $: ";
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
constexpr const char* ERR_MSG_APPID_NOT_EXIST = "The specified appId is empty string.";
constexpr const char* ERR_MSG_PERMISSION_NOT_EXIST = "The specified permission is not found.";
constexpr const char* ERR_MSG_DEVICE_ID_NOT_EXIST = "The specified deviceId is not found.";
constexpr const char* ERR_MSG_INSTALL_PARSE_FAILED = "Failed to install the hap since the hap fails to be parsed.";
constexpr const char* ERR_MSG_INSTALL_VERIFY_SIGNATURE_FAILED =
    "Failed to install the hap since the hap signature fails to be verified.";
constexpr const char* ERR_MSG_INSTALL_HAP_FILEPATH_INVALID =
    "Failed to install the hap since the path of the hap is invalid or too large size.";
constexpr const char* ERR_MSG_INSTALL_HAP_SIZE_TOO_LARGE =
    "Failed to install the hap since the hap is too large.";
constexpr const char* ERR_MSG_INSTALL_INCORRECT_SUFFIX =
    "Failed to install the hap since the extension name of the hap is not .hap.";
constexpr const char* ERR_MSG_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT =
    "Failed to install haps since the configuration information of multi haps is inconsistent.";
constexpr const char* ERR_MSG_INSTALL_NO_DISK_SPACE_LEFT =
    "Failed to install the hap since the system disk space is insufficient.";
constexpr const char* ERR_MSG_INSTALL_VERSION_DOWNGRADE =
    "Failed to install the hap since the version of the newly installed hap is too early.";
constexpr const char* ERR_MSG_INSTALL_DEPENDENT_MODULE_NOT_EXIST =
    "Failed to install because the dependent module does not exist.";
constexpr const char* ERR_MSG_UNINSTALL_PREINSTALL_APP_FAILED = "The preinstalled app cannot be uninstalled.";
constexpr const char* ERR_ZLIB_SRC_FILE_INVALID_MSG = "The Input source file is invalid.";
constexpr const char* ERR_ZLIB_DEST_FILE_INVALID_MSG = "The Input destination file is invalid.";
constexpr const char* ERR_MSG_PARAM_NUMBER_ERROR =
    "BusinessError 401: Parameter error. The number of parameters is incorrect.";
constexpr const char* ERR_MSG_BUNDLE_SERVICE_EXCEPTION = "Bundle manager service is excepted.";
constexpr const char* ERROR_MSG_BUNDLE_IS_DISABLED = "The specified bundle is disabled.";
constexpr const char* ERROR_MSG_ABILITY_IS_DISABLED = "The specified ability is disabled.";
constexpr const char* ERROR_MSG_PROFILE_NOT_EXIST = "No profile in the hap.";
constexpr const char* ERROR_INVALID_UID_MSG = "The specified uid is invalid.";
constexpr const char* ERROR_INVALID_HAP_PATH_MSG = "The input source file is invalid.";
constexpr const char* ERROR_DEFAULT_APP_NOT_EXIST_MSG = "The specified default app does not exist.";
constexpr const char* ERROR_INVALID_TYPE_MSG = "The specified type is invalid.";
constexpr const char* ERROR_MSG_DISTRIBUTED_SERVICE_NOT_RUNNING = "The distributed service is not running.";
constexpr const char* ERROR_ABILITY_AND_TYPE_MISMATCH_MSG = "The specified ability and type do not match.";
constexpr const char* ERROR_MSG_CLEAR_CACHE_FILES_UNSUPPORTED =
    "The specified bundle does not support clearing cache files.";
static std::unordered_map<int32_t, const char*> ERR_MSG_MAP = {
    { ERROR_PERMISSION_DENIED_ERROR, ERR_MSG_PERMISSION_DENIED_ERROR },
    { ERROR_NOT_SYSTEM_APP, ERR_MSG_NOT_SYSTEM_APP},
    { ERROR_PARAM_CHECK_ERROR, ERR_MSG_PARAM_TYPE_ERROR },
    { ERROR_SYSTEM_ABILITY_NOT_FOUND, ERR_MSG_ABILITY_NOT_SUPPORTED },
    { ERROR_BUNDLE_NOT_EXIST, ERR_MSG_BUNDLE_NOT_EXIST },
    { ERROR_MODULE_NOT_EXIST, ERR_MSG_MODULE_NOT_EXIST },
    { ERROR_ABILITY_NOT_EXIST, ERR_MSG_ABILITY_NOT_EXIST },
    { ERROR_INVALID_USER_ID, ERR_MSG_INVALID_USER_ID },
    { ERROR_INVALID_APPID, ERR_MSG_APPID_NOT_EXIST },
    { ERROR_PERMISSION_NOT_EXIST, ERR_MSG_PERMISSION_NOT_EXIST },
    { ERROR_DEVICE_ID_NOT_EXIST, ERR_MSG_DEVICE_ID_NOT_EXIST },
    { ERROR_INSTALL_PARSE_FAILED, ERR_MSG_INSTALL_PARSE_FAILED },
    { ERROR_INSTALL_VERIFY_SIGNATURE_FAILED, ERR_MSG_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERROR_INSTALL_HAP_FILEPATH_INVALID, ERR_MSG_INSTALL_HAP_FILEPATH_INVALID },
    { ERROR_INSTALL_HAP_SIZE_TOO_LARGE, ERR_MSG_INSTALL_HAP_SIZE_TOO_LARGE },
    { ERROR_INSTALL_INCORRECT_SUFFIX, ERR_MSG_INSTALL_INCORRECT_SUFFIX },
    { ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT, ERR_MSG_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERROR_INSTALL_NO_DISK_SPACE_LEFT, ERR_MSG_INSTALL_NO_DISK_SPACE_LEFT },
    { ERROR_INSTALL_VERSION_DOWNGRADE, ERR_MSG_INSTALL_VERSION_DOWNGRADE },
    { ERROR_INSTALL_DEPENDENT_MODULE_NOT_EXIST, ERR_MSG_INSTALL_DEPENDENT_MODULE_NOT_EXIST },
    { ERROR_UNINSTALL_PREINSTALL_APP_FAILED, ERR_MSG_UNINSTALL_PREINSTALL_APP_FAILED },
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
    { ERROR_CLEAR_CACHE_FILES_UNSUPPORTED, ERROR_MSG_CLEAR_CACHE_FILES_UNSUPPORTED }
};
} // namespace

void BusinessError::ThrowError(napi_env env, int32_t err, const std::string &msg)
{
    napi_value error = CreateError(env, err, msg);
    napi_throw(env, error);
}

void BusinessError::ThrowParameterTypeError(napi_env env, int32_t err,
    const std::string &parameter, const std::string &type)
{
    napi_value error = CreateCommonError(env, err, parameter, type);
    napi_throw(env, error);
}

void BusinessError::ThrowTooFewParametersError(napi_env env, int32_t err)
{
    ThrowError(env, err, ERR_MSG_PARAM_NUMBER_ERROR);
}

napi_value BusinessError::CreateError(napi_env env, int32_t err, const std::string& msg)
{
    napi_value businessError = nullptr;
    napi_value errorCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, err, &errorCode));
    napi_value errorMessage = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMessage));
    napi_create_error(env, nullptr, errorMessage, &businessError);
    napi_set_named_property(env, businessError, "code", errorCode);
    return businessError;
}

napi_value BusinessError::CreateCommonError(
    napi_env env, int32_t err, const std::string &functionName, const std::string &permissionName)
{
    std::string errMessage = ERR_MSG_BUSINESS_ERROR;
    auto iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, std::to_string(err));
    }
    if (ERR_MSG_MAP.find(err) != ERR_MSG_MAP.end()) {
        errMessage += ERR_MSG_MAP[err];
    }
    iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, functionName);
        iter = errMessage.find("$");
        if (iter != std::string::npos) {
            errMessage = errMessage.replace(iter, 1, permissionName);
        }
    }
    return CreateError(env, err, errMessage);
}
} // AppExecFwk
} // OHOS