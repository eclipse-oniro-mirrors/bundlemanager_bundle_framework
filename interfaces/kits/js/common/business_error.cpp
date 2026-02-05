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

#include "business_error.h"

#include <unordered_map>

#include "bundle_errors.h"
#include "business_error_map.h"
#include "error_data.h"

namespace OHOS {
namespace AppExecFwk {
constexpr const char* ERROR_MESSAGE_APP_DISABLE_FORBIDDEN = "Or the application is forbidden to be disabled.";

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
    ThrowError(env, err, BusinessErrorNS::ERR_MSG_PARAM_NUMBER_ERROR);
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

napi_value BusinessError::CreateError(napi_env env, int32_t err, const std::string& msg, const ErrorData &errorData)
{
    napi_value businessError = nullptr;
    napi_value errorCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, err, &errorCode));
    napi_value errorMessage = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMessage));
    napi_create_error(env, nullptr, errorMessage, &businessError);
    napi_value data = nullptr;
    NAPI_CALL(env, napi_create_object(env, &data));
    napi_value reasonCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errorData.reasonCode, &reasonCode));
    napi_value reasonMsg = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, errorData.reasonMsg.c_str(), NAPI_AUTO_LENGTH, &reasonMsg));
    napi_set_named_property(env, data, "reasonCode", reasonCode);
    napi_set_named_property(env, data, "reasonMsg", reasonMsg);
    napi_set_named_property(env, businessError, "data", data);
    napi_set_named_property(env, businessError, "code", errorCode);
    return businessError;
}

napi_value BusinessError::CreateCommonError(
    napi_env env, int32_t err, const std::string &functionName, const std::string &permissionName)
{
    std::string errMessage = BusinessErrorNS::ERR_MSG_BUSINESS_ERROR;
    auto iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, std::to_string(err));
    }
    std::unordered_map<int32_t, const char*> errMap;
    BusinessErrorMap::GetErrMap(errMap);
    if (errMap.find(err) != errMap.end()) {
        errMessage += errMap[err];
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

napi_value BusinessError::CreateNewCommonError(
    napi_env env, int32_t err, const std::string &functionName, const std::string &permissionName)
{
    std::string errMessage = BusinessErrorNS::ERR_MSG_BUSINESS_ERROR;
    auto iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, std::to_string(err));
    }
    std::unordered_map<int32_t, const char*> errMap;
    BusinessErrorMap::GetNewErrMap(errMap);
    if (errMap.find(err) != errMap.end()) {
        errMessage += errMap[err];
    } else {
        BusinessErrorMap::GetErrMap(errMap);
        if (errMap.find(err) != errMap.end()) {
            errMessage += errMap[err];
        }
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

napi_value BusinessError::CreateInstallError(
    napi_env env, int32_t err, int32_t innerCode,
    const std::string &functionName, const std::string &permissionName)
{
    std::string errMessage = BusinessErrorNS::ERR_MSG_BUSINESS_ERROR;
    auto iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, std::to_string(err));
    }
    std::unordered_map<int32_t, const char*> errMap;
    BusinessErrorMap::GetErrMap(errMap);
    if (errMap.find(err) != errMap.end()) {
        errMessage += errMap[err];
    }
    errMessage += "[" + std::to_string(innerCode) + "]";
    iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, functionName);
        iter = errMessage.find("$");
        if (iter != std::string::npos) {
            errMessage = errMessage.replace(iter, 1, permissionName);
        }
    }
    ErrorData data;
    data.reasonCode = innerCode;
    return CreateError(env, err, errMessage, data);
}

void BusinessError::ThrowEnumError(napi_env env,
    const std::string &parameter, const std::string &type)
{
    napi_value error = CreateEnumError(env, parameter, type);
    napi_throw(env, error);
}

napi_value BusinessError::CreateEnumError(napi_env env,
    const std::string &parameter, const std::string &enumClass)
{
    std::string errMessage = BusinessErrorNS::ERR_MSG_BUSINESS_ERROR;
    auto iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, std::to_string(ERROR_PARAM_CHECK_ERROR));
    }
    errMessage += BusinessErrorNS::ERR_MSG_ENUM_ERROR;
    iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, parameter);
        iter = errMessage.find("$");
        if (iter != std::string::npos) {
            errMessage = errMessage.replace(iter, 1, enumClass);
        }
    }
    return CreateError(env, ERROR_PARAM_CHECK_ERROR, errMessage);
}

napi_value BusinessError::CreateErrorForSetAppEnabled(
    napi_env env, int32_t err, const std::string &functionName, const std::string &permissionName)
{
    std::string errMessage = BusinessErrorNS::ERR_MSG_BUSINESS_ERROR;
    auto iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, std::to_string(err));
    }
    std::unordered_map<int32_t, const char*> errMap;
    BusinessErrorMap::GetErrMap(errMap);
    if (errMap.find(err) != errMap.end()) {
        errMessage += errMap[err];
    }
    iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, functionName);
        iter = errMessage.find("$");
        if (iter != std::string::npos) {
            errMessage = errMessage.replace(iter, 1, permissionName);
            errMessage += ERROR_MESSAGE_APP_DISABLE_FORBIDDEN;
        }
    }
    return CreateError(env, err, errMessage);
}
} // AppExecFwk
} // OHOS
