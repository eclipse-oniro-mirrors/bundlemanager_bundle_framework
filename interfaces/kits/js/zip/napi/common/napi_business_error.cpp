/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_business_error.h"

#include <cstring>
#include <string>
#include <unordered_map>

#include "app_log_wrapper.h"
#include "napi_value.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {

static napi_value GenerateBusinessError(napi_env env, int32_t errCode, std::string errMsg)
{
    napi_value businessError = nullptr;
    napi_value code = nullptr;
    napi_value msg = nullptr;
    code = NapiValue::CreateInt32(env, errCode).val_;
    msg = NapiValue::CreateUTF8String(env, errMsg).val_;
    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, ZLIB_TAG_ERR_CODE.c_str(), code);
    napi_set_named_property(env, businessError, ZLIB_TAG_ERR_MSG.c_str(), msg);
    return businessError;
}

NapiBusinessError::NapiBusinessError()
{}

NapiBusinessError::NapiBusinessError(ELegacy eLegacy) : errno_(eLegacy), codingSystem_(ERR_CODE_SYSTEM_LEGACY)
{}

NapiBusinessError::NapiBusinessError(int32_t ePosix) : errno_(ePosix), codingSystem_(ERR_CODE_SYSTEM_POSIX)
{}

NapiBusinessError::NapiBusinessError(int32_t ePosix, bool throwCode)
    : errno_(ePosix), codingSystem_(ERR_CODE_SYSTEM_POSIX), throwCode_(throwCode)
{}

NapiBusinessError::operator bool() const
{
    return errno_ != ERRNO_NOERR;
}

int32_t NapiBusinessError::GetErrno(ErrCodeSystem cs)
{
    if (errno_ == ERRNO_NOERR) {
        return ERRNO_NOERR;
    }

    if (cs == codingSystem_) {
        return errno_;
    }

    if (cs == ERR_CODE_SYSTEM_POSIX) {
        // Note that we should support more codes here
        return EINVAL;
    }

    // Note that this shall be done properly
    return ELEGACY_INVAL;
}

void NapiBusinessError::SetErrno(ELegacy eLegacy)
{
    errno_ = eLegacy;
    codingSystem_ = ERR_CODE_SYSTEM_LEGACY;
}

void NapiBusinessError::SetErrno(int32_t ePosix)
{
    errno_ = ePosix;
    codingSystem_ = ERR_CODE_SYSTEM_POSIX;
}

std::string NapiBusinessError::GetDefaultErrstr()
{
    if (codingSystem_ != ERR_CODE_SYSTEM_POSIX && codingSystem_ != ERR_CODE_SYSTEM_LEGACY) {
        return "BUG: Curious coding system";
    }
    return strerror(GetErrno(ERR_CODE_SYSTEM_POSIX));
}

napi_value NapiBusinessError::GetNapiErr(napi_env env)
{
    int32_t errCode = GetErrno(codingSystem_);
    if (errCode == ERRNO_NOERR) {
        return nullptr;
    }
    if (!throwCode_) {
        return GetNapiErr(env, GetDefaultErrstr());
    }
    int32_t code = 0;
    std::string msg;
    if (errCodeTable.find(errCode) != errCodeTable.end()) {
        code = errCodeTable.at(errCode).first;
        msg = errCodeTable.at(errCode).second;
    } else {
        code = errCodeTable.at(ENOSTR).first;
        msg = errCodeTable.at(ENOSTR).second;
    }
    return GenerateBusinessError(env, code, msg);
}

napi_value NapiBusinessError::GetNapiErr(napi_env env, const std::string &errMsg)
{
    napi_value msg = NapiValue::CreateUTF8String(env, errMsg).val_;
    napi_value res = nullptr;
    napi_status createRes = napi_create_error(env, nullptr, msg, &res);
    if (createRes) {
        APP_LOGE("Failed to create an exception, errMsg = %{public}s", errMsg.c_str());
    }
    return res;
}

void NapiBusinessError::ThrowErr(napi_env env)
{
    napi_value tmp = nullptr;
    napi_get_and_clear_last_exception(env, &tmp);
    int32_t code = 0;
    std::string msg;
    napi_status throwStatus = napi_ok;
    if (errCodeTable.find(errno_) != errCodeTable.end()) {
        code = errCodeTable.at(errno_).first;
        msg = errCodeTable.at(errno_).second;
    } else {
        code = errCodeTable.at(ENOSTR).first;
        msg = errCodeTable.at(ENOSTR).second;
    }
    if (!throwCode_) {
        throwStatus = napi_throw_error(env, nullptr, msg.c_str());
    } else {
        throwStatus = napi_throw(env, GenerateBusinessError(env, code, msg));
    }

    if (throwStatus != napi_ok) {
        APP_LOGE("Failed to throw an exception, code = %{public}d, msg = %{public}s", throwStatus, msg.c_str());
    }
}

void NapiBusinessError::ThrowErr(napi_env env, int32_t code)
{
    napi_value tmp = nullptr;
    napi_get_and_clear_last_exception(env, &tmp);
    if (errCodeTable.find(code) == errCodeTable.end()) {
        code = ENOSTR;
    }
    napi_status throwStatus =
        napi_throw(env, GenerateBusinessError(env, errCodeTable.at(code).first, errCodeTable.at(code).second));
    if (throwStatus != napi_ok) {
        APP_LOGE("Failed to throw an exception, %{public}d, errMsg = %{public}s",
            throwStatus,
            errCodeTable.at(code).second.c_str());
    }
}

void NapiBusinessError::ThrowErr(napi_env env, const std::string &errMsg)
{
    napi_value tmp = nullptr;
    napi_get_and_clear_last_exception(env, &tmp);
    // Note that ace engine cannot throw errors created by napi_create_error so far
    napi_status throwStatus = napi_throw_error(env, nullptr, errMsg.c_str());
    if (throwStatus != napi_ok) {
        APP_LOGE("Failed to throw an exception, %{public}d, errMsg = %{public}s", throwStatus, errMsg.c_str());
    }
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS