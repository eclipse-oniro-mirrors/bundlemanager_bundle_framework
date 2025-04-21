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
#include <ani.h>
#include <unordered_map>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "business_error_map.h"
#include "napi_constants.h"
#include "common_fun_ani.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUSINESS_ERROR_CLASS = "L@ohos/base/BusinessError;";
} // namespace
    
void BusinessErrorAni::ThrowError(ani_env *env, int32_t err, const std::string &msg)
{
    if (env == nullptr) {
        return;
    }
    ani_object error = CreateError(env, err, msg);
    ThrowError(env, error);
}

ani_object BusinessErrorAni::WrapError(ani_env *env, const std::string &msg)
{
    if (env == nullptr) {
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_method method = nullptr;
    ani_object obj = nullptr;

    ani_string aniMsg = nullptr;
    if (!CommonFunAni::StringToAniStr(env, msg, aniMsg)) {
        APP_LOGE("StringToAniStr failed");
        return nullptr;
    }

    ani_ref undefRef;
    env->GetUndefined(&undefRef);

    ani_status status = env->FindClass("Lescompat/Error;", &cls);
    if (status != ANI_OK) {
        APP_LOGE("FindClass : %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method);
    if (status != ANI_OK) {
        APP_LOGE("Class_FindMethod : %{public}d", status);
        return nullptr;
    }
    status = env->Object_New(cls, method, &obj, aniMsg, undefRef);
    if (status != ANI_OK) {
        APP_LOGE("Object_New : %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_object BusinessErrorAni::CreateError(ani_env *env, int32_t code, const std::string& msg)
{
    if (env == nullptr) {
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_method method = nullptr;
    ani_object obj = nullptr;
    ani_status status = env->FindClass(BUSINESS_ERROR_CLASS, &cls);
    if (status != ANI_OK) {
        APP_LOGE("FindClass : %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindMethod(cls, "<ctor>", "DLescompat/Error;:V", &method);
    if (status != ANI_OK) {
        APP_LOGE("Class_FindMethod : %{public}d", status);
        return nullptr;
    }
    ani_object error = WrapError(env, msg);
    if (error == nullptr) {
        APP_LOGE("WrapError failed");
        return nullptr;
    }
    ani_double dCode(code);
    status = env->Object_New(cls, method, &obj, dCode, error);
    if (status != ANI_OK) {
        APP_LOGE("Object_New : %{public}d", status);
        return nullptr;
    }
    return obj;
}

void BusinessErrorAni::ThrowCommonError(ani_env *env, int32_t err,
    const std::string &parameter, const std::string &type)
{
    if (env == nullptr) {
        return;
    }
    ani_object error = CreateCommonError(env, err, parameter, type);
    ThrowError(env, error);
}

void BusinessErrorAni::ThrowTooFewParametersError(ani_env *env, int32_t err)
{
    if (env == nullptr) {
        return;
    }
    ThrowError(env, err, BussinessErrorNS::ERR_MSG_PARAM_NUMBER_ERROR);
}

ani_object BusinessErrorAni::CreateCommonError(
    ani_env *env, int32_t err, const std::string &functionName, const std::string &permissionName)
{
    if (env == nullptr) {
        return nullptr;
    }
    std::string errMessage = BussinessErrorNS::ERR_MSG_BUSINESS_ERROR;
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

void BusinessErrorAni::ThrowEnumError(ani_env *env,
    const std::string &parameter, const std::string &type)
{
    if (env == nullptr) {
        return;
    }
    ani_object error = CreateEnumError(env, parameter, type);
    ThrowError(env, error);
}

ani_object BusinessErrorAni::CreateEnumError(ani_env *env,
    const std::string &parameter, const std::string &enumClass)
{
    if (env == nullptr) {
        return nullptr;
    }
    std::string errMessage = BussinessErrorNS::ERR_MSG_BUSINESS_ERROR;
    auto iter = errMessage.find("$");
    if (iter != std::string::npos) {
        errMessage = errMessage.replace(iter, 1, std::to_string(ERROR_PARAM_CHECK_ERROR));
    }
    errMessage += BussinessErrorNS::ERR_MSG_ENUM_ERROR;
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

void BusinessErrorAni::ThrowError(ani_env *env, ani_object err)
{
    if (err == nullptr) {
        APP_LOGE("err is nullptr");
        return;
    }
    env->ThrowError(static_cast<ani_error>(err));
}
} // namespace AppExecFwk
} // namespace OHOS