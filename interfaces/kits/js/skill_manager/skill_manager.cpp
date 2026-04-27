/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "skill_manager.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "napi/native_api.h"
#include "skill_manager_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SKILL_NAME = "skillName";
constexpr const char* SKILL_TYPE = "skillType";
constexpr const char* SKILL_PATH = "skillPath";
constexpr const char* VERSION_CODE = "versionCode";
constexpr const char* DESCRIPTION = "description";
constexpr const char* SRC_ENTRIES = "srcEntries";
constexpr const char* PERMISSIONS = "permissions";
constexpr const char* REQUEST_PERMISSIONS = "requestPermissions";
constexpr const char* GET_SKILL_INFO_FOR_SELF = "getSkillInfoForSelf";
constexpr const char* GET_SKILL_INFOS_FOR_SELF = "getSkillInfosForSelf";
constexpr const char* GET_SKILL_INFO = "getSkillInfo";
constexpr const char* GET_SKILL_INFOS = "getSkillInfos";
constexpr const char* GET_ALL_SKILL_INFOS = "getAllSkillInfos";
constexpr const char* GET_SKILL_INFO_DEFAULT = "GET_SKILL_INFO_DEFAULT";
constexpr const char* GET_SKILL_INFO_WITH_DESCRIPTION = "GET_SKILL_INFO_WITH_DESCRIPTION";
constexpr const char* GET_SKILL_INFO_WITH_SRC_ENTRIES = "GET_SKILL_INFO_WITH_SRC_ENTRIES";
constexpr const char* GET_SKILL_INFO_WITH_PERMISSIONS = "GET_SKILL_INFO_WITH_PERMISSIONS";
constexpr const char* GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS = "GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS";

static void ConvertSkillInfo(napi_env env, const SkillInfo &skillInfo, napi_value objSkillInfo,
    uint32_t flags)
{
    APP_LOGD("start");
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, skillInfo.bundleName.c_str(),
        NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, BUNDLE_NAME, nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, skillInfo.moduleName.c_str(),
        NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, MODULE_NAME, nModuleName));

    napi_value nSkillName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, skillInfo.skillName.c_str(),
        NAPI_AUTO_LENGTH, &nSkillName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, SKILL_NAME, nSkillName));

    napi_value nSkillType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(skillInfo.skillType), &nSkillType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, SKILL_TYPE, nSkillType));

    napi_value nSkillPath;
    std::string sandboxSkillPath = skillInfo.skillPath;
    if (sandboxSkillPath.compare(0, strlen(Constants::REAL_SKILL_PATH_PREFIX),
        Constants::REAL_SKILL_PATH_PREFIX) == 0) {
        sandboxSkillPath.replace(0, strlen(Constants::REAL_SKILL_PATH_PREFIX), Constants::SANDBOX_SKILL_PATH_PREFIX);
    }
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, sandboxSkillPath.c_str(),
        NAPI_AUTO_LENGTH, &nSkillPath));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, SKILL_PATH, nSkillPath));

    napi_value nVersionCode;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(skillInfo.versionCode), &nVersionCode));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, VERSION_CODE, nVersionCode));

    napi_value nAbilityName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, skillInfo.abilityName.c_str(),
        NAPI_AUTO_LENGTH, &nAbilityName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, ABILITY_NAME, nAbilityName));

    napi_value nDescription;
    if ((flags & static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_DESCRIPTION)) ==
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_DESCRIPTION)) {
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, skillInfo.description.c_str(),
            NAPI_AUTO_LENGTH, &nDescription));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &nDescription));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, DESCRIPTION, nDescription));

    napi_value nSrcEntries;
    if ((flags & static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES)) ==
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES)) {
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nSrcEntries));
        for (size_t i = 0; i < skillInfo.srcEntries.size(); ++i) {
            napi_value nEntry;
            NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, skillInfo.srcEntries[i].c_str(),
                NAPI_AUTO_LENGTH, &nEntry));
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nSrcEntries, i, nEntry));
        }
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &nSrcEntries));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, SRC_ENTRIES, nSrcEntries));

    napi_value nPermissions;
    if ((flags & static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS)) ==
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS)) {
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nPermissions));
        for (size_t i = 0; i < skillInfo.permissions.size(); ++i) {
            napi_value nPermission;
            NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, skillInfo.permissions[i].c_str(),
                NAPI_AUTO_LENGTH, &nPermission));
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nPermissions, i, nPermission));
        }
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &nPermissions));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, PERMISSIONS, nPermissions));

    napi_value nRequestPermissions;
    if ((flags & static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS)) ==
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS)) {
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nRequestPermissions));
        for (size_t i = 0; i < skillInfo.requestPermissions.size(); ++i) {
            napi_value nReqPermission;
            NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, skillInfo.requestPermissions[i].c_str(),
                NAPI_AUTO_LENGTH, &nReqPermission));
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nRequestPermissions, i, nReqPermission));
        }
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &nRequestPermissions));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objSkillInfo, REQUEST_PERMISSIONS, nRequestPermissions));
    APP_LOGD("end");
}

static void ConvertSkillInfos(napi_env env, const std::vector<SkillInfo> &skillInfos, napi_value arrSkillInfos,
    uint32_t flags)
{
    for (size_t index = 0; index < skillInfos.size(); ++index) {
        napi_value objSkillInfo = nullptr;
        napi_create_object(env, &objSkillInfo);
        ConvertSkillInfo(env, skillInfos[index], objSkillInfo, flags);
        napi_set_element(env, arrSkillInfos, index, objSkillInfo);
    }
}

void GetSkillInfoForSelfExec(napi_env env, void *data)
{
    SkillInfoCallback *asyncCallbackInfo = reinterpret_cast<SkillInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = SkillManagerHelper::InnerGetSkillInfoForSelf(
        asyncCallbackInfo->moduleName, asyncCallbackInfo->skillName,
        asyncCallbackInfo->flags, asyncCallbackInfo->skillInfo);
}

void GetSkillInfoForSelfComplete(napi_env env, napi_status status, void *data)
{
    SkillInfoCallback *asyncCallbackInfo = reinterpret_cast<SkillInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<SkillInfoCallback> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        ConvertSkillInfo(env, asyncCallbackInfo->skillInfo, result[1], asyncCallbackInfo->flags);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_SKILL_INFO_FOR_SELF, "");
    }
    CommonFunc::NapiReturnDeferred<SkillInfoCallback>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}
} // namespace

napi_value GetSkillInfoForSelf(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    SkillInfoCallback *asyncCallbackInfo = new (std::nothrow) SkillInfoCallback(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<SkillInfoCallback> callbackPtr {asyncCallbackInfo};

    std::string moduleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], moduleName)) {
        APP_LOGE("parse moduleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string skillName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], skillName)) {
        APP_LOGE("parse skillName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, SKILL_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_TWO], flags)) {
        APP_LOGE("parse flags failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, "flags", TYPE_NUMBER);
        return nullptr;
    }
    if (flags < 0) {
        flags = static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_DEFAULT);
    }
    asyncCallbackInfo->moduleName = moduleName;
    asyncCallbackInfo->skillName = skillName;
    asyncCallbackInfo->flags = static_cast<uint32_t>(flags);

    auto promise = CommonFunc::AsyncCallNativeMethod<SkillInfoCallback>(
        env, asyncCallbackInfo, GET_SKILL_INFO_FOR_SELF, GetSkillInfoForSelfExec,
        GetSkillInfoForSelfComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void GetSkillInfosForSelfExec(napi_env env, void *data)
{
    SkillInfosCallback *asyncCallbackInfo = reinterpret_cast<SkillInfosCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = SkillManagerHelper::InnerGetSkillInfosForSelf(
        asyncCallbackInfo->flags, asyncCallbackInfo->skillInfos);
}

void GetSkillInfosForSelfComplete(napi_env env, napi_status status, void *data)
{
    SkillInfosCallback *asyncCallbackInfo = reinterpret_cast<SkillInfosCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<SkillInfosCallback> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        ConvertSkillInfos(env, asyncCallbackInfo->skillInfos, result[1], asyncCallbackInfo->flags);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_SKILL_INFOS_FOR_SELF, "");
    }
    CommonFunc::NapiReturnDeferred<SkillInfosCallback>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetSkillInfosForSelf(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    SkillInfosCallback *asyncCallbackInfo = new (std::nothrow) SkillInfosCallback(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<SkillInfosCallback> callbackPtr {asyncCallbackInfo};
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], flags)) {
        APP_LOGE("parse flags failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, "flags", TYPE_NUMBER);
        return nullptr;
    }
    if (flags < 0) {
        flags = static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_DEFAULT);
    }
    asyncCallbackInfo->flags = static_cast<uint32_t>(flags);
    auto promise = CommonFunc::AsyncCallNativeMethod<SkillInfosCallback>(
        env, asyncCallbackInfo, GET_SKILL_INFOS_FOR_SELF, GetSkillInfosForSelfExec,
        GetSkillInfosForSelfComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void GetSkillInfoExec(napi_env env, void *data)
{
    GetSkillInfoCallback *asyncCallbackInfo = reinterpret_cast<GetSkillInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = SkillManagerHelper::InnerGetSkillInfo(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleName, asyncCallbackInfo->skillName,
        asyncCallbackInfo->flags, asyncCallbackInfo->userId, asyncCallbackInfo->skillInfo);
}

void GetSkillInfoComplete(napi_env env, napi_status status, void *data)
{
    GetSkillInfoCallback *asyncCallbackInfo = reinterpret_cast<GetSkillInfoCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetSkillInfoCallback> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        ConvertSkillInfo(env, asyncCallbackInfo->skillInfo, result[1], asyncCallbackInfo->flags);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_SKILL_INFO, Constants::PERMISSION_MANAGE_SKILL_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS);
    }
    CommonFunc::NapiReturnDeferred<GetSkillInfoCallback>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetSkillInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_FOUR, ARGS_SIZE_FIVE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetSkillInfoCallback *asyncCallbackInfo = new (std::nothrow) GetSkillInfoCallback(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetSkillInfoCallback> callbackPtr {asyncCallbackInfo};
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string moduleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], moduleName)) {
        APP_LOGE("parse moduleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string skillName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_TWO], skillName)) {
        APP_LOGE("parse skillName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, SKILL_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_THREE], flags)) {
        APP_LOGE("parse flags failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, "flags", TYPE_NUMBER);
        return nullptr;
    }
    if (flags < 0) {
        flags = static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_DEFAULT);
    }
    asyncCallbackInfo->bundleName = bundleName;
    asyncCallbackInfo->moduleName = moduleName;
    asyncCallbackInfo->skillName = skillName;
    asyncCallbackInfo->flags = static_cast<uint32_t>(flags);
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() >= ARGS_SIZE_FIVE) {
        int32_t userId = 0;
        if (CommonFunc::ParseInt(env, args[ARGS_POS_FOUR], userId)) {
            asyncCallbackInfo->userId = userId;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetSkillInfoCallback>(
        env, asyncCallbackInfo, GET_SKILL_INFO, GetSkillInfoExec, GetSkillInfoComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void GetSkillInfosExec(napi_env env, void *data)
{
    GetSkillInfosCallback *asyncCallbackInfo = reinterpret_cast<GetSkillInfosCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = SkillManagerHelper::InnerGetSkillInfos(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->flags, asyncCallbackInfo->userId,
        asyncCallbackInfo->skillInfos);
}

void GetSkillInfosComplete(napi_env env, napi_status status, void *data)
{
    GetSkillInfosCallback *asyncCallbackInfo = reinterpret_cast<GetSkillInfosCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetSkillInfosCallback> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        ConvertSkillInfos(env, asyncCallbackInfo->skillInfos, result[1], asyncCallbackInfo->flags);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_SKILL_INFOS, Constants::PERMISSION_MANAGE_SKILL_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS);
    }
    CommonFunc::NapiReturnDeferred<GetSkillInfosCallback>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetSkillInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetSkillInfosCallback *asyncCallbackInfo = new (std::nothrow) GetSkillInfosCallback(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetSkillInfosCallback> callbackPtr {asyncCallbackInfo};
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], flags)) {
        APP_LOGE("parse flags failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, "flags", TYPE_NUMBER);
        return nullptr;
    }
    if (flags < 0) {
        flags = static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_DEFAULT);
    }
    asyncCallbackInfo->bundleName = bundleName;
    asyncCallbackInfo->flags = static_cast<uint32_t>(flags);
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        int32_t userId = 0;
        if (CommonFunc::ParseInt(env, args[ARGS_POS_TWO], userId)) {
            asyncCallbackInfo->userId = userId;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetSkillInfosCallback>(
        env, asyncCallbackInfo, GET_SKILL_INFOS, GetSkillInfosExec, GetSkillInfosComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void GetAllSkillInfosExec(napi_env env, void *data)
{
    SkillInfosCallback *asyncCallbackInfo = reinterpret_cast<SkillInfosCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = SkillManagerHelper::InnerGetAllSkillInfos(
        asyncCallbackInfo->flags, asyncCallbackInfo->userId, asyncCallbackInfo->skillInfos);
}

void GetAllSkillInfosComplete(napi_env env, napi_status status, void *data)
{
    SkillInfosCallback *asyncCallbackInfo = reinterpret_cast<SkillInfosCallback *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<SkillInfosCallback> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        ConvertSkillInfos(env, asyncCallbackInfo->skillInfos, result[1], asyncCallbackInfo->flags);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_SKILL_INFOS, Constants::PERMISSION_MANAGE_SKILL_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS);
    }
    CommonFunc::NapiReturnDeferred<SkillInfosCallback>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllSkillInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    SkillInfosCallback *asyncCallbackInfo = new (std::nothrow) SkillInfosCallback(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<SkillInfosCallback> callbackPtr {asyncCallbackInfo};
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], flags)) {
        APP_LOGE("parse flags failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, "flags", TYPE_NUMBER);
        return nullptr;
    }
    if (flags < 0) {
        flags = static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_DEFAULT);
    }
    asyncCallbackInfo->flags = static_cast<uint32_t>(flags);
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        int32_t userId = 0;
        if (CommonFunc::ParseInt(env, args[ARGS_POS_ONE], userId)) {
            asyncCallbackInfo->userId = userId;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<SkillInfosCallback>(
        env, asyncCallbackInfo, GET_ALL_SKILL_INFOS, GetAllSkillInfosExec, GetAllSkillInfosComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void CreateSkillInfoFlagObject(napi_env env, napi_value value)
{
    napi_value nGetDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_DEFAULT), &nGetDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, GET_SKILL_INFO_DEFAULT, nGetDefault));

    napi_value nGetDescription;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_DESCRIPTION), &nGetDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, GET_SKILL_INFO_WITH_DESCRIPTION, nGetDescription));

    napi_value nGetSrcEntries;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES), &nGetSrcEntries));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, GET_SKILL_INFO_WITH_SRC_ENTRIES, nGetSrcEntries));

    napi_value nGetPermissions;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS), &nGetPermissions));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, GET_SKILL_INFO_WITH_PERMISSIONS, nGetPermissions));

    napi_value nGetRequestPermissions;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS), &nGetRequestPermissions));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value,
        GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS, nGetRequestPermissions));
}

} // namespace AppExecFwk
} // namespace OHOS
