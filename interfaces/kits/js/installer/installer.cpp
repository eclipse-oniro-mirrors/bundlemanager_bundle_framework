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

#include <unordered_map>

#include "installer.h"

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_death_recipient.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "common_func.h"
#include "if_system_ability_manager.h"
#include "installer_callback.h"
#include "installer_helper.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// resource name
const char* EMPTY_STRING = "";
// install message
constexpr const char* FUNCTION_TYPE = "napi_function";
constexpr const char* CALLBACK = "callback";
// property name
const char* INSTALL_FLAG = "installFlag";
const char* IS_KEEP_DATA = "isKeepData";
const char* CROWD_TEST_DEADLINE = "crowdtestDeadline";
const char* HASH_VALUE = "hashValue";
const char* HASH_PARAMS = "hashParams";
const char* VERSION_CODE = "versionCode";
const char* SHARED_BUNDLE_DIR_PATHS = "sharedBundleDirPaths";
const char* SPECIFIED_DISTRIBUTION_TYPE = "specifiedDistributionType";
const char* VERIFY_CODE_PARAM = "verifyCodeParams";
const char* SIGNATURE_FILE_PATH = "signatureFilePath";
const char* PGO_PARAM = "pgoParams";
const char* PGO_FILE_PATH = "pgoFilePath";
const char* KEY = "key";
const char* VALUE = "value";
constexpr int32_t FIRST_PARAM = 0;
constexpr int32_t SECOND_PARAM = 1;

constexpr int32_t ILLEGAL_APP_INDEX = -1;
} // namespace
napi_ref thread_local g_classBundleInstaller;
bool g_isSystemApp = false;

AsyncInstallCallbackInfo::~AsyncInstallCallbackInfo()
{
    if (callback) {
        napi_delete_reference(env, callback);
        callback = nullptr;
    }
    if (asyncWork) {
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }
}

AsyncGetBundleInstallerCallbackInfo::~AsyncGetBundleInstallerCallbackInfo()
{
    if (callback) {
        napi_delete_reference(env, callback);
        callback = nullptr;
    }
    if (asyncWork) {
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }
}

void GetBundleInstallerCompleted(napi_env env, napi_status status, void *data)
{
    AsyncGetBundleInstallerCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<AsyncGetBundleInstallerCallbackInfo *>(data);
    std::unique_ptr<AsyncGetBundleInstallerCallbackInfo> callbackPtr {asyncCallbackInfo};

    napi_value m_classBundleInstaller = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, g_classBundleInstaller,
        &m_classBundleInstaller));
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return;
    }
    if (!g_isSystemApp && !iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        result[0] = BusinessError::CreateCommonError(
            env, ERROR_NOT_SYSTEM_APP, RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER, INSTALL_PERMISSION);
        if (callbackPtr->deferred) {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        } else {
            napi_value callback = nullptr;
            napi_value placeHolder = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
            NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
                sizeof(result) / sizeof(result[0]), result, &placeHolder));
        }
        return;
    }
    g_isSystemApp = true;
    NAPI_CALL_RETURN_VOID(env, napi_new_instance(env, m_classBundleInstaller, 0, nullptr, &result[SECOND_PARAM]));

    if (callbackPtr->deferred) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, callbackPtr->deferred, result[SECOND_PARAM]));
    } else {
        napi_value callback = CommonFunc::WrapVoidToJS(env);
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, callbackPtr->callback, &callback));
        napi_value undefined = CommonFunc::WrapVoidToJS(env);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        napi_value callResult = CommonFunc::WrapVoidToJS(env);
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, CALLBACK_PARAM_SIZE,
            &result[FIRST_PARAM], &callResult));
    }
}

/**
 * Promise and async callback
 */
napi_value GetBundleInstaller(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi GetBundleInstaller called");
    NapiArg args(env, info);
    if (!args.Init(FIRST_PARAM, SECOND_PARAM)) {
        APP_LOGE("GetBundleInstaller args init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::unique_ptr<AsyncGetBundleInstallerCallbackInfo> callbackPtr =
        std::make_unique<AsyncGetBundleInstallerCallbackInfo>(env);

    auto argc = args.GetMaxArgc();
    APP_LOGD("GetBundleInstaller argc = [%{public}zu]", argc);
    // check param
    if (argc == SECOND_PARAM) {
        napi_value arg = args.GetArgv(argc - SECOND_PARAM);
        if (arg == nullptr) {
            APP_LOGE("the param is nullptr");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, arg, &valuetype));
        if (valuetype != napi_function) {
            APP_LOGE("the param type is invalid");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, CALLBACK, FUNCTION_TYPE);
            return nullptr;
        }
        NAPI_CALL(env, napi_create_reference(env, arg, NAPI_RETURN_ONE, &callbackPtr->callback));
    }

    auto executeFunc = [](napi_env env, void *data) {};
    napi_value promise = CommonFunc::AsyncCallNativeMethod(
        env,
        callbackPtr.get(),
        RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER,
        executeFunc,
        GetBundleInstallerCompleted);
    callbackPtr.release();
    APP_LOGI_NOFUNC("call GetBundleInstaller done");
    return promise;
}

napi_value GetBundleInstallerSync(napi_env env, napi_callback_info info)
{
    APP_LOGI("NAPI GetBundleInstallerSync called");
    napi_value m_classBundleInstaller = nullptr;
    NAPI_CALL(env, napi_get_reference_value(env, g_classBundleInstaller,
        &m_classBundleInstaller));
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return nullptr;
    }
    if (!g_isSystemApp && !iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_NOT_SYSTEM_APP, RESOURCE_NAME_OF_GET_BUNDLE_INSTALLER_SYNC, INSTALL_PERMISSION);
        napi_throw(env, businessError);
        return nullptr;
    }
    g_isSystemApp = true;
    napi_value nBundleInstaller = nullptr;
    NAPI_CALL(env, napi_new_instance(env, m_classBundleInstaller, 0, nullptr, &nBundleInstaller));
    APP_LOGD("call GetBundleInstallerSync done");
    return nBundleInstaller;
    APP_LOGI("call GetBundleInstallerSync done");
}

static bool ParseHashParam(napi_env env, napi_value args, std::string &key, std::string &value)
{
    APP_LOGD("start to parse moduleName");
    bool ret = CommonFunc::ParseStringPropertyFromObject(env, args, MODULE_NAME, true, key);
    if (!ret || key.empty()) {
        APP_LOGE("param string moduleName is empty");
        return false;
    }
    APP_LOGD("ParseHashParam moduleName=%{public}s", key.c_str());

    APP_LOGD("start to parse hashValue");
    ret = CommonFunc::ParseStringPropertyFromObject(env, args, HASH_VALUE, true, value);
    if (!ret || value.empty()) {
        APP_LOGE("param string hashValue is empty");
        return false;
    }
    APP_LOGD("ParseHashParam hashValue=%{public}s", value.c_str());
    return true;
}

static bool ParseHashParams(napi_env env, napi_value args, std::map<std::string, std::string> &hashParams)
{
    APP_LOGD("start to parse hashParams");
    std::vector<napi_value> valueVec;
    bool res = CommonFunc::ParsePropertyArray(env, args, HASH_PARAMS, valueVec);
    if (!res) {
        APP_LOGW("hashParams type error,using default value");
        return true;
    }
    if (valueVec.empty()) {
        APP_LOGW("hashParams is empty,using default value");
        return true;
    }
    for (const auto &property : valueVec) {
        std::string key;
        std::string value;
        if (!ParseHashParam(env, property, key, value)) {
            APP_LOGE("parse hash param failed");
            return false;
        }
        if (hashParams.find(key) != hashParams.end()) {
            APP_LOGE("moduleName(%{public}s) is duplicate", key.c_str());
            return false;
        }
        hashParams.emplace(key, value);
    }
    return true;
}

static bool ParseVerifyCodeParam(napi_env env, napi_value args, std::string &key, std::string &value)
{
    APP_LOGD("start to parse moduleName");
    bool ret = CommonFunc::ParseStringPropertyFromObject(env, args, MODULE_NAME, true, key);
    if (!ret || key.empty()) {
        APP_LOGE("param string moduleName is empty");
        return false;
    }
    APP_LOGD("ParseVerifyCodeParam moduleName is %{public}s", key.c_str());

    APP_LOGD("start to parse signatureFilePath");
    ret = CommonFunc::ParseStringPropertyFromObject(env, args, SIGNATURE_FILE_PATH, true, value);
    if (!ret || value.empty()) {
        APP_LOGE("param string signatureFilePath is empty");
        return false;
    }
    APP_LOGD("ParseVerifyCodeParam signatureFilePath is %{public}s", value.c_str());
    return true;
}

static bool ParseVerifyCodeParams(napi_env env, napi_value args, std::map<std::string, std::string> &verifyCodeParams)
{
    APP_LOGD("start to parse verifyCodeParams");
    std::vector<napi_value> valueVec;
    bool res = CommonFunc::ParsePropertyArray(env, args, VERIFY_CODE_PARAM, valueVec);
    if (!res) {
        APP_LOGW("verifyCodeParams type error, using default value");
        return true;
    }
    if (valueVec.empty()) {
        APP_LOGW("verifyCodeParams is empty, using default value");
        return true;
    }
    for (const auto &property : valueVec) {
        std::string key;
        std::string value;
        if (!ParseVerifyCodeParam(env, property, key, value)) {
            APP_LOGE("parse verify code param failed");
            return false;
        }
        if (verifyCodeParams.find(key) != verifyCodeParams.end()) {
            APP_LOGE("moduleName(%{public}s) is duplicate", key.c_str());
            return false;
        }
        verifyCodeParams.emplace(key, value);
    }
    return true;
}

static bool ParseParameter(napi_env env, napi_value args, std::string &key, std::string &value)
{
    APP_LOGD("start to parse parameter");
    bool ret = CommonFunc::ParseStringPropertyFromObject(env, args, KEY, true, key);
    if (!ret || key.empty()) {
        APP_LOGE("param key is empty");
        return false;
    }
    APP_LOGD("ParseParameter key is %{public}s", key.c_str());

    APP_LOGD("start to parse value");
    ret = CommonFunc::ParseStringPropertyFromObject(env, args, VALUE, true, value);
    if (!ret || value.empty()) {
        APP_LOGE("param value is empty");
        return false;
    }
    APP_LOGD("ParseParameter value is %{public}s", value.c_str());
    return true;
}

static bool ParseParameters(napi_env env, napi_value args, std::map<std::string, std::string> &parameters)
{
    APP_LOGD("start to parse parameters");
    std::vector<napi_value> valueVec;
    bool res = CommonFunc::ParsePropertyArray(env, args, PARAMETERS, valueVec);
    if (!res) {
        APP_LOGW("parameters type error, using default value");
        return true;
    }
    if (valueVec.empty()) {
        APP_LOGW("parameters is empty, using default value");
        return true;
    }
    for (const auto &property : valueVec) {
        std::string key;
        std::string value;
        if (!ParseParameter(env, property, key, value)) {
            APP_LOGE("parse parameter failed");
            return false;
        }
        if (parameters.find(key) != parameters.end()) {
            APP_LOGE("key(%{public}s) is duplicate", key.c_str());
            return false;
        }
        parameters.emplace(key, value);
    }
    return true;
}

static bool ParsePgoParam(napi_env env, napi_value args, std::string &key, std::string &value)
{
    APP_LOGD("start to parse moduleName");
    bool ret = CommonFunc::ParseStringPropertyFromObject(env, args, MODULE_NAME, true, key);
    if (!ret || key.empty()) {
        APP_LOGE("param string moduleName is empty");
        return false;
    }
    APP_LOGD("ParsePgoParam moduleName is %{public}s", key.c_str());

    APP_LOGD("start to parse pgoFilePath");
    ret = CommonFunc::ParseStringPropertyFromObject(env, args, PGO_FILE_PATH, true, value);
    if (!ret || value.empty()) {
        APP_LOGE("param string pgoFilePath is empty");
        return false;
    }
    APP_LOGD("ParsePgoParam pgoFilePath is %{public}s", value.c_str());
    return true;
}

static bool ParsePgoParams(napi_env env, napi_value args, std::map<std::string, std::string> &pgoParams)
{
    APP_LOGD("start to parse pgoParams");
    std::vector<napi_value> valueVec;
    bool res = CommonFunc::ParsePropertyArray(env, args, PGO_PARAM, valueVec);
    if (!res) {
        APP_LOGW("pgoParams type error, using default value");
        return true;
    }
    if (valueVec.empty()) {
        APP_LOGW("pgoParams is empty, using default value");
        return true;
    }
    for (const auto &property : valueVec) {
        std::string key;
        std::string value;
        if (!ParsePgoParam(env, property, key, value)) {
            APP_LOGW("parse pgo param failed");
            continue;
        }
        pgoParams.emplace(key, value);
    }
    return true;
}

static bool ParseBundleName(napi_env env, napi_value args, std::string &bundleName)
{
    APP_LOGD("start to parse bundleName");
    PropertyInfo propertyInfo = {
        .isNecessary = true,
        .propertyType = napi_string,
        .propertyName = BUNDLE_NAME
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse bundleName failed, bundleName is %{public}s", bundleName.c_str());
        return res;
    }
    if (property != nullptr) {
        if (!CommonFunc::ParseString(env, property, bundleName)) {
            APP_LOGE("ParseString failed");
            return false;
        }
    }
    APP_LOGD("param bundleName is %{public}s", bundleName.c_str());
    return true;
}

static bool ParseModuleName(napi_env env, napi_value args, std::string &moduleName)
{
    APP_LOGD("start to parse moduleName");
    PropertyInfo propertyInfo = {
        .isNecessary = false,
        .propertyType = napi_string,
        .propertyName = MODULE_NAME
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse moduleName failed");
        return res;
    }
    if (property != nullptr) {
        if (!CommonFunc::ParseString(env, property, moduleName)) {
            APP_LOGE("ParseString failed");
            return false;
        }
    }
    return true;
}

static bool ParseVersionCode(napi_env env, napi_value args, int32_t &versionCode)
{
    APP_LOGD("start to parse versionCode");
    PropertyInfo propertyInfo = {
        .isNecessary = false,
        .propertyType = napi_number,
        .propertyName = VERSION_CODE
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse versionCode failed");
        return res;
    }
    if (property != nullptr) {
        PARSE_PROPERTY(env, property, int32, versionCode);
    }
    APP_LOGD("param versionCode is %{public}d", versionCode);
    return true;
}

static bool ParseUserId(napi_env env, napi_value args, int32_t &userId)
{
    APP_LOGD("start to parse userId");
    PropertyInfo propertyInfo = {
        .isNecessary = false,
        .propertyType = napi_number,
        .propertyName = USER_ID
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse userId failed");
        return res;
    }
    if (property != nullptr) {
        PARSE_PROPERTY(env, property, int32, userId);
    }
    APP_LOGD("param userId is %{public}d", userId);
    return true;
}

static bool ParseAppIndex(napi_env env, napi_value args, int32_t &appIndex)
{
    APP_LOGD("start to parse appIndex");
    PropertyInfo propertyInfo = {
        .isNecessary = true,
        .propertyType = napi_number,
        .propertyName = APP_INDEX
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse appIndex failed");
        return res;
    }
    if (property != nullptr) {
        PARSE_PROPERTY(env, property, int32, appIndex);
    }
    APP_LOGD("param appIndex is %{public}d", appIndex);
    return true;
}

static bool ParseInstallFlag(napi_env env, napi_value args, InstallFlag &installFlag)
{
    APP_LOGD("start to parse installFlag");
    PropertyInfo propertyInfo = {
        .isNecessary = false,
        .propertyType = napi_number,
        .propertyName = INSTALL_FLAG
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse installFlag failed");
        return res;
    }

    if (property != nullptr) {
        int32_t flag = 0;
        PARSE_PROPERTY(env, property, int32, flag);
        APP_LOGD("param installFlag is %{public}d", flag);
        if ((flag != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::NORMAL)) &&
            (flag != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::REPLACE_EXISTING)) &&
            (flag != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::FREE_INSTALL))) {
            APP_LOGE("invalid installFlag param");
            return false;
        }
        installFlag = static_cast<OHOS::AppExecFwk::InstallFlag>(flag);
    }
    return true;
}

static bool ParseIsKeepData(napi_env env, napi_value args, bool &isKeepData)
{
    APP_LOGD("start to parse isKeepData");
    PropertyInfo propertyInfo = {
        .isNecessary = false,
        .propertyType = napi_boolean,
        .propertyName = IS_KEEP_DATA
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse isKeepData failed");
        return res;
    }
    if (property != nullptr) {
        PARSE_PROPERTY(env, property, bool, isKeepData);
    }
    APP_LOGD("param isKeepData is %{public}d", isKeepData);
    return true;
}

static bool ParseCrowdtestDeadline(napi_env env, napi_value args, int64_t &crowdtestDeadline)
{
    APP_LOGD("start to parse crowdtestDeadline");
    PropertyInfo propertyInfo = {
        .isNecessary = false,
        .propertyType = napi_number,
        .propertyName = CROWD_TEST_DEADLINE
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse crowdtestDeadline failed");
        return res;
    }
    if (property != nullptr) {
        PARSE_PROPERTY(env, property, int64, crowdtestDeadline);
    }
    return true;
}

static bool ParseSharedBundleDirPaths(napi_env env, napi_value args, std::vector<std::string> &sharedBundleDirPaths)
{
    APP_LOGD("start to parse sharedBundleDirPaths");
    std::vector<napi_value> valueVec;
    bool res = CommonFunc::ParsePropertyArray(env, args, SHARED_BUNDLE_DIR_PATHS, valueVec);
    if (!res) {
        APP_LOGE("parse sharedBundleDirPaths failed");
        return res;
    }
    if (valueVec.empty()) {
        APP_LOGD("sharedBundleDirPaths is empty");
        return true;
    }
    for (const auto &value : valueVec) {
        std::string path;
        if (!CommonFunc::ParseString(env, value, path)) {
            APP_LOGE("parse sharedBundleDirPaths element failed");
            return false;
        }
        sharedBundleDirPaths.emplace_back(path);
    }
    return true;
}

static bool ParseSpecifiedDistributionType(napi_env env, napi_value args, std::string &specifiedDistributionType)
{
    APP_LOGD("start to parse specifiedDistributionType");
    PropertyInfo propertyInfo = {
        .isNecessary = false,
        .propertyType = napi_string,
        .propertyName = SPECIFIED_DISTRIBUTION_TYPE
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse specifiedDistributionType failed");
        return res;
    }
    if (property != nullptr) {
        if (!CommonFunc::ParseString(env, property, specifiedDistributionType)) {
            APP_LOGE("ParseString failed");
            return false;
        }
    }
    APP_LOGD("param specifiedDistributionType is %{public}s", specifiedDistributionType.c_str());
    return true;
}

static bool ParseAdditionalInfo(napi_env env, napi_value args, std::string &additionalInfo)
{
    APP_LOGD("start to parse the additionalInfo");
    PropertyInfo propertyInfo = {
        .isNecessary = false,
        .propertyType = napi_string,
        .propertyName = ADDITIONAL_INFO
    };
    napi_value property = nullptr;
    bool res = CommonFunc::ParsePropertyFromObject(env, args, propertyInfo, property);
    if (!res) {
        APP_LOGE("parse additionalInfo failed");
        return res;
    }
    if (property != nullptr) {
        if (!CommonFunc::ParseString(env, property, additionalInfo)) {
            APP_LOGE("ParseString failed");
            return false;
        }
    }
    APP_LOGD("param additionalInfo is %{public}s", additionalInfo.c_str());
    return true;
}

static bool CheckInstallParam(napi_env env, InstallParam &installParam)
{
    if (installParam.specifiedDistributionType.size() > SPECIFIED_DISTRIBUTION_TYPE_MAX_SIZE) {
        APP_LOGE("Parse specifiedDistributionType size failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR,
            "BusinessError 401: The size of specifiedDistributionType is greater than 128");
        return false;
    }
    if (installParam.additionalInfo.size() > ADDITIONAL_INFO_MAX_SIZE) {
        APP_LOGE("Parse additionalInfo size failed");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR,
            "BusinessError 401: The size of additionalInfo is greater than 3000");
        return false;
    }
    return true;
}

static bool ParseInstallParam(napi_env env, napi_value args, InstallParam &installParam)
{
    if (!ParseHashParams(env, args, installParam.hashParams)) {
        return false;
    }
    if (!ParseVerifyCodeParams(env, args, installParam.verifyCodeParams)) {
        return false;
    }
    if (!ParsePgoParams(env, args, installParam.pgoParams)) {
        return false;
    }
    if (!ParseUserId(env, args, installParam.userId)) {
        APP_LOGW("Parse userId failed,using default value");
    }
    if (!ParseInstallFlag(env, args, installParam.installFlag)) {
        APP_LOGW("Parse installFlag failed,using default value");
    }
    if (!ParseIsKeepData(env, args, installParam.isKeepData)) {
        APP_LOGW("Parse isKeepData failed,using default value");
    }
    if (!ParseCrowdtestDeadline(env, args, installParam.crowdtestDeadline)) {
        APP_LOGW("Parse crowdtestDeadline failed,using default value");
    }
    if (!ParseSharedBundleDirPaths(env, args, installParam.sharedBundleDirPaths)) {
        APP_LOGW("Parse sharedBundleDirPaths failed,using default value");
    }
    if (!ParseSpecifiedDistributionType(env, args, installParam.specifiedDistributionType)) {
        APP_LOGW("Parse specifiedDistributionType failed,using default value");
    }
    if (!ParseAdditionalInfo(env, args, installParam.additionalInfo)) {
        APP_LOGW("Parse additionalInfo failed,using default value");
    }
    if (!ParseParameters(env, args, installParam.parameters)) {
        APP_LOGW("Parse parameters failed,using default value");
    }
    return true;
}

static bool ParseUninstallParam(napi_env env, napi_value args, UninstallParam &uninstallParam)
{
    if (!ParseBundleName(env, args, uninstallParam.bundleName) ||
        !ParseModuleName(env, args, uninstallParam.moduleName) ||
        !ParseVersionCode(env, args, uninstallParam.versionCode) ||
        !ParseUserId(env, args, uninstallParam.userId)) {
            APP_LOGE("Parse UninstallParam faied");
            return false;
    }
    return true;
}

void InstallExecuter(napi_env env, void *data)
{
    AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    const std::vector<std::string> bundleFilePath = asyncCallbackInfo->hapFiles;
    InstallResult &installResult = asyncCallbackInfo->installResult;
    if (bundleFilePath.empty() && asyncCallbackInfo->installParam.sharedBundleDirPaths.empty()) {
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FILE_PATH_INVALID);
        return;
    }
    auto iBundleInstaller = CommonFunc::GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }

    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    if (callback == nullptr || recipient == nullptr) {
        APP_LOGE("callback or death recipient is nullptr");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }
    iBundleInstaller->AsObject()->AddDeathRecipient(recipient);
    if (asyncCallbackInfo->installParam.installFlag == InstallFlag::NORMAL) {
        asyncCallbackInfo->installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    }
    ErrCode res = iBundleInstaller->StreamInstall(bundleFilePath, asyncCallbackInfo->installParam, callback);
    if (res == ERR_OK) {
        installResult.resultCode = callback->GetResultCode();
        APP_LOGD("InnerInstall resultCode %{public}d", installResult.resultCode);
        installResult.resultMsg = callback->GetResultMsg();
        APP_LOGD("InnerInstall resultMsg %{public}s", installResult.resultMsg.c_str());
        installResult.innerCode = callback->GetInnerCode();
        return;
    }
    APP_LOGE("install failed due to %{public}d", res);
    std::unordered_map<int32_t, int32_t> proxyErrCodeMap;
    InstallerHelper::CreateProxyErrCode(proxyErrCodeMap);
    if (proxyErrCodeMap.find(res) != proxyErrCodeMap.end()) {
        installResult.resultCode = proxyErrCodeMap.at(res);
        // append inner error code to TS interface result message
        installResult.innerCode = res;
    } else {
        installResult.resultCode = IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR;
    }
}

static std::string GetFunctionName(const InstallOption &option)
{
    if (option == InstallOption::INSTALL) {
        return RESOURCE_NAME_OF_INSTALL;
    } else if (option == InstallOption::RECOVER) {
        return RESOURCE_NAME_OF_RECOVER;
    } else if (option == InstallOption::UNINSTALL) {
        return RESOURCE_NAME_OF_UNINSTALL;
    } else if (option == InstallOption::UPDATE_BUNDLE_FOR_SELF) {
        return RESOURCE_NAME_OF_UPDATE_BUNDLE_FOR_SELF;
    } else if (option == InstallOption::UNINSTALL_AND_RECOVER) {
        return RESOURCE_NAME_OF_UNINSTALL_AND_RECOVER;
    }
    return EMPTY_STRING;
}

void OperationCompleted(napi_env env, napi_status status, void *data)
{
    AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    InstallerHelper::ConvertInstallResult(callbackPtr->installResult);
    if (callbackPtr->installResult.resultCode != SUCCESS) {
        switch (callbackPtr->option) {
            case InstallOption::INSTALL:
                result[FIRST_PARAM] = BusinessError::CreateInstallError(env, callbackPtr->installResult.resultCode,
                    callbackPtr->installResult.innerCode, RESOURCE_NAME_OF_INSTALL, INSTALL_PERMISSION);
                break;
            case InstallOption::RECOVER:
                result[FIRST_PARAM] = BusinessError::CreateCommonError(env, callbackPtr->installResult.resultCode,
                    RESOURCE_NAME_OF_RECOVER, RECOVER_PERMISSION);
                break;
            case InstallOption::UNINSTALL:
                result[FIRST_PARAM] = BusinessError::CreateCommonError(env, callbackPtr->installResult.resultCode,
                    RESOURCE_NAME_OF_UNINSTALL, UNINSTALL_PERMISSION);
                break;
            case InstallOption::UPDATE_BUNDLE_FOR_SELF:
                result[FIRST_PARAM] = BusinessError::CreateCommonError(env, callbackPtr->installResult.resultCode,
                    RESOURCE_NAME_OF_UPDATE_BUNDLE_FOR_SELF, INSTALL_SELF_PERMISSION);
                break;
            case InstallOption::UNINSTALL_AND_RECOVER:
                result[FIRST_PARAM] = BusinessError::CreateCommonError(env, callbackPtr->installResult.resultCode,
                    RESOURCE_NAME_OF_UNINSTALL_AND_RECOVER, UNINSTALL_PERMISSION);
                break;
            default:
                break;
        }
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[FIRST_PARAM]));
    }
    callbackPtr->err = callbackPtr->installResult.resultCode;
    APP_LOGI("installer callback");
    CommonFunc::NapiReturnDeferred<AsyncInstallCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

/**
 * Promise and async callback
 */
napi_value Install(napi_env env, napi_callback_info info)
{
    APP_LOGI("Install called");
    // obtain arguments of install interface
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("init param failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto argc = args.GetMaxArgc();
    APP_LOGD("the number of argc is  %{public}zu", argc);
    if (argc < ARGS_SIZE_ONE) {
        APP_LOGE("the params number is incorrect");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr = std::make_unique<AsyncInstallCallbackInfo>(env);
    callbackPtr->option = InstallOption::INSTALL;
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseStringArray(env, callbackPtr->hapFiles, args[i])) {
                APP_LOGE("Flags %{public}s invalid", callbackPtr->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &callbackPtr->callback));
                break;
            }
            if (valueType == napi_object && !ParseInstallParam(env, args[i], callbackPtr->installParam)) {
                APP_LOGE("Parse installParam failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &callbackPtr->callback));
                break;
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
            return nullptr;
        }
    }
    if (!CheckInstallParam(env, callbackPtr->installParam)) {
        return nullptr;
    }
    if (callbackPtr->hapFiles.empty() && !callbackPtr->installParam.verifyCodeParams.empty()) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_HAPS_FILE_EMPTY_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod(env, callbackPtr.get(), RESOURCE_NAME_OF_INSTALL, InstallExecuter,
        OperationCompleted);
    callbackPtr.release();
    APP_LOGI("call Install done");
    return promise;
}

void UninstallOrRecoverExecuter(napi_env env, void *data)
{
    AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    const std::string bundleName = asyncCallbackInfo->bundleName;
    InstallResult &installResult = asyncCallbackInfo->installResult;
    if (bundleName.empty()) {
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_RECOVER_INVALID_BUNDLE_NAME);
        return;
    }
    auto iBundleInstaller = CommonFunc::GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }

    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    if (callback == nullptr || recipient == nullptr) {
        APP_LOGE("callback or death recipient is nullptr");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }
    iBundleInstaller->AsObject()->AddDeathRecipient(recipient);
    if (asyncCallbackInfo->option == InstallOption::RECOVER) {
        iBundleInstaller->Recover(bundleName, asyncCallbackInfo->installParam, callback);
    } else if (asyncCallbackInfo->option == InstallOption::UNINSTALL) {
        iBundleInstaller->Uninstall(bundleName, asyncCallbackInfo->installParam, callback);
    } else {
        APP_LOGE("error install option");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }
    installResult.resultMsg = callback->GetResultMsg();
    APP_LOGD("InnerRecover resultMsg %{public}s", installResult.resultMsg.c_str());
    installResult.resultCode = callback->GetResultCode();
    APP_LOGD("InnerRecover resultCode %{public}d", installResult.resultCode);
}

void UninstallByUninstallParamExecuter(napi_env env, void* data)
{
    AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    const std::string bundleName = asyncCallbackInfo->uninstallParam.bundleName;
    InstallResult &installResult = asyncCallbackInfo->installResult;
    if (bundleName.empty()) {
        installResult.resultCode =
            static_cast<int32_t>(IStatusReceiver::ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST);
        return;
    }
    auto iBundleInstaller = CommonFunc::GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }
    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    if (callback == nullptr || recipient == nullptr) {
        APP_LOGE("callback or death recipient is nullptr");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }
    iBundleInstaller->AsObject()->AddDeathRecipient(recipient);
    iBundleInstaller->Uninstall(asyncCallbackInfo->uninstallParam, callback);
    installResult.resultMsg = callback->GetResultMsg();
    installResult.resultCode = callback->GetResultCode();
}

napi_value UninstallByUninstallParam(napi_env env, napi_callback_info info,
    std::unique_ptr<AsyncInstallCallbackInfo> &callbackPtr)
{
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("init param failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!ParseUninstallParam(env, args[i], callbackPtr->uninstallParam)) {
                APP_LOGE("parse uninstallParam failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &callbackPtr->callback));
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod(env, callbackPtr.get(), GetFunctionName(callbackPtr->option),
        UninstallByUninstallParamExecuter, OperationCompleted);
    callbackPtr.release();
    return promise;
}

napi_value UninstallOrRecover(napi_env env, napi_callback_info info,
    std::unique_ptr<AsyncInstallCallbackInfo> &callbackPtr)
{
    APP_LOGD("UninstallOrRecover by bundleName called");
    // obtain arguments of install interface
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("init param failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    auto argc = args.GetMaxArgc();
    APP_LOGD("the number of argc is  %{public}zu", argc);
    if (argc < ARGS_SIZE_ONE) {
        APP_LOGE("the params number is incorrect");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], callbackPtr->bundleName)) {
                APP_LOGE("Flags %{public}s invalid", callbackPtr->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &callbackPtr->callback));
                break;
            }
            if (valueType == napi_object && !ParseInstallParam(env, args[i], callbackPtr->installParam)) {
                APP_LOGE("Parse installParam.hashParams failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &callbackPtr->callback));
                break;
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
            return nullptr;
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod(env, callbackPtr.get(), GetFunctionName(callbackPtr->option),
        UninstallOrRecoverExecuter, OperationCompleted);
    callbackPtr.release();
    return promise;
}

napi_value Recover(napi_env env, napi_callback_info info)
{
    APP_LOGI("Recover called");
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr = std::make_unique<AsyncInstallCallbackInfo>(env);
    callbackPtr->option = InstallOption::RECOVER;
    APP_LOGI("call Recover done");
    return UninstallOrRecover(env, info, callbackPtr);
}

napi_value Uninstall(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("Uninstall called");
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr = std::make_unique<AsyncInstallCallbackInfo>(env);
    callbackPtr->option = InstallOption::UNINSTALL;
    // uninstall uninstallParam
    NapiArg args(env, info);
    args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE);
    napi_valuetype firstType = napi_undefined;
    napi_typeof(env, args[FIRST_PARAM], &firstType);
    if (firstType == napi_object) {
        return UninstallByUninstallParam(env, info, callbackPtr);
    }
    APP_LOGI_NOFUNC("call Uninstall done");
    return UninstallOrRecover(env, info, callbackPtr);
}

napi_value BundleInstallerConstructor(napi_env env, napi_callback_info info)
{
    napi_value jsthis = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr));
    return jsthis;
}

/**
 * Promise and async callback
 */
napi_value UpdateBundleForSelf(napi_env env, napi_callback_info info)
{
    APP_LOGI("UpdateBundleForSelf called");
    // obtain arguments of install interface
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("init param failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto argc = args.GetMaxArgc();
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr = std::make_unique<AsyncInstallCallbackInfo>(env);
    callbackPtr->option = InstallOption::UPDATE_BUNDLE_FOR_SELF;
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseStringArray(env, callbackPtr->hapFiles, args[i])) {
                APP_LOGE("Flags %{public}s invalid", callbackPtr->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &callbackPtr->callback));
                break;
            }
            if (valueType == napi_object && !ParseInstallParam(env, args[i], callbackPtr->installParam)) {
                APP_LOGE("Parse installParam failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &callbackPtr->callback));
                break;
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETERS, CORRESPONDING_TYPE);
            return nullptr;
        }
    }
    if (!CheckInstallParam(env, callbackPtr->installParam)) {
        return nullptr;
    }
    if (callbackPtr->hapFiles.empty() && !callbackPtr->installParam.verifyCodeParams.empty()) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_HAPS_FILE_EMPTY_ERROR);
        return nullptr;
    }
    callbackPtr->installParam.isSelfUpdate = true;
    auto promise = CommonFunc::AsyncCallNativeMethod(env, callbackPtr.get(), RESOURCE_NAME_OF_INSTALL, InstallExecuter,
        OperationCompleted);
    callbackPtr.release();
    APP_LOGI("call UpdateBundleForSelf done");
    return promise;
}

void UninstallAndRecoverExecuter(napi_env env, void *data)
{
    AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    const std::string bundleName = asyncCallbackInfo->bundleName;
    InstallResult &installResult = asyncCallbackInfo->installResult;
    if (bundleName.empty()) {
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_RECOVER_INVALID_BUNDLE_NAME);
        return;
    }
    auto iBundleInstaller = CommonFunc::GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }
    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    if (callback == nullptr || recipient == nullptr) {
        APP_LOGE("callback or death recipient is nullptr");
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
        return;
    }
    iBundleInstaller->AsObject()->AddDeathRecipient(recipient);
    iBundleInstaller->UninstallAndRecover(bundleName, asyncCallbackInfo->installParam, callback);
    installResult.resultMsg = callback->GetResultMsg();
    installResult.resultCode = callback->GetResultCode();
}

napi_value UninstallAndRecover(napi_env env, napi_callback_info info)
{
    APP_LOGI("UninstallAndRecover called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("init param failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr = std::make_unique<AsyncInstallCallbackInfo>(env);
    callbackPtr->option = InstallOption::UNINSTALL_AND_RECOVER;
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], callbackPtr->bundleName)) {
                APP_LOGE("bundleName %{public}s invalid!", callbackPtr->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType != napi_object || !ParseInstallParam(env, args[i], callbackPtr->installParam)) {
                APP_LOGW("Parse installParam failed");
            }
        } else {
            APP_LOGE("The number of parameters is incorrect.");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod(env, callbackPtr.get(), RESOURCE_NAME_OF_UNINSTALL_AND_RECOVER,
        UninstallAndRecoverExecuter, OperationCompleted);
    callbackPtr.release();
    APP_LOGI("call UninstallAndRecover done");
    return promise;
}

void AddExtResourceExec(napi_env env, void *data)
{
    ExtResourceCallbackInfo *asyncCallbackInfo = reinterpret_cast<ExtResourceCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InstallerHelper::InnerAddExtResource(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->filePaths);
}

void AddExtResourceComplete(napi_env env, napi_status status, void *data)
{
    ExtResourceCallbackInfo *asyncCallbackInfo = reinterpret_cast<ExtResourceCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<ExtResourceCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, ADD_EXT_RESOURCE, Constants::PERMISSION_INSTALL_BUNDLE);
    }

    CommonFunc::NapiReturnDeferred<ExtResourceCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value AddExtResource(napi_env env, napi_callback_info info)
{
    APP_LOGD("AddExtResource called");
    NapiArg args(env, info);
    ExtResourceCallbackInfo *asyncCallbackInfo = new (std::nothrow) ExtResourceCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<ExtResourceCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("bundleName invalid");
                BusinessError::ThrowParameterTypeError(
                    env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (CommonFunc::ParseStringArray(env, asyncCallbackInfo->filePaths, args[i]) == nullptr) {
                APP_LOGE("filePaths invalid");
                BusinessError::ThrowParameterTypeError(
                    env, ERROR_PARAM_CHECK_ERROR, FILE_PATH, TYPE_ARRAY);
                return nullptr;
            }
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ExtResourceCallbackInfo>(
        env, asyncCallbackInfo, "AddExtResource", AddExtResourceExec, AddExtResourceComplete);
    callbackPtr.release();
    APP_LOGD("call AddExtResource done");
    return promise;
}

void RemoveExtResourceExec(napi_env env, void *data)
{
    ExtResourceCallbackInfo *asyncCallbackInfo = reinterpret_cast<ExtResourceCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InstallerHelper::InnerRemoveExtResource(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleNames);
}

void RemoveExtResourceComplete(napi_env env, napi_status status, void *data)
{
    ExtResourceCallbackInfo *asyncCallbackInfo = reinterpret_cast<ExtResourceCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<ExtResourceCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, REMOVE_EXT_RESOURCE, Constants::PERMISSION_INSTALL_BUNDLE);
    }

    CommonFunc::NapiReturnDeferred<ExtResourceCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value RemoveExtResource(napi_env env, napi_callback_info info)
{
    APP_LOGD("RemoveExtResource called");
    NapiArg args(env, info);
    ExtResourceCallbackInfo *asyncCallbackInfo = new (std::nothrow) ExtResourceCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<ExtResourceCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("bundleName invalid");
                BusinessError::ThrowParameterTypeError(
                    env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (CommonFunc::ParseStringArray(env, asyncCallbackInfo->moduleNames, args[i]) == nullptr) {
                APP_LOGE("moduleNames invalid");
                BusinessError::ThrowParameterTypeError(
                    env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_ARRAY);
                return nullptr;
            }
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ExtResourceCallbackInfo>(
        env, asyncCallbackInfo, "RemoveExtResource", RemoveExtResourceExec, RemoveExtResourceComplete);
    callbackPtr.release();
    APP_LOGD("call RemoveExtResource done");
    return promise;
}

void CreateAppCloneExec(napi_env env, void *data)
{
    CreateAppCloneCallbackInfo *asyncCallbackInfo = reinterpret_cast<CreateAppCloneCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    APP_LOGD("CreateAppCloneExec param: bundleName = %{public}s, userId = %{public}d, appIndex = %{public}d",
        asyncCallbackInfo->bundleName.c_str(),
        asyncCallbackInfo->userId,
        asyncCallbackInfo->appIndex);
    asyncCallbackInfo->err = InstallerHelper::InnerCreateAppClone(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->userId, asyncCallbackInfo->appIndex);
}

void CreateAppCloneComplete(napi_env env, napi_status status, void *data)
{
    CreateAppCloneCallbackInfo *asyncCallbackInfo = reinterpret_cast<CreateAppCloneCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<CreateAppCloneCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
    APP_LOGD("CreateAppCloneComplete err is %{public}d, appIndex is %{public}d",
        asyncCallbackInfo->err,
        asyncCallbackInfo->appIndex);
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[FIRST_PARAM]));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->appIndex, &result[SECOND_PARAM]));
    } else {
        result[FIRST_PARAM] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            CREATE_APP_CLONE, Constants::PERMISSION_INSTALL_CLONE_BUNDLE);
    }
    CommonFunc::NapiReturnDeferred<CreateAppCloneCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

void ParseAppCloneParam(napi_env env, napi_value args, int32_t &userId, int32_t &appIndex)
{
    if (!ParseUserId(env, args, userId)) {
        APP_LOGI("parse userId failed. assign a default value = %{public}d", userId);
    }
    if (ParseAppIndex(env, args, appIndex)) {
        if (appIndex == 0) {
            APP_LOGI("parse appIndex success, but appIndex is 0, assign a value: %{public}d", ILLEGAL_APP_INDEX);
            appIndex = ILLEGAL_APP_INDEX;
        }
    } else {
        APP_LOGI("parse appIndex failed. assign a default value = %{public}d", appIndex);
    }
}

napi_value CreateAppClone(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to CreateAppClone");
    NapiArg args(env, info);
    std::unique_ptr<CreateAppCloneCallbackInfo> asyncCallbackInfo = std::make_unique<CreateAppCloneCallbackInfo>(env);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGW("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t argc = args.GetMaxArgc();
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGW("parse bundleName failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_object) {
                ParseAppCloneParam(env, args[i], asyncCallbackInfo->userId, asyncCallbackInfo->appIndex);
            }
        } else {
            APP_LOGW("The number of parameters is incorrect");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    if (asyncCallbackInfo->userId == Constants::UNSPECIFIED_USERID) {
        asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<CreateAppCloneCallbackInfo>(
        env, asyncCallbackInfo.get(), CREATE_APP_CLONE, CreateAppCloneExec, CreateAppCloneComplete);
    asyncCallbackInfo.release();
    APP_LOGI("call napi CreateAppClone done");
    return promise;
}

void DestroyAppCloneExec(napi_env env, void *data)
{
    CreateAppCloneCallbackInfo *asyncCallbackInfo = reinterpret_cast<CreateAppCloneCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    APP_LOGD("DestroyAppCloneExec param: bundleName = %{public}s, userId = %{public}d, appIndex = %{public}d",
        asyncCallbackInfo->bundleName.c_str(),
        asyncCallbackInfo->userId,
        asyncCallbackInfo->appIndex);
    asyncCallbackInfo->err = InstallerHelper::InnerDestroyAppClone(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->userId, asyncCallbackInfo->appIndex, asyncCallbackInfo->destroyAppCloneParam);
}

void DestroyAppCloneComplete(napi_env env, napi_status status, void *data)
{
    CreateAppCloneCallbackInfo *asyncCallbackInfo = reinterpret_cast<CreateAppCloneCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<CreateAppCloneCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
    APP_LOGD("DestroyAppCloneComplete err is %{public}d, appIndex is %{public}d",
        asyncCallbackInfo->err,
        asyncCallbackInfo->appIndex);
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[FIRST_PARAM]));
    } else {
        result[FIRST_PARAM] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            DESTROY_APP_CLONE, Constants::PERMISSION_UNINSTALL_CLONE_BUNDLE);
    }
    CommonFunc::NapiReturnDeferred<CreateAppCloneCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

static bool ParseDestroyAppCloneParam(napi_env env, napi_value args, napi_valuetype valueType, int32_t &userId,
                                      DestroyAppCloneParam &destroyAppCloneParam)
{
    if (valueType == napi_number && !CommonFunc::ParseInt(env, args, userId)) {
        APP_LOGW("parse userId failed,set this parameter to the caller userId");
    } else if (valueType == napi_object) {
        if (!ParseUserId(env, args, destroyAppCloneParam.userId)) {
            APP_LOGW("parse userId failed,using default value");
        } else {
            userId = destroyAppCloneParam.userId;
        }
        if (!ParseParameters(env, args, destroyAppCloneParam.parameters)) {
            APP_LOGW("parse parameters failed,using default value");
        }
    }
    return true;
}

napi_value DestroyAppClone(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to destroyAppClone");
    NapiArg args(env, info);
    std::unique_ptr<CreateAppCloneCallbackInfo> asyncCallbackInfo = std::make_unique<CreateAppCloneCallbackInfo>(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("asyncCallbackInfo is null");
        return nullptr;
    }
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGW("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t argc = args.GetMaxArgc();
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGW("parse bundleName failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->appIndex)) {
                APP_LOGW("parse appIndex failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (!ParseDestroyAppCloneParam(
                env, args[i], valueType, asyncCallbackInfo->userId, asyncCallbackInfo->destroyAppCloneParam)) {
                APP_LOGW("parse destroyAppCloneParam failed");
            }
        } else {
            APP_LOGE("The number of parameters is incorrect");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    if (asyncCallbackInfo->userId == Constants::UNSPECIFIED_USERID) {
        asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<CreateAppCloneCallbackInfo>(
        env, asyncCallbackInfo.get(), DESTROY_APP_CLONE, DestroyAppCloneExec, DestroyAppCloneComplete);
    asyncCallbackInfo.release();
    APP_LOGI("call napi destroyAppTwin done");
    return promise;
}

void InstallPreexistingAppExec(napi_env env, void *data)
{
    InstallPreexistingAppCallbackInfo *asyncCallbackInfo = reinterpret_cast<InstallPreexistingAppCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    APP_LOGD("param: bundleName = %{public}s, userId = %{public}d",
        asyncCallbackInfo->bundleName.c_str(),
        asyncCallbackInfo->userId);
    asyncCallbackInfo->err =
        InstallerHelper::InnerInstallPreexistingApp(asyncCallbackInfo->bundleName, asyncCallbackInfo->userId);
}

void InstallPreexistingAppComplete(napi_env env, napi_status status, void *data)
{
    InstallPreexistingAppCallbackInfo *asyncCallbackInfo = reinterpret_cast<InstallPreexistingAppCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<InstallPreexistingAppCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
    APP_LOGD("err is %{public}d", asyncCallbackInfo->err);

    napi_value result[ARGS_SIZE_ONE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[FIRST_PARAM]));
    } else {
        result[FIRST_PARAM] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            INSTALL_PREEXISTING_APP, Constants::PERMISSION_INSTALL_BUNDLE);
    }
    CommonFunc::NapiReturnDeferred<InstallPreexistingAppCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value InstallPreexistingApp(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin");
    NapiArg args(env, info);
    std::unique_ptr<InstallPreexistingAppCallbackInfo> asyncCallbackInfo
        = std::make_unique<InstallPreexistingAppCallbackInfo>(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("asyncCallbackInfo is null");
        return nullptr;
    }
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGW("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t argc = args.GetMaxArgc();
    for (size_t i = 0; i < argc; ++i) {
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGW("parse bundleName failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("parse userId failed");
            }
        } else {
            APP_LOGW("The number of parameters is incorrect");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    if (asyncCallbackInfo->userId == Constants::UNSPECIFIED_USERID) {
        asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<InstallPreexistingAppCallbackInfo>(
        env, asyncCallbackInfo.get(), INSTALL_PREEXISTING_APP,
        InstallPreexistingAppExec, InstallPreexistingAppComplete);
    asyncCallbackInfo.release();
    APP_LOGI("call napi done");
    return promise;
}


void ParseInstallPluginParam(napi_env env, napi_value args, InstallPluginParam &installPluginParam)
{
    if (!ParseUserId(env, args, installPluginParam.userId)) {
        APP_LOGW("parse userId failed. assign default value");
    }
    if (!ParseParameters(env, args, installPluginParam.parameters)) {
        APP_LOGW("parse parameters failed. using default value");
    }
}

void InstallPluginExec(napi_env env, void *data)
{
    PluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<PluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InstallerHelper::InnerInstallPlugin(asyncCallbackInfo->hostBundleName,
        asyncCallbackInfo->pluginFilePaths, asyncCallbackInfo->installPluginParam);
}

void InstallPluginComplete(napi_env env, napi_status status, void *data)
{
    PluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<PluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<PluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
    APP_LOGD("InstallPluginComplete err is %{public}d", asyncCallbackInfo->err);

    napi_value result[ARGS_SIZE_ONE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[FIRST_PARAM]));
    } else {
        result[FIRST_PARAM] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            INSTALL_PLUGIN, Constants::PERMISSION_INSTALL_PLUGIN);
    }
    CommonFunc::NapiReturnDeferred<PluginCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value InstallPlugin(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to InstallPlugin");
    NapiArg args(env, info);
    std::unique_ptr<PluginCallbackInfo> asyncCallbackInfo = std::make_unique<PluginCallbackInfo>(env);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGW("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t argc = args.GetMaxArgc();
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->hostBundleName)) {
                APP_LOGW("parse hostBundleName failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseStringArray(env, asyncCallbackInfo->pluginFilePaths, args[i])) {
                APP_LOGE("pluginFilePaths invalid");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, FILE_PATH, TYPE_ARRAY);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_object) {
                ParseInstallPluginParam(env, args[i], asyncCallbackInfo->installPluginParam);
            }
        } else {
            APP_LOGW("The number of parameters is incorrect");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    if (asyncCallbackInfo->installPluginParam.userId == Constants::UNSPECIFIED_USERID) {
        asyncCallbackInfo->installPluginParam.userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<PluginCallbackInfo>(
        env, asyncCallbackInfo.get(), INSTALL_PLUGIN, InstallPluginExec, InstallPluginComplete);
    asyncCallbackInfo.release();
    APP_LOGI("call napi InstallPlugin done");
    return promise;
}

void UninstallPluginExec(napi_env env, void *data)
{
    PluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<PluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    APP_LOGD("param: hostBundleName = %{public}s, pluginBundleName = %{public}s, userId = %{public}d",
        asyncCallbackInfo->hostBundleName.c_str(),
        asyncCallbackInfo->pluginBundleName.c_str(),
        asyncCallbackInfo->installPluginParam.userId);
    asyncCallbackInfo->err = InstallerHelper::InnerUninstallPlugin(asyncCallbackInfo->hostBundleName,
        asyncCallbackInfo->pluginBundleName, asyncCallbackInfo->installPluginParam);
}

void UninstallPluginComplete(napi_env env, napi_status status, void *data)
{
    PluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<PluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<PluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(asyncCallbackInfo->err);
    APP_LOGD("UninstallPluginComplete err is %{public}d", asyncCallbackInfo->err);

    napi_value result[ARGS_SIZE_ONE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[FIRST_PARAM]));
    } else {
        result[FIRST_PARAM] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            UNINSTALL_PLUGIN, Constants::PERMISSION_UNINSTALL_PLUGIN);
    }
    CommonFunc::NapiReturnDeferred<PluginCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value UninstallPlugin(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to UninstallPlugin");
    NapiArg args(env, info);
    std::unique_ptr<PluginCallbackInfo> asyncCallbackInfo = std::make_unique<PluginCallbackInfo>(env);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGW("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t argc = args.GetMaxArgc();
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->hostBundleName)) {
                APP_LOGW("parse hostBundleName failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->pluginBundleName)) {
                APP_LOGW("parse pluginBundleName failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PLUGIN_BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_object) {
                ParseInstallPluginParam(env, args[i], asyncCallbackInfo->installPluginParam);
            }
        } else {
            APP_LOGW("The number of parameters is incorrect");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    if (asyncCallbackInfo->installPluginParam.userId == Constants::UNSPECIFIED_USERID) {
        asyncCallbackInfo->installPluginParam.userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<PluginCallbackInfo>(
        env, asyncCallbackInfo.get(), UNINSTALL_PLUGIN, UninstallPluginExec, UninstallPluginComplete);
    asyncCallbackInfo.release();
    APP_LOGI("call napi UninstallPlugin done");
    return promise;
}
} // AppExecFwk
} // OHOS
