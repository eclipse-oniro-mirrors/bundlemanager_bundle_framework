/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "bundle_constants.h"
#include "common_func.h"
#include "hap_module_info.h"
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "bundle_manager_sync.h"

namespace OHOS {
namespace AppExecFwk {
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* ABILITY_INFO = "abilityInfo";
constexpr const char* IS_ENABLE = "isEnable";
constexpr const char* BUNDLE_FLAGS = "bundleFlags";
constexpr const char* HAP_FILE_PATH = "hapFilePath";
constexpr const char* UID = "uid";
constexpr const char* USER_ID = "userId";
constexpr const char* EXTENSIONABILITY_TYPE = "extensionAbilityType";
constexpr const char* FLAGS = "flags";
constexpr const char* ERR_MSG_BUNDLE_SERVICE_EXCEPTION = "Bundle manager service is excepted.";
const std::string SET_APPLICATION_ENABLED_SYNC = "SetApplicationEnabledSync";
const std::string SET_ABILITY_ENABLED_SYNC = "SetAbilityEnabledSync";
const std::string IS_APPLICATION_ENABLED_SYNC = "IsApplicationEnabledSync";
const std::string IS_ABILITY_ENABLED_SYNC = "IsAbilityEnabledSync";
const std::string GET_ABILITY_LABEL_SYNC = "GetAbilityLabelSync";
const std::string GET_LAUNCH_WANT_FOR_BUNDLE_SYNC = "GetLaunchWantForBundleSync";
const std::string GET_BUNDLE_ARCHIVE_INFO_SYNC = "GetBundleArchiveInfoSync";
const std::string GET_BUNDLE_NAME_BY_UID_SYNC = "GetBundleNameByUidSync";
const std::string GET_PROFILE_BY_EXTENSION_ABILITY_SYNC = "GetProfileByExtensionAbilitySync";
const std::string GET_PROFILE_BY_ABILITY_SYNC = "GetProfileByAbilitySync";
const std::string QUERY_EXTENSION_INFOS_SYNC = "QueryExtensionInfosSync";
const std::string GET_PERMISSION_DEF_SYNC = "GetPermissionDefSync";
const std::string BUNDLE_PERMISSIONS = "ohos.permission.GET_BUNDLE_INFO or ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
const std::string PERMISSION_NAME = "permissionName";
const std::string INVALID_WANT_ERROR =
    "implicit query condition, at least one query param(action entities uri type) non-empty.";
const std::string PARAM_TYPE_CHECK_ERROR = "param type check error";

napi_value SetApplicationEnabledSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI SetApplicationEnabledSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    bool isEnable;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (!CommonFunc::ParseBool(env, args[ARGS_POS_ONE], isEnable)) {
        APP_LOGE("parse isEnable failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->SetApplicationEnabled(bundleName, isEnable));
    if (ret != NO_ERROR) {
        APP_LOGE("SetApplicationEnabledSync failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, SET_APPLICATION_ENABLED_SYNC, Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nRet = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &nRet));
    APP_LOGD("call SetApplicationEnabledSync done");
    return nRet;
}

napi_value SetAbilityEnabledSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI SetAbilityEnabledSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    AbilityInfo abilityInfo;
    bool isEnable;
    if (!CommonFunc::ParseAbilityInfo(env, args[ARGS_POS_ZERO], abilityInfo)) {
        APP_LOGE("parse abilityInfo failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
        return nullptr;
    }
    if (!CommonFunc::ParseBool(env, args[ARGS_POS_ONE], isEnable)) {
        APP_LOGE("parse isEnable failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->SetAbilityEnabled(abilityInfo, isEnable));
    if (ret != NO_ERROR) {
        APP_LOGE("SetAbilityEnabledSync failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, SET_ABILITY_ENABLED_SYNC, Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nRet = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &nRet));
    APP_LOGD("call SetAbilityEnabledSync done");
    return nRet;
}

napi_value IsApplicationEnabledSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI IsApplicationEnabledSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    bool isEnable;
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->IsApplicationEnabled(bundleName, isEnable));
    if (ret != NO_ERROR) {
        APP_LOGE("IsApplicationEnabledSync failed");
        napi_value businessError = BusinessError::CreateCommonError(env, ret, IS_APPLICATION_ENABLED_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nIsEnabled = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isEnable, &nIsEnabled));
    APP_LOGD("call IsApplicationEnabledSync done.");
    return nIsEnabled;
}

napi_value IsAbilityEnabledSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI IsAbilityEnabledSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    AbilityInfo abilityInfo;
    if (!CommonFunc::ParseAbilityInfo(env, args[ARGS_POS_ZERO], abilityInfo)) {
        APP_LOGE("parse abilityInfo failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    bool isEnable;
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->IsAbilityEnabled(abilityInfo, isEnable));
    if (ret != NO_ERROR) {
        APP_LOGE("IsAbilityEnabledSync failed");
        napi_value businessError = BusinessError::CreateCommonError(env, ret, IS_ABILITY_ENABLED_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nIsEnabled = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isEnable, &nIsEnabled));
    APP_LOGD("call IsAbilityEnabledSync done.");
    return nIsEnabled;
}

ErrCode ParamsProcessQueryExtensionInfosSync(napi_env env, napi_callback_info info,
    ExtensionParamInfo& extensionParamInfo)
{
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return ERROR_PARAM_CHECK_ERROR;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseWantPerformance(env, args[i], extensionParamInfo.want)) {
                APP_LOGE("invalid want");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_WANT_ERROR);
                return ERROR_PARAM_CHECK_ERROR;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], extensionParamInfo.extensionAbilityType)) {
                APP_LOGE("invalid extensionAbilityType");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR,
                    EXTENSIONABILITY_TYPE, TYPE_NUMBER);
                return ERROR_PARAM_CHECK_ERROR;
            }
        } else if (i == ARGS_POS_TWO) {
            if (!CommonFunc::ParseInt(env, args[i], extensionParamInfo.flags)) {
                APP_LOGE("invalid flags");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, FLAGS, TYPE_NUMBER);
                return ERROR_PARAM_CHECK_ERROR;
            }
        } else if (i == ARGS_POS_THREE) {
            if (!CommonFunc::ParseInt(env, args[i], extensionParamInfo.userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId!");
            }
        } else {
            APP_LOGE("parameter is invalid");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return ERROR_PARAM_CHECK_ERROR;
        }
    }
    if (extensionParamInfo.userId == Constants::UNSPECIFIED_USERID) {
        extensionParamInfo.userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    return ERR_OK;
}

napi_value QueryExtensionInfosSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI QueryExtensionInfosSync call");
    ExtensionParamInfo extensionParamInfo;
    if (ParamsProcessQueryExtensionInfosSync(env, info, extensionParamInfo) != ERR_OK) {
        APP_LOGE("paramsProcess is invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return nullptr;
    }
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ErrCode ret;
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    if (extensionParamInfo.extensionAbilityType == static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED)) {
        APP_LOGD("query extensionAbilityInfo sync without type");
        ret = CommonFunc::ConvertErrCode(
            iBundleMgr->QueryExtensionAbilityInfosV9(extensionParamInfo.want, extensionParamInfo.flags,
            extensionParamInfo.userId, extensionInfos));
    } else {
        ExtensionAbilityType type = static_cast<ExtensionAbilityType>(extensionParamInfo.extensionAbilityType);
        APP_LOGD("query extensionAbilityInfo sync with type %{public}d", extensionParamInfo.extensionAbilityType);
        ret = CommonFunc::ConvertErrCode(iBundleMgr->QueryExtensionAbilityInfosV9(
            extensionParamInfo.want, type, extensionParamInfo.flags,
            extensionParamInfo.userId, extensionInfos));
    }
    if (ret != NO_ERROR) {
        APP_LOGE("QueryExtensionAbilityInfosV9 failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, QUERY_EXTENSION_INFOS_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nExtensionInfos = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nExtensionInfos));
    CommonFunc::ConvertExtensionInfos(env, extensionInfos, nExtensionInfos);
    APP_LOGD("call QueryExtensionInfosSync done");
    return nExtensionInfos;
}

napi_value GetPermissionDefSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetPermissionDefSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string permissionName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], permissionName)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PERMISSION_NAME, TYPE_STRING);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    OHOS::AppExecFwk::PermissionDef permissionDef;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetPermissionDef(permissionName, permissionDef));
    if (ret != NO_ERROR) {
        APP_LOGE("GetPermissionDef failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_PERMISSION_DEF_SYNC, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nPermissionDef = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nPermissionDef));
    CommonFunc::ConvertPermissionDef(env, nPermissionDef, permissionDef);
    APP_LOGD("call GetPermissionDefSync done");
    return nPermissionDef;
}

ErrCode ParamsProcessGetAbilityLabelSync(napi_env env, napi_callback_info info,
    std::string& bundleName, std::string& moduleName, std::string& abilityName)
{
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return ERROR_PARAM_CHECK_ERROR;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return ERROR_PARAM_CHECK_ERROR;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], moduleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
            return ERROR_PARAM_CHECK_ERROR;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_TWO], abilityName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_NAME, TYPE_STRING);
            return ERROR_PARAM_CHECK_ERROR;
        }
    } else {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return ERROR_PARAM_CHECK_ERROR;
    }
    return ERR_OK;
}

napi_value GetAbilityLabelSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetAbilityLabelSync");
#ifdef GLOBAL_RESMGR_ENABLE
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    if (ParamsProcessGetAbilityLabelSync(env, info, bundleName, moduleName, abilityName) != ERR_OK) {
        APP_LOGE("paramsProcess is invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::string abilityLabel;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetAbilityLabel(bundleName, moduleName, abilityName, abilityLabel));
    if (ret != NO_ERROR) {
        APP_LOGE("GetAbilityLabel failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_ABILITY_LABEL_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nAbilityLabel = nullptr;
    napi_create_string_utf8(env, abilityLabel.c_str(), NAPI_AUTO_LENGTH, &nAbilityLabel);
    APP_LOGD("call GetAbilityLabelSync done");
    return nAbilityLabel;
#else
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "getAbilityLabel");
    napi_throw(env, error);
    return nullptr;
#endif
}

ErrCode ParamsProcessGetLaunchWantForBundleSync(napi_env env, napi_callback_info info,
    std::string& bundleName, int32_t& userId)
{
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return ERROR_PARAM_CHECK_ERROR;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], bundleName)) {
                APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return ERROR_PARAM_CHECK_ERROR;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], userId)) {
                APP_LOGE("parseInt failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
                return ERROR_PARAM_CHECK_ERROR;
            }
        } else {
            APP_LOGE("parameter is invalid");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return ERROR_PARAM_CHECK_ERROR;
        }
    }
    if (bundleName.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_NOT_EXIST, GET_LAUNCH_WANT_FOR_BUNDLE_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return ERROR_PARAM_CHECK_ERROR;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    return ERR_OK;
}

napi_value GetLaunchWantForBundleSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetLaunchWantForBundleSync call");
    std::string bundleName;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    if (ParamsProcessGetLaunchWantForBundleSync(env, info, bundleName, userId) != ERR_OK) {
        APP_LOGE("paramsProcess is invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    OHOS::AAFwk::Want want;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetLaunchWantForBundle(bundleName, want, userId));
    if (ret != NO_ERROR) {
        APP_LOGE("GetLaunchWantForBundle failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_LAUNCH_WANT_FOR_BUNDLE_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nWant = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nWant));
    CommonFunc::ConvertWantInfo(env, nWant, want);
    APP_LOGD("call GetLaunchWantForBundleSync done");
    return nWant;
}

napi_value GetBundleArchiveInfoSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI getBundleArchiveInfoSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string hapFilePath;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], hapFilePath)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, HAP_FILE_PATH, TYPE_STRING);
        return nullptr;
    }
    int32_t bundleFlags;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], bundleFlags)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        napi_value error = BusinessError::CreateCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            GET_BUNDLE_ARCHIVE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, error);
        return nullptr;
    }
    BundleInfo bundleInfo;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetBundleArchiveInfoV9(hapFilePath, bundleFlags, bundleInfo));
    if (ret != ERR_OK) {
        APP_LOGE("getBundleArchiveInfoSync failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_BUNDLE_ARCHIVE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nBundleInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nBundleInfo));
    CommonFunc::ConvertBundleInfo(env, bundleInfo, nBundleInfo, bundleFlags);
    APP_LOGD("call getBundleArchiveInfoSync done.");
    return nBundleInfo;
}

napi_value GetBundleNameByUidSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetBundleNameByUidSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    int32_t uid = -1;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], uid)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, UID, TYPE_NUMBER);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        napi_value error = BusinessError::CreateCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            GET_BUNDLE_NAME_BY_UID_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, error);
        return nullptr;
    }
    std::string bundleName;
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->GetNameForUid(uid, bundleName));
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleNameByUidSync failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_BUNDLE_NAME_BY_UID_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nBundleName = nullptr;
    napi_create_string_utf8(env, bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName);
    APP_LOGD("call GetBundleNameByUidSync done.");
    return nBundleName;
}

ErrCode ParamsProcessGetProfileByAbilitySync(napi_env env, napi_callback_info info,
    std::string& moduleName, std::string& abilityName, std::string& metadataName)
{
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return ERROR_PARAM_CHECK_ERROR;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], moduleName)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return ERROR_PARAM_CHECK_ERROR;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], abilityName)) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_NAME, TYPE_STRING);
        return ERROR_PARAM_CHECK_ERROR;
    }
    if (args.GetMaxArgc() == ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_TWO], metadataName)) {
            APP_LOGW("Parse metadataName param failed");
        }
    }
    return ERR_OK;
}

ErrCode CheckAbilityFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, AbilityInfo& targetAbilityInfo)
{
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& abilityInfo : hapModuleInfo.abilityInfos) {
            if (abilityInfo.name == abilityName && abilityInfo.moduleName == moduleName) {
                targetAbilityInfo = abilityInfo;
                return ERR_OK;
            }
        }
    }
    return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
}

napi_value GetProfileByAbilitySync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetProfileByAbilitySync called");
    std::string moduleName;
    std::string abilityName;
    std::string metadataName;
    if (ParamsProcessGetProfileByAbilitySync(env, info, moduleName, abilityName, metadataName) != ERR_OK) {
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        napi_value error = BusinessError::CreateCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            GET_PROFILE_BY_ABILITY_SYNC);
        napi_throw(env, error);
        return nullptr;
    }
    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA);
    auto getAbilityFlag = baseFlag + static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
    BundleInfo bundleInfo;
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->GetBundleInfoForSelf(getAbilityFlag, bundleInfo));
    if (ret != ERR_OK) {
        APP_LOGE("GetProfileByAbilitySync failed");
        napi_value businessError = BusinessError::CreateCommonError(env, ret, GET_PROFILE_BY_ABILITY_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    AbilityInfo targetAbilityInfo;
    ret = CheckAbilityFromBundleInfo(bundleInfo, abilityName, moduleName, targetAbilityInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetProfileByAbilitySync failed by CheckAbilityFromBundleInfo");
        napi_value businessError = BusinessError::CreateCommonError(env, ret, GET_PROFILE_BY_ABILITY_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    BundleMgrClient client;
    std::vector<std::string> profileVec;
    if (!client.GetProfileFromAbility(targetAbilityInfo, metadataName, profileVec)) {
        APP_LOGE("GetProfileByAbilitySync failed by GetProfileFromAbility");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST, GET_PROFILE_BY_ABILITY_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nProfileInfos = nullptr;
    NAPI_CALL(env, napi_create_array(env, &nProfileInfos));
    CommonFunc::ConvertStringArrays(env, profileVec, nProfileInfos);
    return nProfileInfos;
}

ErrCode CheckExtensionFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, ExtensionAbilityInfo& targetExtensionInfo)
{
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& extensionInfo : hapModuleInfo.extensionInfos) {
            if (extensionInfo.name == abilityName && extensionInfo.moduleName == moduleName) {
                targetExtensionInfo = extensionInfo;
                return ERR_OK;
            }
        }
    }
    return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
}

napi_value GetProfileByExAbilitySync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetProfileByExAbilitySync called");
    std::string moduleName;
    std::string extensionAbilityName;
    std::string metadataName;
    if (ParamsProcessGetProfileByAbilitySync(env, info, moduleName, extensionAbilityName, metadataName) != ERR_OK) {
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        napi_value error = BusinessError::CreateCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            GET_PROFILE_BY_EXTENSION_ABILITY_SYNC);
        napi_throw(env, error);
        return nullptr;
    }
    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA);
    auto getExtensionFlag = baseFlag +
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY);
    BundleInfo bundleInfo;
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->GetBundleInfoForSelf(getExtensionFlag, bundleInfo));
    if (ret != ERR_OK) {
        APP_LOGE("GetProfileByExAbilitySync failed");
        napi_value businessError = BusinessError::CreateCommonError(env, ret, GET_PROFILE_BY_EXTENSION_ABILITY_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    ExtensionAbilityInfo targetExtensionInfo;
    ret = CheckExtensionFromBundleInfo(bundleInfo, extensionAbilityName, moduleName, targetExtensionInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetProfileByExAbilitySync failed by CheckExtensionFromBundleInfo");
        napi_value businessError = BusinessError::CreateCommonError(env, ret, GET_PROFILE_BY_EXTENSION_ABILITY_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    BundleMgrClient client;
    std::vector<std::string> profileVec;
    if (!client.GetProfileFromExtension(targetExtensionInfo, metadataName, profileVec)) {
        APP_LOGE("GetProfileByExAbilitySync failed by GetProfileFromExtension");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST, GET_PROFILE_BY_ABILITY_SYNC);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nProfileInfos = nullptr;
    NAPI_CALL(env, napi_create_array(env, &nProfileInfos));
    CommonFunc::ConvertStringArrays(env, profileVec, nProfileInfos);
    return nProfileInfos;
}
}  // namespace AppExecFwk
}  // namespace OHOS
