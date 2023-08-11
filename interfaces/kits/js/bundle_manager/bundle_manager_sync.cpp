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
#include "bundle_manager_sync.h"

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

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* BUNDLE_FLAGS = "bundleFlags";
constexpr const char* HAP_FILE_PATH = "hapFilePath";
constexpr const char* UID = "uid";
const std::string BUNDLE_PERMISSIONS = "ohos.permission.GET_BUNDLE_INFO or ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
const std::string GET_BUNDLE_ARCHIVE_INFO_SYNC = "GetBundleArchiveInfoSync";
const std::string GET_BUNDLE_NAME_BY_UID_SYNC = "GetBundleNameByUidSync";
const std::string GET_PROFILE_BY_EXTENSION_ABILITY_SYNC = "GetProfileByExtensionAbilitySync";
const std::string GET_PROFILE_BY_ABILITY_SYNC = "GetProfileByAbilitySync";
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
