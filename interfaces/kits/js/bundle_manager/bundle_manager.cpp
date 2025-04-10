/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "bundle_manager.h"

#include <shared_mutex>
#include <string>

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_errors.h"
#include "bundle_manager_sync.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "bundle_constants.h"
#include "common_func.h"
#include "hap_module_info.h"
#include "plugin/plugin_bundle_info.h"
#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
#include "image_source.h"
#include "pixel_map_napi.h"
#endif
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_common_want.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* ABILITY_INFO = "abilityInfo";
constexpr const char* IS_ENABLE = "isEnable";
constexpr const char* USER_ID = "userId";
constexpr const char* APP_FLAGS = "appFlags";
constexpr const char* PROFILE_TYPE = "profileType";
constexpr const char* STRING_TYPE = "napi_string";
constexpr const char* GET_LAUNCH_WANT_FOR_BUNDLE = "GetLaunchWantForBundle";
constexpr const char* VERIFY_ABC = "VerifyAbc";
constexpr const char* DELETE_ABC = "DeleteAbc";
constexpr const char* ERR_MSG_LAUNCH_WANT_INVALID = "The launch want is not found.";
constexpr const char* ADDITIONAL_INFO = "additionalInfo";
constexpr const char* LINK = "link";
constexpr const char* DEVELOPER_ID = "developerId";
constexpr const char* APP_DISTRIBUTION_TYPE = "appDistributionType";
constexpr const char* APP_DISTRIBUTION_TYPE_ENUM = "AppDistributionType";
constexpr const char* ICON_ID = "iconId";
constexpr const char* LABEL_ID = "labelId";
constexpr const char* STATE = "state";
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* SOURCE_PATHS = "sourcePaths";
constexpr const char* DESTINATION_PATHS = "destinationPath";
constexpr const char* HOST_BUNDLE_NAME = "hostBundleName";
const std::string GET_BUNDLE_ARCHIVE_INFO = "GetBundleArchiveInfo";
const std::string GET_BUNDLE_NAME_BY_UID = "GetBundleNameByUid";
const std::string GET_APP_CLONE_IDENTITY = "getAppCloneIdentity";
const std::string GET_ALL_BUNDLE_CACHE_SIZE = "getAllBundleCacheSize";
const std::string CLEAN_ALL_BUNDLE_CACHE = "cleanAllBundleCache";
const std::string QUERY_ABILITY_INFOS = "QueryAbilityInfos";
const std::string BATCH_QUERY_ABILITY_INFOS = "BatchQueryAbilityInfos";
const std::string QUERY_EXTENSION_INFOS = "QueryExtensionInfos";
const std::string GET_PERMISSION_DEF = "GetPermissionDef";
const std::string PERMISSION_NAME = "permissionName";
const std::string APP_CLONE_IDENTITY_PERMISSIONS = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
const std::string PARAM_TYPE_CHECK_ERROR_WITH_POS = "param type check error, error position : ";
const std::string GET_ALL_SHARED_BUNDLE_INFO = "GetAllSharedBundleInfo";
const std::string GET_SHARED_BUNDLE_INFO = "GetSharedBundleInfo";
const std::string GET_EXT_RESOURCE = "GetExtResource";
const std::string ENABLE_DYNAMIC_ICON = "EnableDynamicIcon";
const std::string DISABLE_DYNAMIC_ICON = "DisableDynamicIcon";
const std::string GET_DYNAMIC_ICON = "GetDynamicIcon";
const std::string GET_APP_PROVISION_INFO = "GetAppProvisionInfo";
const std::string RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE = "GetSpecifiedDistributionType";
const std::string RESOURCE_NAME_OF_GET_ADDITIONAL_INFO = "GetAdditionalInfo";
const std::string GET_JSON_PROFILE = "GetJsonProfile";
const std::string GET_RECOVERABLE_APPLICATION_INFO = "GetRecoverableApplicationInfo";
const std::string RESOURCE_NAME_OF_SET_ADDITIONAL_INFO = "SetAdditionalInfo";
const std::string CAN_OPEN_LINK = "CanOpenLink";
const std::string GET_ALL_PREINSTALLED_APP_INFOS = "GetAllPreinstalledApplicationInfos";
const std::string GET_ALL_BUNDLE_INFO_BY_DEVELOPER_ID = "GetAllBundleInfoByDeveloperId";
const std::string GET_DEVELOPER_IDS = "GetDeveloperIds";
const std::string SWITCH_UNINSTALL_STATE = "SwitchUninstallState";
const std::string GET_APP_CLONE_BUNDLE_INFO = "GetAppCloneBundleInfo";
const std::string GET_ALL_APP_CLONE_BUNDLE_INFO = "GetAllAppCloneBundleInfo";
const std::string GET_ALL_PLUGIN_INFO = "GetAllPluginInfo";
const std::string MIGRATE_DATA = "MigrateData";
const std::string CLONE_BUNDLE_PREFIX = "clone_";
constexpr int32_t ENUM_ONE = 1;
constexpr int32_t ENUM_TWO = 2;
constexpr int32_t ENUM_THREE = 3;
constexpr int32_t ENUM_FOUR = 4;
constexpr int32_t ENUM_FIVE = 5;
constexpr int32_t ENUM_SIX = 6;
constexpr int32_t ENUM_SEVEN = 7;
constexpr const char* UNSPECIFIED = "UNSPECIFIED";
constexpr const char* MULTI_INSTANCE = "MULTI_INSTANCE";
constexpr const char* APP_CLONE = "APP_CLONE";
} // namespace
using namespace OHOS::AAFwk;
static std::shared_ptr<ClearCacheListener> g_clearCacheListener;
static std::mutex g_clearCacheListenerMutex;
static std::unordered_map<Query, napi_ref, QueryHash> cache;
static std::string g_ownBundleName;
static std::mutex g_ownBundleNameMutex;
static std::shared_mutex g_cacheMutex;
static std::set<int32_t> g_supportedProfileList = { 1 };
static std::map<int32_t, std::string> appDistributionTypeMap = {
    { ENUM_ONE, Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY },
    { ENUM_TWO, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE },
    { ENUM_THREE, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL },
    { ENUM_FOUR, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM },
    { ENUM_FIVE, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION },
    { ENUM_SIX, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING },
    { ENUM_SEVEN, Constants::APP_DISTRIBUTION_TYPE_NONE },
};
namespace {
const std::string PARAMETER_BUNDLE_NAME = "bundleName";
}

void ClearCacheListener::HandleCleanEnv(void *data)
{
    std::unique_lock<std::shared_mutex> lock(g_cacheMutex);
    cache.clear();
}

ClearCacheListener::ClearCacheListener(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

void ClearCacheListener::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::unique_lock<std::shared_mutex> lock(g_cacheMutex);
    cache.clear();
}

void RegisterClearCacheListener()
{
    std::lock_guard<std::mutex> lock(g_clearCacheListenerMutex);
    if (g_clearCacheListener != nullptr) {
        return;
    }
    APP_LOGD("register clear cache listener");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    g_clearCacheListener = std::make_shared<ClearCacheListener>(subscribeInfo);
    (void)EventFwk::CommonEventManager::SubscribeCommonEvent(g_clearCacheListener);
}

static ErrCode InnerGetBundleArchiveInfo(std::string &hapFilePath, int32_t flags, BundleInfo &bundleInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetBundleArchiveInfoV9(hapFilePath, flags, bundleInfo);
    APP_LOGD("GetBundleArchiveInfoV9 ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

void GetBundleArchiveInfoExec(napi_env env, void *data)
{
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleArchiveInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetBundleArchiveInfo(
        asyncCallbackInfo->hapFilePath, asyncCallbackInfo->flags, asyncCallbackInfo->bundleInfo);
}

void GetBundleArchiveInfoComplete(napi_env env, napi_status status, void *data)
{
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleArchiveInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetBundleArchiveInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertBundleInfo(env,
            asyncCallbackInfo->bundleInfo, result[ARGS_POS_ONE], asyncCallbackInfo->flags);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_BUNDLE_ARCHIVE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<GetBundleArchiveInfoCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetBundleArchiveInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetBundleArchiveInfo");
    NapiArg args(env, info);
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetBundleArchiveInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetBundleArchiveInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->hapFilePath)) {
                APP_LOGE("hapFilePath %{public}s invalid", asyncCallbackInfo->hapFilePath.c_str());
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags);
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetBundleArchiveInfoCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_ARCHIVE_INFO, GetBundleArchiveInfoExec, GetBundleArchiveInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetBundleArchiveInfo done");
    return promise;
}

static ErrCode InnerGetAppCloneIdentity(int32_t uid, std::string &bundleName, int32_t &appIndex)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetNameAndIndexForUid(uid, bundleName, appIndex);
    APP_LOGD("GetNameAndIndexForUid ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerGetApplicationInfo(const std::string &bundleName, int32_t flags,
    int32_t userId, ApplicationInfo &appInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetApplicationInfoV9(bundleName, flags, userId, appInfo);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerGetApplicationInfos(int32_t flags,
    int32_t userId, std::vector<ApplicationInfo> &appInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetApplicationInfosV9(flags, userId, appInfos);
    return CommonFunc::ConvertErrCode(ret);
}

static void ProcessApplicationInfos(
    napi_env env, napi_value result, const std::vector<ApplicationInfo> &appInfos)
{
    if (appInfos.empty()) {
        APP_LOGD("appInfos is null");
        return;
    }
    size_t index = 0;
    for (const auto &item : appInfos) {
        APP_LOGD("name: %{public}s, bundleName: %{public}s ", item.name.c_str(), item.bundleName.c_str());
        napi_value objAppInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objAppInfo));
        CommonFunc::ConvertApplicationInfo(env, objAppInfo, item);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, objAppInfo));
        index++;
    }
}

void GetBundleNameAndIndexByName(
    const std::string &keyName, std::string &bundleName, int32_t &appIndex)
{
    bundleName = keyName;
    appIndex = 0;
    // for clone bundle name
    auto pos = keyName.find(CLONE_BUNDLE_PREFIX);
    if ((pos == std::string::npos) || (pos == 0)) {
        return;
    }
    std::string index = keyName.substr(0, pos);
    if (!OHOS::StrToInt(index, appIndex)) {
        appIndex = 0;
        return;
    }
    bundleName = keyName.substr(pos + CLONE_BUNDLE_PREFIX.size());
}

std::string GetCloneBundleIdKey(const std::string &bundleName, const int32_t appIndex)
{
    return std::to_string(appIndex) + CLONE_BUNDLE_PREFIX + bundleName;
}

void GetBundleNameByUidExec(napi_env env, void *data)
{
    GetBundleNameByUidCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleNameByUidCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    bool queryOwn = (asyncCallbackInfo->uid == IPCSkeleton::GetCallingUid());
    if (queryOwn) {
        std::lock_guard<std::mutex> lock(g_ownBundleNameMutex);
        if (!g_ownBundleName.empty()) {
            APP_LOGD("query own bundleName, has cache, no need to query from host");
            int32_t appIndex = 0;
            GetBundleNameAndIndexByName(g_ownBundleName, asyncCallbackInfo->bundleName, appIndex);
            asyncCallbackInfo->err = NO_ERROR;
            return;
        }
    }
    int32_t appIndex = 0;
    asyncCallbackInfo->err =
        InnerGetAppCloneIdentity(asyncCallbackInfo->uid, asyncCallbackInfo->bundleName, appIndex);
    if ((asyncCallbackInfo->err == NO_ERROR) && queryOwn && g_ownBundleName.empty()) {
        std::string bundleNameCached = asyncCallbackInfo->bundleName;
        if (appIndex > 0) {
            bundleNameCached = GetCloneBundleIdKey(asyncCallbackInfo->bundleName, appIndex);
        }
        APP_LOGD("put own bundleName = %{public}s to cache", bundleNameCached.c_str());
        std::lock_guard<std::mutex> lock(g_ownBundleNameMutex);
        g_ownBundleName = bundleNameCached;
    }
}

void GetBundleNameByUidComplete(napi_env env, napi_status status, void *data)
{
    GetBundleNameByUidCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleNameByUidCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetBundleNameByUidCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(env, asyncCallbackInfo->bundleName.c_str(), NAPI_AUTO_LENGTH, &result[1]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_BUNDLE_NAME_BY_UID, BUNDLE_PERMISSIONS);
    }
    CommonFunc::NapiReturnDeferred<GetBundleNameByUidCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

void GetAppCloneIdentityExec(napi_env env, void *data)
{
    GetAppCloneIdentityCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetAppCloneIdentityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    bool queryOwn = (asyncCallbackInfo->uid == IPCSkeleton::GetCallingUid());
    if (queryOwn) {
        std::lock_guard<std::mutex> lock(g_ownBundleNameMutex);
        if (!g_ownBundleName.empty()) {
            APP_LOGD("query own bundleName and appIndex, has cache, no need to query from host");
            GetBundleNameAndIndexByName(g_ownBundleName, asyncCallbackInfo->bundleName, asyncCallbackInfo->appIndex);
            asyncCallbackInfo->err = NO_ERROR;
            return;
        }
    }
    asyncCallbackInfo->err = InnerGetAppCloneIdentity(
        asyncCallbackInfo->uid, asyncCallbackInfo->bundleName, asyncCallbackInfo->appIndex);
    if ((asyncCallbackInfo->err == NO_ERROR) && queryOwn && g_ownBundleName.empty()) {
        std::string bundleNameCached = asyncCallbackInfo->bundleName;
        if (asyncCallbackInfo->appIndex > 0) {
            bundleNameCached = GetCloneBundleIdKey(asyncCallbackInfo->bundleName, asyncCallbackInfo->appIndex);
        }
        APP_LOGD("put own bundleName = %{public}s to cache", bundleNameCached.c_str());
        std::lock_guard<std::mutex> lock(g_ownBundleNameMutex);
        g_ownBundleName = bundleNameCached;
    }
}

void GetAppCloneIdentityComplete(napi_env env, napi_status status, void *data)
{
    GetAppCloneIdentityCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetAppCloneIdentityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetAppCloneIdentityCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));

        napi_value nName;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->bundleName.c_str(),
            NAPI_AUTO_LENGTH, &nName));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[ARGS_POS_ONE], BUNDLE_NAME, nName));

        napi_value nAppIndex;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->appIndex, &nAppIndex));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[ARGS_POS_ONE], APP_INDEX, nAppIndex));
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_APP_CLONE_IDENTITY, APP_CLONE_IDENTITY_PERMISSIONS);
    }
    CommonFunc::NapiReturnDeferred<GetAppCloneIdentityCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

void GetApplicationInfoComplete(napi_env env, napi_status status, void *data)
{
    ApplicationInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<ApplicationInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<ApplicationInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertApplicationInfo(env, result[ARGS_POS_ONE], asyncCallbackInfo->appInfo);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_APPLICATION_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<ApplicationInfoCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

void GetApplicationInfosComplete(napi_env env, napi_status status, void *data)
{
    ApplicationInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<ApplicationInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<ApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        ProcessApplicationInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->appInfos);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_APPLICATION_INFOS, Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST);
    }
    CommonFunc::NapiReturnDeferred<ApplicationInfosCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

void GetApplicationInfoExec(napi_env env, void *data)
{
    ApplicationInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetApplicationInfo(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->flags, asyncCallbackInfo->userId, asyncCallbackInfo->appInfo);
}

void GetApplicationInfosExec(napi_env env, void *data)
{
    ApplicationInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetApplicationInfos(asyncCallbackInfo->flags,
        asyncCallbackInfo->userId, asyncCallbackInfo->appInfos);
}

napi_value GetBundleNameByUid(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetBundleNameByUid");
    NapiArg args(env, info);
    GetBundleNameByUidCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetBundleNameByUidCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetBundleNameByUidCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->uid);
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetBundleNameByUidCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_NAME_BY_UID, GetBundleNameByUidExec, GetBundleNameByUidComplete);
    callbackPtr.release();
    APP_LOGD("call GetBundleNameByUid done");
    return promise;
}

napi_value GetAppCloneIdentity(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetAppCloneIdentity");
    NapiArg args(env, info);
    GetAppCloneIdentityCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetAppCloneIdentityCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetAppCloneIdentityCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], asyncCallbackInfo->uid)) {
        APP_LOGW("parse uid failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, "uid", TYPE_NUMBER);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetAppCloneIdentityCallbackInfo>(env, asyncCallbackInfo,
        GET_APP_CLONE_IDENTITY, GetAppCloneIdentityExec, GetAppCloneIdentityComplete);
    callbackPtr.release();
    APP_LOGD("call GetAppCloneIdentity done");
    return promise;
}

void GetAllBundleCacheSizeExec(napi_env env, void *data)
{
    GetAllBundleCacheCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetAllBundleCacheCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    asyncCallbackInfo->cacheCallback = new (std::nothrow) ProcessCacheCallbackHost();
    if (asyncCallbackInfo->cacheCallback == nullptr) {
        APP_LOGE("cacheCallback is null");
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        asyncCallbackInfo->err = CommonFunc::ConvertErrCode(ERROR_BUNDLE_SERVICE_EXCEPTION);
        return;
    }

    asyncCallbackInfo->err =
        CommonFunc::ConvertErrCode(iBundleMgr->GetAllBundleCacheStat(asyncCallbackInfo->cacheCallback));

    APP_LOGI("GetAllBundleCacheStat call, result is %{public}d", asyncCallbackInfo->err);
    if ((asyncCallbackInfo->err == NO_ERROR) && (asyncCallbackInfo->cacheCallback != nullptr)) {
        // wait for GetAllBundleCacheStat
        APP_LOGI("GetAllBundleCacheStat exec wait");
        asyncCallbackInfo->cacheSize = asyncCallbackInfo->cacheCallback->GetCacheStat();
    }
    APP_LOGI("GetAllBundleCacheStat exec end");
}

void GetAllBundleCacheSizeComplete(napi_env env, napi_status status, void *data)
{
    GetAllBundleCacheCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetAllBundleCacheCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetAllBundleCacheCallbackInfo> callbackPtr{ asyncCallbackInfo };
    napi_value result[ARGS_POS_TWO] = { 0 };
    if (asyncCallbackInfo->cacheSize > uint64_t(INT64_MAX)) {
        APP_LOGW("value out of range for int64");
        asyncCallbackInfo->cacheSize = uint64_t(INT64_MAX);
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(
            env, napi_create_int64(env, static_cast<int64_t>(asyncCallbackInfo->cacheSize), &result[ARGS_POS_ONE]));
    } else {
        APP_LOGE("GetAllBundleCacheSizeComplete failed");
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, GET_ALL_BUNDLE_CACHE_SIZE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<GetAllBundleCacheCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllBundleCacheSize(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetAllBundleCacheSize");
    GetAllBundleCacheCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetAllBundleCacheCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }

    std::unique_ptr<GetAllBundleCacheCallbackInfo> callbackPtr{ asyncCallbackInfo };
    auto promise = CommonFunc::AsyncCallNativeMethod<GetAllBundleCacheCallbackInfo>(
        env, asyncCallbackInfo, GET_ALL_BUNDLE_CACHE_SIZE, GetAllBundleCacheSizeExec, GetAllBundleCacheSizeComplete);
    callbackPtr.release();
    APP_LOGD("call GetAllBundleCacheSize done");
    return promise;
}

void CleanAllBundleCacheSizeExec(napi_env env, void *data)
{
    CleanAllBundleCacheCallbackInfo *asyncCallbackInfo = reinterpret_cast<CleanAllBundleCacheCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    asyncCallbackInfo->cacheCallback = new (std::nothrow) ProcessCacheCallbackHost();
    if (asyncCallbackInfo->cacheCallback == nullptr) {
        APP_LOGE("cacheCallback is null");
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        asyncCallbackInfo->err = CommonFunc::ConvertErrCode(ERROR_BUNDLE_SERVICE_EXCEPTION);
        return;
    }

    asyncCallbackInfo->err =
        CommonFunc::ConvertErrCode(iBundleMgr->CleanAllBundleCache(asyncCallbackInfo->cacheCallback));

    APP_LOGI("CleanAllBundleCache call, result is %{public}d", asyncCallbackInfo->err);
    if ((asyncCallbackInfo->err == NO_ERROR) && (asyncCallbackInfo->cacheCallback != nullptr)) {
        // wait for CleanAllBundleCache
        APP_LOGI("CleanAllBundleCache exec wait");
        auto result = asyncCallbackInfo->cacheCallback->GetCleanRet();
        if (result != 0) {
            APP_LOGE("CleanAllBundleCache exec failed, result is %{public}d", result);
        }
    }
    APP_LOGI("CleanAllBundleCache exec end");
}

void CleanAllBundleCacheComplete(napi_env env, napi_status status, void *data)
{
    CleanAllBundleCacheCallbackInfo *asyncCallbackInfo = reinterpret_cast<CleanAllBundleCacheCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<CleanAllBundleCacheCallbackInfo> callbackPtr{ asyncCallbackInfo };
    napi_value result[ARGS_SIZE_ONE] = { 0 };
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("asyncCallbackInfo is null");
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, CLEAN_ALL_BUNDLE_CACHE, Constants::PERMISSION_REMOVECACHEFILE);
    }
    CommonFunc::NapiReturnDeferred<CleanAllBundleCacheCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value CleanAllBundleCache(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to CleanAllBundleCache");

    CleanAllBundleCacheCallbackInfo *asyncCallbackInfo = new (std::nothrow) CleanAllBundleCacheCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<CleanAllBundleCacheCallbackInfo> callbackPtr{ asyncCallbackInfo };
    auto promise = CommonFunc::AsyncCallNativeMethod<CleanAllBundleCacheCallbackInfo>(
        env, asyncCallbackInfo, CLEAN_ALL_BUNDLE_CACHE, CleanAllBundleCacheSizeExec, CleanAllBundleCacheComplete);
    callbackPtr.release();
    APP_LOGD("call CleanAllBundleCache done");
    return promise;
}

napi_value GetLaunchWant(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetLaunchWant call");
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    OHOS::AAFwk::Want want;
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->GetLaunchWant(want));
    if (ret != NO_ERROR) {
        APP_LOGE("GetLaunchWant failed");
        BusinessError::ThrowError(env, ERROR_GET_LAUNCH_WANT_INVALID, ERR_MSG_LAUNCH_WANT_INVALID);
        return nullptr;
    }
    ElementName elementName = want.GetElement();
    if (elementName.GetBundleName().empty() || elementName.GetAbilityName().empty()) {
        APP_LOGE("bundleName or abilityName is empty");
        BusinessError::ThrowError(env, ERROR_GET_LAUNCH_WANT_INVALID, ERR_MSG_LAUNCH_WANT_INVALID);
        return nullptr;
    }
    napi_value nWant = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nWant));
    CommonFunc::ConvertWantInfo(env, nWant, want);
    APP_LOGD("call GetLaunchWant done");
    return nWant;
}

napi_value GetApplicationInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetApplicationInfo called");
    NapiArg args(env, info);
    ApplicationInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<ApplicationInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() < ARGS_SIZE_TWO) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("appId %{public}s invalid", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags %{public}d invalid", asyncCallbackInfo->flags);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else if (i == ARGS_SIZE_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationInfoCallbackInfo>(
        env, asyncCallbackInfo, GET_APPLICATION_INFO, GetApplicationInfoExec, GetApplicationInfoComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetApplicationInfo done");
    return promise;
}

napi_value GetApplicationInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetApplicationInfos called");
    NapiArg args(env, info);
    ApplicationInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<ApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() < ARGS_SIZE_ONE) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags %{public}d invalid", asyncCallbackInfo->flags);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationInfosCallbackInfo>(
        env, asyncCallbackInfo, GET_APPLICATION_INFOS, GetApplicationInfosExec, GetApplicationInfosComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetApplicationInfos done");
    return promise;
}

static ErrCode InnerQueryAbilityInfos(const Want &want,
    int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->QueryAbilityInfosV9(want, flags, userId, abilityInfos);
    APP_LOGD("QueryAbilityInfosV9 ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerBatchQueryAbilityInfos(const std::vector<OHOS::AAFwk::Want> &wants,
    int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos);
    APP_LOGD("BatchQueryAbilityInfos ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerSetApplicationEnabled(const std::string &bundleName, bool &isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex == 0) {
        ret = bundleMgr->SetApplicationEnabled(bundleName, isEnable);
    } else {
        ret = bundleMgr->SetCloneApplicationEnabled(bundleName, appIndex, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerIsApplicationEnabled(const std::string &bundleName, bool &isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex != 0) {
        ret = bundleMgr->IsCloneApplicationEnabled(bundleName, appIndex, isEnable);
    } else {
        ret = bundleMgr->IsApplicationEnabled(bundleName, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerSetAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex != 0) {
        ret = bundleMgr->SetCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
    } else {
        ret = bundleMgr->SetAbilityEnabled(abilityInfo, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerIsAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex != 0) {
        ret = bundleMgr->IsCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
    } else {
        ret = bundleMgr->IsAbilityEnabled(abilityInfo, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerGetAbilityLabel(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::string &abilityLabel)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    ErrCode ret = bundleMgr->GetAbilityLabel(bundleName, moduleName, abilityName, abilityLabel);
    return CommonFunc::ConvertErrCode(ret);
}

#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
static std::shared_ptr<Media::PixelMap> LoadImageFile(const uint8_t *data, size_t len)
{
    APP_LOGD("begin LoadImageFile");
    uint32_t errorCode = 0;
    Media::SourceOptions opts;
    std::unique_ptr<Media::ImageSource> imageSource = Media::ImageSource::CreateImageSource(data, len, opts, errorCode);
    if ((errorCode != 0) || (imageSource == nullptr)) {
        APP_LOGE("failed to create image source err is %{public}d", errorCode);
        return nullptr;
    }

    Media::DecodeOptions decodeOpts;
    auto pixelMapPtr = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != 0) {
        APP_LOGE("failed to create pixelmap err %{public}d", errorCode);
        return nullptr;
    }
    APP_LOGD("LoadImageFile finish");
    return std::shared_ptr<Media::PixelMap>(std::move(pixelMapPtr));
}

static ErrCode InnerGetAbilityIcon(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::shared_ptr<Media::PixelMap> &pixelMap)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_SYSTEM_ABILITY_NOT_FOUND;
    }
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGE("GetAbilityIcon check param failed");
        return ERROR_PARAM_CHECK_ERROR;
    }
    std::unique_ptr<uint8_t[]> mediaDataPtr = nullptr;
    size_t len = 0;
    ErrCode ret = bundleMgr->GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, len);
    if (ret != ERR_OK) {
        APP_LOGE("get media data failed, bundleName is %{public}s", bundleName.c_str());
        return CommonFunc::ConvertErrCode(ret);
    }
    if (mediaDataPtr == nullptr || len == 0) {
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto pixelMapPtr = LoadImageFile(mediaDataPtr.get(), len);
    if (pixelMapPtr == nullptr) {
        APP_LOGE("loadImageFile failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    pixelMap = std::move(pixelMapPtr);
    return SUCCESS;
}
#endif

static void CheckAbilityInfoCache(napi_env env, const Query &query,
    const OHOS::AAFwk::Want &want, std::vector<AbilityInfo> abilityInfos,  napi_value jsObject)
{
    ElementName element = want.GetElement();
    if (element.GetBundleName().empty() || element.GetAbilityName().empty()) {
        return;
    }

    uint32_t explicitQueryResultLen = 1;
    if (abilityInfos.size() != explicitQueryResultLen ||
        abilityInfos[0].uid != IPCSkeleton::GetCallingUid()) {
        return;
    }

    napi_ref cacheAbilityInfo = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, jsObject, NAPI_RETURN_ONE, &cacheAbilityInfo));
    std::unique_lock<std::shared_mutex> lock(g_cacheMutex);
    cache[query] = cacheAbilityInfo;
}

static void CheckAbilityInfoCache(
    napi_env env, const Query &query, const AbilityCallbackInfo *info, napi_value jsObject)
{
    if (info == nullptr) {
        return;
    }
    CheckAbilityInfoCache(env, query, info->want, info->abilityInfos, jsObject);
}

static void CheckBatchAbilityInfoCache(napi_env env, const Query &query,
    const std::vector<OHOS::AAFwk::Want> &wants, std::vector<AbilityInfo> abilityInfos,  napi_value jsObject)
{
    for (size_t i = 0; i < wants.size(); i++) {
        ElementName element = wants[i].GetElement();
        if (element.GetBundleName().empty() || element.GetAbilityName().empty()) {
            return;
        }
    }

    uint32_t explicitQueryResultLen = 1;
    if (abilityInfos.size() != explicitQueryResultLen ||
        (abilityInfos.size() > 0 && abilityInfos[0].uid != IPCSkeleton::GetCallingUid())) {
        return;
    }

    napi_ref cacheAbilityInfo = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, jsObject, NAPI_RETURN_ONE, &cacheAbilityInfo));
    std::unique_lock<std::shared_mutex> lock(g_cacheMutex);
    cache[query] = cacheAbilityInfo;
}

static void CheckBatchAbilityInfoCache(
    napi_env env, const Query &query, const BatchAbilityCallbackInfo *info, napi_value jsObject)
{
    if (info == nullptr) {
        return;
    }
    CheckBatchAbilityInfoCache(env, query, info->wants, info->abilityInfos, jsObject);
}

void QueryAbilityInfosExec(napi_env env, void *data)
{
    AbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        auto item = cache.find(Query(asyncCallbackInfo->want.ToString(),
            QUERY_ABILITY_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
        if (item != cache.end()) {
            asyncCallbackInfo->isSavedInCache = true;
            APP_LOGD("has cache, no need to query from host");
            return;
        }
    }
    asyncCallbackInfo->err = InnerQueryAbilityInfos(asyncCallbackInfo->want, asyncCallbackInfo->flags,
        asyncCallbackInfo->userId, asyncCallbackInfo->abilityInfos);
}

void QueryAbilityInfosComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGI_NOFUNC("QueryAbilityInfosComplete begin");
    AbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        if (asyncCallbackInfo->isSavedInCache) {
            std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
            auto item = cache.find(Query(asyncCallbackInfo->want.ToString(),
                QUERY_ABILITY_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
            if (item == cache.end()) {
                APP_LOGE("cannot find result in cache");
                return;
            }
            NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, item->second, &result[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
            CommonFunc::ConvertAbilityInfos(env, asyncCallbackInfo->abilityInfos, result[1]);
            Query query(asyncCallbackInfo->want.ToString(),
                QUERY_ABILITY_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env);
            CheckAbilityInfoCache(env, query, asyncCallbackInfo, result[1]);
        }
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            QUERY_ABILITY_INFOS, BUNDLE_PERMISSIONS);
    }
    APP_LOGI_NOFUNC("QueryAbilityInfosComplete before return");
    CommonFunc::NapiReturnDeferred<AbilityCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value QueryAbilityInfos(napi_env env, napi_callback_info info)
{
    APP_LOGI_NOFUNC("napi QueryAbilityInfos");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (IsArray(env, args[0])) {
        return BatchQueryAbilityInfos(env, info);
    }
    AbilityCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    std::unique_ptr<AbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            // parse want with parameter
            if (!ParseWantWithParameter(env, args[i], asyncCallbackInfo->want)) {
                APP_LOGE("invalid want");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_WANT_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags);
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityCallbackInfo>(
        env, asyncCallbackInfo, QUERY_ABILITY_INFOS, QueryAbilityInfosExec, QueryAbilityInfosComplete);
    callbackPtr.release();
    APP_LOGI_NOFUNC("napi QueryAbilityInfos end");
    return promise;
}

static ErrCode InnerGetAllPluginInfo(std::string &hostBundleName, int32_t userId,
    std::vector<PluginBundleInfo> &pluginBundleInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAllPluginInfo(hostBundleName, userId, pluginBundleInfos);
    return CommonFunc::ConvertErrCode(ret);
}

void GetAllPluginInfoExec(napi_env env, void *data)
{
    PluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<PluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetAllPluginInfo(asyncCallbackInfo->hostBundleName,
        asyncCallbackInfo->userId, asyncCallbackInfo->pluginBundleInfos);
}

static void ProcessPluginInfos(
    napi_env env, napi_value result, const std::vector<PluginBundleInfo> &pluginBundleInfos)
{
    if (pluginBundleInfos.empty()) {
        APP_LOGD("pluginBundleInfos is null");
        return;
    }
    size_t index = 0;
    for (const auto &item : pluginBundleInfos) {
        napi_value objPluginInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objPluginInfo));
        CommonFunc::ConvertPluginBundleInfo(env, item, objPluginInfo);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, objPluginInfo));
        index++;
    }
}

void GetAllPluginInfoComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGI("GetAllPluginInfoComplete begin");
    PluginCallbackInfo *asyncCallbackInfo = reinterpret_cast<PluginCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<PluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        ProcessPluginInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->pluginBundleInfos);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_PLUGIN_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<PluginCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllPluginInfo(napi_env env, napi_callback_info info)
{
    APP_LOGI("napi GetAllPluginInfo begin");
    NapiArg args(env, info);
    PluginCallbackInfo *asyncCallbackInfo = new (std::nothrow) PluginCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<PluginCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->hostBundleName)) {
                APP_LOGE("parse hostBundleName failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, HOST_BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_SIZE_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<PluginCallbackInfo>(
        env, asyncCallbackInfo, GET_ALL_PLUGIN_INFO, GetAllPluginInfoExec, GetAllPluginInfoComplete);
    callbackPtr.release();
    APP_LOGI_NOFUNC("napi GetAllPluginInfo end");
    return promise;
}

void BatchQueryAbilityInfosExec(napi_env env, void *data)
{
    BatchAbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<BatchAbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        std::string bundleNames = "[";
        for (uint32_t i = 0; i < asyncCallbackInfo->wants.size(); i++) {
            bundleNames += ((i > 0) ? "," : "");
            bundleNames += asyncCallbackInfo->wants[i].ToString();
        }
        bundleNames += "]";
        auto item = cache.find(Query(bundleNames,
            BATCH_QUERY_ABILITY_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
        if (item != cache.end()) {
            asyncCallbackInfo->isSavedInCache = true;
            APP_LOGE("has cache, no need to query from host");
            return;
        }
    }
    asyncCallbackInfo->err = InnerBatchQueryAbilityInfos(asyncCallbackInfo->wants, asyncCallbackInfo->flags,
        asyncCallbackInfo->userId, asyncCallbackInfo->abilityInfos);
}

void BatchQueryAbilityInfosComplete(napi_env env, napi_status status, void *data)
{
    BatchAbilityCallbackInfo *asyncCallbackInfo = reinterpret_cast<BatchAbilityCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<BatchAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        if (asyncCallbackInfo->isSavedInCache) {
            std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
            std::string bundleNames = "[";
            for (uint32_t i = 0; i < asyncCallbackInfo->wants.size(); i++) {
                bundleNames += ((i > 0) ? "," : "");
                bundleNames += asyncCallbackInfo->wants[i].ToString();
            }
            bundleNames += "]";
            auto item = cache.find(Query(bundleNames,
                BATCH_QUERY_ABILITY_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
            if (item == cache.end()) {
                APP_LOGE("cannot find result in cache");
                return;
            }
            NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, item->second, &result[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
            CommonFunc::ConvertAbilityInfos(env, asyncCallbackInfo->abilityInfos, result[1]);
            std::string bundleNames = "[";
            for (uint32_t i = 0; i < asyncCallbackInfo->wants.size(); i++) {
                bundleNames += ((i > 0) ? "," : "");
                bundleNames += asyncCallbackInfo->wants[i].ToString();
            }
            bundleNames += "]";
            Query query(bundleNames,
                BATCH_QUERY_ABILITY_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env);
            CheckBatchAbilityInfoCache(env, query, asyncCallbackInfo, result[1]);
        }
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            BATCH_QUERY_ABILITY_INFOS, BUNDLE_PERMISSIONS);
    }
    APP_LOGI("before return");
    CommonFunc::NapiReturnDeferred<BatchAbilityCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value BatchQueryAbilityInfos(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to BatchQueryAbilityInfos");
    NapiArg args(env, info);
    BatchAbilityCallbackInfo *asyncCallbackInfo = new (std::nothrow) BatchAbilityCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    std::unique_ptr<BatchAbilityCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            // parse want with parameter
            if (!ParseWantListWithParameter(env, args[i], asyncCallbackInfo->wants)) {
                APP_LOGE("invalid wants");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_WANT_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags);
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else {
            APP_LOGE("param check error");
            std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<BatchAbilityCallbackInfo>(
        env, asyncCallbackInfo, BATCH_QUERY_ABILITY_INFOS, BatchQueryAbilityInfosExec, BatchQueryAbilityInfosComplete);
    callbackPtr.release();
    APP_LOGI("call BatchQueryAbilityInfos done");
    return promise;
}

ErrCode ParamsProcessQueryAbilityInfosSync(napi_env env, napi_callback_info info,
    OHOS::AAFwk::Want& want, int32_t& abilityFlags, int32_t& userId)
{
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return ERROR_PARAM_CHECK_ERROR;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            // parse want with parameter
            if (!ParseWantWithParameter(env, args[i], want)) {
                APP_LOGE("invalid want");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_WANT_ERROR);
                return ERROR_PARAM_CHECK_ERROR;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], abilityFlags)) {
                APP_LOGE("abilityFlags %{public}d invalid", abilityFlags);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_FLAGS, TYPE_NUMBER);
                return ERROR_PARAM_CHECK_ERROR;
            }
        } else if (i == ARGS_POS_TWO) {
            if (!CommonFunc::ParseInt(env, args[i], userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else {
            APP_LOGE("parameter is invalid");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return ERROR_PARAM_CHECK_ERROR;
        }
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    return ERR_OK;
}

napi_value QueryAbilityInfosSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI QueryAbilityInfosSync call");
    OHOS::AAFwk::Want want;
    int32_t abilityFlags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    if (ParamsProcessQueryAbilityInfosSync(env, info, want, abilityFlags, userId) != ERR_OK) {
        APP_LOGE("paramsProcess is invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return nullptr;
    }
    napi_value nAbilityInfos = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        auto item = cache.find(Query(want.ToString(),
            QUERY_ABILITY_INFOS_SYNC, abilityFlags, userId, env));
        if (item != cache.end()) {
            APP_LOGD("QueryAbilityInfosSync param from cache");
            NAPI_CALL(env,
                napi_get_reference_value(env, item->second, &nAbilityInfos));
            return nAbilityInfos;
        }
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->QueryAbilityInfosV9(want, abilityFlags, userId, abilityInfos));
    if (ret != NO_ERROR) {
        APP_LOGE("QueryAbilityInfosV9 failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, QUERY_ABILITY_INFOS_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    NAPI_CALL(env, napi_create_array(env, &nAbilityInfos));
    CommonFunc::ConvertAbilityInfos(env, abilityInfos, nAbilityInfos);
    Query query(want.ToString(),
                QUERY_ABILITY_INFOS_SYNC, abilityFlags, userId, env);
    CheckAbilityInfoCache(env, query, want, abilityInfos, nAbilityInfos);
    APP_LOGD("call QueryAbilityInfosSync done");
    return nAbilityInfos;
}

static ErrCode InnerQueryExtensionInfos(ExtensionCallbackInfo *info)
{
    if (info == nullptr) {
        APP_LOGE("ExtensionCallbackInfo is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (info->extensionAbilityType == static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED)) {
        APP_LOGD("query extensionAbilityInfo without type");
        ret = iBundleMgr->QueryExtensionAbilityInfosV9(info->want, info->flags, info->userId, info->extensionInfos);
    } else {
        ExtensionAbilityType type = static_cast<ExtensionAbilityType>(info->extensionAbilityType);
        APP_LOGD("query extensionAbilityInfo with type %{public}d", info->extensionAbilityType);
        ret = iBundleMgr->QueryExtensionAbilityInfosV9(
            info->want, type, info->flags, info->userId, info->extensionInfos);
    }
    APP_LOGD("QueryExtensionAbilityInfosV9 ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

static void HandleExtensionCache(
    napi_env env, const Query &query, const ExtensionCallbackInfo *info, napi_value jsObject)
{
    if (info == nullptr) {
        return;
    }

    ElementName element = info->want.GetElement();
    if (element.GetBundleName().empty() || element.GetAbilityName().empty()) {
        return;
    }

    uint32_t explicitQueryResultLen = 1;
    if (info->extensionInfos.size() != explicitQueryResultLen ||
        info->extensionInfos[0].uid != IPCSkeleton::GetCallingUid()) {
        return;
    }

    napi_ref cacheExtensionInfo = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, jsObject, NAPI_RETURN_ONE, &cacheExtensionInfo));
    std::unique_lock<std::shared_mutex> lock(g_cacheMutex);
    cache[query] = cacheExtensionInfo;
}

void QueryExtensionInfosExec(napi_env env, void *data)
{
    ExtensionCallbackInfo *asyncCallbackInfo = reinterpret_cast<ExtensionCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        std::string key = asyncCallbackInfo->want.ToString() + std::to_string(asyncCallbackInfo->extensionAbilityType);
        auto item = cache.find(
            Query(key, QUERY_EXTENSION_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
        if (item != cache.end()) {
            asyncCallbackInfo->isSavedInCache = true;
            APP_LOGD("extension has cache, no need to query from host");
            return;
        }
    }
    asyncCallbackInfo->err = InnerQueryExtensionInfos(asyncCallbackInfo);
}

void QueryExtensionInfosComplete(napi_env env, napi_status status, void *data)
{
    ExtensionCallbackInfo *asyncCallbackInfo = reinterpret_cast<ExtensionCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<ExtensionCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        std::string key = asyncCallbackInfo->want.ToString() + std::to_string(asyncCallbackInfo->extensionAbilityType);
        Query query(key, QUERY_EXTENSION_INFOS, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env);
        if (asyncCallbackInfo->isSavedInCache) {
            // get from cache
            std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
            auto item = cache.find(query);
            if (item != cache.end()) {
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, item->second, &result[1]));
            } else {
                APP_LOGE("extension not in cache");
                asyncCallbackInfo->isSavedInCache = false;
            }
        } else {
            CommonFunc::ConvertExtensionInfos(env, asyncCallbackInfo->extensionInfos, result[1]);
            // optionally save to cache
            HandleExtensionCache(env, query, asyncCallbackInfo, result[1]);
        }
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            QUERY_EXTENSION_INFOS, BUNDLE_PERMISSIONS);
    }
    CommonFunc::NapiReturnDeferred<ExtensionCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value QueryExtensionInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to QueryExtensionInfos");
    NapiArg args(env, info);
    ExtensionCallbackInfo *asyncCallbackInfo = new (std::nothrow) ExtensionCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    std::unique_ptr<ExtensionCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FIVE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_object)) {
            // parse want with parameter
            if (!ParseWantWithParameter(env, args[i], asyncCallbackInfo->want)) {
                APP_LOGE("invalid want");
                BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_WANT_ERROR);
                return nullptr;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->extensionAbilityType);
        } else if ((i == ARGS_POS_TWO) && (valueType == napi_number)) {
            CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags);
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else if (i == ARGS_POS_FOUR) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            std::string errMsg = PARAM_TYPE_CHECK_ERROR_WITH_POS + std::to_string(i + 1);
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, errMsg);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ExtensionCallbackInfo>(
        env, asyncCallbackInfo, QUERY_EXTENSION_INFOS, QueryExtensionInfosExec, QueryExtensionInfosComplete);
    callbackPtr.release();
    APP_LOGD("call QueryExtensionInfos done");
    return promise;
}

void CreateAbilityFlagObject(napi_env env, napi_value value)
{
    napi_value nGetAbilityInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), &nGetAbilityInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_DEFAULT",
        nGetAbilityInfoDefault));

    napi_value nGetAbilityInfoWithPermission;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION), &nGetAbilityInfoWithPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_PERMISSION",
        nGetAbilityInfoWithPermission));

    napi_value nGetAbilityInfoWithApplication;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION), &nGetAbilityInfoWithApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_APPLICATION",
        nGetAbilityInfoWithApplication));

    napi_value nGetAbilityInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA), &nGetAbilityInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_METADATA",
        nGetAbilityInfoWithMetadata));

    napi_value nGetAbilityInfoWithDisabled;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE), &nGetAbilityInfoWithDisabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_DISABLE",
        nGetAbilityInfoWithDisabled));

    napi_value nGetAbilityInfOnlySystemApp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP), &nGetAbilityInfOnlySystemApp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_ONLY_SYSTEM_APP",
        nGetAbilityInfOnlySystemApp));

    napi_value nGetAbilityInfoWithSkill;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL), &nGetAbilityInfoWithSkill));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_SKILL",
        nGetAbilityInfoWithSkill));

    napi_value nGetAbilityInfoWithAppLinking;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APP_LINKING), &nGetAbilityInfoWithAppLinking));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_ABILITY_INFO_WITH_APP_LINKING",
        nGetAbilityInfoWithAppLinking));
}

void GetAbilityLabelExec(napi_env env, void *data)
{
    AbilityLabelCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityLabelCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    asyncCallbackInfo->err = InnerGetAbilityLabel(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->abilityName, asyncCallbackInfo->abilityLabel);
}

void GetAbilityLabelComplete(napi_env env, napi_status status, void *data)
{
    AbilityLabelCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityLabelCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AbilityLabelCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->abilityLabel.c_str(),
            NAPI_AUTO_LENGTH, &result[1]));
    } else {
        APP_LOGE("asyncCallbackInfo is null");
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, "GetAbilityLabel", Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<AbilityLabelCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAbilityLabel(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetAbilityLabel");
#ifdef GLOBAL_RESMGR_ENABLE
    NapiArg args(env, info);
    AbilityLabelCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityLabelCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AbilityLabelCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("Napi func init failed");
        return nullptr;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->moduleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_TWO], asyncCallbackInfo->abilityName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_NAME, TYPE_STRING);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_FOUR) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_THREE], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_THREE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityLabelCallbackInfo>(
        env, asyncCallbackInfo, "GetAbilityLabel", GetAbilityLabelExec, GetAbilityLabelComplete);
    callbackPtr.release();
    APP_LOGD("call GetAbilityLabel done");
    return promise;
#else
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "getAbilityLabel");
    napi_throw(env, error);
    return nullptr;
#endif
}

#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
void GetAbilityIconExec(napi_env env, void *data)
{
    AbilityIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    asyncCallbackInfo->err = InnerGetAbilityIcon(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->abilityName, asyncCallbackInfo->pixelMap);
}

void GetAbilityIconComplete(napi_env env, napi_status status, void *data)
{
    AbilityIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AbilityIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        result[1] = Media::PixelMapNapi::CreatePixelMap(env, asyncCallbackInfo->pixelMap);
    } else {
        APP_LOGE("asyncCallbackInfo is null");
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, "GetAbilityIcon", Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<AbilityIconCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}
#endif

napi_value GetAbilityIcon(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to GetAbilityIcon");
#ifdef BUNDLE_FRAMEWORK_GET_ABILITY_ICON_ENABLED
    NapiArg args(env, info);
    AbilityIconCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityIconCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AbilityIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("Napi func init failed");
        return nullptr;
    }

    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->moduleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_TWO], asyncCallbackInfo->abilityName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_NAME, TYPE_STRING);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_FOUR) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_THREE], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_THREE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityIconCallbackInfo>(
        env, asyncCallbackInfo, "GetAbilityIcon", GetAbilityIconExec, GetAbilityIconComplete);
    callbackPtr.release();
    APP_LOGD("call GetAbilityIcon done");
    return promise;
#else
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "getAbilityIcon");
    napi_throw(env, error);
    return nullptr;
#endif
}

void SetApplicationEnabledExec(napi_env env, void *data)
{
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    asyncCallbackInfo->err = InnerSetApplicationEnabled(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->isEnable, asyncCallbackInfo->appIndex);
}

void SetApplicationEnabledComplete(napi_env env, napi_status status, void *data)
{
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("asyncCallbackInfo is null");
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, "SetApplicationEnabled", Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
    }
    CommonFunc::NapiReturnDeferred<ApplicationEnableCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

bool ParseBundleName(napi_env env, const napi_value& value, std::string& bundleName)
{
    if (!CommonFunc::ParseString(env, value, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return false;
    }
    return true;
}

bool ParseAppIndex(napi_env env, const napi_value& value, int32_t& appIndex)
{
    if (!CommonFunc::ParseInt(env, value, appIndex)) {
        APP_LOGE("parse appIndex failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return false;
    }
    return true;
}

bool ParseIsEnable(napi_env env, const napi_value& value, bool& isEnabled)
{
    if (!CommonFunc::ParseBool(env, value, isEnabled)) {
        APP_LOGE("parse isEnabled failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
        return false;
    }
    return true;
}

bool HandleSetApplicationEnabledArg(
    napi_env env, napi_value arg, size_t index, ApplicationEnableCallbackInfo *asyncCallbackInfo,
    bool& callCloneFunc)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);

    if (index == ARGS_POS_ZERO) {
        return ParseBundleName(env, arg, asyncCallbackInfo->bundleName);
    } else if (index == ARGS_POS_ONE) {
        if (valueType == napi_number) {
            callCloneFunc = true;
            return ParseAppIndex(env, arg, asyncCallbackInfo->appIndex);
        } else if (valueType == napi_boolean) {
            return ParseIsEnable(env, arg, asyncCallbackInfo->isEnable);
        } else {
            APP_LOGE("parse isEnable failed");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
            return false;
        }
    } else if (index == ARGS_POS_TWO) {
        if (callCloneFunc && valueType != napi_boolean) {
            APP_LOGE("parse isEnable failed");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
            return false;
        }
        if (valueType == napi_boolean && !CommonFunc::ParseBool(env, arg, asyncCallbackInfo->isEnable)) {
            APP_LOGE("parse isEnable failed");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
            return false;
        }
    } else {
        APP_LOGE("param check error");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return false;
    }
    return true;
}

napi_value SetApplicationEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to SetApplicationEnabled");
    NapiArg args(env, info);
    ApplicationEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Napi func init failed");
        return nullptr;
    }
    bool callCloneFunc = false;
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        if (!HandleSetApplicationEnabledArg(env, args[i], i, asyncCallbackInfo, callCloneFunc)) {
            return nullptr;
        }
        if (i == ARGS_POS_TWO) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[i], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    }
    if (callCloneFunc && (args.GetMaxArgc() == ARGS_SIZE_TWO)) {
        APP_LOGE("params are too few for clone app");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationEnableCallbackInfo>(
        env, asyncCallbackInfo, "SetApplicationEnabled", SetApplicationEnabledExec, SetApplicationEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call SetApplicationEnabled done");
    return promise;
}

void SetAbilityEnabledExec(napi_env env, void *data)
{
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    asyncCallbackInfo->err = InnerSetAbilityEnabled(asyncCallbackInfo->abilityInfo,
        asyncCallbackInfo->isEnable, asyncCallbackInfo->appIndex);
}

void SetAbilityEnabledComplete(napi_env env, napi_status status, void *data)
{
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("asyncCallbackInfo is null");
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, "SetAbilityEnabled", Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
    }
    CommonFunc::NapiReturnDeferred<AbilityEnableCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

bool HandleSetAbilityEnabledArg(napi_env env, napi_value arg, size_t index,
    AbilityEnableCallbackInfo *asyncCallbackInfo, bool& callCloneFunc)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);

    if (index == ARGS_POS_ZERO) {
        if (!CommonFunc::ParseAbilityInfo(env, arg, asyncCallbackInfo->abilityInfo)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
            return false;
        }
    } else if (index == ARGS_POS_ONE) {
        if (valueType == napi_number) {
            callCloneFunc = true;
            return ParseAppIndex(env, arg, asyncCallbackInfo->appIndex);
        } else if (valueType == napi_boolean) {
            return ParseIsEnable(env, arg, asyncCallbackInfo->isEnable);
        } else {
            APP_LOGE("parse isEnable failed");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
            return false;
        }
    } else if (index == ARGS_POS_TWO) {
        if (callCloneFunc && valueType != napi_boolean) {
            APP_LOGE("parse isEnable failed");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
            return false;
        }
        if (valueType == napi_boolean && !CommonFunc::ParseBool(env, arg, asyncCallbackInfo->isEnable)) {
            APP_LOGE("parse isEnable failed");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, IS_ENABLE, TYPE_BOOLEAN);
            return false;
        }
    } else {
        APP_LOGE("param check error");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return false;
    }
    return true;
}

napi_value SetAbilityEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to SetAbilityEnabled");
    NapiArg args(env, info);
    AbilityEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    bool callCloneFunc = false;
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        if (!HandleSetAbilityEnabledArg(env, args[i], i, asyncCallbackInfo, callCloneFunc)) {
            return nullptr;
        }
        if (i == ARGS_POS_TWO) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[i], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    }
    if (callCloneFunc && (args.GetMaxArgc() == ARGS_SIZE_TWO)) {
        APP_LOGE("params are too few for clone app");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityEnableCallbackInfo>(
        env, asyncCallbackInfo, "SetAbilityEnabled", SetAbilityEnabledExec, SetAbilityEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call SetAbilityEnabled done");
    return promise;
}

void IsApplicationEnabledExec(napi_env env, void *data)
{
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    asyncCallbackInfo->err = InnerIsApplicationEnabled(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->isEnable, asyncCallbackInfo->appIndex);
}

void IsApplicationEnabledComplete(napi_env env, napi_status status, void *data)
{
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->isEnable, &result[ARGS_POS_ONE]));
    } else {
        APP_LOGE("asyncCallbackInfo is null");
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, "", "");
    }
    CommonFunc::NapiReturnDeferred<ApplicationEnableCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

bool HandleIsApplicationEnabledArg(napi_env env, napi_value arg, size_t index,
    ApplicationEnableCallbackInfo *asyncCallbackInfo)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);

    if (index == ARGS_POS_ZERO) {
        return ParseBundleName(env, arg, asyncCallbackInfo->bundleName);
    } else if (index == ARGS_POS_ONE) {
        if (valueType == napi_number) {
            return ParseAppIndex(env, arg, asyncCallbackInfo->appIndex);
        }
    } else {
        APP_LOGE("param check error");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return false;
    }
    return true;
}

napi_value IsApplicationEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to IsApplicationEnabled");
    NapiArg args(env, info);
    ApplicationEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        if (!HandleIsApplicationEnabledArg(env, args[i], i, asyncCallbackInfo)) {
            return nullptr;
        }
        if (i == ARGS_POS_ONE) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[i], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationEnableCallbackInfo>(
        env, asyncCallbackInfo, "IsSetApplicationEnabled", IsApplicationEnabledExec, IsApplicationEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call IsSetApplicationEnabled done");
    return promise;
}

void IsAbilityEnabledExec(napi_env env, void *data)
{
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    asyncCallbackInfo->err = InnerIsAbilityEnabled(asyncCallbackInfo->abilityInfo,
        asyncCallbackInfo->isEnable, asyncCallbackInfo->appIndex);
}

void IsAbilityEnabledComplete(napi_env env, napi_status status, void *data)
{
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->isEnable, &result[ARGS_POS_ONE]));
    } else {
        APP_LOGE("asyncCallbackInfo is null");
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, "", "");
    }
    CommonFunc::NapiReturnDeferred<AbilityEnableCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

bool HandleIsAbilityEnabledArg(napi_env env, napi_value arg, size_t index,
    AbilityEnableCallbackInfo *asyncCallbackInfo)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);

    if (index == ARGS_POS_ZERO) {
        if (!CommonFunc::ParseAbilityInfo(env, arg, asyncCallbackInfo->abilityInfo)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
            return false;
        }
    } else if (index == ARGS_POS_ONE) {
        if (valueType == napi_number) {
            return ParseAppIndex(env, arg, asyncCallbackInfo->appIndex);
        }
    } else {
        APP_LOGE("param check error");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return false;
    }
    return true;
}

napi_value IsAbilityEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to IsAbilityEnabled");
    NapiArg args(env, info);
    AbilityEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("Napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        if (!HandleIsAbilityEnabledArg(env, args[i], i, asyncCallbackInfo)) {
            return nullptr;
        }
        if (i == ARGS_POS_ONE) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[i], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityEnableCallbackInfo>(
        env, asyncCallbackInfo, "IsAbilityEnabled", IsAbilityEnabledExec, IsAbilityEnabledComplete);
    callbackPtr.release();
    APP_LOGD("call SetAbilityEnabled done");
    return promise;
}

static ErrCode InnerCleanBundleCacheCallback(
    const std::string &bundleName, int32_t appIndex, const OHOS::sptr<CleanCacheCallback> cleanCacheCallback)
{
    if (cleanCacheCallback == nullptr) {
        APP_LOGE("callback nullptr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode result = iBundleMgr->CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId, appIndex);
    if (result != ERR_OK) {
        APP_LOGE("call error, bundleName is %{public}s, userId is %{public}d, appIndex is %{public}d",
            bundleName.c_str(), userId, appIndex);
    }
    return CommonFunc::ConvertErrCode(result);
}

void CleanBundleCacheFilesExec(napi_env env, void *data)
{
    CleanBundleCacheCallbackInfo* asyncCallbackInfo = reinterpret_cast<CleanBundleCacheCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("error CleanBundleCacheCallbackInfo is nullptr");
        return;
    }
    if (asyncCallbackInfo->cleanCacheCallback == nullptr) {
        asyncCallbackInfo->cleanCacheCallback = new (std::nothrow) CleanCacheCallback();
    }
    asyncCallbackInfo->err = InnerCleanBundleCacheCallback(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->appIndex, asyncCallbackInfo->cleanCacheCallback);
    if ((asyncCallbackInfo->err == NO_ERROR) && (asyncCallbackInfo->cleanCacheCallback != nullptr)) {
        // wait for OnCleanCacheFinished
        APP_LOGI("clean exec wait");
        if (asyncCallbackInfo->cleanCacheCallback->WaitForCompletion()) {
            asyncCallbackInfo->err = asyncCallbackInfo->cleanCacheCallback->GetErr() ?
                NO_ERROR : ERROR_BUNDLE_SERVICE_EXCEPTION;
        } else {
            APP_LOGI("clean exec timeout");
            asyncCallbackInfo->err = ERROR_BUNDLE_SERVICE_EXCEPTION;
        }
    }
    APP_LOGI("clean exec end");
}

void CleanBundleCacheFilesComplete(napi_env env, napi_status status, void *data)
{
    CleanBundleCacheCallbackInfo* asyncCallbackInfo = reinterpret_cast<CleanBundleCacheCallbackInfo*>(data);
    std::unique_ptr<CleanBundleCacheCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[1] = { 0 };
    // implement callback or promise
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            "CleanBundleCacheFiles", Constants::PERMISSION_REMOVECACHEFILE);
    }
    CommonFunc::NapiReturnDeferred<CleanBundleCacheCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

bool ParseCleanBundleCacheFilesAppIndex(napi_env env, napi_value args, int32_t &appIndex)
{
    if (!CommonFunc::ParseInt(env, args, appIndex)) {
        APP_LOGE("parse appIndex failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_INVALID_APPINDEX, APP_INDEX, TYPE_NUMBER);
        return false;
    }
    if (appIndex < Constants::MAIN_APP_INDEX || appIndex > Constants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("appIndex: %{public}d not in valid range", appIndex);
        BusinessError::ThrowParameterTypeError(env, ERROR_INVALID_APPINDEX, APP_INDEX, TYPE_NUMBER);
        return false;
    }
    return true;
}

napi_value CleanBundleCacheFiles(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to CleanBundleCacheFiles");
    NapiArg args(env, info);
    CleanBundleCacheCallbackInfo *asyncCallbackInfo = new (std::nothrow) CleanBundleCacheCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("CleanBundleCacheFiles asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<CleanBundleCacheCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("CleanBundleCacheFiles napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    if (maxArgc < ARGS_SIZE_ONE) {
        APP_LOGE("param error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
        APP_LOGE("CleanBundleCacheFiles bundleName is not a string");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PARAMETER_BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (maxArgc >= ARGS_SIZE_TWO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_ONE], &valueType);
        if (valueType == napi_function) {
            NAPI_CALL(
                env, napi_create_reference(env, args[ARGS_POS_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else if (valueType == napi_number) {
            if (!ParseCleanBundleCacheFilesAppIndex(env, args[ARGS_POS_ONE], asyncCallbackInfo->appIndex)) {
                return nullptr;
            }
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<CleanBundleCacheCallbackInfo>(
        env, asyncCallbackInfo, "CleanBundleCacheFiles", CleanBundleCacheFilesExec, CleanBundleCacheFilesComplete);
    callbackPtr.release();
    APP_LOGD("napi call CleanBundleCacheFiles done");
    return promise;
}

ErrCode InnerVerify(const std::vector<std::string> &abcPaths, bool flag)
{
    auto verifyManager = CommonFunc::GetVerifyManager();
    if (verifyManager == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode ret = verifyManager->Verify(abcPaths);
    if (ret == ERR_OK && flag) {
        verifyManager->RemoveFiles(abcPaths);
    }
    return CommonFunc::ConvertErrCode(ret);
}

void VerifyExec(napi_env env, void *data)
{
    VerifyCallbackInfo* asyncCallbackInfo = reinterpret_cast<VerifyCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("error VerifyCallbackInfo is nullptr");
        return;
    }

    asyncCallbackInfo->err = InnerVerify(asyncCallbackInfo->abcPaths, asyncCallbackInfo->flag);
}

void VerifyComplete(napi_env env, napi_status status, void *data)
{
    VerifyCallbackInfo *asyncCallbackInfo = reinterpret_cast<VerifyCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<VerifyCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, VERIFY_ABC, Constants::PERMISSION_RUN_DYN_CODE);
    }

    CommonFunc::NapiReturnDeferred<VerifyCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value VerifyAbc(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi call VerifyAbc called");
    NapiArg args(env, info);
    VerifyCallbackInfo *asyncCallbackInfo = new (std::nothrow) VerifyCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("VerifyCallbackInfo asyncCallbackInfo is null");
        return nullptr;
    }

    std::unique_ptr<VerifyCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("VerifyCallbackInfo napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (!CommonFunc::ParseStringArray(env, asyncCallbackInfo->abcPaths, args[ARGS_POS_ZERO])) {
        APP_LOGE("ParseStringArray invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, VERIFY_ABC, TYPE_ARRAY);
        return nullptr;
    }

    if (!CommonFunc::ParseBool(env, args[ARGS_POS_ONE], asyncCallbackInfo->flag)) {
        APP_LOGE("ParseBool invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, VERIFY_ABC, TYPE_BOOLEAN);
        return nullptr;
    }

    size_t maxArgc = args.GetMaxArgc();
    if (maxArgc > ARGS_SIZE_TWO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[ARGS_SIZE_TWO], &valueType);
        if (valueType == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[ARGS_SIZE_TWO],
                NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<VerifyCallbackInfo>(
        env, asyncCallbackInfo, "VerifyAbc", VerifyExec, VerifyComplete);
    callbackPtr.release();
    APP_LOGD("napi call VerifyAbc done");
    return promise;
}

ErrCode InnerGetExtResource(
    const std::string &bundleName, std::vector<std::string> &moduleNames)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode ret = extResourceManager->GetExtResource(bundleName, moduleNames);
    if (ret != ERR_OK) {
        APP_LOGE("GetExtResource failed");
    }

    return CommonFunc::ConvertErrCode(ret);
}

void GetExtResourceExec(napi_env env, void *data)
{
    DynamicIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<DynamicIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetExtResource(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleNames);
}

static void SetStrArrayToNapiObj(
    napi_env env, napi_value result, const std::vector<std::string> &strArray)
{
    if (strArray.size() == 0) {
        APP_LOGD("bundleInfos is null");
        return;
    }
    size_t index = 0;
    for (const auto &item : strArray) {
        APP_LOGD("item: %{public}s ", item.c_str());
        napi_value itemStr;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(
            env, item.c_str(), NAPI_AUTO_LENGTH, &itemStr));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, itemStr));
        index++;
    }
}

void GetExtResourceComplete(napi_env env, napi_status status, void *data)
{
    DynamicIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<DynamicIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<DynamicIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        SetStrArrayToNapiObj(env, result[ARGS_POS_ONE], asyncCallbackInfo->moduleNames);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_EXT_RESOURCE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }

    CommonFunc::NapiReturnDeferred<DynamicIconCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetExtResource(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetExtResource called");
    NapiArg args(env, info);
    DynamicIconCallbackInfo *asyncCallbackInfo = new (std::nothrow) DynamicIconCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<DynamicIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (!CommonFunc::ParseString(env, args[0], asyncCallbackInfo->bundleName)) {
        APP_LOGE("bundleName invalid");
        BusinessError::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DynamicIconCallbackInfo>(
        env, asyncCallbackInfo, "GetExtResource", GetExtResourceExec, GetExtResourceComplete);
    callbackPtr.release();
    APP_LOGD("call GetExtResource done");
    return promise;
}

ErrCode InnerEnableDynamicIcon(
    const std::string &bundleName, const std::string &moduleName)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode ret = extResourceManager->EnableDynamicIcon(bundleName, moduleName);
    if (ret != ERR_OK) {
        APP_LOGE("EnableDynamicIcon failed");
    }

    return CommonFunc::ConvertErrCode(ret);
}

void EnableDynamicIconExec(napi_env env, void *data)
{
    DynamicIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<DynamicIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerEnableDynamicIcon(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleName);
}

void EnableDynamicIconComplete(napi_env env, napi_status status, void *data)
{
    DynamicIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<DynamicIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<DynamicIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
    } else {
        result[0] = BusinessError::CreateCommonError(env,
            asyncCallbackInfo->err, ENABLE_DYNAMIC_ICON, Constants::PERMISSION_ACCESS_DYNAMIC_ICON);
    }

    CommonFunc::NapiReturnDeferred<DynamicIconCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value EnableDynamicIcon(napi_env env, napi_callback_info info)
{
    APP_LOGD("EnableDynamicIcon called");
    NapiArg args(env, info);
    DynamicIconCallbackInfo *asyncCallbackInfo = new (std::nothrow) DynamicIconCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<DynamicIconCallbackInfo> callbackPtr {asyncCallbackInfo};
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
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->moduleName)) {
                APP_LOGE("moduleName invalid");
                BusinessError::ThrowParameterTypeError(
                    env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
                return nullptr;
            }
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DynamicIconCallbackInfo>(
        env, asyncCallbackInfo, "EnableDynamicIcon", EnableDynamicIconExec, EnableDynamicIconComplete);
    callbackPtr.release();
    APP_LOGD("call EnableDynamicIcon done");
    return promise;
}

ErrCode InnerDisableDynamicIcon(const std::string &bundleName)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode ret = extResourceManager->DisableDynamicIcon(bundleName);
    if (ret != ERR_OK) {
        APP_LOGE("DisableDynamicIcon failed");
    }

    return CommonFunc::ConvertErrCode(ret);
}

void DisableDynamicIconExec(napi_env env, void *data)
{
    DynamicIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<DynamicIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerDisableDynamicIcon(asyncCallbackInfo->bundleName);
}

void DisableDynamicIconComplete(napi_env env, napi_status status, void *data)
{
    DynamicIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<DynamicIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<DynamicIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, DISABLE_DYNAMIC_ICON, Constants::PERMISSION_ACCESS_DYNAMIC_ICON);
    }

    CommonFunc::NapiReturnDeferred<DynamicIconCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value DisableDynamicIcon(napi_env env, napi_callback_info info)
{
    APP_LOGD("DisableDynamicIcon called");
    NapiArg args(env, info);
    DynamicIconCallbackInfo *asyncCallbackInfo = new (std::nothrow) DynamicIconCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<DynamicIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (!CommonFunc::ParseString(env, args[0], asyncCallbackInfo->bundleName)) {
        APP_LOGE("bundleName invalid");
        BusinessError::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DynamicIconCallbackInfo>(
        env, asyncCallbackInfo, "DisableDynamicIcon", DisableDynamicIconExec, DisableDynamicIconComplete);
    callbackPtr.release();
    APP_LOGD("call DisableDynamicIcon done");
    return promise;
}

ErrCode InnerGetDynamicIcon(const std::string &bundleName, std::string &moduleName)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode ret = extResourceManager->GetDynamicIcon(bundleName, moduleName);
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("GetDynamicIcon failed");
    }

    return CommonFunc::ConvertErrCode(ret);
}

void GetDynamicIconExec(napi_env env, void *data)
{
    DynamicIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<DynamicIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetDynamicIcon(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleName);
}

void GetDynamicIconComplete(napi_env env, napi_status status, void *data)
{
    DynamicIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<DynamicIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<DynamicIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env,
            asyncCallbackInfo->moduleName.c_str(), NAPI_AUTO_LENGTH, &result[ARGS_POS_ONE]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_DYNAMIC_ICON, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }

    CommonFunc::NapiReturnDeferred<DynamicIconCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetDynamicIcon(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetDynamicIcon called");
    NapiArg args(env, info);
    DynamicIconCallbackInfo *asyncCallbackInfo = new (std::nothrow) DynamicIconCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<DynamicIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (!CommonFunc::ParseString(env, args[0], asyncCallbackInfo->bundleName)) {
        APP_LOGE("bundleName invalid");
        BusinessError::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<DynamicIconCallbackInfo>(
        env, asyncCallbackInfo, "GetDynamicIcon", GetDynamicIconExec, GetDynamicIconComplete);
    callbackPtr.release();
    APP_LOGD("call GetDynamicIcon done");
    return promise;
}

ErrCode InnerDeleteAbc(const std::string &path)
{
    auto verifyManager = CommonFunc::GetVerifyManager();
    if (verifyManager == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode ret = verifyManager->DeleteAbc(path);
    if (ret != ERR_OK) {
        APP_LOGE("DeleteAbc failed");
    }

    return CommonFunc::ConvertErrCode(ret);
}

void DeleteAbcExec(napi_env env, void *data)
{
    VerifyCallbackInfo* asyncCallbackInfo = reinterpret_cast<VerifyCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("error VerifyCallbackInfo is nullptr");
        return;
    }

    asyncCallbackInfo->err = InnerDeleteAbc(asyncCallbackInfo->deletePath);
}

void DeleteAbcComplete(napi_env env, napi_status status, void *data)
{
    VerifyCallbackInfo *asyncCallbackInfo = reinterpret_cast<VerifyCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<VerifyCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, DELETE_ABC, Constants::PERMISSION_RUN_DYN_CODE);
    }

    CommonFunc::NapiReturnDeferred<VerifyCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value DeleteAbc(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi call DeleteAbc called");
    NapiArg args(env, info);
    VerifyCallbackInfo *asyncCallbackInfo = new (std::nothrow) VerifyCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("VerifyCallbackInfo asyncCallbackInfo is null");
        return nullptr;
    }

    std::unique_ptr<VerifyCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("VerifyCallbackInfo napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->deletePath)) {
        APP_LOGE("CleanBundleCacheFiles deletePath is not a string");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, DELETE_ABC, TYPE_STRING);
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<VerifyCallbackInfo>(
        env, asyncCallbackInfo, "DeleteAbc", DeleteAbcExec, DeleteAbcComplete);
    callbackPtr.release();
    APP_LOGD("napi call DeleteAbc done");
    return promise;
}

static ErrCode InnerGetLaunchWantForBundleExec(
    const std::string& bundleName, Want &want, int32_t userId)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode result = iBundleMgr->GetLaunchWantForBundle(bundleName, want, userId);
    if (result != ERR_OK) {
        APP_LOGE("GetLaunchWantForBundle call error, bundleName is %{public}s, userId is %{public}d",
            bundleName.c_str(), userId);
    }

    return CommonFunc::ConvertErrCode(result);
}

void GetLaunchWantForBundleExec(napi_env env, void *data)
{
    LaunchWantCallbackInfo* asyncCallbackInfo = reinterpret_cast<LaunchWantCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("error LaunchWantCallbackInfo is nullptr");
        return;
    }

    asyncCallbackInfo->err = InnerGetLaunchWantForBundleExec(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->want, asyncCallbackInfo->userId);
}

void GetLaunchWantForBundleComplete(napi_env env, napi_status status, void *data)
{
    LaunchWantCallbackInfo *asyncCallbackInfo = reinterpret_cast<LaunchWantCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<LaunchWantCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        CommonFunc::ConvertWantInfo(env, result[1], asyncCallbackInfo->want);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, GET_LAUNCH_WANT_FOR_BUNDLE,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }

    CommonFunc::NapiReturnDeferred<LaunchWantCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetLaunchWantForBundle(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to GetLaunchWantForBundle");
    NapiArg args(env, info);
    LaunchWantCallbackInfo *asyncCallbackInfo = new (std::nothrow) LaunchWantCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("GetLaunchWantForBundle asyncCallbackInfo is null");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    std::unique_ptr<LaunchWantCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("GetLaunchWantForBundle napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    for (size_t i = 0; i < maxArgc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (valueType != napi_string) {
                APP_LOGE("GetLaunchWantForBundle bundleName is not a string");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, STRING_TYPE);
                return nullptr;
            }
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName);
            if (asyncCallbackInfo->bundleName.size() == 0) {
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, STRING_TYPE);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
        } else {
            APP_LOGE("GetLaunchWantForBundle arg err");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<LaunchWantCallbackInfo>(
        env, asyncCallbackInfo, "GetLaunchWantForBundle", GetLaunchWantForBundleExec, GetLaunchWantForBundleComplete);
    callbackPtr.release();
    APP_LOGD("napi call GetLaunchWantForBundle done");
    return promise;
}

ErrCode GetAbilityFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, AbilityInfo& targetAbilityInfo)
{
    bool ifExists = false;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& abilityInfo : hapModuleInfo.abilityInfos) {
            if (abilityInfo.name == abilityName && abilityInfo.moduleName == moduleName) {
                if (!abilityInfo.enabled) {
                    APP_LOGI("ability disabled");
                    return ERR_BUNDLE_MANAGER_ABILITY_DISABLED;
                }
                ifExists = true;
                targetAbilityInfo = abilityInfo;
                break;
            }
        }
        if (ifExists) {
            break;
        }
    }
    if (!ifExists) {
        APP_LOGE("ability not exist");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode GetExtensionFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, ExtensionAbilityInfo& targetExtensionInfo)
{
    bool ifExists = false;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& extensionInfo : hapModuleInfo.extensionInfos) {
            if (extensionInfo.name == abilityName && extensionInfo.moduleName == moduleName) {
                ifExists = true;
                targetExtensionInfo = extensionInfo;
                break;
            }
            if (!extensionInfo.enabled) {
                APP_LOGI("extension disabled");
                return ERR_BUNDLE_MANAGER_ABILITY_DISABLED;
            }
        }
        if (ifExists) {
            break;
        }
    }
    if (!ifExists) {
        APP_LOGE("ability not exist");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

static ErrCode InnerGetProfile(GetProfileCallbackInfo &info)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    if (info.abilityName.empty()) {
        APP_LOGE("InnerGetProfile failed due to empty abilityName");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }

    if (info.moduleName.empty()) {
        APP_LOGE("InnerGetProfile failed due to empty moduleName");
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    ErrCode result;
    BundleMgrClient client;
    BundleInfo bundleInfo;
    if (info.type == AbilityProfileType::ABILITY_PROFILE) {
        auto getAbilityFlag = baseFlag +
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
        result = iBundleMgr->GetBundleInfoForSelf(getAbilityFlag, bundleInfo);
        if (result != ERR_OK) {
            APP_LOGE("GetBundleInfoForSelf failed");
            return result;
        }
        AbilityInfo targetAbilityInfo;
        result = GetAbilityFromBundleInfo(
            bundleInfo, info.abilityName, info.moduleName, targetAbilityInfo);
        if (result != ERR_OK) {
            return result;
        }
        if (!client.GetProfileFromAbility(targetAbilityInfo, info.metadataName, info.profileVec)) {
            APP_LOGE("GetProfileFromExtension failed");
            return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST;
        }
        return ERR_OK;
    }

    if (info.type == AbilityProfileType::EXTENSION_PROFILE) {
        auto getExtensionFlag = baseFlag +
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY);
        result = iBundleMgr->GetBundleInfoForSelf(getExtensionFlag, bundleInfo);
        if (result != ERR_OK) {
            APP_LOGE("GetBundleInfoForSelf failed");
            return result;
        }

        ExtensionAbilityInfo targetExtensionInfo;
        result = GetExtensionFromBundleInfo(
            bundleInfo, info.abilityName, info.moduleName, targetExtensionInfo);
        if (result != ERR_OK) {
            return result;
        }
        if (!client.GetProfileFromExtension(targetExtensionInfo, info.metadataName, info.profileVec)) {
            APP_LOGE("GetProfileFromExtension failed");
            return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST;
        }
        return ERR_OK;
    }

    APP_LOGE("InnerGetProfile failed due to type is invalid");
    return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
}

void GetProfileExec(napi_env env, void *data)
{
    GetProfileCallbackInfo* asyncCallbackInfo = reinterpret_cast<GetProfileCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("error GetProfileCallbackInfo is nullptr");
        return;
    }

    ErrCode result = InnerGetProfile(*asyncCallbackInfo);
    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(result);
}

void GetProfileComplete(napi_env env, napi_status status, void *data)
{
    GetProfileCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetProfileCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<GetProfileCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_POS_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
        CommonFunc::ConvertStringArrays(env, asyncCallbackInfo->profileVec, result[1]);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, "", "");
    }

    CommonFunc::NapiReturnDeferred<GetProfileCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetProfile(napi_env env, napi_callback_info info, const AbilityProfileType &profileType)
{
    APP_LOGD("napi begin to GetProfile");
    NapiArg args(env, info);
    GetProfileCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetProfileCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("GetProfile asyncCallbackInfo is null");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    asyncCallbackInfo->type = profileType;
    std::unique_ptr<GetProfileCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_POS_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("GetProfile napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    size_t maxArgc = args.GetMaxArgc();
    for (size_t i = 0; i < maxArgc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (valueType != napi_string) {
                APP_LOGE("GetProfile moduleName is not a string");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, STRING_TYPE);
                return nullptr;
            }
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->moduleName);
        } else if (i == ARGS_POS_ONE) {
            if (valueType != napi_string) {
                APP_LOGE("GetProfile abilityName is not a string");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_NAME, STRING_TYPE);
                return nullptr;
            }
            CommonFunc::ParseString(env, args[i], asyncCallbackInfo->abilityName);
        } else if (i == ARGS_POS_TWO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->metadataName)) {
                APP_LOGW("Parse metadataName failed, The default value is undefined");
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
        } else {
            APP_LOGE("GetProfile arg err");
            BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetProfileCallbackInfo>(
        env, asyncCallbackInfo, "GetProfile", GetProfileExec, GetProfileComplete);
    callbackPtr.release();
    APP_LOGD("napi call GetProfile done");
    return promise;
}

napi_value GetProfileByAbility(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to GetProfileByAbility");
    return GetProfile(env, info, AbilityProfileType::ABILITY_PROFILE);
}

napi_value GetProfileByExAbility(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to GetProfileByExAbility");
    return GetProfile(env, info, AbilityProfileType::EXTENSION_PROFILE);
}

void CreateExtensionAbilityFlagObject(napi_env env, napi_value value)
{
    napi_value nGetExtensionAbilityInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT), &nGetExtensionAbilityInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_DEFAULT",
        nGetExtensionAbilityInfoDefault));

    napi_value nGetExtensionAbilityInfoWithPermission;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(
            GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION),
            &nGetExtensionAbilityInfoWithPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION",
        nGetExtensionAbilityInfoWithPermission));

    napi_value nGetExtensionAbilityInfoWithApplication;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(
            GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION),
            &nGetExtensionAbilityInfoWithApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION",
        nGetExtensionAbilityInfoWithApplication));

    napi_value nGetExtensionAbilityInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(
            GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA),
            &nGetExtensionAbilityInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_WITH_METADATA",
        nGetExtensionAbilityInfoWithMetadata));

    napi_value nGetExtensionAbilityInfoWithSkill;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(
            GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL),
            &nGetExtensionAbilityInfoWithSkill));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_EXTENSION_ABILITY_INFO_WITH_SKILL",
        nGetExtensionAbilityInfoWithSkill));
}

void CreateExtensionAbilityTypeObject(napi_env env, napi_value value)
{
    napi_value nForm;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::FORM), &nForm));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FORM", nForm));

    napi_value nWorkSchedule;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::WORK_SCHEDULER), &nWorkSchedule));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WORK_SCHEDULER", nWorkSchedule));

    napi_value nInputMethod;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD), &nInputMethod));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "INPUT_METHOD", nInputMethod));

    napi_value nService;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::SERVICE), &nService));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SERVICE", nService));

    napi_value nAccessibility;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::ACCESSIBILITY), &nAccessibility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ACCESSIBILITY", nAccessibility));

    napi_value nDataShare;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::DATASHARE), &nDataShare));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DATA_SHARE", nDataShare));

    napi_value nFileShare;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::FILESHARE), &nFileShare));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FILE_SHARE", nFileShare));

    napi_value nStaticSubscriber;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::STATICSUBSCRIBER), &nStaticSubscriber));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STATIC_SUBSCRIBER", nStaticSubscriber));

    napi_value nWallpaper;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::WALLPAPER), &nWallpaper));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WALLPAPER", nWallpaper));

    napi_value nBackup;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::BACKUP), &nBackup));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "BACKUP", nBackup));

    napi_value nDistributed;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::DISTRIBUTED), &nDistributed));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DISTRIBUTED", nDistributed));

    napi_value nWindow;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::WINDOW), &nWindow));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WINDOW", nWindow));

    napi_value nEnterpriseAdmin;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::ENTERPRISE_ADMIN), &nEnterpriseAdmin));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ENTERPRISE_ADMIN", nEnterpriseAdmin));

    napi_value nTHUMBNAIL;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::THUMBNAIL), &nTHUMBNAIL));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "THUMBNAIL", nTHUMBNAIL));

    napi_value nPREVIEW;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::PREVIEW), &nPREVIEW));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PREVIEW", nPREVIEW));

    napi_value nPrint;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::PRINT), &nPrint));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PRINT", nPrint));

    napi_value nShare;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SHARE), &nShare));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SHARE", nShare));

    napi_value nAction;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::ACTION), &nAction));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ACTION", nAction));

    napi_value nAdsService;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::ADS_SERVICE), &nAdsService));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ADS_SERVICE", nAdsService));

    napi_value nEmbeddedUI;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::EMBEDDED_UI), &nEmbeddedUI));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EMBEDDED_UI", nEmbeddedUI));

    napi_value nfence;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::FENCE), &nfence));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FENCE", nfence));

    napi_value nInsightIntentUI;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::INSIGHT_INTENT_UI), &nInsightIntentUI));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "INSIGHT_INTENT_UI", nInsightIntentUI));

    napi_value nAuthorization;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION), &nAuthorization));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "APP_ACCOUNT_AUTHORIZATION", nAuthorization));

    napi_value nUI;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::UI), &nUI));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UI", nUI));

    napi_value nPush;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::PUSH), &nPush));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PUSH", nPush));

    napi_value nDriver;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::DRIVER), &nDriver));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DRIVER", nDriver));

    napi_value nUnspecified;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED), &nUnspecified));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNSPECIFIED", nUnspecified));

    napi_value nRemoteNotification;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::REMOTE_NOTIFICATION), &nRemoteNotification));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "REMOTE_NOTIFICATION", nRemoteNotification));

    napi_value nRemoteLocation;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::REMOTE_LOCATION), &nRemoteLocation));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "REMOTE_LOCATION", nRemoteLocation));

    napi_value nVoip;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::VOIP), &nVoip));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "VOIP", nVoip));

    napi_value nSysDialogUserAuth;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYSDIALOG_USERAUTH), &nSysDialogUserAuth));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSDIALOG_USERAUTH", nSysDialogUserAuth));

    napi_value nSysDialogCommon;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::SYSDIALOG_COMMON), &nSysDialogCommon));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSDIALOG_COMMON", nSysDialogCommon));

    napi_value nMediaControl;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYSPICKER_MEDIACONTROL), &nMediaControl));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSPICKER_MEDIACONTROL", nMediaControl));

    napi_value nSysDialogAtomicServicePanel;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYSDIALOG_ATOMICSERVICEPANEL), &nSysDialogAtomicServicePanel));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, value, "SYSDIALOG_ATOMICSERVICEPANEL", nSysDialogAtomicServicePanel));

    napi_value nSysDialogPower;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::SYSDIALOG_POWER), &nSysDialogPower));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSDIALOG_POWER", nSysDialogPower));

    napi_value nSysPickerShare;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYSPICKER_SHARE), &nSysPickerShare));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSPICKER_SHARE", nSysPickerShare));

    napi_value nSysHmsAccount;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::HMS_ACCOUNT), &nSysHmsAccount));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "HMS_ACCOUNT", nSysHmsAccount));

    napi_value nSysDialogMeetimeCall;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYSDIALOG_MEETIMECALL), &nSysDialogMeetimeCall));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSDIALOG_MEETIMECALL", nSysDialogMeetimeCall));

    napi_value nSysDialogMeetimeContact;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYSDIALOG_MEETIMECONTACT), &nSysDialogMeetimeContact));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSDIALOG_MEETIMECONTACT",
        nSysDialogMeetimeContact));

    napi_value nSysDialogMeetimeMessage;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYSDIALOG_MEETIMEMESSAGE), &nSysDialogMeetimeMessage));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSDIALOG_MEETIMEMESSAGE",
        nSysDialogMeetimeMessage));

    napi_value nSysPickerMeetimeContact;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYSPICKER_MEETIMECONTACT), &nSysPickerMeetimeContact));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSPICKER_MEETIMECONTACT",
        nSysPickerMeetimeContact));

    napi_value nSysPickerMeetimeCallLog;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYSPICKER_MEETIMECALLLOG), &nSysPickerMeetimeCallLog));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYSPICKER_MEETIMECALLLOG",
        nSysPickerMeetimeCallLog));

    napi_value nAds;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(ExtensionAbilityType::ADS), &nAds));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ADS", nAds));

    napi_value nSysCommonUI;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::SYS_COMMON_UI), &nSysCommonUI));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SYS_COMMON_UI", nSysCommonUI));

    napi_value nPhotoEditor;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::PHOTO_EDITOR), &nPhotoEditor));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PHOTO_EDITOR", nPhotoEditor));

    napi_value nCallerInfoQuery;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::CALLER_INFO_QUERY), &nCallerInfoQuery));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "CALLER_INFO_QUERY", nCallerInfoQuery));

    napi_value nAssetAcceleration;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::ASSET_ACCELERATION), &nAssetAcceleration));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ASSET_ACCELERATION", nAssetAcceleration));

    napi_value nFormEdit;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(ExtensionAbilityType::FORM_EDIT), &nFormEdit));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FORM_EDIT", nFormEdit));
}

void CreateApplicationFlagObject(napi_env env, napi_value value)
{
    napi_value nGetApplicationInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), &nGetApplicationInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_DEFAULT",
        nGetApplicationInfoDefault));

    napi_value nGetApplicationInfoWithPermission;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION), &nGetApplicationInfoWithPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_WITH_PERMISSION",
        nGetApplicationInfoWithPermission));

    napi_value nGetApplicationInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA), &nGetApplicationInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_WITH_METADATA",
        nGetApplicationInfoWithMetadata));

    napi_value nGetApplicationInfoWithDisable;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), &nGetApplicationInfoWithDisable));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_APPLICATION_INFO_WITH_DISABLE",
        nGetApplicationInfoWithDisable));
}

void CreateApplicationInfoFlagObject(napi_env env, napi_value value)
{
    napi_value nApplicationInfoFlagInstalled;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        ApplicationInfoFlag::FLAG_INSTALLED), &nApplicationInfoFlagInstalled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FLAG_INSTALLED",
        nApplicationInfoFlagInstalled));

    napi_value nApplicationInfoFlagOtherInstalled;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        ApplicationInfoFlag::FLAG_OTHER_INSTALLED), &nApplicationInfoFlagOtherInstalled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FLAG_OTHER_INSTALLED",
        nApplicationInfoFlagOtherInstalled));

    napi_value nApplicationInfoFlagPreinstalledApp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        ApplicationInfoFlag::FLAG_PREINSTALLED_APP), &nApplicationInfoFlagPreinstalledApp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FLAG_PREINSTALLED_APP",
        nApplicationInfoFlagPreinstalledApp));

    napi_value nApplicationInfoFlagPreinstalledAppUpdate;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        ApplicationInfoFlag::FLAG_PREINSTALLED_APP_UPDATE), &nApplicationInfoFlagPreinstalledAppUpdate));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FLAG_PREINSTALLED_APP_UPDATE",
        nApplicationInfoFlagPreinstalledAppUpdate));
}

void CreateAppDistributionTypeObject(napi_env env, napi_value value)
{
    napi_value nAppGallery;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ENUM_ONE, &nAppGallery));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "APP_GALLERY", nAppGallery));

    napi_value nEnterprise;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ENUM_TWO, &nEnterprise));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ENTERPRISE", nEnterprise));

    napi_value nEnterPriseNormal;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ENUM_THREE, &nEnterPriseNormal));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ENTERPRISE_NORMAL", nEnterPriseNormal));

    napi_value nEnterPriseMdm;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ENUM_FOUR, &nEnterPriseMdm));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ENTERPRISE_MDM", nEnterPriseMdm));

    napi_value nOsIntegration;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ENUM_FIVE, &nOsIntegration));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "OS_INTEGRATION", nOsIntegration));

    napi_value nCrowdTesting;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ENUM_SIX, &nCrowdTesting));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "CROWDTESTING", nCrowdTesting));

    napi_value nNone;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ENUM_SEVEN, &nNone));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "NONE", nNone));
}

static ErrCode InnerGetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetPermissionDef(permissionName, permissionDef);
    return CommonFunc::ConvertErrCode(ret);
}

void GetPermissionDefExec(napi_env env, void *data)
{
    AsyncPermissionDefineCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncPermissionDefineCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerGetPermissionDef(asyncCallbackInfo->permissionName,
            asyncCallbackInfo->permissionDef);
    }
}

void GetPermissionDefComplete(napi_env env, napi_status status, void *data)
{
    AsyncPermissionDefineCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncPermissionDefineCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AsyncPermissionDefineCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertPermissionDef(env, result[ARGS_POS_ONE], asyncCallbackInfo->permissionDef);
    } else {
        result[0] = BusinessError::CreateCommonError(
            env, asyncCallbackInfo->err, GET_PERMISSION_DEF, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<AsyncPermissionDefineCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

/**
 * Promise and async callback
 */
napi_value GetPermissionDef(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetPermissionDef called");
    NapiArg args(env, info);
    AsyncPermissionDefineCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncPermissionDefineCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AsyncPermissionDefineCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[i], &valuetype));
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->permissionName)) {
                APP_LOGE("permissionName invalid");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PERMISSION_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valuetype == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                APP_LOGD("GetPermissionDef extra arg ignored");
            }
        } else {
            APP_LOGE("GetPermissionDef arg err");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<AsyncPermissionDefineCallbackInfo>(
        env, asyncCallbackInfo, "GetPermissionDef", GetPermissionDefExec, GetPermissionDefComplete);
    callbackPtr.release();
    return promise;
}

static void CheckToCache(napi_env env, int32_t uid, int32_t callingUid, const Query &query, napi_value jsObject)
{
    if (uid != callingUid) {
        APP_LOGD("uid %{public}d and callingUid %{public}d not equal", uid, callingUid);
        return;
    }
    napi_ref cacheApplicationInfo = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, jsObject, NAPI_RETURN_ONE, &cacheApplicationInfo));
    std::unique_lock<std::shared_mutex> lock(g_cacheMutex);
    cache[query] = cacheApplicationInfo;
}

napi_value GetApplicationInfoSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetApplicationInfoSync call");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], bundleName)) {
                APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], flags)) {
                APP_LOGE("parseInt failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (!CommonFunc::ParseInt(env, args[i], userId)) {
                APP_LOGW("userId parseInt failed");
            }
        } else {
            APP_LOGE("parameter is invalid");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    if (bundleName.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_NOT_EXIST, GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    napi_value nApplicationInfo = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        auto item = cache.find(Query(bundleName, GET_APPLICATION_INFO, flags, userId, env));
        if (item != cache.end()) {
            APP_LOGD("getApplicationInfo param from cache");
            NAPI_CALL(env,
                napi_get_reference_value(env, item->second, &nApplicationInfo));
            return nApplicationInfo;
        }
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return nullptr;
    }
    AppExecFwk::ApplicationInfo appInfo;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetApplicationInfoV9(bundleName, flags, userId, appInfo));
    if (ret != NO_ERROR) {
        APP_LOGE_NOFUNC("GetApplicationInfo failed -n:%{public}s -f: %{public}d -u: %{public}d",
            bundleName.c_str(), flags, userId);
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    NAPI_CALL(env, napi_create_object(env, &nApplicationInfo));
    CommonFunc::ConvertApplicationInfo(env, nApplicationInfo, appInfo);
    Query query(bundleName, GET_APPLICATION_INFO, flags, userId, env);
    CheckToCache(env, appInfo.uid, IPCSkeleton::GetCallingUid(), query, nApplicationInfo);
    return nApplicationInfo;
}

napi_value GetBundleInfoSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetBundleInfoSync call");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[i], &valueType));
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], bundleName)) {
                APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], flags)) {
                APP_LOGE("parseInt failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if ((valueType == napi_number) && (!CommonFunc::ParseInt(env, args[i], userId))) {
                APP_LOGE("parseInt failed");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
                return nullptr;
            }
        } else {
            APP_LOGE("parameter is invalid");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    if (bundleName.size() == 0) {
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_NOT_EXIST, GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    napi_value nBundleInfo = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        auto item = cache.find(Query(bundleName, GET_BUNDLE_INFO, flags, userId, env));
        if (item != cache.end()) {
            APP_LOGD("GetBundleInfo param from cache");
            NAPI_CALL(env,
                napi_get_reference_value(env, item->second, &nBundleInfo));
            return nBundleInfo;
        }
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("BundleMgr is null");
        return nullptr;
    }
    BundleInfo bundleInfo;
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->GetBundleInfoV9(bundleName, flags, bundleInfo, userId));
    if (ret != NO_ERROR) {
        APP_LOGE_NOFUNC("GetBundleInfoV9 failed -n %{public}s -f %{public}d -u %{public}d",
            bundleName.c_str(), flags, userId);
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    NAPI_CALL(env, napi_create_object(env,  &nBundleInfo));
    CommonFunc::ConvertBundleInfo(env, bundleInfo, nBundleInfo, flags);
    if (!CommonFunc::CheckBundleFlagWithPermission(flags)) {
        Query query(bundleName, GET_BUNDLE_INFO, flags, userId, env);
        CheckToCache(env, bundleInfo.uid, IPCSkeleton::GetCallingUid(), query, nBundleInfo);
    }
    return nBundleInfo;
}

static ErrCode InnerGetBundleInfos(int32_t flags,
    int32_t userId, std::vector<BundleInfo> &bundleInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetBundleInfosV9(flags, bundleInfos, userId);
    return CommonFunc::ConvertErrCode(ret);
}

void CreateBundleFlagObject(napi_env env, napi_value value)
{
    napi_value nBundleInfoDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT),
        &nBundleInfoDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_DEFAULT",
        nBundleInfoDefault));

    napi_value nGetBundleInfoWithApplication;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION), &nGetBundleInfoWithApplication));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_APPLICATION",
        nGetBundleInfoWithApplication));

    napi_value nGetBundleInfoWithHapModule;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE), &nGetBundleInfoWithHapModule));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_HAP_MODULE",
        nGetBundleInfoWithHapModule));

    napi_value nGetBundleInfoWithAbility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY), &nGetBundleInfoWithAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_ABILITY",
        nGetBundleInfoWithAbility));

    napi_value nGetBundleInfoWithExtensionAbility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY), &nGetBundleInfoWithExtensionAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY",
        nGetBundleInfoWithExtensionAbility));

    napi_value nGetBundleInfoWithRequestedPermission;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION), &nGetBundleInfoWithRequestedPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION",
        nGetBundleInfoWithRequestedPermission));

    napi_value nGetBundleInfoWithMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), &nGetBundleInfoWithMetadata));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_METADATA",
        nGetBundleInfoWithMetadata));

    napi_value nGetBundleInfoWithDisable;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), &nGetBundleInfoWithDisable));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_DISABLE",
        nGetBundleInfoWithDisable));

    napi_value nGetBundleInfoWithSignatureInfo;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), &nGetBundleInfoWithSignatureInfo));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_SIGNATURE_INFO",
        nGetBundleInfoWithSignatureInfo));

    napi_value nGetBundleInfoWithMenu;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_MENU), &nGetBundleInfoWithMenu));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_MENU",
        nGetBundleInfoWithMenu));

    napi_value nGetBundleInfoWithRouterMap;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ROUTER_MAP), &nGetBundleInfoWithRouterMap));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_ROUTER_MAP",
        nGetBundleInfoWithRouterMap));

    napi_value nGetBundleInfoWithSkill;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SKILL), &nGetBundleInfoWithSkill));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_WITH_SKILL",
        nGetBundleInfoWithSkill));

    napi_value nGetBundleInfoOnlyWithLauncherAbility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_ONLY_WITH_LAUNCHER_ABILITY), &nGetBundleInfoOnlyWithLauncherAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_ONLY_WITH_LAUNCHER_ABILITY",
        nGetBundleInfoOnlyWithLauncherAbility));

    napi_value nGetBundleInfoExcludeClone;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_EXCLUDE_CLONE), &nGetBundleInfoExcludeClone));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_EXCLUDE_CLONE",
        nGetBundleInfoExcludeClone));
    napi_value nGetBundleInfoOfAnyUser;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(
        GetBundleInfoFlag::GET_BUNDLE_INFO_OF_ANY_USER), &nGetBundleInfoOfAnyUser));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_INFO_OF_ANY_USER",
        nGetBundleInfoOfAnyUser));
}

static ErrCode InnerGetBundleInfo(const std::string &bundleName, int32_t flags,
    int32_t userId, BundleInfo &bundleInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetBundleInfoV9(bundleName, flags, bundleInfo, userId);
    return CommonFunc::ConvertErrCode(ret);
}

static ErrCode InnerGetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetBundleInfoForSelf(flags, bundleInfo);
    return CommonFunc::ConvertErrCode(ret);
}

static void ProcessBundleInfos(
    napi_env env, napi_value result, const std::vector<BundleInfo> &bundleInfos, int32_t flags)
{
    if (bundleInfos.size() == 0) {
        APP_LOGD("bundleInfos is null");
        return;
    }
    size_t index = 0;
    for (const auto &item : bundleInfos) {
        APP_LOGD("name: %{public}s ", item.name.c_str());
        napi_value objBundleInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objBundleInfo));
        CommonFunc::ConvertBundleInfo(env, item, objBundleInfo, flags);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, objBundleInfo));
        index++;
    }
}

void GetBundleInfosComplete(napi_env env, napi_status status, void *data)
{
    BundleInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<BundleInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<BundleInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        ProcessBundleInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->bundleInfos, asyncCallbackInfo->flags);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_BUNDLE_INFOS, Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST);
    }
    CommonFunc::NapiReturnDeferred<BundleInfosCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

void GetBundleInfoComplete(napi_env env, napi_status status, void *data)
{
    BundleInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<BundleInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<BundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        if (asyncCallbackInfo->isSavedInCache) {
            std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
            auto item = cache.find(Query(
                asyncCallbackInfo->bundleName, GET_BUNDLE_INFO,
                asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
            if (item == cache.end()) {
                APP_LOGE("cannot find result in cache");
                return;
            }
            NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, item->second, &result[ARGS_POS_ONE]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
            CommonFunc::ConvertBundleInfo(env,
                asyncCallbackInfo->bundleInfo, result[ARGS_POS_ONE], asyncCallbackInfo->flags);
            if (!CommonFunc::CheckBundleFlagWithPermission(asyncCallbackInfo->flags)) {
                Query query(
                    asyncCallbackInfo->bundleName, GET_BUNDLE_INFO,
                    asyncCallbackInfo->flags, asyncCallbackInfo->userId, env);
                CheckToCache(env, asyncCallbackInfo->bundleInfo.uid, IPCSkeleton::GetCallingUid(),
                    query, result[ARGS_POS_ONE]);
            }
        }
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<BundleInfoCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

void GetBundleInfoExec(napi_env env, void *data)
{
    BundleInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<BundleInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        if (!CommonFunc::CheckBundleFlagWithPermission(asyncCallbackInfo->flags)) {
            std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
            auto item = cache.find(Query(asyncCallbackInfo->bundleName,
                GET_BUNDLE_INFO, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
            if (item != cache.end()) {
                asyncCallbackInfo->isSavedInCache = true;
                APP_LOGD("GetBundleInfo param from cache");
                return;
            }
        }
        asyncCallbackInfo->err = InnerGetBundleInfo(asyncCallbackInfo->bundleName,
            asyncCallbackInfo->flags, asyncCallbackInfo->userId, asyncCallbackInfo->bundleInfo);
    }
}

void GetBundleInfoForSelfExec(napi_env env, void *data)
{
    BundleInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<BundleInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err != NO_ERROR) {
        return;
    }
    auto uid = IPCSkeleton::GetCallingUid();
    asyncCallbackInfo->uid = uid;
    asyncCallbackInfo->bundleName = std::to_string(uid);
    asyncCallbackInfo->userId = uid / Constants::BASE_USER_RANGE;
    if (!CommonFunc::CheckBundleFlagWithPermission(asyncCallbackInfo->flags)) {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        auto item = cache.find(Query(
            asyncCallbackInfo->bundleName, GET_BUNDLE_INFO,
            asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
        if (item != cache.end()) {
            asyncCallbackInfo->isSavedInCache = true;
            APP_LOGD("GetBundleInfo param from cache");
            return;
        }
    }
    asyncCallbackInfo->err = InnerGetBundleInfoForSelf(
        asyncCallbackInfo->flags, asyncCallbackInfo->bundleInfo);
}

napi_value GetBundleInfo(napi_env env, napi_callback_info info)
{
    LOG_NOFUNC_I(BMS_TAG_COMMON, "NAPI GetBundleInfo call");
    NapiArg args(env, info);
    BundleInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) BundleInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<BundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->uid = IPCSkeleton::GetCallingUid();
    asyncCallbackInfo->userId = asyncCallbackInfo->uid / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() < ARGS_SIZE_TWO) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("appId %{public}s invalid", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags %{public}d invalid", asyncCallbackInfo->flags);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<BundleInfoCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_INFO, GetBundleInfoExec, GetBundleInfoComplete);
    callbackPtr.release();
    LOG_NOFUNC_I(BMS_TAG_COMMON, "NAPI GetBundleInfo done");
    return promise;
}

void GetBundleInfosExec(napi_env env, void *data)
{
    BundleInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<BundleInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetBundleInfos(asyncCallbackInfo->flags,
        asyncCallbackInfo->userId, asyncCallbackInfo->bundleInfos);
}

napi_value GetBundleInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetBundleInfos called");
    NapiArg args(env, info);
    BundleInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) BundleInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<BundleInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    if (args.GetMaxArgc() < ARGS_SIZE_ONE) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags %{public}d invalid", asyncCallbackInfo->flags);
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("Parse userId failed, set this parameter to the caller userId");
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<BundleInfosCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_INFOS, GetBundleInfosExec, GetBundleInfosComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetBundleInfos done");
    return promise;
}

napi_value GetBundleInfoForSelf(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetBundleInfoForSelf called");
    NapiArg args(env, info);
    BundleInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) BundleInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<BundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("Flags invalid");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<BundleInfoCallbackInfo>(
        env, asyncCallbackInfo, "GetBundleInfoForSelf", GetBundleInfoForSelfExec, GetBundleInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetBundleInfoForSelf done");
    return promise;
}

static ErrCode InnerGetAllSharedBundleInfo(std::vector<SharedBundleInfo> &sharedBundles)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAllSharedBundleInfo(sharedBundles);
    return CommonFunc::ConvertErrCode(ret);
}

void GetAllSharedBundleInfoExec(napi_env env, void *data)
{
    SharedBundleCallbackInfo *asyncCallbackInfo = reinterpret_cast<SharedBundleCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetAllSharedBundleInfo(asyncCallbackInfo->sharedBundles);
}

void GetAllSharedBundleInfoComplete(napi_env env, napi_status status, void *data)
{
    SharedBundleCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SharedBundleCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<SharedBundleCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertAllSharedBundleInfo(env, result[ARGS_POS_ONE], asyncCallbackInfo->sharedBundles);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_SHARED_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<SharedBundleCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllSharedBundleInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetAllSharedBundleInfo called");
    NapiArg args(env, info);
    SharedBundleCallbackInfo *asyncCallbackInfo = new (std::nothrow) SharedBundleCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<SharedBundleCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ZERO, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (args.GetMaxArgc() < ARGS_SIZE_ZERO) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<SharedBundleCallbackInfo>(env, asyncCallbackInfo,
        GET_ALL_SHARED_BUNDLE_INFO, GetAllSharedBundleInfoExec, GetAllSharedBundleInfoComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetAllSharedBundleInfo done");
    return promise;
}

static ErrCode InnerGetSharedBundleInfo(const std::string &bundleName, const std::string &moduleName,
    std::vector<SharedBundleInfo> &sharedBundles)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetSharedBundleInfo(bundleName, moduleName, sharedBundles);
    return CommonFunc::ConvertErrCode(ret);
}

void GetSharedBundleInfoExec(napi_env env, void *data)
{
    SharedBundleCallbackInfo *asyncCallbackInfo = reinterpret_cast<SharedBundleCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetSharedBundleInfo(asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleName,
        asyncCallbackInfo->sharedBundles);
}

void GetSharedBundleInfoComplete(napi_env env, napi_status status, void *data)
{
    SharedBundleCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SharedBundleCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<SharedBundleCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertAllSharedBundleInfo(env, result[ARGS_POS_ONE], asyncCallbackInfo->sharedBundles);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_SHARED_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<SharedBundleCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetSharedBundleInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetSharedBundleInfo called");
    NapiArg args(env, info);
    SharedBundleCallbackInfo *asyncCallbackInfo = new (std::nothrow) SharedBundleCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<SharedBundleCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (args.GetMaxArgc() < ARGS_SIZE_TWO) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    for (size_t i = 0; i < args.GetMaxArgc(); i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("appId %{public}s invalid", asyncCallbackInfo->bundleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_ONE) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->moduleName)) {
                APP_LOGE("appId %{public}s invalid", asyncCallbackInfo->moduleName.c_str());
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
                return nullptr;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<SharedBundleCallbackInfo>(env, asyncCallbackInfo,
        GET_SHARED_BUNDLE_INFO, GetSharedBundleInfoExec, GetSharedBundleInfoComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetSharedBundleInfo done");
    return promise;
}

void CreatePermissionGrantStateObject(napi_env env, napi_value value)
{
    napi_value nPermissionDenied;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, -1, &nPermissionDenied));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PERMISSION_DENIED",
        nPermissionDenied));

    napi_value nPermissionGranted;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &nPermissionGranted));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PERMISSION_GRANTED",
        nPermissionGranted));
}

void CreateAbilityTypeObject(napi_env env, napi_value value)
{
    napi_value nUnknow;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::UNKNOWN), &nUnknow));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNKNOWN", nUnknow));
    napi_value nPage;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::PAGE), &nPage));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PAGE", nPage));
    napi_value nService;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::SERVICE), &nService));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SERVICE", nService));
    napi_value nData;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::DATA), &nData));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DATA", nData));
}

void CreateBundleTypeObject(napi_env env, napi_value value)
{
    napi_value nApp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(BundleType::APP), &nApp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "APP", nApp));
    napi_value nAtomicService;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(BundleType::ATOMIC_SERVICE), &nAtomicService));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ATOMIC_SERVICE", nAtomicService));
}

void CreateDisplayOrientationObject(napi_env env, napi_value value)
{
    napi_value nUnspecified;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::UNSPECIFIED), &nUnspecified));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNSPECIFIED", nUnspecified));
    napi_value nLandscape;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::LANDSCAPE), &nLandscape));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "LANDSCAPE", nLandscape));
    napi_value nPortrait;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::PORTRAIT), &nPortrait));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PORTRAIT", nPortrait));
    napi_value nFollowrecent;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::FOLLOWRECENT), &nFollowrecent));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FOLLOW_RECENT", nFollowrecent));
    napi_value nReverseLandscape;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::LANDSCAPE_INVERTED), &nReverseLandscape));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "LANDSCAPE_INVERTED", nReverseLandscape));
    napi_value nReversePortrait;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::PORTRAIT_INVERTED), &nReversePortrait));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PORTRAIT_INVERTED", nReversePortrait));
    napi_value nLocked;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::LOCKED), &nLocked));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "LOCKED", nLocked));
    CreateOrientationRelatedToSensor(env, value);
}

void CreateOrientationRelatedToSensor(napi_env env, napi_value value)
{
    napi_value nAutoRotation;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION), &nAutoRotation));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION", nAutoRotation));
    napi_value nAutoRotationLandscape;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_LANDSCAPE),
            &nAutoRotationLandscape));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION_LANDSCAPE", nAutoRotationLandscape));
    napi_value nAutoRotationPortrait;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_PORTRAIT),
            &nAutoRotationPortrait));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION_PORTRAIT", nAutoRotationPortrait));
    napi_value nAutoRotationRestricted;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_RESTRICTED),
            &nAutoRotationRestricted));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION_RESTRICTED",
        nAutoRotationRestricted));
    napi_value nAutoRotationLandscapeRestricted;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_LANDSCAPE_RESTRICTED),
            &nAutoRotationLandscapeRestricted));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, value, "AUTO_ROTATION_LANDSCAPE_RESTRICTED", nAutoRotationLandscapeRestricted));
    napi_value nAutoRotationPortraitRestricted;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_PORTRAIT_RESTRICTED),
            &nAutoRotationPortraitRestricted));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_ROTATION_PORTRAIT_RESTRICTED",
        nAutoRotationPortraitRestricted));
    napi_value nAutoRotationUnspecified;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_UNSPECIFIED),
            &nAutoRotationUnspecified));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, value, "AUTO_ROTATION_UNSPECIFIED", nAutoRotationUnspecified));
    napi_value nFollowDesktop;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::FOLLOW_DESKTOP), &nFollowDesktop));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, value, "FOLLOW_DESKTOP", nFollowDesktop));
}

void CreateLaunchTypeObject(napi_env env, napi_value value)
{
    napi_value nSingleton;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::SINGLETON), &nSingleton));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SINGLETON", nSingleton));
    napi_value nStandard;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::STANDARD), &nStandard));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STANDARD", nStandard));
    napi_value nMultiton;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::STANDARD), &nMultiton));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MULTITON", nMultiton));
    napi_value nSpecified;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::SPECIFIED), &nSpecified));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SPECIFIED", nSpecified));
}

void CreateSupportWindowModesObject(napi_env env, napi_value value)
{
    napi_value nFullscreen;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(SupportWindowMode::FULLSCREEN), &nFullscreen));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FULL_SCREEN", nFullscreen));

    napi_value nSplit;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SupportWindowMode::SPLIT), &nSplit));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SPLIT", nSplit));

    napi_value nFloat;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SupportWindowMode::FLOATING), &nFloat));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FLOATING", nFloat));
}

void CreateModuleTypeObject(napi_env env, napi_value value)
{
    napi_value nUnknown;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ModuleType::UNKNOWN), &nUnknown));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNKNOWN", nUnknown));

    napi_value nEntry;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ModuleType::ENTRY), &nEntry));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ENTRY", nEntry));

    napi_value nFeature;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ModuleType::FEATURE), &nFeature));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FEATURE", nFeature));

    napi_value nShared;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(ModuleType::SHARED), &nShared));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SHARED", nShared));
}

void CreateCompatiblePolicyObject(napi_env env, napi_value value)
{
    napi_value nNORMAL;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(CompatiblePolicy::NORMAL), &nNORMAL));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "NORMAL", nNORMAL));

    napi_value nBackwardCompatibility;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(CompatiblePolicy::BACKWARD_COMPATIBILITY), &nBackwardCompatibility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "BACKWARD_COMPATIBILITY", nBackwardCompatibility));
}

void CreateProfileTypeObject(napi_env env, napi_value value)
{
    napi_value nIntentProfile;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(
        env, static_cast<int32_t>(ProfileType::INTENT_PROFILE), &nIntentProfile));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "INTENT_PROFILE", nIntentProfile));
}

ErrCode InnerGetAppProvisionInfo(
    const std::string &bundleName, int32_t userId, AppProvisionInfo &appProvisionInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAppProvisionInfo(bundleName, userId, appProvisionInfo);
    return CommonFunc::ConvertErrCode(ret);
}

void GetAppProvisionInfoExec(napi_env env, void *data)
{
    AppProvisionInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<AppProvisionInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->err = InnerGetAppProvisionInfo(
            asyncCallbackInfo->bundleName, asyncCallbackInfo->userId, asyncCallbackInfo->appProvisionInfo);
    }
}

void GetAppProvisionInfoComplete(napi_env env, napi_status status, void *data)
{
    AppProvisionInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<AppProvisionInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AppProvisionInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertAppProvisionInfo(env, asyncCallbackInfo->appProvisionInfo, result[ARGS_POS_ONE]);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_APP_PROVISION_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<AppProvisionInfoCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAppProvisionInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi GetAppProvisionInfo called");
    NapiArg args(env, info);
    AppProvisionInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) AppProvisionInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AppProvisionInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    for (size_t i = 0; i < args.GetArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->bundleName)) {
                APP_LOGE("bundleName invalid");
                BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
                return nullptr;
            }
            CHECK_STRING_EMPTY(env, asyncCallbackInfo->bundleName, std::string{ BUNDLE_NAME });
        } else if (i == ARGS_POS_ONE) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->userId)) {
                APP_LOGW("parse userId failed, set this parameter to the caller userId");
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<AppProvisionInfoCallbackInfo>(
        env, asyncCallbackInfo, GET_APP_PROVISION_INFO, GetAppProvisionInfoExec, GetAppProvisionInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetAppProvisionInfo done");
    return promise;
}

napi_value GetSpecifiedDistributionType(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetSpecifiedDistributionType napi called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("bundleName invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_SERVICE_EXCEPTION, RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }

    std::string specifiedDistributionType;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetSpecifiedDistributionType(bundleName, specifiedDistributionType));
    if (ret != SUCCESS) {
        APP_LOGE_NOFUNC("GetSpecifiedDistributionType failed -n %{public}s ret:%{public}d",
            bundleName.c_str(), ret);
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }

    napi_value nSpecifiedDistributionType;
    napi_create_string_utf8(env, specifiedDistributionType.c_str(), NAPI_AUTO_LENGTH, &nSpecifiedDistributionType);
    APP_LOGD("call GetSpecifiedDistributionType done");
    return nSpecifiedDistributionType;
}

napi_value GetAdditionalInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetAdditionalInfo napi called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("bundleName invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    CHECK_STRING_EMPTY(env, bundleName, std::string{ BUNDLE_NAME });

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_SERVICE_EXCEPTION, RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }

    std::string additionalInfo;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetAdditionalInfo(bundleName, additionalInfo));
    if (ret != SUCCESS) {
        APP_LOGE_NOFUNC("GetAdditionalInfo %{public}s error", bundleName.c_str());
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, RESOURCE_NAME_OF_GET_ADDITIONAL_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }

    napi_value nAdditionalInfo;
    napi_create_string_utf8(env, additionalInfo.c_str(), NAPI_AUTO_LENGTH, &nAdditionalInfo);
    APP_LOGD("call GetAdditionalInfo done");
    return nAdditionalInfo;
}

napi_value GetBundleInfoForSelfSync(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetBundleInfoForSelfSync called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    int32_t flags = 0;
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], flags)) {
        APP_LOGE("parseInt invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("BundleMgr is null");
        return nullptr;
    }
    auto uid = IPCSkeleton::GetCallingUid();
    std::string bundleName = std::to_string(uid);
    int32_t userId = uid / Constants::BASE_USER_RANGE;
    napi_value nBundleInfo = nullptr;
    if (!CommonFunc::CheckBundleFlagWithPermission(flags)) {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        auto item = cache.find(Query(bundleName, GET_BUNDLE_INFO, flags, userId, env));
        if (item != cache.end()) {
            APP_LOGD("GetBundleInfo param from cache");
            NAPI_CALL(env,
                napi_get_reference_value(env, item->second, &nBundleInfo));
            return nBundleInfo;
        }
    }
    BundleInfo bundleInfo;
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->GetBundleInfoForSelf(flags, bundleInfo));
    if (ret != NO_ERROR) {
        APP_LOGE("GetBundleInfoForSelfSync failed, bundleName is %{public}s", bundleName.c_str());
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_BUNDLE_INFO_FOR_SELF_SYNC, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    NAPI_CALL(env, napi_create_object(env,  &nBundleInfo));
    CommonFunc::ConvertBundleInfo(env, bundleInfo, nBundleInfo, flags);
    if (!CommonFunc::CheckBundleFlagWithPermission(flags)) {
        Query query(bundleName, GET_BUNDLE_INFO, flags, userId, env);
        CheckToCache(env, bundleInfo.uid, IPCSkeleton::GetCallingUid(), query, nBundleInfo);
    }
    return nBundleInfo;
}

bool ParamsProcessGetJsonProfile(napi_env env, napi_callback_info info,
    int32_t& profileType, std::string& bundleName, std::string& moduleName, int32_t& userId)
{
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return false;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], profileType)) {
        APP_LOGE("profileType invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, PROFILE_TYPE, TYPE_NUMBER);
        return false;
    }
    if (g_supportedProfileList.find(profileType) == g_supportedProfileList.end()) {
        APP_LOGE("JS request profile error, type is %{public}d, profile not exist", profileType);
        BusinessError::ThrowParameterTypeError(env, ERROR_PROFILE_NOT_EXIST, PROFILE_TYPE, TYPE_NUMBER);
        return false;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], bundleName)) {
        APP_LOGE("bundleName invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ERROR_BUNDLE_NOT_EXIST, GET_JSON_PROFILE, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return false;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_TWO], moduleName)) {
            APP_LOGW("parse moduleName failed, try to get profile from entry module");
        } else if (moduleName.empty()) {
            APP_LOGE("moduleName is empty");
            napi_value businessError = BusinessError::CreateCommonError(
                env, ERROR_MODULE_NOT_EXIST, GET_JSON_PROFILE, BUNDLE_PERMISSIONS);
            napi_throw(env, businessError);
            return false;
        }
    }
    if (args.GetMaxArgc() == ARGS_SIZE_FOUR) {
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_THREE], userId)) {
            APP_LOGE("userId invalid");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
            return false;
        }
    }
    return true;
}

napi_value GetJsonProfile(napi_env env, napi_callback_info info)
{
    APP_LOGD("GetJsonProfile napi called");
    int32_t profileType = 0;
    std::string bundleName;
    std::string moduleName;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    if (!ParamsProcessGetJsonProfile(env, info, profileType, bundleName, moduleName, userId)) {
        APP_LOGE("paramsProcess failed");
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return nullptr;
    }
    std::string profile;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetJsonProfile(static_cast<ProfileType>(profileType), bundleName, moduleName, profile, userId));
    if (ret != SUCCESS) {
        APP_LOGD("napi GetJsonProfile err:%{public}d -n %{public}s", ret, bundleName.c_str());
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_JSON_PROFILE, BUNDLE_PERMISSIONS);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nProfile;
    napi_create_string_utf8(env, profile.c_str(), NAPI_AUTO_LENGTH, &nProfile);
    APP_LOGD("call GetJsonProfile done");
    return nProfile;
}

static ErrCode InnerGetRecoverableApplicationInfo(std::vector<RecoverableApplicationInfo> &recoverableApplications)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetRecoverableApplicationInfo(recoverableApplications);
    return CommonFunc::ConvertErrCode(ret);
}

void GetRecoverableApplicationInfoExec(napi_env env, void *data)
{
    RecoverableApplicationCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<RecoverableApplicationCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        return;
    }
    asyncCallbackInfo->err = InnerGetRecoverableApplicationInfo(asyncCallbackInfo->recoverableApplicationInfos);
}

void GetRecoverableApplicationInfoExecComplete(napi_env env, napi_status status, void *data)
{
    RecoverableApplicationCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<RecoverableApplicationCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        return;
    }
    std::unique_ptr<RecoverableApplicationCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertRecoverableApplicationInfos(
            env, result[ARGS_POS_ONE], asyncCallbackInfo->recoverableApplicationInfos);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_RECOVERABLE_APPLICATION_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<RecoverableApplicationCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetRecoverableApplicationInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetRecoverableApplicationInfo called");
    NapiArg args(env, info);
    RecoverableApplicationCallbackInfo *asyncCallbackInfo = new (std::nothrow) RecoverableApplicationCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<RecoverableApplicationCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ZERO, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            }
        } else {
            APP_LOGE("param check error");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
            return nullptr;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<RecoverableApplicationCallbackInfo>(
        env, asyncCallbackInfo, GET_RECOVERABLE_APPLICATION_INFO,
        GetRecoverableApplicationInfoExec, GetRecoverableApplicationInfoExecComplete);
    callbackPtr.release();
    APP_LOGD("call NAPI_GetRecoverableApplicationInfo done");
    return promise;
}

napi_value SetAdditionalInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("Called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("Param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("Parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    CHECK_STRING_EMPTY(env, bundleName, std::string{ BUNDLE_NAME });
    std::string additionalInfo;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], additionalInfo)) {
        APP_LOGE("Parse additionalInfo failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ADDITIONAL_INFO, TYPE_STRING);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->SetAdditionalInfo(bundleName, additionalInfo));
    if (ret != NO_ERROR) {
        APP_LOGE("Call failed, bundleName is %{public}s", bundleName.c_str());
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, RESOURCE_NAME_OF_SET_ADDITIONAL_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nRet = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &nRet));
    APP_LOGD("Call done");
    return nRet;
}

ErrCode ParamsProcessCanOpenLink(napi_env env, napi_callback_info info,
    std::string& link)
{
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return ERROR_PARAM_CHECK_ERROR;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], link)) {
        APP_LOGW("Parse link failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, LINK, TYPE_STRING);
        return ERROR_PARAM_CHECK_ERROR;
    }
    return ERR_OK;
}

napi_value CanOpenLink(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI CanOpenLink call");
    napi_value nRet;
    bool canOpen = false;
    napi_get_boolean(env, canOpen, &nRet);
    std::string link;
    if (ParamsProcessCanOpenLink(env, info, link) != ERR_OK) {
        APP_LOGE("paramsProcess is invalid");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return nRet;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nRet;
    }
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->CanOpenLink(link, canOpen));
    if (ret != NO_ERROR) {
        APP_LOGE("CanOpenLink failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, CAN_OPEN_LINK, "");
        napi_throw(env, businessError);
        return nRet;
    }
    NAPI_CALL(env, napi_get_boolean(env, canOpen, &nRet));
    APP_LOGD("call CanOpenLink done");
    return nRet;
}

void ConvertPreinstalledApplicationInfo(napi_env env, const PreinstalledApplicationInfo &preinstalledApplicationInfo,
    napi_value objPreinstalledApplicationInfo)
{
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_string_utf8(env, preinstalledApplicationInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objPreinstalledApplicationInfo, BUNDLE_NAME, nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_string_utf8(env, preinstalledApplicationInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, objPreinstalledApplicationInfo, MODULE_NAME, nModuleName));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, preinstalledApplicationInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objPreinstalledApplicationInfo, LABEL_ID, nLabelId));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, preinstalledApplicationInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objPreinstalledApplicationInfo, ICON_ID, nIconId));
}


static void ProcessPreinstalledApplicationInfos(
    napi_env env, napi_value result, const std::vector<PreinstalledApplicationInfo> &preinstalledApplicationInfos)
{
    if (preinstalledApplicationInfos.size() == 0) {
        APP_LOGD("PreinstalledApplicationInfos is null");
        return;
    }
    size_t index = 0;
    napi_value objPreinstalledApplicationInfo;
    for (const auto &item : preinstalledApplicationInfos) {
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objPreinstalledApplicationInfo));
        ConvertPreinstalledApplicationInfo(env, item, objPreinstalledApplicationInfo);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, objPreinstalledApplicationInfo));
        index++;
    }
}

void GetAllPreinstalledApplicationInfosComplete(napi_env env, napi_status status, void *data)
{
    PreinstalledApplicationInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<PreinstalledApplicationInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("AsyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<PreinstalledApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        ProcessPreinstalledApplicationInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->preinstalledApplicationInfos);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_PREINSTALLED_APP_INFOS, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    CommonFunc::NapiReturnDeferred<PreinstalledApplicationInfosCallbackInfo>(
        env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

static ErrCode InnerGetAllPreinstalledApplicationInfos(
    std::vector<PreinstalledApplicationInfo> &preinstalledApplicationInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("IBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAllPreinstalledApplicationInfos(preinstalledApplicationInfos);
    return CommonFunc::ConvertErrCode(ret);
}

void GetAllPreinstalledApplicationInfosExec(napi_env env, void *data)
{
    PreinstalledApplicationInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<PreinstalledApplicationInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("AsyncCallbackInfo is null");
        return;
    }
    asyncCallbackInfo->err = InnerGetAllPreinstalledApplicationInfos(asyncCallbackInfo->preinstalledApplicationInfos);
}

napi_value GetAllPreinstalledApplicationInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("Called");
    NapiArg args(env, info);
    PreinstalledApplicationInfosCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) PreinstalledApplicationInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("AsyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<PreinstalledApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (!args.Init(ARGS_SIZE_ZERO, ARGS_SIZE_ZERO)) {
        APP_LOGE("Param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<PreinstalledApplicationInfosCallbackInfo>(env, asyncCallbackInfo,
        GET_ALL_PREINSTALLED_APP_INFOS, GetAllPreinstalledApplicationInfosExec,
        GetAllPreinstalledApplicationInfosComplete);
    callbackPtr.release();
    return promise;
}

napi_value GetAllBundleInfoByDeveloperId(napi_env env, napi_callback_info info)
{
    APP_LOGD("Called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        APP_LOGE("Param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string developerId;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], developerId)) {
        APP_LOGE("Parse developerId failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, DEVELOPER_ID, TYPE_STRING);
        return nullptr;
    }
    CHECK_STRING_EMPTY(env, developerId, std::string{ DEVELOPER_ID });
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetAllBundleInfoByDeveloperId(developerId, bundleInfos, userId));
    if (ret != NO_ERROR) {
        APP_LOGE("Call failed, developerId is %{public}s", developerId.c_str());
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_ALL_BUNDLE_INFO_BY_DEVELOPER_ID, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nBundleInfos;
    NAPI_CALL(env, napi_create_array(env, &nBundleInfos));
    ProcessBundleInfos(env, nBundleInfos, bundleInfos,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION));
    APP_LOGD("Call done");
    return nBundleInfos;
}

static void ProcessStringVec(
    napi_env env, napi_value result, const std::vector<std::string> &stringList)
{
    if (stringList.size() == 0) {
        APP_LOGD("stringList is null");
        return;
    }
    size_t index = 0;
    for (const auto &item : stringList) {
        APP_LOGD("string: %{public}s ", item.c_str());
        napi_value nString;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &nString));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, nString));
        index++;
    }
}

napi_value GetDeveloperIds(napi_env env, napi_callback_info info)
{
    APP_LOGD("Called");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ZERO, ARGS_SIZE_ONE)) {
        APP_LOGE("Param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string distributionType;
    if (args.GetMaxArgc() >= ARGS_SIZE_ONE) {
        int32_t appDistributionTypeEnum = 0;
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ZERO], appDistributionTypeEnum)) {
            APP_LOGE("parseInt failed");
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_DISTRIBUTION_TYPE, TYPE_NUMBER);
            return nullptr;
        }
        if (appDistributionTypeMap.find(appDistributionTypeEnum) == appDistributionTypeMap.end()) {
            APP_LOGE("request error, type %{public}d is invalid", appDistributionTypeEnum);
            BusinessError::ThrowEnumError(env, APP_DISTRIBUTION_TYPE, APP_DISTRIBUTION_TYPE_ENUM);
            return nullptr;
        }
        distributionType = std::string{ appDistributionTypeMap[appDistributionTypeEnum] };
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::vector<std::string> developerIds;
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode ret = CommonFunc::ConvertErrCode(
        iBundleMgr->GetDeveloperIds(distributionType, developerIds, userId));
    if (ret != NO_ERROR) {
        APP_LOGW("Call failed, appDistributionType is %{public}s", distributionType.c_str());
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, GET_DEVELOPER_IDS, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nDeveloperIds;
    NAPI_CALL(env, napi_create_array(env, &nDeveloperIds));
    ProcessStringVec(env, nDeveloperIds, developerIds);
    APP_LOGD("Call done");
    return nDeveloperIds;
}

napi_value SwitchUninstallState(napi_env env, napi_callback_info info)
{
    APP_LOGI("NAPI SwitchUninstallState call");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("Param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], bundleName)) {
        APP_LOGE("Parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    bool state;
    if (!CommonFunc::ParseBool(env, args[ARGS_POS_ONE], state)) {
        APP_LOGE("Parse state failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, STATE, TYPE_BOOLEAN);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->SwitchUninstallState(bundleName, state));
    if (ret != NO_ERROR) {
        APP_LOGE("SwitchUninstallState failed");
        napi_value businessError = BusinessError::CreateCommonError(
            env, ret, SWITCH_UNINSTALL_STATE, "");
        napi_throw(env, businessError);
        return nullptr;
    }
    napi_value nRet = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &nRet));
    APP_LOGD("call SwitchUninstallState done");
    return nRet;
}

static ErrCode InnerGetAppCloneBundleInfo(const std::string &bundleName, int32_t appIndex,
    int32_t bundleFlags, int32_t userId, BundleInfo &bundleInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetCloneBundleInfo(bundleName, bundleFlags, appIndex, bundleInfo, userId);
    APP_LOGD("GetCloneBundleInfo result is %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

void GetAppCloneBundleInfoExec(napi_env env, void *data)
{
    CloneAppBundleInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<CloneAppBundleInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    APP_LOGD("param: name=%{public}s,index=%{public}d,bundleFlags=%{public}d,userId=%{public}d",
        asyncCallbackInfo->bundleName.c_str(),
        asyncCallbackInfo->appIndex,
        asyncCallbackInfo->bundleFlags,
        asyncCallbackInfo->userId);
    asyncCallbackInfo->err =
        InnerGetAppCloneBundleInfo(asyncCallbackInfo->bundleName, asyncCallbackInfo->appIndex,
            asyncCallbackInfo->bundleFlags, asyncCallbackInfo->userId, asyncCallbackInfo->bundleInfo);
}

void GetAppCloneBundleInfoComplete(napi_env env, napi_status status, void *data)
{
    CloneAppBundleInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<CloneAppBundleInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<CloneAppBundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[ARGS_POS_ONE]));
        CommonFunc::ConvertBundleInfo(env, asyncCallbackInfo->bundleInfo, result[ARGS_POS_ONE],
            asyncCallbackInfo->bundleFlags);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_APP_CLONE_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO);
    }
    CommonFunc::NapiReturnDeferred<CloneAppBundleInfoCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAppCloneBundleInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetAppCloneBundleInfo call");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("Param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::unique_ptr<CloneAppBundleInfoCallbackInfo> asyncCallbackInfo =
        std::make_unique<CloneAppBundleInfoCallbackInfo>(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("asyncCallbackInfo is null");
        return nullptr;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
        APP_LOGE("Parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], asyncCallbackInfo->appIndex)) {
        APP_LOGE("Parse appIndex failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return nullptr;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_TWO], asyncCallbackInfo->bundleFlags)) {
        APP_LOGE("Parse bundleFlags failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_THREE], asyncCallbackInfo->userId)) {
        APP_LOGI("Parse userId failed, use default value");
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<CloneAppBundleInfoCallbackInfo>(
        env, asyncCallbackInfo.get(), GET_APP_CLONE_BUNDLE_INFO,
        GetAppCloneBundleInfoExec, GetAppCloneBundleInfoComplete);
    asyncCallbackInfo.release();
    APP_LOGD("call GetAppCloneBundleInfo done");
    return promise;
}

static ErrCode InnerGetAllAppCloneBundleInfo(const std::string &bundleName, int32_t bundleFlags,
    int32_t userId, std::vector<BundleInfo> &bundleInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    BundleInfo bundleInfoMain;
    ErrCode ret = iBundleMgr->GetCloneBundleInfo(bundleName, bundleFlags, 0, bundleInfoMain, userId);
    APP_LOGD("GetMainBundleInfo appIndex = 0, ret=%{public}d", ret);
    if (ret == ERR_OK) {
        bundleInfos.emplace_back(bundleInfoMain);
    }
    if (ret != ERR_OK && ret != ERR_BUNDLE_MANAGER_APPLICATION_DISABLED &&
        ret != ERR_BUNDLE_MANAGER_BUNDLE_DISABLED) {
        return CommonFunc::ConvertErrCode(ret);
    }
    // handle clone apps
    std::vector<int32_t> appIndexes;
    ErrCode getCloneIndexesRet = iBundleMgr->GetCloneAppIndexes(bundleName, appIndexes, userId);
    if (getCloneIndexesRet != ERR_OK) {
        if (ret == ERR_OK) {
            return SUCCESS;
        }
        return CommonFunc::ConvertErrCode(ret);
    }
    for (int32_t appIndex : appIndexes) {
        BundleInfo bundleInfo;
        ret = iBundleMgr->GetCloneBundleInfo(bundleName, bundleFlags, appIndex, bundleInfo, userId);
        if (ret == ERR_OK) {
            bundleInfos.emplace_back(bundleInfo);
        }
    }
    if (bundleInfos.empty()) {
        return ERROR_BUNDLE_IS_DISABLED;
    }
    return SUCCESS;
}

void GetAllAppCloneBundleInfoExec(napi_env env, void *data)
{
    CloneAppBundleInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<CloneAppBundleInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    APP_LOGD("param: name=%{public}s,bundleFlags=%{public}d,userId=%{public}d",
        asyncCallbackInfo->bundleName.c_str(),
        asyncCallbackInfo->bundleFlags,
        asyncCallbackInfo->userId);
    asyncCallbackInfo->err =
        InnerGetAllAppCloneBundleInfo(asyncCallbackInfo->bundleName, asyncCallbackInfo->bundleFlags,
            asyncCallbackInfo->userId, asyncCallbackInfo->bundleInfos);
}

static void CloneAppBundleInfos(
    napi_env env, napi_value result, const std::vector<BundleInfo> &bundleInfos, int32_t flags)
{
    if (bundleInfos.size() == 0) {
        APP_LOGD("bundleInfos is null");
        return;
    }
    size_t index = 0;
    for (const auto &item : bundleInfos) {
        napi_value objBundleInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objBundleInfo));
        CommonFunc::ConvertBundleInfo(env, item, objBundleInfo, flags);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index++, objBundleInfo));
    }
}

void GetAllAppCloneBundleInfoComplete(napi_env env, napi_status status, void *data)
{
    CloneAppBundleInfosCallbackInfo *asyncCallbackInfo = reinterpret_cast<CloneAppBundleInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<CloneAppBundleInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[CALLBACK_PARAM_SIZE] = {0};
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_POS_ZERO]));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
        CloneAppBundleInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->bundleInfos, asyncCallbackInfo->bundleFlags);
    } else {
        result[ARGS_POS_ZERO] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            GET_ALL_APP_CLONE_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO);
    }
    CommonFunc::NapiReturnDeferred<CloneAppBundleInfosCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
}

napi_value GetAllAppCloneBundleInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetAllAppCloneBundleInfo call");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("Param count invalid");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::unique_ptr<CloneAppBundleInfosCallbackInfo> asyncCallbackInfo =
        std::make_unique<CloneAppBundleInfosCallbackInfo>(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("asyncCallbackInfo is null");
        return nullptr;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
        APP_LOGE("Parse bundleName failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], asyncCallbackInfo->bundleFlags)) {
        APP_LOGE("Parse bundleFlags failed");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (!CommonFunc::ParseInt(env, args[ARGS_POS_TWO], asyncCallbackInfo->userId)) {
        APP_LOGI("Parse userId failed, use default value");
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<CloneAppBundleInfosCallbackInfo>(
        env, asyncCallbackInfo.get(), GET_ALL_APP_CLONE_BUNDLE_INFO,
        GetAllAppCloneBundleInfoExec, GetAllAppCloneBundleInfoComplete);
    asyncCallbackInfo.release();
    APP_LOGD("call GetAllAppCloneBundleInfo done");
    return promise;
}

void CreateMultiAppModeTypeObject(napi_env env, napi_value value)
{
    napi_value nUnspecified;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(MultiAppModeType::UNSPECIFIED),
        &nUnspecified));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, UNSPECIFIED, nUnspecified));

    napi_value nMultiInstance;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(MultiAppModeType::MULTI_INSTANCE),
        &nMultiInstance));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, MULTI_INSTANCE, nMultiInstance));

    napi_value nAppClone;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(MultiAppModeType::APP_CLONE),
        &nAppClone));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, APP_CLONE, nAppClone));
}

void MigrateDataExec(napi_env env, void *data)
{
    MigrateDataCallbackInfo *asyncCallbackInfo = reinterpret_cast<MigrateDataCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        asyncCallbackInfo->err = CommonFunc::ConvertErrCode(ERROR_BUNDLE_SERVICE_EXCEPTION);
        return;
    }

    asyncCallbackInfo->err = CommonFunc::ConvertErrCode(iBundleMgr->MigrateData(
        asyncCallbackInfo->sourcePaths, asyncCallbackInfo->destinationPath));
}

void MigrateDataComplete(napi_env env, napi_status status, void *data)
{
    MigrateDataCallbackInfo *asyncCallbackInfo = reinterpret_cast<MigrateDataCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }

    std::unique_ptr<MigrateDataCallbackInfo> callbackPtr{ asyncCallbackInfo };
    napi_value result[ARGS_SIZE_ONE] = { 0 };
    if (asyncCallbackInfo->err == NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        APP_LOGE("MigrateData err! code :%{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err, "", "");
    }
    CommonFunc::NapiReturnDeferred<MigrateDataCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_ONE);
}

napi_value MigrateData(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to MigrateData");
    NapiArg args(env, info);
    MigrateDataCallbackInfo *asyncCallbackInfo = new (std::nothrow) MigrateDataCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("VerifyCallbackInfo asyncCallbackInfo is null");
        return nullptr;
    }

    std::unique_ptr<MigrateDataCallbackInfo> callbackPtr{ asyncCallbackInfo };
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        APP_LOGE("MigrateData napi func init failed");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (!CommonFunc::ParseStringArray(env, asyncCallbackInfo->sourcePaths, args[ARGS_POS_ZERO])) {
        APP_LOGE("ParseStringArray invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, SOURCE_PATHS, TYPE_ARRAY);
        return nullptr;
    }

    if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->destinationPath)) {
        APP_LOGE("ParseString invalid");
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, DESTINATION_PATHS, TYPE_STRING);
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<MigrateDataCallbackInfo>(
        env, asyncCallbackInfo, MIGRATE_DATA, MigrateDataExec, MigrateDataComplete);
    callbackPtr.release();
    APP_LOGI("call MigrateData done");
    return promise;
}
} // namespace AppExecFwk
} // namespace OHOS
