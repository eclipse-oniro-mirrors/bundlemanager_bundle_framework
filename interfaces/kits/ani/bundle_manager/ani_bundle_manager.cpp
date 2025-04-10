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

#include <cmath>
#include <cstring>
#include <iostream>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "ani_bundle_manager.h"
#include "ani_common_want.h"
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static ani_vm* g_vm;
static std::mutex g_aniClearCacheListenerMutex;
static std::shared_ptr<ANIClearCacheListener> g_aniClearCacheListener;
static std::shared_mutex g_aniCacheMutex;
static std::unordered_map<ANIQuery, ani_ref, ANIQueryHash> g_aniCache;
constexpr int32_t EMPTY_USER_ID = -500;
} // namespace

static void CheckToCache(
    ani_env* env, const int32_t uid, const int32_t callingUid, const ANIQuery& query, ani_object aniObject)
{
    if (uid != callingUid) {
        return;
    }

    ani_ref info = nullptr;
    ani_status status = env->GlobalReference_Create(aniObject, &info);
    if (status == ANI_OK) {
        std::unique_lock<std::shared_mutex> lock(g_aniCacheMutex);
        g_aniCache[query] = info;
    }
}

static void CheckAbilityInfoCache(ani_env* env, const ANIQuery& query,
    const OHOS::AAFwk::Want& want, std::vector<AbilityInfo> abilityInfos, ani_object aniObject)
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

    ani_ref cacheAbilityInfo = nullptr;
    ani_status status = env->GlobalReference_Create(aniObject, &cacheAbilityInfo);
    if (status == ANI_OK) {
        std::unique_lock<std::shared_mutex> lock(g_aniCacheMutex);
        g_aniCache[query] = cacheAbilityInfo;
    }
}

static bool ParseAniWant(ani_env* env, ani_object aniWant, OHOS::AAFwk::Want& want)
{
    ani_string string = nullptr;
    std::string bundleName;
    std::string abilityName;
    std::string moduleName;

    if (CommonFunAni::CallGetterOptional(env, aniWant, Constants::BUNDLE_NAME, &string)) {
        bundleName = CommonFunAni::AniStrToString(env, string);
    }
    if (CommonFunAni::CallGetterOptional(env, aniWant, Constants::ABILITY_NAME, &string)) {
        abilityName = CommonFunAni::AniStrToString(env, string);
    }
    if (CommonFunAni::CallGetterOptional(env, aniWant, Constants::MODULE_NAME, &string)) {
        moduleName = CommonFunAni::AniStrToString(env, string);
    }
    if (!bundleName.empty() && !abilityName.empty()) {
        ElementName elementName("", bundleName, abilityName, moduleName);
        want.SetElement(elementName);
        return true;
    }
    if (!UnwrapWant(env, aniWant, want)) {
        APP_LOGW("parse want failed");
        return false;
    }
    bool isExplicit = !want.GetBundle().empty() && !want.GetElement().GetAbilityName().empty();
    if (!isExplicit && want.GetAction().empty() && want.GetEntities().empty() &&
        want.GetUriString().empty() && want.GetType().empty() && want.GetStringParam(LINK_FEATURE).empty()) {
        APP_LOGW("implicit params all empty");
        return false;
    }
    return true;
}

static ani_object GetBundleInfoForSelfSync(ani_env* env, ani_double aniBundleFlags)
{
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    const auto uid = IPCSkeleton::GetCallingUid();
    std::string bundleName = std::to_string(uid);
    int32_t userId = uid / Constants::BASE_USER_RANGE;
    const ANIQuery query(bundleName, GET_BUNDLE_INFO, bundleFlags, userId);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        std::shared_lock<std::shared_mutex> lock(g_aniCacheMutex);
        auto item = g_aniCache.find(query);
        if (item != g_aniCache.end()) {
            return reinterpret_cast<ani_object>(item->second);
        }
    }

    BundleInfo bundleInfo;
    ErrCode ret = iBundleMgr->GetBundleInfoForSelf(bundleFlags, bundleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleInfoForSelf failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret), GET_BUNDLE_INFO_FOR_SELF_SYNC, BUNDLE_PERMISSIONS);
        return nullptr;
    }

    ani_object objectBundleInfo = CommonFunAni::ConvertBundleInfo(env, bundleInfo, bundleFlags);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        CheckToCache(env, bundleInfo.uid, uid, query, objectBundleInfo);
    }

    return objectBundleInfo;
}

static ani_object GetBundleInfoSync(ani_env* env,
    ani_string aniBundleName, ani_double aniBundleFlags, ani_double aniUserId)
{
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast userId failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("Bundle name is empty.");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }

    ANIQuery query(bundleName, GET_BUNDLE_INFO, bundleFlags, userId);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        std::shared_lock<std::shared_mutex> lock(g_aniCacheMutex);
        auto item = g_aniCache.find(query);
        if (item != g_aniCache.end()) {
            APP_LOGD("Get bundle info from global cache.");
            return reinterpret_cast<ani_object>(item->second);
        }
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Get bundle mgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    BundleInfo bundleInfo;
    ErrCode ret = iBundleMgr->GetBundleInfoV9(bundleName, bundleFlags, bundleInfo, userId);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleInfoV9 failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret), GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
        return nullptr;
    }

    ani_object objectBundleInfo = CommonFunAni::ConvertBundleInfo(env, bundleInfo, bundleFlags);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        CheckToCache(env, bundleInfo.uid, callingUid, query, objectBundleInfo);
    }

    return objectBundleInfo;
}

static ani_object GetApplicationInfoSync(ani_env* env,
    ani_string aniBundleName, ani_double aniApplicationFlags, ani_double aniUserId)
{
    int32_t applicationFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniApplicationFlags, &applicationFlags)) {
        APP_LOGE("Cast aniApplicationFlags failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, APPLICATION_FLAGS, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast aniUserId failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }

    const ANIQuery query(bundleName, GET_APPLICATION_INFO, applicationFlags, userId);
    {
        std::shared_lock<std::shared_mutex> lock(g_aniCacheMutex);
        auto item = g_aniCache.find(query);
        if (item != g_aniCache.end()) {
            return reinterpret_cast<ani_object>(item->second);
        }
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("nullptr iBundleMgr");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    ApplicationInfo appInfo;
    ErrCode ret = iBundleMgr->GetApplicationInfoV9(bundleName, applicationFlags, userId, appInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetApplicationInfoV9 failed ret: %{public}d,userId: %{public}d", ret, userId);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret), GET_APPLICATION_INFO_SYNC, BUNDLE_PERMISSIONS);
        return nullptr;
    }

    ani_object objectApplicationInfo = CommonFunAni::ConvertApplicationInfo(env, appInfo);
    CheckToCache(env, appInfo.uid, callingUid, query, objectApplicationInfo);

    return objectApplicationInfo;
}

static ani_object GetAllBundleInfoSync(ani_env* env, ani_double aniBundleFlags, ani_double aniUserId)
{
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast aniUserId failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Get bundle mgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = iBundleMgr->GetBundleInfosV9(bundleFlags, bundleInfos, userId);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleInfosV9 failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(env, CommonFunc::ConvertErrCode(ret), GET_BUNDLE_INFOS,
            Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST);
        return nullptr;
    }
    APP_LOGI("GetBundleInfosV9 ret: %{public}d, bundleInfos size: %{public}d", ret, bundleInfos.size());

    return CommonFunAni::ConvertAniArray(env, bundleInfos, CommonFunAni::ConvertBundleInfo, bundleFlags);
}

static ani_object GetAllApplicationInfoSync(ani_env* env, ani_double aniApplicationFlags, ani_double aniUserId)
{
    int32_t applicationFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniApplicationFlags, &applicationFlags)) {
        APP_LOGE("Cast aniApplicationFlags failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, APPLICATION_FLAGS, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast aniUserId failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("nullptr iBundleMgr");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::vector<ApplicationInfo> appInfos;
    ErrCode ret = iBundleMgr->GetApplicationInfosV9(applicationFlags, userId, appInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetApplicationInfosV9 failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(env, CommonFunc::ConvertErrCode(ret), GET_APPLICATION_INFOS,
            Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST);
        return nullptr;
    }
    APP_LOGI("applicationInfos size: %{public}d", appInfos.size());

    return CommonFunAni::ConvertAniArray(env, appInfos, CommonFunAni::ConvertApplicationInfo);
}

static ani_boolean IsApplicationEnabledSyncInner(ani_env* env,
    ani_string aniBundleName, ani_double aniAppIndex)
{
    bool isEnable = false;
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return isEnable;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::APP_INDEX, CommonFunAniNS::TYPE_NUMBER);
        return false;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return isEnable;
    }
    ErrCode ret = ERR_OK;
    if (appIndex != 0) {
        ret = iBundleMgr->IsCloneApplicationEnabled(bundleName, appIndex, isEnable);
    } else {
        ret = iBundleMgr->IsApplicationEnabled(bundleName, isEnable);
    }
    if (ret != ERR_OK) {
        APP_LOGE("IsCloneApplicationEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret), IS_APPLICATION_ENABLED, "");
    }
    return isEnable;
}

static ani_object QueryAbilityInfoSyncInner(ani_env* env,
    ani_object aniWant, ani_double aniAbilityFlags, ani_double aniUserId)
{
    OHOS::AAFwk::Want want;
    int32_t abilityFlags = 0;
    int32_t userId = EMPTY_USER_ID;
    if (!ParseAniWant(env, aniWant, want)) {
        APP_LOGE("ParseAniWant failed");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_WANT_ERROR);
        return nullptr;
    }
    if (!CommonFunAni::TryCastDoubleTo(aniAbilityFlags, &abilityFlags)) {
        APP_LOGE("Cast aniAbilityFlags failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, ABILITY_FLAGS, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast aniUserId failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }
    const ANIQuery query(want.ToString(), QUERY_ABILITY_INFOS_SYNC, abilityFlags, userId);
    {
        std::shared_lock<std::shared_mutex> lock(g_aniCacheMutex);
        auto item = g_aniCache.find(query);
        if (item != g_aniCache.end()) {
            return reinterpret_cast<ani_object>(item->second);
        }
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = iBundleMgr->QueryAbilityInfosV9(want, abilityFlags, userId, abilityInfos);
    if (ret != ERR_OK) {
        APP_LOGE("QueryAbilityInfosV9 failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret), QUERY_ABILITY_INFOS_SYNC, BUNDLE_PERMISSIONS);
        return nullptr;
    }
    ani_object aniAbilityInfos =
        CommonFunAni::ConvertAniArray(env, abilityInfos, CommonFunAni::ConvertAbilityInfo);
    CheckAbilityInfoCache(env, query, want, abilityInfos, aniAbilityInfos);
    return aniAbilityInfos;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    static const char* nsName = "L@ohos/bundle/bundleManager/bundleManager;";
    ani_namespace kitNs;
    res = env->FindNamespace(nsName, &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Not found nameSpace L@ohos/bundle/bundleManager/bundleManager;");

    std::array methods = {
        ani_native_function { "isApplicationEnabledSyncInner", "Lstd/core/String;D:Z",
            reinterpret_cast<void*>(IsApplicationEnabledSyncInner) },
        ani_native_function { "getBundleInfoForSelfSync", "D:LbundleManager/BundleInfo/BundleInfo;",
            reinterpret_cast<void*>(GetBundleInfoForSelfSync) },
        ani_native_function { "getBundleInfoSync", "Lstd/core/String;DD:LbundleManager/BundleInfo/BundleInfo;",
            reinterpret_cast<void*>(GetBundleInfoSync) },
        ani_native_function { "getApplicationInfoSync",
            "Lstd/core/String;DD:LbundleManager/ApplicationInfo/ApplicationInfo;",
            reinterpret_cast<void*>(GetApplicationInfoSync) },
        ani_native_function { "getAllBundleInfoSync", "DD:Lescompat/Array;",
            reinterpret_cast<void*>(GetAllBundleInfoSync) },
        ani_native_function { "getAllApplicationInfoSync", "DD:Lescompat/Array;",
            reinterpret_cast<void*>(GetAllApplicationInfoSync) },
        ani_native_function { "queryAbilityInfoSyncInner",
            "L@ohos/app/ability/Want/Want;DD:Lescompat/Array;",
            reinterpret_cast<void*>(QueryAbilityInfoSyncInner) },
    };

    res = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods");

    *result = ANI_VERSION_1;

    RegisterANIClearCacheListenerAndEnv(vm);

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}

void ANIClearCacheListener::DoClearCache()
{
    std::unique_lock<std::shared_mutex> lock(g_aniCacheMutex);
    ani_env* env = nullptr;
    ani_option interopEnabled { "--interop=enable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    g_vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    for (auto& item : g_aniCache) {
        env->GlobalReference_Delete(item.second);
    }
    g_vm->DetachCurrentThread();
    g_aniCache.clear();
}

void ANIClearCacheListener::HandleCleanEnv(void* data)
{
    DoClearCache();
}

ANIClearCacheListener::ANIClearCacheListener(const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

void ANIClearCacheListener::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    DoClearCache();
}

void RegisterANIClearCacheListenerAndEnv(ani_vm* vm)
{
    std::lock_guard<std::mutex> lock(g_aniClearCacheListenerMutex);
    if (g_aniClearCacheListener != nullptr) {
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    g_aniClearCacheListener = std::make_shared<ANIClearCacheListener>(subscribeInfo);
    (void)EventFwk::CommonEventManager::SubscribeCommonEvent(g_aniClearCacheListener);
    g_vm = vm;
}
} // namespace AppExecFwk
} // namespace OHOS
