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
#include <ani_signature_builder.h>
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_FLAGS = "bundleFlags";
constexpr const char* APPLICATION_FLAGS = "applicationFlags";
constexpr const char* ERR_MSG_BUNDLE_SERVICE_EXCEPTION = "Bundle manager service is excepted.";
const std::string IS_APPLICATION_ENABLED_SYNC = "IsApplicationEnabledSync";
const std::string GET_BUNDLE_INFO_FOR_SELF_SYNC = "GetBundleInfoForSelfSync";
const std::string GET_BUNDLE_INFO_SYNC = "GetBundleInfoSync";
const std::string GET_APPLICATION_INFO_SYNC = "GetApplicationInfoSync";
const std::string BUNDLE_PERMISSIONS = "ohos.permission.GET_BUNDLE_INFO or ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
const std::string GET_BUNDLE_INFO = "GetBundleInfo";
constexpr const char* GET_APPLICATION_INFO = "GetApplicationInfo";
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
    RETURN_IF_NULL(aniObject);
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

static ani_boolean IsApplicationEnabledSync(ani_env* env, ani_string aniBundleName)
{
    bool isEnable = false;
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return isEnable;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return isEnable;
    }
    ErrCode ret = iBundleMgr->IsApplicationEnabled(bundleName, isEnable);
    if (ret != ERR_OK) {
        APP_LOGE("IsApplicationEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret), IS_APPLICATION_ENABLED_SYNC, "");
    }
    return isEnable;
}

static ani_object GetBundleInfoForSelfSync(ani_env* env, ani_double aniBundleFlags)
{
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowCommonError(
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
        BusinessErrorAni::ThrowCommonError(
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
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast userId failed");
        BusinessErrorAni::ThrowCommonError(
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
        BusinessErrorAni::ThrowCommonError(
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
        BusinessErrorAni::ThrowCommonError(
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
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, APPLICATION_FLAGS, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast aniUserId failed");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowCommonError(
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
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret), GET_APPLICATION_INFO_SYNC, BUNDLE_PERMISSIONS);
        return nullptr;
    }

    ani_object objectApplicationInfo = CommonFunAni::ConvertApplicationInfo(env, appInfo);
    CheckToCache(env, appInfo.uid, callingUid, query, objectApplicationInfo);

    return objectApplicationInfo;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    auto nsName = arkts::ani_signature::Builder::BuildNamespace({"@ohos", "bundle", "bundleManager", "bundleManager"});
    ani_namespace kitNs;
    res = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Not found nameSpace L@ohos/bundle/bundleManager/bundleManager;");

    std::array methods = {
        ani_native_function { "isApplicationEnabledSync", "Lstd/core/String;:Z",
            reinterpret_cast<void*>(IsApplicationEnabledSync) },
        ani_native_function { "getBundleInfoForSelfSync", "D:LbundleManager/BundleInfo/BundleInfo;",
            reinterpret_cast<void*>(GetBundleInfoForSelfSync) },
        ani_native_function { "getBundleInfoSync", "Lstd/core/String;DD:LbundleManager/BundleInfo/BundleInfo;",
            reinterpret_cast<void*>(GetBundleInfoSync) },
        ani_native_function { "getApplicationInfoSync",
            "Lstd/core/String;DD:LbundleManager/ApplicationInfo/ApplicationInfo;",
            reinterpret_cast<void*>(GetApplicationInfoSync) },
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
    ani_option interopEnabled { "--interop=disable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    if (g_vm == nullptr) {
        APP_LOGE("g_vm is empty");
        return;
    }
    ani_status status = g_vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        APP_LOGE("AttachCurrentThread fail %{public}d", status);
        return;
    }
    if (env == nullptr) {
        APP_LOGE("env is empty");
    } else {
        for (auto& item : g_aniCache) {
            env->GlobalReference_Delete(item.second);
        }
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
