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

#include <cstring>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "ani_bundle_manager.h"
#include "app_log_wrapper.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string GET_BUNDLE_INFO = "GetBundleInfo";
constexpr const char* GET_APPLICATION_INFO = "GetApplicationInfo";
static ani_vm* g_vm;
static std::mutex g_clearCacheListenerMutex;
static std::shared_ptr<ClearCacheListener> g_clearCacheListener;
static std::shared_mutex g_cacheMutex;
static std::unordered_map<Query, ani_ref, QueryHash> g_cache;
constexpr int32_t INVALID_USER_ID = -500;
}

static void CheckToCache(
    ani_env* env, const int32_t uid, const int32_t callingUid, const Query& query, ani_object aniObject)
{
    if (uid != callingUid) {
        return;
    }

    ani_ref refBundleInfo = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(aniObject, &refBundleInfo)) == ANI_OK) {
        std::unique_lock<std::shared_mutex> lock(g_cacheMutex);
        g_cache[query] = refBundleInfo;
    }
}

static ani_boolean isApplicationEnabledSync([[maybe_unused]] ani_env* env, ani_string aniBundleName)
{
    bool isEnable = false;
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        return isEnable;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        return isEnable;
    }
    int32_t ret = iBundleMgr->IsApplicationEnabled(bundleName, isEnable);
    if (ret != ERR_OK) {
        APP_LOGE("IsApplicationEnabled failed ret: %{public}d", ret);
    }
    return isEnable;
}

static ani_object getBundleInfoForSelfSync([[maybe_unused]] ani_env* env, ani_int bundleFlags)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        return nullptr;
    }
    const auto uid = IPCSkeleton::GetCallingUid();
    std::string bundleName = std::to_string(uid);
    int32_t userId = uid / Constants::BASE_USER_RANGE;
    const Query query(bundleName, GET_BUNDLE_INFO, bundleFlags, userId);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        auto item = g_cache.find(query);
        if (item != g_cache.end()) {
            return reinterpret_cast<ani_object>(item->second);
        }
    }

    BundleInfo bundleInfo;
    int32_t ret = iBundleMgr->GetBundleInfoForSelf(bundleFlags, bundleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleInfoForSelf failed ret: %{public}d", ret);
        return nullptr;
    }

    ani_object objectBundleInfo = CommonFunAni::ConvertBundleInfo(env, bundleInfo);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        CheckToCache(env, bundleInfo.uid, uid, query, objectBundleInfo);
    }

    return objectBundleInfo;
}

static ani_object getBundleInfoSync([[maybe_unused]] ani_env *env, ani_string aniBundleName, ani_int bundleFlags,
    ani_int userId)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (userId == INVALID_USER_ID) {
        userId = uid / Constants::BASE_USER_RANGE;
    }
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("Bundle name is empty.");
        return nullptr;
    }

    Query query(bundleName, GET_BUNDLE_INFO, bundleFlags, userId);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        auto item = g_cache.find(query);
        if (item != g_cache.end()) {
            APP_LOGD("Get bundle info from global cache.");
            return reinterpret_cast<ani_object>(item->second);
        }
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Get bundle mgr failed");
        return nullptr;
    }
    BundleInfo bundleInfo;
    ErrCode ret = iBundleMgr->GetBundleInfoV9(bundleName, bundleFlags, bundleInfo, userId);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleInfoV9 failed ret: %{public}d", ret);
        return nullptr;
    }

    ani_object objectBundleInfo = CommonFunAni::ConvertBundleInfo(env, bundleInfo);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        CheckToCache(env, bundleInfo.uid, uid, query, objectBundleInfo);
    }

    return objectBundleInfo;
}

static ani_object getApplicationInfoSync([[maybe_unused]] ani_env *env, ani_string aniBundleName,
    ani_int applicationFlags, ani_int userId)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        return nullptr;
    }

    if (userId == INVALID_USER_ID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }

    const Query query(bundleName, GET_APPLICATION_INFO, applicationFlags, userId);
    {
        std::shared_lock<std::shared_mutex> lock(g_cacheMutex);
        auto item = g_cache.find(query);
        if (item != g_cache.end()) {
            return reinterpret_cast<ani_object>(item->second);
        }
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("nullptr iBundleMgr");
        return nullptr;
    }
    ApplicationInfo appInfo;
    
    ErrCode ret = iBundleMgr->GetApplicationInfoV9(bundleName, applicationFlags, userId, appInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetApplicationInfoV9 failed ret: %{public}d,userId: %{public}d", ret, getuid());
        return nullptr;
    }

    ani_object objectApplicationInfo = CommonFunAni::ConvertApplicationInfo(env, appInfo);
    CheckToCache(env, appInfo.uid, IPCSkeleton::GetCallingUid(), query, objectApplicationInfo);

    return objectApplicationInfo;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        APP_LOGE("Unsupported ANI_VERSION_1");
        return (ani_status)9;
    }

    static const char* nsName = "L@ohos/bundle/bundleManager/bundleManager;";
    ani_namespace kitNs;
    if (env->FindNamespace(nsName, &kitNs) != ANI_OK) {
        APP_LOGE("Not found nameSpace name: %{public}s", nsName);
        return (ani_status)2;
    }

    std::array methods = {
        ani_native_function {
            "isApplicationEnabledSync", "Lstd/core/String;:Z", reinterpret_cast<void*>(isApplicationEnabledSync) },
        ani_native_function {
            "getBundleInfoForSelfSync", "I:LBundleInfo/BundleInfo;",
            reinterpret_cast<void*>(getBundleInfoForSelfSync) },
        ani_native_function {
            "getBundleInfoSync",
            "Lstd/core/String;II:LBundleInfo/BundleInfo;",
            reinterpret_cast<void*>(getBundleInfoSync)
        },
        ani_native_function {
            "getApplicationInfoSync",
            "Lstd/core/String;II:LApplicationInfo/ApplicationInfo;",
            reinterpret_cast<void*>(getApplicationInfoSync)
        },
    };

    if (env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size()) != ANI_OK) {
        APP_LOGE("Cannot bind native methods to %{public}s", nsName);
        return (ani_status)3;
    };

    *result = ANI_VERSION_1;

    RegisterClearCacheListenerAndEnv(vm);

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}

void ClearCacheListener::DoClearCache()
{
    std::unique_lock<std::shared_mutex> lock(g_cacheMutex);
    ani_env* env = nullptr;
    ani_option interopEnabled { "--interop=enable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    g_vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    for (auto& item : g_cache) {
        env->GlobalReference_Delete(item.second);
    }
    g_vm->DetachCurrentThread();
    g_cache.clear();
}

void ClearCacheListener::HandleCleanEnv(void* data)
{
    DoClearCache();
}

ClearCacheListener::ClearCacheListener(const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

void ClearCacheListener::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    DoClearCache();
}

void RegisterClearCacheListenerAndEnv(ani_vm* vm)
{
    std::lock_guard<std::mutex> lock(g_clearCacheListenerMutex);
    if (g_clearCacheListener != nullptr) {
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    g_clearCacheListener = std::make_shared<ClearCacheListener>(subscribeInfo);
    (void)EventFwk::CommonEventManager::SubscribeCommonEvent(g_clearCacheListener);
    g_vm = vm;
}
} // AppExecFwk
} // OHOS
