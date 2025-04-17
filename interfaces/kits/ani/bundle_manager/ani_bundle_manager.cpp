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
#include "bundle_manager_helper.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "enum_util.h"
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
static std::string g_aniOwnBundleName;
static std::mutex g_aniOwnBundleNameMutex;
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

template <typename T>
static void CheckInfoCache(ani_env* env, const ANIQuery& query,
    const OHOS::AAFwk::Want& want, std::vector<T> infos, ani_object aniObject)
{
    ElementName element = want.GetElement();
    if (element.GetBundleName().empty() || element.GetAbilityName().empty()) {
        return;
    }

    uint32_t explicitQueryResultLen = 1;
    if (infos.size() != explicitQueryResultLen || infos[0].uid != IPCSkeleton::GetCallingUid()) {
        return;
    }

    ani_ref cacheInfo = nullptr;
    ani_status status = env->GlobalReference_Create(aniObject, &cacheInfo);
    if (status == ANI_OK) {
        std::unique_lock<std::shared_mutex> lock(g_aniCacheMutex);
        g_aniCache[query] = cacheInfo;
    }
}

static void CheckBatchAbilityInfoCache(ani_env* env, const ANIQuery &query,
    const std::vector<OHOS::AAFwk::Want> &wants, std::vector<AbilityInfo> abilityInfos, ani_object aniObject)
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

    ani_ref cacheInfo = nullptr;
    ani_status status = env->GlobalReference_Create(aniObject, &cacheInfo);
    if (status == ANI_OK) {
        std::unique_lock<std::shared_mutex> lock(g_aniCacheMutex);
        g_aniCache[query] = cacheInfo;
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

static bool ParseAniWantList(ani_env* env, ani_object aniWants, std::vector<OHOS::AAFwk::Want> &wants)
{
    return CommonFunAni::AniArrayForeach(env, aniWants, [env, &wants](ani_object aniWantItem) {
        OHOS::AAFwk::Want want;
        bool result = UnwrapWant(env, aniWantItem, want);
        if (!result) {
            wants.clear();
            return false;
        }
        bool isExplicit = !want.GetBundle().empty() && !want.GetElement().GetAbilityName().empty();
        if (!isExplicit && want.GetAction().empty() && want.GetEntities().empty() &&
            want.GetUriString().empty() && want.GetType().empty() && want.GetStringParam(LINK_FEATURE).empty()) {
            APP_LOGW("implicit params all empty of want");
            return true;
        }
        wants.emplace_back(want);

        return true;
    });
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
    CheckInfoCache(env, query, want, abilityInfos, aniAbilityInfos);
    return aniAbilityInfos;
}

static ani_object GetAppCloneIdentitySync(ani_env* env, ani_double aniUid)
{
    int32_t uid = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniUid, &uid)) {
        APP_LOGE("Cast aniUid failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::UID, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }

    bool queryOwn = (uid == IPCSkeleton::GetCallingUid());
    std::string bundleName;
    int32_t appIndex = 0;
    if (queryOwn) {
        std::lock_guard<std::mutex> lock(g_aniOwnBundleNameMutex);
        if (!g_aniOwnBundleName.empty()) {
            APP_LOGD("ani query own bundleName and appIndex, has cache, no need to query from host");
            CommonFunc::GetBundleNameAndIndexByName(g_aniOwnBundleName, bundleName, appIndex);
            return CommonFunAni::ConvertAppCloneIdentity(env, bundleName, appIndex);
        }
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    ErrCode ret = iBundleMgr->GetNameAndIndexForUid(uid, bundleName, appIndex);
    if (ret != ERR_OK) {
        APP_LOGE("GetNameAndIndexForUid failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret), GET_APP_CLONE_IDENTITY, APP_CLONE_IDENTITY_PERMISSIONS);
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(g_aniOwnBundleNameMutex);
    if (queryOwn && g_aniOwnBundleName.empty()) {
        g_aniOwnBundleName = bundleName;
        if (appIndex > 0) {
            g_aniOwnBundleName = CommonFunc::GetCloneBundleIdKey(bundleName, appIndex);
        }
        APP_LOGD("ani put own bundleName = %{public}s to cache", g_aniOwnBundleName.c_str());
    }
    return CommonFunAni::ConvertAppCloneIdentity(env, bundleName, appIndex);
}

static ani_string GetAbilityLabelSync(ani_env* env,
    ani_string aniBundleName, ani_string aniModuleName, ani_string aniAbilityName)
{
#ifdef GLOBAL_RESMGR_ENABLE
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    std::string moduleName = CommonFunAni::AniStrToString(env, aniModuleName);
    if (moduleName.empty()) {
        APP_LOGE("ModuleName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::MODULE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    std::string abilityName = CommonFunAni::AniStrToString(env, aniAbilityName);
    if (abilityName.empty()) {
        APP_LOGE("AbilityName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::ABILITY_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::string abilityLabel;
    ErrCode ret = iBundleMgr->GetAbilityLabel(bundleName, moduleName, abilityName, abilityLabel);
    if (ret != ERR_OK) {
        APP_LOGE("GetAbilityLabel failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(env, CommonFunc::ConvertErrCode(ret),
            GET_ABILITY_LABEL, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    ani_string aniAbilityLabel = nullptr;
    if (!CommonFunAni::StringToAniStr(env, abilityLabel, aniAbilityLabel)) {
        APP_LOGE("StringToAniStr failed");
        return nullptr;
    }
    return aniAbilityLabel;
#else
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowParameterTypeError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_ABILITY_LABEL, "");
    return nullptr;
#endif
}

static ani_object GetLaunchWantForBundleSyncInner(ani_env* env, ani_string aniBundleName, ani_double aniUserId)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
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
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    OHOS::AAFwk::Want want;
    ErrCode ret = iBundleMgr->GetLaunchWantForBundle(bundleName, want, userId);
    if (ret != ERR_OK) {
        APP_LOGE("GetLaunchWantForBundle failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret),
            GET_LAUNCH_WANT_FOR_BUNDLE_SYNC, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
            return nullptr;
    }
    return WrapWant(env, want);
}

static ani_object GetAppCloneBundleInfoInner(ani_env* env, ani_string aniBundleName,
    ani_double aniAppIndex, ani_double aniBundleFlags, ani_double aniUserId)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("Bundle name is empty.");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::APP_INDEX, CommonFunAniNS::TYPE_NUMBER);
        return nullptr;
    }
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

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Get bundle mgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    BundleInfo bundleInfo;
    ErrCode ret = iBundleMgr->GetCloneBundleInfo(bundleName, bundleFlags, appIndex, bundleInfo, userId);
    if (ret != ERR_OK) {
        APP_LOGE("GetCloneBundleInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret), GET_APP_CLONE_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO);
        return nullptr;
    }

    return CommonFunAni::ConvertBundleInfo(env, bundleInfo, bundleFlags);
}

static ani_string GetSpecifiedDistributionType(ani_env* env, ani_string aniBundleName)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Get bundle mgr failed");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    std::string specifiedDistributionType;
    ErrCode ret = iBundleMgr->GetSpecifiedDistributionType(bundleName, specifiedDistributionType);
    if (ret != ERR_OK) {
        APP_LOGE("GetSpecifiedDistributionType failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(env, CommonFunc::ConvertErrCode(ret),
            RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    ani_string aniSpecifiedDistributionType = nullptr;
    if (!CommonFunAni::StringToAniStr(env, specifiedDistributionType, aniSpecifiedDistributionType)) {
        APP_LOGE("StringToAniStr failed");
        return nullptr;
    }
    return aniSpecifiedDistributionType;
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

static ani_string GetBundleNameByUidSync(ani_env* env, ani_double aniUserId)
{
    int32_t userId = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast userId failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_INT);
        return nullptr;
    }

    std::string bundleName;
    ani_string aniBundleName = nullptr;
    bool queryOwn = (userId == IPCSkeleton::GetCallingUid());
    if (queryOwn) {
        std::lock_guard<std::mutex> lock(g_aniOwnBundleNameMutex);
        if (!g_aniOwnBundleName.empty()) {
            APP_LOGD("query own bundleName, has cache, no need to query from host");
            int32_t appIndex = 0;
            CommonFunc::GetBundleNameAndIndexByName(g_aniOwnBundleName, bundleName, appIndex);
            if (CommonFunAni::StringToAniStr(env, bundleName, aniBundleName)) {
                return aniBundleName;
            } else {
                APP_LOGE("Convert ani_string failed");
                return nullptr;
            }
        }
    }
    int32_t appIndex = 0;
    ErrCode ret = InnerGetAppCloneIdentity(userId, bundleName, appIndex);
    if (ret != ERR_OK) {
        BusinessErrorAni::ThrowParameterTypeError(env, ret, GET_BUNDLE_NAME_BY_UID, BUNDLE_PERMISSIONS);
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(g_aniOwnBundleNameMutex);
    if (queryOwn && g_aniOwnBundleName.empty()) {
        g_aniOwnBundleName = bundleName;
        if (appIndex > 0) {
            g_aniOwnBundleName = std::to_string(appIndex) + "clone_" + bundleName;
        }
        APP_LOGD("put own bundleName = %{public}s to cache", g_aniOwnBundleName.c_str());
    }
    
    if (CommonFunAni::StringToAniStr(env, bundleName, aniBundleName)) {
        return aniBundleName;
    } else {
        APP_LOGE("Convert ani_string failed");
        return nullptr;
    }
}

static ani_object QueryAbilityInfoWithWants(ani_env* env,
    ani_object aniWants, ani_double aniAbilityFlags, ani_double aniUserId)
{
    std::vector<OHOS::AAFwk::Want> wants;
    int32_t abilityFlags = 0;
    int32_t userId = EMPTY_USER_ID;
    if (!ParseAniWantList(env, aniWants, wants)) {
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
    std::string bundleNames = "[";
    for (uint32_t i = 0; i < wants.size(); i++) {
        bundleNames += ((i > 0) ? "," : "");
        bundleNames += wants[i].ToString();
    }
    bundleNames += "]";
    const ANIQuery query(bundleNames, BATCH_QUERY_ABILITY_INFOS, abilityFlags, userId);
    {
        std::shared_lock<std::shared_mutex> lock(g_aniCacheMutex);
        auto item = g_aniCache.find(query);
        if (item != g_aniCache.end()) {
            APP_LOGD("has cache, no need to query from host");
            return reinterpret_cast<ani_object>(item->second);
        }
    }

    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = BundleManagerHelper::InnerBatchQueryAbilityInfos(wants, abilityFlags, userId, abilityInfos);
    if (ret != ERR_OK) {
        APP_LOGE("BatchQueryAbilityInfos failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(env, ret, BATCH_QUERY_ABILITY_INFOS, BUNDLE_PERMISSIONS);
        return nullptr;
    }
    ani_object aniAbilityInfos =
        CommonFunAni::ConvertAniArray(env, abilityInfos, CommonFunAni::ConvertAbilityInfo);
    CheckBatchAbilityInfoCache(env, query, wants, abilityInfos, aniAbilityInfos);
    return aniAbilityInfos;
}

static ani_string GetDynamicIconInner(ani_env* env, ani_string aniBundleName)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return nullptr;
    }
    std::string moduleName;
    ErrCode ret = BundleManagerHelper::InnerGetDynamicIcon(bundleName, moduleName);
    if (ret != ERR_OK) {
        APP_LOGE("GetDynamicIcon failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(env, ret,
            GET_DYNAMIC_ICON, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    ani_string aniModuleName = nullptr;
    if (!CommonFunAni::StringToAniStr(env, moduleName, aniModuleName)) {
        APP_LOGE("StringToAniStr failed");
        return nullptr;
    }
    return aniModuleName;
}

static ani_boolean IsAbilityEnabledSyncInner(ani_env* env,
    ani_object aniAbilityInfo, ani_double aniAppIndex)
{
    bool isEnable = false;
    AbilityInfo abilityInfo;
    if (!CommonFunAni::ParseAbilityInfo(env, aniAbilityInfo, abilityInfo)) {
        APP_LOGE("ParseAbilityInfo failed");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
        return isEnable;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::APP_INDEX, CommonFunAniNS::TYPE_NUMBER);
        return isEnable;
    }
    ErrCode ret = BundleManagerHelper::InnerIsAbilityEnabled(abilityInfo, isEnable, appIndex);
    if (ret != ERR_OK) {
        APP_LOGE("IsAbilityEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(env, ret, IS_ABILITY_ENABLED_SYNC, "");
    }
    return isEnable;
}

static void SetAbilityEnabledSyncInner(ani_env* env,
    ani_object aniAbilityInfo, ani_boolean aniIsEnable, ani_double aniAppIndex)
{
    AbilityInfo abilityInfo;
    bool isEnable = CommonFunAni::AniBooleanToBool(aniIsEnable);
    if (!CommonFunAni::ParseAbilityInfo(env, aniAbilityInfo, abilityInfo)) {
        APP_LOGE("ParseAbilityInfo failed");
        BusinessErrorAni::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
        return;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::APP_INDEX, CommonFunAniNS::TYPE_NUMBER);
        return;
    }
    ErrCode ret = BundleManagerHelper::InnerSetAbilityEnabled(abilityInfo, isEnable, appIndex);
    if (ret != ERR_OK) {
        APP_LOGE("SetAbilityEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(env, ret,
            SET_ABILITY_ENABLED_SYNC, Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
    }
}

static void SetApplicationEnabledSyncInner(ani_env* env,
    ani_string aniBundleName, ani_boolean aniIsEnable, ani_double aniAppIndex)
{
    bool isEnable = CommonFunAni::AniBooleanToBool(aniIsEnable);
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, CommonFunAniNS::TYPE_STRING);
        return;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::APP_INDEX, CommonFunAniNS::TYPE_NUMBER);
        return;
    }
    ErrCode ret = BundleManagerHelper::InnerSetApplicationEnabled(bundleName, isEnable, appIndex);
    if (ret != ERR_OK) {
        APP_LOGE("SetApplicationEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(env, ret,
            SET_APPLICATION_ENABLED_SYNC, Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
    }
}

static ani_object QueryExtensionAbilityInfoInner(ani_env* env, ani_object aniWant,
    ani_enum_item aniExtensionAbilityType, ani_string aniExtensionAbilityTypeName,
    ani_double aniExtensionAbilityFlags, ani_double aniUserId, ani_boolean aniIsExtensionTypeName)
{
    OHOS::AAFwk::Want want;
    ExtensionAbilityType extensionAbilityType = ExtensionAbilityType::UNSPECIFIED;
    int32_t flags = 0;
    int32_t userId = EMPTY_USER_ID;
    std::string extensionTypeName;
    bool isExtensionTypeName = CommonFunAni::AniBooleanToBool(aniIsExtensionTypeName);

    if (!ParseAniWant(env, aniWant, want)) {
        APP_LOGE("ParseAniWant failed");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, INVALID_WANT_ERROR);
        return nullptr;
    }
    if (isExtensionTypeName) {
        extensionTypeName = CommonFunAni::AniStrToString(env, aniExtensionAbilityTypeName);
        if (extensionTypeName.empty()) {
            APP_LOGE("extensionTypeName is empty");
            BusinessErrorAni::ThrowParameterTypeError(
                env, ERROR_PARAM_CHECK_ERROR, EXTENSION_TYPE_NAME, CommonFunAniNS::TYPE_STRING);
            return nullptr;
        }
    } else {
        if (!EnumUtils::EnumETSToNative(env, aniExtensionAbilityType, extensionAbilityType)) {
            APP_LOGE("Parse extensionAbilityType failed");
            BusinessErrorAni::ThrowParameterTypeError(
                env, ERROR_PARAM_CHECK_ERROR, EXTENSION_ABILITY_TYPE, CommonFunAniNS::TYPE_NUMBER);
            return nullptr;
        }
    }
    if (!CommonFunAni::TryCastDoubleTo(aniExtensionAbilityFlags, &flags)) {
        APP_LOGE("Cast aniExtensionAbilityFlags failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, FLAGS, CommonFunAniNS::TYPE_NUMBER);
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

    std::string key = want.ToString() + std::to_string(static_cast<int32_t>(extensionAbilityType));
    const ANIQuery query(key, QUERY_EXTENSION_INFOS_SYNC, flags, userId);
    {
        std::shared_lock<std::shared_mutex> lock(g_aniCacheMutex);
        auto item = g_aniCache.find(query);
        if (item != g_aniCache.end()) {
            APP_LOGD("ani extension has cache, no need to query from host");
            return reinterpret_cast<ani_object>(item->second);
        }
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    ErrCode ret = ERR_OK;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    if (!isExtensionTypeName) {
        if (extensionAbilityType == ExtensionAbilityType::UNSPECIFIED) {
            APP_LOGD("Query aniExtensionAbilityInfo sync without type");
            ret = iBundleMgr->QueryExtensionAbilityInfosV9(want, flags, userId, extensionInfos);
        } else {
            APP_LOGD("Query aniExtensionAbilityInfo sync with type %{public}d",
                static_cast<int32_t>(extensionAbilityType));
            ret = iBundleMgr->QueryExtensionAbilityInfosV9(want, extensionAbilityType, flags, userId, extensionInfos);
        }
    } else {
        APP_LOGD("Query aniExtensionAbilityInfo sync with extensionTypeName %{public}s", extensionTypeName.c_str());
        ret = iBundleMgr->QueryExtensionAbilityInfosWithTypeName(
            want, extensionTypeName, flags, userId, extensionInfos);
    }

    if (ret != ERR_OK) {
        APP_LOGE("QueryExtensionAbilityInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret), QUERY_EXTENSION_INFOS_SYNC, BUNDLE_PERMISSIONS);
            return nullptr;
    }
    ani_object aniExtensionAbilityInfos =
        CommonFunAni::ConvertAniArray(env, extensionInfos, CommonFunAni::ConvertExtensionInfo);
    CheckInfoCache(env, query, want, extensionInfos, aniExtensionAbilityInfos);
    return aniExtensionAbilityInfos;
}

static ani_object QueryExAbilityInfoSyncWithoutWant(ani_env* env, ani_string aniExtensionAbilityTypeName,
    ani_double aniExtensionAbilityFlags, ani_double aniUserId)
{
    int32_t flags = 0;
    int32_t userId = EMPTY_USER_ID;

    std::string extensionTypeName = CommonFunAni::AniStrToString(env, aniExtensionAbilityTypeName);
    if (extensionTypeName.empty()) {
        APP_LOGE("extensionTypeName is empty");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, PARAM_EXTENSION_ABILITY_TYPE_EMPTY_ERROR, "");
        return nullptr;
    }
    if (!CommonFunAni::TryCastDoubleTo(aniExtensionAbilityFlags, &flags)) {
        APP_LOGE("Cast aniExtensionAbilityFlags failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, FLAGS, CommonFunAniNS::TYPE_NUMBER);
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

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = iBundleMgr->QueryExtensionAbilityInfosOnlyWithTypeName(extensionTypeName,
        (flags < 0 ? 0 : static_cast<uint32_t>(flags)), userId, extensionInfos);
    if (ret != ERR_OK) {
        APP_LOGE("QueryExAbilityInfoSync without want failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowParameterTypeError(
            env, CommonFunc::ConvertErrCode(ret), QUERY_EXTENSION_INFOS_SYNC, BUNDLE_PERMISSIONS);
            return nullptr;
    }
    return CommonFunAni::ConvertAniArray(env, extensionInfos, CommonFunAni::ConvertExtensionInfo);
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
        ani_native_function { "getAppCloneIdentitySync", nullptr, reinterpret_cast<void*>(GetAppCloneIdentitySync) },
        ani_native_function { "getAbilityLabelSync", nullptr, reinterpret_cast<void*>(GetAbilityLabelSync) },
        ani_native_function { "getLaunchWantForBundleSyncInner", nullptr,
            reinterpret_cast<void*>(GetLaunchWantForBundleSyncInner) },
        ani_native_function { "getAppCloneBundleInfoInner", nullptr,
            reinterpret_cast<void*>(GetAppCloneBundleInfoInner) },
        ani_native_function { "getSpecifiedDistributionType", nullptr,
            reinterpret_cast<void*>(GetSpecifiedDistributionType) },
        ani_native_function { "getBundleNameByUidSync", nullptr, reinterpret_cast<void*>(GetBundleNameByUidSync) },
        ani_native_function { "queryExtensionAbilityInfoInner", nullptr,
            reinterpret_cast<void*>(QueryExtensionAbilityInfoInner) },
        ani_native_function { "queryExAbilityInfoSyncWithoutWant", nullptr,
            reinterpret_cast<void*>(QueryExAbilityInfoSyncWithoutWant) },
        ani_native_function { "isAbilityEnabledSyncInner", nullptr,
            reinterpret_cast<void*>(IsAbilityEnabledSyncInner) },
        ani_native_function { "setAbilityEnabledSyncInner", nullptr,
            reinterpret_cast<void*>(SetAbilityEnabledSyncInner) },
        ani_native_function { "setApplicationEnabledSyncInner", nullptr,
            reinterpret_cast<void*>(SetApplicationEnabledSyncInner) },
        ani_native_function { "getDynamicIconInner", nullptr, reinterpret_cast<void*>(GetDynamicIconInner) },
        ani_native_function { "queryAbilityInfoWithWants", nullptr,
            reinterpret_cast<void*>(QueryAbilityInfoWithWants) },
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
