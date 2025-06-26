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
#include <ani_signature_builder.h>
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_manager_helper.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error_ani.h"
#include "clean_cache_callback.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "enum_util.h"
#include "ipc_skeleton.h"
#include "napi_constants.h"
#include "process_cache_callback_host.h"

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

template <typename T>
static void CheckInfoCache(ani_env* env, const ANIQuery& query,
    const OHOS::AAFwk::Want& want, std::vector<T> infos, ani_object aniObject)
{
    RETURN_IF_NULL(aniObject);
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
    RETURN_IF_NULL(aniObject);
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
    RETURN_FALSE_IF_NULL(aniWant);
    ani_string string = nullptr;
    std::string bundleName;
    std::string abilityName;
    std::string moduleName;

    if (CommonFunAni::CallGetterOptional(env, aniWant, BUNDLE_NAME, &string)) {
        bundleName = CommonFunAni::AniStrToString(env, string);
    }
    if (CommonFunAni::CallGetterOptional(env, aniWant, Constants::ABILITY_NAME, &string)) {
        abilityName = CommonFunAni::AniStrToString(env, string);
    }
    if (CommonFunAni::CallGetterOptional(env, aniWant, MODULE_NAME, &string)) {
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
    RETURN_FALSE_IF_NULL(aniWants);
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

static ani_object GetBundleInfoForSelfNative(ani_env* env, ani_double aniBundleFlags, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetBundleInfoForSelf called");
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
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
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleInfoForSelf failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? GET_BUNDLE_INFO_FOR_SELF_SYNC : GET_BUNDLE_INFO,
            isSync ? BUNDLE_PERMISSIONS : Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    ani_object objectBundleInfo = CommonFunAni::ConvertBundleInfo(env, bundleInfo, bundleFlags);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        CheckToCache(env, bundleInfo.uid, uid, query, objectBundleInfo);
    }

    return objectBundleInfo;
}

static ani_object GetBundleInfoNative(ani_env* env,
    ani_string aniBundleName, ani_double aniBundleFlags, ani_double aniUserId, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetBundleInfo called");
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (isSync && bundleName.size() == 0) {
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_BUNDLE_NOT_EXIST, GET_BUNDLE_INFO_SYNC, BUNDLE_PERMISSIONS);
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
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? GET_BUNDLE_INFO_SYNC : GET_BUNDLE_INFO,
            isSync ? BUNDLE_PERMISSIONS : Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    ani_object objectBundleInfo = CommonFunAni::ConvertBundleInfo(env, bundleInfo, bundleFlags);
    if (!CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        CheckToCache(env, bundleInfo.uid, callingUid, query, objectBundleInfo);
    }

    return objectBundleInfo;
}

static ani_object GetApplicationInfoNative(ani_env* env,
    ani_string aniBundleName, ani_double aniApplicationFlags, ani_double aniUserId, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetApplicationInfo called");
    int32_t applicationFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniApplicationFlags, &applicationFlags)) {
        APP_LOGE("Cast aniApplicationFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
    }
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }

    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (isSync && bundleName.size() == 0) {
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_BUNDLE_NOT_EXIST, GET_APPLICATION_INFO_SYNC, BUNDLE_PERMISSIONS);
        return nullptr;
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
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? GET_APPLICATION_INFO_SYNC : GET_APPLICATION_INFO,
            isSync ? BUNDLE_PERMISSIONS : Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    ani_object objectApplicationInfo = CommonFunAni::ConvertApplicationInfo(env, appInfo);
    CheckToCache(env, appInfo.uid, callingUid, query, objectApplicationInfo);

    return objectApplicationInfo;
}

static ani_object GetAllBundleInfoNative(ani_env* env, ani_double aniBundleFlags, ani_double aniUserId)
{
    APP_LOGD("ani GetAllBundleInfo called");
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
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
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), GET_BUNDLE_INFOS,
            Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST);
        return nullptr;
    }
    APP_LOGI("GetBundleInfosV9 ret: %{public}d, bundleInfos size: %{public}d", ret, bundleInfos.size());

    return CommonFunAni::ConvertAniArray(env, bundleInfos, CommonFunAni::ConvertBundleInfo, bundleFlags);
}

static ani_object GetAllApplicationInfoNative(ani_env* env, ani_double aniApplicationFlags, ani_double aniUserId)
{
    APP_LOGD("ani GetAllApplicationInfo called");
    int32_t applicationFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniApplicationFlags, &applicationFlags)) {
        APP_LOGE("Cast aniApplicationFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
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
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), GET_APPLICATION_INFOS,
            Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST);
        return nullptr;
    }
    APP_LOGI("applicationInfos size: %{public}d", appInfos.size());

    return CommonFunAni::ConvertAniArray(env, appInfos, CommonFunAni::ConvertApplicationInfo);
}

static ani_boolean IsApplicationEnabledNative(ani_env* env,
    ani_string aniBundleName, ani_double aniAppIndex, ani_boolean aniIsSync)
{
    APP_LOGD("ani IsApplicationEnabled called");
    bool isEnable = false;
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return isEnable;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return isEnable;
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
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("IsCloneApplicationEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret), isSync ? IS_APPLICATION_ENABLED_SYNC : "", "");
    }
    return isEnable;
}

static ani_object QueryAbilityInfoSyncNative(ani_env* env,
    ani_object aniWant, ani_double aniAbilityFlags, ani_double aniUserId, ani_boolean aniIsSync)
{
    APP_LOGD("ani QueryAbilityInfoSync called");
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
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
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
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("QueryAbilityInfosV9 failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? QUERY_ABILITY_INFOS_SYNC : QUERY_ABILITY_INFOS, BUNDLE_PERMISSIONS);
        return nullptr;
    }
    ani_object aniAbilityInfos =
        CommonFunAni::ConvertAniArray(env, abilityInfos, CommonFunAni::ConvertAbilityInfo);
    CheckInfoCache(env, query, want, abilityInfos, aniAbilityInfos);
    return aniAbilityInfos;
}

static ani_object GetAppCloneIdentityNative(ani_env* env, ani_double aniUid)
{
    APP_LOGD("ani GetAppCloneIdentity called");
    int32_t uid = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniUid, &uid)) {
        APP_LOGE("Cast aniUid failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::UID, TYPE_NUMBER);
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
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_APP_CLONE_IDENTITY, APP_CLONE_IDENTITY_PERMISSIONS);
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

static ani_string GetAbilityLabelNative(ani_env* env,
    ani_string aniBundleName, ani_string aniModuleName, ani_string aniAbilityName, ani_boolean aniIsSync)
{
#ifdef GLOBAL_RESMGR_ENABLE
    APP_LOGD("ani GetAbilityLabel called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName)) {
        APP_LOGE("moduleName %{public}s invalid", moduleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string abilityName;
    if (!CommonFunAni::ParseString(env, aniAbilityName, abilityName)) {
        APP_LOGE("abilityName %{public}s invalid", abilityName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::ABILITY_NAME, TYPE_STRING);
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
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("GetAbilityLabel failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? GET_ABILITY_LABEL_SYNC : GET_ABILITY_LABEL, BUNDLE_PERMISSIONS);
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
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_ABILITY_LABEL, "");
    return nullptr;
#endif
}

static ani_object GetLaunchWantForBundleNative(ani_env* env,
    ani_string aniBundleName, ani_double aniUserId, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetLaunchWantForBundle called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
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
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("GetLaunchWantForBundle failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? GET_LAUNCH_WANT_FOR_BUNDLE_SYNC : GET_LAUNCH_WANT_FOR_BUNDLE,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    return WrapWant(env, want);
}

static ani_object GetAppCloneBundleInfoNative(ani_env* env, ani_string aniBundleName,
    ani_double aniAppIndex, ani_double aniBundleFlags, ani_double aniUserId)
{
    APP_LOGD("ani GetAppCloneBundleInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return nullptr;
    }
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, use default value");
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
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_APP_CLONE_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO);
        return nullptr;
    }

    return CommonFunAni::ConvertBundleInfo(env, bundleInfo, bundleFlags);
}

static ani_string GetSpecifiedDistributionType(ani_env* env, ani_string aniBundleName)
{
    APP_LOGD("ani GetSpecifiedDistributionType called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Get bundle mgr failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    std::string specifiedDistributionType;
    ErrCode ret = iBundleMgr->GetSpecifiedDistributionType(bundleName, specifiedDistributionType);
    if (ret != ERR_OK) {
        APP_LOGE("GetSpecifiedDistributionType failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
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

static ani_string GetBundleNameByUidNative(ani_env* env, ani_double aniUserId, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetBundleNameByUid called");
    int32_t userId = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast userId failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::UID, TYPE_NUMBER);
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
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        BusinessErrorAni::ThrowCommonError(
            env, ret, isSync ? GET_BUNDLE_NAME_BY_UID_SYNC : GET_BUNDLE_NAME_BY_UID, BUNDLE_PERMISSIONS);
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

static ani_object QueryAbilityInfoWithWantsNative(ani_env* env,
    ani_object aniWants, ani_double aniAbilityFlags, ani_double aniUserId)
{
    APP_LOGD("ani QueryAbilityInfoWithWants called");
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
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
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
        BusinessErrorAni::ThrowCommonError(env, ret, BATCH_QUERY_ABILITY_INFOS, BUNDLE_PERMISSIONS);
        return nullptr;
    }
    ani_object aniAbilityInfos =
        CommonFunAni::ConvertAniArray(env, abilityInfos, CommonFunAni::ConvertAbilityInfo);
    CheckBatchAbilityInfoCache(env, query, wants, abilityInfos, aniAbilityInfos);
    return aniAbilityInfos;
}

static ani_string GetDynamicIconNative(ani_env* env, ani_string aniBundleName)
{
    APP_LOGD("ani GetDynamicIcon called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string moduleName;
    ErrCode ret = BundleManagerHelper::InnerGetDynamicIcon(bundleName, moduleName);
    if (ret != ERR_OK) {
        APP_LOGE("GetDynamicIcon failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret,
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

static ani_boolean IsAbilityEnabledNative(ani_env* env,
    ani_object aniAbilityInfo, ani_double aniAppIndex, ani_boolean aniIsSync)
{
    APP_LOGD("ani IsAbilityEnabled called");
    bool isEnable = false;
    AbilityInfo abilityInfo;
    if (!CommonFunAni::ParseAbilityInfo(env, aniAbilityInfo, abilityInfo)) {
        APP_LOGE("ParseAbilityInfo failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
        return isEnable;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return isEnable;
    }
    ErrCode ret = BundleManagerHelper::InnerIsAbilityEnabled(abilityInfo, isEnable, appIndex);
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("IsAbilityEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, isSync ? IS_ABILITY_ENABLED_SYNC : "", "");
    }
    return isEnable;
}

static void SetAbilityEnabledNative(ani_env* env,
    ani_object aniAbilityInfo, ani_boolean aniIsEnable, ani_double aniAppIndex, ani_boolean aniIsSync)
{
    APP_LOGD("ani SetAbilityEnabled called");
    AbilityInfo abilityInfo;
    bool isEnable = CommonFunAni::AniBooleanToBool(aniIsEnable);
    if (!CommonFunAni::ParseAbilityInfo(env, aniAbilityInfo, abilityInfo)) {
        APP_LOGE("ParseAbilityInfo failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, ABILITY_INFO, TYPE_OBJECT);
        return;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return;
    }
    ErrCode ret = BundleManagerHelper::InnerSetAbilityEnabled(abilityInfo, isEnable, appIndex);
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("SetAbilityEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, isSync ? SET_ABILITY_ENABLED_SYNC : SET_ABILITY_ENABLED,
            Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
    }
}

static void SetApplicationEnabledNative(ani_env* env,
    ani_string aniBundleName, ani_boolean aniIsEnable, ani_double aniAppIndex, ani_boolean aniIsSync)
{
    APP_LOGD("ani SetApplicationEnabled called");
    bool isEnable = CommonFunAni::AniBooleanToBool(aniIsEnable);
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return;
    }
    ErrCode ret = BundleManagerHelper::InnerSetApplicationEnabled(bundleName, isEnable, appIndex);
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("SetApplicationEnabled failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, isSync ? SET_APPLICATION_ENABLED_SYNC : SET_APPLICATION_ENABLED,
            Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE);
    }
}

static ani_object QueryExtensionAbilityInfoNative(ani_env* env,
    ani_object aniWant, ani_enum_item aniExtensionAbilityType, ani_string aniExtensionAbilityTypeName,
    ani_double aniExtensionAbilityFlags, ani_double aniUserId,
    ani_boolean aniIsExtensionTypeName, ani_boolean aniIsSync)
{
    APP_LOGD("ani QueryExtensionAbilityInfo called");
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
        if (!CommonFunAni::ParseString(env, aniExtensionAbilityTypeName, extensionTypeName)) {
            APP_LOGE("parse extensionTypeName failed");
            BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, EXTENSION_TYPE_NAME, TYPE_STRING);
            return nullptr;
        }
    } else {
        if (!EnumUtils::EnumETSToNative(env, aniExtensionAbilityType, extensionAbilityType)) {
            APP_LOGE("Parse extensionAbilityType failed");
            BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, EXTENSION_ABILITY_TYPE, TYPE_NUMBER);
            return nullptr;
        }
    }
    if (!CommonFunAni::TryCastDoubleTo(aniExtensionAbilityFlags, &flags)) {
        APP_LOGE("Cast aniExtensionAbilityFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
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

    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("QueryExtensionAbilityInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? QUERY_EXTENSION_INFOS_SYNC : QUERY_EXTENSION_INFOS, BUNDLE_PERMISSIONS);
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
    APP_LOGD("ani QueryExAbilityInfoSyncWithoutWant called");
    int32_t flags = 0;
    int32_t userId = EMPTY_USER_ID;

    std::string extensionTypeName;
    if (!CommonFunAni::ParseString(env, aniExtensionAbilityTypeName, extensionTypeName)) {
        APP_LOGE("parse extensionTypeName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, EXTENSION_TYPE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (extensionTypeName.empty()) {
        APP_LOGE("the input extensionAbilityType is empty");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_EXTENSION_ABILITY_TYPE_EMPTY_ERROR);
        return nullptr;
    }
    if (!CommonFunAni::TryCastDoubleTo(aniExtensionAbilityFlags, &flags)) {
        APP_LOGE("Cast aniExtensionAbilityFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
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
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            QUERY_EXTENSION_INFOS_SYNC, BUNDLE_PERMISSIONS);
        return nullptr;
    }
    return CommonFunAni::ConvertAniArray(env, extensionInfos, CommonFunAni::ConvertExtensionInfo);
}

static void EnableDynamicIconNative(ani_env* env, ani_string aniBundleName, ani_string aniModuleName)
{
    APP_LOGD("ani EnableDynamicIcon called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName %{public}s invalid", bundleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return;
    }
    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName)) {
        APP_LOGE("moduleName %{public}s invalid", moduleName.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return;
    }
    
    ErrCode ret = BundleManagerHelper::InnerEnableDynamicIcon(bundleName, moduleName);
    if (ret != ERR_OK) {
        APP_LOGE("EnableDynamicIcon failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret,
            ENABLE_DYNAMIC_ICON, Constants::PERMISSION_ACCESS_DYNAMIC_ICON);
    }
}

static ani_object GetBundleArchiveInfoNative(
    ani_env* env, ani_string aniHapFilePath, ani_double aniBundleFlags, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetBundleArchiveInfoNative called");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    std::string hapFilePath;
    if (!CommonFunAni::ParseString(env, aniHapFilePath, hapFilePath)) {
        APP_LOGE("hapFilePath parse failed");
        if (isSync) {
            BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, HAP_FILE_PATH, TYPE_STRING);
        } else {
            BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        }
        return nullptr;
    }
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }

    BundleInfo bundleInfo;
    ErrCode ret = BundleManagerHelper::InnerGetBundleArchiveInfo(hapFilePath, bundleFlags, bundleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetBundleArchiveInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, isSync ? GET_BUNDLE_ARCHIVE_INFO_SYNC : GET_BUNDLE_ARCHIVE_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    return CommonFunAni::ConvertBundleInfo(env, bundleInfo, bundleFlags);
}

static ani_object GetLaunchWant(ani_env* env)
{
    APP_LOGD("ani GetLaunchWant called");
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    OHOS::AAFwk::Want want;
    ErrCode ret = iBundleMgr->GetLaunchWant(want);
    if (ret != ERR_OK) {
        APP_LOGE("GetLaunchWant failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowError(env, ERROR_GET_LAUNCH_WANT_INVALID, ERR_MSG_LAUNCH_WANT_INVALID);
        return nullptr;
    }
    ElementName elementName = want.GetElement();
    if (elementName.GetBundleName().empty() || elementName.GetAbilityName().empty()) {
        APP_LOGE("bundleName or abilityName is empty");
        BusinessErrorAni::ThrowError(env, ERROR_GET_LAUNCH_WANT_INVALID, ERR_MSG_LAUNCH_WANT_INVALID);
        return nullptr;
    }

    return WrapWant(env, want);
}

static ani_object GetProfileByAbilityNative(ani_env* env, ani_string aniModuleName, ani_string aniAbilityName,
    ani_string aniMetadataName, ani_boolean aniIsExtensionProfile, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetProfileByAbilityNative called");
    std::string moduleName;
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName)) {
        APP_LOGE("moduleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::MODULE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (isSync && moduleName.empty()) {
        APP_LOGE("param failed due to empty moduleName");
        BusinessErrorAni::ThrowCommonError(env, ERROR_MODULE_NOT_EXIST, "", "");
        return nullptr;
    }
    std::string abilityName;
    if (!CommonFunAni::ParseString(env, aniAbilityName, abilityName)) {
        APP_LOGE("abilityName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::ABILITY_NAME, TYPE_STRING);
        return nullptr;
    }
    if (isSync && abilityName.empty()) {
        APP_LOGE("param failed due to empty abilityName");
        BusinessErrorAni::ThrowCommonError(env, ERROR_ABILITY_NOT_EXIST, "", "");
        return nullptr;
    }
    std::string metadataName;
    if (!CommonFunAni::ParseString(env, aniMetadataName, metadataName)) {
        APP_LOGW("Parse metadataName failed, The default value is undefined");
    }
    bool isExtensionProfile = CommonFunAni::AniBooleanToBool(aniIsExtensionProfile);

    std::vector<std::string> profileVec;
    ErrCode ret = BundleManagerHelper::CommonInnerGetProfile(
        moduleName, abilityName, metadataName, isExtensionProfile, profileVec);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetProfile failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            (isSync ? (isExtensionProfile ? GET_PROFILE_BY_EXTENSION_ABILITY_SYNC : GET_PROFILE_BY_ABILITY_SYNC) : ""),
            "");
        return nullptr;
    }
    return CommonFunAni::ConvertAniArrayString(env, profileVec);
}

static ani_object GetPermissionDefNative(ani_env* env, ani_string aniPermissionName, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetPermissionDefNative called");
    std::string permissionName;
    if (!CommonFunAni::ParseString(env, aniPermissionName, permissionName)) {
        APP_LOGE("permissionName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PERMISSION_NAME, TYPE_STRING);
        return nullptr;
    }
    PermissionDef permissionDef;
    ErrCode ret = BundleManagerHelper::InnerGetPermissionDef(permissionName, permissionDef);
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetPermissionDef failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, isSync ? GET_PERMISSION_DEF_SYNC : GET_PERMISSION_DEF,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    return CommonFunAni::ConvertPermissionDef(env, permissionDef);
}

static void CleanBundleCacheFilesNative(ani_env* env, ani_string aniBundleName, ani_double aniAppIndex)
{
    APP_LOGD("ani CleanBundleCacheFilesNative called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return;
    }
    int32_t appIndex = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGE("Cast aniAppIndex failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPINDEX, Constants::APP_INDEX, TYPE_NUMBER);
        return;
    }
    if (appIndex < Constants::MAIN_APP_INDEX || appIndex > Constants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("appIndex: %{public}d not in valid range", appIndex);
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPINDEX, Constants::APP_INDEX, TYPE_NUMBER);
        return;
    }

    sptr<CleanCacheCallback> cleanCacheCallback = new (std::nothrow) CleanCacheCallback();
    ErrCode ret = BundleManagerHelper::InnerCleanBundleCacheCallback(bundleName, appIndex, cleanCacheCallback);
    if ((ret == ERR_OK) && (cleanCacheCallback != nullptr)) {
        APP_LOGI("clean exec wait");
        if (cleanCacheCallback->WaitForCompletion()) {
            ret = cleanCacheCallback->GetErr() ? ERR_OK : ERROR_BUNDLE_SERVICE_EXCEPTION;
        } else {
            APP_LOGI("clean exec timeout");
            ret = ERROR_BUNDLE_SERVICE_EXCEPTION;
        }
    }
    if (ret != ERR_OK) {
        APP_LOGE("CleanBundleCacheFiles failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, CLEAN_BUNDLE_CACHE_FILES, Constants::PERMISSION_REMOVECACHEFILE);
    }
}

static ani_double GetAllBundleCacheSizeNative(ani_env* env)
{
    APP_LOGD("ani GetAllBundleCacheSizeNative called");
    sptr<ProcessCacheCallbackHost> cacheCallback = new (std::nothrow) ProcessCacheCallbackHost();
    if (cacheCallback == nullptr) {
        APP_LOGE("cacheCallback is null");
        return 0;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return 0;
    }

    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->GetAllBundleCacheStat(cacheCallback));
    APP_LOGI("GetAllBundleCacheStat call, result is %{public}d", ret);
    if (ret != ERR_OK) {
        APP_LOGE("GetAllBundleCacheSize failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_ALL_BUNDLE_CACHE_SIZE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return 0;
    }

    uint64_t cacheSize = 0;
    APP_LOGI("GetCacheStat wait");
    cacheSize = cacheCallback->GetCacheStat();
    APP_LOGI("GetCacheStat finished");
    if (cacheSize > uint64_t(INT64_MAX)) {
        APP_LOGW("value out of range for int64");
        cacheSize = uint64_t(INT64_MAX);
    }

    return static_cast<ani_double>(cacheSize);
}

static void CleanAllBundleCacheNative(ani_env* env)
{
    APP_LOGD("ani CleanAllBundleCacheNative called");
    sptr<ProcessCacheCallbackHost> cacheCallback = new (std::nothrow) ProcessCacheCallbackHost();
    if (cacheCallback == nullptr) {
        APP_LOGE("cacheCallback is null");
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return;
    }

    ErrCode ret = CommonFunc::ConvertErrCode(iBundleMgr->CleanAllBundleCache(cacheCallback));
    APP_LOGI("CleanAllBundleCache call, result is %{public}d", ret);
    if (ret != ERR_OK) {
        APP_LOGE("CleanAllBundleCache failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, CLEAN_ALL_BUNDLE_CACHE, Constants::PERMISSION_REMOVECACHEFILE);
        return;
    }

    APP_LOGI("GetCleanRet wait");
    auto result = cacheCallback->GetCleanRet();
    APP_LOGI("GetCleanRet finished");
    if (result != 0) {
        APP_LOGE("CleanAllBundleCache failed, result %{public}d", result);
    }
}

static ani_object GetAppProvisionInfoNative(
    ani_env* env, ani_string aniBundleName, ani_double aniUserId, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetAppProvisionInfoNative called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }
    AppProvisionInfo appProvisionInfo;
    ErrCode ret = BundleManagerHelper::InnerGetAppProvisionInfo(bundleName, userId, appProvisionInfo);
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetAppProvisionInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, isSync ? GET_APP_PROVISION_INFO_SYNC : GET_APP_PROVISION_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    return CommonFunAni::ConvertAppProvisionInfo(env, appProvisionInfo);
}

static ani_boolean CanOpenLink(ani_env* env, ani_string aniLink)
{
    APP_LOGD("ani CanOpenLink called");
    bool canOpen = false;
    std::string link;
    if (!CommonFunAni::ParseString(env, aniLink, link)) {
        APP_LOGE("link parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, LINK, TYPE_STRING);
        return canOpen;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return canOpen;
    }
    ErrCode ret = iBundleMgr->CanOpenLink(link, canOpen);
    if (ret != ERR_OK) {
        APP_LOGE("CanOpenLink failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), CAN_OPEN_LINK, "");
    }
    return canOpen;
}

static ani_object GetAllPreinstalledApplicationInfoNative(ani_env* env)
{
    APP_LOGD("ani GetAllPreinstalledApplicationInfoNative called");
    std::vector<PreinstalledApplicationInfo> preinstalledApplicationInfos;
    ErrCode ret = BundleManagerHelper::InnerGetAllPreinstalledApplicationInfos(preinstalledApplicationInfos);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetAllPreinstalledApplicationInfos failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_ALL_PREINSTALLED_APP_INFOS, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    return CommonFunAni::ConvertAniArray(
        env, preinstalledApplicationInfos, CommonFunAni::ConvertPreinstalledApplicationInfo);
}

static ani_object GetAllBundleInfoByDeveloperId(ani_env* env, ani_string aniDeveloperId)
{
    APP_LOGD("ani GetAllBundleInfoByDeveloperId called");
    std::string developerId;
    if (!CommonFunAni::ParseString(env, aniDeveloperId, developerId)) {
        APP_LOGE("developerId parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, DEVELOPER_ID, TYPE_STRING);
        return nullptr;
    }
    if (developerId.empty()) {
        APP_LOGE("developerId is empty");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_DEVELOPER_ID_EMPTY_ERROR);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode ret = iBundleMgr->GetAllBundleInfoByDeveloperId(developerId, bundleInfos, userId);
    if (ret != ERR_OK) {
        APP_LOGE("GetAllBundleInfoByDeveloperId failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), GET_ALL_BUNDLE_INFO_BY_DEVELOPER_ID,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    return CommonFunAni::ConvertAniArray(env, bundleInfos, CommonFunAni::ConvertBundleInfo,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION));
}

static void SwitchUninstallState(ani_env* env, ani_string aniBundleName, ani_boolean aniState)
{
    APP_LOGD("ani SwitchUninstallState called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return;
    }
    bool state = CommonFunAni::AniBooleanToBool(aniState);
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return;
    }
    ErrCode ret = iBundleMgr->SwitchUninstallState(bundleName, state);
    if (ret != ERR_OK) {
        APP_LOGE("SwitchUninstallState failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), SWITCH_UNINSTALL_STATE, "");
    }
}

static ani_object GetSignatureInfo(ani_env* env, ani_double aniUid)
{
    APP_LOGD("ani GetSignatureInfo called");
    int32_t uid = -1;
    if (!CommonFunAni::TryCastDoubleTo(aniUid, &uid)) {
        APP_LOGE("Cast aniUid failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::UID, TYPE_NUMBER);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    SignatureInfo signatureInfo;
    ErrCode ret = iBundleMgr->GetSignatureInfoByUid(uid, signatureInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetSignatureInfoByUid failed ret: %{public}d, uid is %{public}d", ret, uid);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret), GET_SIGNATURE_INFO_SYNC, GET_SIGNATURE_INFO_PERMISSIONS);
        return nullptr;
    }
    return CommonFunAni::ConvertSignatureInfo(env, signatureInfo);
}

static ani_object GetAllAppCloneBundleInfoNative(
    ani_env* env, ani_string aniBundleName, ani_double aniBundleFlags, ani_double aniUserId)
{
    APP_LOGD("ani GetAllAppCloneBundleInfoNative called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t bundleFlags = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniBundleFlags, &bundleFlags)) {
        APP_LOGE("Cast aniBundleFlags failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_FLAGS, TYPE_NUMBER);
        return nullptr;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, use default value");
    }
    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = BundleManagerHelper::InnerGetAllAppCloneBundleInfo(bundleName, bundleFlags, userId, bundleInfos);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetAllAppCloneBundleInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_ALL_APP_CLONE_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO);
        return nullptr;
    }
    APP_LOGI("GetAllAppCloneBundleInfoNative bundleInfos size: %{public}d", bundleInfos.size());

    return CommonFunAni::ConvertAniArray(env, bundleInfos, CommonFunAni::ConvertBundleInfo, bundleFlags);
}

static ani_object GetAllSharedBundleInfoNative(ani_env* env)
{
    APP_LOGD("ani GetAllSharedBundleInfoNative called");
    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = BundleManagerHelper::InnerGetAllSharedBundleInfo(sharedBundles);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetAllSharedBundleInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_ALL_SHARED_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    return CommonFunAni::ConvertAniArray(env, sharedBundles, CommonFunAni::ConvertSharedBundleInfo);
}

static ani_object GetSharedBundleInfoNative(ani_env* env, ani_string aniBundleName, ani_string aniModuleName)
{
    APP_LOGD("ani GetSharedBundleInfoNative called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName)) {
        APP_LOGE("moduleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::MODULE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = BundleManagerHelper::InnerGetSharedBundleInfo(bundleName, moduleName, sharedBundles);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetSharedBundleInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_SHARED_BUNDLE_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    return CommonFunAni::ConvertAniArray(env, sharedBundles, CommonFunAni::ConvertSharedBundleInfo);
}

static ani_string GetAdditionalInfo(ani_env* env, ani_string aniBundleName)
{
    APP_LOGD("ani GetAdditionalInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    std::string additionalInfo;
    ErrCode ret = iBundleMgr->GetAdditionalInfo(bundleName, additionalInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetAdditionalInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), RESOURCE_NAME_OF_GET_ADDITIONAL_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    ani_string aniAdditionalInfo = nullptr;
    if (!CommonFunAni::StringToAniStr(env, additionalInfo, aniAdditionalInfo)) {
        APP_LOGE("StringToAniStr failed");
        return nullptr;
    }
    return aniAdditionalInfo;
}

static ani_string GetJsonProfileNative(ani_env* env, ani_enum_item aniProfileType, ani_string aniBundleName,
    ani_string aniModuleName, ani_double aniUserId)
{
    ProfileType profileType = ProfileType::INTENT_PROFILE;
    if (!EnumUtils::EnumETSToNative(env, aniProfileType, profileType)) {
        APP_LOGE("Parse profileType failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PROFILE_TYPE, TYPE_NUMBER);
        return nullptr;
    }
    if (g_supportedProfileList.find(profileType) == g_supportedProfileList.end()) {
        APP_LOGE("JS request profile error, type is %{public}d, profile not exist", profileType);
        BusinessErrorAni::ThrowCommonError(env, ERROR_PROFILE_NOT_EXIST, PROFILE_TYPE, TYPE_NUMBER);
        return nullptr;
    }
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_NOT_EXIST, GET_JSON_PROFILE, BUNDLE_PERMISSIONS);
        return nullptr;
    }
    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName)) {
        APP_LOGW("parse moduleName failed, try to get profile from entry module");
    } else if (moduleName.empty()) {
        APP_LOGE("moduleName is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_MODULE_NOT_EXIST, GET_JSON_PROFILE, BUNDLE_PERMISSIONS);
        return nullptr;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast aniUserId failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, TYPE_NUMBER);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::string profile;
    ErrCode ret = iBundleMgr->GetJsonProfile(profileType, bundleName, moduleName, profile, userId);
    if (ret != ERR_OK) {
        APP_LOGE("GetJsonProfile failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), GET_JSON_PROFILE, BUNDLE_PERMISSIONS);
        return nullptr;
    }
    ani_string aniProfile = nullptr;
    if (!CommonFunAni::StringToAniStr(env, profile, aniProfile)) {
        APP_LOGE("StringToAniStr failed");
        return nullptr;
    }
    return aniProfile;
}

static ani_object GetExtResourceNative(ani_env* env, ani_string aniBundleName)
{
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::vector<std::string> moduleNames;
    ErrCode ret = BundleManagerHelper::InnerGetExtResource(bundleName, moduleNames);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetExtResource failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_EXT_RESOURCE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    return CommonFunAni::ConvertAniArrayString(env, moduleNames);
}

static void DisableDynamicIconNative(ani_env* env, ani_string aniBundleName)
{
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return;
    }
    ErrCode ret = BundleManagerHelper::InnerDisableDynamicIcon(bundleName);
    if (ret != ERR_OK) {
        APP_LOGE("InnerDisableDynamicIcon failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, DISABLE_DYNAMIC_ICON, Constants::PERMISSION_ACCESS_DYNAMIC_ICON);
    }
}

static void VerifyAbcNative(ani_env* env, ani_object aniAbcPaths, ani_boolean aniDeleteOriginalFiles)
{
    std::vector<std::string> abcPaths;
    if (!CommonFunAni::ParseStrArray(env, aniAbcPaths, abcPaths)) {
        APP_LOGE("ParseStrArray failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, VERIFY_ABC, TYPE_ARRAY);
        return;
    }
    bool flag = CommonFunAni::AniBooleanToBool(aniDeleteOriginalFiles);

    ErrCode ret = BundleManagerHelper::InnerVerify(abcPaths, flag);
    if (ret != ERR_OK) {
        APP_LOGE("InnerVerify failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, VERIFY_ABC, Constants::PERMISSION_RUN_DYN_CODE);
    }
}

static void DeleteAbcNative(ani_env* env, ani_string aniAbcPath)
{
    std::string deletePath;
    if (!CommonFunAni::ParseString(env, aniAbcPath, deletePath)) {
        APP_LOGE("deletePath parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, DELETE_ABC, TYPE_STRING);
        return;
    }

    ErrCode ret = BundleManagerHelper::InnerDeleteAbc(deletePath);
    if (ret != ERR_OK) {
        APP_LOGE("InnerDeleteAbc failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, ret, DELETE_ABC, Constants::PERMISSION_RUN_DYN_CODE);
    }
}

static ani_object GetRecoverableApplicationInfoNative(ani_env* env)
{
    std::vector<RecoverableApplicationInfo> recoverableApplicationInfos;
    ErrCode ret = BundleManagerHelper::InnerGetRecoverableApplicationInfo(recoverableApplicationInfos);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetRecoverableApplicationInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_RECOVERABLE_APPLICATION_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    return CommonFunAni::ConvertAniArray(
        env, recoverableApplicationInfos, CommonFunAni::ConvertRecoverableApplicationInfo);
}

static void SetAdditionalInfo(ani_env* env, ani_string aniBundleName, ani_string aniAdditionalInfo)
{
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, Constants::BUNDLE_NAME, TYPE_STRING);
        return;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
        return;
    }
    std::string additionalInfo;
    if (!CommonFunAni::ParseString(env, aniAdditionalInfo, additionalInfo)) {
        APP_LOGE("additionalInfo parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, ADDITIONAL_INFO, TYPE_STRING);
        return;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return;
    }
    ErrCode ret = iBundleMgr->SetAdditionalInfo(bundleName, additionalInfo);
    if (ret != ERR_OK) {
        APP_LOGE("SetAdditionalInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), RESOURCE_NAME_OF_SET_ADDITIONAL_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
}

static ani_object GetDeveloperIdsNative(ani_env* env, ani_double aniAppDistributionType)
{
    int32_t appDistributionTypeEnum = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniAppDistributionType, &appDistributionTypeEnum)) {
        APP_LOGE("Cast aniAppDistributionType failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_DISTRIBUTION_TYPE, TYPE_NUMBER);
        return nullptr;
    }
    if (appDistributionTypeMap.find(appDistributionTypeEnum) == appDistributionTypeMap.end()) {
        APP_LOGE("request error, type %{public}d is invalid", appDistributionTypeEnum);
        BusinessErrorAni::ThrowEnumError(env, APP_DISTRIBUTION_TYPE, APP_DISTRIBUTION_TYPE_ENUM);
        return nullptr;
    }
    std::string distributionType = std::string { appDistributionTypeMap[appDistributionTypeEnum] };
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return nullptr;
    }
    std::vector<std::string> developerIds;
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode ret = iBundleMgr->GetDeveloperIds(distributionType, developerIds, userId);
    if (ret != ERR_OK) {
        APP_LOGE(
            "GetDeveloperIds failed ret: %{public}d, appDistributionType is %{public}s", ret, distributionType.c_str());
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret), GET_DEVELOPER_IDS, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    return CommonFunAni::ConvertAniArrayString(env, developerIds);
}

static ani_object GetAllPluginInfoNative(ani_env* env, ani_string aniHostBundleName, ani_double aniUserId)
{
    std::string hostBundleName;
    if (!CommonFunAni::ParseString(env, aniHostBundleName, hostBundleName)) {
        APP_LOGE("Plugin bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, HOST_BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("Parse userId failed, set this parameter to the caller userId");
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }
    std::vector<PluginBundleInfo> pluginBundleInfos;
    ErrCode ret = BundleManagerHelper::InnerGetAllPluginInfo(hostBundleName, userId, pluginBundleInfos);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetAllPluginInfo failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, ret, GET_ALL_PLUGIN_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    return CommonFunAni::ConvertAniArray(env, pluginBundleInfos, CommonFunAni::ConvertPluginBundleInfo);
}

static void MigrateDataNative(ani_env* env, ani_object aniSourcePaths, ani_string aniDestinationPath)
{
    std::vector<std::string> sourcePaths;
    if (!CommonFunAni::ParseStrArray(env, aniSourcePaths, sourcePaths)) {
        APP_LOGE("ParseStrArray failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, SOURCE_PATHS, TYPE_ARRAY);
        return;
    }
    std::string destinationPath;
    if (!CommonFunAni::ParseString(env, aniDestinationPath, destinationPath)) {
        APP_LOGE("DestinationPath is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, DESTINATION_PATHS, TYPE_STRING);
        return;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr failed");
        BusinessErrorAni::ThrowError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, ERR_MSG_BUNDLE_SERVICE_EXCEPTION);
        return;
    }

    ErrCode ret = iBundleMgr->MigrateData(sourcePaths, destinationPath);
    if (ret != ERR_OK) {
        APP_LOGE("MigrateData failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env,
            CommonFunc::ConvertErrCode(ret), MIGRATE_DATA, Constants::PERMISSION_MIGRATE_DATA);
    }
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
        ani_native_function { "isApplicationEnabledNative", nullptr,
            reinterpret_cast<void*>(IsApplicationEnabledNative) },
        ani_native_function { "getBundleInfoForSelfNative", nullptr,
            reinterpret_cast<void*>(GetBundleInfoForSelfNative) },
        ani_native_function { "getBundleInfoNative", nullptr, reinterpret_cast<void*>(GetBundleInfoNative) },
        ani_native_function { "getApplicationInfoNative", nullptr, reinterpret_cast<void*>(GetApplicationInfoNative) },
        ani_native_function { "getAllBundleInfoNative", nullptr, reinterpret_cast<void*>(GetAllBundleInfoNative) },
        ani_native_function { "getAllApplicationInfoNative", nullptr,
            reinterpret_cast<void*>(GetAllApplicationInfoNative) },
        ani_native_function { "queryAbilityInfoSyncNative", nullptr,
            reinterpret_cast<void*>(QueryAbilityInfoSyncNative) },
        ani_native_function { "getAppCloneIdentityNative", nullptr,
            reinterpret_cast<void*>(GetAppCloneIdentityNative) },
        ani_native_function { "getAbilityLabelNative", nullptr, reinterpret_cast<void*>(GetAbilityLabelNative) },
        ani_native_function { "getLaunchWantForBundleNative", nullptr,
            reinterpret_cast<void*>(GetLaunchWantForBundleNative) },
        ani_native_function { "getAppCloneBundleInfoNative", nullptr,
            reinterpret_cast<void*>(GetAppCloneBundleInfoNative) },
        ani_native_function { "getSpecifiedDistributionType", nullptr,
            reinterpret_cast<void*>(GetSpecifiedDistributionType) },
        ani_native_function { "getBundleNameByUidNative", nullptr, reinterpret_cast<void*>(GetBundleNameByUidNative) },
        ani_native_function { "queryExtensionAbilityInfoNative", nullptr,
            reinterpret_cast<void*>(QueryExtensionAbilityInfoNative) },
        ani_native_function { "queryExAbilityInfoSyncWithoutWantNative", nullptr,
            reinterpret_cast<void*>(QueryExAbilityInfoSyncWithoutWant) },
        ani_native_function { "isAbilityEnabledNative", nullptr,
            reinterpret_cast<void*>(IsAbilityEnabledNative) },
        ani_native_function { "setAbilityEnabledNative", nullptr,
            reinterpret_cast<void*>(SetAbilityEnabledNative) },
        ani_native_function { "setApplicationEnabledNative", nullptr,
            reinterpret_cast<void*>(SetApplicationEnabledNative) },
        ani_native_function { "getDynamicIconNative", nullptr, reinterpret_cast<void*>(GetDynamicIconNative) },
        ani_native_function { "queryAbilityInfoWithWantsNative", nullptr,
            reinterpret_cast<void*>(QueryAbilityInfoWithWantsNative) },
        ani_native_function { "enableDynamicIconNative", nullptr, reinterpret_cast<void*>(EnableDynamicIconNative) },
        ani_native_function { "getBundleArchiveInfoNative", nullptr,
            reinterpret_cast<void*>(GetBundleArchiveInfoNative) },
        ani_native_function { "getLaunchWant", nullptr, reinterpret_cast<void*>(GetLaunchWant) },
        ani_native_function { "getProfileByAbilityNative", nullptr,
            reinterpret_cast<void*>(GetProfileByAbilityNative) },
        ani_native_function { "getPermissionDefNative", nullptr, reinterpret_cast<void*>(GetPermissionDefNative) },
        ani_native_function { "cleanBundleCacheFilesNative", nullptr,
            reinterpret_cast<void*>(CleanBundleCacheFilesNative) },
        ani_native_function { "getAllBundleCacheSizeNative", nullptr,
            reinterpret_cast<void*>(GetAllBundleCacheSizeNative) },
        ani_native_function { "cleanAllBundleCacheNative", nullptr,
            reinterpret_cast<void*>(CleanAllBundleCacheNative) },
        ani_native_function { "getAppProvisionInfoNative", nullptr,
            reinterpret_cast<void*>(GetAppProvisionInfoNative) },
        ani_native_function { "canOpenLink", nullptr, reinterpret_cast<void*>(CanOpenLink) },
        ani_native_function { "getAllPreinstalledApplicationInfoNative", nullptr,
            reinterpret_cast<void*>(GetAllPreinstalledApplicationInfoNative) },
        ani_native_function { "getAllBundleInfoByDeveloperId", nullptr,
            reinterpret_cast<void*>(GetAllBundleInfoByDeveloperId) },
        ani_native_function { "switchUninstallState", nullptr, reinterpret_cast<void*>(SwitchUninstallState) },
        ani_native_function { "getSignatureInfo", nullptr, reinterpret_cast<void*>(GetSignatureInfo) },
        ani_native_function { "getAllAppCloneBundleInfoNative", nullptr,
            reinterpret_cast<void*>(GetAllAppCloneBundleInfoNative) },
        ani_native_function { "getAllSharedBundleInfoNative", nullptr,
            reinterpret_cast<void*>(GetAllSharedBundleInfoNative) },
        ani_native_function { "getSharedBundleInfoNative", nullptr,
            reinterpret_cast<void*>(GetSharedBundleInfoNative) },
        ani_native_function { "getAdditionalInfo", nullptr, reinterpret_cast<void*>(GetAdditionalInfo) },
        ani_native_function { "getJsonProfileNative", nullptr, reinterpret_cast<void*>(GetJsonProfileNative) },
        ani_native_function { "getExtResourceNative", nullptr, reinterpret_cast<void*>(GetExtResourceNative) },
        ani_native_function { "disableDynamicIconNative", nullptr, reinterpret_cast<void*>(DisableDynamicIconNative) },
        ani_native_function { "verifyAbcNative", nullptr, reinterpret_cast<void*>(VerifyAbcNative) },
        ani_native_function { "deleteAbcNative", nullptr, reinterpret_cast<void*>(DeleteAbcNative) },
        ani_native_function { "getRecoverableApplicationInfoNative", nullptr,
            reinterpret_cast<void*>(GetRecoverableApplicationInfoNative) },
        ani_native_function { "setAdditionalInfo", nullptr, reinterpret_cast<void*>(SetAdditionalInfo) },
        ani_native_function { "getDeveloperIdsNative", nullptr, reinterpret_cast<void*>(GetDeveloperIdsNative) },
        ani_native_function { "getAllPluginInfoNative", nullptr, reinterpret_cast<void*>(GetAllPluginInfoNative) },
        ani_native_function { "migrateDataNative", nullptr, reinterpret_cast<void*>(MigrateDataNative) },
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
