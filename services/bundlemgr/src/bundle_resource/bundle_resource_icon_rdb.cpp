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

#include "bundle_resource_icon_rdb.h"

#include "app_log_wrapper.h"
#include "bundle_resource_constants.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "hitrace_meter.h"
#include "scope_guard.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t INDEX_NAME = 0;
constexpr int32_t INDEX_USERID = 1;
constexpr int32_t INDEX_ICON_TYPE = 2;
constexpr int32_t INDEX_ICON = 3;
constexpr int32_t INDEX_FOREGROUND = 4;
constexpr int32_t INDEX_BACKGROUND = 5;
}

BundleResourceIconRdb::BundleResourceIconRdb()
{
    APP_LOGI_NOFUNC("BundleResourceIconRdb create");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = BundleResourceConstants::BUNDLE_RESOURCE_RDB_NAME;
    bmsRdbConfig.dbPath = BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH;
    bmsRdbConfig.tableName = BundleResourceConstants::BUNDLE_ICON_RESOURCE_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string(BundleResourceConstants::BUNDLE_ICON_RESOURCE_RDB_TABLE_NAME)
        + "(NAME TEXT NOT NULL, USER_ID INTEGER, ICON_TYPE INTEGER, ICON TEXT, "
        + "FOREGROUND BLOB, BACKGROUND BLOB, PRIMARY KEY (NAME, USER_ID, ICON_TYPE));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

BundleResourceIconRdb::~BundleResourceIconRdb()
{
}

bool BundleResourceIconRdb::AddResourceIconInfo(const int32_t userId, const IconResourceType type,
    const ResourceInfo &resourceInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (resourceInfo.bundleName_.empty()) {
        APP_LOGE("failed, bundleName is empty");
        return false;
    }
    APP_LOGD("insert resource key:%{public}s", resourceInfo.GetKey().c_str());
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BundleResourceConstants::NAME, resourceInfo.GetKey());
    valuesBucket.PutInt(BundleResourceConstants::USER_ID, userId);
    valuesBucket.PutInt(BundleResourceConstants::ICON_TYPE, static_cast<int32_t>(type));
    valuesBucket.PutString(BundleResourceConstants::ICON, resourceInfo.icon_);
    // used for layered icons
    valuesBucket.PutBlob(BundleResourceConstants::FOREGROUND, resourceInfo.foreground_);
    valuesBucket.PutBlob(BundleResourceConstants::BACKGROUND, resourceInfo.background_);
    APP_LOGD("key:%{public}s foreground: %{public}zu, background: %{public}zu", resourceInfo.GetKey().c_str(),
        resourceInfo.foreground_.size(), resourceInfo.background_.size());

    return rdbDataManager_->InsertData(valuesBucket);
}

bool BundleResourceIconRdb::AddResourceIconInfos(const int32_t userId, const IconResourceType type,
    const std::vector<ResourceInfo> &resourceInfos)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (resourceInfos.empty()) {
        APP_LOGE("failed, resourceInfos is empty");
        return false;
    }
    if (resourceInfos.size() == 1) {
        return AddResourceIconInfo(userId, type, resourceInfos[0]);
    }
    bool ret = true;
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (const auto &info : resourceInfos) {
        if (info.bundleName_.empty()) {
            APP_LOGE("failed, bundleName is empty");
            ret = false;
            continue;
        }
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(BundleResourceConstants::NAME, info.GetKey());
        valuesBucket.PutInt(BundleResourceConstants::USER_ID, userId);
        valuesBucket.PutInt(BundleResourceConstants::ICON_TYPE, static_cast<int32_t>(type));
        valuesBucket.PutString(BundleResourceConstants::ICON, info.icon_);
        // used for layered icons
        valuesBucket.PutBlob(BundleResourceConstants::FOREGROUND, info.foreground_);
        valuesBucket.PutBlob(BundleResourceConstants::BACKGROUND, info.background_);
        APP_LOGD("key:%{public}s foreground: %{public}zu, background: %{public}zu", info.GetKey().c_str(),
            info.foreground_.size(), info.background_.size());
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    bool insertRet = rdbDataManager_->BatchInsert(insertNum, valuesBuckets);
    if (!insertRet) {
        APP_LOGE("BatchInsert failed");
        return false;
    }
    if (valuesBuckets.size() != static_cast<uint64_t>(insertNum)) {
        APP_LOGE("BatchInsert size not expected");
        return false;
    }
    return ret;
}

bool BundleResourceIconRdb::DeleteResourceIconInfo(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex, const IconResourceType type)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (bundleName.empty()) {
        APP_LOGE("failed, bundleName is empty");
        return false;
    }
    APP_LOGD("need delete resource info, -n %{public}s, -u %{public}d, -i %{public}d, -t %{public}d",
        bundleName.c_str(), userId, appIndex, static_cast<int32_t>(type));
    std::string key = bundleName;
    if (appIndex > 0) {
        key = std::to_string(appIndex) + BundleResourceConstants::UNDER_LINE + bundleName;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_ICON_RESOURCE_RDB_TABLE_NAME);
    /**
     * key:
     * appIndex_bundleName
     * appIndex_bundleName/moduleName/abilityName
     */
    absRdbPredicates.BeginWrap();
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, key);
    absRdbPredicates.Or();
    absRdbPredicates.BeginsWith(BundleResourceConstants::NAME, key + BundleResourceConstants::SEPARATOR);
    absRdbPredicates.EndWrap();

    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    if (type != IconResourceType::UNKNOWN) {
        absRdbPredicates.EqualTo(BundleResourceConstants::ICON_TYPE, static_cast<int32_t>(type));
    }
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGW("delete key:%{public}s failed", key.c_str());
        return false;
    }
    return true;
}

bool BundleResourceIconRdb::DeleteResourceIconInfos(const std::string &bundleName,
    const int32_t userId, const IconResourceType type)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (bundleName.empty()) {
        APP_LOGE("failed, bundleName is empty");
        return false;
    }
    APP_LOGD("need delete resource info, -n %{public}s, -u %{public}d, -t %{public}d",
        bundleName.c_str(), userId, static_cast<int32_t>(type));
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_ICON_RESOURCE_RDB_TABLE_NAME);
    /**
     * key:
     * bundleName
     * bundleName/moduleName/abilityName
     * appIndex_bundleName
     * appIndex_bundleName/moduleName/abilityName
     */
    absRdbPredicates.BeginWrap();
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, bundleName);
    absRdbPredicates.Or();
    absRdbPredicates.BeginsWith(BundleResourceConstants::NAME, key + BundleResourceConstants::SEPARATOR);
    for (int32_t index = BundleServiceConstants::CLONE_APP_INDEX_MIN;
        index <= BundleServiceConstants::CLONE_APP_INDEX_MAX; ++index) {
        absRdbPredicates.Or();
        absRdbPredicates.EqualTo(BundleResourceConstants::NAME, std::to_string(index) +
            BundleResourceConstants::UNDER_LINE + bundleName);
        absRdbPredicates.Or();
        absRdbPredicates.BeginsWith(BundleResourceConstants::NAME, std::to_string(index) +
            BundleResourceConstants::UNDER_LINE + bundleName + BundleResourceConstants::SEPARATOR);
    }
    absRdbPredicates.EndWrap();

    if (userId != Constants::UNSPECIFIED_USERID) {
        absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    }
    if (type != IconResourceType::UNKNOWN) {
        absRdbPredicates.EqualTo(BundleResourceConstants::ICON_TYPE, static_cast<int32_t>(type));
    }
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGW("delete bundleName:%{public}s failed", bundleName.c_str());
        return false;
    }
    return true;
}

bool BundleResourceIconRdb::DeleteResourceIconInfos(const std::string &bundleName, const IconResourceType type)
{
    return DeleteResourceIconInfos(bundleName, Constants::UNSPECIFIED_USERID, type);
}

bool BundleResourceIconRdb::GetAllResourceIconName(const int32_t userId, std::set<std::string> &resourceNames,
    const IconResourceType type)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_ICON_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    if (type != IconResourceType::UNKNOWN) {
        absRdbPredicates.EqualTo(BundleResourceConstants::ICON_TYPE, static_cast<int32_t>(type));
    }
    auto absSharedResultSet = rdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("QueryByStep failed");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });

    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret %{public}d", ret);
        return false;
    }
    do {
        std::string name;
        std::string resourceName;
        ret = absSharedResultSet->GetString(BundleResourceConstants::INDEX_NAME, name);
        if (ret != NativeRdb::E_OK) {
            APP_LOGE("GetString name failed, ret %{public}d", ret);
            return false;
        }
        ParseNameToResourceName(name, resourceName);
        resourceNames.insert(resourceName);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    APP_LOGI_NOFUNC("end");
    return true;
}

void BundleResourceIconRdb::ParseNameToResourceName(const std::string &name, std::string &resourceName)
{
    resourceName = name;
    // clone bundle no need to add
    auto pos = name.find_first_of(BundleResourceConstants::UNDER_LINE);
    if (pos != std::string::npos) {
        int32_t appIndex = 0;
        if (!OHOS::StrToInt(name.substr(0, pos), appIndex)) {
            return;
        }
        resourceName = name.substr(pos + 1);
    }
}

bool BundleResourceIconRdb::GetResourceIconInfos(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex, const uint32_t resourceFlag,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos,
    const IconResourceType type)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    APP_LOGI_NOFUNC("icon rdb get resource icon start -n %{public}s -i %{public}d", bundleName.c_str(), appIndex);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = bundleName;
    resourceInfo.appIndex_ = appIndex;
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_ICON_RESOURCE_RDB_TABLE_NAME);
    // bundleName or bundleName/moduleName/abilityName
    absRdbPredicates.BeginWrap();
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, resourceInfo.GetKey());
    absRdbPredicates.Or();
    absRdbPredicates.BeginsWith(BundleResourceConstants::NAME, resourceInfo.GetKey() +
        BundleResourceConstants::SEPARATOR);
    absRdbPredicates.EndWrap();

    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    if (type != IconResourceType::UNKNOWN) {
        absRdbPredicates.EqualTo(BundleResourceConstants::ICON_TYPE, static_cast<int32_t>(type));
    }

    auto absSharedResultSet = rdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("QueryByStep failed bundleName %{public}s failed", bundleName.c_str());
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGD("bundleName %{public}s GoToFirstRow failed, ret %{public}d", bundleName.c_str(), ret);
        return false;
    }

    do {
        LauncherAbilityResourceInfo resourceInfo;
        IconResourceType type;
        if (ConvertToLauncherAbilityResourceInfo(absSharedResultSet, resourceFlag, resourceInfo, type)) {
            InnerProcessResourceIconInfos(resourceInfo, type, userId, launcherAbilityResourceInfos);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    APP_LOGI_NOFUNC("icon rdb get resource icon end -n %{public}s -i %{public}d", bundleName.c_str(), appIndex);
    return !launcherAbilityResourceInfos.empty();
}

bool BundleResourceIconRdb::GetAllResourceIconInfo(const int32_t userId, const uint32_t resourceFlag,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    APP_LOGI("start get all launcher resource");
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_ICON_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    auto absSharedResultSet = rdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet nullptr");
        return false;
    }

    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret %{public}d", ret);
        return false;
    }

    do {
        LauncherAbilityResourceInfo resourceInfo;
        IconResourceType type;
        if (ConvertToLauncherAbilityResourceInfo(absSharedResultSet, resourceFlag, resourceInfo, type)) {
            InnerProcessResourceIconInfos(resourceInfo, type, userId, launcherAbilityResourceInfos);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    APP_LOGI_NOFUNC("end get all launcher resource");
    return !launcherAbilityResourceInfos.empty();
}

bool BundleResourceIconRdb::ConvertToLauncherAbilityResourceInfo(
    const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet,
    const uint32_t resourceFlag,
    LauncherAbilityResourceInfo &launcherAbilityResourceInfo,
    IconResourceType &iconType)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is nullptr");
        return false;
    }
    std::string key;
    auto ret = absSharedResultSet->GetString(INDEX_NAME, key);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString name failed, ret: %{public}d");
    ParseKey(key, launcherAbilityResourceInfo);

    bool getIcon = ((resourceFlag & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ||
        ((resourceFlag & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL));
    if (getIcon) {
        ret = absSharedResultSet->GetString(INDEX_ICON, launcherAbilityResourceInfo.icon);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString label icon, ret: %{public}d");
    }

    bool getDrawable = (resourceFlag & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR))
        == static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
    if (getDrawable) {
        ret = absSharedResultSet->GetBlob(INDEX_FOREGROUND, launcherAbilityResourceInfo.foreground);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetBlob foreground, ret: %{public}d");

        ret = absSharedResultSet->GetBlob(INDEX_BACKGROUND, launcherAbilityResourceInfo.background);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetBlob background, ret: %{public}d");
    }
    int32_t type = 0;
    ret = absSharedResultSet->GetInt(INDEX_ICON_TYPE, type);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetInt iconType, ret: %{public}d");
    iconType = static_cast<IconResourceType>(type);

    return true;
}

void BundleResourceIconRdb::ParseKey(const std::string &key,
    LauncherAbilityResourceInfo &launcherAbilityResourceInfo)
{
    ResourceInfo info;
    info.ParseKey(key);
    launcherAbilityResourceInfo.bundleName = info.bundleName_;
    launcherAbilityResourceInfo.moduleName = info.moduleName_;
    launcherAbilityResourceInfo.abilityName = info.abilityName_;
    launcherAbilityResourceInfo.appIndex = info.appIndex_;
}

bool BundleResourceIconRdb::GetIsOnlineTheme(const int32_t userId)
{
    std::shared_lock<ffrt::shared_mutex> lock(isOnlineThemeMutex_);
    auto iter = isOnlineThemeMap_.find(userId);
    if (iter == isOnlineThemeMap_.end()) {
        return false;
    }
    return iter->second;
}

void BundleResourceIconRdb::SetIsOnlineTheme(const int32_t userId, bool isOnlineTheme)
{
    std::unique_lock<ffrt::shared_mutex> lock(isOnlineThemeMutex_);
    isOnlineThemeMap_[userId] = isOnlineTheme;
}

void BundleResourceIconRdb::InnerProcessResourceIconInfos(const LauncherAbilityResourceInfo &resourceInfo,
    const IconResourceType type, const int32_t userId,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    if (!resourceInfo.abilityName.empty() && GetIsOnlineTheme(userId)) {
        launcherAbilityResourceInfos.push_back(resourceInfo);
        return;
    }
    auto iter = std::find_if(launcherAbilityResourceInfos.begin(), launcherAbilityResourceInfos.end(),
        [resourceInfo](const LauncherAbilityResourceInfo info) {
            return (resourceInfo.bundleName == info.bundleName) && (resourceInfo.appIndex == info.appIndex);
        });
    // not exist
    if (iter == launcherAbilityResourceInfos.end()) {
        launcherAbilityResourceInfos.push_back(resourceInfo);
        return;
    }
    // if exist, need to process theme or dynamic icon
    if (((type == IconResourceType::THEME_ICON) && GetIsOnlineTheme(userId)) ||
        ((type == IconResourceType::DYNAMIC_ICON) && !GetIsOnlineTheme(userId))) {
        for (auto iter = launcherAbilityResourceInfos.begin(); iter != launcherAbilityResourceInfos.end();) {
            if ((iter->bundleName == resourceInfo.bundleName) && (iter->appIndex == resourceInfo.appIndex)) {
                iter = launcherAbilityResourceInfos.erase(iter);
            } else {
                ++iter;
            }
        }
        launcherAbilityResourceInfos.push_back(resourceInfo);
    }
}
} // AppExecFwk
} // OHOS
