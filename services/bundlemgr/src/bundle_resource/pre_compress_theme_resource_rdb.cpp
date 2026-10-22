/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "pre_compress_theme_resource_rdb.h"

#include "app_log_wrapper.h"
#include "bundle_resource_constants.h"
#include "bundle_service_constants.h"
#include "hitrace_meter.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t INDEX_NAME = 0;
constexpr int32_t INDEX_ICON = 2;
constexpr int32_t INDEX_FOREGROUND = 3;
constexpr int32_t INDEX_BACKGROUND = 4;
}

PreCompressThemeResourceRdb::PreCompressThemeResourceRdb()
{
    APP_LOGI_NOFUNC("PreCompressThemeResourceRdb create");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.dbPath = ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH;
    bmsRdbConfig.tableName = BundleResourceConstants::PRE_COMPRESS_THEME_RESOURCE_RDB;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string(BundleResourceConstants::PRE_COMPRESS_THEME_RESOURCE_RDB)
        + "(NAME TEXT NOT NULL, USER_ID INTEGER, ICON TEXT, "
        + "FOREGROUND BLOB, BACKGROUND BLOB, PRIMARY KEY (NAME, USER_ID));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

bool PreCompressThemeResourceRdb::AddPreCompressThemeResource(const int32_t userId,
    const ResourceInfo &resourceInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BundleResourceConstants::NAME, resourceInfo.bundleName_);
    valuesBucket.PutInt(BundleResourceConstants::USER_ID, userId);
    valuesBucket.PutString(BundleResourceConstants::ICON, resourceInfo.icon_);
    valuesBucket.PutBlob(BundleResourceConstants::FOREGROUND, resourceInfo.foreground_);
    valuesBucket.PutBlob(BundleResourceConstants::BACKGROUND, resourceInfo.background_);
    if (!rdbDataManager_->InsertData(valuesBucket)) {
        APP_LOGE_NOFUNC("-n %{public}s -u %{public}d add theme resource failed",
            resourceInfo.bundleName_.c_str(), userId);
        return false;
    }
    return true;
}

bool PreCompressThemeResourceRdb::DeletePreCompressThemeResource(const std::string &bundleName,
    const int32_t userId)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::PRE_COMPRESS_THEME_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, bundleName);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGW("delete -n %{public}s -u %{public}d failed", bundleName.c_str(), userId);
        return false;
    }
    return true;
}

bool PreCompressThemeResourceRdb::DeletePreCompressThemeResource(const std::string &bundleName)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::PRE_COMPRESS_THEME_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, bundleName);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGW("delete -n %{public}s failed", bundleName.c_str());
        return false;
    }
    return true;
}

bool PreCompressThemeResourceRdb::DeletePreCompressThemeResourceForUser(const int32_t userId)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::PRE_COMPRESS_THEME_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGW("delete -u %{public}d failed", userId);
        return false;
    }
    return true;
}

bool PreCompressThemeResourceRdb::GetPreCompressThemeResources(const int32_t userId,
    const std::vector<std::string> &bundleNames, const uint32_t flags,
    std::map<std::string, BundleResourceInfo> &themeResourceInfos)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (bundleNames.empty()) {
        return true;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::PRE_COMPRESS_THEME_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    absRdbPredicates.In(BundleResourceConstants::NAME, bundleNames);
    auto absSharedResultSet = rdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE_NOFUNC("QueryByStep failed -u %{public}d", userId);
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_ROW_OUT_RANGE) {
        APP_LOGD("-u %{public}d no theme resource", userId);
        return true;
    }
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GoToFirstRow failed, ret %{public}d");
    do {
        std::string bundleName;
        BundleResourceInfo themeResourceInfo;
        if ((absSharedResultSet->GetString(INDEX_NAME, bundleName) == NativeRdb::E_OK) &&
            ConvertToBundleResourceInfo(absSharedResultSet, flags, themeResourceInfo)) {
            themeResourceInfos[bundleName] = std::move(themeResourceInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return true;
}

bool PreCompressThemeResourceRdb::ConvertToBundleResourceInfo(
    const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet, const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo)
{
    bool getIcon = ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ||
        ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL));
    if (getIcon) {
        auto ret = absSharedResultSet->GetString(INDEX_ICON, bundleResourceInfo.icon);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString icon failed, ret: %{public}d");
    }
    bool getDrawable = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
    if (getDrawable) {
        auto ret = absSharedResultSet->GetBlob(INDEX_FOREGROUND, bundleResourceInfo.foreground);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetBlob foreground, ret: %{public}d");
        ret = absSharedResultSet->GetBlob(INDEX_BACKGROUND, bundleResourceInfo.background);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetBlob background, ret: %{public}d");
    }
    return true;
}
} // AppExecFwk
} // OHOS
