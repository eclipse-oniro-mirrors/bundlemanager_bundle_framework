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

#include "bundle_stats/bundle_stats_cache_rdb.h"

#include <nlohmann/json.hpp>
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* STATS_RDB_TABLE_NAME = "bundle_stats_cache";
constexpr const char* BUNDLE_NAME_COL = "BUNDLE_NAME";
constexpr const char* USER_ID_COL = "USER_ID";
constexpr const char* APP_INDEX_COL = "APP_INDEX";
constexpr const char* VALUE_COL = "VALUE";
const int8_t BUNDLE_NAME_INDEX = 0;
const int8_t USER_ID_INDEX = 1;
const int8_t APP_INDEX_INDEX = 2;
const int8_t VALUE_INDEX = 3;
// sanity cap for the persisted stats vector: the interface has 5 dims, allow
// one spare for forward compatibility, reject anything larger
constexpr size_t BUNDLE_STATS_MAX_SIZE = 6;
} // namespace

std::string BundleStatsCacheData::ToJson() const
{
    nlohmann::json obj;
    obj["uid"] = uid;
    obj["bundleStats"] = bundleStats;
    obj["inodeCount"] = inodeCount;
    obj["scanTime"] = scanTime;
    return obj.dump();
}

bool BundleStatsCacheData::FromJson(const std::string &json, BundleStatsCacheData &data)
{
    if (json.empty()) {
        return false;
    }
    nlohmann::json obj = nlohmann::json::parse(json, nullptr, false);
    if (obj.is_discarded()) {
        APP_LOGE_NOFUNC("BundleStatsCacheData FromJson parse failed");
        return false;
    }
    // is_number_integer only: float/unsigned values would silently truncate
    // through get<int>, corrupting the cache with wrong dims
    if (obj.contains("uid") && obj["uid"].is_number_integer()) {
        data.uid = obj["uid"].get<int32_t>();
    }
    if (obj.contains("bundleStats") && obj["bundleStats"].is_array()
        && obj["bundleStats"].size() <= BUNDLE_STATS_MAX_SIZE) {
        data.bundleStats.clear();
        for (const auto &item : obj["bundleStats"]) {
            if (item.is_number_integer()) {
                data.bundleStats.push_back(item.get<int64_t>());
            }
        }
    }
    if (obj.contains("inodeCount") && obj["inodeCount"].is_number_integer()) {
        data.inodeCount = obj["inodeCount"].get<int64_t>();
    }
    if (obj.contains("scanTime") && obj["scanTime"].is_number_integer()) {
        data.scanTime = obj["scanTime"].get<int64_t>();
    }
    return true;
}

BundleStatsCacheRdb::BundleStatsCacheRdb()
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = STATS_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string(STATS_RDB_TABLE_NAME)
        + "(BUNDLE_NAME TEXT NOT NULL, USER_ID INTEGER, APP_INDEX INTEGER, VALUE TEXT NOT NULL, "
        + "PRIMARY KEY (BUNDLE_NAME, USER_ID, APP_INDEX));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

bool BundleStatsCacheRdb::GetCacheData(const std::string &bundleName, int32_t userId,
    int32_t appIndex, BundleStatsCacheData &data)
{
    if (bundleName.empty() || userId < 0) {
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(STATS_RDB_TABLE_NAME);
    predicates.EqualTo(BUNDLE_NAME_COL, bundleName);
    predicates.EqualTo(USER_ID_COL, userId);
    predicates.EqualTo(APP_INDEX_COL, appIndex);
    auto resultSet = rdbDataManager_->QueryData(predicates);
    if (resultSet == nullptr) {
        return false;
    }
    int32_t count = 0;
    if (resultSet->GetRowCount(count) != NativeRdb::E_OK || count == 0) {
        resultSet->Close();
        return false;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return false;
    }
    std::string value;
    if (resultSet->GetString(VALUE_INDEX, value) != NativeRdb::E_OK || value.empty()) {
        resultSet->Close();
        return false;
    }
    resultSet->Close();
    return BundleStatsCacheData::FromJson(value, data);
}

bool BundleStatsCacheRdb::UpsertCache(const std::string &bundleName, int32_t userId,
    int32_t appIndex, const BundleStatsCacheData &data)
{
    if (bundleName.empty() || userId < 0) {
        return false;
    }
    NativeRdb::ValuesBucket bucket;
    bucket.PutString(BUNDLE_NAME_COL, bundleName);
    bucket.PutInt(USER_ID_COL, userId);
    bucket.PutInt(APP_INDEX_COL, appIndex);
    bucket.PutString(VALUE_COL, data.ToJson());
    NativeRdb::AbsRdbPredicates predicates(STATS_RDB_TABLE_NAME);
    predicates.EqualTo(BUNDLE_NAME_COL, bundleName);
    predicates.EqualTo(USER_ID_COL, userId);
    predicates.EqualTo(APP_INDEX_COL, appIndex);
    if (!rdbDataManager_->UpdateOrInsertData(bucket, predicates)) {
        APP_LOGE_NOFUNC("BundleStatsCacheRdb UpsertCache failed -n:%{public}s -u:%{public}d -i:%{public}d",
            bundleName.c_str(), userId, appIndex);
        return false;
    }
    return true;
}

bool BundleStatsCacheRdb::DeleteBundle(const std::string &bundleName)
{
    if (bundleName.empty()) {
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(STATS_RDB_TABLE_NAME);
    predicates.EqualTo(BUNDLE_NAME_COL, bundleName);
    return rdbDataManager_->DeleteData(predicates);
}

bool BundleStatsCacheRdb::DeleteUser(int32_t userId)
{
    if (userId < 0) {
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(STATS_RDB_TABLE_NAME);
    predicates.EqualTo(USER_ID_COL, userId);
    return rdbDataManager_->DeleteData(predicates);
}

bool BundleStatsCacheRdb::DeleteAll()
{
    // Empty predicates deletes all rows in the table.
    NativeRdb::AbsRdbPredicates predicates(STATS_RDB_TABLE_NAME);
    return rdbDataManager_->DeleteData(predicates);
}
} // namespace AppExecFwk
} // namespace OHOS
