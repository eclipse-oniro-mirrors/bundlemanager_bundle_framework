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

#include "app_clone_preference_storage.h"

#include "app_log_wrapper.h"
#include "bundle_service_constants.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string APP_CLONE_PREFERENCE_TABLE_NAME = "app_clone_preference";
const std::string BUNDLE_NAME_COLUMN = "BUNDLE_NAME";
const std::string USER_ID_COLUMN = "USER_ID";
const std::string PREFERENCE_TYPE_COLUMN = "PREFERENCE_TYPE";
const std::string APP_INDEX_COLUMN = "APP_INDEX";

const std::string CREATE_TABLE_SQL = std::string("CREATE TABLE IF NOT EXISTS ")
    + APP_CLONE_PREFERENCE_TABLE_NAME
    + "(BUNDLE_NAME TEXT NOT NULL, "
    + "USER_ID INTEGER NOT NULL, "
    + "PREFERENCE_TYPE INTEGER NOT NULL, "
    + "APP_INDEX INTEGER DEFAULT 0, "
    + "PRIMARY KEY (BUNDLE_NAME, USER_ID));";
}  // namespace

AppClonePreferenceStorage::AppClonePreferenceStorage()
{
    APP_LOGD("create AppClonePreferenceStorage");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = APP_CLONE_PREFERENCE_TABLE_NAME;
    bmsRdbConfig.createTableSql = CREATE_TABLE_SQL;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

bool AppClonePreferenceStorage::InsertOrReplace(const std::string &bundleName, int32_t userId,
    const AppClonePreference &preference)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE_NOFUNC("InsertOrReplace rdbDataManager is null");
        return false;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BUNDLE_NAME_COLUMN, bundleName);
    valuesBucket.PutInt(USER_ID_COLUMN, userId);
    valuesBucket.PutInt(PREFERENCE_TYPE_COLUMN, static_cast<int32_t>(preference.mode));
    valuesBucket.PutInt(APP_INDEX_COLUMN, preference.appIndex);

    NativeRdb::AbsRdbPredicates predicates(APP_CLONE_PREFERENCE_TABLE_NAME);
    predicates.EqualTo(BUNDLE_NAME_COLUMN, bundleName);
    predicates.EqualTo(USER_ID_COLUMN, userId);
    if (!rdbDataManager_->UpdateOrInsertData(valuesBucket, predicates)) {
        APP_LOGE_NOFUNC("InsertOrReplace UpdateOrInsertData failed, bundleName: %{public}s, userId: %{public}d",
            bundleName.c_str(), userId);
        return false;
    }
    return true;
}

bool AppClonePreferenceStorage::Query(const std::string &bundleName, int32_t userId,
    AppClonePreference &preference)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE_NOFUNC("Query rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(APP_CLONE_PREFERENCE_TABLE_NAME);
    predicates.EqualTo(BUNDLE_NAME_COLUMN, bundleName);
    predicates.EqualTo(USER_ID_COLUMN, userId);

    auto resultSet = rdbDataManager_->QueryData(predicates);
    if (resultSet == nullptr) {
        APP_LOGE_NOFUNC("Query QueryData returned null");
        return false;
    }
    ScopeGuard stateGuard([resultSet] { resultSet->Close(); });

    int32_t count = 0;
    if (resultSet->GetRowCount(count) != NativeRdb::E_OK) {
        APP_LOGE_NOFUNC("Query GetRowCount failed");
        return false;
    }
    if (count == 0) {
        APP_LOGD("Query no record for bundleName: %{public}s, userId: %{public}d",
            bundleName.c_str(), userId);
        return false;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        APP_LOGE_NOFUNC("Query GoToFirstRow failed");
        return false;
    }

    int32_t typeColumnIndex = -1;
    if (resultSet->GetColumnIndex(PREFERENCE_TYPE_COLUMN, typeColumnIndex) != NativeRdb::E_OK
        || typeColumnIndex == -1) {
        APP_LOGE_NOFUNC("Query GetColumnIndex PREFERENCE_TYPE failed");
        return false;
    }
    int32_t typeValue = 0;
    if (resultSet->GetInt(typeColumnIndex, typeValue) != NativeRdb::E_OK) {
        APP_LOGE_NOFUNC("Query GetInt type failed");
        return false;
    }
    preference.mode = static_cast<AppClonePreferenceMode>(typeValue);

    int32_t appIndexColumnIndex = -1;
    if (resultSet->GetColumnIndex(APP_INDEX_COLUMN, appIndexColumnIndex) != NativeRdb::E_OK
        || appIndexColumnIndex == -1) {
        APP_LOGE_NOFUNC("Query GetColumnIndex APP_INDEX failed");
        return false;
    }
    int32_t appIndex = 0;
    if (resultSet->GetInt(appIndexColumnIndex, appIndex) != NativeRdb::E_OK) {
        APP_LOGE_NOFUNC("Query GetInt appIndex failed");
        return false;
    }
    preference.appIndex = appIndex;
    return true;
}

bool AppClonePreferenceStorage::Delete(const std::string &bundleName, int32_t userId)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE_NOFUNC("Delete rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(APP_CLONE_PREFERENCE_TABLE_NAME);
    predicates.EqualTo(BUNDLE_NAME_COLUMN, bundleName);
    predicates.EqualTo(USER_ID_COLUMN, userId);
    if (!rdbDataManager_->DeleteData(predicates)) {
        APP_LOGE_NOFUNC("Delete DeleteData failed, bundleName: %{public}s, userId: %{public}d",
            bundleName.c_str(), userId);
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
