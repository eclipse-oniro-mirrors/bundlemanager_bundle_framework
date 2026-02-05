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

#include "disable_forbidden_rdb.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string DISABLE_FORBIDDEN_RDB_TABLE_NAME = "disable_forbidden";
// disable forbidden table key
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string USER_ID = "USER_ID";
const std::string APP_INDEX = "APP_INDEX";

}
DisableForbiddenRdb::DisableForbiddenRdb()
{
    APP_LOGD("create DisableForbiddenRdb");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = DISABLE_FORBIDDEN_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + DISABLE_FORBIDDEN_RDB_TABLE_NAME
        + "(BUNDLE_NAME TEXT NOT NULL, "
        + "USER_ID INTEGER NOT NULL, "
        + "APP_INDEX INTEGER NOT NULL, "
        + "PRIMARY KEY (BUNDLE_NAME, USER_ID, APP_INDEX));");

    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

DisableForbiddenRdb::~DisableForbiddenRdb()
{
    APP_LOGD("destroy DisableForbiddenRdb");
}

bool DisableForbiddenRdb::AddDisableForbiddenData(const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE_NOFUNC("rdbDataManager is null");
        return false;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BUNDLE_NAME, bundleName);
    valuesBucket.PutInt(USER_ID, userId);
    valuesBucket.PutInt(APP_INDEX, appIndex);
    if (!rdbDataManager_->InsertData(valuesBucket)) {
        APP_LOGE_NOFUNC("InsertData failed");
        return false;
    }
    return true;
}

bool DisableForbiddenRdb::DeleteDisableForbiddenData(const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE_NOFUNC("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(DISABLE_FORBIDDEN_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(USER_ID, userId);
    absRdbPredicates.EqualTo(APP_INDEX, appIndex);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGE_NOFUNC("DeleteData failed");
        return false;
    }
    return true;
}

bool DisableForbiddenRdb::IsApplicationDisableForbidden(const std::string &bundleName, int32_t userId,
    int32_t appIndex, bool &forbidden)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE_NOFUNC("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(DISABLE_FORBIDDEN_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(APP_INDEX, appIndex);

    if (userId >= Constants::START_USERID) {
        absRdbPredicates.BeginWrap();
        absRdbPredicates.EqualTo(USER_ID, userId);
        absRdbPredicates.Or();
        absRdbPredicates.EqualTo(USER_ID, Constants::DEFAULT_USERID);
        absRdbPredicates.Or();
        absRdbPredicates.EqualTo(USER_ID, Constants::U1);
        absRdbPredicates.EndWrap();
    } else {
        absRdbPredicates.EqualTo(USER_ID, userId);
    }

    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE_NOFUNC("QueryData failed");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE_NOFUNC("GetRowCount failed");
        return false;
    }
    if (count == 0) {
        APP_LOGD("count is 0");
        forbidden = false;
    } else {
        APP_LOGD("count is not 0");
        forbidden = true;
    }
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS