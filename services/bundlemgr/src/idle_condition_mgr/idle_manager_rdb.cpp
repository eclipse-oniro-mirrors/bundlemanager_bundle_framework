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

#include "idle_manager_rdb.h"

#include "app_log_wrapper.h"
#include "bundle_service_constants.h"
#include "hitrace_meter.h"
#include "scope_guard.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* IDLE_RDB_TABLE_NAME = "idle_info";
constexpr const char* BUNDLE_NAME = "BUNDLE_NAME";
constexpr const char* USER_ID = "USER_ID";
constexpr const char* APP_INDEX = "APP_INDEX";
constexpr const char* VALUE = "VALUE";
const int8_t BUNDLE_NAME_INDEX = 0;
const int8_t USER_ID_INDEX = 1;
const int8_t APP_INDEX_INDEX = 2;
const int8_t VALUE_INDEX = 3;
}
IdleManagerRdb::IdleManagerRdb()
{
    APP_LOGI("IdleManagerRdb created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = IDLE_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string(IDLE_RDB_TABLE_NAME)
        + "(BUNDLE_NAME TEXT NOT NULL, USER_ID INTEGER, APP_INDEX INTEGER, VALUE INTEGER, "
        + "PRIMARY KEY (BUNDLE_NAME, USER_ID, APP_INDEX));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

IdleManagerRdb::~IdleManagerRdb()
{
    APP_LOGI("IdleManagerRdb destroyed");
}

ErrCode IdleManagerRdb::AddBundles(const std::vector<BundleOptionInfo> &bundleOptionInfos)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (const auto &bundleOptionInfo : bundleOptionInfos) {
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(BUNDLE_NAME, bundleOptionInfo.bundleName);
        valuesBucket.PutInt(USER_ID, bundleOptionInfo.userId);
        valuesBucket.PutInt(APP_INDEX, bundleOptionInfo.appIndex);
        valuesBucket.PutInt(VALUE, 0);
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    auto ret = rdbDataManager_->BatchInsert(insertNum, valuesBuckets);
    if (!ret) {
        APP_LOGE("BatchInsert failed");
        return ERR_APPEXECFWK_DB_BATCH_INSERT_ERROR;
    }
    if (valuesBuckets.size() != static_cast<uint64_t>(insertNum)) {
        APP_LOGE("BatchInsert size not expected");
        return ERR_APPEXECFWK_DB_BATCH_INSERT_ERROR;
    }
    return ERR_OK;
}

ErrCode IdleManagerRdb::AddBundle(const BundleOptionInfo &bundleOptionInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (bundleOptionInfo.bundleName.empty()) {
        APP_LOGE("AddBundle failed, bundleName is empty");
        return ERR_APPEXECFWK_DB_PARAM_ERROR;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BUNDLE_NAME, bundleOptionInfo.bundleName);
    valuesBucket.PutInt(USER_ID, bundleOptionInfo.userId);
    valuesBucket.PutInt(APP_INDEX, bundleOptionInfo.appIndex);
    valuesBucket.PutInt(VALUE, 0);
    auto ret = rdbDataManager_->InsertData(valuesBucket);
    if (!ret) {
        APP_LOGE("AddBundle failed -n:%{public}s -u:%{public}d -i:%{public}d", bundleOptionInfo.bundleName.c_str(),
            bundleOptionInfo.userId, bundleOptionInfo.appIndex);
        return ERR_APPEXECFWK_DB_INSERT_ERROR;
    }
    return ERR_OK;
}

ErrCode IdleManagerRdb::DeleteBundle(const BundleOptionInfo &bundleOptionInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (bundleOptionInfo.bundleName.empty()) {
        APP_LOGE("DeleteBundle failed, bundleName is empty");
        return ERR_APPEXECFWK_DB_PARAM_ERROR;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(IDLE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleOptionInfo.bundleName);
    absRdbPredicates.EqualTo(USER_ID, bundleOptionInfo.userId);
    absRdbPredicates.EqualTo(APP_INDEX, bundleOptionInfo.appIndex);
    auto ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        APP_LOGE("DeleteBundle failed -n:%{public}s -u:%{public}d -i:%{public}d", bundleOptionInfo.bundleName.c_str(),
            bundleOptionInfo.userId, bundleOptionInfo.appIndex);
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode IdleManagerRdb::GetAllBundle(int32_t userId, std::vector<BundleOptionInfo> &bundleOptionInfos)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(IDLE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(USER_ID, userId);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetAllBundle failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    int32_t count;
    auto ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetRowCount failed, -u:%{public}d, ret: %{public}d", userId, ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    if (count == 0) {
        APP_LOGD("count size 0");
        return ERR_OK;
    }

    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    do {
        BundleOptionInfo bundleOptionInfo;
        if (ConvertToBundleOptionInfo(absSharedResultSet, bundleOptionInfo)) {
            bundleOptionInfos.emplace_back(bundleOptionInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return ERR_OK;
}

bool IdleManagerRdb::ConvertToBundleOptionInfo(
    const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet,
    BundleOptionInfo &bundleOptionInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is nullptr");
        return false;
    }
    auto ret = absSharedResultSet->GetString(BUNDLE_NAME_INDEX, bundleOptionInfo.bundleName);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString bundleName failed, ret: %{public}d");

    ret = absSharedResultSet->GetInt(USER_ID_INDEX, bundleOptionInfo.userId);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetInt userId failed, ret: %{public}d");

    ret = absSharedResultSet->GetInt(APP_INDEX_INDEX, bundleOptionInfo.appIndex);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetInt appIndex failed, ret: %{public}d");
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS