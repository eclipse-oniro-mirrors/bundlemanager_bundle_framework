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

#include "first_install_data_mgr_storage_rdb.h"

#include "app_log_wrapper.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* const FIRST_INSTALL_BUNDLE_TABLE_NAME = "first_install_bundle_info";
const char* const BUNDLE_NAME = "BUNDLE_NAME";
const char* const USER_ID = "USER_ID";

const char* const FIRST_INSTALL_BUNDLE_INFO = "FIRST_INSTALL_BUNDLE_INFO";
const int8_t BUNDLE_INFO_INDEX = 2;
}
FirstInstallDataMgrStorageRdb::FirstInstallDataMgrStorageRdb()
{
    APP_LOGI("created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = FIRST_INSTALL_BUNDLE_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string{ FIRST_INSTALL_BUNDLE_TABLE_NAME }
        + "(BUNDLE_NAME TEXT NOT NULL, "
        + "USER_ID INTEGER NOT NULL, "
        + "FIRST_INSTALL_BUNDLE_INFO TEXT NOT NULL, "
        + "PRIMARY KEY (BUNDLE_NAME, USER_ID));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

FirstInstallDataMgrStorageRdb::~FirstInstallDataMgrStorageRdb()
{
    APP_LOGI("~");
}

bool FirstInstallDataMgrStorageRdb::IsExistFirstInstallBundleInfo(const std::string &bundleName,
    int32_t userId)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(FIRST_INSTALL_BUNDLE_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(USER_ID, userId);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is null");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    int32_t count = 0;
    auto ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetRowCount failed, ret: %{public}d", ret);
        return false;
    }
    if (count == 0) {
        APP_LOGD("GetRowCount count is 0");
        return false;
    }
    return true;
}

bool FirstInstallDataMgrStorageRdb::AddFirstInstallBundleInfo(const std::string &bundleName, int32_t userId,
    const FirstInstallBundleInfo &firstInstallBundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BUNDLE_NAME, bundleName);
    valuesBucket.PutInt(USER_ID, userId);
    valuesBucket.PutString(FIRST_INSTALL_BUNDLE_INFO, firstInstallBundleInfo.ToString());
    return rdbDataManager_->InsertData(valuesBucket);
}

bool FirstInstallDataMgrStorageRdb::GetFirstInstallBundleInfo(const std::string &bundleName, int32_t userId,
    FirstInstallBundleInfo &firstInstallBundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(FIRST_INSTALL_BUNDLE_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(USER_ID, userId);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGD("GoToFirstRow failed, ret: %{public}d", ret);
        return false;
    }
    std::string value;
    ret = absSharedResultSet->GetString(BUNDLE_INFO_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetString failed, ret: %{public}d", ret);
        return false;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("error key");
        return false;
    }
    from_json(jsonObject, firstInstallBundleInfo);
    return true;
}

bool FirstInstallDataMgrStorageRdb::DeleteFirstInstallBundleInfo(int32_t userId)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(FIRST_INSTALL_BUNDLE_TABLE_NAME);
    absRdbPredicates.EqualTo(USER_ID, userId);
    return rdbDataManager_->DeleteData(absRdbPredicates);
}
}  // namespace AppExecFwk
}  // namespace OHOS