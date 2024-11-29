/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "router_data_storage_rdb.h"

#include "app_log_wrapper.h"
#include "bundle_parser.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* const ROUTER_RDB_TABLE_NAME = "router_map";
const char* const BUNDLE_NAME = "BUNDLE_NAME";
const char* const MODULE_NAME = "MODULE_NAME";
const char* const ROUTER_MAP_INFO = "ROUTER_MAP_INFO";
const int8_t BUNDLE_NAME_INDEX = 0;
const int8_t MODULE_NAME_INDEX = 1;
const int8_t ROUTER_INFO_INDEX = 2;
}
RouterDataStorageRdb::RouterDataStorageRdb()
{
    APP_LOGI("RouterDataStorageRdb instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = ROUTER_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string{ ROUTER_RDB_TABLE_NAME }
        + "(BUNDLE_NAME TEXT NOT NULL, "
        + "MODULE_NAME TEXT NOT NULL, ROUTER_MAP_INFO TEXT NOT NULL, "
        + "PRIMARY KEY (BUNDLE_NAME, MODULE_NAME));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

RouterDataStorageRdb::~RouterDataStorageRdb()
{
    APP_LOGI("~");
}

bool RouterDataStorageRdb::UpdateRouterInfo(
    const std::string &bundleName, const std::map<std::string, std::string> &routerInfoMap)
{
    DeleteRouterInfo(bundleName);
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("param error");
        return false;
    }
    bool result = true;
    for (const auto &item : routerInfoMap) {
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(BUNDLE_NAME, bundleName);
        valuesBucket.PutString(MODULE_NAME, item.first);
        valuesBucket.PutString(ROUTER_MAP_INFO, item.second);
        if (!rdbDataManager_->InsertData(valuesBucket)) {
            APP_LOGE("insert %{public}s %{public}s failed", bundleName.c_str(), item.first.c_str());
            result = false;
        }
    }
    return result;
}

bool RouterDataStorageRdb::GetRouterInfo(const std::string &bundleName, const std::string &moduleName,
    std::vector<RouterItem> &routerInfos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(ROUTER_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(MODULE_NAME, moduleName);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetRouterInfo %{public}s %{public}s failed", bundleName.c_str(), moduleName.c_str());
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        APP_LOGW("GetRowCount failed, ret: %{public}d", ret);
        return false;
    }
    if (count == 0) {
        APP_LOGI("GetRouterInfo size 0");
        return false;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGW("GoToFirstRow failed, ret: %{public}d", ret);
        return false;
    }
    do {
        std::string value;
        auto ret = absSharedResultSet->GetString(ROUTER_INFO_INDEX, value);
        if (ret != NativeRdb::E_OK) {
            APP_LOGE("GetString failed, ret: %{public}d", ret);
            return false;
        }
        BundleParser bundleParser;
        if (bundleParser.ParseRouterArray(value, routerInfos) != ERR_OK) {
            APP_LOGE("parse router %{public}s %{public}s failed", bundleName.c_str(), moduleName.c_str());
            return false;
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return true;
}

void RouterDataStorageRdb::GetAllBundleNames(std::set<std::string> &bundleNames)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(ROUTER_RDB_TABLE_NAME);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetAllBundleNames failed");
        return;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });

    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return;
    }
    do {
        std::string name;
        ret = absSharedResultSet->GetString(BUNDLE_NAME_INDEX, name);
        if (ret != NativeRdb::E_OK) {
            APP_LOGE("GetString bundleName failed, ret: %{public}d", ret);
            return;
        }
        bundleNames.insert(name);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
}

bool RouterDataStorageRdb::DeleteRouterInfo(const std::string &bundleName)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(ROUTER_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    return rdbDataManager_->DeleteData(absRdbPredicates);
}

bool RouterDataStorageRdb::DeleteRouterInfo(const std::string &bundleName, const std::string &moduleName)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(ROUTER_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(MODULE_NAME, moduleName);
    return rdbDataManager_->DeleteData(absRdbPredicates);
}
}  // namespace AppExecFwk
}  // namespace OHOS