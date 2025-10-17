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
const char* const ROUTER_RDB_TABLE_NAME = "router_map_V2";
const char* const OLD_ROUTER_RDB_TABLE_NAME = "router_map";
const char* const BUNDLE_NAME = "BUNDLE_NAME";
const char* const MODULE_NAME = "MODULE_NAME";
const char* const ROUTER_MAP_INFO = "ROUTER_MAP_INFO";
const char* const VERSION_CODE = "VERSION_CODE";
const int8_t BUNDLE_NAME_INDEX = 0;
const int8_t ROUTER_INFO_INDEX = 2;
}
RouterDataStorageRdb::RouterDataStorageRdb()
{
    APP_LOGI_NOFUNC("RouterDataStorageRdb instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = ROUTER_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string{ ROUTER_RDB_TABLE_NAME }
        + "(BUNDLE_NAME TEXT NOT NULL, "
        + "MODULE_NAME TEXT NOT NULL, ROUTER_MAP_INFO TEXT NOT NULL, "
        + "VERSION_CODE INTEGER NOT NULL, "
        + "PRIMARY KEY (BUNDLE_NAME, MODULE_NAME, VERSION_CODE));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

RouterDataStorageRdb::~RouterDataStorageRdb()
{
    APP_LOGI("~");
}

bool RouterDataStorageRdb::UpdateDB()
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + std::string(OLD_ROUTER_RDB_TABLE_NAME) +
        " ADD VERSION_CODE INTEGER DEFAULT 0;"));
    auto alterRdbManager = std::make_shared<RdbDataManager>(bmsRdbConfig);
    if (!alterRdbManager->ExecuteSql()) {
        APP_LOGE("alter router_map failed.");
    }
    bmsRdbConfig.insertColumnSql.clear();
    bmsRdbConfig.insertColumnSql.push_back(std::string("INSERT INTO " + std::string(ROUTER_RDB_TABLE_NAME)
        + " (BUNDLE_NAME, MODULE_NAME, VERSION_CODE, ROUTER_MAP_INFO) "
        + " SELECT BUNDLE_NAME, MODULE_NAME, VERSION_CODE, ROUTER_MAP_INFO FROM "
        + std::string(OLD_ROUTER_RDB_TABLE_NAME)));
    auto insertRdbManager = std::make_shared<RdbDataManager>(bmsRdbConfig);
    bool ret = insertRdbManager->ExecuteSql();
    if (!ret) {
        APP_LOGE("insert router_map_V2 failed.");
        return false;
    }
    bmsRdbConfig.insertColumnSql.clear();
    bmsRdbConfig.insertColumnSql.push_back("DROP TABLE " + std::string(OLD_ROUTER_RDB_TABLE_NAME));
    auto deleteRdbManager = std::make_shared<RdbDataManager>(bmsRdbConfig);
    (void)deleteRdbManager->ExecuteSql();
    APP_LOGI("Update router db success");
    return true;
}

bool RouterDataStorageRdb::UpdateRouterInfo(const std::string &bundleName,
    const std::map<std::string, std::string> &routerInfoMap, const uint32_t versionCode)
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
        valuesBucket.PutInt(VERSION_CODE, static_cast<int32_t>(versionCode));
        if (!rdbDataManager_->InsertData(valuesBucket)) {
            APP_LOGE("insert %{public}s %{public}s failed", bundleName.c_str(), item.first.c_str());
            result = false;
        }
    }
    return result;
}

bool RouterDataStorageRdb::GetRouterInfo(const std::string &bundleName, const std::string &moduleName,
    const uint32_t versionCode, std::vector<RouterItem> &routerInfos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(ROUTER_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(MODULE_NAME, moduleName);
    absRdbPredicates.EqualTo(VERSION_CODE, static_cast<int32_t>(versionCode));
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

bool RouterDataStorageRdb::DeleteRouterInfo(const std::string &bundleName,
    const std::string &moduleName,
    const uint32_t versionCode)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(ROUTER_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(MODULE_NAME, moduleName);
    absRdbPredicates.EqualTo(VERSION_CODE, static_cast<int32_t>(versionCode));
    return rdbDataManager_->DeleteData(absRdbPredicates);
}

bool RouterDataStorageRdb::InsertRouterInfo(const std::string &bundleName,
    const std::map<std::string, std::string> &routerInfoMap, const uint32_t versionCode)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    bool result = true;
    for (const auto &item : routerInfoMap) {
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(BUNDLE_NAME, bundleName);
        valuesBucket.PutString(MODULE_NAME, item.first);
        valuesBucket.PutString(ROUTER_MAP_INFO, item.second);
        valuesBucket.PutInt(VERSION_CODE, static_cast<int32_t>(versionCode));
        if (!rdbDataManager_->InsertData(valuesBucket)) {
            APP_LOGE("insert %{public}s %{public}s failed", bundleName.c_str(), item.first.c_str());
            result = false;
        }
    }
    return result;
}
}  // namespace AppExecFwk
}  // namespace OHOS