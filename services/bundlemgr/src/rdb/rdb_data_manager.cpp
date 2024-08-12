/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "rdb_data_manager.h"

#include "app_log_wrapper.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BMS_KEY = "KEY";
const std::string BMS_VALUE = "VALUE";
const int32_t BMS_KEY_INDEX = 0;
const int32_t BMS_VALUE_INDEX = 1;
const int32_t WRITE_TIMEOUT = 300; // 300s
const int32_t CLOSE_TIME = 20; // delay 20s stop rdbStore
constexpr const char* BMS_BACK_UP_RDB_NAME = "bms-backup.db";
}

std::mutex RdbDataManager::restoreRdbMutex_;

RdbDataManager::RdbDataManager(const BmsRdbConfig &bmsRdbConfig)
    : bmsRdbConfig_(bmsRdbConfig)
{
}

RdbDataManager::~RdbDataManager()
{
    rdbStore_ = nullptr;
}

void RdbDataManager::ClearCache()
{
    NativeRdb::RdbHelper::ClearCache();
}

std::shared_ptr<NativeRdb::RdbStore> RdbDataManager::GetRdbStore()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
    if (rdbStore_ != nullptr) {
        return rdbStore_;
    }
    std::lock_guard<std::mutex> restoreLock(restoreRdbMutex_);
    NativeRdb::RdbStoreConfig rdbStoreConfig(bmsRdbConfig_.dbPath + bmsRdbConfig_.dbName);
    rdbStoreConfig.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    rdbStoreConfig.SetWriteTime(WRITE_TIMEOUT);
    rdbStoreConfig.SetAllowRebuild(true);
    if (!isInitial_) {
        rdbStoreConfig.SetIntegrityCheck(NativeRdb::IntegrityCheck::FULL);
        isInitial_ = true;
    }
    // for check db exist or not
    if (access(rdbStoreConfig.GetPath().c_str(), F_OK) != 0) {
        APP_LOGW("bms db :%{public}s is not exist, need to create. errno:%{public}d",
            rdbStoreConfig.GetPath().c_str(), errno);
    }
    int32_t errCode = NativeRdb::E_OK;
    BmsRdbOpenCallback bmsRdbOpenCallback(bmsRdbConfig_);
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(
        rdbStoreConfig,
        bmsRdbConfig_.version,
        bmsRdbOpenCallback,
        errCode);
    if (rdbStore_ == nullptr) {
        APP_LOGE("GetRdbStore failed, errCode:%{public}d", errCode);
        return nullptr;
    }

    NativeRdb::RebuiltType rebuildType = NativeRdb::RebuiltType::NONE;
    int32_t rebuildCode = rdbStore_->GetRebuilt(rebuildType);
    if (rebuildType == NativeRdb::RebuiltType::REBUILT) {
        APP_LOGI("start %{public}s restore ret %{public}d, type:%{public}d", bmsRdbConfig_.dbName.c_str(),
            rebuildCode, static_cast<int32_t>(rebuildType));
        int32_t restoreRet = rdbStore_->Restore(bmsRdbConfig_.dbPath + std::string("/") +
            std::string(BMS_BACK_UP_RDB_NAME));
        if (restoreRet != NativeRdb::E_OK) {
            APP_LOGE("rdb restore failed ret:%{public}d", restoreRet);
        }
    }

    if (rdbStore_ != nullptr) {
        DelayCloseRdbStore();
    }
    return rdbStore_;
}

void RdbDataManager::BackupRdb()
{
    APP_LOGI("%{public}s backup start", bmsRdbConfig_.dbName.c_str());
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return;
    }
    auto ret = rdbStore->Backup(bmsRdbConfig_.dbPath + std::string("/") + std::string(BMS_BACK_UP_RDB_NAME));
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("Backup failed, errCode:%{public}d", ret);
    }
    APP_LOGI("%{public}s backup end", bmsRdbConfig_.dbName.c_str());
}

bool RdbDataManager::InsertData(const std::string &key, const std::string &value)
{
    APP_LOGD("InsertData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    int64_t rowId = -1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BMS_KEY, key);
    valuesBucket.PutString(BMS_VALUE, value);
    auto ret = rdbStore->InsertWithConflictResolution(
        rowId, bmsRdbConfig_.tableName, valuesBucket, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::InsertData(const NativeRdb::ValuesBucket &valuesBucket)
{
    APP_LOGD("InsertData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    int64_t rowId = -1;
    auto ret = rdbStore->InsertWithConflictResolution(
        rowId, bmsRdbConfig_.tableName, valuesBucket, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::BatchInsert(int64_t &outInsertNum, const std::vector<NativeRdb::ValuesBucket> &valuesBuckets)
{
    APP_LOGD("BatchInsert start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }
    auto ret = rdbStore->BatchInsert(outInsertNum, bmsRdbConfig_.tableName, valuesBuckets);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::UpdateData(const std::string &key, const std::string &value)
{
    APP_LOGD("UpdateData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    int32_t rowId = -1;
    NativeRdb::AbsRdbPredicates absRdbPredicates(bmsRdbConfig_.tableName);
    absRdbPredicates.EqualTo(BMS_KEY, key);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BMS_KEY, key);
    valuesBucket.PutString(BMS_VALUE, value);
    auto ret = rdbStore->Update(rowId, valuesBucket, absRdbPredicates);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::UpdateData(
    const NativeRdb::ValuesBucket &valuesBucket, const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    APP_LOGD("UpdateData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }
    if (absRdbPredicates.GetTableName() != bmsRdbConfig_.tableName) {
        APP_LOGE("RdbStore table is invalid");
        return false;
    }
    int32_t rowId = -1;
    auto ret = rdbStore->Update(rowId, valuesBucket, absRdbPredicates);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::UpdateOrInsertData(
    const NativeRdb::ValuesBucket &valuesBucket, const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    APP_LOGD("UpdateOrInsertData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }
    if (absRdbPredicates.GetTableName() != bmsRdbConfig_.tableName) {
        APP_LOGE("RdbStore table is invalid");
        return false;
    }
    int32_t rowId = -1;
    auto ret = rdbStore->Update(rowId, valuesBucket, absRdbPredicates);
    if ((ret == NativeRdb::E_OK) && (rowId == 0)) {
        APP_LOGI_NOFUNC("data not exist, need insert data");
        int64_t rowIdInsert = -1;
        ret = rdbStore->InsertWithConflictResolution(
            rowIdInsert, bmsRdbConfig_.tableName, valuesBucket, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    }
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::DeleteData(const std::string &key)
{
    APP_LOGD("DeleteData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    int32_t rowId = -1;
    NativeRdb::AbsRdbPredicates absRdbPredicates(bmsRdbConfig_.tableName);
    absRdbPredicates.EqualTo(BMS_KEY, key);
    auto ret = rdbStore->Delete(rowId, absRdbPredicates);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::DeleteData(const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }
    if (absRdbPredicates.GetTableName() != bmsRdbConfig_.tableName) {
        APP_LOGE("RdbStore table is invalid");
        return false;
    }
    int32_t rowId = -1;
    auto ret = rdbStore->Delete(rowId, absRdbPredicates);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::QueryData(const std::string &key, std::string &value)
{
    APP_LOGD("QueryData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(bmsRdbConfig_.tableName);
    absRdbPredicates.EqualTo(BMS_KEY, key);
    auto absSharedResultSet = rdbStore->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet failed");
        return false;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    if (!absSharedResultSet->HasBlock()) {
        APP_LOGE("absSharedResultSet has no block");
        return false;
    }
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return false;
    }

    ret = absSharedResultSet->GetString(BMS_VALUE_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("QueryData failed, ret: %{public}d", ret);
        return false;
    }

    return true;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> RdbDataManager::QueryData(
    const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    APP_LOGD("QueryData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return nullptr;
    }
    if (absRdbPredicates.GetTableName() != bmsRdbConfig_.tableName) {
        APP_LOGE("RdbStore table is invalid");
        return nullptr;
    }
    auto absSharedResultSet = rdbStore->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
        APP_LOGE("absSharedResultSet failed");
        return nullptr;
    }
    return absSharedResultSet;
}

bool RdbDataManager::QueryAllData(std::map<std::string, std::string> &datas)
{
    APP_LOGD("QueryAllData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(bmsRdbConfig_.tableName);
    auto absSharedResultSet = rdbStore->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet failed");
        return false;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    if (!absSharedResultSet->HasBlock()) {
        APP_LOGE("absSharedResultSet has no block");
        return false;
    }

    if (absSharedResultSet->GoToFirstRow() != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed");
        return false;
    }

    do {
        std::string key;
        if (absSharedResultSet->GetString(BMS_KEY_INDEX, key) != NativeRdb::E_OK) {
            APP_LOGE("GetString key failed");
            return false;
        }

        std::string value;
        if (absSharedResultSet->GetString(BMS_VALUE_INDEX, value) != NativeRdb::E_OK) {
            APP_LOGE("GetString value failed");
            return false;
        }

        datas.emplace(key, value);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return !datas.empty();
}

bool RdbDataManager::CreateTable()
{
    std::string createTableSql;
    if (bmsRdbConfig_.createTableSql.empty()) {
        createTableSql = std::string(
            "CREATE TABLE IF NOT EXISTS "
            + bmsRdbConfig_.tableName
            + "(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);");
    } else {
        createTableSql = bmsRdbConfig_.createTableSql;
    }
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }
    int ret = rdbStore->ExecuteSql(createTableSql);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("CreateTable failed, ret: %{public}d", ret);
        return false;
    }
    for (const auto &sql : bmsRdbConfig_.insertColumnSql) {
        int32_t insertRet = rdbStore->ExecuteSql(sql);
        if (insertRet != NativeRdb::E_OK) {
            APP_LOGW_NOFUNC("ExecuteSql insertColumnSql failed ret: %{public}d", insertRet);
        }
    }
    return true;
}

void RdbDataManager::DelayCloseRdbStore()
{
    APP_LOGD("RdbDataManager DelayCloseRdbStore start");
    std::weak_ptr<RdbDataManager> weakPtr = shared_from_this();
    auto task = [weakPtr]() {
        APP_LOGD("RdbDataManager DelayCloseRdbStore thread begin");
        std::this_thread::sleep_for(std::chrono::seconds(CLOSE_TIME));
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            return;
        }
        std::lock_guard<std::mutex> lock(sharedPtr->rdbMutex_);
        sharedPtr->rdbStore_ = nullptr;
        APP_LOGD("RdbDataManager DelayCloseRdbStore thread end");
    };
    std::thread closeRdbStoreThread(task);
    closeRdbStoreThread.detach();
}

std::shared_ptr<NativeRdb::ResultSet> RdbDataManager::QueryByStep(
    const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    APP_LOGD("QueryByStep start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return nullptr;
    }
    if (absRdbPredicates.GetTableName() != bmsRdbConfig_.tableName) {
        APP_LOGE("RdbStore table is invalid");
        return nullptr;
    }
    auto absSharedResultSet = rdbStore->QueryByStep(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet failed");
        return nullptr;
    }
    return absSharedResultSet;
}
}  // namespace AppExecFwk
}  // namespace OHOS
