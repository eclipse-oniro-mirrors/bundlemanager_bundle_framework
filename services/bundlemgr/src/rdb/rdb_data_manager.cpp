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
#include <atomic>
#include <cstdlib>
#include "bundle_service_constants.h"
#include "rdb_data_manager.h"

#include "app_log_wrapper.h"
#include "bundle_util.h"
#include "event_report.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BMS_KEY = "KEY";
constexpr const char* BMS_VALUE = "VALUE";
constexpr int8_t BMS_KEY_INDEX = 0;
constexpr int8_t BMS_VALUE_INDEX = 1;
constexpr int16_t WRITE_TIMEOUT = 300; // 300s
constexpr int8_t CLOSE_TIME = 20; // delay 20s stop rdbStore
constexpr const char* BMS_BACK_UP_RDB_NAME = "bms-backup.db";
constexpr int32_t OPERATION_TYPE_OF_INSUFFICIENT_DISK = 3;
static std::atomic<int64_t> g_lastReportTime = 0;
constexpr int64_t REPORTING_INTERVAL = 1000 * 60 * 30; // 30min
constexpr int32_t RETRY_TIMES = 3;
constexpr int32_t RETRY_INTERVAL = 500; // 500ms
constexpr const char* INTEGRITY_CHECK = "PRAGMA integrity_check";
constexpr const char* CHECK_OK = "ok";
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
    rdbStoreConfig.SetBundleName(ServiceConstants::CALLER_NAME_BMS);
    // for check db exist or not
    bool isNeedRebuildDb = false;
    std::string rdbFilePath = bmsRdbConfig_.dbPath + std::string("/") + std::string(BMS_BACK_UP_RDB_NAME);
    if (access(rdbStoreConfig.GetPath().c_str(), F_OK) != 0) {
        APP_LOGW("bms db :%{public}s is not exist, need to create. errno:%{public}d",
            rdbStoreConfig.GetPath().c_str(), errno);
        if (access(rdbFilePath.c_str(), F_OK) == 0) {
            isNeedRebuildDb = true;
        }
    }
    int32_t errCode = NativeRdb::E_OK;
    BmsRdbOpenCallback bmsRdbOpenCallback(bmsRdbConfig_);
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(
        rdbStoreConfig,
        bmsRdbConfig_.version,
        bmsRdbOpenCallback, errCode);
    if (rdbStore_ == nullptr) {
        APP_LOGE("GetRdbStore failed, errCode:%{public}d", errCode);
        SendDbErrorEvent(bmsRdbConfig_.dbName, static_cast<int32_t>(DB_OPERATION_TYPE::OPEN), errCode);
        return nullptr;
    }
    CheckSystemSizeAndHisysEvent(bmsRdbConfig_.dbPath, bmsRdbConfig_.dbName);
    if (!isInitial_ && !isNeedRebuildDb) {
        isNeedRebuildDb = RdbIntegrityCheckNeedRestore();
        isInitial_ = true;
    }
    NativeRdb::RebuiltType rebuildType = NativeRdb::RebuiltType::NONE;
    int32_t rebuildCode = rdbStore_->GetRebuilt(rebuildType);
    if (rebuildType == NativeRdb::RebuiltType::REBUILT || isNeedRebuildDb) {
        APP_LOGI("start %{public}s restore ret %{public}d, type:%{public}d", bmsRdbConfig_.dbName.c_str(),
            rebuildCode, static_cast<int32_t>(rebuildType));
        int32_t restoreRet = rdbStore_->Restore(rdbFilePath);
        if (restoreRet != NativeRdb::E_OK) {
            APP_LOGE("rdb restore failed ret:%{public}d", restoreRet);
        }
        SendDbErrorEvent(bmsRdbConfig_.dbName, static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), rebuildCode);
    }

    if (rdbStore_ != nullptr) {
        DelayCloseRdbStore();
    }
    return rdbStore_;
}

void RdbDataManager::CheckSystemSizeAndHisysEvent(const std::string &path, const std::string &fileName)
{
    if (!CheckIsSatisfyTime()) {
        APP_LOGD("not satisfy time");
        return;
    }
    bool isInsufficientSpace = BundleUtil::CheckSystemSizeAndHisysEvent(path, fileName);
    if (isInsufficientSpace) {
        APP_LOGW("space not enough %{public}s", fileName.c_str());
        EventReport::SendDiskSpaceEvent(fileName, 0, OPERATION_TYPE_OF_INSUFFICIENT_DISK);
    }
}

bool RdbDataManager::CheckIsSatisfyTime()
{
    int64_t now = BundleUtil::GetCurrentTimeMs();
    if (abs(now - g_lastReportTime) < REPORTING_INTERVAL) {
        APP_LOGD("time is not up yet");
        return false;
    }
    g_lastReportTime = now;
    return true;
}

void RdbDataManager::SendDbErrorEvent(const std::string &dbName, int32_t operationType, int32_t errorCode)
{
    EventReport::SendDbErrorEvent(dbName, operationType, errorCode);
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
    auto ret = InsertWithRetry(rdbStore, rowId, valuesBucket);
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
    auto ret = InsertWithRetry(rdbStore, rowId, valuesBucket);
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
    auto absSharedResultSet = rdbStore->QueryByStep(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet failed");
        return false;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
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

std::shared_ptr<NativeRdb::ResultSet> RdbDataManager::QueryData(
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
    auto absSharedResultSet = rdbStore->QueryByStep(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
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
    auto absSharedResultSet = rdbStore->QueryByStep(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet failed");
        return false;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });

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
    APP_LOGI_NOFUNC("th");
    std::thread closeRdbStoreThread(task);
    APP_LOGI_NOFUNC("th end");
    closeRdbStoreThread.detach();
}

bool RdbDataManager::RdbIntegrityCheckNeedRestore()
{
    APP_LOGI("integrity check start");
    if (rdbStore_ == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }
    auto [ret, outValue] = rdbStore_->Execute(INTEGRITY_CHECK);
    if (ret == NativeRdb::E_OK) {
        std::string outputResult;
        outValue.GetString(outputResult);
        if (outputResult != CHECK_OK) {
            APP_LOGW("rdb error need to restore");
            return true;
        }
        APP_LOGI("rdb integrity check succeed");
    }
    return false;
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

int32_t RdbDataManager::InsertWithRetry(std::shared_ptr<NativeRdb::RdbStore> rdbStore, int64_t &rowId,
    const NativeRdb::ValuesBucket &valuesBucket)
{
    int32_t retryCnt = 0;
    int32_t ret = 0;
    do {
        ret = rdbStore->InsertWithConflictResolution(rowId, bmsRdbConfig_.tableName,
            valuesBucket, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
        if (ret == NativeRdb::E_OK || !IsRetryErrCode(ret)) {
            break;
        }
        if (++retryCnt < RETRY_TIMES) {
            std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_INTERVAL));
        }
        APP_LOGW("rdb insert failed, retry count: %{public}d, ret: %{public}d", retryCnt, ret);
    } while (retryCnt < RETRY_TIMES);
    return ret;
}

bool RdbDataManager::IsRetryErrCode(int32_t errCode)
{
    if (errCode == NativeRdb::E_DATABASE_BUSY ||
        errCode == NativeRdb::E_SQLITE_BUSY ||
        errCode == NativeRdb::E_SQLITE_LOCKED ||
        errCode == NativeRdb::E_SQLITE_NOMEM ||
        errCode == NativeRdb::E_SQLITE_IOERR) {
        return true;
    }
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
