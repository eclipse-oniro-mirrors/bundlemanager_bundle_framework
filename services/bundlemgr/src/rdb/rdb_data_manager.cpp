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
#include "bundle_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BMS_KEY = "KEY";
const std::string BMS_VALUE = "VALUE";
const int32_t BMS_KEY_INDEX = 0;
const int32_t BMS_VALUE_INDEX = 1;
}

RdbDataManager::RdbDataManager(const BmsRdbConfig &bmsRdbConfig)
    : bmsRdbConfig_(bmsRdbConfig) {}

RdbDataManager::~RdbDataManager() {}

bool RdbDataManager::Init()
{
    if (rdbStore_ == nullptr) {
        APP_LOGD("Create rdbStore");
        NativeRdb::RdbStoreConfig rdbStoreConfig(
            bmsRdbConfig_.dbPath + bmsRdbConfig_.dbName,
            NativeRdb::StorageMode::MODE_DISK,
            false,
            std::vector<uint8_t>(),
            bmsRdbConfig_.journalMode,
            bmsRdbConfig_.syncMode);

        int32_t errCode = NativeRdb::E_OK;
        BmsRdbOpenCallback bmsRdbOpenCallback(bmsRdbConfig_);
        rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(
            rdbStoreConfig,
            bmsRdbConfig_.version,
            bmsRdbOpenCallback,
            errCode);
    }

    return rdbStore_ != nullptr;
}

bool RdbDataManager::InsertData(const std::string &key, const std::string &value)
{
    APP_LOGD("InsertData start");
    if (rdbStore_ == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    int64_t rowId = -1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BMS_KEY, key);
    valuesBucket.PutString(BMS_VALUE, value);
    auto ret = rdbStore_->InsertWithConflictResolution(
        rowId, bmsRdbConfig_.tableName, valuesBucket, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::UpdateData(const std::string &key, const std::string &value)
{
    APP_LOGD("UpdateData start");
    if (rdbStore_ == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    int32_t rowId = -1;
    NativeRdb::AbsRdbPredicates absRdbPredicates(bmsRdbConfig_.tableName);
    absRdbPredicates.EqualTo(BMS_KEY, key);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BMS_KEY, key);
    valuesBucket.PutString(BMS_VALUE, value);
    auto ret = rdbStore_->Update(rowId, valuesBucket, absRdbPredicates);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::DeleteData(const std::string &key)
{
    APP_LOGD("DeleteData start");
    if (rdbStore_ == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    int32_t rowId = -1;
    NativeRdb::AbsRdbPredicates absRdbPredicates(bmsRdbConfig_.tableName);
    absRdbPredicates.EqualTo(BMS_KEY, key);
    auto ret = rdbStore_->Delete(rowId, absRdbPredicates);
    return ret == NativeRdb::E_OK;
}

bool RdbDataManager::QueryData(const std::string &key, std::string &value)
{
    APP_LOGD("QueryData start");
    if (rdbStore_ == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(bmsRdbConfig_.tableName);
    absRdbPredicates.EqualTo(BMS_KEY, key);
    auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
        APP_LOGE("absSharedResultSet failed");
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

bool RdbDataManager::QueryAllData(std::map<std::string, std::string> &datas)
{
    APP_LOGD("QueryAllData start");
    if (rdbStore_ == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(bmsRdbConfig_.tableName);
    auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
        APP_LOGE("absSharedResultSet failed");
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
}  // namespace AppExecFwk
}  // namespace OHOS
