/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_APP_PROVISION_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_APP_PROVISION_INFO_H

#include "app_provision_info_rdb.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::NativeRdb;

class MockAppProvisionInfo : public RdbStore {
public:
    virtual int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int BatchInsert(int64_t &outInsertNum, const std::string &table,
        const std::vector<ValuesBucket> &initialBatchValues)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int InsertWithConflictResolution(int64_t &outRowId, const std::string &table,
        const ValuesBucket &initialValues,
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClaus,
        const std::vector<std::string> &whereArgs)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause = "",
        const std::vector<ValueObject> &bindArgs = {})
    {
        return NativeRdb::E_ERROR;
    };
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs,
        ConflictResolution conflictResolution)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause = "", const std::vector<ValueObject> &bindArgs = {},
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &whereArgs)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause = "",
        const std::vector<ValueObject> &bindArgs = {})
    {
        return NativeRdb::E_ERROR;
    };
    virtual std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(int &errCode, bool distinct, const std::string &table,
        const std::vector<std::string> &columns, const std::string &whereClause = "",
        const std::vector<ValueObject> &bindArgs = {}, const std::string &groupBy = "",
        const std::string &indexName = "", const std::string &orderBy = "",
        const int &limit = AbsPredicates::INIT_LIMIT_VALUE,
        const int &offset = AbsPredicates::INIT_LIMIT_VALUE)
    {
        return nullptr;
    };
    virtual std::shared_ptr<NativeRdb::AbsSharedResultSet> QuerySql(
        const std::string &sql, const std::vector<std::string> &selectionArgs)
    {
        return nullptr;
    };
    virtual std::shared_ptr<NativeRdb::AbsSharedResultSet> QuerySql(
        const std::string &sql, const std::vector<ValueObject> &selectionArgs = {})
    {
        return nullptr;
    };
    virtual std::shared_ptr<NativeRdb::ResultSet> QueryByStep(
        const std::string &sql, const std::vector<std::string> &selectionArgs)
    {
        return nullptr;
    };
    virtual std::shared_ptr<NativeRdb::ResultSet> QueryByStep(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = {})
    {
        return nullptr;
    };
    virtual int ExecuteSql(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
    {
        return NativeRdb::E_ERROR;
    };
    virtual int ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
    {
        return NativeRdb::E_ERROR;
    };
    virtual int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
    {
        return NativeRdb::E_ERROR;
    };
    virtual int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
    {
        return NativeRdb::E_ERROR;
    };
    virtual int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
    {
        return NativeRdb::E_ERROR;
    };
    virtual int Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int Attach(
        const std::string &alias, const std::string &pathName, const std::vector<uint8_t> destEncryptKey)
    {
        return NativeRdb::E_ERROR;
    };

    virtual int Count(int64_t &outValue, const AbsRdbPredicates &predicates)
    {
        return NativeRdb::E_ERROR;
    };
    virtual std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
    {
        std::shared_ptr<NativeRdb::AbsSharedResultSet> sharedResultSet =
        std::make_shared<NativeRdb::AbsSharedResultSet>();
        return sharedResultSet;
    };
    virtual std::shared_ptr<NativeRdb::ResultSet> QueryByStep(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
    {
        return nullptr;
    };
    virtual std::shared_ptr<NativeRdb::ResultSet> RemoteQuery(const std::string &device,
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns, int &errCode)
    {
        return nullptr;
    };
    virtual int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int Delete(int &deletedRows, const AbsRdbPredicates &predicates)
    {
        return NativeRdb::E_ERROR;
    };

    virtual int GetStatus()
    {
        return NativeRdb::E_ERROR;
    };
    virtual void SetStatus(int status) {};
    virtual int GetVersion(int &version)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int SetVersion(int version)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int BeginTransaction()
    {
        return NativeRdb::E_ERROR;
    };
    virtual int RollBack()
    {
        return NativeRdb::E_ERROR;
    };
    virtual int Commit()
    {
        return NativeRdb::E_ERROR;
    };
    virtual bool IsInTransaction()
    {
        return false;
    };
    virtual std::string GetPath()
    {
        return "";
    }
    virtual bool IsHoldingConnection()
    {
        return false;
    };
    virtual bool IsOpen() const
    {
        return false;
    };
    virtual bool IsReadOnly() const
    {
        return false;
    };
    virtual bool IsMemoryRdb() const
    {
        return false;
    };
    virtual int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey)
    {
        return NativeRdb::E_ERROR;
    };
    virtual int ChangeDbFileForRestore(const std::string newPath, const std::string backupPath,
        const std::vector<uint8_t> &newKey)
    {
        return NativeRdb::E_ERROR;
    };

    virtual int SetDistributedTables(const std::vector<std::string>& tables, int type,
        const DistributedRdb::DistributedConfig &distributedConfig)
    {
        return E_ERROR;
    };

    virtual std::string ObtainDistributedTableName(
        const std::string &device, const std::string &table, int &errCode)
    {
        return "";
    }

    virtual int Sync(const SyncOption& option, const AbsRdbPredicates& predicate, const AsyncBrief& async)
    {
        return E_ERROR;
    };

    virtual int Sync(const SyncOption& option, const AbsRdbPredicates& predicate, const AsyncDetail& async)
    {
        return E_ERROR;
    };
    
    virtual int Sync(const SyncOption& option, const std::vector<std::string>& tables, const AsyncDetail& async)
    {
        return E_ERROR;
    };

    virtual int Subscribe(const SubscribeOption& option, RdbStoreObserver *observer)
    {
        return E_ERROR;
    };

    virtual int UnSubscribe(const SubscribeOption& option, RdbStoreObserver *observer)
    {
        return E_ERROR;
    };

    virtual int RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> syncObserver)
    {
        return E_ERROR;
    };

    virtual int UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> syncObserver)
    {
        return E_ERROR;
    };

    virtual int Notify(const std::string &event)
    {
        return E_ERROR;
    }

    virtual bool DropDeviceData(const std::vector<std::string>& devices, const DropOption& option)
    {
        return false;
    };

    virtual ModifyTime GetModifyTime(
        const std::string &table, const std::string &columnName, std::vector<PRIKey> &keys)
    {
        return {};
    };

    virtual int CleanDirtyData(const std::string &table, uint64_t cursor)
    {
        return E_ERROR;
    };

    virtual int GetRebuilt(RebuiltType &rebuilt)
    {
        return E_OK;
    }
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_APP_PROVISION_INFO_H