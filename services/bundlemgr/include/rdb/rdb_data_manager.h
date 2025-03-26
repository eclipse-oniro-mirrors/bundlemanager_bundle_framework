/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_RDB_DATA_MANAGER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_RDB_DATA_MANAGER_H

#include <mutex>

#include "bms_rdb_config.h"
#include "bms_rdb_open_callback.h"
#include "rdb_helper.h"
#include "single_delayed_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {
class RdbDataManager : public std::enable_shared_from_this<RdbDataManager> {
public:
    RdbDataManager(const BmsRdbConfig &bmsRdbConfig);
    ~RdbDataManager();

    static void ClearCache();
    bool InsertData(const std::string &key, const std::string &value);
    bool InsertData(const NativeRdb::ValuesBucket &valuesBucket);
    bool UpdateData(const std::string &key, const std::string &value);
    bool DeleteData(const std::string &key);
    bool QueryData(const std::string &key, std::string &value);
    bool QueryAllData(std::map<std::string, std::string> &datas);

    bool BatchInsert(int64_t &outInsertNum, const std::vector<NativeRdb::ValuesBucket> &valuesBuckets);
    bool UpdateData(const NativeRdb::ValuesBucket &valuesBucket,
        const NativeRdb::AbsRdbPredicates &absRdbPredicates);
    bool DeleteData(const NativeRdb::AbsRdbPredicates &absRdbPredicates);
    std::shared_ptr<NativeRdb::ResultSet> QueryData(
        const NativeRdb::AbsRdbPredicates &absRdbPredicates);
    bool CreateTable();
    void DelayCloseRdbStore();
    std::shared_ptr<NativeRdb::ResultSet> QueryByStep(
        const NativeRdb::AbsRdbPredicates &absRdbPredicates);

    bool UpdateOrInsertData(
        const NativeRdb::ValuesBucket &valuesBucket, const NativeRdb::AbsRdbPredicates &absRdbPredicates);

    void BackupRdb();

    bool RdbIntegrityCheckNeedRestore();

    void CheckSystemSizeAndHisysEvent(const std::string &path, const std::string &fileName);

    bool CheckIsSatisfyTime();

    void SendDbErrorEvent(const std::string &dbName, int32_t operationType, int32_t errorCode);
private:
    std::shared_ptr<NativeRdb::RdbStore> GetRdbStore();
    void GetRdbStoreFromNative();
    int32_t InsertWithRetry(std::shared_ptr<NativeRdb::RdbStore> rdbStore, int64_t &rowId,
        const NativeRdb::ValuesBucket &valuesBucket);
    bool IsRetryErrCode(int32_t errCode);
    bool isInitial_ = false;
    std::mutex rdbMutex_;

    static std::mutex restoreRdbMutex_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;

    BmsRdbConfig bmsRdbConfig_;
    std::shared_ptr<SingleDelayedTaskMgr> delayedTaskMgr_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_RDB_DATA_MANAGER_H
