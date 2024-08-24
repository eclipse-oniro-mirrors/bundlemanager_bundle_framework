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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_RDB_DATA_MANAGER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_RDB_DATA_MANAGER_H

#include <mutex>

#include "bms_rdb_config.h"
#include "bms_rdb_open_callback.h"
#include "rdb_helper.h"

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
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryData(
        const NativeRdb::AbsRdbPredicates &absRdbPredicates);
    bool CreateTable();
    void DelayCloseRdbStore();
    std::shared_ptr<NativeRdb::ResultSet> QueryByStep(
        const NativeRdb::AbsRdbPredicates &absRdbPredicates);

    bool UpdateOrInsertData(
        const NativeRdb::ValuesBucket &valuesBucket, const NativeRdb::AbsRdbPredicates &absRdbPredicates);

    void BackupRdb();

    void CheckSystemSizeAndHisysEvent(const std::string &path, const std::string &fileName);
private:
    std::shared_ptr<NativeRdb::RdbStore> GetRdbStore();
    std::mutex rdbMutex_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    bool isInitial_ = false;

    static std::mutex restoreRdbMutex_;

    BmsRdbConfig bmsRdbConfig_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_RDB_DATA_MANAGER_H
