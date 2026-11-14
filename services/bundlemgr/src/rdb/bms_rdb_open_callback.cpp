/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "bms_rdb_open_callback.h"

#include "app_log_wrapper.h"
#include "event_report.h"

namespace OHOS {
namespace AppExecFwk {
BmsRdbOpenCallback::BmsRdbOpenCallback(const BmsRdbConfig &bmsRdbConfig)\
    : bmsRdbConfig_(bmsRdbConfig) {}

int32_t BmsRdbOpenCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    APP_LOGI("OnCreate");
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    APP_LOGI("OnUpgrade currentVersion: %{public}d, targetVersion: %{public}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::OnDowngrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    APP_LOGI("OnDowngrade  currentVersion: %{public}d, targetVersion: %{public}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    APP_LOGI_NOFUNC("rdb open");
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::onCorruption(std::string databaseFile)
{
    // the rdb framework detected the corruption by itself: this is the earliest
    // db abnormal signal, report it to the DB_ERROR fault channel
    APP_LOGW("onCorruption, databaseFile:%{private}s", databaseFile.c_str());
    EventReport::SendDbErrorEvent(bmsRdbConfig_.dbName,
        static_cast<int32_t>(DB_OPERATION_TYPE::CORRUPT), NativeRdb::E_SQLITE_CORRUPT);
    return NativeRdb::E_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
