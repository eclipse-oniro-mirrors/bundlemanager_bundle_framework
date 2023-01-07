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

#include "bms_rdb_open_callback.h"

#include "app_log_wrapper.h"

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
    APP_LOGI("OnUpgrade currentVersion: %{plubic}d, targetVersion: %{plubic}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::OnDowngrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    APP_LOGI("OnDowngrade  currentVersion: %{plubic}d, targetVersion: %{plubic}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    APP_LOGI("OnOpen");
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::onCorruption(std::string databaseFile)
{
    return NativeRdb::E_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
