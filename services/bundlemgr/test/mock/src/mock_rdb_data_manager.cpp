/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
}

RdbDataManager::RdbDataManager(const BmsRdbConfig &bmsRdbConfig)
    : bmsRdbConfig_(bmsRdbConfig) {}

RdbDataManager::~RdbDataManager() {}

void RdbDataManager::ClearCache()
{
    NativeRdb::RdbHelper::ClearCache();
}

std::shared_ptr<NativeRdb::RdbStore> RdbDataManager::GetRdbStore()
{
    return nullptr;
}

bool RdbDataManager::InsertData(const std::string &key, const std::string &value)
{
    return false;
}

bool RdbDataManager::InsertData(const NativeRdb::ValuesBucket &valuesBucket)
{
    return false;
}

bool RdbDataManager::BatchInsert(int64_t &outInsertNum, const std::vector<NativeRdb::ValuesBucket> &valuesBuckets)
{
    return false;
}

bool RdbDataManager::UpdateData(const std::string &key, const std::string &value)
{
    return false;
}

bool RdbDataManager::UpdateData(
    const NativeRdb::ValuesBucket &valuesBucket, const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    return false;
}

bool RdbDataManager::DeleteData(const std::string &key)
{
    return false;
}

bool RdbDataManager::DeleteData(const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    return false;
}

bool RdbDataManager::QueryData(const std::string &key, std::string &value)
{
    return false;
}

std::shared_ptr<NativeRdb::ResultSet> RdbDataManager::QueryData(
    const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    return nullptr;
}

bool RdbDataManager::QueryAllData(std::map<std::string, std::string> &datas)
{
    return false;
}

bool RdbDataManager::CreateTable()
{
    return false;
}

std::shared_ptr<NativeRdb::ResultSet> RdbDataManager::QueryByStep(
    const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    return nullptr;
}
}  // namespace AppExecFwk
}  // namespace OHOS
