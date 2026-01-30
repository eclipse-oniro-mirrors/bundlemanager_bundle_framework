/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "shortcut_enabled_data_storage_rdb.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string SHORTCUT_ID = "SHORTCUT_ID";
const std::string ENABLED = "ENABLED";
const std::string SHORTCUT_ENABLED_RDB_TABLE_NAME = "shortcut_enabled";
const int32_t SHORTCUT_ID_INDEX = 0;
const int32_t ENABLED_INDEX = 2;
}
ShortcutEnabledDataStorageRdb::ShortcutEnabledDataStorageRdb()
{
    APP_LOGI_NOFUNC("ShortcutEnabledDataStorageRdb instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = SHORTCUT_ENABLED_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + SHORTCUT_ENABLED_RDB_TABLE_NAME
        + "(SHORTCUT_ID TEXT NOT NULL, "
        + "BUNDLE_NAME TEXT NOT NULL, "
        + "ENABLED INTEGER NOT NULL, "
        + "PRIMARY KEY (SHORTCUT_ID, BUNDLE_NAME));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

ShortcutEnabledDataStorageRdb::~ShortcutEnabledDataStorageRdb()
{
    APP_LOGI_NOFUNC("ShortcutEnabledDataStorageRdb instance is destroyed");
}

bool ShortcutEnabledDataStorageRdb::SaveStorageShortcutEnabledInfos(const std::vector<ShortcutInfo> shortcutInfos,
    bool isEnabled)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    int32_t isEnabledValue = isEnabled ? 1 : 0;
    for (const auto &shortcutInfo : shortcutInfos) {
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(BUNDLE_NAME, shortcutInfo.bundleName);
        valuesBucket.PutString(SHORTCUT_ID, shortcutInfo.id);
        valuesBucket.PutInt(ENABLED, isEnabledValue);
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    bool ret = rdbDataManager_->BatchInsert(insertNum, valuesBuckets);
    if (!ret) {
        APP_LOGE("BatchInsert failed");
        return false;
    }
    if (valuesBuckets.size() != static_cast<uint64_t>(insertNum)) {
        APP_LOGE("BatchInsert size not expected");
        return false;
    }
    return true;
}

bool ShortcutEnabledDataStorageRdb::DeleteShortcutEnabledInfo(const std::string &bundleName)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_ENABLED_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    APP_LOGD("DeleteShortcutEnabledInfo by bundleName %{public}d", ret);
    return ret;
}

bool ShortcutEnabledDataStorageRdb::DeleteShortcutEnabledInfo(
    const std::string &bundleName, const std::vector<std::string> &shortcutIdList)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (shortcutIdList.empty()) {
        APP_LOGD("no need to delete");
        return true;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_ENABLED_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.In(SHORTCUT_ID, shortcutIdList);
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    APP_LOGD("DeleteShortcutEnabledInfo by bundleName and ids %{public}d", ret);
    return ret;
}

void ShortcutEnabledDataStorageRdb::FilterShortcutInfosEnabled(
    const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfos) const
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_ENABLED_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(ENABLED, 0);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is null");
        return;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    if (absSharedResultSet->GoToFirstRow() != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed");
        return;
    }
    std::set<std::string> shortcutIdSet;
    do {
        std::string shortcutId;
        if (absSharedResultSet->GetString(SHORTCUT_ID_INDEX, shortcutId) != NativeRdb::E_OK) {
            APP_LOGE("GetString shortcutId failed");
            return;
        }
        shortcutIdSet.insert(shortcutId);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    shortcutInfos.erase(std::remove_if(shortcutInfos.begin(), shortcutInfos.end(),
        [&shortcutIdSet](const ShortcutInfo &s) { return shortcutIdSet.count(s.id) > 0; }), shortcutInfos.end());
    return;
}

ErrCode ShortcutEnabledDataStorageRdb::GetShortcutEnabledStatus(
    const std::string &bundleName, const std::string &shortcutId, bool &isEnabled) const
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_ENABLED_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(SHORTCUT_ID, shortcutId);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is null, bundleName: %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetRowCount failed, bundleName: %{public}s, ret: %{public}d", bundleName.c_str(), ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        APP_LOGD("count size 0");
        isEnabled = true;
        return ERR_OK;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, bundleName: %{public}s, ret: %{public}d", bundleName.c_str(), ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }

    int32_t value;
    ret = absSharedResultSet->GetInt(ENABLED_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetInt failed, bundleName: %{public}s, ret: %{public}d", bundleName.c_str(), ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    isEnabled = value == 1;
    return ERR_OK;
}

bool ShortcutEnabledDataStorageRdb::UpdateShortcutEnabledInfo(const std::string &bundleName,
    const std::vector<ShortcutInfo> &shortcutInfos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_ENABLED_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is null.");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    int32_t count = 0;
    if (absSharedResultSet->GetRowCount(count) != NativeRdb::E_OK) {
        APP_LOGE("GetRowCount failed");
        return false;
    }
    if (count == 0) {
        APP_LOGD("%{public}s not need to update shortCut", bundleName.c_str());
        return true;
    }
    APP_LOGI_NOFUNC("rdb UpdateShortcutEnabledInfo -n %{public}s", bundleName.c_str());
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return false;
    }
    std::vector<std::string> shortcutIdList;
    do {
        std::string shortcutId;
        if (absSharedResultSet->GetString(SHORTCUT_ID_INDEX, shortcutId) != NativeRdb::E_OK) {
            APP_LOGE("GetString shortcutId failed");
            continue;
        }
        auto iter = std::find_if(shortcutInfos.begin(), shortcutInfos.end(),
            [ &shortcutId ](const ShortcutInfo &info) {
            return info.id == shortcutId;
        });
        if (iter == shortcutInfos.end()) {
            APP_LOGW("shortcut %{public}s not exist", shortcutId.c_str());
            shortcutIdList.emplace_back(shortcutId);
            continue;
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return DeleteShortcutEnabledInfo(bundleName, shortcutIdList);
}
}
}