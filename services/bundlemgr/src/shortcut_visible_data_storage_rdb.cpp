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

#include "shortcut_visible_data_storage_rdb.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "json_serializer.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string SHORTCUT_ID = "SHORTCUT_ID";
const std::string USER_ID = "USER_ID";
const std::string APP_INDEX = "APP_INDEX";
const std::string VISIBLE = "VISIBLE";
const std::string SOURCE_TYPE = "SOURCE_TYPE";
const std::string SHORTCUT_INFO = "SHORTCUT_INFO";
const std::string SHORTCUT_VISIBLE_RDB_TABLE_NAME = "shortcut_visible";
const std::string PORT_SEPARATOR = ":";
const int32_t SHORTCUT_ID_INDEX = 0;
const int32_t VISIBLE_INDEX = 4;
const int32_t SHORTCUT_INFO_INDEX = 6;
const int32_t DYNAMIC_SHORTCUT_TYPE = 2;
}
ShortcutVisibleDataStorageRdb::ShortcutVisibleDataStorageRdb()
{
    APP_LOGI_NOFUNC("ShortcutVisibleDataStorageRdb instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = SHORTCUT_VISIBLE_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + SHORTCUT_VISIBLE_RDB_TABLE_NAME
        + "(SHORTCUT_ID TEXT NOT NULL, "
        + "BUNDLE_NAME TEXT NOT NULL, "
        + "USER_ID INTEGER NOT NULL, "
        + "APP_INDEX INTEGER NOT NULL, "
        + "VISIBLE INTEGER NOT NULL, "
        + "PRIMARY KEY (SHORTCUT_ID, BUNDLE_NAME, USER_ID, APP_INDEX));");
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + SHORTCUT_VISIBLE_RDB_TABLE_NAME +
        " ADD SOURCE_TYPE INTEGER DEFAULT 1;"));
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + SHORTCUT_VISIBLE_RDB_TABLE_NAME +
        " ADD SHORTCUT_INFO TEXT;"));
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

ShortcutVisibleDataStorageRdb::~ShortcutVisibleDataStorageRdb()
{
    APP_LOGI_NOFUNC("ShortcutVisibleDataStorageRdb instance is destroyed");
}

bool ShortcutVisibleDataStorageRdb::IsShortcutVisibleInfoExist(
    const std::string &bundleName, const std::string &shortcutId, int32_t appIndex, int32_t userId, bool visible)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_VISIBLE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(SHORTCUT_ID, shortcutId);
    absRdbPredicates.EqualTo(APP_INDEX, appIndex);
    absRdbPredicates.EqualTo(USER_ID, userId);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is null.");
        return false;
    }
    int32_t visibleValue;
    if (absSharedResultSet->GoToFirstRow() != NativeRdb::E_OK) {
        APP_LOGD("absSharedResultSet GoToFirstRow is null.");
        return false;
    }
    if (absSharedResultSet->GetInt(VISIBLE_INDEX, visibleValue) != NativeRdb::E_OK) {
        APP_LOGE("absSharedResultSet GetInt is null.");
        return false;
    }
    bool visibleResult = visibleValue == 1 ? true : false;
    if (visible == visibleResult) {
        return true;
    }
    return false;
}

bool ShortcutVisibleDataStorageRdb::SaveStorageShortcutVisibleInfo(
    const std::string &bundleName, const std::string &shortcutId, int32_t appIndex, int32_t userId, bool visible)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    int32_t visibleValue = visible ? 1 : 0;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BUNDLE_NAME, bundleName);
    valuesBucket.PutString(SHORTCUT_ID, shortcutId);
    valuesBucket.PutInt(USER_ID, userId);
    valuesBucket.PutInt(APP_INDEX, appIndex);
    valuesBucket.PutInt(VISIBLE, visibleValue);
    bool ret = rdbDataManager_->InsertData(valuesBucket);
    APP_LOGD("SaveStorageShortcutVisibleInfo %{public}d", ret);
    return ret;
}

bool ShortcutVisibleDataStorageRdb::AddDynamicShortcutInfos(
    const std::vector<ShortcutInfo> &shortcutInfos, int32_t userId)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (auto shortcutInfo : shortcutInfos) {
        int32_t visibleValue = shortcutInfo.visible ? 1 : 0;
        nlohmann::json jsonObject;
        to_json(jsonObject, shortcutInfo);
        std::string value = jsonObject.dump();
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(BUNDLE_NAME, shortcutInfo.bundleName);
        valuesBucket.PutString(SHORTCUT_ID, shortcutInfo.id);
        valuesBucket.PutInt(USER_ID, userId);
        valuesBucket.PutInt(APP_INDEX, shortcutInfo.appIndex);
        valuesBucket.PutInt(VISIBLE, visibleValue);
        valuesBucket.PutInt(SOURCE_TYPE, shortcutInfo.sourceType);
        valuesBucket.PutString(SHORTCUT_INFO, value);
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    if (!rdbDataManager_->BatchInsert(insertNum, valuesBuckets)) {
        APP_LOGE("BatchInsert dynamicShortcutInfos failed");
        return false;
    }
    if (valuesBuckets.size() != static_cast<uint64_t>(insertNum)) {
        APP_LOGE("BatchInsert size not expected");
        return false;
    }
    return true;
}

bool ShortcutVisibleDataStorageRdb::DeleteShortcutVisibleInfo(
    const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_VISIBLE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(USER_ID, userId);
    if (appIndex != 0)  {
        absRdbPredicates.EqualTo(APP_INDEX, appIndex);
    }
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    APP_LOGD("DeleteShortcutVisibleInfo %{public}d", ret);
    return ret;
}

bool ShortcutVisibleDataStorageRdb::DeleteDynamicShortcutInfos(const std::string &bundleName, const int32_t appIndex,
    const int32_t userId, const std::vector<std::string> &ids)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_VISIBLE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    if (!ids.empty()) {
        absRdbPredicates.In(SHORTCUT_ID, ids);
    }
    absRdbPredicates.EqualTo(USER_ID, userId);
    absRdbPredicates.EqualTo(APP_INDEX, appIndex);
    absRdbPredicates.EqualTo(SOURCE_TYPE, DYNAMIC_SHORTCUT_TYPE);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGE("DeleteData failed");
        return false;
    }
    return true;
}

void ShortcutVisibleDataStorageRdb::ProcessStaticShortcutInfos(const NativeRdb::AbsRdbPredicates &absRdbPredicatesConst,
    std::vector<ShortcutInfo> &shortcutInfos)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(absRdbPredicatesConst);
    absRdbPredicates.NotEqualTo(SOURCE_TYPE, DYNAMIC_SHORTCUT_TYPE);
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
    std::vector<std::string> deleteIds;
    do {
        std::string shortcutId;
        if (absSharedResultSet->GetString(SHORTCUT_ID_INDEX, shortcutId) != NativeRdb::E_OK) {
            APP_LOGE("GetString shortcutId failed");
            return;
        }
        int32_t visibleValue;
        if (absSharedResultSet->GetInt(VISIBLE_INDEX, visibleValue) != NativeRdb::E_OK) {
            APP_LOGE("GetInt visibleValue failed");
            return;
        }
        bool foundAny = false;
        for (auto &info : shortcutInfos) {
            if (info.id == shortcutId) {
                info.visible = visibleValue == 1 ? true : false;
                foundAny = true;
            }
        }
        if (!foundAny) {
            APP_LOGW("delete invalid static shortcutInfo, id:%{public}s", shortcutId.c_str());
            deleteIds.emplace_back(shortcutId);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    if (!deleteIds.empty()) {
        absRdbPredicates.In(SHORTCUT_ID, deleteIds);
        if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
            APP_LOGE("DeleteData failed");
        }
    }
}

void ShortcutVisibleDataStorageRdb::GetStorageShortcutInfos(const std::string &bundleName, const int32_t appIndex,
    const int32_t userId, std::vector<ShortcutInfo> &shortcutInfos, const bool onlyDynamic)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_VISIBLE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(USER_ID, userId);
    if (appIndex != Constants::ALL_CLONE_APP_INDEX) {
        absRdbPredicates.EqualTo(APP_INDEX, appIndex);
    }
    if (!onlyDynamic) {
        ProcessStaticShortcutInfos(absRdbPredicates, shortcutInfos);
    }
    absRdbPredicates.EqualTo(SOURCE_TYPE, DYNAMIC_SHORTCUT_TYPE);
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
    std::vector<ShortcutInfo> result;
    do {
        std::string value;
        if (absSharedResultSet->GetString(SHORTCUT_INFO_INDEX, value) != NativeRdb::E_OK) {
            APP_LOGE("GetString shortcutInfo failed");
            return;
        }
        nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
        if (jsonObject.is_discarded()) {
            APP_LOGE("Shortcut jsonObject is discarded");
            return;
        }
        ShortcutInfo shortcutInfo;
        from_json(jsonObject, shortcutInfo);
        shortcutInfos.erase(std::remove_if(shortcutInfos.begin(), shortcutInfos.end(),
            [&shortcutInfo](const ShortcutInfo &s) { return s.id == shortcutInfo.id; }), shortcutInfos.end());
        result.emplace_back(shortcutInfo);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    shortcutInfos.insert(shortcutInfos.end(), result.begin(), result.end());
}
}
}