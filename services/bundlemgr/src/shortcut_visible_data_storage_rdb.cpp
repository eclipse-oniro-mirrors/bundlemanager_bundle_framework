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
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string SHORTCUT_ID = "SHORTCUT_ID";
const std::string USER_ID = "USER_ID";
const std::string APP_INDEX = "APP_INDEX";
const std::string VISIBLE = "VISIBLE";
const std::string SHORTCUT_VISIBLE_RDB_TABLE_NAME = "shortcut_visible";
const int32_t VISIBLE_INDEX = 4;
}
ShortcutVisibleDataStorageRdb::ShortcutVisibleDataStorageRdb()
{
    APP_LOGI("ShortcutVisibleDataStorageRdb instance is created");
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
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

ShortcutVisibleDataStorageRdb::~ShortcutVisibleDataStorageRdb()
{
    APP_LOGI("ShortcutVisibleDataStorageRdb instance is destroyed");
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
}
}