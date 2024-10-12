/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "shortcut_data_storage_rdb.h"

#include "app_log_wrapper.h"
#include "json_serializer.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string SHORTCUT_RDB_TABLE_NAME = "shortcut_info";
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string SHORTCUT_ID = "SHORTCUT_ID";
const std::string USER_ID = "USER_ID";
const std::string APP_INDEX = "APP_INDEX";
const std::string SHORTCUT_INFO = "SHORTCUT_INFO";
const int32_t SHORTCUT_INFO_INDEX = 5;
}
ShortcutDataStorageRdb::ShortcutDataStorageRdb()
{
    APP_LOGI("ShortcutDataStorageRdb instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = SHORTCUT_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + SHORTCUT_RDB_TABLE_NAME
        + "(ID INTEGER PRIMARY KEY AUTOINCREMENT, BUNDLE_NAME TEXT NOT NULL, "
        + "SHORTCUT_ID TEXT NOT NULL, USER_ID INTEGER, "
        + "APP_INDEX INTEGER, SHORTCUT_INFO TEXT NOT NULL);");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

ShortcutDataStorageRdb::~ShortcutDataStorageRdb()
{
    APP_LOGI("ShortcutDataStorageRdb instance is destroyed");
}

bool ShortcutDataStorageRdb::AddDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId, bool &isIdIllegal)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (!ShortcutIdVerification(shortcutInfo, userId)) {
        APP_LOGD("ShortcutIdVerification is fail");
        isIdIllegal = true;
        return false;
    }
    nlohmann::json jsonObject;
    to_json(jsonObject, shortcutInfo);
    std::string value = jsonObject.dump();
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BUNDLE_NAME, shortcutInfo.bundleName);
    valuesBucket.PutString(SHORTCUT_ID, shortcutInfo.id);
    valuesBucket.PutInt(USER_ID, userId);
    valuesBucket.PutInt(APP_INDEX, shortcutInfo.appIndex);
    valuesBucket.PutString(SHORTCUT_INFO, value);
    bool ret = rdbDataManager_->InsertData(valuesBucket);
    APP_LOGD("AddDesktopShortcutInfo %{public}d", ret);
    return ret;
}

bool ShortcutDataStorageRdb::DeleteDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, shortcutInfo.bundleName);
    absRdbPredicates.EqualTo(SHORTCUT_ID, shortcutInfo.id);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.EqualTo(APP_INDEX, std::to_string(shortcutInfo.appIndex));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    APP_LOGD("DeleteDesktopShortcutInfo %{public}d", ret);
    return ret;
}

void ShortcutDataStorageRdb::GetAllDesktopShortcutInfo(int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is null.");
        return;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return;
    }
    do {
        std::string value;
        ret = absSharedResultSet->GetString(SHORTCUT_INFO_INDEX, value);
        if (ret != NativeRdb::E_OK) {
            APP_LOGE("GetString shortcutInfo failed, ret: %{public}d", ret);
            return;
        }
        nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
        if (jsonObject.is_discarded()) {
            APP_LOGE("Shortcut jsonObject is discarded");
            return;
        }
        ShortcutInfo shortcutInfo;
        from_json(jsonObject, shortcutInfo);
        shortcutInfos.emplace_back(shortcutInfo);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    if (userId != 0) {
        GetDesktopShortcutInfosByDefaultUserId(shortcutInfos);
    }
}

bool ShortcutDataStorageRdb::DeleteDesktopShortcutInfo(const std::string &bundleName)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    APP_LOGD("DeleteDesktopShortcutInfo by bundleName %{public}d", ret);
    return ret;
}

bool ShortcutDataStorageRdb::DeleteDesktopShortcutInfo(const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.EqualTo(APP_INDEX, std::to_string(appIndex));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    APP_LOGD("DeleteDesktopShortcutInfo by remove cloneApp %{public}d", ret);
    return ret;
}

bool ShortcutDataStorageRdb::ShortcutIdVerification(const ShortcutInfo &shortcutInfo, int32_t userId)
{
    if (shortcutInfo.id.empty()) {
        APP_LOGD("ShortcutInfo id is empty");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, shortcutInfo.bundleName);
    absRdbPredicates.EqualTo(SHORTCUT_ID, shortcutInfo.id);
    absRdbPredicates.EqualTo(APP_INDEX, shortcutInfo.appIndex);
    absRdbPredicates.EqualTo(USER_ID, userId);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is null");
        return true;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    int32_t count = 0;
    auto ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetRowCount failed, ret: %{public}d", ret);
        return true;
    }
    if (count == 0) {
        APP_LOGD("GetRowCount count is 0");
        return true;
    }
    return false;
}

void ShortcutDataStorageRdb::GetDesktopShortcutInfosByDefaultUserId(std::vector<ShortcutInfo> &shortcutInfos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_RDB_TABLE_NAME);
    int32_t userId = 0;
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is null.");
        return;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return;
    }
    do {
        std::string value;
        ret = absSharedResultSet->GetString(SHORTCUT_INFO_INDEX, value);
        if (ret != NativeRdb::E_OK) {
            APP_LOGE("GetString shortcutInfo failed, ret: %{public}d", ret);
            return;
        }
        nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
        if (jsonObject.is_discarded()) {
            APP_LOGE("Shortcut jsonObject is discarded");
            return;
        }
        ShortcutInfo shortcutInfo;
        from_json(jsonObject, shortcutInfo);
        shortcutInfos.emplace_back(shortcutInfo);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
}
}  // namespace AppExecFwk
}  // namespace OHOS