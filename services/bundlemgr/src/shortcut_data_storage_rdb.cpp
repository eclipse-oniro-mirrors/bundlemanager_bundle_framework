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
const int32_t BUNDLE_NAME_INDEX = 1;
const int32_t SHORTCUT_ID_INDEX = 2;
const int32_t USER_ID_INDEX = 3;
const int32_t APP_INDEX_INDEX = 4;
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

bool ShortcutDataStorageRdb::GetAllTableDataToJson(nlohmann::json &jsonResult)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_RDB_TABLE_NAME);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is null.");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return false;
    }
    do {
        nlohmann::json rowData;
        std::string bundleName;
        if (absSharedResultSet->GetString(BUNDLE_NAME_INDEX, bundleName) == NativeRdb::E_OK) {
            rowData[BUNDLE_NAME] = bundleName;
        }
        
        std::string shortcutId;
        if (absSharedResultSet->GetString(SHORTCUT_ID_INDEX, shortcutId) == NativeRdb::E_OK) {
            rowData[SHORTCUT_ID] = shortcutId;
        }
        
        int32_t userId = 0;
        if (absSharedResultSet->GetInt(USER_ID_INDEX, userId) == NativeRdb::E_OK) {
            rowData[USER_ID] = userId;
        }
        
        int32_t appIndex = 0;
        if (absSharedResultSet->GetInt(APP_INDEX_INDEX, appIndex) == NativeRdb::E_OK) {
            rowData[APP_INDEX] = appIndex;
        }
        
        std::string shortcutInfoJson;
        if (absSharedResultSet->GetString(SHORTCUT_INFO_INDEX, shortcutInfoJson) == NativeRdb::E_OK) {
            auto jsonObj = nlohmann::json::parse(shortcutInfoJson, nullptr, false);
            if (!jsonObj.is_discarded()) {
                rowData[SHORTCUT_INFO] = jsonObj;
            }
        }
        jsonResult.emplace_back(rowData);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return true;
}

bool ShortcutDataStorageRdb::UpdateAllShortcuts(nlohmann::json &jsonResult)
{
    if (!jsonResult.is_array()) {
        APP_LOGE("Invalid JSON format: expected array");
        return false;
    }
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    bool finalResult = true;
    for (auto& item : jsonResult) {
        NativeRdb::AbsRdbPredicates absRdbPredicates(SHORTCUT_RDB_TABLE_NAME);
        absRdbPredicates.EqualTo(BUNDLE_NAME, item[BUNDLE_NAME].get<std::string>());
        absRdbPredicates.EqualTo(SHORTCUT_ID, item[SHORTCUT_ID].get<std::string>());
        absRdbPredicates.EqualTo(APP_INDEX, item[APP_INDEX].get<int>());
        absRdbPredicates.EqualTo(USER_ID, item[USER_ID].get<int>());

        auto resultSet = rdbDataManager_->QueryData(absRdbPredicates);
        if (resultSet == nullptr) {
            APP_LOGE("resultSet is null.");
            continue;
        }
        ScopeGuard guard([resultSet] { resultSet->Close(); });
        NativeRdb::ValuesBucket bucket;
        bucket.PutString(BUNDLE_NAME, item[BUNDLE_NAME]);
        bucket.PutString(SHORTCUT_ID, item[SHORTCUT_ID]);
        bucket.PutInt(USER_ID, item[USER_ID]);
        bucket.PutInt(APP_INDEX, item[APP_INDEX]);
        bucket.PutString(SHORTCUT_INFO, item[SHORTCUT_INFO].dump());
        if (!rdbDataManager_->UpdateOrInsertData(bucket, absRdbPredicates)) {
            finalResult = false;
        }
    }
    return finalResult;
}
}  // namespace AppExecFwk
}  // namespace OHOS