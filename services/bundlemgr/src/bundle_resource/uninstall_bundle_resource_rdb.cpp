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

#include "uninstall_bundle_resource_rdb.h"

#include "exception_util.h"
#include "json_util.h"
#include "nlohmann/json.hpp"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_resource_constants.h"
#include "bundle_resource_param.h"
#include "bundle_service_constants.h"
#include "hitrace_meter.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t INDEX_NAME = 0;
constexpr int32_t INDEX_USERID = 1;
constexpr int32_t INDEX_APPINDEX = 2;
constexpr int32_t INDEX_LABEL = 3;
constexpr int32_t INDEX_ICON = 4;
constexpr int32_t INDEX_FOREGROUND = 5;
constexpr int32_t INDEX_BACKGROUND = 6;
constexpr const char* DEFAULT_LANGUAGE = "zh-Hans";
}

UninstallBundleResourceRdb::UninstallBundleResourceRdb()
{
    APP_LOGI_NOFUNC("UninstallBundleResourceRdb create");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;  // bmsdb.db
    bmsRdbConfig.dbPath = ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH;
    bmsRdbConfig.tableName = BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string(BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB)
        + "(NAME TEXT NOT NULL, USER_ID INTEGER, APP_INDEX INTEGER, LABEL TEXT, ICON TEXT, "
        + "FOREGROUND BLOB, BACKGROUND BLOB, PRIMARY KEY (NAME, USER_ID, APP_INDEX));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();

    // Old database configuration (bundleresource.db)
    BmsRdbConfig oldBmsRdbConfig;
    oldBmsRdbConfig.dbName = BundleResourceConstants::BUNDLE_RESOURCE_RDB_NAME;  // bundleResource.db
    oldBmsRdbConfig.dbPath = BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH;
    oldBmsRdbConfig.tableName = BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB;
    oldRdbDataManager_ = std::make_shared<RdbDataManager>(oldBmsRdbConfig);
}

UninstallBundleResourceRdb::~UninstallBundleResourceRdb()
{
}

std::map<std::string, std::string> UninstallBundleResourceRdb::FromString(const std::string &labels)
{
    std::map<std::string, std::string> labelMap;
    nlohmann::json jsonObject = nlohmann::json::parse(labels, nullptr, false, true);
    if (jsonObject.is_discarded()) {
        APP_LOGE("failed parse labels: %{public}s", labels.c_str());
        return labelMap;
    }
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(jsonObject, jsonObjectEnd,
        BundleResourceConstants::LABEL, labelMap, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read labelMap jsonObject error : %{public}d", parseResult);
        return labelMap;
    }
    return labelMap;
}

std::string UninstallBundleResourceRdb::ToString(const std::map<std::string, std::string> &labelMap)
{
    nlohmann::json json;
    json[BundleResourceConstants::LABEL] = labelMap;
    std::string result;
    if (!ExceptionUtil::GetInstance().SafeDump(json, result)) {
        APP_LOGE_NOFUNC("SafeDump failed");
        return Constants::EMPTY_STRING;
    }
    return result;
}

bool UninstallBundleResourceRdb::AddUninstallBundleResource(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex,
    const std::map<std::string, std::string> &labelMap, const BundleResourceInfo &bundleResourceInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (bundleName.empty()) {
        APP_LOGE("failed, bundleName is empty");
        return false;
    }

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BundleResourceConstants::NAME, bundleName);
    valuesBucket.PutInt(BundleResourceConstants::USER_ID, userId);
    valuesBucket.PutInt(BundleResourceConstants::APP_INDEX, appIndex);
    valuesBucket.PutString(BundleResourceConstants::LABEL, ToString(labelMap));
    valuesBucket.PutString(BundleResourceConstants::ICON, bundleResourceInfo.icon);
    valuesBucket.PutBlob(BundleResourceConstants::FOREGROUND, bundleResourceInfo.foreground);
    valuesBucket.PutBlob(BundleResourceConstants::BACKGROUND, bundleResourceInfo.background);
    if (!rdbDataManager_->InsertData(valuesBucket)) {
        APP_LOGE("-n %{public}s -u %{public}d -i %{public}d add uninstall resource failed",
            bundleName.c_str(), userId, appIndex);
        return false;
    }
    return true;
}

bool UninstallBundleResourceRdb::DeleteUninstallBundleResource(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (bundleName.empty()) {
        APP_LOGE("failed, bundleName is empty");
        return false;
    }
    APP_LOGD("need delete resource info, -n %{public}s, -u %{public}d, -i %{public}d",
        bundleName.c_str(), userId, appIndex);
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, bundleName);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    absRdbPredicates.EqualTo(BundleResourceConstants::APP_INDEX, appIndex);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGW("delete -n %{public}s, -u %{public}d, -i %{public}d failed", bundleName.c_str(), userId, appIndex);
        return false;
    }
    return true;
}

bool UninstallBundleResourceRdb::DeleteUninstallBundleResourceForUser(const int32_t userId)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    APP_LOGD("need delete resource info -u %{public}d", userId);
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGW("delete -u %{public}d failed", userId);
        return false;
    }
    return true;
}

bool UninstallBundleResourceRdb::GetUninstallBundleResource(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex, const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (bundleName.empty()) {
        APP_LOGE("failed, bundleName is empty");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, bundleName);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    absRdbPredicates.EqualTo(BundleResourceConstants::APP_INDEX, appIndex);
    auto absSharedResultSet = rdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("QueryByStep failed -n %{public}s, -u %{public}d, -i %{public}d failed", bundleName.c_str(),
            userId, appIndex);
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return QueryFromOldTable(bundleName, userId, appIndex, flags, bundleResourceInfo);
    }
    return ConvertToBundleResourceInfo(absSharedResultSet, flags, BundleResourceParam::GetSystemLocale(),
        bundleResourceInfo);
}

bool UninstallBundleResourceRdb::GetAllUninstallBundleResource(
    const int32_t userId, const uint32_t flags, std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    auto absSharedResultSet = rdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("get all uninstall resource failed -u %{public}d", userId);
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_ROW_OUT_RANGE) {
        APP_LOGI_NOFUNC("no uninstall bundle resource in rdb -u %{public}d", userId);
        return true;
    }
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GoToFirstRow failed, ret %{public}d");
    std::string language = BundleResourceParam::GetSystemLocale();
    do {
        BundleResourceInfo bundleResourceInfo;
        if (ConvertToBundleResourceInfo(absSharedResultSet, flags, language, bundleResourceInfo)) {
            bundleResourceInfos.emplace_back(bundleResourceInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    APP_LOGI_NOFUNC("rdb get all uninstall resource end -u %{public}d size%{public}zu",
        userId, bundleResourceInfos.size());
    return true;
}

bool UninstallBundleResourceRdb::ConvertToBundleResourceInfo(
    const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet,
    const uint32_t flags,
    const std::string &language,
    BundleResourceInfo &bundleResourceInfo)
{
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is nullptr");
        return false;
    }
    auto ret = absSharedResultSet->GetString(INDEX_NAME, bundleResourceInfo.bundleName);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString name failed, ret: %{public}d");

    ret = absSharedResultSet->GetInt(INDEX_APPINDEX, bundleResourceInfo.appIndex);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString name failed, ret: %{public}d");

    bool getAll = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    bool getLabel = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL);
    if (getAll || getLabel) {
        std::string label;
        ret = absSharedResultSet->GetString(INDEX_LABEL, label);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString label failed, ret: %{public}d");
        bundleResourceInfo.label = GetAvailableLabel(bundleResourceInfo.bundleName, language, label);
    }
    bool getIcon = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
    if (getAll || getIcon) {
        ret = absSharedResultSet->GetString(INDEX_ICON, bundleResourceInfo.icon);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString icon failed, ret: %{public}d");
        if (bundleResourceInfo.icon.empty()) {
            APP_LOGW("-n %{public}s icon is empty", bundleResourceInfo.bundleName.c_str());
            return false;
        }
    }
    bool getDrawable = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
    if (getDrawable) {
        ret = absSharedResultSet->GetBlob(INDEX_FOREGROUND, bundleResourceInfo.foreground);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetBlob foreground, ret: %{public}d");
        if (bundleResourceInfo.foreground.empty()) {
            APP_LOGW("-n %{public}s foreground is empty", bundleResourceInfo.bundleName.c_str());
            return false;
        }
        ret = absSharedResultSet->GetBlob(INDEX_BACKGROUND, bundleResourceInfo.background);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetBlob background, ret: %{public}d");
    }
    return true;
}

std::string UninstallBundleResourceRdb::GetAvailableLabel(const std::string &bundleName, const std::string &language,
    const std::string &labels)
{
    std::map<std::string, std::string> labelMap = FromString(labels);
    auto iter = labelMap.find(language);
    if (iter != labelMap.end()) {
        return iter->second;
    }
    iter = labelMap.find(DEFAULT_LANGUAGE);
    if (iter != labelMap.end()) {
        return iter->second;
    }
    APP_LOGW("-n %{public}s -l %{public}s label not exist", bundleName.c_str(), language.c_str());
    return bundleName;
}

bool UninstallBundleResourceRdb::MigrateData()
{
    APP_LOGI_NOFUNC("MigrateData start");

    if (oldRdbDataManager_ == nullptr) {
        APP_LOGE("oldRdbDataManager_ is nullptr");
        return false;
    }

    // Query all data from old table
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB);
    auto absSharedResultSet = oldRdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGW_NOFUNC("Old table may not exist, skip migration");
        return true;
    }

    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_ROW_OUT_RANGE) {
        APP_LOGI_NOFUNC("No data in old table, skip migration");
        absSharedResultSet->Close();
        return true;
    }
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        absSharedResultSet->Close();
        return false;
    }

    int32_t migratedCount = 0;
    bool res = true;
    do {
        std::string name;
        int32_t userId = 0;
        int32_t appIndex = 0;
        std::string label;
        std::string icon;
        std::vector<uint8_t> foreground;
        std::vector<uint8_t> background;

        auto result = absSharedResultSet->GetString(INDEX_NAME, name);
        if (result != NativeRdb::E_OK) {
            APP_LOGW("Failed to get NAME, ret: %{public}d", result);
            continue;
        }

        result = absSharedResultSet->GetInt(INDEX_APPINDEX, appIndex);
        if (result != NativeRdb::E_OK) {
            APP_LOGW("Failed to get APP_INDEX, ret: %{public}d", result);
            continue;
        }

        result = absSharedResultSet->GetInt(INDEX_USERID, userId);  // USER_ID is at index 1
        if (result != NativeRdb::E_OK) {
            APP_LOGW("Failed to get USER_ID, ret: %{public}d", result);
            continue;
        }

        // Get optional fields
        absSharedResultSet->GetString(INDEX_LABEL, label);
        absSharedResultSet->GetString(INDEX_ICON, icon);
        absSharedResultSet->GetBlob(INDEX_FOREGROUND, foreground);
        absSharedResultSet->GetBlob(INDEX_BACKGROUND, background);

        // Insert into new table
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(BundleResourceConstants::NAME, name);
        valuesBucket.PutInt(BundleResourceConstants::USER_ID, userId);
        valuesBucket.PutInt(BundleResourceConstants::APP_INDEX, appIndex);
        valuesBucket.PutString(BundleResourceConstants::LABEL, label);
        valuesBucket.PutString(BundleResourceConstants::ICON, icon);
        valuesBucket.PutBlob(BundleResourceConstants::FOREGROUND, foreground);
        valuesBucket.PutBlob(BundleResourceConstants::BACKGROUND, background);

        if (!rdbDataManager_->InsertData(valuesBucket)) {
            APP_LOGW("Insert data failed for -n %{public}s -u %{public}d -i %{public}d",
                name.c_str(), userId, appIndex);
            res = false;
        } else {
            migratedCount++;
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    absSharedResultSet->Close();
    APP_LOGI_NOFUNC("MigrateData success, migrated %{public}d rows", migratedCount);
    return res;
}

bool UninstallBundleResourceRdb::DeleteTable()
{
    APP_LOGI_NOFUNC("drop old uninstall resource table");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = BundleResourceConstants::BUNDLE_RESOURCE_RDB_NAME;
    bmsRdbConfig.dbPath = BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH;
    bmsRdbConfig.tableName = BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB;
    bmsRdbConfig.insertColumnSql.push_back(
        "DROP TABLE IF EXISTS " + std::string(BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB));
    auto deleteRdbManager = std::make_shared<RdbDataManager>(bmsRdbConfig);
    return deleteRdbManager->ExecuteSql();
}

bool UninstallBundleResourceRdb::QueryFromOldTable(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex, const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, bundleName);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    absRdbPredicates.EqualTo(BundleResourceConstants::APP_INDEX, appIndex);
    auto absSharedResultSet = oldRdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("Query from old table failed -n %{public}s", bundleName.c_str());
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGW("Old table query failed, ret: %{public}d", ret);
        return false;
    }
    return ConvertToBundleResourceInfo(absSharedResultSet, flags,
        BundleResourceParam::GetSystemLocale(), bundleResourceInfo);
}

bool UninstallBundleResourceRdb::QueryAllFromOldTable(
    const int32_t userId, const uint32_t flags, std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::UINSTALL_BUNDLE_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::USER_ID, userId);
    auto absSharedResultSet = oldRdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("get all from old table failed -u %{public}d", userId);
        return true;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_ROW_OUT_RANGE) {
        APP_LOGI_NOFUNC("no data in old table -u %{public}d", userId);
        return true;
    }
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return true;
    }

    std::string language = BundleResourceParam::GetSystemLocale();
    do {
        BundleResourceInfo bundleResourceInfo;
        if (ConvertToBundleResourceInfo(absSharedResultSet, flags, language, bundleResourceInfo)) {
            bundleResourceInfos.emplace_back(bundleResourceInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    APP_LOGI_NOFUNC("get all from old table end -u %{public}d size%{public}zu",
                    userId, bundleResourceInfos.size());
    return true;
}
} // AppExecFwk
} // OHOS
