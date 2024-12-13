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

#include "uninstall_data_mgr_storage_rdb.h"

#include "app_log_wrapper.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* const UNINSTALL_BUNDLE_TABLE_NAME = "uninstall_bundle_info";
const char* const BUNDLENAME = "BUNDLENAME";
const char* const UNINSTALL_BUNDLE_INFO = "UNINSTALL_BUNDLE_INFO";
const int8_t KEY_INDEX = 0;
const int8_t BUNDLE_INFO_INDEX = 1;
}
UninstallDataMgrStorageRdb::UninstallDataMgrStorageRdb()
{
    APP_LOGI("created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = UNINSTALL_BUNDLE_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string{ UNINSTALL_BUNDLE_TABLE_NAME }
        + "(BUNDLENAME TEXT PRIMARY KEY NOT NULL, "
        + "UNINSTALL_BUNDLE_INFO TEXT NOT NULL);");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

UninstallDataMgrStorageRdb::~UninstallDataMgrStorageRdb()
{
    APP_LOGI("~");
}

bool UninstallDataMgrStorageRdb::UpdateUninstallBundleInfo(const std::string &bundleName,
    const UninstallBundleInfo &uninstallbundleInfo)
{
    APP_LOGI("update -n %{public}s", bundleName.c_str());
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("param error");
        return false;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BUNDLENAME, bundleName);
    valuesBucket.PutString(UNINSTALL_BUNDLE_INFO, uninstallbundleInfo.ToString());

    return rdbDataManager_->InsertData(valuesBucket);
}

bool UninstallDataMgrStorageRdb::GetUninstallBundleInfo(const std::string &bundleName,
    UninstallBundleInfo &uninstallbundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("param error");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(UNINSTALL_BUNDLE_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLENAME, bundleName);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGD("GoToFirstRow failed, ret: %{public}d", ret);
        return false;
    }
    std::string value;
    ret = absSharedResultSet->GetString(BUNDLE_INFO_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetString failed, ret: %{public}d", ret);
        return false;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("error key");
        return false;
    }
    from_json(jsonObject, uninstallbundleInfo);
    return true;
}

bool UninstallDataMgrStorageRdb::GetAllUninstallBundleInfo(
    std::map<std::string, UninstallBundleInfo> &uninstallBundleInfos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("null rdbDataManager");
        return false;
    }

    std::map<std::string, std::string> datas;
    if (!rdbDataManager_->QueryAllData(datas)) {
        return false;
    }
    TransformStrToInfo(datas, uninstallBundleInfos);
    return !uninstallBundleInfos.empty();
}

void UninstallDataMgrStorageRdb::TransformStrToInfo(const std::map<std::string, std::string> &datas,
    std::map<std::string, UninstallBundleInfo> &uninstallBundleInfos)
{
    APP_LOGI("start");
    if (rdbDataManager_ == nullptr || datas.empty()) {
        APP_LOGE("null rdbDataManager");
        return;
    }

    for (auto &data : datas) {
        UninstallBundleInfo uninstallBundleInfo;
        nlohmann::json jsonObject = nlohmann::json::parse(data.second, nullptr, false);
        if (jsonObject == nullptr || jsonObject.is_discarded()) {
            APP_LOGE("error key: %{plublic}s", data.first.c_str());
            continue;
        }
        from_json(jsonObject, uninstallBundleInfo);
        uninstallBundleInfos.insert(std::make_pair(data.first, uninstallBundleInfo));
    }
}

bool UninstallDataMgrStorageRdb::DeleteUninstallBundleInfo(const std::string &bundleName)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("param error");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(UNINSTALL_BUNDLE_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLENAME, bundleName);
    return rdbDataManager_->DeleteData(absRdbPredicates);
}
}  // namespace AppExecFwk
}  // namespace OHOS