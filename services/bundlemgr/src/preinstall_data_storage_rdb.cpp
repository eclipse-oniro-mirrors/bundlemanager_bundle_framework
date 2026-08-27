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

#include "preinstall_data_storage_rdb.h"

#include "dual_mode_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* PRE_BUNDLE_RDB_TABLE_NAME = "preinstalled_bundle";

// The RDB key for a PreInstallBundleInfo: the clone-prefixed name for the secondary variant
// (IsDualModeCloneApp=true) so primary and secondary are two independent rows, the original name
// otherwise. The value's bundleName field stays the original (app real name).
std::string GetPreInstallStorageKey(const PreInstallBundleInfo &info)
{
    std::string bundleName = info.GetBundleName();
    if (bundleName.empty()) {
        return bundleName;
    }
    return info.IsDualModeCloneApp() ? DualModeHelper::GetDualModeBundleName(bundleName) : bundleName;
}
}
PreInstallDataStorageRdb::PreInstallDataStorageRdb()
{
    APP_LOGI("PreInstallDataStorageRdb instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = PRE_BUNDLE_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

PreInstallDataStorageRdb::~PreInstallDataStorageRdb()
{
    APP_LOGI("PreInstallDataStorageRdb instance is destroyed");
}

bool PreInstallDataStorageRdb::LoadAllPreInstallBundleInfos(
    std::vector<PreInstallBundleInfo> &preInstallBundleInfos)
{
    APP_LOGI_NOFUNC("Load all prebundle data to vector");
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    std::map<std::string, std::string> datas;
    if (!rdbDataManager_->QueryAllData(datas)) {
        APP_LOGE("QueryAllData failed");
        return false;
    }

    TransformStrToInfo(datas, preInstallBundleInfos);
    return !preInstallBundleInfos.empty();
}

void PreInstallDataStorageRdb::TransformStrToInfo(
    const std::map<std::string, std::string> &datas,
    std::vector<PreInstallBundleInfo> &preInstallBundleInfos)
{
    APP_LOGD("TransformStrToInfo start");
    if (rdbDataManager_ == nullptr || datas.empty()) {
        APP_LOGE("data is null");
        return;
    }

    std::map<std::string, PreInstallBundleInfo> updateInfos;
    for (const auto &data : datas) {
        PreInstallBundleInfo preInstallBundleInfo;
        nlohmann::json jsonObject = nlohmann::json::parse(data.second, nullptr, false, true);
        if (jsonObject.is_discarded()) {
            APP_LOGE("Error key: %{public}s", data.first.c_str());
            rdbDataManager_->DeleteData(data.first);
            continue;
        }

        if (preInstallBundleInfo.FromJson(jsonObject) != ERR_OK) {
            APP_LOGE("Error key: %{public}s", data.first.c_str());
            rdbDataManager_->DeleteData(data.first);
            continue;
        }

        preInstallBundleInfos.emplace_back(preInstallBundleInfo);
        // database update: only fix records whose key drifted from the value's bundleName. Dual-mode
        // secondary records are keyed by the clone-prefixed name by design (key != value.bundleName),
        // so skip them — re-saving would be a no-op (same derived key) and a failed re-save would
        // wrongly delete the record.
        std::string key = data.first;
        if (key != preInstallBundleInfo.GetBundleName() && !preInstallBundleInfo.IsDualModeCloneApp()) {
            updateInfos.emplace(key, preInstallBundleInfo);
        }
    }

    if (updateInfos.size() > 0) {
        UpdateDataBase(updateInfos);
    }
}

void PreInstallDataStorageRdb::UpdateDataBase(
    std::map<std::string, PreInstallBundleInfo> &infos)
{
    APP_LOGD("Begin to update preInstall database");
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return;
    }

    for (const auto& item : infos) {
        if (!SavePreInstallStorageBundleInfo(item.second)) {
            rdbDataManager_->DeleteData(item.first);
        }
    }
    APP_LOGD("Update preInstall database done");
}

bool PreInstallDataStorageRdb::SavePreInstallStorageBundleInfo(
    const PreInstallBundleInfo &preInstallBundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    if (preInstallBundleInfo.GetBundleName().empty()) {
        APP_LOGE("Save failed due to key is empty");
        return false;
    }

    bool ret = rdbDataManager_->InsertData(
        GetPreInstallStorageKey(preInstallBundleInfo), preInstallBundleInfo.ToString());
    APP_LOGD("SavePreInstallStorageBundleInfo %{public}d", ret);
    return ret;
}

bool PreInstallDataStorageRdb::DeletePreInstallStorageBundleInfo(
    const PreInstallBundleInfo &preInstallBundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    if (preInstallBundleInfo.GetBundleName().empty()) {
        APP_LOGE("Delete failed due to key is empty");
        return false;
    }

    bool ret = rdbDataManager_->DeleteData(GetPreInstallStorageKey(preInstallBundleInfo));
    APP_LOGD("DeletePreInstallStorageBundleInfo %{public}d", ret);
    return ret;
}

bool PreInstallDataStorageRdb::LoadPreInstallBundleInfo(const std::string &bundleName,
    PreInstallBundleInfo &preInstallBundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    if (bundleName.empty()) {
        APP_LOGE("Query failed due to key is empty");
        return false;
    }

    std::string value;
    bool ret = rdbDataManager_->QueryData(bundleName, value);
    if (!ret) {
        APP_LOGE_NOFUNC("LoadPreInstallBundleInfo QueryData failed");
        return ret;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false, true);
    if (jsonObject.is_discarded() || (preInstallBundleInfo.FromJson(jsonObject) != ERR_OK)) {
        APP_LOGE("error key : %{public}s", bundleName.c_str());
        return false;
    }
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS