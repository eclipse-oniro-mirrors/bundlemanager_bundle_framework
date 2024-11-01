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

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* PRE_BUNDLE_RDB_TABLE_NAME = "preinstalled_bundle";
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
    APP_LOGI("Load all prebundle data to vector");
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
        nlohmann::json jsonObject = nlohmann::json::parse(data.second, nullptr, false);
        if (jsonObject.is_discarded()) {
            APP_LOGE("Error key: %{plublic}s", data.first.c_str());
            rdbDataManager_->DeleteData(data.first);
            continue;
        }

        if (preInstallBundleInfo.FromJson(jsonObject) != ERR_OK) {
            APP_LOGE("Error key: %{plublic}s", data.first.c_str());
            rdbDataManager_->DeleteData(data.first);
            continue;
        }

        preInstallBundleInfos.emplace_back(preInstallBundleInfo);
        // database update
        std::string key = data.first;
        if (key != preInstallBundleInfo.GetBundleName()) {
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
        preInstallBundleInfo.GetBundleName(), preInstallBundleInfo.ToString());
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

    bool ret = rdbDataManager_->DeleteData(preInstallBundleInfo.GetBundleName());
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
        APP_LOGE("LoadPreInstallBundleInfo QueryData failed");
        return ret;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_discarded() || (preInstallBundleInfo.FromJson(jsonObject) != ERR_OK)) {
        APP_LOGE("error key : %{public}s", bundleName.c_str());
        return false;
    }
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS