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

#include "on_demand_install_data_storage_rdb.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* PRE_BUNDLE_RDB_TABLE_NAME = "pre_on_demand_install_bundle";
}
OnDemandInstallDataStorageRdb::OnDemandInstallDataStorageRdb()
{
    APP_LOGI("OnDemandInstallRdb created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = PRE_BUNDLE_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

OnDemandInstallDataStorageRdb::~OnDemandInstallDataStorageRdb()
{
    APP_LOGI("OnDemandInstallRdb destroyed");
}

bool OnDemandInstallDataStorageRdb::SaveOnDemandInstallBundleInfo(
    const PreInstallBundleInfo &preInstallBundleInfo)
{
    if (preInstallBundleInfo.GetBundleName().empty()) {
        APP_LOGE("Save failed due to key is empty");
        return false;
    }

    bool ret = rdbDataManager_->InsertData(
        preInstallBundleInfo.GetBundleName(), preInstallBundleInfo.ToString());
    APP_LOGD("SaveOnDemandInstallBundleInfo %{public}d", ret);
    return ret;
}

bool OnDemandInstallDataStorageRdb::DeleteOnDemandInstallBundleInfo(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("Delete failed due to bundleName is empty");
        return false;
    }

    bool ret = rdbDataManager_->DeleteData(bundleName);
    APP_LOGD("DeleteOnDemandInstallBundleInfo %{public}d", ret);
    return ret;
}

bool OnDemandInstallDataStorageRdb::GetOnDemandInstallBundleInfo(const std::string &bundleName,
    PreInstallBundleInfo &preInstallBundleInfo)
{
    if (bundleName.empty()) {
        APP_LOGE("Query failed due to key is empty");
        return false;
    }

    std::string value;
    bool ret = rdbDataManager_->QueryData(bundleName, value);
    if (!ret) {
        APP_LOGE("GetOnDemandInstallBundleInfo QueryData failed");
        return ret;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_discarded() || (preInstallBundleInfo.FromJson(jsonObject) != ERR_OK)) {
        APP_LOGE("error key : %{public}s", bundleName.c_str());
        return false;
    }
    return ret;
}

bool OnDemandInstallDataStorageRdb::GetAllOnDemandInstallBundleInfos(
    std::vector<PreInstallBundleInfo> &preInstallBundleInfos)
{
    APP_LOGI_NOFUNC("Load all onDemandInstall bundle to vector");
    std::map<std::string, std::string> datas;
    if (!rdbDataManager_->QueryAllData(datas)) {
        APP_LOGE("QueryAllData failed");
        return false;
    }

    TransformStrToInfo(datas, preInstallBundleInfos);
    return !preInstallBundleInfos.empty();
}

void OnDemandInstallDataStorageRdb::TransformStrToInfo(
    const std::map<std::string, std::string> &datas,
    std::vector<PreInstallBundleInfo> &preInstallBundleInfos)
{
    APP_LOGD("TransformStrToInfo start");
    std::map<std::string, PreInstallBundleInfo> updateInfos;
    for (const auto &data : datas) {
        PreInstallBundleInfo preInstallBundleInfo;
        nlohmann::json jsonObject = nlohmann::json::parse(data.second, nullptr, false);
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
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS