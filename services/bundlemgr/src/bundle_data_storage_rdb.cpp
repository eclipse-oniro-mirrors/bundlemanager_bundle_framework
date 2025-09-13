/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "bundle_data_storage_rdb.h"

#include "app_log_tag_wrapper.h"
#include "bundle_exception_handler.h"
#include "event_report.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_RDB_TABLE_NAME = "installed_bundle";
}
BundleDataStorageRdb::BundleDataStorageRdb()
{
    APP_LOGI("BundleDataStorageRdb instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = BUNDLE_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

BundleDataStorageRdb::~BundleDataStorageRdb()
{
    APP_LOGI("BundleDataStorageRdb instance is destroyed");
}

bool BundleDataStorageRdb::LoadAllData(std::map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGI("Load all installed bundle data to map");
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    std::map<std::string, std::string> datas;
    if (!rdbDataManager_->QueryAllData(datas)) {
        APP_LOGE("QueryAllData failed");
        return false;
    }

    TransformStrToInfo(datas, infos);
    return !infos.empty();
}

void BundleDataStorageRdb::TransformStrToInfo(
    const std::map<std::string, std::string> &datas,
    std::map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGI("TransformStrToInfo start");
    if (rdbDataManager_ == nullptr || datas.empty()) {
        APP_LOGE("rdbDataManager is null");
        return;
    }

    std::map<std::string, InnerBundleInfo> updateInfos;
    for (const auto &data : datas) {
        InnerBundleInfo innerBundleInfo;
        nlohmann::json jsonObject = nlohmann::json::parse(data.second, nullptr, false);
        if (jsonObject.is_discarded()) {
            APP_LOGE("Error key: %{public}s", data.first.c_str());
            rdbDataManager_->DeleteData(data.first);
            continue;
        }

        if (innerBundleInfo.FromJson(jsonObject) != ERR_OK) {
            APP_LOGE("Error key: %{public}s", data.first.c_str());
            rdbDataManager_->DeleteData(data.first);
            continue;
        }

        bool isBundleValid = true;
        auto handler = std::make_shared<BundleExceptionHandler>(shared_from_this());
        handler->HandleInvalidBundle(innerBundleInfo, isBundleValid);
        if (!isBundleValid) {
            continue;
        }
        // reset privilege capability when load info from db
        ApplicationInfo applicationInfo;
        innerBundleInfo.UpdatePrivilegeCapability(applicationInfo);
        innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        infos.emplace(innerBundleInfo.GetBundleName(), innerBundleInfo);
        // database update
        std::string key = data.first;
        if (key != innerBundleInfo.GetBundleName()) {
            updateInfos.emplace(key, innerBundleInfo);
        }
    }

    if (updateInfos.size() > 0) {
        UpdateDataBase(updateInfos);
    }
}

void BundleDataStorageRdb::UpdateDataBase(std::map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGD("Begin to update database");
    EventReport::ReportDataPartitionUsageEvent();
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return;
    }

    for (const auto& item : infos) {
        if (SaveStorageBundleInfo(item.second)) {
            rdbDataManager_->DeleteData(item.first);
        }
    }
    APP_LOGD("Update database done");
}

bool BundleDataStorageRdb::SaveStorageBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    EventReport::ReportDataPartitionUsageEvent();
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    LOG_NOFUNC_I(BMS_TAG_COMMON, "rdb SaveStorageBundleInfo -n %{public}s", innerBundleInfo.GetBundleName().c_str());
    std::string value = innerBundleInfo.ToString();
    if (value.empty()) {
        LOG_NOFUNC_E(BMS_TAG_COMMON, "err: empty str");
        return false;
    }
    bool ret = rdbDataManager_->InsertData(
        innerBundleInfo.GetBundleName(), value);
    return ret;
}

ErrCode BundleDataStorageRdb::SaveStorageBundleInfoWithCode(const InnerBundleInfo &innerBundleInfo)
{
    EventReport::ReportDataPartitionUsageEvent();
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    LOG_NOFUNC_I(BMS_TAG_COMMON, "rdb SaveStorageBundleInfo -n %{public}s", innerBundleInfo.GetBundleName().c_str());
    std::string value = innerBundleInfo.ToString();
    if (value.empty()) {
        LOG_NOFUNC_E(BMS_TAG_COMMON, "err: empty str");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return rdbDataManager_->InsertDataWithCode(
        innerBundleInfo.GetBundleName(), value);
}


bool BundleDataStorageRdb::DeleteStorageBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    bool ret = rdbDataManager_->DeleteData(innerBundleInfo.GetBundleName());
    APP_LOGD("DeleteStorageBundleInfo %{public}d", ret);
    return ret;
}

bool BundleDataStorageRdb::ResetKvStore()
{
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS