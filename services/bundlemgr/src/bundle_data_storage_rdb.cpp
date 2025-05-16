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

#include "bundle_data_storage_rdb.h"

#include "bundle_exception_handler.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_RDB_TABLE_NAME = "installed_bundle";
constexpr const char* TASK_NAME = "BackUpBMSDbTask";
constexpr uint64_t DELAY_TIME_MILLI_SECONDS = 6 * 60 * 1000; // 6min
}
BundleDataStorageRdb::BundleDataStorageRdb()
{
    APP_LOGI("BundleDataStorageRdb instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = BUNDLE_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();

    delayedTaskMgr_ = std::make_shared<SingleDelayedTaskMgr>(TASK_NAME, DELAY_TIME_MILLI_SECONDS);
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
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    APP_LOGI("rdb SaveStorageBundleInfo -n %{public}s", innerBundleInfo.GetBundleName().c_str());
    bool ret = rdbDataManager_->InsertData(
        innerBundleInfo.GetBundleName(), innerBundleInfo.ToString());
    if (ret) {
        BackupRdb();
    }
    return ret;
}

bool BundleDataStorageRdb::DeleteStorageBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    bool ret = rdbDataManager_->DeleteData(innerBundleInfo.GetBundleName());
    APP_LOGD("DeleteStorageBundleInfo %{public}d", ret);
    if (ret) {
        BackupRdb();
    }
    return ret;
}

bool BundleDataStorageRdb::ResetKvStore()
{
    return true;
}

void BundleDataStorageRdb::BackupRdb()
{
    std::weak_ptr<BundleDataStorageRdb> weakPtr = weak_from_this();
    auto task = [weakPtr] {
        APP_LOGI("backup BMS db begin");
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr || sharedPtr->rdbDataManager_ == nullptr) {
            APP_LOGE("backup BMS db failed");
            return;
        }
        sharedPtr->rdbDataManager_->BackupRdb();
        APP_LOGI("backup BMS db end");
    };
    delayedTaskMgr_->ScheduleDelayedTask(task);
}
}  // namespace AppExecFwk
}  // namespace OHOS