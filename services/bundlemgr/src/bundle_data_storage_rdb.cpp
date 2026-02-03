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

#include <algorithm>
#include <future>
#include <thread>

#include "app_log_tag_wrapper.h"
#include "bundle_exception_handler.h"
#include "event_report.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_RDB_TABLE_NAME = "installed_bundle";
const uint8_t MAX_THREADS = 8;  // Cap to avoid over-scheduling
const uint8_t PARALLEL_SIZE = 30;
 // Thread-local storage for results
struct ThreadResult {
    uint64_t totalSize = 0;
    std::map<std::string, InnerBundleInfo> validInfos;  // bundleName -> InnerBundleInfo
    std::vector<std::string> errorKeys;
    std::vector<InnerBundleInfo> needExceptionHandle;  // Bundles needing exception handling
    // Directly store bundles that need database update (key != bundleName)
    std::vector<std::pair<std::string, InnerBundleInfo>> needUpdateInfos;  // originalKey -> InnerBundleInfo
};

void TransResult(const std::string &key, const std::string &jsonStr, ThreadResult &result)
{
    result.totalSize += static_cast<uint64_t>(jsonStr.size());
    InnerBundleInfo innerBundleInfo;
    nlohmann::json jsonObject = nlohmann::json::parse(jsonStr, nullptr, false);
    // Collect error keys for later batch deletion
    if (jsonObject.is_discarded()) {
        result.errorKeys.push_back(key);
        return;
    }
    if (innerBundleInfo.FromJson(jsonObject) != ERR_OK) {
        result.errorKeys.push_back(key);
        return;
    }
    // Performance optimization: Reset privilege capability directly
    innerBundleInfo.ResetPrivilegeCapability();
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    const std::string &bundleName = innerBundleInfo.GetBundleName();
    // Check if exception handling is needed (deferred to main thread)
    if (innerBundleInfo.GetInstallMark().status != InstallExceptionStatus::INSTALL_FINISH) {
        result.needExceptionHandle.push_back(innerBundleInfo);
    }
    // Store in thread-local results
    result.validInfos.emplace(bundleName, innerBundleInfo);
    // This avoids the need to traverse a map later to find the mapping
    if (key != bundleName) {
        result.needUpdateInfos.emplace_back(key, innerBundleInfo);
    }
}

void ProcessRsult(ThreadResult &result, std::shared_ptr<BundleExceptionHandler> &handler,
    std::map<std::string, InnerBundleInfo> &infos,
    std::map<std::string, InnerBundleInfo> &updateInfos)
{
    for (auto &innerBundleInfo : result.needExceptionHandle) {
        bool isBundleValid = true;
        handler->HandleInvalidBundle(innerBundleInfo, isBundleValid);
        if (!isBundleValid) {
            continue;
        }
        // Add valid bundle after exception handling
        const std::string &bundleName = innerBundleInfo.GetBundleName();
        infos.emplace(bundleName, innerBundleInfo);
    }
    for (auto &pair : result.validInfos) {
        const std::string &bundleName = pair.first;
        InnerBundleInfo &innerBundleInfo = pair.second;
        // Check if this bundle was already added via exception handling
        if (infos.find(bundleName) == infos.end()) {
            infos.emplace(bundleName, innerBundleInfo);
        }
    }
    // Directly merge needUpdateInfos - no traversal needed
    for (const auto &updatePair : result.needUpdateInfos) {
        updateInfos.emplace(updatePair.first, updatePair.second);
    }
}
}
BundleDataStorageRdb::BundleDataStorageRdb()
{
    APP_LOGI_NOFUNC("BundleDataStorageRdb instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = BUNDLE_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

BundleDataStorageRdb::~BundleDataStorageRdb()
{
    APP_LOGI_NOFUNC("BundleDataStorageRdb instance is destroyed");
}

bool BundleDataStorageRdb::LoadAllData(std::map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGI_NOFUNC("Load all installed bundle data to map");
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
    APP_LOGI_NOFUNC("bundle TransformStrToInfo start");
    if (rdbDataManager_ == nullptr || datas.empty()) {
        APP_LOGE("rdbDataManager is null");
        return;
    }
    const uint8_t actualThreads = datas.size() > PARALLEL_SIZE ? std::max(uint8_t(1), std::min(
        static_cast<uint8_t>(std::thread::hardware_concurrency()), MAX_THREADS)) : 1;
    const uint16_t itemsPerThread = (datas.size() + actualThreads - 1) / actualThreads;
    APP_LOGI_NOFUNC("Processing %{public}zu bundles with %{public}u parallel threads",
        datas.size(), actualThreads);
    std::vector<ThreadResult> threadResults(actualThreads);
    std::vector<std::future<void>> futures;
    for (uint16_t i = 0; i < actualThreads; ++i) {
        // Calculate the range for this thread
        const uint16_t startIndex = i * itemsPerThread;
        const uint16_t endIndex = std::min(static_cast<uint16_t>(startIndex + itemsPerThread),
            static_cast<uint16_t>(datas.size()));
        auto startIter = datas.begin();
        std::advance(startIter, startIndex);
        auto endIter = datas.begin();
        std::advance(endIter, endIndex);
        futures.push_back(std::async(std::launch::async,
            [this, startIter, endIter, &result = threadResults[i]]() {
            for (auto iter = startIter; iter != endIter; ++iter) {
                TransResult(iter->first, iter->second, result);
            }
        }));
    }
    for (auto &future : futures) {
        future.get();
    }
    std::map<std::string, InnerBundleInfo> updateInfos;
    uint64_t totalSize = 0;
    auto handler = std::make_shared<BundleExceptionHandler>(shared_from_this());
    for (auto &result : threadResults) {
        totalSize += result.totalSize;
        for (const auto &errorKey : result.errorKeys) {
            APP_LOGE_NOFUNC("Error key: %{public}s", errorKey.c_str());
            rdbDataManager_->DeleteData(errorKey);
        }
        ProcessRsult(result, handler, infos, updateInfos);
    }
    if (updateInfos.size() > 0) {
        UpdateDataBase(updateInfos);
    }
    APP_LOGI_NOFUNC("bundle TransformStrToInfo end totalSize:%{public}" PRIu64, totalSize);
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