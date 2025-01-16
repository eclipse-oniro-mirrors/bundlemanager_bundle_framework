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

#include "patch_data_storage_rdb.h"

#include "app_log_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_RDB_TABLE_NAME = "install_patch_bundle";
}  // namespace

PatchDataStorageRdb::PatchDataStorageRdb()
{
    APP_LOGI("PatchDataStorageRdb instance is create");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = BUNDLE_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

PatchDataStorageRdb::~PatchDataStorageRdb()
{
    APP_LOGI("PatchDataStorageRdb instance is destroyed");
}

bool PatchDataStorageRdb::GetStoragePatchInfo(const std::string &bundleName, InnerPatchInfo &info)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    std::string value;
    if (!rdbDataManager_->QueryData(bundleName, value) || value.empty()) {
        return false;
    }
    if (!info.FromJson(value)) {
        APP_LOGE("Error bundleName: %{public}s", bundleName.c_str());
        rdbDataManager_->DeleteData(bundleName);
        return false;
    }
    APP_LOGI("get patchInfo success, bundleName: %{public}s", bundleName.c_str());
    return true;
}

bool PatchDataStorageRdb::SaveStoragePatchInfo(const std::string &bundleName, const InnerPatchInfo &InnerPatchInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    std::string value = InnerPatchInfo.ToString();
    if (value.empty()) {
        APP_LOGE("value is empty");
        return false;
    }
    APP_LOGI("insertData, key: %{public}s, value: %{public}s", bundleName.c_str(), value.c_str());
    return rdbDataManager_->InsertData(bundleName, value);
}

bool PatchDataStorageRdb::DeleteStoragePatchInfo(const std::string &bundleName)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    APP_LOGI("deleteData, key: %{public}s", bundleName.c_str());
    return rdbDataManager_->DeleteData(bundleName);
}
}  // namespace AppExecFwk
}  // namespace OHOS
