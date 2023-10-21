/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_resource_rdb.h"

#include "app_log_wrapper.h"
#include "bms_rdb_config.h"
#include "bundle_resource_constants.h"
#include "bundle_system_state.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
BundleResourceRdb::BundleResourceRdb()
{
    APP_LOGI("create");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = BundleResourceConstants::BUNDLE_RESOURCE_RDB_NAME;
    bmsRdbConfig.dbPath = BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH;
    bmsRdbConfig.tableName = BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME)
        + "(NAME TEXT NOT NULL, UPDATE_TIME INTEGER, LABEL TEXT, ICON TEXT, "
        + "SYSTEM_STATE TEXT NOT NULL, PRIMARY KEY (NAME, SYSTEM_STATE));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

BundleResourceRdb::~BundleResourceRdb()
{
}

bool BundleResourceRdb::AddResourceInfo(const ResourceInfo &resourceInfo)
{
    if (resourceInfo.bundleName_.empty()) {
        APP_LOGE("failed, bundleName is empty");
        return false;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BundleResourceConstants::NAME, resourceInfo.GetKey());
    valuesBucket.PutLong(BundleResourceConstants::UPDATE_TIME, resourceInfo.updateTime_);
    valuesBucket.PutString(BundleResourceConstants::LABEL, resourceInfo.label_);
    valuesBucket.PutString(BundleResourceConstants::ICON, resourceInfo.icon_);
    valuesBucket.PutString(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    return rdbDataManager_->InsertData(valuesBucket);
}

bool BundleResourceRdb::AddResourceInfos(const std::vector<ResourceInfo> &resourceInfos)
{
    if (resourceInfos.empty()) {
        APP_LOGE("failed, resourceInfos is empty");
        return false;
    }
    for (const auto &info : resourceInfos) {
        if (!AddResourceInfo(info)) {
            APP_LOGE("failed, key:%{public}s", info.GetKey().c_str());
            return false;
        }
    }
    return true;
}

bool BundleResourceRdb::DeleteResourceInfo(const std::string &key)
{
    if (key.empty()) {
        APP_LOGE("failed, key is empty");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    /**
     * begin with bundle name, like:
     * 1. bundleName
     * 2. bundleName/moduleName/abilityName
     */
    absRdbPredicates.BeginsWith(BundleResourceConstants::NAME, key);
    return rdbDataManager_->DeleteData(absRdbPredicates);
}

bool BundleResourceRdb::GetAllResourceName(std::vector<std::string> &keyNames)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("QueryData failed");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });

    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return false;
    }
    do {
        std::string name;
        ret = absSharedResultSet->GetString(BundleResourceConstants::INDEX_NAME, name);
        if (ret != NativeRdb::E_OK) {
            APP_LOGE("GetString name failed, ret: %{public}d", ret);
            return false;
        }
        keyNames.push_back(name);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return true;
}

bool BundleResourceRdb::IsCurrentColorModeExist()
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("QueryData failed");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return false;
    }
    return true;
}

bool BundleResourceRdb::DeleteAllResourceInfo()
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    // delete all resource info
    return rdbDataManager_->DeleteData(absRdbPredicates);
}
} // AppExecFwk
} // OHOS
