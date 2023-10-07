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
#include "bundle_system_state.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// resource database name
const std::string BUNDLE_RESOURCE_RDB_NAME = "/bundleResource.db";
// need to create resource rdb path
const std::string BUNDLE_RESOURCE_RDB_PATH = "/data/service/el1/public/bms/bundle_manager_service";
// resource table name
const std::string BUNDLE_RESOURCE_RDB_TABLE_NAME = "bundleResource";
// bundle resource info table key
const std::string NAME = "NAME";
const std::string UPDATE_TIME = "UPDATE_TIME";
const std::string LABEL = "LABEL";
const std::string ICON = "ICON";
const std::string SYSTEM_STATE = "SYSTEM_STATE";

const int32_t INDEX_NAME = 0;
const int32_t INDEX_UPDATE_TIME = 1;
const int32_t INDEX_LABEL = 2;
const int32_t INDEX_ICON = 3;
const int32_t INDEX_SYSTEM_STATE = 4;
}

BundleResourceRdb::BundleResourceRdb()
{
    APP_LOGI("create BundleResourceRdb.");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = BUNDLE_RESOURCE_RDB_NAME;
    bmsRdbConfig.dbPath = BUNDLE_RESOURCE_RDB_PATH;
    bmsRdbConfig.tableName = BUNDLE_RESOURCE_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + BUNDLE_RESOURCE_RDB_TABLE_NAME
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
    valuesBucket.PutString(NAME, resourceInfo.GetKey());
    valuesBucket.PutLong(UPDATE_TIME, resourceInfo.updateTime_);
    valuesBucket.PutString(LABEL, resourceInfo.label_);
    valuesBucket.PutString(ICON, resourceInfo.icon_);
    valuesBucket.PutString(SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    return rdbDataManager_->InsertData(valuesBucket);
}

bool BundleResourceRdb::AddResourceInfos(const std::vector<ResourceInfo> &resourceInfos)
{
    if (resourceInfos.empty()) {
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
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BUNDLE_RESOURCE_RDB_TABLE_NAME);
    /**
     * begin with bundle name, like:
     * 1. bundleName
     * 2. bundleName/moduleName/abilityName
     */
    absRdbPredicates.BeginsWith(NAME, key);
    return rdbDataManager_->DeleteData(absRdbPredicates);
}

bool BundleResourceRdb::GetAllResourceName(std::vector<std::string> &keyNames)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(SYSTEM_STATE, BundleSystemState::GetInstance().ToString());
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
        ret = absSharedResultSet->GetString(INDEX_NAME, name);
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
    NativeRdb::AbsRdbPredicates absRdbPredicates(BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(SYSTEM_STATE, BundleSystemState::GetInstance().ToString());
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
    NativeRdb::AbsRdbPredicates absRdbPredicates(BUNDLE_RESOURCE_RDB_TABLE_NAME);
    // delete all resource info
    return rdbDataManager_->DeleteData(absRdbPredicates);
}
} // AppExecFwk
} // OHOS
