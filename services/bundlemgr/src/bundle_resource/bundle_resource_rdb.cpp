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

bool BundleResourceRdb::GetBundleResourceInfo(
    const std::string &bundleName,
    const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, bundleName);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("bundleName:%{public}s failed due rdb QueryData failed", bundleName.c_str());
        return false;
    }

    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "failed, ret: %{public}d");

    return ConvertToBundleResourceInfo(absSharedResultSet, flags, bundleResourceInfo);
}

bool BundleResourceRdb::GetLauncherAbilityResourceInfo(
    const std::string &bundleName,
    const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.BeginsWith(BundleResourceConstants::NAME, bundleName + BundleResourceConstants::SEPARATOR);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("bundleName:%{public}s failed due rdb QueryData failed", bundleName.c_str());
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "failed, ret: %{public}d");

    do {
        LauncherAbilityResourceInfo resourceInfo;
        if (ConvertToLauncherAbilityResourceInfo(absSharedResultSet, flags, resourceInfo)) {
            launcherAbilityResourceInfos.push_back(resourceInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    if ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) {
        APP_LOGD("need sort by label");
        std::sort(launcherAbilityResourceInfos.begin(), launcherAbilityResourceInfos.end(),
            [](LauncherAbilityResourceInfo &resourceA, LauncherAbilityResourceInfo &resourceB) {
                return resourceA.label < resourceB.label;
            });
    }
    return !launcherAbilityResourceInfos.empty();
}

bool BundleResourceRdb::GetAllBundleResourceInfo(const uint32_t flags,
    std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    APP_LOGD("start");
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is nullptr");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "failed, ret: %{public}d");
    do {
        BundleResourceInfo resourceInfo;
        if (ConvertToBundleResourceInfo(absSharedResultSet, flags, resourceInfo)) {
            bundleResourceInfos.push_back(resourceInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    if ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) {
        APP_LOGD("need sort by label");
        std::sort(bundleResourceInfos.begin(), bundleResourceInfos.end(),
            [](BundleResourceInfo &resourceA, BundleResourceInfo &resourceB) {
                return resourceA.label < resourceB.label;
            });
    }
    return !bundleResourceInfos.empty();
}

bool BundleResourceRdb::GetAllLauncherAbilityResourceInfo(const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    APP_LOGD("start");
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.Contains(BundleResourceConstants::NAME, BundleResourceConstants::SEPARATOR);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is nullptr");
        return false;
    }

    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "failed, ret: %{public}d");

    do {
        LauncherAbilityResourceInfo resourceInfo;
        if (ConvertToLauncherAbilityResourceInfo(absSharedResultSet, flags, resourceInfo)) {
            launcherAbilityResourceInfos.push_back(resourceInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    if ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) {
        std::sort(launcherAbilityResourceInfos.begin(), launcherAbilityResourceInfos.end(),
            [](LauncherAbilityResourceInfo &resourceA, LauncherAbilityResourceInfo &resourceB) {
                return resourceA.label < resourceB.label;
            });
    }
    return !launcherAbilityResourceInfos.empty();
}

bool BundleResourceRdb::ConvertToBundleResourceInfo(
    const std::shared_ptr<NativeRdb::AbsSharedResultSet> &absSharedResultSet,
    const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo)
{
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is nullptr");
        return false;
    }
    auto ret = absSharedResultSet->GetString(BundleResourceConstants::INDEX_NAME, bundleResourceInfo.bundleName);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString name failed, ret: %{public}d");
    if (bundleResourceInfo.bundleName.find_first_of(BundleResourceConstants::SEPARATOR) != std::string::npos) {
        APP_LOGW("key:%{public}s not bundle resource info", bundleResourceInfo.bundleName.c_str());
        return false;
    }

    bool getAll = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);

    bool getLabel = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL);
    if (getAll || getLabel) {
        ret = absSharedResultSet->GetString(BundleResourceConstants::INDEX_LABEL, bundleResourceInfo.label);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString label failed, ret: %{public}d");
    }

    bool getIcon = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
    if (getAll || getIcon) {
        ret = absSharedResultSet->GetString(BundleResourceConstants::INDEX_ICON, bundleResourceInfo.icon);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString label icon, ret: %{public}d");
    }
    return true;
}

bool BundleResourceRdb::ConvertToLauncherAbilityResourceInfo(
    const std::shared_ptr<NativeRdb::AbsSharedResultSet> &absSharedResultSet,
    const uint32_t flags,
    LauncherAbilityResourceInfo &launcherAbilityResourceInfo)
{
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is nullptr");
        return false;
    }
    std::string key;
    auto ret = absSharedResultSet->GetString(BundleResourceConstants::INDEX_NAME, key);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString name failed, ret: %{public}d");
    ParseKey(key, launcherAbilityResourceInfo);
    if (launcherAbilityResourceInfo.moduleName.empty() || launcherAbilityResourceInfo.abilityName.empty()) {
        APP_LOGW("key:%{public}s not launcher ability resource info", key.c_str());
        return false;
    }
    bool getAll = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    bool getLabel = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL);
    if (getAll || getLabel) {
        ret = absSharedResultSet->GetString(BundleResourceConstants::INDEX_LABEL, launcherAbilityResourceInfo.label);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString label failed, ret: %{public}d");
    }

    bool getIcon = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
    if (getAll || getIcon) {
        ret = absSharedResultSet->GetString(BundleResourceConstants::INDEX_ICON, launcherAbilityResourceInfo.icon);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString label icon, ret: %{public}d");
    }
    return true;
}

void BundleResourceRdb::ParseKey(const std::string &key,
    LauncherAbilityResourceInfo &launcherAbilityResourceInfo)
{
    ResourceInfo info;
    info.ParseKey(key);
    launcherAbilityResourceInfo.bundleName = info.bundleName_;
    launcherAbilityResourceInfo.moduleName = info.moduleName_;
    launcherAbilityResourceInfo.abilityName = info.abilityName_;
}
} // AppExecFwk
} // OHOS