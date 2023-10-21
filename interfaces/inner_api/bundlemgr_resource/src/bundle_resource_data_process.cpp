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

#include "bundle_constants.h"
#include "bundle_resource_constants.h"
#include "bundle_resource_data_process.h"
#include "bundle_resource_rdb_callback.h"
#include "bundle_system_state.h"

namespace OHOS {
namespace AppExecFwk {
ErrCode BundleResourceDataProcess::GetBundleResourceInfo(
    const std::string &bundleName,
    const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("rdbStore is nullptr");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, bundleName);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    auto absSharedResultSet = QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("failed due rdb QueryData failed");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("bundleName: %{public}s not found", bundleName.c_str());
        absSharedResultSet->Close();
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (!ConvertToBundleResourceInfo(absSharedResultSet, flags, bundleResourceInfo)) {
        APP_LOGE("bundleName: %{public}s ConvertToBundleResourceInfo failed", bundleName.c_str());
        absSharedResultSet->Close();
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    absSharedResultSet->Close();
    return ERR_OK;
}

ErrCode BundleResourceDataProcess::GetLauncherAbilityResourceInfo(
    const std::string &bundleName,
    const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("rdbStore is nullptr");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.BeginsWith(BundleResourceConstants::NAME, bundleName + BundleResourceConstants::SEPARATOR);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    auto absSharedResultSet = QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetBundleResourceInfo failed due rdb QueryData failed");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("bundleName: %{public}s not found", bundleName.c_str());
        absSharedResultSet->Close();
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    do {
        LauncherAbilityResourceInfo resourceInfo;
        if (ConvertToLauncherAbilityResourceInfo(absSharedResultSet, flags, resourceInfo)) {
            launcherAbilityResourceInfos.push_back(resourceInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    if ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) {
        std::sort(launcherAbilityResourceInfos.begin(), launcherAbilityResourceInfos.end(),
            [](LauncherAbilityResourceInfo resourceA, LauncherAbilityResourceInfo resourceB) {
                return resourceA.label < resourceB.label;
            }
        );
    }
    return ERR_OK;
}

ErrCode BundleResourceDataProcess::GetAllBundleResourceInfo(const uint32_t flags,
    std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    APP_LOGD("start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("rdbStore is nullptr");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    auto absSharedResultSet = QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetBundleResourceInfo failed due rdb QueryData failed");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetAllBundleResourceInfo failed, no data");
        absSharedResultSet->Close();
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    do {
        BundleResourceInfo resourceInfo;
        if (ConvertToBundleResourceInfo(absSharedResultSet, flags, resourceInfo)) {
            bundleResourceInfos.push_back(resourceInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();

    if ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) {
        std::sort(bundleResourceInfos.begin(), bundleResourceInfos.end(),
            [](BundleResourceInfo resourceA, BundleResourceInfo resourceB) {
                return resourceA.label < resourceB.label;
            }
        );
    }
    return ERR_OK;
}

ErrCode BundleResourceDataProcess::GetAllLauncherAbilityResourceInfo(const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    APP_LOGD("start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("rdbStore is nullptr");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME);
    absRdbPredicates.Contains(BundleResourceConstants::NAME, BundleResourceConstants::SEPARATOR);
    absRdbPredicates.EqualTo(BundleResourceConstants::SYSTEM_STATE, BundleSystemState::GetInstance().ToString());

    auto absSharedResultSet = QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetBundleResourceInfo failed due rdb QueryData failed");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetAllBundleResourceInfo failed, no data");
        absSharedResultSet->Close();
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    do {
        LauncherAbilityResourceInfo resourceInfo;
        if (ConvertToLauncherAbilityResourceInfo(absSharedResultSet, flags, resourceInfo)) {
            launcherAbilityResourceInfos.push_back(resourceInfo);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();

    if ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL)) {
        std::sort(launcherAbilityResourceInfos.begin(), launcherAbilityResourceInfos.end(),
            [](LauncherAbilityResourceInfo resourceA, LauncherAbilityResourceInfo resourceB) {
                return resourceA.label < resourceB.label;
            }
        );
    }
    return ERR_OK;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> BundleResourceDataProcess::QueryData(
    const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    APP_LOGD("QueryData start");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return nullptr;
    }
    if (absRdbPredicates.GetTableName() != BundleResourceConstants::BUNDLE_RESOURCE_RDB_TABLE_NAME) {
        APP_LOGE("RdbStore table is invalid");
        return nullptr;
    }
    auto absSharedResultSet = rdbStore->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
        APP_LOGE("absSharedResultSet failed");
        return nullptr;
    }
    return absSharedResultSet;
}

std::shared_ptr<NativeRdb::RdbStore> BundleResourceDataProcess::GetRdbStore()
{
    // sandbox for hap
    NativeRdb::RdbStoreConfig rdbStoreConfig(std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_STORAGE_PATH) +
        std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_NAME));
    rdbStoreConfig.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = NativeRdb::E_OK;
    BundleResourceRdbCallback openCallback;
    return NativeRdb::RdbHelper::GetRdbStore(
        rdbStoreConfig,
        Constants::BUNDLE_RDB_VERSION,
        openCallback,
        errCode);
}

bool BundleResourceDataProcess::ConvertToBundleResourceInfo(
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

bool BundleResourceDataProcess::ConvertToLauncherAbilityResourceInfo(
    const std::shared_ptr<NativeRdb::AbsSharedResultSet> &absSharedResultSet,
    const uint32_t flags,
    LauncherAbilityResourceInfo &launcherAbilityResourceInfo)
{
    if (absSharedResultSet == nullptr) {
        return false;
    }
        if (absSharedResultSet == nullptr) {
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

void BundleResourceDataProcess::ParseKey(const std::string &key,
    LauncherAbilityResourceInfo &launcherAbilityResourceInfo)
{
    auto firstPos = key.find_first_of(BundleResourceConstants::SEPARATOR);
    if (firstPos == std::string::npos) {
        launcherAbilityResourceInfo.bundleName = key;
        launcherAbilityResourceInfo.moduleName = std::string();
        launcherAbilityResourceInfo.abilityName = std::string();
        return;
    }
    launcherAbilityResourceInfo.bundleName = key.substr(0, firstPos);
    auto lastPos = key.find_last_of(BundleResourceConstants::SEPARATOR);
    launcherAbilityResourceInfo.abilityName = key.substr(lastPos + 1);
    if (firstPos != lastPos) {
        launcherAbilityResourceInfo.moduleName = key.substr(firstPos + 1, lastPos - firstPos - 1);
        return;
    }
    launcherAbilityResourceInfo.moduleName = std::string();
}
} // namespace AppExecFwk
} // namespace OHOS
