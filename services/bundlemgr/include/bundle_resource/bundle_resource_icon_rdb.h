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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_ICON_RDB_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_ICON_RDB_H

#include <unordered_map>
#include <shared_mutex>
#include <vector>

#include "bundle_resource_info.h"
#include "launcher_ability_resource_info.h"
#include "rdb_data_manager.h"
#include "resource_info.h"

namespace OHOS {
namespace AppExecFwk {
class BundleResourceIconRdb : public std::enable_shared_from_this<BundleResourceIconRdb> {
public:
    BundleResourceIconRdb();
    ~BundleResourceIconRdb();
    // add resource info to resource rdb
    bool AddResourceIconInfo(const int32_t userId, const IconResourceType type,
        const ResourceInfo &resourceInfo);

    bool AddResourceIconInfos(const int32_t userId, const IconResourceType type,
        const std::vector<ResourceInfo> &resourceInfos);

    bool DeleteResourceIconInfo(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex = 0, const IconResourceType type = IconResourceType::UNKNOWN);

    bool DeleteResourceIconInfos(const std::string &bundleName, const int32_t userId,
        const IconResourceType type = IconResourceType::UNKNOWN);

    bool DeleteResourceIconInfos(const std::string &bundleName,
        const IconResourceType type = IconResourceType::UNKNOWN);

    bool GetAllResourceIconName(const int32_t userId, std::set<std::string> &resourceNames,
        const IconResourceType type = IconResourceType::UNKNOWN);

    bool GetResourceIconInfos(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex, const uint32_t resourceFlag,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos,
        const IconResourceType type = IconResourceType::UNKNOWN);

    bool GetAllResourceIconInfo(const int32_t userId, const uint32_t resourceFlag,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos);

    void SetIsOnlineTheme(const int32_t userId, bool isOnlineTheme);

    bool GetIsOnlineTheme(const int32_t userId);

private:
    void ParseNameToResourceName(const std::string &name, std::string &resourceName);

    bool ConvertToLauncherAbilityResourceInfo(
        const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet, const uint32_t resourceFlag,
        LauncherAbilityResourceInfo &launcherAbilityResourceInfo, IconResourceType &iconType);

    void ParseKey(const std::string &key,
        LauncherAbilityResourceInfo &launcherAbilityResourceInfo);

    void InnerProcessResourceIconInfos(const LauncherAbilityResourceInfo &resourceInfo,
        const IconResourceType type, const int32_t userId,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos);

    std::shared_ptr<RdbDataManager> rdbDataManager_;
    mutable std::shared_mutex isOnlineThemeMutex_;
    std::unordered_map<int32_t, bool> isOnlineThemeMap_;

#define CHECK_RDB_RESULT_RETURN_IF_FAIL(errcode, errmsg)                           \
    do {                                                                           \
        if ((errcode) != NativeRdb::E_OK) {                                          \
            APP_LOGE(errmsg, errcode);                                             \
            return false;                                                          \
        }                                                                          \
    } while (0)
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_ICON_RDB_H
