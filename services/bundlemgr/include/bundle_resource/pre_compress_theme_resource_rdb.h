/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_PRE_COMPRESS_THEME_RESOURCE_RDB_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_PRE_COMPRESS_THEME_RESOURCE_RDB_H

#include <map>
#include <string>
#include <vector>

#include "bundle_rdb_util.h"
#include "bundle_resource_info.h"
#include "rdb_data_manager.h"
#include "resource_info.h"

namespace OHOS {
namespace AppExecFwk {
class PreCompressThemeResourceRdb {
public:
    PreCompressThemeResourceRdb();

    bool AddPreCompressThemeResource(const int32_t userId, const ResourceInfo &resourceInfo);

    bool DeletePreCompressThemeResource(const std::string &bundleName, const int32_t userId);

    bool DeletePreCompressThemeResource(const std::string &bundleName);

    bool DeletePreCompressThemeResourceForUser(const int32_t userId);

    bool GetPreCompressThemeResources(const int32_t userId, const std::vector<std::string> &bundleNames,
        const uint32_t flags, std::map<std::string, BundleResourceInfo> &themeResourceInfos);

private:
    bool ConvertToBundleResourceInfo(const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet,
        const uint32_t flags, BundleResourceInfo &bundleResourceInfo);

    std::shared_ptr<RdbDataManager> rdbDataManager_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_PRE_COMPRESS_THEME_RESOURCE_RDB_H
