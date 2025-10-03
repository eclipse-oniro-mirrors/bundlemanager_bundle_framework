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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_UNINSTALL_BUNDLE_RESOURCE_RDB_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_UNINSTALL_BUNDLE_RESOURCE_RDB_H

#include <map>
#include <vector>

#include "bundle_resource_info.h"
#include "rdb_data_manager.h"
#include "resource_info.h"

namespace OHOS {
namespace AppExecFwk {
class UninstallBundleResourceRdb : public std::enable_shared_from_this<UninstallBundleResourceRdb> {
public:
    UninstallBundleResourceRdb();
    ~UninstallBundleResourceRdb();
    bool AddUninstallBundleResource(const std::string &bundleName, const int32_t userId, const int32_t appIndex,
        const std::map<std::string, std::string> &labelMap, const ResourceInfo &resourceInfo);
    bool DeleteUninstallBundleResource(const std::string &bundleName, const int32_t userId, const int32_t appIndex);
    bool GetUninstallBundleResource(const std::string &bundleName, const int32_t userId, const int32_t appIndex,
        BundleResourceInfo &bundleResourceInfo);
    bool GetAllUninstallBundleResource(const int32_t userId, std::vector<BundleResourceInfo> &bundleResourceInfos);

private:
    std::map<std::string, std::string> FromString(const std::string &labels);
    std::string ToString(const std::map<std::string, std::string> &labelMap);
    bool ConvertToBundleResourceInfo(const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet,
        const std::string &language, BundleResourceInfo &bundleResourceInfo);
    std::string GetAvailableLabel(const std::string &bundleName, const std::string &language,
        const std::string &labels);

    std::shared_ptr<RdbDataManager> rdbDataManager_;

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
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_UNINSTALL_BUNDLE_RESOURCE_RDB_H
