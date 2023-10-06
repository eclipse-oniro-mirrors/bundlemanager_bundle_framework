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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_RDB_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_RDB_H

#include "bundle_system_state.h"
#include "rdb_data_manager.h"
#include "resource_info.h"

#include <vector>

namespace OHOS {
namespace AppExecFwk {
class BundleResourceRdb {
public:
    BundleResourceRdb();
    ~BundleResourceRdb();
    // add resource info to resource rdb
    bool AddResourceInfo(const ResourceInfo &resourceInfo);

    bool DeleteResourceInfo(const std::string &key);

    bool DeleteAllResourceInfo();

    bool AddResourceInfos(const std::vector<ResourceInfo> &resourceInfos);

    // whether the current color mode exists
    bool IsCurrentColorModeExist();

    bool GetAllResourceName(std::vector<std::string> &keyName);

private:
    std::shared_ptr<RdbDataManager> rdbDataManager_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_RDB_H
