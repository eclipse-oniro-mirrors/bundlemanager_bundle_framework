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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_PARSER_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_PARSER_H

#include <string>
#include <vector>

#include "resource_info.h"
#include "resource_manager.h"

namespace OHOS {
namespace AppExecFwk {
class BundleResourceParser {
public:
    BundleResourceParser();

    ~BundleResourceParser();
    // parse label and icon
    bool ParseResourceInfo(ResourceInfo &resourceInfo);

    // parse label and icon
    bool ParseResourceInfos(std::vector<ResourceInfo> &resourceInfos);

private:
    // for defaultIconPath is empty, icon and label exist in same hap.
    bool ParseResourceInfoWithSameHap(ResourceInfo &resourceInfo);

    // for defaultIconPath is not empty, icon and label not exist in same hap.
    bool ParseResourceInfoWithDifferentHap(ResourceInfo &resourceInfo);

    // parse label resource by hapPath
    bool ParseLabelResourceByPath(const std::string &hapPath, const int32_t labelId, std::string &label);

    // parse icon resource by hapPath
    bool ParseIconResourceByPath(const std::string &hapPath, const int32_t iconId, std::string &icon);

    bool ParseResourceInfoByResourceManager(const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
        ResourceInfo &resourceInfo);

    // parse label resource by resourceManager
    bool ParseLabelResourceByResourceManager(const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
        const int32_t labelId, std::string &label);

    // parse label resource by resourceManager
    bool ParseIconResourceByResourceManager(const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
        const int32_t iconId, std::string &icon);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_PARSER_H