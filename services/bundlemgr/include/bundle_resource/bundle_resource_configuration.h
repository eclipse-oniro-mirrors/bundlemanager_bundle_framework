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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_CONFIGURATION_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_CONFIGURATION_H

#include <string>

#include "resource_manager.h"

namespace OHOS {
namespace AppExecFwk {
class BundleResourceConfiguration {
public:
    static bool InitResourceGlobalConfig(const std::string &hapPath,
        std::shared_ptr<Global::Resource::ResourceManager> resourceManager);

    static bool InitResourceGlobalConfig(std::shared_ptr<Global::Resource::ResourceManager> resourceManager);

    static bool InitResourceGlobalConfig(const std::string &hapPath,
        const std::vector<std::string> &overlayHaps,
        std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
        bool needParseIcon = true, bool needParseLabel = true);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_CONFIGURATION_H
