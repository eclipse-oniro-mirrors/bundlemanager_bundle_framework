/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_RESOURCE_INFO_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_RESOURCE_INFO_H

#include <string>
#include <vector>

#include "bundle_resource_info.h"
#include "launcher_ability_resource_info.h"
namespace OHOS {
namespace AppExecFwk {
enum class IconResourceType {
    UNKNOWN = 0,
    THEME_ICON = 1,
    DYNAMIC_ICON = 2
};
class ResourceInfo {
public:
    ResourceInfo();
    ~ResourceInfo();

    void ConvertFromBundleResourceInfo(const BundleResourceInfo &bundleResourceInfo);

    void ConvertFromLauncherAbilityResourceInfo(const LauncherAbilityResourceInfo &launcherAbilityResourceInfo);
    /**
     * key:
     * 1. bundleName
     * 2. bundleName/moduleName/abilityName
     */
    std::string GetKey() const;
    void ParseKey(const std::string &key);
    bool labelNeedParse_ = true;
    bool iconNeedParse_ = true;
    // label resource
    uint32_t labelId_ = 0;
    // icon resource
    uint32_t iconId_ = 0;
    // for app clone
    int32_t appIndex_ = 0;
    int32_t extensionAbilityType_ = -1;
    // for dynamic icon
    bool hasDynamicIcon_ = false;
    // for icon type
    IconResourceType iconType_ = IconResourceType::THEME_ICON;
    // key
    std::string bundleName_;
    std::string moduleName_;
    std::string abilityName_;
    std::string label_;
    std::string icon_;
    // used for parse label and icon
    std::string hapPath_;
    // used for parse overlay label and icon
    std::vector<std::string> overlayHapPaths_;
    // used for layer icons
    std::vector<uint8_t> foreground_;
    std::vector<uint8_t> background_;
    std::vector<int32_t> appIndexes_;

private:
    void InnerParseAppIndex(const std::string &key);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_RESOURCE_INFO_H
