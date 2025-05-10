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

#include "resource_info.h"

#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SEPARATOR = "/";
constexpr const char* UNDER_LINE = "_";
constexpr const char* EXTENSION_ABILITY_SEPARATOR = "+";
}

ResourceInfo::ResourceInfo()
{}

ResourceInfo::~ResourceInfo()
{}

std::string ResourceInfo::GetKey() const
{
    std::string key = bundleName_;
    /**
    * if moduleName and abilityName both empty, it represents bundle resource,
    * otherwise it represents launcher ability resource.
    */
    if (!abilityName_.empty()) {
        key = moduleName_.empty() ? key : (key + SEPARATOR + moduleName_);
        key = abilityName_.empty() ? key : (key + SEPARATOR + abilityName_);
    }
    if (appIndex_ > 0) {
        key = std::to_string(appIndex_) + UNDER_LINE + key;
    }
    if (extensionAbilityType_ >= 0) {
        key = key + EXTENSION_ABILITY_SEPARATOR + std::to_string(extensionAbilityType_);
    }
    return key;
}

void ResourceInfo::ParseKey(const std::string &key)
{
    std::string baseKey = key;
    auto plusPos = key.find_last_of(EXTENSION_ABILITY_SEPARATOR);
    if (plusPos != std::string::npos) {
        std::string extensionTypeStr = key.substr(plusPos + 1);
        if (!OHOS::StrToInt(extensionTypeStr, extensionAbilityType_)) {
            extensionAbilityType_ = -1;
        }
        baseKey = key.substr(0, plusPos);
    }
    auto firstPos = baseKey.find_first_of(SEPARATOR);
    if (firstPos == std::string::npos) {
        InnerParseAppIndex(baseKey);
        moduleName_ = std::string();
        abilityName_ = std::string();
        return;
    }
    InnerParseAppIndex(baseKey.substr(0, firstPos));
    auto lastPos = baseKey.find_last_of(SEPARATOR);
    abilityName_ = baseKey.substr(lastPos + 1);
    if (firstPos != lastPos) {
        moduleName_ = baseKey.substr(firstPos + 1, lastPos - firstPos - 1);
        return;
    }
    moduleName_ = std::string();
}

void ResourceInfo::ConvertFromBundleResourceInfo(const BundleResourceInfo &bundleResourceInfo)
{
    bundleName_ = bundleResourceInfo.bundleName;
    moduleName_ = std::string();
    abilityName_ = std::string();
    icon_ = bundleResourceInfo.icon;
    foreground_ = bundleResourceInfo.foreground;
    background_ = bundleResourceInfo.background;
    appIndex_ = bundleResourceInfo.appIndex;
    if (appIndex_ > 0) {
        label_ = bundleResourceInfo.label + std::to_string(appIndex_);
    } else {
        label_ = bundleResourceInfo.label;
    }
}

void ResourceInfo::ConvertFromLauncherAbilityResourceInfo(
    const LauncherAbilityResourceInfo &launcherAbilityResourceInfo)
{
    bundleName_ = launcherAbilityResourceInfo.bundleName;
    moduleName_ = launcherAbilityResourceInfo.moduleName;
    abilityName_ = launcherAbilityResourceInfo.abilityName;
    icon_ = launcherAbilityResourceInfo.icon;
    foreground_ = launcherAbilityResourceInfo.foreground;
    background_ = launcherAbilityResourceInfo.background;
    appIndex_ = launcherAbilityResourceInfo.appIndex;
    if (appIndex_ > 0) {
        label_ = launcherAbilityResourceInfo.label + std::to_string(appIndex_);
    } else {
        label_ = launcherAbilityResourceInfo.label;
    }
    extensionAbilityType_ = launcherAbilityResourceInfo.extensionAbilityType;
}

void ResourceInfo::InnerParseAppIndex(const std::string &key)
{
    bundleName_ = key;
    appIndex_ = 0;
    auto pos = key.find(UNDER_LINE);
    if ((pos == std::string::npos) || (pos == 0)) {
        return;
    }
    std::string index = key.substr(0, pos);
    if (!OHOS::StrToInt(index, appIndex_)) {
        appIndex_ = 0;
        return;
    }
    bundleName_ = key.substr(pos + 1);
}
} // AppExecFwk
} // OHOS
