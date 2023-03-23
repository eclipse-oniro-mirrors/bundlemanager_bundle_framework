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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_UTIL_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_UTIL_H

#include <string>
#include <vector>

#include "bundle_constants.h"
#include "bundle_info.h"
#include "inner_service_info.h"
#include "service_info.h"
#include "sr_constants.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    static std::unordered_map<std::string, BusinessType> BUSINESS_TYPE_MAP = {
        {"share", BusinessType::SHARE}};
}
class BundleInfoResolveUtil {
public:
    static bool ResolveBundleInfo(const BundleInfo &bundleInfo, std::vector<PurposeInfo> &purposeInfos,
        std::vector<BusinessAbilityInfo> &businessAbilityInfos, const AppInfo &appInfo)
    {
        if (bundleInfo.name.empty()) {
            APP_LOGE("ConvertBundleInfo, bundleInfo invalid");
            return false;
        }
        ResolveAbilityInfos(bundleInfo.abilityInfos, purposeInfos, appInfo);
        ResolveExtAbilityInfos(bundleInfo.extensionInfos, purposeInfos, businessAbilityInfos, appInfo);
        if (purposeInfos.empty() && businessAbilityInfos.empty()) {
            APP_LOGI("ResolveBundleInfo, not support, bundleName: %{public}s", bundleInfo.name.c_str());
            return false;
        }
        return true;
}

static BusinessType findBusinessType(const std::string businessType)
{
    if (businessType.empty()) {
        return BusinessType::UNSPECIFIED;
    }

    auto item = BUSINESS_TYPE_MAP.find(LowerStr(businessType));
    if (item != BUSINESS_TYPE_MAP.end()) {
        return item->second;
    }
    return BusinessType::UNSPECIFIED;
}

private:
    static void ResolveAbilityInfos(const std::vector<AbilityInfo> &abilityInfos,
        std::vector<PurposeInfo> &purposeInfos, const AppInfo appInfo)
    {
    if (abilityInfos.empty()) {
        return;
    }
    for (const auto &abilityInfo : abilityInfos) {
        ConvertAbilityToPurposes(abilityInfo, purposeInfos, appInfo);
    }
}

static void ResolveExtAbilityInfos(const std::vector<ExtensionAbilityInfo> &extensionInfos,
    std::vector<PurposeInfo> &purposeInfos, std::vector<BusinessAbilityInfo> &businessAbilityInfos,
    const AppInfo appInfo)
{
    if (extensionInfos.empty()) {
        return;
    }
    for (const auto &extensionInfo : extensionInfos) {
        ConvertExtAbilityToPurposes(extensionInfo, purposeInfos, appInfo);
        ConvertExtAbilityToService(extensionInfo, businessAbilityInfos, appInfo);
    }
}

static void ConvertAbilityToPurposes(const AbilityInfo &abilityInfo, std::vector<PurposeInfo> &purposeInfos,
    const AppInfo appInfo)
{
    std::string supportPurpose = GetAbilityMetadataValue(abilityInfo, SrConstants::METADATA_SUPPORT_PURPOSE_KEY);
    if (supportPurpose.empty()) {
        return;
    }
    std::vector<std::string> purposeNames;
    SplitStr(supportPurpose, SrConstants::MUTIL_SPLIT_KEY, purposeNames);
    for (std::string &name : purposeNames) {
        PurposeInfo purposeInfo;
        purposeInfo.purposeName = name;
        purposeInfo.abilityName = abilityInfo.name;
        purposeInfo.moduleName = abilityInfo.moduleName;
        purposeInfo.bundleName = abilityInfo.bundleName;
        purposeInfo.componentType = ComponentType::UI_ABILITY;
        purposeInfo.appInfo = appInfo;
        purposeInfos.emplace_back(purposeInfo);
        APP_LOGI("AbilityToPurposes, bundle: %{public}s ,ability: %{public}s, purposeName: %{public}s",
            abilityInfo.bundleName.c_str(), abilityInfo.name.c_str(), name.c_str());
    }
}

static void ConvertExtAbilityToPurposes(const ExtensionAbilityInfo &extAbilityInfo,
    std::vector<PurposeInfo> &purposeInfos, const AppInfo appInfo)
{
    if (extAbilityInfo.type != ExtensionAbilityType::FORM && extAbilityInfo.type != ExtensionAbilityType::UI) {
        return;
    }
    std::string supportPurpose = GetExtAbilityMetadataValue(extAbilityInfo, SrConstants::METADATA_SUPPORT_PURPOSE_KEY);
    if (supportPurpose.empty()) {
        return;
    }
    std::vector<std::string> purposes;
    SplitStr(supportPurpose, SrConstants::MUTIL_SPLIT_KEY, purposes);
    for (std::string &purposeAndCard : purposes) {
        PurposeInfo purposeInfo;
        purposeInfo.abilityName = extAbilityInfo.name;
        purposeInfo.moduleName = extAbilityInfo.moduleName;
        purposeInfo.bundleName = extAbilityInfo.bundleName;
        purposeInfo.appInfo = appInfo;
        if (extAbilityInfo.type == ExtensionAbilityType::UI) {
            purposeInfo.purposeName = purposeAndCard;
            purposeInfo.componentType = ComponentType::UI_EXTENSION;
            purposeInfos.emplace_back(purposeInfo);
            APP_LOGI("UIExtToPurposes, bundle: %{public}s, abilityName: %{public}s, purposeName: %{public}s",
                extAbilityInfo.bundleName.c_str(), extAbilityInfo.name.c_str(), purposeAndCard.c_str());
        } else {
            std::vector<std::string> purposeNameAndCardName;
            SplitStr(purposeAndCard, SrConstants::FORM_PURPOSE_CARD_SPLIT_KEY, purposeNameAndCardName);
            if (purposeNameAndCardName.size() == SrConstants::FORM_PURPOSE_CARD_SPLIT_SIZE) {
                purposeInfo.purposeName = purposeNameAndCardName[0];
                purposeInfo.cardName = purposeNameAndCardName[1];
                purposeInfo.componentType = ComponentType::FORM;
                purposeInfos.emplace_back(purposeInfo);
                APP_LOGI("FormToPurposes, bundle: %{public}s, abilityName: %{public}s, purposeName: %{public}s",
                    extAbilityInfo.bundleName.c_str(), extAbilityInfo.name.c_str(), purposeInfo.purposeName.c_str());
            } else {
                APP_LOGW("FormToPurposes invalid supportPurpose");
            }
        }
    }
}

static void ConvertExtAbilityToService(const ExtensionAbilityInfo &extAbilityInfo,
    std::vector<BusinessAbilityInfo> &businessAbilityInfos, const AppInfo appInfo)
{
    if (extAbilityInfo.type != ExtensionAbilityType::UI) {
        return;
    }
    std::string businessType = GetExtAbilityMetadataValue(extAbilityInfo, SrConstants::METADATA_SERVICE_TYPE_KEY);
    APP_LOGI("ToService, abilityName: %{public}s, businessType: %{public}s",
        extAbilityInfo.name.c_str(), businessType.c_str());
    auto item = BUSINESS_TYPE_MAP.find(LowerStr(businessType));
    BusinessType type = findBusinessType(businessType);
    if (type != BusinessType::UNSPECIFIED) {
        BusinessAbilityInfo businessAbilityInfo;
        businessAbilityInfo.appInfo = appInfo;
        businessAbilityInfo.abilityName = extAbilityInfo.name;
        businessAbilityInfo.moduleName = extAbilityInfo.moduleName;
        businessAbilityInfo.bundleName = extAbilityInfo.bundleName;
        businessAbilityInfo.businessType = item->second;
        businessAbilityInfo.iconId = extAbilityInfo.iconId;
        businessAbilityInfo.labelId = extAbilityInfo.labelId;
        businessAbilityInfo.descriptionId = extAbilityInfo.descriptionId;
        businessAbilityInfo.permissions = extAbilityInfo.permissions;
        businessAbilityInfos.emplace_back(businessAbilityInfo);
    }
}

static std::string GetAbilityMetadataValue(const AbilityInfo &abilityInfo, const std::string &name)
{
    if (abilityInfo.metadata.empty()) {
        return Constants::EMPTY_STRING;
    }
    for (auto &metadata : abilityInfo.metadata) {
        if (name == metadata.name && !metadata.value.empty()) {
            return metadata.value;
        }
    }
    return Constants::EMPTY_STRING;
}

static std::string GetExtAbilityMetadataValue(const ExtensionAbilityInfo &extAbilityInfo, const std::string &name)
{
    if (extAbilityInfo.metadata.empty()) {
        return Constants::EMPTY_STRING;
    }
    for (auto &metadata : extAbilityInfo.metadata) {
        if (name == metadata.name && !metadata.value.empty()) {
            return metadata.value;
        }
    }
    return Constants::EMPTY_STRING;
}
}; // namespace ServiceRouterUtil
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_UTIL_H
