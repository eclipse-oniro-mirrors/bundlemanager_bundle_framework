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

#include <cstddef>
#include <cstdint>
#include <set>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bundle_resource_manager.h"
#include "bmsbundleresourcemanager_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t CODE_MAX = 8;
const int32_t USERID = 100;
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "com.example.bmsaccesstoken1.MainAbility";
const std::string BUNDLE_NAME_NO_ICON = "com.third.hiworld.example1";

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = GenerateRandomUser(fdp);
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.label_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.icon_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.appIndex_ = Constants::UNSPECIFIED_USERID;
    std::vector<ResourceInfo> resourceInfos;
    resourceInfos.push_back(resourceInfo);
    std::vector<ResourceInfo> resourceInfos2;
    manager->DeleteNotExistResourceInfo();
    std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
    resourceInfosMap[BUNDLE_NAME_NO_ICON] = resourceInfos;
    std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap2;
    std::vector<std::string> existResourceNames;
    manager->DeleteNotExistResourceInfo(resourceInfosMap, existResourceNames);
    manager->DeleteNotExistResourceInfo(bundleName, appIndex, resourceInfos);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    manager->AddAllResourceInfo(USERID, 0);
    uint32_t type = fdp.ConsumeIntegral<uint32_t>();
    int32_t oldUserId = fdp.ConsumeIntegral<int32_t>();
    manager->AddAllResourceInfo(userId, type);
    manager->InnerProcessResourceInfoBySystemLanguageChanged(resourceInfosMap);
    manager->InnerProcessResourceInfoBySystemThemeChanged(resourceInfosMap, userId);
    uint32_t tempTaskNumber = fdp.ConsumeIntegral<uint32_t>();
    ResourceInfo resourceInfo2;
    resourceInfo2.label_ = "";
    resourceInfo2.icon_ = "";
    manager->DeleteResourceInfo(bundleName);
    std::vector<std::string> keyNames;
    manager->GetAllResourceName(keyNames);
    BundleResourceInfo info;
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    manager->GetBundleResourceInfo(bundleName, 0, info);
    manager->GetBundleResourceInfo(bundleName, flags, info, appIndex);
    std::vector<LauncherAbilityResourceInfo> launcherInfos;
    manager->GetLauncherAbilityResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), launcherInfos);
    manager->GetLauncherAbilityResourceInfo(bundleName, flags, launcherInfos, appIndex);
    std::vector<BundleResourceInfo> infos;
    manager->GetAllBundleResourceInfo(0, infos);
    manager->GetAllBundleResourceInfo(flags, infos);
    manager->GetAllLauncherAbilityResourceInfo(flags, launcherInfos);
    manager->FilterLauncherAbilityResourceInfoWithFlag(1, bundleName, launcherInfos);
    manager->FilterLauncherAbilityResourceInfoWithFlag(flags, bundleName, launcherInfos);
    manager->FilterLauncherAbilityResourceInfoWithFlag(0, bundleName, launcherInfos);
    std::vector<AbilityInfo> abilityInfos;
    manager->GetLauncherAbilityInfos(bundleName, abilityInfos);
    manager->GetLauncherAbilityInfos("", abilityInfos);
    manager->CheckResourceFlags(static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL));
    manager->CheckResourceFlags(static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL));
    manager->CheckResourceFlags(static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON));
    manager->CheckResourceFlags(static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR));
    manager->CheckResourceFlags(static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY));
    manager->CheckResourceFlags(0);
    ResourceInfo resourceInfo3;
    resourceInfo3.label_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo3.bundleName_ = "ohos.global.systemres";
    resourceInfo3.appIndex_ = 0;
    ResourceInfo resourceInfo4;
    resourceInfo4.label_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo4.bundleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo4.icon_ = "";
    resourceInfo4.appIndex_ = 1;
    manager->ProcessResourceInfoWhenParseFailed(resourceInfo);
    manager->ProcessResourceInfoWhenParseFailed(resourceInfo2);
    manager->ProcessResourceInfoWhenParseFailed(resourceInfo3);
    manager->ProcessResourceInfoWhenParseFailed(resourceInfo4);
    manager->GetDefaultIcon(resourceInfo);
    manager->SendBundleResourcesChangedEvent(userId, type);
    std::string targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    manager->GetTargetBundleName(bundleName, targetBundleName);
    manager->GetBundleResourceInfoForCloneBundle(bundleName, appIndex,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE), resourceInfos);

    std::vector<LauncherAbilityResourceInfo> extensionAbilityResourceInfo;
    manager->GetExtensionAbilityResourceInfo(bundleName, ExtensionAbilityType::RECENT_PHOTO, flags,
        extensionAbilityResourceInfo, appIndex);
    manager->GetExtensionAbilityResourceInfo(bundleName, ExtensionAbilityType::RECENT_PHOTO,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), extensionAbilityResourceInfo, appIndex);
    manager->DeleteAllResourceInfo();
    manager->ProcessResourceInfoNoNeedToParseOtherIcon(resourceInfos);
    manager->PrepareSysRes();
    BundleResourceInfo bundleResourceInfo;
    bundleResourceInfo.appIndex = Constants::UNSPECIFIED_USERID;
    BundleResourceInfo bundleResourceInfo2;
    bundleResourceInfo2.appIndex = fdp.ConsumeIntegral<int32_t>();
    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    launcherAbilityResourceInfo.appIndex = Constants::UNSPECIFIED_USERID;
    LauncherAbilityResourceInfo launcherAbilityResourceInfo2;
    launcherAbilityResourceInfo2.appIndex = fdp.ConsumeIntegral<int32_t>();
    manager->IsLauncherAbility(launcherAbilityResourceInfo, abilityInfos);
    manager->GetSingleLauncherAbilityResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), launcherInfos, appIndex);
    bool isBundleFirstInstall = fdp.ConsumeBool();
    manager->AddResourceInfoByBundleNameWhenInstall(bundleName, userId, isBundleFirstInstall);
    manager->AddResourceInfoByBundleNameWhenUpdate(bundleName, userId);
    manager->ProcessCloneBundleResourceInfo(bundleName, appIndex);
    manager->AddResourceInfoByBundleNameWhenCreateUser(bundleName, userId);
    bool isExistInOtherUser = fdp.ConsumeBool();
    manager->DeleteBundleResourceInfo(bundleName, userId, isExistInOtherUser);
    manager->AddDynamicIconResource(bundleName, userId, appIndex, resourceInfo);
    manager->DeleteDynamicIconResource(bundleName, userId, appIndex);
    manager->AddAllResourceInfo(userId, type);
    manager->IsNeedInterrupted(tempTaskNumber, BundleResourceChangeType::SYSTEM_THEME_CHANGE);
    manager->AddResourceInfosWhenSystemLanguageChanged(resourceInfosMap, userId, tempTaskNumber);
    manager->ProcessCloneBundleResourceInfoWhenSystemLanguageChanged(bundleName, userId, appIndex);
    std::set<std::string> oldResourceNames;
    std::set<std::string> oldResourceNames2 = {"group1", "group2"};
    manager->DeleteNotExistThemeResource(resourceInfosMap, oldResourceNames, userId);
    manager->DeleteNotExistThemeResource(resourceInfosMap, oldResourceNames2, userId);
    manager->AddResourceInfosWhenSystemThemeChanged(resourceInfosMap, userId, tempTaskNumber);
    manager->ProcessCloneBundleResourceInfoWhenSystemThemeChanged(bundleName, userId, appIndex);
    manager->InnerProcessResourceInfoBySystemThemeChanged(resourceInfosMap, userId);
    manager->AddCloneBundleResourceInfoWhenInstall(bundleName, userId, appIndex, isExistInOtherUser);
    manager->DeleteCloneBundleResourceInfoWhenUninstall(bundleName, userId, appIndex, isExistInOtherUser);
    uint32_t resourceFlags = fdp.ConsumeIntegral<uint32_t>();
    manager->IsNeedProcessResourceIconInfo(resourceFlags);
    manager->GetUserId();
    manager->SetIsOnlineThemeWhenBoot();
    manager->SetIsOnlineTheme(userId);
    std::set<int32_t> userIds;
    bool hasBundleUpdated = fdp.ConsumeBool();
    manager->InnerProcessThemeIconWhenOta(bundleName, userIds, hasBundleUpdated);
    manager->InnerProcessDynamicIconWhenOta(bundleName);
    manager->AddUninstallBundleResource(bundleName, userId, appIndex);
    manager->DeleteUninstallBundleResource(bundleName, userId, appIndex);
    manager->DeleteUninstallBundleResourceForUser(userId);
    manager->GetUninstallBundleResource(bundleName, userId, appIndex, flags, bundleResourceInfo);
    std::vector<BundleResourceInfo> bundleResourceInfos;
    bundleResourceInfos.push_back(bundleResourceInfo);
    manager->GetAllUninstallBundleResourceInfo(userId, flags, bundleResourceInfos);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}