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
    manager->AddResourceInfoByBundleName(bundleName, USERID);
    manager->AddResourceInfoByBundleName(bundleName, userId);
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    manager->AddResourceInfoByBundleName(bundleName, userId, appIndex);
    manager->AddResourceInfoByBundleName(bundleName, userId, 0);
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
    manager->AddResourceInfoByAbility(bundleName, MODULE_NAME, ABILITY_NAME, USERID);
    manager->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    manager->AddAllResourceInfo(USERID, 0, 0);
    uint32_t type = fdp.ConsumeIntegral<uint32_t>();
    int32_t oldUserId = fdp.ConsumeIntegral<int32_t>();
    manager->AddAllResourceInfo(userId, type, oldUserId);
    manager->AddResourceInfo(USERID, resourceInfo);
    manager->AddResourceInfo(userId, resourceInfo);
    manager->AddResourceInfos(userId, resourceInfos);
    manager->AddResourceInfos(userId, resourceInfos2);
    manager->InnerProcessResourceInfoByResourceUpdateType(resourceInfosMap,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE), userId, oldUserId);
    manager->InnerProcessResourceInfoByResourceUpdateType(resourceInfosMap,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE), userId, oldUserId);
    manager->InnerProcessResourceInfoByResourceUpdateType(resourceInfosMap,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE), userId, oldUserId);
    manager->InnerProcessResourceInfoByResourceUpdateType(resourceInfosMap, type, userId, oldUserId);
    manager->InnerProcessResourceInfoBySystemLanguageChanged(resourceInfosMap);
    manager->InnerProcessResourceInfoBySystemThemeChanged(resourceInfosMap, userId);
    manager->CheckAllAddResourceInfo(userId);
    manager->CheckAllAddResourceInfo(oldUserId);
    manager->InnerProcessResourceInfoByUserIdChanged(resourceInfosMap, USERID, USERID);
    manager->InnerProcessResourceInfoByUserIdChanged(resourceInfosMap, userId, oldUserId);
    manager->InnerProcessWhetherThemeExist(bundleName, userId);
    uint32_t tempTaskNumber = fdp.ConsumeIntegral<uint32_t>();
    manager->AddResourceInfosByMap(resourceInfosMap, manager->currentTaskNum_,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE), USERID, USERID);
    manager->AddResourceInfosByMap(resourceInfosMap2, manager->currentTaskNum_,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE), USERID, USERID);
    manager->AddResourceInfosByMap(resourceInfosMap2, manager->currentTaskNum_,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE), userId, userId);
    manager->AddResourceInfosByMap(resourceInfosMap, manager->currentTaskNum_, type, userId, userId);
    manager->AddResourceInfosByMap(resourceInfosMap, tempTaskNumber, type, userId, userId);
    manager->ProcessResourceInfo(resourceInfos, resourceInfo);
    ResourceInfo resourceInfo2;
    resourceInfo2.label_ = "";
    resourceInfo2.icon_ = "";
    manager->ProcessResourceInfo(resourceInfos, resourceInfo2);
    manager->ProcessResourceInfo(resourceInfos2, resourceInfo);
    manager->ProcessResourceInfo(resourceInfos2, resourceInfo2);
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
    manager->SaveResourceInfos(resourceInfos);
    manager->SaveResourceInfos(resourceInfos2);
    manager->GetDefaultIcon(resourceInfo);
    manager->SendBundleResourcesChangedEvent(userId, type);
    std::string targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    manager->GetTargetBundleName(bundleName, targetBundleName);
    manager->UpdateBundleIcon(bundleName, resourceInfo);
    manager->UpdateBundleIcon(bundleName, resourceInfo2);
    manager->UpdateBundleIcon(bundleName, resourceInfo3);
    manager->UpdateBundleIcon(bundleName, resourceInfo4);
    manager->AddCloneBundleResourceInfo(bundleName, appIndex, Constants::UNSPECIFIED_USERID);
    manager->AddCloneBundleResourceInfo(bundleName, appIndex, userId);
    manager->DeleteCloneBundleResourceInfo(bundleName, appIndex);
    manager->GetBundleResourceInfoForCloneBundle(bundleName, appIndex, resourceInfos);
    manager->UpdateCloneBundleResourceInfo(bundleName, 1,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE));
    manager->UpdateCloneBundleResourceInfo(bundleName, 1,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE));
    manager->UpdateCloneBundleResourceInfo(bundleName, appIndex,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE));
    manager->UpdateCloneBundleResourceInfo(bundleName, appIndex, type);
    std::vector<LauncherAbilityResourceInfo> extensionAbilityResourceInfo;
    manager->GetExtensionAbilityResourceInfo(bundleName, ExtensionAbilityType::RECENT_PHOTO, flags,
        extensionAbilityResourceInfo, appIndex);
    manager->GetExtensionAbilityResourceInfo(bundleName, ExtensionAbilityType::RECENT_PHOTO,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), extensionAbilityResourceInfo, appIndex);
    manager->DeleteAllResourceInfo();
    manager->ProcessResourceInfoNoNeedToParseOtherIcon(resourceInfos);
    manager->PrepareSysRes();
    manager->ProcessUpdateCloneBundleResourceInfo(bundleName);
    BundleResourceInfo bundleResourceInfo;
    bundleResourceInfo.appIndex = Constants::UNSPECIFIED_USERID;
    BundleResourceInfo bundleResourceInfo2;
    bundleResourceInfo2.appIndex = fdp.ConsumeIntegral<int32_t>();
    manager->BundleResourceConvertToResourceInfo(bundleResourceInfo, resourceInfo);
    manager->BundleResourceConvertToResourceInfo(bundleResourceInfo2, resourceInfo);
    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    launcherAbilityResourceInfo.appIndex = Constants::UNSPECIFIED_USERID;
    LauncherAbilityResourceInfo launcherAbilityResourceInfo2;
    launcherAbilityResourceInfo2.appIndex = fdp.ConsumeIntegral<int32_t>();
    manager->LauncherAbilityResourceConvertToResourceInfo(launcherAbilityResourceInfo, resourceInfo);
    manager->LauncherAbilityResourceConvertToResourceInfo(launcherAbilityResourceInfo2, resourceInfo);
    manager->IsLauncherAbility(launcherAbilityResourceInfo, abilityInfos);
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