/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#define private public
#include "bundleresmgr_fuzzer.h"

#include "bundle_resource_manager.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t CODE_MAX = 8;
const int32_t USERID = 100;
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "com.example.bmsaccesstoken1.MainAbility";
const std::string BUNDLE_NAME_NO_ICON = "com.third.hiworld.example1";

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    std::string bundleName(data, size);
    manager->AddResourceInfoByBundleName(bundleName, USERID);
    manager->DeleteResourceInfo(bundleName);
    manager->AddAllResourceInfo(USERID, 0, 0);
    manager->DeleteAllResourceInfo();
    manager->AddResourceInfoByAbility(bundleName, MODULE_NAME, ABILITY_NAME, USERID);
    std::vector<std::string> keyNames;
    manager->GetAllResourceName(keyNames);
    BundleResourceInfo info;
    manager->GetBundleResourceInfo(bundleName, 0, info);
    std::vector<LauncherAbilityResourceInfo> launcherInfos;
    manager->GetLauncherAbilityResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), launcherInfos);
    std::vector<BundleResourceInfo> infos;
    manager->GetAllBundleResourceInfo(0, infos);
    manager->GetAllLauncherAbilityResourceInfo(0, launcherInfos);
    std::vector<ResourceInfo> resourceInfos;
    manager->SaveResourceInfos(resourceInfos);
    std::string targetBundleName(data, size);
    manager->GetTargetBundleName(bundleName, targetBundleName);
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = bundleName;
    resourceInfo.label_ = bundleName;
    manager->UpdateBundleIcon(bundleName, resourceInfo);
    int32_t appIndex = 1;
    manager->AddCloneBundleResourceInfo(bundleName, appIndex);
    manager->DeleteCloneBundleResourceInfo(bundleName, appIndex);
    manager->DeleteNotExistResourceInfo();
    manager->AddResourceInfo(USERID, resourceInfo);
    manager->AddResourceInfos(USERID, resourceInfos);
    std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
    resourceInfosMap[BUNDLE_NAME_NO_ICON] = resourceInfos;
    manager->AddResourceInfosByMap(resourceInfosMap, manager->currentTaskNum_,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE), USERID, USERID);
    manager->InnerProcessResourceInfoByResourceUpdateType(resourceInfosMap,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE), USERID, USERID);
    manager->ProcessResourceInfoWhenParseFailed(resourceInfo);
    manager->ProcessResourceInfo(resourceInfos, resourceInfo);
    manager->GetDefaultIcon(resourceInfo);
    manager->CheckResourceFlags(static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE));
    manager->SendBundleResourcesChangedEvent(USERID,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE));
    manager->InnerProcessResourceInfoBySystemLanguageChanged(resourceInfosMap);
    manager->InnerProcessResourceInfoBySystemThemeChanged(resourceInfosMap, USERID);
    manager->InnerProcessResourceInfoByUserIdChanged(resourceInfosMap, USERID, USERID);
    std::vector<std::string> existResourceNames;
    manager->DeleteNotExistResourceInfo(resourceInfosMap, existResourceNames);
    manager->InnerProcessWhetherThemeExist(bundleName, USERID);
    manager->GetBundleResourceInfoForCloneBundle(bundleName, appIndex, resourceInfos);
    manager->UpdateCloneBundleResourceInfo(bundleName, appIndex,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE));
    manager->DeleteNotExistResourceInfo(bundleName, appIndex, resourceInfos);
    manager->ProcessResourceInfoNoNeedToParseOtherIcon(resourceInfos);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    /* Validate the length of size */
    if (size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}