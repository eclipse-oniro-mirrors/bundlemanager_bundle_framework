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

#define private public
#include <fuzzer/FuzzedDataProvider.h>
#include "bmsbundleresprocess_fuzzer.h"
#include "bundle_resource_process.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "com.example.bmsaccesstoken1.MainAbility";
void GeneratResourceInfo(FuzzedDataProvider& fdp, ResourceInfo &resourceInfo)
{
    resourceInfo.labelNeedParse_ = fdp.ConsumeBool();
    resourceInfo.iconNeedParse_ = fdp.ConsumeBool();
    resourceInfo.iconId_ = fdp.ConsumeIntegral<uint32_t>();
    resourceInfo.appIndex_ = fdp.ConsumeIntegral<uint32_t>();
    resourceInfo.extensionAbilityType_ = fdp.ConsumeIntegral<uint32_t>();
    resourceInfo.bundleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.moduleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.abilityName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.label_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.icon_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.hapPath_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

bool DoSomethingInterestingWithMyAPIOne(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
    std::vector<ResourceInfo> resourceInfos;
    ResourceInfo resourceInfo;
    GeneratResourceInfo(fdp, resourceInfo);
    resourceInfos.emplace_back(resourceInfo);
    int32_t userId = BMSFuzzTestUtil::GenerateRandomUser(fdp);
    InnerBundleUserInfo innerUserInfo;
    innerUserInfo.bundleUserInfo.userId = userId;
    BundleResourceProcess::GetResourceInfoByBundleName(bundleName, userId, resourceInfos);
    BundleResourceProcess::GetLauncherResourceInfoByAbilityName(bundleName, MODULE_NAME, ABILITY_NAME,
        userId, resourceInfo);
    std::map<std::string, std::vector<ResourceInfo>> resourceMapInfos;
    BundleResourceProcess::GetAllResourceInfo(userId, resourceMapInfos);
    std::vector<std::string> resourceNames = BMSFuzzTestUtil::GenerateStringArray(fdp);
    BundleResourceProcess::GetResourceInfoByColorModeChanged(resourceNames, userId, resourceInfos);
    std::string targetBundleName = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
    BundleResourceProcess::GetTargetBundleName(bundleName, targetBundleName);
    ApplicationInfo applicationInfo;
    BMSFuzzTestUtil::GenerateApplicationInfo(fdp, applicationInfo);
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::APP;
    InnerBundleInfo bundleInfo;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::GetBundleResourceInfo(bundleInfo, userId, resourceInfo);
    applicationInfo.bundleName = "";
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::GetBundleResourceInfo(bundleInfo, userId, resourceInfo);
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::GetBundleResourceInfo(bundleInfo, userId, resourceInfo);
    applicationInfo.bundleType = BundleType::APP;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::GetLauncherAbilityResourceInfos(bundleInfo, userId, resourceInfos);
    bundleInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, userId, resourceInfos);
    BundleResourceProcess::ConvertToBundleResourceInfo(bundleInfo);
    BundleResourceProcess::InnerGetResourceInfo(bundleInfo, userId, resourceInfos);
    BundleResourceProcess::OnGetResourceInfo(bundleInfo, userId, resourceInfos);
    return true;
}
bool DoSomethingInterestingWithMyAPITwo(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    ApplicationInfo applicationInfo;
    applicationInfo.hideDesktopIcon = false;
    InnerBundleInfo bundleInfo;
    std::string bundleName = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    InnerBundleUserInfo innerUserInfo;
    int32_t userId = BMSFuzzTestUtil::GenerateRandomUser(fdp);
    innerUserInfo.bundleUserInfo.overlayModulesState.push_back("1_overlay_1");
    innerUserInfo.bundleUserInfo.overlayModulesState.push_back("2_overlay_2");
    innerUserInfo.bundleName = bundleName;
    bundleInfo.AddInnerBundleUserInfo(innerUserInfo);
    std::vector<std::string> overlayHapPaths = BMSFuzzTestUtil::GenerateStringArray(fdp);
    BundleResourceProcess::GetOverlayModuleHapPaths(bundleInfo, MODULE_NAME, userId, overlayHapPaths);
    std::vector<ResourceInfo> resourceInfos;
    ResourceInfo resourceInfo;
    GeneratResourceInfo(fdp, resourceInfo);
    resourceInfos.emplace_back(resourceInfo);
    BundleResourceProcess::ChangeDynamicIcon(resourceInfos, resourceInfo);
    BundleResourceProcess::GetDynamicIcon(bundleInfo, userId, resourceInfo);
    AbilityInfo abilityInfo;
    BMSFuzzTestUtil::GenerateAbilityInfo<AbilityInfo>(fdp, abilityInfo);
    InnerModuleInfo innerModuleInfo;
    bundleInfo.InsertInnerModuleInfo("moduleinfo", innerModuleInfo);
    BundleResourceProcess::ConvertToBundleResourceInfo(bundleInfo);
    return true;
}
bool DoSomethingInterestingWithMyAPIThree(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InnerExtensionInfo innerExtensionInfo;
    ApplicationInfo applicationInfo;
    BMSFuzzTestUtil::GenerateApplicationInfo(fdp, applicationInfo);
    applicationInfo.bundleName = "";
    InnerBundleInfo bundleInfo;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    std::string bundleName = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    applicationInfo.bundleType = BundleType::APP;
    applicationInfo.hideDesktopIcon = true;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    applicationInfo.hideDesktopIcon = false;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInforTest;
    bundleInforTest.entryInstallationFree = true;
    bundleInfo.SetBaseBundleInfo(bundleInforTest);
    BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    int32_t state = 0;
    int32_t userId = BMSFuzzTestUtil::GenerateRandomUser(fdp);
    BundleResourceProcess::GetExternalOverlayHapState(ABILITY_NAME, MODULE_NAME, userId, state);
    applicationInfo.bundleName = "";
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    std::vector<ResourceInfo> resourceInfos;
    BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, userId, resourceInfos);
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, userId, resourceInfos);
    InnerAbilityInfo innerAbilityInfo;
    BMSFuzzTestUtil::GenerateAbilityInfo<InnerAbilityInfo>(fdp, innerAbilityInfo);
    bundleInfo.InsertAbilitiesInfo("key", innerAbilityInfo);
    applicationInfo.bundleType = BundleType::APP;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, userId, resourceInfos);
    bundleInfo.InsertExtensionInfo("key", innerExtensionInfo);
    BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, userId, resourceInfos);
    BundleResourceProcess::GetAppIndexByBundleName(ABILITY_NAME);
    BundleResourceProcess::GetCurDynamicIconModule(ABILITY_NAME, userId, state);
    ExtendResourceInfo extendResourceInfo;
    BundleResourceProcess::GetExtendResourceInfo(ABILITY_NAME, MODULE_NAME, extendResourceInfo);
    BundleResourceProcess::IsOnlineTheme(ABILITY_NAME);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPIOne(data, size);
    OHOS::DoSomethingInterestingWithMyAPITwo(data, size);
    OHOS::DoSomethingInterestingWithMyAPIThree(data, size);
    return 0;
}