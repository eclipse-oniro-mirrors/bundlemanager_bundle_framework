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
#include <fuzzer/FuzzedDataProvider.h>
#include "bundle_resource_theme_process.h"
#include "bmsbundleresourcethemeprocess_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const int32_t TEST_USER_ID = 20000;
constexpr const char* TEST_BUNDLE_NAME = "com.example.bmsaccesstoken1";
constexpr const char* TEST_MODULE_NAME = "entry";
constexpr const char* TEST_ABILITY_NAME = "EntryAbility";
constexpr const char* COM_OHOS_CONTACTS_ENTRY_ABILITY = "com.ohos.contacts.EntryAbility";
constexpr const char* COM_OHOS_CONTACTS_ENTRY = "entry";
constexpr const char* COM_OHOS_CONTACTS = "com.ohos.contacts";
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = GenerateRandomUser(fdp);
    BundleResourceThemeProcess::IsBundleThemeExist("", userId);
    BundleResourceThemeProcess::IsBundleThemeExist(bundleName, userId);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleResourceThemeProcess::IsAbilityThemeExist("", "", "", userId);
    BundleResourceThemeProcess::IsAbilityThemeExist(bundleName, moduleName, abilityName, userId);
    BundleResourceThemeProcess::IsAbilityThemeExist(TEST_BUNDLE_NAME, TEST_MODULE_NAME, TEST_ABILITY_NAME,
        TEST_USER_ID);
    BundleResourceThemeProcess::IsThemeExistInFlagA(bundleName, userId);
    BundleResourceThemeProcess::IsThemeExistInFlagB(bundleName, userId);
    std::vector<LauncherAbilityResourceInfo> resourceIconInfos;
    BundleResourceInfo bundleResourceInfo;
    BundleResourceThemeProcess::ProcessSpecialBundleResource(resourceIconInfos, bundleResourceInfo);
    LauncherAbilityResourceInfo info;
    info.bundleName = COM_OHOS_CONTACTS;
    info.moduleName = COM_OHOS_CONTACTS_ENTRY;
    info.abilityName = COM_OHOS_CONTACTS_ENTRY_ABILITY;
    info.icon = "icon";
    info.foreground.push_back(1);
    info.background.push_back(1);
    resourceIconInfos.push_back(info);
    bundleResourceInfo.bundleName = TEST_BUNDLE_NAME;
    bundleResourceInfo.icon = "icon1";
    BundleResourceThemeProcess::ProcessSpecialBundleResource(resourceIconInfos, bundleResourceInfo);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
