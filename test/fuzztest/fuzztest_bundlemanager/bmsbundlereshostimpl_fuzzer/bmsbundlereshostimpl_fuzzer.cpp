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
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "bundle_resource_host_impl.h"
#include "bmsbundlereshostimpl_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleResourceInfo info;
    bundleResourceHostImpl->GetBundleResourceInfo(bundleName, 0, info);
    bundleResourceHostImpl->GetBundleResourceInfo(bundleName, 0, info, -1);
    std::vector<LauncherAbilityResourceInfo> launcherInfos;
    bundleResourceHostImpl->GetLauncherAbilityResourceInfo(bundleName, 0, launcherInfos);
    bundleResourceHostImpl->GetLauncherAbilityResourceInfo(bundleName, 0, launcherInfos, -1);
    std::vector<BundleResourceInfo> infos;
    bundleResourceHostImpl->GetAllBundleResourceInfo(0, infos);
    bundleResourceHostImpl->GetAllLauncherAbilityResourceInfo(0, launcherInfos);
    int32_t userId = GenerateRandomUser(fdp);
    bundleResourceHostImpl->AddResourceInfoByBundleName(bundleName, userId);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleResourceHostImpl->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    std::string key = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleResourceHostImpl->DeleteResourceInfo(key);
    int32_t appIndex = 1;
    bundleResourceHostImpl->CheckBundleNameValid(bundleName, appIndex);

    uint32_t flags = 0;
    bundleResourceHostImpl->CheckExtensionAbilityValid(bundleName, ExtensionAbilityType::INPUTMETHOD, flags, 0);
    bundleResourceHostImpl->CheckExtensionAbilityValid(bundleName, ExtensionAbilityType::INPUTMETHOD, flags, 1);
    
    std::vector<BundleOptionInfo> optionsList;
    BundleOptionInfo bundleOptionInfo;
    GenerateBundleOptionInfo(fdp, bundleOptionInfo);
    bundleOptionInfo.appIndex = 0;
    optionsList.push_back(bundleOptionInfo);
    bundleResourceHostImpl->GetLauncherAbilityResourceInfoList(optionsList, flags, launcherInfos);
    std::vector<LauncherAbilityResourceInfo> extensionAbilityResourceInfo;
    bundleResourceHostImpl->GetExtensionAbilityResourceInfo(bundleName, ExtensionAbilityType::INPUTMETHOD,
        flags, extensionAbilityResourceInfo, appIndex);
    std::vector<BundleResourceInfo> bundleResourceInfos;
    bundleResourceHostImpl->FilterUninstallResource(userId, bundleResourceInfos);
    bundleResourceHostImpl->GetAllUninstallBundleResourceInfo(userId, flags, bundleResourceInfos);
    std::vector<LauncherAbilityResourceInfo> allResources;
    LauncherAbilityResourceInfo resourceInfo;
    bundleResourceHostImpl->GetElementLauncherAbilityResourceInfo(allResources,
        moduleName, abilityName, appIndex, resourceInfo);
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