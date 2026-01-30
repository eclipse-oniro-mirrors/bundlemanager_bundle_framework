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

#include "bundle_resource_proxy.h"

#include "bmsbundleresourceproxy_fuzzer.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> object;
    BundleResourceProxy bundleResourceProxy(object);

    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    BundleResourceInfo bundleResourceInfo;
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    bundleResourceProxy.GetBundleResourceInfo(bundleName, flags, bundleResourceInfo, appIndex);
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    bundleResourceProxy.GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfo, appIndex);
    std::vector<BundleResourceInfo> bundleResourceInfos;
    bundleResourceProxy.GetAllBundleResourceInfo(flags, bundleResourceInfos);
    bundleResourceProxy.GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfo);
    int32_t userId = GenerateRandomUser(fdp);
    bundleResourceProxy.AddResourceInfoByBundleName(bundleName, userId);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleResourceProxy.AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    std::string key = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleResourceProxy.DeleteResourceInfo(key);
    ExtensionAbilityType extensionAbilityType =
        static_cast<ExtensionAbilityType>(fdp.ConsumeIntegralInRange<uint16_t>(0, EXTENSION_ABILITY_MAX));
    bundleResourceProxy.GetExtensionAbilityResourceInfo(bundleName, extensionAbilityType, flags,
        launcherAbilityResourceInfo, appIndex);

    std::vector<BundleOptionInfo> optionsList;
    BundleOptionInfo bundleOptionInfo;
    GenerateBundleOptionInfo(fdp, bundleOptionInfo);
    bundleOptionInfo.appIndex = 0;
    optionsList.emplace_back(bundleOptionInfo);
    bundleResourceProxy.GetLauncherAbilityResourceInfoList(optionsList,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), launcherAbilityResourceInfo);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}