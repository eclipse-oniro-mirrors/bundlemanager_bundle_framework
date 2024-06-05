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

#include <cstddef>
#include <cstdint>

#include "bms_extension_client.h"

#include "bmsextensionclient_fuzzer.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
namespace OHOS {
    constexpr uint8_t ENABLE = 2;
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {   
        Want want;
        std::string bundleName (reinterpret_cast<const char*>(data), size);
        bool boolParam = *data % ENABLE;
        want.SetAction(bundleName);
        std::vector<AbilityInfo> abilityInfos;
        AbilityInfo abilityInfo;
        std::vector<Want> wants;
        const std::vector<std::string> bundleNames;
        std::vector<BundleInfo> bundleInfos;
        std::vector<int64_t> bundleStats;
        sptr<IRemoteObject> callback;
        BmsExtensionClient bmsExtensionClient;
        BundleInfo bundleInfo;
        bmsExtensionClient.QueryLauncherAbility(want, reinterpret_cast<uintptr_t>(data),
        abilityInfos);
        bmsExtensionClient.QueryAbilityInfos(want, reinterpret_cast<uintptr_t>(data),
                                            reinterpret_cast<uintptr_t>(data),
                                            abilityInfos);
        bmsExtensionClient.BatchQueryAbilityInfos(wants, reinterpret_cast<uintptr_t>(data),
                                                  reinterpret_cast<uintptr_t>(data),
                                                  abilityInfos);
        bmsExtensionClient.QueryAbilityInfo(want, reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data), abilityInfo);
        bmsExtensionClient.GetBundleInfos(reinterpret_cast<uintptr_t>(data), bundleInfos, reinterpret_cast<uintptr_t>(data));
        bmsExtensionClient.GetBundleInfo(bundleName, reinterpret_cast<uintptr_t>(data), bundleInfo, reinterpret_cast<uintptr_t>(data), boolParam);
        bmsExtensionClient.BatchGetBundleInfo(bundleNames, reinterpret_cast<uintptr_t>(data),
                                              bundleInfos, reinterpret_cast<uintptr_t>(data));
        bmsExtensionClient.ImplicitQueryAbilityInfos(want, reinterpret_cast<uintptr_t>(data),
                                                     reinterpret_cast<uintptr_t>(data),
                                                     abilityInfos, boolParam);
        bmsExtensionClient.GetBundleStats(bundleName, reinterpret_cast<uintptr_t>(data), bundleStats);
        bmsExtensionClient.ClearCache(bundleName, callback, reinterpret_cast<uintptr_t>(data));
        bmsExtensionClient.ClearData(bundleName, reinterpret_cast<uintptr_t>(data));
        int32_t uid =  reinterpret_cast<int32_t>(data);
        bmsExtensionClient.GetUidByBundleName(bundleName, reinterpret_cast<uintptr_t>(data),
                                              uid);
        bmsExtensionClient.GetBundleNameByUid(reinterpret_cast<uintptr_t>(data), bundleName);
                                             
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