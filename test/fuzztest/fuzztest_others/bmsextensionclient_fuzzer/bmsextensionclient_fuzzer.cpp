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
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bms_extension_client.h"
#include "bms_fuzztest_util.h"

#include "bmsextensionclient_fuzzer.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint8_t ENABLE = 2;
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        Want want;
        FuzzedDataProvider fdp(data, size);
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
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
        int32_t userId = GenerateRandomUser(fdp);
        bmsExtensionClient.QueryLauncherAbility(want, userId,
                                                abilityInfos);
        bmsExtensionClient.QueryAbilityInfos(want, userId,
                                             userId, abilityInfos);
        bmsExtensionClient.BatchQueryAbilityInfos(wants, userId,
                                                  userId,
                                                  abilityInfos);
        bmsExtensionClient.QueryAbilityInfo(want, userId,
                                            userId, abilityInfo);
        bmsExtensionClient.GetBundleInfos(userId, bundleInfos,
                                          userId);
        bmsExtensionClient.GetBundleInfo(bundleName, userId, bundleInfo,
                                         userId, boolParam);
        bmsExtensionClient.BatchGetBundleInfo(bundleNames, userId,
                                              bundleInfos, userId);
        bmsExtensionClient.ImplicitQueryAbilityInfos(want, userId,
                                                     userId,
                                                     abilityInfos, boolParam);
        bmsExtensionClient.GetBundleStats(bundleName, userId, bundleStats);
        bmsExtensionClient.ClearCache(bundleName, callback, userId);
        bmsExtensionClient.ClearData(bundleName, userId);
        int32_t uid =  3024;
        bmsExtensionClient.GetUidByBundleName(bundleName, userId,
                                              uid);
        bmsExtensionClient.GetBundleNameByUid(userId, bundleName);
    
        bmsExtensionClient.ModifyLauncherAbilityInfo(abilityInfo);
        bmsExtensionClient.GetDataMgr();
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