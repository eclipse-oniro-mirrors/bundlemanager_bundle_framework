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
#include "bms_extension_client.h"
#include "bmsextensionclient_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using Want = OHOS::AAFwk::Want;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS
{
    bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
    {
        Want want;
        FuzzedDataProvider fdp(data, size);
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bool boolParam = fdp.ConsumeBool();
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
        int32_t flags = fdp.ConsumeIntegral<int32_t>();
        bmsExtensionClient.QueryLauncherAbility(want, userId, abilityInfos);
        bmsExtensionClient.QueryAbilityInfos(want, flags, userId, abilityInfos);
        bmsExtensionClient.BatchQueryAbilityInfos(wants, flags, userId, abilityInfos);
        bmsExtensionClient.QueryAbilityInfo(want, flags, userId, abilityInfo);
        bmsExtensionClient.GetBundleInfos(flags, bundleInfos, userId);
        bmsExtensionClient.GetBundleInfo(bundleName, flags, bundleInfo, userId, boolParam);
        bmsExtensionClient.BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
        bmsExtensionClient.ImplicitQueryAbilityInfos(want, flags, userId, abilityInfos, boolParam);
        bmsExtensionClient.GetBundleStats(bundleName, userId, bundleStats);
        bmsExtensionClient.ClearCache(bundleName, callback, userId);
        bmsExtensionClient.ClearData(bundleName, userId);
        int32_t uid = fdp.ConsumeIntegral<int32_t>();
        bmsExtensionClient.GetUidByBundleName(bundleName, userId, uid);
        bmsExtensionClient.GetBundleNameByUid(uid, bundleName);
        bmsExtensionClient.ModifyLauncherAbilityInfo(abilityInfo);
        bmsExtensionClient.GetDataMgr();
        return true;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}