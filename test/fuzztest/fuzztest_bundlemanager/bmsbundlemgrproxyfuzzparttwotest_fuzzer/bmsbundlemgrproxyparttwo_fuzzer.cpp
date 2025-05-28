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

#include "bundle_mgr_proxy.h"

#include "bmsbundlemgrproxyparttwo_fuzzer.h"
#include "../../bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object;
        BundleMgrProxy bundleMgrProxy(object);
        FuzzedDataProvider fdp(data, size);

        ElementName name;
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        name.SetBundleName(bundleName);
        Want want;
        want.SetElement(name);
        std::vector<Want> wants;
        wants.push_back(want);
        int32_t flags = fdp.ConsumeIntegral<int32_t>();
        int32_t userId = fdp.ConsumeIntegral<int32_t>();
        std::vector<BundleInfo> bundleInfos;
        bundleMgrProxy.BatchGetBundleInfo(wants, flags, bundleInfos, userId);
        std::vector<std::string> bundleNames = GenerateStringArray(fdp);
        bundleMgrProxy.BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
        BundleInfo bundleInfo;
        bundleMgrProxy.GetBundleInfoForSelf(flags, bundleInfo);
        BundlePackInfo bundlePackInfo;
        bundleMgrProxy.GetBundlePackInfo(bundleName, flags, bundlePackInfo, userId);
        bundleMgrProxy.GetBundlePackInfo(bundleName, BundleFlag::GET_BUNDLE_DEFAULT, bundlePackInfo, userId);
        bundleMgrProxy.GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, userId);
        bundleMgrProxy.GetBundleInfos(flags, bundleInfos, userId);
        bundleMgrProxy.GetBundleInfosV9(flags, bundleInfos, userId);
        int uid = bundleMgrProxy.GetUidByBundleName(bundleName, userId);
        int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
        bundleMgrProxy.GetUidByBundleName(bundleName, userId, appIndex);
        bundleMgrProxy.GetUidByDebugBundleName(bundleName, userId);
        std::string appId = bundleMgrProxy.GetAppIdByBundleName(bundleName, userId);
        bundleMgrProxy.GetBundleNameForUid(uid, bundleName);
        bundleMgrProxy.GetBundlesForUid(uid, bundleNames);
        bundleMgrProxy.GetNameAndIndexForUid(uid, bundleName, appIndex);
        std::vector<int> gids;
        bundleMgrProxy.GetBundleGids(bundleName, gids);
        bundleMgrProxy.GetBundleGidsByUid(bundleName, uid, gids);
        bundleMgrProxy.GetAppType(bundleName);
        bundleMgrProxy.CheckIsSystemAppByUid(uid);
        std::string metaData = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.GetBundleInfosByMetaData(metaData, bundleInfos);
        AbilityInfo abilityInfo;
        bundleMgrProxy.QueryAbilityInfo(want, abilityInfo);
        bundleMgrProxy.QueryAbilityInfo(want, flags, userId, abilityInfo, nullptr);
        bundleMgrProxy.UpgradeAtomicService(want, userId);
        bundleMgrProxy.QueryAbilityInfo(want, flags, userId, abilityInfo);
        std::vector<AbilityInfo> abilityInfos;
        bundleMgrProxy.QueryAbilityInfos(want, abilityInfos);
        bundleMgrProxy.QueryAbilityInfos(
            want, GET_ABILITY_INFO_DEFAULT, userId, abilityInfos);
        bundleMgrProxy.QueryAbilityInfosV9(
            want, GET_ABILITY_INFO_DEFAULT, userId, abilityInfos);
        bundleMgrProxy.QueryAbilityInfos(
            want, GET_ABILITY_INFO_DEFAULT, userId, abilityInfos);
        bundleMgrProxy.QueryLauncherAbilityInfos(want, userId, abilityInfos);
        bundleMgrProxy.QueryAllAbilityInfos(want, userId, abilityInfos);
        std::string uri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.QueryAbilityInfoByUri(uri, abilityInfo);
        bundleMgrProxy.QueryAbilityInfosByUri(uri, abilityInfos);
        bundleMgrProxy.QueryAbilityInfoByUri(uri, userId, abilityInfo);
        bundleMgrProxy.QueryKeepAliveBundleInfos(bundleInfos);
        std::string abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.GetAbilityLabel(bundleName, abilityName);
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