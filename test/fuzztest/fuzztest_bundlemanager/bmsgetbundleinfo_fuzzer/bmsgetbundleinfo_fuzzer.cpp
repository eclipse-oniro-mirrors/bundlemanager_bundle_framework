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

#include "bundle_mgr_proxy.h"

#include "bmsgetbundleinfo_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object;
        BundleMgrProxy bundleMgrProxy(object);
        FuzzedDataProvider fdp(data, size);
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        BundleFlag flag = static_cast<BundleFlag>(fdp.ConsumeIntegral<int32_t>());
        int32_t flags = fdp.ConsumeIntegral<int32_t>();
        int32_t userId = BMSFuzzTestUtil::GenerateRandomUser(fdp);
        BundleInfo bundleInfo;
        bundleMgrProxy.GetBundleInfo(bundleName, flag, bundleInfo, userId);
        bundleMgrProxy.GetBundleInfo(bundleName, flags, bundleInfo, userId);
        bundleMgrProxy.GetBundleInfoV9(bundleName, flags, bundleInfo, userId);

        BundleInfoForException bundleInfoForException;
        uint32_t catchSoNum = BMSFuzzTestUtil::GenerateRandomUser(fdp);
        uint64_t catchSoMaxSize = BMSFuzzTestUtil::GenerateRandomUser(fdp);
        bundleMgrProxy.GetBundleInfoForException(bundleName, userId, catchSoNum,
            catchSoMaxSize, bundleInfoForException);

        AssetGroupInfo assetGroupInfo;
        int32_t uid = BMSFuzzTestUtil::GenerateRandomUser(fdp);
        bundleMgrProxy.GetAssetGroupsInfo(uid, assetGroupInfo);
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