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

#include "bundle_user_info.h"
#include "parcel.h"

#include "bmsbundleuserinfo_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        Parcel dataMessageParcel;
        BundleUserInfo bundleUserInfo;
        FuzzedDataProvider fdp(data, size);
        GenerateBundleUserInfo(fdp, bundleUserInfo);
        if (!bundleUserInfo.Marshalling(dataMessageParcel)) {
            return false;
        }
        auto rulePtr = BundleUserInfo::Unmarshalling(dataMessageParcel);
        if (rulePtr == nullptr) {
            return false;
        }
        delete rulePtr;
        rulePtr = nullptr;
        BundleUserInfo newBundleUserInfo;
        GenerateBundleUserInfo(fdp, newBundleUserInfo);
        bool ret = newBundleUserInfo.ReadFromParcel(dataMessageParcel);
        return ret;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
