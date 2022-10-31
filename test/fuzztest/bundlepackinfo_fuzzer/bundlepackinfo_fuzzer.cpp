/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bundle_pack_info.h"
#include "parcel.h"

#include "bundlepackinfo_fuzzer.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        Parcel dataMessageParcel;
        BundlePackInfo info;
        if (dataMessageParcel.WriteBuffer(data, size)) {
            info.Marshalling(dataMessageParcel);
            auto infoPtr = BundlePackInfo::Unmarshalling(dataMessageParcel);
            return infoPtr != nullptr;
        }
        info.SetValid(true);
        info.GetValid();
        BundlePackInfo *bundlePackInfo = new (std::nothrow) BundlePackInfo();
        if (bundlePackInfo == nullptr) {
            return false;
        }
        bundlePackInfo->ReadFromParcel(dataMessageParcel);
        delete bundlePackInfo;
        bundlePackInfo = nullptr;
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
