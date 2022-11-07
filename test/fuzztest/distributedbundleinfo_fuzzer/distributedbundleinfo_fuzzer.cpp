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

#include "distributed_bundle_info.h"
#include "parcel.h"

#include "distributedbundleinfo_fuzzer.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        Parcel dataMessageParcel;
        DistributedBundleInfo info;
        bool ret = false;
        if (dataMessageParcel.WriteBuffer(data, size)) {
            info.Marshalling(dataMessageParcel);
            auto infoPtr = DistributedBundleInfo::Unmarshalling(dataMessageParcel);
            ret = (infoPtr != nullptr);
            if (ret) {
                delete infoPtr;
            }
        }
        std::string jsonString (reinterpret_cast<const char*>(data), size);
        info.FromJsonString(jsonString);
        info.ToString();
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
