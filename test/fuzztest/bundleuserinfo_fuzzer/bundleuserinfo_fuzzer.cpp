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

#include "bundle_user_info.h"
#include "parcel.h"

#include "bundleuserinfo_fuzzer.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        Parcel dataMessageParcel;
        std::string disabledAbilities (reinterpret_cast<const char*>(data), size);
        BundleUserInfo oldRule;
        oldRule.disabledAbilities.push_back(disabledAbilities);
        oldRule.IsInitialState();
        oldRule.Reset();
        if (!oldRule.Marshalling(dataMessageParcel)) {
            return false;
        }
        auto rulePtr = BundleUserInfo::Unmarshalling(dataMessageParcel);
        if (rulePtr == nullptr) {
            return false;
        }
        delete rulePtr;
        rulePtr = nullptr;
        BundleUserInfo *readRule = new (std::nothrow) BundleUserInfo();
        if (readRule == nullptr) {
            return false;
        }
        bool ret = readRule->ReadFromParcel(dataMessageParcel);
        delete readRule;
        readRule = nullptr;
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
