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

#include "bmscheckencryptionparam_fuzzer.h"
#include "ipc/check_encryption_param.h"
#include "parcel_macro.h"
#include "string_ex.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    constexpr uint32_t CODE_MAX = 26;
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    CheckEncryptionParam checkEncryptionParam;
    FuzzedDataProvider fdp(data, size);
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH)));
    parcel.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    parcel.WriteUint32(fdp.ConsumeIntegralInRange<uint32_t>(0, CODE_MAX));

    checkEncryptionParam.ReadFromParcel(parcel);
    checkEncryptionParam.Marshalling(parcel);
    if (!checkEncryptionParam.Marshalling(parcel)) {
            return false;
        }
    auto rulePtr = CheckEncryptionParam::Unmarshalling(parcel);
        if (rulePtr == nullptr) {
            return false;
        }
        delete rulePtr;
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