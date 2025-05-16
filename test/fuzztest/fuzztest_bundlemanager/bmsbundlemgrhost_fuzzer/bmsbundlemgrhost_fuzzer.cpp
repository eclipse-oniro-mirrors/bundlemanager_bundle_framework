/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "bmsbundlemgrhost_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "bundle_mgr_host.h"
#include "securec.h"
#include "../../bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t CODE_MAX = 187;

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    for (uint32_t code = 0; code <= CODE_MAX; code++) {
        MessageParcel datas;
        std::u16string descriptor = BundleMgrHost::GetDescriptor();
        datas.WriteInterfaceToken(descriptor);
        datas.WriteBuffer(data, size);
        datas.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        BundleMgrHost bundleMgrHost;
        bundleMgrHost.OnRemoteRequest(code, datas, reply, option);
    }
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}