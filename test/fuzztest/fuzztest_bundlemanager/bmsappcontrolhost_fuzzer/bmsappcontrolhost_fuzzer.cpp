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
#include "bmsappcontrolhost_fuzzer.h"

#include <cstddef>
#include <cstdint>
 #include <fuzzer/FuzzedDataProvider.h>

#include "app_control_host.h"
#include "securec.h"
 #include "../../bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr uint32_t CODE_MAX = 26;

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    AppControlHost appControlHost;
    MessageParcel datas;
    MessageParcel reply;
    appControlHost.HandleAddAppInstallControlRule(datas, reply);
    appControlHost.HandleDeleteAppInstallControlRule(datas, reply);

    FuzzedDataProvider fdp(data, size);
    uint8_t code = fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX);
    std::u16string descriptor = AppControlHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageOption option;
    appControlHost.OnRemoteRequest(code, datas, reply, option);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}