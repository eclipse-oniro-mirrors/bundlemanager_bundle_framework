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

#include "bmsbundlestreaminstallerhost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bundle_stream_installer_host.h"
#include "message_parcel.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint32_t CODE_MAX = 4;

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    std::u16string descriptor = BundleStreamInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleStreamInstallerHost host;
    FuzzedDataProvider fdp(data, size);
    uint8_t code = fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX);
    host.OnRemoteRequest(code, datas, reply, option);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}