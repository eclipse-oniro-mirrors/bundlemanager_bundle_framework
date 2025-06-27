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
#define private public
#include "bundle_manager_callback_stub.h"

#include "message_parcel.h"
#include "bmsbundlemanagercallbackstub_fuzzer.h"
#include "bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr size_t MESSAGE_SIZE = 10;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.appexecfwk.FormMgr";
class BundleManagerCallbackStubFuzzTest : public BundleManagerCallbackStub {
public:
    BundleManagerCallbackStubFuzzTest() = default;
    virtual ~BundleManagerCallbackStubFuzzTest() = default;
    int32_t OnQueryRpcIdFinished(const std::string &RpcIdResult) override
    {
        return 0;
    }
};
bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    BundleManagerCallbackStubFuzzTest bundleManagerCallbackStub;
    FuzzedDataProvider fdp(data, size);
    uint32_t code = fdp.ConsumeIntegralInRange<uint32_t>(0, MESSAGE_SIZE);
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    bundleManagerCallbackStub.OnRemoteRequest(code, datas, reply, option);
    MessageParcel data2;
    MessageParcel reply2;
    data2.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    data2.WriteBuffer(data, size);
    data2.RewindRead(0);
    bundleManagerCallbackStub.HandleQueryRpcIdCallBack(data2, reply2);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}