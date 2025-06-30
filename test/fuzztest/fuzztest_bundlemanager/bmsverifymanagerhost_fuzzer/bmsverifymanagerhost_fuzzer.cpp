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

#include "bmsverifymanagerhost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bms_fuzztest_util.h"
#include "securec.h"
#include "verify_manager_stub.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr size_t MESSAGE_SIZE = 3;

class MockVerifyManagerStub : public VerifyManagerStub {
public:
    int32_t CallbackEnter(uint32_t code) override
    {
        return 0;
    }
    
    int32_t CallbackExit(uint32_t code, int32_t result) override
    {
        return 0;
    }
    
    ErrCode Verify(const std::vector<std::string>& abcPaths, int32_t& funcResult) override
    {
        return ERR_OK;
    }
        
    ErrCode DeleteAbc(const std::string& path, int32_t& funcResult) override
    {
        return ERR_OK;
    }
};

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    uint32_t code = fdp.ConsumeIntegralInRange<uint32_t>(0, MESSAGE_SIZE);
    MessageParcel datas;
    std::u16string descriptor = MockVerifyManagerStub::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    MockVerifyManagerStub verifyManagerStub;
    verifyManagerStub.OnRemoteRequest(code, datas, reply, option);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}