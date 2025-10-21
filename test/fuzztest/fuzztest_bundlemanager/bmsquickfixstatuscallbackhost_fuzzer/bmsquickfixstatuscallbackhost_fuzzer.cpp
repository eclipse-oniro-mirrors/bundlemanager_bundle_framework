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
#define private public
#include "quick_fix_status_callback_host.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bmsquickfixstatuscallbackhost_fuzzer.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
class QuickFixStatusCallbackHostTest : public QuickFixStatusCallbackHost {
public:
    QuickFixStatusCallbackHostTest() = default;
    virtual ~QuickFixStatusCallbackHostTest() = default;
    void OnPatchDeployed(const std::shared_ptr<QuickFixResult> &result)
    {
        return;
    }
    void OnPatchSwitched(const std::shared_ptr<QuickFixResult> &result)
    {
        return;
    }
    void OnPatchDeleted(const std::shared_ptr<QuickFixResult> &result)
    {
        return;
    }
};
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    QuickFixStatusCallbackHostTest quickFixStatusCallbackHost;

    uint32_t code = fdp.ConsumeIntegral<uint32_t>();
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    quickFixStatusCallbackHost.OnRemoteRequest(code, datas, reply, option);
    quickFixStatusCallbackHost.OnRemoteRequest(static_cast<uint32_t>
        (QuickFixStatusCallbackInterfaceCode::ON_PATCH_DEPLOYED), datas, reply, option);
    quickFixStatusCallbackHost.OnRemoteRequest(static_cast<uint32_t>
        (QuickFixStatusCallbackInterfaceCode::ON_PATCH_SWITCHED), datas, reply, option);
    quickFixStatusCallbackHost.OnRemoteRequest(static_cast<uint32_t>
        (QuickFixStatusCallbackInterfaceCode::ON_PATCH_DELETED), datas, reply, option);
    quickFixStatusCallbackHost.HandleOnPatchDeployed(datas, reply);
    quickFixStatusCallbackHost.HandleOnPatchSwitched(datas, reply);
    quickFixStatusCallbackHost.HandleOnPatchDeleted(datas, reply);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}