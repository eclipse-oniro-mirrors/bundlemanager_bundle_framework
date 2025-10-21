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
#include "extend_resource_manager_host.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bmsextendresourcemanagerhost_fuzzer.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    ExtendResourceManagerHost host;
    uint32_t code = fdp.ConsumeIntegral<uint32_t>();
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    host.OnRemoteRequest(code, datas, reply, option);
    host.OnRemoteRequest(static_cast<uint32_t>
        (ExtendResourceManagerInterfaceCode::ADD_EXT_RESOURCE), datas, reply, option);
    host.OnRemoteRequest(static_cast<uint32_t>
        (ExtendResourceManagerInterfaceCode::REMOVE_EXT_RESOURCE), datas, reply, option);
    host.OnRemoteRequest(static_cast<uint32_t>
        (ExtendResourceManagerInterfaceCode::GET_EXT_RESOURCE), datas, reply, option);
    host.OnRemoteRequest(static_cast<uint32_t>
        (ExtendResourceManagerInterfaceCode::ENABLE_DYNAMIC_ICON), datas, reply, option);
    host.OnRemoteRequest(static_cast<uint32_t>
        (ExtendResourceManagerInterfaceCode::DISABLE_DYNAMIC_ICON), datas, reply, option);
    host.OnRemoteRequest(static_cast<uint32_t>
        (ExtendResourceManagerInterfaceCode::GET_DYNAMIC_ICON), datas, reply, option);
    host.OnRemoteRequest(static_cast<uint32_t>
        (ExtendResourceManagerInterfaceCode::CREATE_FD), datas, reply, option);
    host.OnRemoteRequest(static_cast<uint32_t>
        (ExtendResourceManagerInterfaceCode::GET_ALL_DYNAMIC_ICON_INFO), datas, reply, option);
    host.OnRemoteRequest(static_cast<uint32_t>
        (ExtendResourceManagerInterfaceCode::GET_DYNAMIC_ICON_INFO), datas, reply, option);
    host.HandleAddExtResource(datas, reply);
    host.HandleRemoveExtResource(datas, reply);
    host.HandleGetExtResource(datas, reply);
    host.HandleEnableDynamicIcon(datas, reply);
    host.HandleDisableDynamicIcon(datas, reply);
    host.HandleGetDynamicIcon(datas, reply);
    host.HandleCreateFd(datas, reply);
    host.HandleGetAllDynamicIconInfo(datas, reply);
    host.HandleGetDynamicIconInfo(datas, reply);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}