/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <iostream>
#include "bundle_distributed_manager.h"
#include "distributedmanager_fuzzer.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;
namespace OHOS {

constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_SIZE = 21;
constexpr size_t DCAMERA_SHIFT_24 = 24;
constexpr size_t DCAMERA_SHIFT_16 = 16;
constexpr size_t DCAMERA_SHIFT_8 = 8;
uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << DCAMERA_SHIFT_24) | (ptr[1] << DCAMERA_SHIFT_16) | (ptr[2] << DCAMERA_SHIFT_8) | (ptr[3]);
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    BundleDistributedManager bundleDistributedManager;
    Want want;
    int32_t missionId = static_cast<int32_t>(GetU32Data(data));
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    sptr<IRemoteObject> callerToken = nullptr;
    bundleDistributedManager.CheckAbilityEnableInstall(want, missionId, userId, callerToken);
    std::string queryRpcIdResult(data, size);
    bundleDistributedManager.OnQueryRpcIdFinished(queryRpcIdResult);
    TargetAbilityInfo targetAbilityInfo;
    bundleDistributedManager.ConvertTargetAbilityInfo(want, targetAbilityInfo);
    bundleDistributedManager.QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
    int32_t resultCode = static_cast<int32_t>(GetU32Data(data));
    const std::string transactId(data, size);
    bundleDistributedManager.SendCallbackRequest(resultCode, transactId);
    QueryRpcIdParams queryRpcIdParams;
    bundleDistributedManager.SendCallback(resultCode, queryRpcIdParams);
    RpcIdResult rcIdResult;
    bundleDistributedManager.ComparePcIdString(want, rcIdResult);
    bundleDistributedManager.OutTimeMonitor(transactId);
    bundleDistributedManager.GetTransactId();
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

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}