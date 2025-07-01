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
#include "bundle_distributed_manager.h"
#include "bmscheckabilityenableinstall_fuzzer.h"
#include "bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
std::string DEVICE_ID_NORMAL = "deviceId";
std::string BUNDLE_NAME_TEST = "com.example.bundlekit.test";
std::string MODULE_NAME_MY_APPLICATION = "com.example.MyModuleName";
std::string ABILITY_NAME_MY_APPLICATION = "com.example.MyApplication.MainAbility";
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<BundleDistributedManager> BundleDistributedManager_ =
        std::make_shared<BundleDistributedManager>();
    if (BundleDistributedManager_ == nullptr) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    Want want;
    std::string deviceId = DEVICE_ID_NORMAL;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = GenerateRandomUser(fdp);
    sptr<IRemoteObject> callerToken = nullptr;
    BundleDistributedManager_->CheckAbilityEnableInstall(want, missionId, userId, callerToken);
#ifdef BMS_DEVICE_INFO_MANAGER_ENABLE
    RpcIdResult rpcIdResult;
    rpcIdResult.retCode = fdp.ConsumeIntegral<int32_t>();
    rpcIdResult.version = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    rpcIdResult.transactId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    rpcIdResult.resultMsg = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleDistributedManager_->ComparePcIdString(want, rpcIdResult);
#endif
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