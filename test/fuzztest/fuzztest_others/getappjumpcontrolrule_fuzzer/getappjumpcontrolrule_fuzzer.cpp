/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "getappjumpcontrolrule_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "app_control_proxy.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object;
    AppControlProxy appControl(object);
    std::string callerBundleName;
    std::string targetBundleName;
    AppJumpControlRule controlRules;
    appControl.GetAppJumpControlRule(
        callerBundleName, targetBundleName, reinterpret_cast<uintptr_t>(data), controlRules);
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}