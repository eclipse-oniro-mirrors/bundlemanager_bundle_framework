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

#include "app_control_proxy.h"

#include "bmsappcontrolproxy_fuzzer.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object;
    AppControlProxy appControl(object);

    FuzzedDataProvider fdp(data, size);
    std::string callerBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = GenerateRandomUser(fdp);
    appControl.ConfirmAppJumpControlRule(callerBundleName, targetBundleName, userId);
    std::string appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    DisposedRule disposedRule;
    appControl.SetDisposedRule(appId, disposedRule, userId);
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    appControl.SetDisposedRules(disposedRuleConfigurations, userId);
    appControl.DeleteDisposedRules(disposedRuleConfigurations, userId);
    appControl.GetDisposedRule(appId, disposedRule, userId);
    appControl.GetDisposedRules(userId, disposedRuleConfigurations);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<DisposedRule> rules;
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    appControl.GetAbilityRunningControlRule(bundleName, userId, rules, appIndex);
    appControl.SetDisposedRuleForCloneApp(appId, disposedRule, appIndex, userId);
    appControl.GetDisposedRuleForCloneApp(appId, disposedRule, appIndex, userId);
    appControl.DeleteDisposedRuleForCloneApp(appId, appIndex, userId);
    std::string appIdentifier = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    UninstallDisposedRule uninstallDisposedRule;
    appControl.SetUninstallDisposedRule(appIdentifier, uninstallDisposedRule, appIndex, userId);
    appControl.GetUninstallDisposedRule(appIdentifier, appIndex, userId, uninstallDisposedRule);
    appControl.DeleteUninstallDisposedRule(appIdentifier, appIndex, userId);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}