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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bms_fuzztest_util.h"
#include "launcher_service.h"

#include "launcherservice_fuzzer.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        LauncherService launcherService;
        FuzzedDataProvider fdp(data, size);
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        int32_t userId = GenerateRandomUser(fdp);
        std::vector<LauncherAbilityInfo> launcherAbilityInfos;
        launcherService.GetAbilityList(bundleName, userId, launcherAbilityInfos);

        std::vector<ShortcutInfo> shortcutInfos;
        launcherService.GetShortcutInfos(bundleName, shortcutInfos);
        launcherService.GetAllLauncherAbilityInfos(userId, launcherAbilityInfos);
        launcherService.GetLauncherAbilityByBundleName(bundleName,
            userId, launcherAbilityInfos);
        launcherService.GetAllLauncherAbility(userId, launcherAbilityInfos);
        launcherService.GetShortcutInfoV9(bundleName, shortcutInfos);
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