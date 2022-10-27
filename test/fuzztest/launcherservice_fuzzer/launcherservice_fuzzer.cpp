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

#include "launcher_service.h"

#include "launcherservice_fuzzer.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        LauncherService launcherService;
        sptr<IBundleStatusCallback> callback;
        launcherService.RegisterCallback(callback);
        launcherService.UnRegisterCallback();
        std::string bundleName (reinterpret_cast<const char*>(data), size);
        LauncherAbilityInfo launcherAbilityInfo;
        launcherAbilityInfo.userId = reinterpret_cast<uintptr_t>(data);
        std::vector<LauncherAbilityInfo> launcherAbilityInfos;
        launcherAbilityInfos.push_back(launcherAbilityInfo);
        launcherService.GetAbilityList(bundleName, reinterpret_cast<uintptr_t>(data), launcherAbilityInfos);
        Want want;
        want.SetAction(bundleName);
        launcherService.GetAbilityInfo(want, reinterpret_cast<uintptr_t>(data), launcherAbilityInfo);
        ApplicationFlag flags = ApplicationFlag::GET_BASIC_APPLICATION_INFO;
        ApplicationInfo applicationInfo;
        launcherService.GetApplicationInfo(bundleName, flags, reinterpret_cast<uintptr_t>(data), applicationInfo);
        launcherService.IsBundleEnabled(bundleName);
        AbilityInfo abilityInfo;
        launcherService.IsAbilityEnabled(abilityInfo);
        ShortcutInfo shortcutInfo;
        shortcutInfo.bundleName = bundleName;
        std::vector<ShortcutInfo> shortcutInfos;
        shortcutInfos.push_back(shortcutInfo);
        launcherService.GetShortcutInfos(bundleName, shortcutInfos);
        launcherService.GetAllLauncherAbilityInfos(reinterpret_cast<uintptr_t>(data), launcherAbilityInfos);
        launcherService.GetLauncherAbilityByBundleName(bundleName,
            reinterpret_cast<uintptr_t>(data), launcherAbilityInfos);
        launcherService.GetAllLauncherAbility(reinterpret_cast<uintptr_t>(data), launcherAbilityInfos);
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