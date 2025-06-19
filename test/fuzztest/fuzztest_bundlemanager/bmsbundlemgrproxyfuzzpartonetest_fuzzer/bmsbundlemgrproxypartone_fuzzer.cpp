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

#include "bundle_mgr_proxy.h"

#include "bmsbundlemgrproxypartone_fuzzer.h"
#include "bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object;
        BundleMgrProxy bundleMgrProxy(object);
        FuzzedDataProvider fdp(data, size);
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        BundleInfo bundleInfo;
        GenerateBundleInfo(fdp, bundleInfo);
        std::vector<BundleInfo> bundleInfos;
        bundleMgrProxy.QueryKeepAliveBundleInfos(bundleInfos);

        sptr<IBundleStatusCallback> bundleStatusCallback;
        bundleMgrProxy.RegisterBundleStatusCallback(bundleStatusCallback);
        bundleMgrProxy.ClearBundleStatusCallback(bundleStatusCallback);

        DumpFlag dumpFlag = static_cast<DumpFlag>(fdp.ConsumeIntegralInRange<uint8_t>(1, 4));
        int32_t userId = GenerateRandomUser(fdp);
        std::string result = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.DumpInfos(dumpFlag, bundleName, userId, result);

        bool isEnable = fdp.ConsumeBool();
        bundleMgrProxy.IsApplicationEnabled(bundleName, isEnable);
        bundleMgrProxy.SetApplicationEnabled(bundleName, isEnable, userId);

        AbilityInfo abilityInfo;
        GenerateAbilityInfo(fdp, abilityInfo);
        bundleMgrProxy.IsAbilityEnabled(abilityInfo, isEnable);
        bundleMgrProxy.SetAbilityEnabled(abilityInfo, isEnable, reinterpret_cast<uintptr_t>(data));

        FormInfo formInfo;
        formInfo.bundleName = bundleName;
        std::vector<FormInfo> formInfos;
        formInfos.push_back(formInfo);
        bundleMgrProxy.GetAllFormsInfo(formInfos);
        bundleMgrProxy.GetFormsInfoByApp(bundleName, formInfos);
        std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.GetFormsInfoByModule(bundleName, moduleName, formInfos);

        std::vector<ShortcutInfo> shortcutInfos;
        bundleMgrProxy.GetShortcutInfos(bundleName, shortcutInfos);
        bundleMgrProxy.GetShortcutInfoV9(bundleName, shortcutInfos);

        std::string eventKey = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::vector<CommonEventInfo> commonEventInfos;
        bundleMgrProxy.GetAllCommonEventInfo(eventKey, commonEventInfos);

        std::string networkId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        DistributedBundleInfo distributedBundleInfo;
        bundleMgrProxy.GetDistributedBundleInfo(networkId, bundleName, distributedBundleInfo);
        bundleMgrProxy.GetAppPrivilegeLevel(bundleName, reinterpret_cast<uintptr_t>(data));

        Want want;
        want.SetAction(bundleName);
        ExtensionAbilityInfo extensionInfo;
        std::vector<ExtensionAbilityInfo> extensionInfos;
        int32_t flag = fdp.ConsumeIntegral<int32_t>();
        bundleMgrProxy.QueryExtensionAbilityInfos(want, userId, flag, extensionInfos);
        bundleMgrProxy.QueryExtensionAbilityInfosV9(want, userId, flag, extensionInfos);
        ExtensionAbilityType extensionType =
            static_cast<ExtensionAbilityType>(fdp.ConsumeIntegralInRange<uint8_t>(0, 24));
        bundleMgrProxy.QueryExtensionAbilityInfos(want, extensionType, userId, flag, extensionInfos);
        bundleMgrProxy.QueryExtensionAbilityInfosV9(want, extensionType, userId, flag, extensionInfos);
        bundleMgrProxy.QueryExtensionAbilityInfos(extensionType, flag, extensionInfos);
        std::string permission = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.VerifyCallingPermission(permission);
        std::string uri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.QueryExtensionAbilityInfoByUri(uri, userId, extensionInfo);
        bundleMgrProxy.ImplicitQueryInfoByPriority(want, userId, flag, abilityInfo, extensionInfo);

        abilityInfo.name = bundleName;
        std::vector<AbilityInfo> abilityInfos;
        abilityInfos.push_back(abilityInfo);
        bool findDafaultApp = fdp.ConsumeBool();
        bool withDefault = fdp.ConsumeBool();
        bundleMgrProxy.ImplicitQueryInfos(
            want, flag, userId, withDefault, abilityInfos, extensionInfos, findDafaultApp);

        std::string abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.GetAbilityInfo(bundleName, abilityName, abilityInfo);
        bundleMgrProxy.GetAbilityInfo(bundleName, moduleName, abilityName, abilityInfo);
        BundleInfo info;
        int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
        bundleMgrProxy.GetSandboxBundleInfo(bundleName, appIndex, userId, info);
        bundleMgrProxy.IsModuleRemovable(bundleName, moduleName, isEnable);
        bundleMgrProxy.SetModuleRemovable(bundleName, moduleName, isEnable);
        std::vector<std::string> dependentModuleNames;
        bundleMgrProxy.GetAllDependentModuleNames(bundleName, moduleName, dependentModuleNames);
        bundleMgrProxy.GetModuleUpgradeFlag(bundleName, moduleName);
        int32_t upgradeFlag = fdp.ConsumeIntegral<int32_t>();
        bundleMgrProxy.SetModuleUpgradeFlag(bundleName, moduleName, upgradeFlag);
        bundleMgrProxy.ObtainCallingBundleName(bundleName);
        std::vector<int64_t> bundleStats;
        bundleMgrProxy.GetBundleStats(bundleName, userId, bundleStats);
        sptr<IRemoteObject> callback;
        int32_t missionId = fdp.ConsumeIntegral<int32_t>();
        bundleMgrProxy.CheckAbilityEnableInstall(want, missionId, userId, callback);
        std::unique_ptr<uint8_t[]> mediaDataPtr;
        bundleMgrProxy.GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, size, userId);
        uint32_t resId = fdp.ConsumeIntegral<uint32_t>();
        std::string localeInfo = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.GetStringById(bundleName, moduleName, resId, userId, localeInfo);
        uint32_t density = fdp.ConsumeIntegral<uint32_t>();
        bundleMgrProxy.GetIconById(bundleName, moduleName, resId, density, userId);
        bundleMgrProxy.GetSandboxAbilityInfo(want, appIndex, flag, userId, abilityInfo);
        bundleMgrProxy.GetSandboxExtAbilityInfos(want, appIndex, flag, userId, extensionInfos);
        HapModuleInfo hapModuleInfo;
        bundleMgrProxy.GetSandboxHapModuleInfo(abilityInfo, appIndex, userId, hapModuleInfo);
        bundleMgrProxy.UnregisterBundleStatusCallback();
        bundleMgrProxy.GetBundleInstaller();
        bundleMgrProxy.GetBundleUserMgr();
        bundleMgrProxy.GetQuickFixManagerProxy();
        bundleMgrProxy.GetAppControlProxy();

        ApplicationInfo appInfo;
        bundleMgrProxy.GetApplicationInfo(bundleName, flag, userId, appInfo);
        bundleMgrProxy.GetApplicationInfo(bundleName, flag, userId, appInfo);
        bundleMgrProxy.GetApplicationInfoV9(bundleName, flag, userId, appInfo);
        std::vector<ApplicationInfo> appInfos;
        bundleMgrProxy.GetApplicationInfos(flag, userId, appInfos);
        bundleMgrProxy.GetApplicationInfos(flag, userId, appInfos);
        bundleMgrProxy.GetApplicationInfosV9(flag, userId, appInfos);
        bundleMgrProxy.GetBundleInfo(bundleName, flag, bundleInfo, userId);
        bundleMgrProxy.GetBundleInfo(bundleName, flag, bundleInfo, userId);
        bundleMgrProxy.GetBundleInfoV9(bundleName, flag, bundleInfo, userId);
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