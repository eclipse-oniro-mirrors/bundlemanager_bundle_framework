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

#include "bundle_mgr_proxy.h"

#include "bundlemgrproxy_fuzzer.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
namespace OHOS {
    constexpr size_t THRESHOLD = 2;
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object;
        BundleMgrProxy bundleMgrProxy(object);
        std::string bundleName (reinterpret_cast<const char*>(data), size);
        BundleInfo bundleInfo;
        bundleInfo.name = bundleName;
        std::vector<BundleInfo> bundleInfos;
        bundleInfos.push_back(bundleInfo);
        bundleMgrProxy.QueryKeepAliveBundleInfos(bundleInfos);

        sptr<IBundleStatusCallback> bundleStatusCallback;
        bundleMgrProxy.RegisterBundleStatusCallback(bundleStatusCallback);
        bundleMgrProxy.ClearBundleStatusCallback(bundleStatusCallback);

        DumpFlag flag = DumpFlag::DUMP_BUNDLE_LIST;
        std::string result (reinterpret_cast<const char*>(data), size);
        bundleMgrProxy.DumpInfos(flag, bundleName, reinterpret_cast<uintptr_t>(data), result);

        bool isEnable = false;
        if (size % THRESHOLD) {
            isEnable = true;
        }
        bundleMgrProxy.IsApplicationEnabled(bundleName, isEnable);
        bundleMgrProxy.SetApplicationEnabled(bundleName, isEnable, reinterpret_cast<uintptr_t>(data));

        AbilityInfo abilityInfo;
        bundleMgrProxy.IsAbilityEnabled(abilityInfo, isEnable);
        bundleMgrProxy.SetAbilityEnabled(abilityInfo, isEnable, reinterpret_cast<uintptr_t>(data));

        FormInfo formInfo;
        formInfo.bundleName = bundleName;
        std::vector<FormInfo> formInfos;
        formInfos.push_back(formInfo);
        bundleMgrProxy.GetAllFormsInfo(formInfos);
        bundleMgrProxy.GetFormsInfoByApp(bundleName, formInfos);
        std::string moduleName (reinterpret_cast<const char*>(data), size);
        bundleMgrProxy.GetFormsInfoByModule(bundleName, moduleName, formInfos);

        ShortcutInfo shortcutInfo;
        shortcutInfo.bundleName = bundleName;
        std::vector<ShortcutInfo> shortcutInfos;
        shortcutInfos.push_back(shortcutInfo);
        bundleMgrProxy.GetShortcutInfos(bundleName, shortcutInfos);
        bundleMgrProxy.GetShortcutInfoV9(bundleName, shortcutInfos);

        std::string eventKey (reinterpret_cast<const char*>(data), size);
        CommonEventInfo commonEventInfo;
        commonEventInfo.bundleName = bundleName;
        std::vector<CommonEventInfo> commonEventInfos;
        commonEventInfos.push_back(commonEventInfo);
        bundleMgrProxy.GetAllCommonEventInfo(eventKey, commonEventInfos);

        std::string networkId (reinterpret_cast<const char*>(data), size);
        DistributedBundleInfo distributedBundleInfo;
        bundleMgrProxy.GetDistributedBundleInfo(networkId, bundleName, distributedBundleInfo);
        bundleMgrProxy.GetAppPrivilegeLevel(bundleName, reinterpret_cast<uintptr_t>(data));

        Want want;
        want.SetAction(bundleName);
        ExtensionAbilityInfo extensionInfo;
        extensionInfo.bundleName = bundleName;
        std::vector<ExtensionAbilityInfo> extensionInfos;
        extensionInfos.push_back(extensionInfo);
        bundleMgrProxy.QueryExtensionAbilityInfos(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), extensionInfos);
        bundleMgrProxy.QueryExtensionAbilityInfosV9(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), extensionInfos);
        ExtensionAbilityType extensionType = ExtensionAbilityType::WORK_SCHEDULER;
        bundleMgrProxy.QueryExtensionAbilityInfos(want, extensionType,
            reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data), extensionInfos);
        bundleMgrProxy.QueryExtensionAbilityInfosV9(want, extensionType,
            reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data), extensionInfos);
        bundleMgrProxy.QueryExtensionAbilityInfos(extensionType,
            reinterpret_cast<uintptr_t>(data), extensionInfos);

        std::string permission (reinterpret_cast<const char*>(data), size);
        bundleMgrProxy.VerifyCallingPermission(permission);
        bundleMgrProxy.GetAccessibleAppCodePaths(reinterpret_cast<uintptr_t>(data));
        std::string uri (reinterpret_cast<const char*>(data), size);
        bundleMgrProxy.QueryExtensionAbilityInfoByUri(uri, reinterpret_cast<uintptr_t>(data), extensionInfo);
        bundleMgrProxy.ImplicitQueryInfoByPriority(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), abilityInfo, extensionInfo);

        abilityInfo.name = bundleName;
        std::vector<AbilityInfo> abilityInfos;
        abilityInfos.push_back(abilityInfo);
        bundleMgrProxy.ImplicitQueryInfos(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), abilityInfos, extensionInfos);
        
        std::string abilityName (reinterpret_cast<const char*>(data), size);
        bundleMgrProxy.GetAbilityInfo(bundleName, abilityName, abilityInfo);
        bundleMgrProxy.GetAbilityInfo(bundleName, moduleName, abilityName, abilityInfo);
        BundleInfo info;
        bundleMgrProxy.GetSandboxBundleInfo(bundleName, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), info);
        bundleMgrProxy.IsModuleRemovable(bundleName, moduleName, isEnable);
        bundleMgrProxy.SetModuleRemovable(bundleName, moduleName, isEnable);
        std::vector<std::string> dependentModuleNames;
        dependentModuleNames.push_back(bundleName);
        bundleMgrProxy.GetAllDependentModuleNames(bundleName, moduleName, dependentModuleNames);
        bundleMgrProxy.GetModuleUpgradeFlag(bundleName, moduleName);
        bundleMgrProxy.SetModuleUpgradeFlag(bundleName, moduleName, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.SetDisposedStatus(bundleName, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetDisposedStatus(bundleName);
        bundleMgrProxy.ObtainCallingBundleName(bundleName);
        std::vector<int64_t> bundleStats;
        bundleStats.push_back(reinterpret_cast<intptr_t>(data));
        bundleMgrProxy.GetBundleStats(bundleName, reinterpret_cast<uintptr_t>(data), bundleStats);
        sptr<IRemoteObject> callback;
        bundleMgrProxy.CheckAbilityEnableInstall(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), callback);
        std::unique_ptr<uint8_t[]> mediaDataPtr;
        bundleMgrProxy.GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr,
            size, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetStringById(bundleName, moduleName, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetIconById(bundleName, moduleName, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data));
        std::string udid (reinterpret_cast<const char*>(data), size);
        bundleMgrProxy.GetUdidByNetworkId(networkId, udid);
        bundleMgrProxy.GetSandboxAbilityInfo(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data), abilityInfo);
        bundleMgrProxy.GetSandboxExtAbilityInfos(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data), extensionInfos);
        HapModuleInfo hapModuleInfo;
        bundleMgrProxy.GetSandboxHapModuleInfo(abilityInfo, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), hapModuleInfo);
        bundleMgrProxy.IsSafeMode();
        bundleMgrProxy.UnregisterBundleStatusCallback();
        bundleMgrProxy.GetBundleInstaller();
        bundleMgrProxy.GetBundleUserMgr();
        bundleMgrProxy.GetQuickFixManagerProxy();
        bundleMgrProxy.GetAppControlProxy();
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