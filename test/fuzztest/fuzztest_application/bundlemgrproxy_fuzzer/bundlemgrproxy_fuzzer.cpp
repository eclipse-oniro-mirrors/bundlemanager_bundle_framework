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
        std::string uri (reinterpret_cast<const char*>(data), size);
        bundleMgrProxy.QueryExtensionAbilityInfoByUri(uri, reinterpret_cast<uintptr_t>(data), extensionInfo);
        bundleMgrProxy.ImplicitQueryInfoByPriority(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), abilityInfo, extensionInfo);

        abilityInfo.name = bundleName;
        std::vector<AbilityInfo> abilityInfos;
        abilityInfos.push_back(abilityInfo);
        bool findDafaultApp = false;
        bundleMgrProxy.ImplicitQueryInfos(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), true, abilityInfos, extensionInfos, findDafaultApp);

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
        bundleMgrProxy.GetSandboxAbilityInfo(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data), abilityInfo);
        bundleMgrProxy.GetSandboxExtAbilityInfos(want, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data), extensionInfos);
        HapModuleInfo hapModuleInfo;
        bundleMgrProxy.GetSandboxHapModuleInfo(abilityInfo, reinterpret_cast<uintptr_t>(data),
            reinterpret_cast<uintptr_t>(data), hapModuleInfo);
        bundleMgrProxy.UnregisterBundleStatusCallback();
        bundleMgrProxy.GetBundleInstaller();
        bundleMgrProxy.GetBundleUserMgr();
        bundleMgrProxy.GetQuickFixManagerProxy();
        bundleMgrProxy.GetAppControlProxy();

        ApplicationInfo appInfo;
        bundleMgrProxy.GetApplicationInfo(bundleName + "1", ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION,
            reinterpret_cast<uintptr_t>(data), appInfo);
        bundleMgrProxy.GetApplicationInfo(bundleName + "1", 0, reinterpret_cast<uintptr_t>(data), appInfo);
        bundleMgrProxy.GetApplicationInfoV9(bundleName + "1", 0, reinterpret_cast<uintptr_t>(data), appInfo);
        std::vector<ApplicationInfo> appInfos;
        bundleMgrProxy.GetApplicationInfos(
            ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, reinterpret_cast<uintptr_t>(data), appInfos);
        bundleMgrProxy.GetApplicationInfos(0, reinterpret_cast<uintptr_t>(data), appInfos);
        bundleMgrProxy.GetApplicationInfosV9(0, reinterpret_cast<uintptr_t>(data), appInfos);
        bundleMgrProxy.GetBundleInfo(
            bundleName + "1", BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetBundleInfo(bundleName + "1", 0, bundleInfo, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetBundleInfoV9(bundleName + "1", 0, bundleInfo, reinterpret_cast<uintptr_t>(data));
        
        ElementName name;
        name.SetBundleName(bundleName + "1");
        want.SetElement(name);
        std::vector<Want> wants;
        wants.push_back(want);
        auto flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION);
        bundleMgrProxy.BatchGetBundleInfo(wants, flags, bundleInfos, reinterpret_cast<uintptr_t>(data));
        std::vector<std::string> bundleNames;
        bundleMgrProxy.BatchGetBundleInfo(bundleNames, flags, bundleInfos, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetBundleInfoForSelf(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
        BundlePackInfo bundlePackInfo;
        bundleMgrProxy.GetBundlePackInfo(bundleName + "1", 0, bundlePackInfo, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetBundlePackInfo(
            bundleName + "1", BundleFlag::GET_BUNDLE_DEFAULT, bundlePackInfo, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetBundleInfos(0, bundleInfos, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetBundleInfosV9(0, bundleInfos, reinterpret_cast<uintptr_t>(data));
        int uid = bundleMgrProxy.GetUidByBundleName(bundleName, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetUidByBundleName(bundleName, reinterpret_cast<uintptr_t>(data), 0);
        bundleMgrProxy.GetUidByDebugBundleName(bundleName, reinterpret_cast<uintptr_t>(data));
        std::string appId = bundleMgrProxy.GetAppIdByBundleName(bundleName, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetBundleNameForUid(uid, bundleName);
        bundleMgrProxy.GetBundlesForUid(uid, bundleNames);
        int32_t appIndex = -1;
        bundleMgrProxy.GetNameAndIndexForUid(uid, bundleName, appIndex);
        std::vector<int> gids;
        bundleMgrProxy.GetBundleGids(bundleName, gids);
        bundleMgrProxy.GetBundleGidsByUid(bundleName, uid, gids);
        bundleMgrProxy.GetAppType(bundleName);
        bundleMgrProxy.CheckIsSystemAppByUid(uid);
        bundleMgrProxy.GetBundleInfosByMetaData("string", bundleInfos);
        bundleMgrProxy.QueryAbilityInfo(want, abilityInfo);
        bundleMgrProxy.QueryAbilityInfo(
            want, GET_ABILITY_INFO_WITH_APPLICATION, reinterpret_cast<uintptr_t>(data), abilityInfo, nullptr);
        bundleMgrProxy.UpgradeAtomicService(want, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.QueryAbilityInfo(
            want, GET_ABILITY_INFO_WITH_APPLICATION, reinterpret_cast<uintptr_t>(data), abilityInfo);
        bundleMgrProxy.QueryAbilityInfos(want, abilityInfos);
        bundleMgrProxy.QueryAbilityInfos(
            want, GET_ABILITY_INFO_DEFAULT, reinterpret_cast<uintptr_t>(data), abilityInfos);
        bundleMgrProxy.QueryAbilityInfosV9(
            want, GET_ABILITY_INFO_DEFAULT, reinterpret_cast<uintptr_t>(data), abilityInfos);
        bundleMgrProxy.QueryAbilityInfos(
            want, GET_ABILITY_INFO_DEFAULT, reinterpret_cast<uintptr_t>(data), abilityInfos);
        bundleMgrProxy.QueryLauncherAbilityInfos(want, reinterpret_cast<uintptr_t>(data), abilityInfos);
        bundleMgrProxy.QueryAllAbilityInfos(want, reinterpret_cast<uintptr_t>(data), abilityInfos);
        bundleMgrProxy.QueryAbilityInfoByUri(std::string(reinterpret_cast<const char*>(data), size), abilityInfo);
        bundleMgrProxy.QueryAbilityInfosByUri(std::string(reinterpret_cast<const char*>(data), size), abilityInfos);
        bundleMgrProxy.QueryAbilityInfoByUri(
            std::string(reinterpret_cast<const char*>(data), size), reinterpret_cast<uintptr_t>(data), abilityInfo);
        bundleMgrProxy.QueryKeepAliveBundleInfos(bundleInfos);
        bundleMgrProxy.GetAbilityLabel(bundleName, std::string(reinterpret_cast<const char*>(data), size));
        bundleMgrProxy.GetBundleArchiveInfo(
            std::string(reinterpret_cast<const char*>(data), size), BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo);
        bundleMgrProxy.GetBundleArchiveInfo(std::string(reinterpret_cast<const char*>(data), size), 0, bundleInfo);
        bundleMgrProxy.GetBundleArchiveInfoV9(std::string(reinterpret_cast<const char*>(data), size), 0, bundleInfo);
        bundleMgrProxy.GetHapModuleInfo(abilityInfo, hapModuleInfo);
        bundleMgrProxy.GetHapModuleInfo(abilityInfo, reinterpret_cast<uintptr_t>(data), hapModuleInfo);
        bundleMgrProxy.GetLaunchWantForBundle(bundleName, want, reinterpret_cast<uintptr_t>(data));
        PermissionDef permissionDef;
        std::string permissionName = "ohos.permission.READ_CALENDAR";
        bundleMgrProxy.GetPermissionDef(permissionName, permissionDef);
        bundleMgrProxy.CleanBundleCacheFilesAutomatic(reinterpret_cast<uintptr_t>(data));
        sptr<ICleanCacheCallback> cleanCacheCallback;
        bundleMgrProxy.CleanBundleCacheFiles(bundleName, cleanCacheCallback, reinterpret_cast<uintptr_t>(data), 0);
        bundleMgrProxy.CleanBundleDataFiles(bundleName, reinterpret_cast<uintptr_t>(data), 0);

        bundleMgrProxy.GetDependentBundleInfo(bundleName, bundleInfo);
        bundleMgrProxy.GetNameForUid(uid, bundleName);
        bundleMgrProxy.BatchQueryAbilityInfos(wants, 0, reinterpret_cast<uintptr_t>(data), abilityInfos);
        bundleMgrProxy.IsCloneApplicationEnabled(bundleName, 0, isEnable);
        bundleMgrProxy.SetCloneApplicationEnabled(bundleName, 0, true);
        bundleMgrProxy.IsCloneAbilityEnabled(abilityInfo, 0, isEnable);
        bundleMgrProxy.SetCloneAbilityEnabled(abilityInfo, 0, true);
        bundleMgrProxy.GetVerifyManager();
        bundleMgrProxy.GetExtendResourceManager();
        bundleMgrProxy.GetAllBundleStats(reinterpret_cast<uintptr_t>(data), bundleStats);
        bundleMgrProxy.GetDefaultAppProxy();
        bundleMgrProxy.GetAppControlProxy();
        bundleMgrProxy.SetDebugMode(false);
        bundleMgrProxy.VerifySystemApi();
        bundleMgrProxy.ProcessPreload(want);
        bundleMgrProxy.GetOverlayManagerProxy();
        AppProvisionInfo appProvisionInfo;
        bundleMgrProxy.GetAppProvisionInfo(bundleName, reinterpret_cast<uintptr_t>(data), appProvisionInfo);
        std::vector<BaseSharedBundleInfo> baseSharedBundleInfos;
        bundleMgrProxy.GetBaseSharedBundleInfos(bundleName, baseSharedBundleInfos);
        std::vector<SharedBundleInfo> sharedBundles;
        bundleMgrProxy.GetAllSharedBundleInfo(sharedBundles);
        bundleMgrProxy.GetSharedBundleInfo(bundleName, moduleName, sharedBundles);
        SharedBundleInfo sharedBundleInfo;
        bundleMgrProxy.GetSharedBundleInfoBySelf(bundleName, sharedBundleInfo);
        std::vector<Dependency> dependencies;
        bundleMgrProxy.GetSharedDependencies(bundleName, moduleName, dependencies);
        std::vector<ProxyData> proxyDatas;
        bundleMgrProxy.GetProxyDataInfos(bundleName, moduleName, proxyDatas);
        bundleMgrProxy.GetAllProxyDataInfos(proxyDatas);
        std::string specifiedDistributionType;
        bundleMgrProxy.GetSpecifiedDistributionType(bundleName, specifiedDistributionType);
        std::string additionalInfo;
        bundleMgrProxy.GetAdditionalInfo(bundleName, additionalInfo);
        bundleMgrProxy.SetExtNameOrMIMEToApp(bundleName, moduleName,
            std::string(reinterpret_cast<const char*>(data), size),
            std::string(reinterpret_cast<const char*>(data), size),
            std::string(reinterpret_cast<const char*>(data), size));
        bundleMgrProxy.DelExtNameOrMIMEToApp(bundleName, moduleName,
            std::string(reinterpret_cast<const char*>(data), size),
            std::string(reinterpret_cast<const char*>(data), size),
            std::string(reinterpret_cast<const char*>(data), size));
        std::vector<DataGroupInfo> infos;
        bundleMgrProxy.QueryDataGroupInfos(bundleName, reinterpret_cast<uintptr_t>(data), infos);
        std::string dir;
        bundleMgrProxy.GetGroupDir(std::string(reinterpret_cast<const char*>(data), size), dir);
        bundleMgrProxy.QueryAppGalleryBundleName(bundleName);
        bundleMgrProxy.QueryExtensionAbilityInfosWithTypeName(
            want, std::string(reinterpret_cast<const char*>(data), size),
            0, reinterpret_cast<uintptr_t>(data), extensionInfos);
        bundleMgrProxy.QueryExtensionAbilityInfosOnlyWithTypeName(
            std::string(reinterpret_cast<const char*>(data), size),
            0, reinterpret_cast<uintptr_t>(data), extensionInfos);
        bundleMgrProxy.ResetAOTCompileStatus(bundleName, moduleName, reinterpret_cast<uintptr_t>(data));
        std::string profile;
        bundleMgrProxy.GetJsonProfile(ProfileType::ADDITION_PROFILE, bundleName, moduleName, profile);
        bundleMgrProxy.GetBundleResourceProxy();
        std::vector<RecoverableApplicationInfo> recoverableApplications;
        bundleMgrProxy.GetRecoverableApplicationInfo(recoverableApplications);
        bundleMgrProxy.GetUninstalledBundleInfo(bundleName, bundleInfo);
        bundleMgrProxy.SetAdditionalInfo(bundleName, std::string(reinterpret_cast<const char*>(data), size));
        bundleMgrProxy.CreateBundleDataDir(reinterpret_cast<uintptr_t>(data));
        std::string odid;
        bundleMgrProxy.GetOdid(odid);
        bundleMgrProxy.GetAllBundleInfoByDeveloperId(
            std::string(reinterpret_cast<const char*>(data), size), bundleInfos);
        std::string appDistributionType = "invalidType";
        std::vector<std::string> developerIdList;
        bundleMgrProxy.GetDeveloperIds(appDistributionType, developerIdList);
        std::vector<std::string> results;
        bundleMgrProxy.CompileProcessAOT(bundleName, "none", false, results);
        bundleMgrProxy.ResetAOTCompileStatus(bundleName, moduleName, 0);
        bundleMgrProxy.CopyAp(bundleName, false, results);
        std::string link = "http://";
        bool canOpen = false;
        bundleMgrProxy.CanOpenLink(link, canOpen);
        std::vector<PreinstalledApplicationInfo> preinstalledApplicationInfos;
        bundleMgrProxy.GetAllPreinstalledApplicationInfos(preinstalledApplicationInfos);
        bundleMgrProxy.SwitchUninstallState(bundleName, false);
        bundleMgrProxy.QueryAbilityInfoByContinueType(bundleName, "BROWSER", abilityInfo);
        ElementName element;
        bundleMgrProxy.QueryCloneAbilityInfo(element, 0, 0, abilityInfo, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetCloneBundleInfo(bundleName, 0, 0, bundleInfo);
        element.SetAbilityName(abilityName);
        element.SetBundleName(bundleName);
        SignatureInfo sinfo;
        bundleMgrProxy.GetSignatureInfoByBundleName(bundleName, sinfo);
        bundleMgrProxy.AddDesktopShortcutInfo(shortcutInfo, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.DeleteDesktopShortcutInfo(shortcutInfo, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetAllDesktopShortcutInfo(reinterpret_cast<uintptr_t>(data), shortcutInfos);
        bundleMgrProxy.GetOdidByBundleName(bundleName, odid);
        bundleMgrProxy.GetBundleInfosForContinuation(0, bundleInfos, reinterpret_cast<uintptr_t>(data));
        std::string deviceType;
        bundleMgrProxy.GetCompatibleDeviceType(bundleName, deviceType);
        std::string queryBundleName;
        bundleMgrProxy.GetBundleNameByAppIdOrAppIdentifier(appId, queryBundleName);
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