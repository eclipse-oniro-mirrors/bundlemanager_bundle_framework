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
#include <set>

#include "bundle_mgr_proxy.h"

#include "bmsbundlemgrproxypartthree_fuzzer.h"
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
        int32_t userId = GenerateRandomUser(fdp);
        int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
        int32_t flags = fdp.ConsumeIntegral<int32_t>();
        std::string hapFilePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

        BundleInfo bundleInfo;
        AbilityInfo abilityInfo;
        bundleMgrProxy.GetBundleArchiveInfo(hapFilePath, flags, bundleInfo);
        BundleFlag bundleFlag = GET_BUNDLE_DEFAULT;
        bundleMgrProxy.GetBundleArchiveInfo(hapFilePath, bundleFlag, bundleInfo);
        bundleMgrProxy.GetBundleArchiveInfoV9(hapFilePath, flags, bundleInfo);
        HapModuleInfo hapModuleInfo;
        bundleMgrProxy.GetHapModuleInfo(abilityInfo, hapModuleInfo);
        bundleMgrProxy.GetHapModuleInfo(abilityInfo, userId, hapModuleInfo);
        Want want;
        bundleMgrProxy.GetLaunchWantForBundle(bundleName, want, userId);
        PermissionDef permissionDef;
        std::string permissionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.GetPermissionDef(permissionName, permissionDef);

        uint64_t cacheSize = fdp.ConsumeIntegral<uint64_t>();
        bundleMgrProxy.CleanBundleCacheFilesAutomatic(cacheSize);
        sptr<ICleanCacheCallback> cleanCacheCallback;
        bundleMgrProxy.CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId, appIndex);
        bundleMgrProxy.CleanBundleDataFiles(bundleName, userId, appIndex);

        bundleMgrProxy.GetDependentBundleInfo(bundleName, bundleInfo);
        int uid = fdp.ConsumeIntegral<int>();
        bundleMgrProxy.GetNameForUid(uid, bundleName);
        std::vector<AbilityInfo> abilityInfos;
        std::vector<Want> wants;
        bundleMgrProxy.BatchQueryAbilityInfos(wants, flags, userId, abilityInfos);
        bool isEnable = fdp.ConsumeBool();
        bundleMgrProxy.IsCloneApplicationEnabled(bundleName, appIndex, isEnable);
        bundleMgrProxy.SetCloneApplicationEnabled(bundleName, appIndex, isEnable);
        bundleMgrProxy.IsCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
        bundleMgrProxy.SetCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
        bundleMgrProxy.GetVerifyManager();
        bundleMgrProxy.GetExtendResourceManager();
        std::vector<int64_t> bundleStats;
        bundleMgrProxy.GetAllBundleStats(userId, bundleStats);
        bundleMgrProxy.GetDefaultAppProxy();
        bundleMgrProxy.GetAppControlProxy();
        bundleMgrProxy.SetDebugMode(isEnable);
        bundleMgrProxy.VerifySystemApi();
        bundleMgrProxy.ProcessPreload(want);
        bundleMgrProxy.GetOverlayManagerProxy();
        AppProvisionInfo appProvisionInfo;
        bundleMgrProxy.GetAppProvisionInfo(bundleName, userId, appProvisionInfo);
        std::vector<BaseSharedBundleInfo> baseSharedBundleInfos;
        bundleMgrProxy.GetBaseSharedBundleInfos(bundleName, baseSharedBundleInfos);
        std::vector<SharedBundleInfo> sharedBundles;
        bundleMgrProxy.GetAllSharedBundleInfo(sharedBundles);
        std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
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
        bundleMgrProxy.GetAdditionalInfoForAllUser(bundleName, additionalInfo);
        std::string abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::string extName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::string mimeType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.SetExtNameOrMIMEToApp(bundleName, moduleName, abilityName, extName, mimeType);
        bundleMgrProxy.DelExtNameOrMIMEToApp(bundleName, moduleName, abilityName, extName, mimeType);
        std::vector<DataGroupInfo> infos;
        bundleMgrProxy.QueryDataGroupInfos(bundleName, userId, infos);
        std::string dir;
        std::string dataGroupId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.GetGroupDir(dataGroupId, dir);
        bundleMgrProxy.QueryAppGalleryBundleName(bundleName);
        std::string extensionTypeName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::vector<ExtensionAbilityInfo> extensionInfos;
        bundleMgrProxy.QueryExtensionAbilityInfosWithTypeName(want, extensionTypeName, flags, userId, extensionInfos);
        bundleMgrProxy.QueryExtensionAbilityInfosOnlyWithTypeName(extensionTypeName, flags, userId, extensionInfos);
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