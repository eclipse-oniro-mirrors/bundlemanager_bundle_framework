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

#include "bmsbundlemgrproxypartfour_fuzzer.h"
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
        std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::string abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        int32_t userId = GenerateRandomUser(fdp);
        int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
        int32_t flags = fdp.ConsumeIntegral<int32_t>();
        int32_t triggerMode = fdp.ConsumeIntegral<int32_t>();

        bundleMgrProxy.ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
        std::string profile;
        ProfileType profileType = static_cast<ProfileType>(fdp.ConsumeIntegralInRange<uint8_t>(1, 7));
        bundleMgrProxy.GetJsonProfile(profileType, bundleName, moduleName, profile);
        bundleMgrProxy.GetBundleResourceProxy();
        std::vector<RecoverableApplicationInfo> recoverableApplications;
        bundleMgrProxy.GetRecoverableApplicationInfo(recoverableApplications);
        BundleInfo bundleInfo;
        bundleMgrProxy.GetUninstalledBundleInfo(bundleName, bundleInfo);
        std::string additionalInfo = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.SetAdditionalInfo(bundleName, additionalInfo);
        bundleMgrProxy.CreateBundleDataDir(userId);
        std::string odid;
        bundleMgrProxy.GetOdid(odid);
        std::string developerId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::vector<BundleInfo> bundleInfos;
        bundleMgrProxy.GetAllBundleInfoByDeveloperId(developerId, bundleInfos, userId);
        std::string appDistributionType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::vector<std::string> developerIdList;
        bundleMgrProxy.GetDeveloperIds(appDistributionType, developerIdList);
        std::vector<std::string> results;
        std::string compileMode = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bool isAllBundle = fdp.ConsumeBool();
        bundleMgrProxy.CompileProcessAOT(bundleName, compileMode, isAllBundle, results);
        bundleMgrProxy.ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
        bundleMgrProxy.CopyAp(bundleName, isAllBundle, results);
        std::string link = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bool canOpen = fdp.ConsumeBool();
        bundleMgrProxy.CanOpenLink(link, canOpen);
        std::vector<PreinstalledApplicationInfo> preinstalledApplicationInfos;
        bundleMgrProxy.GetAllPreinstalledApplicationInfos(preinstalledApplicationInfos);
        bool state = fdp.ConsumeBool();
        bool isNeedSendNotify = fdp.ConsumeBool();
        bundleMgrProxy.SwitchUninstallState(bundleName, state, isNeedSendNotify);

        std::string continueType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        AbilityInfo abilityInfo;
        bundleMgrProxy.QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo);
        ElementName element;
        bundleMgrProxy.QueryCloneAbilityInfo(element, flags, appIndex, abilityInfo, reinterpret_cast<uintptr_t>(data));
        bundleMgrProxy.GetCloneBundleInfo(bundleName, flags, appIndex, bundleInfo);
        element.SetAbilityName(abilityName);
        element.SetBundleName(bundleName);
        SignatureInfo sinfo;
        bundleMgrProxy.GetSignatureInfoByBundleName(bundleName, sinfo);
        ShortcutInfo shortcutInfo;
        bundleMgrProxy.AddDesktopShortcutInfo(shortcutInfo, userId);
        bundleMgrProxy.DeleteDesktopShortcutInfo(shortcutInfo, userId);
        std::vector<ShortcutInfo> shortcutInfos;
        bundleMgrProxy.GetAllDesktopShortcutInfo(userId, shortcutInfos);
        bundleMgrProxy.GetOdidByBundleName(bundleName, odid);
        bundleMgrProxy.GetBundleInfosForContinuation(flags, bundleInfos, userId);
        std::string deviceType;
        bundleMgrProxy.GetCompatibleDeviceType(bundleName, deviceType);
        std::string queryBundleName;
        std::string appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleMgrProxy.GetBundleNameByAppId(appId, queryBundleName);
        std::string dataDir;
        bundleMgrProxy.GetDirByBundleNameAndAppIndex(bundleName, appIndex, dataDir);
        std::vector<BundleDir> bundleDirs;
        bundleMgrProxy.GetAllBundleDirs(userId, bundleDirs);
        std::set<AppDistributionTypeEnum> appDistributionTypeEnums{
            AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_APP_GALLERY};
        bundleMgrProxy.SetAppDistributionTypes(appDistributionTypeEnums);
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