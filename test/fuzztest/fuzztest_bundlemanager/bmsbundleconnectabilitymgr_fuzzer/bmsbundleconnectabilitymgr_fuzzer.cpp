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
#define private public
#include "bundle_connect_ability_mgr.h"
#include "bmsbundleconnectabilitymgr_fuzzer.h"
#include "bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    BundleConnectAbilityMgr bundleConnectAbilityMgr;
    FuzzedDataProvider fdp(data, size);
    TargetAbilityInfo targetAbilityInfo1;
    bundleConnectAbilityMgr.ProcessPreloadCheck(targetAbilityInfo1);
    Want want;
    int32_t userId = GenerateRandomUser(fdp);
    int32_t flags = fdp.ConsumeIntegral<int32_t>();
    bundleConnectAbilityMgr.ProcessPreloadRequestToServiceCenter(flags, targetAbilityInfo1);
    bundleConnectAbilityMgr.GetPreloadFlag();
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    sptr<TargetAbilityInfo> targetAbilityInfo = nullptr;
    bundleConnectAbilityMgr.GetPreloadList(bundleName, moduleName, userId, targetAbilityInfo);
    bundleConnectAbilityMgr.ProcessPreload(want);
    FreeInstallParams freeInstallParams;
    freeInstallParams.callback = nullptr;
    bundleConnectAbilityMgr.SilentInstall(targetAbilityInfo1, want, freeInstallParams, userId);
    bundleConnectAbilityMgr.UpgradeCheck(targetAbilityInfo1, want, freeInstallParams, userId);
    bundleConnectAbilityMgr.UpgradeInstall(targetAbilityInfo1, want, freeInstallParams, userId);
    bundleConnectAbilityMgr.SendRequestToServiceCenter(flags, targetAbilityInfo1, want,
        userId, freeInstallParams);
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bundleConnectAbilityMgr.LoadService(saId);
    std::unique_lock<std::mutex> lock;
    bundleConnectAbilityMgr.WaitFromConnecting(lock);
    bundleConnectAbilityMgr.WaitFromConnected(lock);
    sptr<IRemoteObject> callerToken = nullptr;
    bundleConnectAbilityMgr.ConnectAbility(want, callerToken);
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
    std::string transactId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleConnectAbilityMgr.SendCallBack(resultCode, want, userId, transactId);
    FreeInstallParams freeInstallParams2;
    bundleConnectAbilityMgr.SendCallBack(transactId, freeInstallParams);
    bundleConnectAbilityMgr.SendCallBack(transactId, freeInstallParams2);
    bundleConnectAbilityMgr.DeathRecipientSendCallback();
    std::string installResult = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleConnectAbilityMgr.OnServiceCenterCall(installResult);
    bundleConnectAbilityMgr.OnDelayedHeartbeat(installResult);
    bundleConnectAbilityMgr.OnServiceCenterReceived(installResult);
    bundleConnectAbilityMgr.OutTimeMonitor(transactId);
    int32_t code = fdp.ConsumeIntegral<int32_t>();
    MessageParcel datas;
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    bundleConnectAbilityMgr.SendRequest(code, datas, reply);
    bundleConnectAbilityMgr.SendRequest(flags, targetAbilityInfo1, want, userId, freeInstallParams);
    bundleConnectAbilityMgr.GetAbilityManagerServiceCallBack(transactId);
    int32_t callingUid = fdp.ConsumeIntegral<int32_t>();
    std::vector<std::string> bundleNames = GenerateStringArray(fdp);
    std::vector<std::string> callingAppIds = GenerateStringArray(fdp);
    std::vector<std::string> callingBundleNames = GenerateStringArray(fdp);
    bundleConnectAbilityMgr.GetCallingInfo(userId, callingUid, bundleNames, callingAppIds);
    std::string deviceId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    InnerBundleInfo innerBundleInfo;
    sptr<TargetAbilityInfo> targetAbilityInfo2 = new(std::nothrow) TargetAbilityInfo();
    bundleConnectAbilityMgr.GetTargetAbilityInfo(want, userId, innerBundleInfo, targetAbilityInfo);
    bundleConnectAbilityMgr.GetTargetAbilityInfo(want, userId, innerBundleInfo, targetAbilityInfo2);
    bundleConnectAbilityMgr.CheckSubPackageName(innerBundleInfo, want);
    sptr<IRemoteObject> callBack = nullptr;
    bundleConnectAbilityMgr.CallAbilityManager(resultCode, want, userId, callBack);
    bundleConnectAbilityMgr.CheckIsModuleNeedUpdate(innerBundleInfo, want, userId, callBack);
    AbilityInfo abilityInfo;
    bundleConnectAbilityMgr.IsObtainAbilityInfo(want, flags, userId, abilityInfo, callBack, innerBundleInfo);
    bundleConnectAbilityMgr.CheckIsModuleNeedUpdateWrap(innerBundleInfo, want, userId, callBack);
    bundleConnectAbilityMgr.QueryAbilityInfo(want, flags, userId, abilityInfo, callBack);
    bundleConnectAbilityMgr.SilentInstall(want, userId, callBack);
    bundleConnectAbilityMgr.UpgradeAtomicService(want, userId);
    ErmsCallerInfo callerInfo;
    BmsExperienceRule rule;
    bundleConnectAbilityMgr.CheckEcologicalRule(want, callerInfo, rule);
    bundleConnectAbilityMgr.CheckIsOnDemandLoad(targetAbilityInfo1);
    bundleConnectAbilityMgr.GetModuleName(innerBundleInfo, want, moduleName);
    int32_t flag = fdp.ConsumeIntegral<int32_t>();
    bundleConnectAbilityMgr.PreloadRequest(flag, targetAbilityInfo1);
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
