/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bundleconnectabilitymgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#include "bundle_connect_ability_mgr.h"
#include "securec.h"
using Want = OHOS::AAFwk::Want;
using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    BundleConnectAbilityMgr bundleConnectAbilityMgr;
    Want want;
    int32_t userId = reinterpret_cast<uintptr_t>(data);
    int32_t flags = reinterpret_cast<uintptr_t>(data);
    AbilityInfo abilityInfo;
    sptr<IRemoteObject> callBack = nullptr;
    bundleConnectAbilityMgr.UpgradeAtomicService(want, userId);
    bundleConnectAbilityMgr.UpgradeAtomicService(want, userId);
    bundleConnectAbilityMgr.UpgradeAtomicService(want, userId);
    std::string installResult(data, size);
    bundleConnectAbilityMgr.OnServiceCenterCall(installResult);
    bundleConnectAbilityMgr.OnDelayedHeartbeat(installResult);
    bundleConnectAbilityMgr.DeathRecipientSendCallback();
    sptr<IRemoteObject> callerToken = nullptr;
    bundleConnectAbilityMgr.ConnectAbility(want, callerToken);
    bundleConnectAbilityMgr.ProcessPreload(want);
    bundleConnectAbilityMgr.DisconnectAbility();
    int32_t code = reinterpret_cast<uintptr_t>(data);
    MessageParcel datas;
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    bundleConnectAbilityMgr.SendRequest(code, datas, reply);
    TargetAbilityInfo targetAbilityInfo1;
    FreeInstallParams freeInstallParams;
    bundleConnectAbilityMgr.UpgradeCheck(targetAbilityInfo1, want, freeInstallParams, userId);
    int32_t callingUid = reinterpret_cast<uintptr_t>(data);
    std::vector<std::string> bundleNames = { std::string(data, size) };
    std::vector<std::string> callingAppIds = { std::string(data, size) };
    bundleConnectAbilityMgr.GetCallingInfo(userId, callingUid, bundleNames, callingAppIds);
    InnerBundleInfo innerBundleInfo;
    sptr<TargetAbilityInfo> targetAbilityInfo = nullptr;
    bundleConnectAbilityMgr.GetTargetAbilityInfo(want, userId, innerBundleInfo, targetAbilityInfo);
    bundleConnectAbilityMgr.CheckIsModuleNeedUpdate(innerBundleInfo, want, userId, callBack);
    int32_t resultCode = reinterpret_cast<uintptr_t>(data);
    std::string transactId(data, size);
    bundleConnectAbilityMgr.SendCallBack(resultCode, want, userId, transactId);
    freeInstallParams.callback = nullptr;
    bundleConnectAbilityMgr.SendCallBack(transactId, freeInstallParams);
    bundleConnectAbilityMgr.SendRequestToServiceCenter(flags, targetAbilityInfo1, want,
        userId, freeInstallParams);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}