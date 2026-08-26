/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "bmsbatchsetenabled_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "bundle_file_util.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgr()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        std::cout << "GetBundleMgr GetSystemAbilityManager is null" << std::endl;
        return nullptr;
    }

    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        std::cout << "[fuzz] GetBundleMgr GetSystemAbility is null" << std::endl;
        return nullptr;
    }

    return iface_cast<IBundleMgr>(bundleMgrSa);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    static sptr<OHOS::AppExecFwk::IBundleMgr> bundleMgr = GetBundleMgr();
    if (bundleMgr == nullptr) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t userId = GenerateRandomUser(fdp);
    int32_t enableAppIndex = fdp.ConsumeIntegral<int32_t>();
    int32_t disableAppIndex = fdp.ConsumeIntegral<int32_t>();
    bool killProcess = fdp.ConsumeBool();
    bool needSendEvent = fdp.ConsumeBool();

    // Fuzz BatchSetApplicationEnabled via real system proxy
    auto ret = bundleMgr->BatchSetApplicationEnabled(
        userId, enableAppIndex, disableAppIndex, killProcess, needSendEvent);
    if (ret != ERR_OK) {
        std::cout << "[fuzz] BatchSetApplicationEnabled ret=" << ret << std::endl;
    }

    // Fuzz with boundary appIndex values
    int32_t maxCloneCount = OHOS::AppExecFwk::BundleFileUtil::GetCloneMaxCount();
    bundleMgr->BatchSetApplicationEnabled(userId, -1, 1, true, true);
    bundleMgr->BatchSetApplicationEnabled(userId, 1, -1, true, true);
    bundleMgr->BatchSetApplicationEnabled(userId, 0, 0, false, false);
    bundleMgr->BatchSetApplicationEnabled(userId, 1, 1, false, false);
    bundleMgr->BatchSetApplicationEnabled(userId, maxCloneCount, 1, true, true);
    bundleMgr->BatchSetApplicationEnabled(userId, maxCloneCount + 1, 1, false, false);
    bundleMgr->BatchSetApplicationEnabled(userId, INT32_MAX, 1, false, false);
    bundleMgr->BatchSetApplicationEnabled(userId, 1, INT32_MIN, false, false);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
