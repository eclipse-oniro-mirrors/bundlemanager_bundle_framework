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

#define private public
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bmsfreeinstall_fuzzer.h"
#include "bms_ecological_rule_mgr_service_param.h"
#include "bms_fuzztest_util.h"
#include "bundle_connect_ability_mgr.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "service_center_connection.h"
#include "service_center_status_callback.h"
#include "target_ability_info.h"
#include "system_ability_definition.h"

#include "want.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    FuzzedDataProvider fdp(data, size);
    std::shared_ptr<BundleConnectAbilityMgr> bundleConnectAbilityMgrPtr = std::make_shared<BundleConnectAbilityMgr>();
    int32_t connectState = fdp.ConsumeIntegralInRange<int32_t>(0, 2);
    std::condition_variable cv;
    OHOS::AppExecFwk::ServiceCenterConnection serviceCenterConnection(connectState, cv, bundleConnectAbilityMgrPtr);
    AppExecFwk::ElementName element;
    int32_t resultCode = fdp.ConsumeIntegralInRange<int32_t>(0, 1);
    serviceCenterConnection.OnAbilityConnectDone(element, nullptr, resultCode);
    serviceCenterConnection.OnAbilityConnectDone(element, nullptr, resultCode);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    serviceCenterConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    serviceCenterConnection.OnAbilityDisconnectDone(element, resultCode);
#endif
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}