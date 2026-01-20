/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "idle_condition_mgr.h"
#include "bmsidleconditionmgr_fuzzer.h"
#undef private
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    int32_t userId = GenerateRandomUser(fdp);
    idleMgr->OnScreenLocked();
    idleMgr->OnScreenUnlocked();
    idleMgr->OnUserUnlocked(userId);
    idleMgr->OnUserStopping(userId);
    idleMgr->OnPowerConnected();
    idleMgr->OnPowerDisconnected();
    idleMgr->HandleOnTrim(Memory::SystemMemoryLevel::UNKNOWN);
    idleMgr->HandleOnTrim(Memory::SystemMemoryLevel::MEMORY_LEVEL_PURGEABLE);
    idleMgr->HandleOnTrim(Memory::SystemMemoryLevel::MEMORY_LEVEL_MODERATE);
    idleMgr->HandleOnTrim(Memory::SystemMemoryLevel::MEMORY_LEVEL_LOW);
    idleMgr->HandleOnTrim(Memory::SystemMemoryLevel::MEMORY_LEVEL_CRITICAL);
    idleMgr->IsBufferSufficient();
    idleMgr->IsThermalSatisfied();
    idleMgr->SetIsRelabeling();
    idleMgr->CheckRelabelConditions(userId);
    idleMgr->TryStartRelabel();
    idleMgr->InterruptRelabel();
    idleMgr->OnThermalLevelChanged(PowerMgr::ThermalLevel::WARM);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}