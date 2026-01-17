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

#include <string>
#include <thread>
#include <chrono>
#include <gtest/gtest.h>

#define private public
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "idle_condition_mgr/idle_condition_mgr.h"
#include "idle_condition_mgr/idle_condition_event_subscribe.h"
#include "parameter.h"
#include "parameters.h"

#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr const char* BMS_PARAM_RELABEL_BATTERY_CAPACITY = "ohos.bms.param.relabelBatteryCapacity";
constexpr const char* BMS_PARAM_RELABEL_WAIT_TIME = "ohos.bms.param.relabelWaitTimeMinutes";
constexpr int32_t WAIT_TIME = 1; // 1 second
} // namespace

class BmsIdleConditionMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsIdleConditionMgrTest::SetUpTestCase()
{}

void BmsIdleConditionMgrTest::TearDownTestCase()
{}

void BmsIdleConditionMgrTest::SetUp()
{}

void BmsIdleConditionMgrTest::TearDown()
{}

/**
 * @tc.number: CheckRelabelConditions_0100
 * @tc.name: Check relabel conditions when all conditions are satisfied
 * @tc.desc: 1. System is running normally
 *           2. User is unlocked, screen is locked, power is connected, battery is sufficient
 *           3. Should return true and set isRelabeling flag
 */
HWTEST_F(BmsIdleConditionMgrTest, CheckRelabelConditions_0100, Function | SmallTest | Level0)
{
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    ASSERT_NE(idleMgr, nullptr);

    idleMgr->screenLocked_ = false;
    bool result = idleMgr->CheckRelabelConditions(100);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: OnScreenLocked_0100
 * @tc.name: Handle screen locked event
 * @tc.desc: 1. System is running normally
 *           2. ScreenLocked flag should be set to true
 */
HWTEST_F(BmsIdleConditionMgrTest, OnScreenLocked_0100, Function | SmallTest | Level0)
{
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    ASSERT_NE(idleMgr, nullptr);
    
    idleMgr->OnScreenLocked();
    EXPECT_TRUE(idleMgr->screenLocked_);
    idleMgr->OnScreenUnlocked();
    EXPECT_FALSE(idleMgr->screenLocked_);
}

/**
 * @tc.number: OnUserUnlocked_0100
 * @tc.name: Handle user unlocked event
 * @tc.desc: 1. System is running normally
 *           2. userLocked flag should be set to true
 */
HWTEST_F(BmsIdleConditionMgrTest, OnUserUnlocked_0100, Function | SmallTest | Level0)
{
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    ASSERT_NE(idleMgr, nullptr);
    
    idleMgr->OnUserUnlocked(100);
    EXPECT_TRUE(idleMgr->userUnlockedMap_[100]);
    idleMgr->OnUserStopping(100);
    EXPECT_FALSE(idleMgr->userUnlockedMap_[100]);
}

/**
 * @tc.number: OnPowerConnected_0100
 * @tc.name: Handle power connected event
 * @tc.desc: 1. System is running normally
 *           2. powerConnected flag should be set to true
 */
HWTEST_F(BmsIdleConditionMgrTest, OnPowerConnected_0100, Function | SmallTest | Level0)
{
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    ASSERT_NE(idleMgr, nullptr);

    OHOS::system::SetParameter(BMS_PARAM_RELABEL_WAIT_TIME, "0");
    idleMgr->OnPowerConnected();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    EXPECT_TRUE(idleMgr->powerConnected_);
    idleMgr->OnPowerDisconnected();
    EXPECT_FALSE(idleMgr->powerConnected_);
    EXPECT_FALSE(idleMgr->powerConnectedThreadActive_);
    OHOS::system::SetParameter(BMS_PARAM_RELABEL_WAIT_TIME, "300");
}


/**
 * @tc.number: OnBatteryChanged_0100
 * @tc.name: Handle battery changed event
 * @tc.desc: 1. System is running normally
 *           2. batterySatisfied flag should be set to true
 */
HWTEST_F(BmsIdleConditionMgrTest, OnBatteryChanged_0100, Function | SmallTest | Level0)
{
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    ASSERT_NE(idleMgr, nullptr);

    OHOS::system::SetParameter(BMS_PARAM_RELABEL_BATTERY_CAPACITY, "0");
    idleMgr->OnBatteryChanged();
    EXPECT_TRUE(idleMgr->batterySatisfied_);
    OHOS::system::SetParameter(BMS_PARAM_RELABEL_BATTERY_CAPACITY, "101");
    idleMgr->OnBatteryChanged();
    EXPECT_FALSE(idleMgr->batterySatisfied_);
}

/**
 * @tc.number: TryStartRelabel_0100
 * @tc.name: Handle relabel start event
 * @tc.desc: 1. System is running normally
 *           2. isRelabeling flag should be set to true
 */
HWTEST_F(BmsIdleConditionMgrTest, TryStartRelabel_0100, Function | SmallTest | Level0)
{
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    ASSERT_NE(idleMgr, nullptr);

    idleMgr->userUnlockedMap_[100] = true;
    idleMgr->screenLocked_ = true;
    idleMgr->powerConnected_ = true;
    idleMgr->batterySatisfied_ = true;
    idleMgr->TryStartRelabel();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    EXPECT_FALSE(idleMgr->isRelabeling_);
}

/**
 * @tc.number: InterruptRelabel_0100
 * @tc.name: Handle relabel interrupt event
 * @tc.desc: 1. System is running normally
 *           2. isRelabeling flag should be set to false
 */
HWTEST_F(BmsIdleConditionMgrTest, InterruptRelabel_0100, Function | SmallTest | Level0)
{
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    ASSERT_NE(idleMgr, nullptr);

    idleMgr->isRelabeling_ = false;
    idleMgr->InterruptRelabel("InterruptRelabel_0100");
    EXPECT_FALSE(idleMgr->isRelabeling_);

    idleMgr->isRelabeling_ = true;
    idleMgr->InterruptRelabel("InterruptRelabel_0100");
    EXPECT_TRUE(idleMgr->isRelabeling_);
}

/**
 * @tc.number: OnReceiveEvent_0100
 * @tc.name: OnReceiveEvent_0100
 * @tc.desc: 1. System is running normally
 *           2. receive event
 */
HWTEST_F(BmsIdleConditionMgrTest, OnReceiveEvent_0100, Function | SmallTest | Level0)
{
    EventFwk::MatchingSkills matchingSkills;
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriberPtr = std::make_shared<IdleConditionEventSubscriber>(subscribeInfo);
    ASSERT_NE(subscriberPtr, nullptr);
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    ASSERT_NE(idleMgr, nullptr);

    EventFwk::CommonEventData eventData1;
    EventFwk::Want want1;
    want1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    eventData1.SetWant(want1);
    subscriberPtr->OnReceiveEvent(eventData1);
    EXPECT_TRUE(idleMgr->screenLocked_);

    EventFwk::CommonEventData eventData2;
    EventFwk::Want want2;
    want2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    eventData2.SetWant(want2);
    subscriberPtr->OnReceiveEvent(eventData2);
    if (!OHOS::system::GetBoolParameter(ServiceConstants::BMS_RELABEL_PARAM, false)) {
        EXPECT_TRUE(idleMgr->screenLocked_);
    } else {
        EXPECT_FALSE(idleMgr->screenLocked_);
    }
}
} // namespace OHOS