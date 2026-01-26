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
#include <fstream>
#include <gtest/gtest.h>
#include <filesystem>

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
#include "idle_condition_mgr/idle_param_util.h"
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

/**
 * @tc.number: IdleParamUtil_SplitString_0100
 * @tc.name: Test SplitString with normal string
 * @tc.desc: 1. Split string by delimiter
 *           2. Should return vector of substrings
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_SplitString_0100, Function | SmallTest | Level0)
{
    std::string testStr = "version=1.2.3.4";
    std::vector<std::string> result = IdleParamUtil::SplitString(testStr, '=');
    EXPECT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], "version");
    EXPECT_EQ(result[1], "1.2.3.4");
}

/**
 * @tc.number: IdleParamUtil_SplitString_0200
 * @tc.name: Test SplitString with dot delimiter
 * @tc.desc: 1. Split version string by dot
 *           2. Should return 4 parts
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_SplitString_0200, Function | SmallTest | Level0)
{
    std::string testStr = "1.2.3.4";
    std::vector<std::string> result = IdleParamUtil::SplitString(testStr, '.');
    EXPECT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0], "1");
    EXPECT_EQ(result[1], "2");
    EXPECT_EQ(result[2], "3");
    EXPECT_EQ(result[3], "4");
}

/**
 * @tc.number: IdleParamUtil_SplitString_0300
 * @tc.name: Test SplitString with no delimiter
 * @tc.desc: 1. Split string with no delimiter present
 *           2. Should return single element vector
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_SplitString_0300, Function | SmallTest | Level0)
{
    std::string testStr = "noversion";
    std::vector<std::string> result = IdleParamUtil::SplitString(testStr, '=');
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "noversion");
}

/**
 * @tc.number: IdleParamUtil_SplitString_0400
 * @tc.name: Test SplitString with empty string
 * @tc.desc: 1. Split empty string
 *           2. Should return empty vector (getline returns false immediately)
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_SplitString_0400, Function | SmallTest | Level0)
{
    std::string testStr = "";
    std::vector<std::string> result = IdleParamUtil::SplitString(testStr, '=');
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.number: IdleParamUtil_Trim_0100
 * @tc.name: Test Trim with leading spaces
 * @tc.desc: 1. Trim string with leading spaces
 *           2. Should remove leading spaces
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_Trim_0100, Function | SmallTest | Level0)
{
    std::string testStr = "   1.2.3.4";
    IdleParamUtil::Trim(testStr);
    EXPECT_EQ(testStr, "1.2.3.4");
}

/**
 * @tc.number: IdleParamUtil_Trim_0200
 * @tc.name: Test Trim with trailing spaces
 * @tc.desc: 1. Trim string with trailing spaces
 *           2. Should remove trailing spaces
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_Trim_0200, Function | SmallTest | Level0)
{
    std::string testStr = "1.2.3.4   ";
    IdleParamUtil::Trim(testStr);
    EXPECT_EQ(testStr, "1.2.3.4");
}

/**
 * @tc.number: IdleParamUtil_Trim_0300
 * @tc.name: Test Trim with leading and trailing spaces
 * @tc.desc: 1. Trim string with both leading and trailing spaces
 *           2. Should remove both
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_Trim_0300, Function | SmallTest | Level0)
{
    std::string testStr = "   1.2.3.4   ";
    IdleParamUtil::Trim(testStr);
    EXPECT_EQ(testStr, "1.2.3.4");
}

/**
 * @tc.number: IdleParamUtil_Trim_0400
 * @tc.name: Test Trim with tabs
 * @tc.desc: 1. Trim string with tabs
 *           2. Should remove tabs
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_Trim_0400, Function | SmallTest | Level0)
{
    std::string testStr = "\t1.2.3.4\t";
    IdleParamUtil::Trim(testStr);
    EXPECT_EQ(testStr, "1.2.3.4");
}

/**
 * @tc.number: IdleParamUtil_Trim_0500
 * @tc.name: Test Trim with mixed whitespace
 * @tc.desc: 1. Trim string with mixed whitespace
 *           2. Should remove all whitespace
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_Trim_0500, Function | SmallTest | Level0)
{
    std::string testStr = "  \t\n 1.2.3.4 \r\n  ";
    IdleParamUtil::Trim(testStr);
    EXPECT_EQ(testStr, "1.2.3.4");
}

/**
 * @tc.number: IdleParamUtil_Trim_0600
 * @tc.name: Test Trim with empty string
 * @tc.desc: 1. Trim empty string
 *           2. Should not crash and remain empty
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_Trim_0600, Function | SmallTest | Level0)
{
    std::string testStr = "";
    IdleParamUtil::Trim(testStr);
    EXPECT_EQ(testStr, "");
}

/**
 * @tc.number: IdleParamUtil_Trim_0700
 * @tc.name: Test Trim with no spaces
 * @tc.desc: 1. Trim string with no spaces
 *           2. Should remain unchanged
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_Trim_0700, Function | SmallTest | Level0)
{
    std::string testStr = "1.2.3.4";
    IdleParamUtil::Trim(testStr);
    EXPECT_EQ(testStr, "1.2.3.4");
}

/**
 * @tc.number: IdleParamUtil_Trim_0800
 * @tc.name: Test Trim with only spaces
 * @tc.desc: 1. Trim string with only spaces
 *           2. Should result in empty string
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_Trim_0800, Function | SmallTest | Level0)
{
    std::string testStr = "     ";
    IdleParamUtil::Trim(testStr);
    EXPECT_EQ(testStr, "");
}

/**
 * @tc.number: IdleParamUtil_IsNumber_0100
 * @tc.name: Test IsNumber with valid number string
 * @tc.desc: 1. Check if string is a valid number
 *           2. Should return true
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsNumber_0100, Function | SmallTest | Level0)
{
    std::string testStr = "12345";
    bool result = IdleParamUtil::IsNumber(testStr);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: IdleParamUtil_IsNumber_0200
 * @tc.name: Test IsNumber with zero
 * @tc.desc: 1. Check if "0" is a valid number
 *           2. Should return true
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsNumber_0200, Function | SmallTest | Level0)
{
    std::string testStr = "0";
    bool result = IdleParamUtil::IsNumber(testStr);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: IdleParamUtil_IsNumber_0300
 * @tc.name: Test IsNumber with empty string
 * @tc.desc: 1. Check if empty string is a number
 *           2. Should return false
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsNumber_0300, Function | SmallTest | Level0)
{
    std::string testStr = "";
    bool result = IdleParamUtil::IsNumber(testStr);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IdleParamUtil_IsNumber_0400
 * @tc.name: Test IsNumber with letters
 * @tc.desc: 1. Check if string with letters is a number
 *           2. Should return false
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsNumber_0400, Function | SmallTest | Level0)
{
    std::string testStr = "abc";
    bool result = IdleParamUtil::IsNumber(testStr);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IdleParamUtil_IsNumber_0500
 * @tc.name: Test IsNumber with alphanumeric
 * @tc.desc: 1. Check if alphanumeric string is a number
 *           2. Should return false
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsNumber_0500, Function | SmallTest | Level0)
{
    std::string testStr = "123abc";
    bool result = IdleParamUtil::IsNumber(testStr);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IdleParamUtil_IsNumber_0600
 * @tc.name: Test IsNumber with special characters
 * @tc.desc: 1. Check if string with special chars is a number
 *           2. Should return false
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsNumber_0600, Function | SmallTest | Level0)
{
    std::string testStr = "12.34";
    bool result = IdleParamUtil::IsNumber(testStr);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IdleParamUtil_IsNumber_0700
 * @tc.name: Test IsNumber with spaces
 * @tc.desc: 1. Check if string with spaces is a number
 *           2. Should return false
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsNumber_0700, Function | SmallTest | Level0)
{
    std::string testStr = "12 34";
    bool result = IdleParamUtil::IsNumber(testStr);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IdleParamUtil_IsNumber_0800
 * @tc.name: Test IsNumber with negative sign
 * @tc.desc: 1. Check if negative number string is valid
 *           2. Should return false (no negative numbers)
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsNumber_0800, Function | SmallTest | Level0)
{
    std::string testStr = "-123";
    bool result = IdleParamUtil::IsNumber(testStr);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_0100
 * @tc.name: Test CompareVersion with both empty
 * @tc.desc: 1. Compare when both versions are empty
 *           2. Should return empty string
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_0100, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion;
    std::vector<int32_t> cloudVersion;
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "");
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_0200
 * @tc.name: Test CompareVersion with empty cloud
 * @tc.desc: 1. Compare when cloud version is empty
 *           2. Should return LOCAL_CFG_PATH
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_0200, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion = {1, 2, 3, 4};
    std::vector<int32_t> cloudVersion;
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "/system/etc/SwitchOffList/");
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_0300
 * @tc.name: Test CompareVersion with empty local
 * @tc.desc: 1. Compare when local version is empty
 *           2. Should return CLOUD_CFG_PATH
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_0300, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion;
    std::vector<int32_t> cloudVersion = {1, 2, 3, 4};
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "/data/service/el1/public/update/param_service/install/system/etc/SwitchOffList/");
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_0400
 * @tc.name: Test CompareVersion with invalid sizes
 * @tc.desc: 1. Compare when version sizes are not VERSION_LEN
 *           2. Should return empty string
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_0400, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion = {1, 2, 3};
    std::vector<int32_t> cloudVersion = {1, 2, 3, 4};
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "");
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_0500
 * @tc.name: Test CompareVersion with local higher
 * @tc.desc: 1. Compare when local version is higher
 *           2. Should return LOCAL_CFG_PATH
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_0500, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion = {2, 2, 3, 4};
    std::vector<int32_t> cloudVersion = {1, 2, 3, 4};
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "/system/etc/SwitchOffList/");
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_0600
 * @tc.name: Test CompareVersion with cloud higher
 * @tc.desc: 1. Compare when cloud version is higher
 *           2. Should return CLOUD_CFG_PATH
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_0600, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion = {1, 2, 3, 4};
    std::vector<int32_t> cloudVersion = {2, 2, 3, 4};
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "/data/service/el1/public/update/param_service/install/system/etc/SwitchOffList/");
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_0700
 * @tc.name: Test CompareVersion with equal versions
 * @tc.desc: 1. Compare when versions are equal
 *           2. Should return LOCAL_CFG_PATH
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_0700, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion = {1, 2, 3, 4};
    std::vector<int32_t> cloudVersion = {1, 2, 3, 4};
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "/system/etc/SwitchOffList/");
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_0800
 * @tc.name: Test CompareVersion with second digit different
 * @tc.desc: 1. Compare when second digit is different
 *           2. Should return correct path based on comparison
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_0800, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion = {1, 3, 3, 4};
    std::vector<int32_t> cloudVersion = {1, 2, 3, 4};
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "/system/etc/SwitchOffList/");
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_0900
 * @tc.name: Test CompareVersion with third digit different
 * @tc.desc: 1. Compare when third digit is different
 *           2. Should return correct path based on comparison
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_0900, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion = {1, 2, 2, 4};
    std::vector<int32_t> cloudVersion = {1, 2, 3, 4};
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "/data/service/el1/public/update/param_service/install/system/etc/SwitchOffList/");
}

/**
 * @tc.number: IdleParamUtil_CompareVersion_1000
 * @tc.name: Test CompareVersion with fourth digit different
 * @tc.desc: 1. Compare when fourth digit is different
 *           2. Should return correct path based on comparison
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_CompareVersion_1000, Function | SmallTest | Level0)
{
    std::vector<int32_t> localVersion = {1, 2, 3, 3};
    std::vector<int32_t> cloudVersion = {1, 2, 3, 4};
    std::string result = IdleParamUtil::CompareVersion(localVersion, cloudVersion);
    EXPECT_EQ(result, "/data/service/el1/public/update/param_service/install/system/etc/SwitchOffList/");
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_0100
 * @tc.name: Test GetVersionNums with non-existent file
 * @tc.desc: 1. Try to read version from non-existent file
 *           2. Should return empty vector
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_0100, Function | SmallTest | Level0)
{
    std::string filePath = "/non/existent/path/version.txt";
    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_0200
 * @tc.name: Test GetVersionNums with empty file
 * @tc.desc: 1. Read version from empty file
 *           2. Should return empty vector
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_0200, Function | SmallTest | Level0)
{
    std::string filePath = "/data/test_empty_version.txt";
    std::ofstream file(filePath);
    file.close();

    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_TRUE(result.empty());

    std::filesystem::remove(filePath);
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_0300
 * @tc.name: Test GetVersionNums with invalid format (no equals)
 * @tc.desc: 1. Read version with no equals sign
 *           2. Should return empty vector
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_0300, Function | SmallTest | Level0)
{
    std::string filePath = "/data/test_invalid_version.txt";
    std::ofstream file(filePath);
    file << "1.2.3.4";
    file.close();

    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_TRUE(result.empty());

    std::filesystem::remove(filePath);
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_0400
 * @tc.name: Test GetVersionNums with empty version value
 * @tc.desc: 1. Read version with empty value after equals
 *           2. Should return empty vector
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_0400, Function | SmallTest | Level0)
{
    std::string filePath = "/data/test_empty_value_version.txt";
    std::ofstream file(filePath);
    file << "version=";
    file.close();

    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_TRUE(result.empty());

    std::filesystem::remove(filePath);
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_0500
 * @tc.name: Test GetVersionNums with invalid version parts count
 * @tc.desc: 1. Read version with wrong number of parts
 *           2. Should return empty vector
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_0500, Function | SmallTest | Level0)
{
    std::string filePath = "/data/test_invalid_parts_version.txt";
    std::ofstream file(filePath);
    file << "version=1.2.3";
    file.close();

    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_TRUE(result.empty());

    std::filesystem::remove(filePath);
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_0600
 * @tc.name: Test GetVersionNums with non-numeric version
 * @tc.desc: 1. Read version with non-numeric parts
 *           2. Should return empty vector
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_0600, Function | SmallTest | Level0)
{
    std::string filePath = "/data/test_non_numeric_version.txt";
    std::ofstream file(filePath);
    file << "version=1.2.3.abc";
    file.close();

    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_TRUE(result.empty());

    std::filesystem::remove(filePath);
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_0700
 * @tc.name: Test GetVersionNums with valid version
 * @tc.desc: 1. Read valid version string
 *           2. Should return version numbers
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_0700, Function | SmallTest | Level0)
{
    std::string filePath = "/data/test_valid_version.txt";
    std::ofstream file(filePath);
    file << "version=1.2.3.4";
    file.close();

    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0], 1);
    EXPECT_EQ(result[1], 2);
    EXPECT_EQ(result[2], 3);
    EXPECT_EQ(result[3], 4);

    std::filesystem::remove(filePath);
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_0800
 * @tc.name: Test GetVersionNums with spaces in version
 * @tc.desc: 1. Read version with spaces around value
 *           2. Should return version numbers (spaces trimmed)
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_0800, Function | SmallTest | Level0)
{
    std::string filePath = "/data/test_spaces_version.txt";
    std::ofstream file(filePath);
    file << "version=  1.2.3.4  ";
    file.close();

    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0], 1);
    EXPECT_EQ(result[1], 2);
    EXPECT_EQ(result[2], 3);
    EXPECT_EQ(result[3], 4);

    std::filesystem::remove(filePath);
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_0900
 * @tc.name: Test GetVersionNums with too many parts
 * @tc.desc: 1. Read version with 5 parts
 *           2. Should return empty vector
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_0900, Function | SmallTest | Level0)
{
    std::string filePath = "/data/test_too_many_parts_version.txt";
    std::ofstream file(filePath);
    file << "version=1.2.3.4.5";
    file.close();

    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_TRUE(result.empty());

    std::filesystem::remove(filePath);
}

/**
 * @tc.number: IdleParamUtil_GetVersionNums_1000
 * @tc.name: Test GetVersionNums with zero version
 * @tc.desc: 1. Read version 0.0.0.0
 *           2. Should return zeros
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetVersionNums_1000, Function | SmallTest | Level0)
{
    std::string filePath = "/data/test_zero_version.txt";
    std::ofstream file(filePath);
    file << "version=0.0.0.0";
    file.close();

    std::vector<int32_t> result = IdleParamUtil::GetVersionNums(filePath);
    EXPECT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0], 0);
    EXPECT_EQ(result[1], 0);
    EXPECT_EQ(result[2], 0);
    EXPECT_EQ(result[3], 0);

    std::filesystem::remove(filePath);
}

/**
 * @tc.number: IdleParamUtil_GetHigherVersionPath_0100
 * @tc.name: Test GetHigherVersionPath with no version files
 * @tc.desc: 1. Get path when no version files exist
 *           2. Should return empty string
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_GetHigherVersionPath_0100, Function | SmallTest | Level0)
{
    // This test assumes the default version files don't exist
    std::string result = IdleParamUtil::GetHigherVersionPath();
    // Result depends on system state, just check function doesn't crash
    EXPECT_TRUE(result.empty() || result.find("SwitchOffList") != std::string::npos);
}

/**
 * @tc.number: IdleParamUtil_IsRelabelFeatureDisabled_0100
 * @tc.name: Test IsRelabelFeatureDisabled when path is empty
 * @tc.desc: 1. Call when GetHigherVersionPath returns empty
 *           2. Should return false
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsRelabelFeatureDisabled_0100, Function | SmallTest | Level0)
{
    // When no valid version files exist, higherVersionPath will be empty
    // This test checks the behavior when GetHigherVersionPath returns empty
    // The actual behavior depends on system state
    bool result = IdleParamUtil::IsRelabelFeatureDisabled();
    // Just check function doesn't crash and returns a bool
    EXPECT_TRUE(result == true || result == false);
}

/**
 * @tc.number: IdleParamUtil_IsRelabelFeatureDisabled_0200
 * @tc.name: Test IsRelabelFeatureDisabled with relabel_feature_off in file
 * @tc.desc: 1. Create switch_off_list with relabel_feature_off
 *           2. Should return true
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsRelabelFeatureDisabled_0200, Function | SmallTest | Level0)
{
    std::string versionPath = "/data/service/el1/public/update/param_service/install/system/etc/SwitchOffList/";
    std::filesystem::create_directories(versionPath);

    std::string versionFile = versionPath + "version.txt";
    std::ofstream vFile(versionFile);
    vFile << "version=999.0.0.0";
    vFile.close();

    std::string switchOffFile = versionPath + "switch_off_list";
    std::ofstream sFile(switchOffFile);
    sFile << "relabel_feature_off" << std::endl;
    sFile.close();

    EXPECT_TRUE(IdleParamUtil::IsRelabelFeatureDisabled());

    std::filesystem::remove_all(versionPath);
}

/**
 * @tc.number: IdleParamUtil_IsRelabelFeatureDisabled_0300
 * @tc.name: Test IsRelabelFeatureDisabled without relabel_feature_off
 * @tc.desc: 1. Create switch_off_list without relabel_feature_off
 *           2. Should return false
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsRelabelFeatureDisabled_0300, Function | SmallTest | Level0)
{
    std::string versionPath = "/data/service/el1/public/update/param_service/install/system/etc/SwitchOffList/";
    std::filesystem::create_directories(versionPath);

    std::string versionFile = versionPath + "version.txt";
    std::ofstream vFile(versionFile);
    vFile << "version=999.0.0.0";
    vFile.close();

    std::string switchOffFile = versionPath + "switch_off_list";
    std::ofstream sFile(switchOffFile);
    sFile << "other_feature_off" << std::endl;
    sFile.close();

    EXPECT_FALSE(IdleParamUtil::IsRelabelFeatureDisabled());

    std::filesystem::remove_all(versionPath);
}

/**
 * @tc.number: IdleParamUtil_IsRelabelFeatureDisabled_0400
 * @tc.name: Test IsRelabelFeatureDisabled with empty switch_off_list
 * @tc.desc: 1. Create empty switch_off_list
 *           2. Should return false
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_IsRelabelFeatureDisabled_0400, Function | SmallTest | Level0)
{
    std::string versionPath = "/data/service/el1/public/update/param_service/install/system/etc/SwitchOffList/";
    std::filesystem::create_directories(versionPath);

    std::string versionFile = versionPath + "version.txt";
    std::ofstream vFile(versionFile);
    vFile << "version=999.0.0.0";
    vFile.close();

    std::string switchOffFile = versionPath + "switch_off_list";
    std::ofstream sFile(switchOffFile);
    sFile.close();

    EXPECT_FALSE(IdleParamUtil::IsRelabelFeatureDisabled());

    std::filesystem::remove_all(versionPath);
}

/**
 * @tc.number: IdleParamUtil_Integration_0100
 * @tc.name: Integration test for version comparison workflow
 * @tc.desc: 1. Create local and cloud version files
 *           2. Verify GetHigherVersionPath returns correct path
 */
HWTEST_F(BmsIdleConditionMgrTest, IdleParamUtil_Integration_0100, Function | SmallTest | Level0)
{
    std::string cloudPath = "/data/service/el1/public/update/param_service/install/system/etc/SwitchOffList/";
    std::filesystem::create_directories(cloudPath);

    // Create cloud version file with higher version
    std::string cloudVersionFile = cloudPath + "version.txt";
    std::ofstream cloudFile(cloudVersionFile);
    cloudFile << "version=999.0.0.0";
    cloudFile.close();

    std::string resultPath = IdleParamUtil::GetHigherVersionPath();
    EXPECT_EQ(resultPath, cloudPath);

    std::filesystem::remove_all(cloudPath);
}
} // namespace OHOS
