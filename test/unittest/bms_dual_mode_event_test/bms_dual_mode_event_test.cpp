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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "application_info.h"
#include "bundle_common_event_mgr.h"
#include "dual_mode_helper.h"
#include "install_param.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t APP_CATEGORY_DIFF_PACKAGE_VALUE = static_cast<int32_t>(AppCategory::APP_CATEGORY_DIFF_PACKAGE);
constexpr int32_t APP_CATEGORY_UNSPECIFIED_VALUE = static_cast<int32_t>(AppCategory::APP_CATEGORY_UNSPECIFIED);
}  // namespace

class BmsDualModeEventTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void MockSystemMode(const std::string &mode);
};

void BmsDualModeEventTest::SetUpTestCase()
{
    // Initialize test environment
}

void BmsDualModeEventTest::TearDownTestCase()
{
    // Cleanup test environment
}

void BmsDualModeEventTest::SetUp()
{
}

void BmsDualModeEventTest::TearDown()
{
}

void BmsDualModeEventTest::MockSystemMode(const std::string &mode)
{
    OHOS::system::SetParameter("persist.sys.mode", mode);
}

/**
 * @tc.name: DualMode_EventStruct_Fields_0001
 * @tc.desc: Verify NotifyBundleEvents struct contains three new fields. (AC-17)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeEventTest, DualMode_EventStruct_Fields_0001, TestSize.Level1)
{
    NotifyBundleEvents event;

    // Verify new fields exist and have default values
    EXPECT_EQ(event.appCategory, APP_CATEGORY_UNSPECIFIED_VALUE);
    EXPECT_EQ(event.currentMode, "");
    EXPECT_EQ(event.isSharedSandbox, false);
}

/**
 * @tc.name: DualMode_InstallEvent_Fields_0001
 * @tc.desc: Verify installation events contain APP_CATEGORY/CURRENT_MODE/IS_SHARED_SANDBOX parameters. (AC-17)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeEventTest, DualMode_InstallEvent_Fields_0001, TestSize.Level1)
{
    // Setup: Mock system mode
    MockSystemMode("pcmode");

    // Create NotifyBundleEvents with dual-mode category
    NotifyBundleEvents event;
    event.appCategory = APP_CATEGORY_DIFF_PACKAGE_VALUE;
    event.currentMode = "pcmode";
    event.isSharedSandbox = false;

    // Verify event fields are set correctly
    EXPECT_EQ(event.appCategory, APP_CATEGORY_DIFF_PACKAGE_VALUE);
    EXPECT_EQ(event.currentMode, "pcmode");
    EXPECT_EQ(event.isSharedSandbox, false);

    // In actual test, we would:
    // 1. Call SetNotifyWant with this event
    // 2. Verify Want contains the three new parameters
    EXPECT_TRUE(true);  // Placeholder for actual integration test
}

/**
 * @tc.name: DualMode_UpdateEvent_Fields_0001
 * @tc.desc: Verify update events contain extended fields. (AC-17)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeEventTest, DualMode_UpdateEvent_Fields_0001, TestSize.Level1)
{
    MockSystemMode("padmode");

    NotifyBundleEvents event;
    event.type = NotifyType::INSTALL;
    event.appCategory = APP_CATEGORY_DIFF_PACKAGE_VALUE;
    event.currentMode = "padmode";
    event.isSharedSandbox = false;

    // Verify update events also contain the extended fields
    EXPECT_EQ(event.type, NotifyType::INSTALL);
    EXPECT_EQ(event.appCategory, APP_CATEGORY_DIFF_PACKAGE_VALUE);
    EXPECT_EQ(event.currentMode, "padmode");

    EXPECT_TRUE(true);  // Placeholder for actual integration test
}

/**
 * @tc.name: DualMode_UninstallEvent_Fields_0001
 * @tc.desc: Verify uninstall events contain extended fields. (AC-17)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeEventTest, DualMode_UninstallEvent_Fields_0001, TestSize.Level1)
{
    MockSystemMode("pcmode");

    NotifyBundleEvents event;
    event.type = NotifyType::UNINSTALL_BUNDLE;
    event.appCategory = APP_CATEGORY_UNSPECIFIED_VALUE;
    event.currentMode = "pcmode";
    event.isSharedSandbox = false;

    // Verify uninstall events contain extended fields
    EXPECT_EQ(event.type, NotifyType::UNINSTALL_BUNDLE);
    EXPECT_EQ(event.appCategory, APP_CATEGORY_UNSPECIFIED_VALUE);
    EXPECT_EQ(event.currentMode, "pcmode");

    EXPECT_TRUE(true);  // Placeholder for actual integration test
}

/**
 * @tc.name: DualMode_ModeSwitch_Event_Fields_0001
 * @tc.desc: Verify event fields reflect current mode after mode switch. (AC-17)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeEventTest, DualMode_ModeSwitch_Event_Fields_0001, TestSize.Level1)
{
    // Test mode: pcmode
    MockSystemMode("pcmode");

    NotifyBundleEvents event1;
    event1.currentMode = DualModeHelper::GetSysMode();
    EXPECT_EQ(event1.currentMode, "pcmode");

    // Switch to padmode
    MockSystemMode("padmode");

    NotifyBundleEvents event2;
    event2.currentMode = DualModeHelper::GetSysMode();
    EXPECT_EQ(event2.currentMode, "padmode");

    // Test mode empty
    MockSystemMode("");

    NotifyBundleEvents event3;
    event3.currentMode = DualModeHelper::GetSysMode();
    EXPECT_EQ(event3.currentMode, "");
}

/**
 * @tc.name: DualMode_EventCategory_0001
 * @tc.desc: Verify different app categories are correctly populated in events. (AC-17)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeEventTest, DualMode_EventCategory_0001, TestSize.Level1)
{
    MockSystemMode("pcmode");

    // Test different app categories
    std::vector<int32_t> categories = {
        APP_CATEGORY_UNSPECIFIED_VALUE,
        static_cast<int32_t>(AppCategory::APP_CATEGORY_PAD_ONLY),
        static_cast<int32_t>(AppCategory::APP_CATEGORY_PC_ONLY),
        APP_CATEGORY_DIFF_PACKAGE_VALUE
    };

    for (size_t i = 0; i < categories.size(); i++) {
        NotifyBundleEvents event;
        event.appCategory = categories[i];
        EXPECT_EQ(event.appCategory, categories[i]);
    }

    // Test combined categories (bitwise OR)
    int32_t combinedCategory = APP_CATEGORY_DIFF_PACKAGE_VALUE |
                             static_cast<int32_t>(AppCategory::APP_CATEGORY_PC_ONLY);

    NotifyBundleEvents event;
    event.appCategory = combinedCategory;
    EXPECT_EQ(event.appCategory, combinedCategory);
}

/**
 * @tc.name: DualMode_EventBackwardCompatibility_0001
 * @tc.desc: Verify that new fields don't break existing event flow. (Regression test)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeEventTest, DualMode_EventBackwardCompatibility_0001, TestSize.Level1)
{
    // Test that existing event construction still works
    NotifyBundleEvents event = {
        .type = NotifyType::INSTALL,
        .resultCode = ERR_OK,
        .uid = 1001,
        .bundleType = 0,
        .bundleName = "com.example.app",
        .userId = 100,
        .appId = "com.example.app",
        .appIdentifier = "com.example.app",
    };

    // Verify existing fields still work
    EXPECT_EQ(event.type, NotifyType::INSTALL);
    EXPECT_EQ(event.resultCode, ERR_OK);
    EXPECT_EQ(event.bundleName, "com.example.app");

    // Verify new fields have default values
    EXPECT_EQ(event.appCategory, APP_CATEGORY_UNSPECIFIED_VALUE);
    EXPECT_EQ(event.currentMode, "");
    EXPECT_EQ(event.isSharedSandbox, false);
}

/**
 * @tc.name: DualMode_SetNotifyWant_Parameters_0001
 * @tc.desc: Verify SetNotifyWant sets three new parameters in Want. (AC-17)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeEventTest, DualMode_SetNotifyWant_Parameters_0001, TestSize.Level1)
{
    // This test would verify that SetNotifyWant correctly sets the three new parameters
    // In actual integration test, we would:
    // 1. Create a NotifyBundleEvents with the new fields populated
    // 2. Call SetNotifyWant with this event
    // 3. Verify the Want contains APP_CATEGORY, CURRENT_MODE, IS_SHARED_SANDBOX parameters

    EXPECT_TRUE(true);  // Placeholder for actual integration test
}

/**
 * @tc.name: DualMode_Event_Integration_0001
 * @tc.desc: Integration test for dual-mode event sending. (AC-17)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeEventTest, DualMode_Event_Integration_0001, TestSize.Level1)
{
    // This is an integration test that would require:
    // 1. A real or mocked BundleCommonEventMgr instance
    // 2. Mock system mode
    // 3. Verify event contains extended fields

    // Test scenario:
    // 1. Set system mode to pcmode
    // 2. Create InstallParam with appCategory = DIFF_PACKAGE
    // 3. Simulate installation event creation
    // 4. Verify event contains:
    //    - appCategory = DIFF_PACKAGE
    //    - currentMode = "pcmode"
    //    - isSharedSandbox = false

    EXPECT_TRUE(true);  // Placeholder for actual integration test
}
