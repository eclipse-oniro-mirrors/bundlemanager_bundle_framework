/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <fstream>

#include "app_log_wrapper.h"
#define private public
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_permission_mgr.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_subscriber.h"
#include "scope_guard.h"
#include "want.h"
#include "user_unlocked_event_subscriber.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::DelayedSingleton;

namespace OHOS {
class BmsEventHandlerUnLockedTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId);
    bool OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data);

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsEventHandlerUnLockedTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsEventHandlerUnLockedTest::SetUpTestCase()
{}

void BmsEventHandlerUnLockedTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsEventHandlerUnLockedTest::SetUp()
{}

void BmsEventHandlerUnLockedTest::TearDown()
{}

bool BmsEventHandlerUnLockedTest::CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId)
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(userId);
    return UpdateAppDataMgr::CreateBundleDataDir(bundleInfo, userId, ServiceConstants::DIR_EL2);
}

bool BmsEventHandlerUnLockedTest::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    subscriberPtr->OnReceiveEvent(data);
    std::string action = data.GetWant().GetAction();
    return action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0100
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test CreateBundleDataDir true
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0100, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bool res = CreateBundleDataDir(bundleInfo, Constants::ALL_USERID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0200
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test CreateBundleDataDir true
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0200, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bool res = CreateBundleDataDir(bundleInfo, Constants::ALL_USERID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0300
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test OnReceiveEvent true
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0300, Function | SmallTest | Level0)
{
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventData commonData { want };

    bool res = OnReceiveEvent(commonData);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0400
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test OnReceiveEvent false
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0400, Function | SmallTest | Level0)
{
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventData commonData { want };

    bool res = OnReceiveEvent(commonData);
    EXPECT_EQ(res, false);
}
} // OHOS