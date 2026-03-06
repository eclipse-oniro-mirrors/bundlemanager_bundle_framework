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

#define private public
#define protected public

#include <gtest/gtest.h>
#include <chrono>
#include <thread>

#include "memory/memory_compactor.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "common_event_support.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

extern bool g_mockSubscribeResult;
extern bool g_mockSubscribeCalled;
extern bool g_mockUnsubscribeCalled;

namespace OHOS {
namespace {
constexpr int32_t THREAD_SETTLE_MS = 500;
}  // namespace

class BmsMemoryCompactorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsMemoryCompactorTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsMemoryCompactorTest::SetUpTestCase()
{
}

void BmsMemoryCompactorTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsMemoryCompactorTest::SetUp()
{
    MemoryCompactor::screenOffSubscriber_ = nullptr;
    new (&MemoryCompactor::defragOnceFlag_) std::once_flag();
    g_mockSubscribeResult = false;
    g_mockSubscribeCalled = false;
    g_mockUnsubscribeCalled = false;
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsMemoryCompactorTest::TearDown()
{
    MemoryCompactor::screenOffSubscriber_ = nullptr;
}

/**
 * @tc.number: RegisterScreenOffListener_0001
 * @tc.name: test RegisterScreenOffListener when subscriber already exists
 * @tc.desc: 1.Set screenOffSubscriber_ to non-null
 *           2.Call RegisterScreenOffListener
 *           3.Verify subscriber unchanged and SubscribeCommonEvent not called
 */
HWTEST_F(BmsMemoryCompactorTest, RegisterScreenOffListener_0001, Function | SmallTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto existingSubscriber = std::make_shared<MemoryCompactor::ScreenOffEventSubscriber>(subscribeInfo);
    MemoryCompactor::screenOffSubscriber_ = existingSubscriber;

    MemoryCompactor::RegisterScreenOffListener();

    EXPECT_FALSE(g_mockSubscribeCalled);
    EXPECT_EQ(MemoryCompactor::screenOffSubscriber_, existingSubscriber);
}

/**
 * @tc.number: RegisterScreenOffListener_0002
 * @tc.name: test RegisterScreenOffListener when SubscribeCommonEvent fails
 * @tc.desc: 1.Set screenOffSubscriber_ to nullptr and mock subscribe to return false
 *           2.Call RegisterScreenOffListener
 *           3.Verify subscriber is reset to null after failed subscription
 */
HWTEST_F(BmsMemoryCompactorTest, RegisterScreenOffListener_0002, Function | SmallTest | Level1)
{
    g_mockSubscribeResult = false;

    MemoryCompactor::RegisterScreenOffListener();

    EXPECT_TRUE(g_mockSubscribeCalled);
    EXPECT_EQ(MemoryCompactor::screenOffSubscriber_, nullptr);
}

/**
 * @tc.number: RegisterScreenOffListener_0003
 * @tc.name: test RegisterScreenOffListener when SubscribeCommonEvent succeeds
 * @tc.desc: 1.Set screenOffSubscriber_ to nullptr and mock subscribe to return true
 *           2.Call RegisterScreenOffListener
 *           3.Verify subscriber is set after successful subscription
 */
HWTEST_F(BmsMemoryCompactorTest, RegisterScreenOffListener_0003, Function | SmallTest | Level1)
{
    g_mockSubscribeResult = true;

    MemoryCompactor::RegisterScreenOffListener();

    EXPECT_TRUE(g_mockSubscribeCalled);
    EXPECT_NE(MemoryCompactor::screenOffSubscriber_, nullptr);
}

/**
 * @tc.number: RegisterScreenOffListener_0004
 * @tc.name: test RegisterScreenOffListener idempotency on double registration
 * @tc.desc: 1.Register successfully once
 *           2.Call RegisterScreenOffListener again
 *           3.Verify second call returns early without re-subscribing
 */
HWTEST_F(BmsMemoryCompactorTest, RegisterScreenOffListener_0004, Function | SmallTest | Level1)
{
    g_mockSubscribeResult = true;
    MemoryCompactor::RegisterScreenOffListener();
    ASSERT_NE(MemoryCompactor::screenOffSubscriber_, nullptr);
    auto firstSubscriber = MemoryCompactor::screenOffSubscriber_;

    g_mockSubscribeCalled = false;
    MemoryCompactor::RegisterScreenOffListener();

    EXPECT_FALSE(g_mockSubscribeCalled);
    EXPECT_EQ(MemoryCompactor::screenOffSubscriber_, firstSubscriber);
}

/**
 * @tc.number: UnregisterScreenOffListener_0001
 * @tc.name: test UnregisterScreenOffListener when subscriber is null
 * @tc.desc: 1.Ensure screenOffSubscriber_ is nullptr
 *           2.Call UnregisterScreenOffListener
 *           3.Verify UnSubscribeCommonEvent is not called
 */
HWTEST_F(BmsMemoryCompactorTest, UnregisterScreenOffListener_0001, Function | SmallTest | Level1)
{
    ASSERT_EQ(MemoryCompactor::screenOffSubscriber_, nullptr);

    MemoryCompactor::UnregisterScreenOffListener();

    EXPECT_FALSE(g_mockUnsubscribeCalled);
}

/**
 * @tc.number: UnregisterScreenOffListener_0002
 * @tc.name: test UnregisterScreenOffListener when subscriber exists
 * @tc.desc: 1.Set screenOffSubscriber_ to a valid subscriber
 *           2.Call UnregisterScreenOffListener
 *           3.Verify UnSubscribeCommonEvent called and subscriber reset to null
 */
HWTEST_F(BmsMemoryCompactorTest, UnregisterScreenOffListener_0002, Function | SmallTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    MemoryCompactor::screenOffSubscriber_ =
        std::make_shared<MemoryCompactor::ScreenOffEventSubscriber>(subscribeInfo);
    ASSERT_NE(MemoryCompactor::screenOffSubscriber_, nullptr);

    MemoryCompactor::UnregisterScreenOffListener();

    EXPECT_TRUE(g_mockUnsubscribeCalled);
    EXPECT_EQ(MemoryCompactor::screenOffSubscriber_, nullptr);
}

/**
 * @tc.number: OnReceiveEvent_0001
 * @tc.name: test OnReceiveEvent with non-SCREEN_OFF action
 * @tc.desc: 1.Create an event with a non-SCREEN_OFF action
 *           2.Call OnReceiveEvent
 *           3.Verify no side effects (early return)
 */
HWTEST_F(BmsMemoryCompactorTest, OnReceiveEvent_0001, Function | SmallTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    MemoryCompactor::ScreenOffEventSubscriber subscriber(subscribeInfo);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    EventFwk::CommonEventData eventData(want);

    subscriber.OnReceiveEvent(eventData);

    EXPECT_FALSE(g_mockUnsubscribeCalled);
}

/**
 * @tc.number: OnReceiveEvent_0002
 * @tc.name: test OnReceiveEvent with SCREEN_OFF action triggers OnFirstScreenOff
 * @tc.desc: 1.Create an event with SCREEN_OFF action
 *           2.Set up subscriber_ so UnregisterScreenOffListener has work to do
 *           3.Call OnReceiveEvent
 *           4.Wait for the detached thread to complete
 *           5.Verify subscriber was unregistered via OnFirstScreenOff
 */
HWTEST_F(BmsMemoryCompactorTest, OnReceiveEvent_0002, Function | SmallTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriber = std::make_shared<MemoryCompactor::ScreenOffEventSubscriber>(subscribeInfo);
    MemoryCompactor::screenOffSubscriber_ = subscriber;

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventData eventData(want);

    subscriber->OnReceiveEvent(eventData);

    std::this_thread::sleep_for(std::chrono::milliseconds(THREAD_SETTLE_MS));

    EXPECT_TRUE(g_mockUnsubscribeCalled);
    EXPECT_EQ(MemoryCompactor::screenOffSubscriber_, nullptr);
}

/**
 * @tc.number: OnFirstScreenOff_0001
 * @tc.name: test OnFirstScreenOff when dataMgr is nullptr
 * @tc.desc: 1.Set screenOffSubscriber_ to verify call_once fires
 *           2.Ensure BundleMgrService::GetDataMgr returns nullptr
 *           3.Call OnFirstScreenOff
 *           4.Verify call_once executed (subscriber unregistered) and no crash on nullptr dataMgr
 */
HWTEST_F(BmsMemoryCompactorTest, OnFirstScreenOff_0001, Function | SmallTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    MemoryCompactor::screenOffSubscriber_ =
        std::make_shared<MemoryCompactor::ScreenOffEventSubscriber>(subscribeInfo);
    ASSERT_EQ(bundleMgrService_->GetDataMgr(), nullptr);

    MemoryCompactor::OnFirstScreenOff();

    EXPECT_TRUE(g_mockUnsubscribeCalled);
    EXPECT_EQ(MemoryCompactor::screenOffSubscriber_, nullptr);
}

/**
 * @tc.number: OnFirstScreenOff_0002
 * @tc.name: test OnFirstScreenOff when dataMgr is valid triggers DefragMemory
 * @tc.desc: 1.Set screenOffSubscriber_ for unregister flow
 *           2.Set a valid BundleDataMgr on BundleMgrService
 *           3.Add test data to bundleInfos_
 *           4.Call OnFirstScreenOff
 *           5.Verify DefragMemory was called (data preserved after compaction)
 */
HWTEST_F(BmsMemoryCompactorTest, OnFirstScreenOff_0002, Function | SmallTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    MemoryCompactor::screenOffSubscriber_ =
        std::make_shared<MemoryCompactor::ScreenOffEventSubscriber>(subscribeInfo);

    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace("com.test.bundle", info);
    bundleMgrService_->dataMgr_ = dataMgr;
    ASSERT_NE(bundleMgrService_->GetDataMgr(), nullptr);
    size_t sizeBefore = dataMgr->bundleInfos_.size();

    MemoryCompactor::OnFirstScreenOff();

    EXPECT_TRUE(g_mockUnsubscribeCalled);
    EXPECT_EQ(MemoryCompactor::screenOffSubscriber_, nullptr);
    EXPECT_EQ(dataMgr->bundleInfos_.size(), sizeBefore);
    EXPECT_TRUE(dataMgr->bundleInfos_.count("com.test.bundle") > 0);
}

/**
 * @tc.number: OnFirstScreenOff_0003
 * @tc.name: test OnFirstScreenOff call_once guard ensures single execution
 * @tc.desc: 1.Set subscriber and call OnFirstScreenOff first time (fires call_once)
 *           2.Set new dataMgr with distinct data
 *           3.Call OnFirstScreenOff second time
 *           4.Verify second call is a no-op (unregister not called again)
 */
HWTEST_F(BmsMemoryCompactorTest, OnFirstScreenOff_0003, Function | SmallTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    MemoryCompactor::screenOffSubscriber_ =
        std::make_shared<MemoryCompactor::ScreenOffEventSubscriber>(subscribeInfo);

    MemoryCompactor::OnFirstScreenOff();
    EXPECT_TRUE(g_mockUnsubscribeCalled);

    auto newDataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info;
    newDataMgr->bundleInfos_.emplace("com.test.secondcall", info);
    bundleMgrService_->dataMgr_ = newDataMgr;

    g_mockUnsubscribeCalled = false;
    MemoryCompactor::OnFirstScreenOff();

    EXPECT_FALSE(g_mockUnsubscribeCalled);
    EXPECT_TRUE(newDataMgr->bundleInfos_.count("com.test.secondcall") > 0);
}

/**
 * @tc.number: DefragMemory_0001
 * @tc.name: test DefragMemory with empty bundleInfos map
 * @tc.desc: 1.Create BundleDataMgr with empty bundleInfos_
 *           2.Call DefragMemory
 *           3.Verify no crash and map remains empty
 */
HWTEST_F(BmsMemoryCompactorTest, DefragMemory_0001, Function | SmallTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->bundleInfos_.clear();

    dataMgr->DefragMemory();

    EXPECT_TRUE(dataMgr->bundleInfos_.empty());
}

/**
 * @tc.number: DefragMemory_0002
 * @tc.name: test DefragMemory preserves data integrity
 * @tc.desc: 1.Create BundleDataMgr with multiple bundle entries
 *           2.Call DefragMemory
 *           3.Verify all entries preserved and data consistent
 */
HWTEST_F(BmsMemoryCompactorTest, DefragMemory_0002, Function | SmallTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    constexpr int32_t entryCount = 50;
    for (int32_t i = 0; i < entryCount; ++i) {
        InnerBundleInfo info;
        dataMgr->bundleInfos_.emplace("com.test.bundle" + std::to_string(i), info);
    }
    ASSERT_EQ(static_cast<int32_t>(dataMgr->bundleInfos_.size()), entryCount);

    dataMgr->DefragMemory();

    EXPECT_EQ(static_cast<int32_t>(dataMgr->bundleInfos_.size()), entryCount);
    for (int32_t i = 0; i < entryCount; ++i) {
        EXPECT_TRUE(dataMgr->bundleInfos_.count("com.test.bundle" + std::to_string(i)) > 0);
    }
}

/**
 * @tc.number: DefragMemory_0003
 * @tc.name: test DefragMemory called multiple times is idempotent
 * @tc.desc: 1.Create BundleDataMgr with data
 *           2.Call DefragMemory multiple times
 *           3.Verify data integrity after each call
 */
HWTEST_F(BmsMemoryCompactorTest, DefragMemory_0003, Function | SmallTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace("com.test.stable", info);

    for (int32_t i = 0; i < 10; ++i) {
        dataMgr->DefragMemory();
        EXPECT_EQ(dataMgr->bundleInfos_.size(), 1u);
        EXPECT_TRUE(dataMgr->bundleInfos_.count("com.test.stable") > 0);
    }
}

/**
 * @tc.number: DefragMemory_0004
 * @tc.name: test DefragMemory thread safety under concurrent access
 * @tc.desc: 1.Create BundleDataMgr with data
 *           2.Spawn multiple threads calling DefragMemory concurrently
 *           3.Verify data integrity after all threads complete
 */
HWTEST_F(BmsMemoryCompactorTest, DefragMemory_0004, Function | SmallTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    constexpr int32_t entryCount = 20;
    for (int32_t i = 0; i < entryCount; ++i) {
        InnerBundleInfo info;
        dataMgr->bundleInfos_.emplace("com.test.concurrent" + std::to_string(i), info);
    }

    constexpr int32_t threadCount = 8;
    std::vector<std::thread> threads;
    threads.reserve(threadCount);
    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&dataMgr]() {
            dataMgr->DefragMemory();
        });
    }
    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(static_cast<int32_t>(dataMgr->bundleInfos_.size()), entryCount);
    for (int32_t i = 0; i < entryCount; ++i) {
        EXPECT_TRUE(dataMgr->bundleInfos_.count("com.test.concurrent" + std::to_string(i)) > 0);
    }
}
}  // namespace OHOS
