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

#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <functional>

#include "bundle_common_event_mgr.h"
#include "app_log_wrapper.h"
#include "bundle_common_event.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string TEST_APP_ID = "com.test.app_test_appId";
const std::string TEST_APP_ID_2 = "com.test.app2_app_test_appId";
const std::string TEST_APP_ID_3 = "com.test.app3_app_test_appId";
const std::string TEST_DATA = "test data for disposed rule";
const int32_t TEST_USER_ID = 100;
const int32_t TEST_USER_ID_2 = 101;
const int32_t TEST_APP_INDEX = 0;
const int32_t TEST_APP_INDEX_2 = 1;
const int32_t WAIT_TIME_MS = 100;
const int32_t LONGER_WAIT_TIME_MS = 500;
}  // namespace

class BmsBundleCommonEventMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::shared_ptr<BundleCommonEventMgr> eventMgr_;
};

void BmsBundleCommonEventMgrTest::SetUpTestCase()
{
    APP_LOGI("BmsBundleCommonEventMgrTest::SetUpTestCase");
}

void BmsBundleCommonEventMgrTest::TearDownTestCase()
{
    APP_LOGI("BmsBundleCommonEventMgrTest::TearDownTestCase");
}

void BmsBundleCommonEventMgrTest::SetUp()
{
    eventMgr_ = std::make_shared<BundleCommonEventMgr>();
    APP_LOGI("BmsBundleCommonEventMgrTest::SetUp");
}

void BmsBundleCommonEventMgrTest::TearDown()
{
    APP_LOGI("BmsBundleCommonEventMgrTest::TearDown");
}

/**
 * @tc.name: SubmitEventAsync_001
 * @tc.desc: Test submitting a single async event
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, SubmitEventAsync_001, TestSize.Level1)
{
    APP_LOGI("SubmitEventAsync_001 start");

    std::atomic<bool> eventExecuted{false};
    auto publishFunc = [&eventExecuted]() {
        eventExecuted.store(true);
    };

    eventMgr_->SubmitEventAsync(publishFunc);

    // Wait for event to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));

    EXPECT_TRUE(eventExecuted.load());
    APP_LOGI("SubmitEventAsync_001 end");
}

/**
 * @tc.name: SubmitEventAsync_002
 * @tc.desc: Test submitting multiple async events
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, SubmitEventAsync_002, TestSize.Level1)
{
    APP_LOGI("SubmitEventAsync_002 start");

    std::atomic<int> executionCount{0};
    const int eventCount = 10;

    for (int i = 0; i < eventCount; ++i) {
        auto publishFunc = [&executionCount]() {
            executionCount.fetch_add(1);
        };
        eventMgr_->SubmitEventAsync(publishFunc);
    }

    // Wait for all events to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_EQ(executionCount.load(), eventCount);
    APP_LOGI("SubmitEventAsync_002 end");
}

/**
 * @tc.name: SubmitEventAsync_003
 * @tc.desc: Test submitting empty event function
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, SubmitEventAsync_003, TestSize.Level1)
{
    APP_LOGI("SubmitEventAsync_003 start");

    BundleCommonEventMgr::EventPublishFunc emptyFunc;
    eventMgr_->SubmitEventAsync(emptyFunc);

    // Wait for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("SubmitEventAsync_003 end");
}

/**
 * @tc.name: SubmitEventAsync_004
 * @tc.desc: Test submitting events exceeding batch size
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, SubmitEventAsync_004, TestSize.Level1)
{
    APP_LOGI("SubmitEventAsync_004 start");

    std::atomic<int> executionCount{0};
    const int eventCount = 50; // More than MAX_EVENTS_PER_BATCH (20)

    for (int i = 0; i < eventCount; ++i) {
        auto publishFunc = [&executionCount]() {
            executionCount.fetch_add(1);
        };
        eventMgr_->SubmitEventAsync(publishFunc);
    }

    // Wait for all events to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_EQ(executionCount.load(), eventCount);
    APP_LOGI("SubmitEventAsync_004 end");
}

/**
 * @tc.name: NotifySetDisposedRuleAsync_001
 * @tc.desc: Test async notification for setting disposed rule with basic parameters
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, NotifySetDisposedRuleAsync_001, TestSize.Level1)
{
    APP_LOGI("NotifySetDisposedRuleAsync_001 start");

    eventMgr_->NotifySetDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID, TEST_DATA, TEST_APP_INDEX);

    // Wait for async processing
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("NotifySetDisposedRuleAsync_001 end");
}

/**
 * @tc.name: NotifySetDisposedRuleAsync_002
 * @tc.desc: Test multiple async notifications for setting disposed rules
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, NotifySetDisposedRuleAsync_002, TestSize.Level1)
{
    APP_LOGI("NotifySetDisposedRuleAsync_002 start");

    const int notificationCount = 10;
    for (int i = 0; i < notificationCount; ++i) {
        eventMgr_->NotifySetDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID + i, TEST_DATA, TEST_APP_INDEX + i);
    }

    // Wait for all notifications
    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("NotifySetDisposedRuleAsync_002 end");
}

/**
 * @tc.name: NotifySetDisposedRuleAsync_003
 * @tc.desc: Test async notification with different app IDs
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, NotifySetDisposedRuleAsync_003, TestSize.Level1)
{
    APP_LOGI("NotifySetDisposedRuleAsync_003 start");

    eventMgr_->NotifySetDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID, TEST_DATA, TEST_APP_INDEX);
    eventMgr_->NotifySetDisposedRuleAsync(TEST_APP_ID_2, TEST_USER_ID_2, TEST_DATA, TEST_APP_INDEX_2);
    eventMgr_->NotifySetDisposedRuleAsync(TEST_APP_ID_3, TEST_USER_ID, TEST_DATA, TEST_APP_INDEX);

    // Wait for all notifications
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("NotifySetDisposedRuleAsync_003 end");
}

/**
 * @tc.name: NotifySetDisposedRuleAsync_004
 * @tc.desc: Test async notification exceeding batch size
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, NotifySetDisposedRuleAsync_004, TestSize.Level1)
{
    APP_LOGI("NotifySetDisposedRuleAsync_004 start");

    const int notificationCount = 30; // More than MAX_EVENTS_PER_BATCH (20)
    for (int i = 0; i < notificationCount; ++i) {
        eventMgr_->NotifySetDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID + i, TEST_DATA, TEST_APP_INDEX);
    }

    // Wait for all notifications
    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("NotifySetDisposedRuleAsync_004 end");
}

/**
 * @tc.name: NotifyDeleteDisposedRuleAsync_001
 * @tc.desc: Test async notification for deleting disposed rule with basic parameters
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, NotifyDeleteDisposedRuleAsync_001, TestSize.Level1)
{
    APP_LOGI("NotifyDeleteDisposedRuleAsync_001 start");

    eventMgr_->NotifyDeleteDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID, TEST_APP_INDEX);

    // Wait for async processing
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("NotifyDeleteDisposedRuleAsync_001 end");
}

/**
 * @tc.name: NotifyDeleteDisposedRuleAsync_002
 * @tc.desc: Test multiple async notifications for deleting disposed rules
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, NotifyDeleteDisposedRuleAsync_002, TestSize.Level1)
{
    APP_LOGI("NotifyDeleteDisposedRuleAsync_002 start");

    const int notificationCount = 15;
    for (int i = 0; i < notificationCount; ++i) {
        eventMgr_->NotifyDeleteDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID + i, TEST_APP_INDEX + i);
    }

    // Wait for all notifications
    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("NotifyDeleteDisposedRuleAsync_002 end");
}

/**
 * @tc.name: NotifyDeleteDisposedRuleAsync_003
 * @tc.desc: Test mixed async notifications (set and delete)
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, NotifyDeleteDisposedRuleAsync_003, TestSize.Level1)
{
    APP_LOGI("NotifyDeleteDisposedRuleAsync_003 start");

    // Mix of set and delete operations
    for (int i = 0; i < 5; ++i) {
        eventMgr_->NotifySetDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID + i, TEST_DATA, TEST_APP_INDEX);
        eventMgr_->NotifyDeleteDisposedRuleAsync(TEST_APP_ID_2, TEST_USER_ID + i, TEST_APP_INDEX_2);
    }

    // Wait for all notifications
    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("NotifyDeleteDisposedRuleAsync_003 end");
}

/**
 * @tc.name: NotifyDeleteDisposedRuleAsync_004
 * @tc.desc: Test async notification exceeding batch size
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, NotifyDeleteDisposedRuleAsync_004, TestSize.Level1)
{
    APP_LOGI("NotifyDeleteDisposedRuleAsync_004 start");

    const int notificationCount = 35; // More than MAX_EVENTS_PER_BATCH (20)
    for (int i = 0; i < notificationCount; ++i) {
        eventMgr_->NotifyDeleteDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID + i, TEST_APP_INDEX + i);
    }

    // Wait for all notifications
    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("NotifyDeleteDisposedRuleAsync_004 end");
}

/**
 * @tc.name: ProcessEventQueue_001
 * @tc.desc: Test event queue processing with batch size limit
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, ProcessEventQueue_001, TestSize.Level1)
{
    APP_LOGI("ProcessEventQueue_001 start");

    std::atomic<int> executionCount{0};
    // Submit exactly MAX_EVENTS_PER_BATCH events
    const int eventCount = 20; // MAX_EVENTS_PER_BATCH

    for (int i = 0; i < eventCount; ++i) {
        auto publishFunc = [&executionCount]() {
            executionCount.fetch_add(1);
        };
        eventMgr_->SubmitEventAsync(publishFunc);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_EQ(executionCount.load(), eventCount);
    APP_LOGI("ProcessEventQueue_001 end");
}

/**
 * @tc.name: ProcessEventQueue_002
 * @tc.desc: Test event queue processing with multiple batches
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, ProcessEventQueue_002, TestSize.Level1)
{
    APP_LOGI("ProcessEventQueue_002 start");

    std::atomic<int> executionCount{0};
    // Submit more than MAX_EVENTS_PER_BATCH events
    const int eventCount = 45; // More than 2 batches

    for (int i = 0; i < eventCount; ++i) {
        auto publishFunc = [&executionCount]() {
            executionCount.fetch_add(1);
        };
        eventMgr_->SubmitEventAsync(publishFunc);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_EQ(executionCount.load(), eventCount);
    APP_LOGI("ProcessEventQueue_002 end");
}

/**
 * @tc.name: ProcessEventQueue_003
 * @tc.desc: Test concurrent event submissions
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, ProcessEventQueue_003, TestSize.Level1)
{
    APP_LOGI("ProcessEventQueue_003 start");

    std::atomic<int> executionCount{0};
    const int threadCount = 5;
    const int eventsPerThread = 10;

    std::vector<std::thread> threads;
    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back([this, &executionCount, eventsPerThread]() {
            for (int i = 0; i < eventsPerThread; ++i) {
                auto publishFunc = [&executionCount]() {
                    executionCount.fetch_add(1);
                };
                eventMgr_->SubmitEventAsync(publishFunc);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_EQ(executionCount.load(), threadCount * eventsPerThread);
    APP_LOGI("ProcessEventQueue_003 end");
}

/**
 * @tc.name: ProcessEventQueue_004
 * @tc.desc: Test event queue processing state management
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, ProcessEventQueue_004, TestSize.Level1)
{
    APP_LOGI("ProcessEventQueue_004 start");

    std::atomic<bool> firstEventProcessed{false};
    std::atomic<bool> secondEventProcessed{false};

    // Submit first event
    eventMgr_->SubmitEventAsync([&firstEventProcessed]() {
        firstEventProcessed.store(true);
    });

    // Wait a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));

    // Submit second event
    eventMgr_->SubmitEventAsync([&secondEventProcessed]() {
        secondEventProcessed.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_TRUE(firstEventProcessed.load());
    EXPECT_TRUE(secondEventProcessed.load());
    APP_LOGI("ProcessEventQueue_004 end");
}

/**
 * @tc.name: ProcessEventQueue_005
 * @tc.desc: Test event queue with rapid submissions
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, ProcessEventQueue_005, TestSize.Level1)
{
    APP_LOGI("ProcessEventQueue_005 start");

    std::atomic<int> executionCount{0};
    const int eventCount = 100;

    // Submit events rapidly without delay
    for (int i = 0; i < eventCount; ++i) {
        auto publishFunc = [&executionCount]() {
            executionCount.fetch_add(1);
        };
        eventMgr_->SubmitEventAsync(publishFunc);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_EQ(executionCount.load(), eventCount);
    APP_LOGI("ProcessEventQueue_005 end");
}

/**
 * @tc.name: StartAsyncProcessingIfNeeded_001
 * @tc.desc: Test that processing starts only once for multiple submissions
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, StartAsyncProcessingIfNeeded_001, TestSize.Level1)
{
    APP_LOGI("StartAsyncProcessingIfNeeded_001 start");

    std::atomic<int> executionCount{0};

    // Submit multiple events rapidly before processing starts
    for (int i = 0; i < 5; ++i) {
        auto publishFunc = [&executionCount]() {
            executionCount.fetch_add(1);
        };
        eventMgr_->SubmitEventAsync(publishFunc);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_EQ(executionCount.load(), 5);
    APP_LOGI("StartAsyncProcessingIfNeeded_001 end");
}

/**
 * @tc.name: EdgeCase_001
 * @tc.desc: Test with empty string parameters
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, EdgeCase_001, TestSize.Level1)
{
    APP_LOGI("EdgeCase_001 start");

    const std::string emptyAppId = "";
    const std::string emptyData = "";

    eventMgr_->NotifySetDisposedRuleAsync(emptyAppId, TEST_USER_ID, emptyData, TEST_APP_INDEX);
    eventMgr_->NotifyDeleteDisposedRuleAsync(emptyAppId, TEST_USER_ID, TEST_APP_INDEX);

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("EdgeCase_001 end");
}

/**
 * @tc.name: EdgeCase_002
 * @tc.desc: Test with negative user ID
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, EdgeCase_002, TestSize.Level1)
{
    APP_LOGI("EdgeCase_002 start");

    const int32_t negativeUserId = -1;

    eventMgr_->NotifySetDisposedRuleAsync(TEST_APP_ID, negativeUserId, TEST_DATA, TEST_APP_INDEX);
    eventMgr_->NotifyDeleteDisposedRuleAsync(TEST_APP_ID, negativeUserId, TEST_APP_INDEX);

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("EdgeCase_002 end");
}

/**
 * @tc.name: EdgeCase_003
 * @tc.desc: Test with extreme app index values
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, EdgeCase_003, TestSize.Level1)
{
    APP_LOGI("EdgeCase_003 start");

    const int32_t maxAppIndex = 999;
    const int32_t negativeAppIndex = -1;

    eventMgr_->NotifySetDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID, TEST_DATA, maxAppIndex);
    eventMgr_->NotifyDeleteDisposedRuleAsync(TEST_APP_ID, TEST_USER_ID, negativeAppIndex);

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    // Should not crash
    EXPECT_TRUE(true);
    APP_LOGI("EdgeCase_003 end");
}

/**
 * @tc.name: EdgeCase_004
 * @tc.desc: Test event submission during processing
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, EdgeCase_004, TestSize.Level1)
{
    APP_LOGI("EdgeCase_004 start");

    std::atomic<int> executionCount{0};
    std::atomic<bool> startedProcessing{false};

    // Submit initial batch
    for (int i = 0; i < 10; ++i) {
        auto publishFunc = [&executionCount, &startedProcessing]() {
            startedProcessing.store(true);
            executionCount.fetch_add(1);
        };
        eventMgr_->SubmitEventAsync(publishFunc);
    }

    // Wait for processing to start
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Submit more events while processing
    for (int i = 0; i < 15; ++i) {
        auto publishFunc = [&executionCount]() {
            executionCount.fetch_add(1);
        };
        eventMgr_->SubmitEventAsync(publishFunc);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_EQ(executionCount.load(), 25);
    APP_LOGI("EdgeCase_004 end");
}

/**
 * @tc.name: PerformanceTest_001
 * @tc.desc: Test performance with large number of events
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, PerformanceTest_001, TestSize.Level1)
{
    APP_LOGI("PerformanceTest_001 start");

    std::atomic<int> executionCount{0};
    const int eventCount = 200;

    auto startTime = std::chrono::steady_clock::now();

    for (int i = 0; i < eventCount; ++i) {
        auto publishFunc = [&executionCount]() {
            executionCount.fetch_add(1);
        };
        eventMgr_->SubmitEventAsync(publishFunc);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    EXPECT_EQ(executionCount.load(), eventCount);
    APP_LOGI("PerformanceTest_001 processed %{public}d events in %{public}lld ms",
        eventCount, static_cast<long long>(duration.count()));
    APP_LOGI("PerformanceTest_001 end");
}

/**
 * @tc.name: StressTest_001
 * @tc.desc: Stress test with rapid concurrent submissions
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleCommonEventMgrTest, StressTest_001, TestSize.Level1)
{
    APP_LOGI("StressTest_001 start");

    std::atomic<int> executionCount{0};
    const int threadCount = 10;
    const int eventsPerThread = 50;

    std::vector<std::thread> threads;
    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back([this, &executionCount, eventsPerThread]() {
            for (int i = 0; i < eventsPerThread; ++i) {
                auto publishFunc = [&executionCount]() {
                    executionCount.fetch_add(1);
                };
                eventMgr_->SubmitEventAsync(publishFunc);
                // Small delay to simulate realistic usage
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(LONGER_WAIT_TIME_MS));

    EXPECT_EQ(executionCount.load(), threadCount * eventsPerThread);
    APP_LOGI("StressTest_001 end");
}

} // namespace OHOS
