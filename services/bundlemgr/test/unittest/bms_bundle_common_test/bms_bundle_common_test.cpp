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
#define private public

#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <sstream>
#include <string>

#include "bundle_mgr_service.h"
#include "serial_queue.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    constexpr uint32_t DISCONNECT_DELAY = 20000;
    constexpr uint32_t DISCONNECT_DELAY1 = 0;
    const std::string DISCONNECT_DELAY_TASK = "DisconnectDelayTask";
}  // namespace

class BmsBundleCommonTest : public testing::Test {
public:
    BmsBundleCommonTest();
    ~BmsBundleCommonTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleCommonTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleCommonTest::BmsBundleCommonTest()
{}

BmsBundleCommonTest::~BmsBundleCommonTest()
{}

void BmsBundleCommonTest::SetUpTestCase()
{}

void BmsBundleCommonTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleCommonTest::SetUp()
{}

void BmsBundleCommonTest::TearDown()
{}

/**
 * @tc.number: CheckAppInstallControl
 * @tc.name: test CheckAppInstallControl by InnerBundleInfo
 * @tc.desc: 1.CheckAppInstallControl test
 */
HWTEST_F(BmsBundleCommonTest, CancelDelayTask_0100, Function | SmallTest | Level1)
{
    std::string queueName;
    SerialQueue serialQueue(queueName);
    std::string taskName = "task";
    serialQueue.CancelDelayTask(taskName);
    EXPECT_EQ(serialQueue.taskMap_.size(), 0);
}

/**
 * @tc.number: CheckAppInstallControl
 * @tc.name: test CheckAppInstallControl by InnerBundleInfo
 * @tc.desc: 1.CheckAppInstallControl test
 */
HWTEST_F(BmsBundleCommonTest, CancelDelayTask_0200, Function | SmallTest | Level1)
{
    std::string queueName;
    SerialQueue serialQueue(queueName);
    auto registerEventListenerFunc = []() {
        return;
    };
    std::string taskName = "task";
    serialQueue.ScheduleDelayTask(taskName, DISCONNECT_DELAY, registerEventListenerFunc);

    serialQueue.CancelDelayTask(taskName);
    EXPECT_EQ(serialQueue.taskMap_.size(), 0);
}

/**
 * @tc.number: CheckAppInstallControl
 * @tc.name: test CheckAppInstallControl by InnerBundleInfo
 * @tc.desc: 1.CheckAppInstallControl test
 */
HWTEST_F(BmsBundleCommonTest, CancelDelayTask_0300, Function | SmallTest | Level1)
{
    std::string queueName;
    SerialQueue serialQueue(queueName);
    auto registerEventListenerFunc = []() {
        return;
    };
    std::string taskName = "task";
    serialQueue.ScheduleDelayTask(DISCONNECT_DELAY_TASK, DISCONNECT_DELAY, registerEventListenerFunc);

    serialQueue.CancelDelayTask(taskName);
    EXPECT_EQ(serialQueue.taskMap_.size(), 1);
}

/**
 * @tc.number: CheckAppInstallControl
 * @tc.name: test CheckAppInstallControl by InnerBundleInfo
 * @tc.desc: 1.CheckAppInstallControl test
 */
HWTEST_F(BmsBundleCommonTest, CancelDelayTask_0400, Function | SmallTest | Level1)
{
    std::string queueName;
    SerialQueue serialQueue(queueName);
    auto registerEventListenerFunc = []() {
        return;
    };
    std::string taskName = "task";
    serialQueue.ScheduleDelayTask(DISCONNECT_DELAY_TASK, DISCONNECT_DELAY1, registerEventListenerFunc);

    serialQueue.CancelDelayTask(taskName);
    EXPECT_EQ(serialQueue.taskMap_.size(), 1);
}

/**
 * @tc.number: CheckAppInstallControl
 * @tc.name: test CheckAppInstallControl by InnerBundleInfo
 * @tc.desc: 1.CheckAppInstallControl test
 */
HWTEST_F(BmsBundleCommonTest, CancelDelayTask_0500, Function | SmallTest | Level1)
{
    std::string queueName;
    SerialQueue serialQueue(queueName);
    auto registerEventListenerFunc = []() {
        return;
    };
    std::string taskName = "task";
    uint64_t ms;
    std::function<void()> func;
    serialQueue.ScheduleDelayTask(DISCONNECT_DELAY_TASK, 1000, registerEventListenerFunc);

    serialQueue.CancelDelayTask(taskName);
    EXPECT_EQ(serialQueue.taskMap_.size(), 1);
}
} // OHOS