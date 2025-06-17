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

#include <gtest/gtest.h>

#include "bundle_hitrace_chain.h"
namespace OHOS {
namespace AppExecFwk {
namespace HitraceTest {
using namespace testing::ext;

class TaskHiTraceChainTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void TaskHiTraceChainTest::SetUpTestCase()
{}

void TaskHiTraceChainTest::TearDownTestCase()
{}

void TaskHiTraceChainTest::SetUp()
{
    HiviewDFX::HiTraceChain::ClearId();
}

void TaskHiTraceChainTest::TearDown()
{
    HiviewDFX::HiTraceId endId = HiviewDFX::HiTraceChain::GetId();
    EXPECT_EQ(0, endId.IsValid());
}

HWTEST_F(TaskHiTraceChainTest, IntfTest_001, TestSize.Level1)
{
    auto traceId1 = HiviewDFX::HiTraceChain::Begin("Install", HITRACE_FLAG_INCLUDE_ASYNC);
    HiviewDFX::HiTraceChain::End(traceId1);
    EXPECT_EQ(0, HiviewDFX::HiTraceChain::GetId().IsValid());
    EXPECT_EQ(0, HiviewDFX::HiTraceChain::GetId().IsFlagEnabled(HITRACE_FLAG_INCLUDE_ASYNC));
    TaskHitraceChain taskTraceId(traceId1);
    EXPECT_EQ(1, HiviewDFX::HiTraceChain::GetId().IsValid());
    EXPECT_EQ(1, HiviewDFX::HiTraceChain::GetId().IsFlagEnabled(HITRACE_FLAG_INCLUDE_ASYNC));
}

HWTEST_F(TaskHiTraceChainTest, IntfTest_002, TestSize.Level1)
{
    HiviewDFX::HiTraceId  traceId1;
    TaskHitraceChain traceId2(traceId1);
    EXPECT_EQ(0, HiviewDFX::HiTraceChain::GetId().IsValid());
    EXPECT_EQ(0, HiviewDFX::HiTraceChain::GetId().IsFlagEnabled(HITRACE_FLAG_INCLUDE_ASYNC));
}
}
}
}