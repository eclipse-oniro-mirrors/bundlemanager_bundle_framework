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
#include "hilog/log.h"
namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;

class HiTraceChainTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HiTraceChainTest::SetUpTestCase()
{}

void HiTraceChainTest::TearDownTestCase()
{}

void HiTraceChainTest::SetUp()
{
    HiviewDFX::HiTraceChain::ClearId();
}

void HiTraceChainTest::TearDown()
{
    HiviewDFX::HiTraceId endId = HiviewDFX::HiTraceChain::GetId();
    EXPECT_EQ(0, endId.IsValid());
}

HWTEST_F(HiTraceChainTest, IntfTest_002, TestSize.Level1)
{
    auto traceId1= HiviewDFX::HiTraceChain::Begin("Install", HITRACE_FLAG_INCLUDE_ASYNC);
    BundleHitraceChain traceId2("Install", HITRACE_FLAG_DEFAULT);
    EXPECT_EQ(1, (HiviewDFX::HiTraceChain::GetId().GetChainId())==traceId1.GetChainId());
    EXPECT_EQ(1, HiviewDFX::HiTraceChain::GetId().IsFlagEnabled(HITRACE_FLAG_INCLUDE_ASYNC));
    EXPECT_EQ(0, HiviewDFX::HiTraceChain::GetId().IsFlagEnabled(HITRACE_FLAG_DEFAULT));
    HiviewDFX::HiTraceChain::End(traceId1);
}

HWTEST_F(HiTraceChainTest, IntfTest_003, TestSize.Level1)
{
    auto traceId1 = BundleHitraceChain("Install", HITRACE_FLAG_INCLUDE_ASYNC);
    EXPECT_EQ(1, HiviewDFX::HiTraceChain::GetId().IsValid());
    EXPECT_EQ(1, HiviewDFX::HiTraceChain::GetId().IsFlagEnabled(HITRACE_FLAG_INCLUDE_ASYNC));
}
}
}
