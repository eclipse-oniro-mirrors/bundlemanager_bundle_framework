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
#include "distributed_manager/rpc_id_result.h"
#include "parcel.h"
#include "string_ex.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class BmsRpcIdResultTest : public testing::Test {};

SummaryAbilityInfo CreateTestSummaryAbilityInfo()
{
    SummaryAbilityInfo info;
    info.bundleName = "com.test.bundle";
    info.moduleName = "entry";
    info.abilityName = "MainAbility";
    info.logoUrl = "http://logo.url";
    info.label = "TestLabel";
    info.deviceType = {"phone", "tablet"};
    info.rpcId = {"rpc1", "rpc2"};
    return info;
}

// === SummaryAbilityInfo Parcel ===

TEST_F(BmsRpcIdResultTest, SummaryAbilityInfo_Marshalling_Unmarshalling)
{
    auto original = CreateTestSummaryAbilityInfo();
    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    SummaryAbilityInfo *restored = SummaryAbilityInfo::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->bundleName, original.bundleName);
    EXPECT_EQ(restored->moduleName, original.moduleName);
    EXPECT_EQ(restored->abilityName, original.abilityName);
    EXPECT_EQ(restored->logoUrl, original.logoUrl);
    EXPECT_EQ(restored->label, original.label);
    EXPECT_EQ(restored->deviceType, original.deviceType);
    EXPECT_EQ(restored->rpcId, original.rpcId);
    delete restored;
}

TEST_F(BmsRpcIdResultTest, SummaryAbilityInfo_Unmarshalling_EmptyParcel)
{
    Parcel parcel;
    SummaryAbilityInfo *result = SummaryAbilityInfo::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

TEST_F(BmsRpcIdResultTest, SummaryAbilityInfo_EmptyVectors)
{
    SummaryAbilityInfo info;
    info.bundleName = "com.test";
    info.moduleName = "mod";
    info.abilityName = "ability";
    Parcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    SummaryAbilityInfo *restored = SummaryAbilityInfo::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_TRUE(restored->deviceType.empty());
    EXPECT_TRUE(restored->rpcId.empty());
    delete restored;
}

// === RpcIdResult Parcel ===

TEST_F(BmsRpcIdResultTest, RpcIdResult_Marshalling_Unmarshalling)
{
    RpcIdResult original;
    original.version = "1.0";
    original.transactId = "tx123";
    original.retCode = 0;
    original.resultMsg = "success";
    original.abilityInfo = CreateTestSummaryAbilityInfo();

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    // Manually construct parcel matching ReadFromParcel format
    // (Marshalling does not write resultMsg but ReadFromParcel reads it)
    Parcel manualParcel;
    manualParcel.WriteString16(Str8ToStr16(original.version));
    manualParcel.WriteString16(Str8ToStr16(original.transactId));
    manualParcel.WriteInt32(original.retCode);
    manualParcel.WriteString16(Str8ToStr16(original.resultMsg));
    manualParcel.WriteParcelable(&original.abilityInfo);

    RpcIdResult *restored = RpcIdResult::Unmarshalling(manualParcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->version, original.version);
    EXPECT_EQ(restored->transactId, original.transactId);
    EXPECT_EQ(restored->retCode, original.retCode);
    EXPECT_EQ(restored->resultMsg, original.resultMsg);
    EXPECT_EQ(restored->abilityInfo.bundleName, original.abilityInfo.bundleName);
    delete restored;
}

TEST_F(BmsRpcIdResultTest, RpcIdResult_Unmarshalling_EmptyParcel)
{
    Parcel parcel;
    RpcIdResult *result = RpcIdResult::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}
