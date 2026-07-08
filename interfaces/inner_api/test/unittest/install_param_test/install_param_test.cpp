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

#include "install_param.h"
#include "message_parcel.h"
#include "parcel.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;

namespace {
constexpr int32_t MAX_HASH = 1000;
constexpr int32_t MAX_SHARED = 500;
constexpr int32_t MAX_VERIFY = 500;
constexpr int32_t MAX_PGO = 500;
constexpr uint32_t MAX_PARAM = 1000;

void WriteParcelPrefix(Parcel &parcel)
{
    parcel.WriteInt32(0);
    parcel.WriteInt32(1);
    parcel.WriteInt32(100);
    parcel.WriteBool(false);
}

void WriteString16Pairs(Parcel &parcel, int32_t count)
{
    for (int32_t i = 0; i < count; i++) {
        std::string keyStr = "k" + std::to_string(i);
        std::u16string key(keyStr.begin(), keyStr.end());
        parcel.WriteString16(key);
        parcel.WriteString16(std::u16string(u"v"));
    }
}

void WriteString16Entries(Parcel &parcel, int32_t count)
{
    for (int32_t i = 0; i < count; i++) {
        parcel.WriteString16(std::u16string(u"e"));
    }
}
} // namespace

class InstallParamTest : public testing::Test {
public:
    InstallParamTest() = default;
    ~InstallParamTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void InstallParamTest::SetUpTestCase()
{}

void InstallParamTest::TearDownTestCase()
{}

void InstallParamTest::SetUp()
{}

void InstallParamTest::TearDown()
{}

/**
 * @tc.number: ReadFromParcel_Normal_0100
 * @tc.name: test ReadFromParcel with normal data
 * @tc.desc: Roundtrip Marshalling -> ReadFromParcel succeeds
 */
HWTEST_F(InstallParamTest, ReadFromParcel_Normal_0100, Function | SmallTest | Level0)
{
    InstallParam info;
    info.installFlag = InstallFlag::NORMAL;
    info.installLocation = InstallLocation::INTERNAL_ONLY;
    info.userId = 100;
    info.isKeepData = false;
    info.hashParams["mod1"] = "hash1";
    info.sharedBundleDirPaths.push_back("/data/app/shared");
    info.verifyCodeParams["mod1"] = "/sig/file1.sig";
    info.pgoParams["mod1"] = "/pgo/file1.ap";
    info.parameters["key1"] = "val1";

    Parcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));

    InstallParam result;
    EXPECT_TRUE(result.ReadFromParcel(parcel));
    EXPECT_EQ(result.userId, 100);
    EXPECT_EQ(result.hashParams.size(), 1u);
    EXPECT_EQ(result.sharedBundleDirPaths.size(), 1u);
    EXPECT_EQ(result.verifyCodeParams.size(), 1u);
    EXPECT_EQ(result.pgoParams.size(), 1u);
    EXPECT_EQ(result.parameters.size(), 1u);
}

/**
 * @tc.number: ReadFromParcel_HashParams_Exceed_0200
 * @tc.name: test hashParams size exceeds MAX_INSTALL_HASH_PARAMS
 * @tc.desc: hashParamSize > 1000 returns false before heap allocation
 */
HWTEST_F(InstallParamTest, ReadFromParcel_HashParams_Exceed_0200, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(1001);
    for (int i = 0; i < 2002; i++) {
        parcel.WriteInt32(0);
    }
    InstallParam info;
    EXPECT_FALSE(info.ReadFromParcel(parcel));
}

/**
 * @tc.number: ReadFromParcel_SharedPaths_Exceed_0300
 * @tc.name: test sharedBundleDirPaths size exceeds MAX_INSTALL_SHARED_PATHS
 * @tc.desc: sharedBundleDirPathsSize > 500 returns false
 */
HWTEST_F(InstallParamTest, ReadFromParcel_SharedPaths_Exceed_0300, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(0);
    parcel.WriteInt64(0);
    parcel.WriteInt32(501);
    for (int i = 0; i < 1002; i++) {
        parcel.WriteInt32(0);
    }
    InstallParam info;
    EXPECT_FALSE(info.ReadFromParcel(parcel));
}

/**
 * @tc.number: ReadFromParcel_VerifyCode_Exceed_0400
 * @tc.name: test verifyCodeParams size exceeds MAX_INSTALL_VERIFY_PARAMS
 * @tc.desc: verifyCodeParamSize > 500 returns false
 */
HWTEST_F(InstallParamTest, ReadFromParcel_VerifyCode_Exceed_0400, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(0);
    parcel.WriteInt64(0);
    parcel.WriteInt32(0);
    parcel.WriteString16(u"");
    parcel.WriteString16(u"");
    parcel.WriteBool(false);
    parcel.WriteString16(u"");
    parcel.WriteInt32(501);
    for (int i = 0; i < 1002; i++) {
        parcel.WriteInt32(0);
    }
    InstallParam info;
    EXPECT_FALSE(info.ReadFromParcel(parcel));
}

/**
 * @tc.number: ReadFromParcel_PgoParams_Exceed_0500
 * @tc.name: test pgoParams size exceeds MAX_INSTALL_PGO_PARAMS
 * @tc.desc: pgoParamsSize > 500 returns false
 */
HWTEST_F(InstallParamTest, ReadFromParcel_PgoParams_Exceed_0500, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(0);
    parcel.WriteInt64(0);
    parcel.WriteInt32(0);
    parcel.WriteString16(u"");
    parcel.WriteString16(u"");
    parcel.WriteBool(false);
    parcel.WriteString16(u"");
    parcel.WriteInt32(0);
    parcel.WriteBool(false);
    parcel.WriteInt32(501);
    for (int i = 0; i < 1002; i++) {
        parcel.WriteInt32(0);
    }
    InstallParam info;
    EXPECT_FALSE(info.ReadFromParcel(parcel));
}

/**
 * @tc.number: ReadFromParcel_Parameters_Exceed_0600
 * @tc.name: test parameters size exceeds MAX_INSTALL_PARAM_ENTRIES
 * @tc.desc: parametersSize > 1000 returns false
 */
HWTEST_F(InstallParamTest, ReadFromParcel_Parameters_Exceed_0600, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(0);
    parcel.WriteInt64(0);
    parcel.WriteInt32(0);
    parcel.WriteString16(u"");
    parcel.WriteString16(u"");
    parcel.WriteBool(false);
    parcel.WriteString16(u"");
    parcel.WriteInt32(0);
    parcel.WriteBool(false);
    parcel.WriteInt32(0);
    parcel.WriteUint32(1001);
    for (int i = 0; i < 2002; i++) {
        parcel.WriteInt32(0);
    }
    InstallParam info;
    EXPECT_FALSE(info.ReadFromParcel(parcel));
}

/**
 * @tc.number: ReadFromParcel_HashParams_AtLimit_0700
 * @tc.name: test hashParams at limit succeeds
 * @tc.desc: hashParamSize = 1000 passes the check and populates the map
 */
HWTEST_F(InstallParamTest, ReadFromParcel_HashParams_AtLimit_0700, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(MAX_HASH);
    WriteString16Pairs(parcel, MAX_HASH);
    parcel.WriteInt64(0);
    parcel.WriteInt32(0);
    parcel.WriteString16(u"");
    parcel.WriteString16(u"");
    parcel.WriteBool(false);
    parcel.WriteString16(u"");
    parcel.WriteInt32(0);
    parcel.WriteBool(false);
    parcel.WriteInt32(0);
    parcel.WriteUint32(0);
    parcel.WriteBool(false);

    InstallParam info;
    EXPECT_TRUE(info.ReadFromParcel(parcel));
    EXPECT_EQ(info.hashParams.size(), static_cast<size_t>(MAX_HASH));
}

/**
 * @tc.number: ReadFromParcel_SharedPaths_AtLimit_0800
 * @tc.name: test sharedBundleDirPaths at limit succeeds
 * @tc.desc: sharedBundleDirPathsSize = 500 passes the check
 */
HWTEST_F(InstallParamTest, ReadFromParcel_SharedPaths_AtLimit_0800, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(0);
    parcel.WriteInt64(0);
    parcel.WriteInt32(MAX_SHARED);
    WriteString16Entries(parcel, MAX_SHARED);
    parcel.WriteString16(u"");
    parcel.WriteString16(u"");
    parcel.WriteBool(false);
    parcel.WriteString16(u"");
    parcel.WriteInt32(0);
    parcel.WriteBool(false);
    parcel.WriteInt32(0);
    parcel.WriteUint32(0);
    parcel.WriteBool(false);

    InstallParam info;
    EXPECT_TRUE(info.ReadFromParcel(parcel));
    EXPECT_EQ(info.sharedBundleDirPaths.size(), static_cast<size_t>(MAX_SHARED));
}

/**
 * @tc.number: ReadFromParcel_VerifyCode_AtLimit_0900
 * @tc.name: test verifyCodeParams at limit succeeds
 * @tc.desc: verifyCodeParamSize = 500 passes the check
 */
HWTEST_F(InstallParamTest, ReadFromParcel_VerifyCode_AtLimit_0900, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(0);
    parcel.WriteInt64(0);
    parcel.WriteInt32(0);
    parcel.WriteString16(u"");
    parcel.WriteString16(u"");
    parcel.WriteBool(false);
    parcel.WriteString16(u"");
    parcel.WriteInt32(MAX_VERIFY);
    WriteString16Pairs(parcel, MAX_VERIFY);
    parcel.WriteBool(false);
    parcel.WriteInt32(0);
    parcel.WriteUint32(0);
    parcel.WriteBool(false);

    InstallParam info;
    EXPECT_TRUE(info.ReadFromParcel(parcel));
    EXPECT_EQ(info.verifyCodeParams.size(), static_cast<size_t>(MAX_VERIFY));
}

/**
 * @tc.number: ReadFromParcel_PgoParams_AtLimit_1000
 * @tc.name: test pgoParams at limit succeeds
 * @tc.desc: pgoParamsSize = 500 passes the check
 */
HWTEST_F(InstallParamTest, ReadFromParcel_PgoParams_AtLimit_1000, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(0);
    parcel.WriteInt64(0);
    parcel.WriteInt32(0);
    parcel.WriteString16(u"");
    parcel.WriteString16(u"");
    parcel.WriteBool(false);
    parcel.WriteString16(u"");
    parcel.WriteInt32(0);
    parcel.WriteBool(false);
    parcel.WriteInt32(MAX_PGO);
    WriteString16Pairs(parcel, MAX_PGO);
    parcel.WriteUint32(0);
    parcel.WriteBool(false);

    InstallParam info;
    EXPECT_TRUE(info.ReadFromParcel(parcel));
    EXPECT_EQ(info.pgoParams.size(), static_cast<size_t>(MAX_PGO));
}

/**
 * @tc.number: ReadFromParcel_Parameters_AtLimit_1100
 * @tc.name: test parameters at limit succeeds
 * @tc.desc: parametersSize = 1000 passes the check
 */
HWTEST_F(InstallParamTest, ReadFromParcel_Parameters_AtLimit_1100, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(0);
    parcel.WriteInt64(0);
    parcel.WriteInt32(0);
    parcel.WriteString16(u"");
    parcel.WriteString16(u"");
    parcel.WriteBool(false);
    parcel.WriteString16(u"");
    parcel.WriteInt32(0);
    parcel.WriteBool(false);
    parcel.WriteInt32(0);
    parcel.WriteUint32(MAX_PARAM);
    WriteString16Pairs(parcel, static_cast<int32_t>(MAX_PARAM));
    parcel.WriteBool(false);

    InstallParam info;
    EXPECT_TRUE(info.ReadFromParcel(parcel));
    EXPECT_EQ(info.parameters.size(), static_cast<size_t>(MAX_PARAM));
}

/**
 * @tc.number: ReadFromParcel_NegativeSize_1200
 * @tc.name: test negative size rejected
 * @tc.desc: Negative hashParamSize is caught (CONTAINER_SECURITY_VERIFY casts to size_t and
 *           exceeds readAbleDataSize)
 */
HWTEST_F(InstallParamTest, ReadFromParcel_NegativeSize_1200, Function | SmallTest | Level0)
{
    Parcel parcel;
    WriteParcelPrefix(parcel);
    parcel.WriteInt32(-1);
    InstallParam info;
    EXPECT_FALSE(info.ReadFromParcel(parcel));
}
