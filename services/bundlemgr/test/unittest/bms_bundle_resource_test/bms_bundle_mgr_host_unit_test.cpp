/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <future>
#include <gtest/gtest.h>

#include "bundle_mgr_host.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BmsBundleMgrHostUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsBundleMgrHostUnitTest::SetUpTestCase() {}

void BmsBundleMgrHostUnitTest::TearDownTestCase() {}

void BmsBundleMgrHostUnitTest::SetUp() {}

void BmsBundleMgrHostUnitTest::TearDown() {}

/**
 * @tc.number: OnRemoteRequest_0010
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0010, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0020
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0020, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFO_WITH_INT_FLAGS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0030
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0030, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0040
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0040, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFO_WITH_INT_FLAGS_V9);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0050
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0050, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFOS_WITH_INT_FLAGS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0060
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0060, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0070
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0070, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0080
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0080, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO_WITH_INT_FLAGS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0090
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0090, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO_WITH_INT_FLAGS_V9);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0100, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::BATCH_GET_BUNDLE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0110
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0110, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_PACK_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0120
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0120, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_PACK_INFO_WITH_INT_FLAGS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0130
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0130, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0140
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0140, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_WITH_INT_FLAGS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0150
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0150, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_WITH_INT_FLAGS_V9);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0160
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0160, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_NAME_FOR_UID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0170
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0170, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLES_FOR_UID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0180
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0180, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_NAME_FOR_UID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0190
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0190, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_NAME_AND_APPINDEX_FOR_UID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0200
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0200, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_GIDS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0210
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0210, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_GIDS_BY_UID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0220
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0220, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_BY_METADATA);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0230
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0230, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0240
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0240, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_MUTI_PARAM);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0250
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0250, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0260
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0260, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_MUTI_PARAM);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0270
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0270, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_V9);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0280
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0280, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::BATCH_QUERY_ABILITY_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0290
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0290, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_LAUNCHER_ABILITY_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0300
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0300, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ALL_ABILITY_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0310
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0310, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_URI);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0320
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0320, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_BY_URI);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0330
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0330, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_URI_FOR_USERID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0340
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0340, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_KEEPALIVE_BUNDLE_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0350
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0350, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_LABEL);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0360
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0360, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_LABEL_WITH_MODULE_NAME);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0370
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0370, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::CHECK_IS_SYSTEM_APP_BY_UID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0380
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0380, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0390
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0390, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0400
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0400, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS_V9);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0410
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0410, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_HAP_MODULE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0420
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0420, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_LAUNCH_WANT_FOR_BUNDLE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0430
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0430, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PERMISSION_DEF);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0440
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0440, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::AUTO_CLEAN_CACHE_BY_SIZE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0450
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0450, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::CLEAN_BUNDLE_CACHE_FILES);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0460
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0460, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::CREATE_BUNDLE_DATA_DIR);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0470
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0470, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::CLEAN_BUNDLE_DATA_FILES);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0480
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0480, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::REGISTER_BUNDLE_STATUS_CALLBACK);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0490
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0490, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::REGISTER_BUNDLE_EVENT_CALLBACK);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0500
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0500, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::UNREGISTER_BUNDLE_EVENT_CALLBACK);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0510
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0510, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::CLEAR_BUNDLE_STATUS_CALLBACK);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0520
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0520, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::UNREGISTER_BUNDLE_STATUS_CALLBACK);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0530
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0530, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::IS_APPLICATION_ENABLED);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0540
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0540, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SET_APPLICATION_ENABLED);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0550
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0550, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::IS_ABILITY_ENABLED);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0560
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0560, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SET_ABILITY_ENABLED);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0570
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0570, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0580
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0580, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_INFO_WITH_MODULE_NAME);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0590
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0590, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::DUMP_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0600
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0600, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INSTALLER);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0610
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0610, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_FORMS_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0620
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0620, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_FORMS_INFO_BY_APP);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0630
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0630, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_FORMS_INFO_BY_MODULE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0640
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0640, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHORTCUT_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0650
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0650, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHORTCUT_INFO_V9);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0660
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0660, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_COMMON_EVENT_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0670
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0670, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_USER_MGR);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0680
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0680, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DISTRIBUTE_BUNDLE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0690
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0690, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_PRIVILEGE_LEVEL);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0700
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0700, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_WITHOUT_TYPE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0710
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0710, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_WITHOUT_TYPE_V9);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0720
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0720, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0730
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0730, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_V9);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0740
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0740, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_BY_TYPE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0750
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0750, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::VERIFY_CALLING_PERMISSION);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0760
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0760, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_BY_URI);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0770
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0770, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPID_BY_BUNDLE_NAME);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0780
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0780, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_TYPE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0790
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0790, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_UID_BY_BUNDLE_NAME);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0800
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0800, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::IS_MODULE_REMOVABLE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0810
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0810, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SET_MODULE_REMOVABLE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0820
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0820, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_WITH_CALLBACK);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0830
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0830, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::UPGRADE_ATOMIC_SERVICE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0840
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0840, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::IS_MODULE_NEED_UPDATE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0850
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0850, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SET_MODULE_NEED_UPDATE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0860
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0860, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_HAP_MODULE_INFO_WITH_USERID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0870
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0870, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::IMPLICIT_QUERY_INFO_BY_PRIORITY);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0880
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0880, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::IMPLICIT_QUERY_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0890
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0890, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_DEPENDENT_MODULE_NAMES);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0900
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0900, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_BUNDLE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0910
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0910, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_CALLING_BUNDLE_NAME);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0920
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0920, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_STATS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0930
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0930, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_BUNDLE_STATS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0940
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0940, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::CHECK_ABILITY_ENABLE_INSTALL);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0950
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0950, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_STRING_BY_ID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0960
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0960, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ICON_BY_ID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0970
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0970, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_ABILITY_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
/**
 * @tc.number: OnRemoteRequest_0980
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0980, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DEFAULT_APP_PROXY);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}
#endif

/**
 * @tc.number: OnRemoteRequest_0990
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_0990, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_EXTENSION_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1000
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1000, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_MODULE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1010
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1010, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_MEDIA_DATA);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1020
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1020, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_QUICK_FIX_MANAGER_PROXY);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
/**
 * @tc.number: OnRemoteRequest_1030
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1030, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_CONTROL_PROXY);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}
#endif

/**
 * @tc.number: OnRemoteRequest_1040
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1040, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_ABILITY_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1050
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1050, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_EXTENSION_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1060
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1060, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_MODULE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1070
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1070, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_MEDIA_DATA);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1080
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1080, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_QUICK_FIX_MANAGER_PROXY);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
/**
 * @tc.number: OnRemoteRequest_1090
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1090, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_CONTROL_PROXY);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}
#endif

/**
 * @tc.number: OnRemoteRequest_1100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1100, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SET_DEBUG_MODE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1110
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1110, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO_FOR_SELF);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1120
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1120, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::VERIFY_SYSTEM_API);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1130
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1130, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_OVERLAY_MANAGER_PROXY);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1140
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1140, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SILENT_INSTALL);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1150
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1150, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::PROCESS_PRELOAD);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1160
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1160, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BASE_SHARED_BUNDLE_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1170
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1170, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_SHARED_BUNDLE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1180
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1180, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHARED_BUNDLE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1190
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1190, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHARED_BUNDLE_INFO_BY_SELF);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1200
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1200, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHARED_DEPENDENCIES);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1210
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1210, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DEPENDENT_BUNDLE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1220
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1220, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_UID_BY_DEBUG_BUNDLE_NAME);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1230
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1230, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PROXY_DATA_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1240
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1240, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_PROXY_DATA_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1250
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1250, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SPECIFIED_DISTRIBUTED_TYPE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1260
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1260, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ADDITIONAL_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1270
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1270, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SET_EXT_NAME_OR_MIME_TO_APP);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1280
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1280, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::DEL_EXT_NAME_OR_MIME_TO_APP);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1290
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1290, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_DATA_GROUP_INFOS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1300
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1300, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PREFERENCE_DIR_BY_GROUP_ID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1310
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1310, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_APPGALLERY_BUNDLE_NAME);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1320
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1320, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_WITH_TYPE_NAME);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1330
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1330, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_ONLY_WITH_TYPE_NAME);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1340
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1340, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::RESET_AOT_COMPILE_STATUS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1350
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1350, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_JSON_PROFILE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1360
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1360, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_RESOURCE_PROXY);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1370
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1370, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_VERIFY_MANAGER);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1380
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1380, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_RECOVERABLE_APPLICATION_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1390
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1390, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_UNINSTALLED_BUNDLE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1400
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1400, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SET_ADDITIONAL_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1410
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1410, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::COMPILE_PROCESSAOT);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1420
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1420, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::COMPILE_RESET);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1430
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1430, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::CAN_OPEN_LINK);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1440
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1440, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ODID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1450
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1450, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_EXTEND_RESOURCE_MANAGER);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1460
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1460, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_BUNDLE_INFO_BY_DEVELOPER_ID);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1470
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1470, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DEVELOPER_IDS);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1480
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1480, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SWITCH_UNINSTALL_STATE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1490
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1490, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_CONTINUE_TYPE);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1500
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1500, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_CLONE_ABILITY_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1510
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1510, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_CLONE_BUNDLE_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1520
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1520, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::COPY_AP);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1530
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1530, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_CLONE_APP_INDEXES);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1540
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1540, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_CLONE_EXTENSION_ABILITY_INFO_WITH_APP_INDEX);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1550
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1550, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SET_CLONE_APPLICATION_ENABLED);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1560
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1560, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::IS_CLONE_APPLICATION_ENABLED);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1570
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1570, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::SET_CLONE_ABILITY_ENABLED);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1580
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1580, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::IS_CLONE_ABILITY_ENABLED);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1590
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1590, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::ADD_DESKTOP_SHORTCUT_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1600
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1600, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::DELETE_DESKTOP_SHORTCUT_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1610
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1610, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_DESKTOP_SHORTCUT_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1620
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1620, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_PROVISION_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1630
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1630, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PROVISION_METADATA);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1640
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleMgrHostUnitTest, OnRemoteRequest_1640, Function | SmallTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    uint32_t code = static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PREINSTALLED_APPLICATION_INFO);
    MessageParcel data;
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleMgrHost.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}
} // namespace AppExecFwk
} // namespace OHOS