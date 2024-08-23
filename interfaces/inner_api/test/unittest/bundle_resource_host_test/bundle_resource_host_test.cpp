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

#include <gtest/gtest.h>
#include <vector>

#define private public
#include "bundle_resource_host.h"
#undef private
#include "bundle_resource_interface.h"
#include "iremote_stub.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class MockBundleResourceHostImpl : public BundleResourceHost {
public:
    MockBundleResourceHostImpl() = default;
    virtual ~MockBundleResourceHostImpl() = default;

    virtual ErrCode GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
        BundleResourceInfo &bundleResourceInfo, const int32_t appIndex = 0) override
        {
            return ERR_OK;
        }

    virtual ErrCode GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo, const int32_t appIndex = 0) override
        {
            return ERR_OK;
        }

    virtual ErrCode GetAllBundleResourceInfo(const uint32_t flags,
        std::vector<BundleResourceInfo> &bundleResourceInfos) override
        {
            BundleResourceInfo temp;
            bundleResourceInfos.push_back(temp);
            bundleResourceInfos.push_back(temp);
            return ERR_OK;
        }

    virtual ErrCode GetAllLauncherAbilityResourceInfo(const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos) override
        {
            LauncherAbilityResourceInfo temp;
            launcherAbilityResourceInfos.push_back(temp);
            launcherAbilityResourceInfos.push_back(temp);
            return ERR_OK;
        }
};

class BundleResourceHostTest : public testing::Test {
public:
    BundleResourceHostTest() = default;
    ~BundleResourceHostTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleResourceHostTest::SetUpTestCase()
{}

void BundleResourceHostTest::TearDownTestCase()
{
}

void BundleResourceHostTest::SetUp()
{}

void BundleResourceHostTest::TearDown()
{
}

HWTEST_F(BundleResourceHostTest, GetBundleResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetBundleResourceInfo_0100 start";
    sptr<MockBundleResourceHostImpl> stub = new MockBundleResourceHostImpl();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    BundleResourceInfo info;
    ErrCode ret = proxy->GetBundleResourceInfo("com.test.empty", 0, info, 1);
    GTEST_LOG_(INFO) << "GetBundleResourceInfo_0100 end, " << ret;
    ASSERT_EQ(ret, ERR_OK);
}

HWTEST_F(BundleResourceHostTest, GetLauncherAbilityResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetLauncherAbilityResourceInfo_0100 start";
    sptr<MockBundleResourceHostImpl> stub = new MockBundleResourceHostImpl();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::vector<LauncherAbilityResourceInfo> info;
    ErrCode ret = proxy->GetLauncherAbilityResourceInfo("com.test.empty", 0, info, 1);
    GTEST_LOG_(INFO) << "GetLauncherAbilityResourceInfo_0100 end, " << ret;
    ASSERT_EQ(ret, ERR_OK);
}

HWTEST_F(BundleResourceHostTest, GetAllBundleResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetAllBundleResourceInfo_0100 start";
    sptr<MockBundleResourceHostImpl> stub = new MockBundleResourceHostImpl();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::vector<BundleResourceInfo> info;
    ErrCode ret = proxy->GetAllBundleResourceInfo(0, info);
    GTEST_LOG_(INFO) << "GetAllBundleResourceInfo_0100 end, " << ret;
    ASSERT_EQ(ret, ERR_OK);
}

HWTEST_F(BundleResourceHostTest, GetAllLauncherAbilityResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetAllLauncherAbilityResourceInfo_0100 start";
    sptr<MockBundleResourceHostImpl> stub = new MockBundleResourceHostImpl();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::vector<LauncherAbilityResourceInfo> info;
    ErrCode ret = proxy->GetAllLauncherAbilityResourceInfo(0, info);
    GTEST_LOG_(INFO) << "GetAllLauncherAbilityResourceInfo_0100 end, " << ret;
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. descriptor and remoteDescriptor diff
 *           2. test OnRemoteRequest
 */
HWTEST_F(BundleResourceHostTest, OnRemoteRequest_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "OnRemoteRequest_0100 start";
    BundleResourceHost bundleResourceHost;
    uint32_t code = 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto ret = bundleResourceHost.OnRemoteRequest(code, data, reply, option);
    GTEST_LOG_(INFO) << "OnRemoteRequest_0100 end, " << ret;
    EXPECT_EQ(ret, OBJECT_NULL);
}

/**
 * @tc.number: OnRemoteRequest_0200
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BundleResourceHostTest, OnRemoteRequest_0200, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "OnRemoteRequest_0200 start";
    BundleResourceHost bundleResourceHost;
    uint32_t code = 100;
    MessageParcel data;
    std::u16string descriptor = BundleResourceHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    auto ret = bundleResourceHost.OnRemoteRequest(code, data, reply, option);
    GTEST_LOG_(INFO) << "OnRemoteRequest_0200 end, " << ret;
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.number: HandleGetBundleResourceInfo_0100
 * @tc.name: test the HandleGetBundleResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleResourceInfo
 */
HWTEST_F(BundleResourceHostTest, HandleGetBundleResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "HandleGetBundleResourceInfo_0100 start";
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleResourceHost.HandleGetBundleResourceInfo(data, reply);
    GTEST_LOG_(INFO) << "HandleGetBundleResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HandleGetLauncherAbilityResourceInfo_0100
 * @tc.name: test the HandleGetLauncherAbilityResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetLauncherAbilityResourceInfo
 */
HWTEST_F(BundleResourceHostTest, HandleGetLauncherAbilityResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "HandleGetLauncherAbilityResourceInfo_0100 start";
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleResourceHost.HandleGetLauncherAbilityResourceInfo(data, reply);
    GTEST_LOG_(INFO) << "HandleGetLauncherAbilityResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HandleGetAllBundleResourceInfo_0100
 * @tc.name: test the HandleGetAllBundleResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllBundleResourceInfo
 */
HWTEST_F(BundleResourceHostTest, HandleGetAllBundleResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "HandleGetAllBundleResourceInfo_0100 start";
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleResourceHost.HandleGetAllBundleResourceInfo(data, reply);
    GTEST_LOG_(INFO) << "HandleGetAllBundleResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HandleGetAllLauncherAbilityResourceInfo_0100
 * @tc.name: test the HandleGetAllLauncherAbilityResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllLauncherAbilityResourceInfo
 */
HWTEST_F(BundleResourceHostTest, HandleGetAllLauncherAbilityResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "HandleGetAllLauncherAbilityResourceInfo_0100 start";
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleResourceHost.HandleGetAllLauncherAbilityResourceInfo(data, reply);
    GTEST_LOG_(INFO) << "HandleGetAllLauncherAbilityResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HandleAddResourceInfoByBundleName_0100
 * @tc.name: test the HandleAddResourceInfoByBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleAddResourceInfoByBundleName
 */
HWTEST_F(BundleResourceHostTest, HandleAddResourceInfoByBundleName_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "HandleAddResourceInfoByBundleName_0100 start";
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleResourceHost.HandleAddResourceInfoByBundleName(data, reply);
    GTEST_LOG_(INFO) << "HandleAddResourceInfoByBundleName_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HandleAddResourceInfoByAbility_0100
 * @tc.name: test the HandleAddResourceInfoByAbility
 * @tc.desc: 1. system running normally
 *           2. test HandleAddResourceInfoByAbility
 */
HWTEST_F(BundleResourceHostTest, HandleAddResourceInfoByAbility_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "HandleAddResourceInfoByAbility_0100 start";
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleResourceHost.HandleAddResourceInfoByAbility(data, reply);
    GTEST_LOG_(INFO) << "HandleAddResourceInfoByAbility_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HandleDeleteResourceInfo_0100
 * @tc.name: test the HandleDeleteResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleDeleteResourceInfo
 */
HWTEST_F(BundleResourceHostTest, HandleDeleteResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "HandleDeleteResourceInfo_0100 start";
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleResourceHost.HandleDeleteResourceInfo(data, reply);
    GTEST_LOG_(INFO) << "HandleDeleteResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AllocatAshmemNum_0100
 * @tc.name: test the AllocatAshmemNum
 * @tc.desc: 1. system running normally
 *           2. test AllocatAshmemNum
 */
HWTEST_F(BundleResourceHostTest, AllocatAshmemNum_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "AllocatAshmemNum_0100 start";
    BundleResourceHost bundleResourceHost;
    bundleResourceHost.AllocatAshmemNum();
    GTEST_LOG_(INFO) << "AllocatAshmemNum_0100 end, ";
    EXPECT_NE(bundleResourceHost.ashmemNum_, 0);
}

/**
 * @tc.number: WriteParcelableIntoAshmem_0100
 * @tc.name: test the WriteParcelableIntoAshmem
 * @tc.desc: 1. system running normally
 *           2. test WriteParcelableIntoAshmem
 */
HWTEST_F(BundleResourceHostTest, WriteParcelableIntoAshmem_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "WriteParcelableIntoAshmem_0100 start";
    BundleResourceHost bundleResourceHost;
    MessageParcel tempParcel;
    MessageParcel reply;
    auto ret = bundleResourceHost.WriteParcelableIntoAshmem(tempParcel, reply);
    GTEST_LOG_(INFO) << "WriteParcelableIntoAshmem_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}
}
}