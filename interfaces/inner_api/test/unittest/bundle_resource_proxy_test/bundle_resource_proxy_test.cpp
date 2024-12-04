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
#define private public
#include "bundle_resource_proxy.h"
#undef private
#include "bundle_resource_interface.h"
#include "iremote_stub.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

constexpr int32_t MAX_PARCEL_CAPACITY = 100 * 1024 * 1024; // 100M

ErrCode WriteVectorToParcel(std::vector<BundleResourceInfo> &parcelVector, MessageParcel &reply)
{
    Parcel tempParcel;
    (void)tempParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    if (!tempParcel.WriteInt32(parcelVector.size())) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    for (auto &parcel : parcelVector) {
        if (!tempParcel.WriteParcelable(&parcel)) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRawData(
        reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}

class MockStub : public IRemoteStub<IBundleResource> {
public:
    MockStub() = default;
    virtual ~MockStub() = default;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        if (code == static_cast<uint32_t>(BundleResourceInterfaceCode::GET_BUNDLE_RESOURCE_INFO)) {
            GTEST_LOG_(INFO) << "OnRemoteRequest, GET_BUNDLE_RESOURCE_INFO";
            reply.WriteInt32(ERR_OK);
        
            BundleResourceInfo info;
            reply.WriteUint32(sizeof(info));
            reply.WriteRawData(&info, sizeof(info));
        } else {
            GTEST_LOG_(INFO) << "OnRemoteRequest, GET_ALL_BUNDLE_RESOURCE_INFO";
            reply.WriteInt32(ERR_OK);
        
            std::vector<BundleResourceInfo> infoVector;
            BundleResourceInfo item;
            infoVector.push_back(item);
            infoVector.push_back(item);
            infoVector.push_back(item);
            WriteVectorToParcel(infoVector, reply);
        }
        return 0;
    }
};

class BundleResourceProxyTest : public testing::Test {
public:
    BundleResourceProxyTest() = default;
    ~BundleResourceProxyTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleResourceProxyTest::SetUpTestCase()
{}

void BundleResourceProxyTest::TearDownTestCase()
{
}

void BundleResourceProxyTest::SetUp()
{}

void BundleResourceProxyTest::TearDown()
{
}

HWTEST_F(BundleResourceProxyTest, GetVectorParcelInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetVectorParcelInfo_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::vector<BundleResourceInfo> info;
    ErrCode ret = proxy->GetAllBundleResourceInfo(0, info);
    GTEST_LOG_(INFO) << "GetVectorParcelInfo_0100 end, " << ret;
    ASSERT_EQ(info.size(), 3);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityResourceInfo_0100
 * @tc.name: test the GetLauncherAbilityResourceInfo
 * @tc.desc: 1. bundleName is empty
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BundleResourceProxyTest, GetLauncherAbilityResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetLauncherAbilityResourceInfo_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::string bundleName = "";
    uint32_t flags = 1;
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    int32_t appIndex = 1;
    auto ret = proxy->GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfo, appIndex);
    GTEST_LOG_(INFO) << "GetLauncherAbilityResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: GetLauncherAbilityResourceInfo_0200
 * @tc.name: test the GetLauncherAbilityResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BundleResourceProxyTest, GetLauncherAbilityResourceInfo_0200, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetLauncherAbilityResourceInfo_0200 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::string bundleName = "bundleName";
    uint32_t flags = 1;
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    int32_t appIndex = 1;
    auto ret = proxy->GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfo, appIndex);
    GTEST_LOG_(INFO) << "GetLauncherAbilityResourceInfo_0200 end, " << ret;
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetAllBundleResourceInfo_0100
 * @tc.name: test the GetAllBundleResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test GetAllBundleResourceInfo
 */
HWTEST_F(BundleResourceProxyTest, GetAllBundleResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetAllBundleResourceInfo_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::string bundleName = "bundleName";
    uint32_t flags = 1;
    std::vector<BundleResourceInfo> bundleResourceInfos;
    auto ret = proxy->GetAllBundleResourceInfo(flags, bundleResourceInfos);
    GTEST_LOG_(INFO) << "GetAllBundleResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetAllLauncherAbilityResourceInfo_0100
 * @tc.name: test the GetAllLauncherAbilityResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test GetAllLauncherAbilityResourceInfo
 */
HWTEST_F(BundleResourceProxyTest, GetAllLauncherAbilityResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetAllLauncherAbilityResourceInfo_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::string bundleName = "bundleName";
    uint32_t flags = 1;
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    auto ret = proxy->GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfos);
    GTEST_LOG_(INFO) << "GetAllLauncherAbilityResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: AddResourceInfoByBundleName_0100
 * @tc.name: test the AddResourceInfoByBundleName
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByBundleName
 */
HWTEST_F(BundleResourceProxyTest, AddResourceInfoByBundleName_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "AddResourceInfoByBundleName_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::string bundleName = "bundleName";
    int32_t userId = 100;
    auto ret = proxy->AddResourceInfoByBundleName(bundleName, userId);
    GTEST_LOG_(INFO) << "AddResourceInfoByBundleName_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AddResourceInfoByAbility_0100
 * @tc.name: test the AddResourceInfoByAbility
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByAbility
 */
HWTEST_F(BundleResourceProxyTest, AddResourceInfoByAbility_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "AddResourceInfoByAbility_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::string bundleName = "bundleName";
    std::string moduleName = "moduleName";
    std::string abilityName = "abilityName";
    int32_t userId = 100;
    auto ret = proxy->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    GTEST_LOG_(INFO) << "AddResourceInfoByAbility_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeleteResourceInfo_0100
 * @tc.name: test the DeleteResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test DeleteResourceInfo
 */
HWTEST_F(BundleResourceProxyTest, DeleteResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "DeleteResourceInfo_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::string key = "key";
    auto ret = proxy->DeleteResourceInfo(key);
    GTEST_LOG_(INFO) << "DeleteResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetParcelInfoFromAshMem_0100
 * @tc.name: test the GetParcelInfoFromAshMem
 * @tc.desc: 1. system running normally
 *           2. test GetParcelInfoFromAshMem
 */
HWTEST_F(BundleResourceProxyTest, GetParcelInfoFromAshMem_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetParcelInfoFromAshMem_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    MessageParcel reply;
    void *buffer = nullptr;
    auto ret = proxy->GetParcelInfoFromAshMem(reply, buffer);
    GTEST_LOG_(INFO) << "GetParcelInfoFromAshMem_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: SendRequest_0100
 * @tc.name: test the SendRequest
 * @tc.desc: 1. system running normally
 *           2. test SendRequest
 */
HWTEST_F(BundleResourceProxyTest, SendRequest_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "SendRequest_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());

    BundleResourceInterfaceCode code = BundleResourceInterfaceCode::GET_BUNDLE_RESOURCE_INFO;
    MessageParcel data;
    MessageParcel reply;
    auto ret = proxy->SendRequest(code, data, reply);
    GTEST_LOG_(INFO) << "SendRequest_0100 end, " << ret;
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ClearAshmem_0100
 * @tc.name: test the ClearAshmem
 * @tc.desc: 1. system running normally
 *           2. test ClearAshmem
 */
HWTEST_F(BundleResourceProxyTest, ClearAshmem_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "ClearAshmem_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    int fd = 1;
    int32_t size = 1;
    sptr<Ashmem> ashMem = new Ashmem(fd, size);
    ashMem->flag_ = MAX_PARCEL_CAPACITY;
    ASSERT_NE(ashMem, nullptr);
    proxy->ClearAshmem(ashMem);
    GTEST_LOG_(INFO) << "ClearAshmem_0100 end";
    EXPECT_EQ(ashMem->flag_, 0);
}
}
}