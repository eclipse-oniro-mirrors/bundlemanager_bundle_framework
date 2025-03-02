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
#define protected public

#include <gtest/gtest.h>
#include <vector>
#include <memory>

#define private public
#include "bundle_resource_host.h"
#undef private
#include "bundle_resource_interface.h"
#include "iremote_stub.h"
#include "ability_info.h"
#include "application_info.h"
#include "bundle_info.h"
#include "bundle_user_info.h"
#include "mime_type_mgr.h"
#include "json_serializer.h"

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
/**
 * @tc.number: ReadFromParcel_0001
 * @tc.name: ReadFromParcel_0001
 * @tc.desc: test ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, ReadFromParcel_0001, Function | SmallTest | Level1)
{
    AbilityInfo localAbilityInfo;
    Parcel parcel{};
    auto ret = localAbilityInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: Unmarshalling_0001
 * @tc.name: Unmarshalling_0001
 * @tc.desc: test Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, Unmarshalling_0001, Function | SmallTest | Level1)
{
    AbilityInfo localAbilityInfo;
    Parcel parcel{};

    auto ret = localAbilityInfo.Unmarshalling(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: Marshalling_0001
 * @tc.name: Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, Marshalling_0001, Function | SmallTest | Level1)
{
    AbilityInfo localAbilityInfo;
    Parcel parcel{};

    auto ret = localAbilityInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: Dump_0001
 * @tc.name: Dump_0001
 * @tc.desc: test Dump
 */
HWTEST_F(BundleResourceHostTest, Dump_0001, Function | SmallTest | Level1)
{
    AbilityInfo localAbilityInfo;
    std::string prefix = "localPrefix";
    int fd = -1;

    localAbilityInfo.Dump(prefix, fd);
    EXPECT_EQ(fd, -1);

    fd = 2;
    localAbilityInfo.Dump(prefix, fd);
    EXPECT_EQ(prefix, "localPrefix");
}

/**
 * @tc.number: ConvertToCompatiableAbilityInfo_0001
 * @tc.name: ConvertToCompatiableAbilityInfo_0001
 * @tc.desc: test ConvertToCompatiableAbilityInfo
 */
HWTEST_F(BundleResourceHostTest, ConvertToCompatiableAbilityInfo_0001, Function | SmallTest | Level1)
{
    AbilityInfo localAbilityInfo;
    localAbilityInfo.enabled = true;
    CompatibleAbilityInfo compatibleAbilityInfo{};

    localAbilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    EXPECT_TRUE(compatibleAbilityInfo.enabled);
}

/**
 * @tc.number: MultiAppModeData_ReadFromParcel_0001
 * @tc.name: MultiAppModeData_ReadFromParcel_0001
 * @tc.desc: test ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, MultiAppModeData_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    MultiAppModeData localMultiAppModeData;
    Parcel parcel{};

    auto ret = localMultiAppModeData.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: MultiAppModeData_Marshalling_0001
 * @tc.name: MultiAppModeData_Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, MultiAppModeData_Marshalling_0001, Function | SmallTest | Level1)
{
    MultiAppModeData localMultiAppModeData;
    Parcel parcel{};

    auto ret = localMultiAppModeData.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: MultiAppModeData_Unmarshalling_0001
 * @tc.name: MultiAppModeData_Unmarshalling_0001
 * @tc.desc: test Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, MultiAppModeData_Unmarshalling_0001, Function | SmallTest | Level1)
{
    MultiAppModeData localMultiAppModeData;
    Parcel parcel{};

    auto ret = localMultiAppModeData.Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: Metadata_ReadFromParcel_0001
 * @tc.name: Metadata_ReadFromParcel_0001
 * @tc.desc: test ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, Metadata_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    Metadata localMetadata;
    Parcel parcel{};

    auto ret = localMetadata.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: Metadata_Marshalling_0001
 * @tc.name: Metadata_Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, Metadata_Marshalling_0001, Function | SmallTest | Level1)
{
    Metadata localMetadata;
    Parcel parcel{};

    auto ret = localMetadata.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: Metadata_Unmarshalling_0001
 * @tc.name: Metadata_Unmarshalling_0001
 * @tc.desc: test Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, Metadata_Unmarshalling_0001, Function | SmallTest | Level1)
{
    Metadata localMetadata;
    Parcel parcel{};

    auto ret = localMetadata.Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: HnpPackage_ReadFromParcel_0001
 * @tc.name: HnpPackage_ReadFromParcel_0001
 * @tc.desc: test ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, HnpPackage_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    HnpPackage localHnpPackage;
    Parcel parcel{};

    auto ret = localHnpPackage.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: HnpPackage_Marshalling_0001
 * @tc.name: HnpPackage_Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, HnpPackage_Marshalling_0001, Function | SmallTest | Level1)
{
    HnpPackage localHnpPackage;
    Parcel parcel{};

    auto ret = localHnpPackage.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: HnpPackage_Unmarshalling_0001
 * @tc.name: HnpPackage_Unmarshalling_0001
 * @tc.desc: test Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, HnpPackage_Unmarshalling_0001, Function | SmallTest | Level1)
{
    HnpPackage localHnpPackage;
    Parcel parcel{};

    auto ret = localHnpPackage.Unmarshalling(parcel);
    ASSERT_NE(ret, nullptr);
}

/**
 * @tc.number: CustomizeData_ReadFromParcel_0001
 * @tc.name: CustomizeData_ReadFromParcel_0001
 * @tc.desc: test  ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, CustomizeData_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    CustomizeData localCustomizeData;
    Parcel parcel{};

    auto ret = localCustomizeData.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CustomizeData_Unmarshalling_0001
 * @tc.name: CustomizeData_Unmarshalling_0001
 * @tc.desc: test  Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, CustomizeData_Unmarshalling_0001, Function | SmallTest | Level1)
{
    CustomizeData localCustomizeData;
    Parcel parcel{};

    auto ret = localCustomizeData.Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: CustomizeData_Marshalling_0001
 * @tc.name: CustomizeData_Marshalling_0001
 * @tc.desc: test  Marshalling
 */
HWTEST_F(BundleResourceHostTest, CustomizeData_Marshalling_0001, Function | SmallTest | Level1)
{
    CustomizeData localCustomizeData;
    Parcel parcel {};

    auto ret = localCustomizeData.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: Resource_ReadFromParcel_0001
 * @tc.name: Resource_ReadFromParcel_0001
 * @tc.desc: test  ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, Resource_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    Resource localResource;
    Parcel parcel {};

    auto ret = localResource.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: Resource_Marshalling_0001
 * @tc.name: Resource_Marshalling_0001
 * @tc.desc: test  Marshalling
 */
HWTEST_F(BundleResourceHostTest, Resource_Marshalling_0001, Function | SmallTest | Level1)
{
    Resource localResource;
    Parcel parcel {};

    auto ret = localResource.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: Resource_Unmarshalling_0001
 * @tc.name: Resource_Unmarshalling_0001
 * @tc.desc: test  Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, Resource_Unmarshalling_0001, Function | SmallTest | Level1)
{
    Resource localResource;
    Parcel parcel {};

    auto ret = localResource.Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: ApplicationInfo_ReadMetaDataFromParcel_0001
 * @tc.name: ApplicationInfo_ReadMetaDataFromParcel_0001
 * @tc.desc: test  ReadMetaDataFromParcel
 */
HWTEST_F(BundleResourceHostTest, ApplicationInfo_ReadMetaDataFromParcel_0001, Function | SmallTest | Level1)
{
    ApplicationInfo localApplicationInfo;
    Parcel parcel {};

    auto ret = localApplicationInfo.ReadMetaDataFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ApplicationEnvironment_ReadFromParcel_0001
 * @tc.name: ApplicationEnvironment_ReadFromParcel_0001
 * @tc.desc: test  ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, ApplicationEnvironment_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    ApplicationEnvironment localApplicationEnvironment;
    Parcel parcel {};

    auto ret = localApplicationEnvironment.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ApplicationEnvironment_Marshalling_0001
 * @tc.name: ApplicationEnvironment_Marshalling_0001
 * @tc.desc: test  Marshalling
 */
HWTEST_F(BundleResourceHostTest, ApplicationEnvironment_Marshalling_0001, Function | SmallTest | Level1)
{
    ApplicationEnvironment localApplicationEnvironment;
    Parcel parcel {};

    auto ret = localApplicationEnvironment.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ApplicationEnvironment_Unmarshalling_0001
 * @tc.name: ApplicationEnvironment_Unmarshalling_0001
 * @tc.desc: test Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, ApplicationEnvironment_Unmarshalling_0001, Function | SmallTest | Level1)
{
    ApplicationEnvironment localApplicationEnvironment;
    Parcel parcel {};

    auto ret = localApplicationEnvironment.Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: ApplicationInfo_ReadFromParcel_0001
 * @tc.name: ApplicationInfo_ReadFromParcel_0001
 * @tc.desc: test ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, ApplicationInfo_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    ApplicationInfo localMetadata;
    Parcel parcel {};

    auto ret = localMetadata.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ApplicationInfo_Unmarshalling_0001
 * @tc.name: ApplicationInfo_Unmarshalling_0001
 * @tc.desc: test Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, ApplicationInfo_Unmarshalling_0001, Function | SmallTest | Level1)
{
    ApplicationInfo localMetadata;
    Parcel parcel {};

    auto ret = localMetadata.Unmarshalling(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: ApplicationInfo_Marshalling_0001
 * @tc.name: ApplicationInfo_Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, ApplicationInfo_Marshalling_0001, Function | SmallTest | Level1)
{
    ApplicationInfo localApplicationInfo;
    Parcel parcel {};

    auto ret = localApplicationInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ApplicationInfo_Dump_0001
 * @tc.name: ApplicationInfo_Dump_0001
 * @tc.desc: test Dump
 */
HWTEST_F(BundleResourceHostTest, ApplicationInfo_Dump_0001, Function | SmallTest | Level1)
{
    ApplicationInfo localMetadata;
    std::string prefix = "localPrefix";
    int fd = -1;

    localMetadata.Dump(prefix, fd);
    EXPECT_EQ(fd, -1);

    fd = 2;
    localMetadata.Dump(prefix, fd);
    EXPECT_EQ(prefix, "localPrefix");
}

/**
 * @tc.number: ApplicationInfo_ConvertToCompatibleApplicationInfo_0001
 * @tc.name: ApplicationInfo_ConvertToCompatibleApplicationInfo_0001
 * @tc.desc: test ConvertToCompatibleApplicationInfo
 */
HWTEST_F(BundleResourceHostTest, ApplicationInfo_ConvertToCompatibleApplicationInfo_0001, Function | SmallTest | Level1)
{
    ApplicationInfo localApplicationInfo;
    CompatibleApplicationInfo compatibleApplicationInfo {};
    localApplicationInfo.debug = true;

    localApplicationInfo.ConvertToCompatibleApplicationInfo(compatibleApplicationInfo);
    EXPECT_TRUE(compatibleApplicationInfo.debug);
}

/**
 * @tc.number: RequestPermissionUsedScene_Marshalling_0001
 * @tc.name: RequestPermissionUsedScene_Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, RequestPermissionUsedScene_Marshalling_0001, Function | SmallTest | Level1)
{
    RequestPermissionUsedScene localRequestPermissionUsedScene;
    Parcel parcel {};

    auto ret = localRequestPermissionUsedScene.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: RequestPermission_ReadFromParcel_0001
 * @tc.name: RequestPermission_ReadFromParcel_0001
 * @tc.desc: test ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, RequestPermission_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    RequestPermission localRequestPermission;
    Parcel parcel {};

    auto ret = localRequestPermission.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RequestPermission_Marshalling_0001
 * @tc.name: RequestPermission_Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, RequestPermission_Marshalling_0001, Function | SmallTest | Level1)
{
    RequestPermission localRequestPermission;
    Parcel parcel {};

    auto ret = localRequestPermission.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: RequestPermission_Unmarshalling_0001
 * @tc.name: RequestPermission_Unmarshalling_0001
 * @tc.desc: test Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, RequestPermission_Unmarshalling_0001, Function | SmallTest | Level1)
{
    RequestPermission localRequestPermission;
    Parcel parcel {};

    auto ret = localRequestPermission.Unmarshalling(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: SignatureInfo_ReadFromParcel_0001
 * @tc.name: SignatureInfo_ReadFromParcel_0001
 * @tc.desc: test ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, SignatureInfo_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    SignatureInfo localSignatureInfo;
    Parcel parcel {};

    auto ret = localSignatureInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: SignatureInfo_Marshalling_0001
 * @tc.name: SignatureInfo_Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, SignatureInfo_Marshalling_0001, Function | SmallTest | Level1)
{
    SignatureInfo localSignatureInfo;
    Parcel parcel {};

    auto ret = localSignatureInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: SignatureInfo_Unmarshalling_0001
 * @tc.name: SignatureInfo_Unmarshalling_0001
 * @tc.desc: test Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, SignatureInfo_Unmarshalling_0001, Function | SmallTest | Level1)
{
    SignatureInfo localSignatureInfo;
    Parcel parcel {};

    auto ret = localSignatureInfo.Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: BundleInfo_ReadFromParcel_0001
 * @tc.name: BundleInfo_ReadFromParcel_0001
 * @tc.desc: test ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, BundleInfo_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    BundleInfo localBundleInfo;
    Parcel parcel {};

    auto ret = localBundleInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleInfo_Marshalling_0001
 * @tc.name: BundleInfo_Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, BundleInfo_Marshalling_0001, Function | SmallTest | Level1)
{
    BundleInfo localBundleInfo;
    Parcel parcel {};

    auto ret = localBundleInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BundleInfo_Unmarshalling_0001
 * @tc.name: BundleInfo_Unmarshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, BundleInfo_Unmarshalling_0001, Function | SmallTest | Level1)
{
    BundleInfo localBundleInfo;
    Parcel parcel {};

    auto ret = localBundleInfo.Unmarshalling(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: BundleUserInfo_ReadFromParcel_0001
 * @tc.name: BundleUserInfo_ReadFromParcel_0001
 * @tc.desc: test ReadFromParcel
 */
HWTEST_F(BundleResourceHostTest, BundleUserInfo_ReadFromParcel_0001, Function | SmallTest | Level1)
{
    BundleUserInfo localBundleUserInfo;
    Parcel parcel {};

    auto ret = localBundleUserInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleUserInfo_Unmarshalling_0001
 * @tc.name: BundleUserInfo_Unmarshalling_0001
 * @tc.desc: test Unmarshalling
 */
HWTEST_F(BundleResourceHostTest, BundleUserInfo_Unmarshalling_0001, Function | SmallTest | Level1)
{
    BundleUserInfo localBundleUserInfo;
    Parcel parcel {};

    auto ret = localBundleUserInfo.Unmarshalling(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: BundleUserInfo_Marshalling_0001
 * @tc.name: BundleUserInfo_Marshalling_0001
 * @tc.desc: test Marshalling
 */
HWTEST_F(BundleResourceHostTest, BundleUserInfo_Marshalling_0001, Function | SmallTest | Level1)
{
    BundleUserInfo localBundleUserInfo;
    Parcel parcel {};

    auto ret = localBundleUserInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BundleUserInfo_Dump_0001
 * @tc.name: BundleUserInfo_Dump_0001
 * @tc.desc: test Dump
 */
HWTEST_F(BundleResourceHostTest, BundleUserInfo_Dump_0001, Function | SmallTest | Level2)
{
    BundleUserInfo localBundleUserInfo;
    std::string prefix = "loclaPrefix";
    int fd = -1;

    localBundleUserInfo.Dump(prefix, fd);
    EXPECT_EQ(fd, -1);

    fd = 2;
    localBundleUserInfo.Dump(prefix, fd);
    EXPECT_EQ(prefix, "loclaPrefix");
}

/**
 * @tc.number: BundleUserInfo_IsInitialState_0001
 * @tc.name: BundleUserInfo_IsInitialState_0001
 * @tc.desc: test IsInitialState
 */
HWTEST_F(BundleResourceHostTest, BundleUserInfo_IsInitialState_0001, Function | SmallTest | Level1)
{
    BundleUserInfo localBundleUserInfo;

    auto ret = localBundleUserInfo.IsInitialState();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: MimeTypeMgr_GetMimeTypeByUri_0001
 * @tc.name: MimeTypeMgr_GetMimeTypeByUri_0001
 * @tc.desc: test GetMimeTypeByUri
 */
HWTEST_F(BundleResourceHostTest, MimeTypeMgr_GetMimeTypeByUri_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<MimeTypeMgr> localMimeTypeMgr = std::make_shared<MimeTypeMgr>();
    ASSERT_NE(localMimeTypeMgr, nullptr);
    std::string uri = "localUri";
    std::vector<std::string> mimeTypes;

    auto ret = localMimeTypeMgr->GetMimeTypeByUri(uri, mimeTypes);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MimeTypeMgr_GetUriSuffix_0001
 * @tc.name: MimeTypeMgr_GetUriSuffix_0001
 * @tc.desc: test GetUriSuffix
 */
HWTEST_F(BundleResourceHostTest, MimeTypeMgr_GetUriSuffix_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<MimeTypeMgr> localMimeTypeMgr = std::make_shared<MimeTypeMgr>();
    ASSERT_NE(localMimeTypeMgr, nullptr);
    std::string uri = "localUri";
    std::string suffix = "localSuffix";

    auto ret = localMimeTypeMgr->GetMimeTypeByUri(uri, suffix);
    EXPECT_FALSE(ret);
}
}
}