/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

namespace {
constexpr int32_t MAX_PARCEL_CAPACITY = 100 * 1024 * 1024; // 100M
const std::string TEST_EMPTY_STRING = "";
const std::string TEST_STRING = "test.string";
const int32_t TEST_INVALID_INDEX = -1;
const int32_t TEST_ERROR_INDEX = 10;
const int32_t TEST_ZERO_INDEX = 0;
const uint32_t TEST_FLAGS = 1;
} // namespace

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
 * @tc.number: SendRequest_0200
 * @tc.name: test the SendRequest
 * @tc.desc: 1. system running normally
 *           2. test SendRequest
 */
HWTEST_F(BundleResourceProxyTest, SendRequest_0200, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "SendRequest_0200 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());

    BundleResourceInterfaceCode code = BundleResourceInterfaceCode::GET_ALL_UNINSTALL_BUNDLE_RESOURCE_INFO;
    MessageParcel data;
    MessageParcel reply;
    auto ret = proxy->SendRequest(code, data, reply);
    GTEST_LOG_(INFO) << "SendRequest_0200 end, " << ret;
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetExtensionAbilityResourceInfo_0100
 * @tc.name: test the GetExtensionAbilityResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test GetExtensionAbilityResourceInfo
 */
HWTEST_F(BundleResourceProxyTest, GetExtensionAbilityResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetExtensionAbilityResourceInfo_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::string bundleName = "bundleName";
    ExtensionAbilityType extensionAbilityType = ExtensionAbilityType::INPUTMETHOD;
    uint32_t flags = 1;
    std::vector<LauncherAbilityResourceInfo> extensionAbilityResourceInfo;
    int32_t appIndex = 0;
    auto ret = proxy->GetExtensionAbilityResourceInfo(bundleName, extensionAbilityType, flags,
        extensionAbilityResourceInfo, appIndex);
    GTEST_LOG_(INFO) << "GetExtensionAbilityResourceInfo_0100 end, " << ret;
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetAllUninstallBundleResourceInfo_0100
 * @tc.name: test the GetAllUninstallBundleResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test GetAllUninstallBundleResourceInfo
 */
HWTEST_F(BundleResourceProxyTest, GetAllUninstallBundleResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetAllUninstallBundleResourceInfo_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::vector<BundleResourceInfo> bundleResourceInfos;
    auto ret = proxy->GetAllUninstallBundleResourceInfo(100, 1, bundleResourceInfos);
    GTEST_LOG_(INFO) << "GetAllUninstallBundleResourceInfo end, " << ret;
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckBundleOptionInfoInvalid_0100
 * @tc.name: test CheckBundleOptionInfoInvalid
 * @tc.desc: test CheckBundleOptionInfoInvalid of BundleResourceProxy
 */
HWTEST_F(BundleResourceProxyTest, CheckBundleOptionInfoInvalid_0100, Function | SmallTest | Level0)
{
    sptr<MockStub> stub = new MockStub();
    ASSERT_NE(stub, nullptr);
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    ASSERT_NE(proxy, nullptr);
    std::vector<BundleOptionInfo> optionsList;
    BundleOptionInfo bundleOptionInfo;
    bundleOptionInfo.bundleName = TEST_EMPTY_STRING;
    optionsList.emplace_back(bundleOptionInfo);
    auto ret = proxy->CheckBundleOptionInfoInvalid(optionsList);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    optionsList.clear();
    bundleOptionInfo.bundleName = TEST_STRING;
    bundleOptionInfo.moduleName = TEST_EMPTY_STRING;
    optionsList.emplace_back(bundleOptionInfo);
    ret = proxy->CheckBundleOptionInfoInvalid(optionsList);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    optionsList.clear();
    bundleOptionInfo.bundleName = TEST_STRING;
    bundleOptionInfo.moduleName = TEST_STRING;
    bundleOptionInfo.abilityName = TEST_EMPTY_STRING;
    optionsList.emplace_back(bundleOptionInfo);
    ret = proxy->CheckBundleOptionInfoInvalid(optionsList);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: CheckBundleOptionInfoInvalid_0200
 * @tc.name: test CheckBundleOptionInfoInvalid
 * @tc.desc: test CheckBundleOptionInfoInvalid of BundleResourceProxy
 */
HWTEST_F(BundleResourceProxyTest, CheckBundleOptionInfoInvalid_0200, Function | SmallTest | Level0)
{
    sptr<MockStub> stub = new MockStub();
    ASSERT_NE(stub, nullptr);
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    ASSERT_NE(proxy, nullptr);
    std::vector<BundleOptionInfo> optionsList;
    BundleOptionInfo bundleOptionInfo;
    bundleOptionInfo.bundleName = TEST_STRING;
    bundleOptionInfo.moduleName = TEST_STRING;
    bundleOptionInfo.abilityName = TEST_STRING;
    bundleOptionInfo.appIndex = TEST_INVALID_INDEX;
    optionsList.emplace_back(bundleOptionInfo);
    auto ret = proxy->CheckBundleOptionInfoInvalid(optionsList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);

    optionsList.clear();
    bundleOptionInfo.bundleName = TEST_STRING;
    bundleOptionInfo.moduleName = TEST_STRING;
    bundleOptionInfo.abilityName = TEST_STRING;
    bundleOptionInfo.appIndex = TEST_ERROR_INDEX;
    optionsList.emplace_back(bundleOptionInfo);
    ret = proxy->CheckBundleOptionInfoInvalid(optionsList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);

    optionsList.clear();
    bundleOptionInfo.bundleName = TEST_STRING;
    bundleOptionInfo.moduleName = TEST_STRING;
    bundleOptionInfo.abilityName = TEST_STRING;
    bundleOptionInfo.appIndex = TEST_ZERO_INDEX;
    optionsList.emplace_back(bundleOptionInfo);
    ret = proxy->CheckBundleOptionInfoInvalid(optionsList);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityResourceInfoList_0100
 * @tc.name: test GetLauncherAbilityResourceInfoList
 * @tc.desc: test GetLauncherAbilityResourceInfoList of BundleResourceProxy
 */
HWTEST_F(BundleResourceProxyTest, GetLauncherAbilityResourceInfoList_0100, Function | SmallTest | Level0)
{
    sptr<MockStub> stub = new MockStub();
    ASSERT_NE(stub, nullptr);
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    ASSERT_NE(proxy, nullptr);
    std::vector<BundleOptionInfo> optionsList;
    BundleOptionInfo bundleOptionInfo;
    bundleOptionInfo.bundleName = TEST_EMPTY_STRING;
    optionsList.emplace_back(bundleOptionInfo);
    uint32_t flags = TEST_FLAGS;
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    auto ret = proxy->GetLauncherAbilityResourceInfoList(optionsList, flags, launcherAbilityResourceInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);

    optionsList.clear();
    bundleOptionInfo.bundleName = TEST_STRING;
    bundleOptionInfo.moduleName = TEST_STRING;
    bundleOptionInfo.abilityName = TEST_STRING;
    bundleOptionInfo.appIndex = TEST_ZERO_INDEX;
    optionsList.emplace_back(bundleOptionInfo);
    ret = proxy->GetLauncherAbilityResourceInfoList(optionsList, flags, launcherAbilityResourceInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}
}

namespace AppExecFwk {
namespace {
constexpr int COMPLETE_REPLY_FIELD_COUNT = 2;
}
class ThemeTimestampReplyStub : public IRemoteStub<IBundleResource> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        EXPECT_EQ(code, static_cast<uint32_t>(BundleResourceInterfaceCode::GET_THEME_TIMESTAMP));
        EXPECT_EQ(data.ReadInterfaceToken(), IBundleResource::GetDescriptor());
        EXPECT_EQ(data.ReadInt32(), userId_);
        if (transportResult_ != ERR_OK || fields_ == 0) {
            return transportResult_;
        }
        reply.WriteInt32(result_);
        if (fields_ >= COMPLETE_REPLY_FIELD_COUNT) {
            if (truncateTimestamp_) {
                reply.WriteInt32(INT32_MAX);
            } else {
                reply.WriteInt64(timestamp_);
            }
        }
        return ERR_OK;
    }

    int32_t userId_ = Constants::START_USERID;
    int fields_ = COMPLETE_REPLY_FIELD_COUNT;
    ErrCode result_ = ERR_OK;
    ErrCode transportResult_ = ERR_OK;
    bool truncateTimestamp_ = false;
    int64_t timestamp_ = 1794614400123LL;
};

HWTEST_F(BundleResourceProxyTest, ThemeTimestamp_ValidAndNoRecord, TestSize.Level1)
{
    sptr<ThemeTimestampReplyStub> stub = new ThemeTimestampReplyStub();
    BundleResourceProxy proxy(stub->AsObject());
    const int64_t timestamps[] = {0, 2147483648LL, 1794614400123LL, 9223372036854775807LL, -1};
    for (const auto &value : timestamps) {
        stub->timestamp_ = value;
        int64_t timestamp = 1234;
        ASSERT_EQ(proxy.GetThemeTimestamp(Constants::START_USERID, timestamp), ERR_OK);
        EXPECT_EQ(timestamp, value);
    }
}

HWTEST_F(BundleResourceProxyTest, ThemeTimestamp_ForwardsUserId, TestSize.Level1)
{
    sptr<ThemeTimestampReplyStub> stub = new ThemeTimestampReplyStub();
    BundleResourceProxy proxy(stub->AsObject());
    const int32_t userIds[] = {Constants::START_USERID, Constants::START_USERID + 1};
    for (const int32_t userId : userIds) {
        stub->userId_ = userId;
        int64_t timestamp = -1;
        EXPECT_EQ(proxy.GetThemeTimestamp(userId, timestamp), ERR_OK);
    }
}

HWTEST_F(BundleResourceProxyTest, ThemeTimestamp_PermissionErrors, TestSize.Level1)
{
    sptr<ThemeTimestampReplyStub> stub = new ThemeTimestampReplyStub();
    BundleResourceProxy proxy(stub->AsObject());
    const ErrCode errors[] = {ERR_BUNDLE_MANAGER_PERMISSION_DENIED, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED};
    for (const auto error : errors) {
        stub->result_ = error;
        int64_t timestamp = 1234;
        EXPECT_EQ(proxy.GetThemeTimestamp(Constants::START_USERID, timestamp), error);
        EXPECT_EQ(timestamp, -1);
    }
}

HWTEST_F(BundleResourceProxyTest, ThemeTimestamp_IncompleteReply, TestSize.Level1)
{
    sptr<ThemeTimestampReplyStub> stub = new ThemeTimestampReplyStub();
    BundleResourceProxy proxy(stub->AsObject());
    for (int fields = 0; fields < COMPLETE_REPLY_FIELD_COUNT; ++fields) {
        stub->fields_ = fields;
        int64_t timestamp = 1234;
        EXPECT_EQ(proxy.GetThemeTimestamp(Constants::START_USERID, timestamp), ERR_APPEXECFWK_PARCEL_ERROR);
        EXPECT_EQ(timestamp, -1);
    }
}

HWTEST_F(BundleResourceProxyTest, ThemeTimestamp_TruncatedInt64, TestSize.Level1)
{
    sptr<ThemeTimestampReplyStub> stub = new ThemeTimestampReplyStub();
    stub->truncateTimestamp_ = true;
    BundleResourceProxy proxy(stub->AsObject());
    int64_t timestamp = 1234;
    EXPECT_EQ(proxy.GetThemeTimestamp(Constants::START_USERID, timestamp), ERR_APPEXECFWK_PARCEL_ERROR);
    EXPECT_EQ(timestamp, -1);
}

HWTEST_F(BundleResourceProxyTest, ThemeTimestamp_TransportError, TestSize.Level1)
{
    sptr<ThemeTimestampReplyStub> stub = new ThemeTimestampReplyStub();
    stub->transportResult_ = ERR_INVALID_OPERATION;
    BundleResourceProxy proxy(stub->AsObject());
    int64_t timestamp = 1234;
    EXPECT_EQ(proxy.GetThemeTimestamp(Constants::START_USERID, timestamp), ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(timestamp, -1);
}

} // namespace AppExecFwk

}