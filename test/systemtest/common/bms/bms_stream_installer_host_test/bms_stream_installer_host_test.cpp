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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "appexecfwk_errors.h"
#define private public
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_stream_installer_host.h"
#include "bundle_user_mgr_host.h"
#undef private

using namespace testing::ext;
using testing::_;
namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t FUNCTION_SIZE_OF_STREAM_INSTALL_HOST = 5;
const std::string TEST_FILE_NAME = "/data/test/test.hap";
} // namespace

class BundleStreamInstallerHostMock : public BundleStreamInstallerHost {
public:
    BundleStreamInstallerHostMock() = default;
    virtual ~BundleStreamInstallerHostMock() = default;

    MOCK_METHOD1(CreateStream, int32_t(const std::string &hapName));
    MOCK_METHOD2(CreateSharedBundleStream, int32_t(const std::string &hspName, uint32_t index));
    MOCK_METHOD0(Install, bool());

    uint32_t GetInstallerId() const override
    {
        return 0;
    }
    void SetInstallerId(uint32_t installerId) override {}
    void UnInit() override {}
};

class BundleUserMgrHostMock : public BundleUserMgrHost {
public:
    BundleUserMgrHostMock() = default;
    virtual ~BundleUserMgrHostMock() = default;

    MOCK_METHOD1(RemoveUser, int(int32_t userId));
    MOCK_METHOD2(CreateNewUser, int(int32_t userId, const std::vector<std::string> &disallowList));
};

class BmsStreamInstallerHostTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    sptr<BundleStreamInstallerHostMock> streamInstallerHost_ = nullptr;
    sptr<BundleUserMgrHostMock> userMgrHost_ = nullptr;
};

void BmsStreamInstallerHostTest::SetUpTestCase() {}

void BmsStreamInstallerHostTest::TearDownTestCase() {}

void BmsStreamInstallerHostTest::SetUp()
{
    streamInstallerHost_ = new (std::nothrow) BundleStreamInstallerHostMock();
    userMgrHost_ = new (std::nothrow) BundleUserMgrHostMock();
}

void BmsStreamInstallerHostTest::TearDown() {}

/**
 * @tc.number: StreamInstallerHost_001
 * @tc.name: Constructor
 * @tc.desc: Successful case of verifying Constructor.
 */
HWTEST_F(BmsStreamInstallerHostTest, StreamInstallerHost_001, TestSize.Level1)
{
    auto size = static_cast<int32_t>(streamInstallerHost_->funcMap_.size());
    EXPECT_EQ(size, FUNCTION_SIZE_OF_STREAM_INSTALL_HOST);
}

/**
 * @tc.number: StreamInstallerHost_002
 * @tc.name: OnRemoteRequest
 * @tc.desc: data is not write interface token, failed to verify OnRemoteRequest.
 */
HWTEST_F(BmsStreamInstallerHostTest, StreamInstallerHost_002, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::STREAM_INSTALL);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto result = streamInstallerHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, OBJECT_NULL);
}

/**
 * @tc.number: StreamInstallerHost_003
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.code is StreamMessage::STREAM_INSTALL.
 *           2.data is write interface token.
 *           3.Trigger the mock function to return false.
 *           4.Failed to verify the returned result.
 */
HWTEST_F(BmsStreamInstallerHostTest, StreamInstallerHost_003, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::STREAM_INSTALL);
    MessageParcel data;
    data.WriteInterfaceToken(BundleStreamInstallerHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option;

    auto func = []() -> bool { return false; };
    EXPECT_CALL(*streamInstallerHost_, Install()).Times(1).WillOnce(testing::Invoke(func));

    auto result = streamInstallerHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: StreamInstallerHost_004
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.code is StreamMessage::STREAM_INSTALL.
 *           2.data is write interface token.
 *           3.Trigger the mock function to return true.
 *           4.Verify the returned result successfully.
 */
HWTEST_F(BmsStreamInstallerHostTest, StreamInstallerHost_004, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::STREAM_INSTALL);
    MessageParcel data;
    data.WriteInterfaceToken(BundleStreamInstallerHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option;

    auto func = []() -> bool { return true; };
    EXPECT_CALL(*streamInstallerHost_, Install()).Times(1).WillOnce(testing::Invoke(func));

    auto result = streamInstallerHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: StreamInstallerHost_005
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.code is StreamMessage::CREATE_STREAM.
 *           2.data is write interface token.
 *           3.Trigger the mock function to return -1.
 *           4.Failed to verify the returned result.
 */
HWTEST_F(BmsStreamInstallerHostTest, StreamInstallerHost_005, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::CREATE_STREAM);
    MessageParcel data;
    data.WriteInterfaceToken(BundleStreamInstallerHost::GetDescriptor());
    data.WriteString(TEST_FILE_NAME);
    MessageParcel reply;
    MessageOption option;

    auto func = [](const std::string &fileName) -> int32_t { return -1; };
    EXPECT_CALL(*streamInstallerHost_, CreateStream(_)).Times(1).WillOnce(testing::Invoke(func));

    auto result = streamInstallerHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: StreamInstallerHost_006
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.Code Set non-existent code
 *           2.data is write interface token.
 *           3.Failed to verify the returned result.
 */
HWTEST_F(BmsStreamInstallerHostTest, StreamInstallerHost_006, TestSize.Level1)
{
    uint32_t code = 1024;
    MessageParcel data;
    data.WriteInterfaceToken(BundleStreamInstallerHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    auto result = streamInstallerHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.number: StreamInstallerHost_007
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.code is StreamMessage::CREATE_STREAM.
 *           2.data is write interface token.
 *           3.Failed to verify the returned result.
 */
HWTEST_F(BmsStreamInstallerHostTest, StreamInstallerHost_007, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::CREATE_STREAM);
    MessageParcel data;
    data.WriteInterfaceToken(BundleStreamInstallerHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option;

    auto result = streamInstallerHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: UserMgrHost_001
 * @tc.name: OnRemoteRequest
 * @tc.desc: data is not write interface token, failed to verify OnRemoteRequest.
 */
HWTEST_F(BmsStreamInstallerHostTest, UserMgrHost_001, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(BundleUserMgrInterfaceCode::CREATE_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto result = userMgrHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, OBJECT_NULL);
}

/**
 * @tc.number: UserMgrHost_002
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.Code Set non-existent code
 *           2.data is write interface token.
 *           3.Failed to verify the returned result.
 */
HWTEST_F(BmsStreamInstallerHostTest, UserMgrHost_002, TestSize.Level1)
{
    uint32_t code = 1024;
    MessageParcel data;
    data.WriteInterfaceToken(BundleUserMgrHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    auto result = userMgrHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.number: UserMgrHost_003
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.code is BundleUserMgrInterfaceCode::CREATE_USER.
 *           2.data is write interface token.
 *           3.Verify the returned result successfully.
 */
HWTEST_F(BmsStreamInstallerHostTest, UserMgrHost_003, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(BundleUserMgrInterfaceCode::CREATE_USER);
    MessageParcel data;
    data.WriteInterfaceToken(BundleUserMgrHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option;

    EXPECT_CALL(*userMgrHost_, CreateNewUser(_, _)).Times(1);
    auto result = userMgrHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, NO_ERROR);
}

/**
 * @tc.number: UserMgrHost_004
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.code is BundleUserMgrInterfaceCode::REMOVE_USER.
 *           2.data is write interface token.
 *           3.Verify the returned result successfully.
 */
HWTEST_F(BmsStreamInstallerHostTest, UserMgrHost_004, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(BundleUserMgrInterfaceCode::REMOVE_USER);
    MessageParcel data;
    data.WriteInterfaceToken(BundleUserMgrHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option;

    EXPECT_CALL(*userMgrHost_, RemoveUser(_)).Times(1);
    auto result = userMgrHost_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, NO_ERROR);
}
} // namespace AppExecFwk
} // namespace OHOS