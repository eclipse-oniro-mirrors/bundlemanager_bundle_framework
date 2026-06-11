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
#include <gmock/gmock.h>

#define private public
#include "local_plugin_stream_installer_host.h"
#undef private

#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "iremote_stub.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {

class TestStreamInstallerHost : public LocalPluginStreamInstallerHost {
public:
    int32_t CreatePluginFileStream(const std::string &fileName) override
    {
        createFileName_ = fileName;
        return mockCreateFd_;
    }

    bool CommitLocalPluginInstall() override
    {
        commitCalled_ = true;
        return mockCommitResult_;
    }

    uint32_t GetLocalPluginInstallerId() const override
    {
        return mockInstallerId_;
    }

    void SetLocalPluginInstallerId(uint32_t installerId) override
    {
        mockInstallerId_ = installerId;
    }

    void UnInit() override
    {
        unInitCalled_ = true;
    }

    int32_t mockCreateFd_ = 0;
    bool mockCommitResult_ = true;
    uint32_t mockInstallerId_ = 42;
    mutable std::string createFileName_;
    mutable bool commitCalled_ = false;
    mutable bool unInitCalled_ = false;
};

class LocalPluginStreamInstallerHostTest : public testing::Test {
public:
    void SetUp() override
    {
        host_ = new TestStreamInstallerHost();
    }

    void TearDown() override
    {
        host_ = nullptr;
    }

protected:
    sptr<TestStreamInstallerHost> host_;
};
}

/**
 * @tc.number: Init_SetsFuncMap_001
 * @tc.name: test Init
 */
HWTEST_F(LocalPluginStreamInstallerHostTest, Init_SetsFuncMap_001, TestSize.Level1)
{
    ASSERT_NE(host_->funcMap_.size(), 0);
    EXPECT_NE(host_->funcMap_.find(
        static_cast<uint32_t>(LocalPluginStreamInstallerInterfaceCode::CREATE_PLUGIN_FILE_STREAM)),
        host_->funcMap_.end());
    EXPECT_NE(host_->funcMap_.find(
        static_cast<uint32_t>(LocalPluginStreamInstallerInterfaceCode::COMMIT_LOCAL_PLUGIN_INSTALL)),
        host_->funcMap_.end());
}

/**
 * @tc.number: OnRemoteRequest_InvalidDescriptor_002
 * @tc.name: test OnRemoteRequest
 */
HWTEST_F(LocalPluginStreamInstallerHostTest, OnRemoteRequest_InvalidDescriptor_002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"invalid.descriptor");
    int ret = host_->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, OBJECT_NULL);
}

/**
 * @tc.number: OnRemoteRequest_UnknownCode_003
 * @tc.name: test OnRemoteRequest
 */
HWTEST_F(LocalPluginStreamInstallerHostTest, OnRemoteRequest_UnknownCode_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(host_->GetDescriptor());
    int ret = host_->OnRemoteRequest(999, data, reply, option);
    EXPECT_NE(ret, ERR_OK);
}


/**
 * @tc.number: HandleCreatePluginFileStream_WriteFdFails_005
 * @tc.name: test HandleCreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostTest, HandleCreatePluginFileStream_WriteFdFails_005, TestSize.Level1)
{
    host_->mockCreateFd_ = -1;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("test.hsp");
    ErrCode ret = host_->HandleCreatePluginFileStream(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleCommitLocalPluginInstall_CommitTrue_006
 * @tc.name: test HandleCommitLocalPluginInstall
 */
HWTEST_F(LocalPluginStreamInstallerHostTest, HandleCommitLocalPluginInstall_CommitTrue_006, TestSize.Level1)
{
    host_->mockCommitResult_ = true;
    host_->commitCalled_ = false;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = host_->HandleCommitLocalPluginInstall(data, reply);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(host_->commitCalled_);
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.number: HandleCommitLocalPluginInstall_CommitFalse_007
 * @tc.name: test HandleCommitLocalPluginInstall
 */
HWTEST_F(LocalPluginStreamInstallerHostTest, HandleCommitLocalPluginInstall_CommitFalse_007, TestSize.Level1)
{
    host_->mockCommitResult_ = false;
    host_->commitCalled_ = false;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = host_->HandleCommitLocalPluginInstall(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
    EXPECT_TRUE(host_->commitCalled_);
    EXPECT_FALSE(reply.ReadBool());
}

/**
 * @tc.number: OnRemoteRequest_HandleCreatePluginFileStream_008
 * @tc.name: test OnRemoteRequest
 */
HWTEST_F(LocalPluginStreamInstallerHostTest, OnRemoteRequest_HandleCreatePluginFileStream_008, TestSize.Level1)
{
    host_->mockCreateFd_ = 7;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(host_->GetDescriptor());
    data.WriteString("plugin.hsp");
    int ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(LocalPluginStreamInstallerInterfaceCode::CREATE_PLUGIN_FILE_STREAM),
        data, reply, option);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_HandleCommitLocalPluginInstall_009
 * @tc.name: test OnRemoteRequest
 */
HWTEST_F(LocalPluginStreamInstallerHostTest, OnRemoteRequest_HandleCommitLocalPluginInstall_009, TestSize.Level1)
{
    host_->mockCommitResult_ = true;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(host_->GetDescriptor());
    int ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(LocalPluginStreamInstallerInterfaceCode::COMMIT_LOCAL_PLUGIN_INSTALL),
        data, reply, option);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}
