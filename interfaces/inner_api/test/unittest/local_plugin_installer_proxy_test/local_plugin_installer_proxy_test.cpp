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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>

#define private public
#include "local_plugin_installer_proxy.h"
#include "local_plugin_stream_installer_proxy.h"
#undef private

#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_constants.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "string_ex.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr uint32_t TEST_INSTALLER_ID = 42;
const std::string TEST_BUNDLE_NAME = "com.test.bundle";
const std::string TEST_PLUGIN_BUNDLE_NAME = "com.test.plugin";
const std::string TEST_PLUGIN_FILE_NAME = "plugin.hsp";
const std::string TEST_PLUGIN_FILE_PATH = "/data/test/plugin.hsp";
const std::string TEST_PLUGIN_DIR_PATH = "/data/test/plugins";
const int32_t TEST_USER_ID = 100;

struct StreamInstallerSharedState {
    bool commitResult = true;
    int32_t outputStreamFd = -1;
};
static StreamInstallerSharedState g_streamState;

class MockRemoteObject : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"ohos.appexecfwk.LocalPluginInstaller") {}
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        sendRequestCalled_ = true;
        lastCode_ = code;
        if (shouldFail_) {
            return -1;
        }

        if (code == static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::CREATE_LOCAL_PLUGIN_STREAM_INSTALLER)) {
            reply.WriteBool(createStreamSuccess_);
            if (createStreamSuccess_) {
                reply.WriteUint32(TEST_INSTALLER_ID);
                if (outputRemoteObject_ != nullptr) {
                    reply.WriteRemoteObject(outputRemoteObject_);
                } else {
                    sptr<MockRemoteObject> streamObj(new MockRemoteObject());
                    streamObj->SetStreamInstallerMode(true);
                    reply.WriteRemoteObject(streamObj);
                }
            }
            return ERR_NONE;
        }
        if (code == static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::DESTROY_LOCAL_PLUGIN_STREAM_INSTALLER)) {
            reply.WriteBool(destroyResult_);
            return ERR_NONE;
        }
        if (code == static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::UNINSTALL) ||
            code == static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::INTERNAL_UNINSTALL)) {
            reply.WriteInt32(replyErrCode_);
            return ERR_NONE;
        }

        if (streamInstallerMode_) {
            if (code == static_cast<uint32_t>(LocalPluginStreamInstallerInterfaceCode::CREATE_PLUGIN_FILE_STREAM)) {
                if (g_streamState.outputStreamFd >= 0) {
                    reply.WriteFileDescriptor(g_streamState.outputStreamFd);
                }
                return ERR_NONE;
            }
            if (code == static_cast<uint32_t>(LocalPluginStreamInstallerInterfaceCode::COMMIT_LOCAL_PLUGIN_INSTALL)) {
                reply.WriteBool(g_streamState.commitResult);
                return ERR_NONE;
            }
        }

        return ERR_NONE;
    }

    void SetStreamInstallerMode(bool mode)
    {
        streamInstallerMode_ = mode;
    }

    sptr<IRemoteBroker> AsInterface() override { return nullptr; }
    int32_t GetObjectRefCount() override { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }

    bool sendRequestCalled_ = false;
    uint32_t lastCode_ = 0;
    bool shouldFail_ = false;
    bool createStreamSuccess_ = true;
    bool destroyResult_ = true;
    int32_t replyErrCode_ = ERR_OK;
    bool streamInstallerMode_ = false;
    sptr<IRemoteObject> outputRemoteObject_;
};

class MockStatusReceiver : public IStatusReceiver {
public:
    MockStatusReceiver() = default;
    ~MockStatusReceiver() override = default;
    
    MOCK_METHOD(void, OnStatusNotify, (const int32_t progress), (override));
    MOCK_METHOD(void, OnFinished, (const int32_t resultCode, const std::string &resultMsg), (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
    MOCK_METHOD(void, SetStreamInstallId, (uint32_t installerId), (override));
};

class LocalPluginInstallerProxyTest : public testing::Test {
public:
    void SetUp() override
    {
        g_streamState = StreamInstallerSharedState();
        mockRemote_ = new MockRemoteObject();
        proxy_ = std::make_shared<LocalPluginInstallerProxy>(mockRemote_);

        char templateDir[] = "/data/local/tmp/bms_ut_XXXXXX";
        char *dirResult = mkdtemp(templateDir);
        if (dirResult != nullptr) {
            tempDir_ = dirResult;
            tempDir_ += "/";
        }
    }

    void TearDown() override
    {
        proxy_.reset();
        mockRemote_ = nullptr;
        g_streamState = StreamInstallerSharedState();
        if (!tempDir_.empty()) {
            std::filesystem::remove_all(tempDir_);
        }
    }

protected:
    sptr<MockRemoteObject> mockRemote_;
    std::shared_ptr<LocalPluginInstallerProxy> proxy_;
    std::string tempDir_;
};

/**
 * @tc.number: Install_0010
 * @tc.name: test LocalPluginInstallerProxy::Install
*/
HWTEST_F(LocalPluginInstallerProxyTest, Install_0010, TestSize.Level1)
{
    sptr<IStatusReceiver> nullReceiver = nullptr;
    std::vector<std::string> paths = {TEST_PLUGIN_FILE_PATH};
    ErrCode ret = proxy_->Install(paths, nullReceiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
    EXPECT_FALSE(mockRemote_->sendRequestCalled_);
}

/**
 * @tc.number: Install_0020
 * @tc.name: test LocalPluginInstallerProxy::Install
*/
HWTEST_F(LocalPluginInstallerProxyTest, Install_0020, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    std::vector<std::string> emptyPaths;
    ErrCode ret = proxy_->Install(emptyPaths, receiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: Install_0030
 * @tc.name: test LocalPluginInstallerProxy::Install
*/
HWTEST_F(LocalPluginInstallerProxyTest, Install_0030, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    std::vector<std::string> paths = {"/data/test/plugin.txt"};
    ErrCode ret = proxy_->Install(paths, receiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: Install_0040
 * @tc.name: test LocalPluginInstallerProxy::Install
*/
HWTEST_F(LocalPluginInstallerProxyTest, Install_0040, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    std::vector<std::string> paths = {"/data/test/nonexistent.hsp"};
    ErrCode ret = proxy_->Install(paths, receiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: DestroyStreamInstaller_0010
 * @tc.name: test LocalPluginInstallerProxy::DestroyLocalPluginStreamInstaller
*/
HWTEST_F(LocalPluginInstallerProxyTest, DestroyStreamInstaller_0010, TestSize.Level1)
{
    bool ret = proxy_->DestroyLocalPluginStreamInstaller(TEST_INSTALLER_ID);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(mockRemote_->sendRequestCalled_);
    EXPECT_EQ(mockRemote_->lastCode_,
        static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::DESTROY_LOCAL_PLUGIN_STREAM_INSTALLER));
}

/**
 * @tc.number: DestroyStreamInstaller_0020
 * @tc.name: test LocalPluginInstallerProxy::DestroyLocalPluginStreamInstaller
*/
HWTEST_F(LocalPluginInstallerProxyTest, DestroyStreamInstaller_0020, TestSize.Level1)
{
    mockRemote_->shouldFail_ = true;
    bool ret = proxy_->DestroyLocalPluginStreamInstaller(TEST_INSTALLER_ID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DestroyStreamInstaller_0030
 * @tc.name: test LocalPluginInstallerProxy::DestroyLocalPluginStreamInstaller
*/
HWTEST_F(LocalPluginInstallerProxyTest, DestroyStreamInstaller_0030, TestSize.Level1)
{
    mockRemote_->destroyResult_ = false;
    bool ret = proxy_->DestroyLocalPluginStreamInstaller(TEST_INSTALLER_ID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: Uninstall_0010
 * @tc.name: test LocalPluginInstallerProxy::Uninstall
*/
HWTEST_F(LocalPluginInstallerProxyTest, Uninstall_0010, TestSize.Level1)
{
    sptr<IStatusReceiver> nullReceiver = nullptr;
    ErrCode ret = proxy_->Uninstall(TEST_PLUGIN_BUNDLE_NAME, nullReceiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: Uninstall_0020
 * @tc.name: test LocalPluginInstallerProxy::Uninstall
*/
HWTEST_F(LocalPluginInstallerProxyTest, Uninstall_0020, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    mockRemote_->shouldFail_ = true;
    EXPECT_CALL(*receiver, AsObject()).WillOnce(testing::Return(nullptr));
    ErrCode ret = proxy_->Uninstall(TEST_PLUGIN_BUNDLE_NAME, receiver);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: Uninstall_0030
 * @tc.name: test LocalPluginInstallerProxy::Uninstall
*/
HWTEST_F(LocalPluginInstallerProxyTest, Uninstall_0030, TestSize.Level1)
{
    mockRemote_->shouldFail_ = true;
    ErrCode ret = proxy_->Uninstall(TEST_BUNDLE_NAME, TEST_PLUGIN_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: Uninstall_0040
 * @tc.name: test LocalPluginInstallerProxy::Uninstall
*/
HWTEST_F(LocalPluginInstallerProxyTest, Uninstall_0040, TestSize.Level1)
{
    ErrCode ret = proxy_->Uninstall(TEST_BUNDLE_NAME, TEST_PLUGIN_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(mockRemote_->sendRequestCalled_);
    EXPECT_EQ(mockRemote_->lastCode_,
        static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::INTERNAL_UNINSTALL));
}

/**
 * @tc.number: Uninstall_0050
 * @tc.name: test LocalPluginInstallerProxy::Uninstall
*/
HWTEST_F(LocalPluginInstallerProxyTest, Uninstall_0050, TestSize.Level1)
{
    mockRemote_->replyErrCode_ = ERR_APPEXECFWK_PERMISSION_DENIED;
    ErrCode ret = proxy_->Uninstall(TEST_BUNDLE_NAME, TEST_PLUGIN_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: WriteFileToStream_0010
 * @tc.name: test LocalPluginInstallerProxy::WriteFileToLocalPluginStream
*/
HWTEST_F(LocalPluginInstallerProxyTest, WriteFileToStream_0010, TestSize.Level1)
{
    ErrCode ret = proxy_->WriteFileToLocalPluginStream(nullptr, TEST_PLUGIN_FILE_PATH);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
}

class LocalPluginStreamInstallerProxyTest : public testing::Test {
public:
    void SetUp() override
    {
        g_streamState = StreamInstallerSharedState();
        mockRemote_ = new MockRemoteObject();
        mockRemote_->SetStreamInstallerMode(true);
        realFd_ = open("/dev/null", O_RDONLY);
        if (realFd_ >= 0) {
            g_streamState.outputStreamFd = realFd_;
        }
        proxy_ = std::make_shared<LocalPluginStreamInstallerProxy>(mockRemote_);
    }
    void TearDown() override
    {
        proxy_.reset();
        mockRemote_ = nullptr;
        if (realFd_ >= 0) {
            close(realFd_);
            realFd_ = -1;
        }
        g_streamState = StreamInstallerSharedState();
    }

protected:
    sptr<MockRemoteObject> mockRemote_;
    std::shared_ptr<LocalPluginStreamInstallerProxy> proxy_;
    int32_t realFd_ = -1;
};

/**
 * @tc.number: CreatePluginFileStream_0010
 * @tc.name: test LocalPluginStreamInstallerProxy::CreatePluginFileStream
*/
HWTEST_F(LocalPluginStreamInstallerProxyTest, CreatePluginFileStream_0010, TestSize.Level1)
{
    int32_t fd = proxy_->CreatePluginFileStream("");
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreatePluginFileStream_0020
 * @tc.name: test LocalPluginStreamInstallerProxy::CreatePluginFileStream
*/
HWTEST_F(LocalPluginStreamInstallerProxyTest, CreatePluginFileStream_0020, TestSize.Level1)
{
    mockRemote_->shouldFail_ = true;
    int32_t fd = proxy_->CreatePluginFileStream("test.hsp");
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreatePluginFileStream_0030
 * @tc.name: test LocalPluginStreamInstallerProxy::CreatePluginFileStream
*/
HWTEST_F(LocalPluginStreamInstallerProxyTest, CreatePluginFileStream_0030, TestSize.Level1)
{
    g_streamState.outputStreamFd = -1;
    int32_t fd = proxy_->CreatePluginFileStream("test.hsp");
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreatePluginFileStream_0040
 * @tc.name: test LocalPluginStreamInstallerProxy::CreatePluginFileStream
*/
HWTEST_F(LocalPluginStreamInstallerProxyTest, CreatePluginFileStream_0040, TestSize.Level1)
{
    mockRemote_->shouldFail_ = true;
    mockRemote_->sendRequestCalled_ = false;
    int32_t fd = proxy_->CreatePluginFileStream("test.hsp");
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CommitLocalPluginInstall_0010
 * @tc.name: test LocalPluginStreamInstallerProxy::CommitLocalPluginInstall
*/
HWTEST_F(LocalPluginStreamInstallerProxyTest, CommitLocalPluginInstall_0010, TestSize.Level1)
{
    mockRemote_->shouldFail_ = true;
    bool ret = proxy_->CommitLocalPluginInstall();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CommitLocalPluginInstall_0020
 * @tc.name: test LocalPluginStreamInstallerProxy::CommitLocalPluginInstall
*/
HWTEST_F(LocalPluginStreamInstallerProxyTest, CommitLocalPluginInstall_0020, TestSize.Level1)
{
    bool ret = proxy_->CommitLocalPluginInstall();
    EXPECT_TRUE(ret);
    EXPECT_TRUE(mockRemote_->sendRequestCalled_);
}

/**
 * @tc.number: GetSetInstallerId_0010
 * @tc.name: test LocalPluginStreamInstallerProxy::GetLocalPluginInstallerId
*/
HWTEST_F(LocalPluginStreamInstallerProxyTest, GetSetInstallerId_0010, TestSize.Level1)
{
    EXPECT_EQ(proxy_->GetLocalPluginInstallerId(), Constants::DEFAULT_INSTALLERID);
    proxy_->SetLocalPluginInstallerId(TEST_INSTALLER_ID);
    EXPECT_EQ(proxy_->GetLocalPluginInstallerId(), TEST_INSTALLER_ID);
}
}
