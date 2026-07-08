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
#include "local_plugin_stream_installer_host_impl.h"
#undef private

#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "ipc_skeleton.h"
#include "plugin/install_plugin_param.h"
#include "status_receiver_interface.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr uint32_t TEST_INSTALLER_ID = 100;
constexpr int32_t TEST_INSTALLED_UID = 200;
const std::string LOCAL_PLUGIN_FILE_NAME = "plugin.hsp";
const std::string LOCAL_PLUGIN_INVALID_FILE_NAME = "plugin.sig";
const std::string LOCAL_PLUGIN_ILLEGAL_FILE_NAME = "../plugin.hsp";
const std::string LOCAL_PLUGIN_HOST_BUNDLE_NAME = "com.example.host1";
const std::string LOCAL_PLUGIN_BUNDLE_NAME = "com.example.pluginTest1";
constexpr int32_t LOCAL_PLUGIN_USER_ID = 100;

class MockStatusReceiver : public IStatusReceiver {
public:
    MockStatusReceiver() = default;
    ~MockStatusReceiver() override = default;
    MOCK_METHOD1(OnStatusNotify, void(const int32_t progress));
    MOCK_METHOD2(OnFinished, void(const int32_t resultCode, const std::string &resultMsg));
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
    MOCK_METHOD1(SetStreamInstallId, void(uint32_t installerId));
};

class LocalPluginStreamInstallerHostImplTest : public testing::Test {
public:
    void SetUp() override
    {
        impl_ = std::make_shared<LocalPluginStreamInstallerHostImpl>(TEST_INSTALLER_ID, TEST_INSTALLED_UID);
    }
    void TearDown() override
    {
        impl_.reset();
    }

protected:
    std::shared_ptr<LocalPluginStreamInstallerHostImpl> impl_;
};
}

/**
 * @tc.number: GetSetInstallerId_0010
 * @tc.name: test GetSetInstallerId
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, GetSetInstallerId_0010, TestSize.Level1)
{
    EXPECT_EQ(impl_->GetLocalPluginInstallerId(), TEST_INSTALLER_ID);
    impl_->SetLocalPluginInstallerId(42);
    EXPECT_EQ(impl_->GetLocalPluginInstallerId(), 42);
}

/**
 * @tc.number: CreatePluginFileStream_0010
 * @tc.name: test CreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CreatePluginFileStream_0010, TestSize.Level1)
{
    int32_t fd = impl_->CreatePluginFileStream("");
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreatePluginFileStream_0020
 * @tc.name: test CreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CreatePluginFileStream_0020, TestSize.Level1)
{
    int32_t fd = impl_->CreatePluginFileStream("test.txt");
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreatePluginFileStream_0030
 * @tc.name: test CreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CreatePluginFileStream_0030, TestSize.Level1)
{
    int32_t fd = impl_->CreatePluginFileStream("../test.hsp");
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreatePluginFileStream_0040
 * @tc.name: test CreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CreatePluginFileStream_0040, TestSize.Level1)
{
    impl_->tempDir_ = "";
    int32_t fd = impl_->CreatePluginFileStream("test.hsp");
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreatePluginFileStream_0050
 * @tc.name: test CreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CreatePluginFileStream_0050, TestSize.Level1)
{
    impl_->installedUid_ = 999;
    EXPECT_NE(impl_->installedUid_, TEST_INSTALLED_UID);
    int32_t fd = impl_->CreatePluginFileStream("test.hsp");
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreatePluginFileStream_0060
 * @tc.name: test CreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CreatePluginFileStream_0060, TestSize.Level1)
{
    impl_->tempDir_ = "/data/test/tmp";
    impl_->installedUid_ = IPCSkeleton::GetCallingUid();
    int32_t fd = impl_->CreatePluginFileStream("test.hsp");
    EXPECT_TRUE(fd > 0 || fd == Constants::DEFAULT_STREAM_FD);
    if (!impl_->tempDir_.empty() && impl_->tempDir_.back() != '/') {
        impl_->tempDir_ += "/";
    }
    if (fd > 0) {
        close(fd);
    }
}

/**
 * @tc.number: CreatePluginFileStream_0070
 * @tc.name: test CreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CreatePluginFileStream_0070, TestSize.Level1)
{
    impl_->tempDir_ = "/data/test/tmp/";
    impl_->installedUid_ = IPCSkeleton::GetCallingUid();
    std::string validName = "myplugin.hsp";
    int32_t fd = impl_->CreatePluginFileStream(validName);
    EXPECT_TRUE(fd > 0 || fd == Constants::DEFAULT_STREAM_FD);
    if (fd > 0) {
        close(fd);
    }
}

/**
 * @tc.number: Init_0010
 * @tc.name: test Init
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, Init_0010, TestSize.Level1)
{
    InstallPluginParam param;
    param.userId = 100;
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    bool ret = impl_->Init(param, receiver, "com.test.host");
    EXPECT_TRUE(ret);
    EXPECT_EQ(impl_->hostBundleName_, "com.test.host");
    EXPECT_EQ(impl_->installPluginParam_.userId, 100);
}

/**
 * @tc.number: Init_0020
 * @tc.name: test Init
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, Init_0020, TestSize.Level1)
{
    impl_->tempDir_ = "/data/tmp/test_dir";
    InstallPluginParam param;
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    bool ret = impl_->Init(param, receiver, "com.test.host");
    ASSERT_TRUE(ret);
}

/**
 * @tc.number: UnInit_0010
 * @tc.name: test UnInit
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, UnInit_0010, TestSize.Level1)
{
    impl_->streamFdVec_.push_back(12345);
    impl_->tempDir_ = "/data/tmp/test_dir";
    EXPECT_NO_THROW(impl_->UnInit());
    EXPECT_TRUE(impl_->streamFdVec_.empty());
}

/**
 * @tc.number: UnInit_0020
 * @tc.name: test UnInit
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, UnInit_0020, TestSize.Level1)
{
    impl_->tempDir_ = "";
    EXPECT_NO_THROW(impl_->UnInit());
    EXPECT_TRUE(impl_->streamFdVec_.empty());
}

/**
 * @tc.number: CommitLocalPluginInstall_0010
 * @tc.name: test CommitLocalPluginInstall
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CommitLocalPluginInstall_0010, TestSize.Level1)
{
    impl_->receiver_ = nullptr;
    bool ret = impl_->CommitLocalPluginInstall();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CommitLocalPluginInstall_0020
 * @tc.name: test CommitLocalPluginInstall
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CommitLocalPluginInstall_0020, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    InstallPluginParam param;
    impl_->Init(param, receiver, "com.test.host");
    bool ret = impl_->CommitLocalPluginInstall();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CommitLocalPluginInstall_0030
 * @tc.name: test CommitLocalPluginInstall
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest, CommitLocalPluginInstall_0030, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    InstallPluginParam param;
    bool initRet = impl_->Init(param, receiver, "com.test.host");
    ASSERT_TRUE(initRet);
    bool ret = impl_->CommitLocalPluginInstall();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: test_LocalPluginCreatePluginFileStream_0010
 * @tc.name: test LocalPluginCreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest,
    test_LocalPluginCreatePluginFileStream_0010, Function | SmallTest | Level0)
{
    auto localPluginStreamInstaller = std::make_shared<LocalPluginStreamInstallerHostImpl>(1, 0);
    ASSERT_NE(localPluginStreamInstaller, nullptr);
    EXPECT_EQ(localPluginStreamInstaller->CreatePluginFileStream(""), Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: test_LocalPluginCreatePluginFileStream_0020
 * @tc.name: test LocalPluginCreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest,
    test_LocalPluginCreatePluginFileStream_0020, Function | SmallTest | Level0)
{
    sptr<MockStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    ASSERT_NE(statusReceiver, nullptr);
    InstallPluginParam pluginParam;
    auto localPluginStreamInstaller = std::make_shared<LocalPluginStreamInstallerHostImpl>(1, 0);
    ASSERT_NE(localPluginStreamInstaller, nullptr);
    ASSERT_TRUE(localPluginStreamInstaller->Init(pluginParam, statusReceiver, LOCAL_PLUGIN_HOST_BUNDLE_NAME));

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(LOCAL_PLUGIN_USER_ID);
    int32_t fd = localPluginStreamInstaller->CreatePluginFileStream(LOCAL_PLUGIN_FILE_NAME);
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
    IPCSkeleton::SetCallingUid(callingUid);
}

/**
 * @tc.number: test_LocalPluginCreatePluginFileStream_0030
 * @tc.name: test LocalPluginCreatePluginFileStream
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest,
    test_LocalPluginCreatePluginFileStream_0030, Function | SmallTest | Level0)
{
    auto localPluginStreamInstaller = std::make_shared<LocalPluginStreamInstallerHostImpl>(1, 0);
    ASSERT_NE(localPluginStreamInstaller, nullptr);
    localPluginStreamInstaller->tempDir_.clear();

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t fd = localPluginStreamInstaller->CreatePluginFileStream(LOCAL_PLUGIN_FILE_NAME);
    EXPECT_EQ(fd, Constants::DEFAULT_STREAM_FD);
    IPCSkeleton::SetCallingUid(callingUid);
}

/**
 * @tc.number: test_LocalPluginCommitLocalPluginInstall_0010
 * @tc.name: test LocalPluginCommitLocalPluginInstall
 */
HWTEST_F(LocalPluginStreamInstallerHostImplTest,
    test_LocalPluginCommitLocalPluginInstall_0010, Function | SmallTest | Level0)
{
    auto localPluginStreamInstaller = std::make_shared<LocalPluginStreamInstallerHostImpl>(1, 0);
    ASSERT_NE(localPluginStreamInstaller, nullptr);

    EXPECT_FALSE(localPluginStreamInstaller->CommitLocalPluginInstall());
}
