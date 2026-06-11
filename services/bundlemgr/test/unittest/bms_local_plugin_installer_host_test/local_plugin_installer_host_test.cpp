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
#include "local_plugin_installer_host.h"
#include "local_plugin_stream_installer_host_impl.h"
#undef private

#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_installer_manager.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "ipc_types.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "string_ex.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
void SetVerifyCallingPermissionForTest(bool value);
void SetIsSelfCalling(bool value);
void ResetTestValues();
namespace {
constexpr uint32_t TEST_INSTALLER_ID = 42;
constexpr int32_t TEST_UID = 200;
const std::string TEST_BUNDLE_NAME = "com.test.bundle";
const std::string TEST_PLUGIN_BUNDLE_NAME = "com.test.plugin";
const std::string TEST_PLUGIN_FILE_PATH = "/data/test/plugin.hsp";

class MockStatusReceiver : public IStatusReceiver {
public:
    MockStatusReceiver() = default;
    ~MockStatusReceiver() override = default;
    MOCK_METHOD1(OnStatusNotify, void(const int32_t progress));
    MOCK_METHOD2(OnFinished, void(const int32_t resultCode, const std::string &resultMsg));
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
    MOCK_METHOD1(SetStreamInstallId, void(uint32_t installerId));
};

class PlainRemoteObject : public IRemoteObject {
public:
    PlainRemoteObject() : IRemoteObject(u"plain.remote") {}
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override { return ERR_NONE; }
    sptr<IRemoteBroker> AsInterface() override { return nullptr; }
    int32_t GetObjectRefCount() override { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }
};
}

class LocalPluginInstallerHostTest : public testing::Test {
public:
    void SetUp() override
    {
        host_ = std::make_shared<LocalPluginInstallerHost>();
        host_->Init();
    }
    void TearDown() override
    {
        host_.reset();
    }

protected:
    std::shared_ptr<LocalPluginInstallerHost> host_;
};

/**
 * @tc.number: Init_CreatesManager_001
 * @tc.name: test Init
 */
HWTEST_F(LocalPluginInstallerHostTest, Init_CreatesManager_001, TestSize.Level1)
{
    EXPECT_NE(host_->manager_, nullptr);
}

/**
 * @tc.number: OnRemoteRequest_InvalidDescriptor_002
 * @tc.name: test OnRemoteRequest
 */
HWTEST_F(LocalPluginInstallerHostTest, OnRemoteRequest_InvalidDescriptor_002, TestSize.Level1)
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
HWTEST_F(LocalPluginInstallerHostTest, OnRemoteRequest_UnknownCode_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(host_->GetDescriptor());
    int ret = host_->OnRemoteRequest(999, data, reply, option);
    EXPECT_NE(ret, OHOS::NO_ERROR);
}

/**
 * @tc.number: CheckInstallerManager_NullReceiver_004
 * @tc.name: test CheckInstallerManager
 */
HWTEST_F(LocalPluginInstallerHostTest, CheckInstallerManager_NullReceiver_004, TestSize.Level1)
{
    sptr<IStatusReceiver> nullReceiver = nullptr;
    EXPECT_FALSE(host_->CheckInstallerManager(nullReceiver));
}

/**
 * @tc.number: CheckInstallerManager_NullManager_005
 * @tc.name: test CheckInstallerManager
 */
HWTEST_F(LocalPluginInstallerHostTest, CheckInstallerManager_NullManager_005, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    host_->manager_ = nullptr;
    EXPECT_CALL(*receiver, OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, testing::_)).Times(1);
    EXPECT_FALSE(host_->CheckInstallerManager(receiver));
}

/**
 * @tc.number: CheckInstallerManager_Valid_006
 * @tc.name: test CheckInstallerManager
 */
HWTEST_F(LocalPluginInstallerHostTest, CheckInstallerManager_Valid_006, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    EXPECT_TRUE(host_->CheckInstallerManager(receiver));
}

/**
 * @tc.number: InstallByLocalPluginStream_EmptyPaths_007
 * @tc.name: test InstallByLocalPluginStream
 */
HWTEST_F(LocalPluginInstallerHostTest, InstallByLocalPluginStream_EmptyPaths_007, TestSize.Level1)
{
    InstallPluginParam param;
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    std::vector<std::string> emptyPaths;
    ErrCode ret = host_->InstallByLocalPluginStream(TEST_BUNDLE_NAME, emptyPaths, param, receiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_INSTALL_FILEPATH_INVALID);
}

/**
 * @tc.number: InstallByLocalPluginStream_NullReceiver_008
 * @tc.name: test InstallByLocalPluginStream
 */
HWTEST_F(LocalPluginInstallerHostTest, InstallByLocalPluginStream_NullReceiver_008, TestSize.Level1)
{
    InstallPluginParam param;
    sptr<IStatusReceiver> nullReceiver = nullptr;
    std::vector<std::string> paths = {TEST_PLUGIN_FILE_PATH};
    ErrCode ret = host_->InstallByLocalPluginStream(TEST_BUNDLE_NAME, paths, param, nullReceiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: Uninstall_EmptyPluginBundleName_009
 * @tc.name: test Uninstall
 */
HWTEST_F(LocalPluginInstallerHostTest, Uninstall_EmptyPluginBundleName_009, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new MockStatusReceiver();
    ErrCode ret = host_->Uninstall("", receiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_NOT_FOUND);
}

/**
 * @tc.number: Uninstall_NullReceiver_010
 * @tc.name: test Uninstall
 */
HWTEST_F(LocalPluginInstallerHostTest, Uninstall_NullReceiver_010, TestSize.Level1)
{
    sptr<IStatusReceiver> nullReceiver = nullptr;
    ErrCode ret = host_->Uninstall(TEST_PLUGIN_BUNDLE_NAME, nullReceiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleDestroyLocalPluginStreamInstallerMessage_Success_011
 * @tc.name: test HandleDestroyLocalPluginStreamInstallerMessage
 */
HWTEST_F(LocalPluginInstallerHostTest, HandleDestroyLocalPluginStreamInstallerMessage_Success_011,
    TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteUint32(TEST_INSTALLER_ID);
    ErrCode ret = host_->HandleDestroyLocalPluginStreamInstallerMessage(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DestroyLocalPluginStreamInstaller_EmptyList_012
 * @tc.name: test DestroyLocalPluginStreamInstaller
 */
HWTEST_F(LocalPluginInstallerHostTest, DestroyLocalPluginStreamInstaller_EmptyList_012, TestSize.Level1)
{
    host_->localPluginStreamInstallers_.clear();
    bool ret = host_->DestroyLocalPluginStreamInstaller(TEST_INSTALLER_ID);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DestroyLocalPluginStreamInstaller_MatchingId_013
 * @tc.name: test DestroyLocalPluginStreamInstaller
 */
HWTEST_F(LocalPluginInstallerHostTest, DestroyLocalPluginStreamInstaller_MatchingId_013, TestSize.Level1)
{
    host_->localPluginStreamInstallers_.clear();
    // Add a mock stream installer with the matching ID
    sptr<LocalPluginStreamInstallerHostImpl> mockInstaller(
        new LocalPluginStreamInstallerHostImpl(TEST_INSTALLER_ID, TEST_UID));
    host_->localPluginStreamInstallers_.emplace_back(mockInstaller);
    EXPECT_EQ(host_->localPluginStreamInstallers_.size(), 1);

    bool ret = host_->DestroyLocalPluginStreamInstaller(TEST_INSTALLER_ID);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(host_->localPluginStreamInstallers_.empty());
}

/**
 * @tc.number: DestroyLocalPluginStreamInstaller_NonMatchingId_014
 * @tc.name: test DestroyLocalPluginStreamInstaller
 */
HWTEST_F(LocalPluginInstallerHostTest, DestroyLocalPluginStreamInstaller_NonMatchingId_014, TestSize.Level1)
{
    host_->localPluginStreamInstallers_.clear();
    sptr<LocalPluginStreamInstallerHostImpl> mockInstaller(
        new LocalPluginStreamInstallerHostImpl(99, TEST_UID));
    host_->localPluginStreamInstallers_.emplace_back(mockInstaller);
    EXPECT_EQ(host_->localPluginStreamInstallers_.size(), 1);

    bool ret = host_->DestroyLocalPluginStreamInstaller(TEST_INSTALLER_ID);
    EXPECT_TRUE(ret);
    // Non-matching installer should remain
    EXPECT_EQ(host_->localPluginStreamInstallers_.size(), 1);
}

/**
 * @tc.number: HandleInternalUninstallMessage_Success_015
 * @tc.name: test HandleInternalUninstallMessage
 */
HWTEST_F(LocalPluginInstallerHostTest, HandleInternalUninstallMessage_Success_015, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString16(Str8ToStr16(TEST_BUNDLE_NAME));
    data.WriteString16(Str8ToStr16(TEST_PLUGIN_BUNDLE_NAME));
    data.WriteInt32(100);
    ErrCode ret = host_->HandleInternalUninstallMessage(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HandleCreateLocalPluginStreamInstallerMessage_NullObject_016
 * @tc.name: test HandleCreateLocalPluginStreamInstallerMessage
 */
HWTEST_F(LocalPluginInstallerHostTest, HandleCreateLocalPluginStreamInstallerMessage_NullObject_016,
    TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto object = data.ReadRemoteObject();
    EXPECT_EQ(object, nullptr);
    ErrCode ret = host_->HandleCreateLocalPluginStreamInstallerMessage(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleCreateLocalPluginStreamInstallerMessage_InvalidReceiver_017
 * @tc.name: test HandleCreateLocalPluginStreamInstallerMessage
 */
HWTEST_F(LocalPluginInstallerHostTest, HandleCreateLocalPluginStreamInstallerMessage_InvalidReceiver_017,
    TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    sptr<PlainRemoteObject> plainObj = new PlainRemoteObject();
    data.WriteRemoteObject(plainObj);
    ErrCode ret = host_->HandleCreateLocalPluginStreamInstallerMessage(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HandleUninstallMessage_NullObject_018
 * @tc.name: test HandleUninstallMessage
 */
HWTEST_F(LocalPluginInstallerHostTest, HandleUninstallMessage_NullObject_018, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString16(Str8ToStr16(TEST_PLUGIN_BUNDLE_NAME));
    ErrCode ret = host_->HandleUninstallMessage(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleUninstallMessage_InvalidStatusReceiver_019
 * @tc.name: test HandleUninstallMessage
 */
HWTEST_F(LocalPluginInstallerHostTest, HandleUninstallMessage_InvalidStatusReceiver_019, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString16(Str8ToStr16(TEST_PLUGIN_BUNDLE_NAME));
    sptr<PlainRemoteObject> plainObj = new PlainRemoteObject();
    data.WriteRemoteObject(plainObj);
    ErrCode ret = host_->HandleUninstallMessage(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: test_LocalPluginInstallByLocalPluginStream_0300
 * @tc.name: test LocalPluginInstallByLocalPluginStream
 */
HWTEST_F(LocalPluginInstallerHostTest,
    test_LocalPluginInstallByLocalPluginStream_0300, Function | SmallTest | Level0)
{
    LocalPluginInstallerHost host;
    host.Init();
    InstallPluginParam pluginParam;
    sptr<MockStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    ASSERT_NE(statusReceiver, nullptr);
    std::vector<std::string> pluginFilePaths = { TEST_PLUGIN_BUNDLE_NAME };

    OHOS::system::SetParameter(ServiceConstants::IS_SUPPORT_LOCAL_PLUGIN, "false");
    ErrCode ret = host.InstallByLocalPluginStream(
        TEST_PLUGIN_BUNDLE_NAME, pluginFilePaths, pluginParam, statusReceiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_DEVICE_NOT_SUPPORT_PLUGIN);
    OHOS::system::SetParameter(ServiceConstants::IS_SUPPORT_LOCAL_PLUGIN, "true");
}


/**
 * @tc.number: test_LocalPluginUninstall_0100
 * @tc.name: test LocalPluginUninstall
 */
HWTEST_F(LocalPluginInstallerHostTest,
    test_LocalPluginUninstall_0100, Function | SmallTest | Level0)
{
    LocalPluginInstallerHost host;
    sptr<MockStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    ASSERT_NE(statusReceiver, nullptr);

    ErrCode ret = host.Uninstall("", statusReceiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_NOT_FOUND);
}

/**
 * @tc.number: test_LocalPluginDestroyLocalPluginStreamInstaller_0100
 * @tc.name: test LocalPluginDestroyLocalPluginStreamInstaller
 */
HWTEST_F(LocalPluginInstallerHostTest,
    test_LocalPluginDestroyLocalPluginStreamInstaller_0100, Function | SmallTest | Level0)
{
    LocalPluginInstallerHost host;
    SetIsSelfCalling(false);
    SetVerifyCallingPermissionForTest(false);

    EXPECT_FALSE(host.DestroyLocalPluginStreamInstaller(1));
    ResetTestValues();
}

/**
 * @tc.number: test_LocalPluginDestroyLocalPluginStreamInstaller_0200
 * @tc.name: test LocalPluginDestroyLocalPluginStreamInstaller
 */
HWTEST_F(LocalPluginInstallerHostTest,
    test_LocalPluginDestroyLocalPluginStreamInstaller_0200, Function | SmallTest | Level0)
{
    LocalPluginInstallerHost host;
    sptr<LocalPluginStreamInstallerHostImpl> installer =
        new (std::nothrow) LocalPluginStreamInstallerHostImpl(1, 0);
    ASSERT_NE(installer, nullptr);
    host.localPluginStreamInstallers_.emplace_back(installer);

    EXPECT_TRUE(host.DestroyLocalPluginStreamInstaller(1));
    EXPECT_TRUE(host.localPluginStreamInstallers_.empty());
}
