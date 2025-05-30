/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <vector>

#include "bundle_framework_services_ipc_interface_code.h"
#include "bundle_stream_installer_host_impl.h"
#include "bundle_stream_installer_proxy.h"
#include "bundle_installer_proxy.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "ipc/installd_host.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string HSPNAME = "hspName";
const char* DATA = "data";
const char* FILE_NAME = "manifest.json";
size_t DATA_SIZE = 4;
const std::string OVER_MAX_NAME_SIZE(260, 'x');
constexpr int32_t TEST_INSTALLER_ID = 1024;
constexpr int32_t DEFAULT_INSTALLER_ID = 0;
constexpr int32_t TEST_INSTALLER_UID = 100;
constexpr int32_t INVAILD_ID = -1;
const int32_t ERR_CODE = 8388613;
enum BundleInstallerInterfaceCode : uint32_t {
    INSTALL = 0,
    INSTALL_MULTIPLE_HAPS,
    UNINSTALL,
    UNINSTALL_MODULE,
    UNINSTALL_BY_UNINSTALL_PARAM,
    RECOVER,
    INSTALL_SANDBOX_APP,
    UNINSTALL_SANDBOX_APP,
    CREATE_STREAM_INSTALLER,
    DESTORY_STREAM_INSTALLER,
    UNINSTALL_AND_RECOVER,
    INSTALL_CLONE_APP,
    UNINSTALL_CLONE_APP,
    INSTALL_EXISTED,
    INSTALL_PLUGIN_APP,
    UNINSTALL_PLUGIN_APP
};
constexpr const char* ILLEGAL_PATH_FIELD = "../";
}; // namespace
class BmsBundleInstallerIPCTest : public testing::Test {
public:
    BmsBundleInstallerIPCTest();
    ~BmsBundleInstallerIPCTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    sptr<BundleStreamInstallerProxy> GetStreamInstallerProxy();
    sptr<BundleInstallerProxy> GetInstallerProxy();
    void SetUp();
    void TearDown();

private:
    sptr<BundleStreamInstallerHostImpl> streamInstallerHostImpl_ = nullptr;
    sptr<BundleStreamInstallerProxy> streamInstallerProxy_ = nullptr;
    sptr<BundleInstallerHost> installerHost_ = nullptr;
    sptr<BundleInstallerProxy> installerProxy_ = nullptr;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleInstallerIPCTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleInstallerIPCTest::BmsBundleInstallerIPCTest()
{}

BmsBundleInstallerIPCTest::~BmsBundleInstallerIPCTest()
{}

void BmsBundleInstallerIPCTest::SetUpTestCase()
{
}

void BmsBundleInstallerIPCTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}
void BmsBundleInstallerIPCTest::SetUp()
{}

void BmsBundleInstallerIPCTest::TearDown()
{}

sptr<BundleStreamInstallerProxy> BmsBundleInstallerIPCTest::GetStreamInstallerProxy()
{
    if ((streamInstallerHostImpl_ != nullptr) && (streamInstallerProxy_ != nullptr)) {
        return streamInstallerProxy_;
    }
    streamInstallerHostImpl_ = new (std::nothrow) BundleStreamInstallerHostImpl(TEST_INSTALLER_ID, TEST_INSTALLER_UID);
    if (streamInstallerHostImpl_ == nullptr || streamInstallerHostImpl_->AsObject() == nullptr) {
        return nullptr;
    }
    streamInstallerProxy_ = new (std::nothrow) BundleStreamInstallerProxy(streamInstallerHostImpl_->AsObject());
    if (streamInstallerProxy_ == nullptr) {
        return nullptr;
    }
    return streamInstallerProxy_;
}

sptr<BundleInstallerProxy> BmsBundleInstallerIPCTest::GetInstallerProxy()
{
    if ((installerHost_ != nullptr) && (installerProxy_ != nullptr)) {
        return installerProxy_;
    }
    installerHost_ = new (std::nothrow) BundleInstallerHost();
    if (installerHost_ == nullptr || installerHost_->AsObject() == nullptr) {
        return nullptr;
    }
    installerProxy_ = new (std::nothrow) BundleInstallerProxy(installerHost_->AsObject());
    if (installerProxy_ == nullptr) {
        return nullptr;
    }
    return installerProxy_;
}

/**
 * @tc.number: GetInstallerIdTest_0100
 * @tc.name: test GetInstallerId function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function GetInstallerId
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, GetInstallerIdTest_0100, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    EXPECT_NE(proxy, nullptr);
    proxy->SetInstallerId(TEST_INSTALLER_ID);

    auto id = proxy->GetInstallerId();
    EXPECT_EQ(id, TEST_INSTALLER_ID);
}

/**
 * @tc.number: UnInitTest_0100
 * @tc.name: test UnInit function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function UnInit
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, FileStatTest_0200, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    EXPECT_NE(proxy, nullptr);
    proxy->SetInstallerId(DEFAULT_INSTALLER_ID);

    proxy->UnInit();
    auto id = proxy->GetInstallerId();
    EXPECT_EQ(id, DEFAULT_INSTALLER_ID);
}

/**
 * @tc.number: DestoryBundleStreamInstallerTest_0300
 * @tc.name: test DestoryBundleStreamInstaller function of BundleInstallerProxy
 * @tc.desc: 1. Obtain bundleInstallerProxy
 *           2. Calling function DestoryBundleStreamInstaller
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, FileStatTest_0300, Function | SmallTest | Level0)
{
    auto proxy = GetInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->DestoryBundleStreamInstaller(DEFAULT_INSTALLER_ID);
    EXPECT_TRUE(ret);
}


/**
 * @tc.number: InstallTest_0100
 * @tc.name: test Install function of BundleInstallerProxy
 * @tc.desc: 1. Obtain bundleInstallerProxy
 *           2. Calling function Install
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, InstallTest_0100, Function | SmallTest | Level0)
{
    auto proxy = GetInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver;
    auto ret = proxy->Install("", installParam, statusReceiver);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CreateStream_0100
 * @tc.name: test CreateStream function of BundleInstallerProxy
 * @tc.desc: 1. Obtain CreateStream
 *           2. Calling function CreateStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateStreamInstaller_0100, Function | SmallTest | Level0)
{
    auto proxy = GetInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    InstallParam installParam;
    installParam.userId = TEST_INSTALLER_UID;
    installParam.installFlag = InstallFlag::NORMAL;
    sptr<IStatusReceiver> statusReceiver;
    std::vector<std::string> originHapPaths;
    auto ret = proxy->CreateStreamInstaller(installParam, statusReceiver, originHapPaths);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: CreateStream_0200
 * @tc.name: test CreateStream function of BundleInstallerProxy
 * @tc.desc: 1. Obtain CreateStream
 *           2. Calling function CreateStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateStreamInstaller_0200, Function | SmallTest | Level0)
{
    auto proxy = GetInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver;
    std::vector<std::string> originHapPaths;
    auto ret = proxy->CreateStreamInstaller(installParam, statusReceiver, originHapPaths);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: StreamInstall_0100
 * @tc.name: test CreateStream function of BundleInstallerProxy
 * @tc.desc: 1. Obtain CreateStream
 *           2. Calling function CreateStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, StreamInstall_0100, Function | SmallTest | Level0)
{
    auto proxy = GetInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    std::vector<std::string> bundleFilePaths;
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto ret = proxy->StreamInstall(bundleFilePaths, installParam, statusReceiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: CreateStream_0100
 * @tc.name: test CreateStream function of BundleInstallerProxy
 * @tc.desc: 1. Obtain CreateStream
 *           2. Calling function CreateStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, StreamInstall_0200, Function | SmallTest | Level0)
{
    auto proxy = GetInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    std::vector<std::string> bundleFilePaths;
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver;
    auto ret = proxy->StreamInstall(bundleFilePaths, installParam, statusReceiver);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: CreateStream_0100
 * @tc.name: test CreateStream function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateStream_0100, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    auto id = proxy->CreateStream("");
    EXPECT_EQ(id, INVAILD_ID);
}

/**
 * @tc.number: CreateStream_0200
 * @tc.name: test CreateStream function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateStream_0200, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    auto id = proxy->CreateStream("hapName");
    EXPECT_EQ(id, INVAILD_ID);
}

/**
 * @tc.number: CreateSharedBundleStream_0100
 * @tc.name: test CreateSharedBundleStream function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSharedBundleStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_0100, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    auto id = proxy->CreateSharedBundleStream("", DEFAULT_INSTALLER_ID);
    EXPECT_EQ(id, INVAILD_ID);
}

/**
 * @tc.number: CreateSharedBundleStream_0200
 * @tc.name: test CreateSharedBundleStream function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSharedBundleStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_0200, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    auto id = proxy->CreateSharedBundleStream(HSPNAME, DEFAULT_INSTALLER_ID);
    EXPECT_EQ(id, INVAILD_ID);
}

/**
 * @tc.number: CreateSharedBundleStream_0300
 * @tc.name: test CreateSharedBundleStream function of BundleStreamInstallerHostImpl
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSharedBundleStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_0300, Function | SmallTest | Level0)
{
    BundleStreamInstallerHostImpl impl(TEST_INSTALLER_ID, TEST_INSTALLER_UID);

    auto id = impl.CreateSharedBundleStream(OVER_MAX_NAME_SIZE, DEFAULT_INSTALLER_ID);
    EXPECT_EQ(id, INVAILD_ID);
}

/**
 * @tc.number: CreateSharedBundleStream_0400
 * @tc.name: test CreateSharedBundleStream function of BundleStreamInstallerHostImpl
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSharedBundleStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_0400, Function | SmallTest | Level0)
{
    BundleStreamInstallerHostImpl impl(TEST_INSTALLER_ID, TEST_INSTALLER_UID);

    auto id = impl.CreateSharedBundleStream(HSPNAME + ".", DEFAULT_INSTALLER_ID);
    EXPECT_EQ(id, INVAILD_ID);
}

/**
 * @tc.number: CreateSharedBundleStream_0500
 * @tc.name: test CreateSharedBundleStream function of BundleStreamInstallerHostImpl
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSharedBundleStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_0500, Function | SmallTest | Level0)
{
    BundleStreamInstallerHostImpl impl(TEST_INSTALLER_ID, TEST_INSTALLER_UID);

    impl.installParam_.sharedBundleDirPaths.push_back(OVER_MAX_NAME_SIZE);
    auto id = impl.CreateSharedBundleStream(HSPNAME, DEFAULT_INSTALLER_ID);
    EXPECT_EQ(id, INVAILD_ID);
}

/**
 * @tc.number: CreateSharedBundleStream_0600
 * @tc.name: test CreateSharedBundleStream function of BundleStreamInstallerHostImpl
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSharedBundleStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_0600, Function | SmallTest | Level0)
{
    BundleStreamInstallerHostImpl impl(TEST_INSTALLER_ID, TEST_INSTALLER_UID);

    impl.isInstallSharedBundlesOnly_ = false;
    auto res = impl.Install();
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: CreateSharedBundleStream_0600
 * @tc.name: test CreateSharedBundleStream function of BundleStreamInstallerHostImpl
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSharedBundleStream
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_0700, Function | SmallTest | Level0)
{
    BundleStreamInstallerHostImpl impl(TEST_INSTALLER_ID, TEST_INSTALLER_UID);

    auto id = impl.CreateSharedBundleStream(HSPNAME + ILLEGAL_PATH_FIELD, DEFAULT_INSTALLER_ID);
    EXPECT_EQ(id, INVAILD_ID);
}

/**
 * @tc.number: CreateSharedBundleStream_0800
 * @tc.name: test true function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_0800, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    auto res = proxy->Install();
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: CreateSharedBundleStream_0900
 * @tc.name: test GetInstallerId function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSignatureFileStream
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_0900, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    ASSERT_FALSE(proxy == nullptr);
    int32_t fd = -1;
    auto id = proxy->CreateSignatureFileStream(HSPNAME, HSPNAME);
    EXPECT_EQ(id, fd);
}

/**
 * @tc.number: CreateSharedBundleStream_1000
 * @tc.name: test GetInstallerId function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSignatureFileStream
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_1000, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    ASSERT_FALSE(proxy == nullptr);
    int32_t fd = -1;
    auto id = proxy->CreateSignatureFileStream("", HSPNAME);
    EXPECT_EQ(id, fd);
}

/**
 * @tc.number: CreateSharedBundleStream_1100
 * @tc.name: test GetInstallerId function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateSignatureFileStream
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_1100, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    ASSERT_FALSE(proxy == nullptr);
    int32_t fd = -1;
    auto id = proxy->CreateSignatureFileStream(HSPNAME, "");
    EXPECT_EQ(id, fd);
}

/**
 * @tc.number: CreateSharedBundleStream_1200
 * @tc.name: test GetInstallerId function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreatePgoFileStream
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_1200, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    ASSERT_FALSE(proxy == nullptr);
    int32_t fd = -1;
    auto id = proxy->CreatePgoFileStream("", "");
    EXPECT_EQ(id, fd);

    id = proxy->CreatePgoFileStream(HSPNAME, "");
    EXPECT_EQ(id, fd);

    id = proxy->CreatePgoFileStream("", HSPNAME);
    EXPECT_EQ(id, fd);
}

/**
 * @tc.number: CreateSharedBundleStream_1300
 * @tc.name: test GetInstallerId function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreatePgoFileStream
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_1300, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    ASSERT_FALSE(proxy == nullptr);
    int32_t fd = -1;
    auto id = proxy->CreatePgoFileStream(HSPNAME, HSPNAME);
    EXPECT_EQ(id, fd);
}

/**
 * @tc.number: CreateSharedBundleStream_1400
 * @tc.name: test GetInstallerId function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function CreateExtProfileFileStream
*/
HWTEST_F(BmsBundleInstallerIPCTest, CreateSharedBundleStream_1400, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    ASSERT_FALSE(proxy == nullptr);
    int32_t fd = -1;
    auto id = proxy->CreateExtProfileFileStream("");
    EXPECT_EQ(id, fd);

    id = proxy->CreateExtProfileFileStream(FILE_NAME);
    EXPECT_EQ(id, fd);
}

/**
 * @tc.number: OnRemoteRequestTest_0100
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_0100, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::INSTALL;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_0200
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_0200, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::INSTALL_MULTIPLE_HAPS;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_0300
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_0300, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::UNINSTALL;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_0400
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_0400, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::UNINSTALL_MODULE;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_0500
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_0500, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::UNINSTALL_BY_UNINSTALL_PARAM;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_0600
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_0600, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::RECOVER;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_0700
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_0700, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::INSTALL_SANDBOX_APP;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_0800
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_0800, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::UNINSTALL_SANDBOX_APP;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_0900
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_0900, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::CREATE_STREAM_INSTALLER;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_1000
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1000, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::DESTORY_STREAM_INSTALLER;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_1100
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1100, Function | SmallTest | Level0)
{
    uint32_t code = -1;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_NE(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_1200
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1200, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::UNINSTALL_AND_RECOVER;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_1300
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode CLEAN_BUNDLE_DATA_DIR_BY_NAME
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1300, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::CLEAN_BUNDLE_DATA_DIR_BY_NAME);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_1400
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode GET_ALL_BUNDLE_STATS
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1400, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::GET_ALL_BUNDLE_STATS);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_1500
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode EXTRACT_FILES
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1500, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_FILES);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_1600
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode EXTRACT_HNP_FILES
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1600, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_HNP_FILES);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_1700
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode INSTALL_NATIVE
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1700, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::INSTALL_NATIVE);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_1800
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode UNINSTALL_NATIVE
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1800, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::UNINSTALL_NATIVE);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_1900
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode GET_NATIVE_LIBRARY_FILE_NAMES
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_1900, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::GET_NATIVE_LIBRARY_FILE_NAMES);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_2000
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode EXECUTE_AOT
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2000, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::EXECUTE_AOT);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_2100
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode PEND_SIGN_AOT
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2100, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::PEND_SIGN_AOT);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_2200
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode IS_EXIST_FILE
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2200, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_FILE);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_2300
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode IS_EXIST_AP_FILE
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2300, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_AP_FILE);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_2400
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode MOVE_FILES
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2400, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::MOVE_FILES);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_2500
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode EXTRACT_DRIVER_SO_FILE
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2500, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_DRIVER_SO_FILE);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_2600
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode EXTRACT_CODED_SO_FILE
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2600, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_CODED_SO_FILE);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_2700
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode GET_DISK_USAGE
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2700, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::GET_DISK_USAGE);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_2800
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode DELIVERY_SIGN_PROFILE
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2800, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::DELIVERY_SIGN_PROFILE);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer("a", 1);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_2900
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode REMOVE_EXTENSION_DIR
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_2900, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_EXTENSION_DIR);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer("a", 1);
    datas.WriteBuffer("a", 1);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_3000
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode IS_EXIST_EXTENSION_DIR
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3000, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_EXTENSION_DIR);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_3100
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode GET_EXTENSION_SANDBOX_TYPE_LIST
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3100, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::GET_EXTENSION_SANDBOX_TYPE_LIST);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_3200
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode CREATE_EXTENSION_DATA_DIR
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3200, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::CREATE_EXTENSION_DATA_DIR);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_CODE);
}

/**
 * @tc.number: OnRemoteRequestTest_3300
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3300, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::INSTALL_PLUGIN_APP;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_3400
 * @tc.name: test true function of OnRemoteRequest
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function true
*/
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3400, Function | SmallTest | Level0)
{
    uint32_t code = BundleInstallerInterfaceCode::UNINSTALL_PLUGIN_APP;
    MessageParcel datas;
    std::u16string descriptor = BundleInstallerHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    BundleInstallerHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: HandleExtractFiles_0100
 * @tc.name: HandleExtractFiles
 * @tc.desc: test HandleExtractFiles of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleExtractFiles_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    bool res = host.HandleExtractFiles(datas, reply);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: HandleExtractHnpFiles_0100
 * @tc.name: HandleExtractHnpFiles
 * @tc.desc: test HandleExtractHnpFiles of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleExtractHnpFiles_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    bool res = host.HandleExtractHnpFiles(datas, reply);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: HandleProcessBundleInstallNative_0100
 * @tc.name: HandleProcessBundleInstallNative
 * @tc.desc: test HandleProcessBundleInstallNative of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleProcessBundleInstallNative_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    bool res = host.HandleProcessBundleInstallNative(datas, reply);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: HandleProcessBundleUnInstallNative_0100
 * @tc.name: HandleProcessBundleUnInstallNative
 * @tc.desc: test HandleProcessBundleUnInstallNative of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleProcessBundleUnInstallNative_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    bool res = host.HandleProcessBundleUnInstallNative(datas, reply);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: HandleExecuteAOT_0100
 * @tc.name: HandleExecuteAOT
 * @tc.desc: test HandleExecuteAOT of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleExecuteAOT_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    bool res = host.HandleExecuteAOT(datas, reply);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: HandleCreateBundleDataDirWithVector_0100
 * @tc.name: HandleCreateBundleDataDirWithVector
 * @tc.desc: test HandleCreateBundleDataDirWithVector of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleCreateBundleDataDirWithVector_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    MessageParcel reply;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    reply.WriteInt32(0);
    bool res = host.HandleCreateBundleDataDirWithVector(datas, reply);
    EXPECT_EQ(res, false);

    reply.WriteInt32(Constants::MAX_PARCEL_CAPACITY + 1);
    res = host.HandleCreateBundleDataDirWithVector(datas, reply);
    EXPECT_EQ(res, false);

    reply.WriteInt32(DATA_SIZE);
    res = host.HandleCreateBundleDataDirWithVector(datas, reply);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: HandleCleanBundleDataDirByName_0100
 * @tc.name: HandleCleanBundleDataDirByName
 * @tc.desc: test HandleCleanBundleDataDirByName of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleCleanBundleDataDirByName_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    bool res = host.HandleCleanBundleDataDirByName(datas, reply);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: HandleGetAllBundleStats_0100
 * @tc.name: HandleGetAllBundleStats
 * @tc.desc: test HandleGetAllBundleStats of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleGetAllBundleStats_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteInt32(100);
    datas.WriteInt32(0);
    MessageParcel reply;
    bool res = host.HandleGetAllBundleStats(datas, reply);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: HandleIsExistApFile_0100
 * @tc.name: HandleIsExistApFile
 * @tc.desc: test HandleIsExistApFile of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleIsExistApFile_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    bool res = host.HandleIsExistApFile(datas, reply);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: HandGetNativeLibraryFileNames_0100
 * @tc.name: HandGetNativeLibraryFileNames
 * @tc.desc: test HandGetNativeLibraryFileNames of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandGetNativeLibraryFileNames_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    bool res = host.HandGetNativeLibraryFileNames(datas, reply);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: HandMoveFiles_0100
 * @tc.name: HandMoveFiles
 * @tc.desc: test HandMoveFiles of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandMoveFiles_0100, Function | SmallTest | Level0)
{
    InstalldHost host;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    bool res = host.HandMoveFiles(datas, reply);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: CreateSignatureFileStream_0100
 * @tc.name: CreateSignatureFileStream
 * @tc.desc: test CreateSignatureFileStream of BundleStreamInstallerHostImpl
 */
HWTEST_F(BmsBundleInstallerIPCTest, CreateSignatureFileStream_0100, Function | SmallTest | Level0)
{
    BundleStreamInstallerHostImpl impl(TEST_INSTALLER_ID, TEST_INSTALLER_UID);
    auto res = impl.CreateSignatureFileStream("", HSPNAME);
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);

    res = impl.CreateSignatureFileStream(HSPNAME, "");
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);

    res = impl.CreateSignatureFileStream(HSPNAME, HSPNAME);
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreatePgoFileStream_0100
 * @tc.name: CreatePgoFileStream
 * @tc.desc: test CreatePgoFileStream of BundleStreamInstallerHostImpl
 */
HWTEST_F(BmsBundleInstallerIPCTest, CreatePgoFileStream_0100, Function | SmallTest | Level0)
{
    BundleStreamInstallerHostImpl impl(TEST_INSTALLER_ID, TEST_INSTALLER_UID);
    auto res = impl.CreatePgoFileStream("", "");
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);

    res = impl.CreatePgoFileStream(HSPNAME, "");
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);

    res = impl.CreatePgoFileStream("", HSPNAME);
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: OnRemoteRequestTest_3500
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode MOVE_HAP_TO_CODE_DIR
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3500, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::MOVE_HAP_TO_CODE_DIR);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_3600
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode ADD_USER_DIR_DELETE_DFX
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3600, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::ADD_USER_DIR_DELETE_DFX);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.number: OnRemoteRequestTest_3700
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode DELETE_UNINSTALL_TMP_DIRS
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3700, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::DELETE_UNINSTALL_TMP_DIRS);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_3800
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode GET_DISK_USAGE_FROM_PATH
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3800, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::GET_DISK_USAGE_FROM_PATH);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_3900
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode CREATE_DATA_GROUP_DIRS
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_3900, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::CREATE_DATA_GROUP_DIRS);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_4000
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode DELETE_DATA_GROUP_DIRS
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_4000, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::DELETE_DATA_GROUP_DIRS);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_4200
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with InstalldInterfaceCode MIGRATE_DATA
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_4200, Function | SmallTest | Level0)
{
    uint32_t code = static_cast<uint32_t>(InstalldInterfaceCode::MIGRATE_DATA);
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequestTest_4300
 * @tc.name: test OnRemoteRequest of InstalldHost
 * @tc.desc: 1. Calling function with IPCObjectStub::OnRemoteRequest
 */
HWTEST_F(BmsBundleInstallerIPCTest, OnRemoteRequestTest_4300, Function | SmallTest | Level0)
{
    uint32_t code = 1000;
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    InstalldHost installdHost;
    int res = installdHost.OnRemoteRequest(code, datas, reply, option);
    EXPECT_EQ(res, 305);
}

/**
 * @tc.number: HandleDeleteUninstallTmpDirs_0001
 * @tc.name: HandleDeleteUninstallTmpDirs
 * @tc.desc: test HandleDeleteUninstallTmpDirs of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleDeleteUninstallTmpDirs_0001, Function | SmallTest | Level0)
{
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    InstalldHost installdHost;
    int res = installdHost.HandleDeleteUninstallTmpDirs(datas, reply);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: HandleGetDiskUsageFromPath_0001
 * @tc.name: HandleGetDiskUsageFromPath
 * @tc.desc: test HandleGetDiskUsageFromPath of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleGetDiskUsageFromPath_0001, Function | SmallTest | Level0)
{
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    InstalldHost installdHost;
    int res = installdHost.HandleGetDiskUsageFromPath(datas, reply);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: HandleCreateDataGroupDirs_0001
 * @tc.name: HandleCreateDataGroupDirs
 * @tc.desc: test HandleCreateDataGroupDirs of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleCreateDataGroupDirs_0001, Function | SmallTest | Level0)
{
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    InstalldHost installdHost;
    int res = installdHost.HandleCreateDataGroupDirs(datas, reply);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: HandleDeleteDataGroupDirs_0001
 * @tc.name: HandleDeleteDataGroupDirs
 * @tc.desc: test HandleDeleteDataGroupDirs of InstalldHost
 */
HWTEST_F(BmsBundleInstallerIPCTest, HandleDeleteDataGroupDirs_0001, Function | SmallTest | Level0)
{
    MessageParcel datas;
    std::u16string descriptor = InstalldHost::GetDescriptor();
    datas.WriteInterfaceToken(descriptor);
    datas.WriteBuffer(DATA, DATA_SIZE);
    datas.RewindRead(0);
    MessageParcel reply;
    InstalldHost installdHost;
    int res = installdHost.HandleDeleteDataGroupDirs(datas, reply);
    EXPECT_EQ(res, false);
}
} // OHOS