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

#include "bundle_stream_installer_host_impl.h"
#include "bundle_stream_installer_proxy.h"
#include "bundle_installer_proxy.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string HSPNAME = "hspName";
const char* DATA = "data";
size_t DATA_SIZE = 4;
const std::string OVER_MAX_NAME_SIZE(260, 'x');
constexpr int32_t TEST_INSTALLER_ID = 1024;
constexpr int32_t DEFAULT_INSTALLER_ID = 0;
constexpr int32_t TEST_INSTALLER_UID = 100;
constexpr int32_t INVAILD_ID = -1;
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
    auto ret = proxy->CreateStreamInstaller(installParam, statusReceiver);
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
    auto ret = proxy->CreateStreamInstaller(installParam, statusReceiver);
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
} // OHOS