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

#include <fstream>
#include <future>
#include <gtest/gtest.h>
#define private public
#define protected public
#include "bundle_installer_proxy.h"
#include "peer_holder.h"
#undef private
#undef protected

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "mock_status_receiver.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BmsBundleInstallerProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsBundleInstallerProxyTest::SetUpTestCase()
{}

void BmsBundleInstallerProxyTest::TearDownTestCase()
{}

void BmsBundleInstallerProxyTest::SetUp()
{}

void BmsBundleInstallerProxyTest::TearDown()
{}

/**
 * @tc.number: Install_0100
 * @tc.name: test the Install
 * @tc.desc: 1. statusReceiver is nullptr
 *           2. test Install
 */
HWTEST_F(BmsBundleInstallerProxyTest, Install_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundlePath = "bundlePath";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = bundleInstallerProxy.Install(bundlePath, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Install_0200
 * @tc.name: test the Install
 * @tc.desc: 1. write parcel failed
 *           2. test Install
 */
HWTEST_F(BmsBundleInstallerProxyTest, Install_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundlePath = "bundlePath";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    ASSERT_NE(statusReceiver, nullptr);
    auto res = bundleInstallerProxy.Install(bundlePath, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Install_0300
 * @tc.name: test the Install
 * @tc.desc: 1. statusReceiver is nullptr
 *           2. test Install
 */
HWTEST_F(BmsBundleInstallerProxyTest, Install_0300, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundlePath = "bundlePath";
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.emplace_back(bundlePath);
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = bundleInstallerProxy.Install(bundleFilePaths, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Install_0400
 * @tc.name: test the Install
 * @tc.desc: 1. write parcel failed
 *           2. test Install
 */
HWTEST_F(BmsBundleInstallerProxyTest, Install_0400, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundlePath = "bundlePath";
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.emplace_back(bundlePath);
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    ASSERT_NE(statusReceiver, nullptr);
    auto res = bundleInstallerProxy.Install(bundleFilePaths, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Recover_0100
 * @tc.name: test the Recover
 * @tc.desc: 1. statusReceiver is nullptr
 *           2. test Recover
 */
HWTEST_F(BmsBundleInstallerProxyTest, Recover_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = bundleInstallerProxy.Recover(bundleName, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Recover_0200
 * @tc.name: test the Recover
 * @tc.desc: 1. write parcel failed
 *           2. test Recover
 */
HWTEST_F(BmsBundleInstallerProxyTest, Recover_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    auto res = bundleInstallerProxy.Recover(bundleName, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Uninstall_0100
 * @tc.name: test the Uninstall
 * @tc.desc: 1. statusReceiver is nullptr
 *           2. test Uninstall
 */
HWTEST_F(BmsBundleInstallerProxyTest, Uninstall_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = bundleInstallerProxy.Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Uninstall_0200
 * @tc.name: test the Uninstall
 * @tc.desc: 1. write parcel failed
 *           2. test Uninstall
 */
HWTEST_F(BmsBundleInstallerProxyTest, Uninstall_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    auto res = bundleInstallerProxy.Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Uninstall_0300
 * @tc.name: test the Uninstall
 * @tc.desc: 1. statusReceiver is nullptr
 *           2. test Uninstall
 */
HWTEST_F(BmsBundleInstallerProxyTest, Uninstall_0300, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    std::string modulePackage = "modulePackage";
    auto res = bundleInstallerProxy.Uninstall(bundleName, modulePackage, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Uninstall_0400
 * @tc.name: test the Uninstall
 * @tc.desc: 1. write parcel failed
 *           2. test Uninstall
 */
HWTEST_F(BmsBundleInstallerProxyTest, Uninstall_0400, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    std::string modulePackage = "modulePackage";
    auto res = bundleInstallerProxy.Uninstall(bundleName, modulePackage, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Uninstall_0500
 * @tc.name: test the Uninstall
 * @tc.desc: 1. statusReceiver is nullptr
 *           2. test Uninstall
 */
HWTEST_F(BmsBundleInstallerProxyTest, Uninstall_0500, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    UninstallParam uninstallParam;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = bundleInstallerProxy.Uninstall(uninstallParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: Uninstall_0600
 * @tc.name: test the Uninstall
 * @tc.desc: 1. write parcel failed
 *           2. test Uninstall
 */
HWTEST_F(BmsBundleInstallerProxyTest, Uninstall_0600, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    UninstallParam uninstallParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    auto res = bundleInstallerProxy.Uninstall(uninstallParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: InstallSandboxApp_0100
 * @tc.name: test the InstallSandboxApp
 * @tc.desc: 1. InstallHmpBundle failed
 *           2. test InstallSandboxApp
 */
HWTEST_F(BmsBundleInstallerProxyTest, InstallSandboxApp_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "";
    int32_t dlpType = 1;
    int32_t userId = 1;
    int32_t appIndex = 1;
    auto res = bundleInstallerProxy.InstallSandboxApp(bundleName, dlpType, userId, appIndex);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_SEND_REQUEST_ERROR);
}

/**
 * @tc.number: UninstallSandboxApp_0100
 * @tc.name: test the UninstallSandboxApp
 * @tc.desc: 1. send request fail
 *           2. test UninstallSandboxApp
 */
HWTEST_F(BmsBundleInstallerProxyTest, UninstallSandboxApp_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    int32_t userId = 1;
    int32_t appIndex = 1;
    auto res = bundleInstallerProxy.UninstallSandboxApp(bundleName, userId, appIndex);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_SEND_REQUEST_ERROR);
}

/**
 * @tc.number: CreateStreamInstaller_0100
 * @tc.name: test the CreateStreamInstaller
 * @tc.desc: 1. receiver is nullptr
 *           2. test CreateStreamInstaller
 */
HWTEST_F(BmsBundleInstallerProxyTest, CreateStreamInstaller_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    std::vector<std::string> originHapPaths;
    auto res = bundleInstallerProxy.CreateStreamInstaller(installParam, statusReceiver, originHapPaths);
    ASSERT_EQ(res, nullptr);
}

/**
 * @tc.number: CreateStreamInstaller_0200
 * @tc.name: test the CreateStreamInstaller
 * @tc.desc: 1. write parcel failed
 *           2. test CreateStreamInstaller
 */
HWTEST_F(BmsBundleInstallerProxyTest, CreateStreamInstaller_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    std::vector<std::string> originHapPaths;
    auto res = bundleInstallerProxy.CreateStreamInstaller(installParam, statusReceiver, originHapPaths);
    ASSERT_EQ(res, nullptr);
}

/**
 * @tc.number: DestoryBundleStreamInstaller_0100
 * @tc.name: test the DestoryBundleStreamInstaller
 * @tc.desc: 1. send request fail
 *           2. test DestoryBundleStreamInstaller
 */
HWTEST_F(BmsBundleInstallerProxyTest, DestoryBundleStreamInstaller_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    uint32_t streamInstallerId = 100;
    auto res = bundleInstallerProxy.DestoryBundleStreamInstaller(streamInstallerId);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: UninstallAndRecover_0100
 * @tc.name: test the UninstallAndRecover
 * @tc.desc: 1. statusReceiver is nullptr
 *           2. test UninstallAndRecover
 */
HWTEST_F(BmsBundleInstallerProxyTest, UninstallAndRecover_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    const sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = bundleInstallerProxy.UninstallAndRecover(bundleName, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: UninstallAndRecover_0200
 * @tc.name: test the UninstallAndRecover
 * @tc.desc: 1. statusReceiver is nullptr
 *           2. write parcel failed
 */
HWTEST_F(BmsBundleInstallerProxyTest, UninstallAndRecover_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    const sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    auto res = bundleInstallerProxy.UninstallAndRecover(bundleName, installParam, statusReceiver);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: StreamInstall_0100
 * @tc.name: test the StreamInstall
 * @tc.desc: 1. nullptr status receiver
 *           2. test StreamInstall
 */
HWTEST_F(BmsBundleInstallerProxyTest, StreamInstall_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.emplace_back(bundleName);
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    const sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = bundleInstallerProxy.StreamInstall(bundleFilePaths, installParam, statusReceiver);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: StreamInstall_0200
 * @tc.name: test the StreamInstall
 * @tc.desc: 1. check file failed
 *           2. test StreamInstall
 */
HWTEST_F(BmsBundleInstallerProxyTest, StreamInstall_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.emplace_back(bundleName);
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    const sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();;
    auto res = bundleInstallerProxy.StreamInstall(bundleFilePaths, installParam, statusReceiver);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: StreamInstall_0300
 * @tc.name: test the StreamInstall
 * @tc.desc: 1. nullptr stream installer
 *           2. test StreamInstall
 */
HWTEST_F(BmsBundleInstallerProxyTest, StreamInstall_0300, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::vector<std::string> bundleFilePaths;
    EXPECT_TRUE(bundleFilePaths.empty());
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = 100;
    const sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();;
    auto res = bundleInstallerProxy.StreamInstall(bundleFilePaths, installParam, statusReceiver);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: WriteFile_0100
 * @tc.name: test the WriteFile
 * @tc.desc: 1. open the hap file
 *           2. test WriteFile
 */
HWTEST_F(BmsBundleInstallerProxyTest, WriteFile_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string path = "path";
    int32_t outputFd = 0;
    auto res = bundleInstallerProxy.WriteFile(path, outputFd);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: WriteFile_0200
 * @tc.name: test the WriteFile
 * @tc.desc: 1. invalid file descriptor
 *           2. test WriteFile
 */
HWTEST_F(BmsBundleInstallerProxyTest, WriteFile_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string path = "/";
    int32_t outputFd = 0;
    auto res = bundleInstallerProxy.WriteFile(path, outputFd);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT);
}

/**
 * @tc.number: WriteHapFileToStream_0100
 * @tc.name: test the WriteHapFileToStream
 * @tc.desc: 1. stream installer nullptr
 *           2. test WriteHapFileToStream
 */
HWTEST_F(BmsBundleInstallerProxyTest, WriteHapFileToStream_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<IBundleStreamInstaller> streamInstaller = nullptr;
    std::string path = "path";
    auto res = bundleInstallerProxy.WriteHapFileToStream(streamInstaller, path);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: WriteHapFileToStream_0200
 * @tc.name: test the WriteHapFileToStream
 * @tc.desc: 1. invalid file descriptor
 *           2. test WriteHapFileToStream
 */
HWTEST_F(BmsBundleInstallerProxyTest, WriteHapFileToStream_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<IBundleStreamInstaller> streamInstaller = iface_cast<IBundleStreamInstaller>(remoteObject);
    std::string path = "/";
    auto res = bundleInstallerProxy.WriteHapFileToStream(streamInstaller, path);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: WriteSignatureFileToStream_0100
 * @tc.name: test the WriteSignatureFileToStream
 * @tc.desc: 1. stream installer nullptr
 *           2. test WriteSignatureFileToStream
 */
HWTEST_F(BmsBundleInstallerProxyTest, WriteSignatureFileToStream_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<IBundleStreamInstaller> streamInstaller = nullptr;
    std::string path = "path";
    std::string moduleName = "moduleName";
    auto res = bundleInstallerProxy.WriteSignatureFileToStream(streamInstaller, path, moduleName);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: WriteSignatureFileToStream_0200
 * @tc.name: test the WriteSignatureFileToStream
 * @tc.desc: 1. invalid file descriptor
 *           2. test WriteSignatureFileToStream
 */
HWTEST_F(BmsBundleInstallerProxyTest, WriteSignatureFileToStream_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<IBundleStreamInstaller> streamInstaller = iface_cast<IBundleStreamInstaller>(remoteObject);
    std::string path = "/";
    std::string moduleName = "moduleName";
    auto res = bundleInstallerProxy.WriteSignatureFileToStream(streamInstaller, path, moduleName);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: WriteSharedFileToStream_0100
 * @tc.name: test the WriteSharedFileToStream
 * @tc.desc: 1. stream installer nullptr
 *           2. test WriteSharedFileToStream
 */
HWTEST_F(BmsBundleInstallerProxyTest, WriteSharedFileToStream_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<IBundleStreamInstaller> streamInstaller = nullptr;
    std::string path = "path";
    uint32_t index = 1;
    auto res = bundleInstallerProxy.WriteSharedFileToStream(streamInstaller, path, index);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: WriteSharedFileToStream_0200
 * @tc.name: test the WriteSharedFileToStream
 * @tc.desc: 1. invalid file descriptor
 *           2. test WriteSharedFileToStream
 */
HWTEST_F(BmsBundleInstallerProxyTest, WriteSharedFileToStream_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<IBundleStreamInstaller> streamInstaller = iface_cast<IBundleStreamInstaller>(remoteObject);
    std::string path = "/";
    uint32_t index = 1;
    auto res = bundleInstallerProxy.WriteSharedFileToStream(streamInstaller, path, index);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: WritePgoFileToStream_0100
 * @tc.name: test the WritePgoFileToStream
 * @tc.desc: 1. stream installer nullptr
 *           2. test WritePgoFileToStream
 */
HWTEST_F(BmsBundleInstallerProxyTest, WritePgoFileToStream_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<IBundleStreamInstaller> streamInstaller = nullptr;
    std::string path = "path";
    std::string moduleName = "moduleName";
    auto res = bundleInstallerProxy.WritePgoFileToStream(streamInstaller, path, moduleName);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: WritePgoFileToStream_0200
 * @tc.name: test the WritePgoFileToStream
 * @tc.desc: 1. invalid file descriptor
 *           2. test WritePgoFileToStream
 */
HWTEST_F(BmsBundleInstallerProxyTest, WritePgoFileToStream_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<IBundleStreamInstaller> streamInstaller = iface_cast<IBundleStreamInstaller>(remoteObject);
    std::string path = "/";
    std::string moduleName = "moduleName";
    auto res = bundleInstallerProxy.WritePgoFileToStream(streamInstaller, path, moduleName);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: CopySignatureFileToService_0100
 * @tc.name: test the CopySignatureFileToService
 * @tc.desc: 1. stream installer nullptr
 *           2. test CopySignatureFileToService
 */
HWTEST_F(BmsBundleInstallerProxyTest, CopySignatureFileToService_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<IBundleStreamInstaller> streamInstaller = nullptr;
    InstallParam installParam;
    auto res = bundleInstallerProxy.CopySignatureFileToService(streamInstaller, installParam);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: CopySignatureFileToService_0200
 * @tc.name: test the CopySignatureFileToService
 * @tc.desc: 1. verifyCodeParams of installParam empty
 *           2. test CopySignatureFileToService
 */
HWTEST_F(BmsBundleInstallerProxyTest, CopySignatureFileToService_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<IBundleStreamInstaller> streamInstaller = iface_cast<IBundleStreamInstaller>(remoteObject);
    InstallParam installParam;
    EXPECT_TRUE(installParam.verifyCodeParams.empty());
    auto res = bundleInstallerProxy.CopySignatureFileToService(streamInstaller, installParam);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CopySignatureFileToService_0300
 * @tc.name: test the CopySignatureFileToService
 * @tc.desc: 1. check filePath signature file failed
 *           2. test CopySignatureFileToService
 */
HWTEST_F(BmsBundleInstallerProxyTest, CopySignatureFileToService_0300, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<IBundleStreamInstaller> streamInstaller = iface_cast<IBundleStreamInstaller>(remoteObject);
    InstallParam installParam;
    std::string testModuleName = "testModuleName";
    installParam.verifyCodeParams.emplace(testModuleName, testModuleName);
    EXPECT_FALSE(installParam.verifyCodeParams.empty());
    auto res = bundleInstallerProxy.CopySignatureFileToService(streamInstaller, installParam);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
}

/**
 * @tc.number: CopyPgoFileToService_0100
 * @tc.name: test the CopyPgoFileToService
 * @tc.desc: 1. stream installer nullptr
 *           2. test CopyPgoFileToService
 */
HWTEST_F(BmsBundleInstallerProxyTest, CopyPgoFileToService_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<IBundleStreamInstaller> streamInstaller = nullptr;
    InstallParam installParam;
    auto res = bundleInstallerProxy.CopyPgoFileToService(streamInstaller, installParam);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: CopyPgoFileToService_0200
 * @tc.name: test the CopyPgoFileToService
 * @tc.desc: 1. pgoParams of installParam empty
 *           2. test CopyPgoFileToService
 */
HWTEST_F(BmsBundleInstallerProxyTest, CopyPgoFileToService_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<IBundleStreamInstaller> streamInstaller = iface_cast<IBundleStreamInstaller>(remoteObject);
    InstallParam installParam;
    EXPECT_TRUE(installParam.pgoParams.empty());
    auto res = bundleInstallerProxy.CopyPgoFileToService(streamInstaller, installParam);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CopyPgoFileToService_0300
 * @tc.name: test the CopyPgoFileToService
 * @tc.desc: 1. system running normally
 *           2. test CopyPgoFileToService
 */
HWTEST_F(BmsBundleInstallerProxyTest, CopyPgoFileToService_0300, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<IBundleStreamInstaller> streamInstaller = iface_cast<IBundleStreamInstaller>(remoteObject);
    InstallParam installParam;
    std::string testModuleName = "testModuleName";
    installParam.pgoParams.emplace(testModuleName, testModuleName);
    EXPECT_FALSE(installParam.pgoParams.empty());
    auto res = bundleInstallerProxy.CopyPgoFileToService(streamInstaller, installParam);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetFileNameByFilePath_0100
 * @tc.name: test the GetFileNameByFilePath
 * @tc.desc: 1. write file to stream failed
 *           2. test GetFileNameByFilePath
 */
HWTEST_F(BmsBundleInstallerProxyTest, GetFileNameByFilePath_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string filePath = "filePath";
    std::string fileName = "fileName";
    auto res = bundleInstallerProxy.GetFileNameByFilePath(filePath, fileName);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: SendInstallRequest_0100
 * @tc.name: test the SendInstallRequest
 * @tc.desc: 1. Remote() is nullptr
 *           2. test SendInstallRequest
 */
HWTEST_F(BmsBundleInstallerProxyTest, SendInstallRequest_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    BundleInstallerInterfaceCode code = BundleInstallerInterfaceCode::INSTALL;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto res = bundleInstallerProxy.SendInstallRequest(code, data, reply, option);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: InstallCloneApp_0100
 * @tc.name: test the InstallCloneApp
 * @tc.desc: 1. send request fail
 *           2. test InstallCloneApp
 */
HWTEST_F(BmsBundleInstallerProxyTest, InstallCloneApp_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    int32_t userId = 100;
    int32_t appIndex = 1;
    auto res = bundleInstallerProxy.InstallCloneApp(bundleName, userId, appIndex);
    EXPECT_EQ(res, ERR_APPEXECFWK_CLONE_INSTALL_SEND_REQUEST_ERROR);
}

/**
 * @tc.number: UninstallCloneApp_0100
 * @tc.name: test the UninstallCloneApp
 * @tc.desc: 1. send request fail
 *           2. test UninstallCloneApp
 */
HWTEST_F(BmsBundleInstallerProxyTest, UninstallCloneApp_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    int32_t userId = 100;
    int32_t appIndex = 1;
    DestroyAppCloneParam destroyAppCloneParam;
    auto res = bundleInstallerProxy.UninstallCloneApp(bundleName, userId, appIndex, destroyAppCloneParam);
    EXPECT_EQ(res, ERR_APPEXECFWK_CLONE_UNINSTALL_SEND_REQUEST_ERROR);
}

/**
 * @tc.number: InstallExisted_0100
 * @tc.name: test the InstallExisted
 * @tc.desc: 1. send request fail
 *           2. test InstallExisted
 */
HWTEST_F(BmsBundleInstallerProxyTest, InstallExisted_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string bundleName = "bundleName";
    int32_t userId = 100;
    auto res = bundleInstallerProxy.InstallExisted(bundleName, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_EXISTED_WRITE_PARCEL_ERROR);
}

/**
 * @tc.number: InstallPlugin_0100
 * @tc.name: test the InstallPlugin
 * @tc.desc: 1. send request fail
 *           2. test InstallPlugin
 */
HWTEST_F(BmsBundleInstallerProxyTest, InstallPlugin_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string hostBundleName = "bundleName";
    InstallPluginParam installPluginParam;
    installPluginParam.userId = 100;
    std::vector<std::string> pluginFilePaths;
    pluginFilePaths.emplace_back("bundlePath");
    auto res = bundleInstallerProxy.InstallPlugin(hostBundleName, pluginFilePaths, installPluginParam);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: UninstallPlugin_0100
 * @tc.name: test the UninstallPlugin
 * @tc.desc: 1. send request fail
 *           2. test UninstallPlugin
 */
HWTEST_F(BmsBundleInstallerProxyTest, UninstallPlugin_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleInstallerProxy bundleInstallerProxy(object);
    std::string hostBundleName = "bundleName";
    InstallPluginParam installPluginParam;
    installPluginParam.userId = 100;
    std::string pluginBundleName = "pluginName";
    auto res = bundleInstallerProxy.UninstallPlugin(hostBundleName, pluginBundleName, installPluginParam);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}
}
}