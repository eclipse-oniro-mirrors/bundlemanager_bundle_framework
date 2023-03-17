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

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {

const std::string MODULE_FILE_PATH = "/data/test/resource/bms/sharelibrary/";
const std::string HOST_HAP = "host_hap.hap";
const std::string HOST2_HAP = "host2_hap.hap";
const std::string LIBA_V10000 = "libA_v10000.hsp";
const std::string LIBA_V10001 = "libA_v10001.hsp";
const std::string LIBA_V10002 = "libA_v10002.hsp";
const std::string LIBA_NORMAL_HAP = "libA_normal_hap.hap";
const std::string LIBA_WITHOUT_PROVISION = "libA_without_provision.hsp";
const std::string LIBB_V10001 = "libB_v10001.hsp";
const std::string BUNDLE_NAME_1 = "com.example.host";
const std::string BUNDLE_NAME_2 = "com.example.host2";
const std::string SHARED_BUNDLE_NAME_A = "com.example.liba";
const std::string SHARED_BUNDLE_NAME_B = "com.example.libb";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms

class BmsBundleSharedLibraryInstallTest : public testing::Test {
public:
    BmsBundleSharedLibraryInstallTest();
    ~BmsBundleSharedLibraryInstallTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void StartInstalldService() const;
    void StartBundleService();
    ErrCode InstallBundle(const std::vector<std::string> &bundleFilePaths,
        const std::vector<std::string> &sharedBundlePaths) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    ErrCode UninstallSharedBundle(const std::string &bundleName) const;
private:
    std::shared_ptr<InstalldService> installdService_;
    std::shared_ptr<BundleMgrService> bundleMgrService_;
};

BmsBundleSharedLibraryInstallTest::BmsBundleSharedLibraryInstallTest()
{
    installdService_ = std::make_shared<InstalldService>();
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
}

BmsBundleSharedLibraryInstallTest::~BmsBundleSharedLibraryInstallTest()
{}

void BmsBundleSharedLibraryInstallTest::SetUpTestCase()
{}

void BmsBundleSharedLibraryInstallTest::TearDownTestCase()
{}

void BmsBundleSharedLibraryInstallTest::SetUp()
{
    StartBundleService();
    StartInstalldService();
}

void BmsBundleSharedLibraryInstallTest::TearDown()
{}

void BmsBundleSharedLibraryInstallTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleSharedLibraryInstallTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

ErrCode BmsBundleSharedLibraryInstallTest::InstallBundle(const std::vector<std::string> &bundleFilePaths,
    const std::vector<std::string> &sharedBundlePaths) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    installParam.sharedBundleDirPaths = sharedBundlePaths;
    bool result = installer->Install(bundleFilePaths, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleSharedLibraryInstallTest::UnInstallBundle(const std::string &bundleName) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleSharedLibraryInstallTest::UninstallSharedBundle(const std::string &bundleName) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    UninstallParam uninstallParam;
    uninstallParam.bundleName = bundleName;
    bool result = installer->Uninstall(uninstallParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallPriviledge_0100
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, the hsp has AllowAppShareLibrary priviledge
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallPriviledge_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallPriviledge_0200
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, the hsp has no AllowAppShareLibrary priviledge
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallPriviledge_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_WITHOUT_PROVISION};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallCompatible_0100
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, upgrade the shared bundle to normal hap
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallCompatible_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    sharedBundlePaths = {MODULE_FILE_PATH + LIBA_NORMAL_HAP};
    installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_COMPATIBLE_POLICY_NOT_SAME);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallCompatible_0200
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, upgrade the normal hap to shared bundle
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallCompatible_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{MODULE_FILE_PATH + LIBA_NORMAL_HAP};
    std::vector<std::string> sharedBundlePaths{};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    bundleFilePaths = {};
    sharedBundlePaths = {MODULE_FILE_PATH + LIBA_V10001};
    installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_COMPATIBLE_POLICY_NOT_SAME);

    ErrCode unInstallResult = UnInstallBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallParam_0100
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install without input paths
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallParam_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallParam_0200
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install hsp with -p
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallParam_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{MODULE_FILE_PATH + LIBA_V10001};
    std::vector<std::string> sharedBundlePaths{};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_FILE_IS_SHARED_LIBRARY);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallParam_0300
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install hap with -s
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallParam_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_NORMAL_HAP};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallParam_0400
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install two shared bundles
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallParam_0400, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001, MODULE_FILE_PATH + LIBB_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
    unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_B);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallVersion_0100
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, upgrade to higher version
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallVersion_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    sharedBundlePaths = {MODULE_FILE_PATH + LIBA_V10002};
    installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallVersion_0200
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, upgrade to same version
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallVersion_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    sharedBundlePaths = {MODULE_FILE_PATH + LIBA_V10001};
    installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallVersion_0300
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, upgrade to lower version
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallVersion_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    sharedBundlePaths = {MODULE_FILE_PATH + LIBA_V10000};
    installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallDependency_0100
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install shared bundle together
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallDependency_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{MODULE_FILE_PATH + HOST_HAP};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(unInstallResult, ERR_OK);
    unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallDependency_0200
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install host only
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallDependency_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{MODULE_FILE_PATH + HOST_HAP};
    std::vector<std::string> sharedBundlePaths{};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallDependency_0300
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install hsp and hap seperately
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallDependency_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    bundleFilePaths = {MODULE_FILE_PATH + HOST_HAP};
    sharedBundlePaths = {};
    installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(unInstallResult, ERR_OK);
    unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallDependency_0400
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, hap dependent on two shared bundles
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallDependency_0400, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{MODULE_FILE_PATH + HOST2_HAP};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001, MODULE_FILE_PATH + LIBB_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_2);
    EXPECT_EQ(unInstallResult, ERR_OK);
    unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
    unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_B);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallDependency_0500
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, hap dependent on two shared bundles, one of them is not installed
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallDependency_0500, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{MODULE_FILE_PATH + HOST2_HAP};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallDependency_0600
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, hap dependent on two shared bundles, one of them is already installed
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallDependency_0600, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    bundleFilePaths = {MODULE_FILE_PATH + HOST2_HAP};
    sharedBundlePaths = {MODULE_FILE_PATH + LIBB_V10001};
    installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_2);
    EXPECT_EQ(unInstallResult, ERR_OK);
    unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
    unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_B);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallDependency_0700
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install higher version dependency
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallDependency_0700, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{MODULE_FILE_PATH + HOST_HAP};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10002};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(unInstallResult, ERR_OK);
    unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryInstallDependency_0800
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install lower version dependency
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, BmsBundleSharedLibraryInstallDependency_0800, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{MODULE_FILE_PATH + HOST_HAP};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10000};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
}
}
}