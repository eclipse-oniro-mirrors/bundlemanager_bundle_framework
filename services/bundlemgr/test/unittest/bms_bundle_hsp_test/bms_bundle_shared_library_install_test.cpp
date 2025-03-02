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
#define private public

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "app_provision_info_manager.h"
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
const std::string MOUDLE_PACK_AGE = "modulePackage";
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
    ErrCode InstallBundle(const std::vector<std::string> &bundleFilePaths,
        const InstallParam &installParam) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    ErrCode UninstallSharedBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleSharedLibraryInstallTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleSharedLibraryInstallTest::installdService_ =
    std::make_shared<InstalldService>();

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
{
    bundleMgrService_->OnStop();
}

void BmsBundleSharedLibraryInstallTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
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
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleSharedLibraryInstallTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
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
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundleFilePaths, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleSharedLibraryInstallTest::InstallBundle(const std::vector<std::string> &bundleFilePaths,
    const InstallParam &installParam) const
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
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);

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
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
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

/**
 * @tc.number: GetSpecifiedDistributionType_0010
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install hsp
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetSpecifiedDistributionType_0010, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.specifiedDistributionType = "specifiedDistributionType";
    installParam.additionalInfo = "additionalInfo";
    installParam.sharedBundleDirPaths = sharedBundlePaths;
    ErrCode installResult = InstallBundle(bundleFilePaths, installParam);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    if (!dataMgr) {
        EXPECT_NE(dataMgr, nullptr);
    } else {
        std::string specifiedDistributionType;
        auto ret = dataMgr->GetSpecifiedDistributionType(SHARED_BUNDLE_NAME_A, specifiedDistributionType);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_EQ(installParam.specifiedDistributionType, specifiedDistributionType);

        std::string additionalInfo;
        ret = dataMgr->GetAdditionalInfo(SHARED_BUNDLE_NAME_A, additionalInfo);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_EQ(installParam.additionalInfo, additionalInfo);
    }

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetAppProvisionInfo_0001
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, install hsp
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetAppProvisionInfo_0001, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    AppProvisionInfo appProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(SHARED_BUNDLE_NAME_A,
        appProvisionInfo);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(appProvisionInfo.apl.empty());

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);

    AppProvisionInfo newAppProvisionInfo;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(SHARED_BUNDLE_NAME_A,
        newAppProvisionInfo);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(newAppProvisionInfo.apl.empty());
}

/**
 * @tc.number: ProcessBundleUninstall_0100
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, the hsp has AllowAppShareLibrary priviledge
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, ProcessBundleUninstall_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    int32_t uid = USERID;

    auto res = installer.ProcessBundleUninstall(SHARED_BUNDLE_NAME_A, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_IS_SHARED_LIBRARY);

    res = installer.ProcessBundleUninstall(SHARED_BUNDLE_NAME_A, MOUDLE_PACK_AGE, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_IS_SHARED_LIBRARY);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: ProcessBundleUninstall_0100
 * @tc.name: BmsBundleSharedLibraryInstall
 * @tc.desc: test install, the hsp has AllowAppShareLibrary priviledge
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, ProcessBundleUninstall_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    int32_t uid = USERID;
    auto res = installer.InnerProcessInstallByPreInstallInfo(SHARED_BUNDLE_NAME_A, installParam, uid);
    EXPECT_EQ(res, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetSharedBundleInfoBySelf_0100
 * @tc.name: test GetSharedBundleInfoBySelf
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetSharedBundleInfoBySelf_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    SharedBundleInfo sharedBundleInfo;
    ErrCode res = GetBundleDataMgr()->GetSharedBundleInfoBySelf(
        SHARED_BUNDLE_NAME_A, sharedBundleInfo);
    EXPECT_EQ(res, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetBaseSharedBundleInfo_0100
 * @tc.name: test GetBaseSharedBundleInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetBaseSharedBundleInfo_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    Dependency dependency;
    BaseSharedBundleInfo baseSharedBundleInfo;
    dependency.bundleName = SHARED_BUNDLE_NAME_A;
    bool res = GetBundleDataMgr()->GetBaseSharedBundleInfo(
        dependency, baseSharedBundleInfo);
    EXPECT_EQ(res, true);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetBundleInfos_0100
 * @tc.name: test GetBundleInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetBundleInfos_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    int32_t flags = 0;
    std::vector<BundleInfo> bundleInfos;
    bool res = GetBundleDataMgr()->GetBundleInfos(
        flags, bundleInfos, USERID);
    EXPECT_EQ(res, true);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetAllBundleInfos_0100
 * @tc.name: test GetAllBundleInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetAllBundleInfos_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    int32_t flags = 0;
    std::vector<BundleInfo> bundleInfos;
    bool res = GetBundleDataMgr()->GetAllBundleInfos(
        flags, bundleInfos);
    EXPECT_EQ(res, true);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetBundleInfosV9_0100
 * @tc.name: test GetBundleInfosV9
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetBundleInfosV9_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    int32_t flags = 0;
    std::vector<BundleInfo> bundleInfos;
    ErrCode res = GetBundleDataMgr()->GetBundleInfosV9(
        flags, bundleInfos, USERID);
    EXPECT_EQ(res, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetAllBundleInfosV9_0100
 * @tc.name: test GetAllBundleInfosV9
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetAllBundleInfosV9_0100, Function | SmallTest | Level2)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<BundleInfo> bundleInfos;
    ErrCode res = GetBundleDataMgr()->GetAllBundleInfosV9(
        0, bundleInfos);
    EXPECT_EQ(res, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetAppProvisionInfo_0100
 * @tc.name: test GetAllBundleInfosV9
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetAppProvisionInfo_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    int32_t flags = 0;
    AppProvisionInfo appProvisionInfo;
    ErrCode res = GetBundleDataMgr()->GetAppProvisionInfo(SHARED_BUNDLE_NAME_A,
        flags, appProvisionInfo);
    EXPECT_EQ(res, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetAllSharedBundleInfo_0100
 * @tc.name: test GetAllSharedBundleInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetAllSharedBundleInfo_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode res = GetBundleDataMgr()->GetAllSharedBundleInfo(sharedBundles);
    EXPECT_EQ(res, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetSpecifiedDistributionType_0100
 * @tc.name: test GetSpecifiedDistributionType
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetSpecifiedDistributionType_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    std::string specifiedDistributionType = "";
    ErrCode res = GetBundleDataMgr()->GetSpecifiedDistributionType(SHARED_BUNDLE_NAME_A, specifiedDistributionType);
    EXPECT_EQ(res, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: GetAdditionalInfo_0100
 * @tc.name: test GetAdditionalInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleSharedLibraryInstallTest, GetAdditionalInfo_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    std::string additionalInfo = "";
    ErrCode res = GetBundleDataMgr()->GetAdditionalInfo(SHARED_BUNDLE_NAME_A, additionalInfo);
    EXPECT_EQ(res, ERR_OK);

    ErrCode unInstallResult = UninstallSharedBundle(SHARED_BUNDLE_NAME_A);
    EXPECT_EQ(unInstallResult, ERR_OK);
}
}
}