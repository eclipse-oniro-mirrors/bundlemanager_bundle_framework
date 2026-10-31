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
#define protected public

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "accesstoken_kit.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "parameters.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {

const std::string MODULE_FILE_PATH = "/data/test/resource/bms/sharelibrary/";
const std::string HOST_HAP = "host_hap.hap";
const std::string LIBA_V10001 = "libA_v10001.hsp";
const std::string LIBA_V10002 = "libA_v10002.hsp";
const std::string BUNDLE_NAME = "com.example.host";
const std::string SHARED_BUNDLE_NAME = "com.example.liba";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 2; // init mocked bms

// --- SPM ON install prerequisite -------------------------------------------
// The suite keeps the SPM switch ON (the device default, see
// BundleSpmManager::IsEnabled) and solves the hap sign verification
// positively: the mocked access-token boundary is fed the per-hap data the
// real AT side would return for the installed haps, so every install runs
// the complete SPM ON chain. An install bundles the host hap with the liba
// hsp files (two different packages), so the per-hap-file registry answers
// with one entry per hap path of each install, matched per file and in that
// install's order. Each provision's bundle-name must stay in sync with the
// hap's package name (CheckBundleName cross-checks them).
constexpr int32_t TEST_SPM_SESSION_ID = 4242;
constexpr uint64_t TEST_SPM_TOKEN_ID = 101;
// InitToken rejects a uid outside the installing user's uid segment, so the
// AT-allocated identity must be valid for USERID.
constexpr int32_t TEST_SPM_UID = USERID * Constants::BASE_USER_RANGE + 102;

void SetUpSpmTrustedSignInfoForTest()
{
    // The provisions mirror the profiles the haps are actually signed with
    // (host: sceneProject/signature/com.example.host.p7b, libA:
    // bundle_share_library/libA_v1000x/signature/com.example.liba.p7b):
    // both are "type": "release" + "app-distribution-type": "os_integration".
    // A release/os_integration provision skips the debug/enterprise branch of
    // InnerSharedBundleInstaller::DeliveryProfileToCodeSign (which requires
    // the AT-side signed profile block), exactly like the SPM OFF installs.
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest(HOST_HAP,
        Security::AccessToken::MakeSpmReleaseProvisionRawForTest(BUNDLE_NAME, "os_integration"));
    // libA hsp files are cross-app shared bundles (bundleType SHARED); their
    // provision must carry the AllowAppShareLibrary privilege (the real liba
    // p7b has it top-level), otherwise ProcessBundleInfoByPrivilegeCapability
    // rejects with 8519731.
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest(LIBA_V10001,
        Security::AccessToken::MakeSpmReleaseProvisionRawForTest(SHARED_BUNDLE_NAME,
            "os_integration", true));
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest(LIBA_V10002,
        Security::AccessToken::MakeSpmReleaseProvisionRawForTest(SHARED_BUNDLE_NAME,
            "os_integration", true));
    Security::AccessToken::SetSpmCheckHapSignInfoSessionIdForTest(TEST_SPM_SESSION_ID);
    Security::AccessToken::SetSpmPrepareIdentityForTest(TEST_SPM_TOKEN_ID, TEST_SPM_UID);
    // The mock parameter map makes const.bms.supportAppTypes read empty (on a
    // real device it is a non-empty device-type list): these sharelibrary
    // haps are old-toolchain products whose deviceTypes miss the running
    // device's entry, so CheckSysCap fails and the install drops into
    // CheckDeviceType, where only the non-empty supportAppTypes fast path
    // (the device behavior) lets them through — mirror a full device-type
    // list so every non-empty hap deviceTypes vector intersects it.
    OHOS::system::SetParameter("const.bms.supportAppTypes", "default,phone,tablet,2in1");
}

class BmsBundleSharedLibraryUninstallTest : public testing::Test {
public:
    BmsBundleSharedLibraryUninstallTest();
    ~BmsBundleSharedLibraryUninstallTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void StartInstalldService() const;
    void StartBundleService();
    ErrCode InstallBundle(const std::vector<std::string> &bundleFilePaths,
        const std::vector<std::string> &sharedBundlePaths) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    ErrCode UninstallShred(const UninstallParam &uninstallParam) const;
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleSharedLibraryUninstallTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleSharedLibraryUninstallTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleSharedLibraryUninstallTest::BmsBundleSharedLibraryUninstallTest()
{
    installdService_ = std::make_shared<InstalldService>();
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
}

BmsBundleSharedLibraryUninstallTest::~BmsBundleSharedLibraryUninstallTest()
{}

void BmsBundleSharedLibraryUninstallTest::SetUpTestCase()
{
    SetUpSpmTrustedSignInfoForTest();
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    bundleMgrService_->GetDataMgr()->LoadDataFromPersistentStorage();
}

void BmsBundleSharedLibraryUninstallTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleSharedLibraryUninstallTest::SetUp()
{
    StartInstalldService();
}

void BmsBundleSharedLibraryUninstallTest::TearDown()
{}

void BmsBundleSharedLibraryUninstallTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleSharedLibraryUninstallTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

ErrCode BmsBundleSharedLibraryUninstallTest::InstallBundle(const std::vector<std::string> &bundleFilePaths,
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

ErrCode BmsBundleSharedLibraryUninstallTest::UnInstallBundle(const std::string &bundleName) const
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

ErrCode BmsBundleSharedLibraryUninstallTest::UninstallShred(const UninstallParam &uninstallParam) const
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
    bool result = installer->Uninstall(uninstallParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

/**
 * @tc.number: BmsBundleSharedLibraryUninstall_0100
 * @tc.name: BmsBundleSharedLibraryUninstall
 * @tc.desc: test uninstall shared library
 */
HWTEST_F(BmsBundleSharedLibraryUninstallTest, BmsBundleSharedLibraryUninstall_0100, Function | SmallTest | Level0)
{
    std::string hostPath = MODULE_FILE_PATH + HOST_HAP;
    std::string hspv1 = MODULE_FILE_PATH + LIBA_V10001;
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.push_back(hostPath);
    std::vector<std::string> sharedBundleDirPaths;
    sharedBundleDirPaths.push_back(hspv1);
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundleDirPaths);
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
    UninstallParam uninstallParam;
    uninstallParam.bundleName = SHARED_BUNDLE_NAME;
    unInstallResult = UninstallShred(uninstallParam);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSharedLibraryUninstall_0200
 * @tc.name: BmsBundleSharedLibraryUninstall
 * @tc.desc: test uninstall shared library for multiple version
 */
#ifndef BMS_X86_64_VIRT_SKIP_TESTS
HWTEST_F(BmsBundleSharedLibraryUninstallTest, BmsBundleSharedLibraryUninstall_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);
    sharedBundlePaths = {MODULE_FILE_PATH + LIBA_V10002};
    installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    UninstallParam uninstallParam;
    uninstallParam.bundleName = SHARED_BUNDLE_NAME;
    ErrCode unInstallResult = UninstallShred(uninstallParam);
    EXPECT_EQ(unInstallResult, ERR_OK);
}
#endif

/**
 * @tc.number: BmsBundleSharedLibraryUninstall_0300
 * @tc.name: BmsBundleSharedLibraryUninstall
 * @tc.desc: test uninstall shared library for lower Version
 */
#ifndef BMS_X86_64_VIRT_SKIP_TESTS
HWTEST_F(BmsBundleSharedLibraryUninstallTest, BmsBundleSharedLibraryUninstall_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFilePaths{};
    std::vector<std::string> sharedBundlePaths{MODULE_FILE_PATH + LIBA_V10001};
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    sharedBundlePaths = {MODULE_FILE_PATH + LIBA_V10002};
    installResult = InstallBundle(bundleFilePaths, sharedBundlePaths);
    EXPECT_EQ(installResult, ERR_OK);

    UninstallParam uninstallParam;
    uninstallParam.bundleName = SHARED_BUNDLE_NAME;
    uninstallParam.versionCode = 10001;
    ErrCode unInstallResult = UninstallShred(uninstallParam);
    EXPECT_EQ(unInstallResult, ERR_OK);

    uninstallParam.versionCode = Constants::ALL_VERSIONCODE;
    unInstallResult = UninstallShred(uninstallParam);
    EXPECT_EQ(unInstallResult, ERR_OK);
}
#endif

/**
 * @tc.number: BmsBundleSharedLibraryUninstall_0400
 * @tc.name: BmsBundleSharedLibraryUninstall
 * @tc.desc: test uninstall highest version of shared library when hsp is relied
 */
#ifndef BMS_X86_64_VIRT_SKIP_TESTS
HWTEST_F(BmsBundleSharedLibraryUninstallTest, BmsBundleSharedLibraryUninstall_0400, Function | SmallTest | Level0)
{
    std::string hostPath = MODULE_FILE_PATH + HOST_HAP;
    std::string hspv1 = MODULE_FILE_PATH + LIBA_V10001;
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.push_back(hostPath);
    std::vector<std::string> sharedBundleDirPaths;
    sharedBundleDirPaths.push_back(hspv1);
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundleDirPaths);

    bundleFilePaths = {};
    sharedBundleDirPaths = {MODULE_FILE_PATH + LIBA_V10002};
    installResult = InstallBundle(bundleFilePaths, sharedBundleDirPaths);
    EXPECT_EQ(installResult, ERR_OK);

    UninstallParam uninstallParam;
    uninstallParam.bundleName = SHARED_BUNDLE_NAME;
    uninstallParam.versionCode = 10002;
    ErrCode unInstallResult = UninstallShred(uninstallParam);
    EXPECT_EQ(unInstallResult, ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_RELIED);

    unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
    uninstallParam.bundleName = SHARED_BUNDLE_NAME;
    uninstallParam.versionCode = Constants::ALL_VERSIONCODE;
    unInstallResult = UninstallShred(uninstallParam);
    EXPECT_EQ(unInstallResult, ERR_OK);
}
#endif

/**
 * @tc.number: BmsBundleSharedLibraryUninstall_0500
 * @tc.name: BmsBundleSharedLibraryUninstall
 * @tc.desc: test uninstall lower version of shared library when hsp is relied
 */
#ifndef BMS_X86_64_VIRT_SKIP_TESTS
HWTEST_F(BmsBundleSharedLibraryUninstallTest, BmsBundleSharedLibraryUninstall_0500, Function | SmallTest | Level0)
{
    std::string hostPath = MODULE_FILE_PATH + HOST_HAP;
    std::string hspv1 = MODULE_FILE_PATH + LIBA_V10001;
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.push_back(hostPath);
    std::vector<std::string> sharedBundleDirPaths;
    sharedBundleDirPaths.push_back(hspv1);
    ErrCode installResult = InstallBundle(bundleFilePaths, sharedBundleDirPaths);

    bundleFilePaths = {};
    sharedBundleDirPaths = {MODULE_FILE_PATH + LIBA_V10002};
    installResult = InstallBundle(bundleFilePaths, sharedBundleDirPaths);
    EXPECT_EQ(installResult, ERR_OK);

    UninstallParam uninstallParam;
    uninstallParam.bundleName = SHARED_BUNDLE_NAME;
    uninstallParam.versionCode = 10001;
    ErrCode unInstallResult = UninstallShred(uninstallParam);
    EXPECT_EQ(unInstallResult, ERR_OK);

    unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
    uninstallParam.bundleName = SHARED_BUNDLE_NAME;
    uninstallParam.versionCode = Constants::ALL_VERSIONCODE;
    unInstallResult = UninstallShred(uninstallParam);
    EXPECT_EQ(unInstallResult, ERR_OK);
}
#endif

}
}