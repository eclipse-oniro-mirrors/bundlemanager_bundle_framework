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
#include "permission_define.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.bmsgrantpermission";
const std::string HAP_FILE_PATH = "/data/test/resource/bms/permission_bundle/";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 2; // init mocked bms

// --- SPM ON install prerequisite -------------------------------------------
// The suite keeps the SPM switch ON (the device default, see
// BundleSpmManager::IsEnabled) and solves the hap sign verification
// positively: the mocked access-token boundary is fed the per-hap data the
// real AT side would return for the installed haps, so every install runs
// the complete SPM ON chain. The provisions are minimal valid release
// profiles — release skips the developer-mode gate of CheckDeveloperMode
// that a debug provision would have to pass, keeping the suite independent
// of the developer-mode parameter state. Each provision's bundle-name must
// stay in sync with BUNDLE_NAME (CheckBundleName cross-checks the provision
// against the hap's package name).
constexpr int32_t TEST_SPM_SESSION_ID = 4242;
constexpr uint64_t TEST_SPM_TOKEN_ID = 101;
// InitToken rejects a uid outside the installing user's uid segment, so the
// AT-allocated identity must be valid for USERID.
constexpr int32_t TEST_SPM_UID = USERID * Constants::BASE_USER_RANGE + 102;

void SetUpSpmTrustedSignInfoForTest()
{
    const std::string provision =
        Security::AccessToken::MakeSpmReleaseProvisionRawForTest(BUNDLE_NAME, "app_gallery");
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest("bmsGrantPermission1.hap", provision);
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest("bmsGrantPermission3.hap", provision);
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest("bmsGrantPermission4.hap", provision);
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest("bmsGrantPermission6.hap", provision);
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest("bmsGrantPermission7.hap", provision);
    Security::AccessToken::SetSpmCheckHapSignInfoSessionIdForTest(TEST_SPM_SESSION_ID);
    Security::AccessToken::SetSpmPrepareIdentityForTest(TEST_SPM_TOKEN_ID, TEST_SPM_UID);
}
}  // namespace

class BmsBundlePermissionGrantTest : public testing::Test {
public:
    BmsBundlePermissionGrantTest();
    ~BmsBundlePermissionGrantTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundlePermissionGrantTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundlePermissionGrantTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundlePermissionGrantTest::BmsBundlePermissionGrantTest()
{}

BmsBundlePermissionGrantTest::~BmsBundlePermissionGrantTest()
{}

void BmsBundlePermissionGrantTest::SetUpTestCase()
{
    SetUpSpmTrustedSignInfoForTest();
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    bundleMgrService_->GetDataMgr()->LoadDataFromPersistentStorage();
}

void BmsBundlePermissionGrantTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundlePermissionGrantTest::SetUp()
{
    StartInstalldService();
}

void BmsBundlePermissionGrantTest::TearDown()
{}

ErrCode BmsBundlePermissionGrantTest::InstallBundle(const std::string &bundlePath) const
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
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundlePermissionGrantTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundlePermissionGrantTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundlePermissionGrantTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundlePermissionGrantTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: BmsBundlePermissionGrantTest
 * Function: Install
 * @tc.name: test install a hap with normal permission and normal apl
 * @tc.desc: 1. system running normally
 *           2. install a hap with normal permission and normal apl
 *           3. install succeed
 */
HWTEST_F(BmsBundlePermissionGrantTest, BmsBundlePermissionGrantTest_0100, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + "bmsGrantPermission1.hap");
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundlePermissionGrantTest
 * Function: Install
 * @tc.name: test install a hap with system_bacic/system_core permission and normal apl
 * @tc.desc: 1. system running normally
 *           2. install a hap, the request permission exists in acls
 *           3. install succeed
 */
HWTEST_F(BmsBundlePermissionGrantTest, BmsBundlePermissionGrantTest_0300, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + "bmsGrantPermission3.hap");
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundlePermissionGrantTest
 * Function: Install
 * @tc.name: test install a hap with system_basic/normal permission and system_basic apl
 * @tc.desc: 1. system running normally
 *           2. install a hap
 *           3. install succeed
 */
HWTEST_F(BmsBundlePermissionGrantTest, BmsBundlePermissionGrantTest_0400, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + "bmsGrantPermission4.hap");
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundlePermissionGrantTest
 * Function: Install
 * @tc.name: test install a hap with system_core permission and system_basic apl
 * @tc.desc: 1. system running normally
 *           2. install a hap, the request permission exists in acls
 *           3. install succeed
 */
HWTEST_F(BmsBundlePermissionGrantTest, BmsBundlePermissionGrantTest_0600, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + "bmsGrantPermission6.hap");
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundlePermissionGrantTest
 * Function: Install
 * @tc.name: test install a hap with normal/system_basic/system_core permission and system_core apl
 * @tc.desc: 1. system running normally
 *           2. install a hap
 *           3. install succeed
 */
HWTEST_F(BmsBundlePermissionGrantTest, BmsBundlePermissionGrantTest_0700, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + "bmsGrantPermission7.hap");
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundlePermissionGrantTest
 * Function: ProcessPreload
 * @tc.name: test ProcessPreload verify success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionGrantTest, BmsBundlePermissionGrantTest_0800, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl_ = std::make_unique<BundleMgrHostImpl>();
    OHOS::AAFwk::Want want;
    auto ret = bundleMgrHostImpl_->ProcessPreload(want);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBundlePermissionGrantTest
 * Function: GetBundleInfoForSelf
 * @tc.name: test ProcessPreload verify success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionGrantTest, BmsBundlePermissionGrantTest_0900, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl_ = std::make_unique<BundleMgrHostImpl>();
    BundleInfo bundleInfo;
    auto ret = bundleMgrHostImpl_->GetBundleInfoForSelf(
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT), bundleInfo);
    EXPECT_TRUE(ret);
}
} // OHOS