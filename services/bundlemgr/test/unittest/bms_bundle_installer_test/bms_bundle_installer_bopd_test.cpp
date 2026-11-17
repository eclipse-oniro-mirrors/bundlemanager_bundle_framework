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

#define private public
#define protected public
#include <gtest/gtest.h>

#include "bundle_installer.h"
#include "bundle_mgr_service.h"
#include "system_bundle_installer.h"
#undef protected
#undef private

#include <chrono>
#include <thread>

#include "appexecfwk_errors.h"
#include "bundle_multiuser_installer.h"
#include "clone/bundle_clone_installer.h"
#include "inner_shared_bundle_installer.h"
#include "installd/installd_service.h"
#include "mock_status_receiver.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BOPD_MODE_PARAM = "ohos.boot.bopd.mode";
const std::string VALID_BOPD_MODE = "0x2";
// SPM switch: IsEnabled() caches a function-local static on first call; pin it
// OFF before any install so CheckSignAndInitSession takes the non-SPM path
// (BundleInstallChecker::CheckMultipleHapsSignInfo -> libhapverify), which works
// with the real libbegetutil linked by this target. Left ON (the default),
// the mocked CheckHapSignInfo answers with empty trustedBundleInfos and the
// size-mismatch guard returns ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE.
const std::string SPM_ENABLE_PARAM = "persist.bms.spm.enable";
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/install_bundle/";
// signed with provision app-feature hos_normal_app, actual third party app
const std::string THIRD_PARTY_HAP = RESOURCE_ROOT_PATH + "moduleJsonTest.hap";
const std::string THIRD_PARTY_BUNDLE_NAME = "com.test.modulejsontest";
// signed with provision app-feature hos_system_app, actual system app
const std::string SYSTEM_HAP = RESOURCE_ROOT_PATH + "system_module.hap";
const std::string SYSTEM_BUNDLE_NAME = "com.query.test";
const std::string HSP_RESOURCE_ROOT_PATH = "/data/test/resource/bms/sharelibrary/";
// signed with provision app-feature hos_normal_app, actual third party shared bundle
const std::string THIRD_PARTY_HSP = HSP_RESOURCE_ROOT_PATH + "libA_v10001.hsp";
const std::string THIRD_PARTY_HSP_BUNDLE_NAME = "com.example.liba";
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundleInstallerBopdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallThirdPartyBundle(const std::string &bundlePath) const;
    ErrCode InstallBundleAsSystemApp(const std::string &bundlePath) const;
    ErrCode InstallSharedBundle(const std::string &sharedBundlePath) const;
    ErrCode InstallExistedAppAsMultiUser(const std::string &bundleName, int32_t userId) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;
    ErrCode UninstallSharedBundle(const std::string &bundleName) const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<InstalldService> BmsBundleInstallerBopdTest::installdService_ =
    std::make_shared<InstalldService>();
std::shared_ptr<BundleMgrService> BmsBundleInstallerBopdTest::bundleMgrService_ = nullptr;

void BmsBundleInstallerBopdTest::SetUpTestCase()
{
    // Pin SPM OFF for this process before any install touches IsEnabled().
    OHOS::system::SetParameter(SPM_ENABLE_PARAM, "false");
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
}

void BmsBundleInstallerBopdTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
    sleep(1);
    bundleMgrService_ = nullptr;
    DelayedSingleton<BundleMgrService>::DestroyInstance();
}

void BmsBundleInstallerBopdTest::SetUp()
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "");
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(Constants::START_USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    UninstallBundle(THIRD_PARTY_BUNDLE_NAME);
    UninstallBundle(SYSTEM_BUNDLE_NAME);
}

void BmsBundleInstallerBopdTest::TearDown()
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "");
}

ErrCode BmsBundleInstallerBopdTest::InstallThirdPartyBundle(const std::string &bundlePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(Constants::START_USERID);
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (receiver == nullptr) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.userId = Constants::START_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.withCopyHaps = true;
    installer->Install(bundlePath, installParam, receiver);
    return receiver->GetResultCode();
}

ErrCode BmsBundleInstallerBopdTest::InstallBundleAsSystemApp(const std::string &bundlePath) const
{
    SystemBundleInstaller installer;
    InstallParam installParam;
    installParam.userId = Constants::START_USERID;
    installParam.needSendEvent = false;
    return installer.InstallBundle(bundlePath, installParam, Constants::AppType::SYSTEM_APP);
}

ErrCode BmsBundleInstallerBopdTest::InstallSharedBundle(const std::string &sharedBundlePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(Constants::START_USERID);
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (receiver == nullptr) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.userId = Constants::START_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.withCopyHaps = true;
    installParam.sharedBundleDirPaths = { sharedBundlePath };
    std::vector<std::string> bundleFilePaths;
    installer->Install(bundleFilePaths, installParam, receiver);
    return receiver->GetResultCode();
}

ErrCode BmsBundleInstallerBopdTest::InstallExistedAppAsMultiUser(const std::string &bundleName, int32_t userId) const
{
    BundleMultiUserInstaller installer;
    return installer.InstallExistedApp(bundleName, userId);
}

ErrCode BmsBundleInstallerBopdTest::UninstallBundle(const std::string &bundleName) const
{
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (receiver == nullptr) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.userId = Constants::START_USERID;
    installer->Uninstall(bundleName, installParam, receiver);
    return receiver->GetResultCode();
}

ErrCode BmsBundleInstallerBopdTest::UninstallSharedBundle(const std::string &bundleName) const
{
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (receiver == nullptr) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    UninstallParam uninstallParam;
    uninstallParam.bundleName = bundleName;
    installer->Uninstall(uninstallParam, receiver);
    return receiver->GetResultCode();
}

/**
 * @tc.number: BmsBundleInstallerBopdTest_0001
 * @tc.name: test third party bundle install is blocked in bopd mode
 * @tc.desc: 1. set ohos.boot.bopd.mode to a valid bopd mode
 *           2. install a bundle actually signed as third party app
 *           3. verify install fails with ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED
 */
HWTEST_F(BmsBundleInstallerBopdTest, BmsBundleInstallerBopdTest_0001, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ErrCode result = InstallThirdPartyBundle(THIRD_PARTY_HAP);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED);
}

/**
 * @tc.number: BmsBundleInstallerBopdTest_0002
 * @tc.name: test third party bundle install is blocked for every valid bopd mode
 * @tc.desc: 1. set ohos.boot.bopd.mode to each valid bopd mode
 *           2. install a bundle actually signed as third party app
 *           3. verify each install fails with ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED
 */
HWTEST_F(BmsBundleInstallerBopdTest, BmsBundleInstallerBopdTest_0002, Function | SmallTest | Level0)
{
    const std::vector<std::string> validModes = {"0x2", "0x3", "0x6", "0x7", "0xa", "0xe", "0xf"};
    for (const auto &mode : validModes) {
        OHOS::system::SetParameter(BOPD_MODE_PARAM, mode);
        ErrCode result = InstallThirdPartyBundle(THIRD_PARTY_HAP);
        EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED) << "mode " << mode << " should block install";
    }
}

/**
 * @tc.number: BmsBundleInstallerBopdTest_0003
 * @tc.name: test third party bundle install is not blocked when bopd mode is disabled
 * @tc.desc: 1. keep ohos.boot.bopd.mode empty
 *           2. install a bundle actually signed as third party app
 *           3. verify install is not blocked by the bopd mode check and succeeds
 */
HWTEST_F(BmsBundleInstallerBopdTest, BmsBundleInstallerBopdTest_0003, Function | SmallTest | Level0)
{
    ErrCode result = InstallThirdPartyBundle(THIRD_PARTY_HAP);
    EXPECT_NE(result, ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED);
    EXPECT_EQ(result, ERR_OK);
    if (result == ERR_OK) {
        EXPECT_EQ(UninstallBundle(THIRD_PARTY_BUNDLE_NAME), ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleInstallerBopdTest_0004
 * @tc.name: test third party bundle install is not blocked with invalid bopd mode
 * @tc.desc: 1. set ohos.boot.bopd.mode to an invalid bopd mode
 *           2. install a bundle actually signed as third party app
 *           3. verify install is not blocked by the bopd mode check and succeeds
 */
HWTEST_F(BmsBundleInstallerBopdTest, BmsBundleInstallerBopdTest_0004, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "0x1");
    ErrCode result = InstallThirdPartyBundle(THIRD_PARTY_HAP);
    EXPECT_NE(result, ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED);
    EXPECT_EQ(result, ERR_OK);
    if (result == ERR_OK) {
        EXPECT_EQ(UninstallBundle(THIRD_PARTY_BUNDLE_NAME), ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleInstallerBopdTest_0005
 * @tc.name: test actual system bundle install is not blocked in bopd mode
 * @tc.desc: 1. set ohos.boot.bopd.mode to a valid bopd mode
 *           2. install a bundle actually signed as system app through the third
 *              party entry (caller app type is third party)
 *           3. verify install is not blocked by the bopd mode check and succeeds,
 *              the check uses the actual app type parsed from hap, not the caller input
 */
HWTEST_F(BmsBundleInstallerBopdTest, BmsBundleInstallerBopdTest_0005, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ErrCode result = InstallThirdPartyBundle(SYSTEM_HAP);
    EXPECT_NE(result, ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED);
    EXPECT_EQ(result, ERR_OK);
    if (result == ERR_OK) {
        EXPECT_EQ(UninstallBundle(SYSTEM_BUNDLE_NAME), ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleInstallerBopdTest_0006
 * @tc.name: test actual third party bundle install is blocked even if caller app type is system app
 * @tc.desc: 1. set ohos.boot.bopd.mode to a valid bopd mode
 *           2. install a bundle actually signed as third party app through the system
 *              bundle installer (caller app type is system app)
 *           3. verify install fails with ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED,
 *              the caller input app type can not bypass the bopd mode check
 */
HWTEST_F(BmsBundleInstallerBopdTest, BmsBundleInstallerBopdTest_0006, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ErrCode result = InstallBundleAsSystemApp(THIRD_PARTY_HAP);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED);
}

/**
 * @tc.number: BmsBundleInstallerBopdTest_0008
 * @tc.name: test third party shared bundle install is blocked in bopd mode
 * @tc.desc: 1. set ohos.boot.bopd.mode to a valid bopd mode
 *           2. install a shared bundle actually signed as third party app through
 *              the shared bundle dir path (isOTA is not set)
 *           3. verify install fails with ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED,
 *              the bopd mode check covers the shared bundle install path
 */
HWTEST_F(BmsBundleInstallerBopdTest, BmsBundleInstallerBopdTest_0008, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ErrCode result = InstallSharedBundle(THIRD_PARTY_HSP);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED);
}

/**
 * @tc.number: BmsBundleInstallerBopdTest_0009
 * @tc.name: test third party bundle multi-user install-existed is blocked in bopd mode
 * @tc.desc: 1. install a third party bundle at start user in non-bopd mode (base installed)
 *           2. set ohos.boot.bopd.mode to a valid bopd mode
 *           3. call InstallExistedApp to install the existing third party bundle to a user
 *           4. verify it fails with ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED,
 *              the bopd mode check covers the multi-user install-existed path
 */
HWTEST_F(BmsBundleInstallerBopdTest, BmsBundleInstallerBopdTest_0009, Function | SmallTest | Level0)
{
    ErrCode installRet = InstallThirdPartyBundle(THIRD_PARTY_HAP);
    ASSERT_EQ(installRet, ERR_OK);
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ErrCode result = InstallExistedAppAsMultiUser(THIRD_PARTY_BUNDLE_NAME, Constants::START_USERID);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED);
    EXPECT_EQ(UninstallBundle(THIRD_PARTY_BUNDLE_NAME), ERR_OK);
}
}  // namespace OHOS
