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
const std::string BUNDLE_NAME = "com.example.hsptest";
const std::string MODULE_FILE_PATH = "/data/test/resource/bms/hsp/";
const std::string MODULE_C2_FILE_PATH = "/data/test/resource/bms/hspC2/";
const std::string MODULE_D_FILE_PATH = "/data/test/resource/bms/hspD/";
const std::string HAP_NAME_ENTRY = "hap_entry.hap";
const std::string HSP_NAME_A = "hsp_A.hsp";
const std::string HSP_NAME_B = "hsp_B.hsp";
const std::string HSP_NAME_C = "hsp_C.hsp";
const std::string HSP_NAME_C2 = "hsp_C2.hsp";
const std::string HSP_NAME_D = "hsp_D.hsp";
const std::string MODULE_NAME_ENTRY = "entry";
const std::string MODULE_NAME_A = "hsp_A";
const std::string MODULE_NAME_B = "hsp_B";
const std::string MODULE_NAME_C = "hsp_C";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundleHspTest : public testing::Test {
public:
    BmsBundleHspTest();
    ~BmsBundleHspTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UpdateBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();

private:
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
};

BmsBundleHspTest::BmsBundleHspTest()
{}

BmsBundleHspTest::~BmsBundleHspTest()
{}

void BmsBundleHspTest::SetUpTestCase()
{}

void BmsBundleHspTest::TearDownTestCase()
{}

void BmsBundleHspTest::SetUp()
{
    StartBundleService();
    StartInstalldService();
}

void BmsBundleHspTest::TearDown()
{}

ErrCode BmsBundleHspTest::InstallBundle(const std::string &bundlePath) const
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
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleHspTest::UpdateBundle(const std::string &bundlePath) const
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USERID;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleHspTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleHspTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleHspTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleHspTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: BmsBundleHspTest_0100
 * @tc.name: BmsBundleHspTest
 * @tc.desc: test install, the module does not dependent any hsp
 */
HWTEST_F(BmsBundleHspTest, BmsBundleHspTest_0100, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(MODULE_FILE_PATH + HSP_NAME_C);
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHspTest_0200
 * @tc.name: BmsBundleHspTest
 * @tc.desc: test install, the dependencies is not install
 */
HWTEST_F(BmsBundleHspTest, BmsBundleHspTest_0200, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(MODULE_FILE_PATH + HAP_NAME_ENTRY);
    EXPECT_NE(installResult, ERR_OK);
    installResult = InstallBundle(MODULE_FILE_PATH + HSP_NAME_A);
    EXPECT_NE(installResult, ERR_OK);
    installResult = InstallBundle(MODULE_FILE_PATH + HSP_NAME_B);
    EXPECT_NE(installResult, ERR_OK);
    UnInstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleHspTest_0300
 * @tc.name: BmsBundleHspTest
 * @tc.desc: test install, the hsp_B is not install
 */
HWTEST_F(BmsBundleHspTest, BmsBundleHspTest_0300, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(MODULE_FILE_PATH + HSP_NAME_C);
    EXPECT_EQ(installResult, ERR_OK);
    installResult = InstallBundle(MODULE_FILE_PATH + HSP_NAME_A);
    EXPECT_EQ(installResult, ERR_OK);
    installResult = InstallBundle(MODULE_FILE_PATH + HAP_NAME_ENTRY);
    EXPECT_NE(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHspTest_0400
 * @tc.name: BmsBundleHspTest
 * @tc.desc: test install, the dependencies is installed
 */
HWTEST_F(BmsBundleHspTest, BmsBundleHspTest_0400, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(MODULE_FILE_PATH + HSP_NAME_C);
    EXPECT_EQ(installResult, ERR_OK);
    installResult = InstallBundle(MODULE_FILE_PATH + HSP_NAME_A);
    EXPECT_EQ(installResult, ERR_OK);
    installResult = InstallBundle(MODULE_FILE_PATH + HSP_NAME_B);
    EXPECT_EQ(installResult, ERR_OK);
    installResult = InstallBundle(MODULE_FILE_PATH + HAP_NAME_ENTRY);
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHspTest_0500
 * @tc.name: BmsBundleHspTest
 * @tc.desc: test install with path
 */
HWTEST_F(BmsBundleHspTest, BmsBundleHspTest_0500, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(MODULE_FILE_PATH);
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHspTest_0600
 * @tc.name: BmsBundleHspTest
 * @tc.desc: test install for new version
 */
HWTEST_F(BmsBundleHspTest, BmsBundleHspTest_0600, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(MODULE_FILE_PATH + HSP_NAME_C);
    EXPECT_EQ(installResult, ERR_OK);
    installResult = InstallBundle(MODULE_C2_FILE_PATH + HSP_NAME_C2);
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHspTest_0700
 * @tc.name: BmsBundleHspTest
 * @tc.desc: test install for dependency other app and the app is not install
 */
HWTEST_F(BmsBundleHspTest, BmsBundleHspTest_0700, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(MODULE_D_FILE_PATH + HSP_NAME_D);
    EXPECT_NE(installResult, ERR_OK);
}
} // OHOS