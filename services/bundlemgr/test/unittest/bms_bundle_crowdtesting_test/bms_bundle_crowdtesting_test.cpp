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
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.dependenciestest";
const std::string BUNDLE_NAME_2 = "com.example.l3jsdemo";
const std::string HAP_FILE_PATH = "/data/test/resource/bms/crowdtesting/";
const std::string HAP_NAME_ENTRY_B = "dependencies_entry_B.hap";
const std::string HAP_NAME_ENTRY_C = "dependencies_entry_C.hap";
const std::string HAP_NAME_FIRST_RIGHT = "first_right.hap";
const int32_t USERID = 100;
const int32_t CROWDTEST_DEADLINE = 100000000;
const int32_t CROWDTEST_DEADLINE2 = 200000000;
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundleCrowdtestingTest : public testing::Test {
public:
    BmsBundleCrowdtestingTest();
    ~BmsBundleCrowdtestingTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath, int32_t crowdtestDeadline = 0) const;
    ErrCode InstallBundle(const std::vector<std::string> &bundlePath, int32_t crowdtestDeadline = 0) const;
    ErrCode InstallBundle(const std::string  &bundlePath,
        int32_t crowdtestDeadline, const std::string &specifiedDistributeType) const;
    ErrCode UpdateBundle(const std::string &bundlePath, int32_t crowdtestDeadline = 0) const;
    ErrCode UpdateBundle(const std::string  &bundlePath,
        int32_t crowdtestDeadline, const std::string &specifiedDistributeType) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleCrowdtestingTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleCrowdtestingTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleCrowdtestingTest::BmsBundleCrowdtestingTest()
{}

BmsBundleCrowdtestingTest::~BmsBundleCrowdtestingTest()
{}

void BmsBundleCrowdtestingTest::SetUpTestCase()
{}

void BmsBundleCrowdtestingTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleCrowdtestingTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundleCrowdtestingTest::TearDown()
{}

ErrCode BmsBundleCrowdtestingTest::InstallBundle(const std::string &bundlePath,
    int32_t crowdtestDeadline) const
{
    std::vector<std::string> path {bundlePath};
    return InstallBundle(path, crowdtestDeadline);
}

ErrCode BmsBundleCrowdtestingTest::InstallBundle(const std::vector<std::string> &bundlePath,
    int32_t crowdtestDeadline) const
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
    installParam.crowdtestDeadline = crowdtestDeadline;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleCrowdtestingTest::InstallBundle(const std::string &bundlePath,
    int32_t crowdtestDeadline, const std::string &specifiedDistributeType) const
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
    installParam.crowdtestDeadline = crowdtestDeadline;
    installParam.specifiedDistributionType = specifiedDistributeType;
    installParam.withCopyHaps = true;
    std::vector<std::string> path;
    path.emplace_back(bundlePath);
    bool result = installer->Install(path, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleCrowdtestingTest::UpdateBundle(const std::string &bundlePath,
    int32_t crowdtestDeadline) const
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
    installParam.crowdtestDeadline = crowdtestDeadline;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleCrowdtestingTest::UpdateBundle(const std::string  &bundlePath,
    int32_t crowdtestDeadline, const std::string &specifiedDistributeType) const
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
    installParam.crowdtestDeadline = crowdtestDeadline;
    installParam.specifiedDistributionType = specifiedDistributeType;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleCrowdtestingTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleCrowdtestingTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleCrowdtestingTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleCrowdtestingTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: BmsBundleCrowdtestingTest_001
 * Function: GetApplicationInfo
 * @tc.name: test appDistributionType and appProvisionType
 * @tc.desc: 1. system running normally
 *           2. get appDistributionType and appProvisionType
 */
HWTEST_F(BmsBundleCrowdtestingTest, BmsBundleCrowdtestingTest_001, Function | SmallTest | Level1)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + HAP_NAME_ENTRY_C);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo appInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleCrowdtestingTest_002
 * Function: GetApplicationInfo
 * @tc.name: test appDistributionType and appProvisionType
 * @tc.desc: 1. system running normally
 *           2. get appDistributionType and appProvisionType
 */
HWTEST_F(BmsBundleCrowdtestingTest, BmsBundleCrowdtestingTest_002, Function | SmallTest | Level1)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + HAP_NAME_FIRST_RIGHT);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo appInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_2, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_2);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleCrowdtestingTest_003
 * Function: GetApplicationInfo
 * @tc.name: test crowdtestDeadline, not crowdtesting type
 * @tc.desc: 1. system running normally
 *           2. get crowdtestDeadline
 */
HWTEST_F(BmsBundleCrowdtestingTest, BmsBundleCrowdtestingTest_003, Function | SmallTest | Level1)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + HAP_NAME_FIRST_RIGHT, CROWDTEST_DEADLINE);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo appInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_2, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, Constants::INVALID_CROWDTEST_DEADLINE);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_2);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleCrowdtestingTest_004
 * Function: GetApplicationInfo
 * @tc.name: test crowdtestDeadline, first install
 * @tc.desc: 1. system running normally
 *           2. get crowdtestDeadline
 */
HWTEST_F(BmsBundleCrowdtestingTest, BmsBundleCrowdtestingTest_004, Function | SmallTest | Level1)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + HAP_NAME_ENTRY_C, CROWDTEST_DEADLINE);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo appInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, CROWDTEST_DEADLINE);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleCrowdtestingTest_005
 * Function: GetApplicationInfo
 * @tc.name: test crowdtestDeadline, update the same module
 * @tc.desc: 1. system running normally
 *           2. get crowdtestDeadline
 */
HWTEST_F(BmsBundleCrowdtestingTest, BmsBundleCrowdtestingTest_005, Function | SmallTest | Level1)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + HAP_NAME_ENTRY_C, CROWDTEST_DEADLINE);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo appInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, CROWDTEST_DEADLINE);

    ErrCode updateResult = UpdateBundle(HAP_FILE_PATH + HAP_NAME_ENTRY_C, CROWDTEST_DEADLINE2);
    EXPECT_EQ(updateResult, ERR_OK);
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, CROWDTEST_DEADLINE2); // module update effect the crowdtestDeadline

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleCrowdtestingTest_006
 * Function: GetApplicationInfo
 * @tc.name: test crowdtestDeadline, new module install
 * @tc.desc: 1. system running normally
 *           2. get crowdtestDeadline
 */
HWTEST_F(BmsBundleCrowdtestingTest, BmsBundleCrowdtestingTest_006, Function | SmallTest | Level1)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + HAP_NAME_ENTRY_C, CROWDTEST_DEADLINE);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo appInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, CROWDTEST_DEADLINE);

    ErrCode updateResult = InstallBundle(HAP_FILE_PATH + HAP_NAME_ENTRY_B, CROWDTEST_DEADLINE2);
    EXPECT_EQ(updateResult, ERR_OK);
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, CROWDTEST_DEADLINE); // new module install does not effect crowdtestDealine

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleCrowdtestingTest_007
 * Function: GetApplicationInfo
 * @tc.name: multi-hap install, same type
 * @tc.desc: 1. system running normally
 *           2. multi-hap install
 */
HWTEST_F(BmsBundleCrowdtestingTest, BmsBundleCrowdtestingTest_007, Function | SmallTest | Level1)
{
    std::vector<std::string> bundlePath;
    bundlePath.emplace_back(HAP_FILE_PATH + HAP_NAME_ENTRY_C);
    bundlePath.emplace_back(HAP_FILE_PATH + HAP_NAME_ENTRY_B);
    ErrCode installResult = InstallBundle(bundlePath, CROWDTEST_DEADLINE);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo appInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, CROWDTEST_DEADLINE);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleCrowdtestingTest_008
 * Function: GetApplicationInfo
 * @tc.name: test crowdtestDeadline, specifiedDistributionType is crowdtesting type
 * @tc.desc: 1. system running normally
 *           2. get crowdtestDeadline
 */
HWTEST_F(BmsBundleCrowdtestingTest, BmsBundleCrowdtestingTest_008, Function | SmallTest | Level1)
{
    std::string specifiedDistributeType = Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING;
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + HAP_NAME_FIRST_RIGHT,
        CROWDTEST_DEADLINE, specifiedDistributeType);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo appInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_2, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, CROWDTEST_DEADLINE);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_2);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleCrowdtestingTest_009
 * Function: GetApplicationInfo
 * @tc.name: test crowdtestDeadline, specifiedDistributionType is crowdtesting type
 * @tc.desc: 1. system running normally
 *           2. get crowdtestDeadline
 */
HWTEST_F(BmsBundleCrowdtestingTest, BmsBundleCrowdtestingTest_009, Function | SmallTest | Level1)
{
    std::string specifiedDistributeType = Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING;
    ErrCode installResult = InstallBundle(HAP_FILE_PATH + HAP_NAME_FIRST_RIGHT,
        CROWDTEST_DEADLINE, specifiedDistributeType);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo appInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_2, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, CROWDTEST_DEADLINE);

    installResult = UpdateBundle(HAP_FILE_PATH + HAP_NAME_FIRST_RIGHT,
        -2, specifiedDistributeType);
    EXPECT_EQ(installResult, ERR_OK);
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME_2, 0, USERID, appInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(appInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION);
    EXPECT_EQ(appInfo.appProvisionType, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appInfo.crowdtestDeadline, CROWDTEST_DEADLINE);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_2);
    EXPECT_EQ(unInstallResult, ERR_OK);
}
} // OHOS