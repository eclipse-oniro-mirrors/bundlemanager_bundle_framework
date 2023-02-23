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
#include <vector>

#include "app_provision_info.h"
#include "app_provision_info_manager.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "module_usage_record.h"
#include "remote_ability_info.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest1.hap";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundleAppProvisionInfoTest : public testing::Test {
public:
    BmsBundleAppProvisionInfoTest();
    ~BmsBundleAppProvisionInfoTest();
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
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
};

BmsBundleAppProvisionInfoTest::BmsBundleAppProvisionInfoTest()
{}

BmsBundleAppProvisionInfoTest::~BmsBundleAppProvisionInfoTest()
{}

void BmsBundleAppProvisionInfoTest::SetUpTestCase()
{}

void BmsBundleAppProvisionInfoTest::TearDownTestCase()
{}

void BmsBundleAppProvisionInfoTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundleAppProvisionInfoTest::TearDown()
{}

ErrCode BmsBundleAppProvisionInfoTest::InstallBundle(const std::string &bundlePath) const
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

ErrCode BmsBundleAppProvisionInfoTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleAppProvisionInfoTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleAppProvisionInfoTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleAppProvisionInfoTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0001
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. GetAppProvisionInfo, bundleName not exist
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AppProvisionInfo appProvisionInfo;
    ErrCode result = dataMgr->GetAppProvisionInfo(BUNDLE_NAME, USERID, appProvisionInfo);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0002
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. GetAppProvisionInfo, bundleName exist
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0002, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    AppProvisionInfo appProvisionInfo;
    ErrCode result = dataMgr->GetAppProvisionInfo(BUNDLE_NAME, WAIT_TIME, appProvisionInfo);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    EXPECT_TRUE(appProvisionInfo.type.empty());

    result = dataMgr->GetAppProvisionInfo(BUNDLE_NAME, USERID, appProvisionInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appProvisionInfo.type, "release");

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0003
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. GetAppProvisionInfo, bundleName exist, userId not exist
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0003, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    AppProvisionInfo appProvisionInfo;
    ErrCode result = dataMgr->GetAppProvisionInfo(BUNDLE_NAME, WAIT_TIME, appProvisionInfo);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    EXPECT_TRUE(appProvisionInfo.type.empty());

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0004
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. GetAppProvisionInfo, bundleName exist, userId exist
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0004, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    AppProvisionInfo appProvisionInfo;
    ErrCode result = dataMgr->GetAppProvisionInfo(BUNDLE_NAME, USERID, appProvisionInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appProvisionInfo.type, "release");

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0005
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. GetAppProvisionInfo, bundleName exist, userId exist
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0005, Function | SmallTest | Level0)
{
    AppProvisionInfo appProvisionInfo;
    appProvisionInfo.type = "debug";
    appProvisionInfo.apl = "system_basic";
    appProvisionInfo.issuer = "OpenHarmony";
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME,
        appProvisionInfo);
    EXPECT_TRUE(ret);

    AppProvisionInfo newProvisionInfo;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
        newProvisionInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(appProvisionInfo.type, newProvisionInfo.type);
    EXPECT_EQ(appProvisionInfo.apl, newProvisionInfo.apl);
    EXPECT_EQ(appProvisionInfo.issuer, newProvisionInfo.issuer);

    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ret);

    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
        newProvisionInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0006
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. AddAppProvisionInfo
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0006, Function | SmallTest | Level0)
{
    AppProvisionInfo appProvisionInfo;
    appProvisionInfo.type = "debug";
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME,
        appProvisionInfo);
    EXPECT_TRUE(ret);
    appProvisionInfo.type = "release";
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME,
        appProvisionInfo);
    EXPECT_TRUE(ret);

    AppProvisionInfo newProvisionInfo;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
        newProvisionInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(appProvisionInfo.type, newProvisionInfo.type);

    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0007
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. AddAppProvisionInfo
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0007, Function | SmallTest | Level0)
{
    AppProvisionInfo newProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
        newProvisionInfo);
    EXPECT_FALSE(ret);
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ret);
    std::vector<std::string> bundleNames;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(bundleNames);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(bundleNames.empty());
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0008
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. AddAppProvisionInfo, bundleName empty
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0008, Function | SmallTest | Level0)
{
    AppProvisionInfo newProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo("",
        newProvisionInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0009
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. GetAppProvisionInfo, bundleName empty
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0009, Function | SmallTest | Level0)
{
    AppProvisionInfo newProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo("");
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsGetAppProvisionInfoTest_0010
 * Function: GetAppProvisionInfo
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. AddAppProvisionInfo
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, BmsGetAppProvisionInfoTest_0010, Function | SmallTest | Level0)
{
    AppProvisionInfo appProvisionInfo;
    appProvisionInfo.versionCode = 10;
    appProvisionInfo.versionName = "10.0";
    appProvisionInfo.uuid = "1.2.3";
    appProvisionInfo.type = "release";
    appProvisionInfo.appDistributionType = "none";
    appProvisionInfo.developerId = "123";
    appProvisionInfo.certificate = "certificate";
    appProvisionInfo.apl = "normal";
    appProvisionInfo.issuer = "OpenHarmony";
    appProvisionInfo.validity.notBefore = 90000000000;
    appProvisionInfo.validity.notAfter = 99000000000;

    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME,
        appProvisionInfo);
    EXPECT_TRUE(ret);

    AppProvisionInfo newProvisionInfo;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
        newProvisionInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(appProvisionInfo.versionCode, newProvisionInfo.versionCode);
    EXPECT_EQ(appProvisionInfo.versionName, newProvisionInfo.versionName);
    EXPECT_EQ(appProvisionInfo.uuid, newProvisionInfo.uuid);
    EXPECT_EQ(appProvisionInfo.type, newProvisionInfo.type);
    EXPECT_EQ(appProvisionInfo.appDistributionType, newProvisionInfo.appDistributionType);
    EXPECT_EQ(appProvisionInfo.developerId, newProvisionInfo.developerId);
    EXPECT_EQ(appProvisionInfo.certificate, newProvisionInfo.certificate);
    EXPECT_EQ(appProvisionInfo.apl, newProvisionInfo.apl);
    EXPECT_EQ(appProvisionInfo.issuer, newProvisionInfo.issuer);
    EXPECT_EQ(appProvisionInfo.validity.notBefore, newProvisionInfo.validity.notBefore);
    EXPECT_EQ(appProvisionInfo.validity.notAfter, newProvisionInfo.validity.notAfter);

    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ret);
}
} // OHOS