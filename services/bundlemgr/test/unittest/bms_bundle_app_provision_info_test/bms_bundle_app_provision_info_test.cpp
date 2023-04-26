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
#include <unordered_set>
#include <vector>

#include "app_provision_info.h"
#include "app_provision_info_manager.h"
#include "base_bundle_installer.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "inner_shared_bundle_installer.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
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
const std::string HSP_BUNDLE_NAME = "com.example.liba";
const std::string HSP_FILE_PATH1 = "/data/test/resource/bms/sharelibrary/libA_v10000.hsp";
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
    ErrCode InstallBundle(const std::vector<std::string> &bundlePath, const InstallParam &installParam) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    ErrCode UninstallSharedBundle(const std::string &bundleName) const;
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

ErrCode BmsBundleAppProvisionInfoTest::InstallBundle(const std::vector<std::string> &bundlePath,
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

ErrCode BmsBundleAppProvisionInfoTest::UninstallSharedBundle(const std::string &bundleName) const
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
    std::unordered_set<std::string> bundleNames;
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
    EXPECT_FALSE(ret);
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

/**
 * @tc.number: AddAppProvisionInfo_0001
 * @tc.name: test the start function of AddAppProvisionInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, AddAppProvisionInfo_0001, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    Security::Verify::ProvisionInfo appProvisionInfo;
    std::string bundleName = "";
    InstallParam installParam;
    baseBundleInstaller.AddAppProvisionInfo(bundleName, appProvisionInfo, installParam);
    AppProvisionInfo newProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(bundleName,
        newProvisionInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AddAppProvisionInfo_0002
 * @tc.name: test the start function of AddAppProvisionInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, AddAppProvisionInfo_0002, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    Security::Verify::ProvisionInfo appProvisionInfo;
    std::string bundleName = "";
    InstallParam installParam;
    installParam.specifiedDistributionType = "specifiedDistributionType";
    installParam.additionalInfo = "additionalInfo";
    baseBundleInstaller.AddAppProvisionInfo(bundleName, appProvisionInfo, installParam);
    AppProvisionInfo newProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(bundleName,
        newProvisionInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AddAppProvisionInfo_0003
 * @tc.name: test the start function of AddAppProvisionInfo and DeleteAppProvisionInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, AddAppProvisionInfo_0003, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    Security::Verify::ProvisionInfo appProvisionInfo;
    InstallParam installParam;
    installParam.specifiedDistributionType = "specifiedDistributionType";
    baseBundleInstaller.AddAppProvisionInfo(BUNDLE_NAME, appProvisionInfo, installParam);
    AppProvisionInfo newProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
        newProvisionInfo);
    EXPECT_TRUE(ret);
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AddAppProvisionInfo_0004
 * @tc.name: test the start function of AddAppProvisionInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, AddAppProvisionInfo_0004, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    Security::Verify::ProvisionInfo appProvisionInfo;
    InstallParam installParam;
    installParam.specifiedDistributionType = "specifiedDistributionType";
    installParam.additionalInfo = "additionalInfo";
    baseBundleInstaller.AddAppProvisionInfo(BUNDLE_NAME, appProvisionInfo, installParam);
    AppProvisionInfo newProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
        newProvisionInfo);
    EXPECT_TRUE(ret);

    std::string specifiedDistributionType;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType(BUNDLE_NAME,
        specifiedDistributionType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(installParam.specifiedDistributionType, specifiedDistributionType);

    std::string additionalInfo;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(BUNDLE_NAME,
        additionalInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(installParam.additionalInfo, additionalInfo);

    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: SetSpecifiedDistributionType_0001
 * @tc.name: test the start function of SetSpecifiedDistributionType
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SetSpecifiedDistributionType_0001, Function | SmallTest | Level0)
{
    std::string specifiedDistributionType = "distributionType";
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetSpecifiedDistributionType("",
        specifiedDistributionType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetSpecifiedDistributionType_0002
 * @tc.name: test the start function of SetSpecifiedDistributionType and GetSpecifiedDistributionType
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SetSpecifiedDistributionType_0002, Function | SmallTest | Level0)
{
    AppProvisionInfo appProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME,
        appProvisionInfo);
    EXPECT_TRUE(ret);
    std::string specifiedDistributionType = "distributionType";
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetSpecifiedDistributionType(BUNDLE_NAME,
        specifiedDistributionType);
    EXPECT_TRUE(ret);
    std::string newSpecifiedDistributionType;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType(BUNDLE_NAME,
        newSpecifiedDistributionType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(specifiedDistributionType, newSpecifiedDistributionType);
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetSpecifiedDistributionType_0001
 * @tc.name: test the start function of GetSpecifiedDistributionType
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, GetSpecifiedDistributionType_0001, Function | SmallTest | Level0)
{
    std::string specifiedDistributionType;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType("",
        specifiedDistributionType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetSpecifiedDistributionType_0002
 * @tc.name: test the start function of GetSpecifiedDistributionType
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, GetSpecifiedDistributionType_0002, Function | SmallTest | Level0)
{
    std::string specifiedDistributionType;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType(BUNDLE_NAME,
        specifiedDistributionType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetAdditionalInfo_0001
 * @tc.name: test the start function of SetAdditionalInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SetAdditionalInfo_0001, Function | SmallTest | Level0)
{
    std::string additionalInfo = "additional";
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetAdditionalInfo("",
        additionalInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetAdditionalInfo_0002
 * @tc.name: test the start function of SetAdditionalInfo and GetAdditionalInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SetAdditionalInfo_0002, Function | SmallTest | Level0)
{
    AppProvisionInfo appProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME,
        appProvisionInfo);
    EXPECT_TRUE(ret);
    std::string additionalInfo = "additional";
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetAdditionalInfo(BUNDLE_NAME,
        additionalInfo);
    EXPECT_TRUE(ret);
    std::string newAdditionalInfo;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(BUNDLE_NAME,
        newAdditionalInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(additionalInfo, newAdditionalInfo);
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetAdditionalInfo_0001
 * @tc.name: test the start function of GetAdditionalInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, GetAdditionalInfo_0001, Function | SmallTest | Level0)
{
    std::string additionalInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo("",
        additionalInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetAdditionalInfo_0002
 * @tc.name: test the start function of GetAdditionalInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, GetAdditionalInfo_0002, Function | SmallTest | Level0)
{
    std::string additionalInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(BUNDLE_NAME,
        additionalInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SaveInstallParamInfo_0001
 * @tc.name: test the start function of SaveInstallParamInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveInstallParamInfo_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallParam installParam;
    installer.SaveInstallParamInfo(BUNDLE_NAME, installParam);
    std::string specifiedDistributionType;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType(BUNDLE_NAME,
        specifiedDistributionType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SaveInstallParamInfo_0002
 * @tc.name: test the start function of SaveInstallParamInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveInstallParamInfo_0002, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallParam installParam;
    installParam.specifiedDistributionType = "specifiedDistributionType";
    installParam.additionalInfo = "additionalInfo";
    installer.SaveInstallParamInfo(BUNDLE_NAME, installParam);
    std::string specifiedDistributionType;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType(BUNDLE_NAME,
        specifiedDistributionType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SaveInstallParamInfo_0003
 * @tc.name: test the start function of SaveInstallParamInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveInstallParamInfo_0003, Function | SmallTest | Level0)
{
    AppProvisionInfo appProvisionInfo;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME,
        appProvisionInfo);
    EXPECT_TRUE(ret);
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallParam installParam;
    installParam.specifiedDistributionType = "specifiedDistributionType";
    installParam.additionalInfo = "additionalInfo";
    installer.SaveInstallParamInfo(BUNDLE_NAME, installParam);

    std::string specifiedDistributionType;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType(BUNDLE_NAME,
        specifiedDistributionType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(installParam.specifiedDistributionType, specifiedDistributionType);

    std::string additionalInfo;
    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(BUNDLE_NAME,
        additionalInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(installParam.additionalInfo, additionalInfo);

    ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InnerProcessStockBundleProvisionInfo_0001
 * @tc.name: test the start function of InnerProcessStockBundleProvisionInfo
 * @tc.desc: call InnerProcessStockBundleProvisionInfo, no bundleInfos
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerProcessStockBundleProvisionInfo_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    if (!handler) {
        EXPECT_NE(handler, nullptr);
    } else {
        handler->InnerProcessStockBundleProvisionInfo();
        AppProvisionInfo appProvisionInfo;
        bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
            appProvisionInfo);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: ProcessBundleProvisionInfo_0001
 * @tc.name: test the start function of ProcessBundleProvisionInfo
 * @tc.desc: call ProcessBundleProvisionInfo, no bundleInfos
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessBundleProvisionInfo_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    if (!handler) {
        EXPECT_NE(handler, nullptr);
    } else {
        std::unordered_set<std::string> allBundleNames;
        bool ret =
            DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(allBundleNames.empty());

        handler->ProcessBundleProvisionInfo(allBundleNames);

        AppProvisionInfo appProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
            appProvisionInfo);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: ProcessBundleProvisionInfo_0002
 * @tc.name: test the start function of ProcessBundleProvisionInfo
 * @tc.desc: 1. install hap, delete appProvisionInfo
 *           2. call ProcessBundleProvisionInfo
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessBundleProvisionInfo_0002, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    if (!handler) {
        EXPECT_NE(handler, nullptr);
    } else {
        ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
        EXPECT_EQ(installResult, ERR_OK);

        bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME);
        EXPECT_TRUE(ret);

        std::unordered_set<std::string> allBundleNames;
        ret =
            DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(allBundleNames.empty());

        handler->ProcessBundleProvisionInfo(allBundleNames);
        AppProvisionInfo appProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
            appProvisionInfo);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(appProvisionInfo.apl.empty());

        ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
        EXPECT_EQ(unInstallResult, ERR_OK);
    }
}

/**
 * @tc.number: ProcessBundleProvisionInfo_0003
 * @tc.name: test the start function of ProcessBundleProvisionInfo
 * @tc.desc: 1. install hap
 *           2. call ProcessBundleProvisionInfo
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessBundleProvisionInfo_0003, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    if (!handler) {
        EXPECT_NE(handler, nullptr);
    } else {
        ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
        EXPECT_EQ(installResult, ERR_OK);

        std::unordered_set<std::string> allBundleNames;
        bool ret =
            DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(allBundleNames.empty());

        handler->ProcessBundleProvisionInfo(allBundleNames);
        AppProvisionInfo appProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
            appProvisionInfo);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(appProvisionInfo.apl.empty());

        ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
        EXPECT_EQ(unInstallResult, ERR_OK);
    }
}

/**
 * @tc.number: ProcessBundleProvisionInfo_0004
 * @tc.name: test the start function of ProcessBundleProvisionInfo
 * @tc.desc: 1. install hap
 *           2. call ProcessBundleProvisionInfo
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessBundleProvisionInfo_0004, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    if (!handler) {
        EXPECT_NE(handler, nullptr);
    } else {
        ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
        EXPECT_EQ(installResult, ERR_OK);

        std::unordered_set<std::string> allBundleNames;
        bool ret =
            DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(allBundleNames.empty());

        handler->ProcessBundleProvisionInfo(allBundleNames);
        AppProvisionInfo appProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
            appProvisionInfo);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(appProvisionInfo.apl.empty());

        ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
        EXPECT_EQ(unInstallResult, ERR_OK);

        AppProvisionInfo newAppProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
            newAppProvisionInfo);
        EXPECT_FALSE(ret);
        EXPECT_TRUE(newAppProvisionInfo.apl.empty());
    }
}

/**
 * @tc.number: ProcessSharedBundleProvisionInfo_0001
 * @tc.name: test the start function of ProcessSharedBundleProvisionInfo
 * @tc.desc: call ProcessSharedBundleProvisionInfo, no bundleInfos
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessSharedBundleProvisionInfo_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    if (!handler) {
        EXPECT_NE(handler, nullptr);
    } else {
        std::unordered_set<std::string> allBundleNames;
        bool ret =
            DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(allBundleNames.empty());

        handler->ProcessSharedBundleProvisionInfo(allBundleNames);

        AppProvisionInfo appProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(BUNDLE_NAME,
            appProvisionInfo);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: ProcessSharedBundleProvisionInfo_0002
 * @tc.name: test the start function of ProcessSharedBundleProvisionInfo
 * @tc.desc: 1. install hap, delete appProvisionInfo
 *           2. call ProcessSharedBundleProvisionInfo
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessSharedBundleProvisionInfo_0002, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    if (!handler) {
        EXPECT_NE(handler, nullptr);
    } else {
        std::vector<std::string> bundlePath;
        InstallParam installParam;
        installParam.userId = USERID;
        installParam.installFlag = InstallFlag::NORMAL;
        installParam.sharedBundleDirPaths = std::vector<std::string>{HSP_FILE_PATH1};
        ErrCode installResult = InstallBundle(bundlePath, installParam);
        EXPECT_EQ(installResult, ERR_OK);

        bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(HSP_BUNDLE_NAME);
        EXPECT_TRUE(ret);

        std::unordered_set<std::string> allBundleNames;
        ret =
            DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(allBundleNames.empty());

        handler->ProcessSharedBundleProvisionInfo(allBundleNames);
        AppProvisionInfo appProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(HSP_BUNDLE_NAME,
            appProvisionInfo);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(appProvisionInfo.apl.empty());

        ErrCode unInstallResult = UninstallSharedBundle(HSP_BUNDLE_NAME);
        EXPECT_EQ(unInstallResult, ERR_OK);
    }
}

/**
 * @tc.number: ProcessSharedBundleProvisionInfo_0003
 * @tc.name: test the start function of ProcessSharedBundleProvisionInfo
 * @tc.desc: 1. install hap
 *           2. call ProcessSharedBundleProvisionInfo
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessSharedBundleProvisionInfo_0003, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    if (!handler) {
        EXPECT_NE(handler, nullptr);
    } else {
        std::vector<std::string> bundlePath;
        InstallParam installParam;
        installParam.userId = USERID;
        installParam.installFlag = InstallFlag::NORMAL;
        installParam.sharedBundleDirPaths = std::vector<std::string>{HSP_FILE_PATH1};
        ErrCode installResult = InstallBundle(bundlePath, installParam);
        EXPECT_EQ(installResult, ERR_OK);

        std::unordered_set<std::string> allBundleNames;
        bool ret =
            DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(allBundleNames.empty());

        handler->ProcessSharedBundleProvisionInfo(allBundleNames);
        AppProvisionInfo appProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(HSP_BUNDLE_NAME,
            appProvisionInfo);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(appProvisionInfo.apl.empty());

        ErrCode unInstallResult = UninstallSharedBundle(HSP_BUNDLE_NAME);
        EXPECT_EQ(unInstallResult, ERR_OK);
    }
}

/**
 * @tc.number: ProcessSharedBundleProvisionInfo_0004
 * @tc.name: test the start function of ProcessSharedBundleProvisionInfo
 * @tc.desc: 1. install hap
 *           2. call ProcessSharedBundleProvisionInfo
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessSharedBundleProvisionInfo_0004, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    if (!handler) {
        EXPECT_NE(handler, nullptr);
    } else {
        std::vector<std::string> bundlePath;
        InstallParam installParam;
        installParam.userId = USERID;
        installParam.installFlag = InstallFlag::NORMAL;
        installParam.sharedBundleDirPaths = std::vector<std::string>{HSP_FILE_PATH1};
        ErrCode installResult = InstallBundle(bundlePath, installParam);
        EXPECT_EQ(installResult, ERR_OK);

        std::unordered_set<std::string> allBundleNames;
        bool ret =
            DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(allBundleNames.empty());

        handler->ProcessSharedBundleProvisionInfo(allBundleNames);
        AppProvisionInfo appProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(HSP_BUNDLE_NAME,
            appProvisionInfo);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(appProvisionInfo.apl.empty());

        ErrCode unInstallResult = UninstallSharedBundle(HSP_BUNDLE_NAME);
        EXPECT_EQ(unInstallResult, ERR_OK);

        AppProvisionInfo newAppProvisionInfo;
        ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(HSP_BUNDLE_NAME,
            newAppProvisionInfo);
        EXPECT_FALSE(ret);
        EXPECT_TRUE(newAppProvisionInfo.apl.empty());
    }
}
} // OHOS