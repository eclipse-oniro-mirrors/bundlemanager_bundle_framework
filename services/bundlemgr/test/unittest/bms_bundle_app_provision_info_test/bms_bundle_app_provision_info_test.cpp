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
const std::string HAP_FILE_PATH2 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest2.hap";
const std::string HSP_BUNDLE_NAME = "com.example.liba";
const std::string HSP_FILE_PATH1 = "/data/test/resource/bms/sharelibrary/libA_v10000.hsp";
const std::string TEST_MODULE_NAME = "testModuleName";
const std::string TEST_MODULE_NAME_TMP = "testModuleName_tmp/";
const std::string PATH_SEPARATOR = "/";
const std::string NOT_EXIST_PATH = "notExist";
const std::string EXIST_PATH = "/data/test/resource/bms/quickfix";
const std::string EXIST_PATH2 = "/data/test/resource/bms/accesstoken_bundle";
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
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleAppProvisionInfoTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleAppProvisionInfoTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleAppProvisionInfoTest::BmsBundleAppProvisionInfoTest()
{}

BmsBundleAppProvisionInfoTest::~BmsBundleAppProvisionInfoTest()
{}

void BmsBundleAppProvisionInfoTest::SetUpTestCase()
{}

void BmsBundleAppProvisionInfoTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

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
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    appProvisionInfo.appServiceCapabilities = "{\"com.example.bms\":{\"name\":\"bms\"},\"com.example.bms\":{}}";

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
    EXPECT_EQ(appProvisionInfo.appServiceCapabilities, newProvisionInfo.appServiceCapabilities);

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
 * @tc.number: SaveInstallParamInfo_0004
 * @tc.name: test the start function of SaveInstallParamInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveInstallParamInfo_0004, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallParam installParam;
    ErrCode ret = installer.Install(installParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SaveInstallParamInfo_0005
 * @tc.name: test the start function of SaveInstallParamInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveInstallParamInfo_0005, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    ErrCode res = installer.MkdirIfNotExist("test/test");
    installer.RollBack();
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: SaveInstallParamInfo_0006
 * @tc.name: test the start function of SaveInstallParamInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveInstallParamInfo_0006, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    ErrCode res = installer.CheckAppLabelInfo();
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: SaveInstallParamInfo_0007
 * @tc.name: test the start function of SaveInstallParamInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveInstallParamInfo_0007, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallParam installParam;
    installParam.specifiedDistributionType = "specifiedDistributionType";
    installer.SaveInstallParamInfo("", installParam);

    std::string specifiedDistributionType;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType("",
        specifiedDistributionType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SaveInstallParamInfo_0008
 * @tc.name: test the start function of SaveInstallParamInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveInstallParamInfo_0008, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallParam installParam;
    installParam.specifiedDistributionType = "";
    installParam.additionalInfo = "additionalInfo";
    installer.SaveInstallParamInfo("", installParam);

    std::string specifiedDistributionType;
    bool ret = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType("",
        specifiedDistributionType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_0100
 * @tc.name: test the start function of InnerSharedBundleInstaller
 * @tc.desc: 1.Test CheckBundleTypeWithInstalledVersion
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_0100, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    installer.oldBundleInfo_ = innerBundleInfo;
    std::unordered_map<std::string, InnerBundleInfo> parsedBundles;
    parsedBundles[HAP_FILE_PATH1] = innerBundleInfo;
    installer.parsedBundles_ = parsedBundles;
    auto ret = installer.CheckBundleTypeWithInstalledVersion();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_0200
 * @tc.name: test the start function of InnerSharedBundleInstaller
 * @tc.desc: 1.Test CheckBundleTypeWithInstalledVersion
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_0200, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    installer.oldBundleInfo_ = innerBundleInfo;
    std::unordered_map<std::string, InnerBundleInfo> parsedBundles;
    parsedBundles[HAP_FILE_PATH1] = innerBundleInfo;
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos;
    std::vector<InnerModuleInfo> innerModuleInfos;
    innerSharedModuleInfos[HAP_FILE_PATH1] = innerModuleInfos;
    installer.parsedBundles_ = parsedBundles;
    innerBundleInfo.innerSharedModuleInfos_ = innerSharedModuleInfos;
    auto ret = installer.CheckBundleTypeWithInstalledVersion();
    EXPECT_EQ(ret, ERR_OK);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfos.emplace_back(innerModuleInfo);
    innerSharedModuleInfos[HAP_FILE_PATH1] = innerModuleInfos;
    ret = installer.CheckBundleTypeWithInstalledVersion();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_0400
 * @tc.name: test the start function of InnerSharedBundleInstaller
 * @tc.desc: 1.Test CheckBundleTypeWithInstalledVersion
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_0400, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InnerBundleInfo newInfo;
    auto ret = installer.ExtractSharedBundles("", newInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_0500
 * @tc.name: test the start function of CopyHspToSecurityDir
 * @tc.desc: 1.Test CopyHspToSecurityDir
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_0500, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::vector<std::string> bundlePaths = {"stream_install"};
    auto ret = installer.CopyHspToSecurityDir(bundlePaths);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED);

    bundlePaths.clear();
    bundlePaths.emplace_back(HSP_FILE_PATH1);
    ret = installer.CopyHspToSecurityDir(bundlePaths);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_0600
 * @tc.name: test the start function of ObtainHspFileAndSignatureFilePath
 * @tc.desc: 1.Test ObtainHspFileAndSignatureFilePath
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_0600, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::vector<std::string> inBundlePaths;
    std::vector<std::string> bundlePaths;
    std::string signatureFilePath;
    auto ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePaths, bundlePaths, signatureFilePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);

    inBundlePaths.emplace_back(HSP_FILE_PATH1);
    ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePaths, bundlePaths, signatureFilePath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_0700
 * @tc.name: test the start function of ObtainHspFileAndSignatureFilePath
 * @tc.desc: 1.Test ObtainHspFileAndSignatureFilePath
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_0700, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::vector<std::string> inBundlePaths = {HSP_FILE_PATH1};
    std::vector<std::string> bundlePaths;
    std::string signatureFilePath;
    auto ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePaths, bundlePaths, signatureFilePath);
    EXPECT_EQ(ret, ERR_OK);
    inBundlePaths.emplace_back(HAP_FILE_PATH1);
    inBundlePaths.emplace_back(HSP_FILE_PATH1);
    ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePaths, bundlePaths, signatureFilePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_0800
 * @tc.name: test the start function of ObtainHspFileAndSignatureFilePath
 * @tc.desc: 1.Test ObtainHspFileAndSignatureFilePath
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_0800, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::vector<std::string> inBundlePaths = {HAP_FILE_PATH1, HAP_FILE_PATH1};
    std::vector<std::string> bundlePaths;
    std::string signatureFilePath;
    auto ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePaths, bundlePaths, signatureFilePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);

    inBundlePaths.clear();
    inBundlePaths = {HSP_FILE_PATH1, HSP_FILE_PATH1};
    ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePaths, bundlePaths, signatureFilePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);

    inBundlePaths[0] = "test.sig";
    ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePaths, bundlePaths, signatureFilePath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_0900
 * @tc.name: test the start function of ObtainTempSoPath
 * @tc.desc: 1.Test ObtainTempSoPath
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_0900, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    auto ret = installer.ObtainTempSoPath(TEST_MODULE_NAME, "");
    EXPECT_EQ(ret, "");
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_1000
 * @tc.name: test the start function of ObtainTempSoPath
 * @tc.desc: 1.Test ObtainTempSoPath
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_1000, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::string nativeLibPath = HAP_FILE_PATH1;
    std::string ret = installer.ObtainTempSoPath(TEST_MODULE_NAME, nativeLibPath);
    EXPECT_EQ(ret, TEST_MODULE_NAME_TMP + HAP_FILE_PATH1 + PATH_SEPARATOR);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_1100
 * @tc.name: test the start function of ObtainTempSoPath
 * @tc.desc: 1.Test ObtainTempSoPath
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_1100, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::string nativeLibPath = "path/testModuleName";
    std::string ret = installer.ObtainTempSoPath(TEST_MODULE_NAME, nativeLibPath);
    EXPECT_EQ(ret, nativeLibPath + "_tmp/");
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_1200
 * @tc.name: test the start function of ObtainTempSoPath
 * @tc.desc: 1.Test ObtainTempSoPath
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_1200, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::string versionDir = "data/test";
    auto ret = installer.MoveSoToRealPath(TEST_MODULE_NAME, versionDir);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_1300
 * @tc.name: test the start function of ObtainTempSoPath
 * @tc.desc: 1.Test ObtainTempSoPath
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_1300, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    installer.nativeLibraryPath_ = "path/testModuleName";
    std::string versionDir = "data/test";
    auto ret = installer.MoveSoToRealPath(TEST_MODULE_NAME, versionDir);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED);
}

/**
 * @tc.number: InnerSharedBundleInstallerTest_1400
 * @tc.name: test the start function of ObtainTempSoPath
 * @tc.desc: 1.Test ObtainTempSoPath
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerSharedBundleInstallerTest_1400, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::string versionDir = "data/test";
    InnerBundleInfo newInfo;
    auto ret = installer.ProcessNativeLibrary(
        HAP_FILE_PATH1, TEST_MODULE_NAME, TEST_MODULE_NAME, versionDir, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerProcessStockBundleProvisionInfo_0001
 * @tc.name: test the start function of InnerProcessStockBundleProvisionInfo
 * @tc.desc: call InnerProcessStockBundleProvisionInfo, no bundleInfos
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, InnerProcessStockBundleProvisionInfo_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
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
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
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
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
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
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
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
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
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
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
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
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
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
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
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
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
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

/**
 * @tc.number: ParseHapFiles_0001
 * @tc.name: test the start function of ParseHapFiles
 * @tc.desc: 1. install hap
 *           2. call ParseHapFiles
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ParseHapFiles_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::vector<std::string> bundlePath;
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.sharedBundleDirPaths = std::vector<std::string>{HSP_FILE_PATH1};
    ErrCode installResult = InstallBundle(bundlePath, installParam);
    EXPECT_EQ(installResult, ERR_OK);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    auto iter = handler->ParseHapFiles(HSP_FILE_PATH1, infos);
    EXPECT_EQ(iter, true);

    ErrCode unInstallResult = UninstallSharedBundle(HSP_BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: ProcessRebootQuickFixBundleInstall_0001
 * @tc.name: test the start function of ProcessRebootQuickFixBundleInstall
 * @tc.desc: 1. test ProcessRebootQuickFixBundleInstall
 *           2. path not exist, bundle not exist
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessRebootQuickFixBundleInstall_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if ((handler != nullptr) && (dataMgr != nullptr)) {
        handler->ProcessRebootQuickFixBundleInstall(NOT_EXIST_PATH, false);
        BundleInfo info;
        bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, info, USERID);
        EXPECT_FALSE(result);

        handler->ProcessRebootQuickFixBundleInstall(EXIST_PATH, false);
        result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, info, USERID);
        EXPECT_FALSE(result);
    }
}

/**
 * @tc.number: ProcessRebootQuickFixBundleInstall_0002
 * @tc.name: test the start function of ProcessRebootQuickFixBundleInstall
 * @tc.desc: 1. test ProcessRebootQuickFixBundleInstall
 *           2. path exist, bundle exist, update success
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessRebootQuickFixBundleInstall_0002, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if ((handler != nullptr) && (dataMgr != nullptr)) {
        ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
        EXPECT_EQ(installResult, ERR_OK);

        BundleInfo info;
        bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, info, USERID);
        EXPECT_TRUE(result);
        EXPECT_EQ(info.name, BUNDLE_NAME);

        handler->ProcessRebootQuickFixBundleInstall(EXIST_PATH, false);
        BundleInfo newInfo;
        result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, newInfo, USERID);
        EXPECT_TRUE(result);
        EXPECT_EQ(info.versionCode, newInfo.versionCode); // update failed, keep alive is false
        EXPECT_EQ(info.installTime, newInfo.updateTime);

        ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
        EXPECT_EQ(unInstallResult, ERR_OK);
    }
}

/**
 * @tc.number: ProcessRebootQuickFixBundleInstall_0003
 * @tc.name: test the start function of ProcessRebootQuickFixBundleInstall
 * @tc.desc: 1. test ProcessRebootQuickFixBundleInstall
 *           2. path exist, bundle exist, update failed
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessRebootQuickFixBundleInstall_0003, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if ((handler != nullptr) && (dataMgr != nullptr)) {
        ErrCode installResult = InstallBundle(HAP_FILE_PATH2);
        EXPECT_EQ(installResult, ERR_OK);

        BundleInfo info;
        bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, info, USERID);
        EXPECT_TRUE(result);
        EXPECT_EQ(info.name, BUNDLE_NAME);

        handler->ProcessRebootQuickFixBundleInstall(EXIST_PATH, false);
        BundleInfo newInfo;
        result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, newInfo, USERID);
        EXPECT_TRUE(result);
        EXPECT_EQ(info.versionCode, newInfo.versionCode); // update failed, versionCode is same
        EXPECT_EQ(info.installTime, newInfo.updateTime);

        ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
        EXPECT_EQ(unInstallResult, ERR_OK);
    }
}

/**
 * @tc.number: ProcessRebootQuickFixBundleInstall_0004
 * @tc.name: test the start function of ProcessRebootQuickFixBundleInstall
 * @tc.desc: 1. test ProcessRebootQuickFixBundleInstall
 *           2. path exist, bundle not exist, update failed
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessRebootQuickFixBundleInstall_0004, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if ((handler != nullptr) && (dataMgr != nullptr)) {
        handler->ProcessRebootQuickFixBundleInstall(EXIST_PATH, true);
        BundleInfo newInfo;
        bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, newInfo, USERID);
        EXPECT_FALSE(result);
    }
}

/**
 * @tc.number: ProcessRebootQuickFixBundleInstall_0005
 * @tc.name: test the start function of ProcessRebootQuickFixBundleInstall
 * @tc.desc: 1. test ProcessRebootQuickFixBundleInstall
 *           2. path exist, parse filed
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessRebootQuickFixBundleInstall_0005, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if ((handler != nullptr) && (dataMgr != nullptr)) {
        handler->ProcessRebootQuickFixBundleInstall(EXIST_PATH2, false);
        BundleInfo newInfo;
        bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, newInfo, USERID);
        EXPECT_FALSE(result);
    }
}

/**
 * @tc.number: ProcessRebootQuickFixUnInstallAndRecover_0001
 * @tc.name: test the start function of ProcessRebootQuickFixUnInstallAndRecover
 * @tc.desc: 1. test ProcessRebootQuickFixUnInstallAndRecover
 *           2. path not exist, result filed
 */
HWTEST_F(BmsBundleAppProvisionInfoTest, ProcessRebootQuickFixUnInstallAndRecover_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if ((handler != nullptr) && (dataMgr != nullptr)) {
        BundleInfo oldInfo;
        bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, oldInfo, USERID);
        EXPECT_TRUE(result);
        uint32_t oldVersionCode = oldInfo.versionCode;
        handler->ProcessRebootQuickFixUnInstallAndRecover(NOT_EXIST_PATH);
        BundleInfo newInfo;
        result = dataMgr->GetBundleInfo(BUNDLE_NAME, 0, newInfo, USERID);
        EXPECT_TRUE(result);
        EXPECT_EQ(oldVersionCode, newInfo.versionCode);
    }
}

/**
 * @tc.number: ParseFiles_0001
 * @tc.name: test the start function of ParseFiles
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, ParseFiles_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallCheckParam checkParam;
    ErrCode ret = installer.ParseFiles(checkParam);
    EXPECT_NE(ret, ERR_OK);
    checkParam.isPreInstallApp = true;
    EXPECT_NE(ERR_OK, installer.ParseFiles(checkParam));
    EXPECT_EQ(0, installer.GetBundleName().size());
}
/**
 * @tc.number: CheckDependency_0001
 * @tc.name: test the start function of CheckDependency
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, CheckDependency_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    Dependency dependency;
    bool ret = installer.CheckDependency(dependency);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetCheckResultMsg_0001
 * @tc.name: test the start function of SetCheckResultMsg
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SetCheckResultMsg_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    string checkResultMsg;
    installer.SetCheckResultMsg(checkResultMsg);
    EXPECT_EQ(installer.bundleInstallChecker_->GetCheckResultMsg(), checkResultMsg);
}

/**
 * @tc.number: SendBundleSystemEvent_0001
 * @tc.name: test the start function of SendBundleSystemEvent
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SendBundleSystemEvent_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    EventInfo eventTemplate;
    installer.SendBundleSystemEvent(eventTemplate);
    ASSERT_FALSE(installer.isBundleExist_);
}

/**
 * @tc.number: SendStartSharedBundleInstallNotify_0001
 * @tc.name: test the start function of sendStartSharedBundleInstallNotify
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SendStartSharedBundleInstallNotify_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallCheckParam installCheckParam;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    installer.sendStartSharedBundleInstallNotify(installCheckParam, infos);
    ASSERT_TRUE(true);

    installCheckParam.needSendEvent = false;
    installer.sendStartSharedBundleInstallNotify(installCheckParam, infos);

    ASSERT_TRUE(true);
}

/**
 * @tc.number: NotifyBundleStatusOfShared_0001
 * @tc.name: test the start function of NotifyBundleStatusOfShared
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, NotifyBundleStatusOfShared_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    NotifyBundleEvents installRes;
    ErrCode ret ;
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(std::make_shared<BundleDataMgr>());
    ret = installer.NotifyBundleStatusOfShared(installRes);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: Install_0001
 * @tc.name: test the start function of Install
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, Install_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallParam installParam;
    std::unordered_map<std::string, InnerBundleInfo> parsedBundles_;
    ErrCode ret = installer.Install(installParam);
    auto reseult = parsedBundles_.empty();
    ASSERT_TRUE(reseult);
    EXPECT_EQ(ret, ERR_OK);
}
/**
 * @tc.number: DeliveryProfileToCodeSign_0001
 * @tc.name: test the start function of DeliveryProfileToCodeSign
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, DeliveryProfileToCodeSign_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    ErrCode ret = installer.DeliveryProfileToCodeSign(hapVerifyResults);

    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.profileBlockLength = 0 ;
    installer.DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: MergeBundleInfos_0001
 * @tc.name: test the start function of MergeBundleInfos
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, MergeBundleInfos_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    installer.parsedBundles_["test"] = InnerBundleInfo();
    installer.MergeBundleInfos();
    ASSERT_TRUE(installer.newBundleInfo_.baseApplicationInfo_->hideDesktopIcon);
}

/**
 * @tc.number: SavePreInstallInfo_0001
 * @tc.name: test the start function of SavePreInstallInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SavePreInstallInfo_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    InstallParam installParam;
    installer.SavePreInstallInfo(installParam);
    installParam.needSavePreInstallInfo = true;
    ErrCode ret;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_.reset();
    ret = installer.SavePreInstallInfo(installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(std::make_shared<BundleDataMgr>());
    ret = installer.SavePreInstallInfo(installParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SaveBundleInfoToStorage_0001
 * @tc.name: test the start function of SaveBundleInfoToStorage
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveBundleInfoToStorage_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    ErrCode ret = installer.SaveBundleInfoToStorage();
    installer.isBundleExist_ = true;
    installer.SaveBundleInfoToStorage();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_.reset();
    installer.SaveBundleInfoToStorage();
    ASSERT_FALSE(installer.newBundleInfo_.baseApplicationInfo_->hideDesktopIcon);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetInstallEventInfo_0001
 * @tc.name: test the start function of GetInstallEventInfo
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, GetInstallEventInfo_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    EventInfo eventInfo;
    installer.GetInstallEventInfo(eventInfo);
    ASSERT_EQ(eventInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_NONE);
    ASSERT_TRUE(eventInfo.hideDesktopIcon);
}

/**
 * @tc.number: SaveHspToRealInstallationDir_0001
 * @tc.name: test the start function of SaveHspToRealInstallationDir
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, SaveHspToRealInstallationDir_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::string bundlePath;
    std::string moduleDir;
    std::string moduleName;
    std::string realHspPath;
    std::string signatureFileDir_;

    signatureFileDir_ = "test_signature_file_dir";
    ErrCode ret = installer.SaveHspToRealInstallationDir(bundlePath, moduleDir, moduleName, realHspPath);

    signatureFileDir_ = " ";
    installer.SaveHspToRealInstallationDir(bundlePath, moduleDir, moduleName, realHspPath);

    ErrCode result = ERR_DEAD_OBJECT;
    installer.SaveHspToRealInstallationDir(bundlePath, moduleDir, moduleName, realHspPath);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.number: VerifyCodeSignatureForNativeFiles_0001
 * @tc.name: test the start function of VerifyCodeSignatureForNativeFiles
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, VerifyCodeSignatureForNativeFiles_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::string bundlePath;
    std::string cpuAbi;
    std::string targetSoPath;
    std::string signatureFileDir;
    bool isPreInstalledBundle = false;
    ErrCode ret = installer.VerifyCodeSignatureForNativeFiles(bundlePath,
    cpuAbi, targetSoPath, signatureFileDir, isPreInstalledBundle);

    isPreInstalledBundle = true;
    installer.VerifyCodeSignatureForNativeFiles(bundlePath,
    cpuAbi, targetSoPath, signatureFileDir, isPreInstalledBundle);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: VerifyCodeSignatureForHsp_0001
 * @tc.name: test the start function of VerifyCodeSignatureForHsp
*/
HWTEST_F(BmsBundleAppProvisionInfoTest, VerifyCodeSignatureForHsp_0001, Function | SmallTest | Level0)
{
    InnerSharedBundleInstaller installer(HAP_FILE_PATH1);
    std::string tempHspPath;
    std::string appIdentifier;
    bool isEnterpriseBundle = false;
    bool isCompileSdkOpenHarmony = false;
    std::string bundleName;
    ErrCode ret = installer.VerifyCodeSignatureForHsp(tempHspPath, appIdentifier,
    isEnterpriseBundle, isCompileSdkOpenHarmony, bundleName);
    EXPECT_NE(ret, ERR_OK);
}
} // OHOS