/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_manager_host_impl.h"
#include "app_control_constants.h"
#endif
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "scope_guard.h"
#include "shared/shared_bundle_installer.h"
#include "system_bundle_installer.h"
#include "want.h"
#include "file_ex.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/install_bundle/";
const std::string OTAUPDATETESTBASIS_BUNDLE = "otaUpdateTestBasis.hap";
const std::string OTAUPDATETESTBASISFEATURE1_BUNDLE = "otaUpdateTestBasisFeature1.hap";
const std::string OTAUPDATETESTBASISFEATURE2_BUNDLE = "otaUpdateTestBasisFeature2.hap";
const std::string OTAUPDATETESTAPPFIELD_BUNDLE = "otaUpdateTestAppField.hap";
const std::string OTAUPDATETESTMODULEFIELD_BUNDLE = "otaUpdateTestModuleField.hap";
const std::string OTAUPDATETESTSIGNAICON_BUNDLE = "otaUpdateTestSignaIcon.hap";
const std::string OTAUPDATETEAPLUP_BUNDLE = "otaUpdateTestAplUp.hap";
const std::string OTAUPDATETEAPLDOWN_BUNDLE = "otaUpdateTestAplDown.hap";
const std::string OTAUPDATETESTSOCHANGED_BUNDLE = "otaUpdateTestSoChanged.hap";
const std::string OTAUPDATETESTSOCHANGEDFEATURE1_BUNDLE = "otaUpdateTestSoChangedFeature1.hap";
const std::string OTAUPDATETESTSOCHANGEDFEATURE2_BUNDLE = "otaUpdateTestSoChangedFeature2.hap";
const std::string BUNDLE_OTAUPDATETEST_NAME = "com.example.otaupdatetest";
const std::string OTAUPDATETESTBASIS2_BUNDLE = "otaUpdateTestBasis2.hap";
const std::string OTAUPDATETESTAPPFIELD2_BUNDLE = "otaUpdateTestAppField2.hap";
const int32_t WAIT_TIME = 5; // init mocked bms
const int32_t USERID = 100;
const int32_t USERID_2 = 101;
const int32_t VERSION_CODE1 = 1000000;
const int32_t VERSION_CODE2 = 2000000;
const std::string VERSION_NAME1 = "1.0.0.0";
const std::string VERSION_NAME2 = "2.0.0.0";
const std::string APL_NORMAL = "normal";
const std::string APL_BASIC = "system_basic";
const std::string APL_CORE = "system_core";
const std::string MODULE_NAME1 = "entry1";
const std::string MODULE_NAME2 = "entry2";
const std::string PROCESS_BASIS = "basis";
const std::string PROCESS_MODULEFIELD = "modulefield";
}  // namespace

class BmsBundleOtaUpdateTest : public testing::Test {
public:
    BmsBundleOtaUpdateTest();
    ~BmsBundleOtaUpdateTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool InstallSystemBundle(const std::string &filePath) const;
    bool OTAInstallSystemBundle(const std::string &filePath) const;
    bool OTAInstallSystemBundle(const std::vector<std::string> &filePaths) const;
    void CheckFileExist() const;
    void CheckFileNonExist() const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    const std::shared_ptr<BundleInstallerManager> GetBundleInstallerManager() const;
    void StopInstalldService() const;
    void StopBundleService();
    void CreateInstallerManager();
    void ClearBundleInfo();
    void ClearDataMgr();
    void ResetDataMgr();

private:
    std::shared_ptr<BundleInstallerManager> manager_ = nullptr;
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleOtaUpdateTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleOtaUpdateTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleOtaUpdateTest::BmsBundleOtaUpdateTest()
{}

BmsBundleOtaUpdateTest::~BmsBundleOtaUpdateTest()
{}

bool BmsBundleOtaUpdateTest::InstallSystemBundle(const std::string &filePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    auto installer = std::make_unique<SystemBundleInstaller>();
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    setuid(Constants::FOUNDATION_UID);
    installParam.SetKillProcess(false);
    setuid(Constants::ROOT_UID);
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    return installer->InstallSystemBundle(
        filePath, installParam, Constants::AppType::SYSTEM_APP) == ERR_OK;
}

bool BmsBundleOtaUpdateTest::OTAInstallSystemBundle(const std::vector<std::string> &filePaths) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    auto installer = std::make_unique<SystemBundleInstaller>();
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    setuid(Constants::FOUNDATION_UID);
    installParam.SetKillProcess(false);
    setuid(Constants::ROOT_UID);
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    return installer->OTAInstallSystemBundle(
        filePaths, installParam, Constants::AppType::SYSTEM_APP) == ERR_OK;
}

bool BmsBundleOtaUpdateTest::OTAInstallSystemBundle(const std::string &filePath) const
{
    std::vector<std::string> filePaths;
    filePaths.push_back(filePath);
    return OTAInstallSystemBundle(filePaths);
}

void BmsBundleOtaUpdateTest::SetUpTestCase()
{
}

void BmsBundleOtaUpdateTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleOtaUpdateTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleOtaUpdateTest::TearDown()
{
}

const std::shared_ptr<BundleDataMgr> BmsBundleOtaUpdateTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: SUB_BMS_OTA_0001
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. The system bundle file exists.
 *           2. Lower version of the hap is installed successfully.
 *           3. It's updated to a higher version successfully.
 *           4. Some fields defined in app.json, which will serve as a basis for
 *              judging the update success, are as follows:
 *                  "versionCode": 1000000 -> 2000000
 *                  "versionName": "1.0.0.0" -> "2.0.0.0"
 *                  "asanEnabled": true -> false
 *                  "GWPAsanEnabled": true -> false
 *                  "tsanEnabled": false -> true
 *                  "hwasanEnabled": false -> false
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_0001, Function | SmallTest | Level3)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS_BUNDLE;
    std::string bundleName = BUNDLE_OTAUPDATETEST_NAME;
    bool ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr) << "the dataMgr is nullptr";
    ApplicationInfo applicationInfo;
    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.versionCode, VERSION_CODE1);
    EXPECT_EQ(applicationInfo.versionName, VERSION_NAME1);
    EXPECT_TRUE(applicationInfo.asanEnabled);
    EXPECT_TRUE(applicationInfo.gwpAsanEnabled);
    EXPECT_FALSE(applicationInfo.tsanEnabled);
    EXPECT_FALSE(applicationInfo.hwasanEnabled);

    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTAPPFIELD_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the update failed: " << bundleFile;

    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.versionCode, VERSION_CODE2);
    EXPECT_EQ(applicationInfo.versionName, VERSION_NAME2);
    EXPECT_FALSE(applicationInfo.asanEnabled);
    EXPECT_FALSE(applicationInfo.gwpAsanEnabled);
    EXPECT_TRUE(applicationInfo.tsanEnabled);
    EXPECT_FALSE(applicationInfo.hwasanEnabled);

    auto installer = std::make_unique<SystemBundleInstaller>();
    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(bundleName);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}

/**
 * @tc.number: SUB_BMS_OTA_0002
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. The system bundle file exists.
 *           2. A lower version of the hap is installed successfully.
 *           3. It's updated to a higher version successfully.
 *           4. Some fields defined in module.json, which will serve as a basis for
 *              judging the update success, are as follows:
 *                  "name": "entry1" -> "entry2"
 *                  "process": "basis" -> "modulefield"
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_0002, Function | SmallTest | Level3)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS_BUNDLE;
    std::string bundleName = BUNDLE_OTAUPDATETEST_NAME;
    bool ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr) << "the dataMgr is nullptr";
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    abilityInfo.package = MODULE_NAME1;
    HapModuleInfo hapModuleInfo;
    ret = dataMgr->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(hapModuleInfo.name, MODULE_NAME1);
    EXPECT_EQ(hapModuleInfo.process, PROCESS_BASIS);

    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTMODULEFIELD_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the update failed: " << bundleFile;

    abilityInfo.bundleName = bundleName;
    abilityInfo.package = MODULE_NAME2;
    ret = dataMgr->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(hapModuleInfo.name, MODULE_NAME2);
    EXPECT_EQ(hapModuleInfo.process, PROCESS_MODULEFIELD);

    auto installer = std::make_unique<SystemBundleInstaller>();
    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(bundleName);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}

/**
 * @tc.number: SUB_BMS_OTA_0003
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. The system bundle file exists.
 *           2. A lower version of the hap is installed successfully.
 *           3. It's updated to a higher version successfully.
 *           4. The signature files of these two versions are different.
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_0003, Function | SmallTest | Level3)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS_BUNDLE;
    std::string bundleName = BUNDLE_OTAUPDATETEST_NAME;
    bool ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTSIGNAICON_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the update failed: " << bundleFile;

    auto installer = std::make_unique<SystemBundleInstaller>();
    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(bundleName);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}

/**
 * @tc.number: SUB_BMS_OTA_0004
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. the system bundle file exists
 *           2. A higher version of the hap is installed successfully.
 *           3. It's downgraded to a lower version successfully. However, only by uninstalling
 *              and installing again can a higher version be replaced with a lower.
 *           4. The icons of these two versions are different.
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_0004, Function | SmallTest | Level3)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTSIGNAICON_BUNDLE;
    std::string bundleName = BUNDLE_OTAUPDATETEST_NAME;
    bool ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_FALSE(ret) << "the install succeeded: " << bundleFile;

    auto installer = std::make_unique<SystemBundleInstaller>();
    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(bundleName);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}

/**
 * @tc.number: SUB_BMS_OTA_0005
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. The system bundle file exists.
 *           2. A lower version of the hap with so is installed successfully.
 *           3. It's updated to a higher version successfully.
 *           4. The change of so of different component, which will serve as a basis for
 *              judging the update success, are as follows:
 *                  entry: 0 so -> 2 so
 *                  feature1: 2 so -> 0 so
 *                  feature2: 2 so -> 1 so
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_0005, Function | SmallTest | Level3)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS_BUNDLE;
    std::string bundleName = BUNDLE_OTAUPDATETEST_NAME;
    bool ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr) << "the dataMgr is nullptr";
    ApplicationInfo applicationInfo;
    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.nativeLibraryPath, "");

    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASISFEATURE1_BUNDLE;
    ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;
    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASISFEATURE2_BUNDLE;
    ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_NE(applicationInfo.nativeLibraryPath, "");

    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTSOCHANGED_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the update failed: " << bundleFile;
    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTSOCHANGEDFEATURE1_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the update failed: " << bundleFile;
    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTSOCHANGEDFEATURE2_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the update failed: " << bundleFile;

    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_NE(applicationInfo.nativeLibraryPath, "");

    auto installer = std::make_unique<SystemBundleInstaller>();
    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(bundleName);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}

/**
 * @tc.number: SUB_BMS_OTA_0006
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. the system bundle file exists
 *           2. A lower version of the hap is installed successfully.
 *           3. It's updated to a higher version successfully.
 *           4. Apl of the lower version is system_basic, while apl of the
 *              higher version is system_core.
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_0006, Function | SmallTest | Level3)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS_BUNDLE;
    std::string bundleName = BUNDLE_OTAUPDATETEST_NAME;
    bool ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr) << "the dataMgr is nullptr";
    ApplicationInfo applicationInfo;
    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.appPrivilegeLevel, APL_BASIC);

    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETEAPLUP_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the update successed: " << bundleFile;

    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.appPrivilegeLevel, APL_CORE);

    auto installer = std::make_unique<SystemBundleInstaller>();
    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(bundleName);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}

/**
 * @tc.number: SUB_BMS_OTA_0007
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. the system bundle file exists
 *           2. A lower version of the hap is installed successfully.
 *           3. It's updated to a higher version successfully.
 *           4. Apl of the lower version is system_basic, while apl of the
 *              higher version is normal.
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_0007, Function | SmallTest | Level3)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS_BUNDLE;
    std::string bundleName = BUNDLE_OTAUPDATETEST_NAME;
    bool ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr) << "the dataMgr is nullptr";
    ApplicationInfo applicationInfo;
    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.appPrivilegeLevel, APL_BASIC);

    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETEAPLDOWN_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the update failed: " << bundleFile;

    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.appPrivilegeLevel, APL_NORMAL);

    auto installer = std::make_unique<SystemBundleInstaller>();
    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(bundleName);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}

/**
 * @tc.number: SUB_BMS_OTA_0008
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. the system bundle file exists
 *           2. It's updated to a higher version successfully.
 *           3. The high version has two haps with same bundlename and different
 *              modulenames so the ota interface needs to be called two times.
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_0008, Function | SmallTest | Level3)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS_BUNDLE;
    std::string bundleName = BUNDLE_OTAUPDATETEST_NAME;
    bool ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr) << "the dataMgr is nullptr";

    std::vector<string> bundleFiles;
    bundleFiles.push_back(RESOURCE_ROOT_PATH + OTAUPDATETESTSOCHANGED_BUNDLE);
    bundleFiles.push_back(RESOURCE_ROOT_PATH + OTAUPDATETESTSOCHANGEDFEATURE1_BUNDLE);
    bundleFiles.push_back(RESOURCE_ROOT_PATH + OTAUPDATETESTSOCHANGEDFEATURE2_BUNDLE);
    ret = OTAInstallSystemBundle(bundleFiles);
    EXPECT_TRUE(ret) << "the update failed";

    auto installer = std::make_unique<SystemBundleInstaller>();
    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(bundleName);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}

/**
 * @tc.number: SUB_BMS_OTA_0009
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. the system bundle file exists
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_0009, Function | SmallTest | Level3)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr) << "the dataMgr is nullptr";
    dataMgr->AddUserId(USERID);
    dataMgr->AddUserId(USERID_2);
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS_BUNDLE;
    std::vector<string> bundleFiles;
    bundleFiles.push_back(bundleFile);
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    setuid(Constants::FOUNDATION_UID);
    installParam.SetKillProcess(false);
    setuid(Constants::ROOT_UID);
    installParam.needSendEvent = false;
    installParam.copyHapToInstallPath = false;
    auto installer = std::make_unique<SystemBundleInstaller>();
    auto ret = installer->OTAInstallSystemBundle(
        bundleFiles, installParam, Constants::AppType::SYSTEM_APP);
    EXPECT_EQ(ret, ERR_OK);
    auto currentBundleUserIds = dataMgr->GetUserIds(BUNDLE_OTAUPDATETEST_NAME);
    EXPECT_EQ(currentBundleUserIds.size(), 2);

    ret = installer->UninstallBundle(BUNDLE_OTAUPDATETEST_NAME, installParam);
    EXPECT_EQ(ret, ERR_OK);
    currentBundleUserIds = dataMgr->GetUserIds(BUNDLE_OTAUPDATETEST_NAME);
    EXPECT_EQ(currentBundleUserIds.size(), 1);

    ret = installer->OTAInstallSystemBundleNeedCheckUser(bundleFiles, installParam, BUNDLE_OTAUPDATETEST_NAME,
        Constants::AppType::SYSTEM_APP);
    EXPECT_EQ(ret, ERR_OK);
    currentBundleUserIds = dataMgr->GetUserIds(BUNDLE_OTAUPDATETEST_NAME);
    EXPECT_EQ(currentBundleUserIds.size(), 1);

    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(BUNDLE_OTAUPDATETEST_NAME);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}

/**
 * @tc.number: SUB_BMS_OTA_00100
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1. The system bundle file exists.
 *           2. Lower version of the hap is installed successfully.
 *           3. It's updated to a higher version successfully.
 *           4. Some fields defined in app.json, which will serve as a basis for
 *              judging the update success, are as follows:
 *                  "versionCode": 1000000 -> 2000000
 *                  "versionName": "1.0.0.0" -> "2.0.0.0"
 *                  "hwasanEnabled": false -> true
 */
HWTEST_F(BmsBundleOtaUpdateTest, SUB_BMS_OTA_00100, Function | SmallTest | Level3)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTBASIS2_BUNDLE;
    std::string bundleName = BUNDLE_OTAUPDATETEST_NAME;
    bool ret = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the install failed: " << bundleFile;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr) << "the dataMgr is nullptr";
    ApplicationInfo applicationInfo;
    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.versionCode, VERSION_CODE1);
    EXPECT_EQ(applicationInfo.versionName, VERSION_NAME1);
    EXPECT_FALSE(applicationInfo.hwasanEnabled);

    bundleFile = RESOURCE_ROOT_PATH + OTAUPDATETESTAPPFIELD2_BUNDLE;
    ret = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(ret) << "the update failed: " << bundleFile;

    ret = dataMgr->GetApplicationInfo(bundleName, 0, USERID, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.versionCode, VERSION_CODE2);
    EXPECT_EQ(applicationInfo.versionName, VERSION_NAME2);
    EXPECT_TRUE(applicationInfo.hwasanEnabled);

    auto installer = std::make_unique<SystemBundleInstaller>();
    setuid(Constants::FOUNDATION_UID);
    ret = installer->UninstallSystemBundle(bundleName);
    setuid(Constants::ROOT_UID);
    EXPECT_TRUE(ret) << "the uninstall failed: " << bundleFile;
}
} // OHOS
