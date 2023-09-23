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

#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "system_bundle_installer.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using namespace OHOS;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.driverTest";
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/driver_test/";
const std::string NON_DRIVER_ENTRY_BUNDLE = "non_driver_entry_hap.hap";
const std::string DRIVER_FEATURE_BUNDLE = "driver_feature_hap.hap";
const std::string DRIVER_FEATURE1_BUNDLE = "driver_feature1_hap.hap";
const std::string DRIVER_FEATURE2_BUNDLE = "driver_feature2_hap.hap";
const std::string DRIVER_FEATURE3_BUNDLE = "driver_feature3_hap.hap";
const std::string DRIVER_FEATURE4_BUNDLE = "driver_feature4_hap.hap";
const std::string DRIVER_FEATURE5_BUNDLE = "driver_feature5_hap.hap";
const std::string DRIVER_FEATURE6_BUNDLE = "driver_feature6_hap.hap";
const std::string DRIVER_FEATURE7_BUNDLE = "driver_feature7_hap.hap";
const std::string DRIVER_FEATURE8_BUNDLE = "driver_feature8_hap.hap";
const std::string DRIVER_FEATURE9_BUNDLE = "driver_feature9_hap.hap";
const std::string DRIVER_FEATURE10_BUNDLE = "driver_feature10_hap.hap";
const std::string NON_DRIVER_ENTRY1_BUNDLE = "non_driver_entry1_hap.hap";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.driverTest";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.driverTest";
const std::string PACKAGE_NAME_FIRST = "com.example.driverTest";
const std::string DRIVER_FILE_DIR = "/data/service/el1/public/print_service/cups/datadir/model/";
const std::string DRIVER_FILE_NAME = "main_pages.json";
const std::string MODULE_NAME_FEATURE6 = "feature6";
const std::string PATH_UNDERLIND = "_";
const std::string DEVICE_TYPE_OF_DEFAULT = "default";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::vector<std::string> BUNDLE_DATA_DIR_PAGENAME = {
    "cache",
    "files",
    "temp",
    "preferences",
    "haps",
};
}  // namespace

extern char *g_testDeviceType;

class BmsDriverInstallerTest : public testing::Test {
public:
    BmsDriverInstallerTest();
    ~BmsDriverInstallerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::vector<std::string> &bundlePaths);
    ErrCode UninstallBundle(const std::string &bundleName) const;
    void CheckBundleDirExist() const;
    void CheckBundleDirNonExist() const;
    bool IsDriverDirEmpty() const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StopInstalldService() const;
    void StopBundleService();
    void CheckModuleDirExist() const;
    void CheckModuleDirNonExist(const std::string &packageName) const;
    bool IsFileExisted(const std::string &filePath) const;

private:
    static bool isDriverDirNeedRemoved_;
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsDriverInstallerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsDriverInstallerTest::installdService_ =
    std::make_shared<InstalldService>();

bool BmsDriverInstallerTest::isDriverDirNeedRemoved_ = false;

BmsDriverInstallerTest::BmsDriverInstallerTest()
{}

BmsDriverInstallerTest::~BmsDriverInstallerTest()
{}

ErrCode BmsDriverInstallerTest::InstallBundle(const std::vector<std::string> &bundlePaths)
{
    g_testDeviceType = const_cast<char *>(DEVICE_TYPE_OF_DEFAULT.c_str());
    if (bundleMgrService_ == nullptr) {
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    auto result = installer->Install(bundlePaths, installParam, receiver);
    return receiver->GetResultCode();
}

ErrCode BmsDriverInstallerTest::UninstallBundle(const std::string &bundleName) const
{
    if (bundleMgrService_ == nullptr) {
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
    installParam.userId = USERID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsDriverInstallerTest::SetUpTestCase()
{
}

void BmsDriverInstallerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsDriverInstallerTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    if (access(DRIVER_FILE_DIR.c_str(), F_OK) == 0) {
        return;
    }
    if (OHOS::ForceCreateDirectory(DRIVER_FILE_DIR)) {
        isDriverDirNeedRemoved_ = true;
    }
}

void BmsDriverInstallerTest::TearDown()
{
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
    if (isDriverDirNeedRemoved_) {
        OHOS::ForceRemoveDirectory(DRIVER_FILE_DIR);
        isDriverDirNeedRemoved_ = false;
    }
}

void BmsDriverInstallerTest::CheckBundleDirExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleCodeExist, 0) << "the bundle code dir does not exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleDataExist, 0) << "the bundle data dir does not exists: " << BUNDLE_DATA_DIR;
}

void BmsDriverInstallerTest::CheckBundleDirNonExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_NE(bundleCodeExist, 0) << "the bundle code dir exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_NE(bundleDataExist, 0) << "the bundle data dir exists: " << BUNDLE_DATA_DIR;
}

bool BmsDriverInstallerTest::IsDriverDirEmpty() const
{
    return OHOS::IsEmptyFolder(DRIVER_FILE_DIR);
}

void BmsDriverInstallerTest::CheckModuleDirExist() const
{
    for (unsigned long i = 0; i < BUNDLE_DATA_DIR_PAGENAME.size(); i++) {
        auto moduleDataExist = access((BUNDLE_DATA_DIR + "/" + BUNDLE_DATA_DIR_PAGENAME[i]).c_str(), F_OK);
        EXPECT_EQ(moduleDataExist, 0);
    }
    int codeDirExist = access((BUNDLE_CODE_DIR).c_str(), F_OK);
    EXPECT_EQ(codeDirExist, 0);
}

void BmsDriverInstallerTest::CheckModuleDirNonExist(const std::string &packageName) const
{
    int moduleCodeExist = access((BUNDLE_CODE_DIR + "/" + packageName).c_str(), F_OK);
    int moduleDataExist = access((BUNDLE_DATA_DIR + "/" + packageName).c_str(), F_OK);
    EXPECT_NE(moduleCodeExist, 0);
    EXPECT_NE(moduleDataExist, 0);
}

bool BmsDriverInstallerTest::IsFileExisted(const std::string &filePath) const
{
    return access(filePath.c_str(), F_OK) == 0;
}

const std::shared_ptr<BundleDataMgr> BmsDriverInstallerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

void BmsDriverInstallerTest::StopInstalldService() const
{
    if (installdService_->IsServiceReady()) {
        installdService_->Stop();
        InstalldClient::GetInstance()->ResetInstalldProxy();
    }
}

void BmsDriverInstallerTest::StopBundleService()
{
    if (bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStop();
        bundleMgrService_.reset();
    }
}

/**
 * @tc.number: InstallDriverTest_0100
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install bundle of non-driver type.
 *           2. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirExist();
    CheckModuleDirExist();
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_0200
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install bundle of driver type, but without metadata
 *           2. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirExist();
    CheckModuleDirExist();
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_0300
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install bundle of driver type with metadata, but name of metadata does not satisify the rule
                to copy file.
 *           2. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE1_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirExist();
    CheckModuleDirExist();
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_0400
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install bundle of driver type, the resource path is not existed
 *           2. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_0400, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE2_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_0500
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install bundle of driver type, the prefix of the resource path does not contain "/resources/rawfile/"
 *           2. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_0500, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE3_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_0600
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install bundle of driver type, the target dir is not existed
 *           2. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_0600, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE4_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_0700
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install bundle of driver type, the prefix of the target dir does not contain
                "/data/service/el1/public/print_service/cups/".
 *           2. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_0700, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE5_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_0800
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install bundle of driver type, the resource dir and target dir are valid.
 *           2. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_0800, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE6_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirExist();
    CheckModuleDirExist();

    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_FALSE(isDirEmpty);
    // /data/service/el1/public/print_service/cups/datadir/model/com.example.driverTest_feature6_main_pages.json
    std::string filePath = DRIVER_FILE_DIR + BUNDLE_NAME + PATH_UNDERLIND + MODULE_NAME_FEATURE6 + PATH_UNDERLIND +
        DRIVER_FILE_NAME;
    bool fileExisted = IsFileExisted(filePath);
    EXPECT_TRUE(fileExisted);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_0900
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install multi-bundles of non-driver type.
 *           2. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_0900, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY_BUNDLE,
        RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY1_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirExist();
    CheckModuleDirExist();
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_1000
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, part of them are driver type and without metadata.
 *           2. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1000, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirExist();
    CheckModuleDirExist();
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_1100
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, part of them are driver type and name of metadata does not satisify the rule
                to copy file.
 *           2. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE1_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirExist();
    CheckModuleDirExist();
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_1200
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, part of them are driver type and the resource path is not existed.
 *           2. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE2_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_1300
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, part of them are driver type and the prefix of the resource path does not
                contain "/resources/rawfile/".
 *           2. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1300, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE3_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_1400
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, part of them are driver type and the target dir is not existed.
 *           2. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1400, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE4_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_1500
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, part of them are driver type and the prefix of the target dir does not contain
                "/data/service/el1/public/print_service/cups/".
 *           2. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1500, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE5_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_1600
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, part of them are driver type and the resource dir and target dir are valid.
 *           2. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1600, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + NON_DRIVER_ENTRY_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE6_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_FALSE(isDirEmpty);
    // /data/service/el1/public/print_service/cups/datadir/model/com.example.driverTest_feature6_main_pages.json
    std::string filePath = DRIVER_FILE_DIR + BUNDLE_NAME + PATH_UNDERLIND + MODULE_NAME_FEATURE6 + PATH_UNDERLIND +
        DRIVER_FILE_NAME;
    bool fileExisted = IsFileExisted(filePath);
    EXPECT_TRUE(fileExisted);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_1700
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and without metdata.
 *           2. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1700, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE7_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_1800
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and part of them contain metdata.
 *           2. name of the metadata is not satisified the rule to copy driver files.
 *           3. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1800, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE1_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_1900
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and part of them contain metdata.
 *           2. name of the metadata is satisified the rule to copy driver files, but resources path is not existed.
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_1900, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE2_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_2000
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and part of them contain metdata.
 *           2. name of the metadata is satisified the rule to copy driver files, but resource path does not
 *              contain "/resources/rawfile/".
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2000, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE3_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_2100
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and part of them contain metdata.
 *           2. name of the metadata is satisified the rule to copy driver files, but the target dir is not existed.
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE4_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_2200
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and part of them contain metdata.
 *           2. name of the metadata is satisified the rule to copy driver files, but target dir does not contain
 *              "/data/service/el1/public/print_service/cups/".
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE5_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_2300
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and part of them contain metdata.
 *           2. name of the metadata is satisified the rule to copy driver files and resource dir and target dir
 *              are valid.
 *           3. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2300, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE6_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_FALSE(isDirEmpty);
    // /data/service/el1/public/print_service/cups/datadir/model/com.example.driverTest_feature6_main_pages.json
    std::string filePath = DRIVER_FILE_DIR + BUNDLE_NAME + PATH_UNDERLIND + MODULE_NAME_FEATURE6 + PATH_UNDERLIND +
        DRIVER_FILE_NAME;
    bool fileExisted = IsFileExisted(filePath);
    EXPECT_TRUE(fileExisted);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_2400
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. names of the metadata are not satisified the rule to copy driver files.
 *           3. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2400, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE1_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE8_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_2500
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. partial names of the metadata is satisified the rule to copy driver files, but resources path is
                not existed.
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2500, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE1_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE2_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_2600
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. partial names of the metadata is satisified the rule to copy driver files, but resource path does not
 *              contain "/resources/rawfile/".
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2600, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE1_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE3_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_2700
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. partial names of the metadata is satisified the rule to copy driver files, but the target dir is
                not existed.
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2700, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE1_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE4_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_2800
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. partial names of the metadata is satisified the rule to copy driver files, but target dir does not
 *              contain "/data/service/el1/public/print_service/cups/".
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2800, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE1_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE5_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_2900
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. partial names of the metadata is satisified the rule to copy driver files and resource dir and target dir
 *              are valid.
 *           3. install successfully.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_2900, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE1_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE6_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_OK);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_FALSE(isDirEmpty);
    // /data/service/el1/public/print_service/cups/datadir/model/com.example.driverTest_feature6_main_pages.json
    std::string filePath = DRIVER_FILE_DIR + BUNDLE_NAME + PATH_UNDERLIND + MODULE_NAME_FEATURE6 + PATH_UNDERLIND +
        DRIVER_FILE_NAME;
    bool fileExisted = IsFileExisted(filePath);
    EXPECT_TRUE(fileExisted);

    result = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    CheckBundleDirNonExist();
    CheckModuleDirNonExist(BUNDLE_NAME);
}

/**
 * @tc.number: InstallDriverTest_3000
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. name of the metadata is satisified the rule to copy driver files and resource dirs are invalid.
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_3000, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE2_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE9_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_3100
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. name of the metadata is satisified the rule to copy driver files and resource dirs are invalid.
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_3100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE3_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE9_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_3200
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. name of the metadata is satisified the rule to copy driver files and target dirs are invalid.
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_3200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE4_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE9_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}

/**
 * @tc.number: InstallDriverTest_3300
 * @tc.name: test the installation of driver bundle
 * @tc.desc: 1. install some haps, all of them are driver type and all contain metadata.
 *           2. name of the metadata is satisified the rule to copy driver files and target dirs are invalid.
 *           3. install failed.
 */
HWTEST_F(BmsDriverInstallerTest, InstallDriverTest_3300, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleFileVec = { RESOURCE_ROOT_PATH + DRIVER_FEATURE5_BUNDLE,
        RESOURCE_ROOT_PATH + DRIVER_FEATURE9_BUNDLE };
    ErrCode result = InstallBundle(bundleFileVec);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
    bool isDirEmpty = IsDriverDirEmpty();
    EXPECT_TRUE(isDirEmpty);
}
} // OHOS