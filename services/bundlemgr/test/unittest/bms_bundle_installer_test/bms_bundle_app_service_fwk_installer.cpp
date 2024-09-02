/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "app_service_fwk/app_service_fwk_installer.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "scope_guard.h"
#include "shared/shared_bundle_installer.h"
#include "system_bundle_installer.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const int32_t DEFAULT_USERID = 0;
const int32_t USERID = 100;
const int32_t VERSION_LOW = 0;
const int32_t VERSION = 1000000;
const int32_t WAIT_TIME = 5; // init mocked bms
const int32_t VERSION_HIGH = INT32_MAX;
const std::string BUNDLE_NAME = "com.example.appService";
const std::string BUNDLE_NAME_WRONG = "com.example.appService.wrong";
const std::string BUNDLE_NAME_TEST = "com.example.l3jsdemo";
const std::string MODULE_NAME_TEST = "moduleName";
const std::string MODULE_NAME_LIBRARY_ONE = "library_one";
const std::string EMPTY_STRING = "";
const std::string STRING = "string";
const std::string HAP_PATH_TEST = "/data/test/resource/bms/app_service_test/right.hap";
const std::string VERSION_ONE_LIBRARY_ONE_PATH = "/data/test/resource/bms/app_service_test/appService_v1_library1.hsp";
const std::string VERSION_ONE_LIBRARY_TWO_PATH = "/data/test/resource/bms/app_service_test/appService_v1_library2.hsp";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.l3jsdemo";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const std::string BUNDLE_LIBRARY_PATH_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo/libs/arm";
const std::string TEST_CREATE_FILE_PATH = "/data/test/resource/bms/app_service_test/test_create_dir/test.hap";
const std::string BUILD_HASH = "8670157ae28ac2dc08075c4a9364e320898b4aaf4c1ab691df6afdb854a6811b";
}  // namespace

class BmsBundleAppServiceFwkInstallerTest : public testing::Test {
public:
    BmsBundleAppServiceFwkInstallerTest();
    ~BmsBundleAppServiceFwkInstallerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallSystemBundle(const std::string &filePath, int32_t userId) const;
    ErrCode UnInstallBundle(const std::string &bundleName, int32_t userId) const;
    ErrCode InstallSystemHsp(const std::string &filePath);
    bool DeletePreBundleInfo(const std::string &bundleName);
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    const std::shared_ptr<BundleInstallerManager> GetBundleInstallerManager() const;
    void AddBundleInfo(const std::string &bundleName, const InnerBundleInfo& info);
    void DeleteBundleInfo(const std::string &bundleName);
    void StopInstalldService() const;
    void StopBundleService();
    void CreateInstallerManager();
    void ClearBundleInfo(const std::string &bundleName);
    void ClearDataMgr();
    void ResetDataMgr();
    void InitAppServiceFwkInstaller(AppServiceFwkInstaller &appServiceFwkInstaller);

private:
    std::shared_ptr<BundleInstallerManager> manager_ = nullptr;
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleAppServiceFwkInstallerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleAppServiceFwkInstallerTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleAppServiceFwkInstallerTest::BmsBundleAppServiceFwkInstallerTest()
{}

BmsBundleAppServiceFwkInstallerTest::~BmsBundleAppServiceFwkInstallerTest()
{}

ErrCode BmsBundleAppServiceFwkInstallerTest::InstallSystemHsp(const std::string &filePath)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.removable = false;
    std::vector<std::string> hspPaths{ filePath };
    return appServiceFwkInstaller.Install(hspPaths, installParam);
}

ErrCode BmsBundleAppServiceFwkInstallerTest::InstallSystemBundle(const std::string &filePath, int32_t userId) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    auto installer = std::make_unique<SystemBundleInstaller>();
    InstallParam installParam;
    installParam.userId = userId;
    installParam.isPreInstallApp = true;
    installParam.SetNoSkipsKill(false);
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    return installer->InstallSystemBundle(
        filePath, installParam, Constants::AppType::SYSTEM_APP);
}

ErrCode BmsBundleAppServiceFwkInstallerTest::UnInstallBundle(const std::string &bundleName, int32_t userId) const
{
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
    installParam.userId = userId;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleAppServiceFwkInstallerTest::SetUpTestCase()
{
}

void BmsBundleAppServiceFwkInstallerTest::InitAppServiceFwkInstaller(AppServiceFwkInstaller &appServiceFwkInstaller)
{
    std::vector<std::string> hspPaths;
    hspPaths.push_back(VERSION_ONE_LIBRARY_ONE_PATH);
    InstallParam installParam;
    installParam.isPreInstallApp = true;

    appServiceFwkInstaller.BeforeInstall(hspPaths, installParam);
    appServiceFwkInstaller.versionUpgrade_ = false;
    appServiceFwkInstaller.moduleUpdate_ = false;
}

void BmsBundleAppServiceFwkInstallerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleAppServiceFwkInstallerTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleAppServiceFwkInstallerTest::TearDown()
{
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_LIBRARY_PATH_DIR);
}

const std::shared_ptr<BundleDataMgr> BmsBundleAppServiceFwkInstallerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

const std::shared_ptr<BundleInstallerManager> BmsBundleAppServiceFwkInstallerTest::GetBundleInstallerManager() const
{
    return manager_;
}

void BmsBundleAppServiceFwkInstallerTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleAppServiceFwkInstallerTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleAppServiceFwkInstallerTest::StopInstalldService() const
{
    if (installdService_->IsServiceReady()) {
        installdService_->Stop();
        InstalldClient::GetInstance()->ResetInstalldProxy();
    }
}

void BmsBundleAppServiceFwkInstallerTest::StopBundleService()
{
    if (bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStop();
        bundleMgrService_.reset();
    }
}

void BmsBundleAppServiceFwkInstallerTest::CreateInstallerManager()
{
    if (manager_ != nullptr) {
        return;
    }
    manager_ = std::make_shared<BundleInstallerManager>();
    EXPECT_NE(nullptr, manager_);
}

void BmsBundleAppServiceFwkInstallerTest::ClearBundleInfo(const std::string &bundleName)
{
    if (bundleMgrService_ == nullptr) {
        return;
    }
    auto dataMgr = bundleMgrService_->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    auto dataStorage = dataMgr->GetDataStorage();
    if (dataStorage == nullptr) {
        return;
    }

    // clear innerBundleInfo from data manager
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    // clear innerBundleInfo from data storage
    bool result = dataStorage->DeleteStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(result) << "the bundle info in db clear fail: " << bundleName;
}

void BmsBundleAppServiceFwkInstallerTest::AddBundleInfo(const std::string &bundleName, const InnerBundleInfo& info)
{
    if (bundleMgrService_ == nullptr) {
        return;
    }
    auto dataMgr = bundleMgrService_->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }

    dataMgr->bundleInfos_[bundleName] = info;
}

void BmsBundleAppServiceFwkInstallerTest::DeleteBundleInfo(const std::string &bundleName)
{
    if (bundleMgrService_ == nullptr) {
        return;
    }
    auto dataMgr = bundleMgrService_->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }

    dataMgr->bundleInfos_.erase(bundleName);
}

bool BmsBundleAppServiceFwkInstallerTest::DeletePreBundleInfo(const std::string &bundleName)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }

    PreInstallBundleInfo preInstallBundleInfo;
    bool getRes = dataMgr->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo);
    if (!getRes) {
        return false;
    }
    return dataMgr->DeletePreInstallBundleInfo(bundleName, preInstallBundleInfo);
}

/**
 * @tc.number: BeforeInstall_0100
 * @tc.name: test BeforeInstall
 * @tc.desc: 1.Test the BeforeInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, BeforeInstall_0100, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    std::vector<std::string> hspPaths;
    hspPaths.push_back(TEST_CREATE_FILE_PATH);
    InstallParam installParam;
    installParam.isPreInstallApp = false;

    auto res1 = appServiceFwkInstaller.BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(res1, ERR_APP_SERVICE_FWK_INSTALL_NOT_PREINSTALL);

    installParam.isPreInstallApp = true;
    auto res2 = appServiceFwkInstaller.BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(res2, ERR_OK);

    ClearDataMgr();
    auto res3 = appServiceFwkInstaller.BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(res3, ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR);

    std::vector<std::string> emptyVector;
    auto res4 = appServiceFwkInstaller.BeforeInstall(emptyVector, installParam);
    EXPECT_EQ(res4, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: CheckFileType_0100
 * @tc.name: test CheckFileType
 * @tc.desc: 1.Test the CheckFileType
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckFileType_0100, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    std::vector<std::string> hspPaths;
    auto res = appServiceFwkInstaller.CheckFileType(hspPaths);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);

    hspPaths.push_back(TEST_CREATE_FILE_PATH);
    res = appServiceFwkInstaller.CheckFileType(hspPaths);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME);
}

/**
 * @tc.number: CheckAppLabelInfo_0100
 * @tc.name: test CheckAppLabelInfo
 * @tc.desc: 1.Test the CheckAppLabelInfo
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckAppLabelInfo_0100, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace(TEST_CREATE_FILE_PATH, innerBundleInfo);
    auto res = appServiceFwkInstaller.CheckAppLabelInfo(infos);
    EXPECT_EQ(res, ERR_APP_SERVICE_FWK_INSTALL_TYPE_FAILED);

    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP_SERVICE_FWK;
    res = appServiceFwkInstaller.CheckAppLabelInfo(infos);
    EXPECT_EQ(res, ERR_OK);

    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    innerBundleInfo.innerModuleInfos_.emplace(MODULE_NAME_TEST, innerModuleInfo);
    res = appServiceFwkInstaller.CheckAppLabelInfo(infos);
    EXPECT_EQ(res, ERR_OK);

    innerModuleInfo.bundleType = BundleType::SHARED;
    res = appServiceFwkInstaller.CheckAppLabelInfo(infos);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0100
 * @tc.name: test CheckAppLabelInfo
 * @tc.desc: 1.Test the CheckAppLabelInfo
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckAppLabelInfo_0200, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP_SERVICE_FWK;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    innerModuleInfo.bundleType = BundleType::APP;
    innerBundleInfo.innerModuleInfos_.emplace(MODULE_NAME_TEST, innerModuleInfo);
    infos.emplace(TEST_CREATE_FILE_PATH, innerBundleInfo);

    auto res = appServiceFwkInstaller.CheckAppLabelInfo(infos);
    EXPECT_EQ(res, ERR_APP_SERVICE_FWK_INSTALL_TYPE_FAILED);
}

/**
 * @tc.number: CheckNeedInstall_0100
 * @tc.name: test CheckNeedInstall
 * @tc.desc: 1.Test the CheckNeedInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedInstall_0100, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo oldInfo;
    bool isDowngrade = false;
    bool result = appServiceFwkInstaller.CheckNeedInstall(infos, oldInfo, isDowngrade);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckNeedInstall_0200
 * @tc.name: test CheckNeedInstall
 * @tc.desc: 1.Test the CheckNeedInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedInstall_0200, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo oldInfo;

    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME_WRONG;
    infos[VERSION_ONE_LIBRARY_ONE_PATH] = oldInfo;
    bool isDowngrade = false;
    bool result = appServiceFwkInstaller.CheckNeedInstall(infos, oldInfo, isDowngrade);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckNeedInstall_0400
 * @tc.name: test CheckNeedInstall
 * @tc.desc: 1.Test the CheckNeedInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedInstall_0400, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    AddBundleInfo(BUNDLE_NAME, newInfo);

    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;
    appServiceFwkInstaller.versionCode_ = VERSION_LOW;
    infos[VERSION_ONE_LIBRARY_ONE_PATH] = newInfo;

    InnerBundleInfo oldInfo;
    bool isDowngrade = false;
    bool result = appServiceFwkInstaller.CheckNeedInstall(infos, oldInfo, isDowngrade);
    EXPECT_FALSE(result);

    DeleteBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: CheckNeedInstall_0500
 * @tc.name: test CheckNeedInstall
 * @tc.desc: 1.Test the CheckNeedInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedInstall_0500, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    std::unordered_map<std::string, InnerBundleInfo> infos;

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.baseBundleInfo_->versionCode = VERSION;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    AddBundleInfo(BUNDLE_NAME, innerBundleInfo);
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);


    InnerBundleInfo newInfo;
    bool getRes = dataMgr->FetchInnerBundleInfo(BUNDLE_NAME, newInfo);
    EXPECT_TRUE(getRes);

    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;
    appServiceFwkInstaller.versionCode_ = newInfo.GetVersionCode();
    infos[VERSION_ONE_LIBRARY_ONE_PATH] = newInfo;

    InnerBundleInfo oldInfo;
    bool isDowngrade = false;
    bool result = appServiceFwkInstaller.CheckNeedInstall(infos, oldInfo, isDowngrade);
    EXPECT_FALSE(result);

    DeleteBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: CheckNeedUpdate_0100
 * @tc.name: test CheckNeedUpdate
 * @tc.desc: 1.Test the CheckNeedUpdate
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedUpdate_0100, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    appServiceFwkInstaller.versionCode_ = VERSION;

    InnerBundleInfo oldInfo;
    oldInfo.baseBundleInfo_->versionCode = VERSION_HIGH;
    InnerBundleInfo newInfo;

    bool res = appServiceFwkInstaller.CheckNeedUpdate(newInfo, oldInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: CheckNeedUpdate_0200
 * @tc.name: test CheckNeedUpdate
 * @tc.desc: 1.Test the CheckNeedUpdate
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedUpdate_0200, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    appServiceFwkInstaller.versionCode_ = VERSION_HIGH;

    InnerBundleInfo oldInfo;
    oldInfo.baseBundleInfo_->versionCode = VERSION;
    InnerBundleInfo newInfo;

    bool res = appServiceFwkInstaller.CheckNeedUpdate(newInfo, oldInfo);
    EXPECT_TRUE(appServiceFwkInstaller.versionUpgrade_);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: CheckNeedUpdate_0300
 * @tc.name: test CheckNeedUpdate
 * @tc.desc: 1.Test the CheckNeedUpdate
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedUpdate_0300, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    appServiceFwkInstaller.versionCode_ = VERSION;

    InnerBundleInfo oldInfo;
    oldInfo.baseBundleInfo_->versionCode = VERSION;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME_TEST;

    bool res = appServiceFwkInstaller.CheckNeedUpdate(newInfo, oldInfo);
    EXPECT_TRUE(appServiceFwkInstaller.moduleUpdate_);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: CheckNeedUpdate_0400
 * @tc.name: test CheckNeedUpdate
 * @tc.desc: 1.Test the CheckNeedUpdate
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedUpdate_0400, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    appServiceFwkInstaller.versionCode_ = VERSION;

    InnerBundleInfo oldInfo;
    oldInfo.baseBundleInfo_->versionCode = VERSION;
    oldInfo.currentPackage_ = MODULE_NAME_TEST;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    oldInfo.innerModuleInfos_[MODULE_NAME_TEST] = innerModuleInfo;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME_TEST;
    newInfo.innerModuleInfos_[MODULE_NAME_TEST] = innerModuleInfo;

    bool res = appServiceFwkInstaller.CheckNeedUpdate(newInfo, oldInfo);
    EXPECT_FALSE(appServiceFwkInstaller.moduleUpdate_);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: CheckNeedUpdate_0500
 * @tc.name: test CheckNeedUpdate
 * @tc.desc: 1.Test the CheckNeedUpdate
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedUpdate_0500, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    appServiceFwkInstaller.versionCode_ = VERSION;

    InnerBundleInfo oldInfo;
    oldInfo.baseBundleInfo_->versionCode = VERSION;
    oldInfo.currentPackage_ = MODULE_NAME_TEST;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    oldInfo.innerModuleInfos_[MODULE_NAME_TEST] = innerModuleInfo;

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME_TEST;
    innerModuleInfo.buildHash = BUILD_HASH;
    newInfo.innerModuleInfos_[MODULE_NAME_TEST] = innerModuleInfo;

    bool res = appServiceFwkInstaller.CheckNeedUpdate(newInfo, oldInfo);
    EXPECT_TRUE(appServiceFwkInstaller.moduleUpdate_);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: RemoveBundleCodeDir_0010
 * @tc.name: test RemoveBundleCodeDir
 * @tc.desc: 1.Test the RemoveBundleCodeDir
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, RemoveBundleCodeDir_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;

    InnerBundleInfo info;
    auto res = appServiceFwkInstaller.RemoveBundleCodeDir(info);
    if (appServiceFwkInstaller.dataMgr_ == nullptr) {
        appServiceFwkInstaller.dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    }
    appServiceFwkInstaller.RemoveInfo(EMPTY_STRING);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: GetInnerBundleInfo_0010
 * @tc.name: test GetInnerBundleInfo
 * @tc.desc: 1.Test the GetInnerBundleInfo
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, GetInnerBundleInfo_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    InnerBundleInfo info;
    bool isAppExist;
    auto res = appServiceFwkInstaller.GetInnerBundleInfo(info, isAppExist);
    EXPECT_FALSE(isAppExist);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: UninstallLowerVersion_0010
 * @tc.name: test UninstallLowerVersion
 * @tc.desc: 1.Test the UninstallLowerVersion
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, UninstallLowerVersion_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    std::vector<std::string> moduleNameList;
    auto res = appServiceFwkInstaller.UninstallLowerVersion(moduleNameList);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
}

/**
 * @tc.number: UninstallLowerVersion_0020
 * @tc.name: test UninstallLowerVersion
 * @tc.desc: 1.Test the UninstallLowerVersion
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, UninstallLowerVersion_0020, Function | SmallTest | Level0)
{
    auto installRes = InstallSystemHsp(VERSION_ONE_LIBRARY_ONE_PATH);
    ASSERT_EQ(installRes, ERR_OK);

    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    std::vector<std::string> moduleNameList;
    auto res = appServiceFwkInstaller.UninstallLowerVersion(moduleNameList);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);

    DeleteBundleInfo(BUNDLE_NAME);
    DeletePreBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: UninstallLowerVersion_0030
 * @tc.name: test UninstallLowerVersion
 * @tc.desc: 1.Test the UninstallLowerVersion
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, UninstallLowerVersion_0030, Function | SmallTest | Level0)
{
    auto installRes = InstallSystemHsp(VERSION_ONE_LIBRARY_ONE_PATH);
    ASSERT_EQ(installRes, ERR_OK);

    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;

    std::vector<std::string> moduleNameList;
    auto res = appServiceFwkInstaller.UninstallLowerVersion(moduleNameList);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);

    DeleteBundleInfo(BUNDLE_NAME);
    DeletePreBundleInfo(BUNDLE_NAME);
    dataMgr->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: UninstallLowerVersion_0040
 * @tc.name: test UninstallLowerVersion
 * @tc.desc: 1.Test the UninstallLowerVersion
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, UninstallLowerVersion_0040, Function | SmallTest | Level0)
{
    auto installRes = InstallSystemHsp(VERSION_ONE_LIBRARY_ONE_PATH);
    ASSERT_EQ(installRes, ERR_OK);

    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;

    std::vector<std::string> moduleNameList { MODULE_NAME_TEST };
    auto res = appServiceFwkInstaller.UninstallLowerVersion(moduleNameList);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);

    DeleteBundleInfo(BUNDLE_NAME);
    DeletePreBundleInfo(BUNDLE_NAME);
    dataMgr->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: UninstallLowerVersion_0050
 * @tc.name: test UninstallLowerVersion
 * @tc.desc: 1.Test the UninstallLowerVersion
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, UninstallLowerVersion_0050, Function | SmallTest | Level0)
{
    auto installRes = InstallSystemHsp(VERSION_ONE_LIBRARY_ONE_PATH);
    ASSERT_EQ(installRes, ERR_OK);

    auto installRes2 = InstallSystemHsp(VERSION_ONE_LIBRARY_TWO_PATH);
    ASSERT_EQ(installRes2, ERR_OK);

    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;

    std::vector<std::string> moduleNameList { MODULE_NAME_LIBRARY_ONE };
    auto res = appServiceFwkInstaller.UninstallLowerVersion(moduleNameList);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);

    DeleteBundleInfo(BUNDLE_NAME);
    DeletePreBundleInfo(BUNDLE_NAME);
    dataMgr->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: ProcessNewModuleInstall_0010
 * @tc.name: test ProcessNewModuleInstall
 * @tc.desc: 1.Test the ProcessNewModuleInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, ProcessNewModuleInstall_0010, Function | SmallTest | Level0)
{
    auto installRes = InstallSystemHsp(VERSION_ONE_LIBRARY_ONE_PATH);
    ASSERT_EQ(installRes, ERR_OK);

    auto installRes2 = InstallSystemHsp(VERSION_ONE_LIBRARY_TWO_PATH);
    ASSERT_EQ(installRes2, ERR_OK);

    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;

    std::vector<std::string> moduleNameList { MODULE_NAME_LIBRARY_ONE };
    auto res = appServiceFwkInstaller.UninstallLowerVersion(moduleNameList);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);

    DeleteBundleInfo(BUNDLE_NAME);
    DeletePreBundleInfo(BUNDLE_NAME);
    dataMgr->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: ProcessInstall_0010
 * @tc.name: test ProcessInstall
 * @tc.desc: 1.Test the ProcessInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, ProcessInstall_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    std::vector<std::string> hspPaths;
    hspPaths.push_back(VERSION_ONE_LIBRARY_ONE_PATH);
    InstallParam installParam;
    installParam.isPreInstallApp = false;
    installParam.specifiedDistributionType = BUNDLE_NAME;
    installParam.additionalInfo = BUNDLE_NAME;

    std::unordered_map<std::string, InnerBundleInfo> infos;
    appServiceFwkInstaller.SavePreInstallBundleInfo(ERR_APPEXECFWK_INSTALL_PARAM_ERROR, infos);

    auto res = appServiceFwkInstaller.ProcessInstall(hspPaths, installParam);
    appServiceFwkInstaller.SavePreInstallBundleInfo(res, infos);
    EXPECT_EQ(res, ERR_OK);

    Security::Verify::ProvisionInfo provisionInfo;
    appServiceFwkInstaller.AddAppProvisionInfo(BUNDLE_NAME, provisionInfo, installParam);
}

/**
 * @tc.number: ProcessInstall_0010
 * @tc.name: test ProcessInstall
 * @tc.desc: 1.Test the ProcessInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, MkdirIfNotExist_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    Security::Verify::ProvisionInfo provisionInfo;
    InstallParam installParam;
    appServiceFwkInstaller.AddAppProvisionInfo(BUNDLE_NAME, provisionInfo, installParam);
    installParam.specifiedDistributionType = BUNDLE_NAME;
    installParam.additionalInfo = BUNDLE_NAME;
    appServiceFwkInstaller.AddAppProvisionInfo(BUNDLE_NAME, provisionInfo, installParam);

    auto res = appServiceFwkInstaller.MkdirIfNotExist(VERSION_ONE_LIBRARY_ONE_PATH);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED);
}

/**
 * @tc.number: InnerProcessInstall_0010
 * @tc.name: test InnerProcessInstall
 * @tc.desc: 1.Test the InnerProcessInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, InnerProcessInstall_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    InstallParam installParam;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
    infos.emplace(TEST_CREATE_FILE_PATH, innerBundleInfo);

    auto res = appServiceFwkInstaller.InnerProcessInstall(infos, installParam);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: ProcessNativeLibrary_0010
 * @tc.name: test ProcessNativeLibrary
 * @tc.desc: 1.Test the ProcessNativeLibrary
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, ProcessNativeLibrary_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
    appServiceFwkInstaller.MergeBundleInfos(innerBundleInfo);
    appServiceFwkInstaller.newInnerBundleInfo_.baseBundleInfo_->name = BUNDLE_NAME;
    appServiceFwkInstaller.MergeBundleInfos(innerBundleInfo);

    auto res = appServiceFwkInstaller.ProcessNativeLibrary(
        VERSION_ONE_LIBRARY_ONE_PATH, BUNDLE_DATA_DIR, MODULE_NAME_TEST, BUNDLE_DATA_DIR, innerBundleInfo);
    EXPECT_EQ(res, ERR_OK);

    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    innerModuleInfo.nativeLibraryPath = BUNDLE_DATA_DIR;
    innerModuleInfo.compressNativeLibs = false;
    innerBundleInfo.innerModuleInfos_.emplace(MODULE_NAME_TEST, innerModuleInfo);

    res = appServiceFwkInstaller.ProcessNativeLibrary(
        VERSION_ONE_LIBRARY_ONE_PATH, BUNDLE_DATA_DIR, MODULE_NAME_TEST, BUNDLE_DATA_DIR, innerBundleInfo);
    EXPECT_EQ(res, ERR_OK);

    res = appServiceFwkInstaller.SaveBundleInfoToStorage();
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: MoveSoToRealPath_0010
 * @tc.name: test MoveSoToRealPath
 * @tc.desc: 1.Test the MoveSoToRealPath
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, MoveSoToRealPath_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    auto res = appServiceFwkInstaller.MoveSoToRealPath(MODULE_NAME_LIBRARY_ONE, "data/test", MODULE_NAME_LIBRARY_ONE);
    EXPECT_EQ(res, ERR_OK);

    InstallParam installParam;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
    infos.emplace(TEST_CREATE_FILE_PATH, innerBundleInfo);
    res = appServiceFwkInstaller.UpdateAppService(innerBundleInfo, infos, installParam);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: ProcessBundleUpdateStatus_0010
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, ProcessBundleUpdateStatus_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    auto res = appServiceFwkInstaller.ProcessBundleUpdateStatus(oldInfo, newInfo, VERSION_ONE_LIBRARY_ONE_PATH);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);

    newInfo.currentPackage_ = MODULE_NAME_TEST;
    res = appServiceFwkInstaller.ProcessBundleUpdateStatus(oldInfo, newInfo, VERSION_ONE_LIBRARY_ONE_PATH);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_STATE_ERROR);

    appServiceFwkInstaller.versionUpgrade_ = true;
    res = appServiceFwkInstaller.ProcessBundleUpdateStatus(oldInfo, newInfo, VERSION_ONE_LIBRARY_ONE_PATH);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: GetInnerBundleInfo_0020
 * @tc.name: test GetInnerBundleInfo
 * @tc.desc: 1.Test the GetInnerBundleInfo
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, GetInnerBundleInfo_0020, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    ClearDataMgr();
    InnerBundleInfo info;
    bool isAppExist;
    auto res = appServiceFwkInstaller.GetInnerBundleInfo(info, isAppExist);
    EXPECT_TRUE(res);
    ResetDataMgr();
}

/**
 * @tc.number: CheckNeedInstall_0010
 * @tc.name: test CheckNeedInstall
 * @tc.desc: 1.Test the CheckNeedInstall
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedInstall_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo oldInfo;
    bool isDowngrade = false;
    auto res = appServiceFwkInstaller.CheckNeedInstall(infos, oldInfo, isDowngrade);
    EXPECT_FALSE(res);

    InnerBundleInfo info;
    infos.emplace(TEST_CREATE_FILE_PATH, info);
    res = appServiceFwkInstaller.CheckNeedInstall(infos, oldInfo, isDowngrade);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: CheckNeedUpdate_0010
 * @tc.name: test CheckNeedUpdate
 * @tc.desc: 1.Test the CheckNeedUpdate
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CheckNeedUpdate_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    newInfo.currentPackage_ = MODULE_NAME_TEST;
    oldInfo.baseBundleInfo_->versionCode = 1;
    appServiceFwkInstaller.versionCode_ = 0;
    auto res = appServiceFwkInstaller.CheckNeedUpdate(newInfo, oldInfo);
    EXPECT_FALSE(res);

    appServiceFwkInstaller.versionCode_ = 2;
    res = appServiceFwkInstaller.CheckNeedUpdate(newInfo, oldInfo);
    EXPECT_TRUE(res);

    appServiceFwkInstaller.versionCode_ = 1;
    res = appServiceFwkInstaller.CheckNeedUpdate(newInfo, oldInfo);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: RemoveLowerVersionSoDir_0010
 * @tc.name: test RemoveLowerVersionSoDir
 * @tc.desc: 1.Test the RemoveLowerVersionSoDir
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, RemoveLowerVersionSoDir_0010, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);

    auto res = appServiceFwkInstaller.RemoveLowerVersionSoDir(VERSION_LOW);
    EXPECT_EQ(res, ERR_OK);

    appServiceFwkInstaller.versionUpgrade_ = true;
    res = appServiceFwkInstaller.RemoveLowerVersionSoDir(VERSION_LOW);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: MoveFiles_0100
 * @tc.name: test function of MoveFiles
 * @tc.desc: calling MoveFiles of InstalldOperator
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, MoveFiles_0100, Function | SmallTest | Level1)
{
    InstalldOperator installdOperator;
    bool ret = installdOperator.MoveFiles(TEST_CREATE_FILE_PATH, TEST_CREATE_FILE_PATH, true);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: ExtractModule_0100
 * @tc.name: test function of ExtractModule
 * @tc.desc: 1. calling ExtractModule of AppServiceFwkInstaller
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, ExtractModule_0100, Function | SmallTest | Level1)
{
    AppServiceFwkInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    std::string bundlePath;
    auto ret = installer.ExtractModule(oldInfo, newInfo, bundlePath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: MoveSoToRealPath_0100
 * @tc.name: test function of MoveSoToRealPath
 * @tc.desc: calling MoveSoToRealPath of AppServiceFwkInstaller
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, MoveSoToRealPath_0100, Function | SmallTest | Level1)
{
    AppServiceFwkInstaller installer;
    auto ret1 = installer.MoveSoToRealPath("", "", "");
    EXPECT_EQ(ret1, ERR_OK);

    auto ret2 = installer.MoveSoToRealPath(STRING, STRING, "");
    EXPECT_EQ(ret2, ERR_OK);
}

/**
 * @tc.number: DeliveryProfileToCodeSign_0100
 * @tc.name: test function of DeliveryProfileToCodeSign
 * @tc.desc: calling DeliveryProfileToCodeSign of AppServiceFwkInstaller
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, DeliveryProfileToCodeSign_0100, Function | SmallTest | Level1)
{
    AppServiceFwkInstaller installer;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    if (installer.dataMgr_ == nullptr) {
        installer.dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    }
    auto ret = installer.DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: CreateSignatureFileStream_0100
 * @tc.name: test function of CreateSignatureFileStream
 * @tc.desc: calling CreateSignatureFileStream of BundleStreamInstallerHostImpl
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, CreateSignatureFileStream_0100, Function | SmallTest | Level1)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    auto ret1 = impl.CreateSignatureFileStream("", STRING);
    EXPECT_EQ(ret1, Constants::DEFAULT_STREAM_FD);

    auto ret2 = impl.CreateSignatureFileStream(STRING, "");
    EXPECT_EQ(ret2, Constants::DEFAULT_STREAM_FD);

    auto ret3 = impl.CreateSignatureFileStream("", "");
    EXPECT_EQ(ret3, Constants::DEFAULT_STREAM_FD);

    auto ret4 = impl.CreateSignatureFileStream(STRING, STRING);
    EXPECT_EQ(ret4, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: GetAllBundleInfoByDeveloperId_0100
 * @tc.name: test function of GetAllBundleInfoByDeveloperId
 * @tc.desc: calling GetAllBundleInfoByDeveloperId of BundleDataMgr
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, GetAllBundleInfoByDeveloperId_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<BundleInfo> bundleInfos;
    auto ret1 = dataMgr->GetAllBundleInfoByDeveloperId(STRING, bundleInfos, Constants::INVALID_USERID);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    auto ret2 = dataMgr->GetAllBundleInfoByDeveloperId(STRING, bundleInfos, Constants::ANY_USERID);
    EXPECT_EQ(ret2, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    std::map<std::string, InnerBundleInfo> map;
    InnerBundleInfo info;
    info.SetApplicationBundleType(BundleType::SHARED);
    map.try_emplace(BUNDLE_NAME, info);
    info.SetApplicationBundleType(BundleType::APP_SERVICE_FWK);
    map.try_emplace(BUNDLE_NAME_TEST, info);
    dataMgr->bundleInfos_ = map;
    auto ret3 = dataMgr->GetAllBundleInfoByDeveloperId(STRING, bundleInfos, Constants::ANY_USERID);
    EXPECT_NE(ret3, ERR_OK);
}

/**
 * @tc.number: VerifyCodeSignatureForNativeFiles_0010
 * @tc.name: test VerifyCodeSignatureForNativeFiles
 * @tc.desc: 1.verify the code signature of the local file
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, VerifyCodeSignatureForNativeFiles_0010, Function | SmallTest | Level1)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;

    std::string bundlePath;
    std::string cpuAbi;
    std::string targetSoPath;
    auto res = appServiceFwkInstaller.VerifyCodeSignatureForNativeFiles(bundlePath, cpuAbi, targetSoPath);
    EXPECT_NE(res, ERR_OK);

    DeleteBundleInfo(BUNDLE_NAME);
    DeletePreBundleInfo(BUNDLE_NAME);
    dataMgr->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: RollBack_0010
 * @tc.name: test RollBack
 * @tc.desc: 1.test roll back
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, RollBack_0010, Function | SmallTest | Level1)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;

    appServiceFwkInstaller.RollBack();
    InnerBundleInfo innerBundleInfo;
    auto res = appServiceFwkInstaller.RemoveBundleCodeDir(innerBundleInfo);
    appServiceFwkInstaller.RemoveInfo(EMPTY_STRING);
    EXPECT_NE(res, ERR_OK);

    DeleteBundleInfo(BUNDLE_NAME);
    DeletePreBundleInfo(BUNDLE_NAME);
    dataMgr->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: ProcessModuleUpdate_0010
 * @tc.name: test ProcessModuleUpdate
 * @tc.desc: 1.test process module update
*/
HWTEST_F(BmsBundleAppServiceFwkInstallerTest, ProcessModuleUpdate_0010, Function | SmallTest | Level1)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InitAppServiceFwkInstaller(appServiceFwkInstaller);
    appServiceFwkInstaller.bundleName_ = BUNDLE_NAME;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;

    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::string hspPath;
    auto res = appServiceFwkInstaller.ProcessModuleUpdate(newInfo, oldInfo, hspPath);
    EXPECT_NE(res, ERR_OK);

    DeleteBundleInfo(BUNDLE_NAME);
    DeletePreBundleInfo(BUNDLE_NAME);
    dataMgr->installStates_.erase(BUNDLE_NAME);
}
}
