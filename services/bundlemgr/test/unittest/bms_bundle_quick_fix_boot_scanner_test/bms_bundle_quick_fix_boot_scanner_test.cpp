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

#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "file_ex.h"
#include "inner_app_quick_fix.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "quick_fix_boot_scanner.h"
#include "quick_fix_data_mgr.h"
#include "system_bundle_installer.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string BUNDLE_PATH = "/data/test/resource/bms/quick_fix/first_right.hap";
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string RESULT_CODE = "resultCode";
const std::string RESULT_BUNDLE_NAME = "bundleName";
const std::string HAP_FILE_PATH = "/data/app/el1/bundle/public/com.example.l3jsdemo/patch_1000001/entry.hqf";
const std::string PATCH_PATH = "/data/app/el1/bundle/public/com.example.l3jsdemo/patch_1000001";
const int32_t VERSION_CODE = 1000001;
const int32_t USERID = 100;
const int32_t WAIT_TIME = 1; // wait for stopping service
}

class BmsBundleQuickFixBootScannerTest : public testing::Test {
public:
    BmsBundleQuickFixBootScannerTest();
    ~BmsBundleQuickFixBootScannerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void AddInnerAppQuickFix(const InnerAppQuickFix &appQuickFixInfo) const;
    InnerAppQuickFix GenerateAppQuickFixInfo(const std::string &bundleName, const QuickFixStatus &status,
        bool flag = true) const;
    void StartService();
    void AddInnerBundleInfo(const std::string &bundleName) const;
    void CheckQuickFixInfo(const std::string &bundleName, size_t size) const;
    void QueryAllInnerQuickFixInfo(std::map<std::string, InnerAppQuickFix> &innerQuickFixInfos) const;
    void DeleteInnerAppQuickFix(const std::string &bundleName) const;
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;
    void CreateQuickFileDir() const;
    void DeleteQuickFileDir() const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_;
};

std::shared_ptr<BundleMgrService> BmsBundleQuickFixBootScannerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleQuickFixBootScannerTest::installdService_ =
    std::make_shared<InstalldService>();

std::shared_ptr<QuickFixDataMgr> BmsBundleQuickFixBootScannerTest::quickFixDataMgr_ =
    DelayedSingleton<QuickFixDataMgr>::GetInstance();

BmsBundleQuickFixBootScannerTest::BmsBundleQuickFixBootScannerTest()
{}

BmsBundleQuickFixBootScannerTest::~BmsBundleQuickFixBootScannerTest()
{}

void BmsBundleQuickFixBootScannerTest::SetUpTestCase()
{}

void BmsBundleQuickFixBootScannerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleQuickFixBootScannerTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    StartService();
}

void BmsBundleQuickFixBootScannerTest::TearDown()
{}

void BmsBundleQuickFixBootScannerTest::StartService()
{
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    EXPECT_NE(bundleMgrService_, nullptr);
    if (bundleMgrService_ != nullptr && !bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleQuickFixBootScannerTest::AddInnerAppQuickFix(const InnerAppQuickFix &appQuickFixInfo) const
{
    EXPECT_NE(quickFixDataMgr_, nullptr) << "the quickFixDataMgr_ is nullptr";
    bool ret = quickFixDataMgr_->SaveInnerAppQuickFix(appQuickFixInfo);
    EXPECT_TRUE(ret);

    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(1, innerQuickFixInfos.size());
}

const std::shared_ptr<BundleDataMgr> BmsBundleQuickFixBootScannerTest::GetBundleDataMgr() const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    return bundleMgrService_->GetDataMgr();
}

InnerAppQuickFix BmsBundleQuickFixBootScannerTest::GenerateAppQuickFixInfo(const std::string &bundleName,
    const QuickFixStatus &status, bool flag) const
{
    InnerAppQuickFix innerAppQuickFix;
    HqfInfo hqfInfo;
    hqfInfo.hqfFilePath = HAP_FILE_PATH;
    AppQuickFix appQuickFix;
    if (flag) {
        appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(hqfInfo);
        appQuickFix.deployingAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.versionCode = VERSION_CODE;
    } else {
        appQuickFix.deployedAppqfInfo.hqfInfos.emplace_back(hqfInfo);
        appQuickFix.deployedAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployedAppqfInfo.versionCode = VERSION_CODE;
    }

    appQuickFix.bundleName = bundleName;
    QuickFixMark quickFixMark = { .status = status };
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    innerAppQuickFix.SetQuickFixMark(quickFixMark);
    return innerAppQuickFix;
}

void BmsBundleQuickFixBootScannerTest::CheckQuickFixInfo(const std::string &bundleName, size_t size) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr) << "the data mgr is nullptr";

    InnerBundleInfo innerBundleInfo;
    bool result = dataMgr->GetInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_TRUE(result);
    auto appqfInof = innerBundleInfo.GetAppQuickFix();
    size_t ret = appqfInof.deployedAppqfInfo.hqfInfos.size();
    EXPECT_EQ(ret, size);

    result = dataMgr->EnableBundle(bundleName);
    EXPECT_TRUE(result);
}

void BmsBundleQuickFixBootScannerTest::QueryAllInnerQuickFixInfo(std::map<std::string,
    InnerAppQuickFix> &innerQuickFixInfos) const
{
    EXPECT_NE(quickFixDataMgr_, nullptr) << "the quickFixDataMgr_ is nullptr";
    bool ret = quickFixDataMgr_->QueryAllInnerAppQuickFix(innerQuickFixInfos);
    EXPECT_TRUE(ret);
}

void BmsBundleQuickFixBootScannerTest::DeleteInnerAppQuickFix(const std::string &bundleName) const
{
    EXPECT_NE(quickFixDataMgr_, nullptr) << "the quickFixDataMgr_ is nullptr";
    quickFixDataMgr_->DeleteInnerAppQuickFix(bundleName);
}

ErrCode BmsBundleQuickFixBootScannerTest::InstallBundle(const std::string &bundlePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleQuickFixBootScannerTest::UninstallBundle(const std::string &bundleName) const
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleQuickFixBootScannerTest::AddInnerBundleInfo(const std::string &bundleName) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr) << "the data mgr is nullptr";

    InnerBundleInfo innerBundleInfo;
    bool result = dataMgr->GetInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_TRUE(result);

    AppQuickFix appQuickFix;
    appQuickFix.deployedAppqfInfo.versionCode = VERSION_CODE;
    appQuickFix.deployedAppqfInfo.type = QuickFixType::PATCH;
    HqfInfo hqfInfo;
    hqfInfo.hqfFilePath = HAP_FILE_PATH;
    appQuickFix.deployedAppqfInfo.hqfInfos.emplace_back(hqfInfo);
    innerBundleInfo.SetAppQuickFix(appQuickFix);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);

    result = dataMgr->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_TRUE(result);
}

void BmsBundleQuickFixBootScannerTest::CreateQuickFileDir() const
{
    bool ret = BundleUtil::CreateDir(PATCH_PATH);
    EXPECT_TRUE(ret);

    bool res = SaveStringToFile(HAP_FILE_PATH, HAP_FILE_PATH);
    EXPECT_TRUE(res);
}

void BmsBundleQuickFixBootScannerTest::DeleteQuickFileDir() const
{
    bool ret = BundleUtil::DeleteDir(PATCH_PATH);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_0100
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is SWITCH_END
 *           2. scan successfully
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_0100, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    CheckQuickFixInfo(BUNDLE_NAME, 0);

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    SetUp();
    StartService();

    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(1, innerQuickFixInfos.size());

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_0200
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is SWITCH_ENABLE_END
 *           2. scan successfully
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_0200, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    CheckQuickFixInfo(BUNDLE_NAME, 0);

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_ENABLE_START);
    AddInnerAppQuickFix(innerAppQuickFix);

    SetUp();
    StartService();

    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(1, innerQuickFixInfos.size());

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_0300
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is SWITCH_DISABLE_END
 *           2. scan successfully
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_0300, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    AddInnerBundleInfo(BUNDLE_NAME);
    CheckQuickFixInfo(BUNDLE_NAME, 1);

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_DISABLE_START);
    AddInnerAppQuickFix(innerAppQuickFix);
    CreateQuickFileDir();

    SetUp();
    StartService();

    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_EQ(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(1, innerQuickFixInfos.size());

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_0400
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is SWITCH_END
 *           2. scan successfully
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_0400, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_END, false);
    AddInnerAppQuickFix(innerAppQuickFix);
    CreateQuickFileDir();

    SetUp();
    StartService();

    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_EQ(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(1, innerQuickFixInfos.size());

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_0500
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is DELETE_START
 *           2. scan successfully
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_0500, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DELETE_START, false);
    AddInnerAppQuickFix(innerAppQuickFix);
    CreateQuickFileDir();

    SetUp();
    StartService();

    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_EQ(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(1, innerQuickFixInfos.size());

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}


/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_0600
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is DELETE_START
 *           2. scan successfully
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_0600, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DELETE_END, false);
    AddInnerAppQuickFix(innerAppQuickFix);
    CreateQuickFileDir();

    SetUp();
    StartService();

    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_EQ(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(1, innerQuickFixInfos.size());

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_0700
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is DELETE_START
 *           2. scan successfully
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_0700, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEFAULT_STATUS, false);
    AddInnerAppQuickFix(innerAppQuickFix);
    CreateQuickFileDir();

    SetUp();
    StartService();

    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_EQ(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(1, innerQuickFixInfos.size());

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_0800
 * @tc.name: test QuickFixBootScanner
 * @tc.desc: 1. quick fix database empty
 *           2. scan successfully
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_0800, Function | SmallTest | Level0)
{
    DeleteInnerAppQuickFix(BUNDLE_NAME);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->ProcessQuickFixBootUp();
        EXPECT_EQ(scanner->state_, nullptr);
    }
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_0900
 * @tc.name: test QuickFixBootScanner
 * @tc.desc: 1. quick fix database not empty
 *           2. DEFAULT_STATUS
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_0900, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEFAULT_STATUS, false);
    AddInnerAppQuickFix(innerAppQuickFix);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->ProcessQuickFixBootUp();
        EXPECT_EQ(scanner->state_, nullptr);
    }
    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1001
 * @tc.name: test QuickFixBootScanner
 * @tc.desc: 1. quick fix database not empty
 *           2. DELETE_END
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1001, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DELETE_END, false);
    AddInnerAppQuickFix(innerAppQuickFix);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->ProcessQuickFixBootUp();
        EXPECT_EQ(scanner->state_, nullptr);
    }
    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1002
 * @tc.name: test QuickFixBootScanner
 * @tc.desc: 1. quick fix database not empty
 *           2. DEPLOY_START
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1002, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_START, false);
    AddInnerAppQuickFix(innerAppQuickFix);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->ProcessQuickFixBootUp();
        EXPECT_EQ(scanner->state_, nullptr);
    }
    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1003
 * @tc.name: test QuickFixBootScanner
 * @tc.desc: 1. quick fix database not empty
 *           2. DEPLOY_END
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1003, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END, false);
    AddInnerAppQuickFix(innerAppQuickFix);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->ProcessQuickFixBootUp();
        EXPECT_EQ(scanner->state_, nullptr);
    }
    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1004
 * @tc.name: test QuickFixBootScanner
 * @tc.desc: 1. quick fix database not empty
 *           2. SWITCH_ENABLE_START
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1004, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_ENABLE_START,
        false);
    AddInnerAppQuickFix(innerAppQuickFix);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->ProcessQuickFixBootUp();
        EXPECT_EQ(scanner->state_, nullptr);
    }
    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1005
 * @tc.name: test QuickFixBootScanner
 * @tc.desc: 1. quick fix database not empty
 *           2. SWITCH_DISABLE_START
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1005, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_DISABLE_START);
    AddInnerAppQuickFix(innerAppQuickFix);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->ProcessQuickFixBootUp();
        EXPECT_EQ(scanner->state_, nullptr);
    }
    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1006
 * @tc.name: test QuickFixBootScanner
 * @tc.desc: 1. quick fix database not empty
 *           2. SWITCH_DISABLE_START
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1006, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_DISABLE_START);
    AddInnerAppQuickFix(innerAppQuickFix);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->ProcessQuickFixBootUp();
        EXPECT_EQ(scanner->state_, nullptr);
    }
    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1007
 * @tc.name: test QuickFixBootScanner
 * @tc.desc: 1. state_ is nullptr
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1007, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->state_ = nullptr;
        auto ret = scanner->ProcessState();
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1008
 * @tc.name: test RestoreQuickFix
 * @tc.desc: 1. quickFixInfoMap_ empty
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1008, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->RestoreQuickFix();
        EXPECT_EQ(scanner->state_, nullptr);
        EXPECT_TRUE(scanner->quickFixInfoMap_.empty());
    }
    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1009
 * @tc.name: test RestoreQuickFix
 * @tc.desc: 1. RestoreQuickFix, file patch exist
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1009, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";
    CreateQuickFileDir();

    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->RestoreQuickFix();
        EXPECT_EQ(scanner->state_, nullptr);
        EXPECT_FALSE(scanner->quickFixInfoMap_.empty());
    }
    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1010
 * @tc.name: test RestoreQuickFix
 * @tc.desc: 1. RestoreQuickFix, file patch exist
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1010, Function | SmallTest | Level0)
{
    CreateQuickFileDir();
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->RestoreQuickFix();
        EXPECT_EQ(scanner->state_, nullptr);
        EXPECT_FALSE(scanner->quickFixInfoMap_.empty());
    }
    DeleteQuickFileDir();
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1011
 * @tc.name: test RestoreQuickFix
 * @tc.desc: 1. RestoreQuickFix, file patch exist
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1011, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";
    CreateQuickFileDir();

    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->RestoreQuickFix();
        EXPECT_EQ(scanner->state_, nullptr);
        EXPECT_FALSE(scanner->quickFixInfoMap_.empty());
    }
    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1012
 * @tc.name: test RestoreQuickFix
 * @tc.desc: 1. RestoreQuickFix, file patch exist
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1012, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";
    CreateQuickFileDir();
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    InnerAppQuickFix innerAppQuickFix;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    AddInnerAppQuickFix(innerAppQuickFix);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->RestoreQuickFix();
        EXPECT_EQ(scanner->state_, nullptr);
        EXPECT_FALSE(scanner->quickFixInfoMap_.empty());
    }
    DeleteInnerAppQuickFix(BUNDLE_NAME);
    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1013
 * @tc.name: test ProcessQuickFixDir
 * @tc.desc: 1. ProcessQuickFixDir, empty paramater
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1013, Function | SmallTest | Level0)
{
    CreateQuickFileDir();
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        std::vector<std::string> dirs;
        scanner->ProcessQuickFixDir(dirs);
        EXPECT_EQ(scanner->state_, nullptr);
    }
    DeleteQuickFileDir();
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1014
 * @tc.name: test ProcessQuickFixDir
 * @tc.desc: 1. ProcessQuickFixDir
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1014, Function | SmallTest | Level0)
{
    CreateQuickFileDir();
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        std::vector<std::string> dirs;
        dirs.push_back(PATCH_PATH);
        scanner->ProcessQuickFixDir(dirs);
        EXPECT_FALSE(scanner->quickFixInfoMap_.empty());
    }
    DeleteQuickFileDir();
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1015
 * @tc.name: test ProcessQuickFixDir
 * @tc.desc: 1. ProcessQuickFixDir, invalid path
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1015, Function | SmallTest | Level0)
{
    CreateQuickFileDir();
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->quickFixInfoMap_.clear();
        std::vector<std::string> dirs;
        dirs.push_back("wrong");
        dirs.push_back("bundleName_1000wrong");
        dirs.push_back("/bundleName");
        scanner->ProcessQuickFixDir(dirs);
        EXPECT_TRUE(scanner->quickFixInfoMap_.empty());
    }
    DeleteQuickFileDir();
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1016
 * @tc.name: test ReprocessQuickFix
 * @tc.desc: 1. ReprocessQuickFix, invalid path
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1016, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        auto ret = scanner->ReprocessQuickFix("", "");
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1017
 * @tc.name: test ReprocessQuickFix
 * @tc.desc: 1. ReprocessQuickFix, invalid path
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1017, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        auto ret = scanner->ReprocessQuickFix("", "");
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1018
 * @tc.name: test ReprocessQuickFix
 * @tc.desc: 1. ReprocessQuickFix
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1018, Function | SmallTest | Level0)
{
    CreateQuickFileDir();
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        auto ret = scanner->ReprocessQuickFix(HAP_FILE_PATH, BUNDLE_NAME);
        EXPECT_FALSE(ret);
    }
    DeleteQuickFileDir();
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1019
 * @tc.name: test GetApplicationInfo
 * @tc.desc: 1. GetApplicationInfo
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1019, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        ApplicationInfo info;
        auto ret = scanner->GetApplicationInfo(BUNDLE_NAME, HAP_FILE_PATH, info);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1020
 * @tc.name: test ProcessWithBundleHasQuickFixInfo
 * @tc.desc: 1. ProcessWithBundleHasQuickFixInfo, quickFixVersion == fileVersion
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1020, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        int32_t quickFixVersion = 1000;
        int32_t fileVersion = 1000;
        auto ret = scanner->ProcessWithBundleHasQuickFixInfo(BUNDLE_NAME, HAP_FILE_PATH, quickFixVersion, fileVersion);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1021
 * @tc.name: test ProcessWithBundleHasQuickFixInfo
 * @tc.desc: 1. ProcessWithBundleHasQuickFixInfo, quickFixVersion > fileVersion
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1021, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        int32_t quickFixVersion = 1001;
        int32_t fileVersion = 1000;
        auto ret = scanner->ProcessWithBundleHasQuickFixInfo(BUNDLE_NAME, HAP_FILE_PATH, quickFixVersion, fileVersion);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1022
 * @tc.name: test ProcessWithBundleHasQuickFixInfo
 * @tc.desc: 1. ProcessWithBundleHasQuickFixInfo, quickFixVersion > fileVersion
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1022, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        int32_t quickFixVersion = 1001;
        int32_t fileVersion = 1000;
        auto ret = scanner->ProcessWithBundleHasQuickFixInfo(BUNDLE_NAME, HAP_FILE_PATH, quickFixVersion, fileVersion);
        EXPECT_TRUE(ret);
    }
    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1023
 * @tc.name: test ProcessWithBundleHasQuickFixInfo
 * @tc.desc: 1. ProcessWithBundleHasQuickFixInfo
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1023, Function | SmallTest | Level0)
{
    CreateQuickFileDir();
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->invalidQuickFixDir_.push_back(PATCH_PATH);
        scanner->RemoveInvalidDir();
        int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
        EXPECT_NE(patchPathExist, 0);
    }
    DeleteQuickFileDir();
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1024
 * @tc.name: test ProcessWithBundleHasQuickFixInfo
 * @tc.desc: 1. ProcessWithBundleHasQuickFixInfo, quickFixVersion < fileVersion
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1024, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        int32_t quickFixVersion = 1000;
        int32_t fileVersion = 1001;
        auto ret = scanner->ProcessWithBundleHasQuickFixInfo(BUNDLE_NAME, HAP_FILE_PATH, quickFixVersion, fileVersion);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1025
 * @tc.name: test ProcessQuickFixDir
 * @tc.desc: 1. ProcessQuickFixDir, invalid path
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1025, Function | SmallTest | Level0)
{
    CreateQuickFileDir();
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->quickFixInfoMap_.clear();
        std::vector<std::string> dirs;
        dirs.push_back("wrong");
        dirs.push_back("bundleName_1000wrong");
        scanner->ProcessQuickFixDir(dirs);
        EXPECT_TRUE(scanner->quickFixInfoMap_.empty());
        dirs.push_back("/");
        scanner->ProcessQuickFixDir(dirs);
        EXPECT_TRUE(scanner->quickFixInfoMap_.empty());
    }
    DeleteQuickFileDir();
}

/**
 * @tc.number: BmsBundleQuickFixBootScannerTest_1026
 * @tc.name: test RestoreQuickFix
 * @tc.desc: 1. RestoreQuickFix, file patch not exist
 * @tc.require: issueI5MZ6Z
 */
HWTEST_F(BmsBundleQuickFixBootScannerTest, BmsBundleQuickFixBootScannerTest_1026, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";
    CreateQuickFileDir();
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->quickFixInfoMap_.clear();
        bool res = scanner->ReprocessQuickFix(HAP_FILE_PATH, BUNDLE_NAME);
        EXPECT_FALSE(res);
    }
    DeleteQuickFileDir();
    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}
} // OHOS