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
    void StopService();
    void AddInnerBundleInfo(const std::string &bundleName) const;
    void CheckQuickFixInfo(const std::string &bundleName, size_t size) const;
    void QueryAllInnerQuickFixInfo(std::map<std::string, InnerAppQuickFix> &innerQuickFixInfos) const;
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;
    void CreateQuickFileDir() const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = nullptr;
    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
};

BmsBundleQuickFixBootScannerTest::BmsBundleQuickFixBootScannerTest()
{}

BmsBundleQuickFixBootScannerTest::~BmsBundleQuickFixBootScannerTest()
{}

void BmsBundleQuickFixBootScannerTest::SetUpTestCase()
{}

void BmsBundleQuickFixBootScannerTest::TearDownTestCase()
{}

void BmsBundleQuickFixBootScannerTest::SetUp()
{
    if (installdService_ != nullptr && !installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    StartService();
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr != nullptr) {
        dataMgr->AddUserId(USERID);
    }
}

void BmsBundleQuickFixBootScannerTest::TearDown()
{}

void BmsBundleQuickFixBootScannerTest::StartService()
{
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bundleMgrService_ != nullptr && !bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
    }
}

void BmsBundleQuickFixBootScannerTest::StopService()
{
    if (bundleMgrService_ != nullptr && bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStop();
        bundleMgrService_.reset();
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

ErrCode BmsBundleQuickFixBootScannerTest::InstallBundle(const std::string &bundlePath) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleQuickFixBootScannerTest::UninstallBundle(const std::string &bundleName) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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

    StopService();
    StartService();

    CheckQuickFixInfo(BUNDLE_NAME, 1);
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(0, innerQuickFixInfos.size());

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

    StopService();
    StartService();

    CheckQuickFixInfo(BUNDLE_NAME, 1);
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(0, innerQuickFixInfos.size());

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

    StopService();
    StartService();

    CheckQuickFixInfo(BUNDLE_NAME, 0);
    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_NE(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(0, innerQuickFixInfos.size());

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

    StopService();
    StartService();

    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_NE(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(0, innerQuickFixInfos.size());

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

    StopService();
    StartService();

    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_NE(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(0, innerQuickFixInfos.size());

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

    StopService();
    StartService();

    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_NE(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(0, innerQuickFixInfos.size());

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

    StopService();
    StartService();

    int patchPathExist = access(PATCH_PATH.c_str(), F_OK);
    EXPECT_NE(patchPathExist, 0) << "the patch path does not exists: " << PATCH_PATH;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    QueryAllInnerQuickFixInfo(innerQuickFixInfos);
    EXPECT_EQ(0, innerQuickFixInfos.size());

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}
} // OHOS