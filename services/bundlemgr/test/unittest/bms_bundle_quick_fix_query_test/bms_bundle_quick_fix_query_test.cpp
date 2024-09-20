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

#include <gtest/gtest.h>
#include <string>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "inner_app_quick_fix.h"
#include "inner_bundle_info.h"
#include "mock_status_receiver.h"
#include "quick_fix_data_mgr.h"


using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.quickfix_query_test";
const std::string BUNDLE_NAME_DEMO = "com.example.demo.quickfix_query_test";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string QUICK_FIX_ABI = "arms";
const std::string QUICK_FIX_SO_PATH = "libs/arms";
const uint32_t QUICK_FIX_VERSION_CODE = 1;
const uint32_t QUICK_FIX_VERSION_CODE_ZERO = 0;
const std::string QUICK_FIX_VERSION_NAME = "1.0";
const uint32_t BUNDLE_VERSION_CODE = 1;
const std::string BUNDLE_VERSION_NAME = "1.0";
const std::string EMPTY_STRING = "";

class BmsBundleQuickFixQueryTest : public testing::Test {
public:
    BmsBundleQuickFixQueryTest();
    ~BmsBundleQuickFixQueryTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void MockInstallBundleInfo();
    void MockUninstallBundleInfo() const;
    void MockDeployQuickFix() const;
    void MockEnableQuickFix() const;
    void MockDisableQuickFix() const;
    void MockDeleteQuickFix() const;
    void CheckAppQuickFixInfo(const AppqfInfo &appqfInfo) const;
    void CheckAppQuickFixInfoEmpty(const AppqfInfo &appqfInfo) const;

    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    const std::shared_ptr<QuickFixDataMgr> GetQuickFixDataMgr() const;
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_;
};

std::shared_ptr<BundleMgrService> BmsBundleQuickFixQueryTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<QuickFixDataMgr> BmsBundleQuickFixQueryTest::quickFixDataMgr_ =
    DelayedSingleton<QuickFixDataMgr>::GetInstance();

BmsBundleQuickFixQueryTest::BmsBundleQuickFixQueryTest()
{}

BmsBundleQuickFixQueryTest::~BmsBundleQuickFixQueryTest()
{}

void BmsBundleQuickFixQueryTest::SetUpTestCase()
{}

void BmsBundleQuickFixQueryTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleQuickFixQueryTest::SetUp()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr != nullptr) {
        dataMgr->AddUserId(USERID);
    }
}

void BmsBundleQuickFixQueryTest::TearDown()
{}

const std::shared_ptr<BundleDataMgr> BmsBundleQuickFixQueryTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

const std::shared_ptr<QuickFixDataMgr> BmsBundleQuickFixQueryTest::GetQuickFixDataMgr() const
{
    return quickFixDataMgr_;
}

void BmsBundleQuickFixQueryTest::CheckAppQuickFixInfo(const AppqfInfo &appqfInfo) const
{
    EXPECT_EQ(QUICK_FIX_VERSION_CODE, appqfInfo.versionCode);
    EXPECT_EQ(QUICK_FIX_VERSION_NAME, appqfInfo.versionName);
    EXPECT_EQ(QUICK_FIX_ABI, appqfInfo.cpuAbi);
    EXPECT_EQ(QUICK_FIX_SO_PATH, appqfInfo.nativeLibraryPath);
}

void BmsBundleQuickFixQueryTest::CheckAppQuickFixInfoEmpty(const AppqfInfo &appqfInfo) const
{
    EXPECT_EQ(QUICK_FIX_VERSION_CODE_ZERO, appqfInfo.versionCode);
    EXPECT_EQ(EMPTY_STRING, appqfInfo.versionName);
    EXPECT_EQ(EMPTY_STRING, appqfInfo.cpuAbi);
    EXPECT_EQ(EMPTY_STRING, appqfInfo.nativeLibraryPath);
}

void BmsBundleQuickFixQueryTest::MockInstallBundleInfo()
{
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.versionCode = BUNDLE_VERSION_CODE;
    bundleInfo.versionName = BUNDLE_VERSION_NAME;

    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = BUNDLE_NAME;
    userInfo.bundleUserInfo.userId = USERID;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    bool startRet = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool addRet = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    bool endRet = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(addRet);
    EXPECT_TRUE(endRet);
}

void BmsBundleQuickFixQueryTest::MockUninstallBundleInfo() const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
    MockDeleteQuickFix();
}

void BmsBundleQuickFixQueryTest::MockEnableQuickFix() const
{
    auto quickFixMgr = GetQuickFixDataMgr();
    EXPECT_FALSE(quickFixMgr == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    auto ret = quickFixMgr->QueryInnerAppQuickFix(BUNDLE_NAME, innerAppQuickFix);
    EXPECT_TRUE(ret);

    InnerBundleInfo innerBundleInfo;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    auto result = dataMgr->GetInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(result);

    AppQuickFix appQuickFix = innerBundleInfo.GetAppQuickFix();
    appQuickFix.deployedAppqfInfo = innerAppQuickFix.GetAppQuickFix().deployingAppqfInfo;
    innerBundleInfo.SetAppQuickFix(appQuickFix);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    auto result1 = dataMgr->UpdateQuickFixInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(result1);

    AppQuickFix appQuickFix_1 = innerAppQuickFix.GetAppQuickFix();
    appQuickFix_1.deployingAppqfInfo = AppqfInfo();
    innerAppQuickFix.SetAppQuickFix(appQuickFix_1);
    auto ret1 = quickFixMgr->SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_TRUE(ret1);
}

void BmsBundleQuickFixQueryTest::MockDisableQuickFix() const
{
    auto quickFixMgr = GetQuickFixDataMgr();
    EXPECT_FALSE(quickFixMgr == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    auto ret = quickFixMgr->QueryInnerAppQuickFix(BUNDLE_NAME, innerAppQuickFix);
    EXPECT_TRUE(ret);

    InnerBundleInfo innerBundleInfo;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    auto result = dataMgr->GetInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(result);

    AppQuickFix appQuickFix_1 = innerAppQuickFix.GetAppQuickFix();
    appQuickFix_1.deployedAppqfInfo = innerBundleInfo.GetAppQuickFix().deployedAppqfInfo;
    innerAppQuickFix.SetAppQuickFix(appQuickFix_1);
    auto ret1 = quickFixMgr->SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_TRUE(ret1);

    AppQuickFix appQuickFix = innerBundleInfo.GetAppQuickFix();
    appQuickFix.deployedAppqfInfo = AppqfInfo();
    innerBundleInfo.SetAppQuickFix(appQuickFix);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    auto result1 = dataMgr->UpdateQuickFixInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(result1);
}

void BmsBundleQuickFixQueryTest::MockDeployQuickFix() const
{
    AppqfInfo appqfInfo;
    appqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    appqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    appqfInfo.cpuAbi = QUICK_FIX_ABI;
    appqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;

    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    appQuickFix.versionCode = QUICK_FIX_VERSION_CODE;
    appQuickFix.versionName = QUICK_FIX_VERSION_NAME;
    appQuickFix.deployingAppqfInfo = appqfInfo;

    InnerBundleInfo innerBundleInfo;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    auto result = dataMgr->GetInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(result);
    innerBundleInfo.SetAppQuickFix(appQuickFix);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    dataMgr->UpdateQuickFixInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    
    InnerAppQuickFix innerAppQuickFix;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    auto quickFixMgr = GetQuickFixDataMgr();
    EXPECT_FALSE(quickFixMgr == nullptr);
    quickFixMgr->SaveInnerAppQuickFix(innerAppQuickFix);
}

void BmsBundleQuickFixQueryTest::MockDeleteQuickFix() const
{
    auto quickFixMgr = GetQuickFixDataMgr();
    EXPECT_FALSE(quickFixMgr == nullptr);
    quickFixMgr->DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: GetApplicationInfo_0100
 * Function: GetApplicationInfo
 * @tc.name: test GetApplicationInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.GetApplicationInfo before deploy AppQuickFix, so get empty AppQuickFix
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetApplicationInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();

    ApplicationInfo result;
    bool ret = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppQuickFixInfoEmpty(result.appQuickFix.deployedAppqfInfo);
    CheckAppQuickFixInfoEmpty(result.appQuickFix.deployingAppqfInfo);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetApplicationInfo_0200
 * Function: GetApplicationInfo
 * @tc.name: test GetApplicationInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.deploy but not enable AppQuickFix, deploying is not empty
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetApplicationInfo_0200, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();
    ApplicationInfo result;
    bool ret = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppQuickFixInfo(result.appQuickFix.deployingAppqfInfo);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetApplicationInfo_0300
 * Function: GetApplicationInfo
 * @tc.name: test GetApplicationInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.enable AppQuickFix, deployed is not empty
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetApplicationInfo_0300, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();
    MockEnableQuickFix();

    ApplicationInfo result;
    bool ret = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppQuickFixInfo(result.appQuickFix.deployedAppqfInfo);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetApplicationInfo_0400
 * Function: GetApplicationInfo
 * @tc.name: test GetApplicationInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.enable and delete AppQuickFix, deployed is not empty
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetApplicationInfo_0400, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();
    MockEnableQuickFix();
    MockDeleteQuickFix();

    ApplicationInfo result;
    bool ret = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppQuickFixInfo(result.appQuickFix.deployedAppqfInfo);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetApplicationInfo_0500
 * Function: GetApplicationInfo
 * @tc.name: test GetApplicationInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.disable AppQuickFix, deployed is empty
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetApplicationInfo_0500, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();
    MockDisableQuickFix();

    ApplicationInfo result;
    bool ret = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppQuickFixInfoEmpty(result.appQuickFix.deployedAppqfInfo);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetApplicationInfo_0600
 * Function: GetApplicationInfo
 * @tc.name: test GetApplicationInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.disable and delete AppQuickFix, deployed is empty
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetApplicationInfo_0600, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();
    MockDisableQuickFix();
    MockDeleteQuickFix();

    ApplicationInfo result;
    bool ret = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppQuickFixInfoEmpty(result.appQuickFix.deployedAppqfInfo);

    MockUninstallBundleInfo();
}
}
}