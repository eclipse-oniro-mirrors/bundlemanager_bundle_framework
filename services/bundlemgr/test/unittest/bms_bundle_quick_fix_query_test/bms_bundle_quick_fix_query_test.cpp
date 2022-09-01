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
    void GenerateInnerQuickFixInfo(InnerAppQuickFix &innerQuickFixInfo) const;
    void MockDeployQuickFix() const;
    void MockSwitchQuickFix(bool enable);
    void MockDeleteQuickFix() const;
    void CheckAppqfInfo(const BundleInfo &bundleInfo) const;
    void CheckAppqfInfoEmpty(const BundleInfo &bundleInfo) const;

    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
private:
    InnerBundleInfo innerBundleInfo;
    AppqfInfo appqfInfo;
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
};

BmsBundleQuickFixQueryTest::BmsBundleQuickFixQueryTest()
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

    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    appqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    appqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    appqfInfo.cpuAbi = QUICK_FIX_ABI;
    appqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
}

BmsBundleQuickFixQueryTest::~BmsBundleQuickFixQueryTest()
{}

void BmsBundleQuickFixQueryTest::SetUpTestCase()
{}

void BmsBundleQuickFixQueryTest::TearDownTestCase()
{}

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

void BmsBundleQuickFixQueryTest::CheckAppqfInfo(const BundleInfo &bundleInfo) const
{
    EXPECT_EQ(QUICK_FIX_VERSION_CODE, bundleInfo.appqfInfo.versionCode);
    EXPECT_EQ(QUICK_FIX_VERSION_NAME, bundleInfo.appqfInfo.versionName);
    EXPECT_EQ(QUICK_FIX_ABI, bundleInfo.appqfInfo.cpuAbi);
    EXPECT_EQ(QUICK_FIX_SO_PATH, bundleInfo.appqfInfo.nativeLibraryPath);
}

void BmsBundleQuickFixQueryTest::CheckAppqfInfoEmpty(const BundleInfo &bundleInfo) const
{
    EXPECT_EQ(QUICK_FIX_VERSION_CODE_ZERO, bundleInfo.appqfInfo.versionCode);
    EXPECT_EQ(EMPTY_STRING, bundleInfo.appqfInfo.versionName);
    EXPECT_EQ(EMPTY_STRING, bundleInfo.appqfInfo.cpuAbi);
    EXPECT_EQ(EMPTY_STRING, bundleInfo.appqfInfo.nativeLibraryPath);
}

void BmsBundleQuickFixQueryTest::MockInstallBundleInfo()
{
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
}

void BmsBundleQuickFixQueryTest::GenerateInnerQuickFixInfo(InnerAppQuickFix &innerQuickFixInfo) const
{
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    appQuickFix.versionCode = QUICK_FIX_VERSION_CODE;
    appQuickFix.versionName = QUICK_FIX_VERSION_NAME;
    appQuickFix.deployedAppqfInfo = appqfInfo;
    appQuickFix.deployingAppqfInfo = appqfInfo;

    innerQuickFixInfo.SetAppQuickFix(appQuickFix);
}

void BmsBundleQuickFixQueryTest::MockSwitchQuickFix(bool enable)
{
    if (!enable) {
        appqfInfo = AppqfInfo();
    }
    BundleInfo bundleInfo = innerBundleInfo.GetBundleInfo();
    bundleInfo.appqfInfo = appqfInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
}

void BmsBundleQuickFixQueryTest::MockDeployQuickFix() const
{
    InnerAppQuickFix innerQuickFixInfo;
    GenerateInnerQuickFixInfo(innerQuickFixInfo);
    EXPECT_NE(quickFixDataMgr_, nullptr) << "the quickFixDataMgr_ is nullptr";
    bool ret = quickFixDataMgr_->SaveInnerAppQuickFix(innerQuickFixInfo);
    EXPECT_TRUE(ret);
}

void BmsBundleQuickFixQueryTest::MockDeleteQuickFix() const
{
    EXPECT_NE(quickFixDataMgr_, nullptr) << "the quickFixDataMgr_ is nullptr";
    bool ret = quickFixDataMgr_->DeleteInnerAppQuickFix(BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetBundleInfo_0100
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
             2.get bundle info failed with empty bundle name
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetBundleInfo_0100, Function | SmallTest | Level0)
{
    BundleInfo result;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret = dataMgr->GetBundleInfo(
        EMPTY_STRING, BundleFlag::GET_BUNDLE_WITH_APPQF_INFO, result, USERID);
    EXPECT_FALSE(ret);
    EXPECT_EQ(EMPTY_STRING, result.name);
}

/**
 * @tc.number: GetBundleInfo_0200
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normal
 *           2.get bundleInfo unsuccessfully because of wrong bundleName
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetBundleInfo_0200, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(
        BUNDLE_NAME_DEMO, BundleFlag::GET_BUNDLE_WITH_APPQF_INFO, result, USERID);
    EXPECT_FALSE(ret);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetBundleInfo_0300
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.get empty AppqfInfo because of bundleFlag
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetBundleInfo_0300, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, result, USERID);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppqfInfoEmpty(result);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetBundleInfo_0400
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.getBundleInfo before deploy AppQuickFix, so get empty AppqfInfo
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetBundleInfo_0400, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_APPQF_INFO, result, USERID);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppqfInfoEmpty(result);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetBundleInfo_0500
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.deploy but not enable AppQuickFix, so get empty AppqfInfo
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetBundleInfo_0500, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_APPQF_INFO, result, USERID);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppqfInfoEmpty(result);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetBundleInfo_0600
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.deploy and enable AppQuickFix, so get valid AppqfInfo
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetBundleInfo_0600, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();
    MockSwitchQuickFix(true);

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_APPQF_INFO, result, USERID);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppqfInfo(result);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetBundleInfo_0700
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.enable and delete AppQuickFix, get valid AppqfInfo
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetBundleInfo_0700, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();
    MockSwitchQuickFix(true);
    MockDeleteQuickFix();

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_APPQF_INFO, result, USERID);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppqfInfo(result);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetBundleInfo_0800
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.disable AppQuickFix, get empty AppqfInfo
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetBundleInfo_0800, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();
    MockSwitchQuickFix(false);

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_APPQF_INFO, result, USERID);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppqfInfoEmpty(result);

    MockUninstallBundleInfo();
}

/**
 * @tc.number: GetBundleInfo_0900
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5MZ5Y
 * @tc.desc: 1.system run normally
 *           2.disable and delete AppQuickFix, get empty AppqfInfo
 */
HWTEST_F(BmsBundleQuickFixQueryTest, GetBundleInfo_0900, Function | SmallTest | Level1)
{
    MockInstallBundleInfo();
    MockDeployQuickFix();
    MockSwitchQuickFix(false);
    MockDeleteQuickFix();

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_APPQF_INFO, result, USERID);
    EXPECT_TRUE(ret);
    EXPECT_EQ(BUNDLE_NAME, result.name);
    CheckAppqfInfoEmpty(result);

    MockUninstallBundleInfo();
}
}
}