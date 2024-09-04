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

#include "bundle_data_mgr.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "inner_app_quick_fix.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "quick_fix_data_mgr.h"
#include "mock_quick_fix_callback.h"
#include "mock_status_receiver.h"
#include "nlohmann/json.hpp"
#include "system_bundle_installer.h"
#include "quick_fix_switcher.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string BUNDLE_PATH = "/data/test/resource/bms/quick_fix/first_right.hap";
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string BUNDLE_NAME_TEST = "com.example.l3jsdemo.test";
const std::string RESULT_CODE = "resultCode";
const std::string RESULT_BUNDLE_NAME = "bundleName";
const int32_t USERID = 100;
}

class BmsBundleQuickFixSwitcherTest : public testing::Test {
public:
    BmsBundleQuickFixSwitcherTest();
    ~BmsBundleQuickFixSwitcherTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;
    void AddInnerAppQuickFix(const InnerAppQuickFix &appQuickFixInfo) const;
    void DeleteInnerAppQuickFix(const std::string &bundleName) const;
    void QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix) const;
    InnerAppQuickFix GenerateAppQuickFixInfo(const std::string &bundleName, const QuickFixStatus &status) const;
    void CheckResult(const sptr<MockQuickFixCallback> &callback, const std::string &bundleName, int32_t errCode) const;
    void SetAppQuickFix(InnerBundleInfo &innerBundleInfo) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_;
};

std::shared_ptr<BundleMgrService> BmsBundleQuickFixSwitcherTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleQuickFixSwitcherTest::installdService_ =
    std::make_shared<InstalldService>();

std::shared_ptr<QuickFixDataMgr> BmsBundleQuickFixSwitcherTest::quickFixDataMgr_ =
    DelayedSingleton<QuickFixDataMgr>::GetInstance();

BmsBundleQuickFixSwitcherTest::BmsBundleQuickFixSwitcherTest()
{}

BmsBundleQuickFixSwitcherTest::~BmsBundleQuickFixSwitcherTest()
{}

void BmsBundleQuickFixSwitcherTest::SetUpTestCase()
{}

void BmsBundleQuickFixSwitcherTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleQuickFixSwitcherTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    }
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr != nullptr) {
        dataMgr->AddUserId(USERID);
    }
}

void BmsBundleQuickFixSwitcherTest::TearDown()
{}

ErrCode BmsBundleQuickFixSwitcherTest::InstallBundle(const std::string &bundlePath) const
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
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleQuickFixSwitcherTest::UninstallBundle(const std::string &bundleName) const
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

void BmsBundleQuickFixSwitcherTest::AddInnerAppQuickFix(const InnerAppQuickFix &appQuickFixInfo) const
{
    EXPECT_NE(quickFixDataMgr_, nullptr) << "the quickFixDataMgr_ is nullptr";
    bool ret = quickFixDataMgr_->SaveInnerAppQuickFix(appQuickFixInfo);
    EXPECT_TRUE(ret);
}

void BmsBundleQuickFixSwitcherTest::DeleteInnerAppQuickFix(const std::string &bundleName) const
{
    EXPECT_NE(quickFixDataMgr_, nullptr) << "the quickFixDataMgr_ is nullptr";
    bool ret = quickFixDataMgr_->DeleteInnerAppQuickFix(bundleName);
    EXPECT_TRUE(ret);
}

void BmsBundleQuickFixSwitcherTest::QueryInnerAppQuickFix(const std::string &bundleName,
    InnerAppQuickFix &innerAppQuickFix) const
{
    EXPECT_NE(quickFixDataMgr_, nullptr) << "the quickFixDataMgr_ is nullptr";
    bool ret = quickFixDataMgr_->QueryInnerAppQuickFix(bundleName, innerAppQuickFix);
    EXPECT_TRUE(ret);
}

const std::shared_ptr<BundleDataMgr> BmsBundleQuickFixSwitcherTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

InnerAppQuickFix BmsBundleQuickFixSwitcherTest::GenerateAppQuickFixInfo(const std::string &bundleName,
    const QuickFixStatus &status) const
{
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = bundleName;
    QuickFixMark quickFixMark = { .status = status };
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    innerAppQuickFix.SetQuickFixMark(quickFixMark);
    return innerAppQuickFix;
}

void BmsBundleQuickFixSwitcherTest::CheckResult(const sptr<MockQuickFixCallback> &callback,
    const std::string &bundleName, int32_t errCode) const
{
    auto callbackRes = callback->GetResCode();
    EXPECT_NE(callbackRes, nullptr) << "the callbackRes is nullptr";

    auto jsonObject = nlohmann::json::parse(callbackRes->ToString());
    const std::string resultBundleName = jsonObject[RESULT_BUNDLE_NAME];
    const int32_t resultCode = jsonObject[RESULT_CODE];

    EXPECT_EQ(bundleName, resultBundleName);
    EXPECT_EQ(errCode, resultCode);
}

void BmsBundleQuickFixSwitcherTest::SetAppQuickFix(InnerBundleInfo &innerBundleInfo) const
{
    AppqfInfo qfInfo;
    HqfInfo hqfInfo;
    qfInfo.hqfInfos.emplace_back(hqfInfo);
    AppQuickFix appQuickFix;
    appQuickFix.deployedAppqfInfo = qfInfo;
    innerBundleInfo.SetAppQuickFix(appQuickFix);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_0100
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1.the input param bundleName is empty
 *           2. switch failed
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_0100, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->SwitchQuickFix("", true, callback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_0200
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1.the input param bundleName is empty
 *           2. switch failed
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_0200, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->SwitchQuickFix("", false, callback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_0300
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1.the input param statusCallback is empty
 *           2. switch failed
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_0300, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    ErrCode result = quickFixHost->SwitchQuickFix(BUNDLE_NAME, false, nullptr);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_0400
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1.the input param statusCallback is empty
 *           2. switch failed
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_0400, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    ErrCode result = quickFixHost->SwitchQuickFix(BUNDLE_NAME, true, nullptr);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_0500
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1.the quick fix database is empty
 *           2. switch failed
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_0500, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->SwitchQuickFix(BUNDLE_NAME, true, callback);
    EXPECT_EQ(result, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_IN_DATABASE);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_0600
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1.the quick fix database is not empty, but BUNDLE_NAME_TEST is not contained.
 *           2. switch failed
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_0600, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";

    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr) << "the data mgr is nullptr";

    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);

    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ret = quickFixHost->SwitchQuickFix(BUNDLE_NAME_TEST, true, callback);
    EXPECT_EQ(ret, ERR_OK);
    CheckResult(callback, BUNDLE_NAME_TEST, ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_IN_DATABASE);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_0700
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is SWITCH_END.
 *           2. switch failed
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_0700, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->SwitchQuickFix(BUNDLE_NAME, true, callback);
    EXPECT_EQ(result, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS);

    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_0800
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is DEPLOY_END and the original bundle is not existed.
 *           2. switch failed
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_0800, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->SwitchQuickFix(BUNDLE_NAME, true, callback);
    EXPECT_EQ(result, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO);

    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_0900
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is DEPLOY_END and original bundle is existed.
 *           2. switch successfully.
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_0900, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr) << "the data mgr is nullptr";

    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";

    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ret = quickFixHost->SwitchQuickFix(BUNDLE_NAME, true, callback);
    EXPECT_EQ(ret, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_OK);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1000
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is DEPLOY_END and original bundle is existed.
 *           2. switch twice, first successfully and second failed.
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1000, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr) << "the data mgr is nullptr";

    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";

    sptr<MockQuickFixCallback> callback1 = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback1, nullptr) << "the callback1 is nullptr";
    ret = quickFixHost->SwitchQuickFix(BUNDLE_NAME, true, callback1);
    EXPECT_EQ(ret, ERR_OK);
    CheckResult(callback1, BUNDLE_NAME, ERR_OK);

    sptr<MockQuickFixCallback> callback2 = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback2, nullptr) << "the callback2 is nullptr";
    ret = quickFixHost->SwitchQuickFix(BUNDLE_NAME, true, callback2);
    EXPECT_EQ(ret, ERR_OK);
    CheckResult(callback2, BUNDLE_NAME, ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_IN_DATABASE);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1100
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. disable quick fix and original bundle is not existed.
 *           2. switch failed.
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1100, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";

    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->SwitchQuickFix(BUNDLE_NAME, false, callback);
    EXPECT_EQ(result, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1200
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. disable quick fix and original bundle is existed, but the original bundle does not contain
 *              quick fix info.
 *           2. switch failed.
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1200, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr) << "the data mgr is nullptr";

    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);

    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";

    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ret = quickFixHost->SwitchQuickFix(BUNDLE_NAME, false, callback);
    EXPECT_EQ(ret, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_INFO_IN_BUNDLE_INFO);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1300
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. disable quick fix and original bundle is existed, but the original bundle contain
 *              quick fix info.
 *           2. switch successfully.
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1300, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr) << "the data mgr is nullptr";

    InnerBundleInfo innerBundleInfo;
    bool result = dataMgr->GetInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(result);
    SetAppQuickFix(innerBundleInfo);
    result = dataMgr->UpdateQuickFixInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(result);

    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ret = quickFixHost->SwitchQuickFix(BUNDLE_NAME, false, callback);
    EXPECT_EQ(ret, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_OK);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1400
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. disable quick fix and the status of quick fix info is SWITCH_END in db.
 *           2. switch failed.
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1400, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->SwitchQuickFix(BUNDLE_NAME, false, callback);
    EXPECT_EQ(result, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS);

    DeleteInnerAppQuickFix(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1500
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. disable quick fix and the status of quick fix info is DEPLOY_END in db.
 *           2. switch successfully.
 * @tc.require: issueI5MZ6P
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1500, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr) << "the data mgr is nullptr";

    InnerBundleInfo innerBundleInfo;
    bool result = dataMgr->GetInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(result);
    SetAppQuickFix(innerBundleInfo);
    result = dataMgr->UpdateQuickFixInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(result);

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ret = quickFixHost->SwitchQuickFix(BUNDLE_NAME, false, callback);
    EXPECT_EQ(ret, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_OK);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1600
 * Function: Execute
 * @tc.desc: 1. system running normally
 *           2. test QuickFixSwitcher
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1600, Function | SmallTest | Level0)
{
    std::shared_ptr<QuickFixSwitcher> quickFixSwitcher = std::make_shared<QuickFixSwitcher>("", false);
    ErrCode result = quickFixSwitcher->Execute();
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1700
 * Function: Execute
 * @tc.desc: 1. system running normally
 *           2. test QuickFixSwitcher
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1700, Function | SmallTest | Level0)
{
    std::shared_ptr<QuickFixSwitcher> quickFixSwitcher = std::make_shared<QuickFixSwitcher>("", true);
    ErrCode result = quickFixSwitcher->Execute();
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1800
 * Function: Execute
 * @tc.desc: 1. system running normally
 *           2. test QuickFixSwitcher
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1800, Function | SmallTest | Level0)
{
    std::shared_ptr<QuickFixSwitcher> quickFixSwitcher = std::make_shared<QuickFixSwitcher>(BUNDLE_NAME, false);
    ErrCode result = quickFixSwitcher->Execute();
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO);
}

/**
 * @tc.number: BmsBundleQuickFixSwitcherTest_1900
 * Function: Execute
 * @tc.desc: 1. system running normally
 *           2. test QuickFixSwitcher
 */
HWTEST_F(BmsBundleQuickFixSwitcherTest, BmsBundleQuickFixSwitcherTest_1900, Function | SmallTest | Level0)
{
    std::shared_ptr<QuickFixSwitcher> quickFixSwitcher = std::make_shared<QuickFixSwitcher>(BUNDLE_NAME, true);
    ErrCode result = quickFixSwitcher->Execute();
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_IN_DATABASE);
}
} // OHOS