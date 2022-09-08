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

#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "inner_app_quick_fix.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "quick_fix_data_mgr.h"
#include "mock_quick_fix_callback.h"
#include "nlohmann/json.hpp"
#include "system_bundle_installer.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string RESULT_CODE = "resultCode";
const std::string RESULT_BUNDLE_NAME = "bundleName";
const int32_t USERID = 100;
}

class BmsBundleQuickFixDeleterTest : public testing::Test {
public:
    BmsBundleQuickFixDeleterTest();
    ~BmsBundleQuickFixDeleterTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void AddInnerAppQuickFix(const InnerAppQuickFix &appQuickFixInfo) const;
    InnerAppQuickFix GenerateAppQuickFixInfo(const std::string &bundleName, const QuickFixStatus &status) const;
    void CheckResult(const sptr<MockQuickFixCallback> &callback, const std::string &bundleName, int32_t errCode) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
};

BmsBundleQuickFixDeleterTest::BmsBundleQuickFixDeleterTest()
{}

BmsBundleQuickFixDeleterTest::~BmsBundleQuickFixDeleterTest()
{}

void BmsBundleQuickFixDeleterTest::SetUpTestCase()
{}

void BmsBundleQuickFixDeleterTest::TearDownTestCase()
{}

void BmsBundleQuickFixDeleterTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
    }
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr != nullptr) {
        dataMgr->AddUserId(USERID);
    }
}

void BmsBundleQuickFixDeleterTest::TearDown()
{}


void BmsBundleQuickFixDeleterTest::AddInnerAppQuickFix(const InnerAppQuickFix &appQuickFixInfo) const
{
    EXPECT_NE(quickFixDataMgr_, nullptr) << "the quickFixDataMgr_ is nullptr";
    bool ret = quickFixDataMgr_->SaveInnerAppQuickFix(appQuickFixInfo);
    EXPECT_TRUE(ret);
}

const std::shared_ptr<BundleDataMgr> BmsBundleQuickFixDeleterTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

InnerAppQuickFix BmsBundleQuickFixDeleterTest::GenerateAppQuickFixInfo(const std::string &bundleName,
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

void BmsBundleQuickFixDeleterTest::CheckResult(const sptr<MockQuickFixCallback> &callback,
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

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_0100
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1.the input param bundleName is empty
 *           2. delete failed
 * @tc.require: issueI5MZ69
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_0100, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->DeleteQuickFix("", callback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_0200
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1.the input param callback is nullptr
 *           2. delete failed
 * @tc.require: issueI5MZ69
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_0200, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    ErrCode result = quickFixHost->DeleteQuickFix(BUNDLE_NAME, nullptr);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_0300
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. no quick fix info in db
 *           2. delete failed
 * @tc.require: issueI5MZ69
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_0300, Function | SmallTest | Level0)
{
    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->DeleteQuickFix(BUNDLE_NAME, callback);
    EXPECT_EQ(result, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_0400
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is DEPLOY_END
 *           2. delete successfully
 * @tc.require: issueI5MZ69
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_0400, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->DeleteQuickFix(BUNDLE_NAME, callback);
    EXPECT_EQ(result, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_0500
 * @tc.name: test SwitchQuickFix
 * @tc.desc: 1. the status of quick fix info is SWITCH_END
 *           2. delete successfully
 * @tc.require: issueI5MZ69
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_0500, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    auto quickFixHost = DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
    EXPECT_NE(quickFixHost, nullptr) << "the quickFixHost is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->DeleteQuickFix(BUNDLE_NAME, callback);
    EXPECT_EQ(result, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_OK);
}
} // OHOS