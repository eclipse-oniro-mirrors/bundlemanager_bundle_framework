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
#define protected public

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
#include "quick_fix_deleter.h"

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
const int32_t WAIT_TIME = 2; // init mocked bms
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
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_;
};

std::shared_ptr<BundleMgrService> BmsBundleQuickFixDeleterTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleQuickFixDeleterTest::installdService_ =
    std::make_shared<InstalldService>();

std::shared_ptr<QuickFixDataMgr> BmsBundleQuickFixDeleterTest::quickFixDataMgr_ =
    DelayedSingleton<QuickFixDataMgr>::GetInstance();

BmsBundleQuickFixDeleterTest::BmsBundleQuickFixDeleterTest()
{}

BmsBundleQuickFixDeleterTest::~BmsBundleQuickFixDeleterTest()
{}

void BmsBundleQuickFixDeleterTest::SetUpTestCase()
{
    bundleMgrService_->InitQuickFixManager();
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->LoadDataFromPersistentStorage();
}

void BmsBundleQuickFixDeleterTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleQuickFixDeleterTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
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
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    auto quickFixHost = std::make_shared<QuickFixManagerHostImpl>();
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
    auto quickFixHost = std::make_shared<QuickFixManagerHostImpl>();
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
    auto quickFixHost = std::make_shared<QuickFixManagerHostImpl>();
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

    auto quickFixHost = std::make_shared<QuickFixManagerHostImpl>();
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

    auto quickFixHost = std::make_shared<QuickFixManagerHostImpl>();
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode result = quickFixHost->DeleteQuickFix(BUNDLE_NAME, callback);
    EXPECT_EQ(result, ERR_OK);
    CheckResult(callback, BUNDLE_NAME, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_0600
 * Function: Execute
 * @tc.desc: 1. system running normally
 *           2. test QuickFixDeleter
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_0600, Function | SmallTest | Level0)
{
    std::shared_ptr<QuickFixDeleter> quickFixDeleter = std::make_shared<QuickFixDeleter>("");
    ErrCode result = quickFixDeleter->Execute();
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_0700
 * Function: Execute
 * @tc.desc: 1. system running normally
 *           2. test QuickFixDeleter
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_0700, Function | SmallTest | Level0)
{
    std::shared_ptr<QuickFixDeleter> quickFixDeleter = std::make_shared<QuickFixDeleter>(BUNDLE_NAME);
    ErrCode result = quickFixDeleter->Execute();
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_0800
 * Function: AddHqfInfo
 * @tc.desc: 1. system running normally
 *           2. test InnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_0800, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix;
    QuickFixMark mark;
    std::shared_ptr<InnerAppQuickFix> innerAppQuickFix = std::make_shared<InnerAppQuickFix>(appQuickFix, mark);
    ErrCode result = innerAppQuickFix->AddHqfInfo(appQuickFix);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_0900
 * Function: AddHqfInfo
 * @tc.desc: 1. system running normally
 *           2. test InnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_0900, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "moduleName";
    hqfInfo.hapSha256 = "hapSha256";
    hqfInfo.hqfFilePath = "/data/test/";
    appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(hqfInfo);
    QuickFixMark mark;
    std::shared_ptr<InnerAppQuickFix> innerAppQuickFix = std::make_shared<InnerAppQuickFix>(appQuickFix, mark);
    ErrCode result = innerAppQuickFix->AddHqfInfo(appQuickFix);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_1000
 * Function: RemoveHqfInfo
 * @tc.desc: 1. system running normally
 *           2. test InnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_1000, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "moduleName";
    hqfInfo.hapSha256 = "hapSha256";
    hqfInfo.hqfFilePath = "/data/test/";
    appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(hqfInfo);
    QuickFixMark mark;
    std::shared_ptr<InnerAppQuickFix> innerAppQuickFix = std::make_shared<InnerAppQuickFix>(appQuickFix, mark);
    innerAppQuickFix->SetAppQuickFix(appQuickFix);
    ErrCode result = innerAppQuickFix->RemoveHqfInfo("moduleNameNo");
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_1100
 * Function: RemoveHqfInfo
 * @tc.desc: 1. system running normally
 *           2. test InnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_1100, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "moduleName";
    hqfInfo.hapSha256 = "hapSha256";
    hqfInfo.hqfFilePath = "/data/test/";
    appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(hqfInfo);
    QuickFixMark mark;
    std::shared_ptr<InnerAppQuickFix> innerAppQuickFix = std::make_shared<InnerAppQuickFix>(appQuickFix, mark);
    innerAppQuickFix->SetAppQuickFix(appQuickFix);
    ErrCode result = innerAppQuickFix->RemoveHqfInfo("moduleName");
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_1200
 * Function: InnerAppQuickFix FromJson
 * @tc.desc: 1. system running normally
 *           2. test InnerAppQuickFix FromJson with empty JSON
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_1200, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    nlohmann::json emptyJson = nlohmann::json::object();
    auto ret = innerAppQuickFix.FromJson(emptyJson);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_1300
 * Function: InnerAppQuickFix SwitchQuickFix
 * @tc.desc: 1. system running normally
 *           2. test InnerAppQuickFix SwitchQuickFix swaps deployed and deploying
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_1300, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix;
    HqfInfo hqfDeployed;
    hqfDeployed.moduleName = "deployed_mod";
    appQuickFix.deployedAppqfInfo.hqfInfos.emplace_back(hqfDeployed);
    HqfInfo hqfDeploying;
    hqfDeploying.moduleName = "deploying_mod";
    appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(hqfDeploying);
    QuickFixMark mark;
    auto innerAppQuickFix = std::make_shared<InnerAppQuickFix>(appQuickFix, mark);
    innerAppQuickFix->SwitchQuickFix();
    auto result = innerAppQuickFix->GetAppQuickFix();
    EXPECT_EQ(result.deployedAppqfInfo.hqfInfos[0].moduleName, "deploying_mod");
    EXPECT_EQ(result.deployingAppqfInfo.hqfInfos[0].moduleName, "deployed_mod");
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_1400
 * Function: InnerAppQuickFix ToString
 * @tc.desc: 1. system running normally
 *           2. test InnerAppQuickFix ToString returns valid JSON
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_1400, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    QuickFixMark mark;
    mark.bundleName = BUNDLE_NAME;
    mark.status = QuickFixStatus::DEPLOY_START;
    InnerAppQuickFix innerAppQuickFix(appQuickFix, mark);
    std::string str = innerAppQuickFix.ToString();
    EXPECT_FALSE(str.empty());
    auto json = nlohmann::json::parse(str, nullptr, false);
    EXPECT_FALSE(json.is_discarded());
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_1500
 * Function: QuickFixDeleter DeleteQuickFix
 * @tc.desc: 1. system running normally
 *           2. test QuickFixDeleter with non-existent bundle (no patch in db returns OK)
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_1500, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::SWITCH_END);
    AddInnerAppQuickFix(innerAppQuickFix);

    std::shared_ptr<QuickFixDeleter> deleter = std::make_shared<QuickFixDeleter>(BUNDLE_NAME);
    ErrCode result = deleter->Execute();
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_1600
 * Function: InnerAppQuickFix parametric constructor
 * @tc.desc: 1. system running normally
 *           2. test InnerAppQuickFix with appQuickFix and mark params
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_1600, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    QuickFixMark mark;
    mark.bundleName = BUNDLE_NAME;
    mark.status = QuickFixStatus::DEPLOY_END;
    InnerAppQuickFix innerAppQuickFix(appQuickFix, mark);
    EXPECT_EQ(innerAppQuickFix.GetAppQuickFix().bundleName, BUNDLE_NAME);
    EXPECT_EQ(innerAppQuickFix.GetQuickFixMark().status, QuickFixStatus::DEPLOY_END);
}

/**
 * @tc.number: BmsBundleQuickFixDeleterTest_1700
 * Function: QuickFixMark from_json
 * @tc.desc: 1. system running normally
 *           2. test QuickFixMark from_json with valid JSON
 */
HWTEST_F(BmsBundleQuickFixDeleterTest, BmsBundleQuickFixDeleterTest_1700, Function | SmallTest | Level0)
{
    nlohmann::json markJson = R"({"bundleName": "com.example.test", "status": 3})"_json;
    QuickFixMark mark;
    from_json(markJson, mark);
    EXPECT_EQ(mark.bundleName, "com.example.test");
    EXPECT_EQ(mark.status, 3);
}
} // OHOS