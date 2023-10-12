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
#define private public

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "ability_info.h"
#include "application_info.h"
#include "app_control_constants.h"
#include "app_control_manager_rdb.h"
#include "app_control_manager_host_impl.h"
#include "app_jump_interceptor_manager_rdb.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;


namespace OHOS {
namespace {
const std::string BUNDLE_TEST = "app_bundleName";
const std::string APPID = "com.third.hiworld.example1_BNtg4JBClbl92Rgc3jm/"
    "RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=";
const int32_t USERID = 100;
}  // namespace

class BmsBundleMockAppControlTest : public testing::Test {
public:
    BmsBundleMockAppControlTest();
    ~BmsBundleMockAppControlTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void ClearDataMgr();
    void ResetDataMgr();

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleMockAppControlTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleMockAppControlTest::BmsBundleMockAppControlTest()
{}

BmsBundleMockAppControlTest::~BmsBundleMockAppControlTest()
{}

void BmsBundleMockAppControlTest::SetUpTestCase()
{}

void BmsBundleMockAppControlTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleMockAppControlTest::SetUp()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
}

void BmsBundleMockAppControlTest::TearDown()
{
}

void BmsBundleMockAppControlTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleMockAppControlTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    ASSERT_NE(bundleMgrService_->dataMgr_, nullptr);
}

const std::shared_ptr<BundleDataMgr> BmsBundleMockAppControlTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: AppControlManagerRdb_0010
 * @tc.name: test AddAppInstallControlRule by AppControlManagerRdb
 * @tc.desc: 1.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0010, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    std::vector<std::string> appIds;
    auto res = rdb.AddAppInstallControlRule("", appIds, "", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0020
 * @tc.name: test AddAppInstallControlRule by AppControlManagerRdb
 * @tc.desc: 1.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0020, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    std::vector<std::string> appIds;
    appIds.push_back("appId");
    auto res = rdb.AddAppInstallControlRule("", appIds, "", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0030
 * @tc.name: test DeleteAppInstallControlRule by AppControlManagerRdb
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0030, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    std::vector<std::string> appIds;
    appIds.push_back("appId");
    auto res = rdb.DeleteAppInstallControlRule("", "", appIds, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0040
 * @tc.name: test DeleteAppInstallControlRule by AppControlManagerRdb
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0040, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    auto res = rdb.DeleteAppInstallControlRule("", "", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0050
 * @tc.name: test GetAppInstallControlRule by AppControlManagerRdb
 * @tc.desc: 1.GetAppInstallControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0050, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    std::vector<std::string> appIds;
    auto res = rdb.GetAppInstallControlRule("", "", USERID, appIds);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0060
 * @tc.name: test AddAppRunningControlRule by AppControlManagerRdb
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0060, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule appRunningControlRule;
    controlRules.push_back(appRunningControlRule);
    ErrCode res = rdb.AddAppRunningControlRule("", controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0070
 * @tc.name: test AddAppRunningControlRule by AppControlManagerRdb
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0070, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    std::vector<AppRunningControlRule> controlRules;
    ErrCode res = rdb.AddAppRunningControlRule("", controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0080
 * @tc.name: test DeleteAppRunningControlRule by AppControlManagerRdb
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0080, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule appRunningControlRule;
    controlRules.push_back(appRunningControlRule);
    ErrCode res = rdb.DeleteAppRunningControlRule("", controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0090
 * @tc.name: test DeleteAppRunningControlRule by AppControlManagerRdb
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0090, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    ErrCode res = rdb.DeleteAppRunningControlRule("", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0100
 * @tc.name: test GetAppRunningControlRule by AppControlManagerRdb
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0100, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    std::vector<std::string> appIds;
    appIds.push_back("appId");
    auto res = rdb.GetAppRunningControlRule("", USERID, appIds);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0110
 * @tc.name: test GetAppRunningControlRule by AppControlManagerRdb
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0110, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    std::vector<std::string> appIds;
    appIds.push_back("appId");
    AppRunningControlRuleResult controlRuleResult;
    auto res = rdb.GetAppRunningControlRule("", USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0120
 * @tc.name: test SetDisposedStatus by AppControlManagerRdb
 * @tc.desc: 1.SetDisposedStatus test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0120, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    Want want;
    AppRunningControlRuleResult controlRuleResult;
    auto res = rdb.SetDisposedStatus("", "", want, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0130
 * @tc.name: test DeleteDisposedStatus by AppControlManagerRdb
 * @tc.desc: 1.DeleteDisposedStatus test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0130, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    AppRunningControlRuleResult controlRuleResult;
    auto res = rdb.DeleteDisposedStatus("", "", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerRdb_0140
 * @tc.name: test GetDisposedStatus by AppControlManagerRdb
 * @tc.desc: 1.GetDisposedStatus test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerRdb_0140, Function | SmallTest | Level1)
{
    AppControlManagerRdb rdb;
    Want want;
    AppRunningControlRuleResult controlRuleResult;
    auto res = rdb.GetDisposedStatus("", "", want, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppJumpInterceptorManagerRdb_0010
 * @tc.name: test DeleteRuleByTargetBundleName by AppJumpInterceptorManagerRdb
 * @tc.desc: 1.DeleteRuleByTargetBundleName test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppJumpInterceptorManagerRdb_0010, Function | SmallTest | Level1)
{
    AppJumpInterceptorManagerRdb rdb;
    auto res = rdb.DeleteRuleByTargetBundleName("", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppJumpInterceptorManagerRdb_0020
 * @tc.name: test GetAppJumpControlRule by AppJumpInterceptorManagerRdb
 * @tc.desc: 1.GetAppJumpControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppJumpInterceptorManagerRdb_0020, Function | SmallTest | Level1)
{
    AppJumpInterceptorManagerRdb rdb;
    AppJumpControlRule controlRule;
    auto res = rdb.GetAppJumpControlRule("", "", USERID, controlRule);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_JUMP_INTERCEPTOR_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManager_0010
 * @tc.name: test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManager_0010, Function | SmallTest | Level1)
{
    AppControlManager mgr;
    AppRunningControlRuleResult controlRuleResult;
    std::vector<AppRunningControlRule> rules;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    mgr.KillRunningApp(rules, USERID);
    auto res = mgr.GetAppRunningControlRule("", USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManager_0020
 * @tc.name: test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManager_0020, Function | SmallTest | Level1)
{
    AppControlManager mgr;
    AppRunningControlRuleResult controlRuleResult;

    auto res = mgr.GetAppRunningControlRule("", Constants::INVALID_USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: AppControlManager_0040
 * @tc.name: test KillRunningApp by AppControlManager
 * @tc.desc: 1.KillRunningApp test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManager_0040, Function | SmallTest | Level1)
{
    AppControlManager mgr;
    std::vector<AppRunningControlRule> rules;
    AppRunningControlRule rule;
    rule.appId = "APPID";
    rules.push_back(rule);

    mgr.KillRunningApp(rules, USERID);
    auto res = GetBundleDataMgr()->GetBundleNameByAppId(rule.appId);
    EXPECT_EQ(res, Constants::EMPTY_STRING);
}

/**
 * @tc.number: AppControlManagerHostImpl_0010
 * @tc.name: test GetAppRunningControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerHostImpl_0010, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;
    AppRunningControlRuleResult controlRuleResult;

    setuid(AppControlConstants::FOUNDATION_UID);
    auto res = impl.GetAppRunningControlRule("", USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: AppControlManagerHostImpl_0020
 * @tc.name: test ConfirmAppJumpControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.ConfirmAppJumpControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerHostImpl_0020, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;

    setuid(AppControlConstants::FOUNDATION_UID);
    auto res = impl.ConfirmAppJumpControlRule("", "", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerHostImpl_0030
 * @tc.name: test AddAppJumpControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.AddAppJumpControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerHostImpl_0030, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;
    std::vector<AppJumpControlRule> controlRules;

    setuid(AppControlConstants::FOUNDATION_UID);
    auto res = impl.AddAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerHostImpl_0040
 * @tc.name: test DeleteAppJumpControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteAppJumpControlRule test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerHostImpl_0040, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;
    std::vector<AppJumpControlRule> controlRules;

    setuid(AppControlConstants::FOUNDATION_UID);
    auto res = impl.DeleteAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerHostImpl_0050
 * @tc.name: test DeleteRuleByCallerBundleName by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteRuleByCallerBundleName test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerHostImpl_0050, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;

    setuid(AppControlConstants::FOUNDATION_UID);
    auto res = impl.DeleteRuleByCallerBundleName("", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerHostImpl_0060
 * @tc.name: test DeleteRuleByTargetBundleName by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteRuleByTargetBundleName test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerHostImpl_0060, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;

    setuid(AppControlConstants::FOUNDATION_UID);
    auto res = impl.DeleteRuleByTargetBundleName("", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerHostImpl_0070
 * @tc.name: test SetDisposedStatus by AppControlManagerHostImpl
 * @tc.desc: 1.SetDisposedStatus test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerHostImpl_0070, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;
    Want want;
    auto res = impl.SetDisposedStatus("", want, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerHostImpl_0080
 * @tc.name: test DeleteDisposedStatus by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteDisposedStatus test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerHostImpl_0080, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;
    Want want;
    auto res = impl.DeleteDisposedStatus("", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}

/**
 * @tc.number: AppControlManagerHostImpl_0090
 * @tc.name: test GetDisposedStatus by AppControlManagerHostImpl
 * @tc.desc: 1.GetDisposedStatus test
 */
HWTEST_F(BmsBundleMockAppControlTest, AppControlManagerHostImpl_0090, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;
    Want want;
    auto res = impl.GetDisposedStatus("", want, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR);
}
} // OHOS