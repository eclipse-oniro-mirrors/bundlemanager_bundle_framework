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

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "ability_info.h"
#include "app_control_constants.h"
#include "app_control_manager_rdb.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "permission_define.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::AAFwk::Want;


namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.third.hiworld.example.h1";
const std::string APPID = "com.third.hiworld.example1_BNtg4JBClbl92Rgc3jm/"
    "RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=";
const std::string CONTROL_MESSAGE = "this is control message";
const std::string CALLING_NAME = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
const std::string APP_CONTROL_EDM_DEFAULT_MESSAGE = "The app has been disabled by EDM";
const std::string PERMISSION_DISPOSED_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundleAppControlTest : public testing::Test {
public:
    BmsBundleAppControlTest();
    ~BmsBundleAppControlTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static sptr<BundleMgrProxy> GetBundleMgrProxy();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UpdateBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();
    std::shared_ptr<IAppControlManagerDb> appControlManagerDb_ = std::make_shared<AppControlManagerRdb>();

private:
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
};

BmsBundleAppControlTest::BmsBundleAppControlTest()
{}

BmsBundleAppControlTest::~BmsBundleAppControlTest()
{}

void BmsBundleAppControlTest::SetUpTestCase()
{}

void BmsBundleAppControlTest::TearDownTestCase()
{}

void BmsBundleAppControlTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundleAppControlTest::TearDown()
{
}

sptr<BundleMgrProxy> BmsBundleAppControlTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        APP_LOGE("fail to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        APP_LOGE("fail to get bundle manager proxy.");
        return nullptr;
    }

    APP_LOGI("get bundle manager proxy success.");
    return iface_cast<BundleMgrProxy>(remoteObject);
}

ErrCode BmsBundleAppControlTest::InstallBundle(const std::string &bundlePath) const
{
    if (!bundleMgrService_) {
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USERID;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleAppControlTest::UpdateBundle(const std::string &bundlePath) const
{
    if (!bundleMgrService_) {
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USERID;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleAppControlTest::UnInstallBundle(const std::string &bundleName) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
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
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleAppControlTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleAppControlTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleAppControlTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: AppInstallControlRule_0100
 * @tc.name: test can not add app install control rule
 * @tc.require: issueI5MZ8Q
 * @tc.desc: 1.system run normally
 *           2.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppInstallControlRule_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(1000);
    std::vector<std::string> appIds;
    auto res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    appIds.emplace_back(APPID);
    res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(537);
    res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::UNSPECIFIED, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID);
    res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
    std::vector<std::string> resultAppIds;
    res = appControlProxy->
        GetAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID, resultAppIds);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(appIds.size(), resultAppIds.size());
    for (size_t i = 0; i < AppControlConstants::LIST_MAX_SIZE; i++) {
        appIds.emplace_back(APPID);
    }
    res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppInstallControlRule_0200
 * @tc.name: test can not add app install control rule
 * @tc.require: issueI5MZ8Q
 * @tc.desc: 1.system run normally
 *           2.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppInstallControlRule_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(1000);
    std::vector<std::string> appIds;
    auto res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL,
        appIds, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    appIds.emplace_back(APPID);
    res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL,
        appIds, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(537);
    res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::UNSPECIFIED, appIds, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID);
    res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_OK);
    for (size_t i = 0; i < AppControlConstants::LIST_MAX_SIZE; i++) {
        appIds.emplace_back(APPID);
    }
    res = appControlProxy->
        DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AppInstallControlRule_0300
 * @tc.name: test can  add app install control rule
 * @tc.require: issueI5MZ8Q
 * @tc.desc: 1.system run normally
 *           2.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppInstallControlRule_0300, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(1000);
    auto res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(537);
    res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::UNSPECIFIED, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID);
    res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppInstallControlRule_0400
 * @tc.name: test can not add app install control rule
 * @tc.require: issueI5MZ8Q
 * @tc.desc: 1.system run normally
 *           2.GetAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppInstallControlRule_0400, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(1000);
    std::vector<std::string> appIds;
    auto res = appControlProxy->
        GetAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID, appIds);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(537);
    appIds.emplace_back(APPID);
    res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlProxy->
        GetAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID, appIds);
    EXPECT_EQ(res, ERR_OK);
    res = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppInstallControlRule_0500
 * @tc.name: test can not add app install control rule
 * @tc.require: issueI5MZ8Q
 * @tc.desc: 1.system run normally
 *           2.GetAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppInstallControlRule_0500, Function | SmallTest | Level1)
{
    std::vector<std::string> appIds;
    auto InstallRes = appControlManagerDb_->AddAppInstallControlRule(
        AppControlConstants::EDM_CALLING, appIds, APPID, USERID);
    auto InstallRes1 = appControlManagerDb_->GetAppInstallControlRule(
        AppControlConstants::EDM_CALLING, APPID, USERID, appIds);
    auto InstallRes2 = appControlManagerDb_->DeleteAppInstallControlRule(
        AppControlConstants::EDM_CALLING, APPID, appIds, USERID);
    appControlManagerDb_->AddAppInstallControlRule(
        AppControlConstants::EDM_CALLING, appIds, APPID, USERID);
    auto InstallRes3 = appControlManagerDb_->DeleteAppInstallControlRule(
        AppControlConstants::EDM_CALLING, APPID, USERID);

    EXPECT_EQ(InstallRes, ERR_OK);
    EXPECT_EQ(InstallRes1, ERR_OK);
    EXPECT_EQ(InstallRes2, ERR_OK);
    EXPECT_EQ(InstallRes3, ERR_OK);
}

/**
 * @tc.number: AppRunningControlRule_0100
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(1000);
    std::vector<AppRunningControlRule> controlRules;
    auto res = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(controlRule);
    res = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(537);
    res = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    for (size_t i = 0; i < AppControlConstants::LIST_MAX_SIZE; i++) {
        controlRules.emplace_back(controlRule);
    }
    res = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    res = appControlProxy->DeleteAppRunningControlRule(USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppRunningControlRule_0200
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(1000);
    std::vector<AppRunningControlRule> controlRules;
    auto res = appControlProxy->DeleteAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(controlRule);
    auto res1 = appControlProxy->DeleteAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res1, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(537);
    auto res2 = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res2, ERR_OK);
    auto res3 = appControlProxy->DeleteAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res3, ERR_OK);
    for (size_t i = 0; i < AppControlConstants::LIST_MAX_SIZE; i++) {
        controlRules.emplace_back(controlRule);
    }
    res = appControlProxy->DeleteAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AppRunningControlRule_0300
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_0300, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(1000);
    auto res = appControlProxy->DeleteAppRunningControlRule(USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(537);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(ruleParam);
    res = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlProxy->DeleteAppRunningControlRule(USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppRunningControlRule_0400
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_0400, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(1000);
    std::vector<std::string> appIds;
    auto res = appControlProxy->GetAppRunningControlRule(USERID, appIds);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(537);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(controlRule);
    res = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlProxy->GetAppRunningControlRule(USERID, appIds);
    EXPECT_EQ(res, ERR_OK);
    res = appControlProxy->DeleteAppRunningControlRule(USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppRunningControlRule_0500
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_0500, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(537);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(controlRule);
    auto res = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);

    AppRunningControlRuleResult controlRuleResult;
    res = appControlProxy->GetAppRunningControlRule(BUNDLE_NAME, USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(5523);
    res = appControlProxy->GetAppRunningControlRule(BUNDLE_NAME, USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    seteuid(537);
    res = appControlProxy->DeleteAppRunningControlRule(USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppRunningControlRule_0600
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_0600, Function | SmallTest | Level1)
{
    std::vector<std::string> appIds;
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = "test control message";
    controlRules.emplace_back(controlRule);
    AppRunningControlRuleResult controlRuleResult;
    auto RunningRes = appControlManagerDb_->AddAppRunningControlRule(
        AppControlConstants::EDM_CALLING, controlRules, 100);
    auto RunningRes1 = appControlManagerDb_->GetAppRunningControlRule(AppControlConstants::EDM_CALLING, 100, appIds);
    auto RunningRes2 = appControlManagerDb_->GetAppRunningControlRule(APPID, 100, controlRuleResult);
    auto RunningRes3 = appControlManagerDb_->DeleteAppRunningControlRule(
        AppControlConstants::EDM_CALLING, controlRules, 100);
    appControlManagerDb_->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, 100);
    auto RunningRes4 = appControlManagerDb_->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, 100);

    EXPECT_EQ(RunningRes, ERR_OK);
    EXPECT_EQ(RunningRes1, ERR_OK);
    EXPECT_EQ(RunningRes2, ERR_OK);
    EXPECT_EQ(RunningRes3, ERR_OK);
    EXPECT_EQ(RunningRes4, ERR_OK);
}

/**
 * @tc.number: AppRunningControlRule_0700
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_0700, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    seteuid(537);
    auto ret = appControlProxy->DeleteAppRunningControlRule(100);
    EXPECT_EQ(ret, ERR_OK);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = "test message";
    controlRules.emplace_back(controlRule);
    ret = appControlManagerDb_->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, 100);
    EXPECT_EQ(ret, ERR_OK);
    AppRunningControlRuleResult controlRuleResult;
    ret = appControlManagerDb_->GetAppRunningControlRule(APPID, 100, controlRuleResult);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(controlRuleResult.controlMessage, "test message");
    EXPECT_EQ(controlRuleResult.controlWant, nullptr);
    ret = appControlManagerDb_->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, 100);
    EXPECT_EQ(ret, ERR_OK);
    controlRules.clear();
    controlRule.controlMessage = "";
    controlRules.emplace_back(controlRule);
    ret = appControlManagerDb_->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, 100);
    EXPECT_EQ(ret, ERR_OK);
    ret = appControlManagerDb_->GetAppRunningControlRule(APPID, 100, controlRuleResult);
    EXPECT_EQ(controlRuleResult.controlMessage, APP_CONTROL_EDM_DEFAULT_MESSAGE);
    EXPECT_EQ(controlRuleResult.controlWant, nullptr);
    ret = appControlManagerDb_->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, 100);
    EXPECT_EQ(ret, ERR_OK);
    controlRules.clear();
    Want want;
    ret = appControlManagerDb_->SetDisposedStatus(PERMISSION_DISPOSED_STATUS, APPID, want, 100);
    EXPECT_EQ(ret, ERR_OK);
    AppRunningControlRuleResult ruleResult;
    ret = appControlManagerDb_->GetAppRunningControlRule(APPID, 100, ruleResult);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(ruleResult.controlMessage, "");
    EXPECT_NE(ruleResult.controlWant, nullptr);
    ret = appControlManagerDb_->DeleteAppRunningControlRule(PERMISSION_DISPOSED_STATUS, 100);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppRunningControlRule_0800
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_0800, Function | SmallTest | Level1)
{
    AppRunningControlRuleResult controlRuleResult;
    auto RunningRes = appControlManagerDb_->GetAppRunningControlRule(APPID, USERID, controlRuleResult);
    EXPECT_EQ(RunningRes, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
}

/**
 * @tc.number: DisposedStatus_0100
 * @tc.name: test setting disposed status
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.SetDisposedStatus test
 */
HWTEST_F(BmsBundleAppControlTest, DisposedStatus_0100, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction("action.system.home");
    auto res = appControlManagerDb_->SetDisposedStatus(CALLING_NAME, APPID, want, 100);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: DisposedStatus_0200
 * @tc.name: test deleting disposed status
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteDisposedStatus test
 */
HWTEST_F(BmsBundleAppControlTest, DisposedStatus_0200, Function | SmallTest | Level1)
{
    auto res = appControlManagerDb_->DeleteDisposedStatus(CALLING_NAME, APPID, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: DisposedStatus_0300
 * @tc.name: test getting disposed status
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.GetDisposedStatus test
 */
HWTEST_F(BmsBundleAppControlTest, DisposedStatus_0300, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction("action.system.home");
    auto res = appControlManagerDb_->SetDisposedStatus(CALLING_NAME, APPID, want, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlManagerDb_->GetDisposedStatus(CALLING_NAME, APPID, want, USERID);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(want.GetAction(), "action.system.home");
}

/**
 * @tc.number: DisposedStatus_0400
 * @tc.name: test setting disposed status
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.SetDisposedStatus test
 */
HWTEST_F(BmsBundleAppControlTest, DisposedStatus_0400, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    Want want;
    want.SetAction("action.system.home");
    APP_LOGE("disposedstatus 4");
    auto res = appControlProxy->SetDisposedStatus(APPID, want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: DisposedStatus_0500
 * @tc.name: test deleting disposed status
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteDisposedStatus test
 */
HWTEST_F(BmsBundleAppControlTest, DisposedStatus_0500, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    auto res = appControlProxy->DeleteDisposedStatus(APPID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: DisposedStatus_0600
 * @tc.name: test getting disposed status
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.GetDisposedStatus test
 */
HWTEST_F(BmsBundleAppControlTest, DisposedStatus_0600, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    Want want;
    want.SetAction("action.system.home");
    auto res = appControlProxy->SetDisposedStatus(APPID, want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    res = appControlProxy->GetDisposedStatus(APPID, want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}
} // OHOS