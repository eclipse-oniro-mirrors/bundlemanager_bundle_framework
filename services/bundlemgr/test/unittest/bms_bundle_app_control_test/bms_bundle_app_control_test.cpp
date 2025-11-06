/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "app_control_constants.h"
#include "app_control_manager_rdb.h"
#include "app_control_manager_host_impl.h"
#include "app_jump_interceptor_manager_rdb.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "if_system_ability_manager.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "iservice_registry.h"
#include "mock_status_receiver.h"
#include "permission_define.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::AAFwk::Want;


namespace OHOS {
namespace {
const std::string INSTALL_PATH = "/data/test/resource/bms/app_control/bmsThirdBundle1.hap";
const std::string BUNDLE_NAME = "com.third.hiworld.example1";
const std::string CALLER_BUNDLE_NAME = "callerBundleName";
const std::string TARGET_BUNDLE_NAME = "targetBundleName";
const std::string APPID = "com.third.hiworld.example1_BNtg4JBClbl92Rgc3jm/"
    "RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=";
const std::string CONTROL_MESSAGE = "this is control message";
const std::string CALLING_NAME = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
const std::string APP_CONTROL_EDM_DEFAULT_MESSAGE = "The app has been disabled by EDM";
const std::string PERMISSION_DISPOSED_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
const std::string ABILITY_RUNNING_KEY = "ABILITY_RUNNING_KEY";
const std::string INVALID_MESSAGE = "INVALID_MESSAGE";
const int32_t USERID = 100;
const int32_t USERID2 = 101;
const int32_t TEST_USERID = 2000;
const int32_t WAIT_TIME = 1; // init mocked bms
const int NOT_EXIST_USERID = -5;
const int ALL_USERID = -3;
const int32_t MAIN_APP_INDEX = -1;
const int32_t CLONE_APP_INDEX_MAX = 6;
const int32_t APP_INDEX = 1;
const int32_t UNSPECIFIED_USERID = -2;
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
    std::shared_ptr<IAppControlManagerDb> appControlManagerDb_ =
        DelayedSingleton<AppControlManager>::GetInstance()->appControlManagerDb_;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleAppControlTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleAppControlTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleAppControlTest::BmsBundleAppControlTest()
{}

BmsBundleAppControlTest::~BmsBundleAppControlTest()
{}

void BmsBundleAppControlTest::SetUpTestCase()
{}

void BmsBundleAppControlTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleAppControlTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundleAppControlTest::TearDown()
{}

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
    installParam.withCopyHaps = true;
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
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    seteuid(3057);
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
    EXPECT_EQ(appIds.size() * 2, resultAppIds.size());
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
    seteuid(3057);
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
    seteuid(3057);
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
    seteuid(3057);
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
    seteuid(3057);
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
    seteuid(3057);
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
    seteuid(3057);
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
    bool allowRunning = false;
    auto res = appControlProxy->GetAppRunningControlRule(USERID, appIds, allowRunning);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(3057);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRule.allowRunning = false;
    controlRules.emplace_back(controlRule);
    res = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlProxy->GetAppRunningControlRule(USERID, appIds, allowRunning);
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
    seteuid(3057);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule. allowRunning = false;
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
    seteuid(3057);
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
    controlRule. allowRunning = false;
    controlRules.emplace_back(controlRule);
    AppRunningControlRuleResult controlRuleResult;
    bool allowRunning = false;
    auto RunningRes = appControlManagerDb_->AddAppRunningControlRule(
        AppControlConstants::EDM_CALLING, controlRules, 100);
    auto RunningRes1 = appControlManagerDb_->GetAppRunningControlRule(
        AppControlConstants::EDM_CALLING, 100, appIds, allowRunning);
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
    seteuid(3057);
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
    std::string runningAppId = APPID;
    auto RunningRes = appControlManagerDb_->GetAppRunningControlRule(runningAppId, USERID, controlRuleResult);
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

/**
 * @tc.number: AppControlManagerHostImpl_0100
 * @tc.name: test AddAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_0100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->AddAppInstallControlRule(
        appIds, AppInstallControlRuleType::ALLOWED_INSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_0200
 * @tc.name: test AddAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_0200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    ErrCode res = impl->AddAppInstallControlRule(
        appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_0300
 * @tc.name: test AddAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_0300, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->AddAppInstallControlRule(
        appIds, AppInstallControlRuleType::UNSPECIFIED, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID);
}

/**
 * @tc.number: AppControlManagerHostImpl_0400
 * @tc.name: test DeleteAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_0400, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->DeleteAppInstallControlRule(
        AppInstallControlRuleType::ALLOWED_INSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_0500
 * @tc.name: test DeleteAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_0500, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    ErrCode res = impl->DeleteAppInstallControlRule(
        AppInstallControlRuleType::ALLOWED_INSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_0600
 * @tc.name: test DeleteAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_0600, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    ErrCode res = impl->DeleteAppInstallControlRule(
        AppInstallControlRuleType::UNSPECIFIED, appIds, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID);
}

/**
 * @tc.number: AppControlManagerHostImpl_0700
 * @tc.name: test DeleteAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_0700, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->DeleteAppInstallControlRule(
        AppInstallControlRuleType::ALLOWED_INSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_0800
 * @tc.name: test DeleteAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_0800, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ErrCode res = impl->DeleteAppInstallControlRule(
        AppInstallControlRuleType::ALLOWED_INSTALL, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_0900
 * @tc.name: test DeleteAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_0900, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->DeleteAppInstallControlRule(
        AppInstallControlRuleType::UNSPECIFIED, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID);
}

/**
 * @tc.number: AppControlManagerHostImpl_1000
 * @tc.name: test GetAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.GetAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1000, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->GetAppInstallControlRule(
        AppInstallControlRuleType::ALLOWED_INSTALL, USERID, appIds);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_1100
 * @tc.name: test GetAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.GetAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    ErrCode res = impl->GetAppInstallControlRule(
        AppInstallControlRuleType::ALLOWED_INSTALL, USERID, appIds);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_1200
 * @tc.name: test GetAppInstallControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.GetAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->GetAppInstallControlRule(
        AppInstallControlRuleType::UNSPECIFIED, USERID, appIds);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID);
}

/**
 * @tc.number: AppControlManagerHostImpl_1300
 * @tc.name: test AddAppRunningControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1300, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_1400
 * @tc.name: test AddAppRunningControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1400, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<AppRunningControlRule> controlRules;
    ErrCode res = impl->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_1500
 * @tc.name: test DeleteAppRunningControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1500, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->DeleteAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_1600
 * @tc.name: test DeleteAppRunningControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1600, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<AppRunningControlRule> controlRules;
    ErrCode res = impl->DeleteAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_1700
 * @tc.name: test DeleteAppRunningControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1700, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->DeleteAppRunningControlRule(USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_1800
 * @tc.name: test DeleteAppRunningControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1800, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ErrCode res = impl->DeleteAppRunningControlRule(USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_1900
 * @tc.name: test GetAppRunningControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_1900, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    bool allowRunning = false;
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->GetAppRunningControlRule(USERID, appIds, allowRunning);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_2000
 * @tc.name: test GetAppRunningControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2000, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    bool allowRunning = false;
    ErrCode res = impl->GetAppRunningControlRule(USERID, appIds, allowRunning);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_2100
 * @tc.name: test GetAppRunningControlRule by AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    AppRunningControlRuleResult controlRuleResult;
    ErrCode res = impl->GetAppRunningControlRule(BUNDLE_NAME, USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_2200
 * @tc.name: test AppControlManagerHostImpl
 * @tc.require: issueI5MZ8C
 * @tc.desc: 1.SetDisposedStatus test
 *           2.GetDisposedStatus test
 *           3.DeleteDisposedStatus test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    Want want;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    ErrCode res = impl->SetDisposedStatus(APPID, want, userId);
    EXPECT_EQ(res, ERR_OK);

    res = impl->GetDisposedStatus(APPID, want, userId);
    EXPECT_EQ(res, ERR_OK);

    res = impl->DeleteDisposedStatus(APPID, userId);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetBundleNameByAppId_0100
 * @tc.name: test GetBundleNameByAppId
 * @tc.require: issueI5MZ8C
 * @tc.desc: with valid appId, return related bundleName; with invalid appId, return empty
 */
HWTEST_F(BmsBundleAppControlTest, GetBundleNameByAppId_0100, Function | SmallTest | Level1)
{
    InstallBundle(INSTALL_PATH);
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    // success test case
    std::string bundleName = dataMgr->GetBundleNameByAppId(APPID);
    EXPECT_EQ(bundleName, BUNDLE_NAME);
    // failed test case
    bundleName = dataMgr->GetBundleNameByAppId("invalidAppId");
    EXPECT_EQ(bundleName, "");
    UnInstallBundle(BUNDLE_NAME);
}
/**
 * @tc.number: AppControlManagerHostImpl_2300
 * @tc.name: test ConfirmAppJumpControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.ConfirmAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2300, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ErrCode res = impl->ConfirmAppJumpControlRule(CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_2400
 * @tc.name: test AddAppJumpControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.AddAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2400, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<AppJumpControlRule> controlRules;
    ErrCode res = impl->AddAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_2500
 * @tc.name: test DeleteAppJumpControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2500, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<AppJumpControlRule> controlRules;
    ErrCode res = impl->DeleteAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_2600
 * @tc.name: test DeleteRuleByCallerBundleName by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteRuleByCallerBundleName test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2600, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ErrCode res = impl->DeleteRuleByCallerBundleName(CALLER_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_2700
 * @tc.name: test GetAppJumpControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.GetAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2700, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    AppJumpControlRule controlRule;
    ErrCode res = impl->GetAppJumpControlRule(CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID, controlRule);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_2800
 * @tc.name: test ConfirmAppJumpControlRule by AppControlManager
 * @tc.desc: 1.ConfirmAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2800, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    auto appControlManager = impl->appControlManager_;
    ErrCode res = appControlManager->ConfirmAppJumpControlRule(CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    appControlManager->appJumpInterceptorManagerDb_ = std::make_shared<AppJumpInterceptorManagerRdb>();
    res = appControlManager->ConfirmAppJumpControlRule(CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_2900
 * @tc.name: test AddAppJumpControlRule by AppControlManager
 * @tc.desc: 1.AddAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_2900, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<AppJumpControlRule> controlRules;
    auto appControlManager = impl->appControlManager_;
    appControlManager->appJumpInterceptorManagerDb_ = nullptr;
    ErrCode res = appControlManager->AddAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    appControlManager->appJumpInterceptorManagerDb_ = std::make_shared<AppJumpInterceptorManagerRdb>();
    res = appControlManager->AddAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_3000
 * @tc.name: test DeleteAppJumpControlRule by AppControlManager
 * @tc.desc: 1.DeleteAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3000, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<AppJumpControlRule> controlRules;
    auto appControlManager = impl->appControlManager_;
    appControlManager->appJumpInterceptorManagerDb_ = nullptr;
    ErrCode res = appControlManager->DeleteAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    appControlManager->appJumpInterceptorManagerDb_ = std::make_shared<AppJumpInterceptorManagerRdb>();
    res = appControlManager->DeleteAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_3100
 * @tc.name: test DeleteRuleByCallerBundleName by AppControlManager
 * @tc.desc: 1.DeleteRuleByCallerBundleName test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    auto appControlManager = impl->appControlManager_;
    appControlManager->appJumpInterceptorManagerDb_ = nullptr;
    ErrCode res = appControlManager->DeleteRuleByCallerBundleName(CALLER_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    appControlManager->appJumpInterceptorManagerDb_ = std::make_shared<AppJumpInterceptorManagerRdb>();
    res = appControlManager->DeleteRuleByCallerBundleName(CALLER_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_3200
 * @tc.name: test GetAppJumpControlRule by AppControlManager
 * @tc.desc: 1.GetAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    AppJumpControlRule controlRule;
    auto appControlManager = impl->appControlManager_;
    appControlManager->appJumpInterceptorManagerDb_ = nullptr;
    ErrCode res = appControlManager->GetAppJumpControlRule(
        CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID, controlRule);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    appControlManager->appJumpInterceptorManagerDb_ = std::make_shared<AppJumpInterceptorManagerRdb>();
    res = appControlManager->GetAppJumpControlRule(CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID, controlRule);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_JUMP_INTERCPTOR);
}

/**
 * @tc.number: AppControlManagerHostImpl_3300
 * @tc.name: test ConfirmAppJumpControlRule by AppJumpInterceptorManagerRdb
 * @tc.desc: 1.ConfirmAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3300, Function | SmallTest | Level1)
{
    auto appJumpRdb = std::make_shared<AppJumpInterceptorManagerRdb>();
    ErrCode res = appJumpRdb->ConfirmAppJumpControlRule(CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_3400
 * @tc.name: test DeleteRuleByCallerBundleName by AppJumpInterceptorManagerRdb
 * @tc.desc: 1.DeleteRuleByCallerBundleName test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3400, Function | SmallTest | Level1)
{
    auto appJumpRdb = std::make_shared<AppJumpInterceptorManagerRdb>();
    ErrCode res = appJumpRdb->DeleteRuleByCallerBundleName(CALLER_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_3500
 * @tc.name: test DeleteRuleByTargetBundleName by AppJumpInterceptorManagerRdb
 * @tc.desc: 1.DeleteRuleByTargetBundleName test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3500, Function | SmallTest | Level1)
{
    auto appJumpRdb = std::make_shared<AppJumpInterceptorManagerRdb>();
    ErrCode res = appJumpRdb->DeleteRuleByTargetBundleName(TARGET_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_3600
 * @tc.name: test GetAppJumpControlRule by AppJumpInterceptorManagerRdb
 * @tc.desc: 1.GetAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3600, Function | SmallTest | Level1)
{
    AppJumpControlRule controlRule;
    auto appJumpRdb = std::make_shared<AppJumpInterceptorManagerRdb>();
    ErrCode res = appJumpRdb->GetAppJumpControlRule(CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID, controlRule);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_JUMP_INTERCPTOR);
}

/**
 * @tc.number: AppControlManagerHostImpl_3700
 * @tc.name: test ConfirmAppJumpControlRule
 * @tc.desc: 1.ConfirmAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3700, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    auto res = appControlProxy->ConfirmAppJumpControlRule("", TARGET_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    res = appControlProxy->ConfirmAppJumpControlRule(CALLER_BUNDLE_NAME, "", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AppControlManagerHostImpl_3800
 * @tc.name: test AddAppJumpControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.AddAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3800, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();

    std::vector<AppJumpControlRule> controlRules;
    auto res = appControlProxy->AddAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AppControlManagerHostImpl_3900
 * @tc.name: test AddAppJumpControlRule by AppControlManager
 * @tc.desc: 1.AddAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_3900, Function | SmallTest | Level1)
{
    std::vector<AppJumpControlRule> controlRules;
    AppJumpControlRule controlRule;
    controlRule.callerPkg = CALLER_BUNDLE_NAME;
    controlRule.targetPkg = TARGET_BUNDLE_NAME;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(controlRule);

    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    auto res = appControlProxy->AddAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_4000
 * @tc.name: test DeleteRuleByCallerBundleName by AppControlManager
 * @tc.desc: 1.DeleteRuleByCallerBundleName test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4000, Function | SmallTest | Level1)
{
    std::vector<AppJumpControlRule> controlRules;
    AppJumpControlRule controlRule;
    controlRule.callerPkg = CALLER_BUNDLE_NAME;
    controlRule.targetPkg = TARGET_BUNDLE_NAME;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(controlRule);

    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    auto res = appControlProxy->DeleteAppJumpControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_4100
 * @tc.name: test DeleteRuleByCallerBundleName by AppControlManager
 * @tc.desc: 1.DeleteRuleByCallerBundleName test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4100, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    auto res = appControlProxy->DeleteRuleByCallerBundleName(CALLER_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_4200
 * @tc.name: test DeleteRuleByCallerBundleName by AppControlManager
 * @tc.desc: 1.DeleteRuleByCallerBundleName test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4200, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    auto res = appControlProxy->DeleteRuleByTargetBundleName(CALLER_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_4300
 * @tc.name: test GetAppJumpControlRule by AppJumpInterceptorManagerRdb
 * @tc.desc: 1.GetAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4300, Function | SmallTest | Level1)
{
    AppJumpControlRule controlRule;
    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    auto res = appControlProxy->GetAppJumpControlRule(CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID, controlRule);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_4400
 * @tc.name: test AppControlManagerHostImpl
 * @tc.desc: 1.GetAbilityRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4400, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<DisposedRule> disposedRules;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    ErrCode res = impl->GetAbilityRunningControlRule(CALLER_BUNDLE_NAME, userId, disposedRules);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    EXPECT_EQ(disposedRules.empty(), true);
}

/**
 * @tc.number: AppControlManagerHostImpl_4400
 * @tc.name: test AppControlManagerHostImpl
 * @tc.desc: 1.GetAbilityRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4500, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    auto appControlManager = impl->appControlManager_;
    std::vector<DisposedRule> disposedRules;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    ErrCode res = appControlManager->GetAbilityRunningControlRule(CALLER_BUNDLE_NAME, Constants::MAIN_APP_INDEX,
        userId, disposedRules);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_EQ(disposedRules.empty(), true);
}

/**
 * @tc.number: AppControlManagerHostImpl_2800
 * @tc.name: test SetDisposedRule by AppControlManager
 * @tc.desc: 1.SetDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4600, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    DisposedRule rule;
    ErrCode res = appControlManager->GetDisposedRule(CALLER_BUNDLE_NAME, APPID, rule, Constants::MAIN_APP_INDEX,
        USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_4700
 * @tc.name: test SetDisposedRule by AppControlManager
 * @tc.desc: 1.SetDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4700, Function | SmallTest | Level1)
{
    std::shared_ptr<IAppJumpInterceptorlManagerDb> appJumpInterceptorManagerDb
        = std::make_shared<AppJumpInterceptorManagerRdb>();
    ASSERT_NE(appJumpInterceptorManagerDb, nullptr);
    auto res = appJumpInterceptorManagerDb->SubscribeCommonEvent();
    EXPECT_TRUE(res);

    AppJumpInterceptorEventSubscriber subscriber = AppJumpInterceptorEventSubscriber(appJumpInterceptorManagerDb);
    AAFwk::Want want;
    EventFwk::CommonEventData eventData {want};
    subscriber.OnReceiveEvent(eventData);
}

/**
 * @tc.number: AppControlManagerHostImpl_2800
 * @tc.name: test ConfirmAppJumpControlRule by AppControlManager
 * @tc.desc: 1.ConfirmAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4800, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleResult;
    appControlManager->appRunningControlRuleResult_["1"] = ruleResult;
    appControlManager->appRunningControlRuleResult_["100"] = ruleResult;
    ErrCode res = appControlManager->DeleteAppRunningControlRule(CALLER_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_4900
 * @tc.name: test UpdateAppControlledInfo by AppControlManagerHostImpl
 * @tc.desc: 1.UpdateAppControlledInfo test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_4900, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    std::vector<std::string> modifyAppIds;
    impl->UpdateAppControlledInfo(NOT_EXIST_USERID, modifyAppIds);
    EXPECT_TRUE(dataMgr->bundleInfos_[BUNDLE_NAME].innerBundleUserInfos_.empty());
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: AppControlManagerHostImpl_5000
 * @tc.name: test UpdateAppControlledInfo by AppControlManagerHostImpl
 * @tc.desc: 1.UpdateAppControlledInfo test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5000, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    std::vector<std::string> modifyAppIds;
    impl->UpdateAppControlledInfo(ALL_USERID, modifyAppIds);
    EXPECT_TRUE(dataMgr->bundleInfos_[BUNDLE_NAME].innerBundleUserInfos_.empty());
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: AppControlManagerHostImpl_5100
 * @tc.name: test GetDisposedRule by AppControlManagerHostImpl
 * @tc.desc: 1.GetDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    DisposedRule rule;
    auto ret = impl->GetDisposedRule(APPID, rule, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_5200
 * @tc.name: test GetDisposedRuleForCloneApp by AppControlManagerHostImpl
 * @tc.desc: 1.GetDisposedRuleForCloneApp test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    DisposedRule rule;
    auto ret = impl->GetDisposedRuleForCloneApp(APPID, rule, MAIN_APP_INDEX, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
    ret = impl->GetDisposedRuleForCloneApp(APPID, rule, CLONE_APP_INDEX_MAX, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
    ret = impl->GetDisposedRuleForCloneApp(APPID, rule, APP_INDEX, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_5300
 * @tc.name: test SetDisposedRuleForCloneApp by AppControlManagerHostImpl
 * @tc.desc: 1.SetDisposedRuleForCloneApp test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5300, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    DisposedRule rule;
    auto ret = impl->SetDisposedRuleForCloneApp(APPID, rule, MAIN_APP_INDEX, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
    ret = impl->SetDisposedRuleForCloneApp(APPID, rule, CLONE_APP_INDEX_MAX, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

/**
 * @tc.number: AppControlManagerHostImpl_5400
 * @tc.name: test DeleteDisposedRuleForCloneApp by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteDisposedRuleForCloneApp test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5400, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    DisposedRule rule;
    auto ret = impl->DeleteDisposedRuleForCloneApp(APPID, MAIN_APP_INDEX, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
    ret = impl->DeleteDisposedRuleForCloneApp(APPID, CLONE_APP_INDEX_MAX, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
    ret = impl->DeleteDisposedRuleForCloneApp(APPID, APP_INDEX, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_5500
 * @tc.name: test CheckCanDispose by appControlManager
 * @tc.desc: 1.CheckCanDispose test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5500, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    bool ret = appControlManager->CheckCanDispose(APPID, USERID);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AppControlManagerHostImpl_5600
 * @tc.name: test CheckCanDispose by appControlManager
 * @tc.desc: 1.CheckCanDispose test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5600, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    appControlManager->noControllingList_.push_back(BUNDLE_NAME);
    bool ret = appControlManager->CheckCanDispose(APPID, USERID);
    EXPECT_TRUE(ret);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: GetAbilityRunningControlRule_0100
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.GetAbilityRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, GetAbilityRunningControlRule_0100, Function | SmallTest | Level1)
{
    std::string appId = "appId";
    int32_t appIndex = 100;
    int32_t userId = 100;
    std::vector<DisposedRule> disposedRules;
    ASSERT_NE(appControlManagerDb_, nullptr);
    ErrCode result = appControlManagerDb_->GetAbilityRunningControlRule({ appId }, appIndex, userId, disposedRules);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: GetAbilityRunningControlRule_0200
 * @tc.name: test running control rule
 * @tc.require: issueI5MZ8K
 * @tc.desc: 1.GetAbilityRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, GetAbilityRunningControlRule_0200, Function | SmallTest | Level1)
{
    std::string appId = "appId";
    int32_t appIndex = 100;
    int32_t userId = 100;
    DisposedRule disposedRule;
    disposedRule.componentType = ComponentType::UI_ABILITY;
    disposedRule.disposedType = DisposedType::BLOCK_APPLICATION;
    disposedRule.controlType = ControlType::DISALLOWED_LIST;
    appControlManagerDb_->SetDisposedRule("testCaller", appId, disposedRule, appIndex, userId);
    std::vector<DisposedRule> disposedRules;
    ASSERT_NE(appControlManagerDb_, nullptr);
    ErrCode result = appControlManagerDb_->GetAbilityRunningControlRule({ appId }, appIndex, userId, disposedRules);
    EXPECT_EQ(result, ERR_OK);
}


/**
 * @tc.number: AppControlManagerHostImpl_5700
 * @tc.name: test ConfirmAppJumpControlRule by AppControlManager
 * @tc.desc: 1.ConfirmAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5700, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    std::string appId;
    DisposedRule disposedRule;
    int32_t userId = 0;
    ErrCode res = appControlProxy->SetDisposedRule(appId, disposedRule, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_5800
 * @tc.name: test SetDisposedRuleForCloneApp by AppControlManager
 * @tc.desc: 1.SetDisposedRuleForCloneApp test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5800, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    std::string appId;
    DisposedRule disposedRule;
    int32_t appIndex = 0;
    int32_t userId = 0;
    ErrCode res = appControlProxy->SetDisposedRuleForCloneApp(appId, disposedRule, appIndex, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_5900
 * @tc.name: test SetDisposedRuleForCloneApp by AppControlManager
 * @tc.desc: 1.SetDisposedRuleForCloneApp test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_5900, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    std::string appId;
    DisposedRule rule;
    int32_t appIndex = 0;
    int32_t userId = 0;
    ErrCode res = appControlProxy->GetDisposedRuleForCloneApp(appId, rule, appIndex, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_6000
 * @tc.name: test SetDisposedRuleForCloneApp by AppControlManager
 * @tc.desc: 1.SetDisposedRuleForCloneApp test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6000, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    std::string appId;
    int32_t appIndex = 0;
    int32_t userId = 0;
    ErrCode res = appControlProxy->DeleteDisposedRuleForCloneApp(appId, appIndex, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_6100
 * @tc.name: test SetDisposedRules by AppControlManagerHostImpl
 * @tc.desc: 1.SetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    DisposedRuleConfiguration disposedRuleConfiguration;
    disposedRuleConfiguration.appId = APPID;
    disposedRuleConfiguration.appIndex = APP_INDEX;
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    disposedRuleConfigurations.push_back(disposedRuleConfiguration);

    impl->appControlManager_ = nullptr;
    ErrCode res = impl->SetDisposedRules(disposedRuleConfigurations, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: AppControlManagerHostImpl_6200
 * @tc.name: test SetDisposedRules by AppControlManagerHostImpl
 * @tc.desc: 1.SetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    DisposedRuleConfiguration disposedRuleConfiguration;
    disposedRuleConfiguration.appId = APPID;
    disposedRuleConfiguration.appIndex = APP_INDEX;
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    disposedRuleConfigurations.push_back(disposedRuleConfiguration);

    impl->appControlManager_ = DelayedSingleton<AppControlManager>::GetInstance();
    ErrCode res = impl->SetDisposedRules(disposedRuleConfigurations, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_6200
 * @tc.name: test SetDisposedRules by AppControlManagerHostImpl
 * @tc.desc: 1.SetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_8000, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    DisposedRuleConfiguration disposedRuleConfiguration;
    disposedRuleConfiguration.appId = APPID;
    disposedRuleConfiguration.appIndex = APP_INDEX;
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    disposedRuleConfigurations.push_back(disposedRuleConfiguration);

    impl->appControlManager_ = DelayedSingleton<AppControlManager>::GetInstance();
    ErrCode res = impl->SetDisposedRules(disposedRuleConfigurations, UNSPECIFIED_USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppJumpInterceptorManagerRdb_6100
 * @tc.name: test AddAppJumpControlRule by AppJumpInterceptorManagerRdb
 * @tc.desc: 1.AddAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppJumpInterceptorManagerRdb_6100, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppJumpInterceptorManagerRdb>();
    ASSERT_NE(rdb, nullptr);

    std::vector<AppJumpControlRule> controlRules;
    int32_t userId = 100;
    ErrCode ret = rdb->AddAppJumpControlRule(controlRules, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppJumpInterceptorManagerRdb_6200
 * @tc.name: test DeleteAppJumpControlRule by AppJumpInterceptorManagerRdb
 * @tc.desc: 1.DeleteAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppJumpInterceptorManagerRdb_6200, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppJumpInterceptorManagerRdb>();
    ASSERT_NE(rdb, nullptr);

    std::vector<AppJumpControlRule> controlRules;
    int32_t userId = 100;
    ErrCode ret = rdb->DeleteAppJumpControlRule(controlRules, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppControlProxyGetDisposedRule_0100
 * @tc.name: test GetDisposedRule by AppControlProxy
 * @tc.desc: 1.GetDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlProxyGetDisposedRule_0100, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    std::string appId = "0";
    DisposedRule disposedRule;
    int32_t userId = 0;
    ErrCode res = appControlProxy->GetDisposedRule(appId, disposedRule, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlProxyGetAbilityRunningControlRule_0100
 * @tc.name: test GetAbilityRunningControlRule by AppControlProxy
 * @tc.desc: 1.GetAbilityRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlProxyGetAbilityRunningControlRule_0100, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    std::string bundleName = "bundleName";
    int32_t userId = 100;
    std::vector<DisposedRule> disposedRules;
    int32_t appIndex = 0;
    ErrCode result = appControlProxy->GetAbilityRunningControlRule(bundleName, userId, disposedRules, appIndex);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlProxyAppInstallControlRule_0100
 * @tc.name: test AddAppInstallControlRule by AppControlProxy
 * @tc.desc: 1.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlProxyAppInstallControlRule_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    const int32_t size = AppControlConstants::LIST_MAX_SIZE + 1;
    std::vector<std::string> appIds(size);
    auto res = appControlProxy->AddAppInstallControlRule(
        appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AppControlProxyConfirmAppJumpControlRule_0100
 * @tc.name: test ConfirmAppJumpControlRule by AppControlProxy
 * @tc.desc: 1.ConfirmAppJumpControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlProxyConfirmAppJumpControlRule_0100, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    auto res = appControlProxy->ConfirmAppJumpControlRule("", "", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    res = appControlProxy->ConfirmAppJumpControlRule(CALLER_BUNDLE_NAME, TARGET_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlHostHandleSetDisposedRuleForCloneApp_0100
 * @tc.name: test HandleSetDisposedRuleForCloneApp by AppControlHost
 * @tc.desc: 1.HandleSetDisposedRuleForCloneApp test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlHostHandleSetDisposedRuleForCloneApp_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleSetDisposedRuleForCloneApp(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: AppControlHostHandleSetDisposedRule_0100
 * @tc.name: test HandleSetDisposedRule by AppControlHost
 * @tc.desc: 1.HandleSetDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlHostHandleSetDisposedRule_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleSetDisposedRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: AppControlHostHandleSetDisposedStatus_0100
 * @tc.name: test HandleSetDisposedStatus by AppControlHost
 * @tc.desc: 1.HandleSetDisposedStatus test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlHostHandleSetDisposedStatus_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleSetDisposedStatus(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: AppControlManagerHostImpl_6300
 * @tc.name: Test DeleteRuleByTargetBundleName by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteRuleByTargetBundleName test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6300, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    ErrCode res = impl->DeleteRuleByTargetBundleName(CALLER_BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AppControlManagerHostImpl_6400
 * @tc.name: Test GetDisposedRuleForCloneApp by AppControlManagerHostImpl
 * @tc.desc: 1.GetDisposedRuleForCloneApp test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6400, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    DisposedRule rule;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    auto ret = impl->GetDisposedRuleForCloneApp(APPID, rule, APP_INDEX, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_6500
 * @tc.name: Test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6500, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AppRunningControlRuleResult controlRuleResult;
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    appControlManager->appRunningControlRuleResult_.clear();
    ErrCode res = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
}

/**
 * @tc.number: AppControlManagerHostImpl_6600
 * @tc.name: Test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6600, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AppRunningControlRuleResult controlRuleResult;
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    std::string key = std::string("_") + std::to_string(USERID);
    AppRunningControlRuleResult value;
    value.controlMessage = "_MESSAGE";
    appControlManager->appRunningControlRuleResult_.clear();
    appControlManager->appRunningControlRuleResult_.emplace(key, value);
    ErrCode res = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_6700
 * @tc.name: Test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6700, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AppRunningControlRuleResult controlRuleResult;
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    std::string key = std::string("_") + std::to_string(USERID);
    AppRunningControlRuleResult value;
    value.controlMessage = "INVALID_MESSAGE";
    appControlManager->appRunningControlRuleResult_.clear();
    appControlManager->appRunningControlRuleResult_.emplace(key, value);
    ErrCode res = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
}

/**
 * @tc.number: AppControlManagerHostImpl_6800
 * @tc.name: Test GetDisposedRule by AppControlManager
 * @tc.desc: 1.GetDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6800, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    DisposedRule rule;
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    rdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";
    appControlManager.appControlManagerDb_ = rdb;
    auto res = appControlManager.GetDisposedRule(CALLER_BUNDLE_NAME, APPID, rule, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_DB_RESULT_SET_EMPTY);
}

/**
 * @tc.number: AppControlManagerHostImpl_6900
 * @tc.name: Test DeleteDisposedRule by AppControlManager
 * @tc.desc: 1.DeleteDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_6900, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    std::string key = APPID + std::string("_") + std::to_string(USERID) + std::string("_") + std::to_string(APP_INDEX);
    std::vector<DisposedRule> value;
    appControlManager->abilityRunningControlRuleCache_.emplace(key, value);
    auto res = appControlManager->DeleteDisposedRule(CALLER_BUNDLE_NAME, APPID, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_7000
 * @tc.name: Test GetDisposedRule by AppControlManager
 * @tc.desc: 1.GetDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7000, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    DisposedRule rule;
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    rdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";
    appControlManager.appControlManagerDb_ = rdb;
    auto res = appControlManager.GetDisposedRule(CALLER_BUNDLE_NAME, APPID, rule, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_DB_RESULT_SET_EMPTY);
}

/**
 * @tc.number: AppControlManagerHostImpl_7100
 * @tc.name: Test DeleteAllDisposedRuleByBundle by AppControlManager
 * @tc.desc: 1.DeleteAllDisposedRuleByBundle test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7100, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    InnerBundleInfo bundleInfo;
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    rdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";
    appControlManager.appControlManagerDb_ = rdb;
    auto res = appControlManager.DeleteAllDisposedRuleByBundle(bundleInfo, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_DB_DELETE_ERROR);
}

/**
 * @tc.number: AppControlManagerHostImpl_7200
 * @tc.name: Test DeleteAllDisposedRuleByBundle by AppControlManager
 * @tc.desc: 1.DeleteAllDisposedRuleByBundle test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    InnerBundleInfo bundleInfo;
    auto res = appControlManager->DeleteAllDisposedRuleByBundle(bundleInfo, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_7300
 * @tc.name: Test DeleteAllDisposedRuleByBundle by AppControlManager
 * @tc.desc: 1.DeleteAllDisposedRuleByBundle test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7300, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo bundleInfo;
    ASSERT_NE(bundleInfo.baseApplicationInfo_, nullptr);
    bundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleCloneInfo cloneInfo;
    InnerBundleUserInfo userInfo;
    userInfo.cloneInfos.emplace(BUNDLE_NAME, cloneInfo);
    std::string key = BUNDLE_NAME + Constants::FILE_UNDERLINE + std::to_string(USERID);
    bundleInfo.innerBundleUserInfos_.emplace(key, userInfo);
    dataMgr->multiUserIdsSet_.insert(USERID);
    auto it = dataMgr->bundleInfos_.find(BUNDLE_NAME);
    dataMgr->bundleInfos_.erase(it);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, bundleInfo);
    auto res = appControlManager->DeleteAllDisposedRuleByBundle(bundleInfo, Constants::MAIN_APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_7400
 * @tc.name: Test DeleteAppRunningRuleCacheExcludeEdm by AppControlManager
 * @tc.desc: 1.DeleteAppRunningRuleCacheExcludeEdm test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7400, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    std::string key = "key";
    AppRunningControlRuleResult appRunningControlRuleResult;
    appControlManager->appRunningControlRuleResult_.emplace(key, appRunningControlRuleResult);
    appControlManager->DeleteAppRunningRuleCacheExcludeEdm(key);
    EXPECT_EQ(appControlManager->appRunningControlRuleResult_.find(key),
              appControlManager->appRunningControlRuleResult_.end());
}

/**
 * @tc.number: AppControlManagerHostImpl_7500
 * @tc.name: Test DeleteAbilityRunningRuleCache by AppControlManager
 * @tc.desc: 1.DeleteAbilityRunningRuleCache test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7500, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    std::string key = "key";
    std::vector<DisposedRule> disposedRule;
    appControlManager->abilityRunningControlRuleCache_.emplace(key, disposedRule);
    appControlManager->DeleteAbilityRunningRuleCache({ key });
    EXPECT_EQ(appControlManager->abilityRunningControlRuleCache_.find(key),
              appControlManager->abilityRunningControlRuleCache_.end());
}

/**
 * @tc.number: AppControlManagerHostImpl_7600
 * @tc.name: Test GetAbilityRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAbilityRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7600, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    std::vector<DisposedRule> disposedRules;
    auto res = appControlManager->GetAbilityRunningControlRule(BUNDLE_NAME, APP_INDEX, USERID, disposedRules);
    EXPECT_EQ(ERR_OK, res);
}

/**
 * @tc.number: AppControlManagerHostImpl_7700
 * @tc.name: Test GetAbilityRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAbilityRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7700, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    std::vector<DisposedRule> disposedRules;
    std::string key = std::string("_") + std::to_string(USERID) + std::string("_") + std::to_string(APP_INDEX);
    appControlManager->abilityRunningControlRuleCache_.emplace(key, disposedRules);
    auto res = appControlManager->GetAbilityRunningControlRule(BUNDLE_NAME, APP_INDEX, USERID, disposedRules);
    EXPECT_EQ(ERR_OK, res);
}

/**
 * @tc.number: AppControlManagerHostImpl_7800
 * @tc.name: Test GetAbilityRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAbilityRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7800, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    rdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";
    appControlManager.appControlManagerDb_ = rdb;
    std::vector<DisposedRule> disposedRules;
    auto res = appControlManager.GetAbilityRunningControlRule(BUNDLE_NAME, APP_INDEX, USERID, disposedRules);
    EXPECT_EQ(res, ERR_APPEXECFWK_DB_RESULT_SET_EMPTY);
}

/**
 * @tc.number: AppControlManagerHostImpl_7900
 * @tc.name: Test DeleteAppInstallControlRule by AppControlManager
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_7900, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    appControlManager->isAppInstallControlEnabled_ = true;
    std::string controlRuleType;
    auto res = appControlManager->DeleteAppInstallControlRule(CALLER_BUNDLE_NAME, controlRuleType, USERID);
    EXPECT_EQ(ERR_OK, res);
}

/**
 * @tc.number: UninstallDisposedRule_0100
 * @tc.name: Test SetUninstallDisposedRule by AppControlProxy
 * @tc.desc: 1.SetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_0100, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    UninstallDisposedRule uninstallDisposedRule;
    ErrCode res = appControlProxy->SetUninstallDisposedRule(APPID, uninstallDisposedRule, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: UninstallDisposedRule_0200
 * @tc.name: Test HandleSetUninstallDisposedRule by AppControlHost
 * @tc.desc: 1.HandleSetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleSetUninstallDisposedRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: UninstallDisposedRule_0300
 * @tc.name: Test SetUninstallDisposedRule by AppControlManager
 * @tc.desc: 1.SetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_0300, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    UninstallDisposedRule rule;
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    rdb->rdbDataManager_->bmsRdbConfig_.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    rdb->rdbDataManager_->bmsRdbConfig_.tableName = "app_control";
    appControlManager.appControlManagerDb_ = rdb;
    auto res = appControlManager.SetUninstallDisposedRule(CALLER_BUNDLE_NAME, APPID, rule, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: UninstallDisposedRule_0400
 * @tc.name: Test SetUninstallDisposedRule by AppControlManagerRdb
 * @tc.desc: 1.SetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_0400, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    UninstallDisposedRule uninstallDisposedRule;
    auto res = rdb->SetUninstallDisposedRule(CALLER_BUNDLE_NAME, APPID, uninstallDisposedRule, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: UninstallDisposedRule_0500
 * @tc.name: Test GetUninstallDisposedRule by AppControlProxy
 * @tc.desc: 1.GetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_0500, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    UninstallDisposedRule uninstallDisposedRule;
    ErrCode res = appControlProxy->GetUninstallDisposedRule(APPID, APP_INDEX, USERID, uninstallDisposedRule);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: UninstallDisposedRule_0600
 * @tc.name: Test HandleGetUninstallDisposedRule by AppControlHost
 * @tc.desc: 1.HandleGetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_0600, Function | SmallTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleGetUninstallDisposedRule(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: UninstallDisposedRule_0700
 * @tc.name: Test GetUninstallDisposedRule by AppControlManager
 * @tc.desc: 1.GetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_0700, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    UninstallDisposedRule uninstallDisposedRule;
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    rdb->rdbDataManager_->bmsRdbConfig_.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    rdb->rdbDataManager_->bmsRdbConfig_.tableName = "app_control";
    appControlManager.appControlManagerDb_ = rdb;
    auto res = appControlManager.GetUninstallDisposedRule(APPID, APP_INDEX, USERID, uninstallDisposedRule);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: UninstallDisposedRule_0800
 * @tc.name: Test GetUninstallDisposedRule by AppControlManagerRdb
 * @tc.desc: 1.GetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_0800, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    UninstallDisposedRule uninstallDisposedRule;
    auto res = rdb->GetUninstallDisposedRule(APPID, APP_INDEX, USERID, uninstallDisposedRule);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: UninstallDisposedRule_0900
 * @tc.name: Test GetUninstallDisposedRule by AppControlManagerRdb
 * @tc.desc: 1.GetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_0900, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    UninstallDisposedRule rule;
    rule.uninstallComponentType = UninstallComponentType::EXTENSION;
    rule.priority = 0;
    rdb->SetUninstallDisposedRule(CALLER_BUNDLE_NAME, APPID, rule, APP_INDEX, USERID);
    UninstallDisposedRule uninstallDisposedRule;
    auto res = rdb->GetUninstallDisposedRule(APPID, APP_INDEX, USERID, uninstallDisposedRule);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(rule.uninstallComponentType, uninstallDisposedRule.uninstallComponentType);
    EXPECT_EQ(rule.priority, uninstallDisposedRule.priority);
}

/**
 * @tc.number: UninstallDisposedRule_2000
 * @tc.name: Test GetUninstallDisposedRule by AppControlManagerRdb
 * @tc.desc: 1.GetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_2000, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    UninstallDisposedRule rule;
    rule.uninstallComponentType = UninstallComponentType::UI_EXTENSION;
    rule.priority = 0;
    rdb->SetUninstallDisposedRule(CALLER_BUNDLE_NAME, APPID, rule, APP_INDEX, USERID);
    UninstallDisposedRule uninstallDisposedRule;
    auto res = rdb->GetUninstallDisposedRule(APPID, APP_INDEX, USERID, uninstallDisposedRule);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(rule.uninstallComponentType, uninstallDisposedRule.uninstallComponentType);
    EXPECT_EQ(rule.priority, uninstallDisposedRule.priority);
}

/**
 * @tc.number: UninstallDisposedRule_1000
 * @tc.name: Test DeleteUninstallDisposedRule by AppControlManager
 * @tc.desc: 1.DeleteUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_1000, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    UninstallDisposedRule uninstallDisposedRule;
    auto res = appControlManager->DeleteUninstallDisposedRule(CALLER_BUNDLE_NAME, APPID, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: UninstallDisposedRule_1100
 * @tc.name: Test HandleDeleteUninstallDisposedRule by AppControlHost
 * @tc.desc: 1.HandleDeleteUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_1100, Function | SmallTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleDeleteUninstallDisposedRule(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: UninstallDisposedRule_1200
 * @tc.name: Test DeleteUninstallDisposedRule by AppControlManager
 * @tc.desc: 1.DeleteUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_1200, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    UninstallDisposedRule uninstallDisposedRule;
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    rdb->rdbDataManager_->bmsRdbConfig_.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    rdb->rdbDataManager_->bmsRdbConfig_.tableName = "app_control";
    appControlManager.appControlManagerDb_ = rdb;
    auto res = appControlManager.DeleteUninstallDisposedRule(CALLER_BUNDLE_NAME, APPID, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: UninstallDisposedRule_1300
 * @tc.name: Test DeleteUninstallDisposedRule by AppControlManagerRdb
 * @tc.desc: 1.DeleteUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, UninstallDisposedRule_1300, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    UninstallDisposedRule uninstallDisposedRule;
    auto res = rdb->DeleteUninstallDisposedRule(CALLER_BUNDLE_NAME, APPID, APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_0100, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::ADD_APP_INSTALL_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);
}

/**
 * @tc.number: OnRemoteRequest_0200
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_0200, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::ADD_APP_INSTALL_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_0300
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_0300, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_APP_JUMP_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0400
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_0400, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_INSTALL_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_0500
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_0500, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::CLEAN_APP_INSTALL_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_0600
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_0600, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_APP_INSTALL_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_0700
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_0700, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::ADD_APP_RUNNING_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_0800
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_0800, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_RUNNING_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_0900
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_0900, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::CLEAN_APP_RUNNING_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1000
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1000, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_APP_RUNNING_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1100, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_APP_RUNNING_CONTROL_RULE_RESULT),
        data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1200
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1200, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::CONFIRM_APP_JUMP_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1300
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1300, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::ADD_APP_JUMP_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1400
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1400, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1500
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1500, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE_BY_CALLER),
        data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1600
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1600, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE_BY_TARGET),
        data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1700
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1700, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_DISPOSED_STATUS), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1800
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1800, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_DISPOSED_STATUS), data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1800
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2800, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_DISPOSED_STATUS), data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_1900
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_1900, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_DISPOSED_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_2000
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2000, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_DISPOSED_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_2100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2100, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_ABILITY_RUNNING_CONTROL_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_2200
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2200, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_DISPOSED_RULE_FOR_CLONE_APP), data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_2300
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2300, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_DISPOSED_RULE_FOR_CLONE_APP), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_2400
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2400, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_DISPOSED_RULE_FOR_CLONE_APP), data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_2500
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2500, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_UNINSTALL_DISPOSED_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_2600
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2600, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_UNINSTALL_DISPOSED_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_2700
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2700, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_UNINSTALL_DISPOSED_RULE), data, reply, option);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppJumpInterceptorEventSubscriber_0100
 * @tc.name: test AppJumpInterceptorEventSubscriber OnReceiveEvent
 * @tc.desc: AppJumpInterceptorEventSubscriber OnReceiveEvent
 */
HWTEST_F(BmsBundleAppControlTest, AppJumpInterceptorEventSubscriber_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<IAppJumpInterceptorlManagerDb> appJumpInterceptorManagerDb
        = std::make_shared<AppJumpInterceptorManagerRdb>();
    ASSERT_NE(appJumpInterceptorManagerDb, nullptr);
    auto res = appJumpInterceptorManagerDb->SubscribeCommonEvent();
    EXPECT_TRUE(res);

    AppJumpInterceptorEventSubscriber subscriber = AppJumpInterceptorEventSubscriber(appJumpInterceptorManagerDb);
    AAFwk::Want want;
    want.SetAction("ohos.action.test");
    EventFwk::CommonEventData eventData {want};
    EXPECT_NO_THROW(subscriber.OnReceiveEvent(eventData));
}

/**
 * @tc.number: AppJumpInterceptorEventSubscriber_0200
 * @tc.name: test AppJumpInterceptorEventSubscriber OnReceiveEvent
 * @tc.desc: AppJumpInterceptorEventSubscriber OnReceiveEvent
 */
HWTEST_F(BmsBundleAppControlTest, AppJumpInterceptorEventSubscriber_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<IAppJumpInterceptorlManagerDb> appJumpInterceptorManagerDb
        = std::make_shared<AppJumpInterceptorManagerRdb>();
    ASSERT_NE(appJumpInterceptorManagerDb, nullptr);
    auto res = appJumpInterceptorManagerDb->SubscribeCommonEvent();
    EXPECT_TRUE(res);

    AppJumpInterceptorEventSubscriber subscriber = AppJumpInterceptorEventSubscriber(appJumpInterceptorManagerDb);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    ElementName element;
    element.SetBundleName("com.ohos.test");
    want.SetParam(Constants::USER_ID, 100);
    EventFwk::CommonEventData eventData {want};
    EXPECT_NO_THROW(subscriber.OnReceiveEvent(eventData));
}

/**
 * @tc.number: AppJumpInterceptorEventSubscriber_0300
 * @tc.name: test AppJumpInterceptorEventSubscriber OnReceiveEvent
 * @tc.desc: AppJumpInterceptorEventSubscriber OnReceiveEvent
 */
HWTEST_F(BmsBundleAppControlTest, AppJumpInterceptorEventSubscriber_0300, Function | SmallTest | Level1)
{
    std::shared_ptr<IAppJumpInterceptorlManagerDb> appJumpInterceptorManagerDb
        = std::make_shared<AppJumpInterceptorManagerRdb>();
    ASSERT_NE(appJumpInterceptorManagerDb, nullptr);
    auto res = appJumpInterceptorManagerDb->SubscribeCommonEvent();
    EXPECT_TRUE(res);

    AppJumpInterceptorEventSubscriber subscriber = AppJumpInterceptorEventSubscriber(appJumpInterceptorManagerDb);
    AAFwk::Want want;
    want.SetAction("ohos.action.test");
    ElementName element;
    element.SetBundleName("com.ohos.test");
    want.SetParam(Constants::USER_ID, 100);
    EventFwk::CommonEventData eventData {want};
    EXPECT_NO_THROW(subscriber.OnReceiveEvent(eventData));
}

/**
 * @tc.number: AppJumpInterceptorEventSubscriber_0400
 * @tc.name: test AppJumpInterceptorEventSubscriber OnReceiveEvent
 * @tc.desc: AppJumpInterceptorEventSubscriber OnReceiveEvent
 */
HWTEST_F(BmsBundleAppControlTest, AppJumpInterceptorEventSubscriber_0400, Function | SmallTest | Level1)
{
    std::shared_ptr<IAppJumpInterceptorlManagerDb> appJumpInterceptorManagerDb
        = std::make_shared<AppJumpInterceptorManagerRdb>();
    ASSERT_NE(appJumpInterceptorManagerDb, nullptr);
    auto res = appJumpInterceptorManagerDb->SubscribeCommonEvent();
    EXPECT_TRUE(res);

    AppJumpInterceptorEventSubscriber subscriber = AppJumpInterceptorEventSubscriber(appJumpInterceptorManagerDb);
    AAFwk::Want want;
    want.SetAction("ohos.action.test");
    ElementName element;
    element.SetBundleName("");
    want.SetParam(Constants::USER_ID, 100);
    EventFwk::CommonEventData eventData {want};
    EXPECT_NO_THROW(subscriber.OnReceiveEvent(eventData));
}

/**
 * @tc.number: GetUninstallDisposedRuleImpl_0100
 * @tc.name: test GetUninstallDisposedRule by AppControlManagerHostImpl
 * @tc.desc: 1.GetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, GetUninstallDisposedRuleImpl_0100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::string appIdentifier = "";
    int32_t appIndex = 0;
    int32_t userId = 100;
    UninstallDisposedRule uninstallDisposedRule;

    ErrCode res = impl->GetUninstallDisposedRule(appIdentifier, appIndex, userId, uninstallDisposedRule);
    EXPECT_EQ(res, ERR_OK);

    res = impl->GetUninstallDisposedRule(appIdentifier, -1, userId, uninstallDisposedRule);
    EXPECT_EQ(res, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);

    res = impl->GetUninstallDisposedRule(appIdentifier, appIndex, -2, uninstallDisposedRule);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: SetUninstallDisposedRuleImpl_0100
 * @tc.name: test SetUninstallDisposedRule by AppControlManagerHostImpl
 * @tc.desc: 1.SetUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, SetUninstallDisposedRuleImpl_0100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::string appIdentifier = "";
    int32_t appIndex = 0;
    int32_t userId = 100;
    UninstallDisposedRule uninstallDisposedRule;

    ErrCode res = impl->SetUninstallDisposedRule(appIdentifier, uninstallDisposedRule, appIndex, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_UNINSTALL_RULE);

    res = impl->SetUninstallDisposedRule(appIdentifier, uninstallDisposedRule, -1, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);

    res = impl->SetUninstallDisposedRule(appIdentifier, uninstallDisposedRule, appIndex, -2);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_UNINSTALL_RULE);
}

/**
 * @tc.number: DeleteUninstallDisposedRuleImpl_0100
 * @tc.name: test DeleteUninstallDisposedRule by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteUninstallDisposedRule test
 */
HWTEST_F(BmsBundleAppControlTest, DeleteUninstallDisposedRuleImpl_0100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::string appIdentifier = "";
    int32_t appIndex = 0;
    int32_t userId = 100;

    ErrCode res = impl->DeleteUninstallDisposedRule(appIdentifier, appIndex, userId);
    EXPECT_EQ(res, ERR_OK);

    res = impl->DeleteUninstallDisposedRule(appIdentifier, -1, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);

    res = impl->DeleteUninstallDisposedRule(appIdentifier, appIndex, -2);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetDisposedRuleFromResultSet_0100
 * @tc.name: Test GetDisposedRuleFromResultSet by AppControlManagerRdb
 * @tc.desc: 1.GetDisposedRuleFromResultSet test
 */
HWTEST_F(BmsBundleAppControlTest, GetDisposedRuleFromResultSet_0100, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    std::vector<DisposedRule> disposedRules;
    auto res = rdb->GetDisposedRuleFromResultSet(nullptr, disposedRules);
    EXPECT_EQ(res, ERR_APPEXECFWK_DB_RESULT_SET_EMPTY);
}

/**
 * @tc.number: PrintDisposedRuleInfo_0100
 * @tc.name: Test PrintDisposedRuleInfo_0100
 * @tc.desc: PrintDisposedRuleInfo_0100 test
 */
HWTEST_F(BmsBundleAppControlTest, PrintDisposedRuleInfo_0100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);

    std::string appId = "com.test.appcontrol";
    std::string atomicServiceId = "com.atomicservice.appcontrol";
    DisposedRule rule;
    rule.callerName = "com.xxx.xx";
    rule.setTime = 11111111;
    std::vector<DisposedRule> disposedRules;
    disposedRules.emplace_back(rule);
    EXPECT_NO_THROW(appControlManager->PrintDisposedRuleInfo(disposedRules, appId));
    EXPECT_NO_THROW(appControlManager->PrintDisposedRuleInfo(disposedRules, atomicServiceId));
}

/**
 * @tc.number: AbilityRunningRuleCache_0100
 * @tc.name: Test AbilityRunningRuleCache
 * @tc.desc: AbilityRunningRuleCache test
 */
HWTEST_F(BmsBundleAppControlTest, AbilityRunningRuleCache_0100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);

    DisposedRule rule;
    rule.callerName = "com.xxx.xx";
    rule.setTime = 11111111;
    std::vector<DisposedRule> disposedRules;
    disposedRules.emplace_back(rule);
    EXPECT_NO_THROW(appControlManager->SetAbilityRunningRuleCache(ABILITY_RUNNING_KEY, disposedRules));

    std::vector<DisposedRule> resultRules;
    bool ret = appControlManager->GetAbilityRunningRuleCache(ABILITY_RUNNING_KEY, resultRules);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(resultRules.empty());

    EXPECT_NO_THROW(appControlManager->DeleteAbilityRunningRuleCache({ ABILITY_RUNNING_KEY }));

    std::vector<DisposedRule> resultRules2;
    ret = appControlManager->GetAbilityRunningRuleCache(ABILITY_RUNNING_KEY, resultRules2);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(resultRules2.empty());
}

/**
 * @tc.number: GenerateAppRunningRuleCacheKey_0100
 * @tc.name: Test GenerateAppRunningRuleCacheKey_0100
 * @tc.desc: GenerateAppRunningRuleCacheKey_0100 test
 */
HWTEST_F(BmsBundleAppControlTest, GenerateAppRunningRuleCacheKey_0100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    std::string key = appControlManager->GenerateAppRunningRuleCacheKey("appid", 100, 0);
    EXPECT_EQ(key, "appid_100_0");
}

/**
 * @tc.number: SendAppControlEvent_0100
 * @tc.name: test SendAppControlEvent
 * @tc.desc: SendAppControlEvent test
 */
HWTEST_F(BmsBundleAppControlTest, SendAppControlEvent_0100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    EXPECT_NO_THROW(impl->SendAppControlEvent(ControlActionType::INSTALL, ControlOperationType::ADD_RULE,
        "test", 100, 0, { "test_appId "}, "rule"));
}

/**
 * @tc.number: AppControlHostHandleSetDisposedRules_0100
 * @tc.name: test HandleSetDisposedRules by AppControlHost
 * @tc.desc: 1.HandleSetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlHostHandleSetDisposedRules_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleSetDisposedRules(data, reply);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_2900
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_2900, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_DISPOSED_RULES), data, reply, option);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_3000
 * @tc.name: test the OnRemoteRequest by AppControlHost
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_3000, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_DISPOSED_RULES), data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);
}

/**
 * @tc.number: OnRemoteRequest_3100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_3100, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    data.WriteInterfaceToken(AppControlHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_DISPOSED_RULES), data, reply, option);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_3200
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_3200, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(2);
    ErrCode res = appControlHost.HandleDeleteDisposedRules(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_3300
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, OnRemoteRequest_3300, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(1);
    DisposedRuleConfiguration config;
    data.WriteParcelable(&config);
    data.WriteInt32(100);
    ErrCode res = appControlHost.HandleDeleteDisposedRules(data, reply);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: DisposeRuleCacheOnlyForBms_1000
 * @tc.name: test DisposeRuleCacheOnlyForBms
 * @tc.desc: test cache
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleAppControlTest, DisposeRuleCacheOnlyForBms_0100, Function | MediumTest | Level0)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    auto appControlManager = impl->appControlManager_;
    ASSERT_NE(appControlManager, nullptr);
    
    std::string appId = "testappId_1";
    appControlManager->SetDisposedRuleOnlyForBms(appId);
    std::vector<DisposedRule> disposedRules;
    bool ret = appControlManager->GetDisposedRuleOnlyForBms(appId, disposedRules);
    EXPECT_TRUE(ret);
    appControlManager->SetDisposedRuleOnlyForBms(appId);
    appControlManager->DeleteDisposedRuleOnlyForBms(appId);
    ret = appControlManager->GetDisposedRuleOnlyForBms(appId, disposedRules);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetAllUserIdsForRunningControl_0100
 * @tc.name: Test GetAllUserIdsForRunningControl by AppControlManagerRdb
 * @tc.desc: 1.GetAllUserIdsForRunningControl test
 */
HWTEST_F(BmsBundleAppControlTest, GetAllUserIdsForRunningControl_0100, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    std::vector<int32_t> outUserIds;
    auto res = rdb->GetAllUserIdsForRunningControl(outUserIds);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(outUserIds.size(), 0);
}

/**
 * @tc.number: GetAllUserIdsForRunningControl_0200
 * @tc.name: Test GetAllUserIdsForRunningControl by AppControlManagerRdb
 * @tc.desc: 1.GetAllUserIdsForRunningControl test
 */
HWTEST_F(BmsBundleAppControlTest, GetAllUserIdsForRunningControl_0200, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    auto res = rdb->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    std::vector<int32_t> outUserIds;
    res = rdb->GetAllUserIdsForRunningControl(outUserIds);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(outUserIds.size(), 1);
    res = rdb->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetAllUserIdsForRunningControl_0300
 * @tc.name: Test GetAllUserIdsForRunningControl by AppControlManagerRdb
 * @tc.desc: 1.GetAllUserIdsForRunningControl test
 */
HWTEST_F(BmsBundleAppControlTest, GetAllUserIdsForRunningControl_0300, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam1;
    ruleParam1.appId = APPID;
    ruleParam1.controlMessage = CONTROL_MESSAGE;
    ruleParam1.allowRunning = true;
    controlRules.emplace_back(ruleParam1);
    AppRunningControlRule ruleParam2;
    ruleParam2.appId = APPID;
    ruleParam2.controlMessage = CONTROL_MESSAGE;
    ruleParam2.allowRunning = true;
    controlRules.emplace_back(ruleParam2);
    auto res = rdb->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    std::vector<int32_t> outUserIds;
    res = rdb->GetAllUserIdsForRunningControl(outUserIds);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(outUserIds.size(), 1);
    res = rdb->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetAppIdsByUserId_0100
 * @tc.name: Test GetAppIdsByUserId by AppControlManagerRdb
 * @tc.desc: 1.GetAppIdsByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppIdsByUserId_0100, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    auto res = rdb->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    std::vector<std::string> appIds;
    res = rdb->GetAppIdsByUserId(USERID, appIds);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(appIds.size(), 1);
    res = rdb->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetAppIdsByUserId_0200
 * @tc.name: Test GetAppIdsByUserId by AppControlManagerRdb
 * @tc.desc: 1.GetAppIdsByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppIdsByUserId_0200, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    std::vector<std::string> appIds;
    auto res = rdb->GetAppIdsByUserId(USERID, appIds);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(appIds.size(), 0);
}

/**
 * @tc.number: GetAppRunningControlRuleByUserId_0100
 * @tc.name: Test GetAppRunningControlRuleByUserId by AppControlManagerRdb
 * @tc.desc: 1.GetAppRunningControlRuleByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppRunningControlRuleByUserId_0100, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    std::string appId;
    AppRunningControlRule ruleParam;
    auto res = rdb->GetAppRunningControlRuleByUserId(USERID, appId, ruleParam);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_TRUE(appId.empty());
}

/**
 * @tc.number: GetAppRunningControlRuleByUserId_0200
 * @tc.name: Test GetAppRunningControlRuleByUserId by AppControlManagerRdb
 * @tc.desc: 1.GetAppRunningControlRuleByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppRunningControlRuleByUserId_0200, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    auto res = rdb->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    std::string appId;
    AppRunningControlRule ruleParam1;
    res = rdb->GetAppRunningControlRuleByUserId(USERID, appId, ruleParam1);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(appId, APPID);
    res = rdb->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GenerateRunningRuleSettingStatusMap_0100
 * @tc.name: Test GenerateRunningRuleSettingStatusMap by AppControlManager
 * @tc.desc: 1.GenerateRunningRuleSettingStatusMap test
 */
HWTEST_F(BmsBundleAppControlTest, GenerateRunningRuleSettingStatusMap_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    auto res = appControlManager->GenerateRunningRuleSettingStatusMap();
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GenerateRunningRuleSettingStatusMap_0200
 * @tc.name: Test GenerateRunningRuleSettingStatusMap by AppControlManager
 * @tc.desc: 1.GenerateRunningRuleSettingStatusMap test
 */
HWTEST_F(BmsBundleAppControlTest, GenerateRunningRuleSettingStatusMap_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = "";
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    auto res = rdb->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlManager->GenerateRunningRuleSettingStatusMap();
    EXPECT_EQ(res, ERR_OK);
    auto ret = appControlManager->GenerateRunningRuleSettingStatusMap();
    EXPECT_EQ(ret, AppExecFwk::AppControlManager::RunningRuleSettingStatus::NO_SET);
    res = rdb->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GenerateRunningRuleSettingStatusMap_0300
 * @tc.name: Test GenerateRunningRuleSettingStatusMap by AppControlManager
 * @tc.desc: 1.GenerateRunningRuleSettingStatusMap test
 */
HWTEST_F(BmsBundleAppControlTest, GenerateRunningRuleSettingStatusMap_0300, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    auto res = rdb->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlManager->GenerateRunningRuleSettingStatusMap();
    EXPECT_EQ(res, ERR_OK);
    auto ret = appControlManager->GetRunningRuleSettingStatusByUserId(USERID);
    EXPECT_EQ(ret, AppExecFwk::AppControlManager::RunningRuleSettingStatus::WHITE_LIST);
    res = rdb->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GenerateRunningRuleSettingStatusMap_0400
 * @tc.name: Test GenerateRunningRuleSettingStatusMap by AppControlManager
 * @tc.desc: 1.GenerateRunningRuleSettingStatusMap test
 */
HWTEST_F(BmsBundleAppControlTest, GenerateRunningRuleSettingStatusMap_0400, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = false;
    controlRules.emplace_back(ruleParam);
    auto res = rdb->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlManager->GenerateRunningRuleSettingStatusMap();
    EXPECT_EQ(res, ERR_OK);
    auto ret = appControlManager->GetRunningRuleSettingStatusByUserId(USERID);
    EXPECT_EQ(ret, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    res = rdb->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AddAppRunningControlRule_0100
 * @tc.name: Test AddAppRunningControlRule by AppControlManager
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AddAppRunningControlRule_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    auto res = appControlManager->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    res = appControlManager->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AddAppRunningControlRule_0200
 * @tc.name: Test AddAppRunningControlRule by AppControlManager
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AddAppRunningControlRule_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = false;
    controlRules.emplace_back(ruleParam);
    auto res = appControlManager->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlManager->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AddAppRunningControlRule_0300
 * @tc.name: Test AddAppRunningControlRule by AppControlManager
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AddAppRunningControlRule_0300, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    auto res = appControlManager->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    res = appControlManager->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CheckControlRules_0100
 * @tc.name: Test CheckControlRules by AppControlManager
 * @tc.desc: 1.CheckControlRules test
 */
HWTEST_F(BmsBundleAppControlTest, CheckControlRules_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    auto res = appControlManager->CheckControlRules(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: CheckControlRules_0200
 * @tc.name: Test CheckControlRules by AppControlManager
 * @tc.desc: 1.CheckControlRules test
 */
HWTEST_F(BmsBundleAppControlTest, CheckControlRules_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam1;
    ruleParam1.appId = APPID;
    ruleParam1.controlMessage = CONTROL_MESSAGE;
    ruleParam1.allowRunning = true;
    controlRules.emplace_back(ruleParam1);
    AppRunningControlRule ruleParam2;
    ruleParam2.appId = APPID;
    ruleParam2.controlMessage = CONTROL_MESSAGE;
    ruleParam2.allowRunning = false;
    controlRules.emplace_back(ruleParam2);
    auto res = appControlManager->CheckControlRules(controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_CONTROL_RULE_NOT_CONSISTENT);
}

/**
 * @tc.number: CheckControlRules_0300
 * @tc.name: Test CheckControlRules by AppControlManager
 * @tc.desc: 1.CheckControlRules test
 */
HWTEST_F(BmsBundleAppControlTest, CheckControlRules_0300, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules1;
    AppRunningControlRule ruleParam1;
    ruleParam1.appId = APPID;
    ruleParam1.controlMessage = CONTROL_MESSAGE;
    ruleParam1.allowRunning = true;
    controlRules1.emplace_back(ruleParam1);
    auto res = appControlManager->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules1, USERID);
    EXPECT_EQ(res, ERR_OK);
    std::vector<AppRunningControlRule> controlRules2;
    AppRunningControlRule ruleParam2;
    ruleParam2.appId = APPID;
    ruleParam2.controlMessage = CONTROL_MESSAGE;
    ruleParam2.allowRunning = false;
    controlRules2.emplace_back(ruleParam2);
    res = appControlManager->CheckControlRules(controlRules2, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_CONTROL_RULE_NOT_CONSISTENT);
    res = appControlManager->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules1, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CheckControlRules_0400
 * @tc.name: Test CheckControlRules by AppControlManager
 * @tc.desc: 1.CheckControlRules test
 */
HWTEST_F(BmsBundleAppControlTest, CheckControlRules_0400, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    auto res = appControlManager->CheckControlRules(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetRunningRuleSettingStatusByUserId_0100
 * @tc.name: Test GetRunningRuleSettingStatusByUserId by AppControlManager
 * @tc.desc: 1.GetRunningRuleSettingStatusByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, GetRunningRuleSettingStatusByUserId_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    auto res = appControlManager->GetRunningRuleSettingStatusByUserId(USERID);
    EXPECT_EQ(res, AppExecFwk::AppControlManager::RunningRuleSettingStatus::NO_SET);
}

/**
 * @tc.number: GetRunningRuleSettingStatusByUserId_0200
 * @tc.name: Test GetRunningRuleSettingStatusByUserId by AppControlManager
 * @tc.desc: 1.GetRunningRuleSettingStatusByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, GetRunningRuleSettingStatusByUserId_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    auto res = appControlManager->GetRunningRuleSettingStatusByUserId(USERID);
    EXPECT_EQ(res, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    auto ret = appControlManager->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, USERID);
    EXPECT_EQ(ret, ERR_OK);
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::WHITE_LIST);
    res = appControlManager->GetRunningRuleSettingStatusByUserId(USERID);
    EXPECT_EQ(res, AppExecFwk::AppControlManager::RunningRuleSettingStatus::WHITE_LIST);
    ret = appControlManager->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeleteAppRunningControlRule_0100
 * @tc.name: Test DeleteAppRunningControlRule by AppControlManager
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, DeleteAppRunningControlRule_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    auto res = appControlManager->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: DeleteAppRunningControlRule_0200
 * @tc.name: Test DeleteAppRunningControlRule by AppControlManager
 * @tc.desc: 1.DeleteAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, DeleteAppRunningControlRule_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = false;
    controlRules.emplace_back(ruleParam);
    auto res = appControlManager->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: SetAppRunningControlRuleCache_0100
 * @tc.name: Test SetAppRunningControlRuleCache by AppControlManager
 * @tc.desc: 1.SetAppRunningControlRuleCache test
 */
HWTEST_F(BmsBundleAppControlTest, SetAppRunningControlRuleCache_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    std::string key = APPID + std::string("_") + std::to_string(USERID);
    appControlManager->SetAppRunningControlRuleCache(key, ruleParam);
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRuleCache(key, rule);
    EXPECT_TRUE(ret);
    EXPECT_EQ(rule.controlMessage, ruleParam.controlMessage);
    appControlManager->appRunningControlRuleResult_.clear();
}

/**
 * @tc.number: DeleteAppRunningControlRuleCache_0100
 * @tc.name: Test DeleteAppRunningControlRuleCache by AppControlManager
 * @tc.desc: 1.DeleteAppRunningControlRuleCache test
 */
HWTEST_F(BmsBundleAppControlTest, DeleteAppRunningControlRuleCache_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    std::string key = APPID + std::string("_") + std::to_string(USERID);
    appControlManager->SetAppRunningControlRuleCache(key, ruleParam);
    appControlManager->DeleteAppRunningControlRuleCache(key);
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRuleCache(key, rule);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteAppRunningControlRuleCacheForUserId_0100
 * @tc.name: Test DeleteAppRunningControlRuleCacheForUserId by AppControlManager
 * @tc.desc: 1.DeleteAppRunningControlRuleCacheForUserId test
 */
HWTEST_F(BmsBundleAppControlTest, DeleteAppRunningControlRuleCacheForUserId_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    std::string key = APPID + std::string("_") + std::to_string(USERID);
    appControlManager->SetAppRunningControlRuleCache(key, ruleParam);
    appControlManager->DeleteAppRunningControlRuleCacheForUserId(USERID);
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRuleCache(key, rule);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckAppControlRuleIntercept_0100
 * @tc.name: Test CheckAppControlRuleIntercept by AppControlManager
 * @tc.desc: 1.CheckAppControlRuleIntercept test
 */
HWTEST_F(BmsBundleAppControlTest, CheckAppControlRuleIntercept_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.isEdm = false;
    auto ret = appControlManager->CheckAppControlRuleIntercept(BUNDLE_NAME, USERID, true, ruleParam);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(ruleParam.controlMessage, CONTROL_MESSAGE);
}

/**
 * @tc.number: CheckAppControlRuleIntercept_0200
 * @tc.name: Test CheckAppControlRuleIntercept by AppControlManager
 * @tc.desc: 1.CheckAppControlRuleIntercept test
 */
HWTEST_F(BmsBundleAppControlTest, CheckAppControlRuleIntercept_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.isEdm = true;
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::NO_SET);
    auto ret = appControlManager->CheckAppControlRuleIntercept(BUNDLE_NAME, USERID, true, ruleParam);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    EXPECT_EQ(ruleParam.controlMessage, INVALID_MESSAGE);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: CheckAppControlRuleIntercept_0300
 * @tc.name: Test CheckAppControlRuleIntercept by AppControlManager
 * @tc.desc: 1.CheckAppControlRuleIntercept test
 */
HWTEST_F(BmsBundleAppControlTest, CheckAppControlRuleIntercept_0300, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.isEdm = true;
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::WHITE_LIST);
    auto ret = appControlManager->CheckAppControlRuleIntercept(BUNDLE_NAME, USERID, true, ruleParam);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    EXPECT_EQ(ruleParam.controlMessage, INVALID_MESSAGE);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: CheckAppControlRuleIntercept_0400
 * @tc.name: Test CheckAppControlRuleIntercept by AppControlManager
 * @tc.desc: 1.CheckAppControlRuleIntercept test
 */
HWTEST_F(BmsBundleAppControlTest, CheckAppControlRuleIntercept_0400, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.isEdm = true;
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    auto ret = appControlManager->CheckAppControlRuleIntercept(BUNDLE_NAME, USERID, true, ruleParam);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(ruleParam.controlMessage, CONTROL_MESSAGE);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: CheckAppControlRuleIntercept_0500
 * @tc.name: Test CheckAppControlRuleIntercept by AppControlManager
 * @tc.desc: 1.CheckAppControlRuleIntercept test
 */
HWTEST_F(BmsBundleAppControlTest, CheckAppControlRuleIntercept_0500, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.isEdm = true;
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    auto ret = appControlManager->CheckAppControlRuleIntercept(BUNDLE_NAME, USERID, false, ruleParam);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    EXPECT_EQ(ruleParam.controlMessage, INVALID_MESSAGE);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: CheckAppControlRuleIntercept_0600
 * @tc.name: Test CheckAppControlRuleIntercept by AppControlManager
 * @tc.desc: 1.CheckAppControlRuleIntercept test
 */
HWTEST_F(BmsBundleAppControlTest, CheckAppControlRuleIntercept_0600, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.isEdm = true;
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::NO_SET);
    auto ret = appControlManager->CheckAppControlRuleIntercept(BUNDLE_NAME, USERID, false, ruleParam);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    EXPECT_EQ(ruleParam.controlMessage, INVALID_MESSAGE);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: CheckAppControlRuleIntercept_0700
 * @tc.name: Test CheckAppControlRuleIntercept by AppControlManager
 * @tc.desc: 1.CheckAppControlRuleIntercept test
 */
HWTEST_F(BmsBundleAppControlTest, CheckAppControlRuleIntercept_0700, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.isEdm = true;
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::WHITE_LIST);
    auto ret = appControlManager->CheckAppControlRuleIntercept(BUNDLE_NAME, USERID, false, ruleParam);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(ruleParam.controlMessage, APP_CONTROL_EDM_DEFAULT_MESSAGE);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: GetAppRunningControlRule_0100
 * @tc.name: Test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppRunningControlRule_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = INVALID_MESSAGE;
    ruleParam.isEdm = true;
    std::string key = APPID + std::string("_") + std::to_string(USERID);
    appControlManager->SetAppRunningControlRuleCache(key, ruleParam);
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, rule);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    appControlManager->appRunningControlRuleResult_.clear();
}

/**
 * @tc.number: GetAppRunningControlRule_0200
 * @tc.name: Test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppRunningControlRule_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.isEdm = true;
    std::string key = APPID + std::string("_") + std::to_string(USERID);
    appControlManager->SetAppRunningControlRuleCache(key, ruleParam);
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, rule);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    appControlManager->appRunningControlRuleResult_.clear();
}

/**
 * @tc.number: GetAppRunningControlRule_0300
 * @tc.name: Test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppRunningControlRule_0300, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, rule);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
}

/**
 * @tc.number: AppControlManagerHostImpl_8100
 * @tc.name: test DeleteAppInstallControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.DeleteAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_8100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    ErrCode res = impl->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_OK);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->appId = APPID;
    innerBundleInfo.SetAppIdentifier("appIdentifier");
    impl->dataMgr_->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    res = impl->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_OK);
    impl->dataMgr_->bundleInfos_.erase(BUNDLE_NAME);

    impl->dataMgr_ = nullptr;
    res = impl->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
    impl->dataMgr_ = std::make_shared<BundleDataMgr>();
}

/**
 * @tc.number: AppControlManagerHostImpl_8200
 * @tc.name: test AddAppInstallControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_8200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->appId = APPID;
    innerBundleInfo.SetAppIdentifier("appIdentifier");
    impl->dataMgr_->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    res = impl->AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
    impl->dataMgr_->bundleInfos_.erase(BUNDLE_NAME);

    impl->dataMgr_ = nullptr;
    res = impl->AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
    impl->dataMgr_ = std::make_shared<BundleDataMgr>();

    res = impl->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_8300
 * @tc.name: test AddAppInstallControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_8300, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
    std::vector<std::string> modifyAppIds;
    res = impl->GetAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID, modifyAppIds);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(modifyAppIds.size(), 2);
    impl->dataMgr_ = nullptr;
    res = impl->GetAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID, modifyAppIds);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
    impl->dataMgr_ = std::make_shared<BundleDataMgr>();

    res = impl->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AppControlManagerHostImpl_8400
 * @tc.name: test AddAppInstallControlRule by AppControlManagerHostImpl
 * @tc.desc: 1.AddAppInstallControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_8400, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    std::vector<std::string> appIds;
    std::string appIdentifier = "appIdentifier";
    appIds.emplace_back(appIdentifier);
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->appId = APPID;
    innerBundleInfo.SetAppIdentifier(appIdentifier);
    impl->dataMgr_->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    ErrCode res = impl->AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);

    appIds.emplace_back(APPID);
    res = impl->AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);

    res = impl->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, appIds, USERID);
    EXPECT_EQ(res, ERR_OK);
    impl->dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: AppRunningControlRule_0900
 * @tc.name: test running control rule
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_0900, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(controlRule);
    auto res = appControlManager.AddAppRunningControlRule(CALLER_BUNDLE_NAME, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);

    std::string key = "" + std::string("_") + std::to_string(USERID);
    AppRunningControlRuleResult controlRuleResult;
    appControlManager.appRunningControlRuleResult_.emplace(key, controlRuleResult);
    res = appControlManager.AddAppRunningControlRule(CALLER_BUNDLE_NAME, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);

    res = appControlManager.DeleteAppRunningControlRule(CALLER_BUNDLE_NAME, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    appControlManager.appRunningControlRuleResult_.clear();
}

/**
 * @tc.number: AppRunningControlRule_1000
 * @tc.name: test running control rule
 * @tc.desc: 1.AddAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_1000, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(controlRule);
    auto res = appControlManager.DeleteAppRunningControlRule(CALLER_BUNDLE_NAME, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);

    std::string key = "" + std::string("_") + std::to_string(USERID);
    AppRunningControlRuleResult controlRuleResult;
    appControlManager.appRunningControlRuleResult_.emplace(key, controlRuleResult);
    res = appControlManager.DeleteAppRunningControlRule(CALLER_BUNDLE_NAME, controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    appControlManager.appRunningControlRuleResult_.clear();
}

/**
 * @tc.number: DeleteDisposedRules_0100
 * @tc.name: test DeleteDisposedRules_0100
 * @tc.desc: test DeleteDisposedRules_0100
 */
HWTEST_F(BmsBundleAppControlTest, DeleteDisposedRules_0100, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    DisposedRuleConfiguration disposedRuleConfiguration;
    disposedRuleConfiguration.appId = APPID;
    disposedRuleConfiguration.appIndex = APP_INDEX;
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    disposedRuleConfigurations.push_back(disposedRuleConfiguration);

    impl->appControlManager_ = nullptr;
    ErrCode res = impl->DeleteDisposedRules(disposedRuleConfigurations, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: DeleteDisposedRules_0200
 * @tc.name: test DeleteDisposedRules_0200
 * @tc.desc: test DeleteDisposedRules_0200
 */
HWTEST_F(BmsBundleAppControlTest, DeleteDisposedRules_0200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    DisposedRuleConfiguration disposedRuleConfiguration;
    disposedRuleConfiguration.appId = APPID;
    disposedRuleConfiguration.appIndex = APP_INDEX;
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    disposedRuleConfigurations.push_back(disposedRuleConfiguration);

    impl->appControlManager_ = DelayedSingleton<AppControlManager>::GetInstance();
    ErrCode res = impl->DeleteDisposedRules(disposedRuleConfigurations, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetDisposedRules_0100
 * @tc.name: test GetDisposedRules by AppControlProxy
 * @tc.desc: 1.GetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, GetDisposedRules_0100, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    ASSERT_NE(appControlProxy, nullptr);
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    ErrCode ret = appControlProxy->GetDisposedRules(TEST_USERID, disposedRuleConfigurations);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetDisposedRules_0200
 * @tc.name: test GetDisposedRules by AppControlManagerHostImpl
 * @tc.desc: 1.GetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, GetDisposedRules_0200, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    auto ret = impl->GetDisposedRules(TEST_USERID, disposedRuleConfigurations);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(disposedRuleConfigurations.size(), 0);
}

/**
 * @tc.number: GetDisposedRules_0300
 * @tc.name: test GetDisposedRules by AppControlManager
 * @tc.desc: 1.GetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, GetDisposedRules_0300, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    auto ret = appControlManager.GetDisposedRules(CALLER_BUNDLE_NAME, TEST_USERID, disposedRuleConfigurations);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(disposedRuleConfigurations.size(), 0);
}

/**
 * @tc.number: GetDisposedRules_0400
 * @tc.name: test GetDisposedRules by AppControlManager
 * @tc.desc: 1.GetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, GetDisposedRules_0400, Function | SmallTest | Level1)
{
    AppControlManager appControlManager;
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    rdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";
    appControlManager.appControlManagerDb_ = rdb;
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    auto ret = appControlManager.GetDisposedRules(CALLER_BUNDLE_NAME, TEST_USERID, disposedRuleConfigurations);
    EXPECT_EQ(ret, ERR_APPEXECFWK_DB_RESULT_SET_EMPTY);
}

/**
 * @tc.number: GetDisposedRules_0500
 * @tc.name: test GetDisposedRules by AppControlManagerRdb
 * @tc.desc: 1.GetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, GetDisposedRules_0500, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    ASSERT_NE(rdb->rdbDataManager_, nullptr);
    rdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    auto ret = rdb->GetDisposedRules(CALLER_BUNDLE_NAME, TEST_USERID, disposedRuleConfigurations);
    EXPECT_EQ(ret, ERR_APPEXECFWK_DB_RESULT_SET_EMPTY);
}

/**
 * @tc.number: GetDisposedRules_0600
 * @tc.name: test GetDisposedRules by AppControlManagerRdb
 * @tc.desc: 1.GetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, GetDisposedRules_0600, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    auto ret = rdb->GetDisposedRules(CALLER_BUNDLE_NAME, TEST_USERID, disposedRuleConfigurations);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetDisposedRules_0700
 * @tc.name: test GetDisposedRules by AppControlManagerRdb
 * @tc.desc: 1.GetDisposedRules test
 */
HWTEST_F(BmsBundleAppControlTest, GetDisposedRules_0700, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    std::string appId = "appId";
    int32_t appIndex = 100;
    DisposedRule disposedRule;
    disposedRule.componentType = ComponentType::UI_ABILITY;
    disposedRule.disposedType = DisposedType::BLOCK_APPLICATION;
    disposedRule.controlType = ControlType::DISALLOWED_LIST;
    auto ret = rdb->SetDisposedRule(CALLER_BUNDLE_NAME, appId, disposedRule, appIndex, TEST_USERID);
    EXPECT_EQ(ret, ERR_OK);

    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    ret = rdb->GetDisposedRules(CALLER_BUNDLE_NAME, TEST_USERID, disposedRuleConfigurations);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(disposedRuleConfigurations.size(), 1);
    EXPECT_EQ(disposedRuleConfigurations[0].appId, appId);
    EXPECT_EQ(disposedRuleConfigurations[0].appIndex, appIndex);
    EXPECT_EQ(disposedRuleConfigurations[0].disposedRule.componentType, disposedRule.componentType);
    EXPECT_EQ(disposedRuleConfigurations[0].disposedRule.disposedType, disposedRule.disposedType);
    EXPECT_EQ(disposedRuleConfigurations[0].disposedRule.controlType, disposedRule.controlType);

    ret = rdb->DeleteDisposedRule(CALLER_BUNDLE_NAME, { appId }, appIndex, TEST_USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ConvertToDisposedRuleConfiguration_0100
 * @tc.name: Test ConvertToDisposedRuleConfiguration by AppControlManagerRdb
 * @tc.desc: 1.ConvertToDisposedRuleConfiguration test
 */
HWTEST_F(BmsBundleAppControlTest, ConvertToDisposedRuleConfiguration_0100, Function | SmallTest | Level1)
{
    auto rdb = std::make_shared<AppControlManagerRdb>();
    ASSERT_NE(rdb, nullptr);
    DisposedRuleConfiguration disposedRuleConfiguration;
    auto ret = rdb->ConvertToDisposedRuleConfiguration(nullptr, disposedRuleConfiguration);
    EXPECT_EQ(ret, ERR_APPEXECFWK_DB_RESULT_SET_EMPTY);
}

/**
 * @tc.number: AppRunningControlRule_1100
 * @tc.name: test running control rule
 * @tc.desc: 1.AppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, AppRunningControlRule_1100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule ruleParam;
    ruleParam.appId = APPID;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.allowRunning = true;
    controlRules.emplace_back(ruleParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    auto res = appControlManager->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
    res = appControlManager->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
}

/**
 * @tc.number: AppControlManagerHostImpl_8500
 * @tc.name: test UpdateAppControlledInfo by AppControlManagerHostImpl
 * @tc.desc: 1.UpdateAppControlledInfo test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_8500, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    ASSERT_NE(impl->dataMgr_, nullptr);
    InnerBundleInfo innerBundleInfo;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    innerModuleInfos.try_emplace("module", innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetAppIdentifier("appId4");
    innerBundleInfo.baseBundleInfo_->appId = "appId5";
    impl->dataMgr_->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    std::string key = BUNDLE_NAME + Constants::FILE_UNDERLINE + std::to_string(ALL_USERID);
    impl->dataMgr_->bundleInfos_.at(BUNDLE_NAME).innerBundleUserInfos_.emplace(key, userInfo);

    std::vector<std::string> appIds = {"appId1", "appId2", "appId3"};
    ErrCode res = appControlManagerDb_->AddAppInstallControlRule(
        AppControlConstants::EDM_CALLING, appIds, AppControlConstants::APP_DISALLOWED_UNINSTALL, ALL_USERID);
    EXPECT_EQ(res, ERR_OK);
    impl->UpdateAppControlledInfo(ALL_USERID, appIds);
    impl->dataMgr_->bundleInfos_.at(BUNDLE_NAME).GetInnerBundleUserInfo(ALL_USERID, userInfo);
    EXPECT_TRUE(userInfo.isRemovable);

    innerBundleInfo.baseBundleInfo_->appId = "appId3";
    impl->dataMgr_->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    impl->UpdateAppControlledInfo(ALL_USERID, appIds);
    impl->dataMgr_->bundleInfos_.at(BUNDLE_NAME).GetInnerBundleUserInfo(ALL_USERID, userInfo);
    EXPECT_FALSE(userInfo.isRemovable);

    innerBundleInfo.SetAppIdentifier("appId3");
    innerBundleInfo.baseBundleInfo_->appId = "appId4";
    impl->dataMgr_->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    impl->UpdateAppControlledInfo(ALL_USERID, appIds);
    impl->dataMgr_->bundleInfos_.at(BUNDLE_NAME).GetInnerBundleUserInfo(ALL_USERID, userInfo);
    EXPECT_FALSE(userInfo.isRemovable);

    res = appControlManagerDb_->DeleteAppInstallControlRule(
        AppControlConstants::EDM_CALLING, AppControlConstants::APP_DISALLOWED_UNINSTALL, appIds, ALL_USERID);
    EXPECT_EQ(res, ERR_OK);
    impl->dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: AppControlManagerHostImpl_8600
 * @tc.name: test UpdateAppControlledInfo by AppControlManagerHostImpl
 * @tc.desc: 1.UpdateAppControlledInfo test
 */
HWTEST_F(BmsBundleAppControlTest, AppControlManagerHostImpl_8600, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    ASSERT_NE(impl->dataMgr_, nullptr);
    InnerBundleInfo innerBundleInfo;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    innerModuleInfos.try_emplace("module", innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetAppIdentifier("appId1");
    innerBundleInfo.baseBundleInfo_->appId = "appId1";
    impl->dataMgr_->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    std::string key = BUNDLE_NAME + Constants::FILE_UNDERLINE + std::to_string(ALL_USERID);
    impl->dataMgr_->bundleInfos_.at(BUNDLE_NAME).innerBundleUserInfos_.emplace(key, userInfo);

    std::vector<std::string> appIds;
    impl->UpdateAppControlledInfo(ALL_USERID, appIds);
    impl->dataMgr_->bundleInfos_.at(BUNDLE_NAME).GetInnerBundleUserInfo(ALL_USERID, userInfo);
    EXPECT_TRUE(userInfo.isRemovable);

    appIds = {"appId1", "appId2"};
    ErrCode res = appControlManagerDb_->AddAppInstallControlRule(
        AppControlConstants::EDM_CALLING, appIds, AppControlConstants::APP_DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_OK);
    innerBundleInfo.SetAppIdentifier("appId3");
    innerBundleInfo.baseBundleInfo_->appId = "appId3";
    impl->dataMgr_->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    impl->UpdateAppControlledInfo(ALL_USERID, appIds);
    impl->dataMgr_->bundleInfos_.at(BUNDLE_NAME).GetInnerBundleUserInfo(ALL_USERID, userInfo);
    EXPECT_TRUE(userInfo.isRemovable);

    res = appControlManagerDb_->DeleteAppInstallControlRule(
        AppControlConstants::EDM_CALLING, AppControlConstants::APP_DISALLOWED_UNINSTALL, appIds, ALL_USERID);
    EXPECT_EQ(res, ERR_OK);
    impl->dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: GetAppRunningControlRule_0400
 * @tc.name: Test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppRunningControlRule_0400, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->appId = APPID;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, rule);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    appControlManager->appRunningControlRuleResult_.clear();

    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRule.allowRunning = true;
    controlRules.emplace_back(controlRule);
    ret = appControlManagerDb_->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(ret, ERR_OK);
    ret = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, rule);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    EXPECT_EQ(rule.controlMessage, INVALID_MESSAGE);
    appControlManager->appRunningControlRuleResult_.clear();
    ret = appControlManagerDb_->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetAppRunningControlRule_0500
 * @tc.name: Test GetAppRunningControlRule by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRule test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppRunningControlRule_0500, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->appId = APPID;
    innerBundleInfo.SetAppIdentifier("appIdentifier_test");
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    AppRunningControlRuleResult rule;

    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = "appId";
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRule.allowRunning = true;
    controlRules.emplace_back(controlRule);
    auto ret = appControlManagerDb_->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(ret, ERR_OK);
    ret = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, rule);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    appControlManager->appRunningControlRuleResult_.clear();

    controlRule.appId = APPID;
    controlRule.controlMessage = "message";
    controlRules.emplace_back(controlRule);
    ret = appControlManagerDb_->AddAppRunningControlRule(AppControlConstants::EDM_CALLING, controlRules, USERID);
    EXPECT_EQ(ret, ERR_OK);
    ret = appControlManager->GetAppRunningControlRule(BUNDLE_NAME, USERID, rule);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    EXPECT_EQ(rule.controlMessage, INVALID_MESSAGE);
    appControlManager->appRunningControlRuleResult_.clear();
    ret = appControlManagerDb_->DeleteAppRunningControlRule(AppControlConstants::EDM_CALLING, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetRunningRuleSettingStatusByUserId_0300
 * @tc.name: Test GetRunningRuleSettingStatusByUserId by AppControlManager
 * @tc.desc: 1.GetRunningRuleSettingStatusByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, GetRunningRuleSettingStatusByUserId_0300, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    appControlManager->runningRuleSettingStatusMap_.clear();
    auto res = appControlManager->GetRunningRuleSettingStatusByUserId(0);
    EXPECT_EQ(res, AppExecFwk::AppControlManager::RunningRuleSettingStatus::NO_SET);
}

/**
 * @tc.number: GetRunningRuleSettingStatusByUserId_0400
 * @tc.name: Test GetRunningRuleSettingStatusByUserId by AppControlManager
 * @tc.desc: 1.GetRunningRuleSettingStatusByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, GetRunningRuleSettingStatusByUserId_0400, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    auto res = appControlManager->GetRunningRuleSettingStatusByUserId(USERID2);
    EXPECT_EQ(res, AppExecFwk::AppControlManager::RunningRuleSettingStatus::NO_SET);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: CheckAppControlRuleIntercept_0800
 * @tc.name: Test CheckAppControlRuleIntercept by AppControlManager
 * @tc.desc: 1.CheckAppControlRuleIntercept test
 */
HWTEST_F(BmsBundleAppControlTest, CheckAppControlRuleIntercept_0800, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    ruleParam.isEdm = true;
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::WHITE_LIST);
    auto ret = appControlManager->CheckAppControlRuleIntercept("", USERID, false, ruleParam);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SetRunningRuleSettingStatusByUserId_0100
 * @tc.name: Test SetRunningRuleSettingStatusByUserId by AppControlManager
 * @tc.desc: 1.SetRunningRuleSettingStatusByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, SetRunningRuleSettingStatusByUserId_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    appControlManager->runningRuleSettingStatusMap_.clear();
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    auto ret = appControlManager->GetRunningRuleSettingStatusByUserId(USERID);
    EXPECT_EQ(ret, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: SetRunningRuleSettingStatusByUserId_0200
 * @tc.name: Test SetRunningRuleSettingStatusByUserId by AppControlManager
 * @tc.desc: 1.SetRunningRuleSettingStatusByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, SetRunningRuleSettingStatusByUserId_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    appControlManager->runningRuleSettingStatusMap_.emplace(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::NO_SET);
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    auto ret = appControlManager->GetRunningRuleSettingStatusByUserId(USERID);
    EXPECT_EQ(ret, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: SetRunningRuleSettingStatusByUserId_0300
 * @tc.name: Test SetRunningRuleSettingStatusByUserId by AppControlManager
 * @tc.desc: 1.SetRunningRuleSettingStatusByUserId test
 */
HWTEST_F(BmsBundleAppControlTest, SetRunningRuleSettingStatusByUserId_0300, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    appControlManager->runningRuleSettingStatusMap_.emplace(
        USERID, AppExecFwk::AppControlManager::RunningRuleSettingStatus::NO_SET);
    appControlManager->SetRunningRuleSettingStatusByUserId(
        USERID2, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    auto ret = appControlManager->GetRunningRuleSettingStatusByUserId(USERID2);
    EXPECT_EQ(ret, AppExecFwk::AppControlManager::RunningRuleSettingStatus::BLACK_LIST);
    appControlManager->runningRuleSettingStatusMap_.clear();
}

/**
 * @tc.number: GetAppRunningControlRuleCache_0100
 * @tc.name: Test GetAppRunningControlRuleCache by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRuleCache test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppRunningControlRuleCache_0100, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    appControlManager->appRunningControlRuleResult_.clear();
    AppRunningControlRuleResult rule;
    std::string key = APPID + std::string("_") + std::to_string(USERID);
    auto ret = appControlManager->GetAppRunningControlRuleCache(key, rule);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetAppRunningControlRuleCache_0200
 * @tc.name: Test GetAppRunningControlRuleCache by AppControlManager
 * @tc.desc: 1.GetAppRunningControlRuleCache test
 */
HWTEST_F(BmsBundleAppControlTest, GetAppRunningControlRuleCache_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    std::string key = "";
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRuleCache(key, rule);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteAppRunningControlRuleCache_0200
 * @tc.name: Test DeleteAppRunningControlRuleCache by AppControlManager
 * @tc.desc: 1.DeleteAppRunningControlRuleCache test
 */
HWTEST_F(BmsBundleAppControlTest, DeleteAppRunningControlRuleCache_0200, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    AppRunningControlRuleResult ruleParam;
    ruleParam.controlMessage = CONTROL_MESSAGE;
    std::string key = APPID + std::string("_") + std::to_string(USERID);
    appControlManager->SetAppRunningControlRuleCache(key, ruleParam);
    appControlManager->DeleteAppRunningControlRuleCache("");
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRuleCache(key, rule);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DeleteAppRunningControlRuleCache_0300
 * @tc.name: Test DeleteAppRunningControlRuleCache by AppControlManager
 * @tc.desc: 1.DeleteAppRunningControlRuleCache test
 */
HWTEST_F(BmsBundleAppControlTest, DeleteAppRunningControlRuleCache_0300, Function | SmallTest | Level1)
{
    auto appControlManager = DelayedSingleton<AppControlManager>::GetInstance();
    ASSERT_NE(appControlManager, nullptr);
    appControlManager->appRunningControlRuleResult_.clear();
    std::string key = APPID + std::string("_") + std::to_string(USERID);
    appControlManager->DeleteAppRunningControlRuleCache(key);
    AppRunningControlRuleResult rule;
    auto ret = appControlManager->GetAppRunningControlRuleCache(key, rule);
    EXPECT_FALSE(ret);
}
} // OHOS