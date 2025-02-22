/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const int NOT_EXIST_USERID = -5;
const int ALL_USERID = -3;
const int32_t MAIN_APP_INDEX = -1;
const int32_t CLONE_APP_INDEX_MAX = 6;
const int32_t APP_INDEX = 1;
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

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<IAppControlManagerDb> appControlManagerDb_;
};

std::shared_ptr<BundleMgrService> BmsBundleAppControlTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleAppControlTest::installdService_ =
    std::make_shared<InstalldService>();

std::shared_ptr<IAppControlManagerDb> BmsBundleAppControlTest::appControlManagerDb_ =
    std::make_shared<AppControlManagerRdb>();

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
    auto res = appControlProxy->GetAppRunningControlRule(USERID, appIds);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(3057);
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
    seteuid(3057);
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
    impl->callingNameMap_.insert(pair<int32_t, std::string>(0, AppControlConstants::EDM_CALLING));
    ErrCode res = impl->GetAppRunningControlRule(USERID, appIds);
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
    ErrCode res = impl->GetAppRunningControlRule(USERID, appIds);
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
    EXPECT_FALSE(dataMgr->bundleInfos_[BUNDLE_NAME].innerBundleUserInfos_.empty());
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
    ErrCode result = appControlManagerDb_->GetAbilityRunningControlRule(appId, appIndex, userId, disposedRules);
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
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();

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
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();

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
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();

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
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();

    std::string appId;
    int32_t appIndex = 0;
    int32_t userId = 0;
    ErrCode res = appControlProxy->DeleteDisposedRuleForCloneApp(appId, appIndex, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
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
} // OHOS