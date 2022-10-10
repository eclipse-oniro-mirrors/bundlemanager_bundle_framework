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
const std::string BUNDLE_NAME = "com.third.hiworld.example1";
const std::string ABILITY_NAME = "bmsThirdBundle_A1";
const std::string MODULE_NAME = "testability1";
const std::string HAP_FILE_PATH = "/data/test/resource/bms/app_control/bmsThirdBundle1.hap";
const std::string APPID = "com.third.hiworld.example1_BNtg4JBClbl92Rgc3jm/"
    "RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=";
const std::string CONTROL_MESSAGE = "this is control message";
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
    installParam.installFlag = InstallFlag::NORMAL;
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
    res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
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
    auto res1 = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL,
        appIds, USERID);
    EXPECT_EQ(res1, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    appIds.emplace_back(APPID);
    auto res2 = appControlProxy->DeleteAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL,
        appIds, USERID);
    EXPECT_EQ(res2, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(537);
    auto res3 = appControlProxy->GetAppInstallControlRule(AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID, appIds);
    EXPECT_EQ(res3, ERR_OK);
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
}
} // OHOS