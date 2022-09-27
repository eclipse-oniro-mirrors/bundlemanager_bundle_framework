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
 * @tc.desc: 1.system run normally
 *           2.AddAppInstallControlRule failed by empty appIds
 *           3.DeleteAppInstallControlRule failed by empty appIds
 *           4.GetAppInstallControlRule failed by empty appIds
 */
HWTEST_F(BmsBundleAppControlTest, AppInstallControlRule_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();

    std::vector<std::string> appIds;
    auto res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::DISALLOWED_UNINSTALL, USERID);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
    auto res1 = appControlProxy->
        DeleteAppInstallControlRule(appIds, USERID);
    EXPECT_EQ(res1, ERR_INVALID_VALUE);
    auto res2 = appControlProxy->
        DeleteAppInstallControlRule(AppInstallControlRuleType::ALLOWED_INSTALL, USERID);
    EXPECT_EQ(res2, ERR_BUNDLE_MANAGER_APP_CONTROL_PERMISSION_DENIED);
    auto res3 = appControlProxy->
        GetAppInstallControlRule(AppInstallControlRuleType::ALLOWED_INSTALL, USERID, appIds);
    EXPECT_EQ(res3, ERR_BUNDLE_MANAGER_APP_CONTROL_PERMISSION_DENIED);
}

/**
 * @tc.number: AppInstallControlRule_0200
 * @tc.name: test can not add app install control rule
 * @tc.desc: 1.system run normally
 *           2.AddAppInstallControlRule failed by wrong userId
 */
HWTEST_F(BmsBundleAppControlTest, AppInstallControlRule_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    std::vector<std::string> appIds;
    appIds.push_back(APPID);
    auto res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::ALLOWED_INSTALL, 1001);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_APP_CONTROL_PERMISSION_DENIED);
}

/**
 * @tc.number: AppInstallControlRule_0300
 * @tc.name: test can  add app install control rule
 * @tc.desc: 1.system run normally
 *           2.AddAppInstallControlRule success
 *           3.DeleteAppInstallControlRule success
 *           4.GetAppInstallControlRule success
 */
HWTEST_F(BmsBundleAppControlTest, AppInstallControlRule_0300, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    std::vector<std::string> appIds;
    seteuid(537);
    appIds.push_back(APPID);
    auto res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::ALLOWED_INSTALL, USERID);
    auto res1 = appControlProxy->
        GetAppInstallControlRule(AppInstallControlRuleType::ALLOWED_INSTALL, USERID, appIds);
    auto res2 = appControlProxy->
        DeleteAppInstallControlRule(appIds, USERID);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(res1, ERR_OK);
    EXPECT_EQ(res2, ERR_OK);
}

/**
 * @tc.number: AppInstallControlRule_0400
 * @tc.name: test can not add app install control rule
 * @tc.desc: 1.system run normally
 *           2.AddAppInstallControlRule failed by empty appIds
 */
HWTEST_F(BmsBundleAppControlTest, AppInstallControlRule_0400, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    std::vector<std::string> appIds;
    auto res = appControlProxy->
        AddAppInstallControlRule(appIds, AppInstallControlRuleType::ALLOWED_INSTALL, USERID);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
    auto res1 = appControlProxy->
        DeleteAppInstallControlRule(appIds, USERID);
    EXPECT_EQ(res1, ERR_INVALID_VALUE);
}

/**
 * @tc.number: AddAppRunningControlRule_0100
 * @tc.name: test can not add app install control rule
 * @tc.desc: 1.system run normally
 *           2.AddAppRunningControlRule failed by empty controlRules
 */
HWTEST_F(BmsBundleAppControlTest, AddAppRunningControlRule_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    const std::vector<AppRunningControlRule> controlRules;
    seteuid(537);

    ErrCode res = appControlProxy->
        AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
    ErrCode res1 = appControlProxy->
        DeleteAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res1, ERR_INVALID_VALUE);
}

} // OHOS