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
#include <future>
#include <gtest/gtest.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_installer_interface.h"
#include "bundle_mgr_interface.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "status_receiver_host.h"

using namespace testing::ext;
using namespace std::chrono_literals;
namespace {
const std::string BUNDLE_PATH_1 = "/data/test/bms_bundle/permissionGrantBundle1.hap";
const std::string BUNDLE_PATH_2 = "/data/test/bms_bundle/permissionGrantBundle2.hap";
const std::string BUNDLE_PATH_3 = "/data/test/bms_bundle/permissionGrantBundle3.hap";
const std::string BUNDLE_PATH_4 = "/data/test/bms_bundle/permissionGrantBundle4.hap";
const std::string BUNDLE_PATH_5 = "/data/test/bms_bundle/permissionGrantBundle5.hap";
const std::string BUNDLE_NAME = "com.example.permissiongrant";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILURE = "Failure";
const std::string OPERATION_SUCCESS = "Success";
const int TIMEOUT = 10;
const int32_t USERID = 100;
}  // namespace

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::EventFwk;
class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    ~StatusReceiverImpl() override;
    void OnStatusNotify(const int progress) override;
    void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    std::string GetResultMsg() const;

private:
    mutable std::promise<std::string> resultMsgSignal_;
    int iProgress_ = 0;

    DISALLOW_COPY_AND_MOVE(StatusReceiverImpl);
};

StatusReceiverImpl::StatusReceiverImpl()
{
    APP_LOGI("create status receiver instance");
}

StatusReceiverImpl::~StatusReceiverImpl()
{
    APP_LOGI("destroy status receiver instance");
}

void StatusReceiverImpl::OnStatusNotify(const int progress)
{
    EXPECT_GT(progress, iProgress_);
    iProgress_ = progress;
    APP_LOGI("OnStatusNotify progress:%{public}d", progress);
}

void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    APP_LOGD("on finished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
    resultMsgSignal_.set_value(resultMsg);
}

std::string StatusReceiverImpl::GetResultMsg() const
{
    auto future = resultMsgSignal_.get_future();
    std::chrono::seconds timeout(TIMEOUT);
    if (future.wait_for(timeout) == std::future_status::timeout) {
        return OPERATION_FAILURE + " timeout";
    }
    std::string resultMsg = future.get();
    if (resultMsg == MSG_SUCCESS) {
        return OPERATION_SUCCESS;
    }
    return OPERATION_FAILURE;
}

class SubscriberTest : public CommonEventSubscriber {
public:
    explicit SubscriberTest(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp){};
    virtual ~SubscriberTest() = default;
    void OnReceiveEvent(const CommonEventData &data) override;
    std::string GetSubscriberResultMsg() const;

private:
    mutable std::promise<std::string> subscriberMsgSignal_;

    DISALLOW_COPY_AND_MOVE(SubscriberTest);
};

void SubscriberTest::OnReceiveEvent(const CommonEventData &data)
{
    Want want = data.GetWant();
    subscriberMsgSignal_.set_value(want.GetAction());
    APP_LOGI("OnReceiveEvent:action = %{public}s", want.GetAction().c_str());
}

std::string SubscriberTest::GetSubscriberResultMsg() const
{
    auto future = subscriberMsgSignal_.get_future();
    future.wait();
    std::string resultMsg = future.get();
    return resultMsg;
}

class BmsPermissionGrantSystemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static int32_t ExcuteMaintainCmd(const std::string &cmd, std::vector<std::string> &cmdRes);
    static void InstallBundle(const std::string &bundleFilePath, std::string &installMsg);
    static void UninstallBundle(const std::string &bundleName, std::string &uninstallMsg);
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
};

sptr<IBundleMgr> BmsPermissionGrantSystemTest::GetBundleMgrProxy()
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
    return iface_cast<IBundleMgr>(remoteObject);
}

sptr<IBundleInstaller> BmsPermissionGrantSystemTest::GetInstallerProxy()
{
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        return nullptr;
    }

    sptr<IBundleInstaller> installerProxy = bundleMgrProxy->GetBundleInstaller();
    if (!installerProxy) {
        APP_LOGE("fail to get bundle installer proxy");
        return nullptr;
    }

    APP_LOGI("get bundle installer proxy success.");
    return installerProxy;
}

void BmsPermissionGrantSystemTest::InstallBundle(
    const std::string &bundleFilePath, std::string &installMsg)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        installMsg = "Failure";
        return;
    }

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    bool installResult = installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    EXPECT_TRUE(installResult);
    installMsg = statusReceiver->GetResultMsg();
}

void BmsPermissionGrantSystemTest::UninstallBundle(
    const std::string &bundleName, std::string &uninstallMsg)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        uninstallMsg = "Failure";
        return;
    }

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;

    bool uninstallResult = installerProxy->Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    uninstallMsg = statusReceiver->GetResultMsg();
}

void BmsPermissionGrantSystemTest::SetUpTestCase()
{}

void BmsPermissionGrantSystemTest::TearDownTestCase()
{}

void BmsPermissionGrantSystemTest::SetUp()
{}

void BmsPermissionGrantSystemTest::TearDown()
{}

/**
 * @tc.number: BmsPermissionGrant_0001
 * @tc.name: test the installation of a bundle with normal apl and normal permission
 * @tc.desc: 1. install a bundle with normal apl and normal permission
 *           2. install succeed.
 */
HWTEST_F(BmsPermissionGrantSystemTest, BmsPermissionGrant_0001, Function | MediumTest | Level1)
{
    std::cout << "START BmsPermissionGrant_0001" << std::endl;
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy) {
        BundleInfo bundleInfo;
        bool ret =
            bundleMgrProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
                bundleInfo, USERID);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(bundleInfo.reqPermissions.empty());
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
    std::cout << "END BmsPermissionGrant_0001" << std::endl;
}

/**
 * @tc.number: BmsPermissionGrant_0002
 * @tc.name: test the installation of a bundle with normal apl and normal permission
 * @tc.desc: 1. install a bundle with normal apl and normal permission
 *           2. install succeed.
 *           3. update it with system_basic apl and system_basic permission
 */
HWTEST_F(BmsPermissionGrantSystemTest, BmsPermissionGrant_0002, Function | MediumTest | Level1)
{
    std::cout << "START BmsPermissionGrant_0002" << std::endl;
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;

    InstallBundle(BUNDLE_PATH_2, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_2;

    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy) {
        BundleInfo bundleInfo;
        bool ret =
            bundleMgrProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
                bundleInfo, USERID);
        EXPECT_TRUE(ret);
        EXPECT_EQ(bundleInfo.reqPermissions.size(), 1);
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
    std::cout << "END BmsPermissionGrant_0002" << std::endl;
}

/**
 * @tc.number: BmsPermissionGrant_0003
 * @tc.name: test the installation of a hap with system_basic apl and system_basic permission
 * @tc.desc: 1. install a bundle with system_basic apl and system_basic permission
 *           2. install succeed.
 *           3. add feature hap
 */
HWTEST_F(BmsPermissionGrantSystemTest, BmsPermissionGrant_0003, Function | MediumTest | Level1)
{
    std::cout << "START BmsPermissionGrant_0003" << std::endl;
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_2, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_2;

    InstallBundle(BUNDLE_PATH_3, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_3;

    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy) {
        BundleInfo bundleInfo;
        bool ret =
            bundleMgrProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
                bundleInfo, USERID);
        EXPECT_TRUE(ret);
        EXPECT_EQ(bundleInfo.reqPermissions.size(), 2);
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
    std::cout << "END BmsPermissionGrant_0003" << std::endl;
}

/**
 * @tc.number: BmsPermissionGrant_0004
 * @tc.name: test the installation of a bundle with normal apl and normal permission
 * @tc.desc: 1. install a bundle with normal apl and normal permission
 *           2. install succeed.
 *           3. update it with normal apl and system_core permission
 */
HWTEST_F(BmsPermissionGrantSystemTest, BmsPermissionGrant_0004, Function | MediumTest | Level1)
{
    std::cout << "START BmsPermissionGrant_0004" << std::endl;
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy) {
        BundleInfo bundleInfo;
        bool ret =
            bundleMgrProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
                bundleInfo, USERID);
        EXPECT_TRUE(ret);
        EXPECT_EQ(bundleInfo.reqPermissions.size(), 1);
    }

    InstallBundle(BUNDLE_PATH_4, installMsg);
    EXPECT_EQ(installMsg, "Failure") << "install fail!" << BUNDLE_PATH_4;

    if (bundleMgrProxy) {
        BundleInfo bundleInfo;
        bool ret =
            bundleMgrProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
                bundleInfo, USERID);
        EXPECT_TRUE(ret);
        EXPECT_EQ(bundleInfo.reqPermissions.size(), 1);
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
    std::cout << "END BmsPermissionGrant_0004" << std::endl;
}

/**
 * @tc.number: BmsPermissionGrant_0005
 * @tc.name: test the installation of a bundle with normal apl and system_core permission
 * @tc.desc: 1. install a bundle with normal apl and system_core permission
 *           2. install failed.
 */
HWTEST_F(BmsPermissionGrantSystemTest, BmsPermissionGrant_0005, Function | MediumTest | Level1)
{
    std::cout << "START BmsPermissionGrant_0005" << std::endl;
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_4, installMsg);
    EXPECT_EQ(installMsg, "Failure") << "install fail!" << BUNDLE_PATH_4;
}

/**
 * @tc.number: BmsPermissionGrant_0006
 * @tc.name: test the installation of a bundle with system_basic apl and system_basic permission
 * @tc.desc: 1. install a bundle with system_basic apl and system_basic permission
 *           2. update with normal apl and system_core permission
 */
HWTEST_F(BmsPermissionGrantSystemTest, BmsPermissionGrant_0006, Function | MediumTest | Level1)
{
    std::cout << "START BmsPermissionGrant_0006" << std::endl;
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_2, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_2;

    InstallBundle(BUNDLE_PATH_4, installMsg);
    EXPECT_EQ(installMsg, "Failure") << "install fail!" << BUNDLE_PATH_2;

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
    std::cout << "END BmsPermissionGrant_0006" << std::endl;
}

/**
 * @tc.number: BmsPermissionGrant_0007
 * @tc.name: test the installation of a bundle with normal apl and normal permission, normal app
 * @tc.desc: 1. install normal app
 *           2. install succeed
 *           3. update system app, high version code
 */
HWTEST_F(BmsPermissionGrantSystemTest, BmsPermissionGrant_0007, Function | MediumTest | Level1)
{
    std::cout << "START BmsPermissionGrant_0007" << std::endl;
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_2;
    
    ApplicationInfo applicationInfo;
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy) {
        bool ret =
            bundleMgrProxy->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO,
                USERID, applicationInfo);
        EXPECT_TRUE(ret);
    }

    InstallBundle(BUNDLE_PATH_5, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_5;

    ApplicationInfo applicationInfo2;
    if (bundleMgrProxy) {
        bool ret = bundleMgrProxy->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO,
            USERID, applicationInfo2);
        EXPECT_TRUE(ret);
    }
    EXPECT_EQ(applicationInfo.accessTokenId, applicationInfo2.accessTokenId);
    EXPECT_NE(applicationInfo.accessTokenIdEx, applicationInfo2.accessTokenIdEx);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
    std::cout << "END BmsPermissionGrant_0007" << std::endl;
}

/**
 * @tc.number: BmsPermissionGrant_0008
 * @tc.name: test the installation of a system app
 * @tc.desc: 1. install system app
 *           2. install succeed
 *           3. update normal app, same version code
 */
HWTEST_F(BmsPermissionGrantSystemTest, BmsPermissionGrant_0008, Function | MediumTest | Level1)
{
    std::cout << "START BmsPermissionGrant_0008" << std::endl;
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_5, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_5;
    
    ApplicationInfo applicationInfo;
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy) {
        bool ret =
            bundleMgrProxy->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO,
                USERID, applicationInfo);
        EXPECT_TRUE(ret);
    }

    InstallBundle(BUNDLE_PATH_2, installMsg);
    EXPECT_EQ(installMsg, "Failure") << "install fail!" << BUNDLE_PATH_2;

    ApplicationInfo applicationInfo2;
    if (bundleMgrProxy) {
        bool ret = bundleMgrProxy->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO,
            USERID, applicationInfo2);
        EXPECT_TRUE(ret);
    }
    EXPECT_EQ(applicationInfo.accessTokenId, applicationInfo2.accessTokenId);
    EXPECT_EQ(applicationInfo.accessTokenIdEx, applicationInfo2.accessTokenIdEx);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
    std::cout << "END BmsPermissionGrant_0008" << std::endl;
}
}  // namespace AppExecFwk
}  // namespace OHOS