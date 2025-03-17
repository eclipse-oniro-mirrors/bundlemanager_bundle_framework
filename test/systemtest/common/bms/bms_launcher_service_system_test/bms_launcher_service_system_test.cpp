/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <condition_variable>
#include <future>
#include <gtest/gtest.h>
#include <iostream>
#include <string>

#include "accesstoken_kit.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_installer_interface.h"
#include "bundle_mgr_interface.h"
#include "common_tool.h"
#include "iservice_registry.h"
#include "launcher_ability_info.h"
#include "launcher_service.h"
#include "nativetoken_kit.h"
#include "operation_builder.h"
#include "status_receiver_host.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

namespace {
const std::string THIRD_BUNDLE_PATH = "/data/test/bms_bundle/";
const std::string TEST_BUNDLE_NAME = "com.example.third1";
const std::string TEST_ABILITY_NAME = "com.example.third1.MainAbility";
const std::string THIRD_BASE_BUNDLE_NAME = "com.example.third";
const std::string SYSTEM_BASE_BUNDLE_NAME = "com.example.system";
const std::string CAMERA = "ohos.permission.CAMERA";
const std::string RESOURCE_ROOT_PATH = "/data/test/";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILED = "Failure";
const std::string OPERATION_SUCCESS = "Success";
const std::string BUNDLE_ADD = "Bundle Add Success";
const std::string BUNDLE_UPDATE = "Bundle Update Success";
const std::string BUNDLE_REMOVE = "Bundle Remove Success";
constexpr uint32_t WAIT_SECONDS = 10;
constexpr uint32_t USERID = 100;
const unsigned int LIST_SIZE = 1;
static const int APP_LABELID = 16777216;
static const int APP_ICONID = 16777218;
const int32_t PERMS_INDEX_ZERO = 0;
const int32_t PERMS_INDEX_ONE = 1;
const int32_t PERMS_INDEX_TWO = 2;
const int32_t PERMS_INDEX_THREE = 3;
const int32_t PERMS_INDEX_FORE = 4;
const int32_t PERMS_INDEX_FIVE = 5;
const int32_t PERMS_INDEX_SIX = 6;
const int32_t PERMS_INDEX_SEVEN = 7;
const int32_t PERMS_INDEX_EIGHT = 8;
const int32_t PERMS_INDEX_NINE = 9;
}  // namespace
using OHOS::AAFwk::Want;
using namespace testing::ext;
using namespace std::chrono_literals;
namespace OHOS {
namespace AppExecFwk {
class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    virtual ~StatusReceiverImpl();
    virtual void OnStatusNotify(const int progress) override;
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    std::string GetResultMsg() const;

private:
    mutable std::promise<std::string> resultMsgSignal_;

    DISALLOW_COPY_AND_MOVE(StatusReceiverImpl);
};
class BmsLauncherServiceSystemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void StartProcess();
    static void Install(const std::string &bundleFilePath, const InstallFlag installFlag, std::string &installMessage);
    static void Uninstall(const std::string &bundleName, std::string &uninstallMessage);
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
    static void CheckApplicationInfo(const std::string &bundleName, ApplicationInfo &applicationInfo);
    static void CheckAbilityList(
        const std::vector<LauncherAbilityInfo> &launcherAbilityInfos, std::string &abilityName);
    static void CheckAbilityInfo(LauncherAbilityInfo &launcherAbilityInfos, const std::string &abilityName);
    static void CheckShortcutInfos(
        const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfo);
    static void Complete(const std::string message);
    static bool Wait(const std::string message);
    static void Clean()
    {
        message_ = "";
        completeMessage_.clear();
    }

private:
    static std::mutex mutex_;
    static std::condition_variable cv_;
    static std::string message_;
    static std::vector<std::string> completeMessage_;
};
std::string BmsLauncherServiceSystemTest::message_ = "";
std::vector<std::string> BmsLauncherServiceSystemTest::completeMessage_ {};
std::condition_variable BmsLauncherServiceSystemTest::cv_ = std::condition_variable();
std::mutex BmsLauncherServiceSystemTest::mutex_ = std::mutex();
void BmsLauncherServiceSystemTest::Complete(const std::string message)
{
    std::this_thread::sleep_for(500ms);
    std::unique_lock<std::mutex> lock(mutex_);
    if (message_.compare(message) == 0) {
        GTEST_LOG_(INFO) << "Complete.";
        cv_.notify_all();
        message_ = "";
        return;
    }
    GTEST_LOG_(INFO) << "Can't Complete." << message_;
    completeMessage_.emplace_back(message);
    return;
}

bool BmsLauncherServiceSystemTest::Wait(const std::string message)
{
    GTEST_LOG_(INFO) << "Wait start.";
    std::unique_lock<std::mutex> lock(mutex_);
    message_ = message;
    if (!message_.empty()) {
        for (size_t i = 0; i < completeMessage_.size(); i++) {
            if (message_.compare(completeMessage_.at(i)) == 0) {
                message_ = "";
                return true;
            }
        }
    }
    if (cv_.wait_for(lock, std::chrono::seconds(WAIT_SECONDS)) == std::cv_status::timeout) {
        GTEST_LOG_(INFO) << "Time out.";
        message_ = "";
        return false;
    }
    GTEST_LOG_(INFO) << "Wait done.";
    return true;
}

sptr<IBundleMgr> BmsLauncherServiceSystemTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BmsLauncherServiceSystemTest::GetInstallerProxy()
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

void BmsLauncherServiceSystemTest::Install(
    const std::string &bundleFilePath, const InstallFlag installFlag, std::string &installMessage)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        installMessage = OPERATION_FAILED;
        return;
    }
    InstallParam installParam;
    installParam.installFlag = installFlag;
    installParam.userId = USERID;
    sptr<StatusReceiverImpl> statusReceiver = new (std::nothrow) StatusReceiverImpl();
    EXPECT_NE(statusReceiver, nullptr);
    installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    installMessage = statusReceiver->GetResultMsg();
}

void BmsLauncherServiceSystemTest::Uninstall(const std::string &bundleName, std::string &uninstallMessage)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        uninstallMessage = OPERATION_FAILED;
        return;
    }

    if (bundleName.empty()) {
        APP_LOGE("bundelname is null.");
        uninstallMessage = OPERATION_FAILED;
    } else {
        InstallParam installParam;
        installParam.userId = USERID;
        sptr<StatusReceiverImpl> statusReceiver = new (std::nothrow) StatusReceiverImpl();
        EXPECT_NE(statusReceiver, nullptr);
        installerProxy->Uninstall(bundleName, installParam, statusReceiver);
        uninstallMessage = statusReceiver->GetResultMsg();
    }
}
void BmsLauncherServiceSystemTest::CheckAbilityList(
    const std::vector<LauncherAbilityInfo> &launcherAbilityInfos, std::string &abilityName)
{
    for (auto launcherAbilityInfo : launcherAbilityInfos) {
        EXPECT_EQ(launcherAbilityInfo.elementName.GetAbilityName(), abilityName);
        EXPECT_EQ(launcherAbilityInfo.labelId, APP_LABELID);
        EXPECT_GE(launcherAbilityInfo.userId, 0);
        EXPECT_GT(launcherAbilityInfo.installTime, 0);
    }
}

void BmsLauncherServiceSystemTest::CheckAbilityInfo(
    LauncherAbilityInfo &launcherAbilityInfos, const std::string &abilityName)
{
    EXPECT_EQ(launcherAbilityInfos.elementName.GetAbilityName(), abilityName);
    EXPECT_EQ(launcherAbilityInfos.labelId, APP_LABELID);
    EXPECT_GE(launcherAbilityInfos.userId, 0);
    EXPECT_GT(launcherAbilityInfos.installTime, 0);
}

void BmsLauncherServiceSystemTest::CheckApplicationInfo(const std::string &bundleName, ApplicationInfo &applicationInfo)
{
    CommonTool commonTool;
    EXPECT_EQ(applicationInfo.bundleName, bundleName);
    EXPECT_EQ(applicationInfo.iconPath, "$media:icon");
    EXPECT_EQ(applicationInfo.label, "$string:app_name");
    EXPECT_EQ(applicationInfo.labelId, APP_LABELID);
    EXPECT_EQ(applicationInfo.iconId, APP_ICONID);
    EXPECT_EQ(applicationInfo.deviceId, "PHONE-001");
    EXPECT_EQ(applicationInfo.signatureKey, "");
    EXPECT_GE(applicationInfo.isSystemApp, 0);
    EXPECT_GE(applicationInfo.isLauncherApp, 0);
    EXPECT_GE(applicationInfo.supportedModes, 0);
    EXPECT_EQ(commonTool.VectorToStr(applicationInfo.permissions), "");
    EXPECT_EQ(commonTool.VectorToStr(applicationInfo.moduleSourceDirs), "");
    EXPECT_EQ(applicationInfo.entryDir, "");
    EXPECT_EQ(applicationInfo.codePath, "/data/app/el1/bundle/public/com.example.third1");
    EXPECT_GE(applicationInfo.flags, 0);
    EXPECT_GT(applicationInfo.enabled, 0);
}

void BmsLauncherServiceSystemTest::CheckShortcutInfos(
    const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfo)
{
    for (auto shortcutinfo : shortcutInfo) {
        EXPECT_EQ(shortcutinfo.bundleName, bundleName);
        EXPECT_EQ(shortcutinfo.icon, "$media:icon");
        EXPECT_EQ(shortcutinfo.id, "id.third1");
        EXPECT_EQ(shortcutinfo.label, "$string:app_name");
        for (auto want : shortcutinfo.intents) {
            EXPECT_EQ(want.targetBundle, TEST_BUNDLE_NAME);
            EXPECT_EQ(want.targetClass, "com.example.third1.MainAbility");
        }
    }
}
void BmsLauncherServiceSystemTest::SetUpTestCase()
{}
void BmsLauncherServiceSystemTest::TearDownTestCase()
{}
void BmsLauncherServiceSystemTest::SetUp()
{
    StartProcess();
}
void BmsLauncherServiceSystemTest::TearDown()
{}

void BmsLauncherServiceSystemTest::StartProcess()
{
    const int32_t permsNum = 10;
    uint64_t tokenId;
    const char *perms[permsNum];
    perms[PERMS_INDEX_ZERO] = "ohos.permission.GET_DEFAULT_APPLICATION";
    perms[PERMS_INDEX_ONE] = "ohos.permission.INSTALL_BUNDLE";
    perms[PERMS_INDEX_TWO] = "ohos.permission.SET_DEFAULT_APPLICATION";
    perms[PERMS_INDEX_THREE] = "ohos.permission.GET_INSTALLED_BUNDLE_LIST";
    perms[PERMS_INDEX_FORE] = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
    perms[PERMS_INDEX_FIVE] = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
    perms[PERMS_INDEX_SIX] = "ohos.permission.CHANGE_BUNDLE_UNINSTALL_STATE";
    perms[PERMS_INDEX_SEVEN] = "ohos.permission.INSTALL_CLONE_BUNDLE";
    perms[PERMS_INDEX_EIGHT] = "ohos.permission.UNINSTALL_CLONE_BUNDLE";
    perms[PERMS_INDEX_NINE] = "ohos.permission.LISTEN_BUNDLE_CHANGE";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsNum,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "kit_system_test",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

class TestBundleStatusCallback : public IBundleStatusCallback {
public:
    TestBundleStatusCallback() = default;
    explicit TestBundleStatusCallback(std::string code) : testCode_(code)
    {}
    ~TestBundleStatusCallback() = default;
    virtual void OnBundleStateChanged(const uint8_t installType, const int32_t resultCode, const std::string &resultMsg,
        const std::string &bundleName) override;
    virtual void OnBundleAdded(const std::string &bundleName, const int userId) override;
    virtual void OnBundleUpdated(const std::string &bundleName, const int userId) override;
    virtual void OnBundleRemoved(const std::string &bundleName, const int userId) override;
    virtual sptr<IRemoteObject> AsObject() override;

private:
    std::string testCode_ {};
};

void TestBundleStatusCallback::OnBundleStateChanged(
    const uint8_t installType, const int32_t resultCode, const std::string &resultMsg, const std::string &bundleName)
{
    GTEST_LOG_(INFO) << "OnBundleStateChanged " << resultMsg << " bundle name is " << bundleName;
}
void TestBundleStatusCallback::OnBundleAdded(const std::string &bundleName, const int userId)
{
    GTEST_LOG_(INFO) << "OnBundleAdded bundle name " << bundleName << "is exist";
    GTEST_LOG_(INFO) << "bundle name is " << bundleName << "is exist";
    BmsLauncherServiceSystemTest::Complete(BUNDLE_ADD + testCode_);
}

void TestBundleStatusCallback::OnBundleUpdated(const std::string &bundleName, const int userId)
{
    GTEST_LOG_(INFO) << "OnBundleUpdated bundle name " << bundleName << "is exist";
    GTEST_LOG_(INFO) << "bundle name is " << bundleName << "is exist";
    BmsLauncherServiceSystemTest::Complete(BUNDLE_UPDATE + testCode_);
}

void TestBundleStatusCallback::OnBundleRemoved(const std::string &bundleName, const int userId)
{
    GTEST_LOG_(INFO) << "OnBundleRemoved bundle name " << bundleName << "is exist";
    GTEST_LOG_(INFO) << "bundle name is " << bundleName << "is exist";
    BmsLauncherServiceSystemTest::Complete(BUNDLE_REMOVE + testCode_);
}

sptr<IRemoteObject> TestBundleStatusCallback::AsObject()
{
    return nullptr;
}

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
    APP_LOGI("OnStatusNotify");
}
void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    APP_LOGD("on finished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
    resultMsgSignal_.set_value(resultMsg);
}

std::string StatusReceiverImpl::GetResultMsg() const
{
    auto future = resultMsgSignal_.get_future();
    future.wait();
    std::string resultMsg = future.get();
    if (resultMsg == MSG_SUCCESS) {
        return OPERATION_SUCCESS;
    } else {
        return OPERATION_FAILED + resultMsg;
    }
}
/**
 * @tc.number: BMS_Register_0100
 * @tc.name: test launcher service RegisterCallback
 * @tc.desc: register callback and listen for add events
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_Register_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_Register_0100";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string message;
    LauncherService launcherservice;
    sptr<TestBundleStatusCallback> callback = new (std::nothrow) TestBundleStatusCallback();
    EXPECT_TRUE(launcherservice.RegisterCallback(callback));
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    EXPECT_TRUE(launcherservice.UnRegisterCallback());
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    Clean();
    GTEST_LOG_(INFO) << "END BMS_Register_0100";
}
/**
 * @tc.number: BMS_Register_0200
 * @tc.name: test launcher service RegisterCallback
 * @tc.desc: register callback and listen for remove events
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_Register_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_Register_0200";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string message;
    LauncherService launcherservice;
    sptr<TestBundleStatusCallback> callback = new (std::nothrow) TestBundleStatusCallback();
    EXPECT_TRUE(launcherservice.RegisterCallback(callback));
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    EXPECT_TRUE(launcherservice.UnRegisterCallback());
    Clean();
    GTEST_LOG_(INFO) << "END BMS_Register_0200";
}
/**
 * @tc.number: BMS_Register_0300
 * @tc.name: test launcher service RegisterCallback
 * @tc.desc: register callback and listen for update events
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_Register_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_Register_0300";
    std::string bundleName = THIRD_BASE_BUNDLE_NAME + "1";
    std::string bundleFilePath1 = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleFilePath2 = THIRD_BUNDLE_PATH + "bmsThirdBundle4.hap";
    std::string message;
    LauncherService launcherservice;
    sptr<TestBundleStatusCallback> callback = new (std::nothrow) TestBundleStatusCallback();
    EXPECT_TRUE(launcherservice.RegisterCallback(callback));
    Install(bundleFilePath1, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    Install(bundleFilePath2, InstallFlag::REPLACE_EXISTING, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    EXPECT_TRUE(launcherservice.UnRegisterCallback());
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    Clean();
    GTEST_LOG_(INFO) << "END BMS_Register_0300";
}
/**
 * @tc.number: BMS_Register_0400
 * @tc.name: test launcher service RegisterCallback
 * @tc.desc: unregister callback and listen for events
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_Register_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_Register_0400";
    std::string bundleName = THIRD_BASE_BUNDLE_NAME + "2";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle2.hap";
    std::string message;
    LauncherService launcherservice;
    sptr<TestBundleStatusCallback> callback = new (std::nothrow) TestBundleStatusCallback();
    EXPECT_TRUE(launcherservice.RegisterCallback(callback));
    EXPECT_TRUE(launcherservice.UnRegisterCallback());
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    EXPECT_FALSE(Wait(BUNDLE_ADD));
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    Clean();
    GTEST_LOG_(INFO) << "END BMS_Register_0400";
}

/**
 * @tc.number: BMS_Register_0500
 * @tc.name: test launcher service RegisterCallback
 * @tc.desc: register callback and listen for add events by other TestBundleStatusCallback object
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_Register_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_Register_0500";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string message;
    LauncherService launcherservice;
    sptr<TestBundleStatusCallback> callback = new (std::nothrow) TestBundleStatusCallback();
    std::string code = "callback2";
    sptr<TestBundleStatusCallback> callback2 = new (std::nothrow) TestBundleStatusCallback(code);
    EXPECT_TRUE(launcherservice.RegisterCallback(callback));
    EXPECT_TRUE(launcherservice.RegisterCallback(callback2));
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    EXPECT_TRUE(launcherservice.UnRegisterCallback());
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    Clean();
    GTEST_LOG_(INFO) << "END BMS_Register_0500";
}

/**
 * @tc.number: BMS_Register_0600
 * @tc.name: test launcher service RegisterCallback
 * @tc.desc: repeatly register callback and listen for events by two launcher objects
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_Register_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_Register_0600";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string message;
    LauncherService launcherservice1;
    LauncherService launcherservice2;
    std::string code1 = "callback1";
    std::string code2 = "callback2";
    sptr<TestBundleStatusCallback> callback1 = new (std::nothrow) TestBundleStatusCallback(code1);
    sptr<TestBundleStatusCallback> callback2 = new (std::nothrow) TestBundleStatusCallback(code2);
    EXPECT_TRUE(launcherservice1.RegisterCallback(callback1));
    EXPECT_TRUE(launcherservice2.RegisterCallback(callback2));
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    EXPECT_TRUE(launcherservice1.UnRegisterCallback());
    EXPECT_TRUE(launcherservice2.UnRegisterCallback());
    Clean();
    GTEST_LOG_(INFO) << "END BMS_Register_0600";
}

/**
 * @tc.number: BMS_Register_0700
 * @tc.name: test launcher service RegisterCallback
 * @tc.desc: repeatly unregister callback
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_Register_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_Register_0700";
    LauncherService launcherservice;
    EXPECT_TRUE(launcherservice.UnRegisterCallback());
    EXPECT_TRUE(launcherservice.UnRegisterCallback());
    GTEST_LOG_(INFO) << "END BMS_Register_0700";
}

/**
 * @tc.number: BMS_Register_0800
 * @tc.name: test launcher service RegisterCallback
 * @tc.desc: register null callback
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_Register_0800, Function | MediumTest | Level2)
{
    GTEST_LOG_(INFO) << "START BMS_Register_0800";
    LauncherService launcherservice;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string message;
    EXPECT_TRUE(launcherservice.RegisterCallback(nullptr));
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    EXPECT_FALSE(Wait(BUNDLE_ADD));
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    Clean();
    GTEST_LOG_(INFO) << "END BMS_Register_0800";
}

/**
 * @tc.number: BMS_Register_0900
 * @tc.name: test launcher service RegisterCallback and UnRegisterCallback
 * @tc.desc: bundleMonitor_ is nullptr, test failed
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_Register_0900, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_Register_0500";
    LauncherService launcherservice;
    sptr<TestBundleStatusCallback> callback = new (std::nothrow) TestBundleStatusCallback();
    launcherservice.bundleMonitor_ = nullptr;
    EXPECT_FALSE(launcherservice.RegisterCallback(callback));
    EXPECT_FALSE(launcherservice.UnRegisterCallback());
    GTEST_LOG_(INFO) << "END BMS_Register_0500";
}

/**
 * @tc.number: BMS_GetAbilityList_0100
 * @tc.name: test GetAbilityList by LauncherService
 * @tc.desc: 1.install a normal hap
 *           2.get ability info of the installed hap by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetAbilityList_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_GetAbilityList_0100";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string abilityName = TEST_ABILITY_NAME;
    std::string message;
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";

    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    LauncherService launcherservice;
    bool result = launcherservice.GetAbilityList(bundleName, USERID, launcherAbilityInfos);
    EXPECT_TRUE(result) << "Get ability list failed";
    EXPECT_FALSE(launcherAbilityInfos.empty()) << "Launcher ability infos is empty";

    if (!launcherAbilityInfos.empty()) {
        EXPECT_EQ(launcherAbilityInfos[0].elementName.GetAbilityName(), abilityName);
        CheckAbilityList(launcherAbilityInfos, abilityName);
    }
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    GTEST_LOG_(INFO) << "END BMS_GetAbilityList_0100";
}
/**
 * @tc.number: BMS_GetAbilityList_0200
 * @tc.name: test GetAbilityList by LauncherService
 * @tc.desc: 1.install a low version hap
 *           2.install a high version hap
 *           3.get the ability info of the high version hap by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetAbilityList_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_GetAbilityList_0200";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string bundleFilePath1 = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleFilePath2 = THIRD_BUNDLE_PATH + "bmsThirdBundle4.hap";
    std::string abilityName = "com.example.third1.AMainAbility";
    std::string message;

    Install(bundleFilePath1, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    Install(bundleFilePath2, InstallFlag::REPLACE_EXISTING, message);
    EXPECT_EQ(message, "Success") << "install fail!";

    LauncherService launcherservice;
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    bool result = launcherservice.GetAbilityList(bundleName, USERID, launcherAbilityInfos);
    EXPECT_TRUE(result) << "Get ability list failed";
    EXPECT_FALSE(launcherAbilityInfos.empty()) << "Launcher ability infos is empty";
    if (!launcherAbilityInfos.empty()) {
        EXPECT_EQ(launcherAbilityInfos[0].elementName.GetAbilityName(), abilityName);
    }
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    GTEST_LOG_(INFO) << "END BMS_GetAbilityList_0200";
}
/**
 * @tc.number: BMS_GetAbilityList_0300
 * @tc.name: test GetAbilityList by LauncherService
 * @tc.desc: 1.install a normal hap with two abilty
 *           2.get ability info of the installed hap by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetAbilityList_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_GetAbilityList_0300";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle5.hap";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string abilityName1 = TEST_ABILITY_NAME;
    std::string message;
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";

    LauncherService launcherservice;
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    bool result = launcherservice.GetAbilityList(bundleName, USERID, launcherAbilityInfos);
    EXPECT_TRUE(result) << "Get ability list failed";
    EXPECT_FALSE(launcherAbilityInfos.empty()) << "Launcher ability infos is empty";

    EXPECT_EQ(launcherAbilityInfos.size(), 1);
    if (!launcherAbilityInfos.empty()) {
        EXPECT_EQ(launcherAbilityInfos[0].elementName.GetAbilityName(), abilityName1);
    }
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    GTEST_LOG_(INFO) << "END BMS_GetAbilityList_0300";
}
/**
 * @tc.number: BMS_GetAbilityList_0400
 * @tc.name: test GetAbilityList by LauncherService
 * @tc.desc: 1.install a hap with moduletype of entry
 *           2.install a hap with moduletype of feature
 *           2.get ability informations of two types of haps
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetAbilityList_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_GetAbilityList_0400";
    std::string bundleFilePath1 = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleFilePath2 = THIRD_BUNDLE_PATH + "bmsThirdBundle3.hap";
    std::string abilityName1 = TEST_ABILITY_NAME;
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string message;

    Install(bundleFilePath1, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    Install(bundleFilePath2, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";
    LauncherService launcherservice;
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    bool result = launcherservice.GetAbilityList(bundleName, USERID, launcherAbilityInfos);
    EXPECT_TRUE(result) << "Get ability list failed";
    EXPECT_FALSE(launcherAbilityInfos.empty()) << "Launcher ability infos is empty";
    EXPECT_EQ(launcherAbilityInfos.size(), LIST_SIZE);

    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
    GTEST_LOG_(INFO) << "END BMS_GetAbilityList_0400";
}
/**
 * @tc.number: BMS_GetAbilityList_0500
 * @tc.name: test GetAbilityList by LauncherService
 * @tc.desc: get ability info by wrong bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetAbilityList_0500, Function | MediumTest | Level2)
{
    GTEST_LOG_(INFO) << "START BMS_GetAbilityList_0500";
    std::string bundleName = "";

    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    LauncherService launcherservice;

    bool result = launcherservice.GetAbilityList(bundleName, USERID, launcherAbilityInfos);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "END BMS_GetAbilityList_0500";
}
/**
 * @tc.number: BMS_GetAbilityList_0600
 * @tc.name: test GetAbilityList by LauncherService
 * @tc.desc: 1.install a normal hap
 *           2.get ability info of this hap by bundleName
 *           2.get ability info after uninstalling the hap
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetAbilityList_0600, Function | MediumTest | Level2)
{
    GTEST_LOG_(INFO) << "START BMS_GetAbilityList_0600";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string abilityName = TEST_ABILITY_NAME;
    std::string message;
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";

    LauncherService launcherservice;
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    bool result1 = launcherservice.GetAbilityList(bundleName, USERID, launcherAbilityInfos);
    EXPECT_TRUE(result1) << "Get ability list failed";
    EXPECT_FALSE(launcherAbilityInfos.empty()) << "Launcher ability infos is empty";
    if (!launcherAbilityInfos.empty()) {
        EXPECT_EQ(launcherAbilityInfos[0].elementName.GetAbilityName(), abilityName);
    }

    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";

    bool result2 = launcherservice.GetAbilityList(bundleName, USERID, launcherAbilityInfos);
    EXPECT_FALSE(result2);
    GTEST_LOG_(INFO) << "END BMS_GetAbilityList_0600";
}

/**
 * @tc.number: GetAllLauncherAbilityInfos_0100
 * @tc.name: test GetAllLauncherAbilityInfos by LauncherService
 * @tc.desc: 1.test GetAllLauncherAbilityInfos success
 */
HWTEST_F(BmsLauncherServiceSystemTest, GetAllLauncherAbilityInfos_0100, Function | MediumTest | Level2)
{
    GTEST_LOG_(INFO) << "START GetAllLauncherAbilityInfos_0100";

    LauncherService launcherservice;
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    bool result = launcherservice.GetAllLauncherAbilityInfos(USERID, launcherAbilityInfos);
    EXPECT_TRUE(result) << "Get ability list failed";

    GTEST_LOG_(INFO) << "END GetAllLauncherAbilityInfos_0100";
}

/**
 * @tc.number: GetAllLauncherAbilityInfos_0200
 * @tc.name: test GetAllLauncherAbilityInfos by LauncherService
 * @tc.desc: 1.test GetAllLauncherAbilityInfos failed by wrong userId
 */
HWTEST_F(BmsLauncherServiceSystemTest, GetAllLauncherAbilityInfos_0200, Function | MediumTest | Level2)
{
    GTEST_LOG_(INFO) << "START GetAllLauncherAbilityInfos_0200";

    LauncherService launcherservice;
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    bool result = launcherservice.GetAllLauncherAbilityInfos(1001, launcherAbilityInfos);
    EXPECT_FALSE(result) << "Get ability list failed";

    GTEST_LOG_(INFO) << "END GetAllLauncherAbilityInfos_0200";
}

/**
 * @tc.number: GetShortcutInfos_0100
 * @tc.name: test GetShortcutInfos by LauncherService
 * @tc.desc: 1.install a normal hap
 *           2.get shortcut infos failed by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, GetShortcutInfos_0100, Function | MediumTest | Level2)
{
    GTEST_LOG_(INFO) << "START GetShortcutInfos_0100";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string message;
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";

    LauncherService launcherservice;
    std::string bundleName = "com.third.hiworld.example1";
    std::vector<ShortcutInfo> shortcutInfos;
    auto result = launcherservice.GetShortcutInfos(bundleName, shortcutInfos);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    Uninstall(TEST_BUNDLE_NAME, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";

    GTEST_LOG_(INFO) << "END GetShortcutInfos_0100";
}

/**
 * @tc.number: GetShortcutInfos_0200
 * @tc.name: test GetShortcutInfos by LauncherService
 * @tc.desc: 1.install a normal hap
 *           2.get shortcut infos failed by empty bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, GetShortcutInfos_0200, Function | MediumTest | Level2)
{
    GTEST_LOG_(INFO) << "START GetShortcutInfos_0200";

    LauncherService launcherservice;

    std::vector<ShortcutInfo> shortcutInfos;
    auto result = launcherservice.GetShortcutInfos("", shortcutInfos);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);

    GTEST_LOG_(INFO) << "END GetShortcutInfos_0200";
}

/**
 * @tc.number: GetShortcutInfoV9_0100
 * @tc.name: test GetShortcutInfoV9 by LauncherService
 * @tc.desc: 1.install a normal hap
 *           2.get shortcut infos failed by wrong bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, GetShortcutInfoV9_0100, Function | MediumTest | Level2)
{
    GTEST_LOG_(INFO) << "START GetShortcutInfoV9_0100";
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string message;
    Install(bundleFilePath, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";

    LauncherService launcherservice;
    std::string bundleName = "com.third.hiworld.example1";
    std::vector<ShortcutInfo> shortcutInfos;
    auto result = launcherservice.GetShortcutInfoV9(bundleName, shortcutInfos);
    EXPECT_NE(result, ERR_OK) << "Get ability list failed";

    Uninstall(TEST_BUNDLE_NAME, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";

    GTEST_LOG_(INFO) << "END GetShortcutInfoV9_0100";
}

/**
 * @tc.number: InstallByBundleName_0100
 * @tc.name: test InstallByBundleName by LauncherService
 * @tc.desc: install fail by invalid bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, InstallByBundleName_0100, Function | MediumTest | Level2)
{
    GTEST_LOG_(INFO) << "START InstallByBundleName_0100";
    std::string message;

    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    sptr<StatusReceiverImpl> statusReceiver = new (std::nothrow) StatusReceiverImpl();
    EXPECT_NE(statusReceiver, nullptr);
    bool result = installerProxy->InstallByBundleName("", installParam, statusReceiver);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "END InstallByBundleName_0100";
}

/**
 * @tc.number: BMS_GetLauncherAbilityByBundleName_0100
 * @tc.name: test GetAbilityInfo by LauncherService
 * @tc.desc: 1.install a low version hap
 *           2.install a high version hap
 *           3.get the application info of the high version hap by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetLauncherAbilityByBundleName_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_GetLauncherAbilityByBundleName_0100";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string bundleFilePath1 = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    std::string message;

    Install(bundleFilePath1, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";

    LauncherService launcherservice;
    ErrCode result = launcherservice.GetLauncherAbilityByBundleName(
        bundleName, USERID, launcherAbilityInfos);
    EXPECT_EQ(result, ERR_OK);
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
}

/**
 * @tc.number: BMS_GetLauncherAbilityByBundleName_0200
 * @tc.name: test GetAbilityInfo by LauncherService
 * @tc.desc: 1.install a low version hap
 *           2.install a high version hap
 *           3.get the application info of the high version hap by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetLauncherAbilityByBundleName_0200, Function | MediumTest | Level1)
{
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    LauncherService launcherservice;
    ErrCode result = launcherservice.GetLauncherAbilityByBundleName(
        "", USERID, launcherAbilityInfos);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BMS_GetLauncherAbilityInfoSync_0100
 * @tc.name: test GetAbilityInfo by LauncherService
 * @tc.desc: 1.install a low version hap
 *           2.install a high version hap
 *           3.get the application info of the high version hap by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetLauncherAbilityInfoSync_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_GetLauncherAbilityInfoSync_0100";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string bundleFilePath1 = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    std::string message;

    Install(bundleFilePath1, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";

    LauncherService launcherservice;
    ErrCode result = launcherservice.GetLauncherAbilityInfoSync(
        bundleName, USERID, launcherAbilityInfos);
    EXPECT_EQ(result, ERR_OK);
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
}

/**
 * @tc.number: BMS_GetLauncherAbilityInfoSync_0200
 * @tc.name: test GetAbilityInfo by LauncherService
 * @tc.desc: 1.install a low version hap
 *           2.install a high version hap
 *           3.get the application info of the high version hap by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetLauncherAbilityInfoSync_0200, Function | MediumTest | Level1)
{
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    LauncherService launcherservice;
    ErrCode result = launcherservice.GetLauncherAbilityInfoSync(
        "", USERID, launcherAbilityInfos);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BMS_GetLauncherAbilityInfoSync_0300
 * @tc.name: test GetAbilityInfo by LauncherService
 * @tc.desc: 1.install a low version hap
 *           2.install a high version hap
 *           3.get the application info of the high version hap by bundleName with invalid userId
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetLauncherAbilityInfoSync_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "START BMS_GetLauncherAbilityInfoSync_0300";
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string bundleFilePath1 = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    std::string message;

    Install(bundleFilePath1, InstallFlag::NORMAL, message);
    EXPECT_EQ(message, "Success") << "install fail!";

    LauncherService launcherservice;
    ErrCode result = launcherservice.GetLauncherAbilityInfoSync(
        bundleName, Constants::INVALID_USERID, launcherAbilityInfos);
    EXPECT_NE(result, ERR_OK);
    Uninstall(bundleName, message);
    EXPECT_EQ(message, "Success") << "uninstall fail!";
}

/**
 * @tc.number: BMS_GetAllLauncherAbility_0100
 * @tc.name: test GetAbilityInfo by LauncherService
 * @tc.desc: 1.install a low version hap
 *           2.install a high version hap
 *           3.get the application info of the high version hap by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetAllLauncherAbility_0100, Function | MediumTest | Level1)
{
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    LauncherService launcherservice;
    ErrCode result = launcherservice.GetAllLauncherAbility(USERID, launcherAbilityInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BMS_GetAllLauncherAbility_0200
 * @tc.name: test GetAbilityInfo by LauncherService
 * @tc.desc: 1.install a low version hap
 *           2.install a high version hap
 *           3.get the application info of the high version hap by bundleName
 */
HWTEST_F(BmsLauncherServiceSystemTest, BMS_GetAllLauncherAbility_0200, Function | MediumTest | Level1)
{
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    LauncherService launcherservice;
    ErrCode result = launcherservice.GetAllLauncherAbility(-1, launcherAbilityInfos);
    EXPECT_NE(result, ERR_OK);
}
 // namespace AppExecFwk
}  // namespace OHOS
}