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

#include <fcntl.h>
#include <fstream>
#include <future>
#include <gtest/gtest.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_event_callback_host.h"
#include "bundle_mgr_proxy.h"
#include "bundle_installer_proxy.h"
#include "bundle_status_callback_host.h"
#include "bundle_pack_info.h"
#include "clean_cache_callback_host.h"
#include "common_tool.h"
#include "extension_ability_info.h"
#include "form_info.h"
#include "permission_define.h"
#include "iservice_registry.h"
#include "nlohmann/json.hpp"
#include "status_receiver_host.h"
#include "system_ability_definition.h"
#include "testConfigParser.h"

using OHOS::AAFwk::Want;
using namespace testing::ext;
using namespace std::chrono_literals;

namespace {
const std::string THIRD_BUNDLE_PATH = "/data/test/bms_bundle/";
const std::string BASE_BUNDLE_NAME = "com.third.hiworld.example";
const std::string BASE_MODULE_NAME = "testability1";
const std::string BASE_ABILITY_NAME = "bmsThirdBundle_A1";
const std::string SYSTEM_SETTINGS_BUNDLE_NAME = "com.ohos.settings";
const std::string BUNDLE_DATA_ROOT_PATH = "/data/app/el2/100/base/";
const std::string ERROR_INSTALL_FAILED = "install failed!";
const std::string ERROR_UNINSTALL_FAILED = "uninstall failed!";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILED = "Failure";
const std::string OPERATION_SUCCESS = "Success";
const std::string APPID = "com.third.hiworld.example1_BNtg4JBClbl92Rgc3jm/"
    "RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=";
const int COMPATIBLEVERSION = 3;
const int TARGETVERSION = 3;
const int32_t USERID = 100;
const int32_t RESID = 16777218;
const int32_t HUNDRED_USERID = 20010037;
constexpr int32_t DISPOSED_STATUS = 10;
}  // namespace

namespace OHOS {
namespace AppExecFwk {
class BundleEventCallbackImpl : public BundleEventCallbackHost {
public:
    BundleEventCallbackImpl();
    virtual ~BundleEventCallbackImpl() override;
    virtual void OnReceiveEvent(const EventFwk::CommonEventData eventData) override;

private:
    DISALLOW_COPY_AND_MOVE(BundleEventCallbackImpl);
};

BundleEventCallbackImpl::BundleEventCallbackImpl()
{
    APP_LOGI("create bundle event instance");
}

BundleEventCallbackImpl::~BundleEventCallbackImpl()
{
    APP_LOGI("destroy bundle event instance");
}

void BundleEventCallbackImpl::OnReceiveEvent(const EventFwk::CommonEventData eventData)
{
    const Want &want = eventData.GetWant();
    std::string action = want.GetAction();
    std::string bundleName = want.GetElement().GetBundleName();
    std::cout << "action : " << action << std::endl;
    std::cout << "bundleName : " << bundleName << std::endl;
}

class BundleStatusCallbackImpl : public BundleStatusCallbackHost {
public:
    BundleStatusCallbackImpl();
    virtual ~BundleStatusCallbackImpl() override;
    virtual void OnBundleStateChanged(const uint8_t installType, const int32_t resultCode, const std::string &resultMsg,
        const std::string &bundleName) override;
    virtual void OnBundleAdded(const std::string &bundleName, const int userId) override {};
    virtual void OnBundleUpdated(const std::string &bundleName, const int userId) override {};
    virtual void OnBundleRemoved(const std::string &bundleName, const int userId) override {};

private:
    DISALLOW_COPY_AND_MOVE(BundleStatusCallbackImpl);
};

BundleStatusCallbackImpl::BundleStatusCallbackImpl()
{
    APP_LOGI("create bundle status instance");
}

BundleStatusCallbackImpl::~BundleStatusCallbackImpl()
{
    APP_LOGI("destroy bundle status instance");
}

void BundleStatusCallbackImpl::OnBundleStateChanged(
    const uint8_t installType, const int32_t resultCode, const std::string &resultMsg, const std::string &bundleName)
{
    APP_LOGI("BMS_Kit_St OnBundleStateChanged results are %{public}d, %{public}d, %{public}s, %{public}s",
        installType,
        resultCode,
        resultMsg.c_str(),
        bundleName.c_str());
}

class CleanCacheCallBackImpl : public CleanCacheCallbackHost {
public:
    CleanCacheCallBackImpl();
    virtual ~CleanCacheCallBackImpl() override;

    virtual void OnCleanCacheFinished(bool succeeded) override;
    bool GetSucceededResult() const;

private:
    mutable std::promise<bool> resultSucceededSignal_;
    DISALLOW_COPY_AND_MOVE(CleanCacheCallBackImpl);
};

CleanCacheCallBackImpl::CleanCacheCallBackImpl()
{
    APP_LOGI("create bundle status instance");
}

CleanCacheCallBackImpl::~CleanCacheCallBackImpl()
{
    APP_LOGI("destroy bundle status instance");
}

void CleanCacheCallBackImpl::OnCleanCacheFinished(bool succeeded)
{
    APP_LOGI("BMS_Kit_St OnCleanCacheFinished results are %{public}d", succeeded);
    resultSucceededSignal_.set_value(succeeded);
}

bool CleanCacheCallBackImpl::GetSucceededResult() const
{
    auto future = resultSucceededSignal_.get_future();
    future.wait();
    return future.get();
}

class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    virtual ~StatusReceiverImpl();
    virtual void OnStatusNotify(const int progress) override;
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
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

void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    APP_LOGD("OnFinished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
    resultMsgSignal_.set_value(resultMsg);
}
void StatusReceiverImpl::OnStatusNotify(const int progress)
{
    EXPECT_GT(progress, iProgress_);
    iProgress_ = progress;
    APP_LOGI("OnStatusNotify progress:%{public}d", progress);
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

class ActsBmsKitSystemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static void Install(
        const std::string &bundleFilePath, const InstallFlag installFlag, std::vector<std::string> &resvec);
    static void Uninstall(const std::string &bundleName, std::vector<std::string> &resvec);
    static void HapUninstall(
        const std::string &bundleName, const std::string &modulePackage, std::vector<std::string> &resvec);
    static sptr<BundleMgrProxy> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
    void CheckBundleInfo(const uint32_t index, BundleInfo &bundleInfo) const;
    void CheckBaseBundleInfo(uint32_t index, const BundleInfo &bundleInfo) const;
    void CreateDir(const std::string &path) const;
    void CheckFileExist(const std::string &bundleName) const;
    void CheckFileExist(const std::string &bundleName, const std::string &modulePackage) const;
    void CheckFileNonExist(const std::string &bundleName) const;
    void CheckFileNonExist(const std::string &bundleName, const std::string &modulePackage) const;
    static StressTestLevel stLevel_;
};
StressTestLevel ActsBmsKitSystemTest::stLevel_{};

void ActsBmsKitSystemTest::SetUpTestCase()
{
    TestConfigParser tcp;
    tcp.ParseFromFile4StressTest(STRESS_TEST_CONFIG_FILE_PATH, stLevel_);
    std::cout << "stress test level : "
              << "BMS : " << stLevel_.BMSLevel << std::endl;
}

void ActsBmsKitSystemTest::TearDownTestCase()
{
    std::cout << "BmsInstallSystemTest TearDownTestCase" << std::endl;
}

void ActsBmsKitSystemTest::SetUp()
{}

void ActsBmsKitSystemTest::TearDown()
{}

void ActsBmsKitSystemTest::Install(
    const std::string &bundleFilePath, const InstallFlag installFlag, std::vector<std::string> &resvec)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        resvec.push_back(ERROR_INSTALL_FAILED);
        return;
    }
    InstallParam installParam;
    installParam.installFlag = installFlag;
    installParam.userId = USERID;
    sptr<StatusReceiverImpl> statusReceiver = (new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    resvec.push_back(statusReceiver->GetResultMsg());
}

void ActsBmsKitSystemTest::Uninstall(const std::string &bundleName, std::vector<std::string> &resvec)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        resvec.push_back(ERROR_UNINSTALL_FAILED);
        return;
    }

    if (bundleName.empty()) {
        APP_LOGE("bundelname is null.");
        resvec.push_back(ERROR_UNINSTALL_FAILED);
    } else {
        InstallParam installParam;
        installParam.userId = USERID;
        sptr<StatusReceiverImpl> statusReceiver = (new (std::nothrow) StatusReceiverImpl());
        EXPECT_NE(statusReceiver, nullptr);
        installerProxy->Uninstall(bundleName, installParam, statusReceiver);
        resvec.push_back(statusReceiver->GetResultMsg());
    }
}

void ActsBmsKitSystemTest::HapUninstall(
    const std::string &bundleName, const std::string &modulePackage, std::vector<std::string> &resvec)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        resvec.push_back(ERROR_UNINSTALL_FAILED);
        return;
    }

    if (bundleName.empty()) {
        APP_LOGE("bundelname is null.");
        resvec.push_back(ERROR_UNINSTALL_FAILED);
    } else {
        InstallParam installParam;
        installParam.userId = USERID;
        sptr<StatusReceiverImpl> statusReceiver = (new (std::nothrow) StatusReceiverImpl());
        EXPECT_NE(statusReceiver, nullptr);
        installerProxy->Uninstall(bundleName, modulePackage, installParam, statusReceiver);
        resvec.push_back(statusReceiver->GetResultMsg());
    }
}

sptr<BundleMgrProxy> ActsBmsKitSystemTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> ActsBmsKitSystemTest::GetInstallerProxy()
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        return nullptr;
    }

    sptr<IBundleInstaller> installerProxy = bundleMgrProxy->GetBundleInstaller();
    if (!installerProxy) {
        APP_LOGE("fail to get bundle installer proxy.");
        return nullptr;
    }

    APP_LOGI("get bundle installer proxy success.");
    return installerProxy;
}

void ActsBmsKitSystemTest::CheckFileExist(const std::string &bundleName) const
{
    int bundleDataExist = access((BUNDLE_DATA_ROOT_PATH + bundleName).c_str(), F_OK);
    EXPECT_EQ(bundleDataExist, 0) << "the bundle data dir doesn't exist: " << bundleName;
}

void ActsBmsKitSystemTest::CheckFileExist(const std::string &bundleName, const std::string &modulePackage) const
{
    int bundleDataExist = access((BUNDLE_DATA_ROOT_PATH + bundleName + "/" + modulePackage).c_str(), F_OK);
    EXPECT_EQ(bundleDataExist, 0) << "the bundle data dir doesn't exist: " << bundleName;
}

void ActsBmsKitSystemTest::CheckFileNonExist(const std::string &bundleName) const
{
    int bundleDataExist = access((BUNDLE_DATA_ROOT_PATH + bundleName).c_str(), F_OK);
    EXPECT_NE(bundleDataExist, 0) << "the bundle data dir exists: " << bundleName;
}

void ActsBmsKitSystemTest::CheckFileNonExist(const std::string &bundleName, const std::string &modulePackage) const
{
    int bundleDataExist = access((BUNDLE_DATA_ROOT_PATH + bundleName + "/" + modulePackage).c_str(), F_OK);
    EXPECT_NE(bundleDataExist, 0) << "the bundle data dir exists: " << bundleName;
}

void ActsBmsKitSystemTest::CheckBundleInfo(const uint32_t index, BundleInfo &bundleInfo) const
{
    EXPECT_EQ(bundleInfo.name, BASE_BUNDLE_NAME + std::to_string(index));
    EXPECT_GE(bundleInfo.uid, Constants::BASE_USER_RANGE);
    EXPECT_EQ(bundleInfo.vendor, "example");
    EXPECT_EQ(bundleInfo.versionCode, index);
    std::string strVersion = std::to_string(index) + ".0";
    EXPECT_EQ(bundleInfo.versionName, strVersion);
    EXPECT_EQ(bundleInfo.jointUserId, "");
    EXPECT_EQ(bundleInfo.compatibleVersion, COMPATIBLEVERSION);
    EXPECT_EQ(bundleInfo.targetVersion, TARGETVERSION);
    std::vector<AbilityInfo> abilities = bundleInfo.abilityInfos;
    for (auto iter = abilities.begin(); iter != abilities.end(); iter++) {
        EXPECT_EQ(iter->bundleName, BASE_BUNDLE_NAME + std::to_string(index));
        EXPECT_EQ(iter->description, "");
        EXPECT_EQ(iter->label, "bmsThirdBundle_A2 Ability");
        EXPECT_EQ(iter->moduleName, "testability");
        std::cout << "abilityInfo-moduleName:" << iter->moduleName << std::endl;
        EXPECT_EQ(iter->uri, "");
        EXPECT_EQ(iter->visible, true);
        int iLaunchMode = (int)iter->launchMode;
        EXPECT_EQ(iLaunchMode, 0);
        int iOrientation = (int)iter->orientation;
        EXPECT_EQ(iOrientation, 0);
        int iType = (int)iter->type;
        EXPECT_EQ(iType, 1);
    }
    ApplicationInfo applicationInfo = bundleInfo.applicationInfo;
    EXPECT_EQ(applicationInfo.name, (BASE_BUNDLE_NAME + std::to_string(index)));
    EXPECT_EQ(applicationInfo.supportedModes, 0);
    for (auto appModuleInfo : applicationInfo.moduleInfos) {
        std::cout << "applicationInfo-moduleName:" << appModuleInfo.moduleName << std::endl;
        std::cout << "applicationInfo-moduleSourceDir:" << appModuleInfo.moduleSourceDir << std::endl;
    }
    std::cout << "applicationInfo-entryDir:" << applicationInfo.entryDir << std::endl;
}

void ActsBmsKitSystemTest::CheckBaseBundleInfo(uint32_t index, const BundleInfo &bundleInfo) const
{
    EXPECT_EQ(bundleInfo.name, BASE_BUNDLE_NAME + std::to_string(index));
    EXPECT_EQ(bundleInfo.vendor, "example");
    EXPECT_EQ(bundleInfo.versionCode, index);
    std::string strVersion = std::to_string(index) + ".0";
    EXPECT_EQ(bundleInfo.versionName, strVersion);
    EXPECT_EQ(bundleInfo.jointUserId, "");
    EXPECT_EQ(bundleInfo.targetVersion, TARGETVERSION);
}

void ActsBmsKitSystemTest::CreateDir(const std::string &path) const
{
    if (access(path.c_str(), F_OK) != 0) {
        if (mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
            APP_LOGE("CreateDir:%{private}s error", path.c_str());
        }
    }
}

/**
 * @tc.number: GetBundleInfo_0100
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfo_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfo_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    bool getInfoResult = bundleMgrProxy->GetBundleInfo(appName, 0, bundleInfo, USERID);
    EXPECT_TRUE(getInfoResult);
    CheckBundleInfo(1, bundleInfo);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfo_0100" << std::endl;
}

/**
 * @tc.number: GetBundleInfo_0200
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfo_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfo_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle25.hap";
    std::string appName = BASE_BUNDLE_NAME + "2";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    bool getInfoResult =
        bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USERID);
    EXPECT_TRUE(getInfoResult);
    CheckBundleInfo(2, bundleInfo);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfo_0200" << std::endl;
}

/**
 * @tc.number: GetBundleInfo_0300
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfo_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfo_0300" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle26.hap";
    std::string appName = BASE_BUNDLE_NAME + "3";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);

    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    bool getInfoResult =
        bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USERID);
    EXPECT_TRUE(getInfoResult);
    CheckBundleInfo(3, bundleInfo);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundleInfo_0300" << std::endl;
}

/**
 * @tc.number: GetBundleInfo_0500
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfo_0500, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfo_0500" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle28.rpk";
        std::string appName = BASE_BUNDLE_NAME + "5";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Failure[ERR_INSTALL_INVALID_HAP_NAME]");
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        BundleInfo bundleInfo;
        bool getInfoResult =
            bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USERID);
        EXPECT_FALSE(getInfoResult);
        if (getInfoResult) {
            APP_LOGI("GetBundleInfo_0500 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleInfo_0500 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleInfo_0500" << std::endl;
}

/**
 * @tc.number: GetBundleInfo_0600
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query bundleInfo with wrong appname
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfo_0600, Function | MediumTest | Level2)
{
    std::cout << "START GetBundleInfo_0600" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        appName = BASE_BUNDLE_NAME + "e";
        BundleInfo bundleInfo;
        bool getInfoResult = bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
        EXPECT_FALSE(getInfoResult);
        resvec.clear();
        appName = BASE_BUNDLE_NAME + "1";
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (getInfoResult) {
            APP_LOGI("GetBundleInfo_0600 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleInfo_0600 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleInfo_0600" << std::endl;
}

/**
 * @tc.number: GetBundleInfo_0800
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/system/app/',there is a hap
 *           2.install the hap
 *           3.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfo_0800, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    BundleInfo bundleInfo;
    bool getInfoResult = bundleMgrProxy->GetBundleInfo("", BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    EXPECT_FALSE(getInfoResult);
}

/**
 * @tc.number: GetBundleInfo_0900
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/system/app/',there is a hap
 *           2.bundlename is null
 *           3.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfo_0900, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    BundleInfo bundleInfo;
    int32_t flags = 1;
    bool getInfoResult = bundleMgrProxy->GetBundleInfo("", flags, bundleInfo, USERID);
    EXPECT_FALSE(getInfoResult);
}

/**
 * @tc.number: GetBundleInfoV9_0010
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query bundleInfo failed for wrong BundleName
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0010, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0010" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9("",
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0010" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0011
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query bundleInfo failed for wrong UserId
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0011, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0011" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT), bundleInfo, 99);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0011" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0012
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query default bundleInfo successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0012, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0012" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    CheckBaseBundleInfo(1, bundleInfo);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0012" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0013
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query default bundleInfo and applicationInfo successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0013, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0013" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    CheckBaseBundleInfo(1, bundleInfo);
    EXPECT_EQ(bundleInfo.applicationInfo.name, appName);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0013" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0014
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query default bundleInfo and hapModuleInfos successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0014, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0014" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    CheckBaseBundleInfo(1, bundleInfo);
    EXPECT_GT(bundleInfo.hapModuleInfos.size(), 0);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0014" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0015
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get abilityInfo successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0015, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0015" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    CheckBaseBundleInfo(1, bundleInfo);
    EXPECT_GT(bundleInfo.hapModuleInfos.size(), 0);
    EXPECT_GT(bundleInfo.hapModuleInfos[0].abilityInfos.size(), 0);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0015" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0016
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get extensionInfos successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0016, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0016" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    EXPECT_GT(bundleInfo.hapModuleInfos.size(), 0);
    EXPECT_GT(bundleInfo.hapModuleInfos[0].extensionInfos.size(), 0);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0016" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0017
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get reqPermissions, defPermissions and reqPermissionDetails successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0017, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0017" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    EXPECT_GT(bundleInfo.reqPermissions.size(), 0);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0017" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0018
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get applicationInfo which contain metadata successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0018, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0018" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    EXPECT_EQ(bundleInfo.applicationInfo.name, appName);
    EXPECT_GT(bundleInfo.applicationInfo.metadata.size(), 0);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0018" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0019
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get hapModuleInfos which contain metadata successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0019, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0019" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    EXPECT_GT(bundleInfo.hapModuleInfos[0].metadata.size(), 0);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0019" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0020
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get abilityInfo which contain metadata successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0020, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0020" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    EXPECT_GT(bundleInfo.hapModuleInfos[0].abilityInfos[0].metadata.size(), 0);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0020" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0021
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get extensionInfos which contain metadata successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0021, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0021" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    EXPECT_GT(bundleInfo.hapModuleInfos[0].extensionInfos[0].metadata.size(), 0);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0021" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0022
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get disabled bundleInfo successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0022, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0022" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto setResult = bundleMgrProxy->SetApplicationEnabled(appName, false, USERID);
    EXPECT_EQ(setResult, ERR_OK);
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    auto resetResult = bundleMgrProxy->SetApplicationEnabled(appName, true, USERID);
    EXPECT_EQ(resetResult, ERR_OK);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0022" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0023
 * @tc.name: test query bundle information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get bundleInfo which contain signatureInfo successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0023, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0023" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    EXPECT_EQ(bundleInfo.signatureInfo.appId, APPID);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0023" << std::endl;
}

/**
 * @tc.number: GetBundleInfos_0100
 * @tc.name: test query bundleinfos
 * @tc.desc: 1.under '/data/test/bms_bundle',there exist three bundles
 *           2.install the bundles
 *           3.query all bundleinfos
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfos_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfos_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        CommonTool commonTool;
        std::string installResult;
        for (int i = 6; i < 9; i++) {
            std::vector<std::string> resvec;
            std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
            Install(hapFilePath, InstallFlag::NORMAL, resvec);
            installResult = commonTool.VectorToStr(resvec);
            EXPECT_EQ(installResult, "Success") << "install fail!";
        }
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::vector<BundleInfo> bundleInfos;
        bool getInfoResult = bundleMgrProxy->GetBundleInfos(0, bundleInfos, USERID);
        EXPECT_TRUE(getInfoResult);

        bool isSubStrExist = false;
        for (int i = 1; i <= 3; i++) {
            std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
            for (auto iter = bundleInfos.begin(); iter != bundleInfos.end(); iter++) {
                if (IsSubStr(iter->name, appName)) {
                    isSubStrExist = true;
                    break;
                }
            }
            EXPECT_TRUE(isSubStrExist);
            std::vector<std::string> resvec2;
            Uninstall(appName, resvec2);
            std::string uninstallResult = commonTool.VectorToStr(resvec2);
            EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
        }
        if (!getInfoResult) {
            APP_LOGI("GetBundleInfos_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleInfos_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleInfos_0100" << std::endl;
}

/**
 * @tc.number: GetBundleInfos_0200
 * @tc.name: test query bundleinfos
 * @tc.desc: 1.under '/system/app/bms_bundle',there exist some hap
 *           2.query all bundleinfos
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfos_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfos_0200" << std::endl;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }

        std::vector<BundleInfo> bundleInfos;
        bool getInfoResult = bundleMgrProxy->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, USERID);
        EXPECT_TRUE(getInfoResult);
    }
    std::cout << "END GetBundleInfos_0200" << std::endl;
}

/**
 * @tc.number: GetBundleInfosV9_0100
 * @tc.name: test query bundleinfos
 * @tc.desc: 1.under '/data/test/bms_bundle',there exist three bundles
 *           2.install the bundles
 *           3.query all bundleinfos failed for wrong UserId
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfosV9_0100, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::vector<BundleInfo> bundleInfos;
    auto getInfoResult = bundleMgrProxy->GetBundleInfosV9(
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT), bundleInfos, Constants::INVALID_USERID);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetBundleInfosV9_0200
 * @tc.name: test query bundleinfos
 * @tc.desc: 1.under '/data/test/bms_bundle',there exist three bundles
 *           2.install the bundles
 *           3.query all bundleinfos
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfosV9_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfosV9_0200" << std::endl;
    CommonTool commonTool;
    std::string installResult;
    for (int i = 6; i < 9; i++) {
        std::vector<std::string> resvec;
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
        Install(hapFilePath, InstallFlag::NORMAL, resvec);
        installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
    }
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::vector<BundleInfo> bundleInfos;
    auto getInfoResult = bundleMgrProxy->GetBundleInfosV9(
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT), bundleInfos, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);

    bool isSubStrExist = false;
    for (int i = 1; i <= 3; i++) {
        std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
        for (auto iter = bundleInfos.begin(); iter != bundleInfos.end(); iter++) {
            if (IsSubStr(iter->name, appName)) {
                isSubStrExist = true;
                break;
            }
        }
        EXPECT_TRUE(isSubStrExist);
        std::vector<std::string> resvec2;
        Uninstall(appName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    }

    std::cout << "END GetBundleInfos_0200" << std::endl;
}

/**
 * @tc.number: GetBundleInfosV9_0300
 * @tc.name: test query bundleinfos
 * @tc.desc: 1.under '/data/test/bms_bundle',there exist three bundles
 *           2.install the bundles
 *           3.query disabled bundleinfos failed
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfosV9_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfosV9_0300" << std::endl;
    CommonTool commonTool;
    std::string installRes;
    for (int i = 6; i < 9; i++) {
        std::vector<std::string> resvec;
        std::string hapFile = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
        Install(hapFile, InstallFlag::NORMAL, resvec);
        installRes = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installRes, "Success") << "install fail!";
    }
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::string bundleName = BASE_BUNDLE_NAME + std::to_string(1);
    auto setBundleRes = bundleMgrProxy->SetApplicationEnabled(bundleName, false, USERID);
    EXPECT_EQ(setBundleRes, ERR_OK);

    std::vector<BundleInfo> bundleInfos;
    auto getInfoResult = bundleMgrProxy->GetBundleInfosV9(
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT), bundleInfos, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);

    bool findDisabledBundle = false;

    for (auto iter = bundleInfos.begin(); iter != bundleInfos.end(); iter++) {
        if (IsSubStr(iter->name, bundleName)) {
            findDisabledBundle = true;
            break;
        }
    }
    EXPECT_FALSE(findDisabledBundle);

    auto resetBundleRes = bundleMgrProxy->SetApplicationEnabled(bundleName, true, USERID);
    EXPECT_EQ(resetBundleRes, ERR_OK);
    for (int i = 1; i <= 3; i++) {
        std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
        std::vector<std::string> resvec2;
        Uninstall(appName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    }

    std::cout << "END GetBundleInfos_0300" << std::endl;
}

/**
 * @tc.number: GetBundleInfosV9_0400
 * @tc.name: test query bundleinfos
 * @tc.desc: 1.under '/data/test/bms_bundle',there exist three bundles
 *           2.install the bundles
 *           3.query disabled bundleinfos successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfosV9_0400, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfosV9_0400" << std::endl;
    CommonTool commonTool;
    std::string installRes;
    for (int i = 6; i < 9; i++) {
        std::vector<std::string> resvec;
        std::string hapFile = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
        Install(hapFile, InstallFlag::NORMAL, resvec);
        installRes = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installRes, "Success") << "install fail!";
    }
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::string bundleName = BASE_BUNDLE_NAME + std::to_string(1);
    auto setBundleRes = bundleMgrProxy->SetApplicationEnabled(bundleName, false, USERID);
    EXPECT_EQ(setBundleRes, ERR_OK);

    std::vector<BundleInfo> bundleInfos;
    auto getInfoResult = bundleMgrProxy->GetBundleInfosV9(
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), bundleInfos, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);

    bool findDisabledBundle = false;

    for (auto iter = bundleInfos.begin(); iter != bundleInfos.end(); iter++) {
        if (IsSubStr(iter->name, bundleName)) {
            findDisabledBundle = true;
            break;
        }
    }
    EXPECT_TRUE(findDisabledBundle);

    auto resetBundleRes = bundleMgrProxy->SetApplicationEnabled(bundleName, true, USERID);
    EXPECT_EQ(resetBundleRes, ERR_OK);
    for (int i = 1; i <= 3; i++) {
        std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
        std::vector<std::string> resvec2;
        Uninstall(appName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    }

    std::cout << "END GetBundleInfos_0300" << std::endl;
}

/**
 * @tc.number: GetApplicationInfo_0100
 * @tc.name: test query application information
 * EnvConditions: system running normally
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query appinfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfo_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfo_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        ApplicationInfo appInfo;
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfo(appName, 0, USERID, appInfo);
        EXPECT_TRUE(getInfoResult);
        EXPECT_EQ(appInfo.name, appName);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!getInfoResult) {
            APP_LOGI("GetApplicationInfo_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetApplicationInfo_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetApplicationInfo_0100" << std::endl;
}

/**
 * @tc.number: GetApplicationInfo_0200
 * @tc.name: test query application information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query appinfo with permission
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfo_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfo_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        ApplicationInfo appInfo;
        bool getInfoResult = bundleMgrProxy->GetApplicationInfo(
            appName, ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, USERID, appInfo);
        std::string permission = commonTool.VectorToStr(appInfo.permissions);
        EXPECT_TRUE(getInfoResult);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!getInfoResult) {
            APP_LOGI("GetApplicationInfo_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetApplicationInfo_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetApplicationInfo_0200" << std::endl;
}

/**
 * @tc.number: GetApplicationInfo_0300
 * @tc.name: test query application information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query appInfo with wrong appname
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfo_0300, Function | MediumTest | Level2)
{
    std::cout << "START GetApplicationInfo_0300" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        ApplicationInfo appInfo;
        appName = BASE_BUNDLE_NAME + "e";
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfo(appName, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, appInfo);
        EXPECT_FALSE(getInfoResult);
        resvec.clear();
        appName = BASE_BUNDLE_NAME + "1";
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (getInfoResult) {
            APP_LOGI("GetApplicationInfo_0300 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetApplicationInfo_0300 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetApplicationInfo_0300" << std::endl;
}

/**
 * @tc.number: GetApplicationInfo_0400
 * @tc.name: test GetApplicationInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call GetApplicationInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfo_0400, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfo_0400" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle3.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        ApplicationInfo appInfo;
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfo(appName, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, appInfo);
        EXPECT_TRUE(getInfoResult);
        EXPECT_EQ(appInfo.name, appName);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!getInfoResult) {
            APP_LOGI("GetApplicationInfo_0400 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetApplicationInfo_0400 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetApplicationInfo_0400" << std::endl;
}

/**
 * @tc.number: GetApplicationInfo_0500
 * @tc.name: test GetApplicationInfo interface
 * @tc.desc: 1.under '/system/app',there is a hap
 *           2.install the hap
 *           3.call GetApplicationInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfo_0500, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfo_0500" << std::endl;
    CommonTool commonTool;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    ApplicationInfo appInfo;
    bool getInfoResult = bundleMgrProxy->GetApplicationInfo(
        appName, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, appInfo);
    EXPECT_TRUE(getInfoResult);
    EXPECT_EQ(appInfo.name, appName);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetApplicationInfo_0500" << std::endl;
}

/**
 * @tc.number: GetApplicationInfo_0600
 * @tc.name: test GetApplicationInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.uninstall the hap
 *           4.call GetApplicationInfo to get application info
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfo_0600, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfo_0600" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success");

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        ApplicationInfo appInfo;
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfo(appName, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, appInfo);
        EXPECT_FALSE(getInfoResult);
        if (getInfoResult) {
            APP_LOGI("GetApplicationInfo_0600 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetApplicationInfo_0600 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetApplicationInfo_0600" << std::endl;
}

/**
 * @tc.number: GetApplicationInfo_0700
 * @tc.name: test GetApplicationInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.uninstall the hap
 *           4.call GetApplicationInfo to get application info
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfo_0700, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfo_0700" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);
        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        ApplicationInfo appInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfo(appName, 0, USERID, appInfo);
        EXPECT_TRUE(getInfoResult);
        EXPECT_EQ(appInfo.flags, 0);

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
        if (!getInfoResult) {
            APP_LOGI("GetApplicationInfo_0700 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetApplicationInfo_0700 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetApplicationInfo_0700" << std::endl;
}

/**
 * @tc.number: GetApplicationInfo_0800
 * @tc.name: test GetApplicationInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.uninstall the hap
 *           4.call GetApplicationInfo to get application info
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfo_0800, Function | MediumTest | Level1)
{
    ApplicationInfo appInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bool getInfoResult =
        bundleMgrProxy->GetApplicationInfo("", 0, USERID, appInfo);
    EXPECT_FALSE(getInfoResult);
}

/**
 * @tc.number: GetApplicationInfoV9_0100
 * @tc.name: test query application information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query default ApplicationInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfoV9_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfoV9_0100" << std::endl;

    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ApplicationInfo appInfo;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfoV9(
        appName, static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), USERID, appInfo);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(appInfo.name, appName);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetApplicationInfoV9_0100" << std::endl;
}

/**
 * @tc.number: GetApplicationInfoV9_0200
 * @tc.name: test query application information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.fail to query ApplicationInfo for wrong bundleName
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfoV9_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfoV9_0200" << std::endl;

    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ApplicationInfo appInfo;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfoV9(
        "", static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), USERID, appInfo);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetApplicationInfoV9_0200" << std::endl;
}

/**
 * @tc.number: GetApplicationInfoV9_0300
 * @tc.name: test query application information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.fail to query ApplicationInfo for wrong UserId
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfoV9_0300, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ApplicationInfo appInfo;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfoV9(
        "appName", static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT),
            Constants::INVALID_USERID, appInfo);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetApplicationInfoV9_0400
 * @tc.name: test query application information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get ApplicationInfo with permissions
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfoV9_0400, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfoV9_0400" << std::endl;

    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ApplicationInfo appInfo;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfoV9(
        appName, static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION), USERID, appInfo);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(appInfo.name, appName);
    EXPECT_GT(appInfo.permissions.size(), 0);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetApplicationInfoV9_0400" << std::endl;
}

/**
 * @tc.number: GetApplicationInfoV9_0500
 * @tc.name: test query application information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get ApplicationInfo with metadata
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfoV9_0500, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfoV9_0500" << std::endl;

    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ApplicationInfo appInfo;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfoV9(
        appName, static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA), USERID, appInfo);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(appInfo.name, appName);
    EXPECT_GT(appInfo.metadata.size(), 0);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetApplicationInfoV9_0500" << std::endl;
}

/**
 * @tc.number: GetApplicationInfos_0100
 * @tc.name: test query applicationinfos
 * @tc.desc: 1.under '/data/test/bms_bundle',there exist three bundles
 *           2.install these bundles
 *           3.query all appinfos
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfos_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfos_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        CommonTool commonTool;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string installResult;
        for (int i = 6; i <= 8; i++) {
            std::vector<std::string> resvec;
            std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
            std::string appName = BASE_BUNDLE_NAME + std::to_string(i - 5);
            Install(hapFilePath, InstallFlag::NORMAL, resvec);
            installResult = commonTool.VectorToStr(resvec);
            EXPECT_EQ(installResult, "Success") << "install fail!";

            std::vector<ApplicationInfo> appInfos;
            int32_t flags = 8;
            bool getInfoResult = bundleMgrProxy->GetApplicationInfos(flags, USERID, appInfos);
            EXPECT_TRUE(getInfoResult);
            resvec.clear();
            Uninstall(appName, resvec);
            std::string uninstallResult = commonTool.VectorToStr(resvec);
            EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

            bool isSubStrExist = false;
            for (auto iter = appInfos.begin(); iter != appInfos.end(); iter++) {
                if (IsSubStr(iter->name, appName)) {
                    isSubStrExist = true;
                    break;
                }
            }
            EXPECT_TRUE(isSubStrExist);
            if (!getInfoResult) {
                APP_LOGI("GetApplicationInfos_0100 failed - cycle count: %{public}d", i);
                break;
            }
            result = true;
        }
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetApplicationInfos_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetApplicationInfos_0100" << std::endl;
}

/**
 * @tc.number: GetApplicationInfos_0200
 * @tc.name: test query applicationinfos
 * @tc.desc: 1.there are some system-app installed in system
 *           2.query all appinfos
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfos_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfos_0200" << std::endl;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::vector<ApplicationInfo> appInfos;
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfos(
                ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, USERID, appInfos);
        EXPECT_TRUE(getInfoResult);
    }
    std::cout << "END GetApplicationInfos_0200" << std::endl;
}

/**
 * @tc.number: GetApplicationInfosV9_0100
 * @tc.name: test query applicationinfos
 * @tc.desc: 1.fail to query all appinfos for wrong UserId
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfosV9_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfosV9_0100" << std::endl;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::vector<ApplicationInfo> appInfos;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfosV9(
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT),
            Constants::INVALID_USERID, appInfos);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    std::cout << "END GetApplicationInfosV9_0100" << std::endl;
}

/**
 * @tc.number: GetApplicationInfos_0200
 * @tc.name: test query applicationinfos
 * @tc.desc: 1.under '/data/test/bms_bundle',there exist three bundles
 *           2.install these bundles
 *           3.query all appinfos
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfosV9_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfosV9_0200" << std::endl;
    CommonTool commonTool;
    std::string installResult;
    for (int i = 6; i < 9; i++) {
        std::vector<std::string> resvec;
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
        Install(hapFilePath, InstallFlag::NORMAL, resvec);
        installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
    }
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::vector<ApplicationInfo> appInfos;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfosV9(
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), USERID, appInfos);
    EXPECT_EQ(getInfoResult, ERR_OK);

    bool isSubStrExist = false;
    for (int i = 1; i <= 3; i++) {
        std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
        for (auto iter = appInfos.begin(); iter != appInfos.end(); iter++) {
            if (IsSubStr(iter->name, appName)) {
                isSubStrExist = true;
                break;
            }
        }
        EXPECT_TRUE(isSubStrExist);
        std::vector<std::string> resvec2;
        Uninstall(appName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    }
    std::cout << "END GetApplicationInfosV9_0200" << std::endl;
}

/**
 * @tc.number: GetApplicationInfos_0300
 * @tc.name: test query applicationinfos
 * @tc.desc: 1.under '/data/test/bms_bundle',there exist three bundles
 *           2.install these bundles
 *           3.query all disabled appinfos
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfosV9_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfosV9_0300" << std::endl;
    CommonTool commonTool;
    std::string installResult;
    for (int i = 6; i < 9; i++) {
        std::vector<std::string> resvec;
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
        Install(hapFilePath, InstallFlag::NORMAL, resvec);
        installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
    }
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    for (int i = 1; i <= 3; i++) {
        std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
        auto setAppResult = bundleMgrProxy->SetApplicationEnabled(appName, false, USERID);
        EXPECT_EQ(setAppResult, ERR_OK);
    }
    std::vector<ApplicationInfo> appInfos;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfosV9(
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), USERID, appInfos);
    EXPECT_EQ(getInfoResult, ERR_OK);

    bool isSubStrExist = false;
    for (int i = 1; i <= 3; i++) {
        std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
        for (auto iter = appInfos.begin(); iter != appInfos.end(); iter++) {
            if (IsSubStr(iter->name, appName)) {
                isSubStrExist = true;
                break;
            }
        }
        EXPECT_TRUE(isSubStrExist);
        std::vector<std::string> resvec2;
        Uninstall(appName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    }
    std::cout << "END GetApplicationInfosV9_0300" << std::endl;
}

/**
 * @tc.number: GetBundleArchiveInfo_0100
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive information without an ability information
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleArchiveInfo_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleArchiveInfo_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle3.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        int32_t flag = 0;

        BundleInfo bundleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool getInfoResult =
            bundleMgrProxy->GetBundleArchiveInfo(hapFilePath, flag, bundleInfo);
        EXPECT_TRUE(getInfoResult);
        EXPECT_EQ(bundleInfo.name, appName);
        std::string version = "1.0";
        EXPECT_EQ(bundleInfo.versionName, version);

        if (!getInfoResult) {
            APP_LOGI("GetBundleArchiveInfo_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleArchiveInfo_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleArchiveInfo_0100" << std::endl;
}

/**
 * @tc.number: GetBundleArchiveInfo_0200
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive with ability information
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleArchiveInfo_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleArchiveInfo_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string abilityName = "bmsThirdBundle_A1";
        std::string appName = BASE_BUNDLE_NAME + "1";

        BundleInfo bundleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool getInfoResult =
            bundleMgrProxy->GetBundleArchiveInfo(hapFilePath, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo);
        EXPECT_TRUE(getInfoResult);
        EXPECT_EQ(bundleInfo.name, appName);
        std::string version = "1.0";
        EXPECT_EQ(bundleInfo.versionName, version);

        bool isSubStrExist = false;
        for (auto abilityInfo : bundleInfo.abilityInfos) {
            if (IsSubStr(abilityInfo.name, abilityName)) {
                isSubStrExist = true;
                break;
            }
        }
        EXPECT_TRUE(isSubStrExist);

        if (!getInfoResult) {
            APP_LOGI("GetBundleArchiveInfo_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleArchiveInfo_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleArchiveInfo_0200" << std::endl;
}

/**
 * @tc.number: GetBundleArchiveInfo_0300
 * @tc.name: test query hap information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query hap information with wrong name
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleArchiveInfo_0300, Function | MediumTest | Level2)
{
    std::cout << "START GetBundleArchiveInfo_0300" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        BundleInfo bundleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string hapFilePath = THIRD_BUNDLE_PATH + "tt.hap";
        bool getInfoResult =
            bundleMgrProxy->GetBundleArchiveInfo(hapFilePath, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
        EXPECT_FALSE(getInfoResult);

        if (getInfoResult) {
            APP_LOGI("GetBundleArchiveInfo_0300 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleArchiveInfo_0300 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleArchiveInfo_0300" << std::endl;
}

/**
 * @tc.number: GetBundleArchiveInfo_0400
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive information failed without empty path
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleArchiveInfo_0400, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleArchiveInfo_0400" << std::endl;
    std::string appName = BASE_BUNDLE_NAME + "1";
    int32_t flag = 0;

    BundleInfo bundleInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bool getInfoResult =
        bundleMgrProxy->GetBundleArchiveInfo("", flag, bundleInfo);
    EXPECT_FALSE(getInfoResult);
    bool getInfoResult1 =
        bundleMgrProxy->GetBundleArchiveInfo("", BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
    EXPECT_FALSE(getInfoResult1);
    std::cout << "END GetBundleArchiveInfo_0400" << std::endl;
}

/**
 * @tc.number: GetBundleArchiveInfo_0500
 * @tc.name: test query  ".rpk" information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap with invalid suffix
 *           2.query the archive information
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleArchiveInfo_0500, Function | MediumTest | Level2)
{
    std::cout << "START GetBundleArchiveInfo_0500" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle28.rpk";

        BundleInfo bundleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool getInfoResult =
            bundleMgrProxy->GetBundleArchiveInfo(hapFilePath, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
        EXPECT_FALSE(getInfoResult);

        if (getInfoResult) {
            APP_LOGI("GetBundleArchiveInfo_0500 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleArchiveInfo_0500 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleArchiveInfo_0500" << std::endl;
}

/**
 * @tc.number: GetUidByBundleName_0100
 * @tc.name: test query UID
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query UID by bundleName
 */
HWTEST_F(ActsBmsKitSystemTest, GetUidByBundleName_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetUidByBundleName_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string bundleName = BASE_BUNDLE_NAME + "1";
        Install(hapFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        int uid = bundleMgrProxy->GetUidByBundleName(bundleName, USERID);
        EXPECT_GE(uid, Constants::BASE_USER_RANGE);
        resvec.clear();
        Uninstall(bundleName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (uid == Constants::INVALID_UID) {
            APP_LOGI("GetUidByBundleName_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetUidByBundleName_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetUidByBundleName_0100" << std::endl;
}

/**
 * @tc.number: GetUidByBundleName_0200
 * @tc.name: test query UID
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query UID by bundleName with wrong userid
 */
HWTEST_F(ActsBmsKitSystemTest, GetUidByBundleName_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetUidByBundleName_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string bundleName = BASE_BUNDLE_NAME + "1";
        Install(hapFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        int userId = Constants::INVALID_USERID;
        int uid = bundleMgrProxy->GetUidByBundleName(bundleName, userId);
        EXPECT_EQ(uid, Constants::INVALID_USERID);
        resvec.clear();
        Uninstall(bundleName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (uid != Constants::INVALID_UID) {
            APP_LOGI("GetUidByBundleName_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetUidByBundleName_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetUidByBundleName_0200" << std::endl;
}

/**
 * @tc.number: GetUidByBundleName_0300
 * @tc.name: test query UID
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query UID by wrong bundleName
 */
HWTEST_F(ActsBmsKitSystemTest, GetUidByBundleName_0300, Function | MediumTest | Level2)
{
    std::cout << "START GetUidByBundleName_0300" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string bundleName = BASE_BUNDLE_NAME + "1";
        Install(hapFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        int userId = Constants::DEFAULT_USERID;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bundleName = BASE_BUNDLE_NAME + "e";
        int uid = bundleMgrProxy->GetUidByBundleName(bundleName, userId);
        EXPECT_EQ(uid, Constants::INVALID_UID);

        resvec.clear();
        bundleName = BASE_BUNDLE_NAME + "1";
        Uninstall(bundleName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (uid != Constants::INVALID_UID) {
            APP_LOGI("GetUidByBundleName_0300 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetUidByBundleName_0300 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetUidByBundleName_0300" << std::endl;
}

/**
 * @tc.number: GetUidByBundleName_0400
 * @tc.name: test GetUidByBundleName interface
 * @tc.desc: 1.under '/system/app',there is a hap
 *           2.call GetUidByBundleName
 */
HWTEST_F(ActsBmsKitSystemTest, GetUidByBundleName_0400, Function | MediumTest | Level1)
{
    std::cout << "START GetUidByBundleName_0400" << std::endl;
    CommonTool commonTool;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    int uid = bundleMgrProxy->GetUidByBundleName(appName, USERID);
    EXPECT_GE(uid, Constants::BASE_USER_RANGE);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetUidByBundleName_0400" << std::endl;
}

/**
 * @tc.number: GetUidByBundleName_0500
 * @tc.name: test query UID
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query UID by empty bundleName
 */
HWTEST_F(ActsBmsKitSystemTest, GetUidByBundleName_0500, Function | MediumTest | Level1)
{
    std::cout << "START GetUidByBundleName_0500" << std::endl;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::string bundleName = "";
    int uid = bundleMgrProxy->GetUidByBundleName(bundleName, USERID);
    EXPECT_EQ(uid, Constants::INVALID_UID);
    std::cout << "END GetUidByBundleName_0500" << std::endl;
}

/**
 * @tc.number: GetBundleNameForUid_0100
 * @tc.name: test query bundlenames
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query bundlename by uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleNameForUid_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleNameForUid_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(hapFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        BundleInfo bundleInfo;
        bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
        int uid = bundleInfo.uid;

        std::string bundleName;
        bool getInfoResult = bundleMgrProxy->GetBundleNameForUid(uid, bundleName);
        EXPECT_TRUE(getInfoResult);
        EXPECT_EQ(bundleName, appName);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!getInfoResult) {
            APP_LOGI("GetBundleNameForUid_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleNameForUid_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleNameForUid_0100" << std::endl;
}

/**
 * @tc.number: GetBundleNameForUid_0200
 * @tc.name: test query bundlenames
 * @tc.desc: 1.query bundlename by uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleNameForUid_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleNameForUid_0200" << std::endl;
    CommonTool commonTool;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    int uid = bundleInfo.uid;

    std::string bundleName;
    bool getInfoResult = bundleMgrProxy->GetBundleNameForUid(uid, bundleName);
    EXPECT_TRUE(getInfoResult);
    EXPECT_EQ(bundleName, appName);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundleNameForUid_0200" << std::endl;
}

/**
 * @tc.number: GetBundleNameForUid_0300
 * @tc.name: test query bundlenames
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query bundlenames by wrong uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleNameForUid_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleNameForUid_0300" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        int uid = Constants::INVALID_UID;
        std::string bundleName;
        bool getInfoResult = bundleMgrProxy->GetBundleNameForUid(uid, bundleName);
        EXPECT_FALSE(getInfoResult);

        if (getInfoResult) {
            APP_LOGI("GetBundleNameForUid_0300 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleNameForUid_0300 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleNameForUid_0300" << std::endl;
}

/**
 * @tc.number: GetAppType_0100
 * @tc.name: test GetAppType interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call GetAppType
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppType_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetAppType_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string appType = bundleMgrProxy->GetAppType(appName);
        EXPECT_EQ(appType, Constants::EMPTY_STRING);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(appType.c_str(), "") != 0) {
            APP_LOGI("GetAppType_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetAppType_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetAppType_0100" << std::endl;
}

/**
 * @tc.number: GetAppType_0200
 * @tc.name: test GetAppType interface
 * @tc.desc: 1.under '/system/app/',there is a hap
 *           2.install the hap
 *           3.call GetAppType
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppType_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetAppType_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string appType = bundleMgrProxy->GetAppType(SYSTEM_SETTINGS_BUNDLE_NAME);
        EXPECT_EQ(appType, Constants::EMPTY_STRING);

        if (std::strcmp(appType.c_str(), "") != 0) {
            APP_LOGI("GetAppType_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetAppType_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetAppType_0200" << std::endl;
}

/**
 * @tc.number: GetAppType_0300
 * @tc.name: test GetAppType interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call GetAppType by wrong appName
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppType_0300, Function | MediumTest | Level2)
{
    std::cout << "START GetAppType_0300" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        std::string errName = BASE_BUNDLE_NAME + "e";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string appType = bundleMgrProxy->GetAppType(errName);
        EXPECT_EQ(appType, Constants::EMPTY_STRING);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(appType.c_str(), (Constants::EMPTY_STRING).c_str()) != 0) {
            APP_LOGI("GetAppType_0300 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetAppType_0300 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetAppType_0300" << std::endl;
}

/**
 * @tc.number: GetAppType_0400
 * @tc.name: test GetAppType interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call GetAppType by empty appName
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppType_0400, Function | MediumTest | Level2)
{
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string appType = bundleMgrProxy->GetAppType("");
        EXPECT_EQ(appType, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetAppType_0500
 * @tc.name: test GetAppType interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap with invalid suffix
 *           2.install the hap
 *           3.call GetAppType
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppType_0500, Function | MediumTest | Level2)
{
    std::cout << "START GetAppType_0500" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle28.rpk";
        std::string appName = BASE_BUNDLE_NAME + "5";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_NE(installResult, "Success");
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string appType = bundleMgrProxy->GetAppType(appName);
        EXPECT_EQ(appType, Constants::EMPTY_STRING);

        if (std::strcmp(appType.c_str(), (Constants::EMPTY_STRING).c_str()) != 0) {
            APP_LOGI("GetAppType_0500 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetAppType_0500 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetAppType_0500" << std::endl;
}

/**
 * @tc.number: GetAbilityLabel_0100
 * @tc.name: test GetAbilityLabel interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call GetAbilityLabel
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityLabel_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetAbilityLabel_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        std::string abilityName = "bmsThirdBundle_A1";
        std::string label = "$string:MainAbility_label";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string abilityLabel = bundleMgrProxy->GetAbilityLabel(appName, abilityName);
        ErrCode abilityLabel1 = bundleMgrProxy->GetAbilityLabel(appName, abilityName, BASE_MODULE_NAME, label);
        EXPECT_NE(abilityLabel, "EMPTY_STRING");
        EXPECT_NE(abilityLabel1, ERR_OK);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(abilityLabel.c_str(), "EMPTY_STRING") == 0) {
            APP_LOGI("GetAbilityLabel_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetAbilityLabel_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetAbilityLabel_0100" << std::endl;
}

/**
 * @tc.number: GetAbilityLabel_0300
 * @tc.name: test GetAbilityLabel interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call GetAbilityLabel with wrong appName
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityLabel_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetAbilityLabel_0300" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        std::string abilityName = "bmsThirdBundle_A1";
        std::string label = "$string:MainAbility_label";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string errAppName = BASE_BUNDLE_NAME + "e";
        std::string abilityLabel = bundleMgrProxy->GetAbilityLabel(errAppName, abilityName);
        ErrCode abilityLabel1 = bundleMgrProxy->GetAbilityLabel("", abilityName, BASE_MODULE_NAME, label);
        EXPECT_EQ(abilityLabel, Constants::EMPTY_STRING);
        EXPECT_NE(abilityLabel1, ERR_OK);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(abilityLabel.c_str(), (Constants::EMPTY_STRING).c_str()) != 0) {
            APP_LOGI("GetAbilityLabel_0300 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetAbilityLabel_0300 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetAbilityLabel_0300" << std::endl;
}

/**
 * @tc.number: GetAbilityLabel_0400
 * @tc.name: test GetAbilityLabel interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call GetAbilityLabel with wrong abilityname
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityLabel_0400, Function | MediumTest | Level1)
{
    std::cout << "START GetAbilityLabel_0400" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        std::string errAbilityName = "MainAbility";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string abilityLabel = bundleMgrProxy->GetAbilityLabel(appName, errAbilityName);
        EXPECT_EQ(abilityLabel, Constants::EMPTY_STRING);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(abilityLabel.c_str(), (Constants::EMPTY_STRING).c_str()) != 0) {
            APP_LOGI("GetAbilityLabel_0400 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetAbilityLabel_0400 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetAbilityLabel_0400" << std::endl;
}

/**
 * @tc.number: GetAbilityLabel_0500
 * @tc.name: test GetAbilityLabel interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call GetAbilityLabel with empty abilityname
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityLabel_0500, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::string abilityLabel = bundleMgrProxy->GetAbilityLabel("", "");
    EXPECT_EQ(abilityLabel, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetAbilityLabel_0600
 * @tc.name: test GetAbilityLabel interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap with invalid suffix
 *           2.install the hap
 *           3.call GetAbilityLabel
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityLabel_0600, Function | MediumTest | Level2)
{
    std::cout << "START GetAbilityLabel_0600" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle28.rpk";
        std::string appName = BASE_BUNDLE_NAME + "5";
        std::string abilityName = "MainAbility";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_NE(installResult, "Success");
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::string abilityLabel = bundleMgrProxy->GetAbilityLabel(appName, abilityName);
        EXPECT_EQ(abilityLabel, Constants::EMPTY_STRING);

        if (std::strcmp(abilityLabel.c_str(), (Constants::EMPTY_STRING).c_str()) != 0) {
            APP_LOGI("GetAbilityLabel_0600 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetAbilityLabel_0600 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetAbilityLabel_0600" << std::endl;
}

/**
 * @tc.number: GetHapModuleInfo_0100
 * @tc.name: test GetHapModuleInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap with one ability
 *           2.install the hap
 *           3.call GetHapModuleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetHapModuleInfo_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetHapModuleInfo_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        AbilityInfo abilityInfo;
        abilityInfo.bundleName = appName;
        abilityInfo.package = BASE_BUNDLE_NAME + ".h1";
        HapModuleInfo hapModuleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
        EXPECT_TRUE(queryResult);

        EXPECT_EQ(hapModuleInfo.name, "bmsThirdBundle1");
        EXPECT_EQ(hapModuleInfo.moduleName, "testability1");
        EXPECT_EQ(hapModuleInfo.description, "");

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!queryResult) {
            APP_LOGI("GetHapModuleInfo_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetHapModuleInfo_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetHapModuleInfo_0100" << std::endl;
}

/**
 * @tc.number: GetHapModuleInfo_0200
 * @tc.name: test GetHapModuleInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap with two abilities
 *           2.install the hap
 *           3.call GetHapModuleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetHapModuleInfo_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetHapModuleInfo_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle2.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);
        CommonTool commonTool;
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        AbilityInfo abilityInfo;
        abilityInfo.bundleName = appName;
        abilityInfo.package = BASE_BUNDLE_NAME + ".h1";
        HapModuleInfo hapModuleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
        EXPECT_TRUE(queryResult);
        EXPECT_EQ(hapModuleInfo.name, "bmsThirdBundle2");
        EXPECT_EQ(hapModuleInfo.moduleName, "testability");
        bool isSubStrExist = false;
        for (int i = 1; i <= 2; i++) {
            std::string abilityName = "" + std::to_string(i);
            for (auto hapModuleInfo : hapModuleInfo.abilityInfos) {
                if (IsSubStr(hapModuleInfo.name, abilityName)) {
                    isSubStrExist = true;
                    break;
                }
            }
            EXPECT_TRUE(isSubStrExist);
        }
        resvec.clear();
        Uninstall(appName, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "uninstall fail!";

        if (!queryResult) {
            APP_LOGI("GetHapModuleInfo_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }
    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetHapModuleInfo_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetHapModuleInfo_0200" << std::endl;
}

/**
 * @tc.number: GetHapModuleInfo_0300
 * @tc.name: test GetHapModuleInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap without an ability
 *           2.install the hap
 *           3.call GetHapModuleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetHapModuleInfo_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetHapModuleInfo_0300" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle3.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        AbilityInfo abilityInfo;
        abilityInfo.bundleName = appName;
        abilityInfo.package = BASE_BUNDLE_NAME + ".h1";
        HapModuleInfo hapModuleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
        EXPECT_TRUE(queryResult);
        EXPECT_EQ(hapModuleInfo.name, "bmsThirdBundle3");
        EXPECT_EQ(hapModuleInfo.moduleName, "testability3");
        resvec.clear();

        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!queryResult) {
            APP_LOGI("GetHapModuleInfo_0300 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetHapModuleInfo_0300 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetHapModuleInfo_0300" << std::endl;
}

/**
 * @tc.number: GetHapModuleInfo_0400
 * @tc.name: test GetHapModuleInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.use error bundleName to get moduleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetHapModuleInfo_0400, Function | MediumTest | Level1)
{
    std::cout << "START GetHapModuleInfo_0400" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap";
        std::string appName = BASE_BUNDLE_NAME + "2";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        AbilityInfo abilityInfo;
        abilityInfo.bundleName = "error_bundleName";
        abilityInfo.package = BASE_BUNDLE_NAME + ".h2";
        HapModuleInfo hapModuleInfo;

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
        EXPECT_FALSE(queryResult);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (queryResult) {
            APP_LOGI("GetHapModuleInfo_0400 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetHapModuleInfo_0400 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetHapModuleInfo_0400" << std::endl;
}

/**
 * @tc.number: GetHapModuleInfo_0500
 * @tc.name: test GetHapModuleInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.use empty bundleName to get moduleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetHapModuleInfo_0500, Function | MediumTest | Level1)
{
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = "";
    abilityInfo.package = BASE_BUNDLE_NAME + ".h2";
    HapModuleInfo hapModuleInfo;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_FALSE(queryResult);
}

/**
 * @tc.number: GetHapModuleInfo_0600
 * @tc.name: test GetHapModuleInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap with invalid suffix
 *           2.install the hap
 *           3.call GetHapModuleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetHapModuleInfo_0600, Function | MediumTest | Level2)
{
    std::cout << "START GetHapModuleInfo_0600" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle28.rpk";
        std::string appName = BASE_BUNDLE_NAME + "5";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_NE(installResult, "Success") << "install fail!";

        AbilityInfo abilityInfo;
        abilityInfo.bundleName = appName;
        abilityInfo.package = BASE_BUNDLE_NAME + ".h2";
        HapModuleInfo hapModuleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
        EXPECT_FALSE(queryResult);

        if (queryResult) {
            APP_LOGI("GetHapModuleInfo_0600 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetHapModuleInfo_0600 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetHapModuleInfo_0600" << std::endl;
}

/**
 * @tc.number: GetHapModuleInfo_0700
 * @tc.name: test GetHapModuleInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.use empty package to get moduleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetHapModuleInfo_0700, Function | MediumTest | Level1)
{
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap";
    abilityInfo.package = "";
    HapModuleInfo hapModuleInfo;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_FALSE(queryResult);
}

/**
 * @tc.number: GetHapModuleInfo_0800
 * @tc.name: test GetHapModuleInfo interface
 * @tc.desc: 1.bundleName and package is null
 */
HWTEST_F(ActsBmsKitSystemTest, GetHapModuleInfo_0800, Function | MediumTest | Level1)
{
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = "";
    abilityInfo.package = "package";
    HapModuleInfo hapModuleInfo;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_FALSE(queryResult);

    abilityInfo.bundleName = "bundleName";
    abilityInfo.package = "";

    queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_FALSE(queryResult);
}

/**
 * @tc.number: GetLaunchWantForBundle_0100
 * @tc.name: test GetLaunchWantForBundle interface
 * @tc.desc: 1.bundleNameis null
 */
HWTEST_F(ActsBmsKitSystemTest, GetLaunchWantForBundle_0100, Function | MediumTest | Level1)
{
    std::string bundleName = "";
    Want want;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    auto queryResult = bundleMgrProxy->GetLaunchWantForBundle(bundleName, want, USERID);
    EXPECT_NE(queryResult, ERR_OK);
}

/**
 * @tc.number: Callback_0100
 * @tc.name: 1.test RegisterBundleStatusCallback interface
 *           2.test UnregisterBundleStatusCallback interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists a normal hap
 *           2.call RegisterBundleStatusCallback
 *           3.install the hap
 *           4.call UnregisterBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_0100, Function | MediumTest | Level1)
{
    std::cout << "START Callback_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";

        CommonTool commonTool;
        sptr<BundleStatusCallbackImpl> bundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(bundleStatusCallback, nullptr);
        bundleStatusCallback->SetBundleName(appName);
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        bool unRegResult = bundleMgrProxy->UnregisterBundleStatusCallback();
        EXPECT_TRUE(unRegResult);

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!unRegResult) {
            APP_LOGI("Callback_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Callback_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END Callback_0100" << std::endl;
}

/**
 * @tc.number: Callback_0300
 * @tc.name: 1.test RegisterBundleStatusCallback interface
 *           2.test UnregisterBundleStatusCallback interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists two bundles,one's version is
 *                    higher than the other
 *           2.call RegisterBundleStatusCallback
 *           3.install the hap
 *           4.upgrade the hap
 *           5.call UnregisterBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_0300, Function | MediumTest | Level1)
{
    std::cout << "START Callback_0300" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string firstFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap";
        std::string appName = BASE_BUNDLE_NAME + "2";
        std::string secondFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle9.hap";

        CommonTool commonTool;
        sptr<BundleStatusCallbackImpl> bundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(bundleStatusCallback, nullptr);
        bundleStatusCallback->SetBundleName(appName);
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(firstFilePath, InstallFlag::NORMAL, resvec);
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        resvec.clear();
        Install(secondFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        std::string upgradeResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(upgradeResult, "Success") << "upgrade fail!";
        bool unRegResult = bundleMgrProxy->UnregisterBundleStatusCallback();
        EXPECT_TRUE(unRegResult);

        std::vector<std::string> resvec2;
        Uninstall(appName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!unRegResult) {
            APP_LOGI("Callback_0300 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Callback_0300 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END Callback_0300" << std::endl;
}

/**
 * @tc.number: Callback_0400
 * @tc.name: 1.test RegisterBundleStatusCallback interface
 *           2.test UnregisterBundleStatusCallback interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists two bundles,one's version is
 *                    equal than the other
 *           2.call RegisterBundleStatusCallback
 *           3.install the hap
 *           4.upgrade the hap
 *           5.call UnregisterBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_0400, Function | MediumTest | Level1)
{
    std::cout << "START Callback_0400" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string firstFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap";
        std::string appName = BASE_BUNDLE_NAME + "2";
        std::string secondFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle10.hap";

        CommonTool commonTool;
        sptr<BundleStatusCallbackImpl> bundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(bundleStatusCallback, nullptr);
        bundleStatusCallback->SetBundleName(appName);
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(firstFilePath, InstallFlag::NORMAL, resvec);
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        resvec.clear();
        Install(secondFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        std::string upgradeResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(upgradeResult, "Success") << "upgrade fail!";
        bool unRegResult = bundleMgrProxy->UnregisterBundleStatusCallback();
        EXPECT_TRUE(unRegResult);

        std::vector<std::string> resvec2;
        Uninstall(appName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!unRegResult) {
            APP_LOGI("Callback_0400 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Callback_0400 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END Callback_0400" << std::endl;
}

/**
 * @tc.number: Callback_0500
 * @tc.name: 1.test RegisterBundleStatusCallback interface
 *           2.test UnregisterBundleStatusCallback interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists two bundles,one's version is
 *                    lower than the other
 *           2.call RegisterBundleStatusCallback
 *           3.install the hap
 *           4.upgrade the hap
 *           5.call UnregisterBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_0500, Function | MediumTest | Level1)
{
    std::cout << "START Callback_0500" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string firstFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle9.hap";
        std::string appName = BASE_BUNDLE_NAME + "2";
        std::string secondFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle10.hap";

        CommonTool commonTool;
        sptr<BundleStatusCallbackImpl> bundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(bundleStatusCallback, nullptr);
        bundleStatusCallback->SetBundleName(appName);
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(firstFilePath, InstallFlag::NORMAL, resvec);
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        resvec.clear();
        Install(secondFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        std::string upgradeResult = commonTool.VectorToStr(resvec);
        EXPECT_NE(upgradeResult, "Success") << "upgrade success!";
        bool unRegResult = bundleMgrProxy->UnregisterBundleStatusCallback();
        EXPECT_TRUE(unRegResult);

        std::vector<std::string> resvec2;
        Uninstall(appName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!unRegResult) {
            APP_LOGI("Callback_0500 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Callback_0500 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END Callback_0500" << std::endl;
}

/**
 * @tc.number: Callback_0600
 * @tc.name: 1.test RegisterBundleStatusCallback interface
 *           2.test ClearBundleStatusCallback interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.call RegisterBundleStatusCallback
 *           3.install the hap
 *           4.call ClearBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_0600, Function | MediumTest | Level1)
{
    std::cout << "START Callback_0600" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string filePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";

        CommonTool commonTool;
        sptr<BundleStatusCallbackImpl> bundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(bundleStatusCallback, nullptr);
        bundleStatusCallback->SetBundleName(appName);
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(filePath, InstallFlag::NORMAL, resvec);
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        bool clearResult = bundleMgrProxy->ClearBundleStatusCallback(bundleStatusCallback);
        EXPECT_TRUE(clearResult);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!clearResult) {
            APP_LOGI("Callback_0600 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Callback_0600 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END Callback_0600" << std::endl;
}

/**
 * @tc.number: Callback_0700
 * @tc.name: 1.test RegisterBundleStatusCallback interface
 *           2.test ClearBundleStatusCallback interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there 1exists two bundles
 *           2.call RegisterBundleStatusCallback
 *           3.install the first hap
 *           4.call RegisterBundleStatusCallback
 *           5.install the second hap
 *           6.call ClearBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_0700, Function | MediumTest | Level1)
{
    std::cout << "START Callback_0700" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string firstFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string firstAppName = BASE_BUNDLE_NAME + "1";
        std::string secondFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap";
        std::string secondAppName = BASE_BUNDLE_NAME + "2";
        CommonTool commonTool;
        sptr<BundleStatusCallbackImpl> firstBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(firstBundleStatusCallback, nullptr);
        firstBundleStatusCallback->SetBundleName(firstAppName);
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bundleMgrProxy->RegisterBundleStatusCallback(firstBundleStatusCallback);
        Install(firstFilePath, InstallFlag::NORMAL, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        resvec.clear();
        sptr<BundleStatusCallbackImpl> secondBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(secondBundleStatusCallback, nullptr);
        secondBundleStatusCallback->SetBundleName(secondAppName);
        bundleMgrProxy->RegisterBundleStatusCallback(secondBundleStatusCallback);
        Install(secondFilePath, InstallFlag::NORMAL, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        bool clearResult = bundleMgrProxy->ClearBundleStatusCallback(firstBundleStatusCallback);
        EXPECT_TRUE(clearResult);
        std::vector<std::string> resvec2;
        Uninstall(firstAppName, resvec2);
        EXPECT_EQ(commonTool.VectorToStr(resvec2), "Success") << "uninstall fail!";
        resvec2.clear();
        Uninstall(secondAppName, resvec2);
        EXPECT_EQ(commonTool.VectorToStr(resvec2), "Success") << "uninstall fail!";
        if (!clearResult) {
            APP_LOGI("Callback_0700 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }
    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Callback_0700 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END Callback_0700" << std::endl;
}

/**
 * @tc.number: Callback_0800
 * @tc.name: 1.test RegisterBundleStatusCallback interface
 *           2.test ClearBundleStatusCallback interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists two bundles
 *           2.call RegisterBundleStatusCallback
 *           3.install the first hap
 *           4.call RegisterBundleStatusCallback
 *           5.install the second hap
 *           6.call ClearBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_0800, Function | MediumTest | Level1)
{
    std::cout << "START Callback_0800" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string firstFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string firstAppName = BASE_BUNDLE_NAME + "1";
        std::string secondFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap";
        std::string secondAppName = BASE_BUNDLE_NAME + "2";
        CommonTool commonTool;
        sptr<BundleStatusCallbackImpl> firstBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(firstBundleStatusCallback, nullptr);
        firstBundleStatusCallback->SetBundleName(firstAppName);
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bundleMgrProxy->RegisterBundleStatusCallback(firstBundleStatusCallback);
        Install(firstFilePath, InstallFlag::NORMAL, resvec);
        std::string firstinstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(firstinstallResult, "Success") << "install fail!";
        resvec.clear();
        sptr<BundleStatusCallbackImpl> secondBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(secondBundleStatusCallback, nullptr);
        secondBundleStatusCallback->SetBundleName(secondAppName);
        bundleMgrProxy->RegisterBundleStatusCallback(secondBundleStatusCallback);
        Install(secondFilePath, InstallFlag::NORMAL, resvec);
        std::string secondinstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(secondinstallResult, "Success") << "install fail!";
        bool clearResult = bundleMgrProxy->ClearBundleStatusCallback(secondBundleStatusCallback);
        EXPECT_TRUE(clearResult);
        std::vector<std::string> resvec2;
        Uninstall(firstAppName, resvec2);
        EXPECT_EQ(commonTool.VectorToStr(resvec2), "Success") << "uninstall fail!";
        resvec2.clear();
        Uninstall(secondAppName, resvec2);
        EXPECT_EQ(commonTool.VectorToStr(resvec2), "Success") << "uninstall fail!";
        if (!clearResult) {
            APP_LOGI("Callback_0800 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }
    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Callback_0800 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END Callback_0800" << std::endl;
}

/**
 * @tc.number: Callback_0900
 * @tc.name: 1.test RegisterBundleStatusCallback interface
 *           2.test ClearBundleStatusCallback interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists two bundles
 *           2.call RegisterBundleStatusCallback
 *           3.install the first hap
 *           4.call RegisterBundleStatusCallback
 *           5.install the second hap
 *           6.call ClearBundleStatusCallback
 *           7.call ClearBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_0900, Function | MediumTest | Level1)
{
    std::cout << "START Callback_0900" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string firstFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string firstAppName = BASE_BUNDLE_NAME + "1";
        std::string secondFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap";
        std::string secondAppName = BASE_BUNDLE_NAME + "2";
        CommonTool commonTool;
        sptr<BundleStatusCallbackImpl> firstBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(firstBundleStatusCallback, nullptr);
        firstBundleStatusCallback->SetBundleName(firstAppName);
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bundleMgrProxy->RegisterBundleStatusCallback(firstBundleStatusCallback);
        Install(firstFilePath, InstallFlag::NORMAL, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        resvec.clear();
        sptr<BundleStatusCallbackImpl> secondBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(secondBundleStatusCallback, nullptr);
        secondBundleStatusCallback->SetBundleName(secondAppName);
        bundleMgrProxy->RegisterBundleStatusCallback(secondBundleStatusCallback);
        Install(secondFilePath, InstallFlag::NORMAL, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        bool clearResult1 = bundleMgrProxy->ClearBundleStatusCallback(firstBundleStatusCallback);
        EXPECT_TRUE(clearResult1);
        bool clearResult2 = bundleMgrProxy->ClearBundleStatusCallback(secondBundleStatusCallback);
        EXPECT_TRUE(clearResult2);
        std::vector<std::string> resvec2;
        Uninstall(firstAppName, resvec2);
        EXPECT_EQ(commonTool.VectorToStr(resvec2), "Success") << "uninstall fail!";
        resvec2.clear();
        Uninstall(secondAppName, resvec2);
        EXPECT_EQ(commonTool.VectorToStr(resvec2), "Success") << "uninstall fail!";
        if (!clearResult1 && !clearResult2) {
            APP_LOGI("Callback_0900 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }
    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Callback_0900 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END Callback_0900" << std::endl;
}

/**
 * @tc.number: Callback_1000
 * @tc.name: Test SetBundleName
 * @tc.desc: 1.Test the SetBundleName of IBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_1000, Function | MediumTest | Level1)
{
    sptr<IBundleStatusCallback> callBack = (new (std::nothrow) BundleStatusCallbackImpl());
    EXPECT_NE(callBack, nullptr);
    callBack->SetBundleName(BASE_BUNDLE_NAME);
    std::string ret = callBack->GetBundleName();
    EXPECT_EQ(ret, BASE_BUNDLE_NAME);
}

/**
 * @tc.number: QueryAbilityInfo_0100
 * @tc.name: test QueryAbilityInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call QueryAbilityInfo
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfo_0100, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfo_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        std::string abilityName = "bmsThirdBundle_A1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        Want want;
        ElementName name;
        name.SetAbilityName(abilityName);
        name.SetBundleName(appName);
        want.SetElement(name);

        AbilityInfo abilityInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        int32_t flags = 4;
        bool queryResult = bundleMgrProxy->QueryAbilityInfo(want, flags, USERID, abilityInfo);
        EXPECT_TRUE(queryResult);
        EXPECT_EQ(abilityInfo.name, abilityName);
        EXPECT_EQ(abilityInfo.bundleName, appName);

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!queryResult) {
            APP_LOGI("QueryAbilityInfo_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("QueryAbilityInfo_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END QueryAbilityInfo_0100" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfo_0200
 * @tc.name: QueryAbilityInfo
 * @tc.desc: query data then verify
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfo_0200, Function | MediumTest | Level0)
{
    std::cout << "START QueryAbilityInfo_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle3.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        std::string abilityName = "bmsThirdBundle_A1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        Want want;
        ElementName name;
        name.SetBundleName("xxx");
        want.SetElement(name);

        AbilityInfo abilityInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool queryResult =
        bundleMgrProxy->QueryAbilityInfo(want, GET_ABILITY_INFO_WITH_APPLICATION, USERID, abilityInfo);
        EXPECT_FALSE(queryResult);

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (queryResult) {
            APP_LOGI("QueryAbilityInfo_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("QueryAbilityInfo_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END QueryAbilityInfo_0200" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfo_0300
 * @tc.name: test QueryAbilityInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call QueryAbilityInfo
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfo_0300, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfo_0300" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        std::string abilityName = "bmsThirdBundle_A1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        Want want;
        ElementName name;
        name.SetAbilityName(abilityName);
        name.SetBundleName(appName);
        want.SetElement(name);

        AbilityInfo abilityInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool queryResult =
            bundleMgrProxy->QueryAbilityInfo(want, GET_ABILITY_INFO_WITH_APPLICATION, USERID, abilityInfo);
        EXPECT_TRUE(queryResult);
        EXPECT_EQ(abilityInfo.targetAbility, "");

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!queryResult) {
            APP_LOGI("QueryAbilityInfo_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("QueryAbilityInfo_0300 succecc - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END QueryAbilityInfo_0300" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfo_0400
 * @tc.name: test QueryAbilityInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call QueryAbilityInfo
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfo_0400, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfo_0400" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        std::string abilityName = "bmsThirdBundle_A1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        Want want;
        ElementName name;
        name.SetAbilityName(abilityName);
        name.SetBundleName(appName);
        want.SetElement(name);

        AbilityInfo abilityInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool queryResult =
            bundleMgrProxy->QueryAbilityInfo(
                want, GET_ABILITY_INFO_WITH_APPLICATION, USERID, abilityInfo, nullptr);
        EXPECT_FALSE(queryResult);

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!queryResult) {
            APP_LOGI("QueryAbilityInfo_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("QueryAbilityInfo_0400 succecc - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_FALSE(result);
    std::cout << "END QueryAbilityInfo_0400" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfo_0500
 * @tc.name: test QueryAbilityInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call QueryAbilityInfo
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfo_0500, Function | MediumTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    std::string abilityName = "bmsThirdBundle_A1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);

    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    Want want;
    ElementName name;
    name.SetAbilityName(abilityName);
    name.SetBundleName(appName);
    want.SetElement(name);
    sptr<IRemoteObject> callBack;
    int32_t flags = 0;

    AbilityInfo abilityInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bool queryResult =
        bundleMgrProxy->QueryAbilityInfo(
            want, flags, USERID, abilityInfo, callBack);
    EXPECT_FALSE(queryResult);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: GetBundleInfosByMetaData_0100
 * @tc.name: test GetBundleInfosByMetaData interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call GetBundleInfosByMetaData
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfosByMetaData_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfosByMetaData_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle17.hap";
        std::string appName = "com.third.hiworld.example6";

        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        std::vector<BundleInfo> bundleInfos;

        std::string metadata = "string";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool getResult = bundleMgrProxy->GetBundleInfosByMetaData(metadata, bundleInfos);
        EXPECT_TRUE(getResult);

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!getResult) {
            APP_LOGI("GetBundleInfosByMetaData_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleInfosByMetaData_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleInfosByMetaData_0100" << std::endl;
}

/**
 * @tc.number: GetBundleInfosByMetaData_0200
 * @tc.name: test GetBundleInfosByMetaData interface
 * @tc.desc: 1.call GetBundleInfosByMetaData
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfosByMetaData_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfosByMetaData_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<BundleInfo> bundleInfos;
        std::string metadata = "not_exist";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool getResult = bundleMgrProxy->GetBundleInfosByMetaData(metadata, bundleInfos);
        EXPECT_FALSE(getResult);
        if (getResult) {
            APP_LOGI("GetBundleInfosByMetaData_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundleInfosByMetaData_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundleInfosByMetaData_0200" << std::endl;
}

/**
 * @tc.number: GetBundleInfosByMetaData_0300
 * @tc.name: test GetBundleInfosByMetaData interface
 * @tc.desc: 1.call GetBundleInfosByMetaData
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfosByMetaData_0300, Function | MediumTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bool getResult = bundleMgrProxy->GetBundleInfosByMetaData("", bundleInfos);
    EXPECT_FALSE(getResult);
}

/**
 * @tc.number: AbilityDump_0100
 * @tc.name: Dump
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists a hap
 *           2.install the hap
 *           3.call "QueryAbilityInfo" kit
 *           4.Dump abilityInfo
 */
HWTEST_F(ActsBmsKitSystemTest, AbilityDump_0100, Function | MediumTest | Level0)
{
    std::cout << "START AbilityDump_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        std::string abilityName = "bmsThirdBundle_A1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);
        CommonTool commonTool;
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        Want want;
        ElementName name;
        name.SetAbilityName(abilityName);
        name.SetBundleName(appName);
        want.SetElement(name);

        AbilityInfo abilityInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool queryResult =
            bundleMgrProxy->QueryAbilityInfo(want, GET_ABILITY_INFO_WITH_APPLICATION, USERID, abilityInfo);
        EXPECT_EQ(abilityInfo.name, abilityName);
        EXPECT_TRUE(queryResult);
        std::string path = "/data/test/abilityInfo.txt";
        std::ofstream file(path);
        file.close();
        int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
        EXPECT_NE(fd, -1) << "open file error";
        std::string prefix = "[ability]";
        abilityInfo.Dump(prefix, fd);
        long length = lseek(fd, 0, SEEK_END);
        EXPECT_GT(length, 0);
        close(fd);
        resvec.clear();
        Uninstall(appName, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "uninstall fail!";
        if (!queryResult) {
            APP_LOGI("AbilityDump_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }
    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("AbilityDump_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END AbilityDump_0100" << std::endl;
}

/**
 * @tc.number: ApplicationInfoDump_0100
 * @tc.name: Dump
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists a hap
 *           2.install the hap
 *           3.call "GetApplicationInfo" kit
 *           4.Dump appInfo
 */
HWTEST_F(ActsBmsKitSystemTest, ApplicationInfoDump_0100, Function | MediumTest | Level1)
{
    std::cout << "START ApplicationInfoDump_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        ApplicationInfo appInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfo(appName, 0, USERID, appInfo);
        EXPECT_TRUE(getInfoResult);
        EXPECT_EQ(appInfo.name, appName);

        std::string path = "/data/test/appInfo.txt";
        std::ofstream file(path);
        file.close();
        int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
        EXPECT_NE(fd, -1) << "open file error";
        std::string prefix = "[appInfo]";
        appInfo.Dump(prefix, fd);
        long length = lseek(fd, 0, SEEK_END);
        EXPECT_GT(length, 0);
        close(fd);

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (!getInfoResult) {
            APP_LOGI("ApplicationInfoDump_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("ApplicationInfoDump_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END ApplicationInfoDump_0100" << std::endl;
}

/**
 * @tc.number: Errors_0100
 * @tc.name: test error hap
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists an error hap
 *           2.install the hap
 *           3.get ERR_INSTALL_ALREADY_EXIST
 */
HWTEST_F(ActsBmsKitSystemTest, Errors_0100, Function | MediumTest | Level1)
{
    std::cout << "Errors_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;

        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        resvec.clear();
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);
        installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Failure[ERR_INSTALL_ALREADY_EXIST]");

        std::vector<std::string> resvec2;
        Uninstall(appName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(installResult.c_str(), "Success") == 0) {
            APP_LOGI("Errors_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Errors_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "Errors_0100" << std::endl;
}

/**
 * @tc.number: Errors_0200
 * @tc.name: test error hap
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists an error hap
 *           2.install the hap
 *           3.get ERR_INSTALL_VERSION_DOWNGRADE
 */
HWTEST_F(ActsBmsKitSystemTest, Errors_0200, Function | MediumTest | Level1)
{
    std::cout << "Errors_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle9.hap";
        std::string bundleName = BASE_BUNDLE_NAME + "2";
        std::vector<std::string> resvec;
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);
        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        resvec.clear();
        bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap";
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Failure[ERR_INSTALL_VERSION_DOWNGRADE]");

        std::vector<std::string> resvec2;
        Uninstall(bundleName, resvec2);
        std::string uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(installResult.c_str(), "Success") == 0) {
            APP_LOGI("Errors_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Errors_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "Errors_0200" << std::endl;
}

/**
 * @tc.number: Errors_0500
 * @tc.name: test error hap
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists a invalid hap
 *           2.install the hap
 *           3.get ERR_INSTALL_INVALID_HAP_NAME
 */
HWTEST_F(ActsBmsKitSystemTest, Errors_0500, Function | MediumTest | Level1)
{
    std::cout << "Errors_0500" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle12.rpk";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Failure[ERR_INSTALL_INVALID_HAP_NAME]");
        if (std::strcmp(installResult.c_str(), "Success") == 0) {
            APP_LOGI("Errors_0500 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Errors_0500 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "Errors_0500" << std::endl;
}

/**
 * @tc.number: Errors_0600
 * @tc.name: test error hap
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists an error hap
 *           2.install the hap
 *           3.get MSG_ERR_INSTALL_FILE_PATH_INVALID
 */
HWTEST_F(ActsBmsKitSystemTest, Errors_0600, Function | MediumTest | Level1)
{
    std::cout << "Errors_0600" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "e.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;

        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Failure[MSG_ERR_INSTALL_FILE_PATH_INVALID]");
        if (std::strcmp(installResult.c_str(), "Success") == 0) {
            APP_LOGI("Errors_0600 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Errors_0600 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "Errors_0600" << std::endl;
}

/**
 * @tc.number: Errors_0700
 * @tc.name: test error hap
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists an error hap
 *           2.install the hap
 *           3.uninstall hap with wrong appName
 *           4.get ERR_UNINSTALL_MISSING_INSTALLED_BUNDLE
 */
HWTEST_F(ActsBmsKitSystemTest, Errors_0700, Function | MediumTest | Level1)
{
    std::cout << "Errors_0700" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;

        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        resvec.clear();
        appName = BASE_BUNDLE_NAME + "1";
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        std::vector<std::string> resvec2;
        appName = BASE_BUNDLE_NAME + "e";
        Uninstall(appName, resvec2);
        uninstallResult = commonTool.VectorToStr(resvec2);
        EXPECT_EQ(uninstallResult, "Failure[ERR_UNINSTALL_MISSING_INSTALLED_BUNDLE]");

        if (std::strcmp(uninstallResult.c_str(), "Success") == 0) {
            APP_LOGI("Errors_0700 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Errors_0700 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "Errors_0700" << std::endl;
}

/**
 * @tc.number: Errors_0800
 * @tc.name: test error hap
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists an error hap
 *           2.install the hap
 *           3.uninstall hap twice
 *           4.get ERR_UNINSTALL_MISSING_INSTALLED_BUNDLE
 */
HWTEST_F(ActsBmsKitSystemTest, Errors_0800, Function | MediumTest | Level1)
{
    std::cout << "Errors_0800" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);

        CommonTool commonTool;

        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        resvec.clear();
        Uninstall(appName, resvec);
        uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Failure[ERR_UNINSTALL_MISSING_INSTALLED_BUNDLE]");
        if (std::strcmp(uninstallResult.c_str(), "Success") == 0) {
            APP_LOGI("Errors_0800 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Errors_0800 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "Errors_0800" << std::endl;
}

/**
 * @tc.number: Errors_0900
 * @tc.name: test error hap
 * @tc.desc: 1.under '/data/test/bms_bundle',there not exists a hap
 *           2.uninstall the hap
 *           3.get MSG_ERR_UNINSTALL_SYSTEM_APP_ERROR
 */
HWTEST_F(ActsBmsKitSystemTest, Errors_0900, Function | MediumTest | Level1)
{
    std::cout << "Errors_0900" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string appName = "com.ohos.systemui";
        CommonTool commonTool;

        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_NE(uninstallResult, "Success");
        if (std::strcmp(uninstallResult.c_str(), "Success") == 0) {
            APP_LOGI("Errors_0900 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("Errors_0900 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "Errors_0900" << std::endl;
}

/**
 * @tc.number: ApplicationInfo_0100
 * @tc.name: struct ApplicationInfo
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists a hap
 *           2.install the hap
 *           3.call dump
 *           4.check the appInfo in file
 */
HWTEST_F(ActsBmsKitSystemTest, ApplicationInfo_0100, Function | MediumTest | Level1)
{
    std::cout << "START ApplicationInfo_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        std::vector<std::string> resvec;
        std::string appName = BASE_BUNDLE_NAME + "1";
        Install(THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap", InstallFlag::NORMAL, resvec);
        CommonTool commonTool;
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        ApplicationInfo appInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfo(appName, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, appInfo);
        EXPECT_TRUE(getInfoResult);
        EXPECT_EQ(appInfo.name, appName);
        ApplicationInfo *pAppInfo = &appInfo;
        std::string path = "/data/test/pAppInfo_01.txt";
        std::ofstream file(path);
        file.close();
        int fd = open(path.c_str(), O_RDWR);
        EXPECT_NE(fd, -1) << "open file error";
        pAppInfo->Dump("[pAppInfo]", fd);
        long length = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        std::string strAppInfo;
        strAppInfo.resize(length - 1);
        ssize_t retVal = read(fd, strAppInfo.data(), length);
        EXPECT_GT(retVal, 0);
        EXPECT_TRUE(IsSubStr(strAppInfo, appName));
        close(fd);
        resvec.clear();
        Uninstall(appName, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "uninstall fail!";
        if (retVal <= 0) {
            APP_LOGI("ApplicationInfo_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }
    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("ApplicationInfo_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END ApplicationInfo_0100" << std::endl;
}

/**
 * @tc.number: ApplicationInfo_0200
 * @tc.name: struct ApplicationInfo
 * @tc.desc: 1.init appInfo structure
 *           2.Dump the pAppInfo
 */
HWTEST_F(ActsBmsKitSystemTest, ApplicationInfo_0200, Function | MediumTest | Level1)
{
    std::cout << "START ApplicationInfo_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        ApplicationInfo appInfo;
        appInfo.bundleName = "com.third.hiworld.example_02";
        appInfo.label = "bmsThirdBundle_A1 Ability";
        appInfo.description = "example helloworld";
        appInfo.deviceId = Constants::CURRENT_DEVICE_ID;
        appInfo.isSystemApp = false;

        ApplicationInfo *pAppInfo = &appInfo;
        std::string path = "/data/test/pAppInfo_02.txt";
        std::ofstream file(path);
        file.close();
        int fd = open(path.c_str(), O_RDWR | O_CLOEXEC);
        EXPECT_NE(fd, -1) << "open file error";
        std::string prefix = "[pAppInfo]";
        pAppInfo->Dump(prefix, fd);
        long length = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        std::string strAppInfo;
        strAppInfo.resize(length - 1);
        ssize_t retVal = read(fd, strAppInfo.data(), length);
        EXPECT_GT(retVal, 0);
        EXPECT_TRUE(IsSubStr(strAppInfo, appInfo.bundleName));
        EXPECT_TRUE(IsSubStr(strAppInfo, appInfo.label));
        EXPECT_TRUE(IsSubStr(strAppInfo, appInfo.description));
        close(fd);

        if (retVal <= 0) {
            APP_LOGI("ApplicationInfo_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("ApplicationInfo_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END ApplicationInfo_0200" << std::endl;
}

/**
 * @tc.number: QueryKeepAliveBundleInfos_0100
 * @tc.name: test QueryKeepAliveBundleInfos interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap,whose keepAlive-property's value is true
 *           2.install the hap
 *           3.call QueryKeepAliveBundleInfos
 */
HWTEST_F(ActsBmsKitSystemTest, QueryKeepAliveBundleInfos_0100, Function | MediumTest | Level1)
{
    std::cout << "START QueryKeepAliveBundleInfos_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);

    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGI("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    std::vector<BundleInfo> bundleInfos;
    bool result = bundleMgrProxy->QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_TRUE(result);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END QueryKeepAliveBundleInfos_0100" << std::endl;
}

/**
 * @tc.number: QueryKeepAliveBundleInfos_0200
 * @tc.name: test QueryKeepAliveBundleInfos interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap,whose keepAlive-property's value is false
 *           2.install the hap
 *           3.call QueryKeepAliveBundleInfos
 */
HWTEST_F(ActsBmsKitSystemTest, QueryKeepAliveBundleInfos_0200, Function | MediumTest | Level2)
{
    std::cout << "START QueryKeepAliveBundleInfos_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle2.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);

    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGI("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    std::vector<BundleInfo> bundleInfos;
    bool result = bundleMgrProxy->QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_TRUE(result);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END QueryKeepAliveBundleInfos_0100" << std::endl;
}

/**
 * @tc.number: Uninstall_KeepData_0100
 * @tc.name: test whether to keep user data when the app is uninstalled
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.uninstall the hap
 */
HWTEST_F(ActsBmsKitSystemTest, Uninstall_KeepData_0100, Function | MediumTest | Level2)
{
    std::cout << "START Uninstall_KeepData_0100" << std::endl;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";

    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        EXPECT_EQ(installerProxy, nullptr);
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    installParam.isKeepData = false;
    sptr<StatusReceiverImpl> statusReceiver = (new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    std::string installMsg = statusReceiver->GetResultMsg();
    EXPECT_EQ(installMsg, "Success") << "install fail!";
    std::string appName = BASE_BUNDLE_NAME + "1";

    std::vector<std::string> resvec;
    Uninstall(appName, resvec);
    CommonTool commonTool;
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    CheckFileNonExist(appName);
    std::cout << "END Uninstall_KeepData_0100" << std::endl;
}

/**
 * @tc.number: Uninstall_KeepData_0200
 * @tc.name: test whether to keep user data when the app is uninstalled
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.uninstall the hap
 */
HWTEST_F(ActsBmsKitSystemTest, Uninstall_KeepData_0200, Function | MediumTest | Level2)
{
    std::cout << "START Uninstall_KeepData_0200" << std::endl;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle2.hap";

    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        EXPECT_EQ(installerProxy, nullptr);
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    installParam.isKeepData = true;
    sptr<StatusReceiverImpl> statusReceiver = (new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    std::string installMsg = statusReceiver->GetResultMsg();
    EXPECT_EQ(installMsg, "Success") << "install fail!";
    std::string appName = BASE_BUNDLE_NAME + "1";

    std::vector<std::string> resvec;
    Uninstall(appName, resvec);
    CommonTool commonTool;
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END Uninstall_KeepData_0200" << std::endl;
}

/**
 * @tc.number: Uninstall_KeepData_0300
 * @tc.name: test whether to keep user data when the hap is uninstalled
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.uninstall the hap
 */
HWTEST_F(ActsBmsKitSystemTest, Uninstall_KeepData_0300, Function | MediumTest | Level2)
{
    std::cout << "START Uninstall_KeepData_0300" << std::endl;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle2.hap";

    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        EXPECT_EQ(installerProxy, nullptr);
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    installParam.isKeepData = false;
    sptr<StatusReceiverImpl> statusReceiver = (new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    std::string installMsg = statusReceiver->GetResultMsg();
    EXPECT_EQ(installMsg, "Success") << "install fail!";

    bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle4.hap";
    sptr<StatusReceiverImpl> statusReceiver2 = (new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver2, nullptr);
    installerProxy->Install(bundleFilePath, installParam, statusReceiver2);
    installMsg = statusReceiver2->GetResultMsg();
    EXPECT_EQ(installMsg, "Success") << "install fail!";

    std::string appName = BASE_BUNDLE_NAME + "1";

    std::vector<std::string> resvec;
    std::string bundleName = BASE_BUNDLE_NAME + "1";
    std::string modulePackage = BASE_BUNDLE_NAME + ".h1";
    HapUninstall(bundleName, modulePackage, resvec);
    CommonTool commonTool;
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall hap fail!";
    resvec.clear();
    Uninstall(appName, resvec);
    uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END Uninstall_KeepData_0300" << std::endl;
}

/**
 * @tc.number: Uninstall_KeepData_0400
 * @tc.name: test whether to keep user data when the hap is uninstalled
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.uninstall the hap
 */
HWTEST_F(ActsBmsKitSystemTest, Uninstall_KeepData_0400, Function | MediumTest | Level2)
{
    std::cout << "START Uninstall_KeepData_0400" << std::endl;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle2.hap";

    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        EXPECT_EQ(installerProxy, nullptr);
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    installParam.isKeepData = true;
    sptr<StatusReceiverImpl> statusReceiver = (new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    std::string installMsg = statusReceiver->GetResultMsg();
    EXPECT_EQ(installMsg, "Success") << "install fail!";

    bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle4.hap";
    sptr<StatusReceiverImpl> statusReceiver2 = (new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver2, nullptr);
    installerProxy->Install(bundleFilePath, installParam, statusReceiver2);
    installMsg = statusReceiver2->GetResultMsg();
    EXPECT_EQ(installMsg, "Success") << "install fail!";

    std::string appName = BASE_BUNDLE_NAME + "1";
    std::vector<std::string> resvec;
    std::string bundleName = BASE_BUNDLE_NAME + "1";
    std::string modulePackage = BASE_BUNDLE_NAME + ".h1";
    HapUninstall(bundleName, modulePackage, resvec);
    CommonTool commonTool;
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall hap fail!";
    resvec.clear();
    Uninstall(appName, resvec);
    uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END Uninstall_KeepData_0400" << std::endl;
}

/**
 * @tc.number: GetBundlesForUid_0100
 * @tc.name: test GetBundlesForUid interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there exist three bundles
 *           2.install these apps
 *           3.query all bundles by uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundlesForUid_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundlesForUid_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        CommonTool commonTool;
        for (int i = 6; i <= 8; i++) {
            std::vector<std::string> resvec;
            std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
            Install(hapFilePath, InstallFlag::NORMAL, resvec);
            EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        }
        bool ret;
        for (int i = 1; i <= 3; i++) {
            std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
            BundleInfo bundleInfo;
            bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
            std::vector<std::string> bundleNames;
            ret = bundleMgrProxy->GetBundlesForUid(bundleInfo.uid, bundleNames);
            EXPECT_TRUE(ret);
        }
        for (int i = 1; i <= 3; i++) {
            std::vector<std::string> resvec;
            std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
            Uninstall(appName, resvec);
            EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "uninstall fail!";
        }
        if (!ret) {
            APP_LOGI("GetBundlesForUid_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }
    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundlesForUid_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundlesForUid_0100" << std::endl;
}

/**
 * @tc.number: GetBundlesForUid_0200
 * @tc.name: test GetBundlesForUid interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a bundle
 *           2.install the hap
 *           3.query bundles by wrong uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundlesForUid_0200, Function | MediumTest | Level2)
{
    std::cout << "START GetBundlesForUid_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        std::vector<std::string> bundleNames;
        bool ret = bundleMgrProxy->GetBundlesForUid(Constants::INVALID_UID, bundleNames);
        EXPECT_FALSE(ret);
        if (ret) {
            APP_LOGI("GetBundlesForUid_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }
    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetBundlesForUid_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetBundlesForUid_0200" << std::endl;
}

/**
 * @tc.number: GetBundlesForUid_0300
 * @tc.name: test GetBundlesForUid interface
 * @tc.desc: 1.query bundles by uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundlesForUid_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetBundlesForUid_0300" << std::endl;
    CommonTool commonTool;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    int uid = bundleInfo.uid;
    std::vector<std::string> bundleNames;
    bool ret = bundleMgrProxy->GetBundlesForUid(uid, bundleNames);
    EXPECT_TRUE(ret);
    for (auto bundleName : bundleNames) {
        EXPECT_EQ(bundleName, appName);
    }

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundlesForUid_0300" << std::endl;
}

/**
 * @tc.number: GetNameForUid_0100
 * @tc.name: test GetNameForUid interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there are two apps
 *           2.install fist hap
 *           3.get first hap name by uid
 *           4.uninstall first hap
 *           5.install second hap
 *           6.install first hap
 *           7.get first hap name by uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetNameForUid_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetNameForUid_0100" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        CommonTool commonTool;
        std::vector<std::string> resvec;
        std::string name1, name2;
        Install(THIRD_BUNDLE_PATH + "bmsThirdBundle6.hap", InstallFlag::NORMAL, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        resvec.clear();
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        BundleInfo bundleInfo1;
        bundleMgrProxy->GetBundleInfo(BASE_BUNDLE_NAME + '1', BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
        ErrCode ret = bundleMgrProxy->GetNameForUid(bundleInfo1.uid, name1);
        EXPECT_EQ(ret, ERR_OK);
        Uninstall(BASE_BUNDLE_NAME + '1', resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "uninstall fail!";
        resvec.clear();
        Install(THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap", InstallFlag::NORMAL, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        resvec.clear();
        Install(THIRD_BUNDLE_PATH + "bmsThirdBundle6.hap", InstallFlag::NORMAL, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        BundleInfo bundleInfo2;
        bundleMgrProxy->GetBundleInfo(BASE_BUNDLE_NAME + '1', BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, USERID);
        ret = bundleMgrProxy->GetNameForUid(bundleInfo2.uid, name2);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_NE(bundleInfo1.uid, bundleInfo2.uid);
        EXPECT_EQ(name1, name2);
        for (int i = 1; i <= 2; i++) {
            std::string appName = BASE_BUNDLE_NAME + std::to_string(i);
            std::vector<std::string> resvec2;
            Uninstall(appName, resvec2);
            EXPECT_EQ(commonTool.VectorToStr(resvec2), "Success") << "uninstall fail!";
        }
        if (ret != ERR_OK) {
            APP_LOGI("GetNameForUid_0100 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }
    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetNameForUid_0100 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_TRUE(result);
    std::cout << "END GetNameForUid_0100" << std::endl;
}

/**
 * @tc.number: GetNameForUid_0200
 * @tc.name: test GetNameForUid interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get name by wrong uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetNameForUid_0200, Function | MediumTest | Level2)
{
    std::cout << "START GetNameForUid_0200" << std::endl;
    bool result = false;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        CommonTool commonTool;
        std::string installResult;
        std::vector<std::string> resvec;
        std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
        std::string appName = BASE_BUNDLE_NAME + '1';
        Install(bundleFilePath, InstallFlag::NORMAL, resvec);
        installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        if (!bundleMgrProxy) {
            APP_LOGE("bundle mgr proxy is nullptr.");
            EXPECT_EQ(bundleMgrProxy, nullptr);
        }
        BundleInfo bundleInfo;
        bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
        std::string name;
        ErrCode ret = bundleMgrProxy->GetNameForUid(Constants::INVALID_UID, name);
        EXPECT_NE(ret, ERR_OK);
        resvec.clear();
        Uninstall(appName, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "uninstall fail!";
        if (ret != ERR_OK) {
            APP_LOGI("GetNameForUid_0200 failed - cycle count: %{public}d", i);
            break;
        }
        result = true;
    }

    if (result && stLevel_.BMSLevel > 1) {
        APP_LOGI("GetNameForUid_0200 success - cycle count: %{public}d", stLevel_.BMSLevel);
    }
    EXPECT_FALSE(result);
    std::cout << "END GetNameForUid_0200" << std::endl;
}

/**
 * @tc.number: GetNameForUid_0300
 * @tc.name: test GetNameForUid interface
 * @tc.desc: 1.get name by uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetNameForUid_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetNameForUid_0300" << std::endl;
    CommonTool commonTool;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    std::string name;
    ErrCode ret = bundleMgrProxy->GetNameForUid(bundleInfo.uid, name);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(name, appName);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetNameForUid_0300" << std::endl;
}

/**
 * @tc.number: GetAppIdByBundleName_0100
 * @tc.name: test GetAppIdByBundleName proxy
 * @tc.desc: 1.get AppId by BundleName
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppIdByBundleName_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetAppIdByBundleName_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    auto ret = bundleMgrProxy->GetAppIdByBundleName(appName, USERID);
    EXPECT_EQ(ret, APPID);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetAppIdByBundleName_0100" << std::endl;
}

/**
 * @tc.number: GetAppIdByBundleName_0200
 * @tc.name: test GetAppIdByBundleName proxy
 * @tc.desc: 1.get AppId failed by empty BundleName
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppIdByBundleName_0200, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    auto ret = bundleMgrProxy->GetAppIdByBundleName("", USERID);
    EXPECT_NE(ret, APPID);
}

/**
 * @tc.number: GetBundleGidsByUid_0100
 * @tc.name: test GetBundleGidsByUid proxy
 * @tc.desc: 1.get BundleGids by uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleGidsByUid_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleGidsByUid_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::vector<int> gids;
    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    bool ret = bundleMgrProxy->GetBundleGidsByUid(appName, bundleInfo.uid, gids);
    EXPECT_TRUE(ret);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundleGidsByUid_0100" << std::endl;
}

/**
 * @tc.number: CheckIsSystemAppByUid_0100
 * @tc.name: test CheckIsSystemAppByUid proxy
 * @tc.desc: 1.get check  system app by uid
 */
HWTEST_F(ActsBmsKitSystemTest, CheckIsSystemAppByUid_0100, Function | MediumTest | Level1)
{
    std::cout << "START CheckIsSystemAppByUid_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::vector<int> gids;
    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    bool ret = bundleMgrProxy->CheckIsSystemAppByUid(bundleInfo.uid);
    EXPECT_TRUE(ret);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END CheckIsSystemAppByUid_0100" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfos_0100
 * @tc.name: test QueryAbilityInfos proxy
 * @tc.desc: 1.query ability infos
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfos_0100, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfos_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    std::string abilityName = "bmsThirdBundle_A1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    Want want;
    ElementName name;
    name.SetAbilityName(abilityName);
    name.SetBundleName(appName);
    want.SetElement(name);
    std::vector<AbilityInfo> AbilityInfo;
    auto ret = bundleMgrProxy->QueryAbilityInfos(want, GET_ABILITY_INFO_DEFAULT, USERID, AbilityInfo);
    EXPECT_TRUE(ret);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END QueryAbilityInfos_0100" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfos_0200
 * @tc.name: test QueryAbilityInfos proxy
 * @tc.desc: 1.query ability infos
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfos_0200, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfos_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    std::string abilityName = "bmsThirdBundle_A1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    Want want;
    ElementName name;
    name.SetAbilityName(abilityName);
    name.SetBundleName(appName);
    want.SetElement(name);
    std::vector<AbilityInfo> AbilityInfo;
    auto ret = bundleMgrProxy->QueryAbilityInfos(want, AbilityInfo);
    EXPECT_FALSE(ret);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END QueryAbilityInfos_0200" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfosV9_0100
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.query ability infos
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfosV9_0100, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfos_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    std::string abilityName = "bmsThirdBundle_A1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    Want want;
    ElementName name;
    name.SetAbilityName(abilityName);
    name.SetBundleName(appName);
    want.SetElement(name);
    std::vector<AbilityInfo> AbilityInfo;
    auto ret = bundleMgrProxy->QueryAbilityInfosV9(want, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, AbilityInfo);
    EXPECT_EQ(ret, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END QueryAbilityInfos_0100" << std::endl;
}

/**
 * @tc.number: QueryAllAbilityInfos_0100
 * @tc.name: test QueryAllAbilityInfos proxy
 * @tc.desc: 1.query all ability infos
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAllAbilityInfos_0100, Function | MediumTest | Level1)
{
    std::cout << "START QueryAllAbilityInfos_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    std::string abilityName = "bmsThirdBundle_A1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    Want want;
    ElementName name;
    name.SetAbilityName(abilityName);
    name.SetBundleName(appName);
    want.SetElement(name);
    std::vector<AbilityInfo> AbilityInfo;
    auto ret = bundleMgrProxy->QueryAllAbilityInfos(want, USERID, AbilityInfo);
    EXPECT_TRUE(ret);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END QueryAllAbilityInfos_0100" << std::endl;
}

/**
 * @tc.number: CheckPublicKeys_0100
 * @tc.name: test CheckPublicKeys interface
 * @tc.desc: 1.check pubilic keys
 *           2.the pubilic keys is zero
 */
HWTEST_F(ActsBmsKitSystemTest, CheckPublicKeys_0100, Function | MediumTest | Level1)
{
    std::cout << "START CheckPublicKeys_0100" << std::endl;
    std::vector<std::string> resvec;
    std::vector<std::string> resvec2;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string bundleFilePath2 = THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    std::string appName2 = BASE_BUNDLE_NAME + "2";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    Install(bundleFilePath2, InstallFlag::NORMAL, resvec2);
    std::string installResult2 = commonTool.VectorToStr(resvec2);
    EXPECT_EQ(installResult2, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    int ret = bundleMgrProxy->CheckPublicKeys(appName, appName2);
    EXPECT_EQ(ret, 0);

    resvec.clear();
    resvec2.clear();
    Uninstall(appName, resvec);
    Uninstall(appName2, resvec2);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::string uninstallResult2 = commonTool.VectorToStr(resvec2);
    EXPECT_EQ(uninstallResult2, "Success") << "uninstall fail!";
    std::cout << "END CheckPublicKeys_0100" << std::endl;
}

/**
 * @tc.number: CheckPublicKeys_0200
 * @tc.name: test CheckPublicKeys interface
 * @tc.desc: 1.check pubilic keys
 *           2.the pubilic keys is zero
 */
HWTEST_F(ActsBmsKitSystemTest, CheckPublicKeys_0200, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    int ret = bundleMgrProxy->CheckPublicKeys("", "");
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number: GetAppPrivilegeLevel_0100
 * @tc.name: test GetAppPrivilegeLevel interface
 * @tc.desc: 1.get app privilege level
 *           2.the level is system_core
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppPrivilegeLevel_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetAppPrivilegeLevel_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    auto ret = bundleMgrProxy->GetAppPrivilegeLevel(appName, USERID);
    EXPECT_EQ(ret, "system_core");

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetAppPrivilegeLevel_0100" << std::endl;
}

/**
 * @tc.number: GetAppPrivilegeLevel_0200
 * @tc.name: test GetAppPrivilegeLevel interface
 * @tc.desc: 1.get app privilege level failed by empty bundle name
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppPrivilegeLevel_0200, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    auto ret = bundleMgrProxy->GetAppPrivilegeLevel("", USERID);
    EXPECT_NE(ret, "system_core");
}

/**
 * @tc.number: GetAbilityInfo_0100
 * @tc.name: test GetAbilityInfo proxy
 * @tc.desc: 1.get ability info fail by empty abilityName
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityInfo_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetAbilityInfo_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    AbilityInfo abilityInfo;
    bool ret = bundleMgrProxy->GetAbilityInfo(appName, "", abilityInfo);
    EXPECT_FALSE(ret);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetAbilityInfo_0100" << std::endl;
}

/**
 * @tc.number: GetBundlePackInfo_0100
 * @tc.name: test can get the pack info by uri
 * @tc.desc: 1.system run normally
 *           2.get pack info successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundlePackInfo_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetAbilityInfo_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    BundlePackInfo bundlePackInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto testRet = bundleMgrProxy->GetBundlePackInfo(
        appName, GET_PACK_INFO_ALL, bundlePackInfo, USERID);
    EXPECT_EQ(testRet, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundlePackInfo_0100" << std::endl;
}

/**
 * @tc.number: GetBundlePackInfo_0200
 * @tc.name: test can get the pack info by uri
 * @tc.desc: 1.system run normally
 *           2.get pack info successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundlePackInfo_0200, Function | SmallTest | Level1)
{
    std::cout << "START GetBundlePackInfo_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    BundlePackInfo bundlePackInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto testRet = bundleMgrProxy->GetBundlePackInfo(
        appName, BundleFlag::GET_BUNDLE_DEFAULT, bundlePackInfo, USERID);
    EXPECT_EQ(ERR_OK, testRet);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundlePackInfo_0200" << std::endl;
}

/**
 * @tc.number: GetBundlePackInfo_0300
 * @tc.name: test can get the pack info by uri
 * @tc.desc: 1.system run normally
 *           2.get pack info failed by empty bundle name
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundlePackInfo_0300, Function | SmallTest | Level1)
{
    BundlePackInfo bundlePackInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    int32_t flag = 0;
    ErrCode testRet = bundleMgrProxy->GetBundlePackInfo(
        "", BundleFlag::GET_BUNDLE_DEFAULT, bundlePackInfo, USERID);
    EXPECT_NE(ERR_OK, testRet);
    ErrCode testRet1 = bundleMgrProxy->GetBundlePackInfo(
        "", flag, bundlePackInfo, USERID);
    EXPECT_NE(ERR_OK, testRet1);
}

/**
 * @tc.number: ImplicitQueryInfoByPriority_0100
 * @tc.name: test can implicit query Infos by priority
 * @tc.desc: 1.system run normally
 *           2.implicit query Infos by priority failed
 */
HWTEST_F(ActsBmsKitSystemTest, ImplicitQueryInfoByPriority_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetBundlePackInfo_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    Want want;
    ElementName name;
    name.SetAbilityName(BASE_ABILITY_NAME);
    name.SetBundleName(appName);
    want.SetElement(name);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool testRet = bundleMgrProxy->ImplicitQueryInfoByPriority(
        want, BundleFlag::GET_BUNDLE_DEFAULT, USERID, abilityInfo, extensionAbilityInfo);
    EXPECT_EQ(false, testRet);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END ImplicitQueryInfoByPriority_0100" << std::endl;
}

/**
 * @tc.number: ImplicitQueryInfos_0100
 * @tc.name: test can Implicit query Infos
 * @tc.desc: 1.system run normally
 *           2.query Infos failed
 */
HWTEST_F(ActsBmsKitSystemTest, ImplicitQueryInfos_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetBundlePackInfo_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    Want want;
    ElementName name;
    name.SetAbilityName(BASE_ABILITY_NAME);
    name.SetBundleName(appName);
    want.SetElement(name);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool testRet = bundleMgrProxy->ImplicitQueryInfos(
        want, BundleFlag::GET_BUNDLE_DEFAULT, USERID, abilityInfos, extensionInfos);
    EXPECT_EQ(false, testRet);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END ImplicitQueryInfos_0100" << std::endl;
}

/**
 * @tc.number: GetAllDependentModuleNames_0100
 * @tc.name: test can get all dependent module names
 * @tc.desc: 1.system run normally
 *           2.get all dependent module names
 */
HWTEST_F(ActsBmsKitSystemTest, GetAllDependentModuleNames_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetAllDependentModuleNames_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    std::vector<std::string> dependentModuleName;
    auto res = bundleMgrProxy->GetAllDependentModuleNames(appName, BASE_MODULE_NAME, dependentModuleName);
    EXPECT_TRUE(res);
    EXPECT_TRUE(dependentModuleName.empty());

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetAllDependentModuleNames_0100" << std::endl;
}

/**
 * @tc.number: GetAllDependentModuleNames_0200
 * @tc.name: test can get all dependent module names
 * @tc.desc: 1.system run normally
 *           2.get all dependent module names failed by empty bundle name
 */
HWTEST_F(ActsBmsKitSystemTest, GetAllDependentModuleNames_0200, Function | SmallTest | Level1)
{
    std::cout << "START GetAllDependentModuleNames_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    std::vector<std::string> dependentModuleName;
    auto res = bundleMgrProxy->GetAllDependentModuleNames("", BASE_MODULE_NAME, dependentModuleName);
    EXPECT_FALSE(res);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetAllDependentModuleNames_0200" << std::endl;
}

/**
 * @tc.number: GetModuleUpgradeFlag_0100
 * @tc.name: test can get the module upgrade flag
 * @tc.desc: 1.system run normally
 *           2.set module upgrade flag successfully
 *           3.get module upgrade flag successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetModuleUpgradeFlag_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetModuleUpgradeFlag_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto result = bundleMgrProxy->SetModuleUpgradeFlag(appName, BASE_MODULE_NAME, 1);
    EXPECT_TRUE(result == ERR_OK);
    auto res = bundleMgrProxy->GetModuleUpgradeFlag(appName, BASE_MODULE_NAME);
    EXPECT_TRUE(res);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetModuleUpgradeFlag_0100" << std::endl;
}

/**
 * @tc.number: GetModuleUpgradeFlag_0200
 * @tc.name: test can get the module upgrade flag
 * @tc.desc: 1.system run normally
 *           2.set module upgrade flag failed
 *           3.get module upgrade flag failed
 */
HWTEST_F(ActsBmsKitSystemTest, GetModuleUpgradeFlag_0200, Function | SmallTest | Level1)
{
    std::cout << "START GetModuleUpgradeFlag_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ErrCode result = bundleMgrProxy->SetModuleUpgradeFlag("", BASE_MODULE_NAME, 1);
    EXPECT_NE(result, ERR_OK);
    ErrCode result1 = bundleMgrProxy->SetModuleUpgradeFlag(appName, "", 1);
    EXPECT_NE(result1, ERR_OK);
    bool res = bundleMgrProxy->GetModuleUpgradeFlag("", BASE_MODULE_NAME);
    EXPECT_FALSE(res);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetModuleUpgradeFlag_0200" << std::endl;
}

/**
 * @tc.number: ObtainCallingBundleName_0100
 * @tc.name: test can get the calling bundle name
 * @tc.desc: 1.system run normally
 *           2.get calling bundle name failed
 */
HWTEST_F(ActsBmsKitSystemTest, ObtainCallingBundleName_0100, Function | SmallTest | Level1)
{
    std::cout << "START ObtainCallingBundleName_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto res = bundleMgrProxy->ObtainCallingBundleName(appName);
    EXPECT_FALSE(res);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END ObtainCallingBundleName_0100" << std::endl;
}

/**
 * @tc.number: ObtainCallingBundleName_0200
 * @tc.name: test can get the calling bundle name
 * @tc.desc: 1.system run normally
 *           2.get calling bundle name failed by empty bundle name
 */
HWTEST_F(ActsBmsKitSystemTest, ObtainCallingBundleName_0200, Function | SmallTest | Level1)
{
    std::string appName = "";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto res = bundleMgrProxy->ObtainCallingBundleName(appName);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetBundleStats_0100
 * @tc.name: test can get the bundle stats info
 * @tc.desc: 1.system run normally
 *           2.get bundle stats info successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleStats_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetBundleStats_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<int64_t> bundleStats;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto res = bundleMgrProxy->GetBundleStats(appName, USERID, bundleStats);
    EXPECT_TRUE(res);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundleStats_0100" << std::endl;
}

/**
 * @tc.number: GetStringById_0100
 * @tc.name: test can get the string info
 * @tc.desc: 1.system run normally
 *           2.get empty info
 */
HWTEST_F(ActsBmsKitSystemTest, GetStringById_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetStringById_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<int64_t> bundleStats;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto res = bundleMgrProxy->GetStringById(appName, BASE_MODULE_NAME, RESID, USERID);
    EXPECT_EQ(res, "");

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetStringById" << std::endl;
}

/**
 * @tc.number: GetStringById_0200
 * @tc.name: test can get the string info
 * @tc.desc: 1.system run normally
 *           2.get empty info failed by empty bundle name
 */
HWTEST_F(ActsBmsKitSystemTest, GetStringById_0200, Function | SmallTest | Level1)
{
    std::vector<int64_t> bundleStats;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto res = bundleMgrProxy->GetStringById("", BASE_MODULE_NAME, RESID, USERID);
    EXPECT_EQ(res, "");
}

/**
 * @tc.number: GetIconById_0100
 * @tc.name: test can get the icon info
 * @tc.desc: 1.system run normally
 *           2.get GetIconById info successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetIconById_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetIconById_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<int64_t> bundleStats;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto res = bundleMgrProxy->GetIconById(appName, BASE_MODULE_NAME, RESID, 0, USERID);
    EXPECT_NE(res, "");

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetIconById_0100" << std::endl;
}

/**
 * @tc.number: GetIconById_0200
 * @tc.name: test can get the icon info
 * @tc.desc: 1.system run normally
 *           2.get GetIconById info failed by empty bundle name
 */
HWTEST_F(ActsBmsKitSystemTest, GetIconById_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto res = bundleMgrProxy->GetIconById("", BASE_MODULE_NAME, RESID, 0, USERID);
    EXPECT_EQ(res, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetPermissionDef_0100
 * @tc.name: test GetPermissionDef proxy
 * @tc.desc: 1.system run normally
 *           2.get permission info successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetPermissionDef_0100, Function | SmallTest | Level1)
{
    PermissionDef permissionDef;
    std::string permissionName = "ohos.permission.READ_CALENDAR";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    int32_t ret = bundleMgrProxy->GetPermissionDef(permissionName, permissionDef);
    EXPECT_EQ(permissionDef.permissionName, permissionName);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetPermissionDef_0200
 * @tc.name: test GetPermissionDef proxy
 * @tc.desc: 1.system run normally
 *           2.get permission info failed by empty name
 */
HWTEST_F(ActsBmsKitSystemTest, GetPermissionDef_0200, Function | SmallTest | Level1)
{
    PermissionDef permissionDef;
    std::string permissionName = "";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    int32_t ret = bundleMgrProxy->GetPermissionDef(permissionName, permissionDef);
    EXPECT_EQ(permissionDef.permissionName, permissionName);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: DisposedStatus_0100
 * @tc.name: test DisposedStatus proxy
 * @tc.desc: 1.system run normally
 *           2.get disposed status failed by unpermission
 */
HWTEST_F(ActsBmsKitSystemTest, DisposedStatus_0100, Function | SmallTest | Level1)
{
    std::cout << "START DisposedStatus_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool result = bundleMgrProxy->SetDisposedStatus(appName, DISPOSED_STATUS);
    EXPECT_TRUE(result);
    int32_t status = bundleMgrProxy->GetDisposedStatus(appName);
    EXPECT_EQ(status, 10);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END DisposedStatus_0100" << std::endl;
}

/**
 * @tc.number: DisposedStatus_0200
 * @tc.name: test DisposedStatus proxy
 * @tc.desc: 1.system run normally
 *           2.get disposed status failed by empty bundle name
 */
HWTEST_F(ActsBmsKitSystemTest, DisposedStatus_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool result = bundleMgrProxy->SetDisposedStatus("", DISPOSED_STATUS);
    EXPECT_FALSE(result);
    int32_t status = bundleMgrProxy->GetDisposedStatus("");
    EXPECT_EQ(status, 0);
}

/**
 * @tc.number: GetUdidByNetworkId_0100
 * @tc.name: test GetUdidByNetworkId proxy
 * @tc.desc: 1.system run normally
 *           2.get udid info failed by empty networkid
 */
HWTEST_F(ActsBmsKitSystemTest, GetUdidByNetworkId_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetUdidByNetworkId_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::string udid;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bundleMgrProxy->GetUdidByNetworkId("", udid);
    EXPECT_EQ(udid, "");

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetUdidByNetworkId_0100" << std::endl;
}

/**
 * @tc.number: CheckAbilityEnabled_0300
 * @tc.name: test SetAbilityEnabled and IsAbilityEnabled proxy
 * @tc.desc: 1.system run normally
 *           2.set ability failed
 *           3.get ability failed
 */
HWTEST_F(ActsBmsKitSystemTest, CheckAbilityEnabled_0300, Function | SmallTest | Level1)
{
    std::cout << "START GetUdidByNetworkId_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    AbilityInfo abilityInfo;
    abilityInfo.name = "";
    abilityInfo.bundleName = appName;
    abilityInfo.moduleName = BASE_MODULE_NAME;
    int32_t testRet = bundleMgrProxy->SetAbilityEnabled(abilityInfo, false, USERID);
    EXPECT_NE(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = bundleMgrProxy->IsAbilityEnabled(abilityInfo, isEnable);
    EXPECT_NE(0, testRet1);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetUdidByNetworkId_0100" << std::endl;
}

/**
 * @tc.number: CheckAbilityEnabled_0400
 * @tc.name: test SetAbilityEnabled and IsAbilityEnabled proxy
 * @tc.desc: 1.system run normally
 *           2.set ability failed
 *           3.get ability failed
 */
HWTEST_F(ActsBmsKitSystemTest, CheckAbilityEnabled_0400, Function | SmallTest | Level1)
{
    std::cout << "START GetUdidByNetworkId_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    AbilityInfo abilityInfo;
    abilityInfo.name = "";
    abilityInfo.bundleName = "";
    abilityInfo.moduleName = BASE_MODULE_NAME;
    int32_t testRet = bundleMgrProxy->SetAbilityEnabled(abilityInfo, false, USERID);
    EXPECT_NE(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = bundleMgrProxy->IsAbilityEnabled(abilityInfo, isEnable);
    EXPECT_NE(0, testRet1);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetUdidByNetworkId_0100" << std::endl;
}

/**
 * @tc.number: SetDebugMode_0100
 * @tc.name: test SetDebugMode proxy
 * @tc.desc: 1.system run normally
 *           2.set debug mode successfully
 */
HWTEST_F(ActsBmsKitSystemTest, SetDebugMode_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto res = bundleMgrProxy->SetDebugMode(true);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetDefaultAppProxy_0100
 * @tc.name: test GetDefaultAppProxy proxy
 * @tc.desc: 1.system run normally
 *           2.test GetDefaultAppProxy
 */
HWTEST_F(ActsBmsKitSystemTest, GetDefaultAppProxy_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IDefaultApp> getDefaultAppProxy = bundleMgrProxy->GetDefaultAppProxy();
    bool isDefaultApp = false;
    ErrCode res = getDefaultAppProxy->IsDefaultApplication("", isDefaultApp);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: GetDefaultAppProxy_0100
 * @tc.name: test GetDefaultAppProxy proxy
 * @tc.desc: 1.system run normally
 *           2.test GetDefaultApplication
 */
HWTEST_F(ActsBmsKitSystemTest, GetDefaultAppProxy_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IDefaultApp> getDefaultAppProxy = bundleMgrProxy->GetDefaultAppProxy();
    BundleInfo bundleInfo;
    ErrCode res = getDefaultAppProxy->GetDefaultApplication(USERID, "", bundleInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_TYPE);
    res = getDefaultAppProxy->GetDefaultApplication(USERID, "type", bundleInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

/**
 * @tc.number: GetDefaultAppProxy_0100
 * @tc.name: test GetDefaultAppProxy proxy
 * @tc.desc: 1.system run normally
 *           2.test SetDefaultApplication
 */
HWTEST_F(ActsBmsKitSystemTest, GetDefaultAppProxy_0300, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IDefaultApp> getDefaultAppProxy = bundleMgrProxy->GetDefaultAppProxy();
    Want want;
    ErrCode res = getDefaultAppProxy->SetDefaultApplication(USERID, "type", want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

/**
 * @tc.number: GetDefaultAppProxy_0100
 * @tc.name: test GetDefaultAppProxy proxy
 * @tc.desc: 1.system run normally
 *           2.test ResetDefaultApplication
 */
HWTEST_F(ActsBmsKitSystemTest, GetDefaultAppProxy_0400, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IDefaultApp> getDefaultAppProxy = bundleMgrProxy->GetDefaultAppProxy();
    ErrCode res = getDefaultAppProxy->ResetDefaultApplication(USERID, "type");
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

/**
 * @tc.number: CheckAbilityEnabled_0100
 * @tc.name: test SetAbilityEnabled and IsAbilityEnabled proxy
 * @tc.desc: 1.system run normally
 *           2.set ability enabled
 *           3.get ability enabled
 */
HWTEST_F(ActsBmsKitSystemTest, CheckAbilityEnabled_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetUdidByNetworkId_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    AbilityInfo abilityInfo;
    abilityInfo.name = BASE_ABILITY_NAME;
    abilityInfo.bundleName = appName;
    abilityInfo.moduleName = BASE_MODULE_NAME;
    int32_t testRet = bundleMgrProxy->SetAbilityEnabled(abilityInfo, false, USERID);
    EXPECT_EQ(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = bundleMgrProxy->IsAbilityEnabled(abilityInfo, isEnable);
    EXPECT_NE(0, testRet1);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetUdidByNetworkId_0100" << std::endl;
}

/**
 * @tc.number: CheckAbilityEnabled_0200
 * @tc.name: test SetAbilityEnabled and IsAbilityEnabled proxy
 * @tc.desc: 1.system run normally
 *           2.set ability failed
 */
HWTEST_F(ActsBmsKitSystemTest, CheckAbilityEnabled_0200, Function | SmallTest | Level1)
{
    std::cout << "START GetUdidByNetworkId_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    AbilityInfo abilityInfo;
    abilityInfo.name = BASE_ABILITY_NAME;
    abilityInfo.bundleName = "";
    abilityInfo.moduleName = BASE_MODULE_NAME;
    int32_t testRet = bundleMgrProxy->SetAbilityEnabled(abilityInfo, false, USERID);
    EXPECT_NE(0, testRet);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetUdidByNetworkId_0100" << std::endl;
}

/**
 * @tc.number: GetAccessibleAppCodePaths_0100
 * @tc.name: test GetAccessibleAppCodePaths proxy
 * @tc.desc: 1.system run normally
 *           2.get accessible app code paths successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetAccessibleAppCodePaths_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto res = bundleMgrProxy->GetAccessibleAppCodePaths(USERID);
    EXPECT_EQ(res.size(), 0);
}

/**
 * @tc.number: GetBundleUserMgr_0100
 * @tc.name: test GetBundleUserMgr proxy
 * @tc.desc: 1.system run normally
 *           2.GetBundleUserMgr is not nullptr
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleUserMgr_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IBundleUserMgr> getBundleUserMgr = bundleMgrProxy->GetBundleUserMgr();
    if (!getBundleUserMgr) {
        APP_LOGE("getBundleUserMgr is nullptr.");
        EXPECT_EQ(getBundleUserMgr, nullptr);
    }
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0100
 * @tc.name: test QueryExtensionAbilityInfosV9 proxy
 * @tc.desc: 1.system run normally
 *           2.extension not found
 */
HWTEST_F(ActsBmsKitSystemTest, QueryExtensionAbilityInfosV9_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    int32_t flags = 0;
    int32_t userId = 100;
    std::vector<ExtensionAbilityInfo> extensions;
    ErrCode ret = bundleMgrProxy->QueryExtensionAbilityInfosV9(want, flags, userId, extensions);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0200
 * @tc.name: test QueryExtensionAbilityInfosV9 proxy
 * @tc.desc: 1.system run normally
 *           2.extension not found
 */
HWTEST_F(ActsBmsKitSystemTest, QueryExtensionAbilityInfosV9_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    int32_t flags = 0;
    int32_t userId = 100;
    std::vector<ExtensionAbilityInfo> extensions;
    ErrCode ret = bundleMgrProxy->QueryExtensionAbilityInfosV9(want, flags, userId, extensions);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0300
 * @tc.name: test QueryExtensionAbilityInfosV9 proxy
 * @tc.desc: 1.system run normally
 *           2.return ERR_OK
 */
HWTEST_F(ActsBmsKitSystemTest, QueryExtensionAbilityInfosV9_0300, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    want.SetAction("action.system.home");
    int32_t flags = 0;
    int32_t userId = 100;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = bundleMgrProxy->QueryExtensionAbilityInfosV9(want, flags, userId, extensionInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0400
 * @tc.name: test QueryExtensionAbilityInfosV9 proxy
 * @tc.desc: 1.system run normally
 *           2.return ERR_OK
 */
HWTEST_F(ActsBmsKitSystemTest, QueryExtensionAbilityInfosV9_0400, Function | SmallTest | Level1)
{
    auto name = std::string("QueryExtensionAbilityInfos_0001");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = "/data/test/bms_bundle/bundleClient1.hap";
    std::vector<std::string> resvec;
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<ExtensionAbilityInfo> infos;
    OHOS::AAFwk::Want want;
    ElementName element;
    element.SetBundleName("com.example.ohosproject.hmservice");
    element.SetModuleName("entry_phone");
    element.SetAbilityName("Form");
    want.SetElement(element);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ErrCode ret = bundleMgrProxy->QueryExtensionAbilityInfosV9(want, ExtensionAbilityType::FORM,
        ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_DEFAULT, USERID, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(1, infos.size());

    resvec.clear();
    Uninstall("com.example.ohosproject.hmservice", resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetUdidByNetworkId_0100" << std::endl;
}

/**
 * @tc.number: UpgradeAtomicService_0100
 * @tc.name: test UpgradeAtomicService proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, UpgradeAtomicService_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    int32_t userId = 100;
    bundleMgrProxy->UpgradeAtomicService(want, userId);
}

/**
 * @tc.number: QueryAbilityInfosByUri_0100
 * @tc.name: test QueryAbilityInfosByUri proxy
 * @tc.desc: 1.system run normally
 *           2.ability not found
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfosByUri_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string uri = "invalid";
    std::vector<AbilityInfo> abilityInfos;
    bool ret = bundleMgrProxy->QueryAbilityInfosByUri(uri, abilityInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetAbilityLabel_0200
 * @tc.name: test GetAbilityLabel proxy
 * @tc.desc: 1.system run normally
 *           2.ability label not found
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityLabel_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    std::string abilityName = "invalid";
    std::string ret = bundleMgrProxy->GetAbilityLabel(bundleName, abilityName);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.number: IsApplicationEnabled_0100
 * @tc.name: test IsApplicationEnabled proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, IsApplicationEnabled_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    bool isEnable = false;
    ErrCode ret = bundleMgrProxy->IsApplicationEnabled(bundleName, isEnable);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IsModuleRemovable_0100
 * @tc.name: test IsModuleRemovable proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, IsModuleRemovable_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    std::string moduleName = "invalid";
    bool isRemovable = false;
    ErrCode ret = bundleMgrProxy->IsModuleRemovable(bundleName, moduleName, isRemovable);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IsModuleRemovable_0100
 * @tc.name: test IsModuleRemovable proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, IsModuleRemovable_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string moduleName = "invalid";
    bool isRemovable = false;
    ErrCode ret = bundleMgrProxy->IsModuleRemovable("", moduleName, isRemovable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: IsModuleRemovable_0100
 * @tc.name: test IsModuleRemovable proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, IsModuleRemovable_0300, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    bool isRemovable = false;
    ErrCode ret = bundleMgrProxy->IsModuleRemovable(bundleName, "", isRemovable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SetModuleRemovable_0100
 * @tc.name: test SetModuleRemovable proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, SetModuleRemovable_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    std::string moduleName = "invalid";
    bool ret = bundleMgrProxy->SetModuleRemovable(bundleName, moduleName, true);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetModuleRemovable_0200
 * @tc.name: test SetModuleRemovable proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, SetModuleRemovable_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string moduleName = "invalid";
    bool ret = bundleMgrProxy->SetModuleRemovable("", moduleName, true);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetModuleRemovable_0300
 * @tc.name: test SetModuleRemovable proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, SetModuleRemovable_0300, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    bool ret = bundleMgrProxy->SetModuleRemovable(bundleName, "", true);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetApplicationEnabled_0100
 * @tc.name: test SetApplicationEnabled proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, SetApplicationEnabled_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    int32_t userId = 100;
    ErrCode ret = bundleMgrProxy->SetApplicationEnabled(bundleName, true, userId);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetAbilityInfo_0200
 * @tc.name: test GetAbilityInfo proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityInfo_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "";
    std::string abilityName = "invalid";
    AbilityInfo abilityInfo;
    bool ret = bundleMgrProxy->GetAbilityInfo(bundleName, abilityName, abilityInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetAbilityInfo_0300
 * @tc.name: test GetAbilityInfo proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityInfo_0300, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "";
    std::string moduleName = "invalid";
    std::string abilityName = "invalid";
    AbilityInfo abilityInfo;
    bool ret = bundleMgrProxy->GetAbilityInfo(bundleName, moduleName, abilityName, abilityInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetAbilityInfo_0400
 * @tc.name: test GetAbilityInfo proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityInfo_0400, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<std::string> resvec;
    CommonTool commonTool;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    std::string bundleName = BASE_BUNDLE_NAME + "1";
    std::string abilityName = BASE_ABILITY_NAME;
    AbilityInfo abilityInfo;
    bool ret = bundleMgrProxy->GetAbilityInfo(bundleName, abilityName, abilityInfo);
    EXPECT_FALSE(ret);
    resvec.clear();
    Uninstall(bundleName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: GetAbilityInfo_0500
 * @tc.name: test GetAbilityInfo proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, GetAbilityInfo_0500, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<std::string> resvec;
    CommonTool commonTool;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    std::string bundleName = BASE_BUNDLE_NAME + "1";
    std::string moduleName = BASE_MODULE_NAME;
    std::string abilityName = BASE_ABILITY_NAME;
    AbilityInfo abilityInfo;
    bool ret = bundleMgrProxy->GetAbilityInfo(bundleName, moduleName, abilityName, abilityInfo);
    EXPECT_FALSE(ret);
    resvec.clear();
    Uninstall(bundleName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: GetFormsInfoByApp_0100
 * @tc.name: test GetFormsInfoByApp proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, GetFormsInfoByApp_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = BASE_BUNDLE_NAME;
    std::vector<FormInfo> formInfos;
    bool ret = bundleMgrProxy->GetFormsInfoByApp(bundleName, formInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetDistributedBundleInfo_0100
 * @tc.name: test GetDistributedBundleInfo proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, GetDistributedBundleInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string networkId1 = "";
    std::string bundleName1 = "";
    std::string networkId2 = "100";
    std::string bundleName2 = BASE_BUNDLE_NAME;
    DistributedBundleInfo distributedBundleInfo;
    bool ret = bundleMgrProxy->GetDistributedBundleInfo(networkId1, bundleName1, distributedBundleInfo);
    EXPECT_FALSE(ret);
    ret = bundleMgrProxy->GetDistributedBundleInfo(networkId2, bundleName1, distributedBundleInfo);
    EXPECT_FALSE(ret);
    ret = bundleMgrProxy->GetDistributedBundleInfo(networkId1, bundleName2, distributedBundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetSandboxBundleInfo_0100
 * @tc.name: test GetSandboxBundleInfo proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, GetSandboxBundleInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName1 = "";
    std::string bundleName2 = BASE_BUNDLE_NAME;
    int32_t appIndex1 = 0;
    int32_t appIndex2 = 100;
    BundleInfo info;
    auto ret = bundleMgrProxy->GetSandboxBundleInfo(bundleName1, appIndex1, USERID, info);
    EXPECT_NE(ret, ERR_OK);
    ret = bundleMgrProxy->GetSandboxBundleInfo(bundleName2, appIndex1, USERID, info);
    EXPECT_NE(ret, ERR_OK);
    ret = bundleMgrProxy->GetSandboxBundleInfo(bundleName1, appIndex2, USERID, info);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetFormsInfoByModule_0100
 * @tc.name: test GetFormsInfoByModule proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, GetFormsInfoByModule_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    std::string moduleName = "invalid";
    std::vector<FormInfo> formInfos;
    bool ret = bundleMgrProxy->GetFormsInfoByModule(bundleName, moduleName, formInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ImplicitQueryInfoByPriority_0200
 * @tc.name: test ImplicitQueryInfoByPriority proxy
 * @tc.desc: 1.system run normally
 *           2.return true
 */
HWTEST_F(ActsBmsKitSystemTest, ImplicitQueryInfoByPriority_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    int32_t flags = 0;
    int32_t userId = 100;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    bool ret = bundleMgrProxy->ImplicitQueryInfoByPriority(want, flags, userId, abilityInfo, extensionInfo);
    EXPECT_TRUE(ret);
    ret = !abilityInfo.name.empty() || !extensionInfo.name.empty();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ImplicitQueryInfos_0200
 * @tc.name: test ImplicitQueryInfos proxy
 * @tc.desc: 1.system run normally
 *           2.return true
 */
HWTEST_F(ActsBmsKitSystemTest, ImplicitQueryInfos_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    int32_t flags = 0;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = bundleMgrProxy->ImplicitQueryInfos(want, flags, userId, abilityInfos, extensionInfos);
    EXPECT_TRUE(ret);
    ret = !abilityInfos.empty() || !extensionInfos.empty();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetAppControlProxy_0100
 * @tc.name: test GetAppControlProxy proxy
 * @tc.desc: 1.system run normally
 *           2.proxy not null
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppControlProxy_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IAppControlMgr> appControlMgr = bundleMgrProxy->GetAppControlProxy();
    EXPECT_NE(appControlMgr, nullptr);
}

/**
 * @tc.number: GetSandboxAbilityInfo_0100
 * @tc.name: test GetSandboxAbilityInfo proxy
 * @tc.desc: 1.system run normally
 *           2.return not ERR_OK
 */
HWTEST_F(ActsBmsKitSystemTest, GetSandboxAbilityInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    int32_t appIndex = 1;
    int32_t flags = 0;
    int32_t userId = 100;
    AbilityInfo abilityInfo;
    ErrCode ret = bundleMgrProxy->GetSandboxAbilityInfo(want, appIndex, flags, userId, abilityInfo);
    EXPECT_NE(ret, ERR_OK);
    int32_t appIndex1 = 0;
    ret = bundleMgrProxy->GetSandboxAbilityInfo(want, appIndex1, flags, userId, abilityInfo);
    EXPECT_NE(ret, ERR_OK);
    int32_t appIndex2 = 1000;
    ret = bundleMgrProxy->GetSandboxAbilityInfo(want, appIndex2, flags, userId, abilityInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetSandboxExtAbilityInfos_0100
 * @tc.name: test GetSandboxExtAbilityInfos proxy
 * @tc.desc: 1.system run normally
 *           2.return not ERR_OK
 */
HWTEST_F(ActsBmsKitSystemTest, GetSandboxExtAbilityInfos_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    int32_t appIndex = 1;
    int32_t flags = 0;
    int32_t userId = 100;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = bundleMgrProxy->GetSandboxExtAbilityInfos(want, appIndex, flags, userId, extensionInfos);
    EXPECT_NE(ret, ERR_OK);
    int32_t appIndex1 = 0;
    ret = bundleMgrProxy->GetSandboxExtAbilityInfos(want, appIndex1, flags, userId, extensionInfos);
    EXPECT_NE(ret, ERR_OK);
    int32_t appIndex2 = 1000;
    ret = bundleMgrProxy->GetSandboxExtAbilityInfos(want, appIndex2, flags, userId, extensionInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetSandboxHapModuleInfo_0100
 * @tc.name: test GetSandboxHapModuleInfo proxy
 * @tc.desc: 1.system run normally
 *           2.return not ERR_OK
 */
HWTEST_F(ActsBmsKitSystemTest, GetSandboxHapModuleInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    AbilityInfo abilityInfo;
    int32_t appIndex = 1;
    int32_t userId = 100;
    HapModuleInfo hapModuleInfo;
    ErrCode ret = bundleMgrProxy->GetSandboxHapModuleInfo(abilityInfo, appIndex, userId, hapModuleInfo);
    EXPECT_NE(ret, ERR_OK);
    int32_t appIndex1 = 0;
    ret = bundleMgrProxy->GetSandboxHapModuleInfo(abilityInfo, appIndex1, userId, hapModuleInfo);
    EXPECT_NE(ret, ERR_OK);
    int32_t appIndex2 = 1000;
    ret = bundleMgrProxy->GetSandboxHapModuleInfo(abilityInfo, appIndex2, userId, hapModuleInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetMediaData_0100
 * @tc.name: test GetMediaData proxy
 * @tc.desc: 1.system run normally
 *           2.return not ERR_OK
 */
HWTEST_F(ActsBmsKitSystemTest, GetMediaData_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "";
    std::string moduleName = "invalid";
    std::string abilityName = "invalid";
    std::unique_ptr<uint8_t[]> mediaDataPtr = nullptr;
    size_t len = 0;
    ErrCode ret = bundleMgrProxy->GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, len);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetMediaData_0200
 * @tc.name: test GetMediaData proxy
 * @tc.desc: 1.system run normally
 *           2.return not ERR_OK
 */
HWTEST_F(ActsBmsKitSystemTest, GetMediaData_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    std::string moduleName = "";
    std::string abilityName = "invalid";
    std::unique_ptr<uint8_t[]> mediaDataPtr = nullptr;
    size_t len = 0;
    ErrCode ret = bundleMgrProxy->GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, len);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetBundleArchiveInfoV9_0100
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive information without an ability information
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleArchiveInfoV9_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleArchiveInfoV9_0100" << std::endl;
    std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle3.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";

    BundleInfo bundleInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ErrCode getInfoResult =
        bundleMgrProxy->GetBundleArchiveInfoV9(hapFilePath, 0, bundleInfo);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    std::cout << "END GetBundleArchiveInfoV9_0100" << std::endl;
}

/**
 * @tc.number: GetBundleArchiveInfoV9_0200
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive information without an ability information
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleArchiveInfoV9_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleArchiveInfoV9_0200" << std::endl;
    BundleInfo bundleInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ErrCode getInfoResult =
        bundleMgrProxy->GetBundleArchiveInfoV9("", 0, bundleInfo);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
    std::cout << "END GetBundleArchiveInfoV9_0200" << std::endl;
}

/**
 * @tc.number: GetShortcutInfoV9_0100
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive information without an ability information
 */
HWTEST_F(ActsBmsKitSystemTest, GetShortcutInfoV9_0100, Function | MediumTest | Level1)
{
    APP_LOGD("START GetShortcutInfoV9_010");
    int32_t originUid = geteuid();
    seteuid(HUNDRED_USERID);
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode testRet = bundleMgrProxy->GetShortcutInfoV9(appName, shortcutInfos);
    EXPECT_EQ(testRet, ERR_OK);

    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    int uid = bundleInfo.uid;
    std::string callingBundleName;
    bundleMgrProxy->GetBundleNameForUid(uid, callingBundleName);
    testRet = bundleMgrProxy->GetShortcutInfoV9(callingBundleName, shortcutInfos);
    EXPECT_EQ(testRet, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    seteuid(originUid);
    APP_LOGD("END GetShortcutInfoV9_010");
}

/**
 * @tc.number: GetShortcutInfoV9_0200
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive information without an ability information
 */
HWTEST_F(ActsBmsKitSystemTest, GetShortcutInfoV9_0200, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }

    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode testRet = bundleMgrProxy->GetShortcutInfoV9("", shortcutInfos);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetShortcutInfoV9_0300
 * @tc.name: test GetShortcutInfoV9 proxy
 * @tc.desc: 1.system run normally
 *           2.get udid info failed by wrong hap
 */
HWTEST_F(ActsBmsKitSystemTest, GetShortcutInfoV9_0300, Function | SmallTest | Level1)
{
    std::cout << "START GetShortcutInfoV9_0300" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<ShortcutInfo> shortcutInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ErrCode testRet = bundleMgrProxy->GetShortcutInfoV9(appName, shortcutInfos);
    EXPECT_NE(testRet, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetShortcutInfoV9_0300" << std::endl;
}

/**
 * @tc.number: bundle_installer_0100
 * @tc.name: 1.test Install interface
 * @tc.desc: 1. failed condition, return false
 */
HWTEST_F(ActsBmsKitSystemTest, bundle_installer_0100, Function | MediumTest | Level1)
{
    std::cout << "begin to test bundle_installer_0100" << std::endl;
    sptr<IRemoteObject> object;
    BundleInstallerProxy installerProxy(object);
    std::string bundlePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = installerProxy.Install(bundlePath, installParam, statusReceiver);
    EXPECT_FALSE(res);
    std::cout << "test bundle_installer_0100 done" << std::endl;
}

/**
 * @tc.number: bundle_installer_0200
 * @tc.name: 1.test Install interface
 * @tc.desc: 1. failed condition, return false
 */
HWTEST_F(ActsBmsKitSystemTest, bundle_installer_0200, Function | MediumTest | Level1)
{
    std::cout << "begin to test bundle_installer_0200" << std::endl;
    sptr<IRemoteObject> object;
    BundleInstallerProxy installerProxy(object);
    std::vector<std::string> bundlePaths;
    bundlePaths.push_back(THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap");
    bundlePaths.push_back(THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap");
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = installerProxy.Install(bundlePaths, installParam, statusReceiver);
    EXPECT_FALSE(res);
    std::cout << "test bundle_installer_0200 done" << std::endl;
}

/**
 * @tc.number: bundle_installer_0300
 * @tc.name: 1.test Recover interface
 * @tc.desc: 1. failed condition, return false
 */
HWTEST_F(ActsBmsKitSystemTest, bundle_installer_0300, Function | MediumTest | Level1)
{
    std::cout << "begin to test bundle_installer_0300" << std::endl;
    sptr<IRemoteObject> object;
    BundleInstallerProxy installerProxy(object);
    std::string bundlePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = installerProxy.Recover(bundlePath, installParam, statusReceiver);
    EXPECT_FALSE(res);
    std::cout << "test bundle_installer_0300 done" << std::endl;
}

/**
 * @tc.number: bundle_installer_0400
 * @tc.name: 1.test Uninstall interface
 * @tc.desc: 1. failed condition, return false
 */
HWTEST_F(ActsBmsKitSystemTest, bundle_installer_0400, Function | MediumTest | Level1)
{
    std::cout << "begin to test bundle_installer_0400" << std::endl;
    sptr<IRemoteObject> object;
    BundleInstallerProxy installerProxy(object);
    std::string bundlePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = installerProxy.Uninstall(bundlePath, installParam, statusReceiver);
    EXPECT_FALSE(res);
    std::cout << "test bundle_installer_0400 done" << std::endl;
}

/**
 * @tc.number: bundle_installer_0500
 * @tc.name: 1.test Uninstall interface
 * @tc.desc: 1. failed condition, return false
 */
HWTEST_F(ActsBmsKitSystemTest, bundle_installer_0500, Function | MediumTest | Level1)
{
    std::cout << "begin to test bundle_installer_0500" << std::endl;
    sptr<IRemoteObject> object;
    BundleInstallerProxy installerProxy(object);
    std::string bundlePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string modulePackage = BASE_MODULE_NAME;
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = installerProxy.Uninstall(bundlePath, modulePackage, installParam, statusReceiver);
    EXPECT_FALSE(res);
    std::cout << "test bundle_installer_0500 done" << std::endl;
}

/**
 * @tc.number: bundle_installer_0600
 * @tc.name: 1.test InstallSandboxApp interface
 * @tc.desc: 1. failed condition, return false
 */
HWTEST_F(ActsBmsKitSystemTest, bundle_installer_0600, Function | MediumTest | Level1)
{
    std::cout << "begin to test bundle_installer_0600" << std::endl;
    sptr<IRemoteObject> object;
    BundleInstallerProxy installerProxy(object);
    std::string bundlePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    int32_t dlpType = 1;
    int32_t userId = 100;
    int32_t appIndex = 1;
    auto res = installerProxy.InstallSandboxApp(bundlePath, dlpType, userId, appIndex);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_SEND_REQUEST_ERROR);
    std::cout << "test bundle_installer_0600 done" << std::endl;
}

/**
 * @tc.number: bundle_installer_0700
 * @tc.name: 1.test UninstallSandboxApp interface
 * @tc.desc: 1. failed condition, return false
 */
HWTEST_F(ActsBmsKitSystemTest, bundle_installer_0700, Function | MediumTest | Level1)
{
    std::cout << "begin to test bundle_installer_0700" << std::endl;
    sptr<IRemoteObject> object;
    BundleInstallerProxy installerProxy(object);
    std::string bundlePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    int32_t dlpType = 1;
    int32_t userId = 100;
    auto res = installerProxy.UninstallSandboxApp(bundlePath, dlpType, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_SEND_REQUEST_ERROR);
    std::cout << "test bundle_installer_0700 done" << std::endl;
}

/**
 * @tc.number: event_callback_0100
 * @tc.name: 1.test RegisterBundleEventCallback interface
 *           2.test UnregisterBundleEventCallback interface
 * @tc.desc: 1. success condition
 */
HWTEST_F(ActsBmsKitSystemTest, event_callback_0100, Function | MediumTest | Level1)
{
    std::cout << "begin to test event_callback_0100" << std::endl;
    int32_t originUid = geteuid();
    seteuid(Constants::FOUNDATION_UID);

    sptr<BundleEventCallbackImpl> callback = (new (std::nothrow) BundleEventCallbackImpl());
    EXPECT_NE(callback, nullptr);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    bool re = bundleMgrProxy->RegisterBundleEventCallback(callback);
    EXPECT_TRUE(re);

    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    CommonTool commonTool;
    Install(bundleFilePath, InstallFlag::NORMAL, resvec);
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    re = bundleMgrProxy->UnregisterBundleEventCallback(callback);
    EXPECT_TRUE(re);

    seteuid(originUid);
    std::cout << "test event_callback_0100 done" << std::endl;
}

/**
 * @tc.number: event_callback_0200
 * @tc.name: 1.test RegisterBundleEventCallback interface
 *           2.test UnregisterBundleEventCallback interface
 * @tc.desc: 1. failed condition, uid verify failed
 */
HWTEST_F(ActsBmsKitSystemTest, event_callback_0200, Function | MediumTest | Level1)
{
    std::cout << "begin to test event_callback_0200" << std::endl;
    sptr<BundleEventCallbackImpl> callback = (new (std::nothrow) BundleEventCallbackImpl());
    EXPECT_NE(callback, nullptr);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    bool re = bundleMgrProxy->RegisterBundleEventCallback(callback);
    EXPECT_FALSE(re);

    re = bundleMgrProxy->UnregisterBundleEventCallback(callback);
    EXPECT_FALSE(re);
    std::cout << "test event_callback_0200 done" << std::endl;
}

/**
 * @tc.number: event_callback_0300
 * @tc.name: 1.test RegisterBundleEventCallback interface
 *           2.test UnregisterBundleEventCallback interface
 * @tc.desc: 1. failed condition, invalid param
 */
HWTEST_F(ActsBmsKitSystemTest, event_callback_0300, Function | MediumTest | Level1)
{
    std::cout << "begin to test event_callback_0300" << std::endl;
    sptr<BundleEventCallbackImpl> callback = nullptr;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    bool re = bundleMgrProxy->RegisterBundleEventCallback(callback);
    EXPECT_FALSE(re);

    re = bundleMgrProxy->UnregisterBundleEventCallback(callback);
    EXPECT_FALSE(re);
    std::cout << "test event_callback_0300 done" << std::endl;
}

/**
 * @tc.number: CleanBundleCacheFiles_0100
 * @tc.name: test CleanBundleCacheFiles proxy
 * @tc.desc: 1.system run normally
 *           2.get udid info failed by wrong hap
 */
HWTEST_F(ActsBmsKitSystemTest, CleanBundleCacheFiles_0100, Function | SmallTest | Level1)
{
    sptr<ICleanCacheCallback> cleanCacheCallback;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ErrCode testRet = bundleMgrProxy->CleanBundleCacheFiles("", cleanCacheCallback, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: CleanBundleCacheFiles_0200
 * @tc.name: test CleanBundleCacheFiles proxy
 * @tc.desc: 1.system run normally
 *           2.get udid info failed by wrong hap
 */
HWTEST_F(ActsBmsKitSystemTest, CleanBundleCacheFiles_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ErrCode testRet = bundleMgrProxy->CleanBundleCacheFiles("bundleName", nullptr, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: CheckAbilityEnableInstall_0100
 * @tc.name: test CheckAbilityEnableInstall proxy
 * @tc.desc: 1.system run normally
 *           2.get udid info failed by wrong hap
 */
HWTEST_F(ActsBmsKitSystemTest, CheckAbilityEnableInstall_0100, Function | SmallTest | Level1)
{
    Want want;
    int32_t missionId = 0;
    sptr<IRemoteObject> callback;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool testRet = bundleMgrProxy->CheckAbilityEnableInstall(want, missionId, USERID, callback);
    EXPECT_EQ(testRet, false);
}
}  // namespace AppExecFwk
}  // namespace OHOS