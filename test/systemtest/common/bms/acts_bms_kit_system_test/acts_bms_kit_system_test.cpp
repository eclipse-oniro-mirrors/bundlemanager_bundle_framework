/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <fstream>
#include <future>
#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_event_callback_host.h"
#include "bundle_installer_proxy.h"
#include "bundle_mgr_proxy.h"
#include "bundle_resource_info.h"
#include "bundle_resource_proxy.h"
#include "bundle_status_callback_host.h"
#include "bundle_pack_info.h"
#include "bundle_user_info.h"
#include "clean_cache_callback_host.h"
#include "common_tool.h"
#include "extension_ability_info.h"
#include "form_info.h"
#include "permission_define.h"
#include "iservice_registry.h"
#include "launcher_ability_resource_info.h"
#include "nativetoken_kit.h"
#include "nlohmann/json.hpp"
#include "status_receiver_host.h"
#include "system_ability_definition.h"
#include "testConfigParser.h"
#include "token_setproc.h"

using OHOS::AAFwk::Want;
using namespace testing::ext;
using namespace std::chrono_literals;

namespace {
const std::string THIRD_BUNDLE_PATH = "/data/test/bms_bundle/";
const std::string EMPTY_BUNDLE_NAME = "";
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
const std::string FINGER_PRINT = "8E93863FC32EE238060BF69A9B37E2608FFFB21F93C862DD511CBAC9F30024B5";
const std::string DEFAULT_APP_BUNDLE_NAME = "com.test.defaultApp";
const std::string DEFAULT_APP_MODULE_NAME = "module01";
const std::string DEFAULT_APP_VIDEO = "VIDEO";
const std::string DEVICE_ID = "deviceID";
const std::string ROUTER_MAP_TEST_HAP = "/data/test/bms_bundle/hapIncludeso1.hap";
const std::string ROUTER_MAP_TEST_BUNDLE_NAME = "com.example.testhapso1";
const std::string ROUTER_INDEX_ZERO_URL = "DynamicPage1";
const std::string ROUTER_INDEX_ZERO_MDOULE_NAME = "entry";
const std::string ROUTER_INDEX_ZERO_PATH = "entry/src/index";
const std::string ROUTER_INDEX_ZERO_BUILD_FUNCTION = "myFunction";
const std::string ROUTER_INDEX_ONE_URL = "DynamicPage2";
const std::string ROUTER_INDEX_ONE_BUILD_FUNCTION = "myBuilder";
const std::string CONTROL_MESSAGE = "msg1_cantRun";
const std::string CURRENT_DEVICE_ID = "PHONE-001";
const std::string EMPTY_STRING = "";
const int COMPATIBLEVERSION = 3;
const int TARGETVERSION = 3;
const int32_t USERID = 100;
const int32_t RESID = 16777218;
const int32_t HUNDRED_USERID = 20010037;
const int32_t INVALIED_ID = -1;
const int32_t ZERO_SIZE = 0;
const int32_t PERMS_INDEX_ZERO = 0;
const int32_t PERMS_INDEX_ONE = 1;
const int32_t PERMS_INDEX_TWO = 2;
const int32_t PERMS_INDEX_THREE = 3;
const int32_t PERMS_INDEX_FORE = 4;
const int32_t PERMS_INDEX_FIVE = 5;
const int32_t PERMS_INDEX_SIX = 6;
const int32_t PERMS_INDEX_SEVEN = 7;
const int32_t PERMS_INDEX_EIGHT = 8;
const size_t ODID_LENGTH = 36;
const int32_t TEST_INSTALLER_UID = 100;
const int32_t TEST_APP_INDEX1 = 1;
const int32_t TEST_APP_INDEX2 = 2;
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
    void StartProcess();
    static void Install(
        const std::string &bundleFilePath, const InstallFlag installFlag, std::vector<std::string> &resvec);
    static void Install(
        const std::string &bundleFilePath, const InstallParam &installParam, std::vector<std::string> &resvec);
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

void ActsBmsKitSystemTest::StartProcess()
{
    const int32_t permsNum = 9;
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

void ActsBmsKitSystemTest::Install(
    const std::string &bundleFilePath, const InstallParam &installParam, std::vector<std::string> &resvec)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        resvec.push_back(ERROR_INSTALL_FAILED);
        return;
    }
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    bool getInfoResult =
        bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USERID);
    EXPECT_TRUE(getInfoResult);
    EXPECT_EQ(bundleInfo.name, appName);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    bool getInfoResult =
        bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USERID);
    EXPECT_TRUE(getInfoResult);
    EXPECT_EQ(bundleInfo.name, appName);
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Failure[ERR_INSTALL_INVALID_HAP_NAME]");
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    int32_t flags = 1;
    bool getInfoResult = bundleMgrProxy->GetBundleInfo("", flags, bundleInfo, USERID);
    EXPECT_FALSE(getInfoResult);
}

/**
 * @tc.number: GetBundleInfo_1000
 * @tc.name: test query bundle information
 * @tc.desc: 1.install the hap that contains router map json profile
 *           2.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfo_1000, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfo_1000" << std::endl;
    std::vector<std::string> resvec;
    Install(ROUTER_MAP_TEST_HAP, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    bool getInfoResult = bundleMgrProxy->GetBundleInfo(ROUTER_MAP_TEST_BUNDLE_NAME,
        static_cast<int32_t>(BundleFlag::GET_BUNDLE_WITH_ROUTER_MAP), bundleInfo, USERID);
    EXPECT_TRUE(getInfoResult);
    ASSERT_FALSE(bundleInfo.hapModuleInfos.empty());
    ASSERT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray.size(), PERMS_INDEX_TWO);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ZERO].name, ROUTER_INDEX_ZERO_URL);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ZERO].pageSourceFile,
        ROUTER_INDEX_ZERO_PATH);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ZERO].buildFunction,
        ROUTER_INDEX_ZERO_BUILD_FUNCTION);

    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ONE].name, ROUTER_INDEX_ONE_URL);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ONE].pageSourceFile,
        ROUTER_INDEX_ZERO_PATH);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ONE].buildFunction,
        ROUTER_INDEX_ONE_BUILD_FUNCTION);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ONE].data.size(), 2);
    resvec.clear();
    Uninstall(ROUTER_MAP_TEST_BUNDLE_NAME, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfo_1000" << std::endl;
}

/**
 * @tc.number: GetBundleInfo_1100
 * @tc.name: test query bundle information
 * @tc.desc: 1.install the hap that does not contain router map json profile
 *           2.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfo_1100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfo_1100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    bool getInfoResult = bundleMgrProxy->GetBundleInfo(appName,
        static_cast<int32_t>(BundleFlag::GET_BUNDLE_WITH_ROUTER_MAP), bundleInfo, USERID);
    EXPECT_TRUE(getInfoResult);
    ASSERT_FALSE(bundleInfo.hapModuleInfos.empty());
    EXPECT_TRUE(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray.empty());
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfo_1100" << std::endl;
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    CheckBaseBundleInfo(1, bundleInfo);
    EXPECT_FALSE(bundleInfo.hapModuleInfos.empty());
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    CheckBaseBundleInfo(1, bundleInfo);
    EXPECT_FALSE(bundleInfo.hapModuleInfos.empty());
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    EXPECT_FALSE(bundleInfo.hapModuleInfos.empty());
    EXPECT_FALSE(bundleInfo.hapModuleInfos[0].appEnvironments.empty());
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
    EXPECT_EQ(bundleInfo.applicationInfo.name, appName);
    EXPECT_FALSE(bundleInfo.applicationInfo.metadata.empty());
    EXPECT_FALSE(bundleInfo.applicationInfo.appEnvironments.empty());
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.name, appName);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
 * @tc.number: GetBundleInfoV9_0024
 * @tc.name: test query bundle information
 * @tc.desc: 1.install the hap that contains router map json profile
 *           2.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0024, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0024" << std::endl;
    std::vector<std::string> resvec;
    Install(ROUTER_MAP_TEST_HAP, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(ROUTER_MAP_TEST_BUNDLE_NAME,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ROUTER_MAP), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    ASSERT_FALSE(bundleInfo.hapModuleInfos.empty());
    ASSERT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray.size(), PERMS_INDEX_TWO);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ZERO].name, ROUTER_INDEX_ZERO_URL);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ZERO].pageSourceFile,
        ROUTER_INDEX_ZERO_PATH);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ZERO].buildFunction,
        ROUTER_INDEX_ZERO_BUILD_FUNCTION);

    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ONE].name, ROUTER_INDEX_ONE_URL);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ONE].pageSourceFile,
        ROUTER_INDEX_ZERO_PATH);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ONE].buildFunction,
        ROUTER_INDEX_ONE_BUILD_FUNCTION);
    EXPECT_EQ(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray[PERMS_INDEX_ONE].data.size(), 2);
    resvec.clear();
    Uninstall(ROUTER_MAP_TEST_BUNDLE_NAME, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0024" << std::endl;
}

/**
 * @tc.number: GetBundleInfoV9_0025
 * @tc.name: test query bundle information
 * @tc.desc: 1.install the hap that does not contain router map json profile
 *           2.query bundleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoV9_0025, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfoV9_0025" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    auto getInfoResult = bundleMgrProxy->GetBundleInfoV9(appName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ROUTER_MAP), bundleInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    ASSERT_FALSE(bundleInfo.hapModuleInfos.empty());
    EXPECT_TRUE(bundleInfo.hapModuleInfos[PERMS_INDEX_ZERO].routerArray.empty());
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetBundleInfoV9_0025" << std::endl;
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
            Install(hapFilePath, InstallFlag::REPLACE_EXISTING, resvec);
            installResult = commonTool.VectorToStr(resvec);
            EXPECT_EQ(installResult, "Success") << "install fail!";
        }
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::vector<BundleInfo> bundleInfos;
        bool getInfoResult = bundleMgrProxy->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, USERID);
        EXPECT_TRUE(getInfoResult);
    }
    std::cout << "END GetBundleInfos_0200" << std::endl;
}

/**
 * @tc.number: GetBundleInfos_0300
 * @tc.name: test query bundleinfos
 * @tc.desc: 1.under '/system/app/bms_bundle',there exist some hap
 *           2.query all bundleinfos
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfos_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleInfos_0300" << std::endl;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::vector<BundleInfo> bundleInfos;
        bool getInfoResult = bundleMgrProxy->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, INVALIED_ID);
        EXPECT_FALSE(getInfoResult);
    }
    std::cout << "END GetBundleInfos_0300" << std::endl;
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
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::vector<BundleInfo> bundleInfos;
    auto getInfoResult = bundleMgrProxy->GetBundleInfosV9(
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT), bundleInfos, Constants::INVALID_USERID);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success");

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        ApplicationInfo appInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    ApplicationInfo appInfo;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfoV9(
        appName, static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION), USERID, appInfo);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(appInfo.name, appName);
    EXPECT_FALSE(appInfo.permissions.empty());
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    ApplicationInfo appInfo;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfoV9(
        appName, static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA), USERID, appInfo);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(appInfo.name, appName);
    EXPECT_FALSE(appInfo.metadata.empty());

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
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::string installResult;
        for (int i = 6; i <= 8; i++) {
            std::vector<std::string> resvec;
            std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
            std::string appName = BASE_BUNDLE_NAME + std::to_string(i - 5);
            Install(hapFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::vector<ApplicationInfo> appInfos;
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfos(
                ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, USERID, appInfos);
        EXPECT_TRUE(getInfoResult);
    }
    std::cout << "END GetApplicationInfos_0200" << std::endl;
}

/**
 * @tc.number: GetApplicationInfos_0300
 * @tc.name: test query applicationinfos
 * @tc.desc: 1.there are some system-app installed in system
 *           2.query all appinfos
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfos_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfos_0300" << std::endl;
    for (int i = 1; i <= stLevel_.BMSLevel; i++) {
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::vector<ApplicationInfo> appInfos;
        bool getInfoResult =
            bundleMgrProxy->GetApplicationInfos(
                ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, INVALIED_ID, appInfos);
        EXPECT_FALSE(getInfoResult);
    }
    std::cout << "END GetApplicationInfos_0300" << std::endl;
}

/**
 * @tc.number: GetApplicationInfosV9_0100
 * @tc.name: test query applicationinfos
 * @tc.desc: 1.fail to query all appinfos for permission denied
 */
HWTEST_F(ActsBmsKitSystemTest, GetApplicationInfosV9_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetApplicationInfosV9_0100" << std::endl;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::vector<ApplicationInfo> appInfos;
    auto getInfoResult = bundleMgrProxy->GetApplicationInfosV9(
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT),
            Constants::INVALID_USERID, appInfos);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    std::cout << "END GetApplicationInfosV9_0100" << std::endl;
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
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        std::string abilityName = BASE_ABILITY_NAME;
        std::string appName = BASE_BUNDLE_NAME + "1";

        BundleInfo bundleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(hapFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(hapFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(hapFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        int userId = Constants::DEFAULT_USERID;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string bundleName = "";
    int uid = bundleMgrProxy->GetUidByBundleName(bundleName, USERID);
    EXPECT_EQ(uid, Constants::INVALID_UID);
    std::cout << "END GetUidByBundleName_0500" << std::endl;
}

/**
 * @tc.number: GetUidByBundleName_0600
 * @tc.name: test query UID
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.query UID by empty bundleName
 */
HWTEST_F(ActsBmsKitSystemTest, GetUidByBundleName_0600, Function | MediumTest | Level1)
{
    std::cout << "START GetUidByBundleName_0600" << std::endl;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string bundleName = "";
    int uid = bundleMgrProxy->GetUidByBundleName(bundleName, USERID, 0);
    EXPECT_EQ(uid, Constants::INVALID_UID);
    std::cout << "END GetUidByBundleName_0600" << std::endl;
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::string appType = bundleMgrProxy->GetAppType(appName);
        EXPECT_EQ(appType, EMPTY_STRING);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::string appType = bundleMgrProxy->GetAppType(SYSTEM_SETTINGS_BUNDLE_NAME);
        EXPECT_EQ(appType, EMPTY_STRING);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::string appType = bundleMgrProxy->GetAppType(errName);
        EXPECT_EQ(appType, EMPTY_STRING);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(appType.c_str(), (EMPTY_STRING).c_str()) != 0) {
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::string appType = bundleMgrProxy->GetAppType("");
        EXPECT_EQ(appType, EMPTY_STRING);
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_NE(installResult, "Success");
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::string appType = bundleMgrProxy->GetAppType(appName);
        EXPECT_EQ(appType, EMPTY_STRING);

        if (std::strcmp(appType.c_str(), (EMPTY_STRING).c_str()) != 0) {
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
        std::string abilityName = BASE_ABILITY_NAME;
        std::string label = "$string:MainAbility_label";
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        std::string abilityName = BASE_ABILITY_NAME;
        std::string label = "$string:MainAbility_label";
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::string errAppName = BASE_BUNDLE_NAME + "e";
        std::string abilityLabel = bundleMgrProxy->GetAbilityLabel(errAppName, abilityName);
        ErrCode abilityLabel1 = bundleMgrProxy->GetAbilityLabel("", abilityName, BASE_MODULE_NAME, label);
        EXPECT_EQ(abilityLabel, EMPTY_STRING);
        EXPECT_NE(abilityLabel1, ERR_OK);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(abilityLabel.c_str(), (EMPTY_STRING).c_str()) != 0) {
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::string abilityLabel = bundleMgrProxy->GetAbilityLabel(appName, errAbilityName);
        EXPECT_EQ(abilityLabel, EMPTY_STRING);
        resvec.clear();
        Uninstall(appName, resvec);
        std::string uninstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

        if (std::strcmp(abilityLabel.c_str(), (EMPTY_STRING).c_str()) != 0) {
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
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string abilityLabel = bundleMgrProxy->GetAbilityLabel("", "");
    EXPECT_EQ(abilityLabel, EMPTY_STRING);
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_NE(installResult, "Success");
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        std::string abilityLabel = bundleMgrProxy->GetAbilityLabel(appName, abilityName);
        EXPECT_EQ(abilityLabel, EMPTY_STRING);

        if (std::strcmp(abilityLabel.c_str(), (EMPTY_STRING).c_str()) != 0) {
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        AbilityInfo abilityInfo;
        abilityInfo.bundleName = appName;
        abilityInfo.package = BASE_BUNDLE_NAME + ".h1";
        HapModuleInfo hapModuleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
        EXPECT_TRUE(queryResult);

        EXPECT_EQ(hapModuleInfo.name, "bmsThirdBundle1");
        EXPECT_EQ(hapModuleInfo.moduleName, BASE_MODULE_NAME);
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        CommonTool commonTool;
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        AbilityInfo abilityInfo;
        abilityInfo.bundleName = appName;
        abilityInfo.package = BASE_BUNDLE_NAME + ".h1";
        HapModuleInfo hapModuleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        AbilityInfo abilityInfo;
        abilityInfo.bundleName = appName;
        abilityInfo.package = BASE_BUNDLE_NAME + ".h1";
        HapModuleInfo hapModuleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        AbilityInfo abilityInfo;
        abilityInfo.bundleName = "error_bundleName";
        abilityInfo.package = BASE_BUNDLE_NAME + ".h2";
        HapModuleInfo hapModuleInfo;

        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_NE(installResult, "Success") << "install fail!";

        AbilityInfo abilityInfo;
        abilityInfo.bundleName = appName;
        abilityInfo.package = BASE_BUNDLE_NAME + ".h2";
        HapModuleInfo hapModuleInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

    bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_FALSE(queryResult);

    abilityInfo.bundleName = "bundleName";
    abilityInfo.package = "";

    queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_FALSE(queryResult);
}


/**
 * @tc.number: GetHapModuleInfo_0900
 * @tc.name: test GetHapModuleInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap with one ability
 *           2.install the hap
 *           3.call GetHapModuleInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetHapModuleInfo_0900, Function | MediumTest | Level1)
{
    std::cout << "START GetHapModuleInfo_0900" << std::endl;
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = EMPTY_BUNDLE_NAME;
    abilityInfo.package = EMPTY_BUNDLE_NAME;
    HapModuleInfo hapModuleInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    bool queryResult = bundleMgrProxy->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
    EXPECT_FALSE(queryResult);
    std::cout << "END GetHapModuleInfo_0900" << std::endl;
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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
        ASSERT_NE(bundleMgrProxy, nullptr);

        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(firstFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(firstFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(firstFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
        Install(filePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        bundleMgrProxy->RegisterBundleStatusCallback(firstBundleStatusCallback);
        Install(firstFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        resvec.clear();
        sptr<BundleStatusCallbackImpl> secondBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(secondBundleStatusCallback, nullptr);
        secondBundleStatusCallback->SetBundleName(secondAppName);
        bundleMgrProxy->RegisterBundleStatusCallback(secondBundleStatusCallback);
        Install(secondFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        bundleMgrProxy->RegisterBundleStatusCallback(firstBundleStatusCallback);
        Install(firstFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        std::string firstinstallResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(firstinstallResult, "Success") << "install fail!";
        resvec.clear();
        sptr<BundleStatusCallbackImpl> secondBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(secondBundleStatusCallback, nullptr);
        secondBundleStatusCallback->SetBundleName(secondAppName);
        bundleMgrProxy->RegisterBundleStatusCallback(secondBundleStatusCallback);
        Install(secondFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        bundleMgrProxy->RegisterBundleStatusCallback(firstBundleStatusCallback);
        Install(firstFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        resvec.clear();
        sptr<BundleStatusCallbackImpl> secondBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
        EXPECT_NE(secondBundleStatusCallback, nullptr);
        secondBundleStatusCallback->SetBundleName(secondAppName);
        bundleMgrProxy->RegisterBundleStatusCallback(secondBundleStatusCallback);
        Install(secondFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
 * @tc.number: Callback_1100
 * @tc.name: 1.test RegisterBundleStatusCallback interface
 * @tc.desc: 1.install the first hap
 *           4.call RegisterBundleStatusCallback
 */
HWTEST_F(ActsBmsKitSystemTest, Callback_1100, Function | MediumTest | Level1)
{
    sptr<BundleStatusCallbackImpl> firstBundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
    EXPECT_NE(firstBundleStatusCallback, nullptr);
    firstBundleStatusCallback->SetBundleName("");

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    bool res = bundleMgrProxy->RegisterBundleStatusCallback(firstBundleStatusCallback);
    EXPECT_EQ(res, false);

    res = bundleMgrProxy->RegisterBundleStatusCallback(nullptr);
    EXPECT_EQ(res, false);

    res = bundleMgrProxy->ClearBundleStatusCallback(nullptr);
    EXPECT_EQ(res, false);
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
        std::string abilityName = BASE_ABILITY_NAME;
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        std::string abilityName = BASE_ABILITY_NAME;
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        Want want;
        ElementName name;
        name.SetBundleName("xxx");
        want.SetElement(name);

        AbilityInfo abilityInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        std::string abilityName = BASE_ABILITY_NAME;
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        std::string abilityName = BASE_ABILITY_NAME;
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    std::string abilityName = BASE_ABILITY_NAME;
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
 * @tc.number: QueryAbilityInfo_0600
 * @tc.name: test QueryAbilityInfo interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.call QueryAbilityInfo
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfo_0600, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfo_0600" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    std::string abilityName = BASE_ABILITY_NAME;
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

    int32_t flags = 4;
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    bool queryResult = bundleMgrProxy->QueryAbilityInfo(want, flags, USERID, abilityInfo, remoteObject);
    EXPECT_TRUE(queryResult);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END QueryAbilityInfo_0600" << std::endl;
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

        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        std::vector<BundleInfo> bundleInfos;

        std::string metadata = "string";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
        std::string abilityName = BASE_ABILITY_NAME;
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        CommonTool commonTool;
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        Want want;
        ElementName name;
        name.SetAbilityName(abilityName);
        name.SetBundleName(appName);
        want.SetElement(name);

        AbilityInfo abilityInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
 * @tc.number: AbilityDump_0200
 * @tc.name: Dump
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists a hap
 *           2.fd is -1
 *           3.Dump abilityInfo failed
 */
HWTEST_F(ActsBmsKitSystemTest, AbilityDump_0200, Function | MediumTest | Level0)
{
    AbilityInfo abilityInfo;
    std::string path = "/data/test/abilityInfo.txt";
    std::ofstream file(path);
    file.close();
    int fd = INVALIED_ID;
    std::string prefix = "[ability]";
    abilityInfo.Dump(prefix, fd);
    long length = lseek(fd, 0, SEEK_END);
    EXPECT_EQ(length, INVALIED_ID);
    close(fd);
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

        CommonTool commonTool;
        std::string installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";

        ApplicationInfo appInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
 * @tc.number: ApplicationInfoDump_0200
 * @tc.name: Dump
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists a hap
 *           2.fd is -1
 *           3.Dump info failed
 */
HWTEST_F(ActsBmsKitSystemTest, ApplicationInfoDump_0200, Function | MediumTest | Level0)
{
    ApplicationInfo info;
    std::string path = "/data/test/abilityInfo.txt";
    std::ofstream file(path);
    file.close();
    int fd = INVALIED_ID;
    std::string prefix = "[ability]";
    info.Dump(prefix, fd);
    long length = lseek(fd, ZERO_SIZE, SEEK_END);
    EXPECT_EQ(length, INVALIED_ID);
    close(fd);
}

/**
 * @tc.number: ApplicationInfoDump_0100
 * @tc.name: Dump
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists a hap
 *           2.install the hap
 *           3.call "GetApplicationInfo" kit
 *           4.Dump appInfo
 */
HWTEST_F(ActsBmsKitSystemTest, BundleUserInfoDump_0100, Function | MediumTest | Level1)
{
    BundleUserInfo appInfo;
    std::string path = "/data/test/appInfo.txt";
    std::ofstream file(path);
    file.close();
    int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
    EXPECT_NE(fd, INVALIED_ID) << "open file error";
    std::string prefix = "[appInfo]";
    appInfo.Dump(prefix, fd);
    long length = lseek(fd, ZERO_SIZE, SEEK_END);
    EXPECT_GT(length, ZERO_SIZE);
    close(fd);
}

/**
 * @tc.number: BundleUserInfoDump_0200
 * @tc.name: Dump
 * @tc.desc: 1.under '/data/test/bms_bundle',there exists a hap
 *           2.install the hap
 *           3.call "GetApplicationInfo" kit
 *           4.Dump appInfo
 */
HWTEST_F(ActsBmsKitSystemTest, BundleUserInfoDump_0200, Function | MediumTest | Level1)
{
    BundleUserInfo appInfo;
    std::string path = "/data/test/appInfo.txt";
    std::ofstream file(path);
    file.close();
    int fd = INVALIED_ID;
    std::string prefix = "[appInfo]";
    appInfo.Dump(prefix, fd);
    long length = lseek(fd, ZERO_SIZE, SEEK_END);
    EXPECT_EQ(length, INVALIED_ID);
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
        Install(THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap", InstallFlag::REPLACE_EXISTING, resvec);
        CommonTool commonTool;
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        ApplicationInfo appInfo;
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
        appInfo.deviceId = CURRENT_DEVICE_ID;
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
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
        ASSERT_NE(bundleMgrProxy, nullptr);

        CommonTool commonTool;
        for (int i = 6; i <= 8; i++) {
            std::vector<std::string> resvec;
            std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle" + std::to_string(i) + ".hap";
            Install(hapFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(THIRD_BUNDLE_PATH + "bmsThirdBundle6.hap", InstallFlag::REPLACE_EXISTING, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        resvec.clear();
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

        BundleInfo bundleInfo1;
        bundleMgrProxy->GetBundleInfo(BASE_BUNDLE_NAME + '1', BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
        ErrCode ret = bundleMgrProxy->GetNameForUid(bundleInfo1.uid, name1);
        EXPECT_EQ(ret, ERR_OK);
        Uninstall(BASE_BUNDLE_NAME + '1', resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "uninstall fail!";
        resvec.clear();
        Install(THIRD_BUNDLE_PATH + "bmsThirdBundle7.hap", InstallFlag::REPLACE_EXISTING, resvec);
        EXPECT_EQ(commonTool.VectorToStr(resvec), "Success") << "install fail!";
        resvec.clear();
        Install(THIRD_BUNDLE_PATH + "bmsThirdBundle6.hap", InstallFlag::REPLACE_EXISTING, resvec);
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
        Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
        sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
        ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
 * @tc.number: GetBundleGids_0100
 * @tc.name: test GetBundleGids proxy
 * @tc.desc: 1.get BundleGids
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleGids_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleGids_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::vector<int> gids;
    bool ret = bundleMgrProxy->GetBundleGids(appName, gids);
    EXPECT_FALSE(ret);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundleGids_0100" << std::endl;
}

/**
 * @tc.number: GetBundleGids_0200
 * @tc.name: test GetBundleGids proxy
 * @tc.desc: 1.get BundleGids
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleGids_0200, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleGids_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::vector<int> gids;
    int uid = bundleMgrProxy->GetUidByBundleName(appName, USERID);
    bool ret = bundleMgrProxy->GetBundleGidsByUid(appName, uid, gids);
    EXPECT_TRUE(ret);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundleGids_0100" << std::endl;
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    std::string abilityName = BASE_ABILITY_NAME;
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    std::string abilityName = BASE_ABILITY_NAME;
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
 * @tc.number: QueryAbilityInfos_0300
 * @tc.name: test QueryAbilityInfos proxy
 * @tc.desc: 1.install clone app
 *           2.query main and clone app's ability infos
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfos_0300, Function | MediumTest | Level1)
{
    StartProcess();
    std::cout << "START QueryAbilityInfos_0300" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    ASSERT_NE(installerProxy, nullptr);
    int appIndex1 = TEST_APP_INDEX1;
    ErrCode ret = installerProxy->InstallCloneApp(appName, USERID, appIndex1);
    EXPECT_EQ(ret, ERR_OK);
    int appIndex2 = TEST_APP_INDEX2;
    ret = installerProxy->InstallCloneApp(appName, USERID, appIndex2);
    EXPECT_EQ(ret, ERR_OK);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string abilityName = "MainAbility";
    Want want;
    ElementName name;
    name.SetAbilityName(abilityName);
    name.SetBundleName(appName);
    want.SetElement(name);
    std::vector<AbilityInfo> abilityInfos;
    auto queryRes = bundleMgrProxy->QueryAbilityInfos(want, GET_ABILITY_INFO_DEFAULT, USERID, abilityInfos);
    EXPECT_TRUE(queryRes);
    size_t expectedSize = 3;
    EXPECT_EQ(abilityInfos.size(), expectedSize);
    int index = 0;
    for (const auto &item : abilityInfos) {
        EXPECT_EQ(item.appIndex, index++);
    }

    ret = installerProxy->UninstallCloneApp(appName, USERID, appIndex2);
    EXPECT_EQ(ret, ERR_OK);
    ret = installerProxy->UninstallCloneApp(appName, USERID, appIndex1);
    EXPECT_EQ(ret, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END QueryAbilityInfos_0300" << std::endl;
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
    std::string abilityName = BASE_ABILITY_NAME;
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
 * @tc.number: QueryAbilityInfosV9_0200
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.query ability infos
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfosV9_0200, Function | MediumTest | Level1)
{
    StartProcess();
    std::cout << "START QueryAbilityInfosV9_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    ASSERT_NE(installerProxy, nullptr);
    int appIndex1 = TEST_APP_INDEX1;
    ErrCode ret = installerProxy->InstallCloneApp(appName, USERID, appIndex1);
    EXPECT_EQ(ret, ERR_OK);
    int appIndex2 = TEST_APP_INDEX2;
    ret = installerProxy->InstallCloneApp(appName, USERID, appIndex2);
    EXPECT_EQ(ret, ERR_OK);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string abilityName = "MainAbility";
    Want want;
    ElementName name;
    name.SetAbilityName(abilityName);
    name.SetBundleName(appName);
    want.SetElement(name);
    std::vector<AbilityInfo> abilityInfos;
    ret = bundleMgrProxy->QueryAbilityInfosV9(want, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    size_t expectedSize = 3;
    EXPECT_EQ(abilityInfos.size(), expectedSize);
    int index = 0;
    for (const auto &item : abilityInfos) {
        EXPECT_EQ(item.appIndex, index++);
    }

    ret = installerProxy->UninstallCloneApp(appName, USERID, appIndex2);
    EXPECT_EQ(ret, ERR_OK);
    ret = installerProxy->UninstallCloneApp(appName, USERID, appIndex1);
    EXPECT_EQ(ret, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END QueryAbilityInfosV9_0200" << std::endl;
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
    std::string abilityName = BASE_ABILITY_NAME;
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    BundlePackInfo bundlePackInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    BundlePackInfo bundlePackInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    std::cout << "START ImplicitQueryInfoByPriority_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    std::cout << "START ImplicitQueryInfos_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool findDefaultApp = false;
    Want want;
    ElementName name;
    name.SetAbilityName(BASE_ABILITY_NAME);
    name.SetBundleName(appName);
    want.SetElement(name);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    bool testRet = bundleMgrProxy->ImplicitQueryInfos(
        want, BundleFlag::GET_BUNDLE_DEFAULT, USERID, true, abilityInfos, extensionInfos, findDefaultApp);
    EXPECT_EQ(false, testRet);
    EXPECT_EQ(findDefaultApp, false);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<std::string> dependentModuleName;
    auto res = bundleMgrProxy->GetAllDependentModuleNames("", BASE_MODULE_NAME, dependentModuleName);
    EXPECT_FALSE(res);

    res = bundleMgrProxy->GetAllDependentModuleNames(BASE_BUNDLE_NAME, "", dependentModuleName);
    EXPECT_FALSE(res);

    res = bundleMgrProxy->GetAllDependentModuleNames("", "", dependentModuleName);
    EXPECT_FALSE(res);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    ErrCode result = bundleMgrProxy->SetModuleUpgradeFlag("", BASE_MODULE_NAME, 1);
    EXPECT_NE(result, ERR_OK);
    ErrCode result1 = bundleMgrProxy->SetModuleUpgradeFlag(BASE_BUNDLE_NAME, "", 1);
    EXPECT_NE(result1, ERR_OK);
    bool res = bundleMgrProxy->GetModuleUpgradeFlag("", BASE_MODULE_NAME);
    EXPECT_FALSE(res);

    res = bundleMgrProxy->GetModuleUpgradeFlag(BASE_BUNDLE_NAME, "");
    EXPECT_FALSE(res);

    res = bundleMgrProxy->GetModuleUpgradeFlag("", "");
    EXPECT_FALSE(res);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<int64_t> bundleStats;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    auto res = bundleMgrProxy->GetBundleStats(appName, USERID, bundleStats);
    EXPECT_TRUE(res);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundleStats_0100" << std::endl;
}

/**
 * @tc.number: GetBundleStats_0200
 * @tc.name: test can get the bundle stats info
 * @tc.desc: 1.system run normally
 *           2.install the clone app
 *           3.get bundle stats info with appIndex successfully
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleStats_0200, Function | SmallTest | Level1)
{
    StartProcess();
    std::cout << "START GetBundleStats_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    ASSERT_NE(installerProxy, nullptr);
    int appIndex1 = TEST_APP_INDEX1;
    ErrCode ret = installerProxy->InstallCloneApp(appName, USERID, appIndex1);
    EXPECT_EQ(ret, ERR_OK);

    std::vector<int64_t> bundleStats;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    auto res = bundleMgrProxy->GetBundleStats(appName, USERID, bundleStats, appIndex1);
    EXPECT_TRUE(res);

    ret = installerProxy->UninstallCloneApp(appName, USERID, appIndex1);
    EXPECT_EQ(ret, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetBundleStats_0200" << std::endl;
}
/**
 * @tc.number: GetStringById_0100
 * @tc.name: test can get the string info
 * @tc.desc: 1.system run normally
 *           2.get empty info
 */
HWTEST_F(ActsBmsKitSystemTest, GetStringById_0100, Function | SmallTest | Level1)
{
    std::cout << "START GetStringById" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<int64_t> bundleStats;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
    auto res = bundleMgrProxy->GetStringById("", BASE_MODULE_NAME, RESID, USERID);
    EXPECT_EQ(res, "");

    res = bundleMgrProxy->GetStringById(BASE_MODULE_NAME, "", RESID, USERID);
    EXPECT_EQ(res, "");

    res = bundleMgrProxy->GetStringById("", "", RESID, USERID);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<int64_t> bundleStats;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
    auto res = bundleMgrProxy->GetIconById("", BASE_MODULE_NAME, RESID, 0, USERID);
    EXPECT_EQ(res, EMPTY_STRING);

    res = bundleMgrProxy->GetIconById(BASE_MODULE_NAME, "", RESID, 0, USERID);
    EXPECT_EQ(res, EMPTY_STRING);

    res = bundleMgrProxy->GetIconById("", "", RESID, 0, USERID);
    EXPECT_EQ(res, EMPTY_STRING);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
    int32_t ret = bundleMgrProxy->GetPermissionDef(permissionName, permissionDef);
    EXPECT_EQ(permissionDef.permissionName, permissionName);
    EXPECT_NE(ret, ERR_OK);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IDefaultApp> getDefaultAppProxy = bundleMgrProxy->GetDefaultAppProxy();
    bool isDefaultApp = false;
    ErrCode res = getDefaultAppProxy->IsDefaultApplication("", isDefaultApp);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: GetDefaultAppProxy_0400
 * @tc.name: test GetDefaultAppProxy proxy
 * @tc.desc: 1.system run normally
 *           2.test GetDefaultApplication failed
 */
HWTEST_F(ActsBmsKitSystemTest, GetDefaultAppProxy_0400, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IDefaultApp> getDefaultAppProxy = bundleMgrProxy->GetDefaultAppProxy();
    BundleInfo bundleInfo;
    ErrCode result = getDefaultAppProxy->GetDefaultApplication(USERID, "", bundleInfo);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: GetDefaultAppProxy_0500
 * @tc.name: test GetDefaultAppProxy proxy
 * @tc.desc: 1.system run normally
 *           2.test ResetDefaultApplication failed
 */
HWTEST_F(ActsBmsKitSystemTest, GetDefaultAppProxy_0500, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IDefaultApp> getDefaultAppProxy = bundleMgrProxy->GetDefaultAppProxy();
    ErrCode result = getDefaultAppProxy->ResetDefaultApplication(USERID, "");
    EXPECT_NE(result, ERR_OK);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
 * @tc.number: CheckCloneAbilityEnabled_0100
 * @tc.name: test SetCloneAbilityEnabled and IsCloneAbilityEnabled proxy
 * @tc.desc: 1.system run normally
 *           2.set ability enabled
 *           3.get ability enabled
 */
HWTEST_F(ActsBmsKitSystemTest, CheckCloneAbilityEnabled_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    AbilityInfo abilityInfo;
    abilityInfo.name = BASE_ABILITY_NAME;
    abilityInfo.bundleName = ROUTER_MAP_TEST_BUNDLE_NAME;
    abilityInfo.moduleName = BASE_MODULE_NAME;
    int32_t testRet = bundleMgrProxy->SetCloneAbilityEnabled(abilityInfo, 1, false, USERID);
    EXPECT_NE(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = bundleMgrProxy->IsCloneAbilityEnabled(abilityInfo, 1, isEnable);
    EXPECT_NE(0, testRet1);
}

/**
 * @tc.number: CheckCloneApplicationEnabled_0100
 * @tc.name: test SetCloneAbilityEnabled and IsCloneAbilityEnabled proxy
 * @tc.desc: 1.system run normally
 *           2.set ability enabled
 *           3.get ability enabled
 */
HWTEST_F(ActsBmsKitSystemTest, CheckCloneApplicationEnabled_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    int32_t testRet = bundleMgrProxy->SetCloneApplicationEnabled(BASE_ABILITY_NAME, 1, false, USERID);
    EXPECT_NE(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = bundleMgrProxy->IsCloneApplicationEnabled(BASE_ABILITY_NAME, 1, isEnable);
    EXPECT_NE(0, testRet1);
}

/**
 * @tc.number: GetAllBundleInfoByDeveloperId_0001
 * @tc.name: test query bundle information
 * @tc.desc: 1.get information failed
 */
HWTEST_F(ActsBmsKitSystemTest, GetAllBundleInfoByDeveloperId_0001, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string developerId = "testDev";
    std::vector<BundleInfo> bundleInfos;
    auto res = bundleMgrProxy->GetAllBundleInfoByDeveloperId(developerId, bundleInfos, USERID);
    EXPECT_NE(res, ERR_OK);
    EXPECT_TRUE(bundleInfos.empty());
}

/**
 * @tc.number: GetDeveloperIds_0001
 * @tc.name: test query bundle information
 * @tc.desc: 1.get information failed
 */
HWTEST_F(ActsBmsKitSystemTest, GetDeveloperIds_0001, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string appDistributionType = "invalidType";
    std::vector<std::string> developerIdList;
    auto res = bundleMgrProxy->GetDeveloperIds(appDistributionType, developerIdList, USERID);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_TRUE(developerIdList.empty());
}

/**
 * @tc.number: GetExtendResourceManager_0100
 * @tc.name: test GetExtendResourceManager proxy
 * @tc.desc: GetExtendResourceManager success
 */
HWTEST_F(ActsBmsKitSystemTest, GetExtendResourceManager_0100, Function | MediumTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    sptr<IExtendResourceManager> extendResourceManagerProxy = bundleMgrProxy->GetExtendResourceManager();
    EXPECT_NE(extendResourceManagerProxy, nullptr);
}

/**
 * @tc.number: QueryCloneAbilityInfo_0100
 * @tc.name: test QueryCloneAbilityInfo proxy
 * @tc.desc: QueryCloneAbilityInfo param error
 */
HWTEST_F(ActsBmsKitSystemTest, QueryCloneAbilityInfo_0100, Function | MediumTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    const ElementName element;
    int32_t flags = 0;
    int32_t appIndex  = 0;
    AbilityInfo abilityInfo;
    int32_t userId = Constants::START_USERID;
    ErrCode res = bundleMgrProxy->QueryCloneAbilityInfo(element, flags, appIndex, abilityInfo, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_CLONE_QUERY_PARAM_ERROR);
}

/**
 * @tc.number: UninstallAndRecover_0100
 * @tc.name: test UninstallAndRecover proxy
 * @tc.desc: UninstallAndRecover return false
 */
HWTEST_F(ActsBmsKitSystemTest, UninstallAndRecover_0100, Function | MediumTest | Level1)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = TEST_INSTALLER_UID;
    std::string bundleName = BASE_BUNDLE_NAME;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    bool res = installerProxy->UninstallAndRecover(bundleName, installParam, statusReceiver);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: UninstallAndRecover_0200
 * @tc.name: test UninstallAndRecover proxy
 * @tc.desc: UninstallAndRecover return false
 */
HWTEST_F(ActsBmsKitSystemTest, UninstallAndRecover_0200, Function | MediumTest | Level1)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = TEST_INSTALLER_UID;
    std::string bundleName = BASE_BUNDLE_NAME;
    sptr<IStatusReceiver> statusReceiver;
    bool res = installerProxy->UninstallAndRecover(bundleName, installParam, statusReceiver);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstallCloneApp_0100
 * @tc.name: test InstallCloneApp proxy
 * @tc.desc: InstallCloneApp param error
 */
HWTEST_F(ActsBmsKitSystemTest, InstallCloneApp_0100, Function | MediumTest | Level1)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    ASSERT_NE(installerProxy, nullptr);
    std::string bundleName = "";
    int32_t appIndex = TEST_APP_INDEX1;
    ErrCode ret = installerProxy->InstallCloneApp(bundleName, TEST_INSTALLER_UID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BatchGetBundleInfo_0100
 * @tc.name: test BatchGetBundleInfo proxy
 * @tc.desc: BatchGetBundleInfo bundlenames
 */
HWTEST_F(ActsBmsKitSystemTest, BatchGetBundleInfo_0100, Function | MediumTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<std::string> bundleNames;
    bundleNames.push_back(appName);
    std::vector<BundleInfo> bundleInfos;
    int32_t flag = static_cast<int32_t>(BundleFlag::GET_BUNDLE_DEFAULT);
    auto bundleMgrProxy = GetBundleMgrProxy();
    ErrCode res = bundleMgrProxy->BatchGetBundleInfo(bundleNames, flag, bundleInfos, USERID);
    EXPECT_EQ(res, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: BatchGetBundleInfo_0200
 * @tc.name: test BatchGetBundleInfo proxy
 * @tc.desc: BatchGetBundleInfo wants
 */
HWTEST_F(ActsBmsKitSystemTest, BatchGetBundleInfo_0200, Function | MediumTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    Want want;
    ElementName name;
    name.SetBundleName(appName);
    want.SetElement(name);
    std::vector<Want> wants;
    wants.push_back(want);
    std::vector<BundleInfo> bundleInfos;
    int32_t flag = static_cast<int32_t>(BundleFlag::GET_BUNDLE_DEFAULT);
    auto bundleMgrProxy = GetBundleMgrProxy();
    ErrCode res = bundleMgrProxy->BatchGetBundleInfo(wants, flag, bundleInfos, USERID);
    EXPECT_EQ(res, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: BatchQueryAbilityInfos_0100
 * @tc.name: test BatchQueryAbilityInfos proxy
 * @tc.desc: BatchGetBundleInfo wants
 */
HWTEST_F(ActsBmsKitSystemTest, BatchQueryAbilityInfos_0100, Function | MediumTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    std::string abilityName = BASE_ABILITY_NAME;
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    Want want;
    ElementName name;
    name.SetAbilityName(abilityName);
    name.SetBundleName(appName);
    want.SetElement(name);
    std::vector<Want> wants;
    wants.push_back(want);
    std::vector<AbilityInfo> AbilityInfo;
    auto ret = bundleMgrProxy->BatchQueryAbilityInfos(wants, static_cast<int32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, AbilityInfo);
    EXPECT_EQ(ret, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: GetAllBundleStats_0100
 * @tc.name: test GetAllBundleStats proxy
 * @tc.desc: get bundle stats
 */
HWTEST_F(ActsBmsKitSystemTest, GetAllBundleStats_0100, Function | MediumTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    std::vector<int64_t> bundleStats;
    ErrCode res = bundleMgrProxy->GetAllBundleStats(USERID, bundleStats);
    EXPECT_TRUE(res);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
 * @tc.number: GetFormsInfoByApp_0200
 * @tc.name: test GetFormsInfoByApp proxy
 * @tc.desc: 1.system run normally
 *           2.return false
 */
HWTEST_F(ActsBmsKitSystemTest, GetFormsInfoByApp_0200, Function | SmallTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::vector<FormInfo> formInfos;
    bool ret = bundleMgrProxy->GetFormsInfoByApp(appName, formInfos);
    EXPECT_TRUE(ret);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
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
    ret = bundleMgrProxy->GetDistributedBundleInfo(networkId2, bundleName2, distributedBundleInfo);
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
    bool findDefaultApp = false;
    bool ret = bundleMgrProxy->ImplicitQueryInfos(want, flags, userId, true, abilityInfos, extensionInfos,
        findDefaultApp);
    EXPECT_TRUE(ret);
    EXPECT_EQ(findDefaultApp, false);

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
    int32_t appIndex = TEST_APP_INDEX1;
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
    int32_t appIndex = TEST_APP_INDEX1;
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
    int32_t appIndex = TEST_APP_INDEX1;
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
 * @tc.number: GetMediaData_0300
 * @tc.name: test GetMediaData proxy
 * @tc.desc: 1.system run normally
 *           2.return not ERR_OK
 */
HWTEST_F(ActsBmsKitSystemTest, GetMediaData_0300, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "invalid";
    std::string moduleName = "invalid";
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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

    ErrCode getInfoResult =
        bundleMgrProxy->GetBundleArchiveInfoV9("", 0, bundleInfo);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
    std::cout << "END GetBundleArchiveInfoV9_0200" << std::endl;
}

/**
 * @tc.number: GetBundleArchiveInfoV9_0300
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive information with signature information
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleArchiveInfoV9_0300, Function | MediumTest | Level1)
{
    std::cout << "START GetBundleArchiveInfoV9_0300" << std::endl;
    BundleInfo bundleInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string hapFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle3.hap";
    ErrCode getInfoResult = bundleMgrProxy->GetBundleArchiveInfoV9(hapFilePath,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION), bundleInfo);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(bundleInfo.signatureInfo.appId, APPID);
    EXPECT_EQ(bundleInfo.signatureInfo.fingerprint, FINGER_PRINT);
    EXPECT_EQ(bundleInfo.signatureInfo.appIdentifier, "");
    EXPECT_EQ(bundleInfo.applicationInfo.appPrivilegeLevel, "system_core");
    EXPECT_EQ(bundleInfo.applicationInfo.appProvisionType, "release");
    EXPECT_EQ(bundleInfo.applicationInfo.appDistributionType, "os_integration");
    std::cout << "END GetBundleArchiveInfoV9_0300" << std::endl;
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode testRet = bundleMgrProxy->GetShortcutInfoV9(appName, shortcutInfos);
    EXPECT_EQ(testRet, ERR_OK);

    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    int uid = bundleInfo.uid;
    std::string callingBundleName;
    bundleMgrProxy->GetNameForUid(uid, callingBundleName);
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
    ASSERT_NE(bundleMgrProxy, nullptr);

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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    std::vector<ShortcutInfo> shortcutInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    ErrCode testRet = bundleMgrProxy->GetShortcutInfoV9(appName, shortcutInfos);
    EXPECT_NE(testRet, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetShortcutInfoV9_0300" << std::endl;
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
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
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
    int32_t appIndex = TEST_APP_INDEX1;
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
 * @tc.number: bundle_installer_0800
 * @tc.name: 1.test Uninstall interface
 * @tc.desc: 1. failed condition, return false
 */
HWTEST_F(ActsBmsKitSystemTest, bundle_installer_0800, Function | MediumTest | Level1)
{
    std::cout << "begin to test bundle_installer_0800" << std::endl;
    sptr<IRemoteObject> object;
    BundleInstallerProxy installerProxy(object);
    std::string bundlePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string modulePackage = BASE_MODULE_NAME;
    UninstallParam uninstallParam;
    sptr<IStatusReceiver> statusReceiver = nullptr;
    auto res = installerProxy.Uninstall(uninstallParam, statusReceiver);
    EXPECT_FALSE(res);
    std::cout << "test bundle_installer_0800 done" << std::endl;
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
    ASSERT_NE(bundleMgrProxy, nullptr);
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
    ASSERT_NE(bundleMgrProxy, nullptr);
    ErrCode testRet = bundleMgrProxy->CleanBundleCacheFiles("bundleName", nullptr, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: CheckAbilityEnableInstall_0100
 * @tc.name: test CheckAbilityEnableInstall proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, CheckAbilityEnableInstall_0100, Function | SmallTest | Level1)
{
    Want want;
    int32_t missionId = 0;
    sptr<IRemoteObject> callback;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    bool testRet = bundleMgrProxy->CheckAbilityEnableInstall(want, missionId, USERID, callback);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: CheckAbilityEnableInstall_0200
 * @tc.name: test CheckAbilityEnableInstall proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, CheckAbilityEnableInstall_0200, Function | SmallTest | Level1)
{
    Want want;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetDeviceID(DEVICE_ID);
    elementName.SetBundleName(BASE_BUNDLE_NAME);
    want.SetElement(elementName);
    int32_t missionId = 0;
    sptr<IRemoteObject> callback;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    bool testRet = bundleMgrProxy->CheckAbilityEnableInstall(want, missionId, USERID, callback);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetBundleInfoForSelf_0100
 * @tc.name: get bundle info for self
 * @tc.desc: 1.system run normally
 *           2.get bundle info for self success
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoForSelf_0100, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    int32_t flags = 1;
    bool getInfoResult = bundleMgrProxy->GetBundleInfoForSelf(flags, bundleInfo);
    EXPECT_TRUE(getInfoResult);
}

/**
 * @tc.number: GetBundleInfoForSelf_0200
 * @tc.name: get bundle info for self
 * @tc.desc: 1.system run normally
 *           2.get bundle info for self success
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleInfoForSelf_0200, Function | MediumTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    int32_t flags = BundleFlag::GET_BUNDLE_DEFAULT;
    bool getInfoResult = bundleMgrProxy->GetBundleInfoForSelf(flags, bundleInfo);
    EXPECT_TRUE(getInfoResult);
}

/**
 * @tc.number: VerifySystemApi_0100
 * @tc.name: test VerifySystemApi proxy
 * @tc.desc: 1.system run normally
 *           2.verify system api
 */
HWTEST_F(ActsBmsKitSystemTest, VerifySystemApi_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    int32_t beginApiVersion = 1;
    auto res = bundleMgrProxy->VerifySystemApi(beginApiVersion);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: CheckNeedPreload_0100
 * @tc.name: test CheckNeedPreload
 * @tc.desc: 1.system run normally
 *           2.test failed
 */
HWTEST_F(ActsBmsKitSystemTest, CheckNeedPreload_0100, Function | SmallTest | Level1)
{
    ModuleInfo moduleInfo1;
    std::string name1 = "testCheckNeedPreload1";
    moduleInfo1.preloads.push_back(name1);
    moduleInfo1.moduleName = "testCheckNeedPreload1";

    ApplicationInfo applicationInfo;
    applicationInfo.moduleInfos.push_back(moduleInfo1);

    std::string moduleName = "testCheckNeedPreload";
    bool res = applicationInfo.CheckNeedPreload(moduleName);
    EXPECT_EQ(res, false);

    moduleName = "testCheckNeedPreload1";
    res = applicationInfo.CheckNeedPreload(moduleName);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: CheckNeedPreload_0200
 * @tc.name: test CheckNeedPreload
 * @tc.desc: 1.system run normally
 *           2.test successed
 */
HWTEST_F(ActsBmsKitSystemTest, CheckNeedPreload_0200, Function | SmallTest | Level1)
{
    ModuleInfo moduleInfo1;
    std::string name1 = "testCheckNeedPreload1";
    std::string name2 = "testCheckNeedPreload2";
    moduleInfo1.preloads.push_back(name1);
    moduleInfo1.preloads.push_back(name2);
    moduleInfo1.moduleName = "testCheckNeedPreload1";

    ApplicationInfo applicationInfo;
    applicationInfo.moduleInfos.push_back(moduleInfo1);

    std::string moduleName = "testCheckNeedPreload1";
    bool res = applicationInfo.CheckNeedPreload(moduleName);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: SilentInstall_0100
 * @tc.name: test SilentInstall proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, SilentInstall_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    bool ret = bundleMgrProxy->SilentInstall(want, USERID, nullptr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SilentInstall_0200
 * @tc.name: test SilentInstall proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, SilentInstall_0200, Function | MediumTest | Level1)
{
    std::cout << "START SilentInstall_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    std::string abilityName = BASE_ABILITY_NAME;
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);

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
    ASSERT_NE(bundleMgrProxy, nullptr);

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    bool queryResult = bundleMgrProxy->SilentInstall(want, USERID, remoteObject);
    EXPECT_TRUE(queryResult);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END SilentInstall_0200" << std::endl;
}

/**
 * @tc.number: ProcessPreload_0100
 * @tc.name: test ProcessPreload proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, ProcessPreload_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    Want want;
    want.SetElementName("", BASE_ABILITY_NAME, BASE_ABILITY_NAME, BASE_MODULE_NAME);
    bool res = bundleMgrProxy->ProcessPreload(want);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetAllSharedBundleInfo_0100
 * @tc.name: test GetAllSharedBundleInfo proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetAllSharedBundleInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = bundleMgrProxy->GetAllSharedBundleInfo(sharedBundles);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetDependentBundleInfo_0100
 * @tc.name: test GetDependentBundleInfo proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetDependentBundleInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    BundleInfo info;
    ErrCode ret = bundleMgrProxy->GetDependentBundleInfo(BASE_BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetUidByDebugBundleName_0100
 * @tc.name: test GetUidByDebugBundleName proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetUidByDebugBundleName_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    int uid = 0;
    int ret = bundleMgrProxy->GetUidByDebugBundleName(BASE_BUNDLE_NAME, uid);
    EXPECT_EQ(ret, INVALIED_ID);
}

/**
 * @tc.number: GetUidByDebugBundleName_0200
 * @tc.name: test GetUidByDebugBundleName proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetUidByDebugBundleName_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    int uid = 0;
    int ret = bundleMgrProxy->GetUidByDebugBundleName(EMPTY_BUNDLE_NAME, uid);
    EXPECT_EQ(ret, INVALIED_ID);
}

/**
 * @tc.number: GetSharedBundleInfo_0100
 * @tc.name: test GetSharedBundleInfo proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetSharedBundleInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = bundleMgrProxy->GetSharedBundleInfo(
        BASE_BUNDLE_NAME, BASE_MODULE_NAME, sharedBundles);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAppProvisionInfo_0001
 * @tc.name: test GetAppProvisionInfo proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppProvisionInfo_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    if (!bundleMgrProxy) {
        EXPECT_NE(bundleMgrProxy, nullptr);
    } else {
        AppProvisionInfo appProvisionInfo;
        ErrCode ret = bundleMgrProxy->GetAppProvisionInfo(BASE_BUNDLE_NAME, USERID, appProvisionInfo);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: GetAppProvisionInfo_0002
 * @tc.name: test GetAppProvisionInfo proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetAppProvisionInfo_0002, Function | SmallTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    AppProvisionInfo appProvisionInfo;
    ErrCode ret = bundleMgrProxy->GetAppProvisionInfo(appName, INVALIED_ID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    EXPECT_TRUE(appProvisionInfo.apl.empty());
    ret = bundleMgrProxy->GetAppProvisionInfo(appName, USERID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(appProvisionInfo.apl.empty());

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: GetSpecifiedDistributionType_0001
 * @tc.name: test GetSpecifiedDistributionType proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetSpecifiedDistributionType_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    if (!bundleMgrProxy) {
        EXPECT_NE(bundleMgrProxy, nullptr);
    } else {
        std::string specifiedDistributionType;
        ErrCode ret = bundleMgrProxy->GetSpecifiedDistributionType(BASE_BUNDLE_NAME, specifiedDistributionType);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: GetSpecifiedDistributionType_0002
 * @tc.name: test GetSpecifiedDistributionType proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetSpecifiedDistributionType_0002, Function | SmallTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string specifiedDistributionType;
    auto ret = bundleMgrProxy->GetSpecifiedDistributionType(appName, specifiedDistributionType);
    EXPECT_EQ(ret, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: GetAdditionalInfo_0001
 * @tc.name: test GetAdditionalInfo proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetAdditionalInfo_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    if (!bundleMgrProxy) {
        EXPECT_NE(bundleMgrProxy, nullptr);
    } else {
        std::string additionalInfo;
        ErrCode ret = bundleMgrProxy->GetAdditionalInfo(BASE_BUNDLE_NAME, additionalInfo);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: GetAllProxyDataInfos_0100
 * @tc.name: test GetAllProxyDataInfos proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetAllProxyDataInfos_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = bundleMgrProxy->GetAllProxyDataInfos(proxyDatas);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetProxyDataInfos_0100
 * @tc.name: test GetProxyDataInfos proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetProxyDataInfos_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = bundleMgrProxy->GetProxyDataInfos(
        BASE_BUNDLE_NAME, BASE_MODULE_NAME, proxyDatas);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetProxyDataInfos_0200
 * @tc.name: test GetProxyDataInfos proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetProxyDataInfos_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = bundleMgrProxy->GetProxyDataInfos(
        "", BASE_MODULE_NAME, proxyDatas);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: GetAdditionalInfo_0002
 * @tc.name: test GetAdditionalInfo proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetAdditionalInfo_0002, Function | SmallTest | Level1)
{
    std::cout << "START GetAdditionalInfo_0002" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string additionalInfo;
    auto ret = bundleMgrProxy->GetAdditionalInfo(appName, additionalInfo);
    EXPECT_EQ(ret, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetAdditionalInfo_0002" << std::endl;
}

/**
 * @tc.number: GetAdditionalInfo_0003
 * @tc.name: test GetAdditionalInfo proxy
 * @tc.desc: 1.system run normally
 *           2.SetAdditionalInfo and SetSpecifiedDistributionType
 */
HWTEST_F(ActsBmsKitSystemTest, GetAdditionalInfo_0003, Function | SmallTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.specifiedDistributionType = "specifiedDistributionType";
    installParam.additionalInfo = "additionalInfo";
    Install(bundleFilePath, installParam, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string additionalInfo;
    ErrCode ret = bundleMgrProxy->GetAdditionalInfo(appName, additionalInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(installParam.additionalInfo, additionalInfo);
    std::string specifiedDistributionType;
    ret = bundleMgrProxy->GetSpecifiedDistributionType(appName, specifiedDistributionType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(installParam.specifiedDistributionType, specifiedDistributionType);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: GetAdditionalInfo_0004
 * @tc.name: test  GetAdditionalInfo proxy
 * @tc.desc: 1.system run normally
 *           2.2.SetAdditionalInfo and SetSpecifiedDistributionType
 */
HWTEST_F(ActsBmsKitSystemTest, GetAdditionalInfo_0004, Function | SmallTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.specifiedDistributionType = "specifiedDistributionType";
    installParam.additionalInfo = "additionalInfo";
    Install(bundleFilePath, installParam, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    // update hap
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.additionalInfo = "modify additionalInfo";
    resvec.clear();
    Install(bundleFilePath, installParam, resvec);
    installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string additionalInfo;
    ErrCode ret = bundleMgrProxy->GetAdditionalInfo(appName, additionalInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(installParam.additionalInfo, additionalInfo);
    std::string specifiedDistributionType;
    ret = bundleMgrProxy->GetSpecifiedDistributionType(appName, specifiedDistributionType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(installParam.specifiedDistributionType, specifiedDistributionType);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: DumpInfos_0001
 * @tc.name: test  DumpInfos proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, DumpInfos_0001, Function | SmallTest | Level1)
{
    std::cout << "START GetAdditionalInfo_0002" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string result;
    auto ret = bundleMgrProxy->DumpInfos(DumpFlag::DUMP_BUNDLE_INFO, appName, USERID, result);
    EXPECT_EQ(ret, true);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetAdditionalInfo_0002" << std::endl;
}

/**
 * @tc.number: GetOverlayManagerProxy_0100
 * @tc.name: test GetFormsInfoByModule proxy
 * @tc.desc: 1.system run normally
 *           2.return true
 */
HWTEST_F(ActsBmsKitSystemTest, GetOverlayManagerProxy_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IOverlayManager> ret = bundleMgrProxy->GetOverlayManagerProxy();
    EXPECT_NE(ret, nullptr);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
}

/**
 * @tc.number: QueryAppGalleryBundleName_0100
 * @tc.name: test BundleMgr proxy
 * @tc.desc: 1.system run normally
 *           2.return true
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAppGalleryBundleName_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName;
    bool ret = bundleMgrProxy->QueryAppGalleryBundleName(bundleName);
    #ifdef USE_KIT_STSTEM
    EXPECT_TRUE(ret);
    #else
    EXPECT_FALSE(ret);
    #endif
}

/**
 * @tc.number: ResetAOTCompileStatus_0100
 * @tc.name: ResetAOTCompileStatus testcase
 * @tc.desc: 1.bundleName and moduleName exist, call ResetAOTCompileStatus
 *           2.return ERR_OK
 */
HWTEST_F(ActsBmsKitSystemTest, ResetAOTCompileStatus_0100, Function | SmallTest | Level1)
{
    APP_LOGI("ResetAOTCompileStatus_0100 begin");
    // install
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName = "com.example.ohosproject.hmservice";
    std::string moduleName = "entry_phone";
    int32_t triggerMode = 0;

    int32_t originUid = geteuid();
    int32_t uid = bundleMgrProxy->GetUidByBundleName(bundleName, USERID);
    APP_LOGI("uid : %{public}d", uid);
    seteuid(uid);
    // success testcase
    ErrCode ret = bundleMgrProxy->ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
    EXPECT_EQ(ret, ERR_OK);
    // moduleName not exist testcase
    moduleName = "notExistModuleName";
    ret = bundleMgrProxy->ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    seteuid(originUid);
    // uninstall
    resvec.clear();
    Uninstall(bundleName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    APP_LOGI("ResetAOTCompileStatus_0100 end");
}

/**
 * @tc.number: ResetAOTCompileStatus_0200
 * @tc.name: failed testcase, invalid param
 * @tc.desc: 1.call ResetAOTCompileStatus
 *           2.return ERR_BUNDLE_MANAGER_INVALID_PARAMETER
 */
HWTEST_F(ActsBmsKitSystemTest, ResetAOTCompileStatus_0200, Function | SmallTest | Level1)
{
    APP_LOGI("ResetAOTCompileStatus_0200 begin");
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string bundleName = "bundleName";
    std::string moduleName = "moduleName";
    int32_t triggerMode = 0;

    ErrCode ret = bundleMgrProxy->ResetAOTCompileStatus(EMPTY_STRING, moduleName, triggerMode);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    ret = bundleMgrProxy->ResetAOTCompileStatus(bundleName, EMPTY_STRING, triggerMode);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    APP_LOGI("ResetAOTCompileStatus_0200 end");
}

/**
 * @tc.number: ResetAOTCompileStatus_0300
 * @tc.name: failed testcase, invalid calling uid
 * @tc.desc: 1.call ResetAOTCompileStatus
 *           2.return ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(ActsBmsKitSystemTest, ResetAOTCompileStatus_0300, Function | SmallTest | Level1)
{
    APP_LOGI("ResetAOTCompileStatus_0300 begin");
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string bundleName = "bundleName";
    std::string moduleName = "moduleName";
    int32_t triggerMode = 0;
    ErrCode ret = bundleMgrProxy->ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);

    int32_t originUid = geteuid();
    int32_t invalidUid = 1234567;
    seteuid(invalidUid);

    ret = bundleMgrProxy->ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    seteuid(originUid);
    APP_LOGI("ResetAOTCompileStatus_0300 end");
}

/**
 * @tc.number: GetJsonProfile_0100
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call GetJsonProfile
 *           2.return ERR_BUNDLE_MANAGER_PARAM_ERROR
 */
HWTEST_F(ActsBmsKitSystemTest, GetJsonProfile_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string profile;
    ErrCode ret = bundleMgrProxy->GetJsonProfile(ProfileType::INTENT_PROFILE, "", BASE_MODULE_NAME, profile);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: GetJsonProfile_0200
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call GetJsonProfile
 *           2.return ERR_APPEXECFWK_PARCEL_ERROR
 */
HWTEST_F(ActsBmsKitSystemTest, GetJsonProfile_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string profile;
    ErrCode ret = bundleMgrProxy->GetJsonProfile(
        ProfileType::INTENT_PROFILE, BASE_BUNDLE_NAME, BASE_MODULE_NAME, profile);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: QueryExtensionAbilityInfosWithTypeName_0100
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call QueryExtensionAbilityInfosWithTypeName
 *           2.return ERR_APPEXECFWK_PARCEL_ERROR
 */
HWTEST_F(ActsBmsKitSystemTest, QueryExtensionAbilityInfosWithTypeName_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    Want want;
    int32_t flag = 0;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = bundleMgrProxy->QueryExtensionAbilityInfosWithTypeName(want, "", flag, USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: GetBundleResourceInfo_0001
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call GetBundleResourceInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetBundleResourceInfo_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            BundleResourceInfo info;
            ErrCode ret = proxy->GetBundleResourceInfo(EMPTY_BUNDLE_NAME,
                static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
            ret = proxy->GetBundleResourceInfo(BASE_MODULE_NAME,
                static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
        }
    }
}

/**
 * @tc.number: GetLauncherAbilityResourceInfo_0001
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call GetLauncherAbilityResourceInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetLauncherAbilityResourceInfo_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<LauncherAbilityResourceInfo> infos;
            ErrCode ret = proxy->GetLauncherAbilityResourceInfo(EMPTY_BUNDLE_NAME,
                static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
            ret = proxy->GetLauncherAbilityResourceInfo(BASE_MODULE_NAME,
                static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
        }
    }
}

/**
 * @tc.number: GetAllBundleResourceInfo_0001
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call GetAllBundleResourceInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetAllBundleResourceInfo_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<BundleResourceInfo> info;
            ErrCode ret = proxy->GetAllBundleResourceInfo(
                static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
        }
    }
}

/**
 * @tc.number: GetAllLauncherAbilityResourceInfo_0001
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call GetALLLauncherAbilityResourceInfo
 */
HWTEST_F(ActsBmsKitSystemTest, GetAllLauncherAbilityResourceInfo_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<LauncherAbilityResourceInfo> infos;
            ErrCode ret = proxy->GetAllLauncherAbilityResourceInfo(
                static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
        }
    }
}

/**
 * @tc.number: SendRequest_0001
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call SendRequest
 */
HWTEST_F(ActsBmsKitSystemTest, SendRequest_0001, Function | SmallTest | Level1)
{
    sptr<IRemoteObject> object;
    BundleResourceProxy resourceProxy(object);
    MessageParcel data;
    MessageParcel reply;
    bool ret = resourceProxy.SendRequest(BundleResourceInterfaceCode::GET_BUNDLE_RESOURCE_INFO, data, reply);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetDefaultAppProxy_0200
 * @tc.name: test GetDefaultAppProxy proxy
 * @tc.desc: 1.system run normally
 */
HWTEST_F(ActsBmsKitSystemTest, GetDefaultAppProxy_0200, Function | SmallTest | Level1)
{
    StartProcess();
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IDefaultApp> getDefaultAppProxy = bundleMgrProxy->GetDefaultAppProxy();
    AAFwk::Want want;
    ElementName elementName(
        "", DEFAULT_APP_BUNDLE_NAME, DEFAULT_APP_MODULE_NAME, DEFAULT_APP_VIDEO);
    want.SetElement(elementName);
    ErrCode res = getDefaultAppProxy->SetDefaultApplication(USERID, DEFAULT_APP_VIDEO, want);
    EXPECT_NE(res, ERR_OK);
    BundleInfo bundleInfo;
    res = getDefaultAppProxy->GetDefaultApplication(USERID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_NE(res, ERR_OK);
    res = getDefaultAppProxy->ResetDefaultApplication(USERID, DEFAULT_APP_VIDEO);
    EXPECT_EQ(res, ERR_OK);
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
        Install(hapFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
    }
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
        Install(hapFilePath, InstallFlag::REPLACE_EXISTING, resvec);
        installResult = commonTool.VectorToStr(resvec);
        EXPECT_EQ(installResult, "Success") << "install fail!";
    }
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

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
 * @tc.number: CanOpenLink_0001
 * @tc.name: test CanOpenLink interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the app
 *           3.call CanOpenLink
 */
HWTEST_F(ActsBmsKitSystemTest, CanOpenLink_0001, Function | MediumTest | Level1)
{
    std::cout << "START CanOpenLink_0001" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    setuid(bundleInfo.uid);

    std::string link = "http://";
    bool canOpen = false;
    auto queryResult =
        bundleMgrProxy->CanOpenLink(link, canOpen);

    setuid(Constants::ROOT_UID);

    EXPECT_EQ(queryResult, ERR_OK);
    EXPECT_TRUE(canOpen);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END CanOpenLink_0001" << std::endl;
}

/**
 * @tc.number: CanOpenLink_0002
 * @tc.name: test CanOpenLink interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the app
 *           3.call CanOpenLink
 */
HWTEST_F(ActsBmsKitSystemTest, CanOpenLink_0002, Function | MediumTest | Level1)
{
    std::cout << "START CanOpenLink_0002" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    setuid(bundleInfo.uid);

    std::string link = "welink://";
    bool canOpen = false;
    auto queryResult =
        bundleMgrProxy->CanOpenLink(link, canOpen);

    setuid(Constants::ROOT_UID);

    EXPECT_EQ(queryResult, ERR_OK);
    EXPECT_FALSE(canOpen);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END CanOpenLink_0002" << std::endl;
}

/**
 * @tc.number: CanOpenLink_0003
 * @tc.name: test CanOpenLink interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the app
 *           3.call CanOpenLink
 */
HWTEST_F(ActsBmsKitSystemTest, CanOpenLink_0003, Function | MediumTest | Level1)
{
    std::cout << "START CanOpenLink_0003" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    setuid(bundleInfo.uid);

    std::string link = "https://";
    bool canOpen = false;
    auto queryResult =
        bundleMgrProxy->CanOpenLink(link, canOpen);

    setuid(Constants::ROOT_UID);

    EXPECT_NE(queryResult, ERR_OK);
    EXPECT_FALSE(canOpen);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END CanOpenLink_0003" << std::endl;
}

/**
 * @tc.number: GetOdid_0001
 * @tc.name: test GetOdid interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the app
 *           3.call GetOdid
 */
HWTEST_F(ActsBmsKitSystemTest, GetOdid_0001, Function | MediumTest | Level1)
{
    std::cout << "START GetOdid_0001" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);

    setuid(bundleInfo.uid);
    std::string odid;
    auto queryResult = bundleMgrProxy->GetOdid(odid);
    setuid(Constants::ROOT_UID);

    EXPECT_EQ(queryResult, ERR_OK);
    EXPECT_EQ(odid.size(), ODID_LENGTH);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetOdid_0001" << std::endl;
}

/**
 * @tc.number: GetOdid_0002
 * @tc.name: test GetOdid interface
 * @tc.desc: GetOdid failed for calling uid is invalid
 */
HWTEST_F(ActsBmsKitSystemTest, GetOdid_0002, Function | MediumTest | Level1)
{
    std::cout << "START GetOdid_0002" << std::endl;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string odid;
    auto queryResult = bundleMgrProxy->GetOdid(odid);

    EXPECT_NE(queryResult, ERR_OK);
    EXPECT_TRUE(odid.empty());

    std::cout << "END GetOdid_0002" << std::endl;
}

/**
 * @tc.number: AppControlCache_0001
 * @tc.name: test app control cache
 * @tc.desc: test app control cache
 */
HWTEST_F(ActsBmsKitSystemTest, AppControlCache_0001, Function | MediumTest | Level1)
{
    std::cout << "START AppControlCache_0001" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle24.hap";
    std::string appName = BASE_BUNDLE_NAME + "1";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    sptr<IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    setuid(3057);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule controlRule;
    controlRule.appId = APPID;
    controlRule.controlMessage = CONTROL_MESSAGE;
    controlRules.emplace_back(controlRule);
    ErrCode res = appControlProxy->AddAppRunningControlRule(controlRules, USERID);
    EXPECT_EQ(res, ERR_OK);
    setuid(5523);
    AppRunningControlRuleResult controlRuleResult;
    res = appControlProxy->GetAppRunningControlRule(appName, USERID, controlRuleResult);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(controlRuleResult.controlMessage, CONTROL_MESSAGE);
    setuid(3057);
    res = appControlProxy->DeleteAppRunningControlRule(USERID);
    EXPECT_EQ(res, ERR_OK);
    setuid(5523);
    AppRunningControlRuleResult controlRuleResult2;
    res = appControlProxy->GetAppRunningControlRule(appName, USERID, controlRuleResult2);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL);
    EXPECT_EQ(controlRuleResult2.controlMessage, "");
    Uninstall(appName, resvec);
    std::cout << "END AppControlCache_0001" << std::endl;
}

/**
 * @tc.number: SwitchUninstallState_0001
 * @tc.name: test SwitchUninstallState interface
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the app
 *           3.call SwitchUninstallState
 */
HWTEST_F(ActsBmsKitSystemTest, SwitchUninstallState_0001, Function | MediumTest | Level1)
{
    std::cout << "START SwitchUninstallState_0001" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    auto queryResult = bundleMgrProxy->SwitchUninstallState(appName, false);
    EXPECT_EQ(queryResult, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_NE(uninstallResult, "Success");

    queryResult = bundleMgrProxy->SwitchUninstallState(appName, true);
    EXPECT_EQ(queryResult, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END SwitchUninstallState_0001" << std::endl;
}

/**
 * @tc.number: SwitchUninstallState_0002
 * @tc.name: test SwitchUninstallState interface
 * @tc.desc: SwitchUninstallState failed for bundleName is empty
 */
HWTEST_F(ActsBmsKitSystemTest, SwitchUninstallState_0002, Function | MediumTest | Level1)
{
    std::cout << "START SwitchUninstallState_0002" << std::endl;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    auto queryResult = bundleMgrProxy->SwitchUninstallState("", false);
    EXPECT_NE(queryResult, ERR_OK);

    std::cout << "END SwitchUninstallState_0002" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfoByContinueType_0001
 * @tc.name: test query ability information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get ability successfully
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfoByContinueType_0001, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfoByContinueType_0001" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string continueType = "BROWSER";
    AbilityInfo abilityInfo;
    auto getInfoResult = bundleMgrProxy->QueryAbilityInfoByContinueType(appName, continueType, abilityInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_OK);
    EXPECT_EQ(abilityInfo.bundleName, appName);
    EXPECT_EQ(abilityInfo.continueType[0], continueType);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END QueryAbilityInfoByContinueType_0001" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfoByContinueType_0002
 * @tc.name: test query ability information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get ability failed
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfoByContinueType_0002, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfoByContinueType_0002" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string continueType = "BROWSER1";
    AbilityInfo abilityInfo;
    auto getInfoResult = bundleMgrProxy->QueryAbilityInfoByContinueType(appName, continueType, abilityInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END QueryAbilityInfoByContinueType_0002" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfoByContinueType_0003
 * @tc.name: test query ability information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get ability failed
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfoByContinueType_0003, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfoByContinueType_0003" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string continueType = "BROWSER";
    AbilityInfo abilityInfo;
    auto getInfoResult = bundleMgrProxy->QueryAbilityInfoByContinueType(appName, continueType, abilityInfo, 110);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END QueryAbilityInfoByContinueType_0003" << std::endl;
}

/**
 * @tc.number: QueryAbilityInfoByContinueType_0004
 * @tc.name: test query ability information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the hap
 *           3.get ability failed
 */
HWTEST_F(ActsBmsKitSystemTest, QueryAbilityInfoByContinueType_0004, Function | MediumTest | Level1)
{
    std::cout << "START QueryAbilityInfoByContinueType_0004" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::string continueType = "BROWSER";
    AbilityInfo abilityInfo;
    auto getInfoResult = bundleMgrProxy->QueryAbilityInfoByContinueType("appName", continueType, abilityInfo, USERID);
    EXPECT_EQ(getInfoResult, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END QueryAbilityInfoByContinueType_0004" << std::endl;
}

/**
 * @tc.number: InstallCloneAppTest001_AppNotExist
 * @tc.name: test install clone app failed: app not exists
 * @tc.desc: 1.use a invalid bundleName when install clone app
 *           2.get the result
 */
HWTEST_F(ActsBmsKitSystemTest, InstallCloneAppTest001_AppNotExist, Function | MediumTest | Level1)
{
    StartProcess();
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return;
    }
    const std::string bundleName = "ohos.samples.appnotfound";
    const int32_t userId = 100;
    int32_t appIndex = TEST_APP_INDEX1;
    auto result = installerProxy->InstallCloneApp(bundleName, userId, appIndex);

    EXPECT_TRUE(result == ERR_APPEXECFWK_CLONE_INSTALL_APP_NOT_EXISTED
        || result == ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: InstallCloneAppTest002_UserNotFound
 * @tc.name: test install clone app failed: user not exists
 * @tc.desc: 1.use a userId not in system when install clone app
 *           2.get the result
 */
HWTEST_F(ActsBmsKitSystemTest, InstallCloneAppTest002_UserNotFound, Function | MediumTest | Level1)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return;
    }
    const std::string bundleName = "ohos.samples.etsclock";
    const int32_t userId = 200; // ensure userId 200 not in system
    int32_t appIndex = TEST_APP_INDEX1;
    auto result = installerProxy->InstallCloneApp(bundleName, userId, appIndex);
    EXPECT_TRUE(result == ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST
        || result == ERR_APPEXECFWK_PERMISSION_DENIED || result == ERR_APPEXECFWK_CLONE_INSTALL_APP_NOT_EXISTED);
}

/**
 * @tc.number: GetCloneAppIndexes_0001
 * @tc.name: test query clone app's indexes
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.install the clone app
 *           3.get clone app's indexes
 */
HWTEST_F(ActsBmsKitSystemTest, GetCloneAppIndexes_0001, Function | MediumTest | Level1)
{
    std::cout << "START GetCloneAppIndexes_0001" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    int32_t appIndex = TEST_APP_INDEX1;
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    ASSERT_NE(installerProxy, nullptr);
    ErrCode ret = installerProxy->InstallCloneApp(appName, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<int32_t> appIndexes;
    ret = bundleMgrProxy->GetCloneAppIndexes(appName, appIndexes, USERID);
    EXPECT_EQ(ret, ERR_OK) << "GetCloneAppIndexes fail!";
    EXPECT_EQ(appIndexes.size(), 1);

    ret = installerProxy->UninstallCloneApp(appName, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END GetCloneAppIndexes_0001" << std::endl;
}

/**
 * @tc.number: GetNameAndIndexForUid_0100
 * @tc.name: test get name and appIndex by uid
 * @tc.desc: 1.get bundleName and appIndex by uid
 */
HWTEST_F(ActsBmsKitSystemTest, GetNameAndIndexForUid_0100, Function | MediumTest | Level1)
{
    std::cout << "START GetNameAndIndexForUid_0100" << std::endl;
    CommonTool commonTool;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bundleClient1.hap";
    std::string appName = "com.example.ohosproject.hmservice";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    BundleInfo bundleInfo;
    bundleMgrProxy->GetBundleInfo(appName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);

    std::string name;
    int32_t testAppIndex = -1;
    ErrCode ret = bundleMgrProxy->GetNameAndIndexForUid(bundleInfo.uid, name, testAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(name, appName);
    EXPECT_EQ(testAppIndex, 0);

    resvec.clear();
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";
    std::cout << "END GetNameAndIndexForUid_0100" << std::endl;
}

/**
 * @tc.number: AddResourceInfoByBundleName_0001
 * @tc.name: test BundleResourceProxy
 * @tc.desc: 1.call AddResourceInfoByBundleName
 */
HWTEST_F(ActsBmsKitSystemTest, AddResourceInfoByBundleName_0001, Function | SmallTest | Level1)
{
    APP_LOGD("AddResourceInfoByBundleName_0001 start");
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        std::cout << "START AddResourceInfoByBundleName_0001 bundleMgrProxy is null" << std::endl;
        auto proxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::cout << "START AddResourceInfoByBundleName_0001 proxy is null" << std::endl;
            ErrCode ret = proxy->AddResourceInfoByBundleName(EMPTY_BUNDLE_NAME, USERID);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
            ret = proxy->AddResourceInfoByBundleName(BASE_BUNDLE_NAME, -USERID);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
            ret = proxy->AddResourceInfoByBundleName(BASE_BUNDLE_NAME, USERID);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
        } else {
            APP_LOGE("AddResourceInfoByBundleName_0001 proxy is null");
        }
    } else {
        APP_LOGE("AddResourceInfoByBundleName_0001 bundleMgrProxy is null");
    }
    APP_LOGD("AddResourceInfoByBundleName_0001 end");
}

/**
 * @tc.number: AddResourceInfoByAbility_0001
 * @tc.name: test BundleResourceProxy
 * @tc.desc: 1.call AddResourceInfoByAbility
 */
HWTEST_F(ActsBmsKitSystemTest, AddResourceInfoByAbility_0001, Function | SmallTest | Level1)
{
    APP_LOGD("AddResourceInfoByAbility_0001 start");
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        std::cout << "AddResourceInfoByAbility_0001 bundleMgrProxy is null" << std::endl;
        auto proxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::cout << "AddResourceInfoByAbility_0001 proxy is null" << std::endl;
            ErrCode ret = proxy->AddResourceInfoByAbility(EMPTY_BUNDLE_NAME, BASE_MODULE_NAME, BASE_ABILITY_NAME,
                USERID);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
            ret = proxy->AddResourceInfoByAbility(BASE_BUNDLE_NAME, "", BASE_ABILITY_NAME, USERID);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
            ret = proxy->AddResourceInfoByAbility(BASE_BUNDLE_NAME, BASE_MODULE_NAME, "", USERID);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
            ret = proxy->AddResourceInfoByAbility(BASE_BUNDLE_NAME, BASE_MODULE_NAME, BASE_ABILITY_NAME, -USERID);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
            ret = proxy->AddResourceInfoByAbility(BASE_BUNDLE_NAME, BASE_MODULE_NAME, BASE_ABILITY_NAME, USERID);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
        } else {
            APP_LOGE("AddResourceInfoByAbility_0001 proxy is null");
        }
    } else {
        APP_LOGE("AddResourceInfoByAbility_0001 bundleMgrProxy is null");
    }
    APP_LOGD("AddResourceInfoByAbility_0001 end");
}

/**
 * @tc.number: DeleteResourceInfo_0001
 * @tc.name: test BundleResourceProxy
 * @tc.desc: 1.call DeleteResourceInfo
 */
HWTEST_F(ActsBmsKitSystemTest, DeleteResourceInfo_0001, Function | SmallTest | Level1)
{
    APP_LOGD("DeleteResourceInfo_0001 start");
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            ErrCode ret = proxy->DeleteResourceInfo("");
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
            ret = proxy->DeleteResourceInfo(BASE_BUNDLE_NAME);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
        } else {
            APP_LOGE("DeleteResourceInfo_0001 proxy is null");
        }
    } else {
        APP_LOGE("DeleteResourceInfo_0001 bundleMgrProxy is null");
    }
    APP_LOGD("DeleteResourceInfo_0001 end");
}

}  // namespace AppExecFwk
}  // namespace OHOS