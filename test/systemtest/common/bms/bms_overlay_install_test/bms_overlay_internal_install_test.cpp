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

#include <fstream>
#include <future>
#include <gtest/gtest.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_installer_interface.h"
#include "bundle_mgr_interface.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_tool.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "status_receiver_host.h"

using namespace testing::ext;
using namespace std::chrono_literals;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TIMEOUT = 5;
constexpr int32_t USERID = 100;
constexpr int32_t DEFAULT_PRIORITY = 1;
constexpr int32_t OVERLAY_MODULE_INFO_SIZE = 2;
constexpr int32_t MIN_OVERLAY_MODULE_INFO_SIZE = 1;
constexpr int32_t HIGHER_VERSION_CODE = 1000001;
const std::string TARGET_MODULE_ENTRY_PATH = "/data/test/internalOverlayTest/entry_hap.hap";
const std::string TARGET_MODULE_HIGHER_VERSION_ENTRY_PATH =
    "/data/test/internalOverlayTest/higher_version_entry_hap.hap";
const std::string TARGET_MODULE_FEATURE_PATH = "/data/test/internalOverlayTest/feature_hap.hap";
const std::string TARGET_MODULE_HIGHER_VERSION_FEATURE_PATH =
    "/data/test/internalOverlayTest/higher_version_feature_hap.hap";
const std::string INTERNAL_OVERLAY_TEST1_PATH = "/data/test/internalOverlayTest/test1/internalOverlayTest1.hsp";
const std::string INTERNAL_OVERLAY_TEST2_PATH1 = "/data/test/internalOverlayTest/test2/priority_0.hsp";
const std::string INTERNAL_OVERLAY_TEST2_PATH2 = "/data/test/internalOverlayTest/test2/priority_101.hsp";
const std::string INTERNAL_OVERLAY_TEST3_PATH = "/data/test/internalOverlayTest/test3/internalOverlayTest3.hsp";
const std::string INTERNAL_OVERLAY_TEST4_PATH = "/data/test/internalOverlayTest/test4/internalOverlayTest4.hsp";
const std::string INTERNAL_OVERLAY_TEST5_PATH = "/data/test/internalOverlayTest/test5/internalOverlayTest5.hsp";
const std::string INTERNAL_OVERLAY_TEST6_PATH = "/data/test/internalOverlayTest/test6/internalOverlayTest6.hsp";
const std::string INTERNAL_OVERLAY_TEST7_PATH = "/data/test/internalOverlayTest/test7/internalOverlayTest6.hsp";
const std::string INTERNAL_OVERLAY_TEST8_PATH = "/data/test/internalOverlayTest/test8/internalOverlayTest6.hsp";
const std::string INTERNAL_OVERLAY_TEST9_PATH = "/data/test/internalOverlayTest/test9/internalOverlayTest6.hsp";
const std::string INTERNAL_OVERLAY_TEST10_PATH = "/data/test/internalOverlayTest/test10/internalOverlayTest6.hsp";
const std::string INTERNAL_OVERLAY_TEST12_PATH1 = "/data/test/internalOverlayTest/test12/internalOverlayTest6.hsp";
const std::string INTERNAL_OVERLAY_TEST12_PATH2 = "/data/test/internalOverlayTest/test12/internalOverlayTest12.hsp";
const std::string INTERNAL_OVERLAY_TEST14_PATH1 = "/data/test/internalOverlayTest/entry_hap.hap";
const std::string INTERNAL_OVERLAY_TEST14_PATH2 = "/data/test/internalOverlayTest/test14";
const std::string INTERNAL_OVERLAY_TEST15_PATH = "/data/test/internalOverlayTest/test15/internalOverlayTest15.hsp";
const std::string INTERNAL_OVERLAY_TEST16_PATH = "/data/test/internalOverlayTest/test16/internalOverlayTest1.hsp";
const std::string INTERNAL_OVERLAY_TEST17_PATH1 = "/data/test/internalOverlayTest/test17/internalOverlayTest1.hsp";
const std::string INTERNAL_OVERLAY_TEST17_PATH2 = "/data/test/internalOverlayTest/test17/internalOverlayTest15.hsp";
const std::string INTERNAL_OVERLAY_TEST18_PATH1 = "/data/test/internalOverlayTest/test18/internalOverlayTest12.hsp";
const std::string INTERNAL_OVERLAY_TEST18_PATH2 = "/data/test/internalOverlayTest/test18/higher_version_feature_hap.hap";
const std::string INTERNAL_OVERLAY_TEST19_PATH1 = "/data/test/internalOverlayTest/test19/entry_hap.hap";
const std::string INTERNAL_OVERLAY_TEST19_PATH2 = "/data/test/internalOverlayTest/test19/feature_hap.hap";
const std::string INTERNAL_OVERLAY_TEST19_PATH3 = "/data/test/internalOverlayTest/test19/internalOverlayTest1.hsp";
const std::string INTERNAL_OVERLAY_TEST19_PATH4 = "/data/test/internalOverlayTest/test19/internalOverlayTest18.hsp";
const std::string INTERNAL_OVERLAY_TEST21_PATH1 = "/data/test/internalOverlayTest/test21/internalOverlayTest14.hsp";
const std::string INTERNAL_OVERLAY_TEST21_PATH2 = "/data/test/internalOverlayTest/test21/internalOverlayTest15.hsp";
const std::string INTERNAL_OVERLAY_TEST24_PATH1 = "/data/test/internalOverlayTest/test24/feature1_hap.hap";
const std::string INTERNAL_OVERLAY_TEST24_PATH2 = "/data/test/internalOverlayTest/test24/internalOverlayTest12.hsp";
const std::string INTERNAL_OVERLAY_TEST24_PATH3 = "/data/test/internalOverlayTest/test24/internalOverlayTest6.hsp";
const std::string INTERNAL_OVERLAY_TEST25_PATH = "/data/test/internalOverlayTest/test25/entry_fa.hap";
const std::string INTERNAL_OVERLAY_TEST26_PATH = "/data/test/internalOverlayTest/test26";
const std::string INTERNAL_OVERLAY_TEST27_PATH = "/data/test/internalOverlayTest/test27/entry_fa_lower_version.hap";
const std::string BUNDLE_NAME_OF_OVERLAY_TEST1 = "com.example.internalOverlayTest1";
const std::string MODULE_NAME_OF_TARGET_FEATURE = "feature";
const std::string MODULE_NAME_OF_TARGET_ENTRY = "entry";
const std::string MODULE_NAME_OF_TARGET_FEATURE1 = "feature1";
} // namespace
class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    virtual ~StatusReceiverImpl() override;
    virtual void OnStatusNotify(const int progress) override;
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    ErrCode GetResultCode() const;

private:
    mutable std::promise<int32_t> resultMsgCode_;
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
    resultMsgCode_.set_value(resultCode);
}

ErrCode StatusReceiverImpl::GetResultCode() const
{
    auto future = resultMsgCode_.get_future();
    std::chrono::seconds timeout(TIMEOUT);
    if (future.wait_for(timeout) == std::future_status::timeout) {
        return ERR_APPEXECFWK_OPERATION_TIME_OUT;
    }
    return future.get();
}

class BmsOverlayInternalInstallTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static ErrCode InstallOverlayBundle(const std::vector<std::string> &bundleFilePaths);
    static ErrCode UninstallBundle(const std::string &bundleName);
    static ErrCode GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
        OverlayModuleInfo &overlayModuleInfo);
    static ErrCode GetOverlayModuleInfoForTarget(const std::string &targetBundleName, const std::string &moduleName,
        std::vector<OverlayModuleInfo> &overlayModuleInfos);
    static ErrCode GetApplicationInfo(const std::string &appName, ApplicationInfo &appInfo);
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
    static sptr<IOverlayManager> GetOverlayManagerProxy();
};

void BmsOverlayInternalInstallTest::SetUpTestCase()
{}

void BmsOverlayInternalInstallTest::TearDownTestCase()
{}

void BmsOverlayInternalInstallTest::SetUp()
{}

void BmsOverlayInternalInstallTest::TearDown()
{}

sptr<IBundleMgr> BmsOverlayInternalInstallTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BmsOverlayInternalInstallTest::GetInstallerProxy()
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

sptr<IOverlayManager> BmsOverlayInternalInstallTest::GetOverlayManagerProxy()
{
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        return nullptr;
    }
    sptr<IOverlayManager> overlayProxy = bundleMgrProxy->GetOverlayManagerProxy();
    if (!overlayProxy) {
        APP_LOGE("fail to get overlay proxy");
        return nullptr;
    }

    APP_LOGI("get overlay proxy success.");
    return overlayProxy;
}

ErrCode BmsOverlayInternalInstallTest::InstallOverlayBundle(const std::vector<std::string> &bundleFilePaths)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    EXPECT_NE(installerProxy, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    auto installResult = installerProxy->StreamInstall(bundleFilePaths, installParam, statusReceiver);
    EXPECT_EQ(installResult, ERR_OK);
    return statusReceiver->GetResultCode();
}

ErrCode BmsOverlayInternalInstallTest::UninstallBundle(const std::string &bundleName)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    EXPECT_NE(installerProxy, nullptr);

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;

    bool uninstallResult = installerProxy->Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    return statusReceiver->GetResultCode();
}

ErrCode BmsOverlayInternalInstallTest::GetOverlayModuleInfo(const std::string &bundleName,
    const std::string &moduleName, OverlayModuleInfo &overlayModuleInfo)
{
    sptr<IOverlayManager> overlayProxy = GetOverlayManagerProxy();
    EXPECT_NE(overlayProxy, nullptr);

    auto ret = overlayProxy->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, USERID);
    return ret;
}

ErrCode BmsOverlayInternalInstallTest::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &moduleName,
    std::vector<OverlayModuleInfo> &overlayModuleInfos)
{
    sptr<IOverlayManager> overlayProxy = GetOverlayManagerProxy();
    EXPECT_NE(overlayProxy, nullptr);

    auto ret = overlayProxy->GetOverlayModuleInfoForTarget(targetBundleName, moduleName, overlayModuleInfos, USERID);
    return ret;
}

ErrCode BmsOverlayInternalInstallTest::GetApplicationInfo(const std::string &appName, ApplicationInfo &appInfo)
{
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);

    auto ret = bundleMgrProxy->GetApplicationInfoV9(appName,
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), USERID, appInfo);
    return ret;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0100
 * @tc.name:  test the installation of overlay hsp
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test1/',there is an overlay test hsp internalOverlayTest1.hsp.
 *           2.bundleType of module is shared.
 *           3.targetModuleName is entry which is not installed.
 *           4.install successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0100, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0100" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST1_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST1_PATH;

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_0100" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0200
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test2/',there is two overlay hsp priority_0.hsp.
 *           2.targetPriority of priority_0.hsp is 0.
 *           3.install failed.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0200, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0200" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST2_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY) << "install fail!" <<
        INTERNAL_OVERLAY_TEST2_PATH1;
    std::cout << "END Bms_Overlay_Internal_Install_0200" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0300
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test2/',there is an overlay hsp priority_101.hsp.
 *           2.targetPriority of priority_101.hsp is 101.
 *           3.install failed.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0300, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0300" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST2_PATH2 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY) << "install fail!" <<
        INTERNAL_OVERLAY_TEST2_PATH2;
    std::cout << "END Bms_Overlay_Internal_Install_0300" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0400
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test3/',there is an overlay hsp internalOverlayTest3.hsp.
 *           2.targetPriority of internalOverlayTest3.hsp is existed and targetModuleName is not existed.
 *           3.install failed.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0400, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0400" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST3_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_NAME_MISSED) << "install fail!" <<
        INTERNAL_OVERLAY_TEST3_PATH;
    std::cout << "END Bms_Overlay_Internal_Install_0400" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0500
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test4/',there is an overlay hsp internalOverlayTest4.hsp.
 *           2.targetPriority is not existed in the hsp.
 *           3.install successfully, priority will be default-value 1.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0500, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0500" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST4_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST4_PATH;

    OverlayModuleInfo overlayModuleInfo;
    ret = GetOverlayModuleInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_FEATURE, overlayModuleInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfo.priority, DEFAULT_PRIORITY);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_0500" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0600
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test5/',there is an overlay hsp internalOverlayTest5.hsp.
 *           2.internalOverlayTest5.hsp is FA model
 *           3.install successfully, overlay module info will not be inquired.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0600, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0600" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST5_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST5_PATH;

    OverlayModuleInfo overlayModuleInfo;
    ret = GetOverlayModuleInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_FEATURE, overlayModuleInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_0600" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0700
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test6/',there is an overlay hsp internalOverlayTest6.hsp.
 *           2.overlay hsp is valid.
 *           3.install successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0700, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0700" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST6_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST6_PATH;

    OverlayModuleInfo overlayModuleInfo;
    ret = GetOverlayModuleInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_FEATURE, overlayModuleInfo);
    EXPECT_EQ(ret, ERR_OK);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_0700" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0800
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test7/',there is an overlay hsp internalOverlayTest6.hsp.
 *           2.under '/data/test/internalOverlayTest/',there is a target bundle entry_hap.hap.
 *           3.overlay hsp is valid.
 *           4.install successfully, the overlay module info can be inquired.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0800, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0800" << std::endl;
    std::vector<std::string> bundlePaths = { TARGET_MODULE_ENTRY_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<TARGET_MODULE_ENTRY_PATH;

    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST7_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST7_PATH;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_0800" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0900
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test8/',there is an overlay hsp internalOverlayTest6.hsp.
 *           2.under '/data/test/internalOverlayTest/',there is a target bundle higher_version_entry_hap.hap.
 *           3.overlay hsp is valid.
 *           4.install successfully, the lower version-code overlay module will be uninstalled.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0900, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0900" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST8_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST8_PATH;

    bundlePaths.clear();
    bundlePaths.emplace_back(TARGET_MODULE_HIGHER_VERSION_ENTRY_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<TARGET_MODULE_HIGHER_VERSION_ENTRY_PATH;

    OverlayModuleInfo overlayModuleInfo;
    ret = GetOverlayModuleInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_0900" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_1000
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test9/',there is an overlay hsp internalOverlayTest6.hsp.
 *           2.overlay hsp is valid.
 *           3.install successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_1000, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_1000" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST9_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST9_PATH;

    bundlePaths.clear();
    bundlePaths.emplace_back(TARGET_MODULE_FEATURE_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<TARGET_MODULE_FEATURE_PATH;

    OverlayModuleInfo overlayModuleInfo;
    ret = GetOverlayModuleInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_MODULE);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_1000" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_1100
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test10/',there is an overlay hsp internalOverlayTest6.hsp.
 *           2.overlay hsp is valid.
 *           3.install successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_1100, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_1100" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST10_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST10_PATH;

    bundlePaths.clear();
    bundlePaths.emplace_back(TARGET_MODULE_HIGHER_VERSION_FEATURE_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<TARGET_MODULE_HIGHER_VERSION_FEATURE_PATH;

    OverlayModuleInfo overlayModuleInfo;
    ret = GetOverlayModuleInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_1100" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_1200
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test12/',there is an overlay hsp internalOverlayTest6.hsp.
 *           2.overlay hsp is valid.
 *           3.install successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_1200, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_1200" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST12_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST12_PATH1;

    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST12_PATH2);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_IS_OVERLAY_MODULE) <<
        "install fail!" << INTERNAL_OVERLAY_TEST12_PATH2;

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_1200" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_1400
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test14/',there is two overlay hsp internalOverlayTest14.hsp
 *             and internalOverlayTest1.hsp.
 *           2.install entry_hap.hap successfully.
 *           3.install overlay hsp successfully.
 *           4.query overlay hsp overlayModuleInfo successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_1400, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_1400" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST14_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST14_PATH1;

    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST14_PATH2);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST14_PATH2;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfos.size(), OVERLAY_MODULE_INFO_SIZE);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_1400" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_1500
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test15/',there is an overlay hsp internalOverlayTest15.hsp with
 *             version code 1000001.
 *           2.install entry_hap.hap with version code 1000000 successfully.
 *           3.install overlay internalOverlayTest15.hsp failed.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_1500, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_1500" << std::endl;
    std::vector<std::string> bundlePaths = { TARGET_MODULE_ENTRY_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<TARGET_MODULE_ENTRY_PATH;

    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST15_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INCONSISTENT_VERSION_CODE) <<
        "install fail!" << INTERNAL_OVERLAY_TEST15_PATH;

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_1500" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_1600
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test16/',there is an overlay hsp internalOverlayTest1.hsp.
 *           2.install overlay internalOverlayTest1.hsp successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_1600, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_1600" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST16_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST16_PATH;

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_1600" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_1700
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test17/',there is two overlay hsp internalOverlayTest1.hsp and
 *             internalOverlayTest15.hsp.
 *           2.install overlay internalOverlayTest1.hsp successfully.
 *           3.install overlay internalOverlayTest15.hsp successfully and low version code module is uninstalled.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_1700, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_1700" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST17_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST17_PATH1;

    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST17_PATH2);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST17_PATH2;

    ApplicationInfo appInfo;
    ret = GetApplicationInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, appInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appInfo.versionCode, HIGHER_VERSION_CODE);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_1700" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_1800
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test18/',there is two files internalOverlayTest12.hsp and
 *             higher_version_feature_hap.hap.
 *           2.install overlay internalOverlayTest12.hsp successfully.
 *           3.install higher_version_feature_hap.hap to update overlay module to non-overlay module failed.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_1800, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_1800" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST18_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST18_PATH1;

    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST18_PATH2);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME) << "install fail!" <<
        INTERNAL_OVERLAY_TEST18_PATH2;

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_1800" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_1900
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test19/',there is four files entry_hap.hap, feature_hap.hap,
 *             internalOverlayTest1.hsp and internalOverlayTest18.hsp.
 *           2.install target haps successfully.
 *           3.install overlay hsp whose target module name is entry successfully.
 *           4.update overlay hsp whose target module name is feature1 successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_1900, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_1900" << std::endl;
    // install haps which modules are entry and feature1
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST19_PATH1, INTERNAL_OVERLAY_TEST19_PATH2 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!";

    // install overlay hsp whose target module name is entry
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST19_PATH3);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST19_PATH3;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);

    // install overlay hsp whose target module name is feature1
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST19_PATH4);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST19_PATH4;

    overlayModuleInfos.clear();
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(overlayModuleInfos.empty());

    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_FEATURE1, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfos.size(), MIN_OVERLAY_MODULE_INFO_SIZE);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_1900" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_2000
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test19/',there is four files entry_hap.hap
 *             internalOverlayTest1.hsp and internalOverlayTest18.hsp.
 *           2.install target haps successfully.
 *           3.install overlay hsp whose target module name is entry successfully.
 *           4.update overlay hsp whose target module name is feature1 successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_2000, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_2000" << std::endl;
    // install haps which modules are entry
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST19_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST19_PATH1;

    // install overlay hsp whose target module name is entry
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST19_PATH3);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST19_PATH3;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);

    // update overlay hsp whose target module name is feature1
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST19_PATH4);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST19_PATH4;

    overlayModuleInfos.clear();
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(overlayModuleInfos.empty());

    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_FEATURE1, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_MODULE_NOT_EXISTED);
    EXPECT_TRUE(overlayModuleInfos.empty());

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_2000" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_2100
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test21/',there is four files entry_hap.hap
 *             internalOverlayTest14.hsp and internalOverlayTest15.hsp.
 *           2.install target haps successfully.
 *           3.install overlay hsp whose target module name is entry successfully.
 *           4.update overlay hsp failed.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_2100, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_2100" << std::endl;
    // install haps which modules are entry
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST19_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST19_PATH1;

    // install overlay hsp whose target module name is entry
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST21_PATH1);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST21_PATH1;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);

    // install overlay hsp whose target module name is feature1
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST21_PATH2);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INCONSISTENT_VERSION_CODE) << "install fail!" <<
        INTERNAL_OVERLAY_TEST21_PATH2;

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_2100" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_2200
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test19/',there is four files entry_hap.hap
 *             internalOverlayTest14.hsp and internalOverlayTest15.hsp.
 *           2.install target haps successfully.
 *           3.install overlay hsp whose target module name is entry successfully.
 *           4.update overlay entry_hap.hap successfully.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_2200, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_2200" << std::endl;
    // install haps which modules are entry
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST19_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST19_PATH1;

    // install overlay hsp whose target module name is entry
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST21_PATH1);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST21_PATH1;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfos.size(), MIN_OVERLAY_MODULE_INFO_SIZE);

    // update overlay hsp whose target module name is entry
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST21_PATH1);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST21_PATH1;

    overlayModuleInfos.clear();
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfos.size(), MIN_OVERLAY_MODULE_INFO_SIZE);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_2200" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_2300
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test19/',there is a hap entry_hap.hap,
 *             under '/data/test/internalOverlayTest/test21/',there is a hsp internalOverlayTest14.hsp.
 *           2.install target haps successfully.
 *           3.install overlay hsp whose target module name is entry successfully.
 *           4.update entry_hap.hap successfully and low version code overlay module is uninstalled.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_2300, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_2300" << std::endl;
    // install haps which modules are entry
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST19_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST19_PATH1;

    // install overlay hsp whose target module name is entry
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST21_PATH1);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST21_PATH1;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfos.size(), MIN_OVERLAY_MODULE_INFO_SIZE);

    // update overlay entry_hap.hap
    bundlePaths.clear();
    bundlePaths.emplace_back(TARGET_MODULE_HIGHER_VERSION_ENTRY_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << TARGET_MODULE_HIGHER_VERSION_ENTRY_PATH;

    overlayModuleInfos.clear();
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);


    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_2300" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_2400
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test24/',there is a hap feature1_hap.hap,
 *             under '/data/test/internalOverlayTest/test21/',there is a hsp internalOverlayTest14.hsp.
 *           2.install target haps successfully.
 *           3.install overlay hsp whose target module name is entry successfully.
 *           4.update entry_hap.hap failed.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_2400, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_2400" << std::endl;
    // install hap which modules is feature
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST24_PATH1 };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST24_PATH1;

    // install overlay hsp whose target module name is feature
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST24_PATH2);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST24_PATH2;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_FEATURE, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfos.size(), MIN_OVERLAY_MODULE_INFO_SIZE);

    // update hap entry_hap.hap
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST24_PATH3);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME) << "install fail!" <<
        INTERNAL_OVERLAY_TEST24_PATH3;

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_2400" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_2500
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/',there is a hap entry_hap.hap,
 *             under '/data/test/internalOverlayTest/test7/',there is a hsp internalOverlayTest6.hsp,
 *             under '/data/test/internalOverlayTest/test25/',there is a hsp internalOverlayTest6.hsp.
 *           2.install target haps successfully.
 *           3.install overlay hsp whose target module name is entry successfully.
 *           4.update entry_hap.hap to entry_fa.hap successfully and overlay connection is removed.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_2500, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_2500" << std::endl;
    // install hap which modules is entry
    std::vector<std::string> bundlePaths = { TARGET_MODULE_ENTRY_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << TARGET_MODULE_ENTRY_PATH;

    // install overlay hsp whose target module name is feature
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST7_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST7_PATH;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfos.size(), MIN_OVERLAY_MODULE_INFO_SIZE);

    // update hap entry_hap.hap to entry_fa.hap
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST25_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST25_PATH;

    overlayModuleInfos.clear();
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_2500" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_2600
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/',there is a hap entry_hap.hap,
 *             under '/data/test/internalOverlayTest/test21/',there is a hsp internalOverlayTest14.hsp,
 *             under '/data/test/internalOverlayTest/test26/',there is two files internalOverlayTest15.hsp and
 *             higher_version_entry_hap.hap.
 *           2.install target haps successfully.
 *           3.install overlay hsp whose target module name is entry successfully.
 *           4.update entry_hap.hap and internalOverlayTest14.hsp successfully, overlayModuleInfo is reserved.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_2600, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_2600" << std::endl;
    // install hap which modules is feature
    std::vector<std::string> bundlePaths = { TARGET_MODULE_ENTRY_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << TARGET_MODULE_ENTRY_PATH;

    // install overlay hsp whose target module name is feature
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST21_PATH1);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" <<INTERNAL_OVERLAY_TEST21_PATH1;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfos.size(), MIN_OVERLAY_MODULE_INFO_SIZE);

    // update hap entry_hap.hap to entry_fa.hap
    bundlePaths.clear();
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST26_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST26_PATH;

    overlayModuleInfos.clear();
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_2600" << std::endl;
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_2700
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/internalOverlayTest/test27/',there is a hap entry_fa_lower_version.hap,
 *             under '/data/test/internalOverlayTest/test21/',there is a hsp internalOverlayTest14.hsp,
 *             under '/data/test/internalOverlayTest/test26/',there is two files internalOverlayTest15.hsp and
 *             higher_version_entry_hap.hap.
 *           2.install target haps successfully.
 *           3.install overlay hsp whose target module name is entry successfully.
 *           4.update entry_hap.hap and internalOverlayTest14.hsp successfully, overlayModuleInfo is reserved.
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_2700, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_2700" << std::endl;
    // install hap which is entry type and fa model
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST27_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST27_PATH;

    // install overlay hsp and update entry module
    bundlePaths.clear();
    bundlePaths.emplace_back(TARGET_MODULE_ENTRY_PATH);
    bundlePaths.emplace_back(INTERNAL_OVERLAY_TEST7_PATH);
    ret = InstallOverlayBundle(bundlePaths);
    EXPECT_EQ(ret, ERR_OK) << "install fail!";

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ret = GetOverlayModuleInfoForTarget(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_TARGET_ENTRY, overlayModuleInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(overlayModuleInfos.size(), MIN_OVERLAY_MODULE_INFO_SIZE);

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_2700" << std::endl;
}
} // AppExecFwk
} // OHOS