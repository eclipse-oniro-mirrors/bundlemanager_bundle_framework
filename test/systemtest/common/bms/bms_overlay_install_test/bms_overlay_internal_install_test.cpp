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
const std::string BUNDLE_NAME_OF_OVERLAY_TEST1 = "com.example.internalOverlayTest1";
const std::string MODULE_NAME_OF_OVERLAY_TEST4 = "feature";
const std::string MODULE_NAME_OF_TARGET_ENTRY = "entry";
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
    bool installResult = installerProxy->Install(bundleFilePaths, installParam, statusReceiver);
    EXPECT_TRUE(installResult);
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
    ret = GetOverlayModuleInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_OVERLAY_TEST4, overlayModuleInfo);
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
    ret = GetOverlayModuleInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_OVERLAY_TEST4, overlayModuleInfo);
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
    ret = GetOverlayModuleInfo(BUNDLE_NAME_OF_OVERLAY_TEST1, MODULE_NAME_OF_OVERLAY_TEST4, overlayModuleInfo);
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
} // AppExecFwk
} // OHOS