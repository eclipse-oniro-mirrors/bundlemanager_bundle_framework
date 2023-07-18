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
#include "common_tool.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "status_receiver_host.h"

using namespace testing::ext;
using namespace std::chrono_literals;
namespace {
const std::string THIRD_BUNDLE_PATH = "/data/test/testHapSo/";
const std::string CODE_ROOT_PATH = "/data/app/el1/bundle/public/";
const std::string BUNDLE_NAME1 = "com.example.testhapso1";
const std::string BUNDLE_NAME2 = "com.example.testhapso2";
const std::string BUNDLE_NAME3 = "com.example.testhapso3";
const std::string BUNDLE_NAME4 = "com.example.testhapso4";
const std::string BUNDLE_NAME5 = "com.example.testhapso5";
const std::string BUNDLE_NAME6 = "com.example.testhapso6";
const std::string NO_SO_BUNDLE_NAME1 = "com.example.hapNotIncludeso1";
const std::string NO_SO_BUNDLE_NAME2 = "com.example.hapNotIncludeso2";
const std::string NO_SO_BUNDLE_NAME3 = "com.example.hapNotIncludeso3";
const std::string NO_SO_BUNDLE_NAME4 = "com.example.hapNotIncludeso4";
const std::string HAP_INCLUDE_SO1 = "hapIncludeso1.hap";
const std::string HAP_INCLUDE_SO2 = "hapIncludeso2.hap";
const std::string HAP_INCLUDE_SO3 = "hapIncludeso3.hap";
const std::string HAP_INCLUDE_SO4 = "hapIncludeso4.hap";
const std::string HAP_INCLUDE_SO5 = "hapIncludeso5.hap";
const std::string HAP_INCLUDE_SO6 = "hapIncludeso6.hap";
const std::string HAP_NOT_INCLUDE_SO1 = "hapNotIncludeso1.hap";
const std::string HAP_NOT_INCLUDE_SO2 = "hapNotIncludeso2.hap";
const std::string HAP_NOT_INCLUDE_SO3 = "hapNotIncludeso3.hap";
const std::string HAP_NOT_INCLUDE_SO4 = "hapNotIncludeso4.hap";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILURE = "Failure";
const std::string OPERATION_SUCCESS = "Success";
const std::string LIBS = "/libs";
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
    return OPERATION_FAILURE + resultMsg;
}

class BmsInstallHapSoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static std::string InstallBundle(const std::string &hapFile);
    static std::string UninstallBundle(const std::string &bundleName);
    static std::string InstallBundles(const std::vector<string> &hapPaths);
    static std::string UninstallBundles(const std::vector<string> &bundleNames);
    bool CheckFilePath(const std::string &checkFilePath) const;
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
};

sptr<IBundleMgr> BmsInstallHapSoTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BmsInstallHapSoTest::GetInstallerProxy()
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

std::string BmsInstallHapSoTest::InstallBundle(
    const std::string &hapFile)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    bool installResult = installerProxy->Install(THIRD_BUNDLE_PATH + hapFile, installParam, statusReceiver);
    EXPECT_TRUE(installResult);
    return statusReceiver->GetResultMsg();
}

std::string BmsInstallHapSoTest::UninstallBundle(
    const std::string &bundleName)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;

    bool uninstallResult = installerProxy->Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    return statusReceiver->GetResultMsg();
}

std::string BmsInstallHapSoTest::InstallBundles(
    const std::vector<string> &hapPaths)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    bool installResult = installerProxy->Install(hapPaths, installParam, statusReceiver);
    EXPECT_TRUE(installResult);
    return statusReceiver->GetResultMsg();
}

std::string BmsInstallHapSoTest::UninstallBundles(
    const std::vector<string> &bundleNames)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    bool uninstallResult = false;

    for (int i = 1; i <= bundleNames.length; i++) {
        uninstallResult = installerProxy->Uninstall(bundleNames[i], installParam, statusReceiver);
        EXPECT_TRUE(uninstallResult);
    }
    return statusReceiver->GetResultMsg();
}

bool BmsInstallHapSoTest::CheckFilePath(const std::string &checkFilePath) const
{
    CommonTool commonTool;
    bool checkIsExist = commonTool.CheckFilePathISExist(checkFilePath);
    if (!checkIsExist) {
        APP_LOGE("%{private}s does not exist!", checkFilePath.c_str());
        return false;
    }
    return true;
}

void BmsInstallHapSoTest::SetUpTestCase()
{}

void BmsInstallHapSoTest::TearDownTestCase()
{}

void BmsInstallHapSoTest::SetUp()
{}

void BmsInstallHapSoTest::TearDown()
{}

/**
 * @tc.number: BMS_Install_Hap_With_SO_0100
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    res = UninstallBundle(BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_SO_0200
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, true);
    res = UninstallBundle(BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_SO_0300
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is false and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    res = UninstallBundle(BUNDLE_NAME3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_SO_0400
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not existed
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    res = UninstallBundle(BUNDLE_NAME4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_NO_SO_0100
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_NO_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_NO_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_NOT_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    res = UninstallBundle(NO_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_NO_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_NO_SO_0200
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_NO_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_NO_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_NOT_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    res = UninstallBundle(NO_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_NO_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_NO_SO_0300
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is false and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_NO_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_NO_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_NOT_INCLUDE_SO3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    res = UninstallBundle(NO_SO_BUNDLE_NAME3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_NO_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_NO_SO_0400
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_NO_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_NO_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_NOT_INCLUDE_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    res = UninstallBundle(NO_SO_BUNDLE_NAME4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_NO_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0100
 * @tc.name:  test the installation of multiple haps contain so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps contain so
 *           2.install bundles
 *           3.the compressNativeLibs of hap 1 is true and the libIsolation of hap 1 is true
 *             the compressNativeLibs of hap 2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0100" << std::endl;
    std::vector<string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME3);
    auto res = InstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    
    res = UninstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0200
 * @tc.name:  test the installation of multiple haps contain so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps contain so
 *           2.install bundles
 *           3.the compressNativeLibs of hap 1 is true and the libIsolation of hap 1 is false
 *             the compressNativeLibs of hap 2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0200" << std::endl;
    std::vector<string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME3);
    auto res = InstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    
    res = UninstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0300
 * @tc.name:  test the installation of multiple haps contain so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps contain so
 *           2.install bundles
 *           3.the compressNativeLibs of hap 1 is true and the libIsolation of hap 1 is true
 *             the compressNativeLibs of hap 2 is true and the libIsolation of hap 2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0300" << std::endl;
    std::vector<string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME5);
    auto res = InstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    
    res = UninstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0400
 * @tc.name:  test the installation of multiple haps contain so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps contain so
 *           2.install bundles
 *           3.the compressNativeLibs of hap 1 is true and the libIsolation of hap 1 is true
 *             the compressNativeLibs of hap 2 is true and the libIsolation of hap 2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0400" << std::endl;
    std::vector<string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME2);
    auto res = InstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    
    res = UninstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0500
 * @tc.name:  test the installation of multiple haps contain so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps contain so
 *           2.install bundles
 *           3.the compressNativeLibs of hap 1 is true and the libIsolation of hap 1 is false
 *             the compressNativeLibs of hap 2 is true and the libIsolation of hap 2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0500" << std::endl;
    std::vector<string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME1);
    auto res = InstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    
    res = UninstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0600
 * @tc.name:  test the installation of multiple haps contain so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps contain so
 *           2.install bundles
 *           3.the compressNativeLibs of hap 1 is true and the libIsolation of hap 1 is false
 *             the compressNativeLibs of hap 2 is true and the libIsolation of hap 2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0600" << std::endl;
    std::vector<string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME6);
    auto res = InstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);
    
    res = UninstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0700
 * @tc.name:  test the installation of multiple haps contain so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps contain so
 *           2.install bundles
 *           3.the compressNativeLibs of hap 1 is false
 *             the compressNativeLibs of hap 2 is true and the libIsolation of hap 2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0700" << std::endl;
    std::vector<string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME3);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME5);
    auto res = InstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    
    res = UninstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0800
 * @tc.name:  test the installation of multiple haps contain so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps contain so
 *           2.install bundles
 *           3.the compressNativeLibs of hap 1 is false
 *             the compressNativeLibs of hap 2 is true and the libIsolation of hap 2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0800" << std::endl;
    std::vector<string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME3);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME6);
    auto res = InstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);
    
    res = UninstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0900
 * @tc.name:  test the installation of multiple haps contain so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps contain so
 *           2.install bundles
 *           3.the compressNativeLibs of hap 1 is false
 *             the compressNativeLibs of hap 2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0900" << std::endl;
    std::vector<string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME3);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + BUNDLE_NAME4);
    auto res = InstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    
    res = UninstallBundle(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0900" << std::endl;
}
}  // namespace AppExecFwk
}  // namespace OHOScd