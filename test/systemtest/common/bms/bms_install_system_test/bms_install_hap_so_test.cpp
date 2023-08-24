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
#include "parameter.h"

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
const std::string BUNDLE_NAME7 = "com.example.testhapso7";
const std::string BUNDLE_NAME8 = "com.example.testhapso8";
const std::string MODULE_NAME = "/entry";
const std::string FEATURE_MODULE_NAME = "/feature";
const std::string FEATURE_MODULE_NAME1 = "/feature1";
const std::string FEATURE_MODULE_NAME2 = "/feature2";
const std::string FEATURE_MODULE_NAME3 = "/feature3";
const std::string FEATURE_MODULE_NAME4 = "/feature4";
const std::string FEATURE_MODULE_NAME5 = "/feature5";
const std::string FEATURE_MODULE_NAME6 = "/feature6";
const std::string FEATURE_MODULE_NAME7 = "/feature7";
const std::string FEATURE_MODULE_NAME8 = "/feature8";
const std::string NO_SO_BUNDLE_NAME1 = "com.example.hapNotIncludeso1";
const std::string NO_SO_BUNDLE_NAME2 = "com.example.hapNotIncludeso2";
const std::string NO_SO_BUNDLE_NAME3 = "com.example.hapNotIncludeso3";
const std::string NO_SO_BUNDLE_NAME4 = "com.example.hapNotIncludeso4";
const std::string NO_SO_BUNDLE_NAME5 = "com.example.hapNotIncludeso5";
const std::string NO_SO_BUNDLE_NAME6 = "com.example.hapNotIncludeso6";
const std::string SECTION_SO_BUNDLE_NAME1 = "com.example.hapSectionContainso1";
const std::string SECTION_SO_BUNDLE_NAME2 = "com.example.hapSectionContainso2";
const std::string HAP_INCLUDE_SO1 = "hapIncludeso1.hap";
const std::string HAP_INCLUDE_SO2 = "hapIncludeso2.hap";
const std::string HAP_INCLUDE_SO3 = "hapIncludeso3.hap";
const std::string HAP_INCLUDE_SO4 = "hapIncludeso4.hap";
const std::string HAP_INCLUDE_SO5 = "hapIncludeso5.hap";
const std::string HAP_INCLUDE_SO6 = "hapIncludeso6.hap";
const std::string HAP_INCLUDE_SO7 = "hapIncludeso7.hap";
const std::string HAP_INCLUDE_SO8 = "hapIncludeso8.hap";
const std::string HAP_WITHOUT_SO1 = "hapnoso1.hap";
const std::string HAP_WITHOUT_SO2 = "hapnoso2.hap";
const std::string HAP_WITHOUT_SO3 = "hapnoso3.hap";
const std::string HAP_WITHOUT_SO4 = "hapnoso4.hap";
const std::string HAP_INCLUDE_SO5_FEATURE1 = "hapIncludeso5Feature1.hap";
const std::string HAP_INCLUDE_SO5_FEATURE2 = "hapIncludeso5Feature2.hap";
const std::string HAP_INCLUDE_SO5_FEATURE3 = "hapIncludeso5Feature3.hap";
const std::string HAP_INCLUDE_SO5_FEATURE4 = "hapIncludeso5Feature4.hap";
const std::string HAP_INCLUDE_SO5_FEATURE5 = "hapIncludeso5Feature5.hap";
const std::string HAP_INCLUDE_SO5_FEATURE6 = "hapIncludeso5Feature6.hap";
const std::string HAP_INCLUDE_SO5_FEATURE7 = "hapIncludeso5Feature7.hap";
const std::string HAP_INCLUDE_SO5_FEATURE8 = "hapIncludeso5Feature8.hap";
const std::string HAP_INCLUDE_SO6_FEATURE1 = "hapIncludeso6Feature1.hap";
const std::string HAP_INCLUDE_SO6_FEATURE2 = "hapIncludeso6Feature2.hap";
const std::string HAP_INCLUDE_SO6_FEATURE3 = "hapIncludeso6Feature3.hap";
const std::string HAP_INCLUDE_SO7_FEATURE1 = "hapIncludeso7Feature1.hap";
const std::string HAP_INCLUDE_SO8_FEATURE1 = "hapIncludeso8Feature1.hap";
const std::string HAP_INCLUDE_SO8_FEATURE2 = "hapIncludeso8Feature2.hap";
const std::string HAP_INCLUDE_SO8_FEATURE3 = "hapIncludeso8Feature3.hap";
const std::string HAP_NOT_INCLUDE_SO1 = "hapNotIncludeso1.hap";
const std::string HAP_NOT_INCLUDE_SO2 = "hapNotIncludeso2.hap";
const std::string HAP_NOT_INCLUDE_SO3 = "hapNotIncludeso3.hap";
const std::string HAP_NOT_INCLUDE_SO4 = "hapNotIncludeso4.hap";
const std::string HAP_NOT_INCLUDE_SO5 = "hapNotIncludeso5.hap";
const std::string HAP_NOT_INCLUDE_SO6 = "hapNotIncludeso6.hap";
const std::string HAP_SECTION_INCLUDE_SO1 = "hapSectionContainso1.hap";
const std::string HAP_SECTION_INCLUDE_SO2 = "hapSectionContainso2.hap";
const std::string HAP_SECTION_INCLUDE_SO_FEATURE1 = "hapSectionContainsoFeature1.hap";
const std::string HAP_SECTION_INCLUDE_SO_FEATURE2 = "hapSectionContainsoFeature2.hap";
const std::string HAP_SECTION_INCLUDE_SO_FEATURE3 = "hapSectionContainsoFeature3.hap";
const std::string HAP_SECTION_INCLUDE_SO_FEATURE4 = "hapSectionContainsoFeature4.hap";
const std::string HAP_SECTION_INCLUDE_SO_FEATURE5 = "hapSectionContainsoFeature5.hap";
const std::string HAP_SECTION_INCLUDE_SO_FEATURE6 = "hapSectionContainsoFeature6.hap";
const std::string HAP_NOT_INCLUDE_SO_FEATURE1 = "hapNotIncludesoFeature1.hap";
const std::string HAP_NOT_INCLUDE_SO_FEATURE2 = "hapNotIncludesoFeature2.hap";
const std::string HAP_NOT_INCLUDE_SO_FEATURE3 = "hapNotIncludesoFeature3.hap";
const std::string HAP_NOT_INCLUDE_SO_FEATURE4 = "hapNotIncludesoFeature4.hap";
const std::string HAP_NOT_INCLUDE_SO_FEATURE5 = "hapNotIncludesoFeature5.hap";
const std::string HAP_NOT_INCLUDE_SO_FEATURE6 = "hapNotIncludesoFeature6.hap";
const std::string HAP_INCLUDE_SO_PATH1 = "hapIncludeso1/";
const std::string HAP_INCLUDE_SO_PATH2 = "hapIncludeso2/";
const std::string HAP_INCLUDE_SO_PATH3 = "hapIncludeso3/";
const std::string HAP_INCLUDE_SO_PATH4 = "hapIncludeso4/";
const std::string HAP_INCLUDE_SO_PATH5 = "hapIncludeso5/";
const std::string HAP_INCLUDE_SO_PATH6 = "hapIncludeso6/";
const std::string HAP_INCLUDE_SO_PATH7 = "hapIncludeso7/";
const std::string HAP_INCLUDE_SO_PATH8 = "hapIncludeso8/";
const std::string HAP_WITHOUT_SO_PATH1 = "hapnoso1/";
const std::string HAP_WITHOUT_SO_PATH2 = "hapnoso2/";
const std::string HAP_WITHOUT_SO_PATH3 = "hapnoso3/";
const std::string HAP_WITHOUT_SO_PATH4 = "hapnoso4/";
const std::string HAP_INCLUDE_SO_PATH5_FEATURE1 = "hapIncludeso5Feature1/";
const std::string HAP_INCLUDE_SO_PATH5_FEATURE2 = "hapIncludeso5Feature2/";
const std::string HAP_INCLUDE_SO_PATH5_FEATURE3 = "hapIncludeso5Feature3/";
const std::string HAP_INCLUDE_SO_PATH5_FEATURE4 = "hapIncludeso5Feature4/";
const std::string HAP_INCLUDE_SO_PATH5_FEATURE5 = "hapIncludeso5Feature5/";
const std::string HAP_INCLUDE_SO_PATH5_FEATURE6 = "hapIncludeso5Feature6/";
const std::string HAP_INCLUDE_SO_PATH5_FEATURE7 = "hapIncludeso5Feature7/";
const std::string HAP_INCLUDE_SO_PATH5_FEATURE8 = "hapIncludeso5Feature8/";
const std::string HAP_INCLUDE_SO_PATH6_FEATURE1 = "hapIncludeso6Feature1/";
const std::string HAP_INCLUDE_SO_PATH6_FEATURE2 = "hapIncludeso6Feature2/";
const std::string HAP_INCLUDE_SO_PATH6_FEATURE3 = "hapIncludeso6Feature3/";
const std::string HAP_INCLUDE_SO_PATH7_FEATURE1 = "hapIncludeso7Feature1/";
const std::string HAP_INCLUDE_SO_PATH8_FEATURE1 = "hapIncludeso8Feature1/";
const std::string HAP_INCLUDE_SO_PATH8_FEATURE2 = "hapIncludeso8Feature2/";
const std::string HAP_INCLUDE_SO_PATH8_FEATURE3 = "hapIncludeso8Feature3/";
const std::string HAP_NOT_INCLUDE_SO_PATH1 = "hapNotIncludeso1/";
const std::string HAP_NOT_INCLUDE_SO_PATH2 = "hapNotIncludeso2/";
const std::string HAP_NOT_INCLUDE_SO_PATH3 = "hapNotIncludeso3/";
const std::string HAP_NOT_INCLUDE_SO_PATH4 = "hapNotIncludeso4/";
const std::string HAP_NOT_INCLUDE_SO_PATH5 = "hapNotIncludeso5/";
const std::string HAP_NOT_INCLUDE_SO_PATH6 = "hapNotIncludeso6/";
const std::string HAP_NOT_INCLUDE_SO_PATH_FEATURE1 = "hapNotIncludesoFeature1/";
const std::string HAP_NOT_INCLUDE_SO_PATH_FEATURE2 = "hapNotIncludesoFeature2/";
const std::string HAP_NOT_INCLUDE_SO_PATH_FEATURE3 = "hapNotIncludesoFeature3/";
const std::string HAP_NOT_INCLUDE_SO_PATH_FEATURE4 = "hapNotIncludesoFeature4/";
const std::string HAP_NOT_INCLUDE_SO_PATH_FEATURE5 = "hapNotIncludesoFeature5/";
const std::string HAP_NOT_INCLUDE_SO_PATH_FEATURE6 = "hapNotIncludesoFeature6/";
const std::string HAP_SECTION_INCLUDE_SO_PATH1 = "hapSectionContainso1/";
const std::string HAP_SECTION_INCLUDE_SO_PATH2 = "hapSectionContainso2/";
const std::string HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 = "hapSectionContainsoFeature1/";
const std::string HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 = "hapSectionContainsoFeature2/";
const std::string HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 = "hapSectionContainsoFeature3/";
const std::string HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 = "hapSectionContainsoFeature4/";
const std::string HAP_SECTION_INCLUDE_SO_PATH_FEATURE5 = "hapSectionContainsoFeature5/";
const std::string HAP_SECTION_INCLUDE_SO_PATH_FEATURE6 = "hapSectionContainsoFeature6/";
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
    static std::string InstallBundles(const std::vector<std::string> &hapPaths);
    static std::string UninstallBundle(const std::string &bundleName);
    static std::string InstallPathBundle(const std::string &path);
    static std::string UpdateInstall(const std::string &hapFile);
    static std::string UpdateInstalls(const std::vector<std::string> &hapPaths);
    static std::string UpdateInstallPath(const std::string &path);
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
    std::vector<std::string> pathVec { THIRD_BUNDLE_PATH + hapFile };
    auto installResult = installerProxy->StreamInstall(pathVec, installParam, statusReceiver);
    EXPECT_EQ(installResult, ERR_OK);
    return statusReceiver->GetResultMsg();
}

std::string BmsInstallHapSoTest::InstallBundles(
    const std::vector<std::string> &hapPaths)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    auto installResult = installerProxy->StreamInstall(hapPaths, installParam, statusReceiver);
    EXPECT_EQ(installResult, ERR_OK);
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

std::string BmsInstallHapSoTest::InstallPathBundle(
    const std::string &path)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    std::vector<std::string> pathVec { path };
    auto installResult = installerProxy->StreamInstall(pathVec, installParam, statusReceiver);
    EXPECT_EQ(installResult, ERR_OK);
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

std::string BmsInstallHapSoTest::UpdateInstall(
    const std::string &hapFile)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    std::vector<std::string> pathVec { THIRD_BUNDLE_PATH + hapFile };
    auto installResult = installerProxy->StreamInstall(pathVec, installParam, statusReceiver);
    EXPECT_EQ(installResult, ERR_OK);
    return statusReceiver->GetResultMsg();
}

std::string BmsInstallHapSoTest::UpdateInstalls(
    const std::vector<std::string> &hapPaths)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    auto installResult = installerProxy->StreamInstall(hapPaths, installParam, statusReceiver);
    EXPECT_EQ(installResult, ERR_OK);
    return statusReceiver->GetResultMsg();
}

std::string BmsInstallHapSoTest::UpdateInstallPath(
    const std::string &path)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    std::vector<std::string> pathVec { path };
    auto installResult = installerProxy->StreamInstall(pathVec, installParam, statusReceiver);
    EXPECT_EQ(installResult, ERR_OK);
    return statusReceiver->GetResultMsg();
}

void BmsInstallHapSoTest::SetUpTestCase()
{
    int32_t ret = SetParameter("persist.bms.supportCompressNativeLibs", "true");
    if (ret <= 0) {
        APP_LOGE("SetParameter failed!");
    }
}

void BmsInstallHapSoTest::TearDownTestCase()
{}

void BmsInstallHapSoTest::SetUp()
{}

void BmsInstallHapSoTest::TearDown()
{}

//full installation
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
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH1 + HAP_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);

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
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH2 + HAP_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

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
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH3 + HAP_INCLUDE_SO3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + MODULE_NAME + LIBS);
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
 *           4.check the libs path is existed
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH4 + HAP_INCLUDE_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME4 + MODULE_NAME + LIBS);
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
    auto res = InstallBundle(HAP_NOT_INCLUDE_SO_PATH1 + HAP_NOT_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
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
    auto res = InstallBundle(HAP_NOT_INCLUDE_SO_PATH2 + HAP_NOT_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
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
    auto res = InstallBundle(HAP_NOT_INCLUDE_SO_PATH3 + HAP_NOT_INCLUDE_SO3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME3 + MODULE_NAME + LIBS);
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
    auto res = InstallBundle(HAP_NOT_INCLUDE_SO_PATH4 + HAP_NOT_INCLUDE_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME4 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_NO_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0100
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0100" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE1 + HAP_INCLUDE_SO5_FEATURE1);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0200
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0200" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0300
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0300" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0400
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0400" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE3 + HAP_INCLUDE_SO6_FEATURE3);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + FEATURE_MODULE_NAME3 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0500
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0500" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE2 + HAP_INCLUDE_SO5_FEATURE2);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0600
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0600" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE2 + HAP_INCLUDE_SO6_FEATURE2);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0700
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0700" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH7 + HAP_INCLUDE_SO7);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH7_FEATURE1 + HAP_INCLUDE_SO7_FEATURE1);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0800
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0800" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE1 + HAP_INCLUDE_SO8_FEATURE1);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_0900
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_0900" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_0900" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_SO_1000
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_SO_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_SO_1000" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE3 + HAP_INCLUDE_SO8_FEATURE3);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_SO_1000" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Multi_Haps_Without_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Multi_Haps_Without_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Multi_Haps_Without_SO_0100" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_NOT_INCLUDE_SO_PATH5 + HAP_NOT_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_NOT_INCLUDE_SO_PATH_FEATURE1 + HAP_NOT_INCLUDE_SO_FEATURE1);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Multi_Haps_Without_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Multi_Haps_Without_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Multi_Haps_Without_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Multi_Haps_Without_SO_0200" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_NOT_INCLUDE_SO_PATH6 + HAP_NOT_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_NOT_INCLUDE_SO_PATH_FEATURE4 + HAP_NOT_INCLUDE_SO_FEATURE4);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Multi_Haps_Without_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Multi_Haps_Without_SO_0300
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Multi_Haps_Without_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Multi_Haps_Without_SO_0300" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_NOT_INCLUDE_SO_PATH_FEATURE2 + HAP_NOT_INCLUDE_SO_FEATURE2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_NOT_INCLUDE_SO_PATH_FEATURE3 + HAP_NOT_INCLUDE_SO_FEATURE3);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Multi_Haps_Without_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Multi_Haps_Without_SO_0400
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Multi_Haps_Without_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Multi_Haps_Without_SO_0400" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_NOT_INCLUDE_SO_PATH_FEATURE5 + HAP_NOT_INCLUDE_SO_FEATURE5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_NOT_INCLUDE_SO_PATH_FEATURE6 + HAP_NOT_INCLUDE_SO_FEATURE6);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Multi_Haps_Without_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Multi_Haps_Section_With_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Multi_Haps_Section_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Multi_Haps_Section_With_SO_0100" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Multi_Haps_Section_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Multi_Haps_Section_With_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Multi_Haps_Section_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Multi_Haps_Section_With_SO_0200" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Multi_Haps_Section_With_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Multi_Haps_Section_With_SO_0300
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Multi_Haps_Section_With_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Multi_Haps_Section_With_SO_0300" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Multi_Haps_Section_With_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Multi_Haps_Section_With_SO_0400
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Multi_Haps_Section_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Multi_Haps_Section_With_SO_0400" << std::endl;
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE5 + HAP_SECTION_INCLUDE_SO_FEATURE5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE6 + HAP_SECTION_INCLUDE_SO_FEATURE6);
    auto res = InstallBundles(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Multi_Haps_Section_With_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Hap_With_SO_0100
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Hap_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Hap_With_SO_0100" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapIncludeso1");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Hap_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Hap_With_SO_0200
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Hap_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Hap_With_SO_0200" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapIncludeso2");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Hap_With_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Hap_With_SO_0300
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is false and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Hap_With_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Hap_With_SO_0300" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapIncludeso3");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME3 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Hap_With_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Hap_With_SO_0100
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not existed
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Hap_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Hap_With_SO_0100" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapIncludeso4");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME4 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Hap_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Hap_NO_SO_0100
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Hap_NO_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Hap_NO_SO_0100" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludeso1");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Hap_NO_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Hap_NO_SO_0200
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Hap_NO_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Hap_NO_SO_0200" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludeso2");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Hap_NO_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Hap_NO_SO_0300
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is false and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Hap_NO_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Hap_NO_SO_0300" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludeso3");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME3 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Hap_NO_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Hap_NO_SO_0400
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Hap_NO_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Hap_NO_SO_0400" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludeso4");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME4 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Hap_NO_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_0100
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_0100" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE1 + HAP_INCLUDE_SO5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_0200
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_0200" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_0300
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_0300" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_0400
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_0400" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE3 + HAP_INCLUDE_SO6_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_0500
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_0500" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE2 + HAP_INCLUDE_SO5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_0600
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_0600" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE2 + HAP_INCLUDE_SO6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_0700
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_0700" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH7 + HAP_INCLUDE_SO7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH7_FEATURE1 + HAP_INCLUDE_SO7_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_0800
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_0800" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE1 + HAP_INCLUDE_SO8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_0900
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_0900" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_0900" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_SO_1000
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the bundle
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_SO_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_SO_1000" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE3 + HAP_INCLUDE_SO8_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_SO_1000" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Path_Multi_Haps_Without_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Path_Multi_Haps_Without_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Path_Multi_Haps_Without_SO_0100" << std::endl;

    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludeso5");
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludesoFeature1");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Path_Multi_Haps_Without_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Path_Multi_Haps_Without_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Path_Multi_Haps_Without_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Path_Multi_Haps_Without_SO_0200" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludeso6");
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludesoFeature4");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Path_Multi_Haps_Without_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Path_Multi_Haps_Without_SO_0300
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Path_Multi_Haps_Without_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Path_Multi_Haps_Without_SO_0300" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludesoFeature2");
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludesoFeature3");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Path_Multi_Haps_Without_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Path_Multi_Haps_Without_SO_0400
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Path_Multi_Haps_Without_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Path_Multi_Haps_Without_SO_0400" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludesoFeature5");
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapNotIncludesoFeature6");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + NO_SO_BUNDLE_NAME6 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(NO_SO_BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Path_Multi_Haps_Without_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Path_Multi_Haps_Section_With_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Path_Multi_Haps_Section_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Path_Multi_Haps_Section_With_SO_0100" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapSectionContainso1");
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapSectionContainsoFeature1");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Path_Multi_Haps_Section_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Path_Multi_Haps_Section_With_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Path_Multi_Haps_Section_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Path_Multi_Haps_Section_With_SO_0200" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapSectionContainso2");
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapSectionContainsoFeature4");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Path_Multi_Haps_Section_With_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Path_Multi_Haps_Section_With_SO_0300
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Path_Multi_Haps_Section_With_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Path_Multi_Haps_Section_With_SO_0300" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapSectionContainsoFeature2");
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapSectionContainsoFeature3");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Path_Multi_Haps_Section_With_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Installs_Path_Multi_Haps_Section_With_SO_0400
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install bundles
 *           3.the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Installs_Path_Multi_Haps_Section_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Installs_Path_Multi_Haps_Section_With_SO_0400" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapSectionContainsoFeature5");
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + "hapSectionContainsoFeature6");
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Installs_Path_Multi_Haps_Section_With_SO_0400" << std::endl;
}


//upgrade installation
/**
 * @tc.number: BMS_Update_Install_Hap_With_SO_0100
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_SO_0200
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_SO_0300
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_SO_0400
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is existed
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6 + HAP_SECTION_INCLUDE_SO_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_SO_0500
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is existed
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH1 + HAP_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH1 + HAP_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_NO_SO_0100
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_NO_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_NO_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_NO_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_NO_SO_0200
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_NO_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_NO_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_NO_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_NO_SO_0300
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap without so and compressNativeLibs is false and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_NO_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_NO_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_NO_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_NO_SO_0400
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_NO_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_NO_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE5 + HAP_SECTION_INCLUDE_SO_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_NO_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_0100
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_0100" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH1 + HAP_WITHOUT_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE1 + HAP_INCLUDE_SO5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_0200
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_0200" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH2 + HAP_WITHOUT_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_0300
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_0300" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH1 + HAP_WITHOUT_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_0400
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_0400" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH2 + HAP_WITHOUT_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE3 + HAP_INCLUDE_SO6_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_0500
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_0500" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH1 + HAP_WITHOUT_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE2 + HAP_INCLUDE_SO5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_0600
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_0600" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH2 + HAP_WITHOUT_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE2 + HAP_INCLUDE_SO6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_0700
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is false and the libIsolation is true
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_0700" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH3 + HAP_WITHOUT_SO3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH7 + HAP_INCLUDE_SO7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH7_FEATURE1 + HAP_INCLUDE_SO7_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_0800
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_0800" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH4 + HAP_WITHOUT_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE1 + HAP_INCLUDE_SO8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_0900
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_0900" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH4 + HAP_WITHOUT_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_0900" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_Without_SO_1000
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_Without_SO_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_Without_SO_1000" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH4 + HAP_WITHOUT_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE3 + HAP_INCLUDE_SO8_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_Without_SO_1000" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_Without_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_Without_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_Without_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_Without_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_Without_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_Without_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_Without_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE5 + HAP_SECTION_INCLUDE_SO_FEATURE5);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_Without_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE6 + HAP_SECTION_INCLUDE_SO_FEATURE6);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_SO_0100
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_SO_0200
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_SO_0300
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs is false and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_SO_0400
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is existed
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_NO_SO_0100
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_NO_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_NO_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_NO_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_NO_SO_0200
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_NO_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_NO_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_NO_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_NO_SO_0300
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap without so and compressNativeLibs is false and the libIsolation is false
 *           3.update install the hap, the compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_NO_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_NO_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_NO_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_NO_SO_0400
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_NO_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_NO_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_NO_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_0100
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_0100" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH1 + HAP_WITHOUT_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_0200
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_0200" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH2 + HAP_WITHOUT_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_0300
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_0300" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH1 + HAP_WITHOUT_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_0400
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_0400" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH2 + HAP_WITHOUT_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + FEATURE_MODULE_NAME3 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_0500
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_0500" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH1 + HAP_WITHOUT_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_0600
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_0600" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH2 + HAP_WITHOUT_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_0700
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is false and the libIsolation is true
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_0700" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH3 + HAP_WITHOUT_SO3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH7_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_0800
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_0800" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH4 + HAP_WITHOUT_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_0900
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_0900" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH4 + HAP_WITHOUT_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_0900" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_Without_SO_1000
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install hap without so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_Without_SO_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_Without_SO_1000" << std::endl;
    auto res = InstallPathBundle(THIRD_BUNDLE_PATH + HAP_WITHOUT_SO_PATH4 + HAP_WITHOUT_SO4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_Without_SO_1000" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Path_Haps_Without_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Path_Haps_Without_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Path_Haps_Without_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Path_Haps_Without_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Path_Haps_Without_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Path_Haps_Without_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Path_Haps_Without_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Path_Haps_Without_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Path_Haps_With_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Path_Haps_With_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Path_Haps_With_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Path_Haps_With_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Path_Haps_With_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap without so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap, the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Path_Haps_With_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Path_Haps_With_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Path_Haps_With_SO_0200" << std::endl;
}

//update installation/The installed HAP exists in a non-standalone so
/**
 * @tc.number: BMS_Update_Install_Hap_With_Non_Standalone_SO_0100
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Non_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Non_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Non_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Non_Standalone_SO_0200
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Non_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Non_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Non_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Non_Standalone_SO_0300
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Non_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Non_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE2 + HAP_INCLUDE_SO6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Non_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Non_Standalone_SO_0400
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is true
 *           4.check the libs path is existed
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Non_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Non_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE3 + HAP_INCLUDE_SO6_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Non_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_Non_Standalone_SO_0100
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_Non_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_Non_Standalone_SO_0100" << std::endl;
    std::vector<std::string> hapPaths;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE1 + HAP_INCLUDE_SO5_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_Non_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_Non_Standalone_SO_0200
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_Non_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_Non_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_Non_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_Non_Standalone_SO_0300
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_Non_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_Non_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_Non_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_Non_Standalone_SO_0400
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_Non_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_Non_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE3 + HAP_INCLUDE_SO6_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + FEATURE_MODULE_NAME3 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_Non_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_Non_Standalone_SO_0500
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_Non_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_Non_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE2 + HAP_INCLUDE_SO5_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_Non_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_Non_Standalone_SO_0600
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_Non_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_Non_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE2 + HAP_INCLUDE_SO6_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_Non_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_Non_Standalone_SO_0800
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_Non_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_Non_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE1 + HAP_INCLUDE_SO8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE1 + HAP_INCLUDE_SO8_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_Non_Standalone_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_Non_Standalone_SO_0900
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_Non_Standalone_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_Non_Standalone_SO_0900" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE1 + HAP_INCLUDE_SO8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_Non_Standalone_SO_0900" << std::endl;
}

/**
 * @tc.number: BMS_Install_Multi_Haps_With_Non_Standalone_SO_1000
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Multi_Haps_With_Non_Standalone_SO_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Multi_Haps_With_Non_Standalone_SO_1000" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE1 + HAP_INCLUDE_SO8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE3 + HAP_INCLUDE_SO8_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Multi_Haps_With_Non_Standalone_SO_1000" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Non_Standalone_Hap_NO_SO_0100
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Non_Standalone_Hap_NO_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Non_Standalone_Hap_NO_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Non_Standalone_Hap_NO_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Non_Standalone_Hap_NO_SO_0200
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Non_Standalone_Hap_NO_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Non_Standalone_Hap_NO_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Non_Standalone_Hap_NO_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Non_Standalone_Hap_NO_SO_0300
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Non_Standalone_Hap_NO_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Non_Standalone_Hap_NO_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Non_Standalone_Hap_NO_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Non_Standalone_Hap_NO_SO_0400
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is false and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Non_Standalone_Hap_NO_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Non_Standalone_Hap_NO_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE5 + HAP_SECTION_INCLUDE_SO_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Non_Standalone_Hap_NO_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE5 + HAP_SECTION_INCLUDE_SO_FEATURE5);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0500
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0600
 * @tc.name:  test the installation of multiple haps
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0700
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0700" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0800
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE5 + HAP_SECTION_INCLUDE_SO_FEATURE5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE6 + HAP_SECTION_INCLUDE_SO_FEATURE6);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_Non_Standalone_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0100
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0200
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0300
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0400
 * @tc.name:  test the installation of a hap contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is true
 *           4.check the libs path is existed
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Non_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0100
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0200
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0300
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0400
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + FEATURE_MODULE_NAME3 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0500
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0600
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0800
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0900
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0900" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_0900" << std::endl;
}

/**
 * @tc.number: BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_1000
 * @tc.name:  test the installation of haps contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_1000" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Path_Multi_Haps_With_Non_Standalone_SO_1000" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0100
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0200
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is false
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0300
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is false and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0400
 * @tc.name:  test the installation of a hap not contains so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap not contains so
 *           2.install the hap with so and compressNativeLibs is false and the libIsolation is false
 *           3.update install the hap, compressNativeLibs is true and the libIsolation is true
 *           4.check the libs path is not exist
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Non_Standalone_Hap_NO_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap, the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0500
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH1);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0600
 * @tc.name:  test the installation of multiple haps
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0700
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is false
 *           3.the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0700" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0800
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is false
 *           3.the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Non_Standalone_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Standalone_SO_0100
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap with so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE1 + HAP_INCLUDE_SO5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Standalone_SO_0200
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap with so
 *           2.install bundle compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Standalone_SO_0300
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap with so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE2 + HAP_INCLUDE_SO5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Standalone_SO_0400
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap with so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE4 + HAP_INCLUDE_SO5_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Standalone_SO_0500
 * @tc.name:  test the installation of hap without so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap without so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE5 + HAP_INCLUDE_SO5_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Standalone_SO_0600
 * @tc.name:  test the installation of hap without so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap without so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE6 + HAP_INCLUDE_SO5_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Standalone_SO_0700
 * @tc.name:  test the installation of hap without so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap without so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Standalone_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Standalone_SO_0700" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE7 + HAP_INCLUDE_SO5_FEATURE7);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Standalone_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Hap_With_Standalone_SO_0800
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap without so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Hap_With_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Hap_With_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE8 + HAP_INCLUDE_SO5_FEATURE8);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Hap_With_Standalone_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0100
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE1 + HAP_INCLUDE_SO5_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0200
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0300
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0400
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE3 + HAP_INCLUDE_SO6_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0500
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH7 + HAP_INCLUDE_SO7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH7_FEATURE1 + HAP_INCLUDE_SO7_FEATURE1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH7 + HAP_INCLUDE_SO7);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0600
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE2 + HAP_INCLUDE_SO6_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0700
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0700" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE2 + HAP_INCLUDE_SO5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE4 + HAP_INCLUDE_SO5_FEATURE4);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE1 + HAP_INCLUDE_SO5_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0800
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE1 + HAP_INCLUDE_SO8_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0900
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0900" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_0900" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Multi_Haps_With_Standalone_SO_1000
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Multi_Haps_With_Standalone_SO_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Multi_Haps_With_Standalone_SO_1000" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE3 + HAP_INCLUDE_SO8_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Multi_Haps_With_Standalone_SO_1000" << std::endl;
}


/**
 * @tc.number: BMS_Update_Install_Multi_Haps_With_Standalone_SO_0100
 * @tc.name:  test the installation of haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 with so is true and true
 *             the compressNativeLibs and libIsolation of hap2 without so is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Multi_Haps_With_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Multi_Haps_With_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE1 + HAP_INCLUDE_SO5_FEATURE1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE5 + HAP_INCLUDE_SO5_FEATURE5);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Multi_Haps_With_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Multi_Haps_With_Standalone_SO_0200
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 with so is true and false
 *             the compressNativeLibs and libIsolation of hap2 without so is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Multi_Haps_With_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Multi_Haps_With_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE6 + HAP_INCLUDE_SO5_FEATURE6);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Multi_Haps_With_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Multi_Haps_With_Standalone_SO_0300
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 with so is false and true
 *             the compressNativeLibs and libIsolation of hap2 without so is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Multi_Haps_With_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Multi_Haps_With_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE2 + HAP_INCLUDE_SO5_FEATURE2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE7 + HAP_INCLUDE_SO5_FEATURE7);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Multi_Haps_With_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Multi_Haps_With_Standalone_SO_0400
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 with so is false and false
 *             the compressNativeLibs and libIsolation of hap2 without so is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Multi_Haps_With_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Multi_Haps_With_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE4 + HAP_INCLUDE_SO5_FEATURE4);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE8 + HAP_INCLUDE_SO5_FEATURE8);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Multi_Haps_With_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Multi_Haps_With_Standalone_SO_0500
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Multi_Haps_With_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Multi_Haps_With_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE5 + HAP_INCLUDE_SO5_FEATURE5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE6 + HAP_INCLUDE_SO5_FEATURE6);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Multi_Haps_With_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Multi_Haps_With_Standalone_SO_0600
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Multi_Haps_With_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Multi_Haps_With_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE5 + HAP_INCLUDE_SO5_FEATURE5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE7 + HAP_INCLUDE_SO5_FEATURE7);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Multi_Haps_With_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Multi_Haps_With_Standalone_SO_0700
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Multi_Haps_With_Standalone_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Multi_Haps_With_Standalone_SO_0700" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE5 + HAP_INCLUDE_SO5_FEATURE5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE8 + HAP_INCLUDE_SO5_FEATURE8);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Multi_Haps_With_Standalone_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Multi_Haps_With_Standalone_SO_0800
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Multi_Haps_With_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Multi_Haps_With_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE6 + HAP_INCLUDE_SO5_FEATURE6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE7 + HAP_INCLUDE_SO5_FEATURE7);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Multi_Haps_With_Standalone_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Standalone_SO_0100
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap with so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Standalone_SO_0200
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap with so
 *           2.install bundle compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Standalone_SO_0300
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap with so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Standalone_SO_0400
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap with so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Standalone_SO_0500
 * @tc.name:  test the installation of hap without so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap without so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Standalone_SO_0600
 * @tc.name:  test the installation of hap without so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap without so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Standalone_SO_0700
 * @tc.name:  test the installation of hap without so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap without so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Standalone_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Standalone_SO_0700" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE7);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Standalone_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Hap_With_Standalone_SO_0800
 * @tc.name:  test the installation of hap with so
 * @tc.desc: 1.under '/data/test/testHapSo',there is a hap without so
 *           2.install bundle with compressNativeLibs is true and the libIsolation is true
 *           3.the compressNativeLibs and libIsolation of hap is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Hap_With_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Hap_With_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE8);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Hap_With_Standalone_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0100
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0200
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0300
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0400
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0500
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH7_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH7);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME7 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME7);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0600
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0700
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0700" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0800
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0800" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0900
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0900" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_0900" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1000
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is false and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1000" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1000" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1100
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap1 with so and compressNativeLibs is true and the libIsolation is true
 *             install hap2 with so and compressNativeLibs is true and the libIsolation is false
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1200
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *             install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Installs_Path_Multi_Haps_Standalone_SO_1200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0100
 * @tc.name:  test the installation of haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 with so is true and true
 *             the compressNativeLibs and libIsolation of hap2 without so is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0200
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 with so is true and false
 *             the compressNativeLibs and libIsolation of hap2 without so is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0300
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 with so is false and true
 *             the compressNativeLibs and libIsolation of hap2 without so is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE7);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0400
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 with so is false and false
 *             the compressNativeLibs and libIsolation of hap2 without so is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE8);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0500
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0500" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0600
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE7);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0700
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0700" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE8);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0800
 * @tc.name:  test the installation of haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install hap with so and compressNativeLibs is true and the libIsolation is true
 *           3.update install the hap,the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE7);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Update_Install_Path_Multi_Haps_Standalone_SO_0800" << std::endl;
}

//update installation/The installed HAP exists in non-standalone so and Independent so
/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_0100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is true and false
 *             compressNativeLibs and libIsolation of hap2 is true and true
 *           3.update hap: hap with so and compressNativeLibs and libIsolation of update hap is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_0100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_0200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is true and false
 *             compressNativeLibs and libIsolation of hap2 is true and true
 *           3.update hap: hap with so and compressNativeLibs and libIsolation of update hap is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_0200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_0300
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap2 is true and false
 *             compressNativeLibs and libIsolation of hap2 is true and true
 *           3.update hap: hap with so and compressNativeLibs and libIsolation of update hap is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_0300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE2 + HAP_INCLUDE_SO6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_0400
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is false and true
 *             compressNativeLibs and libIsolation of hap2 is false and false
 *           3.update hap: hap with so and compressNativeLibs and libIsolation of update hap is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_0400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_0600
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is true and true
 *             compressNativeLibs and libIsolation of hap2 is true and false
 *           3.update hap: hap without so and compressNativeLibs and libIsolation of update hap is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_0600" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_0700
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is true and true
 *             compressNativeLibs and libIsolation of hap2 is true and false
 *           3.update hap: hap without so and compressNativeLibs and libIsolation of update hap is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_0700" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_0700" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_0900
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is true and true
 *             compressNativeLibs and libIsolation of hap2 is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_0900" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE1 + HAP_INCLUDE_SO5_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_0900" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_1000
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is true and true
 *             compressNativeLibs and libIsolation of hap2 is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_1000" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_1000" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_1100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is true and false
 *             compressNativeLibs and libIsolation of hap2 is true and true
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_1100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_1100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_1100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_1200
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is true and true
 *             compressNativeLibs and libIsolation of hap2 is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_1200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_1200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE3 + HAP_INCLUDE_SO6_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + FEATURE_MODULE_NAME3 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_1200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_1300
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap1 is true and false
 *             compressNativeLibs and libIsolation of hap2 is true and true
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_1300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_1300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3 + HAP_INCLUDE_SO5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5 + HAP_INCLUDE_SO5);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH5_FEATURE2 + HAP_INCLUDE_SO5_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_1300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_1400
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_1400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_1400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1 + HAP_INCLUDE_SO6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6 + HAP_INCLUDE_SO6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH6_FEATURE2 + HAP_INCLUDE_SO6_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_1400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_1600
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and true
 *             compressNativeLibs and libIsolation of hap is false and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_1600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_1600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE1 + HAP_INCLUDE_SO8_FEATURE1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_1600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_1700
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and true
 *             compressNativeLibs and libIsolation of hap is false and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_1700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_1700" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_1700" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_1800
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and true
 *             compressNativeLibs and libIsolation of hap is false and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_1800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_1800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2 + HAP_INCLUDE_SO8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_INCLUDE_SO_PATH8_FEATURE3 + HAP_INCLUDE_SO8_FEATURE3);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_1800" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_1900
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and false
 *             compressNativeLibs and libIsolation of hap is false and true
 *           3.update hap: hap all without so
 *             the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_1900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_1900" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_1900" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_2000
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and false
 *             compressNativeLibs and libIsolation of hap is false and true
 *           3.update hap: hap all without so
 *             the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_2000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_2000" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6 + HAP_SECTION_INCLUDE_SO_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE5 + HAP_SECTION_INCLUDE_SO_FEATURE5);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_2000" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_2100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap all without so
 *             the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_2100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_2100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_2100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_2200
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap with so
 *             compressNativeLibs and libIsolation of update hap is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_2200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_2200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_2200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_2300
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap with so
 *             compressNativeLibs and libIsolation of update hap is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_2300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_2300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_2300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_2400
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and false
 *             compressNativeLibs and libIsolation of hap2 is true and true
 *           3.update hap: hap with so
 *             compressNativeLibs and libIsolation of update hap is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_2400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_2400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_2400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_2500
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and false
 *             compressNativeLibs and libIsolation of hap is true and true
 *           3.update hap: hap with so
 *             compressNativeLibs and libIsolation of update hap is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_2500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_2500" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_2500" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_2600
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap without so
 *             compressNativeLibs and libIsolation of update hap is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_2600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_2600" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_2600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_2700
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap without so
 *             compressNativeLibs and libIsolation of update hap is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_2700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_2700" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_2700" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_2900
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_2900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_2900" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_2900" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_3000
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_3000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_3000" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_3000" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_3100
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_3100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_3100" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_3100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_3200
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_3200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_3200" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + FEATURE_MODULE_NAME3 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_3200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_3300
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is true
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_3300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_3300" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH5_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH5_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME5 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_3300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_3400
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is true and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is true and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_3400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_3400" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH6_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH6_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME6 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_3400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_3600
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and true
 *             compressNativeLibs and libIsolation of hap is false and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is true and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_3600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_3600" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_3600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_3700
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and true
 *             compressNativeLibs and libIsolation of hap is false and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_3700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_3700" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_3700" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_3800
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and true
 *             compressNativeLibs and libIsolation of hap is false and false
 *           3.update hap: hap all with so
 *             the compressNativeLibs of hap1 is false and the libIsolation of hap1 is false
 *             the compressNativeLibs of hap2 is false and the libIsolation of hap2 is false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_3800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_3800" << std::endl;
    auto res = InstallBundle(HAP_INCLUDE_SO_PATH8_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_INCLUDE_SO_PATH8 + HAP_INCLUDE_SO8);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_INCLUDE_SO_PATH8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_INCLUDE_SO_PATH8_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME8 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME8);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_3800" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_3900
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and false
 *             compressNativeLibs and libIsolation of hap is false and true
 *           3.update hap: hap all without so
 *             the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_3900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_3900" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_3900" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_4000
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and false
 *             compressNativeLibs and libIsolation of hap is false and true
 *           3.update hap: hap all without so
 *             the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_4000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_4000" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_4000" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_4100
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and true
 *             compressNativeLibs and libIsolation of hap is false and true
 *           3.update hap: The first HAP has so the second does not
 *             the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_4100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_4100" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH1 + HAP_SECTION_INCLUDE_SO1);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_4100" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_4200
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and false
 *             compressNativeLibs and libIsolation of hap1 is false and true
 *           3.update hap: The first HAP has so the second does not
 *             the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_4200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_4200" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6 + HAP_SECTION_INCLUDE_SO_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH2 + HAP_SECTION_INCLUDE_SO2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_4200" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_4300
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and false
 *             compressNativeLibs and libIsolation of hap is false and true
 *           3.update hap: The first HAP has so the second does not
 *             the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_4300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_4300" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1 + HAP_SECTION_INCLUDE_SO_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE3 + HAP_SECTION_INCLUDE_SO_FEATURE3);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE2 + HAP_SECTION_INCLUDE_SO_FEATURE2);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_4300" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_4400
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and false
 *             compressNativeLibs and libIsolation of hap1 is false and true
 *           3.update hap: The first HAP has so the second does not
 *             the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_4400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_4400" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4 + HAP_SECTION_INCLUDE_SO_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6 + HAP_SECTION_INCLUDE_SO_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE6 + HAP_SECTION_INCLUDE_SO_FEATURE6);
    hapPaths.emplace_back(THIRD_BUNDLE_PATH + HAP_SECTION_INCLUDE_SO_PATH_FEATURE5 + HAP_SECTION_INCLUDE_SO_FEATURE5);
    res = UpdateInstalls(hapPaths);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_4400" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_4500
 * @tc.name:  test the installation of multiple haps without so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps without so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and false
 *             compressNativeLibs and libIsolation of hap is false and true
 *           3.update hap: The first HAP has so the second does not
 *             the compressNativeLibs and libIsolation of hap1 is true and true
 *             the compressNativeLibs and libIsolation of hap2 is true and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_4500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_4500" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_4500" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_4600
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and false
 *             compressNativeLibs and libIsolation of hap1 is false and true
 *           3.update hap: The first HAP has so the second does not
 *             the compressNativeLibs and libIsolation of hap1 is false and false
 *             the compressNativeLibs and libIsolation of hap2 is false and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_4600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_4600" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + MODULE_NAME + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_4600" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_4700
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is true and false
 *             compressNativeLibs and libIsolation of hap is false and true
 *           3.update hap: The first HAP has so the second does not
 *             the compressNativeLibs and libIsolation of hap1 is true and false
 *             the compressNativeLibs and libIsolation of hap2 is true and false
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_4700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_4700" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME1 + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_4700" << std::endl;
}

/**
 * @tc.number: BMS_Install_Hap_With_Multi_Type_SO_4800
 * @tc.name:  test the installation of multiple haps with so
 * @tc.desc: 1.under '/data/test/testHapSo',there are two haps with so
 *           2.install multi hap with non-standalone so and Independent so
 *             compressNativeLibs and libIsolation of hap is false and false
 *             compressNativeLibs and libIsolation of hap1 is false and true
 *           3.update hap: The first HAP has so the second does not
 *             the compressNativeLibs and libIsolation of hap1 is false and true
 *             the compressNativeLibs and libIsolation of hap2 is false and true
 *           4.check installation is successful
 */
HWTEST_F(BmsInstallHapSoTest, BMS_Install_Hap_With_Multi_Type_SO_4800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_Hap_With_Multi_Type_SO_4800" << std::endl;
    auto res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallBundle(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE6);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstall(HAP_SECTION_INCLUDE_SO_PATH_FEATURE5);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + SECTION_SO_BUNDLE_NAME2 + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(SECTION_SO_BUNDLE_NAME2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    std::cout << "END BMS_Install_Hap_With_Multi_Type_SO_4800" << std::endl;
}
}  // namespace AppExecFwk
}  // namespace OHOScd