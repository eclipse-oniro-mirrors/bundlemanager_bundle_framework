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
const std::string BUNDLE_PATH_1 = "/data/test/testHspSo/";
const std::string BUNDLE_PATH_2 = "/data/test/testHspNoSo/";
const std::string CODE_ROOT_PATH = "/data/app/el1/bundle/public/";
const std::string BUNDLE_NAME_1 = "com.example.hspsotest";
const std::string BUNDLE_NAME_2 = "com.example.hspfeature5";
const std::string BUNDLE_NAME_3 = "com.example.hspfeature6";
const std::string BUNDLE_NAME_4 = "com.example.hspfeature7";
const std::string BUNDLE_NAME_5 = "com.example.hspfeature8";
const std::string FEATURE_MODULE_NAME1 = "/feature1";
const std::string FEATURE_MODULE_NAME2 = "/feature2";
const std::string FEATURE_MODULE_NAME3 = "/feature3";
const std::string FEATURE_MODULE_NAME4 = "/feature4";
const std::string FEATURE_MODULE_NAME5 = "/feature5";
const std::string FEATURE_MODULE_NAME6 = "/feature6";
const std::string FEATURE_MODULE_NAME7 = "/feature7";
const std::string FEATURE_MODULE_NAME8 = "/feature8";
const std::string HSP_INCLUDE_SO_PATH1 = "hspASystemtestFeature1/";
const std::string HSP_INCLUDE_SO_PATH2 = "hspASystemtestFeature2/";
const std::string HSP_INCLUDE_SO_PATH3 = "hspASystemtestFeature3/";
const std::string HSP_INCLUDE_SO_PATH4 = "hspASystemtestFeature4/";
const std::string HSP_WITHOUT_SO_PATH1 = "hspASystemtestFeature5/";
const std::string HSP_WITHOUT_SO_PATH2 = "hspASystemtestFeature6/";
const std::string HSP_WITHOUT_SO_PATH3 = "hspASystemtestFeature7/";
const std::string HSP_WITHOUT_SO_PATH4 = "hspASystemtestFeature8/";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILURE = "Failure";
const std::string OPERATION_SUCCESS = "Success";
const std::string LIBS = "/libs";
const std::string VERSION = "/v1000000";
const char *PARAM_ONE = "persist.bms.supportCompressNativeLibs";
const char *TRUE_FLAG = "true";
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

class BmsInstallExternalHspSoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static std::string UninstallBundle(const std::string &bundleName);
    static std::string InstallPathBundle(const std::string &path);
    static std::string UpdateInstallPath(const std::string &path);
    bool CheckFilePath(const std::string &checkFilePath) const;
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
};

sptr<IBundleMgr> BmsInstallExternalHspSoTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BmsInstallExternalHspSoTest::GetInstallerProxy()
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

std::string BmsInstallExternalHspSoTest::UninstallBundle(
    const std::string &bundleName)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    UninstallParam uninstallParam;
    uninstallParam.bundleName = bundleName;
    uninstallParam.versionCode = Constants::ALL_VERSIONCODE;
    bool uninstallResult = installerProxy->Uninstall(uninstallParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    return statusReceiver->GetResultMsg();
}

std::string BmsInstallExternalHspSoTest::InstallPathBundle(
    const std::string &path)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.sharedBundleDirPaths.emplace_back(path);
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    std::vector<std::string> pathVec;
    auto installResult = installerProxy->StreamInstall(pathVec, installParam, statusReceiver);
    EXPECT_EQ(installResult, ERR_OK);
    return statusReceiver->GetResultMsg();
}

bool BmsInstallExternalHspSoTest::CheckFilePath(const std::string &checkFilePath) const
{
    CommonTool commonTool;
    bool checkIsExist = commonTool.CheckFilePathISExist(checkFilePath);
    if (!checkIsExist) {
        APP_LOGE("%{private}s does not exist!", checkFilePath.c_str());
        return false;
    }
    return true;
}

std::string BmsInstallExternalHspSoTest::UpdateInstallPath(
    const std::string &path)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.sharedBundleDirPaths.emplace_back(path);
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    std::vector<std::string> pathVec;
    auto installResult = installerProxy->StreamInstall(pathVec, installParam, statusReceiver);
    EXPECT_EQ(installResult, ERR_OK);
    return statusReceiver->GetResultMsg();
}

void BmsInstallExternalHspSoTest::SetUpTestCase()
{
    int32_t ret = SetParameter(PARAM_ONE, TRUE_FLAG);
    if (ret <= 0) {
        APP_LOGE("SetParameter failed!");
    }
}

void BmsInstallExternalHspSoTest::TearDownTestCase()
{}

void BmsInstallExternalHspSoTest::SetUp()
{}

void BmsInstallExternalHspSoTest::TearDown()
{}

/**
 * @tc.number: BMS_Install_Hsp_Full_Installation_0100
 * @tc.name:  test the installation of hsp contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp contains so
 *           2.install hsp with so and compressNativeLibs is false and the libIsolation is true
 *           3.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Install_Hsp_Full_Installation_0100, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Install_Hsp_Full_Installation_0200
 * @tc.name:  test the installation of hsp contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp contains so
 *           2.install hsp with so and compressNativeLibs is false and the libIsolation is false
 *           3.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Install_Hsp_Full_Installation_0200, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Install_Hsp_Full_Installation_0300
 * @tc.name:  test the installation of hsp contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp contains so
 *           2.install hsp with so and compressNativeLibs is true and the libIsolation is true
 *           3.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Install_Hsp_Full_Installation_0300, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Install_Hsp_Full_Installation_0400
 * @tc.name:  test the installation of hsp contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp contains so
 *           2.install hsp with so and compressNativeLibs is true and the libIsolation is false
 *           3.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Install_Hsp_Full_Installation_0400, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Install_Hsp_Full_Installation_0500
 * @tc.name:  test the installation of hsp not contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp not contains so
 *           2.install hsp without so and compressNativeLibs is false and the libIsolation is true
 *           3.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Install_Hsp_Full_Installation_0500, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_2 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_2 + VERSION + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Install_Hsp_Full_Installation_0600
 * @tc.name:  test the installation of hsp not contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp not contains so
 *           2.install hsp without so and compressNativeLibs is false and the libIsolation is false
 *           3.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Install_Hsp_Full_Installation_0600, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_3 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_3 + VERSION + FEATURE_MODULE_NAME6 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Install_Hsp_Full_Installation_0700
 * @tc.name:  test the installation of hsp not contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp not contains so
 *           2.install hsp without so and compressNativeLibs is true and the libIsolation is true
 *           3.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Install_Hsp_Full_Installation_0700, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_4 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_4 + VERSION + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Install_Hsp_Full_Installation_0800
 * @tc.name:  test the installation of hsp not contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp not contains so
 *           2.install hsp without so and compressNativeLibs is true and the libIsolation is false
 *           3.check the libs path is exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Install_Hsp_Full_Installation_0800, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_5 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_5 + VERSION + FEATURE_MODULE_NAME8 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_5);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_0100
 * @tc.name:  test the installation of hsp contains so
 * @tc.desc: 1.under '/data/test/testHspSo',there is a hsp contains so
 *           2.install and update hsp with so,the compressNativeLibs is false and the libIsolation is true
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_0100, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_0200
 * @tc.name:  test the installation of hsp contains so
 * @tc.desc: 1.under '/data/test/testHspSo',there is a hsp contains so
 *           2.install and update hsp with so,the compressNativeLibs is false and the libIsolation is false
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_0200, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_0300
 * @tc.name:  test the installation of hsp contains so
 * @tc.desc: 1.under '/data/test/testHspSo',there is a hsp contains so
 *           2.install and update hsp with so,the compressNativeLibs is true and the libIsolation is true
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_0300, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_0400
 * @tc.name:  test the installation of hsp contains so
 * @tc.desc: 1.under '/data/test/testHspSo',there is a hsp contains so
 *           2.install and update hsp with so,the compressNativeLibs is true and the libIsolation is false
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_0400, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_0500
 * @tc.name:  test the installation of hsps contains so
 * @tc.desc: 1.under '/data/test/testHspSo',there are hsps not contains so
 *           2.install hsp1 with so and compressNativeLibs is true and the libIsolation is false
 *           2.install hsp2 with so and compressNativeLibs is false and the libIsolation is true
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_0500, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME1 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_0600
 * @tc.name:  test the installation of hsps contains so
 * @tc.desc: 1.under '/data/test/testHspSo',there are hsps not contains so
 *           2.install hsp1 with so and compressNativeLibs is false and the libIsolation is true
 *           2.install hsp2 with so and compressNativeLibs is false and the libIsolation is false
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_0600, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME2 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_0700
 * @tc.name:  test the installation of hsps contains so
 * @tc.desc: 1.under '/data/test/testHspSo',there are hsps not contains so
 *           2.install hsp1 with so and compressNativeLibs is false and the libIsolation is true
 *           2.install hsp2 with so and compressNativeLibs is true and the libIsolation is true
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_0700, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME3 + LIBS);
    EXPECT_EQ(ret, true);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_0800
 * @tc.name:  test the installation of hsps contains so
 * @tc.desc: 1.under '/data/test/testHspSo',there are hsps not contains so
 *           2.install hsp1 with so and compressNativeLibs is false and the libIsolation is true
 *           2.install hsp2 with so and compressNativeLibs is true and the libIsolation is false
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_0800, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(BUNDLE_PATH_1 + HSP_INCLUDE_SO_PATH4);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + LIBS);
    EXPECT_EQ(ret, true);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_1 + VERSION + FEATURE_MODULE_NAME4 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_0900
 * @tc.name:  test the installation of haps bot contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp not contains so
 *           2.install and update hsp without so,the compressNativeLibs is false
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_0900, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_2 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_2 + VERSION + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_1000
 * @tc.name:  test the installation of haps not contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there is a hsp not contains so
 *           2.install and update hsp without so,the compressNativeLibs is true
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_1000, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH3);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = UpdateInstallPath(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_4 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_4 + VERSION + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_1100
 * @tc.name:  test the installation of hsps not contains so
 * @tc.desc: 1.under '/data/test/testHspNoSo',there are hsps not contains so
 *           2.install hsp1 without so and compressNativeLibs is false
 *           2.install hsp2 without so and compressNativeLibs is false
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_1100, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH1);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_2 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_2 + VERSION + FEATURE_MODULE_NAME5 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}

/**
 * @tc.number: BMS_Update_Install_Hsp_1200
 * @tc.name:  test the installation of hsps contains so
 * @tc.desc: 1.under '/data/test/testHspSo',there are hsps not contains so
 *           2.install hsp1 without so and compressNativeLibs is false
 *           2.install hsp2 without so and compressNativeLibs is true
 *           3.check the libs path is not exist and the installation is successful
 */
HWTEST_F(BmsInstallExternalHspSoTest, BMS_Update_Install_Hsp_1200, Function | MediumTest | Level1)
{
    auto res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH2);
    EXPECT_EQ(res, OPERATION_SUCCESS);
    res = InstallPathBundle(BUNDLE_PATH_2 + HSP_WITHOUT_SO_PATH3);
    EXPECT_EQ(res, OPERATION_SUCCESS);

    bool ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_4 + VERSION + LIBS);
    EXPECT_EQ(ret, false);
    ret = CheckFilePath(CODE_ROOT_PATH + BUNDLE_NAME_4 + VERSION + FEATURE_MODULE_NAME7 + LIBS);
    EXPECT_EQ(ret, false);

    res = UninstallBundle(BUNDLE_NAME_4);
    EXPECT_EQ(res, OPERATION_SUCCESS);
}
}  // namespace AppExecFwk
}  // namespace OHOScd