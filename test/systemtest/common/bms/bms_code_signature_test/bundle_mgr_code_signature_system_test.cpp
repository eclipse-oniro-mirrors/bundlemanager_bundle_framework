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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>

#include "app_log_wrapper.h"
#include "bundle_common_event.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_installer_interface.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "iservice_registry.h"
#include "status_receiver_host.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string THIRD_PATH = "/data/test/code_signature/";
const std::string TEST_FILE = "test.txt";
const std::string TEST_HAP_DEMO = "test_demo.hap";
const std::string CODE_SIGNATURE_WITHOUT_LIBS = "CodeSignatureWithoutLibs.hap";
const std::string CODE_SIGNATURE_WITHOUT_LIBS2 = "CodeSignatureWithoutLibs2.hap";
const std::string CODE_SIGNATURE_FILE = "CodeSignatureWithoutLibs.sig";
const std::string CODE_SIGNATURE_FILE2 = "CodeSignatureWithoutLibs2.sig";
const std::string TEST_DEMO_CODE_SIGNATURE_FILE = "testDemo.sig";
const std::string TEST_SIGNATURE_FILE = "/data/test/code_signature/test.sig";
const std::string MODULE_NAME1 = "entry";
const std::string MODULE_NAME2 = "feature";
const std::string TEST_MODULE_NAME = "test_module_name";
const std::string INVALID_THIRD_PATH = "/data/test/test_code_signature/";
const std::string BUNDLE_NAME_WITHOUT_LIBS = "com.example.codeSignature1";
const std::string BUNDLE_NAME_WITH_LIBS = "com.example.codeSignature2";
const int32_t TIMEOUT = 10; // 10s
constexpr int PATH_MAX_SIZE = 256;
} // namespace

class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    ~StatusReceiverImpl() override;
    void OnStatusNotify(const int32_t progress) override;
    void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    int32_t GetResultCode() const;

private:
    mutable std::promise<int32_t> resultMsgSignal_;

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

void StatusReceiverImpl::OnStatusNotify(const int32_t progress)
{
    APP_LOGI("OnStatusNotify progress:%{public}d", progress);
}

void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    APP_LOGD("on finished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
    resultMsgSignal_.set_value(resultCode);
}

int32_t StatusReceiverImpl::GetResultCode() const
{
    auto future = resultMsgSignal_.get_future();
    std::chrono::seconds timeout(TIMEOUT);
    if (future.wait_for(timeout) == std::future_status::timeout) {
        return ERR_APPEXECFWK_OPERATION_TIME_OUT;
    }
    return future.get();
}

class BundleMgrCodeSignatureSystemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static int32_t InstallBundle(const std::vector<std::string> &bundleFilePaths, InstallParam installParam,
        const int32_t userId);
    static int32_t UninstallBundle(const std::string &bundleName, const int32_t userId);
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();

    void CreateSignatureFile() const;
    void DeleteSignatureFile() const;
};

void BundleMgrCodeSignatureSystemTest::SetUpTestCase()
{}

void BundleMgrCodeSignatureSystemTest::TearDownTestCase()
{}

void BundleMgrCodeSignatureSystemTest::SetUp()
{}

void BundleMgrCodeSignatureSystemTest::TearDown()
{}

sptr<IBundleMgr> BundleMgrCodeSignatureSystemTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BundleMgrCodeSignatureSystemTest::GetInstallerProxy()
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

int32_t BundleMgrCodeSignatureSystemTest::InstallBundle(
    const std::vector<std::string> &bundleFilePaths, InstallParam installParam,
    const int32_t userId = Constants::ALL_USERID)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    EXPECT_NE(installerProxy, nullptr);

    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = userId;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    auto installResult = installerProxy->StreamInstall(bundleFilePaths, installParam, statusReceiver);
    if (installResult == ERR_OK) {
        installResult = statusReceiver->GetResultCode();
    }
    return installResult;
}

int32_t BundleMgrCodeSignatureSystemTest::UninstallBundle(
    const std::string &bundleName, const int32_t userId = Constants::ALL_USERID)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    EXPECT_NE(installerProxy, nullptr);

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    if (userId != 0) {
        installParam.userId = userId;
    }
    bool uninstallResult = installerProxy->Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    if (uninstallResult) {
        return statusReceiver->GetResultCode();
    }
    return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
}

void BundleMgrCodeSignatureSystemTest::CreateSignatureFile() const
{
    bool res = SaveStringToFile(TEST_SIGNATURE_FILE, TEST_SIGNATURE_FILE);
    EXPECT_TRUE(res);
}

void BundleMgrCodeSignatureSystemTest::DeleteSignatureFile() const
{
    bool ret = OHOS::RemoveFile(TEST_SIGNATURE_FILE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstallCodeSignatureTest001
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest001, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_001");
    GTEST_LOG_(INFO) << name << " start";
    std::vector<std::string> bundlePathVec { "" };
    InstallParam installParam;

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest002
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest002, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_002");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath(PATH_MAX_SIZE + 1, 'a');
    std::vector<std::string> bundlePathVec { bundlePath };
    InstallParam installParam;

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest003
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest003, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_003");
    GTEST_LOG_(INFO) << name << " start";

    std::string bundlePath = THIRD_PATH + TEST_FILE;
    std::vector<std::string> bundlePathVec { bundlePath };
    InstallParam installParam;

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest004
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest004, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_004");
    GTEST_LOG_(INFO) << name << " start";
    std::string invalidBundlePath = INVALID_THIRD_PATH;
    std::vector<std::string> bundlePathVec { invalidBundlePath };
    InstallParam installParam;

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest005
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest005, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_005");
    GTEST_LOG_(INFO) << name << " start";
    std::string invalidBundlePath = THIRD_PATH + TEST_HAP_DEMO;
    std::vector<std::string> bundlePathVec { invalidBundlePath };
    InstallParam installParam;

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest006
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. size of bundlePath is larger than size of verifyCodeParams
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest006, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_006");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::string bundlePath2 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS2;
    std::vector<std::string> bundlePathVec { bundlePath1, bundlePath2 };
    InstallParam installParam;
    std::string codeSignatureFilePath = THIRD_PATH + CODE_SIGNATURE_FILE;
    installParam.verifyCodeParams.emplace(MODULE_NAME1, codeSignatureFilePath);

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest007
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. size of bundlePath is less than size of verifyCodeParams
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest007, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_007");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1 = THIRD_PATH + CODE_SIGNATURE_FILE;
    std::string codeSignatureFilePath2 = THIRD_PATH + CODE_SIGNATURE_FILE2;
    installParam.verifyCodeParams.emplace(MODULE_NAME1, codeSignatureFilePath1);
    installParam.verifyCodeParams.emplace(MODULE_NAME2, codeSignatureFilePath2);

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest008
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. module name of code signature is empty
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest008, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_008");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1 = THIRD_PATH + CODE_SIGNATURE_FILE;
    installParam.verifyCodeParams.emplace("", codeSignatureFilePath1);

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest009
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. code signature file name is empty
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest009, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_009");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1 = "";
    installParam.verifyCodeParams.emplace(MODULE_NAME1, codeSignatureFilePath1);

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest010
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. the length of code signature file name is longer than PATH_MAX_SIZE
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest010, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_010");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1(PATH_MAX_SIZE + 1, 'a');
    installParam.verifyCodeParams.emplace(MODULE_NAME1, codeSignatureFilePath1);

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest011
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. the suffix of code signature file is not belongs .hap, .hsp, .hqf and .sig
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest011, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_011");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1 = THIRD_PATH + TEST_FILE;
    installParam.verifyCodeParams.emplace(MODULE_NAME1, codeSignatureFilePath1);

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest012
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. invalid code signature file path
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest012, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_012");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1 = INVALID_THIRD_PATH;
    installParam.verifyCodeParams.emplace(MODULE_NAME1, codeSignatureFilePath1);

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest013
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. not existed code signature file
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest013, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_013");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1 = THIRD_PATH + TEST_DEMO_CODE_SIGNATURE_FILE;
    installParam.verifyCodeParams.emplace(MODULE_NAME1, codeSignatureFilePath1);

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest014
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. invalid code signature file is not suffixed with .sig
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest014, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_014");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1 = THIRD_PATH + TEST_HAP_DEMO;
    installParam.verifyCodeParams.emplace(TEST_MODULE_NAME, codeSignatureFilePath1);

    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest015
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. the specified moduleName is not existed
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest015, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_015");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1 = TEST_SIGNATURE_FILE;
    installParam.verifyCodeParams.emplace(TEST_MODULE_NAME, codeSignatureFilePath1);

    CreateSignatureFile();
    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, IStatusReceiver::ERR_INSTALL_CODE_SIGNATURE_FAILED);
    DeleteSignatureFile();
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: InstallCodeSignatureTest016
 * @tc.name: InstallCodeSignature
 * @tc.desc: Test the interface of StreamInstall
 *           1. code signature file is not matched with the corresponding hap
 *           2. install failed
 */
HWTEST_F(BundleMgrCodeSignatureSystemTest, InstallCodeSignatureTest016, TestSize.Level1)
{
    auto name = std::string("InstallCodeSignatureTest_016");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundlePath1 = THIRD_PATH + CODE_SIGNATURE_WITHOUT_LIBS;
    std::vector<std::string> bundlePathVec { bundlePath1 };
    InstallParam installParam;
    std::string codeSignatureFilePath1 = TEST_SIGNATURE_FILE;
    installParam.verifyCodeParams.emplace(MODULE_NAME1, codeSignatureFilePath1);
    CreateSignatureFile();
    auto ret = InstallBundle(bundlePathVec, installParam);
    EXPECT_EQ(ret, IStatusReceiver::ERR_INSTALL_CODE_SIGNATURE_FAILED);
    DeleteSignatureFile();
    if (ret == ERR_OK) {
        ret = UninstallBundle(BUNDLE_NAME_WITHOUT_LIBS);
        EXPECT_EQ(ret, ERR_OK);
    }
    GTEST_LOG_(INFO) << name << " end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
