/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cerrno>
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
namespace {
const std::string BUNDLE_NAME = "com.example.extension";
const std::string BASE_HAP_PATH = "/data/test/bms_bundle/";
const std::string VERSION1_WITHOUT_EXTENSION_ENTRY_HAP = "version1_withoutExtension_entry_hap.hap";
const std::string VERSION1_FORM_EXTENSION_ENTRY_HAP = "version1_withoutExtension_entry_form_hap.hap";
const std::string VERSION2_WITHOUT_EXTENSION_ENTRY_HAP = "version2_withoutExtension_entry_hap.hap";
const std::string VERSION2_FORM_EXTENSION_ENTRY_HAP = "version2_withoutExtension_entry_form_hap.hap";
const std::string VERSION1_WITHOUT_EXTENSION_FEATURE_HAP = "version1_withoutExtension_feature_hap.hap";
const std::string VERSION2_WITHOUT_EXTENSION_FEATURE_HAP = "version2_withoutExtension_feature_hap.hap";
const std::string VERSION1_ONE_EXTENSION_ENTRY_HAP = "version1_oneExtension_entry_hap.hap";
const std::string VERSION1_ONE_EXTENSION2_ENTRY_HAP = "version1_oneExtension2_entry_hap.hap";
const std::string VERSION2_ONE_EXTENSION_ENTRY_HAP = "version2_oneExtension_entry_hap.hap";
const std::string VERSION2_ONE_EXTENSION2_ENTRY_HAP = "version2_oneExtension2_entry_hap.hap";
const std::string VERSION1_ONE_EXTENSION_FEATURE_HAP = "version1_oneExtension_feature_hap.hap";
const std::string VERSION2_ONE_EXTENSION_FEATURE_HAP = "version2_oneExtension_feature_hap.hap";
const std::string VERSION1_TWO_EXTENSION_ENTRY_HAP = "version1_twoExtension_entry_hap.hap";
const std::string VERSION2_TWO_EXTENSION_ENTRY_HAP = "version2_twoExtension_entry_hap.hap";
const std::string VERSION1_TWO_EXTENSION_FEATURE_HAP = "version1_twoExtension_feature_hap.hap";
const std::string VERSION2_TWO_EXTENSION_FEATURE_HAP = "version2_twoExtension_feature_hap.hap";
const std::string ENTRY = "entry";
const std::string FEATURE = "feature";
const std::string ENTRY_EX1 = "EntryInputMethodEx1";
const std::string ENTRY_EX2 = "EntryInputMethodEx2";
const std::string FEATURE_EX1 = "FeatureInputMethodEx1";
const std::string FEATURE_EX2 = "FeatureInputMethodEx2";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILURE = "Failure";
const std::string OPERATION_SUCCESS = "Success";
const std::string EXTENSION_DIR = "+extension-";
const std::string FILE_SEPARATOR_LINE = "-";
const std::string FILE_SEPARATOR_PLUS = "+";
const std::string BASE = "/base/";
const std::string DATABASE = "/database/";
const std::string LOG = "/log/";
const std::vector<std::string> BUNDLE_EL = {"el1", "el2", "el3", "el4"};
const int TIMEOUT = 10;
const int32_t USERID = 100;
}  // namespace

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::EventFwk;
class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    virtual ~StatusReceiverImpl();
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

class BmsInstallExtensionSystemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static void InstallBundle(const std::string &bundleFilePath, std::string &installMsg);
    static void UninstallBundle(const std::string &bundleName, std::string &uninstallMsg);
    std::string GetBundleDataDir(const std::string &el) const;
    void CheckFileNotExist(const std::string &moduleName, const std::string &extensionName) const;
    void CheckFileExist(const std::string &moduleName, const std::string &extensionName) const;
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
    bool UpdateBundleForSelf(const std::vector<std::string> &bundleFilePaths) const;
};

sptr<IBundleMgr> BmsInstallExtensionSystemTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BmsInstallExtensionSystemTest::GetInstallerProxy()
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

void BmsInstallExtensionSystemTest::InstallBundle(
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

void BmsInstallExtensionSystemTest::UninstallBundle(
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

bool BmsInstallExtensionSystemTest::UpdateBundleForSelf(const std::vector<std::string> &bundleFilePaths) const
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return false;
    }

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;

    bool result = installerProxy->UpdateBundleForSelf(bundleFilePaths, installParam, statusReceiver);
    return result;
}

std::string BmsInstallExtensionSystemTest::GetBundleDataDir(const std::string &el) const
{
    std::string dataDir = "/data/app/" +
                          el +
                          "/" +
                          std::to_string(USERID);
    return dataDir;
}

void BmsInstallExtensionSystemTest::CheckFileNotExist(
    const std::string &moduleName, const std::string &extensionName) const
{
    std::string extensionDir = EXTENSION_DIR + moduleName +
        FILE_SEPARATOR_LINE + extensionName +
        FILE_SEPARATOR_PLUS + BUNDLE_NAME;
    for (const auto &el : BUNDLE_EL) {
        std::string bundleDataDir = GetBundleDataDir(el) + BASE;
        std::string baseDir = bundleDataDir + extensionDir;
        int result1 = access(baseDir.c_str(), F_OK);
        EXPECT_NE(result1, 0) << "the dir exist: " << baseDir;

        std::string databaseParentDir = GetBundleDataDir(el) + DATABASE;
        std::string databaseDir = databaseParentDir + extensionDir;
        int result2 = access(databaseDir.c_str(), F_OK);
        EXPECT_NE(result2, 0) << "the dir exist: " << databaseDir;

        if (el == BUNDLE_EL[1]) {
            std::string logParentDir = GetBundleDataDir(el) + LOG;
            std::string logDir = logParentDir + extensionDir;
            int result3 = access(logDir.c_str(), F_OK);
            EXPECT_NE(result3, 0) << "the dir exist: " << logDir;
        }
    }
}

void BmsInstallExtensionSystemTest::CheckFileExist(
    const std::string &moduleName, const std::string &extensionName) const
{
    std::string extensionDir = EXTENSION_DIR + moduleName +
        FILE_SEPARATOR_LINE + extensionName +
        FILE_SEPARATOR_PLUS + BUNDLE_NAME;
    for (const auto &el : BUNDLE_EL) {
        std::string bundleDataDir = GetBundleDataDir(el) + BASE;
        std::string baseDir = bundleDataDir + extensionDir;
        int result1 = access(baseDir.c_str(), F_OK);
        EXPECT_NE(result1, 0) << "the dir not exist: " << baseDir;

        std::string databaseParentDir = GetBundleDataDir(el) + DATABASE;
        std::string databaseDir = databaseParentDir + extensionDir;
        int result2 = access(databaseDir.c_str(), F_OK);
        EXPECT_NE(result2, 0) << "the dir not exist: " << databaseDir;

        if (el == BUNDLE_EL[1]) {
            std::string logParentDir = GetBundleDataDir(el) + LOG;
            std::string logDir = logParentDir + extensionDir;
            int result3 = access(logDir.c_str(), F_OK);
            EXPECT_NE(result3, 0) << "the dir not exist: " << logDir;
        }
    }
}

void BmsInstallExtensionSystemTest::SetUpTestCase()
{}

void BmsInstallExtensionSystemTest::TearDownTestCase()
{}

void BmsInstallExtensionSystemTest::SetUp()
{}

void BmsInstallExtensionSystemTest::TearDown()
{}

/**
 * @tc.number: BmsExtensionInstall_0001
 * @tc.name:  test installing a bundle without extensions
 * @tc.desc: there is not a extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0001, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_WITHOUT_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
}

/**
 * @tc.number: BmsExtensionInstall_0002
 * @tc.name:  test installing a bundle without extensions
 * @tc.desc: there is not a extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0002, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_WITHOUT_EXTENSION_FEATURE_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
}

/**
 * @tc.number: BmsExtensionInstall_0003
 * @tc.name:  test installing a bundle with one extension
 * @tc.desc: there is a extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0003, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0004
 * @tc.name:  test installing a bundle with one extension
 * @tc.desc: there are two extensin dirs for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0004, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_FEATURE_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0005
 * @tc.name:  test installing a bundle with one extension
 * @tc.desc: there is a extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0005, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_FEATURE_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0006
 * @tc.name:  test update a bundle with one extension
 * @tc.desc: there is a extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0006, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION2_ONE_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0007
 * @tc.name:  test update a bundle with one extension
 * @tc.desc: there is a extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0007, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_WITHOUT_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION2_ONE_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0008
 * @tc.name:  test update a bundle with two extension
 * @tc.desc: there is a extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0008, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_WITHOUT_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION2_TWO_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0009
 * @tc.name:  test update a bundle with no extension
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0009, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_TWO_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION2_WITHOUT_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0010
 * @tc.name:  test update a bundle with one extension
 * @tc.desc: there is a extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0010, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION2_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0011
 * @tc.name:  test update a bundle with one extension
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0011, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION1_FORM_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0012
 * @tc.name:  test update a bundle with one extension
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0012, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_FORM_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0013
 * @tc.name:  test update a bundle with one extension
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0013, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_TWO_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0014
 * @tc.name:  test update a bundle with one extension
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0014, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION1_TWO_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0015
 * @tc.name:  test add a module
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0015, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_WITHOUT_EXTENSION_FEATURE_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION1_ONE_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0016
 * @tc.name:  test add a module
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0016, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_FORM_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION1_TWO_EXTENSION_FEATURE_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileExist(FEATURE, FEATURE_EX1);
    CheckFileExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0017
 * @tc.name:  test add a module
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0017, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_WITHOUT_EXTENSION_FEATURE_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION1_FORM_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0018
 * @tc.name:  test add a module
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0018, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION2_TWO_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION2_TWO_EXTENSION_FEATURE_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileExist(ENTRY, ENTRY_EX2);
    CheckFileExist(FEATURE, FEATURE_EX1);
    CheckFileExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}

/**
 * @tc.number: BmsExtensionInstall_0019
 * @tc.name:  test add a module
 * @tc.desc: there is no extensin dir for testing bundle
 */
HWTEST_F(BmsInstallExtensionSystemTest, BmsExtensionInstall_0019, Function | MediumTest | Level1)
{
    std::string bundleFilePath = BASE_HAP_PATH + VERSION1_TWO_EXTENSION_ENTRY_HAP;
    std::string installMsg;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    bundleFilePath = BASE_HAP_PATH + VERSION1_TWO_EXTENSION_FEATURE_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    CheckFileExist(ENTRY, ENTRY_EX1);
    CheckFileExist(ENTRY, ENTRY_EX2);
    CheckFileExist(FEATURE, FEATURE_EX1);
    CheckFileExist(FEATURE, FEATURE_EX2);

    bundleFilePath = BASE_HAP_PATH + VERSION2_FORM_EXTENSION_ENTRY_HAP;
    InstallBundle(bundleFilePath, installMsg);
    ASSERT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);

    std::string uninstallMsg;
    UninstallBundle("com.example.extension", uninstallMsg);
    ASSERT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    CheckFileNotExist(ENTRY, ENTRY_EX1);
    CheckFileNotExist(ENTRY, ENTRY_EX2);
    CheckFileNotExist(FEATURE, FEATURE_EX1);
    CheckFileNotExist(FEATURE, FEATURE_EX2);
}
}  // namespace AppExecFwk
}  // namespace OHOS