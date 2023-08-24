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

#include "account_info.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_installer_interface.h"
#include "bundle_mgr_interface.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_tool.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"
#include "status_receiver_host.h"

using namespace testing::ext;
using namespace std::chrono_literals;
namespace {
const std::string THIRD_BUNDLE_PATH = "/data/test/bms_bundle/";
const std::string BUNDLE_NAME = "com.example.internalOverlayTest1";
const std::string TEST_BUNDLE_HAPA = "entry_hap.hap";
const std::string TEST_BUNDLE_HAPB = "entry_hapB.hap";
const std::string HIGHER_VERSION_CODE_TEST_BUNDLE_HAPA = "higher_version_entry_hap.hap";
const std::string HIGHER_VERSION_CODE_TEST_BUNDLE_HAPB = "higher_version_entry_hapB.hap";
const std::string LOWER_VERSION_CODE_TEST_BUNDLE_HAPA = "lower_versionCode_entry_hap.hap";
const std::string LOWER_VERSION_CODE_TEST_BUNDLE_HAPB = "lower_versionCode_entry_hapB.hap";
const int TIMEOUT = 10;
const int32_t WAIT_TIME = 3; // for creating or removing new user
const int32_t USERID = 100;
const std::string STRING_TEST_NAME = "test_account_name";
}  // namespace

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::EventFwk;
using namespace AccountSA;
class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    virtual ~StatusReceiverImpl() override;
    virtual void OnStatusNotify(const int progress) override;
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    int32_t GetResultCode() const;

private:
    mutable std::promise<int32_t> resultCodeSignal_;

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
{}

void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    APP_LOGD("on finished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
    resultCodeSignal_.set_value(resultCode);
}

int32_t StatusReceiverImpl::GetResultCode() const
{
    auto future = resultCodeSignal_.get_future();
    std::chrono::seconds timeout(TIMEOUT);
    if (future.wait_for(timeout) == std::future_status::timeout) {
        return ERR_APPEXECFWK_OPERATION_TIME_OUT;
    }

    return future.get();
}

class BmsInstallMultiUserTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static ErrCode InstallBundle(const std::vector<std::string> &bundleFilePaths, int32_t userId);
    static void UninstallBundle(const std::string &bundleName, int32_t userId);
    bool CheckFilePath(const std::string &checkFilePath) const;
    void CheckFileNonExist(const std::string &bundleName) const;
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
    static int32_t CreateNewUser();
    static void RemoveUser(int32_t userId);

    static int32_t newUserId_;
};

void BmsInstallMultiUserTest::SetUpTestCase()
{
    newUserId_ = CreateNewUser();
    EXPECT_NE(newUserId_, 0);
}

void BmsInstallMultiUserTest::TearDownTestCase()
{
    RemoveUser(newUserId_);
}

void BmsInstallMultiUserTest::SetUp()
{}

void BmsInstallMultiUserTest::TearDown()
{}

sptr<IBundleMgr> BmsInstallMultiUserTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BmsInstallMultiUserTest::GetInstallerProxy()
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

ErrCode BmsInstallMultiUserTest::InstallBundle(const std::vector<std::string> &bundleFilePaths, int32_t userId)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    InstallParam installParam;
    installParam.userId = userId;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    auto ret = installerProxy->StreamInstall(bundleFilePaths, installParam, statusReceiver);
    if (ret == ERR_OK) {
        ret = statusReceiver->GetResultCode();
    }
    return ret;
}

void BmsInstallMultiUserTest::UninstallBundle(const std::string &bundleName, int32_t userId)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return;
    }

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    installParam.userId = userId;

    bool uninstallResult = installerProxy->Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    auto res = statusReceiver->GetResultCode();
    EXPECT_EQ(res, ERR_OK);
}

int32_t BmsInstallMultiUserTest::CreateNewUser()
{
    if (newUserId_ != 0) {
        return newUserId_;
    }
    OsAccountInfo osAccountInfo;
    auto res = OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::NORMAL, osAccountInfo);
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    EXPECT_EQ(res, ERR_OK);
    return osAccountInfo.GetLocalId();
}

void BmsInstallMultiUserTest::RemoveUser(int32_t userId)
{
    ErrCode ret = OsAccountManager::RemoveOsAccount(userId);
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    EXPECT_EQ(ret, ERR_OK);
}

int32_t BmsInstallMultiUserTest::newUserId_ = 0;

/**
 * @tc.number: BMS_Install_multi_user_0100
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.install the higher version-code hapA under the user 101 successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_0100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_0100" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, newUserId_);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_0100" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_0200
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.install the lower version-code hapA under the user 101 failed
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_0200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_0200" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_0200" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_0300
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.install the same version-code hapA under the user 101 successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_0300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_0300" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_0300" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_0400
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.install the higher version-code hapB under the user 101 successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_0400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_0400" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_NOT_COMPATIBLE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_0400" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_0500
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.install the lower version-code hapB under the user 101 failed
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_0500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_0500" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_0500" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_0600
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.install the same version-code hapB under the user 101 successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_0600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_0600" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_0600" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_0700
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.install the higher version-code hapA and hapB under the user 101 successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_0700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_0700" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPA);
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, newUserId_);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_0700" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_0800
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.install the lower version-code hapA and hapB under the user 101 failed
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_0800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_0800" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPA);
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_0800" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_0900
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.install the same version-code hapA and hapB under the user 101 successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_0900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_0900" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_0900" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1000
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.not install hapA under user 100
 *           2.create user 101 successfully
 *           3.install the same version-code hapA under the user 101 successfully
 *           4.query bundleInfo under user 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1000" << std::endl;
    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_FALSE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1000" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1100
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.not install hapA under user 100
 *           2.create user 101 successfully
 *           3.install the same version-code hapA and hapB under the user 101 successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1100" << std::endl;
    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_FALSE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1100" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1200
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.create user 101
 *           2.install the bundle under user 100 and user 101
 *           3.query bundle info under user 100 and user 101
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1200" << std::endl;
    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, Constants::ALL_USERID);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1200" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1300
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.create user 101
 *           2.install the bundle under user 100 and user 101
 *           3.query bundle info under user 100 and user 101
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1300" << std::endl;
    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, Constants::ALL_USERID);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1300" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1400
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the higher version-code hapA under the ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1400" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, Constants::ALL_USERID);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1400" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1500
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the lower version-code hapA under the user ALL_USERID failed
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1500" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, Constants::ALL_USERID);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1500" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1600
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the same version-code hapA under the user ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1600" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, Constants::ALL_USERID);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1600" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1700
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the higher version-code hapB under the user ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1700" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, Constants::ALL_USERID);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_NOT_COMPATIBLE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1700" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1800
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the lower version-code hapB under the user ALL_USERID failed
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1800" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, Constants::ALL_USERID);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1800" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_1900
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install install the same version-code hapB under the user ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_1900, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_1900" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, Constants::ALL_USERID);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_1900" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_2000
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA and hapB under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the higher version-code hapA under the user ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_2000, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_2000" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, newUserId_);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_2000" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_2100
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA and hapB under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the lower version-code hapA under the user ALL_USERID failed
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_2100, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_2100" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_2100" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_2200
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA and hapB under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the same version-code hapA under the user ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_2200, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_2200" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_2200" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_2300
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA and hapB under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the higher version-code hapB under the user ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_2300, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_2300" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, newUserId_);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_NOT_COMPATIBLE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_2300" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_2400
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA and hapB under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the lower version-code hapB under the user ALL_USERID failed
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_2400, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_2400" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_2400" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_2500
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA and hapB under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the same version-code hapB under the user ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_2500, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_2500" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_2500" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_2600
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA and hapB under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the higher version-code hapA and hapB under the user ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_2600, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_2600" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPA);
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + HIGHER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, newUserId_);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_2600" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_2700
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA and hapB under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the lower version-code hapA and hapB under the user ALL_USERID failed
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_2700, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_2700" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPA);
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + LOWER_VERSION_CODE_TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_FALSE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_2700" << std::endl;
}

/**
 * @tc.number: BMS_Install_multi_user_2800
 * @tc.name:  test the installation of a third-party bundle for multi users
 * @tc.desc: 1.install hapA and hapB under user 100 successfully
 *           2.create user 101 successfully
 *           3.updata install the same version-code hapA and hapB under the user ALL_USERID successfully
 *           4.query bundleInfo under user 100 and 101 successfully
 */
HWTEST_F(BmsInstallMultiUserTest, BMS_Install_multi_user_2800, Function | MediumTest | Level1)
{
    std::cout << "START BMS_Install_multi_user_2800" << std::endl;
    std::vector<std::string> bundleFilePaths = { THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA };
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    auto res = InstallBundle(bundleFilePaths, USERID);
    EXPECT_EQ(res, ERR_OK);

    int32_t userId = CreateNewUser();
    EXPECT_NE(userId, 0);

    bundleFilePaths.clear();
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPA);
    bundleFilePaths.emplace_back(THIRD_BUNDLE_PATH + TEST_BUNDLE_HAPB);
    res = InstallBundle(bundleFilePaths, userId);
    EXPECT_EQ(res, ERR_OK);

    auto bmsProxy = GetBundleMgrProxy();
    EXPECT_NE(bmsProxy, nullptr);

    // query bundleInfo under two users respectively
    BundleInfo bundleInfo1;
    bool ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo1, USERID);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo2;
    ret = bmsProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo2, userId);
    EXPECT_TRUE(ret);

    UninstallBundle(BUNDLE_NAME, Constants::ALL_USERID);
    std::cout << "END BMS_Install_multi_user_2800" << std::endl;
}
} // AppExecFwk
} // OHOS
