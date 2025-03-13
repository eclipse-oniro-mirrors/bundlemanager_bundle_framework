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
#include <gtest/gtest.h>
#include <vector>

#include "system_ability_definition.h"
#include "system_ability.h"
#include "bundle_mgr_interface.h"
#include "bundle_installer_proxy.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#define private public
#include "bundle_multiuser_installer.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string HSPNAME = "hspName";
const char* DATA = "data";
size_t DATA_SIZE = 4;
const std::string OVER_MAX_NAME_SIZE(260, 'x');
constexpr int32_t TEST_INSTALLER_ID = 1024;
constexpr int32_t DEFAULT_INSTALLER_ID = 0;
constexpr int32_t TEST_INSTALLER_UID = 100;
constexpr int32_t INVAILD_ID = -1;

constexpr const char* ILLEGAL_PATH_FIELD = "../";
}; // namespace
class BmsBundleMultiuserInstallIPCTest : public testing::Test {
public:
    BmsBundleMultiuserInstallIPCTest();
    ~BmsBundleMultiuserInstallIPCTest();
    static void SetUpTestCase();
    static void TearDownTestCase();

    sptr<IBundleMgr> GetBundleMgrProxy();
    sptr<IBundleInstaller> GetInstallerProxy();
    void SetUp();
    void TearDown();

private:
    sptr<BundleInstallerHost> installerHost_ = nullptr;
    sptr<BundleInstallerProxy> installerProxy_ = nullptr;
};

BmsBundleMultiuserInstallIPCTest::BmsBundleMultiuserInstallIPCTest()
{}

BmsBundleMultiuserInstallIPCTest::~BmsBundleMultiuserInstallIPCTest()
{}

void BmsBundleMultiuserInstallIPCTest::SetUpTestCase()
{
}

void BmsBundleMultiuserInstallIPCTest::TearDownTestCase()
{
}
void BmsBundleMultiuserInstallIPCTest::SetUp()
{}

void BmsBundleMultiuserInstallIPCTest::TearDown()
{}

sptr<IBundleMgr> BmsBundleMultiuserInstallIPCTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BmsBundleMultiuserInstallIPCTest::GetInstallerProxy()
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

class EmptyTestBundleInstaller : public IBundleInstaller {
public:
    bool Install(const std::string &bundleFilePath, const InstallParam &installParam,
        const sptr<IStatusReceiver> &statusReceiver)
    {
        return false;
    }
    bool Recover(const std::string &bundleName, const InstallParam &installParam,
        const sptr<IStatusReceiver> &statusReceiver)
    {
        return false;
    }
    bool Install(const std::vector<std::string> &bundleFilePaths, const InstallParam &installParam,
        const sptr<IStatusReceiver> &statusReceiver)
    {
        return false;
    }
    bool Uninstall(const std::string &bundleName, const InstallParam &installParam,
        const sptr<IStatusReceiver> &statusReceiver)
    {
        return false;
    }
    bool Uninstall(const UninstallParam &uninstallParam,
        const sptr<IStatusReceiver> &statusReceiver)
    {
        return false;
    }
    bool Uninstall(const std::string &bundleName, const std::string &modulePackage,
        const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
    {
        return false;
    }
    bool InstallByBundleName(const std::string &bundleName, const InstallParam &installParam,
        const sptr<IStatusReceiver> &statusReceiver)
    {
        return false;
    }
    ErrCode InstallSandboxApp(const std::string &bundleName, int32_t dlpType, int32_t userId,
        int32_t &appIndex)
    {
        return ERR_OK;
    }
    ErrCode UninstallSandboxApp(const std::string &bundleName, int32_t appIndex, int32_t userId)
    {
        return ERR_OK;
    }
    sptr<IBundleStreamInstaller> CreateStreamInstaller(const InstallParam &installParam,
        const sptr<IStatusReceiver> &statusReceiver, const std::vector<std::string>& originHapPaths)
    {
        return nullptr;
    }
    bool DestoryBundleStreamInstaller(uint32_t streamInstallerId)
    {
        return false;
    }
    ErrCode StreamInstall(const std::vector<std::string> &bundleFilePaths, const InstallParam &installParam,
        const sptr<IStatusReceiver> &statusReceiver)
    {
        return ERR_OK;
    }
    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }
};

HWTEST_F(BmsBundleMultiuserInstallIPCTest,
    InstallMultiuserInstallTest001_BundleNameEmpty, Function | SmallTest | Level0)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return;
    }
    const std::string bundleName = "";
    const int32_t userId = 100;

    auto result = installerProxy->InstallExisted(bundleName, userId);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

HWTEST_F(BmsBundleMultiuserInstallIPCTest,
    InstallMultiuserInstallTest001_BundleNotFound, Function | SmallTest | Level0)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return;
    }
    const std::string bundleName = "ohos.samples.etsclock.notfound";
    const int32_t userId = 100;

    auto result = installerProxy->InstallExisted(bundleName, userId);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

HWTEST_F(BmsBundleMultiuserInstallIPCTest,
    InstallMultiuserInstallTest001_UserIdNotFound, Function | SmallTest | Level0)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return;
    }
    const std::string bundleName = "ohos.samples.etsclock";
    const int32_t userId = 200;

    auto result = installerProxy->InstallExisted(bundleName, userId);
    EXPECT_TRUE(result == ERR_BUNDLE_MANAGER_INVALID_USER_ID || result == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

HWTEST_F(BmsBundleMultiuserInstallIPCTest,
    InstallMultiuserInstallTest001_PureInstall, Function | SmallTest | Level0)
{
    EmptyTestBundleInstaller installer;
    std::string bundleName = "bundleName";
    int32_t userId = 100;
    auto res = installer.InstallExisted(bundleName, userId);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: InstallExistedApp_0100
 * @tc.name: InstallExistedApp by BundleMultiUserInstaller
 * @tc.desc: test InstallExistedApp
 */
HWTEST_F(BmsBundleMultiuserInstallIPCTest, InstallExistedApp_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    std::string bundleName;
    auto res = installer.InstallExistedApp(bundleName, TEST_INSTALLER_UID);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: ProcessBundleInstall_0100
 * @tc.name: ProcessBundleInstall by BundleMultiUserInstaller
 * @tc.desc: test ProcessBundleInstall
 */
HWTEST_F(BmsBundleMultiuserInstallIPCTest, ProcessBundleInstall_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    auto res = installer.ProcessBundleInstall(HSPNAME, TEST_INSTALLER_UID);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: CreateDataDir_0100
 * @tc.name: CreateDataDir by BundleMultiUserInstaller
 * @tc.desc: test CreateDataDir
 */
HWTEST_F(BmsBundleMultiuserInstallIPCTest, CreateDataDir_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    InnerBundleInfo info;
    auto res = installer.CreateDataDir(info, TEST_INSTALLER_UID, INVAILD_ID);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: RemoveDataDir_0100
 * @tc.name: RemoveDataDir by BundleMultiUserInstaller
 * @tc.desc: test RemoveDataDir
 */
HWTEST_F(BmsBundleMultiuserInstallIPCTest, RemoveDataDir_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    std::string bundleName;
    auto res = installer.RemoveDataDir(bundleName, TEST_INSTALLER_UID);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: GetDataMgr_0100
 * @tc.name: GetDataMgr by BundleMultiUserInstaller
 * @tc.desc: test GetDataMgr
 */
HWTEST_F(BmsBundleMultiuserInstallIPCTest, GetDataMgr_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    auto res = installer.GetDataMgr();
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: ResetInstallProperties_0100
 * @tc.name: ResetInstallProperties by BundleMultiUserInstaller
 * @tc.desc: test ResetInstallProperties
 */
HWTEST_F(BmsBundleMultiuserInstallIPCTest, ResetInstallProperties_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    installer.uid_ = 5;
    installer.ResetInstallProperties();
    EXPECT_EQ(installer.uid_, 0);
}

/**
 * @tc.number: RecoverHapToken_0100
 * @tc.name: RecoverHapToken by BundleMultiUserInstaller
 * @tc.desc: test RecoverHapToken
 */
HWTEST_F(BmsBundleMultiuserInstallIPCTest, RecoverHapToken_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    installer.dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(installer.dataMgr_, nullptr);
    UninstallBundleInfo unInstallBundleInfo;
    unInstallBundleInfo.appId = 1;
    std::map<std::string, UninstallDataUserInfo> userInfos;
    UninstallDataUserInfo uninstallDataUserInfo;
    unInstallBundleInfo.userInfos.try_emplace("100", uninstallDataUserInfo);
    installer.dataMgr_->UpdateUninstallBundleInfo("test", unInstallBundleInfo);
    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    InnerBundleInfo innerBundleInfo;
    auto res = installer.RecoverHapToken("test", 100, accessTokenIdEx, innerBundleInfo);
    EXPECT_EQ(res, true);
    installer.dataMgr_->DeleteUninstallBundleInfo("test", 100);
}
} // OHOS