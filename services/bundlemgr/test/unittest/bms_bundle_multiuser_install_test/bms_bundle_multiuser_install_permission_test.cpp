/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define private public
#include "system_ability_definition.h"
#include "system_ability.h"
#include "bundle_mgr_interface.h"
#include "bundle_installer_proxy.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_multiuser_installer.h"
#include "plugin_installer.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
constexpr int32_t USERID = 100;
constexpr int32_t WAIT_TIME = 5; // init mocked bms

}; // namespace
class BmsBundleMultiuserInstallPermissionTest : public testing::Test {
public:
    BmsBundleMultiuserInstallPermissionTest();
    ~BmsBundleMultiuserInstallPermissionTest();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleMultiuserInstallPermissionTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleMultiuserInstallPermissionTest::BmsBundleMultiuserInstallPermissionTest()
{}

BmsBundleMultiuserInstallPermissionTest::~BmsBundleMultiuserInstallPermissionTest()
{}

void BmsBundleMultiuserInstallPermissionTest::SetUpTestCase()
{
}

void BmsBundleMultiuserInstallPermissionTest::TearDownTestCase()
{
}
void BmsBundleMultiuserInstallPermissionTest::SetUp()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleMultiuserInstallPermissionTest::TearDown()
{}

const std::shared_ptr<BundleDataMgr> BmsBundleMultiuserInstallPermissionTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: ProcessBundleInstall_0100
 * @tc.name: ProcessBundleInstall by BundleMultiUserInstaller
 * @tc.desc: test ProcessBundleInstall
 */
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, ProcessBundleInstall_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    installer.dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(installer.dataMgr_, nullptr);
    installer.dataMgr_->AddUserId(1);
    InnerBundleInfo info;
    installer.dataMgr_->bundleInfos_.try_emplace("test", info);
    auto res = installer.ProcessBundleInstall("test", 1);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
}

/**
 * @tc.number: RecoverHapToken_0100
 * @tc.name: RecoverHapToken by BundleMultiUserInstaller
 * @tc.desc: test RecoverHapToken
 */
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, RecoverHapToken_0100, Function | SmallTest | Level0)
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
    EXPECT_EQ(res, false);
    installer.dataMgr_->DeleteUninstallBundleInfo("test", 100);
}

/**
 * @tc.number: CreateDataDir_0100
 * @tc.name: CreateDataDir by BundleMultiUserInstaller
 * @tc.desc: test CreateDataDir
 */
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, CreateDataDir_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    InnerBundleInfo info;
    auto res = installer.CreateDataDir(info, 100, -1);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: PluginInstaller_0001
 * @tc.name: test VerifyCodeSignatureForNativeFiles
 * @tc.desc: 1.Test VerifyCodeSignatureForNativeFiles the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0001, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    std::string bundlePath;
    std::string cpuAbi;
    std::string targetSoPath;
    std::string signatureFileDir;
    bool isPreInstalledBundle = true;
    auto ret = installer.VerifyCodeSignatureForNativeFiles(bundlePath, cpuAbi, targetSoPath, signatureFileDir,
        isPreInstalledBundle);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: PluginInstaller_0002
 * @tc.name: test VerifyCodeSignatureForNativeFiles
 * @tc.desc: 1.Test VerifyCodeSignatureForNativeFiles the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0002, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    std::string bundlePath;
    std::string cpuAbi;
    std::string targetSoPath;
    std::string signatureFileDir;
    bool isPreInstalledBundle = true;
    auto ret = installer.VerifyCodeSignatureForNativeFiles(bundlePath, cpuAbi, targetSoPath, signatureFileDir,
        isPreInstalledBundle);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: PluginInstaller_0003
 * @tc.name: test VerifyCodeSignatureForHsp
 * @tc.desc: 1.Test VerifyCodeSignatureForHsp the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0003, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    std::string hspPath;
    std::string appIdentifier;
    bool isEnterpriseBundle = true;
    bool isCompileSdkOpenHarmony = true;
    auto ret = installer.VerifyCodeSignatureForHsp(hspPath, appIdentifier, isEnterpriseBundle,
        isCompileSdkOpenHarmony);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: PluginInstaller_0004
 * @tc.name: test CreatePluginDir
 * @tc.desc: 1.Test CreatePluginDir the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0004, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    std::string hostBundleName;
    std::string pluginDir;
    auto ret = installer.CreatePluginDir(hostBundleName, pluginDir);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: PluginInstaller_0005
 * @tc.name: test CreatePluginDir
 * @tc.desc: 1.Test CreatePluginDir the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0005, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    std::string bundlePath;
    InnerBundleInfo newInfo;
    std::string pluginDir;
    auto ret = installer.ExtractPluginBundles(bundlePath, newInfo, pluginDir);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: PluginInstaller_0006
 * @tc.name: test RemovePluginDir
 * @tc.desc: 1.Test RemovePluginDir the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0006, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    InnerBundleInfo newInfo;
    auto ret = installer.RemovePluginDir(newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: PluginInstaller_0007
 * @tc.name: test SaveHspToInstallDir
 * @tc.desc: 1.Test SaveHspToInstallDir the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0007, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    std::string bundlePath;
    std::string pluginBundleDir;
    std::string moduleName;
    InnerBundleInfo newInfo;
    auto ret = installer.SaveHspToInstallDir(bundlePath, pluginBundleDir, moduleName, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: PluginInstaller_0008
 * @tc.name: test SaveHspToInstallDir
 * @tc.desc: 1.Test SaveHspToInstallDir the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0008, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    std::string bundlePath;
    std::string pluginBundleDir;
    std::string moduleName;
    InnerBundleInfo newInfo;
    installer.signatureFileDir_ = "data/";
    auto ret = installer.SaveHspToInstallDir(bundlePath, pluginBundleDir, moduleName, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: PluginInstaller_0009
 * @tc.name: test RemoveEmptyDirs
 * @tc.desc: 1.Test RemoveEmptyDirs the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0009, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    std::string pluginDir;
    installer.RemoveEmptyDirs(pluginDir);
    installer.RemoveDir(pluginDir);
    EXPECT_EQ(pluginDir.empty(), true);
}

/**
 * @tc.number: PluginInstaller_0011
 * @tc.name: test RemoveOldInstallDir
 * @tc.desc: 1.Test RemoveOldInstallDir the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0011, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    installer.isPluginExist_ = false;
    installer.RemoveOldInstallDir();
    EXPECT_EQ(installer.isPluginExist_, false);
}

/**
 * @tc.number: PluginInstaller_0012
 * @tc.name: test RemoveOldInstallDir
 * @tc.desc: 1.Test RemoveOldInstallDir the PluginInstaller
*/
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, PluginInstaller_0012, Function | MediumTest | Level1)
{
    PluginInstaller installer;
    installer.isPluginExist_ = true;
    installer.RemoveOldInstallDir();
    EXPECT_EQ(installer.isPluginExist_, true);
}

/**
 * @tc.number: BaseBundleInstaller_0010
 * @tc.name: test UninstallHspVersion
 * @tc.desc: 1.UninstallHspVersion
 */
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, BaseBundleInstaller_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string bundleName = "test.bundleName";

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer.dataMgr_ = dataMgr;
    dataMgr->installStates_[bundleName] = InstallState::INSTALL_SUCCESS;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = bundleName;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
    innerBundleInfo.innerBundleUserInfos_["test.bundleName_100"] = InnerBundleUserInfo();
    innerBundleInfo.uninstallState_ = false;
    innerBundleInfo.baseApplicationInfo_->removable = false;

    std::string uninstallDir = "test";
    int32_t versionCode = -1;
    auto ret = installer.UninstallHspVersion(uninstallDir, versionCode, innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_RMV_HSP_BY_VERSION_ERROR);

    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: BaseBundleInstaller_0011
 * @tc.name: test UninstallDebugAppSandbox
 * @tc.desc: 1.UninstallDebugAppSandbox
 */
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, BaseBundleInstaller_0011, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    HnpPackage hnpPackage;
    innerModuleInfo.hnpPackages.emplace_back(hnpPackage);

    InnerBundleInfo info;
    info.currentPackage_ = "entry";
    info.innerModuleInfos_["entry"] = innerModuleInfo;

    int32_t userId;
    std::string bundleName;
    ErrCode ret = installer.ProcessBundleUnInstallNative(info, userId, bundleName);
    EXPECT_EQ(ret, ERR_OK);
}
} // OHOS