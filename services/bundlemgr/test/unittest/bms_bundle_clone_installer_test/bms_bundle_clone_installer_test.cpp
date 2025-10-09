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

#define private public

#include <gtest/gtest.h>

#include "bundle_clone_installer.h"

#include "appexecfwk_errors.h"
#include "bundle_data_storage_rdb.h"
#include "bundle_installer.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "parameters.h"
#include "scope_guard.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace {
const std::string BUNDLE_NAME = "com.ohos.cloneinstall";
const std::string MODULE_NAME_TEST = "moduleName";
const std::int32_t installer = 1;
const std::int32_t userId_ = 9989;
const std::int32_t uid_ = 1;
constexpr int32_t  CLONE_NUM = 4;
}

namespace OHOS {
class BmsBundleCloneInstallerTest : public testing::Test {
public:
    BmsBundleCloneInstallerTest();
    ~BmsBundleCloneInstallerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    void SetInnerBundleInfo(const std::string &bundleName);
    BundlePackInfo CreateBundlePackInfo(const std::string &bundleName);
    void DeleteBundle(const std::string &bundleName);
    void SetBundleDataMgr();
    void UnsetBundleDataMgr();
    void SetUserIdToDataMgr(const std::int32_t userId);
    std::shared_ptr<AppExecFwk::BundleCloneInstaller>  bundleCloneInstall_ = nullptr;
    int64_t installerId_ = 1;
    int32_t appIdx_ = 0;
    int32_t appIdx2_ = 2;
    int32_t appIdxs_[CLONE_NUM] = {0};
};

BmsBundleCloneInstallerTest::BmsBundleCloneInstallerTest()
{}

BmsBundleCloneInstallerTest::~BmsBundleCloneInstallerTest()
{}

void BmsBundleCloneInstallerTest::SetUpTestCase()
{}

void BmsBundleCloneInstallerTest::TearDownTestCase()
{}

BundlePackInfo BmsBundleCloneInstallerTest::CreateBundlePackInfo(const std::string &bundleName)
{
    Packages packages;
    packages.name = bundleName;
    Summary summary;
    summary.app.bundleName = bundleName;
    PackageModule packageModule;
    packageModule.mainAbility = "testCloneInstall";
    packageModule.distro.moduleName = MODULE_NAME_TEST;
    summary.modules.push_back(packageModule);

    BundlePackInfo packInfo;
    packInfo.packages.push_back(packages);
    packInfo.summary = summary;
    packInfo.SetValid(true);
    return packInfo;
}

void BmsBundleCloneInstallerTest::SetInnerBundleInfo(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;

    ApplicationInfo application;
    application.name = bundleName;
    application.bundleName = bundleName;
    application.multiAppMode.multiAppModeType = MultiAppModeType::APP_CLONE;
    application.multiAppMode.maxCount = CLONE_NUM;

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = bundleName;
    userInfo.bundleUserInfo.userId = installer;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME_TEST;
    moduleInfo.name = MODULE_NAME_TEST;
    moduleInfo.modulePackage = MODULE_NAME_TEST;

    std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
    innerModuleInfoMap[MODULE_NAME_TEST] = moduleInfo;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(application);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    innerBundleInfo.SetBundlePackInfo(CreateBundlePackInfo(bundleName));
    innerBundleInfo.AddInnerModuleInfo(innerModuleInfoMap);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS);
}

void BmsBundleCloneInstallerTest::DeleteBundle(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);
}

void BmsBundleCloneInstallerTest::SetUp()
{
    bundleCloneInstall_ = std::make_shared<AppExecFwk::BundleCloneInstaller>();
}

void BmsBundleCloneInstallerTest::TearDown()
{}

void BmsBundleCloneInstallerTest::SetBundleDataMgr()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<AppExecFwk::BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
}

void BmsBundleCloneInstallerTest::UnsetBundleDataMgr()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
}

void BmsBundleCloneInstallerTest::SetUserIdToDataMgr(const std::int32_t userId)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(userId);
}
/**
 * @tc.number: BmsBundleCloneInstallerTest_001
 * @tc.name: BmsBundleCloneInstallerTest
 * @tc.desc: ProcessCloneBundleInstall() and ProcessCloneBundleUninstall()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_001, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleInstall("", userId_, appIdx_),
        ERR_APPEXECFWK_CLONE_INSTALL_PARAM_ERROR);
    SetBundleDataMgr();
    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleInstall(BUNDLE_NAME, userId_, appIdx_),
        ERR_APPEXECFWK_CLONE_INSTALL_APP_NOT_EXISTED);

    SetInnerBundleInfo(BUNDLE_NAME);
    ScopeGuard deleteGuard([this] { DeleteBundle(BUNDLE_NAME); });
    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleInstall(BUNDLE_NAME, -1, appIdx_),
        ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleInstall(BUNDLE_NAME, userId_, appIdx_),
        ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST);

    SetUserIdToDataMgr(userId_);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleInstall(BUNDLE_NAME, userId_, appIdx_),
        ERR_APPEXECFWK_CLONE_INSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID);

    int32_t appIndex = 0;
    SetUserIdToDataMgr(installer);
    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleInstall(BUNDLE_NAME, installer, appIndex),
        ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR);

    DestroyAppCloneParam param;
    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall("", userId_, appIdx_, true, param),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, 0, true, param),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, 6, true, param),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, installer, appIndex, true, param),
        ERR_APPEXECFWK_CLONE_UNINSTALL_APP_NOT_CLONED);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_002
 * @tc.name: BmsBundleCloneInstallerTest
 * @tc.desc: InstallCloneApp() and UninstallCloneApp() and UninstallAllCloneApps()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_002, TestSize.Level1)
{
    EXPECT_EQ(bundleCloneInstall_->InstallCloneApp("", userId_, appIdx_),
        ERR_APPEXECFWK_CLONE_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_003
 * @tc.name: BmsBundleCloneInstallerTest
 * @tc.desc: test UninstallCloneApp()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_003, TestSize.Level1)
{
    std::string bundleName = "bundleName";
    ASSERT_NE(bundleCloneInstall_, nullptr);
    DestroyAppCloneParam param;
    EXPECT_EQ(bundleCloneInstall_->UninstallCloneApp("", userId_, appIdx_, true, param),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME);
    EXPECT_EQ(bundleCloneInstall_->UninstallCloneApp(bundleName, userId_, appIdx_, true, param),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);
    EXPECT_EQ(bundleCloneInstall_->UninstallCloneApp(bundleName, userId_, appIdx2_, true, param),
        ERR_APPEXECFWK_CLONE_UNINSTALL_APP_NOT_EXISTED);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_004
 * @tc.name: CreateCloneDataDir
 * @tc.desc: test CreateCloneDataDir()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_004, TestSize.Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.bundleUserInfo.userId = 100;
    innerBundleUserInfos["_100"] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    ASSERT_NE(bundleCloneInstall_, nullptr);
    EXPECT_EQ(bundleCloneInstall_->CreateCloneDataDir(innerBundleInfo, userId_, uid_, appIdx_),
        ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_005
 * @tc.name: RemoveCloneDataDir
 * @tc.desc: test RemoveCloneDataDir()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_005, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    EXPECT_EQ(
        bundleCloneInstall_->RemoveCloneDataDir("", userId_, appIdx_, true),
        ERR_APPEXECFWK_CLONE_INSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_006
 * @tc.name: UninstallAllCloneApps
 * @tc.desc: test UninstallAllCloneApps()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_006, TestSize.Level1)
{
    std::string bundleName = "";
    ASSERT_NE(bundleCloneInstall_, nullptr);
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, true, false, userId_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME);
    bundleName = "bundleName006";
    int32_t userId = 101;
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, true, false, userId),
        ERR_APPEXECFWK_CLONE_UNINSTALL_USER_NOT_EXIST);
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, true, false, userId_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_APP_NOT_EXISTED);
    SetInnerBundleInfo(bundleName);
    ScopeGuard deleteGuard([this, bundleName] { DeleteBundle(bundleName); });
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, true, false, userId_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID);
    int32_t appIndex = 0;
    bundleCloneInstall_->InstallCloneApp(bundleName, installer, appIndex);
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, true, false, installer), ERR_OK);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_007
 * @tc.name: GetDataMgr
 * @tc.desc: test GetDataMgr()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_007, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    EXPECT_EQ(bundleCloneInstall_->GetDataMgr(), ERR_OK);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_008
 * @tc.name: ResetInstallProperties
 * @tc.desc: test ResetInstallProperties()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_008, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    bundleCloneInstall_->ResetInstallProperties();
    EXPECT_EQ(bundleCloneInstall_->uid_, 0);
    EXPECT_EQ(bundleCloneInstall_->accessTokenId_, 0);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_009
 * @tc.name: ProcessCloneBundleUninstall
 * @tc.desc: Test ProcessCloneBundleUninstall()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_009, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    bundleCloneInstall_->dataMgr_ = nullptr;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    DestroyAppCloneParam param;
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer, true, param);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = dataMgr;
    bundleCloneInstall_->GetDataMgr();
    EXPECT_EQ(ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR, res);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_010
 * @tc.name: ProcessCloneBundleUninstall
 * @tc.desc: Test ProcessCloneBundleUninstall()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_010, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    ASSERT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_->multiUserIdsSet_.clear();
    DestroyAppCloneParam param;
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer, true, param);
    EXPECT_EQ(ERR_APPEXECFWK_CLONE_UNINSTALL_USER_NOT_EXIST, res);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_011
 * @tc.name: ProcessCloneBundleUninstall
 * @tc.desc: Test ProcessCloneBundleUninstall()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_011, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    ASSERT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
    InnerBundleInfo info;
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->multiUserIdsSet_.insert(userId_);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.clear();
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_[BUNDLE_NAME] = info;
    DestroyAppCloneParam param;
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer, true, param);
    EXPECT_EQ(ERR_APPEXECFWK_CLONE_UNINSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID, res);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_012
 * @tc.name: ProcessCloneBundleUninstall
 * @tc.desc: Test ProcessCloneBundleUninstall()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_012, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    ASSERT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
    InnerBundleInfo info;
    InnerBundleUserInfo userInfo;
    std::string key = Constants::FILE_UNDERLINE + std::to_string(userId_);
    info.innerBundleUserInfos_.emplace(key, userInfo);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_[BUNDLE_NAME] = info;
    DestroyAppCloneParam param;
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer, true, param);
    EXPECT_EQ(ERR_APPEXECFWK_CLONE_UNINSTALL_APP_NOT_CLONED, res);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_013
 * @tc.name: ProcessCloneBundleUninstall
 * @tc.desc: Test ProcessCloneBundleUninstall()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_013, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    InnerBundleInfo info;
    InnerBundleUserInfo userInfo;
    InnerBundleCloneInfo cloneInfo;
    userInfo.cloneInfos.emplace(std::to_string(installer), cloneInfo);
    std::string key = Constants::FILE_UNDERLINE + std::to_string(userId_);
    info.innerBundleUserInfos_.emplace(key, userInfo);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_[BUNDLE_NAME] = info;
    auto ptr = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(ptr, nullptr);
    ptr->rdbDataManager_ = nullptr;
    auto dataStorage = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->dataStorage_;
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->dataStorage_ = ptr;
    DestroyAppCloneParam param;
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer, true, param);
    EXPECT_EQ(ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR, res);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->dataStorage_ = dataStorage;
}

/**
 * @tc.number: GetAssetAccessGroups_0100
 * @tc.name: test GetAssetAccessGroups
 * @tc.desc: test GetAssetAccessGroups of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, GetAssetAccessGroups_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "bundlename";
    std::string bundleName1 = "testBundleName1";
    std::string asset = "asset1";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.assetAccessGroups.push_back(asset);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_[bundleName] = innerBundleInfo;
    ASSERT_NE(bundleCloneInstall_, nullptr);
    EXPECT_EQ(bundleCloneInstall_->GetAssetAccessGroups(bundleName), "asset1");
    EXPECT_EQ(bundleCloneInstall_->GetAssetAccessGroups(bundleName1), "");
}

/**
 * @tc.number: GetDeveloperId_0100
 * @tc.name: test GetDeveloperId
 * @tc.desc: test GetDeveloperId of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, GetDeveloperId_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.developerId_ = "testDeveloperId";
    std::string bundleName1 = "testBundleName1";
    std::string bundleName = "testBundleName";
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_[bundleName] = innerBundleInfo;
    SetInnerBundleInfo(bundleName);
    ASSERT_NE(bundleCloneInstall_, nullptr);
    EXPECT_EQ(bundleCloneInstall_->GetDeveloperId(bundleName), "testDeveloperId");
    EXPECT_EQ(bundleCloneInstall_->GetDeveloperId(bundleName1), "");
}

/**
 * @tc.number: RemoveEl5Dir_0100
 * @tc.name: test RemoveEl5Dir
 * @tc.desc: test RemoveEl5Dir of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, RemoveEl5Dir_0100, Function | SmallTest | Level1)
{
    InnerBundleUserInfo userInfo;
    int32_t uid = 1;
    int32_t appIndex = 1;
    int32_t userId = 1;
    bundleCloneInstall_->RemoveEl5Dir(userInfo, uid, userId, appIndex);
    EXPECT_EQ(userInfo.cloneInfos.find(std::to_string(appIndex)), userInfo.cloneInfos.end());

    InnerBundleCloneInfo InnerBundleCloneInfotest;
    appIndex = 100;
    std::string key = std::to_string(appIndex);
    userInfo.cloneInfos.insert({key, InnerBundleCloneInfotest});
    bundleCloneInstall_->RemoveEl5Dir(userInfo, uid, userId, appIndex);
    EXPECT_NE(userInfo.cloneInfos.find(std::to_string(appIndex)), userInfo.cloneInfos.end());

    userInfo.cloneInfos[key].keyId = "test_key";
    bundleCloneInstall_->RemoveEl5Dir(userInfo, uid, userId, appIndex);
    auto it = userInfo.cloneInfos.find(std::to_string(appIndex));
    EXPECT_FALSE(it->second.keyId.empty());
    userInfo.cloneInfos.clear();
}

/**
 * @tc.number: CreateEl5Dir_0100
 * @tc.name: test CreateEl5Dir
 * @tc.desc: test CreateEl5Dir of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, CreateEl5Dir_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    int32_t uid = 0;
    int32_t userId = 0;
    int32_t appIndex = 0;
    bundleCloneInstall_->CreateEl5Dir(innerBundleInfo, uid, userId, appIndex);
    EXPECT_EQ(innerBundleInfo.GetBundleName(), "");

    RequestPermission requestPermission;
    requestPermission.name = ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "testname";
    innerModuleInfo.requestPermissions.emplace_back(requestPermission);
    innerBundleInfo.innerModuleInfos_.try_emplace("test", innerModuleInfo);
    bundleCloneInstall_->CreateEl5Dir(innerBundleInfo, uid, userId, appIndex);
    EXPECT_EQ(bundleCloneInstall_->GetDataMgr(), ERR_OK);
}

/**
 * @tc.number: UninstallDebugAppSandbox_0100
 * @tc.name: test UninstallDebugAppSandbox
 * @tc.desc: test UninstallDebugAppSandbox of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, UninstallDebugAppSandbox_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "testBundleName";
    int32_t uid = 0;
    int32_t appIndex = 0;
    InnerBundleInfo innerBundleInfo;
    OHOS::AppExecFwk::ApplicationInfo ApplicationInfo_;
    ApplicationInfo_.appProvisionType = OHOS::AppExecFwk::Constants::APP_PROVISION_TYPE_DEBUG;
    innerBundleInfo.SetBaseApplicationInfo(ApplicationInfo_);
    std::string key = "debug";
    std::string value = "y";
    OHOS::system::SetParameter(key, value);
    bundleCloneInstall_->UninstallDebugAppSandbox(bundleName, uid, appIndex, innerBundleInfo);
    EXPECT_EQ(innerBundleInfo.GetBaseApplicationInfo().appProvisionType,
        OHOS::AppExecFwk::Constants::APP_PROVISION_TYPE_DEBUG);
}

/**
 * @tc.number: RecoverHapToken_0100
 * @tc.name: test RecoverHapToken
 * @tc.desc: test RecoverHapToken of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, RecoverHapToken_0100, Function | SmallTest | Level1)
{
    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    InnerBundleInfo info;
    bundleCloneInstall_->dataMgr_ = nullptr;
    auto res = bundleCloneInstall_->RecoverHapToken(userId_, 1, accessTokenIdEx, info, "");
    EXPECT_FALSE(res);
    bundleCloneInstall_->dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    EXPECT_NE(bundleCloneInstall_->dataMgr_, nullptr);
}

/**
 * @tc.number: RecoverHapToken_0200
 * @tc.name: test RecoverHapToken
 * @tc.desc: test RecoverHapToken of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, RecoverHapToken_0200, Function | SmallTest | Level1)
{
    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    InnerBundleInfo info;
    auto res = bundleCloneInstall_->RecoverHapToken(userId_, 1, accessTokenIdEx, info, "");
    EXPECT_FALSE(res);
}

/**
 * @tc.number: RecoverHapToken_0300
 * @tc.name: test RecoverHapToken
 * @tc.desc: test RecoverHapToken of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, RecoverHapToken_0300, Function | SmallTest | Level1)
{
    UninstallBundleInfo uninstallBundleInfo;
    UninstallDataUserInfo uninstallDataUserInfo;
    std::string key = std::to_string(userId_) + "_" + std::to_string(2);
    uninstallBundleInfo.userInfos[key] = uninstallDataUserInfo;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    EXPECT_TRUE(dataMgr->UpdateUninstallBundleInfo(BUNDLE_NAME, uninstallBundleInfo));

    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    InnerBundleInfo info;
    auto res = bundleCloneInstall_->RecoverHapToken(userId_, 1, accessTokenIdEx, info, "");
    EXPECT_FALSE(res);
    EXPECT_TRUE(dataMgr->DeleteUninstallCloneBundleInfo(BUNDLE_NAME, userId_, 2));
}

/**
 * @tc.number: RecoverHapToken_0400
 * @tc.name: test RecoverHapToken
 * @tc.desc: test RecoverHapToken of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, RecoverHapToken_0400, Function | SmallTest | Level1)
{
    UninstallBundleInfo uninstallBundleInfo;
    UninstallDataUserInfo uninstallDataUserInfo;
    std::string key = std::to_string(userId_) + "_" + std::to_string(1);
    uninstallBundleInfo.userInfos[key] = uninstallDataUserInfo;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    EXPECT_TRUE(dataMgr->UpdateUninstallBundleInfo(BUNDLE_NAME, uninstallBundleInfo));

    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    InnerBundleInfo info;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    info.SetBaseApplicationInfo(applicationInfo);
    auto res = bundleCloneInstall_->RecoverHapToken(userId_, 1, accessTokenIdEx, info, "");
    EXPECT_TRUE(res);
    EXPECT_TRUE(dataMgr->DeleteUninstallCloneBundleInfo(BUNDLE_NAME, userId_, 1));
}

/**
 * @tc.number: DeleteUninstallCloneBundleInfo_0100
 * @tc.name: test DeleteUninstallCloneBundleInfo
 * @tc.desc: test DeleteUninstallCloneBundleInfo of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, DeleteUninstallCloneBundleInfo_0100, Function | SmallTest | Level1)
{
    bundleCloneInstall_->dataMgr_ = nullptr;
    auto res = bundleCloneInstall_->DeleteUninstallCloneBundleInfo(BUNDLE_NAME, userId_, 1);
    EXPECT_FALSE(res);
    bundleCloneInstall_->dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    EXPECT_NE(bundleCloneInstall_->dataMgr_, nullptr);
}

/**
 * @tc.number: DeleteUninstallCloneBundleInfo_0200
 * @tc.name: test DeleteUninstallCloneBundleInfo
 * @tc.desc: test DeleteUninstallCloneBundleInfo of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, DeleteUninstallCloneBundleInfo_0200, Function | SmallTest | Level1)
{
    auto res = bundleCloneInstall_->DeleteUninstallCloneBundleInfo(BUNDLE_NAME, userId_, 1);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: DeleteUninstallCloneBundleInfo_0300
 * @tc.name: test DeleteUninstallCloneBundleInfo
 * @tc.desc: test DeleteUninstallCloneBundleInfo of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, DeleteUninstallCloneBundleInfo_0300, Function | SmallTest | Level1)
{
    bundleCloneInstall_->existBeforeKeepDataApp_ = true;
    auto res = bundleCloneInstall_->DeleteUninstallCloneBundleInfo(BUNDLE_NAME, userId_, 1);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: DeleteUninstallCloneBundleInfo_0400
 * @tc.name: test DeleteUninstallCloneBundleInfo
 * @tc.desc: test DeleteUninstallCloneBundleInfo of BundleCloneInstaller
*/
HWTEST_F(BmsBundleCloneInstallerTest, DeleteUninstallCloneBundleInfo_0400, Function | SmallTest | Level1)
{
    UninstallBundleInfo uninstallBundleInfo;
    UninstallDataUserInfo uninstallDataUserInfo;
    std::string key = std::to_string(userId_) + "_" + std::to_string(1);
    uninstallBundleInfo.userInfos[key] = uninstallDataUserInfo;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    EXPECT_TRUE(dataMgr->UpdateUninstallBundleInfo(BUNDLE_NAME, uninstallBundleInfo));

    bundleCloneInstall_->existBeforeKeepDataApp_ = true;
    auto res = bundleCloneInstall_->DeleteUninstallCloneBundleInfo(BUNDLE_NAME, userId_, 1);
    EXPECT_TRUE(res);
}
}
