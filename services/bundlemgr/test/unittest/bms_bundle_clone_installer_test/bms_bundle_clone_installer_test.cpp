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

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall("", userId_, appIdx_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, 0),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, 6),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, installer, appIndex),
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
    EXPECT_EQ(bundleCloneInstall_->UninstallCloneApp("", userId_, appIdx_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME);
    EXPECT_EQ(bundleCloneInstall_->UninstallCloneApp(bundleName, userId_, appIdx_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);
    EXPECT_EQ(bundleCloneInstall_->UninstallCloneApp(bundleName, userId_, appIdx2_),
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
        bundleCloneInstall_->RemoveCloneDataDir("", userId_, appIdx_), ERR_APPEXECFWK_CLONE_INSTALL_INTERNAL_ERROR);
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
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, userId_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME);
    bundleName = "bundleName006";
    int32_t userId = 101;
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, userId),
        ERR_APPEXECFWK_CLONE_UNINSTALL_USER_NOT_EXIST);
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, userId_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_APP_NOT_EXISTED);
    SetInnerBundleInfo(bundleName);
    ScopeGuard deleteGuard([this, bundleName] { DeleteBundle(bundleName); });
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, userId_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID);
    int32_t appIndex = 0;
    bundleCloneInstall_->InstallCloneApp(bundleName, installer, appIndex);
    EXPECT_EQ(bundleCloneInstall_->UninstallAllCloneApps(bundleName, installer), ERR_OK);
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
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer);
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
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer);
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
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer);
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
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer);
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
    auto res = bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, installer);
    EXPECT_EQ(ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR, res);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->dataStorage_ = dataStorage;
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_014
 * @tc.name: AddKeyOperation
 * @tc.desc: Test AddKeyOperation()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_014, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    bundleCloneInstall_->dataMgr_ = nullptr;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    auto res = bundleCloneInstall_->AddKeyOperation(BUNDLE_NAME, installer, userId_, uid_);
    EXPECT_FALSE(res);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = dataMgr;
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_015
 * @tc.name: AddKeyOperation
 * @tc.desc: Test AddKeyOperation()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_015, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    std::string bundleName;
    auto res = bundleCloneInstall_->AddKeyOperation(bundleName, installer, userId_, uid_);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_016
 * @tc.name: AddKeyOperation
 * @tc.desc: Test AddKeyOperation()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_016, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    auto res = bundleCloneInstall_->AddKeyOperation(BUNDLE_NAME, installer, userId_, uid_);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: BmsBundleCloneInstallerTest_017
 * @tc.name: AddKeyOperation
 * @tc.desc: Test AddKeyOperation()
 */
HWTEST_F(BmsBundleCloneInstallerTest, BmsBundleCloneInstallerTest_017, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->applicationReservedFlag = static_cast<uint32_t>(
        ApplicationReservedFlag::ENCRYPTED_APPLICATION);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_[BUNDLE_NAME] = info;
    bundleCloneInstall_->GetDataMgr();
    auto res = bundleCloneInstall_->AddKeyOperation(BUNDLE_NAME, installer, userId_, uid_);
#ifdef USE_BUNDLE_EXTENSION
    EXPECT_FALSE(res);
#else
    EXPECT_TRUE(res);
#endif
}
}
