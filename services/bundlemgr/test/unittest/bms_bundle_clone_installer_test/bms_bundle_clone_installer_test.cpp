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


    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall("", userId_, appIdx_),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, 0),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleUninstall(BUNDLE_NAME, userId_, 6),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);
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
}