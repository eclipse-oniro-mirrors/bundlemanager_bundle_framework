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
const std::string BUNDLE_NAME = "com.ohos.cloneinstallpermission";
const std::string MODULE_NAME_TEST = "moduleName";
const std::int32_t installer = 1;
const std::int32_t userId_ = 9989;
const std::int32_t uid_ = 1;
constexpr int32_t  CLONE_NUM = 4;
}

namespace OHOS {
class BmsBundleCloneInstallerPermissionTest : public testing::Test {
public:
    BmsBundleCloneInstallerPermissionTest();
    ~BmsBundleCloneInstallerPermissionTest();
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

BmsBundleCloneInstallerPermissionTest::BmsBundleCloneInstallerPermissionTest()
{}

BmsBundleCloneInstallerPermissionTest::~BmsBundleCloneInstallerPermissionTest()
{}

void BmsBundleCloneInstallerPermissionTest::SetUpTestCase()
{}

void BmsBundleCloneInstallerPermissionTest::TearDownTestCase()
{}

BundlePackInfo BmsBundleCloneInstallerPermissionTest::CreateBundlePackInfo(const std::string &bundleName)
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

void BmsBundleCloneInstallerPermissionTest::SetInnerBundleInfo(const std::string &bundleName)
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

void BmsBundleCloneInstallerPermissionTest::DeleteBundle(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);
}

void BmsBundleCloneInstallerPermissionTest::SetUp()
{
    bundleCloneInstall_ = std::make_shared<AppExecFwk::BundleCloneInstaller>();
}

void BmsBundleCloneInstallerPermissionTest::TearDown()
{}

void BmsBundleCloneInstallerPermissionTest::SetBundleDataMgr()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<AppExecFwk::BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
}

void BmsBundleCloneInstallerPermissionTest::UnsetBundleDataMgr()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
}

void BmsBundleCloneInstallerPermissionTest::SetUserIdToDataMgr(const std::int32_t userId)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(userId);
}
/**
 * @tc.number: ProcessCloneBundleInstall_0100
 * @tc.name: BmsBundleCloneInstallerPermissionTest
 * @tc.desc: ProcessCloneBundleInstall()
 */
HWTEST_F(BmsBundleCloneInstallerPermissionTest, ProcessCloneBundleInstall_0100, TestSize.Level1)
{
    ASSERT_NE(bundleCloneInstall_, nullptr);
    SetBundleDataMgr();

    SetInnerBundleInfo(BUNDLE_NAME);
    ScopeGuard deleteGuard([this] { DeleteBundle(BUNDLE_NAME); });

    int32_t appIndex = 0;
    SetUserIdToDataMgr(installer);

    EXPECT_EQ(bundleCloneInstall_->ProcessCloneBundleInstall(BUNDLE_NAME, installer, appIdx_),
        ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
}
}  // namespace OHOS