/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "appexecfwk_errors.h"
#include "bundle_overlay_data_manager.h"
#include "bundle_overlay_install_checker.h"
#include "bundle_overlay_manager.h"
#include "bundle_mgr_service.h"

#include <map>

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string TEST_MODULE_NAME = "testModuleName";
const std::string TEST_MODULE_NAME_ONE = "TEST_MODULE_NAME";
const std::string TEST_MODULE_NAME_SECOND = "testModuleNameSecond";
const std::string TARGET_MODULE_NAME = "targetModuleName";
const std::string OTHER_TARGET_MODULE_NAME = "targetModuleNameTest";
const std::string TARGET_BUNDLE_NAME = "targetBundleName";
const std::string TEST_BUNDLE_NAME = "testBundleName";
const std::string TEST_BUNDLE_NAME2 = "testBundleName2";
const std::string TEST_PATH_FIRST = "testPath1";
const std::string TEST_PATH_SECOND = "testPath2";
const std::string TEST_PACK_AGE = "modulePackage";
const std::string NO_EXIST = "noExist";
const std::string BUNDLE_NAME = "oho.test.bundleName";
const std::string SHARED_HAP_TYPE = "shared";
const std::string FEATURE_HAP_TYPE = "feature";
const std::string SHARED_TYPE = "shared";
const int32_t INVALID_TARGET_PRIORITY_FIRST = 0;
const int32_t INVALID_TARGET_PRIORITY_SECOND = 101;
const int32_t DEFAULT_TARGET_PRIORITY_SECOND = 1;
const int32_t TEST_VERSION_CODE = 1000000;
const int32_t LOWER_TEST_VERSION_CODE = 999999;
const int32_t HIGHER_TEST_VERSION_CODE = 1000001;
const int32_t USERID = 100;
const int32_t FILE_UNDERLINE_NUM = 2;
const int32_t NOT_EXIST_USERID = -5;
const int32_t FOUR = 4;
const int32_t DEFAULT_OVERLAY_BUNDLE_INFO = 0;
const int32_t WAIT_TIME = 5; // init mocked bms
constexpr int32_t OVERLAY_MAXIMUM_PRIORITY = 100;
} // namespace

class BmsBundleOverlayCheckerTest : public testing::Test {
public:
    BmsBundleOverlayCheckerTest();
    ~BmsBundleOverlayCheckerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void AddInnerBundleInfo(InnerBundleInfo innerBundleInfo, InnerBundleInfo oldInfo);
    void UninstallBundleInfo();
    void BuildInternalOverlayConnection(const std::string &moduleName, InnerBundleInfo &oldInfo, int32_t userId);
    void RemoveOverlayBundleInfo(const std::string &targetBundleName, InnerBundleInfo &targetInnerBundleInfo);
    void AddOverlayModuleStates(const InnerBundleInfo &innerBundleInfo, InnerBundleUserInfo &userInfo);
    void ClearDataMgr();
    void ResetDataMgr();
    void AddInnerBundleInfoNoModuleInfo();

    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    const std::shared_ptr<BundleOverlayInstallChecker> GetBundleOverlayChecker() const;

private:
    std::shared_ptr<BundleOverlayInstallChecker> overlayChecker_ = std::make_shared<BundleOverlayInstallChecker>();
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleOverlayCheckerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleOverlayCheckerTest::BmsBundleOverlayCheckerTest()
{}

BmsBundleOverlayCheckerTest::~BmsBundleOverlayCheckerTest()
{}

void BmsBundleOverlayCheckerTest::SetUpTestCase()
{}

void BmsBundleOverlayCheckerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleOverlayCheckerTest::SetUp()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleOverlayCheckerTest::BuildInternalOverlayConnection(
    const std::string &moduleName, InnerBundleInfo &oldInfo, int32_t userId)
{
    OverlayDataMgr overlayDataMgr;
    return overlayDataMgr.BuildInternalOverlayConnection(TEST_MODULE_NAME, oldInfo, USERID);
}

void BmsBundleOverlayCheckerTest::RemoveOverlayBundleInfo(
    const std::string &targetBundleName, InnerBundleInfo &targetInnerBundleInfo)
{
    OverlayDataMgr overlayDataMgr;
    return overlayDataMgr.RemoveOverlayBundleInfo(TEST_MODULE_NAME, targetInnerBundleInfo);
}

void BmsBundleOverlayCheckerTest::AddOverlayModuleStates(
    const InnerBundleInfo &innerBundleInfo, InnerBundleUserInfo &userInfo)
{
    OverlayDataMgr overlayDataMgr;
    return overlayDataMgr.AddOverlayModuleStates(innerBundleInfo, userInfo);
}

void BmsBundleOverlayCheckerTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleOverlayCheckerTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleOverlayCheckerTest::TearDown()
{}

void BmsBundleOverlayCheckerTest::AddInnerBundleInfo(InnerBundleInfo innerBundleInfo, InnerBundleInfo oldInfo)
{
    // construct innerBundleInfo
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.targetBundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    // construct target module
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    InnerModuleInfo targetModuleInfo;
    targetModuleInfo.name = TARGET_MODULE_NAME;
    targetModuleInfo.targetModuleName = OTHER_TARGET_MODULE_NAME;
    targetModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    ApplicationInfo targetApplicationInfo;
    targetApplicationInfo.bundleName = TEST_BUNDLE_NAME;

    oldInfo.InsertInnerModuleInfo(TARGET_MODULE_NAME, targetModuleInfo);
    oldInfo.SetBaseApplicationInfo(targetApplicationInfo);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, oldInfo);
}

void BmsBundleOverlayCheckerTest::AddInnerBundleInfoNoModuleInfo()
{
    // construct innerBundleInfo
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.targetBundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    // construct target module
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    InnerBundleInfo oldInfo;
    ApplicationInfo targetApplicationInfo;
    targetApplicationInfo.bundleName = TEST_BUNDLE_NAME;
    oldInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;

    oldInfo.SetBaseApplicationInfo(targetApplicationInfo);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, oldInfo);
}

void BmsBundleOverlayCheckerTest::UninstallBundleInfo()
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

const std::shared_ptr<BundleDataMgr> BmsBundleOverlayCheckerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

const std::shared_ptr<BundleOverlayInstallChecker> BmsBundleOverlayCheckerTest::GetBundleOverlayChecker() const
{
    return overlayChecker_;
}

/**
 * @tc.number: OverlayCheckerTest_0100
 * @tc.name: test CheckInternalBundle interface in BundleOverlayInstallChecker.
 * @tc.desc: 1.the internal overlay hap is entry type.
 *           2.check failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayCheckerTest_0100, Function | SmallTest | Level0)
{
    // construct innerBundleInfo
    InnerModuleInfo innerModuleInfo;
    Distro distro;
    distro.moduleType = FEATURE_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerModuleInfo.name = TEST_MODULE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    auto overlayChecker = GetBundleOverlayChecker();
    EXPECT_NE(overlayChecker, nullptr);
    auto res = overlayChecker->CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_HAP_TYPE);
}

/**
 * @tc.number: OverlayCheckerTest_0200
 * @tc.name: test CheckInternalBundle interface in BundleOverlayInstallChecker.
 * @tc.desc: 1.the internal overlay bundle is service.
 *           2.check failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayCheckerTest_0200, Function | SmallTest | Level0)
{
    // construct innerBundleInfo
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetEntryInstallationFree(true);
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    auto overlayChecker = GetBundleOverlayChecker();
    EXPECT_NE(overlayChecker, nullptr);
    auto res = overlayChecker->CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_BUNDLE_TYPE);
}

/**
 * @tc.number: OverlayCheckerTest_0400
 * @tc.name: test CheckInternalBundle interface in BundleOverlayInstallChecker.
 * @tc.desc: 1.target priority of internal overlay hap is invalid.
 *           2.check failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayCheckerTest_0400, Function | SmallTest | Level0)
{
    // construct innerBundleInfo
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerModuleInfo.targetPriority = INVALID_TARGET_PRIORITY_FIRST;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    auto overlayChecker = GetBundleOverlayChecker();
    EXPECT_NE(overlayChecker, nullptr);
    auto res = overlayChecker->CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY);
}

/**
 * @tc.number: OverlayCheckerTest_0500
 * @tc.name: test CheckInternalBundle interface in BundleOverlayInstallChecker.
 * @tc.desc: 1.target priority of internal overlay hap is invalid.
 *           2.check failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayCheckerTest_0500, Function | SmallTest | Level0)
{
    // construct innerBundleInfo
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerModuleInfo.targetPriority = INVALID_TARGET_PRIORITY_SECOND;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    auto overlayChecker = GetBundleOverlayChecker();
    EXPECT_NE(overlayChecker, nullptr);
    auto res = overlayChecker->CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY);
}

/**
 * @tc.number: OverlayCheckerTest_0600
 * @tc.name: test CheckInternalBundle interface in BundleOverlayInstallChecker.
 * @tc.desc: 1.target module name of the internal overlay is same as the module name.
 *           2.check failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayCheckerTest_0600, Function | SmallTest | Level0)
{
    // construct innerBundleInfo
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.targetModuleName = TEST_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    auto overlayChecker = GetBundleOverlayChecker();
    EXPECT_NE(overlayChecker, nullptr);
    auto res = overlayChecker->CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_MODULE_NAME);
}

/**
 * @tc.number: OverlayCheckerTest_0700
 * @tc.name: test CheckInternalBundle interface in BundleOverlayInstallChecker.
 * @tc.desc: 1.target module is overlay module.
 *           2.check failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayCheckerTest_0700, Function | SmallTest | Level0)
{
    // construct innerBundleInfo
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    // construct target module
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    InnerBundleInfo oldInfo;
    InnerModuleInfo targetModuleInfo;
    targetModuleInfo.name = TARGET_MODULE_NAME;
    targetModuleInfo.targetModuleName = OTHER_TARGET_MODULE_NAME;
    targetModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    Distro targetDistro;
    targetDistro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = targetDistro;
    ApplicationInfo targetApplicationInfo;
    targetApplicationInfo.bundleName = TEST_BUNDLE_NAME;

    oldInfo.InsertInnerModuleInfo(TARGET_MODULE_NAME, targetModuleInfo);
    oldInfo.SetBaseApplicationInfo(targetApplicationInfo);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, oldInfo);
    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    auto overlayChecker = GetBundleOverlayChecker();
    EXPECT_NE(overlayChecker, nullptr);
    auto res = overlayChecker->CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_IS_OVERLAY_MODULE);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_START);
    bool ret = dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: OverlayCheckerTest_0800
 * @tc.name: test CheckInternalBundle interface in BundleOverlayInstallChecker.
 * @tc.desc: 1.install overlay hap and non-overlay hap simultaneously.
 *           2.check successfully.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayCheckerTest_0800, Function | SmallTest | Level0)
{
    // construct overlay innerBundleInfo
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);

    // construct non-overlay innerBundleInfo
    InnerBundleInfo nonOverlayBundleInfo;
    InnerModuleInfo nonInnerModuleInfo;
    nonInnerModuleInfo.name = TEST_MODULE_NAME_SECOND;
    nonOverlayBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME_SECOND);
    nonOverlayBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME_SECOND, nonInnerModuleInfo);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.emplace(TEST_PATH_FIRST, innerBundleInfo);
    newInfos.emplace(TEST_PATH_SECOND, nonOverlayBundleInfo);

    auto overlayChecker = GetBundleOverlayChecker();
    EXPECT_NE(overlayChecker, nullptr);
    auto res = overlayChecker->CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayCheckerTest_0900
 * @tc.name: test CheckInternalBundle interface in BundleOverlayInstallChecker.
 * @tc.desc: 1.install internal overlay hap.
 *           2.the version code of overlay hap is larger than non-overlay module.
 *           3.check failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayCheckerTest_0900, Function | SmallTest | Level0)
{
    // construct overlay innerBundleInfo
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = HIGHER_TEST_VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    // construct old innerBundleInfo
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    InnerBundleInfo oldInfo;
    InnerModuleInfo oldInnerModuleInfo;
    oldInnerModuleInfo.name = TEST_MODULE_NAME_SECOND;
    oldInfo.InsertInnerModuleInfo(TEST_MODULE_NAME_SECOND, oldInnerModuleInfo);
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = TEST_VERSION_CODE;
    oldInfo.SetBaseBundleInfo(oldBundleInfo);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, oldInfo);

    auto overlayChecker = GetBundleOverlayChecker();
    EXPECT_NE(overlayChecker, nullptr);
    auto res = overlayChecker->CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INCONSISTENT_VERSION_CODE);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_START);
    bool ret = dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: OverlayCheckerTest_1000
 * @tc.name: test CheckInternalBundle interface in BundleOverlayInstallChecker.
 * @tc.desc: 1.install internal overlay hap.
 *           2.the version code of overlay hap is lower than non-overlay module.
 *           3.check failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayCheckerTest_1000, Function | SmallTest | Level0)
{
    // construct overlay innerBundleInfo
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = LOWER_TEST_VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    // construct old innerBundleInfo
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    InnerBundleInfo oldInfo;
    InnerModuleInfo oldInnerModuleInfo;
    oldInnerModuleInfo.name = TEST_MODULE_NAME_SECOND;
    oldInfo.InsertInnerModuleInfo(TEST_MODULE_NAME_SECOND, oldInnerModuleInfo);
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = TEST_VERSION_CODE;
    oldInfo.SetBaseBundleInfo(oldBundleInfo);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, oldInfo);

    auto overlayChecker = GetBundleOverlayChecker();
    EXPECT_NE(overlayChecker, nullptr);
    auto res = overlayChecker->CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INCONSISTENT_VERSION_CODE);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_START);
    bool ret = dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BundleOverlayManagerTest_0100
 * @tc.name: check param is empty
 * @tc.desc: 1.Test BundleOverlayManager
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, BundleOverlayManagerTest_0100, Function | SmallTest | Level0)
{
    BundleOverlayManager manager;
    std::string bundleName = "";
    bool ret = manager.IsExistedNonOverlayHap(bundleName);
    EXPECT_EQ(ret, false);
    InnerBundleInfo innerBundleInfo;
    ret = manager.GetInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret, false);

    int32_t userId = Constants::INVALID_USERID;
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto code = manager.GetAllOverlayModuleInfo(bundleName, overlayModuleInfos, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
    code = manager.GetAllOverlayModuleInfo("com.ohos.test", overlayModuleInfos, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    std::string moduleName = "";
    OverlayModuleInfo overlayModuleInfo;
    code = manager.GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
    code = manager.GetOverlayModuleInfo("com.ohos.test", moduleName, overlayModuleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
    code = manager.GetOverlayModuleInfo("com.ohos.test", "entry", overlayModuleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    std::string targetBundleName = "";
    std::vector<OverlayBundleInfo> overlayBundleInfo;
    code = manager.GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
    code = manager.GetOverlayBundleInfoForTarget("target", overlayBundleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    code = manager.GetOverlayModuleInfoForTarget(targetBundleName, "", overlayModuleInfos, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
    code = manager.GetOverlayModuleInfoForTarget("target", "", overlayModuleInfos, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    userId = Constants::DEFAULT_USERID;
    code = manager.GetAllOverlayModuleInfo("com.ohos.test", overlayModuleInfos, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
    code = manager.GetOverlayModuleInfo("com.ohos.test", "entry", overlayModuleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
}

/**
 * @tc.number: CheckInternalBundle_0100
 * @tc.name: check hap type failed
 * @tc.desc: 1.Test CheckInternalBundle
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, CheckInternalBundle_0100, Function | SmallTest | Level0)
{
    BundleOverlayInstallChecker checker;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    auto code = checker.CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_HAP_TYPE);
    innerModuleInfo.isEntry = false;
    code = checker.CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_HAP_TYPE);

    innerBundleInfo.SetEntryInstallationFree(true);
    code = checker.CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_HAP_TYPE);
}

/**
 * @tc.number: CheckInternalBundle_0200
 * @tc.name: check module target priority range
 * @tc.desc: 1.Test CheckInternalBundle
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, CheckInternalBundle_0200, Function | SmallTest | Level0)
{
    BundleOverlayInstallChecker checker;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerModuleInfo.targetPriority = ServiceConstants::OVERLAY_MINIMUM_PRIORITY - 1;
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    auto code = checker.CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY);
}

/**
 * @tc.number: CheckInternalBundle_0300
 * @tc.name: check module target priority range
 * @tc.desc: 1.Test CheckInternalBundle
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, CheckInternalBundle_0300, Function | SmallTest | Level0)
{
    BundleOverlayInstallChecker checker;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerModuleInfo.targetPriority = ServiceConstants::OVERLAY_MINIMUM_PRIORITY + 1;
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    innerModuleInfo.targetModuleName = TEST_MODULE_NAME;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);

    auto code = checker.CheckInternalBundle(newInfos, innerBundleInfo);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_MODULE_NAME);
}

/**
 * @tc.number: CheckExternalBundle_0100
 * @tc.name: check bundle priority
 * @tc.desc: 1.Test CheckExternalBundle
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, CheckExternalBundle_0100, Function | SmallTest | Level0)
{
    BundleOverlayInstallChecker checker;
    InnerBundleInfo innerBundleInfo;
    int32_t userId = Constants::INVALID_USERID;
    BundleInfo bundleInfo;
    bundleInfo.entryInstallationFree = true;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    auto code = checker.CheckExternalBundle(innerBundleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_BUNDLE_TYPE);

    bundleInfo.entryInstallationFree = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    ApplicationInfo applicationInfo;
    applicationInfo.targetPriority = ServiceConstants::OVERLAY_MINIMUM_PRIORITY - 1;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo innerModuleInfo;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    code = checker.CheckExternalBundle(innerBundleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY);

    applicationInfo.targetPriority = OVERLAY_MAXIMUM_PRIORITY + 1;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    code = checker.CheckExternalBundle(innerBundleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY);
}

/**
 * @tc.number: CheckExternalBundle_0200
 * @tc.name: check bundle priority
 * @tc.desc: 1.Test CheckExternalBundle
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, CheckExternalBundle_0200, Function | SmallTest | Level0)
{
    BundleOverlayInstallChecker checker;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    int32_t userId = Constants::INVALID_USERID;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.targetBundleName = TEST_BUNDLE_NAME;
    applicationInfo.targetPriority = ServiceConstants::OVERLAY_MINIMUM_PRIORITY + 1;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.targetPriority = ServiceConstants::OVERLAY_MINIMUM_PRIORITY + 1;
    Distro distro;
    distro.moduleType = SHARED_HAP_TYPE;
    innerModuleInfo.distro = distro;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    auto code = checker.CheckExternalBundle(innerBundleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_BUNDLE_NAME_SAME_WITH_TARGET_BUNDLE_NAME);
    applicationInfo.bundleName = "";
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    code = checker.CheckExternalBundle(innerBundleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_NO_SYSTEM_APPLICATION_FOR_EXTERNAL_OVERLAY);

    innerBundleInfo.SetIsPreInstallApp(true);
    code = checker.CheckExternalBundle(innerBundleInfo, userId);
    EXPECT_EQ(code, ERR_OK);

    innerBundleInfo.SetCurrentModulePackage(SHARED_TYPE);
    code = checker.CheckExternalBundle(innerBundleInfo, userId);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_HAP_TYPE);
}

/**
 * @tc.number: OverlayDataMgr_0100
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of UpdateOverlayInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_0100, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetInnerBundleInfo;

    newInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    ErrCode res = overlayDataMgr.UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    newInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    res = overlayDataMgr.UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    EXPECT_EQ(res, ERR_OK);
    newInfo.SetOverlayType(OverlayType::NON_OVERLAY_TYPE);
    res = overlayDataMgr.UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    EXPECT_EQ(res, ERR_OK);

    newInfo.SetOverlayType(FOUR);
    res = overlayDataMgr.UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_0200
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of IsExistedNonOverlayHap.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_0200, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    bool res = overlayDataMgr.IsExistedNonOverlayHap("");
    EXPECT_EQ(res, false);
    res = overlayDataMgr.IsExistedNonOverlayHap("wrong");
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: OverlayDataMgr_0300
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of UpdateInternalOverlayInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_0300, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    ErrCode res = overlayDataMgr.UpdateInternalOverlayInfo(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    res = overlayDataMgr.UpdateInternalOverlayInfo(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_0400
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of UpdateExternalOverlayInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_0400, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetInnerBundleInfo;

    ErrCode res = overlayDataMgr.UpdateExternalOverlayInfo(innerBundleInfo, oldInfo, targetInnerBundleInfo);
    EXPECT_EQ(res, ERR_OK);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo targetApplicationInfo;
    targetApplicationInfo.bundleName = TEST_BUNDLE_NAME;

    oldInfo.SetBaseApplicationInfo(targetApplicationInfo);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, oldInfo);
    innerBundleInfo.SetTargetBundleName(TEST_BUNDLE_NAME);
    res = overlayDataMgr.UpdateExternalOverlayInfo(innerBundleInfo, oldInfo, oldInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);

    InnerModuleInfo moduleInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    moduleInfo.moduleName = "moduleName";
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    innerBundleInfo.AddInnerModuleInfo(innerModuleInfos);
    res = overlayDataMgr.UpdateExternalOverlayInfo(innerBundleInfo, oldInfo, oldInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);

    innerBundleInfo.SetUserId(ServiceConstants::NOT_EXIST_USERID);
    res = overlayDataMgr.UpdateExternalOverlayInfo(innerBundleInfo, oldInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);
    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_0500
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of UpdateExternalOverlayInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_0500, Function | SmallTest | Level0)
{
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetInnerBundleInfo;
    AddInnerBundleInfo(newInfo, oldInfo);

    OverlayDataMgr overlayDataMgr;
    ErrCode res = overlayDataMgr.UpdateExternalOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    EXPECT_EQ(res, ERR_OK);
    UninstallBundleInfo();
}

#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
/**
 * @tc.number: OverlayDataMgr_0600
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of BuildOverlayConnection and BuildOverlayConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_0600, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    const auto &moduleInfos = newInfo.GetInnerModuleInfos();
    std::string moduleName = (moduleInfos.begin()->second).moduleName;
    overlayDataMgr.BuildInternalOverlayConnection(moduleName, oldInfo, newInfo.GetUserId());
    EXPECT_EQ(oldInfo.FetchInnerModuleInfos().empty(), true);

    oldInfo.SetOverlayState(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    overlayDataMgr.BuildInternalOverlayConnection(moduleName, oldInfo, newInfo.GetUserId());
    EXPECT_EQ(oldInfo.FetchInnerModuleInfos().empty(), true);
}

/**
 * @tc.number: OverlayDataMgr_0700
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of BuildOverlayConnection and BuildOverlayConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_0700, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    oldInfo.SetIsPreInstallApp(false);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = NO_EXIST;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    EXPECT_EQ(oldInfo.baseApplicationInfo_->bundleName, NO_EXIST);
}

/**
 * @tc.number: OverlayDataMgr_0900
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of BuildOverlayConnection and BuildOverlayConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_0900, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    oldInfo.SetIsPreInstallApp(true);
    oldInfo.SetCertificateFingerprint(NO_EXIST);
    EXPECT_EQ(oldInfo.baseApplicationInfo_->fingerprint, NO_EXIST);
}

/**
 * @tc.number: OverlayDataMgr_1000
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of UpdateOverlayModule.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_1000, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    auto res = overlayDataMgr.UpdateOverlayModule(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);

    newInfo.isNewVersion_ = true;
    res = overlayDataMgr.UpdateOverlayModule(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);

    newInfo.isNewVersion_ = false;
    oldInfo.isNewVersion_ = true;
    res = overlayDataMgr.UpdateOverlayModule(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);

    newInfo.isNewVersion_ = true;
    res = overlayDataMgr.UpdateOverlayModule(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);

    newInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    res = overlayDataMgr.UpdateOverlayModule(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
}
#endif

/**
 * @tc.number: OverlayDataMgr_1200
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of GetBundleDir.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_1200, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    std::string moduleHapPath = "xxx/";
    std::string bundleDir;
    ErrCode res = overlayDataMgr.GetBundleDir(moduleHapPath, bundleDir);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_BUNDLE_DIR);
    moduleHapPath = "//";
    res = overlayDataMgr.GetBundleDir(moduleHapPath, bundleDir);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_1300
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_1300, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_1400
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_1400, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, newInfo);
    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_1500
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_1500, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    newInfo.SetOverlayType(OVERLAY_INTERNAL_BUNDLE);

    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_1600
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of QueryOverlayInnerBundleInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_1600, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo info;
    bool res = overlayDataMgr.QueryOverlayInnerBundleInfo("", info);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: OverlayDataMgr_1700
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of GetAllOverlayModuleInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_1700, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ErrCode res = overlayDataMgr.GetAllOverlayModuleInfo("", overlayModuleInfos, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);

    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInnerBundleInfo;
    AddInnerBundleInfo(innerBundleInfo, oldInnerBundleInfo);
    res = overlayDataMgr.GetAllOverlayModuleInfo(
        TEST_BUNDLE_NAME, overlayModuleInfos, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);

    res = overlayDataMgr.GetAllOverlayModuleInfo(
        TEST_BUNDLE_NAME, overlayModuleInfos, Constants::INVALID_USERID);
    EXPECT_EQ(res,
        ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);

    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfos.push_back(overlayModuleInfo);
    res = overlayDataMgr.GetAllOverlayModuleInfo(
        TEST_BUNDLE_NAME, overlayModuleInfos, ServiceConstants::NOT_EXIST_USERID);

    EXPECT_EQ(res,
        ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);
    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_1800
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of GetOverlayModuleInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_1800, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    OverlayModuleInfo overlayModuleInfos;
    ErrCode res = overlayDataMgr.GetOverlayModuleInfo("", "", overlayModuleInfos, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);

    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInnerBundleInfo;
    AddInnerBundleInfo(innerBundleInfo, oldInnerBundleInfo);
    res = overlayDataMgr.GetOverlayModuleInfo(
        TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfos, Constants::INVALID_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);

    res = overlayDataMgr.GetOverlayModuleInfo(
        TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfos, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);
}

/**
 * @tc.number: OverlayDataMgr_1900
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of GetOverlayBundleInfoForTarget.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_1900, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    std::vector<OverlayBundleInfo> overlayBundleInfo;
    ErrCode res = overlayDataMgr.GetOverlayBundleInfoForTarget("", overlayBundleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_NOT_EXISTED);

    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInnerBundleInfo;
    AddInnerBundleInfo(innerBundleInfo, oldInnerBundleInfo);
    res = overlayDataMgr.GetOverlayBundleInfoForTarget(
        TEST_BUNDLE_NAME, overlayBundleInfo, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(overlayBundleInfo.size(), DEFAULT_OVERLAY_BUNDLE_INFO);

    res = overlayDataMgr.GetOverlayBundleInfoForTarget(
        TEST_BUNDLE_NAME, overlayBundleInfo, Constants::INVALID_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);

    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_2000
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of GetOverlayModuleInfoForTarget.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2000, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInnerBundleInfo;
    AddInnerBundleInfo(innerBundleInfo, oldInnerBundleInfo);
    OverlayDataMgr overlayDataMgr;
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ErrCode res = overlayDataMgr.GetOverlayModuleInfoForTarget(
        TEST_BUNDLE_NAME, TARGET_MODULE_NAME, overlayModuleInfos, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_MODULE_IS_OVERLAY_MODULE);

    res = overlayDataMgr.GetOverlayModuleInfoForTarget(
        TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfos, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_MODULE_NOT_EXISTED);

    res = overlayDataMgr.GetOverlayModuleInfoForTarget(
        TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfos, Constants::INVALID_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);

    res = overlayDataMgr.GetOverlayModuleInfoForTarget(
        TEST_BUNDLE_NAME, "", overlayModuleInfos, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_OK);

    res = overlayDataMgr.GetOverlayModuleInfoForTarget(
        "", "", overlayModuleInfos, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_NOT_EXISTED);

    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_2100
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of SetOverlayEnabled.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2100, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    bool isEnabled = false;
    ErrCode res = overlayDataMgr.SetOverlayEnabled(TEST_BUNDLE_NAME, "", isEnabled, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);

    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInnerBundleInfo;
    AddInnerBundleInfo(innerBundleInfo, oldInnerBundleInfo);
    res = overlayDataMgr.SetOverlayEnabled(
        TEST_BUNDLE_NAME, TEST_MODULE_NAME, isEnabled, Constants::INVALID_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);

    res = overlayDataMgr.SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, isEnabled, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);

    res = overlayDataMgr.SetOverlayEnabled(
        TEST_BUNDLE_NAME, TEST_MODULE_NAME, isEnabled, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);

    UninstallBundleInfo();

    AddInnerBundleInfoNoModuleInfo();
    res = overlayDataMgr.SetOverlayEnabled(
        TEST_BUNDLE_NAME, TEST_MODULE_NAME, isEnabled, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_MODULE);
    UninstallBundleInfo();

    oldInnerBundleInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    AddInnerBundleInfo(innerBundleInfo, oldInnerBundleInfo);
    res = overlayDataMgr.SetOverlayEnabled(
        TEST_BUNDLE_NAME, TARGET_MODULE_NAME, isEnabled, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_OK);
    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_2200
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of GetCallingBundleName.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2200, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    std::string res = overlayDataMgr.GetCallingBundleName();
    EXPECT_EQ(res, "");
}

/**
 * @tc.number: OverlayDataMgr_2300
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of AddOverlayModuleStates.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2300, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    overlayDataMgr.AddOverlayModuleStates(innerBundleInfo, userInfo);
    EXPECT_EQ(userInfo.bundleUserInfo.userId, Constants::INVALID_USERID);

    userInfo.bundleUserInfo.userId = USERID;
    innerBundleInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    overlayDataMgr.AddOverlayModuleStates(innerBundleInfo, userInfo);
    EXPECT_EQ(userInfo.bundleUserInfo.userId, USERID);
}

/**
 * @tc.number: OverlayDataMgr_2400
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of AddOverlayModuleStates.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2400, Function | SmallTest | Level0)
{
    InnerBundleInfo curInnerBundleInfo;
    InnerBundleInfo oldInnerBundleInfo;
    AddInnerBundleInfo(curInnerBundleInfo, oldInnerBundleInfo);
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    innerBundleInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    innerBundleInfo.SetTargetBundleName(TEST_BUNDLE_NAME);
    overlayDataMgr.AddOverlayModuleStates(innerBundleInfo, userInfo);
    EXPECT_EQ(userInfo.bundleUserInfo.userId, USERID);
    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_2500
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2500, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    newInfo.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);

    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.targetBundleName = TEST_BUNDLE_NAME;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    dataMgr->bundleInfos_.insert(
        pair<std::string, InnerBundleInfo>(TEST_BUNDLE_NAME, oldInfo));
    res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_2600
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2600, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    newInfo.SetOverlayType(NON_OVERLAY_TYPE);

    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_2700
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2700, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetInnerBundleInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;

    overlayDataMgr.RemoveOverlayBundleInfo(TEST_BUNDLE_NAME, targetInnerBundleInfo);
    overlayDataMgr.RemoveOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    newInfo.SetOverlayType(OVERLAY_INTERNAL_BUNDLE);

    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_2800
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2800, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    newInfo.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.targetBundleName = TEST_BUNDLE_NAME;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    newInfo.SetTargetBundleName(NO_EXIST);
    dataMgr->bundleInfos_.insert(
        pair<std::string, InnerBundleInfo>(TEST_BUNDLE_NAME, oldInfo));
    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_2900
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_2900, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInnerBundleInfo;
    AddInnerBundleInfo(innerBundleInfo, oldInnerBundleInfo);

    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetInnerBundleInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    overlayDataMgr.RemoveOverlayBundleInfo(TEST_BUNDLE_NAME, targetInnerBundleInfo);
    overlayDataMgr.RemoveOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);

    oldInfo.SetOverlayType(OVERLAY_INTERNAL_BUNDLE);
    overlayDataMgr.RemoveOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);

    oldInfo.SetTargetBundleName(TARGET_MODULE_NAME);
    overlayDataMgr.RemoveOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);

    oldInfo.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);
    overlayDataMgr.RemoveOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);

    oldInfo.SetTargetBundleName(TARGET_MODULE_NAME);
    overlayDataMgr.RemoveOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);

    oldInfo.SetOverlayType(NON_OVERLAY_TYPE);
    overlayDataMgr.RemoveOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);
    overlayDataMgr.RemoveOverlayModuleInfo("noExits", TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);
    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_3000
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3000, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);

    info.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    bool res = dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, info);
    EXPECT_EQ(res, true);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME2, InstallState::INSTALL_START);
    info.SetOverlayType(OverlayType::NON_OVERLAY_TYPE);
    res = dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME2, info);
    EXPECT_EQ(res, true);

    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_3100
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);

    info.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    bool res = dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, info);
    EXPECT_EQ(res, true);

    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_3200
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3200, Function | SmallTest | Level0)
{
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    AddInnerBundleInfo(newInfo, oldInfo);

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    bool res = dataMgr->AddNewModuleInfo(TEST_BUNDLE_NAME, newInfo, oldInfo);
    EXPECT_EQ(res, false);

    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_3300
 * @tc.name: AddBundleInfo
 * @tc.desc: 1. add module info to the data manager
 *           2. query data then verify
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3300, Function | SmallTest | Level0)
{
    InnerBundleInfo info1;
    BundleInfo bundleInfo1;
    bundleInfo1.name = TEST_BUNDLE_NAME;
    bundleInfo1.applicationInfo.bundleName = TEST_BUNDLE_NAME;
    ApplicationInfo applicationInfo1;
    applicationInfo1.name = TEST_BUNDLE_NAME;
    applicationInfo1.bundleName = TEST_BUNDLE_NAME;
    info1.SetBaseBundleInfo(bundleInfo1);
    info1.SetBaseApplicationInfo(applicationInfo1);

    InnerBundleInfo info2;
    BundleInfo bundleInfo2;
    bundleInfo2.name = TEST_BUNDLE_NAME;
    bundleInfo2.applicationInfo.bundleName = TEST_BUNDLE_NAME;
    ApplicationInfo applicationInfo2;
    applicationInfo2.name = TEST_BUNDLE_NAME;
    applicationInfo2.bundleName = TEST_BUNDLE_NAME;
    info2.SetBaseBundleInfo(bundleInfo2);
    info2.SetBaseApplicationInfo(applicationInfo2);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, info1);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UPDATING_START);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
    info1.SetOverlayType(OverlayType::NON_OVERLAY_TYPE);
    info2.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    bool ret = dataMgr->AddNewModuleInfo(TEST_BUNDLE_NAME, info2, info1);
    EXPECT_FALSE(ret);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}


/**
 * @tc.number: OverlayDataMgr_3400
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of IsExistedNonOverlayHap.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3400, Function | SmallTest | Level0)
{
    AddInnerBundleInfoNoModuleInfo();
    OverlayDataMgr overlayDataMgr;
    bool res = overlayDataMgr.IsExistedNonOverlayHap(TEST_BUNDLE_NAME);
    EXPECT_EQ(res, false);
    UninstallBundleInfo();

    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInnerBundleInfo;
    AddInnerBundleInfo(innerBundleInfo, oldInnerBundleInfo);
    res = overlayDataMgr.IsExistedNonOverlayHap(TEST_BUNDLE_NAME);
    EXPECT_EQ(res, false);
    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_3500
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of BuildInternalOverlayConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3500, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.targetBundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, innerBundleInfo);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UPDATING_START);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
    OverlayDataMgr overlayDataMgr;
    overlayDataMgr.BuildInternalOverlayConnection(TARGET_MODULE_NAME, innerBundleInfo, USERID);
    EXPECT_EQ(innerBundleInfo.FetchInnerModuleInfos().empty(), false);
    UninstallBundleInfo();
}

/**
 * @tc.number: OverlayDataMgr_3600
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3600, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    newInfo.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);

    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
}

/**
 * @tc.number: OverlayDataMgr_3700
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3700, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    newInfo.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    newInfo.SetTargetBundleName(NO_EXIST);
    oldInfo.SetTargetBundleName(TEST_BUNDLE_NAME);
    dataMgr->bundleInfos_.insert(
        pair<std::string, InnerBundleInfo>(TEST_BUNDLE_NAME, oldInfo));
    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_3800
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3800, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo targetInnerBundleInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.moduleName = TEST_PACK_AGE;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    innerModuleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = innerModuleInfo;
    innerBundleInfo.AddInnerModuleInfo(innerModuleInfos);
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.targetBundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    innerBundleInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    overlayDataMgr.RemoveOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_PACK_AGE, innerBundleInfo, targetInnerBundleInfo);
    overlayDataMgr.ResetInternalOverlayModuleState(innerModuleInfos, TARGET_MODULE_NAME, innerBundleInfo);
    EXPECT_EQ(innerModuleInfos.at(TEST_PACK_AGE).targetModuleName, TARGET_MODULE_NAME);
}

/**
 * @tc.number: OverlayDataMgr_3900
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of SaveInternalOverlayModuleState.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_3900, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.moduleName = TEST_PACK_AGE;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    innerModuleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = innerModuleInfo;
    innerBundleInfo.AddInnerModuleInfo(innerModuleInfos);
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.targetBundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.targetModuleName = TARGET_MODULE_NAME;

    ErrCode res = overlayDataMgr.SaveInternalOverlayModuleState(overlayModuleInfo, innerBundleInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_4000
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of GetOverlayModuleInfoForTarget.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4000, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ErrCode res = overlayDataMgr.GetOverlayModuleInfoForTarget(
        innerBundleInfo, overlayModuleInfos, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_4100
 * @tc.name: test bundleName is empty.
 * @tc.desc: 1.OverlayDataMgr with SetOverlayEnabled.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4100, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    bool isEnabled = false;
    ErrCode res = overlayDataMgr.SetOverlayEnabled("", TEST_MODULE_NAME, isEnabled, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
}

/**
 * @tc.number: OverlayDataMgr_4200
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of BuildInternalOverlayConnection.
 *           2.system run normally.
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4200, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    oldInfo.SetOverlayType(OVERLAY_INTERNAL_BUNDLE);
    InnerModuleInfo moduleInfo;
    moduleInfo.targetModuleName = TEST_MODULE_NAME;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.targetModuleName = TEST_PACK_AGE;
    innerModuleInfos[TEST_MODULE_NAME] = moduleInfo;
    oldInfo.AddInnerModuleInfo(innerModuleInfos);

    ClearDataMgr();
    BuildInternalOverlayConnection(TEST_MODULE_NAME, oldInfo, USERID);
    ResetDataMgr();
}

/**
 * @tc.number: OverlayDataMgr_4300
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of QueryOverlayInnerBundleInfo.
 *           2.system run normally.
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4300, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    overlayDataMgr.dataMgr_ = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    info.AddInnerModuleInfo(innerModuleInfos);
    overlayDataMgr.dataMgr_->bundleInfos_[NO_EXIST] = info;
    bool ret = overlayDataMgr.QueryOverlayInnerBundleInfo(NO_EXIST, info);
    auto iterator = overlayDataMgr.dataMgr_->bundleInfos_.find(NO_EXIST);
    if (iterator != overlayDataMgr.dataMgr_->bundleInfos_.end()) {
        overlayDataMgr.dataMgr_->bundleInfos_.erase(iterator);
    }
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: OverlayDataMgr_4400
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of QueryOverlayInnerBundleInfo.
 *           2.system run normally.
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4400, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    overlayDataMgr.dataMgr_ = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info;
    info.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfos[TEST_MODULE_NAME] = innerModuleInfo;
    info.AddInnerModuleInfo(innerModuleInfos);
    overlayDataMgr.dataMgr_->bundleInfos_[NO_EXIST] = info;
    std::vector<OverlayModuleInfo> overlayModuleInfo;
    auto ret = overlayDataMgr.GetAllOverlayModuleInfo(NO_EXIST, overlayModuleInfo,
        ServiceConstants::NOT_EXIST_USERID);
    auto iterator = overlayDataMgr.dataMgr_->bundleInfos_.find(NO_EXIST);
    if (iterator != overlayDataMgr.dataMgr_->bundleInfos_.end()) {
        overlayDataMgr.dataMgr_->bundleInfos_.erase(iterator);
    }
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: OverlayDataMgr_4500
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of BuildInternalOverlayConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4500, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    oldInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.targetModuleName = "errModuleName";
    oldInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>("1", innerModuleInfo));
    overlayDataMgr.BuildInternalOverlayConnection(TARGET_MODULE_NAME, oldInfo, USERID);
    EXPECT_EQ(oldInfo.FetchInnerModuleInfos().empty(), false);
}

/**
 * @tc.number: OverlayDataMgr_4600
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of BuildInternalOverlayConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4600, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    oldInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.moduleName = TEST_MODULE_NAME;
    oldInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>("1", innerModuleInfo));
    overlayDataMgr.BuildInternalOverlayConnection(TARGET_MODULE_NAME, oldInfo, USERID);
    EXPECT_EQ(oldInfo.FetchInnerModuleInfos().empty(), false);
}

/**
 * @tc.number: OverlayDataMgr_4700
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of BuildInternalOverlayConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4700, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    oldInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    oldInfo.innerModuleInfos_.clear();
    overlayDataMgr.BuildInternalOverlayConnection(TARGET_MODULE_NAME, oldInfo, USERID);
    EXPECT_EQ(oldInfo.FetchInnerModuleInfos().empty(), true);
}

/**
 * @tc.number: OverlayDataMgr_4800
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of BuildInternalOverlayConnection.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4800, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    oldInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    oldInfo.innerModuleInfos_.clear();
    overlayDataMgr.BuildInternalOverlayConnection(TARGET_MODULE_NAME, oldInfo, USERID);
    EXPECT_EQ(oldInfo.FetchInnerModuleInfos().empty(), true);
}

/**
 * @tc.number: OverlayDataMgr_4900
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of QueryOverlayInnerBundleInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_4900, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    overlayDataMgr.dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    overlayDataMgr.dataMgr_->bundleInfos_.insert(pair<string, InnerBundleInfo>(TEST_BUNDLE_NAME, innerBundleInfo));
    auto res = overlayDataMgr.QueryOverlayInnerBundleInfo(NO_EXIST, innerBundleInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: OverlayDataMgr_5000
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of QueryOverlayInnerBundleInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_5000, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    ClearDataMgr();
    auto res = overlayDataMgr.QueryOverlayInnerBundleInfo(TEST_BUNDLE_NAME, innerBundleInfo);
    EXPECT_FALSE(res);
    ResetDataMgr();
}

/**
 * @tc.number: OverlayDataMgr_5100
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of SaveInternalOverlayModuleState.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_5100, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>(TARGET_MODULE_NAME, innerModuleInfo));
    overlayDataMgr.dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    overlayDataMgr.dataMgr_->AddUserId(NOT_EXIST_USERID);
    auto res = overlayDataMgr.SaveInternalOverlayModuleState(overlayModuleInfo, innerBundleInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: OverlayDataMgr_5200
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of SaveInternalOverlayModuleState.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayDataMgr_5200, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>(TEST_MODULE_NAME, innerModuleInfo));
    overlayDataMgr.dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    overlayDataMgr.dataMgr_->AddUserId(NOT_EXIST_USERID);
    auto res = overlayDataMgr.SaveInternalOverlayModuleState(overlayModuleInfo, innerBundleInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: OverlayManagerHostImpl_0100
 * @tc.name: test overlayManagerHostImpl.
 * @tc.desc: 1.overlayManagerHostImpl of GetAllOverlayModuleInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, OverlayManagerHostImpl_0100, Function | SmallTest | Level0)
{
    OverlayManagerHostImpl overlayManagerHostImpl;
    std::vector<OverlayModuleInfo> overlayModuleInfo;
    ErrCode res = overlayManagerHostImpl.GetAllOverlayModuleInfo("", overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    res = overlayManagerHostImpl.GetAllOverlayModuleInfo(
        "bundleName", overlayModuleInfo, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
}

/**
 * @tc.number: GetOverlayModuleInfo_0200
 * @tc.name: test overlayManagerHostImpl.
 * @tc.desc: 1.overlayManagerHostImpl of GetOverlayModuleInfo.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, GetOverlayModuleInfo_0200, Function | SmallTest | Level0)
{
    OverlayManagerHostImpl overlayManagerHostImpl;
    OverlayModuleInfo overlayModuleInfo;
    ErrCode res = overlayManagerHostImpl.GetOverlayModuleInfo(
        "", "moduleName", overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    res = overlayManagerHostImpl.GetOverlayModuleInfo(
        "bundleName", "", overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    res = overlayManagerHostImpl.GetOverlayModuleInfo(
        "", "", overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    res = overlayManagerHostImpl.GetOverlayModuleInfo(
        "bundleName", "moduleName", overlayModuleInfo, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
}

/**
 * @tc.number: GetOverlayModuleInfo_0300
 * @tc.name: test overlayManagerHostImpl.
 * @tc.desc: 1.overlayManagerHostImpl of GetOverlayBundleInfoForTarget.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, GetOverlayModuleInfo_0300, Function | SmallTest | Level0)
{
    OverlayManagerHostImpl overlayManagerHostImpl;
    std::vector<OverlayBundleInfo> overlayBundleInfo;
    ErrCode res = overlayManagerHostImpl.GetOverlayBundleInfoForTarget(
        "", overlayBundleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    res = overlayManagerHostImpl.GetOverlayBundleInfoForTarget(
        "targetBundleName", overlayBundleInfo, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_NOT_EXISTED);
}

/**
 * @tc.number: GetOverlayModuleInfo_0400
 * @tc.name: test OverlayManagerHostImpl.
 * @tc.desc: 1.OverlayManagerHostImpl of GetOverlayModuleInfoForTarget.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, GetOverlayModuleInfo_0400, Function | SmallTest | Level0)
{
    OverlayManagerHostImpl overlayManagerHostImpl;
    std::vector<OverlayModuleInfo> overlayModuleInfo;
    ErrCode res = overlayManagerHostImpl.GetOverlayModuleInfoForTarget(
        "", "targetModuleName", overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    res = overlayManagerHostImpl.GetOverlayModuleInfoForTarget(
        "targetBundleName", "", overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_NOT_EXISTED);

    res = overlayManagerHostImpl.GetOverlayModuleInfoForTarget(
        "", "", overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    res = overlayManagerHostImpl.GetOverlayModuleInfoForTarget(
        "targetBundleName", "targetModuleName", overlayModuleInfo, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_NOT_EXISTED);
}

/**
 * @tc.number: GetOverlayModuleInfo_0500
 * @tc.name: test OverlayManagerHostImpl.
 * @tc.desc: 1.OverlayManagerHostImpl of SetOverlayEnabled.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, GetOverlayModuleInfo_0500, Function | SmallTest | Level0)
{
    OverlayManagerHostImpl overlayManagerHostImpl;
    bool isEnabled = false;
    ErrCode res = overlayManagerHostImpl.SetOverlayEnabled(
        "", "moduleName", isEnabled, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);

    res = overlayManagerHostImpl.SetOverlayEnabled(
        "bundleName", "", isEnabled, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);

    res = overlayManagerHostImpl.SetOverlayEnabled(
        "", "", isEnabled, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);

    res = overlayManagerHostImpl.SetOverlayEnabled(
        "bundleName", "moduleName", isEnabled, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
}

/**
 * @tc.number: GetOverlayModuleInfo_0800
 * @tc.name: test overlayManagerHostImpl.
 * @tc.desc: 1.OverlayManagerHostImpl with GetOverlayBundleInfoForTarget.
 *           2.system run normally.
  * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, GetOverlayModuleInfo_0800, Function | SmallTest | Level0)
{
    OverlayManagerHostImpl overlayManagerHostImpl;
    std::vector<OverlayBundleInfo> overlayBundleInfo;
    ErrCode res = overlayManagerHostImpl.GetOverlayBundleInfoForTarget(TEST_BUNDLE_NAME,
        overlayBundleInfo, Constants::INVALID_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_2000
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling SetOverlayEnabled interface by using OverlayManagerProxy instance.
 *           3.bundleName is empty and set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, GetOverlayModuleInfo_0900, Function | SmallTest | Level0)
{
    OverlayManagerHostImpl overlayManagerHostImpl;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto errCode = overlayManagerHostImpl.GetTargetOverlayModuleInfo("", overlayModuleInfos,
        USERID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    errCode = overlayManagerHostImpl.GetTargetOverlayModuleInfo(TEST_BUNDLE_NAME, overlayModuleInfos,
        Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(errCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_2000
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerProxy.
 * @tc.desc: 1.construct GetOverlayModuleInfoByBundleName instance.
 *           2.calling SetOverlayEnabled interface by using GetOverlayModuleInfoByBundleName instance.
 *           3.bundleName is empty and set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, GetOverlayModuleInfo_1000, Function | SmallTest | Level0)
{
    OverlayManagerHostImpl overlayManagerHostImpl;

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto errCode = overlayManagerHostImpl.GetOverlayModuleInfoByBundleName("", TEST_MODULE_NAME,
        overlayModuleInfos, USERID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    errCode = overlayManagerHostImpl.GetOverlayModuleInfoByBundleName(TEST_BUNDLE_NAME, "",
        overlayModuleInfos, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);

    errCode = overlayManagerHostImpl.GetOverlayModuleInfoByBundleName(TEST_BUNDLE_NAME, TEST_MODULE_NAME,
        overlayModuleInfos, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);
}

/**
 * @tc.number: OverlayIpcTest_2000
 * @tc.name: test SetOverlayEnabledForSelf interface in OverlayManagerProxy.
 * @tc.desc: 1.construct SetOverlayEnabledForSelf instance.
 *           2.calling SetOverlayEnabled interface by using SetOverlayEnabledForSelf instance.
 *           3.bundleName is empty and set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, GetOverlayModuleInfo_1100, Function | SmallTest | Level0)
{
    OverlayManagerHostImpl overlayManagerHostImpl;

    bool isEnabled = false;
    auto errCode = overlayManagerHostImpl.SetOverlayEnabledForSelf("",
        isEnabled, USERID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);

    errCode = overlayManagerHostImpl.SetOverlayEnabledForSelf(TEST_MODULE_NAME,
        isEnabled, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(errCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: CheckTargetBundle_0100
 * @tc.name: check bundle target priority range
 * @tc.desc: Test CheckTargetBundle
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckTargetBundle_0100, Function | SmallTest | Level0)
{
    BundleOverlayInstallChecker checker;
    auto code = checker.CheckTargetBundle("", "", "", USERID);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_BUNDLE_NAME);
    code = checker.CheckTargetBundle(TEST_BUNDLE_NAME, "", "", USERID);
    EXPECT_EQ(code, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_NO_SYSTEM_APPLICATION_FOR_EXTERNAL_OVERLAY);
}

/**
 * @tc.number: UpdateInnerBundleInfo_0100
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of RemoveOverlayModuleConnection.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, UpdateInnerBundleInfo_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info1;
    BundleInfo bundleInfo1;
    bundleInfo1.name = BUNDLE_NAME;
    bundleInfo1.applicationInfo.bundleName = BUNDLE_NAME;
    ApplicationInfo applicationInfo1;
    applicationInfo1.name = BUNDLE_NAME;
    applicationInfo1.bundleName = BUNDLE_NAME;
    info1.SetBaseBundleInfo(bundleInfo1);
    info1.SetBaseApplicationInfo(applicationInfo1);

    InnerBundleInfo info2;
    BundleInfo bundleInfo2;
    bundleInfo2.name = BUNDLE_NAME;
    bundleInfo2.applicationInfo.bundleName = BUNDLE_NAME;
    ApplicationInfo applicationInfo2;
    applicationInfo2.name = BUNDLE_NAME;
    applicationInfo2.bundleName = BUNDLE_NAME;
    info2.SetBaseBundleInfo(bundleInfo2);
    info2.SetBaseApplicationInfo(applicationInfo2);
    info2.SetIsNewVersion(true);
    info2.SetOverlayType(OverlayType::NON_OVERLAY_TYPE);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(USERID);

    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info1);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
    bool ret4 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
    bool ret5 = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, info2, info1);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
    EXPECT_TRUE(ret4);
    EXPECT_TRUE(ret5);

    info2.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    ret5 = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, info2, info1);
    EXPECT_FALSE(ret5);

    info2.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    ret5 = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, info2, info1);
    EXPECT_TRUE(ret5);

    ret5 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    EXPECT_TRUE(ret5);
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_0100
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_0100, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;

    ClearDataMgr();
    bool resBool = overlayDataMgr.IsExistedNonOverlayHap(TEST_BUNDLE_NAME);
    EXPECT_EQ(resBool, false);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_0200
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_0200, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    newInfo.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);

    ClearDataMgr();
    ErrCode res = overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_0300
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6S6E8
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_0300, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetInnerBundleInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    oldInfo.AddInnerModuleInfo(innerModuleInfos);
    oldInfo.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);

    ClearDataMgr();
    overlayDataMgr.RemoveOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);
    std::map<std::string, InnerModuleInfo> moduleInfos = oldInfo.FetchInnerModuleInfos();
    EXPECT_EQ(moduleInfos.empty(), false);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_0400
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_0400, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.overlayModulesState.clear();
    std::map<std::string, int32_t> statesMap;
    std::map<std::string, int32_t> res = overlayDataMgr.GetModulesStateFromUserInfo(userInfo);
    EXPECT_EQ(res, statesMap);

    userInfo.bundleUserInfo.overlayModulesState.push_back(TEST_MODULE_NAME);
    res = overlayDataMgr.GetModulesStateFromUserInfo(userInfo);
    EXPECT_EQ(res, statesMap);

    userInfo.bundleUserInfo.overlayModulesState.clear();
    userInfo.bundleUserInfo.overlayModulesState.push_back(TEST_MODULE_NAME_ONE);
    res = overlayDataMgr.GetModulesStateFromUserInfo(userInfo);
    statesMap["TEST"] = FILE_UNDERLINE_NUM;
    EXPECT_EQ(res, statesMap);
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_0500
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_0500, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.bundleName = NO_EXIST;
    ErrCode res = overlayDataMgr.ObtainOverlayModuleState(overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_0600
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_0600, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetInnerBundleInfo;

    ClearDataMgr();
    auto resCode = overlayDataMgr.UpdateExternalOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    EXPECT_EQ(resCode, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_0700
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_0700, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;

    ClearDataMgr();
    auto resBool = overlayDataMgr.QueryOverlayInnerBundleInfo(TEST_BUNDLE_NAME, oldInfo);
    EXPECT_EQ(resBool, false);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_0800
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_0800, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;

    ClearDataMgr();
    OverlayModuleInfo overlayModuleInfo;
    ErrCode resCode = overlayDataMgr.SaveInternalOverlayModuleState(overlayModuleInfo, oldInfo);
    EXPECT_EQ(resCode, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_SERVICE_EXCEPTION);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_0900
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_0900, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetBundleInfo;

    ClearDataMgr();
    OverlayModuleInfo overlayModuleInfo;
    ErrCode resCode = overlayDataMgr.SaveExternalOverlayModuleState(
        overlayModuleInfo, targetBundleInfo, USERID, oldInfo);
    EXPECT_EQ(resCode, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_1000
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_1000, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;

    ClearDataMgr();
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ErrCode resCode = overlayDataMgr.GetAllOverlayModuleInfo(TEST_BUNDLE_NAME, overlayModuleInfos, USERID);
    EXPECT_EQ(resCode, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_1100
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_1100, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;

    ClearDataMgr();
    OverlayModuleInfo overlayModuleInfo;
    ErrCode resCode = overlayDataMgr.GetOverlayModuleInfo(
        TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo, USERID);
    EXPECT_EQ(resCode, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_1200
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_1200, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;

    ClearDataMgr();
    std::vector<OverlayBundleInfo> overlayBundleInfo;
    ErrCode resCode = overlayDataMgr.GetOverlayBundleInfoForTarget(
        TEST_MODULE_NAME, overlayBundleInfo, USERID);
    EXPECT_EQ(resCode, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_1300
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_1300, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;

    ClearDataMgr();
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    ErrCode resCode = overlayDataMgr.GetOverlayModuleInfoForTarget(
        TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfos, USERID);
    EXPECT_EQ(resCode, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_1400
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_1400, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;

    ClearDataMgr();
    OverlayModuleInfo overlayModuleInfo;
    ErrCode resCode = overlayDataMgr.ObtainOverlayModuleState(overlayModuleInfo, USERID);
    EXPECT_EQ(resCode, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_1500
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_1500, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;

    ClearDataMgr();
    bool isEnabled = false;
    ErrCode resCode = overlayDataMgr.SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, isEnabled, USERID);
    EXPECT_EQ(resCode, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_1600
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_1600, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;

    ClearDataMgr();
    std::string resString = overlayDataMgr.GetCallingBundleName();
    EXPECT_EQ(resString.empty(), true);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_1700
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_1700, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo oldInfo;
    oldInfo.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);

    ClearDataMgr();
    BuildInternalOverlayConnection(TEST_MODULE_NAME, oldInfo, USERID);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_1900
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_1900, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo targetInnerBundleInfo;

    ClearDataMgr();
    RemoveOverlayBundleInfo(TEST_MODULE_NAME, targetInnerBundleInfo);
    ResetDataMgr();
}

/**
 * @tc.number: TestOverlayByDataMgrFalse_2300
 * @tc.name: test TestOverlayByDataMgrFalse.
 * @tc.desc: 1.test overlay by dataMgr is nullptr.
 *           2.system run normally.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayCheckerTest, TestOverlayByDataMgrFalse_2300, Function | SmallTest | Level0)
{
    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo newInfo;
    InnerBundleUserInfo userInfo;

    ClearDataMgr();
    AddOverlayModuleStates(newInfo, userInfo);
    ResetDataMgr();
}

/**
 * @tc.number: CheckAppLabel_0010
 * @tc.name: test CheckAppLabel
 * @tc.desc: 1.Test the CheckAppLabel
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckAppLabel_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.baseApplicationInfo_->targetBundleName = TEST_MODULE_NAME;
    ErrCode res = installer.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabel_0020
 * @tc.name: test CheckAppLabel
 * @tc.desc: 1.Test the CheckAppLabel
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckAppLabel_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.baseApplicationInfo_->targetPriority = FOUR;
    ErrCode res = installer.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_PRIORITY_NOT_SAME);
}

/**
 * @tc.number: CheckOverlayInstallation_0010
 * @tc.name: test CheckOverlayInstallation
 * @tc.desc: 1.Test the CheckOverlayInstallation
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckOverlayInstallation_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo newInfo;
    newInfo.SetOverlayState(NON_OVERLAY_TYPE);
    newInfos.try_emplace(TEST_MODULE_NAME, newInfo);
    ErrCode res = installer.CheckOverlayInstallation(newInfos, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CheckOverlayInstallation_0020
 * @tc.name: test CheckOverlayInstallation
 * @tc.desc: 1.Test the CheckOverlayInstallation
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckOverlayInstallation_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo info1;
    info1.SetOverlayType(OVERLAY_INTERNAL_BUNDLE);
    newInfos.try_emplace(TEST_MODULE_NAME, info1);
    ErrCode res = installer.CheckOverlayInstallation(newInfos, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_HAP_TYPE);
}

/**
 * @tc.number: CheckOverlayInstallation_0030
 * @tc.name: test CheckOverlayInstallation
 * @tc.desc: 1.Test the CheckOverlayInstallation
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckOverlayInstallation_0030, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo info1;
    info1.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);
    newInfos.try_emplace(TEST_MODULE_NAME, info1);
    ErrCode res = installer.CheckOverlayInstallation(newInfos, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_HAP_TYPE);
}

/**
 * @tc.number: GetNotifyType_0010
 * @tc.name: test GetNotifyType
 * @tc.desc: 1.Test the GetNotifyType
*/
HWTEST_F(BmsBundleOverlayCheckerTest, GetNotifyType_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    installer.hasInstalledInUser_ = true;
    installer.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    NotifyType res = installer.GetNotifyType();
    EXPECT_EQ(res, NotifyType::OVERLAY_UPDATE);
}

/**
 * @tc.number: GetNotifyType_0020
 * @tc.name: test GetNotifyType
 * @tc.desc: 1.Test the GetNotifyType
*/
HWTEST_F(BmsBundleOverlayCheckerTest, GetNotifyType_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    installer.hasInstalledInUser_ = true;
    installer.overlayType_ = NON_OVERLAY_TYPE;
    NotifyType res = installer.GetNotifyType();
    EXPECT_EQ(res, NotifyType::UPDATE);
}

/**
 * @tc.number: GetNotifyType_0030
 * @tc.name: test GetNotifyType
 * @tc.desc: 1.Test the GetNotifyType
*/
HWTEST_F(BmsBundleOverlayCheckerTest, GetNotifyType_0030, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = false;
    installer.hasInstalledInUser_ = true;
    installer.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    NotifyType res = installer.GetNotifyType();
    EXPECT_EQ(res, NotifyType::OVERLAY_INSTALL);
}

/**
 * @tc.number: GetNotifyType_0040
 * @tc.name: test GetNotifyType
 * @tc.desc: 1.Test the GetNotifyType
*/
HWTEST_F(BmsBundleOverlayCheckerTest, GetNotifyType_0040, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    installer.hasInstalledInUser_ = false;
    installer.overlayType_ = NON_OVERLAY_TYPE;
    NotifyType res = installer.GetNotifyType();
    EXPECT_EQ(res, NotifyType::INSTALL);
}

/**
 * @tc.number: CheckOverlayUpdate_0010
 * @tc.name: test CheckOverlayUpdate
 * @tc.desc: 1.Test the CheckOverlayUpdate
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckOverlayUpdate_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    newInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    oldInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    ErrCode res = installer.CheckOverlayUpdate(oldInfo, newInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME);
}

/**
 * @tc.number: CheckOverlayUpdate_0020
 * @tc.name: test CheckOverlayUpdate
 * @tc.desc: 1.Test the CheckOverlayUpdate
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckOverlayUpdate_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    newInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    ErrCode res = installer.CheckOverlayUpdate(oldInfo, newInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME);
}

/**
 * @tc.number: CheckOverlayUpdate_0030
 * @tc.name: test CheckOverlayUpdate
 * @tc.desc: 1.Test the CheckOverlayUpdate
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckOverlayUpdate_0030, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    newInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    newInfo.currentPackage_ = TEST_PACK_AGE;
    ErrCode res = installer.CheckOverlayUpdate(oldInfo, newInfo, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CheckOverlayUpdate_0040
 * @tc.name: test CheckOverlayUpdate
 * @tc.desc: 1.Test the CheckOverlayUpdate
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckOverlayUpdate_0040, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    newInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);

    newInfo.currentPackage_ = TEST_PACK_AGE;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.targetModuleName = "";
    oldInfo.innerModuleInfos_[TEST_PACK_AGE] = innerModuleInfo;
    ErrCode res = installer.CheckOverlayUpdate(oldInfo, newInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME);
}

/**
 * @tc.number: CheckOverlayUpdate_0050
 * @tc.name: test CheckOverlayUpdate
 * @tc.desc: 1.Test the CheckOverlayUpdate
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckOverlayUpdate_0050, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    newInfo.SetOverlayType(OverlayType::NON_OVERLAY_TYPE);

    newInfo.currentPackage_ = TEST_PACK_AGE;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.targetModuleName = "targetModuleName";
    oldInfo.innerModuleInfos_[TEST_PACK_AGE] = innerModuleInfo;
    ErrCode res = installer.CheckOverlayUpdate(oldInfo, newInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME);
}

/**
 * @tc.number: CheckOverlayUpdate_0060
 * @tc.name: test CheckOverlayUpdate
 * @tc.desc: 1.Test the CheckOverlayUpdate
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CheckOverlayUpdate_0060, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    newInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);

    newInfo.currentPackage_ = TEST_PACK_AGE;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.targetModuleName = "targetModuleName";
    oldInfo.innerModuleInfos_[TEST_PACK_AGE] = innerModuleInfo;
    ErrCode res = installer.CheckOverlayUpdate(oldInfo, newInfo, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CopyHapsToSecurityDir_0010
 * @tc.name: test CopyHapsToSecurityDir
 * @tc.desc: 1.Test the CopyHapsToSecurityDir
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CopyHapsToSecurityDir_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.withCopyHaps = true;
    std::vector<std::string> bundlePaths;
    bundlePaths.push_back("data/test/test");
    ErrCode res = installer.CopyHapsToSecurityDir(installParam, bundlePaths);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT);
}

/**
 * @tc.number: CopyHapsToSecurityDir_0020
 * @tc.name: test CopyHapsToSecurityDir
 * @tc.desc: 1.Test the CopyHapsToSecurityDir
*/
HWTEST_F(BmsBundleOverlayCheckerTest, CopyHapsToSecurityDir_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.withCopyHaps = true;
    std::vector<std::string> bundlePaths;
    ErrCode res = installer.CopyHapsToSecurityDir(installParam, bundlePaths);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: FindSignatureFileDir_0010
 * @tc.name: test FindSignatureFileDir
 * @tc.desc: 1.Test the FindSignatureFileDir
*/
HWTEST_F(BmsBundleOverlayCheckerTest, FindSignatureFileDir_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string signatureFileDir;

    installer.verifyCodeParams_.emplace(TEST_MODULE_NAME, TEST_MODULE_NAME);
    ErrCode res = installer.FindSignatureFileDir(TEST_MODULE_NAME + "1", signatureFileDir);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED);
}

/**
 * @tc.number: FindSignatureFileDir_0020
 * @tc.name: test FindSignatureFileDir
 * @tc.desc: 1.Test the FindSignatureFileDir
*/
HWTEST_F(BmsBundleOverlayCheckerTest, FindSignatureFileDir_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string signatureFileDir;

    installer.verifyCodeParams_.emplace(TEST_MODULE_NAME, TEST_MODULE_NAME);
    ErrCode res = installer.FindSignatureFileDir(TEST_MODULE_NAME, signatureFileDir);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
}

/**
 * @tc.number: FindSignatureFileDir_0030
 * @tc.name: test FindSignatureFileDir
 * @tc.desc: 1.Test the FindSignatureFileDir
*/
HWTEST_F(BmsBundleOverlayCheckerTest, FindSignatureFileDir_0030, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string signatureFileDir = "testModuleName.sig";

    installer.verifyCodeParams_.emplace(TEST_MODULE_NAME, signatureFileDir);
    ErrCode res = installer.FindSignatureFileDir(TEST_MODULE_NAME, signatureFileDir);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED);
}

/**
 * @tc.number: AddOverlayModuleStates_0100
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of AddOverlayModuleStates.
 *           2.system run normally.
 */
HWTEST_F(BmsBundleOverlayCheckerTest, AddOverlayModuleStates_0100, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t userIdNew = -3;
    dataMgr->AddUserId(userIdNew);

    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    innerBundleInfo.innerBundleUserInfos_.emplace(TEST_BUNDLE_NAME, userInfo);
    overlayDataMgr.AddOverlayModuleStates(innerBundleInfo, userInfo);
    EXPECT_EQ(userInfo.bundleUserInfo.userId, USERID);
    dataMgr->RemoveUserId(userIdNew);
}

/**
 * @tc.number: AddOverlayModuleStates_0200
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of AddOverlayModuleStates.
 *           2.system run normally.
 */
HWTEST_F(BmsBundleOverlayCheckerTest, AddOverlayModuleStates_0200, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t userIdNew = -3;
    dataMgr->AddUserId(userIdNew);

    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    std::string item = "1";
    userInfo.bundleUserInfo.overlayModulesState.push_back(item);
    innerBundleInfo.innerBundleUserInfos_.emplace(TEST_BUNDLE_NAME, userInfo);
    overlayDataMgr.AddOverlayModuleStates(innerBundleInfo, userInfo);
    EXPECT_EQ(userInfo.bundleUserInfo.userId, USERID);
    dataMgr->RemoveUserId(userIdNew);
}

/**
 * @tc.number: AddOverlayModuleStates_0300
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of AddOverlayModuleStates.
 *           2.system run normally.
 */
HWTEST_F(BmsBundleOverlayCheckerTest, AddOverlayModuleStates_0300, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t userIdNew = -3;
    dataMgr->AddUserId(userIdNew);

    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    std::string item = "test_1";
    userInfo.bundleUserInfo.overlayModulesState.push_back(item);
    innerBundleInfo.innerBundleUserInfos_.emplace(TEST_BUNDLE_NAME, userInfo);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "test";
    innerBundleInfo.innerModuleInfos_.emplace(TEST_BUNDLE_NAME, innerModuleInfo);
    innerBundleInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    innerBundleInfo.SetTargetBundleName(TEST_BUNDLE_NAME);
    overlayDataMgr.AddOverlayModuleStates(innerBundleInfo, userInfo);
    EXPECT_EQ(userInfo.bundleUserInfo.userId, USERID);
    dataMgr->RemoveUserId(userIdNew);
}

/**
 * @tc.number: AddOverlayModuleStates_0400
 * @tc.name: test OverlayDataMgr.
 * @tc.desc: 1.OverlayDataMgr of AddOverlayModuleStates.
 *           2.system run normally.
 */
HWTEST_F(BmsBundleOverlayCheckerTest, AddOverlayModuleStates_0400, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t userIdNew = -3;
    dataMgr->AddUserId(userIdNew);

    OverlayDataMgr overlayDataMgr;
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    std::string item = "test_1";
    userInfo.bundleUserInfo.overlayModulesState.push_back(item);
    innerBundleInfo.innerBundleUserInfos_.emplace(TEST_BUNDLE_NAME, userInfo);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "test";
    innerBundleInfo.innerModuleInfos_.emplace(TEST_BUNDLE_NAME, innerModuleInfo);
    innerBundleInfo.SetOverlayType(OverlayType::OVERLAY_EXTERNAL_BUNDLE);
    innerBundleInfo.SetTargetBundleName(TEST_BUNDLE_NAME);
    overlayDataMgr.AddOverlayModuleStates(innerBundleInfo, userInfo);
    EXPECT_EQ(userInfo.bundleUserInfo.userId, USERID);
    dataMgr->RemoveUserId(userIdNew);
}

/**
 * @tc.number: BaseBundleInstaller_0100
 * @tc.name: test CheckAppService
 * @tc.desc: 1.Test CheckAppService the BaseBundleInstaller
*/
HWTEST_F(BmsBundleOverlayCheckerTest, BaseBundleInstaller_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BaseBundleInstaller> installer = std::make_shared<BaseBundleInstaller>();
    ASSERT_NE(installer, nullptr);

    InnerBundleInfo newInfo;
    newInfo.SetApplicationBundleType(BundleType::APP_SERVICE_FWK);
    InnerBundleInfo oldInfo;
    bool isAppExist = false;
    ErrCode ret = installer->CheckAppService(newInfo, oldInfo, isAppExist);
    EXPECT_EQ(ret, ERR_APP_SERVICE_FWK_INSTALL_TYPE_FAILED);
}

/**
 * @tc.number: BaseBundleInstaller_0200
 * @tc.name: test CheckSingleton
 * @tc.desc: 1.Test CheckSingleton the BaseBundleInstaller
*/
HWTEST_F(BmsBundleOverlayCheckerTest, BaseBundleInstaller_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BaseBundleInstaller> installer = std::make_shared<BaseBundleInstaller>();
    ASSERT_NE(installer, nullptr);

    InnerBundleInfo info;
    int32_t userId = 100;
    installer->isAppService_ = true;
    ErrCode ret = installer->CheckSingleton(info, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON);
}

/**
 * @tc.number: BaseBundleInstaller_0300
 * @tc.name: test CheckInstallCondition
 * @tc.desc: 1.Test CheckInstallCondition the BaseBundleInstaller
*/
HWTEST_F(BmsBundleOverlayCheckerTest, BaseBundleInstaller_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BaseBundleInstaller> installer = std::make_shared<BaseBundleInstaller>();
    ASSERT_NE(installer, nullptr);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::string bundleName;
    bool isUninstalled = false;
    bool isKeepData = false;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    std::vector<std::string> extensionDataGroupIds;
    std::vector<std::string> bundleDataGroupIds;
    std::vector<std::string> validGroupIds;
    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInfo;


    innerBundleInfo.SetApplicationBundleType(BundleType::ATOMIC_SERVICE);
    newInfos.emplace("key", innerBundleInfo);
    installer->isAppExist_ = false;

    installer->dataMgr_ = nullptr;
    installer->MarkPreInstallState(bundleName, isUninstalled);

    installer->DeleteEncryptionKeyId(oldInfo, isKeepData);

    installer->UpdateExtensionSandboxInfo(newInfos, hapVerifyRes);

    extensionDataGroupIds.push_back("test1");
    extensionDataGroupIds.push_back("test2");
    extensionDataGroupIds.push_back("test3");
    bundleDataGroupIds.push_back("test");
    installer->GetValidDataGroupIds(extensionDataGroupIds, bundleDataGroupIds, validGroupIds);

    installer->GetRemoveExtensionDirs(newInfos, oldInfo);

    installer->GenerateOdid(infos, hapVerifyRes);

    bool isSysCapValid = false;
    ErrCode ret = installer->CheckInstallCondition(hapVerifyRes, infos, isSysCapValid);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BaseBundleInstaller_0400
 * @tc.name: test NeedDeleteOldNativeLib
 * @tc.desc: 1.Test NeedDeleteOldNativeLib the BaseBundleInstaller
*/
HWTEST_F(BmsBundleOverlayCheckerTest, BaseBundleInstaller_0400, Function | SmallTest | Level0)
{
    std::shared_ptr<BaseBundleInstaller> installer = std::make_shared<BaseBundleInstaller>();
    ASSERT_NE(installer, nullptr);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo innerBundleInfo;
    newInfos.emplace("key", innerBundleInfo);
    InnerBundleInfo oldInfo;
    oldInfo.SetNativeLibraryPath("test/path");
    BundleInfo bundleInfo;
    bundleInfo.versionCode = 0;
    oldInfo.SetBaseBundleInfo(bundleInfo);
    installer->isAppExist_ = true;
    installer->versionCode_ = 100;
    bool ret = installer->NeedDeleteOldNativeLib(newInfos, oldInfo);
    EXPECT_TRUE(ret);

    bundleInfo.versionCode = 200;
    oldInfo.SetBaseBundleInfo(bundleInfo);
    oldInfo.SetApplicationBundleType(BundleType::APP_SERVICE_FWK);
    ret = installer->NeedDeleteOldNativeLib(newInfos, oldInfo);
    EXPECT_FALSE(ret);
}
} // OHOS