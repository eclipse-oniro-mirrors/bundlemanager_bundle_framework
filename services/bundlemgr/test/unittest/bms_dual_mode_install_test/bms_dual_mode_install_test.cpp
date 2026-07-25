/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

// Unified unit tests for dual-mode app install: DualModeHelper utility + BaseBundleInstaller
// dual-mode hooks. Expose private/protected members so we can drive every branch directly via the
// DualModeHelper cache (cachedMode_/cachedDeviceType_) and BaseBundleInstaller members, without
// reading or modifying real system parameters. IsTestDualMode=true system-parameter branches
// (GetSysMode/InitializeCache/UpdateModeCache) are intentionally not covered.
#define private public
#define protected public
#include <gtest/gtest.h>
#include <string>
#include <unordered_map>

#include "appexecfwk_errors.h"
#include "application_info.h"
#include "base_bundle_installer.h"
#include "bundle_data_mgr.h"
#include "bundle_data_storage_rdb.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_service_constants.h"
#include "dual_mode_helper.h"
#include "inner_bundle_info.h"
#include "install_param.h"
#include "message_parcel.h"
#include "nlohmann/json.hpp"
#include "bundle_resource/bundle_resource_process.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.test";
const std::string PREFIXED_NAME = "+clone-10000+" + BUNDLE_NAME;
const std::string CLONE_APP_NAME = "+clone-1+" + BUNDLE_NAME;  // regular clone (appIndex 1..5), not dual-mode
const int32_t TEST_USERID = 100;
}  // namespace

class BmsDualModeInstallTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown() {}
};

// Reset DualModeHelper cache before each case so cases do not affect each other. No system parameter.
void BmsDualModeInstallTest::SetUp()
{
    DualModeHelper::cachedMode_.clear();
    DualModeHelper::cachedDeviceType_.clear();
}

static void SetDualModeCache(const std::string &mode, const std::string &deviceType)
{
    DualModeHelper::cachedMode_ = mode;
    DualModeHelper::cachedDeviceType_ = deviceType;
}

static void EnableSecondaryMode()
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_PC, ServiceConstants::DUAL_MODE_DEVICE_TABLET);
}

// Build a category-7 (APP_CATEGORY_DIFF_PACKAGE) InnerBundleInfo; mark as dual-mode clone if needed.
static InnerBundleInfo MakeCat7Info(bool isClone)
{
    InnerBundleInfo info;
    info.SetAppCategory(AppCategory::APP_CATEGORY_DIFF_PACKAGE);
    if (isClone) {
        info.SetDualModeCloneApp(true);
    }
    return info;
}

// Build an APP-type InnerBundleInfo (bundleName set) so GetBundleResourceInfo returns true without
// a real hap (ConvertToBundleResourceInfo yields one bundle-level ResourceInfo; GetAbilityResourceInfos
// returns empty for an info with no abilities). isClone drives the dual-mode flag carried onto each
// ResourceInfo; type drives the SHARED/SKILL/APP_SERVICE_FWK skip branches; name="" drives
// the GetBundleResourceInfo empty-name failure branch.
static InnerBundleInfo MakeResourceInfo(bool isClone, BundleType type = BundleType::APP,
    const std::string &name = BUNDLE_NAME)
{
    InnerBundleInfo info;
    ApplicationInfo appInfo;
    appInfo.bundleName = name;
    appInfo.bundleType = type;
    info.SetBaseApplicationInfo(appInfo);
    if (isClone) {
        info.SetDualModeCloneApp(true);
    }
    return info;
}

// APP_SERVICE_FWK bundle whose IsHsp() is true (single MODULE_TYPE_SHARED module) — exercises the
// (APP_SERVICE_FWK && IsHsp) skip branch of GetAllResourceInfo.
static InnerBundleInfo MakeHspAppServiceFwkInfo()
{
    InnerBundleInfo info = MakeResourceInfo(false, BundleType::APP_SERVICE_FWK);
    InnerModuleInfo moduleInfo;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_SHARED;
    info.innerModuleInfos_["module1"] = moduleInfo;
    return info;
}

// Build a fresh BundleDataMgr, register userId (so HasUserId is true) and install it into the global
// BundleMgrService — which is where the static BundleResourceProcess::GetAllResourceInfo fetches its
// dataMgr. Caller fills bundleInfos_/tempBundleInfos_ on the returned manager.
static std::shared_ptr<BundleDataMgr> InstallTestDataMgr(int32_t userId)
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->multiUserIdsSet_.insert(userId);
    service->dataMgr_ = dataMgr;
    return dataMgr;
}

// ====================== DualModeHelper::IsDualModeDevice ======================

HWTEST_F(BmsDualModeInstallTest, IsDualModeDevice_0100, Function | SmallTest | Level0)
{
    SetDualModeCache("", "");
    EXPECT_FALSE(DualModeHelper::IsDualModeDevice());
}

HWTEST_F(BmsDualModeInstallTest, IsDualModeDevice_0200, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_PC, ServiceConstants::DUAL_MODE_DEVICE_TABLET);
    EXPECT_TRUE(DualModeHelper::IsDualModeDevice());
}

// ====================== DualModeHelper::IsSecondaryMode ======================

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0100, Function | SmallTest | Level0)
{
    SetDualModeCache("", ServiceConstants::DUAL_MODE_DEVICE_TABLET);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0200, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_PC, ServiceConstants::DUAL_MODE_DEVICE_TABLET);
    EXPECT_TRUE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0300, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_PAD, ServiceConstants::DUAL_MODE_DEVICE_2IN1);
    EXPECT_TRUE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0400, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_PC, ServiceConstants::DUAL_MODE_DEVICE_2IN1);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0500, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_PAD, ServiceConstants::DUAL_MODE_DEVICE_TABLET);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0600, Function | SmallTest | Level0)
{
    SetDualModeCache("invalidMode", ServiceConstants::DUAL_MODE_DEVICE_TABLET);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
}

// ====================== DualModeHelper::IsDiffPackageCategory ======================

HWTEST_F(BmsDualModeInstallTest, IsDiffPackageCategory_0100, Function | SmallTest | Level0)
{
    EXPECT_TRUE(DualModeHelper::IsDiffPackageCategory(AppCategory::APP_CATEGORY_DIFF_PACKAGE));
}

HWTEST_F(BmsDualModeInstallTest, IsDiffPackageCategory_0200, Function | SmallTest | Level0)
{
    auto combo = static_cast<AppCategory>(
        static_cast<uint32_t>(AppCategory::APP_CATEGORY_DIFF_PACKAGE) |
        static_cast<uint32_t>(AppCategory::APP_CATEGORY_TABLET_ONLY));
    EXPECT_TRUE(DualModeHelper::IsDiffPackageCategory(combo));
}

HWTEST_F(BmsDualModeInstallTest, IsDiffPackageCategory_0300, Function | SmallTest | Level0)
{
    EXPECT_FALSE(DualModeHelper::IsDiffPackageCategory(AppCategory::APP_CATEGORY_UNSPECIFIED));
}

HWTEST_F(BmsDualModeInstallTest, IsDiffPackageCategory_0400, Function | SmallTest | Level0)
{
    EXPECT_FALSE(DualModeHelper::IsDiffPackageCategory(AppCategory::APP_CATEGORY_TABLET_ONLY));
}

// ====================== DualModeHelper::NeedDualModeHandle ======================

HWTEST_F(BmsDualModeInstallTest, NeedDualModeHandle_0100, Function | SmallTest | Level0)
{
    EnableSecondaryMode();
    EXPECT_TRUE(DualModeHelper::NeedDualModeHandle(AppCategory::APP_CATEGORY_DIFF_PACKAGE));
}

HWTEST_F(BmsDualModeInstallTest, NeedDualModeHandle_0200, Function | SmallTest | Level0)
{
    EnableSecondaryMode();
    EXPECT_FALSE(DualModeHelper::NeedDualModeHandle(AppCategory::APP_CATEGORY_TABLET_ONLY));
}

HWTEST_F(BmsDualModeInstallTest, NeedDualModeHandle_0300, Function | SmallTest | Level0)
{
    SetDualModeCache("", "");
    EXPECT_FALSE(DualModeHelper::NeedDualModeHandle(AppCategory::APP_CATEGORY_DIFF_PACKAGE));
}

HWTEST_F(BmsDualModeInstallTest, NeedDualModeHandle_0400, Function | SmallTest | Level0)
{
    SetDualModeCache("", "");
    EXPECT_FALSE(DualModeHelper::NeedDualModeHandle(AppCategory::APP_CATEGORY_UNSPECIFIED));
}

// ====================== DualModeHelper::GetDualModeBundleName ======================

HWTEST_F(BmsDualModeInstallTest, GetDualModeBundleName_0100, Function | SmallTest | Level0)
{
    std::string cloneName = DualModeHelper::GetDualModeBundleName(BUNDLE_NAME);
    std::string expectedPrefix = std::string(ServiceConstants::CLONE_PREFIX) +
        std::to_string(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX) + "+";
    EXPECT_EQ(cloneName.find(expectedPrefix), 0u);
    EXPECT_NE(cloneName.find(BUNDLE_NAME), std::string::npos);
}

// ====================== DualModeHelper::ParseDualModeBundleName ======================

HWTEST_F(BmsDualModeInstallTest, ParseDualModeBundleName_0100, Function | SmallTest | Level0)
{
    std::string cloneName = DualModeHelper::GetDualModeBundleName(BUNDLE_NAME);
    std::string origin;
    EXPECT_TRUE(DualModeHelper::ParseDualModeBundleName(cloneName, origin));
    EXPECT_EQ(origin, BUNDLE_NAME);
}

HWTEST_F(BmsDualModeInstallTest, ParseDualModeBundleName_0200, Function | SmallTest | Level0)
{
    std::string origin;
    EXPECT_FALSE(DualModeHelper::ParseDualModeBundleName(CLONE_APP_NAME, origin));
}

HWTEST_F(BmsDualModeInstallTest, ParseDualModeBundleName_0300, Function | SmallTest | Level0)
{
    std::string origin;
    EXPECT_FALSE(DualModeHelper::ParseDualModeBundleName(BUNDLE_NAME, origin));
}

// ====================== DualModeHelper::IsDualModeCloneKey ======================

HWTEST_F(BmsDualModeInstallTest, IsDualModeCloneKey_0100, Function | SmallTest | Level0)
{
    EXPECT_TRUE(DualModeHelper::IsDualModeCloneKey(DualModeHelper::GetDualModeBundleName(BUNDLE_NAME)));
}

HWTEST_F(BmsDualModeInstallTest, IsDualModeCloneKey_0200, Function | SmallTest | Level0)
{
    EXPECT_FALSE(DualModeHelper::IsDualModeCloneKey(CLONE_APP_NAME));
}

HWTEST_F(BmsDualModeInstallTest, IsDualModeCloneKey_0300, Function | SmallTest | Level0)
{
    EXPECT_FALSE(DualModeHelper::IsDualModeCloneKey(BUNDLE_NAME));
}

HWTEST_F(BmsDualModeInstallTest, IsDualModeCloneKey_0400, Function | SmallTest | Level0)
{
    EXPECT_FALSE(DualModeHelper::IsDualModeCloneKey(""));
}

// ====================== BaseBundleInstaller::GetEffectiveBundleName ======================

HWTEST_F(BmsDualModeInstallTest, GetEffectiveBundleName_0100, Function | SmallTest | Level0)
{
    // no-arg, dualModeBundleName_ empty -> returns bundleName_
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.dualModeBundleName_.clear();
    EXPECT_EQ(installer.GetEffectiveBundleName(), BUNDLE_NAME);
}

HWTEST_F(BmsDualModeInstallTest, GetEffectiveBundleName_0200, Function | SmallTest | Level0)
{
    // no-arg, dualModeBundleName_ non-empty -> returns dualModeBundleName_
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.dualModeBundleName_ = PREFIXED_NAME;
    EXPECT_EQ(installer.GetEffectiveBundleName(), PREFIXED_NAME);
}

HWTEST_F(BmsDualModeInstallTest, GetEffectiveBundleName_0300, Function | SmallTest | Level0)
{
    // InnerBundleInfo overload, dualModeBundleName_ empty + non-clone -> returns original name
    BaseBundleInstaller installer;
    installer.dualModeBundleName_.clear();
    InnerBundleInfo info;
    EXPECT_EQ(installer.GetEffectiveBundleName(info), info.GetBundleName());
}

HWTEST_F(BmsDualModeInstallTest, GetEffectiveBundleName_0400, Function | SmallTest | Level0)
{
    // InnerBundleInfo overload, dualModeBundleName_ non-empty -> returns dualModeBundleName_ (ignores info)
    BaseBundleInstaller installer;
    installer.dualModeBundleName_ = PREFIXED_NAME;
    InnerBundleInfo info;
    EXPECT_EQ(installer.GetEffectiveBundleName(info), PREFIXED_NAME);
}

HWTEST_F(BmsDualModeInstallTest, GetEffectiveBundleName_0500, Function | SmallTest | Level0)
{
    // InnerBundleInfo overload, dualModeBundleName_ empty + clone app -> returns prefixed name.
    // This is the cross-flow (uninstall/recover) path where dualModeBundleName_ is unset on a fresh
    // installer instance; the persisted IsDualModeCloneApp flag must still resolve to the isolated
    // name instead of the original.
    BaseBundleInstaller installer;
    installer.dualModeBundleName_.clear();
    InnerBundleInfo info = MakeCat7Info(true);  // APP_CATEGORY_DIFF_PACKAGE + IsDualModeCloneApp=true
    EXPECT_EQ(installer.GetEffectiveBundleName(info), DualModeHelper::GetDualModeBundleName(info.GetBundleName()));
    EXPECT_NE(installer.GetEffectiveBundleName(info), info.GetBundleName());
}

// ====================== BaseBundleInstaller::InitDualModeBundleName ======================

HWTEST_F(BmsDualModeInstallTest, InitDualModeBundleName_0100, Function | SmallTest | Level0)
{
    // secondary mode + category 7 -> set prefixed name
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_DIFF_PACKAGE;
    installer.InitDualModeBundleName(installParam);
    EXPECT_EQ(installer.dualModeBundleName_, DualModeHelper::GetDualModeBundleName(BUNDLE_NAME));
    EXPECT_NE(installer.dualModeBundleName_.find("10000"), std::string::npos);
}

HWTEST_F(BmsDualModeInstallTest, InitDualModeBundleName_0200, Function | SmallTest | Level0)
{
    // primary mode + category 7 -> clear
    SetDualModeCache("", "");
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.dualModeBundleName_ = "stale";
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_DIFF_PACKAGE;
    installer.InitDualModeBundleName(installParam);
    EXPECT_TRUE(installer.dualModeBundleName_.empty());
}

HWTEST_F(BmsDualModeInstallTest, InitDualModeBundleName_0300, Function | SmallTest | Level0)
{
    // secondary mode + non-category-7 -> clear
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.dualModeBundleName_ = "stale";
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_TABLET_ONLY;
    installer.InitDualModeBundleName(installParam);
    EXPECT_TRUE(installer.dualModeBundleName_.empty());
}

// ====================== BaseBundleInstaller::SetDualModeAppInfo ======================

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0100, Function | SmallTest | Level0)
{
    // not a dual-mode device -> early return, no mutation
    SetDualModeCache("", "");
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = InnerBundleInfo();
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_DIFF_PACKAGE;
    installer.SetDualModeAppInfo(installParam, infos);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0200, Function | SmallTest | Level0)
{
    // dual-mode device but empty infos -> early return, no crash
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;  // empty
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_DIFF_PACKAGE;
    installer.SetDualModeAppInfo(installParam, infos);
    EXPECT_TRUE(infos.empty());
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0300, Function | SmallTest | Level0)
{
    // dual-mode device + category 7 (clone app) -> SetDualModeCloneApp(true) + appCategory
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = InnerBundleInfo();
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_DIFF_PACKAGE;
    installer.SetDualModeAppInfo(installParam, infos);
    EXPECT_TRUE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppCategory(), AppCategory::APP_CATEGORY_DIFF_PACKAGE);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0400, Function | SmallTest | Level0)
{
    // dual-mode device + non-category-7 -> appCategory set, isDualModeCloneApp stays false
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = InnerBundleInfo();
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_TABLET_ONLY;
    installer.SetDualModeAppInfo(installParam, infos);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppCategory(), AppCategory::APP_CATEGORY_TABLET_ONLY);
}

// ====================== BaseBundleInstaller::CheckDualModeCategoryConsistency ======================

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0100, Function | SmallTest | Level0)
{
    // not a dual-mode device -> ERR_OK even if category crosses 7
    SetDualModeCache("", "");
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    InnerBundleInfo oldInfo;
    oldInfo.SetAppCategory(AppCategory::APP_CATEGORY_DIFF_PACKAGE);
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_TABLET_ONLY;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam), OHOS::ERR_OK);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0200, Function | SmallTest | Level0)
{
    // app does not exist -> ERR_OK (no consistency to check)
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.isAppExist_ = false;
    InnerBundleInfo oldInfo;
    oldInfo.SetAppCategory(AppCategory::APP_CATEGORY_DIFF_PACKAGE);
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_TABLET_ONLY;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam), OHOS::ERR_OK);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0300, Function | SmallTest | Level0)
{
    // dual-mode + app exists + cross 7<->non-7 -> ERR_APPEXECFWK_INSTALL_PARAM_ERROR
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    InnerBundleInfo oldInfo;
    oldInfo.SetAppCategory(AppCategory::APP_CATEGORY_DIFF_PACKAGE);
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_TABLET_ONLY;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam),
        OHOS::ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0400, Function | SmallTest | Level0)
{
    // dual-mode + both category 7 -> consistent -> ERR_OK
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    InnerBundleInfo oldInfo;
    oldInfo.SetAppCategory(AppCategory::APP_CATEGORY_DIFF_PACKAGE);
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_DIFF_PACKAGE;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam), OHOS::ERR_OK);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0500, Function | SmallTest | Level0)
{
    // dual-mode + both non-category-7 -> consistent -> ERR_OK
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    InnerBundleInfo oldInfo;
    oldInfo.SetAppCategory(AppCategory::APP_CATEGORY_TABLET_ONLY);
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_2IN1_ONLY;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam), OHOS::ERR_OK);
}

// ====================== BundleDataMgr::ClassifyDualModeAppsNoLock ======================
// dataMgr is a process-wide singleton obtained via BundleMgrService; clear bundleInfos_ /
// tempBundleInfos_ before each case to avoid cross-case residue.

HWTEST_F(BmsDualModeInstallTest, ClassifyDualModeAppsNoLock_0100, Function | SmallTest | Level0)
{
    // not a dual-mode device -> early return, bundleInfos_ unchanged
    SetDualModeCache("", "");
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();
    dataMgr->bundleInfos_[DualModeHelper::GetDualModeBundleName(BUNDLE_NAME)] = MakeCat7Info(true);
    dataMgr->ClassifyDualModeAppsNoLock();
    EXPECT_EQ(dataMgr->bundleInfos_.size(), 1u);
    EXPECT_TRUE(dataMgr->tempBundleInfos_.empty());
}

HWTEST_F(BmsDualModeInstallTest, ClassifyDualModeAppsNoLock_0200, Function | SmallTest | Level0)
{
    // primary mode (pc + 2in1): prefixed clone app -> moved to tempBundleInfos_ (original-name key)
    SetDualModeCache(ServiceConstants::DUAL_MODE_PC, ServiceConstants::DUAL_MODE_DEVICE_2IN1);
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();
    dataMgr->bundleInfos_[DualModeHelper::GetDualModeBundleName(BUNDLE_NAME)] = MakeCat7Info(true);
    dataMgr->ClassifyDualModeAppsNoLock();
    EXPECT_TRUE(dataMgr->bundleInfos_.empty());
    EXPECT_EQ(dataMgr->tempBundleInfos_.count(BUNDLE_NAME), 1u);
}

HWTEST_F(BmsDualModeInstallTest, ClassifyDualModeAppsNoLock_0300, Function | SmallTest | Level0)
{
    // secondary mode (pc + tablet) with both primary (original key) and clone (prefixed key):
    // clone goes to bundleInfos_ (visible), primary swapped to tempBundleInfos_ (hidden)
    EnableSecondaryMode();
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeCat7Info(false);  // primary install, original key
    dataMgr->bundleInfos_[DualModeHelper::GetDualModeBundleName(BUNDLE_NAME)] = MakeCat7Info(true);
    dataMgr->ClassifyDualModeAppsNoLock();
    ASSERT_EQ(dataMgr->bundleInfos_.count(BUNDLE_NAME), 1u);
    EXPECT_TRUE(dataMgr->bundleInfos_[BUNDLE_NAME].IsDualModeCloneApp());  // clone visible
    ASSERT_EQ(dataMgr->tempBundleInfos_.count(BUNDLE_NAME), 1u);
    EXPECT_FALSE(dataMgr->tempBundleInfos_[BUNDLE_NAME].IsDualModeCloneApp());  // primary hidden
}

HWTEST_F(BmsDualModeInstallTest, ClassifyDualModeAppsNoLock_0400, Function | SmallTest | Level0)
{
    // non-category-7 app is never classified, stays in bundleInfos_
    EnableSecondaryMode();
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();
    InnerBundleInfo normal;
    normal.SetAppCategory(AppCategory::APP_CATEGORY_TABLET_ONLY);
    dataMgr->bundleInfos_[BUNDLE_NAME] = normal;
    dataMgr->ClassifyDualModeAppsNoLock();
    EXPECT_EQ(dataMgr->bundleInfos_.count(BUNDLE_NAME), 1u);
    EXPECT_TRUE(dataMgr->tempBundleInfos_.empty());
}

HWTEST_F(BmsDualModeInstallTest, ClassifyDualModeAppsNoLock_0500, Function | SmallTest | Level0)
{
    // primary mode: category-7 app under original key (non-prefixed) is NOT moved
    SetDualModeCache(ServiceConstants::DUAL_MODE_PC, ServiceConstants::DUAL_MODE_DEVICE_2IN1);
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeCat7Info(false);  // original key, not clone
    dataMgr->ClassifyDualModeAppsNoLock();
    EXPECT_EQ(dataMgr->bundleInfos_.count(BUNDLE_NAME), 1u);
    EXPECT_TRUE(dataMgr->tempBundleInfos_.empty());
}

HWTEST_F(BmsDualModeInstallTest, ClassifyDualModeAppsNoLock_0600, Function | SmallTest | Level0)
{
    // secondary mode: category-7 primary (original key, non-clone) with NO clone counterpart in
    // tempBundleInfos_. The swap pass (bundle_data_mgr.cpp:386-395) skips it because there is no
    // temp peer to swap with; the tail guard (:397-408) must hide it in tempBundleInfos_.
    // Without that guard the primary would wrongly stay visible in secondary mode.
    EnableSecondaryMode();
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeCat7Info(false);  // primary only, no clone installed
    dataMgr->ClassifyDualModeAppsNoLock();
    EXPECT_TRUE(dataMgr->bundleInfos_.empty());  // primary hidden in secondary mode
    ASSERT_EQ(dataMgr->tempBundleInfos_.count(BUNDLE_NAME), 1u);
    EXPECT_FALSE(dataMgr->tempBundleInfos_[BUNDLE_NAME].IsDualModeCloneApp());  // the hidden primary
}

// ====================== ResourceInfo::GetOriginalKey (extensionAbilityType branch, resource_info.cpp:70-72) =====
// GetOriginalKey mirrors GetKey()'s assembly (bundleName[/module/ability], optional "_index"
// prefix, optional "+extensionType" suffix) but NEVER prepends the "+clone-10000+" clone prefix —
// BundleResourceIconRdb keeps keys on the original bundleName. Cases focus on the
// extensionAbilityType_ append (lines 70-72) and the no-prefix guarantee for clone apps.

HWTEST_F(BmsDualModeInstallTest, ResourceInfo_GetOriginalKey_0100, Function | SmallTest | Level0)
{
    // Bundle-level key: bundleName only.
    ResourceInfo info;
    info.bundleName_ = BUNDLE_NAME;
    EXPECT_EQ(info.GetOriginalKey(), BUNDLE_NAME);
}

HWTEST_F(BmsDualModeInstallTest, ResourceInfo_GetOriginalKey_0200, Function | SmallTest | Level0)
{
    // extensionAbilityType_ >= 0 branch (resource_info.cpp:70-72): appends "+" + type at the end.
    ResourceInfo info;
    info.bundleName_ = BUNDLE_NAME;
    info.extensionAbilityType_ = 3;
    EXPECT_EQ(info.GetOriginalKey(), BUNDLE_NAME + "+3");
}

HWTEST_F(BmsDualModeInstallTest, ResourceInfo_GetOriginalKey_0300, Function | SmallTest | Level0)
{
    // Core contract: a dual-mode clone app does NOT get the "+clone-10000+" prefix in GetOriginalKey,
    // while GetKey() still isolates it. This is why BundleResourceIconRdb uses GetOriginalKey.
    ResourceInfo info;
    info.bundleName_ = BUNDLE_NAME;
    info.isDualModeCloneApp_ = true;
    EXPECT_EQ(info.GetOriginalKey(), BUNDLE_NAME);   // original name, no prefix
    EXPECT_EQ(info.GetKey(), PREFIXED_NAME);         // GetKey still isolates the clone
}

HWTEST_F(BmsDualModeInstallTest, ResourceInfo_GetOriginalKey_0400, Function | SmallTest | Level0)
{
    // Full assembly with the extension suffix (lines 70-72): index_bundle/module/ability+type.
    // Clone flag is set but ignored by GetOriginalKey, so no prefix is prepended.
    ResourceInfo info;
    info.bundleName_ = BUNDLE_NAME;
    info.moduleName_ = "m";
    info.abilityName_ = "a";
    info.appIndex_ = 2;
    info.extensionAbilityType_ = 5;
    info.isDualModeCloneApp_ = true;
    EXPECT_EQ(info.GetOriginalKey(), "2_" + BUNDLE_NAME + "/m/a+5");
}

// ====================== ResourceInfo::ParseKey (dual-mode clone-key strip branch, resource_info.cpp:82-88) ======
// ParseKey reverses GetKey(): it first strips a leading "+clone-10000+" prefix (lines 82-88 —
// reusing '+' would otherwise corrupt extension-type parsing), then splits "+extensionType",
// "_index" and "/module/ability". Cases focus on the clone-prefix strip and isDualModeCloneApp_ latch.

HWTEST_F(BmsDualModeInstallTest, ResourceInfo_ParseKey_0100, Function | SmallTest | Level0)
{
    // Dual-mode clone key (resource_info.cpp:82-88): prefix stripped, isDualModeCloneApp_ latched true.
    ResourceInfo info;
    info.ParseKey(PREFIXED_NAME);
    EXPECT_TRUE(info.isDualModeCloneApp_);
    EXPECT_EQ(info.bundleName_, BUNDLE_NAME);
    EXPECT_EQ(info.extensionAbilityType_, -1);
    EXPECT_EQ(info.appIndex_, 0);
}

HWTEST_F(BmsDualModeInstallTest, ResourceInfo_ParseKey_0200, Function | SmallTest | Level0)
{
    // Plain key (no "+clone-10000+" prefix): IsDualModeCloneKey guard is false, so the clone flag
    // stays false and bundleName_ is parsed verbatim.
    ResourceInfo info;
    info.ParseKey(BUNDLE_NAME);
    EXPECT_FALSE(info.isDualModeCloneApp_);
    EXPECT_EQ(info.bundleName_, BUNDLE_NAME);
}

HWTEST_F(BmsDualModeInstallTest, ResourceInfo_ParseKey_0300, Function | SmallTest | Level0)
{
    // Trailing "+type" suffix is parsed as extensionAbilityType_ after the (absent) clone strip.
    ResourceInfo info;
    info.ParseKey(BUNDLE_NAME + "+3");
    EXPECT_FALSE(info.isDualModeCloneApp_);
    EXPECT_EQ(info.bundleName_, BUNDLE_NAME);
    EXPECT_EQ(info.extensionAbilityType_, 3);
}

HWTEST_F(BmsDualModeInstallTest, ResourceInfo_ParseKey_0400, Function | SmallTest | Level0)
{
    // Composite key with module/ability: split on "/" into moduleName_/abilityName_.
    ResourceInfo info;
    info.ParseKey(BUNDLE_NAME + "/m/a");
    EXPECT_FALSE(info.isDualModeCloneApp_);
    EXPECT_EQ(info.bundleName_, BUNDLE_NAME);
    EXPECT_EQ(info.moduleName_, "m");
    EXPECT_EQ(info.abilityName_, "a");
}

// ====================== BundleResourceProcess::GetAllResourceInfo (allTempBundleNames) ======================
// Drive the tempBundleInfos_ loop (bundle_resource_process.cpp:105-120) plus the joint-emptiness guard
// (:75-78), userId guard (:69-72) and null-dataMgr guard (:65-68). GetBundleResourceInfo succeeds for
// any non-empty bundleName with bundleType != SHARED/SKILL (no real hap needed), so the append /
// same-name merge / clone-flag branches are all reachable. The FetchTempBundleInfo-fail branch (:107-109)
// is defensive — the key comes from GetAllTempBundleName over the same map under the same lock, so it
// cannot fail in a single-threaded test; left uncovered by design.

HWTEST_F(BmsDualModeInstallTest, GetAllResourceInfo_0100, Function | SmallTest | Level0)
{
    // both bundleInfos_ and tempBundleInfos_ empty -> early return false (allTempBundleNames.empty()
    // branch of the joint guard, :75-78)
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    EXPECT_FALSE(BundleResourceProcess::GetAllResourceInfo(TEST_USERID, resourceInfos));
    EXPECT_TRUE(resourceInfos.empty());
}

HWTEST_F(BmsDualModeInstallTest, GetAllResourceInfo_0200, Function | SmallTest | Level0)
{
    // userId not registered -> return false (:69-72); tempBundleInfos_ content never reached
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeResourceInfo(true);
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    EXPECT_FALSE(BundleResourceProcess::GetAllResourceInfo(TEST_USERID + 1, resourceInfos));
    EXPECT_TRUE(resourceInfos.empty());
}

HWTEST_F(BmsDualModeInstallTest, GetAllResourceInfo_0300, Function | SmallTest | Level0)
{
    // tempBundleInfos_ has a clone that exists ONLY in temp (no bundleInfos_ peer). The
    // allTempBundleNames loop (:105-120) must reach it — iterating bundleInfos_ names would miss it
    // Clone -> every ResourceInfo carries isDualModeCloneApp_=true so GetKey()
    // yields the prefixed key.
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeResourceInfo(true);
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    EXPECT_TRUE(BundleResourceProcess::GetAllResourceInfo(TEST_USERID, resourceInfos));
    ASSERT_EQ(resourceInfos.count(BUNDLE_NAME), 1u);
    EXPECT_FALSE(resourceInfos[BUNDLE_NAME].empty());
    EXPECT_TRUE(resourceInfos[BUNDLE_NAME].front().isDualModeCloneApp_);
}

HWTEST_F(BmsDualModeInstallTest, GetAllResourceInfo_0400, Function | SmallTest | Level0)
{
    // same-name merge: bundleInfos_[primary] + tempBundleInfos_[clone] both processed; the temp result
    // is appended at the end of the same resourceInfosMap[bundleName] (:117-118). Each MakeResourceInfo
    // yields exactly one bundle-level ResourceInfo, so the merged vector has size 2: primary first
    // (bundleInfos_ loop), clone second (temp loop).
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeResourceInfo(false);
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeResourceInfo(true);
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    EXPECT_TRUE(BundleResourceProcess::GetAllResourceInfo(TEST_USERID, resourceInfos));
    ASSERT_EQ(resourceInfos.count(BUNDLE_NAME), 1u);
    EXPECT_EQ(resourceInfos[BUNDLE_NAME].size(), 2u);
    EXPECT_FALSE(resourceInfos[BUNDLE_NAME].front().isDualModeCloneApp_);  // primary (bundleInfos_)
    EXPECT_TRUE(resourceInfos[BUNDLE_NAME].back().isDualModeCloneApp_);   // clone (temp, appended)
}

HWTEST_F(BmsDualModeInstallTest, GetAllResourceInfo_0500, Function | SmallTest | Level0)
{
    // temp entry BundleType::SHARED -> skipped by temp loop (:111-114), not added
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeResourceInfo(false, BundleType::SHARED);
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    EXPECT_TRUE(BundleResourceProcess::GetAllResourceInfo(TEST_USERID, resourceInfos));
    EXPECT_EQ(resourceInfos.count(BUNDLE_NAME), 0u);
}

HWTEST_F(BmsDualModeInstallTest, GetAllResourceInfo_0600, Function | SmallTest | Level0)
{
    // temp entry BundleType::SKILL -> skipped by temp loop (:111-112), not added
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeResourceInfo(false, BundleType::SKILL);
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    EXPECT_TRUE(BundleResourceProcess::GetAllResourceInfo(TEST_USERID, resourceInfos));
    EXPECT_EQ(resourceInfos.count(BUNDLE_NAME), 0u);
}

HWTEST_F(BmsDualModeInstallTest, GetAllResourceInfo_0700, Function | SmallTest | Level0)
{
    // temp entry APP_SERVICE_FWK && IsHsp() -> skipped by temp loop (:112); IsHsp() is true when every
    // InnerModuleInfo is MODULE_TYPE_SHARED (inner_bundle_info.cpp:4698-4706).
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeHspAppServiceFwkInfo();
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    EXPECT_TRUE(BundleResourceProcess::GetAllResourceInfo(TEST_USERID, resourceInfos));
    EXPECT_EQ(resourceInfos.count(BUNDLE_NAME), 0u);
}

HWTEST_F(BmsDualModeInstallTest, GetAllResourceInfo_0800, Function | SmallTest | Level0)
{
    // temp entry APP type but empty bundleName -> GetBundleResourceInfo fails (:45-48) ->
    // InnerGetResourceInfo returns false -> not added (:116 guard). Key is non-empty so the entry is
    // reached, but its ResourceInfo assembly fails.
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->tempBundleInfos_["empty-name"] = MakeResourceInfo(false, BundleType::APP, "");
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    EXPECT_TRUE(BundleResourceProcess::GetAllResourceInfo(TEST_USERID, resourceInfos));
    EXPECT_TRUE(resourceInfos.empty());
}

HWTEST_F(BmsDualModeInstallTest, GetAllResourceInfo_0900, Function | SmallTest | Level0)
{
    // dataMgr null -> return false (:65-68). Restore afterwards so later cases see a valid dataMgr.
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto saved = service->dataMgr_;
    service->dataMgr_ = nullptr;
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    EXPECT_FALSE(BundleResourceProcess::GetAllResourceInfo(TEST_USERID, resourceInfos));
    EXPECT_TRUE(resourceInfos.empty());
    service->dataMgr_ = saved;
}

// ====================== BundlePermissionMgr::CreateHapInfoParams ======================
// CreateHapInfoParams is static; exposed via #define private public. Verify the
// IsDualModeCloneApp && GetAppIndex()==0 branch sets instIndex to DUAL_MODE_CLONE_APP_INDEX.

HWTEST_F(BmsDualModeInstallTest, CreateHapInfoParams_0100, Function | SmallTest | Level0)
{
    // dual-mode clone app + appIndex 0 -> instIndex = DUAL_MODE_CLONE_APP_INDEX (10000)
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.SetAppIndex(0);
    auto hapInfo = BundlePermissionMgr::CreateHapInfoParams(info, 0, 0);
    EXPECT_EQ(hapInfo.instIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeInstallTest, CreateHapInfoParams_0200, Function | SmallTest | Level0)
{
    // dual-mode clone app + appIndex != 0 -> branch NOT hit, instIndex stays = appIndex
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.SetAppIndex(1);
    auto hapInfo = BundlePermissionMgr::CreateHapInfoParams(info, 0, 0);
    EXPECT_EQ(hapInfo.instIndex, 1);
}

HWTEST_F(BmsDualModeInstallTest, CreateHapInfoParams_0300, Function | SmallTest | Level0)
{
    // non-clone app + appIndex 0 -> branch NOT hit (not clone), instIndex = 0
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.SetAppIndex(0);
    auto hapInfo = BundlePermissionMgr::CreateHapInfoParams(info, 0, 0);
    EXPECT_EQ(hapInfo.instIndex, 0);
}

HWTEST_F(BmsDualModeInstallTest, CreateHapInfoParams_0400, Function | SmallTest | Level0)
{
    // non-clone app + appIndex != 0 -> branch NOT hit, instIndex = appIndex
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.SetAppIndex(2);
    auto hapInfo = BundlePermissionMgr::CreateHapInfoParams(info, 0, 0);
    EXPECT_EQ(hapInfo.instIndex, 2);
}

// ====================== BundleDataStorageRdb dual-mode storageKey ======================
// Real RDB (no mock): BundleDataStorageRdb computes storageKey from IsDualModeCloneApp.
// Verify the key landed in the DB via rdbDataManager_->QueryData. dataMgr->dataStorage_ is the
// BMS storage instance (real RdbDataManager + real DB). Each case cleans up its own key.

HWTEST_F(BmsDualModeInstallTest, SaveStorageBundleInfo_DualModeClone_0100, Function | SmallTest | Level0)
{
    // clone app -> stored under prefixed key (+clone-10000+name)
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto storage = std::static_pointer_cast<BundleDataStorageRdb>(dataMgr->dataStorage_);
    ASSERT_NE(storage, nullptr);
    const std::string name = "com.test.dm.save.clone";
    InnerBundleInfo info = MakeCat7Info(true);
    info.baseApplicationInfo_->bundleName = name;
    ASSERT_TRUE(storage->SaveStorageBundleInfo(info));
    std::string value;
    EXPECT_TRUE(storage->rdbDataManager_->QueryData(DualModeHelper::GetDualModeBundleName(name), value));
    storage->DeleteStorageBundleInfo(info);  // cleanup
}

HWTEST_F(BmsDualModeInstallTest, SaveStorageBundleInfo_Normal_0200, Function | SmallTest | Level0)
{
    // non-clone app -> stored under original key (name)
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto storage = std::static_pointer_cast<BundleDataStorageRdb>(dataMgr->dataStorage_);
    ASSERT_NE(storage, nullptr);
    const std::string name = "com.test.dm.save.normal";
    InnerBundleInfo info = MakeCat7Info(false);
    info.baseApplicationInfo_->bundleName = name;
    ASSERT_TRUE(storage->SaveStorageBundleInfo(info));
    std::string value;
    EXPECT_TRUE(storage->rdbDataManager_->QueryData(name, value));
    storage->DeleteStorageBundleInfo(info);  // cleanup
}

HWTEST_F(BmsDualModeInstallTest, SaveStorageBundleInfoWithCode_DualModeClone_0100, Function | SmallTest | Level0)
{
    // clone app -> stored under prefixed key via SaveStorageBundleInfoWithCode
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto storage = std::static_pointer_cast<BundleDataStorageRdb>(dataMgr->dataStorage_);
    ASSERT_NE(storage, nullptr);
    const std::string name = "com.test.dm.code.clone";
    InnerBundleInfo info = MakeCat7Info(true);
    info.baseApplicationInfo_->bundleName = name;
    ASSERT_EQ(storage->SaveStorageBundleInfoWithCode(info), OHOS::ERR_OK);
    std::string value;
    EXPECT_TRUE(storage->rdbDataManager_->QueryData(DualModeHelper::GetDualModeBundleName(name), value));
    storage->DeleteStorageBundleInfo(info);  // cleanup
}

HWTEST_F(BmsDualModeInstallTest, SaveStorageBundleInfoWithCode_Normal_0200, Function | SmallTest | Level0)
{
    // non-clone app -> stored under original key via SaveStorageBundleInfoWithCode
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto storage = std::static_pointer_cast<BundleDataStorageRdb>(dataMgr->dataStorage_);
    ASSERT_NE(storage, nullptr);
    const std::string name = "com.test.dm.code.normal";
    InnerBundleInfo info = MakeCat7Info(false);
    info.baseApplicationInfo_->bundleName = name;
    ASSERT_EQ(storage->SaveStorageBundleInfoWithCode(info), OHOS::ERR_OK);
    std::string value;
    EXPECT_TRUE(storage->rdbDataManager_->QueryData(name, value));
    storage->DeleteStorageBundleInfo(info);  // cleanup
}

HWTEST_F(BmsDualModeInstallTest, DeleteStorageBundleInfo_DualModeClone_0100, Function | SmallTest | Level0)
{
    // clone app -> delete removes the prefixed key
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto storage = std::static_pointer_cast<BundleDataStorageRdb>(dataMgr->dataStorage_);
    ASSERT_NE(storage, nullptr);
    const std::string name = "com.test.dm.del.clone";
    InnerBundleInfo info = MakeCat7Info(true);
    info.baseApplicationInfo_->bundleName = name;
    ASSERT_TRUE(storage->SaveStorageBundleInfo(info));  // pre-populate prefixed key
    ASSERT_TRUE(storage->DeleteStorageBundleInfo(info));
    std::string value;
    EXPECT_FALSE(storage->rdbDataManager_->QueryData(DualModeHelper::GetDualModeBundleName(name), value));
}

HWTEST_F(BmsDualModeInstallTest, DeleteStorageBundleInfo_Normal_0200, Function | SmallTest | Level0)
{
    // non-clone app -> delete removes the original key
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto storage = std::static_pointer_cast<BundleDataStorageRdb>(dataMgr->dataStorage_);
    ASSERT_NE(storage, nullptr);
    const std::string name = "com.test.dm.del.normal";
    InnerBundleInfo info = MakeCat7Info(false);
    info.baseApplicationInfo_->bundleName = name;
    ASSERT_TRUE(storage->SaveStorageBundleInfo(info));  // pre-populate original key
    ASSERT_TRUE(storage->DeleteStorageBundleInfo(info));
    std::string value;
    EXPECT_FALSE(storage->rdbDataManager_->QueryData(name, value));
}

// ====================== ApplicationInfo.appCategory persistence contract ======================
// AppCategory serialization contract (enum bit value / default value drift). Default value is
// APP_CATEGORY_UNSPECIFIED (bit
// value 0); the field must survive Parcel + JSON round trips and legacy (field-absent)
// deserialization. Round-trip cases use non-default values (32 / 33) so a broken or no-op marshal
// is caught instead of masked by default-in/default-out.

HWTEST_F(BmsDualModeInstallTest, AppCategory_Default_0100, Function | SmallTest | Level0)
{
    // ApplicationInfo default appCategory == UNSPECIFIED (bit value 0)
    ApplicationInfo appInfo;
    EXPECT_EQ(appInfo.appCategory, AppCategory::APP_CATEGORY_UNSPECIFIED);
    EXPECT_EQ(static_cast<uint32_t>(appInfo.appCategory), 0u);
}

HWTEST_F(BmsDualModeInstallTest, AppCategory_Default_0200, Function | SmallTest | Level0)
{
    // InstallParam default appCategory == UNSPECIFIED (bit value 0)
    InstallParam installParam;
    EXPECT_EQ(installParam.appCategory, AppCategory::APP_CATEGORY_UNSPECIFIED);
    EXPECT_EQ(static_cast<uint32_t>(installParam.appCategory), 0u);
}

HWTEST_F(BmsDualModeInstallTest, AppCategory_Parcel_0100, Function | SmallTest | Level0)
{
    // category-7 boundary value (32) survives Parcel Marshalling/ReadFromParcel round trip
    OHOS::MessageParcel parcel;
    ApplicationInfo src;
    src.appCategory = AppCategory::APP_CATEGORY_DIFF_PACKAGE;
    ASSERT_TRUE(src.Marshalling(parcel));
    ApplicationInfo dst;
    ASSERT_TRUE(dst.ReadFromParcel(parcel));
    EXPECT_EQ(dst.appCategory, AppCategory::APP_CATEGORY_DIFF_PACKAGE);
    EXPECT_EQ(static_cast<uint32_t>(dst.appCategory), 32u);
}

HWTEST_F(BmsDualModeInstallTest, AppCategory_Parcel_0200, Function | SmallTest | Level0)
{
    // bitwise-or combo (PAD_ONLY | DIFF_PACKAGE = 1 | 32 = 33) survives Parcel round trip
    OHOS::MessageParcel parcel;
    ApplicationInfo src;
    src.appCategory = static_cast<AppCategory>(
        static_cast<uint32_t>(AppCategory::APP_CATEGORY_TABLET_ONLY) |
        static_cast<uint32_t>(AppCategory::APP_CATEGORY_DIFF_PACKAGE));
    ASSERT_TRUE(src.Marshalling(parcel));
    ApplicationInfo dst;
    ASSERT_TRUE(dst.ReadFromParcel(parcel));
    EXPECT_EQ(static_cast<uint32_t>(dst.appCategory), 33u);
}

HWTEST_F(BmsDualModeInstallTest, AppCategory_JsonRoundTrip_0100, Function | SmallTest | Level0)
{
    // category-7 value (32) survives to_json/from_json round trip
    ApplicationInfo src;
    src.appCategory = AppCategory::APP_CATEGORY_DIFF_PACKAGE;
    nlohmann::json jsonObject;
    to_json(jsonObject, src);
    ApplicationInfo dst;
    from_json(jsonObject, dst);
    EXPECT_EQ(dst.appCategory, AppCategory::APP_CATEGORY_DIFF_PACKAGE);
    EXPECT_EQ(static_cast<uint32_t>(dst.appCategory), 32u);
}

HWTEST_F(BmsDualModeInstallTest, AppCategory_LegacyDefault_0100, Function | SmallTest | Level0)
{
    // legacy stored JSON without an appCategory field deserializes to the default
    // UNSPECIFIED (0) — from_json's GetValueIfFindKey must not mutate the field when absent
    nlohmann::json legacyJson = {{"name", "com.test.legacy"}};  // intentionally no appCategory key
    ApplicationInfo dst;
    from_json(legacyJson, dst);
    EXPECT_EQ(dst.appCategory, AppCategory::APP_CATEGORY_UNSPECIFIED);
    EXPECT_EQ(static_cast<uint32_t>(dst.appCategory), 0u);
}

// ====================== BundleDataStorageRdb::TransformStrToInfo (TransResult self-heal branch) =====
// TransResult is an anonymous-namespace free function driven (multi-threaded) by the private
// TransformStrToInfo. Its 74-78 branch marks a record for self-heal rewrite when the DB key differs
// from bundleName AND the key is not a dual-mode clone key:
//   if (key != bundleName && !DualModeHelper::IsDualModeCloneKey(key)) needUpdateInfos.emplace_back(...)
// needUpdateInfos feeds UpdateDataBase, which writes the bundleName key into the real RDB. We drive
// the branch via TransformStrToInfo (exposed by #define private public) with a crafted datas map and
// tell the true/false branches apart by that RDB side effect. InstallMark is forced to INSTALL_FINISH
// so records skip the exception-handling path (default UNKNOWN_STATUS would otherwise change the
// resulting infos key and add unrelated side effects). Each case cleans up the keys it touches.

static std::string MakeTransResultInfoJson(const std::string &bundleName)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = bundleName;
    info.SetInstallMark(bundleName, "", InstallExceptionStatus::INSTALL_FINISH);
    return info.ToString();
}

HWTEST_F(BmsDualModeInstallTest, TransformStrToInfo_SelfHeal_0100, Function | SmallTest | Level0)
{
    // DB key != bundleName and NOT a dual-mode clone key -> branch fires: record marked for
    // self-heal rewrite, UpdateDataBase writes the bundleName key into the RDB.
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto storage = std::static_pointer_cast<BundleDataStorageRdb>(dataMgr->dataStorage_);
    ASSERT_NE(storage, nullptr);
    const std::string key = "com.test.trans.selfheal.stale";
    const std::string bundleName = "com.test.trans.selfheal.real";
    std::map<std::string, std::string> datas;
    datas[key] = MakeTransResultInfoJson(bundleName);
    std::map<std::string, InnerBundleInfo> infos;
    storage->TransformStrToInfo(datas, infos);
    // record still loaded under the original DB key, with the JSON bundleName preserved
    EXPECT_EQ(infos.count(key), 1u);
    EXPECT_EQ(infos[key].GetBundleName(), bundleName);
    // self-heal side effect: bundleName key rewritten into the RDB
    std::string value;
    EXPECT_TRUE(storage->rdbDataManager_->QueryData(bundleName, value));
    storage->rdbDataManager_->DeleteData(bundleName);  // cleanup
}

HWTEST_F(BmsDualModeInstallTest, TransformStrToInfo_KeyEqualsBundleName_0200, Function | SmallTest | Level0)
{
    // DB key == bundleName -> short-circuits at the first operand, branch does NOT fire: no
    // self-heal rewrite and no RDB write.
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto storage = std::static_pointer_cast<BundleDataStorageRdb>(dataMgr->dataStorage_);
    ASSERT_NE(storage, nullptr);
    const std::string key = "com.test.trans.normal";
    std::map<std::string, std::string> datas;
    datas[key] = MakeTransResultInfoJson(key);
    std::map<std::string, InnerBundleInfo> infos;
    storage->TransformStrToInfo(datas, infos);
    EXPECT_EQ(infos.count(key), 1u);
    EXPECT_EQ(infos[key].GetBundleName(), key);
    // no self-heal: nothing written under bundleName (== key) since input never reached the RDB
    std::string value;
    EXPECT_FALSE(storage->rdbDataManager_->QueryData(key, value));
}

HWTEST_F(BmsDualModeInstallTest, TransformStrToInfo_DualModeCloneKey_0300, Function | SmallTest | Level0)
{
    // DB key is a dual-mode clone key (+clone-10000+name), differs from bundleName but is exempt
    // from self-healing -> branch does NOT fire: no RDB write.
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto storage = std::static_pointer_cast<BundleDataStorageRdb>(dataMgr->dataStorage_);
    ASSERT_NE(storage, nullptr);
    const std::string bundleName = "com.test.trans.clone";
    const std::string key = DualModeHelper::GetDualModeBundleName(bundleName);
    ASSERT_TRUE(DualModeHelper::IsDualModeCloneKey(key));
    std::map<std::string, std::string> datas;
    datas[key] = MakeTransResultInfoJson(bundleName);
    std::map<std::string, InnerBundleInfo> infos;
    storage->TransformStrToInfo(datas, infos);
    EXPECT_EQ(infos.count(key), 1u);
    EXPECT_EQ(infos[key].GetBundleName(), bundleName);
    // no self-heal: bundleName key not rewritten into the RDB
    std::string value;
    EXPECT_FALSE(storage->rdbDataManager_->QueryData(bundleName, value));
}

// ====================== BaseBundleInstaller::FillDualModeEventFields ======================
// Single branch: extended fields are filled only on a dual-mode device. Cover both arms via the
// DualModeHelper cache (no system parameter): true -> appCategory / currentMode / isSharedSandbox
// populated; false -> pre-set fields left untouched. BaseBundleInstaller is default-constructed and
// the private method is reached through #define private public.

HWTEST_F(BmsDualModeInstallTest, FillDualModeEventFields_0100, Function | SmallTest | Level0)
{
    // dual-mode device (cachedMode_ non-empty) -> branch fires, extended fields populated
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_DIFF_PACKAGE;
    NotifyBundleEvents installRes;
    installer.FillDualModeEventFields(installParam, installRes);
    EXPECT_EQ(installRes.appCategory, AppCategory::APP_CATEGORY_DIFF_PACKAGE);
    EXPECT_EQ(installRes.currentMode, DualModeHelper::GetSysMode());
    // secondary mode + category 7 => NeedDualModeHandle true => shared sandbox disabled
    EXPECT_FALSE(installRes.isSharedSandbox);
}

HWTEST_F(BmsDualModeInstallTest, FillDualModeEventFields_0200, Function | SmallTest | Level0)
{
    // non-dual-mode device (cachedMode_ empty) -> branch skipped, pre-set markers preserved
    SetDualModeCache("", "");
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.appCategory = AppCategory::APP_CATEGORY_TABLET_ONLY;
    NotifyBundleEvents installRes;
    installRes.appCategory = AppCategory::APP_CATEGORY_2IN1_ONLY;  // non-default marker
    installRes.currentMode = "marker";
    installRes.isSharedSandbox = false;  // flip default true to prove it is not rewritten
    installer.FillDualModeEventFields(installParam, installRes);
    EXPECT_EQ(installRes.appCategory, AppCategory::APP_CATEGORY_2IN1_ONLY);
    EXPECT_EQ(installRes.currentMode, "marker");
    EXPECT_FALSE(installRes.isSharedSandbox);
}

// ====================== BundleDataMgr::GetSkillInfoWithFlags ======================
// skills description data layer: skillPath uses the effective (prefixed) name for clone apps so it
// points at the isolated skill dir; skillInfo.bundleName (Parcelable) keeps the original name.
// flags=0 skips the description (RDB) branch, so each case asserts only path/bundleName assignment.
// The delete-path effective-name derivation is covered by GetEffectiveBundleName_0300~0500 above.

HWTEST_F(BmsDualModeInstallTest, GetSkillInfoWithFlags_DualModeClone_0100, Function | SmallTest | Level0)
{
    // clone app: skillPath uses prefixed name; bundleName keeps original (Parcelable contract)
    InnerBundleInfo info = MakeCat7Info(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    SkillProfile profile;
    profile.name = "skill1";
    profile.abilityName = "MainAbility";
    SkillInfo skillInfo;
    BundleDataMgr::GetSkillInfoWithFlags(info, moduleInfo, profile, 0, skillInfo);
    EXPECT_EQ(skillInfo.bundleName, BUNDLE_NAME);
    EXPECT_NE(skillInfo.skillPath.find(PREFIXED_NAME), std::string::npos);
}

HWTEST_F(BmsDualModeInstallTest, GetSkillInfoWithFlags_Normal_0200, Function | SmallTest | Level0)
{
    // primary (non-clone): skillPath uses original name, no prefix; zero behavior change
    InnerBundleInfo info = MakeCat7Info(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    SkillProfile profile;
    profile.name = "skill1";
    profile.abilityName = "MainAbility";
    SkillInfo skillInfo;
    BundleDataMgr::GetSkillInfoWithFlags(info, moduleInfo, profile, 0, skillInfo);
    EXPECT_EQ(skillInfo.bundleName, BUNDLE_NAME);
    EXPECT_NE(skillInfo.skillPath.find(BUNDLE_NAME), std::string::npos);
    EXPECT_EQ(skillInfo.skillPath.find(PREFIXED_NAME), std::string::npos);
}

// ====================== Router ======================
// Router insert/update pass the effective (prefixed) name for clone apps. A mock
// IRouterDataStorage captures the bundleName handed downstream to assert the key, without needing
// real hap/router.json files (FindRouterHapPath yields an empty map when no module routerMap is set).
namespace {
class MockRouterStorage : public IRouterDataStorage {
public:
    std::string insertedKey;
    std::string updatedKey;
    bool InsertRouterInfo(const std::string &bundleName,
        const std::map<std::string, std::string> &, const uint32_t) override
    {
        insertedKey = bundleName;
        return true;
    }
    bool UpdateRouterInfo(const std::string &bundleName,
        const std::map<std::string, std::string> &, const uint32_t) override
    {
        updatedKey = bundleName;
        return true;
    }
    bool GetRouterInfo(const std::string &, const std::string &,
        const uint32_t, std::vector<RouterItem> &) override { return false; }
    void GetAllBundleNames(std::set<std::string> &) override {}
    bool DeleteRouterInfo(const std::string &) override { return true; }
    bool DeleteRouterInfo(const std::string &, const std::string &) override { return true; }
    bool DeleteRouterInfo(const std::string &, const std::string &, const uint32_t) override { return true; }
    bool UpdateDB() override { return true; }
};
}  // namespace

HWTEST_F(BmsDualModeInstallTest, InsertRouterInfo_DualModeClone_0100, Function | SmallTest | Level0)
{
    // clone app: InsertRouterInfo passes the prefixed name downstream
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto mockStorage = std::make_shared<MockRouterStorage>();
    dataMgr->routerStorage_ = mockStorage;
    InnerBundleInfo cloneInfo = MakeCat7Info(true);
    cloneInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->InsertRouterInfo(cloneInfo);
    EXPECT_EQ(mockStorage->insertedKey, PREFIXED_NAME);
}

HWTEST_F(BmsDualModeInstallTest, InsertRouterInfo_Normal_0200, Function | SmallTest | Level0)
{
    // non-clone: InsertRouterInfo passes the original name; zero change
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto mockStorage = std::make_shared<MockRouterStorage>();
    dataMgr->routerStorage_ = mockStorage;
    InnerBundleInfo info = MakeCat7Info(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->InsertRouterInfo(info);
    EXPECT_EQ(mockStorage->insertedKey, BUNDLE_NAME);
}

HWTEST_F(BmsDualModeInstallTest, UpdateRouterInfo_ByBundleName_DualModeClone_0300, Function | SmallTest | Level0)
{
    // clone under original-name key (post ClassifyDualModeAppsNoLock): UpdateRouterInfo(original)
    // finds the clone and passes the prefixed name downstream
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto mockStorage = std::make_shared<MockRouterStorage>();
    dataMgr->routerStorage_ = mockStorage;
    InnerBundleInfo cloneInfo = MakeCat7Info(true);
    cloneInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = cloneInfo;
    dataMgr->UpdateRouterInfo(BUNDLE_NAME);
    EXPECT_EQ(mockStorage->updatedKey, PREFIXED_NAME);
}

HWTEST_F(BmsDualModeInstallTest, UpdateRouterInfo_ByBundleName_Normal_0400, Function | SmallTest | Level0)
{
    // non-clone: UpdateRouterInfo(original) keeps the original name; zero change
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto mockStorage = std::make_shared<MockRouterStorage>();
    dataMgr->routerStorage_ = mockStorage;
    InnerBundleInfo info = MakeCat7Info(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    dataMgr->UpdateRouterInfo(BUNDLE_NAME);
    EXPECT_EQ(mockStorage->updatedKey, BUNDLE_NAME);
}

// ====================== BundleDataMgr::GenerateOdidNoLock ======================
// Cross-mode odid reuse relies on GenerateOdidNoLock scanning BOTH bundleInfos_ and tempBundleInfos_.
// In secondary mode ClassifyDualModeAppsNoLock hides the primary-mode variant (same developerId) in
// tempBundleInfos_; scanning only bundleInfos_ would miss it and generate a fresh odid for
// the clone, breaking cross-mode odid consistency.

HWTEST_F(BmsDualModeInstallTest, GenerateOdid_ReuseFromTempBundleInfos_0100, Function | SmallTest | Level0)
{
    // primary-mode variant sits in tempBundleInfos_ (hidden by classification); clone install
    // for the same developerId must reuse its odid, not generate a new one.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();

    const std::string developerId = "com.example.developer";
    const std::string primaryOdid = "odid-from-primary";
    InnerBundleInfo primaryInfo;
    primaryInfo.UpdateOdid(developerId, primaryOdid);
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = primaryInfo;

    std::string odid;
    dataMgr->GenerateOdid(developerId, odid);
    EXPECT_EQ(odid, primaryOdid);
}

HWTEST_F(BmsDualModeInstallTest, GenerateOdid_ReuseFromBundleInfos_0200, Function | SmallTest | Level0)
{
    // Regression: same-groupId odid already in bundleInfos_ is reused (pre-existing behavior).
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();

    const std::string developerId = "com.example.developer";
    const std::string existingOdid = "existing-odid";
    InnerBundleInfo info;
    info.UpdateOdid(developerId, existingOdid);
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;

    std::string odid;
    dataMgr->GenerateOdid(developerId, odid);
    EXPECT_EQ(odid, existingOdid);
}

HWTEST_F(BmsDualModeInstallTest, GenerateOdid_BothMapsBundleInfosFirst_0300, Function | SmallTest | Level0)
{
    // When both maps hold the groupId, bundleInfos_ wins (scanned first), preserving prior behavior.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();

    const std::string developerId = "com.example.developer";
    InnerBundleInfo cloneInfo;
    cloneInfo.UpdateOdid(developerId, "odid-in-bundleinfos");
    dataMgr->bundleInfos_[PREFIXED_NAME] = cloneInfo;
    InnerBundleInfo primaryInfo;
    primaryInfo.UpdateOdid(developerId, "odid-in-temp");
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = primaryInfo;

    std::string odid;
    dataMgr->GenerateOdid(developerId, odid);
    EXPECT_EQ(odid, "odid-in-bundleinfos");
}

HWTEST_F(BmsDualModeInstallTest, GenerateOdid_NoMatchGenerateNew_0400, Function | SmallTest | Level0)
{
    // Neither map has the groupId -> a fresh uuid odid is generated.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();

    std::string odid;
    dataMgr->GenerateOdid("com.example.fresh", odid);
    EXPECT_FALSE(odid.empty());
}

// ====================== BundleDataMgr::installStates_ state machine ====
// Callers pass the effective name (prefixed for clone apps, original otherwise); it is used directly
// as the installStates_ key. The old GetInstallStateKey lookup and the INSTALL_START info overload
// were removed.

HWTEST_F(BmsDualModeInstallTest, UpdateBundleInstallState_InstallStartClonePrefixed_0100, Function | SmallTest | Level0)
{
    // Fresh install of a clone app: caller passes the prefixed effective name; it becomes the state
    // key directly, matching the post-restart installStates_ initialization (prefixed DB key).
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(PREFIXED_NAME, InstallState::INSTALL_START, false));
    EXPECT_EQ(dataMgr->installStates_.count(PREFIXED_NAME), 1u);
    EXPECT_EQ(dataMgr->installStates_[PREFIXED_NAME], InstallState::INSTALL_START);
    EXPECT_EQ(dataMgr->installStates_.count(BUNDLE_NAME), 0u);
}

HWTEST_F(BmsDualModeInstallTest, UpdateBundleInstallState_InstallStartNonCloneOriginal_0200,
    Function | SmallTest | Level0)
{
    // Non-clone fresh install: caller passes the original name; emplaces under the original name.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START, false));
    EXPECT_EQ(dataMgr->installStates_.count(BUNDLE_NAME), 1u);
    EXPECT_EQ(dataMgr->installStates_.count(PREFIXED_NAME), 0u);
}

HWTEST_F(BmsDualModeInstallTest, UpdateBundleInstallState_RestartUpdateClone_0300, Function | SmallTest | Level0)
{
    // after restart installStates_ is keyed by the prefixed name; the runtime update
    // passes the prefixed effective name so UPDATING_START lands on the same key as INSTALL_SUCCESS
    // (previously two truth sources mismatched and the transition returned false).
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[PREFIXED_NAME] = InstallState::INSTALL_SUCCESS;
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(PREFIXED_NAME, InstallState::UPDATING_START));
    EXPECT_EQ(dataMgr->installStates_[PREFIXED_NAME], InstallState::UPDATING_START);
}

HWTEST_F(BmsDualModeInstallTest, UpdateBundleInstallState_RollbackClone_0400, Function | SmallTest | Level0)
{
    // Rollback: caller passes the prefixed effective name; ROLL_BACK transitions on the prefixed key.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[PREFIXED_NAME] = InstallState::UPDATING_START;
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(PREFIXED_NAME, InstallState::ROLL_BACK));
    EXPECT_EQ(dataMgr->installStates_.count(PREFIXED_NAME), 1u);
}

HWTEST_F(BmsDualModeInstallTest, UpdateBundleInstallState_RestartNonCloneRegression_0500, Function | SmallTest | Level0)
{
    // non-clone uses the original name end-to-end, zero behavioral change.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START));
    EXPECT_EQ(dataMgr->installStates_[BUNDLE_NAME], InstallState::UPDATING_START);
    EXPECT_EQ(dataMgr->installStates_.count(PREFIXED_NAME), 0u);
}
} // OHOS
