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

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.test";
const std::string PREFIXED_NAME = "+clone-10000+" + BUNDLE_NAME;
const std::string CLONE_APP_NAME = "+clone-1+" + BUNDLE_NAME;  // regular clone (appIndex 1..5), not dual-mode
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
    // name instead of the original (ADR-16 helper contract change).
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
// Cover AC-1 / AC-2 / AC-18 — the AppCategory serialization contract that Review-1 FAIL-1 nearly
// broke (enum bit value / default value drift). Default value is APP_CATEGORY_UNSPECIFIED (bit
// value 0); the field must survive Parcel + JSON round trips and legacy (field-absent)
// deserialization. Round-trip cases use non-default values (32 / 33) so a broken or no-op marshal
// is caught instead of masked by default-in/default-out.

HWTEST_F(BmsDualModeInstallTest, AppCategory_Default_0100, Function | SmallTest | Level0)
{
    // AC-2: ApplicationInfo default appCategory == UNSPECIFIED (bit value 0)
    ApplicationInfo appInfo;
    EXPECT_EQ(appInfo.appCategory, AppCategory::APP_CATEGORY_UNSPECIFIED);
    EXPECT_EQ(static_cast<uint32_t>(appInfo.appCategory), 0u);
}

HWTEST_F(BmsDualModeInstallTest, AppCategory_Default_0200, Function | SmallTest | Level0)
{
    // AC-2: InstallParam default appCategory == UNSPECIFIED (bit value 0)
    InstallParam installParam;
    EXPECT_EQ(installParam.appCategory, AppCategory::APP_CATEGORY_UNSPECIFIED);
    EXPECT_EQ(static_cast<uint32_t>(installParam.appCategory), 0u);
}

HWTEST_F(BmsDualModeInstallTest, AppCategory_Parcel_0100, Function | SmallTest | Level0)
{
    // AC-1: category-7 boundary value (32) survives Parcel Marshalling/ReadFromParcel round trip
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
    // AC-1: bitwise-or combo (PAD_ONLY | DIFF_PACKAGE = 1 | 32 = 33) survives Parcel round trip
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
    // AC-1: category-7 value (32) survives to_json/from_json round trip
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
    // AC-18: legacy stored JSON without an appCategory field deserializes to the default
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

// ====================== BundleDataMgr::GetSkillInfoWithFlags (ADR-17 / AC-23) ======================
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

// ====================== Router (ADR-20 / AC-26) ======================
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
    // clone app: InsertRouterInfo passes the prefixed name downstream (ADR-20)
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
    // finds the clone and passes the prefixed name downstream (ADR-20)
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

// ====================== BundleDataMgr::GenerateOdidNoLock (ADR-7 / AC-16) ======================
// Cross-mode odid reuse relies on GenerateOdidNoLock scanning BOTH bundleInfos_ and tempBundleInfos_.
// In secondary mode ClassifyDualModeAppsNoLock hides the primary-mode variant (same developerId) in
// tempBundleInfos_ (AC-14); scanning only bundleInfos_ would miss it and generate a fresh odid for
// the clone, breaking cross-mode odid consistency (AC-16).

HWTEST_F(BmsDualModeInstallTest, GenerateOdid_ReuseFromTempBundleInfos_0100, Function | SmallTest | Level0)
{
    // AC-16: primary-mode variant sits in tempBundleInfos_ (hidden by classification); clone install
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

// ====================== BundleDataMgr::installStates_ state machine (ADR-21 amendment Review-14 / AC-27/28/32) ====
// Callers pass the effective name (prefixed for clone apps, original otherwise); it is used directly
// as the installStates_ key. The old GetInstallStateKey lookup and the INSTALL_START info overload
// were removed (design ADR-21 amendment).

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
    // Non-clone fresh install: caller passes the original name; emplaces under the original name
    // (AC-28 regression, zero change).
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START, false));
    EXPECT_EQ(dataMgr->installStates_.count(BUNDLE_NAME), 1u);
    EXPECT_EQ(dataMgr->installStates_.count(PREFIXED_NAME), 0u);
}

HWTEST_F(BmsDualModeInstallTest, UpdateBundleInstallState_RestartUpdateClone_0300, Function | SmallTest | Level0)
{
    // AC-27 fix: after restart installStates_ is keyed by the prefixed name; the runtime update
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
    // AC-28 regression: non-clone uses the original name end-to-end, zero behavioral change.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START));
    EXPECT_EQ(dataMgr->installStates_[BUNDLE_NAME], InstallState::UPDATING_START);
    EXPECT_EQ(dataMgr->installStates_.count(PREFIXED_NAME), 0u);
}
} // OHOS
