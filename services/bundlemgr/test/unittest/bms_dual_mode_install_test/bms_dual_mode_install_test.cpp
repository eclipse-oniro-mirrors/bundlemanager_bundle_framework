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
// DualModeHelper cache (cachedIspcmode_/cachedMainmode_) and BaseBundleInstaller members, without
// reading or modifying real system parameters. The system-parameter read paths
// (GetSysMode/InitializeCache/UpdateModeCache) are intentionally not covered.
#define private public
#define protected public
#include <gtest/gtest.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "appexecfwk_errors.h"
#include "application_info.h"
#include "bundle_info.h"
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
#include "parameters.h"
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
    DualModeHelper::cachedIspcmode_ = ServiceConstants::DUAL_MODE_VALUE_INVALID;
    DualModeHelper::cachedMainmode_ = ServiceConstants::DUAL_MODE_VALUE_INVALID;
}

// Drive DualModeHelper mode judgment by writing the int cache directly (no system parameter).
// ispcmode: 0=tablet, 1=2in1 (current mode); mainmode: 0=main tablet, 1=main 2in1; -1=invalid (non-dual-mode).
static void SetDualModeCache(int ispcmode, int mainmode)
{
    DualModeHelper::cachedIspcmode_ = ispcmode;
    DualModeHelper::cachedMainmode_ = mainmode;
}

static void EnableSecondaryMode()
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
}

// Primary mode: ispcmode == mainmode (both tablet), so IsSecondaryMode() == false.
static void EnablePrimaryMode()
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_TABLET, ServiceConstants::DUAL_MODE_VALUE_TABLET);
}

// Build a different-package (UNIVERSAL_DIFFERENT_PACKAGE) InnerBundleInfo; mark as dual-mode clone if needed.
static InnerBundleInfo MakeCat7Info(bool isClone)
{
    InnerBundleInfo info;
    info.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
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
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    EXPECT_FALSE(DualModeHelper::IsDualModeDevice());
}

HWTEST_F(BmsDualModeInstallTest, IsDualModeDevice_0200, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    EXPECT_TRUE(DualModeHelper::IsDualModeDevice());
}

// ====================== DualModeHelper::IsSecondaryMode ======================

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0100, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0200, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    EXPECT_TRUE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0300, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_TABLET, ServiceConstants::DUAL_MODE_VALUE_2IN1);
    EXPECT_TRUE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0400, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_2IN1);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0500, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_TABLET, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
}

HWTEST_F(BmsDualModeInstallTest, IsSecondaryMode_0600, Function | SmallTest | Level0)
{
    // ispcmode=2 is illegal (not in {0,1}) -> treated as invalid -> non-dual-mode (AC-33 value check)
    SetDualModeCache(2, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
}

// ====================== DualModeHelper::IsDiffPackageCategory ======================

HWTEST_F(BmsDualModeInstallTest, IsDiffPackageCategory_0100, Function | SmallTest | Level0)
{
    EXPECT_TRUE(DualModeHelper::IsDiffPackageCategory(
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE));
}

HWTEST_F(BmsDualModeInstallTest, IsDiffPackageCategory_0200, Function | SmallTest | Level0)
{
    // New enum values are mutually exclusive (no bitwise-or). All three *_DIFFERENT_PACKAGE
    // values are different-package categories.
    EXPECT_TRUE(DualModeHelper::IsDiffPackageCategory(
        DeviceModeDistributionPolicy::PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE));
    EXPECT_TRUE(DualModeHelper::IsDiffPackageCategory(
        DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE));
}

HWTEST_F(BmsDualModeInstallTest, IsDiffPackageCategory_0300, Function | SmallTest | Level0)
{
    EXPECT_FALSE(DualModeHelper::IsDiffPackageCategory(DeviceModeDistributionPolicy::UNSPECIFIED));
}

HWTEST_F(BmsDualModeInstallTest, IsDiffPackageCategory_0400, Function | SmallTest | Level0)
{
    EXPECT_FALSE(DualModeHelper::IsDiffPackageCategory(DeviceModeDistributionPolicy::MAIN_ONLY));
}

// ====================== DualModeHelper::NeedDualModeHandle ======================

HWTEST_F(BmsDualModeInstallTest, NeedDualModeHandle_0100, Function | SmallTest | Level0)
{
    EnableSecondaryMode();
    EXPECT_TRUE(DualModeHelper::NeedDualModeHandle(
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE));
}

HWTEST_F(BmsDualModeInstallTest, NeedDualModeHandle_0200, Function | SmallTest | Level0)
{
    EnableSecondaryMode();
    EXPECT_FALSE(DualModeHelper::NeedDualModeHandle(DeviceModeDistributionPolicy::MAIN_ONLY));
}

HWTEST_F(BmsDualModeInstallTest, NeedDualModeHandle_0300, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    EXPECT_FALSE(DualModeHelper::NeedDualModeHandle(
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE));
}

HWTEST_F(BmsDualModeInstallTest, NeedDualModeHandle_0400, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    EXPECT_FALSE(DualModeHelper::NeedDualModeHandle(DeviceModeDistributionPolicy::UNSPECIFIED));
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
    InnerBundleInfo info = MakeCat7Info(true);  // UNIVERSAL_DIFFERENT_PACKAGE + IsDualModeCloneApp=true
    EXPECT_EQ(installer.GetEffectiveBundleName(info), DualModeHelper::GetDualModeBundleName(info.GetBundleName()));
    EXPECT_NE(installer.GetEffectiveBundleName(info), info.GetBundleName());
}

// ====================== BaseBundleInstaller::InitDualModeBundleName ======================

HWTEST_F(BmsDualModeInstallTest, InitDualModeBundleName_0100, Function | SmallTest | Level0)
{
    // secondary mode + different-package -> set prefixed name
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    installer.InitDualModeBundleName(installParam);
    EXPECT_EQ(installer.dualModeBundleName_, DualModeHelper::GetDualModeBundleName(BUNDLE_NAME));
    EXPECT_NE(installer.dualModeBundleName_.find("10000"), std::string::npos);
}

HWTEST_F(BmsDualModeInstallTest, InitDualModeBundleName_0200, Function | SmallTest | Level0)
{
    // primary mode + different-package -> clear
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.dualModeBundleName_ = "stale";
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    installer.InitDualModeBundleName(installParam);
    EXPECT_TRUE(installer.dualModeBundleName_.empty());
}

HWTEST_F(BmsDualModeInstallTest, InitDualModeBundleName_0300, Function | SmallTest | Level0)
{
    // secondary mode + non-different-package -> clear
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.dualModeBundleName_ = "stale";
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    installer.InitDualModeBundleName(installParam);
    EXPECT_TRUE(installer.dualModeBundleName_.empty());
}

HWTEST_F(BmsDualModeInstallTest, InitDualModeBundleNameByInfo_0100, Function | SmallTest | Level0)
{
    // Uninstall must derive the physical identity from the persisted clone flag instead of current mode.
    BaseBundleInstaller installer;
    InnerBundleInfo secondaryInfo = MakeResourceInfo(true);
    secondaryInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    installer.InitDualModeBundleName(secondaryInfo);
    EXPECT_EQ(installer.GetEffectiveBundleName(), DualModeHelper::GetDualModeBundleName(secondaryInfo.GetBundleName()));

    InnerBundleInfo primaryInfo = MakeResourceInfo(false);
    installer.InitDualModeBundleName(primaryInfo);
    EXPECT_TRUE(installer.dualModeBundleName_.empty());
    EXPECT_EQ(installer.GetEffectiveBundleName(), primaryInfo.GetBundleName());
}

HWTEST_F(BmsDualModeInstallTest, DualModeUninstallEventFields_0100, Function | SmallTest | Level0)
{
    EnableSecondaryMode();
    ASSERT_TRUE(OHOS::system::SetParameter(ServiceConstants::DUAL_MODE_ISPCMODE_PARAM_KEY,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_2IN1)));

    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;

    // Full-bundle and module-uninstall notifications use the uninstall request, just as install events do.
    NotifyBundleEvents uninstallEvent;
    installer.FillDualModeUninstallEventFields(installParam, uninstallEvent);
    EXPECT_EQ(uninstallEvent.deviceModeDistributionPolicy,
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(uninstallEvent.currentMode, ServiceConstants::DUAL_MODE_VALUE_2IN1);
    EXPECT_EQ(uninstallEvent.appSandboxPolicy, AppSandboxPolicy::ISOLATED_SANDBOX);
    OHOS::system::RemoveParameter(ServiceConstants::DUAL_MODE_ISPCMODE_PARAM_KEY);
}

HWTEST_F(BmsDualModeInstallTest, DualModeUninstallEventFields_0200, Function | SmallTest | Level0)
{
    // A non-dual-mode device must not overwrite event fields which are populated by the common path.
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    NotifyBundleEvents uninstallEvent;
    uninstallEvent.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::SUB_ONLY;
    uninstallEvent.currentMode = 99;
    uninstallEvent.appSandboxPolicy = AppSandboxPolicy::ISOLATED_SANDBOX;

    installer.FillDualModeUninstallEventFields(installParam, uninstallEvent);

    EXPECT_EQ(uninstallEvent.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::SUB_ONLY);
    EXPECT_EQ(uninstallEvent.currentMode, 99);
    EXPECT_EQ(uninstallEvent.appSandboxPolicy, AppSandboxPolicy::ISOLATED_SANDBOX);
}

HWTEST_F(BmsDualModeInstallTest, DualModeUninstallEventFields_0300, Function | SmallTest | Level0)
{
    // A same-package app in the primary mode reports the current mode and shared-sandbox policy.
    EnablePrimaryMode();
    ASSERT_TRUE(OHOS::system::SetParameter(ServiceConstants::DUAL_MODE_ISPCMODE_PARAM_KEY,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_TABLET)));

    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE;
    NotifyBundleEvents uninstallEvent;
    installer.FillDualModeUninstallEventFields(installParam, uninstallEvent);

    EXPECT_EQ(uninstallEvent.deviceModeDistributionPolicy,
        DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE);
    EXPECT_EQ(uninstallEvent.currentMode, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    EXPECT_EQ(uninstallEvent.appSandboxPolicy, AppSandboxPolicy::SHARED_SANDBOX);
    OHOS::system::RemoveParameter(ServiceConstants::DUAL_MODE_ISPCMODE_PARAM_KEY);
}

// ====================== BaseBundleInstaller::SetDualModeAppInfo ======================

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0100, Function | SmallTest | Level0)
{
    // not a dual-mode device -> early return, no mutation
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = InnerBundleInfo();
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
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
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    installer.SetDualModeAppInfo(installParam, infos);
    EXPECT_TRUE(infos.empty());
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0300, Function | SmallTest | Level0)
{
    // dual-mode device + different-package (clone) + system app -> clone flag set,
    // deviceModeDistributionPolicy set, ERR_OK
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo systemInfo;
    ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    systemInfo.SetBaseApplicationInfo(appInfo);
    infos[BUNDLE_NAME] = systemInfo;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos), OHOS::ERR_OK);
    EXPECT_TRUE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppIndex(), ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(),
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0400, Function | SmallTest | Level0)
{
    // dual-mode device + non-different-package (non-mode-exclusive) -> deviceModeDistributionPolicy set,
    // isDualModeCloneApp stays false. UNIVERSAL_IDENTICAL_PACKAGE is neither a different-package category
    // nor a mode-exclusive policy, so it is admissible in either mode.
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = InnerBundleInfo();
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE;
    installer.SetDualModeAppInfo(installParam, infos);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(),
        DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0500, Function | SmallTest | Level0)
{
    // dual-mode device + different-package (clone) + non-system app -> rejected with NOT_SYSTEM_APP, no mutation
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo normalInfo;  // isSystemApp defaults to false
    normalInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNSPECIFIED);
    infos[BUNDLE_NAME] = normalInfo;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos),
        OHOS::ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP);
    // rejected before the set-loop: clone flag stays false, deviceModeDistributionPolicy unchanged
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(), DeviceModeDistributionPolicy::UNSPECIFIED);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0600, Function | SmallTest | Level0)
{
    // dual-mode device + different-package (clone) + mixed (system + non-system) -> rejected, no partial mutation
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo systemInfo;
    ApplicationInfo systemAppInfo;
    systemAppInfo.isSystemApp = true;
    systemInfo.SetBaseApplicationInfo(systemAppInfo);
    InnerBundleInfo normalInfo;  // isSystemApp = false
    normalInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNSPECIFIED);
    infos["com.system.app"] = systemInfo;
    infos["com.normal.app"] = normalInfo;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos),
        OHOS::ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP);
    // rejected before the set-loop regardless of iteration order: neither info mutated
    EXPECT_FALSE(infos["com.system.app"].IsDualModeCloneApp());
    EXPECT_FALSE(infos["com.normal.app"].IsDualModeCloneApp());
    EXPECT_EQ(infos["com.normal.app"].GetDeviceModeDistributionPolicy(), DeviceModeDistributionPolicy::UNSPECIFIED);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0700, Function | SmallTest | Level0)
{
    // primary mode + different-package + system app -> policy set, clone flag NOT set (primary mode is not
    // clone), ERR_OK. The system-app check now applies to different-package regardless of mode.
    EnablePrimaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo systemInfo;
    ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    systemInfo.SetBaseApplicationInfo(appInfo);
    infos[BUNDLE_NAME] = systemInfo;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos), OHOS::ERR_OK);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(),
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0800, Function | SmallTest | Level0)
{
    // primary mode + different-package + non-system app -> rejected with NOT_SYSTEM_APP. The system-app
    // check applies to different-package in both modes, not only the secondary-mode clone path.
    EnablePrimaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo normalInfo;  // isSystemApp defaults to false
    normalInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNSPECIFIED);
    infos[BUNDLE_NAME] = normalInfo;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos),
        OHOS::ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(), DeviceModeDistributionPolicy::UNSPECIFIED);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_0900, Function | SmallTest | Level0)
{
    // Sync-27: a successful dual-mode install persists appSandboxPolicy on the info (the sticky-isolation
    // source of truth) via ComputeCurrentAppSandboxPolicy. diff-package -> ISOLATED; non-diff -> SHARED.
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo systemInfo;
    ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    systemInfo.SetBaseApplicationInfo(appInfo);
    infos[BUNDLE_NAME] = systemInfo;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos), OHOS::ERR_OK);
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::ISOLATED_SANDBOX);

    // non-diff policy persists SHARED (derived from the policy; before stays default SHARED -> not sticky)
    std::unordered_map<std::string, InnerBundleInfo> infos2;
    InnerBundleInfo systemInfo2;
    ApplicationInfo appInfo2;
    appInfo2.isSystemApp = true;
    systemInfo2.SetBaseApplicationInfo(appInfo2);
    infos2[BUNDLE_NAME] = systemInfo2;
    InstallParam installParam2;
    installParam2.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam2, infos2), OHOS::ERR_OK);
    EXPECT_EQ(infos2[BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::SHARED_SANDBOX);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_1000, Function | SmallTest | Level0)
{
    // MAIN_ONLY is primary-mode-only; installing it in secondary mode is rejected (the policy is not
    // supported in the current device mode) and no info is mutated (the check runs before the set-loop).
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo normalInfo;
    normalInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNSPECIFIED);
    infos[BUNDLE_NAME] = normalInfo;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos),
        OHOS::ERR_APPEXECFWK_INSTALL_DUAL_MODE_POLICY_NOT_SUPPORTED);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(), DeviceModeDistributionPolicy::UNSPECIFIED);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_1100, Function | SmallTest | Level0)
{
    // SUB_ONLY is secondary-mode-only; installing it in primary mode is rejected (the policy is not
    // supported in the current device mode) and no info is mutated.
    EnablePrimaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo normalInfo;
    normalInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNSPECIFIED);
    infos[BUNDLE_NAME] = normalInfo;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::SUB_ONLY;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos),
        OHOS::ERR_APPEXECFWK_INSTALL_DUAL_MODE_POLICY_NOT_SUPPORTED);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(), DeviceModeDistributionPolicy::UNSPECIFIED);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_1200, Function | SmallTest | Level0)
{
    // MAIN_ONLY in primary mode is admissible; policy is set, clone flag stays false (primary mode
    // is not a clone), sandbox policy derives SHARED (non-different-package).
    EnablePrimaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = InnerBundleInfo();
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos), OHOS::ERR_OK);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(), DeviceModeDistributionPolicy::MAIN_ONLY);
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::SHARED_SANDBOX);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_1300, Function | SmallTest | Level0)
{
    // SUB_ONLY in secondary mode is admissible; policy is set, clone flag stays false (SUB_ONLY is
    // not a different-package category so it does not trigger clone isolation), sandbox policy SHARED.
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = InnerBundleInfo();
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::SUB_ONLY;
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos), OHOS::ERR_OK);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(), DeviceModeDistributionPolicy::SUB_ONLY);
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::SHARED_SANDBOX);
}

// ====================== BaseBundleInstaller::CheckDualModeCategoryConsistency ======================

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0100, Function | SmallTest | Level0)
{
    // not a dual-mode device -> ERR_OK even if category crosses 7
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    InnerBundleInfo oldInfo;
    oldInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam), OHOS::ERR_OK);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0200, Function | SmallTest | Level0)
{
    // app does not exist -> ERR_OK (no consistency to check)
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.isAppExist_ = false;
    InnerBundleInfo oldInfo;
    oldInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam), OHOS::ERR_OK);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0300, Function | SmallTest | Level0)
{
    // dual-mode + app exists + cross 7<->non-7 -> ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    InnerBundleInfo oldInfo;
    oldInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam),
        OHOS::ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0400, Function | SmallTest | Level0)
{
    // dual-mode + both different-package -> consistent -> ERR_OK
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    InnerBundleInfo oldInfo;
    oldInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam), OHOS::ERR_OK);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistency_0500, Function | SmallTest | Level0)
{
    // dual-mode + both non-different-package -> consistent -> ERR_OK
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    InnerBundleInfo oldInfo;
    oldInfo.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::MAIN_ONLY);
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::SUB_ONLY;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistency(oldInfo, installParam), OHOS::ERR_OK);
}

// ====================== BaseBundleInstaller::CheckDualModeCategoryConsistencyInTemp ======================
// Cross-map (tempBundleInfos_) different-package consistency — the other-mode variant of the same bundleName.
// dataMgr_ + bundleName_ + tempBundleInfos_ entry drive FetchTempBundleInfo; different-package-ness mismatch
// between the temp variant and the current install returns ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT.

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistencyInTemp_0100, Function | SmallTest | Level0)
{
    // not a dual-mode device -> early return ERR_OK (dataMgr_ not touched)
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistencyInTemp(installParam), OHOS::ERR_OK);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistencyInTemp_0200, Function | SmallTest | Level0)
{
    // dual-mode device but bundleName_ absent from tempBundleInfos_ -> FetchTempBundleInfo false -> ERR_OK
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    installer.dataMgr_ = dataMgr;  // tempBundleInfos_ empty -> not found
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistencyInTemp(installParam), OHOS::ERR_OK);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistencyInTemp_0300, Function | SmallTest | Level0)
{
    // dual-mode + temp variant is different-package + new install is different-package -> consistent -> ERR_OK
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeCat7Info(false);  // existing temp variant, diff-package
    installer.dataMgr_ = dataMgr;
    InstallParam installParam;
    // new install is different-package
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistencyInTemp(installParam), OHOS::ERR_OK);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistencyInTemp_0400, Function | SmallTest | Level0)
{
    // dual-mode + temp variant is different-package + new install is non-different-package -> mismatch -> CONFLICT
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeCat7Info(false);  // existing temp diff-package
    installer.dataMgr_ = dataMgr;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;  // new non-diff-package
    EXPECT_EQ(installer.CheckDualModeCategoryConsistencyInTemp(installParam),
        OHOS::ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT);
}

HWTEST_F(BmsDualModeInstallTest, CheckDualModeCategoryConsistencyInTemp_0500, Function | SmallTest | Level0)
{
    // dual-mode + temp variant is non-different-package + new install is different-package
    // -> mismatch (other dir) -> CONFLICT
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo nonCat7Temp;
    // existing temp variant is non-diff-package
    nonCat7Temp.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = nonCat7Temp;
    installer.dataMgr_ = dataMgr;
    InstallParam installParam;
    // new install is different-package
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    EXPECT_EQ(installer.CheckDualModeCategoryConsistencyInTemp(installParam),
        OHOS::ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT);
}

// ====================== BaseBundleInstaller::InitTempBundleFromCache ======================
// Clone-key input (+clone-10000+X) is parsed back to the original name for the storage lookup.
// crossMode is decided by IsCrossModeInstall() (fan-out) or, for the user-100 path (role=NONE +
// policy=UNSPECIFIED), by the second branch: a clone-named secondary variant is cross (hidden in
// tempBundleInfos_) when the device is NOT in secondary mode. The second branch is guarded by
// IsDualModeDevice() so a stray clone key on a non-dual-mode device falls through to
// FetchInnerBundleInfo (tempBundleInfos_ is empty there).

static InnerBundleInfo MakeNamedInfo(const std::string &name)
{
    InnerBundleInfo info;
    ApplicationInfo appInfo;
    appInfo.bundleName = name;
    info.SetBaseApplicationInfo(appInfo);
    return info;
}

HWTEST_F(BmsDualModeInstallTest, InitTempBundleFromCache_0100, Function | SmallTest | Level0)
{
    // Non-dual-mode device + clone key (data residue) + package in bundleInfos_ (original name):
    // must fall through to FetchInnerBundleInfo. Before the IsDualModeDevice() guard,
    // !IsSecondaryMode() (always true on non-dual-mode) wrongly set crossMode=true and queried the
    // empty tempBundleInfos_, returning isAppExist=false.
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    BaseBundleInstaller installer;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeNamedInfo(BUNDLE_NAME);
    installer.dataMgr_ = dataMgr;
    InnerBundleInfo info;
    bool isAppExist = false;
    EXPECT_TRUE(installer.InitTempBundleFromCache(info, isAppExist, PREFIXED_NAME));
    EXPECT_TRUE(isAppExist);                         // found via FetchInnerBundleInfo(lookupKey)
    EXPECT_EQ(installer.bundleName_, BUNDLE_NAME);  // clone key parsed back to original name
}

HWTEST_F(BmsDualModeInstallTest, InitTempBundleFromCache_0200, Function | SmallTest | Level0)
{
    // Non-dual-mode device + clone key + package absent: crossMode stays false (not wrongly true),
    // isAppExist=false, bundleName_ normalized to the original name.
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    BaseBundleInstaller installer;
    installer.dataMgr_ = std::make_shared<BundleDataMgr>();  // both maps empty
    InnerBundleInfo info;
    bool isAppExist = true;  // poisoned to detect the pre-fix misclassification
    EXPECT_TRUE(installer.InitTempBundleFromCache(info, isAppExist, PREFIXED_NAME));
    EXPECT_FALSE(isAppExist);
    EXPECT_EQ(installer.bundleName_, BUNDLE_NAME);
}

HWTEST_F(BmsDualModeInstallTest, InitTempBundleFromCache_0300, Function | SmallTest | Level0)
{
    // Dual-mode primary device + clone key: secondary variant is hidden in tempBundleInfos_
    // (original-name key); the second branch sets crossMode=true (NOT secondary mode) ->
    // FetchTempBundleInfo finds it.
    EnablePrimaryMode();
    BaseBundleInstaller installer;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeNamedInfo(BUNDLE_NAME);
    installer.dataMgr_ = dataMgr;
    InnerBundleInfo info;
    bool isAppExist = false;
    EXPECT_TRUE(installer.InitTempBundleFromCache(info, isAppExist, PREFIXED_NAME));
    EXPECT_TRUE(isAppExist);
    EXPECT_EQ(installer.bundleName_, BUNDLE_NAME);
}

HWTEST_F(BmsDualModeInstallTest, InitTempBundleFromCache_0400, Function | SmallTest | Level0)
{
    // Dual-mode secondary device + clone key: secondary variant is visible in bundleInfos_
    // (original-name key); the second branch leaves crossMode=false (IS secondary mode) ->
    // FetchInnerBundleInfo finds it.
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeNamedInfo(BUNDLE_NAME);
    installer.dataMgr_ = dataMgr;
    InnerBundleInfo info;
    bool isAppExist = false;
    EXPECT_TRUE(installer.InitTempBundleFromCache(info, isAppExist, PREFIXED_NAME));
    EXPECT_TRUE(isAppExist);
    EXPECT_EQ(installer.bundleName_, BUNDLE_NAME);
}

// ====================== BaseBundleInstaller::DeliveryProfileToCodeSign ======================
// Lines 8530-8532 (dual-mode effective-name selection for DeliverySignProfile):
//   deliveryBundleName = dualModeBundleName_.empty() ? provisionInfo.bundleInfo.bundleName
//                                                     : dualModeBundleName_;
// The mock InstalldClient::DeliverySignProfile returns ERR_APPEXECFWK_INSTALLD_PARAM_ERROR for an
// empty bundleName before reaching the service, ERR_OK/error otherwise. By leaving
// provisionInfo.bundleInfo.bundleName empty and toggling dualModeBundleName_, the two ternary
// branches yield distinguishable results without depending on the installd service.

HWTEST_F(BmsDualModeInstallTest, DeliveryProfileToCodeSign_0100, Function | SmallTest | Level0)
{
    // dualModeBundleName_ empty -> true branch -> deliveryBundleName = provision name (empty)
    // -> DeliverySignProfile gets empty name -> mock returns INSTALLD_PARAM_ERROR
    BaseBundleInstaller installer;
    installer.dualModeBundleName_.clear();
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;  // enter the delivery if-block
    provisionInfo.profileBlockLength = 1;
    provisionInfo.bundleInfo.bundleName = "";  // empty
    provisionInfo.profileBlock = std::make_unique<unsigned char[]>(provisionInfo.profileBlockLength);
    installer.verifyRes_.SetProvisionInfo(provisionInfo);
    EXPECT_EQ(installer.DeliveryProfileToCodeSign(), OHOS::ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

HWTEST_F(BmsDualModeInstallTest, DeliveryProfileToCodeSign_0200, Function | SmallTest | Level0)
{
    // dualModeBundleName_ non-empty -> false branch -> deliveryBundleName = dualModeBundleName_
    // (prefixed, non-empty; the empty provision name must NOT be used) -> name reaches the service
    BaseBundleInstaller installer;
    installer.dualModeBundleName_ = PREFIXED_NAME;  // non-empty
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    provisionInfo.profileBlockLength = 1;
    provisionInfo.bundleInfo.bundleName = "";  // empty, but the false branch must skip it
    provisionInfo.profileBlock = std::make_unique<unsigned char[]>(provisionInfo.profileBlockLength);
    installer.verifyRes_.SetProvisionInfo(provisionInfo);
    // non-empty name reached DeliverySignProfile (not the empty-name PARAM_ERROR path) -> false branch
    EXPECT_NE(installer.DeliveryProfileToCodeSign(), OHOS::ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

// ====================== BundleDataMgr::ClassifyDualModeAppsNoLock ======================
// dataMgr is a process-wide singleton obtained via BundleMgrService; clear bundleInfos_ /
// tempBundleInfos_ before each case to avoid cross-case residue.

HWTEST_F(BmsDualModeInstallTest, ClassifyDualModeAppsNoLock_0100, Function | SmallTest | Level0)
{
    // not a dual-mode device -> early return, bundleInfos_ unchanged
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
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
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_2IN1);
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
    // non-different-package app is never classified, stays in bundleInfos_
    EnableSecondaryMode();
    std::shared_ptr<BundleDataMgr> dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();
    InnerBundleInfo normal;
    normal.SetDeviceModeDistributionPolicy(DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr->bundleInfos_[BUNDLE_NAME] = normal;
    dataMgr->ClassifyDualModeAppsNoLock();
    EXPECT_EQ(dataMgr->tempBundleInfos_.count(BUNDLE_NAME), 1u);
    EXPECT_TRUE(dataMgr->bundleInfos_.empty());
}

HWTEST_F(BmsDualModeInstallTest, ClassifyDualModeAppsNoLock_0500, Function | SmallTest | Level0)
{
    // primary mode: different-package app under original key (non-prefixed) is NOT moved
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_2IN1);
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
    // secondary mode: different-package primary (original key, non-clone) with NO clone counterpart in
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
// CreateHapInfoParams is static; exposed via #define private public. It propagates
// InnerBundleInfo.GetAppIndex() directly to hapInfo.instIndex; a dual-mode clone app carries
// appIndex = DUAL_MODE_CLONE_APP_INDEX (set by SetDualModeAppInfo), yielding an independent hap token.

HWTEST_F(BmsDualModeInstallTest, CreateHapInfoParams_0100, Function | SmallTest | Level0)
{
    // dual-mode clone app: appIndex is set to DUAL_MODE_CLONE_APP_INDEX (10000) by SetDualModeAppInfo;
    // CreateHapInfoParams propagates GetAppIndex() directly to instIndex (10000) for an independent hap token.
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.SetAppIndex(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    auto hapInfo = BundlePermissionMgr::CreateHapInfoParams(info, 0, 0);
    EXPECT_EQ(hapInfo.instIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeInstallTest, CreateHapInfoParams_0200, Function | SmallTest | Level0)
{
    // dual-mode clone app + non-default appIndex -> instIndex = appIndex (propagated directly)
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.SetAppIndex(1);
    auto hapInfo = BundlePermissionMgr::CreateHapInfoParams(info, 0, 0);
    EXPECT_EQ(hapInfo.instIndex, 1);
}

HWTEST_F(BmsDualModeInstallTest, CreateHapInfoParams_0300, Function | SmallTest | Level0)
{
    // non-clone app + appIndex 0 -> instIndex = 0 (propagated directly)
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.SetAppIndex(0);
    auto hapInfo = BundlePermissionMgr::CreateHapInfoParams(info, 0, 0);
    EXPECT_EQ(hapInfo.instIndex, 0);
}

HWTEST_F(BmsDualModeInstallTest, CreateHapInfoParams_0400, Function | SmallTest | Level0)
{
    // non-clone app + appIndex != 0 -> instIndex = appIndex (propagated directly)
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

// ====================== BundleInfo.deviceModeDistributionPolicy persistence contract ======================
// DeviceModeDistributionPolicy serialization contract (enum int value / default value drift). Default value is
// UNSPECIFIED (0); the field must survive Parcel + JSON round trips and legacy (field-absent)
// deserialization. Round-trip cases use non-default values (4 / 1) so a broken or no-op marshal
// is caught instead of masked by default-in/default-out.

HWTEST_F(BmsDualModeInstallTest, DeviceModeDistributionPolicy_Default_0100, Function | SmallTest | Level0)
{
    // BundleInfo default deviceModeDistributionPolicy == UNSPECIFIED (value 0)
    BundleInfo bundleInfo;
    EXPECT_EQ(bundleInfo.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNSPECIFIED);
    EXPECT_EQ(static_cast<int32_t>(bundleInfo.deviceModeDistributionPolicy), 0);
}

HWTEST_F(BmsDualModeInstallTest, DeviceModeDistributionPolicy_Default_0200, Function | SmallTest | Level0)
{
    // InstallParam default deviceModeDistributionPolicy == UNSPECIFIED (value 0)
    InstallParam installParam;
    EXPECT_EQ(installParam.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNSPECIFIED);
    EXPECT_EQ(static_cast<int32_t>(installParam.deviceModeDistributionPolicy), 0);
}

HWTEST_F(BmsDualModeInstallTest, DeviceModeDistributionPolicy_Parcel_0100, Function | SmallTest | Level0)
{
    // different-package value (4) survives Parcel Marshalling/ReadFromParcel round trip
    OHOS::MessageParcel parcel;
    BundleInfo src;
    src.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    ASSERT_TRUE(src.Marshalling(parcel));
    BundleInfo dst;
    ASSERT_TRUE(dst.ReadFromParcel(parcel));
    EXPECT_EQ(dst.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(static_cast<int32_t>(dst.deviceModeDistributionPolicy), 4);
}

HWTEST_F(BmsDualModeInstallTest, DeviceModeDistributionPolicy_Parcel_0200, Function | SmallTest | Level0)
{
    // New enum values are mutually exclusive (no bitwise-or). A non-different-package value
    // (MAIN_ONLY = 1) also survives Parcel round trip, covering the non-isolation serialization branch.
    OHOS::MessageParcel parcel;
    BundleInfo src;
    src.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    ASSERT_TRUE(src.Marshalling(parcel));
    BundleInfo dst;
    ASSERT_TRUE(dst.ReadFromParcel(parcel));
    EXPECT_EQ(dst.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::MAIN_ONLY);
    EXPECT_EQ(static_cast<int32_t>(dst.deviceModeDistributionPolicy), 1);
}

HWTEST_F(BmsDualModeInstallTest, DeviceModeDistributionPolicy_JsonRoundTrip_0100, Function | SmallTest | Level0)
{
    // different-package value (4) survives to_json/from_json round trip
    BundleInfo src;
    src.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    nlohmann::json jsonObject;
    to_json(jsonObject, src);
    BundleInfo dst;
    from_json(jsonObject, dst);
    EXPECT_EQ(dst.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(static_cast<int32_t>(dst.deviceModeDistributionPolicy), 4);
}

HWTEST_F(BmsDualModeInstallTest, DeviceModeDistributionPolicy_LegacyDefault_0100, Function | SmallTest | Level0)
{
    // legacy stored JSON without a deviceModeDistributionPolicy field deserializes to the default
    // UNSPECIFIED (0) — from_json's GetValueIfFindKey must not mutate the field when absent
    nlohmann::json legacyJson = {{"name", "com.test.legacy"}};  // intentionally no deviceModeDistributionPolicy key
    BundleInfo dst;
    from_json(legacyJson, dst);
    EXPECT_EQ(dst.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNSPECIFIED);
    EXPECT_EQ(static_cast<int32_t>(dst.deviceModeDistributionPolicy), 0);
}

// ====================== InstallParam::RefreshDeviceModeDistributionPolicy (TS parameters passthrough) =====
// TS install interfaces pass the policy through the existing installParam.parameters channel as the
// reserved key Constants::DEVICE_MODE_DISTRIBUTION_POLICY_KEY with a decimal-string enum value; the
// install adapters (NAPI installer.cpp Install / ANI ani_bundle_installer.cpp AniInstall path) invoke
// this method right after CheckInstallParam. Contract: an absent key leaves the field untouched
// (zero regression for existing callers), a valid decimal string within [0,8] refreshes the field
// before the IPC hop, and any other value is rejected (adapters log a warning and continue with the
// default policy, per the 2026-08-17 ruling: no BusinessError 401) without mutating the field.

HWTEST_F(BmsDualModeInstallTest, RefreshDeviceModeDistributionPolicy_0100, Function | SmallTest | Level0)
{
    // key present with valid value "4" -> field refreshed to UNIVERSAL_DIFFERENT_PACKAGE (4)
    InstallParam installParam;
    installParam.parameters[Constants::DEVICE_MODE_DISTRIBUTION_POLICY_KEY] = "4";
    EXPECT_TRUE(installParam.RefreshDeviceModeDistributionPolicy());
    EXPECT_EQ(installParam.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(static_cast<int32_t>(installParam.deviceModeDistributionPolicy), 4);
}

HWTEST_F(BmsDualModeInstallTest, RefreshDeviceModeDistributionPolicy_0200, Function | SmallTest | Level0)
{
    // key absent -> true (accepted, nothing to refresh) and a pre-set field is NOT overwritten,
    // covering both the fresh default and an already-populated IPC value
    InstallParam installParam;
    EXPECT_TRUE(installParam.RefreshDeviceModeDistributionPolicy());
    EXPECT_EQ(installParam.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNSPECIFIED);
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    EXPECT_TRUE(installParam.RefreshDeviceModeDistributionPolicy());
    EXPECT_EQ(installParam.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::MAIN_ONLY);
}

HWTEST_F(BmsDualModeInstallTest, RefreshDeviceModeDistributionPolicy_0300, Function | SmallTest | Level0)
{
    // range boundaries "0"/"8" and leading-zero decimal "04" are accepted
    InstallParam installParam;
    installParam.parameters[Constants::DEVICE_MODE_DISTRIBUTION_POLICY_KEY] = "0";
    EXPECT_TRUE(installParam.RefreshDeviceModeDistributionPolicy());
    EXPECT_EQ(installParam.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNSPECIFIED);
    installParam.parameters[Constants::DEVICE_MODE_DISTRIBUTION_POLICY_KEY] = "8";
    EXPECT_TRUE(installParam.RefreshDeviceModeDistributionPolicy());
    EXPECT_EQ(installParam.deviceModeDistributionPolicy,
        DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);
    installParam.parameters[Constants::DEVICE_MODE_DISTRIBUTION_POLICY_KEY] = "04";
    EXPECT_TRUE(installParam.RefreshDeviceModeDistributionPolicy());
    EXPECT_EQ(installParam.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
}

HWTEST_F(BmsDualModeInstallTest, RefreshDeviceModeDistributionPolicy_0400, Function | SmallTest | Level0)
{
    // invalid values (non-digit / sign / space / trailing char / above range / empty / overflow-long)
    // are rejected with false and must not mutate the field from its pre-set value
    const std::vector<std::string> invalidValues = {"abc", "-1", " 4", "4x", "9", "", "99999999999999"};
    for (const auto &value : invalidValues) {
        InstallParam installParam;
        installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;  // sentinel
        installParam.parameters[Constants::DEVICE_MODE_DISTRIBUTION_POLICY_KEY] = value;
        EXPECT_FALSE(installParam.RefreshDeviceModeDistributionPolicy()) << "value: " << value;
        EXPECT_EQ(installParam.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::MAIN_ONLY)
            << "value: " << value;
    }
}

HWTEST_F(BmsDualModeInstallTest, RefreshDeviceModeDistributionPolicy_0500, Function | SmallTest | Level0)
{
    // refreshed field survives the existing Parcel hop so the value reaches the service side intact
    InstallParam installParam;
    installParam.parameters[Constants::DEVICE_MODE_DISTRIBUTION_POLICY_KEY] = "6";
    ASSERT_TRUE(installParam.RefreshDeviceModeDistributionPolicy());
    OHOS::MessageParcel parcel;
    ASSERT_TRUE(installParam.Marshalling(parcel));
    InstallParam dst;
    ASSERT_TRUE(dst.ReadFromParcel(parcel));
    EXPECT_EQ(dst.deviceModeDistributionPolicy,
        DeviceModeDistributionPolicy::PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE);
    EXPECT_EQ(static_cast<int32_t>(dst.deviceModeDistributionPolicy), 6);
}

HWTEST_F(BmsDualModeInstallTest, RefreshDeviceModeDistributionPolicy_0600, Function | SmallTest | Level0)
{
    // an out-of-range int32 on the wire (native caller bypassing the kit-layer value check) is
    // degraded to UNSPECIFIED by the server-side ReadFromParcel value-range whitelist, so the
    // overflow value never reaches the broadcast event fields (codecheck F-P2-01 hardening)
    for (const int32_t invalidPolicy : {999, -5}) {
        InstallParam installParam;
        installParam.deviceModeDistributionPolicy = static_cast<DeviceModeDistributionPolicy>(invalidPolicy);
        OHOS::MessageParcel parcel;
        ASSERT_TRUE(installParam.Marshalling(parcel));
        InstallParam dst;
        ASSERT_TRUE(dst.ReadFromParcel(parcel));
        EXPECT_EQ(dst.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNSPECIFIED)
            << "policy: " << invalidPolicy;
    }
    // whitelist boundaries pass through the same hop untouched
    for (const int32_t validPolicy : {0, 8}) {
        InstallParam installParam;
        installParam.deviceModeDistributionPolicy = static_cast<DeviceModeDistributionPolicy>(validPolicy);
        OHOS::MessageParcel parcel;
        ASSERT_TRUE(installParam.Marshalling(parcel));
        InstallParam dst;
        ASSERT_TRUE(dst.ReadFromParcel(parcel));
        EXPECT_EQ(static_cast<int32_t>(dst.deviceModeDistributionPolicy), validPolicy)
            << "policy: " << validPolicy;
    }
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
// DualModeHelper cache (no system parameter): true -> deviceModeDistributionPolicy / currentMode /
// appSandboxPolicy + beforeDeviceModeDistributionPolicy / beforeAppSandboxPolicy populated; false ->
// pre-set fields left untouched. BaseBundleInstaller is default-constructed and the private method
// (and before_* members) are reached through #define private public.

HWTEST_F(BmsDualModeInstallTest, FillDualModeEventFields_0100, Function | SmallTest | Level0)
{
    // dual-mode device (cache valid) + fresh install (before members stay default) + different-package:
    // current appSandboxPolicy = ISOLATED (derived from policy); before fields keep defaults.
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    NotifyBundleEvents installRes;
    installer.FillDualModeEventFields(installParam, installRes);
    EXPECT_EQ(installRes.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(installRes.currentMode, DualModeHelper::GetSysMode());
    // different-package (not sticky, before shared) => isolated sandbox
    EXPECT_EQ(installRes.appSandboxPolicy, AppSandboxPolicy::ISOLATED_SANDBOX);
    // fresh install: before values are defaults
    EXPECT_EQ(installRes.beforeDeviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNSPECIFIED);
    EXPECT_EQ(installRes.beforeAppSandboxPolicy, AppSandboxPolicy::SHARED_SANDBOX);
}

HWTEST_F(BmsDualModeInstallTest, FillDualModeEventFields_0200, Function | SmallTest | Level0)
{
    // non-dual-mode device (cache invalid) -> branch skipped, pre-set markers preserved
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    NotifyBundleEvents installRes;
    installRes.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::SUB_ONLY;  // non-default marker
    installRes.currentMode = 999;
    installRes.appSandboxPolicy = AppSandboxPolicy::ISOLATED_SANDBOX;  // flip default to prove not rewritten
    installRes.beforeAppSandboxPolicy = AppSandboxPolicy::ISOLATED_SANDBOX;  // non-default marker
    installer.FillDualModeEventFields(installParam, installRes);
    EXPECT_EQ(installRes.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::SUB_ONLY);
    EXPECT_EQ(installRes.currentMode, 999);
    EXPECT_EQ(installRes.appSandboxPolicy, AppSandboxPolicy::ISOLATED_SANDBOX);
    EXPECT_EQ(installRes.beforeAppSandboxPolicy, AppSandboxPolicy::ISOLATED_SANDBOX);
}

HWTEST_F(BmsDualModeInstallTest, FillDualModeEventFields_0300, Function | SmallTest | Level0)
{
    // Sticky isolation (Sync-27): before was ISOLATED, new policy is same-package (non-diff) which would
    // normally yield SHARED, but isolation is sticky -> current stays ISOLATED, independent of new policy.
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.beforeAppSandboxPolicy_ = AppSandboxPolicy::ISOLATED_SANDBOX;  // prior state: isolated
    installer.beforeDeviceModeDistributionPolicy_ = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE;
    NotifyBundleEvents installRes;
    installer.FillDualModeEventFields(installParam, installRes);
    // sticky: isolated before + same-package now -> still ISOLATED (not SHARED)
    EXPECT_EQ(installRes.appSandboxPolicy, AppSandboxPolicy::ISOLATED_SANDBOX);
    EXPECT_EQ(installRes.beforeAppSandboxPolicy, AppSandboxPolicy::ISOLATED_SANDBOX);
    EXPECT_EQ(installRes.beforeDeviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(installRes.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE);
}

HWTEST_F(BmsDualModeInstallTest, FillDualModeEventFields_0400, Function | SmallTest | Level0)
{
    // dual-mode device + clone install (dualModeBundleName_ set) -> event carries clone appIndex (10000)
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.dualModeBundleName_ = PREFIXED_NAME;  // dual-mode clone variant present
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    NotifyBundleEvents installRes;
    installer.FillDualModeEventFields(installParam, installRes);
    EXPECT_EQ(installRes.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeInstallTest, FillDualModeEventFields_0500, Function | SmallTest | Level0)
{
    // dual-mode device but non-clone (dualModeBundleName_ empty) -> appIndex is not modified
    EnableSecondaryMode();
    BaseBundleInstaller installer;  // dualModeBundleName_ defaults empty
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::MAIN_ONLY;
    NotifyBundleEvents installRes;
    installRes.appIndex = 7;  // pre-set marker to prove it is not overwritten
    installer.FillDualModeEventFields(installParam, installRes);
    EXPECT_EQ(installRes.appIndex, 7);
}

// ====================== BaseBundleInstaller sandbox policy & reset (Sync-27) ======================
// ComputeCurrentAppSandboxPolicy applies the sticky-isolation rule: an app that was already isolated
// stays isolated regardless of the new policy; otherwise the policy is derived (diff-package -> ISOLATED,
// same/other -> SHARED). Shared by SetDualModeAppInfo (persist) and FillDualModeEventFields (broadcast).

HWTEST_F(BmsDualModeInstallTest, ComputeCurrentAppSandboxPolicy_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    // before = SHARED (fresh-install default): derive from the new policy
    installer.beforeAppSandboxPolicy_ = AppSandboxPolicy::SHARED_SANDBOX;
    EXPECT_EQ(installer.ComputeCurrentAppSandboxPolicy(
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE), AppSandboxPolicy::ISOLATED_SANDBOX);
    EXPECT_EQ(installer.ComputeCurrentAppSandboxPolicy(
        DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE), AppSandboxPolicy::SHARED_SANDBOX);
    // before = ISOLATED: sticky, isolated regardless of the new policy
    installer.beforeAppSandboxPolicy_ = AppSandboxPolicy::ISOLATED_SANDBOX;
    EXPECT_EQ(installer.ComputeCurrentAppSandboxPolicy(
        DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE), AppSandboxPolicy::ISOLATED_SANDBOX);
    EXPECT_EQ(installer.ComputeCurrentAppSandboxPolicy(
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE), AppSandboxPolicy::ISOLATED_SANDBOX);
}

// ResetInstallProperties must clear the Sync-27 before-values so a reused installer instance does not
// leak the prior install's sandbox / distribution policy into the next fresh install. Before the fix they
// were not reset, so a second install on a reused instance broadcast stale before-values and could trip
// the sticky-isolation rule in ComputeCurrentAppSandboxPolicy.

HWTEST_F(BmsDualModeInstallTest, ResetInstallProperties_BeforeDualModeFields_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    // leftover state from a previous install on the same (reused) instance
    installer.beforeDeviceModeDistributionPolicy_ = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    installer.beforeAppSandboxPolicy_ = AppSandboxPolicy::ISOLATED_SANDBOX;
    installer.ResetInstallProperties();
    EXPECT_EQ(installer.beforeDeviceModeDistributionPolicy_, DeviceModeDistributionPolicy::UNSPECIFIED);
    EXPECT_EQ(installer.beforeAppSandboxPolicy_, AppSandboxPolicy::SHARED_SANDBOX);
}

HWTEST_F(BmsDualModeInstallTest, ResetInstallProperties_ClearsStickySandbox_0200, Function | SmallTest | Level0)
{
    // ComputeCurrentAppSandboxPolicy depends only on beforeAppSandboxPolicy_ + the new policy, not on the
    // mode cache; the point is that Reset clears the stale before-value so the sticky rule cannot fire.
    BaseBundleInstaller installer;
    installer.beforeAppSandboxPolicy_ = AppSandboxPolicy::ISOLATED_SANDBOX;  // stale from a prior install
    installer.ResetInstallProperties();
    // same-package policy normally yields SHARED; a stale ISOLATED before-value would force ISOLATED
    EXPECT_EQ(installer.ComputeCurrentAppSandboxPolicy(
        DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE), AppSandboxPolicy::SHARED_SANDBOX);
    // different-package still derives ISOLATED from the policy (not from a sticky before-value)
    EXPECT_EQ(installer.ComputeCurrentAppSandboxPolicy(
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE), AppSandboxPolicy::ISOLATED_SANDBOX);
}

// InnerBundleInfo sandbox-policy accessor (Sync-27): default SHARED_SANDBOX + round-trip.

HWTEST_F(BmsDualModeInstallTest, AppSandboxPolicy_InnerBundleInfo_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    EXPECT_EQ(info.GetAppSandboxPolicy(), AppSandboxPolicy::SHARED_SANDBOX);  // default
    info.SetAppSandboxPolicy(AppSandboxPolicy::ISOLATED_SANDBOX);
    EXPECT_EQ(info.GetAppSandboxPolicy(), AppSandboxPolicy::ISOLATED_SANDBOX);
    info.SetAppSandboxPolicy(AppSandboxPolicy::SHARED_SANDBOX);
    EXPECT_EQ(info.GetAppSandboxPolicy(), AppSandboxPolicy::SHARED_SANDBOX);
}

// Dual-mode system parameter keys: ispcmode stays persist.sceneboard.*; mainmode is a read-only boot
// constant under const.sceneboard.*. Both are read via GetIntParameter, which is prefix-agnostic.

HWTEST_F(BmsDualModeInstallTest, DualModeParamKeys_0100, Function | SmallTest | Level0)
{
    EXPECT_STREQ(ServiceConstants::DUAL_MODE_ISPCMODE_PARAM_KEY, "persist.sceneboard.ispcmode");
    EXPECT_STREQ(ServiceConstants::DUAL_MODE_MAINMODE_PARAM_KEY, "const.sceneboard.mainmode");
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

// ====================== BundleDataMgr::FetchTempBundleInfo ======================
// dual-mode: the same-name counterpart of a dual-mode app lives in tempBundleInfos_
// (the non-current-mode variant). Mirrors FetchInnerBundleInfo. Branches: empty name (false),
// not found in tempBundleInfos_ (false), found (true + copy out param).

HWTEST_F(BmsDualModeInstallTest, FetchTempBundleInfo_EmptyName_0100, Function | SmallTest | Level0)
{
    // bundleName empty -> early return false before the lock; out param left untouched.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo sentinel = MakeResourceInfo(true);
    InnerBundleInfo out = sentinel;
    EXPECT_FALSE(dataMgr->FetchTempBundleInfo("", out));
    EXPECT_TRUE(out.IsDualModeCloneApp());  // unchanged, same as sentinel
}

HWTEST_F(BmsDualModeInstallTest, FetchTempBundleInfo_NotFound_0200, Function | SmallTest | Level0)
{
    // bundleName non-empty but absent from tempBundleInfos_ -> return false.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->tempBundleInfos_.clear();
    InnerBundleInfo out;
    EXPECT_FALSE(dataMgr->FetchTempBundleInfo(BUNDLE_NAME, out));
}

HWTEST_F(BmsDualModeInstallTest, FetchTempBundleInfo_FoundAssign_0300, Function | SmallTest | Level0)
{
    // tempBundleInfos_ holds the dual-mode same-name counterpart -> return true and copy it out.
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeResourceInfo(true);  // clone variant lives in temp
    InnerBundleInfo out;
    EXPECT_TRUE(dataMgr->FetchTempBundleInfo(BUNDLE_NAME, out));
    EXPECT_EQ(out.GetBundleName(), BUNDLE_NAME);
    EXPECT_TRUE(out.IsDualModeCloneApp());
}

// ====================== BaseBundleInstaller::SetDualModeAppInfo ======================
// Sets deviceModeDistributionPolicy / isDualModeCloneApp / appIndex / appSandboxPolicy on each info.
// Guards: non-dual-mode device (no-op), invalid policy value (range check -> PARAM_ERROR), non-system
// app + different-package (NOT_SYSTEM_APP). isCloneApp (clone flag + appIndex=10000) is set only in
// secondary mode + different-package. BaseBundleInstaller is default-constructed and the private method
// is reached through #define private public, like FillDualModeEventFields above.

static InnerBundleInfo MakeDualModeInstallInfo(bool isSystemApp)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_->isSystemApp = isSystemApp;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    return info;
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_NonDualModeDevice_Guard_0100, Function | SmallTest | Level0)
{
    // non-dual-mode device (cache invalid) -> guard returns ERR_OK before touching any info; the
    // policy/clone flag stay at their defaults, proving dual-mode handling is fully skipped.
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = MakeDualModeInstallInfo(true);
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos), ERR_OK);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(), DeviceModeDistributionPolicy::UNSPECIFIED);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_InvalidPolicy_RangeCheck_0200, Function | SmallTest | Level0)
{
    // out-of-range policy (native IPC caller bypassing the kit-layer value check) is rejected before
    // any flag is persisted, so the overflow value never reaches the broadcast event fields.
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = static_cast<DeviceModeDistributionPolicy>(999);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = MakeDualModeInstallInfo(true);
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos),
        ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_NonSystemApp_DiffPackage_Rejected_0300,
    Function | SmallTest | Level0)
{
    // different-package is a system-level capability: a non-system app is rejected with
    // ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP before the clone flag is set, and the check runs
    // before isCloneApp so a failed non-system app leaves no isDualModeCloneApp=true side effect.
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = MakeDualModeInstallInfo(false);  // non-system app
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos),
        ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());  // no side effect on failure
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_Secondary_DiffPackage_CloneFlagSet_0400,
    Function | SmallTest | Level0)
{
    // secondary mode + different-package + system app -> isCloneApp=true: clone flag set, appIndex=10000,
    // policy persisted, sandbox derived ISOLATED (diff-package, before=SHARED fresh install).
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.beforeAppSandboxPolicy_ = AppSandboxPolicy::SHARED_SANDBOX;  // fresh-install default
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = MakeDualModeInstallInfo(true);
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos), ERR_OK);
    EXPECT_TRUE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppIndex(), ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(),
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::ISOLATED_SANDBOX);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_Primary_DiffPackage_NoCloneFlag_0500,
    Function | SmallTest | Level0)
{
    // primary mode (ispcmode==mainmode) + different-package -> isCloneApp=false (NeedDualModeHandle is
    // secondary-only): the policy is still persisted and sandbox derived, but no clone flag/appIndex.
    EnablePrimaryMode();
    BaseBundleInstaller installer;
    installer.beforeAppSandboxPolicy_ = AppSandboxPolicy::SHARED_SANDBOX;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = MakeDualModeInstallInfo(true);
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos), ERR_OK);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(),
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::ISOLATED_SANDBOX);
}

HWTEST_F(BmsDualModeInstallTest, SetDualModeAppInfo_NonDiffPackage_NoCloneFlag_0600,
    Function | SmallTest | Level0)
{
    // non-different-package (same-package) policy -> isCloneApp=false and no system-app gate; sandbox
    // derives SHARED (same-package, before=SHARED). Proves the clone flag is gated on diff-package.
    EnableSecondaryMode();
    BaseBundleInstaller installer;
    installer.beforeAppSandboxPolicy_ = AppSandboxPolicy::SHARED_SANDBOX;
    InstallParam installParam;
    installParam.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos[BUNDLE_NAME] = MakeDualModeInstallInfo(false);  // non-system app, but non-diff -> no gate
    EXPECT_EQ(installer.SetDualModeAppInfo(installParam, infos), ERR_OK);
    EXPECT_FALSE(infos[BUNDLE_NAME].IsDualModeCloneApp());
    EXPECT_EQ(infos[BUNDLE_NAME].GetDeviceModeDistributionPolicy(),
        DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE);
    EXPECT_EQ(infos[BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::SHARED_SANDBOX);
}

// ====================== bundleInfos_ key contract (ADR-4 / P1 regression guard) ======================
// bundleInfos_ is keyed by the ORIGINAL bundleName (clone apps are classified in at load time, key
// stays original). The P1 fix split SaveInstallInfoToCache so FetchInnerBundleInfo/AddInnerBundleInfo
// receive the original name while directories/installStates_ use the effective name. This guards the
// data-layer contract the fix relies on: a clone app is findable by its original name and NOT by the
// effective (prefixed) name, so passing the effective name to these lookups (the original bug) would miss.

HWTEST_F(BmsDualModeInstallTest, FetchInnerBundleInfo_DualModeClone_OriginalNameKey_0100,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo cloneInfo = MakeCat7Info(true);
    cloneInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = cloneInfo;  // ADR-4: keyed by original name
    InnerBundleInfo out;
    EXPECT_TRUE(dataMgr->FetchInnerBundleInfo(BUNDLE_NAME, out));       // original key -> found
    EXPECT_TRUE(out.IsDualModeCloneApp());
    EXPECT_FALSE(dataMgr->FetchInnerBundleInfo(PREFIXED_NAME, out));   // effective key -> not found
}
} // OHOS
