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

#define private public

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "application_info.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_resource_host_impl.h"
#include "bundle_resource_info.h"
#include "inner_bundle_info.h"
#include "launcher_ability_resource_info.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int32_t USERID = 100;
const std::string SYSTEM_BUNDLE_NAME = "com.ohos.systemapp";
const std::string THIRD_PARTY_BUNDLE_NAME = "com.example.thirdparty";
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "MainAbility";
const std::string BOPD_MODE_PARAM = "ohos.boot.bopd.mode";
const std::string VALID_BOPD_MODE = "0x2";
const std::vector<uint8_t> ICON_BYTES = {0x01, 0x02, 0x03, 0x04};
const std::vector<uint8_t> FG_BYTES = {0x05, 0x06, 0x07, 0x08};
const std::vector<uint8_t> BG_BYTES = {0x09, 0x0A, 0x0B, 0x0C};
}  // namespace

class BmsBundleResourceBopdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    InnerBundleInfo MakeInnerBundleInfo(const std::string &bundleName, bool isSystemApp) const;
    void InjectBundle(const std::string &bundleName, const InnerBundleInfo &info);
    void RemoveBundle(const std::string &bundleName);
    bool IsBopdModeEnabled() const;
    static bool IconCleared(const BundleResourceInfo &info);
    static bool IconCleared(const LauncherAbilityResourceInfo &info);

    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleResourceBopdTest::bundleMgrService_ = nullptr;

void BmsBundleResourceBopdTest::SetUpTestCase()
{
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
}

void BmsBundleResourceBopdTest::TearDownTestCase()
{
    bundleMgrService_ = nullptr;
    DelayedSingleton<BundleMgrService>::DestroyInstance();
}

void BmsBundleResourceBopdTest::SetUp()
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "");
}

void BmsBundleResourceBopdTest::TearDown()
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "");
    auto dataMgr = bundleMgrService_ != nullptr ? bundleMgrService_->GetDataMgr() : nullptr;
    if (dataMgr != nullptr) {
        dataMgr->bundleInfos_.erase(SYSTEM_BUNDLE_NAME);
        dataMgr->bundleInfos_.erase(THIRD_PARTY_BUNDLE_NAME);
    }
}

InnerBundleInfo BmsBundleResourceBopdTest::MakeInnerBundleInfo(const std::string &bundleName,
    bool isSystemApp) const
{
    InnerBundleInfo info;
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    appInfo.isSystemApp = isSystemApp;
    info.SetBaseApplicationInfo(appInfo);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    info.innerBundleUserInfos_[bundleName + "_" + std::to_string(USERID)] = userInfo;
    return info;
}

void BmsBundleResourceBopdTest::InjectBundle(const std::string &bundleName, const InnerBundleInfo &info)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_[bundleName] = info;
}

void BmsBundleResourceBopdTest::RemoveBundle(const std::string &bundleName)
{
    auto dataMgr = bundleMgrService_ != nullptr ? bundleMgrService_->GetDataMgr() : nullptr;
    if (dataMgr != nullptr) {
        dataMgr->bundleInfos_.erase(bundleName);
    }
}

bool BmsBundleResourceBopdTest::IsBopdModeEnabled() const
{
    auto dataMgr = bundleMgrService_ != nullptr ? bundleMgrService_->GetDataMgr() : nullptr;
    if (dataMgr == nullptr) {
        return false;
    }
    return dataMgr->IsBopdModeEnabled();
}

bool BmsBundleResourceBopdTest::IconCleared(const BundleResourceInfo &info)
{
    return info.icon.empty() && info.foreground.empty() && info.background.empty();
}

bool BmsBundleResourceBopdTest::IconCleared(const LauncherAbilityResourceInfo &info)
{
    return info.icon.empty() && info.foreground.empty() && info.background.empty();
}

static void FillBundleResourceInfo(BundleResourceInfo &info, const std::string &bundleName)
{
    info.bundleName = bundleName;
    info.label = "Test App";
    info.icon = "/data/icons/" + bundleName + ".png";
    info.foreground = FG_BYTES;
    info.background = BG_BYTES;
    info.appIndex = 0;
}

static void FillLauncherAbilityResourceInfo(LauncherAbilityResourceInfo &info, const std::string &bundleName)
{
    info.bundleName = bundleName;
    info.moduleName = MODULE_NAME;
    info.abilityName = ABILITY_NAME;
    info.label = "Test App";
    info.icon = "/data/icons/" + bundleName + ".png";
    info.foreground = FG_BYTES;
    info.background = BG_BYTES;
    info.appIndex = 0;
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0001
 * @tc.name: test IsBopdModeEnabled returns true for valid modes
 * @tc.desc: 1. set ohos.boot.bopd.mode to each valid value
 *           2. verify IsBopdModeEnabled returns true
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0001, Function | SmallTest | Level0)
{
    const std::vector<std::string> validModes = {"0x2", "0x3", "0x6", "0x7", "0xa", "0xe", "0xf"};
    for (const auto &mode : validModes) {
        OHOS::system::SetParameter(BOPD_MODE_PARAM, mode);
        EXPECT_TRUE(IsBopdModeEnabled()) << "mode " << mode << " should be enabled";
    }
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0002
 * @tc.name: test IsBopdModeEnabled returns false for invalid modes
 * @tc.desc: 1. set ohos.boot.bopd.mode to invalid/empty values
 *           2. verify IsBopdModeEnabled returns false
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0002, Function | SmallTest | Level0)
{
    const std::vector<std::string> invalidModes = {"", "0x0", "0x1", "0x4", "0x5", "invalid"};
    for (const auto &mode : invalidModes) {
        OHOS::system::SetParameter(BOPD_MODE_PARAM, mode);
        EXPECT_FALSE(IsBopdModeEnabled()) << "mode " << mode << " should be disabled";
    }
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0003
 * @tc.name: BOPD on, third-party BundleResourceInfo icon cleared
 * @tc.desc: 1. enable BOPD mode
 *           2. inject a third-party InnerBundleInfo
 *           3. call FilterThirdPartyIconInBopdMode
 *           4. verify icon/foreground/background are cleared
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0003, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ASSERT_TRUE(IsBopdModeEnabled());
    InjectBundle(THIRD_PARTY_BUNDLE_NAME, MakeInnerBundleInfo(THIRD_PARTY_BUNDLE_NAME, false));

    BundleResourceHostImpl hostImpl;
    BundleResourceInfo info;
    FillBundleResourceInfo(info, THIRD_PARTY_BUNDLE_NAME);
    ASSERT_FALSE(info.icon.empty());

    hostImpl.FilterThirdPartyIconInBopdMode(THIRD_PARTY_BUNDLE_NAME, info);
    EXPECT_TRUE(IconCleared(info));
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0004
 * @tc.name: BOPD on, system app BundleResourceInfo icon preserved
 * @tc.desc: 1. enable BOPD mode
 *           2. inject a system app InnerBundleInfo
 *           3. call FilterThirdPartyIconInBopdMode
 *           4. verify icon/foreground/background are NOT cleared
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0004, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ASSERT_TRUE(IsBopdModeEnabled());
    InjectBundle(SYSTEM_BUNDLE_NAME, MakeInnerBundleInfo(SYSTEM_BUNDLE_NAME, true));

    BundleResourceHostImpl hostImpl;
    BundleResourceInfo info;
    FillBundleResourceInfo(info, SYSTEM_BUNDLE_NAME);

    hostImpl.FilterThirdPartyIconInBopdMode(SYSTEM_BUNDLE_NAME, info);
    EXPECT_FALSE(IconCleared(info));
    EXPECT_EQ(info.icon, "/data/icons/" + SYSTEM_BUNDLE_NAME + ".png");
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0005
 * @tc.name: BOPD off, third-party icon preserved
 * @tc.desc: 1. keep BOPD mode disabled
 *           2. inject a third-party InnerBundleInfo
 *           3. call FilterThirdPartyIconInBopdMode
 *           4. verify icon is NOT cleared (filtering skipped when BOPD off)
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0005, Function | SmallTest | Level0)
{
    ASSERT_FALSE(IsBopdModeEnabled());
    InjectBundle(THIRD_PARTY_BUNDLE_NAME, MakeInnerBundleInfo(THIRD_PARTY_BUNDLE_NAME, false));

    BundleResourceHostImpl hostImpl;
    BundleResourceInfo info;
    FillBundleResourceInfo(info, THIRD_PARTY_BUNDLE_NAME);

    hostImpl.FilterThirdPartyIconInBopdMode(THIRD_PARTY_BUNDLE_NAME, info);
    EXPECT_FALSE(IconCleared(info));
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0006
 * @tc.name: BOPD on, bundle not installed, icon preserved
 * @tc.desc: 1. enable BOPD mode
 *           2. do NOT inject the bundle into BundleDataMgr
 *           3. call FilterThirdPartyIconInBopdMode
 *           4. verify icon is NOT cleared (lookup failure must not clear icons)
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0006, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ASSERT_TRUE(IsBopdModeEnabled());
    RemoveBundle(THIRD_PARTY_BUNDLE_NAME);

    BundleResourceHostImpl hostImpl;
    BundleResourceInfo info;
    FillBundleResourceInfo(info, THIRD_PARTY_BUNDLE_NAME);

    hostImpl.FilterThirdPartyIconInBopdMode(THIRD_PARTY_BUNDLE_NAME, info);
    EXPECT_FALSE(IconCleared(info));
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0007
 * @tc.name: BOPD on, vector of BundleResourceInfo with mixed apps
 * @tc.desc: 1. enable BOPD mode
 *           2. inject one system app and one third-party app
 *           3. call vector FilterThirdPartyIconInBopdMode
 *           4. verify third-party icon cleared and system app icon preserved
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0007, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ASSERT_TRUE(IsBopdModeEnabled());
    InjectBundle(SYSTEM_BUNDLE_NAME, MakeInnerBundleInfo(SYSTEM_BUNDLE_NAME, true));
    InjectBundle(THIRD_PARTY_BUNDLE_NAME, MakeInnerBundleInfo(THIRD_PARTY_BUNDLE_NAME, false));

    std::vector<BundleResourceInfo> infos(2);
    FillBundleResourceInfo(infos[0], SYSTEM_BUNDLE_NAME);
    FillBundleResourceInfo(infos[1], THIRD_PARTY_BUNDLE_NAME);

    BundleResourceHostImpl hostImpl;
    hostImpl.FilterThirdPartyIconInBopdMode(infos);
    EXPECT_FALSE(IconCleared(infos[0]));
    EXPECT_TRUE(IconCleared(infos[1]));
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0008
 * @tc.name: BOPD on, multiple launcher abilities of one third-party bundle
 * @tc.desc: 1. enable BOPD mode
 *           2. inject one third-party app
 *           3. build several LauncherAbilityResourceInfo of the same bundle
 *           4. call vector FilterThirdPartyIconInBopdMode
 *           5. verify icons of all abilities are cleared (cache returns same result)
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0008, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ASSERT_TRUE(IsBopdModeEnabled());
    InjectBundle(THIRD_PARTY_BUNDLE_NAME, MakeInnerBundleInfo(THIRD_PARTY_BUNDLE_NAME, false));

    std::vector<LauncherAbilityResourceInfo> infos(3);
    for (auto &item : infos) {
        FillLauncherAbilityResourceInfo(item, THIRD_PARTY_BUNDLE_NAME);
    }

    BundleResourceHostImpl hostImpl;
    hostImpl.FilterThirdPartyIconInBopdMode(infos);
    for (const auto &item : infos) {
        EXPECT_TRUE(IconCleared(item));
    }
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0009
 * @tc.name: BOPD on, mixed launcher abilities (system + third-party, third-party duplicated)
 * @tc.desc: 1. enable BOPD mode
 *           2. inject one system app and one third-party app
 *           3. build abilities: system, third-party, third-party (same bundle, cache hit)
 *           4. call vector FilterThirdPartyIconInBopdMode
 *           5. verify system ability icon preserved and all third-party icons cleared
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0009, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, VALID_BOPD_MODE);
    ASSERT_TRUE(IsBopdModeEnabled());
    InjectBundle(SYSTEM_BUNDLE_NAME, MakeInnerBundleInfo(SYSTEM_BUNDLE_NAME, true));
    InjectBundle(THIRD_PARTY_BUNDLE_NAME, MakeInnerBundleInfo(THIRD_PARTY_BUNDLE_NAME, false));

    std::vector<LauncherAbilityResourceInfo> infos(3);
    FillLauncherAbilityResourceInfo(infos[0], SYSTEM_BUNDLE_NAME);
    FillLauncherAbilityResourceInfo(infos[1], THIRD_PARTY_BUNDLE_NAME);
    FillLauncherAbilityResourceInfo(infos[2], THIRD_PARTY_BUNDLE_NAME);

    BundleResourceHostImpl hostImpl;
    hostImpl.FilterThirdPartyIconInBopdMode(infos);
    EXPECT_FALSE(IconCleared(infos[0]));
    EXPECT_TRUE(IconCleared(infos[1]));
    EXPECT_TRUE(IconCleared(infos[2]));
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0010
 * @tc.name: dataMgr is nullptr, no crash and icon preserved
 * @tc.desc: 1. save and register nullptr as BundleDataMgr
 *           2. call FilterThirdPartyIconInBopdMode
 *           3. verify no crash and icon is NOT cleared (null branch returns before BOPD check)
 *           4. restore the original BundleDataMgr
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0010, Function | SmallTest | Level0)
{
    auto savedDataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(savedDataMgr, nullptr);
    bundleMgrService_->RegisterDataMgr(nullptr);

    BundleResourceHostImpl hostImpl;
    BundleResourceInfo info;
    FillBundleResourceInfo(info, THIRD_PARTY_BUNDLE_NAME);

    hostImpl.FilterThirdPartyIconInBopdMode(THIRD_PARTY_BUNDLE_NAME, info);
    EXPECT_FALSE(IconCleared(info));

    bundleMgrService_->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0011
 * @tc.name: dataMgr is nullptr, vector<BundleResourceInfo> no crash and icons preserved
 * @tc.desc: 1. save and register nullptr as BundleDataMgr
 *           2. call vector FilterThirdPartyIconInBopdMode
 *           3. verify no crash and icons are NOT cleared (null branch returns before BOPD check)
 *           4. restore the original BundleDataMgr
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0011, Function | SmallTest | Level0)
{
    auto savedDataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(savedDataMgr, nullptr);
    bundleMgrService_->RegisterDataMgr(nullptr);

    BundleResourceHostImpl hostImpl;
    std::vector<BundleResourceInfo> infos(2);
    FillBundleResourceInfo(infos[0], SYSTEM_BUNDLE_NAME);
    FillBundleResourceInfo(infos[1], THIRD_PARTY_BUNDLE_NAME);

    hostImpl.FilterThirdPartyIconInBopdMode(infos);
    EXPECT_FALSE(IconCleared(infos[0]));
    EXPECT_FALSE(IconCleared(infos[1]));

    bundleMgrService_->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: BmsBundleResourceBopdTest_0012
 * @tc.name: dataMgr is nullptr, vector<LauncherAbilityResourceInfo> no crash and icons preserved
 * @tc.desc: 1. save and register nullptr as BundleDataMgr
 *           2. call vector FilterThirdPartyIconInBopdMode
 *           3. verify no crash and icons are NOT cleared (null branch returns before BOPD check)
 *           4. restore the original BundleDataMgr
 */
HWTEST_F(BmsBundleResourceBopdTest, BmsBundleResourceBopdTest_0012, Function | SmallTest | Level0)
{
    auto savedDataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(savedDataMgr, nullptr);
    bundleMgrService_->RegisterDataMgr(nullptr);

    BundleResourceHostImpl hostImpl;
    std::vector<LauncherAbilityResourceInfo> infos(2);
    FillLauncherAbilityResourceInfo(infos[0], SYSTEM_BUNDLE_NAME);
    FillLauncherAbilityResourceInfo(infos[1], THIRD_PARTY_BUNDLE_NAME);

    hostImpl.FilterThirdPartyIconInBopdMode(infos);
    EXPECT_FALSE(IconCleared(infos[0]));
    EXPECT_FALSE(IconCleared(infos[1]));

    bundleMgrService_->RegisterDataMgr(savedDataMgr);
}
