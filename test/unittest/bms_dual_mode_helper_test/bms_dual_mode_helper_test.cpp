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

#include <gtest/gtest.h>

#include "application_info.h"
#include "dual_mode_helper.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t APP_CATEGORY_DIFF_PACKAGE_VALUE = static_cast<int32_t>(AppCategory::APP_CATEGORY_DIFF_PACKAGE);
constexpr int32_t APP_CATEGORY_UNSPECIFIED_VALUE = static_cast<int32_t>(AppCategory::APP_CATEGORY_UNSPECIFIED);
constexpr int32_t APP_CATEGORY_PC_ONLY_VALUE = static_cast<int32_t>(AppCategory::APP_CATEGORY_PC_ONLY);
}  // namespace

class BmsDualModeHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: IsDiffPackageCategory_0001
 * @tc.desc: Verify category-7 detection via bitwise-and. (AC-4/AC-6)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeHelperTest, IsDiffPackageCategory_0001, TestSize.Level1)
{
    EXPECT_TRUE(DualModeHelper::IsDiffPackageCategory(APP_CATEGORY_DIFF_PACKAGE_VALUE));
    EXPECT_FALSE(DualModeHelper::IsDiffPackageCategory(APP_CATEGORY_UNSPECIFIED_VALUE));
    // combination: PC_ONLY | DIFF_PACKAGE
    EXPECT_TRUE(DualModeHelper::IsDiffPackageCategory(APP_CATEGORY_PC_ONLY_VALUE | APP_CATEGORY_DIFF_PACKAGE_VALUE));
    EXPECT_FALSE(DualModeHelper::IsDiffPackageCategory(0));
}

/**
 * @tc.name: GetDualModeBundleName_0001
 * @tc.desc: Verify dual-mode clone bundle name format "+clone-10000+{name}". (AC-4/AC-10)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeHelperTest, GetDualModeBundleName_0001, TestSize.Level1)
{
    EXPECT_EQ(DualModeHelper::GetDualModeBundleName("com.example.app"), "+clone-10000+com.example.app");
}

/**
 * @tc.name: ParseDualModeBundleName_0001
 * @tc.desc: Verify dual-mode name parses back to original bundleName. (AC-11/AC-14)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeHelperTest, ParseDualModeBundleName_0001, TestSize.Level1)
{
    std::string bundleName;
    EXPECT_TRUE(DualModeHelper::ParseDualModeBundleName("+clone-10000+com.example.app", bundleName));
    EXPECT_EQ(bundleName, "com.example.app");
}

/**
 * @tc.name: ParseDualModeBundleName_0002
 * @tc.desc: Verify clone app (appIndex=1) and normal names are NOT dual-mode. (AC-6)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeHelperTest, ParseDualModeBundleName_0002, TestSize.Level1)
{
    std::string bundleName;
    EXPECT_FALSE(DualModeHelper::ParseDualModeBundleName("+clone-1+com.example.app", bundleName));
    EXPECT_FALSE(DualModeHelper::ParseDualModeBundleName("com.example.app", bundleName));
}

/**
 * @tc.name: IsDualModeCloneKey_0001
 * @tc.desc: Verify dual-mode clone key detection. (AC-4/AC-11, TASK-4 self-heal guard)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeHelperTest, IsDualModeCloneKey_0001, TestSize.Level1)
{
    EXPECT_TRUE(DualModeHelper::IsDualModeCloneKey("+clone-10000+com.example.app"));
    EXPECT_FALSE(DualModeHelper::IsDualModeCloneKey("com.example.app"));
}

/**
 * @tc.name: RoundTrip_0001
 * @tc.desc: Verify GetDualModeBundleName/ParseDualModeBundleName round-trip. (AC-4/AC-11)
 * @tc.type: FUNC
 */
HWTEST_F(BmsDualModeHelperTest, RoundTrip_0001, TestSize.Level1)
{
    const std::string origin = "com.example.roundtrip";
    std::string cloneName = DualModeHelper::GetDualModeBundleName(origin);
    std::string parsed;
    EXPECT_TRUE(DualModeHelper::ParseDualModeBundleName(cloneName, parsed));
    EXPECT_EQ(parsed, origin);
}
