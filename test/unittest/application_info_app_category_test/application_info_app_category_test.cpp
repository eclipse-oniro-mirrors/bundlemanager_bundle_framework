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
#include "install_param.h"
#include "nlohmann/json.hpp"
#include "parcel.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t APP_CATEGORY_DIFF_PACKAGE_VALUE = static_cast<int32_t>(AppCategory::APP_CATEGORY_DIFF_PACKAGE);
constexpr int32_t APP_CATEGORY_PC_ONLY_VALUE = static_cast<int32_t>(AppCategory::APP_CATEGORY_PC_ONLY);
constexpr int32_t APP_CATEGORY_UNSPECIFIED_VALUE = static_cast<int32_t>(AppCategory::APP_CATEGORY_UNSPECIFIED);
}  // namespace

class BmsAppCategoryTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: ApplicationInfo_AppCategory_Default_0001
 * @tc.desc: Verify ApplicationInfo.appCategory default value is UNSPECIFIED. (AC-2)
 * @tc.type: FUNC
 */
HWTEST_F(BmsAppCategoryTest, ApplicationInfo_AppCategory_Default_0001, TestSize.Level1)
{
    ApplicationInfo info;
    EXPECT_EQ(info.appCategory, APP_CATEGORY_UNSPECIFIED_VALUE);
}

/**
 * @tc.name: ApplicationInfo_AppCategory_Parcel_0001
 * @tc.desc: Verify ApplicationInfo.appCategory survives Parcel marshalling round-trip. (AC-1)
 * @tc.type: FUNC
 */
HWTEST_F(BmsAppCategoryTest, ApplicationInfo_AppCategory_Parcel_0001, TestSize.Level1)
{
    ApplicationInfo info;
    info.bundleName = "com.example.dualmode";
    info.appCategory = APP_CATEGORY_DIFF_PACKAGE_VALUE;
    Parcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    auto *decoded = ApplicationInfo::Unmarshalling(parcel);
    ASSERT_NE(decoded, nullptr);
    EXPECT_EQ(decoded->appCategory, APP_CATEGORY_DIFF_PACKAGE_VALUE);
    delete decoded;
}

/**
 * @tc.name: ApplicationInfo_AppCategory_Json_0001
 * @tc.desc: Verify ApplicationInfo.appCategory survives json round-trip. (AC-1)
 * @tc.type: FUNC
 */
HWTEST_F(BmsAppCategoryTest, ApplicationInfo_AppCategory_Json_0001, TestSize.Level1)
{
    ApplicationInfo info;
    info.bundleName = "com.example.dualmode";
    info.appCategory = APP_CATEGORY_PC_ONLY_VALUE;
    nlohmann::json jsonObject = info;
    ApplicationInfo decoded = jsonObject.get<ApplicationInfo>();
    EXPECT_EQ(decoded.appCategory, APP_CATEGORY_PC_ONLY_VALUE);
}

/**
 * @tc.name: ApplicationInfo_AppCategory_LegacyDefault_0001
 * @tc.desc: Verify legacy json without appCategory field falls back to UNSPECIFIED. (AC-18)
 * @tc.type: FUNC
 */
HWTEST_F(BmsAppCategoryTest, ApplicationInfo_AppCategory_LegacyDefault_0001, TestSize.Level1)
{
    nlohmann::json legacyJson = nlohmann::json{
        {"bundleName", "com.example.legacy"},
        {"versionCode", 1},
    };
    ApplicationInfo info = legacyJson.get<ApplicationInfo>();
    EXPECT_EQ(info.appCategory, APP_CATEGORY_UNSPECIFIED_VALUE);
}

/**
 * @tc.name: InstallParam_AppCategory_Default_0001
 * @tc.desc: Verify InstallParam.appCategory default value is UNSPECIFIED. (AC-2)
 * @tc.type: FUNC
 */
HWTEST_F(BmsAppCategoryTest, InstallParam_AppCategory_Default_0001, TestSize.Level1)
{
    InstallParam param;
    EXPECT_EQ(param.appCategory, APP_CATEGORY_UNSPECIFIED_VALUE);
}

/**
 * @tc.name: InstallParam_AppCategory_Parcel_0001
 * @tc.desc: Verify InstallParam.appCategory survives Parcel marshalling round-trip. (AC-1)
 * @tc.type: FUNC
 */
HWTEST_F(BmsAppCategoryTest, InstallParam_AppCategory_Parcel_0001, TestSize.Level1)
{
    InstallParam param;
    param.appCategory = APP_CATEGORY_DIFF_PACKAGE_VALUE;
    Parcel parcel;
    ASSERT_TRUE(param.Marshalling(parcel));
    auto *decoded = InstallParam::Unmarshalling(parcel);
    ASSERT_NE(decoded, nullptr);
    EXPECT_EQ(decoded->appCategory, APP_CATEGORY_DIFF_PACKAGE_VALUE);
    delete decoded;
}

/**
 * @tc.name: AppCategory_BitwiseOr_0001
 * @tc.desc: Verify AppCategory values support bitwise-or combination. (AC-1 / ADR-8)
 * @tc.type: FUNC
 */
HWTEST_F(BmsAppCategoryTest, AppCategory_BitwiseOr_0001, TestSize.Level1)
{
    int32_t combined = APP_CATEGORY_PC_ONLY_VALUE | APP_CATEGORY_DIFF_PACKAGE_VALUE;
    EXPECT_TRUE((combined & APP_CATEGORY_DIFF_PACKAGE_VALUE) != 0);
    EXPECT_TRUE((combined & APP_CATEGORY_PC_ONLY_VALUE) != 0);
    EXPECT_FALSE((combined & APP_CATEGORY_UNSPECIFIED_VALUE) != 0);
}
