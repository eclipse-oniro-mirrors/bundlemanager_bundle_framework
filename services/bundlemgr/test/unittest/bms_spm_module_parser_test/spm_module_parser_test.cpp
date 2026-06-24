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

#include "spm_module_parser.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk::Spm;

namespace OHOS {
namespace AppExecFwk {
namespace {

// ---------- valid JSON helpers ----------

const char* VALID_MINIMAL_JSON = R"({
  "app": {
    "bundleName": "com.example.test"
  },
  "module": {
    "name": "entry"
  }
})";

const char* VALID_FULL_JSON = R"({
  "app": {
    "bundleName": "com.example.full",
    "bundleType": "atomicService",
    "targetAPIVersion": 12
  },
  "module": {
    "name": "feature",
    "skillProfiles": [
      { "name": "skill1" },
      { "name": "skill2" }
    ],
    "requestPermissions": [
      {
        "name": "ohos.permission.INTERNET",
        "reason": "network access",
        "reasonId": 12345,
        "moduleName": "entry",
        "requiredFeature": "true"
      }
    ],
    "definePermissions": [
      {
        "name": "com.example.MY_PERM",
        "grantMode": "system_grant",
        "availableLevel": "system_core",
        "provisionEnable": true,
        "distributedSceneEnable": false,
        "label": "My Permission",
        "labelId": 100,
        "description": "A custom permission",
        "descriptionId": 200,
        "availableType": "normal",
        "kernelEffect": true,
        "hasValue": true
      }
    ]
  }
})";
}  // namespace

class SpmModuleParserTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

// ============================================================
// 1. Basic parsing – success / failure
// ============================================================

/**
 * @tc.name: ParseSpmModule_0100
 * @tc.desc: Valid minimal JSON with only required fields.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_0100, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(VALID_MINIMAL_JSON, info));
    EXPECT_EQ(info.bundleName, "com.example.test");
    EXPECT_EQ(info.moduleName, "entry");
    EXPECT_EQ(info.bundleType, BundleType::APP);
    EXPECT_EQ(info.apiTargetVersion, 0);
    EXPECT_TRUE(info.skillName.empty());
    EXPECT_TRUE(info.requestPermission.empty());
    EXPECT_TRUE(info.definePermission.empty());
}

/**
 * @tc.name: ParseSpmModule_0200
 * @tc.desc: Valid full JSON with all optional fields populated.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_0200, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(VALID_FULL_JSON, info));

    EXPECT_EQ(info.bundleName, "com.example.full");
    EXPECT_EQ(info.moduleName, "feature");
    EXPECT_EQ(info.bundleType, BundleType::ATOMIC_SERVICE);
    EXPECT_EQ(info.apiTargetVersion, 12);

    // skillProfiles
    ASSERT_EQ(info.skillName.size(), 2u);
    EXPECT_EQ(info.skillName[0], "skill1");
    EXPECT_EQ(info.skillName[1], "skill2");

    // requestPermissions
    ASSERT_EQ(info.requestPermission.size(), 1u);
    EXPECT_EQ(info.requestPermission[0].name, "ohos.permission.INTERNET");
    EXPECT_EQ(info.requestPermission[0].reason, "network access");
    EXPECT_EQ(info.requestPermission[0].reasonId, 12345u);
    EXPECT_EQ(info.requestPermission[0].moduleName, "entry");
    EXPECT_EQ(info.requestPermission[0].requiredFeature, "true");

    // definePermissions
    ASSERT_EQ(info.definePermission.size(), 1u);
    const auto &dp = info.definePermission[0];
    EXPECT_EQ(dp.name, "com.example.MY_PERM");
    EXPECT_EQ(dp.grantMode, "system_grant");
    EXPECT_EQ(dp.availableLevel, "system_core");
    EXPECT_TRUE(dp.provisionEnable);
    EXPECT_FALSE(dp.distributedSceneEnable);
    EXPECT_TRUE(dp.isKernelEffect);
    EXPECT_TRUE(dp.hasValue);
    EXPECT_EQ(dp.label, "My Permission");
    EXPECT_EQ(dp.labelId, 100u);
    EXPECT_EQ(dp.description, "A custom permission");
    EXPECT_EQ(dp.descriptionId, 200u);
    EXPECT_EQ(dp.availableType, "normal");
}

// ============================================================
// 2. Invalid / missing required fields
// ============================================================

/**
 * @tc.name: ParseSpmModule_0300
 * @tc.desc: Empty string input should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_0300, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule("", info));
}

/**
 * @tc.name: ParseSpmModule_0400
 * @tc.desc: Invalid JSON string should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_0400, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule("not json at all", info));
}

/**
 * @tc.name: ParseSpmModule_0500
 * @tc.desc: JSON is valid but top-level is not an object (array).
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_0500, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule("[]", info));
}

/**
 * @tc.name: ParseSpmModule_0600
 * @tc.desc: Missing "app" section should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_0600, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(R"({ "module": { "name": "entry" } })", info));
}

/**
 * @tc.name: ParseSpmModule_0700
 * @tc.desc: "app" is not an object should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_0700, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(R"({ "app": "string", "module": { "name": "entry" } })", info));
}

/**
 * @tc.name: ParseSpmModule_0800
 * @tc.desc: Missing bundleName in app section should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_0800, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(R"({ "app": {}, "module": { "name": "entry" } })", info));
}

/**
 * @tc.name: ParseSpmModule_0900
 * @tc.desc: bundleName is empty string should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_0900, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(R"({ "app": { "bundleName": "" }, "module": { "name": "entry" } })", info));
}

/**
 * @tc.name: ParseSpmModule_1000
 * @tc.desc: Missing "module" section should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1000, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(R"({ "app": { "bundleName": "com.example.test" } })", info));
}

/**
 * @tc.name: ParseSpmModule_1100
 * @tc.desc: "module" is not an object should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1100, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.example.test" }, "module": 123 })", info));
}

/**
 * @tc.name: ParseSpmModule_1200
 * @tc.desc: Missing module "name" should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1200, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.example.test" }, "module": {} })", info));
}

/**
 * @tc.name: ParseSpmModule_1300
 * @tc.desc: Module name is empty string should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1300, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.example.test" }, "module": { "name": "" } })", info));
}

// ============================================================
// 3. bundleType conversion
// ============================================================

/**
 * @tc.name: ParseSpmModule_1400
 * @tc.desc: bundleType "app" or missing defaults to APP.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1400, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info1;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "bundleType": "app" }, "module": { "name": "m" } })",
        info1));
    EXPECT_EQ(info1.bundleType, BundleType::APP);

    InnerModuleInfoForSpm info2;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" }, "module": { "name": "m" } })",
        info2));
    EXPECT_EQ(info2.bundleType, BundleType::APP);
}

/**
 * @tc.name: ParseSpmModule_1500
 * @tc.desc: bundleType "atomicService" → ATOMIC_SERVICE.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1500, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "bundleType": "atomicService" },
            "module": { "name": "m" } })",
        info));
    EXPECT_EQ(info.bundleType, BundleType::ATOMIC_SERVICE);
}

/**
 * @tc.name: ParseSpmModule_1600
 * @tc.desc: bundleType "shared" → SHARED.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1600, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "bundleType": "shared" },
            "module": { "name": "m" } })",
        info));
    EXPECT_EQ(info.bundleType, BundleType::SHARED);
}

/**
 * @tc.name: ParseSpmModule_1700
 * @tc.desc: bundleType "appService" → APP_SERVICE_FWK.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1700, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "bundleType": "appService" },
            "module": { "name": "m" } })",
        info));
    EXPECT_EQ(info.bundleType, BundleType::APP_SERVICE_FWK);
}

/**
 * @tc.name: ParseSpmModule_1800
 * @tc.desc: bundleType "appPlugin" → APP_PLUGIN.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1800, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "bundleType": "appPlugin" },
            "module": { "name": "m" } })",
        info));
    EXPECT_EQ(info.bundleType, BundleType::APP_PLUGIN);
}

/**
 * @tc.name: ParseSpmModule_1900
 * @tc.desc: bundleType "skill" → SKILL.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_1900, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "bundleType": "skill" },
            "module": { "name": "m" } })",
        info));
    EXPECT_EQ(info.bundleType, BundleType::SKILL);
}

/**
 * @tc.name: ParseSpmModule_2000
 * @tc.desc: Unknown bundleType string defaults to APP.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2000, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "bundleType": "unknownType" },
            "module": { "name": "m" } })",
        info));
    EXPECT_EQ(info.bundleType, BundleType::APP);
}

/**
 * @tc.name: ParseSpmModule_2100
 * @tc.desc: bundleType is a number (not string) defaults to APP.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2100, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "bundleType": 42 },
            "module": { "name": "m" } })",
        info));
    EXPECT_EQ(info.bundleType, BundleType::APP);
}

// ============================================================
// 4. targetAPIVersion
// ============================================================

/**
 * @tc.name: ParseSpmModule_2200
 * @tc.desc: targetAPIVersion is correctly parsed.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2200, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "targetAPIVersion": 14 },
            "module": { "name": "m" } })",
        info));
    EXPECT_EQ(info.apiTargetVersion, 14);
}

/**
 * @tc.name: ParseSpmModule_2300
 * @tc.desc: targetAPIVersion missing defaults to 0.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2300, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(VALID_MINIMAL_JSON, info));
    EXPECT_EQ(info.apiTargetVersion, 0);
}

// ============================================================
// 5. skillProfiles parsing
// ============================================================

/**
 * @tc.name: ParseSpmModule_2400
 * @tc.desc: skillProfiles with multiple entries parsed correctly.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2400, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "skillProfiles": [
                { "name": "s1" },
                { "name": "s2" },
                { "name": "s3" }
              ]
            } })",
        info));
    ASSERT_EQ(info.skillName.size(), 3u);
    EXPECT_EQ(info.skillName[0], "s1");
    EXPECT_EQ(info.skillName[1], "s2");
    EXPECT_EQ(info.skillName[2], "s3");
}

/**
 * @tc.name: ParseSpmModule_2500
 * @tc.desc: skillProfiles with empty name is skipped.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2500, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "skillProfiles": [
                { "name": "valid" },
                { "name": "" },
                { "other": "no name field" }
              ]
            } })",
        info));
    ASSERT_EQ(info.skillName.size(), 1u);
    EXPECT_EQ(info.skillName[0], "valid");
}

/**
 * @tc.name: ParseSpmModule_2600
 * @tc.desc: skillProfiles is not an array should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2600, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": { "name": "m", "skillProfiles": "not_array" } })",
        info));
}

/**
 * @tc.name: ParseSpmModule_2700
 * @tc.desc: skillProfiles with non-object items are skipped.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2700, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "skillProfiles": [ "string_item", 123, { "name": "ok" } ]
            } })",
        info));
    ASSERT_EQ(info.skillName.size(), 1u);
    EXPECT_EQ(info.skillName[0], "ok");
}

/**
 * @tc.name: ParseSpmModule_2800
 * @tc.desc: skillProfiles empty array produces empty vector.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2800, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": { "name": "m", "skillProfiles": [] } })",
        info));
    EXPECT_TRUE(info.skillName.empty());
}

// ============================================================
// 6. requestPermissions parsing
// ============================================================

/**
 * @tc.name: ParseSpmModule_2900
 * @tc.desc: Multiple requestPermissions parsed correctly.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_2900, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "requestPermissions": [
                { "name": "perm1", "reason": "r1", "reasonId": 10, "moduleName": "mod1" },
                { "name": "perm2", "reason": "r2", "reasonId": 20, "requiredFeature": "feat" }
              ]
            } })",
        info));
    ASSERT_EQ(info.requestPermission.size(), 2u);
    EXPECT_EQ(info.requestPermission[0].name, "perm1");
    EXPECT_EQ(info.requestPermission[0].reason, "r1");
    EXPECT_EQ(info.requestPermission[0].reasonId, 10u);
    EXPECT_EQ(info.requestPermission[0].moduleName, "mod1");
    EXPECT_EQ(info.requestPermission[1].name, "perm2");
    EXPECT_EQ(info.requestPermission[1].reasonId, 20u);
    EXPECT_EQ(info.requestPermission[1].requiredFeature, "feat");
}

/**
 * @tc.name: ParseSpmModule_3000
 * @tc.desc: requestPermissions not an array should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3000, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": { "name": "m", "requestPermissions": 42 } })",
        info));
}

/**
 * @tc.name: ParseSpmModule_3100
 * @tc.desc: requestPermissions with missing string fields defaults to empty.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3100, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "requestPermissions": [ { "reasonId": 99 } ]
            } })",
        info));
    ASSERT_EQ(info.requestPermission.size(), 1u);
    EXPECT_TRUE(info.requestPermission[0].name.empty());
    EXPECT_TRUE(info.requestPermission[0].reason.empty());
    EXPECT_TRUE(info.requestPermission[0].moduleName.empty());
    EXPECT_TRUE(info.requestPermission[0].requiredFeature.empty());
    EXPECT_EQ(info.requestPermission[0].reasonId, 99u);
}

/**
 * @tc.name: ParseSpmModule_3200
 * @tc.desc: requestPermissions with non-object items are skipped.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3200, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "requestPermissions": [ "bad", { "name": "ok" } ]
            } })",
        info));
    ASSERT_EQ(info.requestPermission.size(), 1u);
    EXPECT_EQ(info.requestPermission[0].name, "ok");
}

// ============================================================
// 7. definePermissions parsing
// ============================================================

/**
 * @tc.name: ParseSpmModule_3300
 * @tc.desc: definePermissions with full fields parsed correctly.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3300, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "definePermissions": [
                {
                  "name": "perm",
                  "grantMode": "user_grant",
                  "availableLevel": "system_basic",
                  "provisionEnable": false,
                  "distributedSceneEnable": true,
                  "label": "L",
                  "labelId": 50,
                  "description": "D",
                  "descriptionId": 60,
                  "availableType": "system",
                  "kernelEffect": true,
                  "hasValue": true
                }
              ]
            } })",
        info));
    ASSERT_EQ(info.definePermission.size(), 1u);
    const auto &dp = info.definePermission[0];
    EXPECT_EQ(dp.name, "perm");
    EXPECT_EQ(dp.grantMode, "user_grant");
    EXPECT_EQ(dp.availableLevel, "system_basic");
    EXPECT_FALSE(dp.provisionEnable);
    EXPECT_TRUE(dp.distributedSceneEnable);
    EXPECT_TRUE(dp.isKernelEffect);
    EXPECT_TRUE(dp.hasValue);
    EXPECT_EQ(dp.label, "L");
    EXPECT_EQ(dp.labelId, 50u);
    EXPECT_EQ(dp.description, "D");
    EXPECT_EQ(dp.descriptionId, 60u);
    EXPECT_EQ(dp.availableType, "system");
}

/**
 * @tc.name: ParseSpmModule_3400
 * @tc.desc: definePermissions defaults: provisionEnable=true, others=false.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3400, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "definePermissions": [ { "name": "p" } ]
            } })",
        info));
    ASSERT_EQ(info.definePermission.size(), 1u);
    EXPECT_TRUE(info.definePermission[0].provisionEnable);     // default true
    EXPECT_FALSE(info.definePermission[0].distributedSceneEnable); // default false
    EXPECT_FALSE(info.definePermission[0].isKernelEffect);     // default false
    EXPECT_FALSE(info.definePermission[0].hasValue);           // default false
}

/**
 * @tc.name: ParseSpmModule_3500
 * @tc.desc: definePermissions not an array should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3500, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": { "name": "m", "definePermissions": {} } })",
        info));
}

/**
 * @tc.name: ParseSpmModule_3600
 * @tc.desc: definePermissions with non-object items are skipped.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3600, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "definePermissions": [ "bad", 123, { "name": "ok" } ]
            } })",
        info));
    ASSERT_EQ(info.definePermission.size(), 1u);
    EXPECT_EQ(info.definePermission[0].name, "ok");
}

/**
 * @tc.name: ParseSpmModule_3700
 * @tc.desc: definePermissions empty array produces empty vector.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3700, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": { "name": "m", "definePermissions": [] } })",
        info));
    EXPECT_TRUE(info.definePermission.empty());
}

// ============================================================
// 8. Multiple optional fields together
// ============================================================

/**
 * @tc.name: ParseSpmModule_3800
 * @tc.desc: All optional fields present together with multiple items each.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3800, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test.multi", "bundleType": "shared", "targetAPIVersion": 15 },
            "module": {
              "name": "multi",
              "skillProfiles": [
                { "name": "sk1" }, { "name": "sk2" }
              ],
              "requestPermissions": [
                { "name": "rp1" }, { "name": "rp2" }
              ],
              "definePermissions": [
                { "name": "dp1" }, { "name": "dp2" }
              ]
            } })",
        info));
    EXPECT_EQ(info.bundleName, "com.test.multi");
    EXPECT_EQ(info.bundleType, BundleType::SHARED);
    EXPECT_EQ(info.apiTargetVersion, 15);
    EXPECT_EQ(info.skillName.size(), 2u);
    EXPECT_EQ(info.requestPermission.size(), 2u);
    EXPECT_EQ(info.definePermission.size(), 2u);
}

/**
 * @tc.name: ParseSpmModule_3900
 * @tc.desc: Optional fields absent – all vectors empty.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_3900, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test.noopts" }, "module": { "name": "bare" } })",
        info));
    EXPECT_TRUE(info.skillName.empty());
    EXPECT_TRUE(info.requestPermission.empty());
    EXPECT_TRUE(info.definePermission.empty());
}

// ============================================================
// 9. Edge cases – wrong types for fields
// ============================================================

/**
 * @tc.name: ParseSpmModule_4000
 * @tc.desc: bundleName as number (not string) treated as empty → fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_4000, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(
        R"({ "app": { "bundleName": 12345 }, "module": { "name": "m" } })",
        info));
}

/**
 * @tc.name: ParseSpmModule_4100
 * @tc.desc: Module name as number (not string) treated as empty → fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_4100, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" }, "module": { "name": 999 } })",
        info));
}

/**
 * @tc.name: ParseSpmModule_4200
 * @tc.desc: reasonId as string (not number) defaults to 0.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_4200, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "requestPermissions": [ { "name": "p", "reasonId": "bad" } ]
            } })",
        info));
    ASSERT_EQ(info.requestPermission.size(), 1u);
    EXPECT_EQ(info.requestPermission[0].reasonId, 0u);
}

/**
 * @tc.name: ParseSpmModule_4300
 * @tc.desc: provisionEnable as string (not bool) defaults to true.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_4300, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test" },
            "module": {
              "name": "m",
              "definePermissions": [ { "name": "p", "provisionEnable": "yes" } ]
            } })",
        info));
    ASSERT_EQ(info.definePermission.size(), 1u);
    EXPECT_TRUE(info.definePermission[0].provisionEnable); // default true
}

/**
 * @tc.name: ParseSpmModule_4400
 * @tc.desc: Truncated / malformed JSON should fail.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_4400, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_FALSE(ParseSpmModule(R"({ "app": { "bundleNa)", info));
}

/**
 * @tc.name: ParseSpmModule_4500
 * @tc.desc: Extra unknown fields in app/module are silently ignored.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_4500, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.test", "unknownField": 42 },
            "module": { "name": "m", "extra": true } })",
        info));
    EXPECT_EQ(info.bundleName, "com.test");
    EXPECT_EQ(info.moduleName, "m");
}

/**
 * @tc.name: ParseSpmModule_4600
 * @tc.desc: FA model – module.name starts with "." should prepend module.package.
 */
HWTEST_F(SpmModuleParserTest, ParseSpmModule_4600, Function | SmallTest | Level1)
{
    InnerModuleInfoForSpm info;
    EXPECT_TRUE(ParseSpmModule(
        R"({ "app": { "bundleName": "com.example.test" },
            "module": { "package": "com.example.entry", "name": ".MainAbility" } })",
        info));
    EXPECT_EQ(info.moduleName, "com.example.entry.MainAbility");
}
}  // namespace AppExecFwk
}  // namespace OHOS
