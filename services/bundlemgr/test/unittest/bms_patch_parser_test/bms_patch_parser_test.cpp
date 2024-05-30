/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <sstream>
#include <string>
#include <gtest/gtest.h>

#define private public
#include "app_log_wrapper.h"
#include "app_quick_fix.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "json_constants.h"
#include "quick_fix/patch_extractor.h"
#include "quick_fix/patch_parser.h"
#include "quick_fix/patch_profile.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const nlohmann::json PATCH_JSON = R"(
    {
        "app" : {
            "bundleName" : "com.example.test",
            "versionCode" : 1000000,
            "versionName" : "1.0.0",
            "patchVersionCode" : 1000000,
            "patchVersionName" : "1.0.0"
        },
        "module" : {
            "name" : "entry",
            "type" : "patch",
            "deviceTypes" : [
                "phone",
                "tablet"
            ],
            "originalModuleHash" : "11223344556677889900"
        }
    }
)"_json;

std::string BUNDLE_PATCH_PROFILE_APP_KEY_BUNDLE_NAME = "bundleName";
std::string BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_CODE = "versionCode";
std::string BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_NAME = "versionName";
std::string BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_CODE = "patchVersionCode";
std::string BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_NAME = "patchVersionName";
std::string BUNDLE_PATCH_PROFILE_MODULE_KEY_NAME = "name";
std::string BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE = "type";
std::string BUNDLE_PATCH_PROFILE_MODULE_KEY_DEVICE_TYPES = "deviceTypes";
std::string BUNDLE_PATCH_PROFILE_MODULE_KEY_ORIGINAL_MODULE_HASH = "originalModuleHash";
std::string BUNDLE_PATCH_PROFILE_KEY_APP = "app";
std::string BUNDLE_PATCH_PROFILE_KEY_MODULE = "module";
constexpr const char* BUNDLE_PATCH_TYPE_HOT_RELOAD = "hotreload";
} // namespace

class BmsPatchParserTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    void CheckNoPropProfileParseApp(const std::string &propKey, const ErrCode expectCode) const;
    void CheckNoPropProfileParseModule(const std::string &propKey, const ErrCode expectCode) const;
    void CheckProfileTypes(const nlohmann::json &checkedProfileJson) const;
    
private:
    std::ostringstream pathStream_;
};

void BmsPatchParserTest::SetUpTestCase()
{}

void BmsPatchParserTest::TearDownTestCase()
{}

void BmsPatchParserTest::SetUp()
{}

void BmsPatchParserTest::TearDown()
{
    pathStream_.clear();
}

void BmsPatchParserTest::CheckNoPropProfileParseApp(const std::string &propKey, const ErrCode expectCode) const
{
    nlohmann::json errorProfileJson = PATCH_JSON;
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_APP].erase(propKey);
    std::ostringstream profileFileBuffer;
    profileFileBuffer << errorProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ret, expectCode);
}

void BmsPatchParserTest::CheckNoPropProfileParseModule(const std::string &propKey, const ErrCode expectCode) const
{
    nlohmann::json errorProfileJson = PATCH_JSON;
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_MODULE].erase(propKey);
    std::ostringstream profileFileBuffer;
    profileFileBuffer << errorProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ret, expectCode);
}

void BmsPatchParserTest::CheckProfileTypes(const nlohmann::json &checkedProfileJson) const
{
    std::ostringstream profileFileBuffer;
    profileFileBuffer << checkedProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: TestParse_0001
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test success
 */
HWTEST_F(BmsPatchParserTest, TestParse_0001, Function | SmallTest | Level0)
{
    nlohmann::json object = PATCH_JSON;
    std::ostringstream profileFileBuffer;
    profileFileBuffer << object.dump();
    PatchProfile patchProfile;
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appQuickFix.bundleName, "com.example.test");
    EXPECT_EQ(appQuickFix.versionCode, 1000000);
    EXPECT_EQ(appQuickFix.versionName, "1.0.0");
    EXPECT_EQ(appQuickFix.deployingAppqfInfo.versionCode, 1000000);
    EXPECT_EQ(appQuickFix.deployingAppqfInfo.versionName, "1.0.0");
    EXPECT_EQ(appQuickFix.deployingAppqfInfo.nativeLibraryPath, "");
    EXPECT_EQ(appQuickFix.deployingAppqfInfo.hqfInfos[0].hapSha256, "11223344556677889900");
    EXPECT_EQ(appQuickFix.deployingAppqfInfo.hqfInfos[0].moduleName, "entry");
}

/**
 * @tc.number: TestParse_0002
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when bundleName does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0002, Function | SmallTest | Level0)
{
    CheckNoPropProfileParseApp(BUNDLE_PATCH_PROFILE_APP_KEY_BUNDLE_NAME, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestParse_0003
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when versionCode does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0003, Function | SmallTest | Level0)
{
    CheckNoPropProfileParseApp(BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_CODE, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestParse_0004
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch succeed when versionName does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0004, Function | SmallTest | Level0)
{
    CheckNoPropProfileParseApp(BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_NAME, ERR_OK);
}

/**
 * @tc.number: TestParse_0005
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when patchVersionCode does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0005, Function | SmallTest | Level0)
{
    CheckNoPropProfileParseApp(BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_CODE,
        ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestParse_0006
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch succeed when patchVersionName does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0006, Function | SmallTest | Level0)
{
    CheckNoPropProfileParseApp(BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_NAME, ERR_OK);
}

/**
 * @tc.number: TestParse_0007
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when name does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0007, Function | SmallTest | Level0)
{
    CheckNoPropProfileParseModule(BUNDLE_PATCH_PROFILE_MODULE_KEY_NAME, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestParse_0008
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when type does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0008, Function | SmallTest | Level0)
{
    CheckNoPropProfileParseModule(BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestParse_0009
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch succeed when deviceTypes does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0009, Function | SmallTest | Level0)
{
    CheckNoPropProfileParseModule(BUNDLE_PATCH_PROFILE_MODULE_KEY_DEVICE_TYPES, ERR_OK);
}

/**
 * @tc.number: TestParse_0010
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch succeed when originalModuleHash does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0010, Function | SmallTest | Level0)
{
    CheckNoPropProfileParseModule(BUNDLE_PATCH_PROFILE_MODULE_KEY_ORIGINAL_MODULE_HASH, ERR_OK);
}

/**
 * @tc.number: TestParse_0011
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when app does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0011, Function | SmallTest | Level0)
{
    nlohmann::json errorProfileJson = PATCH_JSON;
    errorProfileJson.erase(BUNDLE_PATCH_PROFILE_KEY_APP);
    std::ostringstream profileFileBuffer;
    profileFileBuffer << errorProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestParse_0012
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when module does not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0012, Function | SmallTest | Level0)
{
    nlohmann::json errorProfileJson = PATCH_JSON;
    errorProfileJson.erase(BUNDLE_PATCH_PROFILE_KEY_MODULE);
    std::ostringstream profileFileBuffer;
    profileFileBuffer << errorProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestParse_0013
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when both app and module do not exist in the patch.json
 */
HWTEST_F(BmsPatchParserTest, TestParse_0013, Function | SmallTest | Level0)
{
    nlohmann::json errorProfileJson = PATCH_JSON;
    errorProfileJson.erase(BUNDLE_PATCH_PROFILE_KEY_APP);
    errorProfileJson.erase(BUNDLE_PATCH_PROFILE_KEY_MODULE);
    std::ostringstream profileFileBuffer;
    profileFileBuffer << errorProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestParse_0014
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when app is not an object
 */
HWTEST_F(BmsPatchParserTest, TestParse_0014, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_APP] = "an_app";
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0015
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when module is not an object
 */
HWTEST_F(BmsPatchParserTest, TestParse_0015, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_MODULE] = "a_module";
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0016
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when bundlename is not a string
 */
HWTEST_F(BmsPatchParserTest, TestParse_0016, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_APP][BUNDLE_PATCH_PROFILE_APP_KEY_BUNDLE_NAME] = 1;
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0017
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when versionCode is not a number
 */
HWTEST_F(BmsPatchParserTest, TestParse_0017, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_APP][BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_CODE] = "1000000";
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0018
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when versionName is not a string
 */
HWTEST_F(BmsPatchParserTest, TestParse_0018, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_APP][BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_NAME] = 1;
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0019
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when patchVersionCode is not a number
 */
HWTEST_F(BmsPatchParserTest, TestParse_0019, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_APP][BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_CODE] = "1000000";
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0020
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when versionName is not a string
 */
HWTEST_F(BmsPatchParserTest, TestParse_0020, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_APP][BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_NAME] = 1;
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0021
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when name is not a string
 */
HWTEST_F(BmsPatchParserTest, TestParse_0021, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_MODULE][BUNDLE_PATCH_PROFILE_MODULE_KEY_NAME] = 1;
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0022
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when type is not a string
 */
HWTEST_F(BmsPatchParserTest, TestParse_0022, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_MODULE][BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE] = 1;
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0023
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when deviceType is not a array
 */
HWTEST_F(BmsPatchParserTest, TestParse_0023, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_MODULE][BUNDLE_PATCH_PROFILE_MODULE_KEY_DEVICE_TYPES] = "device_type";
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0024
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when deviceType is a array but its arrayType is not string
 */
HWTEST_F(BmsPatchParserTest, TestParse_0024, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_MODULE][BUNDLE_PATCH_PROFILE_MODULE_KEY_DEVICE_TYPES] = {1, 2};
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0025
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch succeed when deviceType is a array but it is NULL
 */
HWTEST_F(BmsPatchParserTest, TestParse_0025, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_MODULE][BUNDLE_PATCH_PROFILE_MODULE_KEY_DEVICE_TYPES] = {};
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: TestParse_0026
 * @tc.name: parse patch package by patch.json
 * @tc.require: issueI5MZ7R
 * @tc.desc: 1. system running normally
 *           2. test parse patch failed when originalModuleHash is not a string
 */
HWTEST_F(BmsPatchParserTest, TestParse_0026, Function | SmallTest | Level0)
{
    nlohmann::json errorTypeJson = PATCH_JSON;
    errorTypeJson[BUNDLE_PATCH_PROFILE_KEY_MODULE][BUNDLE_PATCH_PROFILE_MODULE_KEY_ORIGINAL_MODULE_HASH] = 1234567890;
    CheckProfileTypes(errorTypeJson);
}

/**
 * @tc.number: PatchExtractor_ExtractPatchProfile_0100
 * @tc.name: ExtractPatchProfile
 * @tc.desc: system running normally
 */
HWTEST_F(BmsPatchParserTest, PatchExtractor_ExtractPatchProfile_0100, Function | SmallTest | Level0)
{
    PatchExtractor patchExtractor("");
    std::ostringstream osForTest;
    bool result = patchExtractor.ExtractPatchProfile(osForTest);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: PatchProfile_DefaultNativeSo_0100
 * @tc.name: DefaultNativeSo
 * @tc.desc: 1. system running normally
 *           2. call DefaultNativeSo with isSystemLib64Exist is true
 */
HWTEST_F(BmsPatchParserTest, PatchProfile_DefaultNativeSo_0100, Function | SmallTest | Level0)
{
    PatchExtractor patchExtractor("");
    bool isSystemLib64Exist = true;
    PatchProfile patchProfile;
    AppqfInfo appqfInfo;
    bool result = patchProfile.DefaultNativeSo(patchExtractor, isSystemLib64Exist, appqfInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: PatchProfile_DefaultNativeSo_0200
 * @tc.name: DefaultNativeSo
 * @tc.desc: 1. system running normally
 *           2. call DefaultNativeSo with isSystemLib64Exist is false
 */
HWTEST_F(BmsPatchParserTest, PatchProfile_DefaultNativeSo_0200, Function | SmallTest | Level0)
{
    PatchExtractor patchExtractor("");
    bool isSystemLib64Exist = false;
    PatchProfile patchProfile;
    AppqfInfo appqfInfo;
    bool result = patchProfile.DefaultNativeSo(patchExtractor, isSystemLib64Exist, appqfInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: PatchProfile_TransformTo_0100
 * @tc.name: TransformTo
 * @tc.desc: 1. system running normally
 *           2. call TransformTo with module name is invalid
 */
HWTEST_F(BmsPatchParserTest, PatchProfile_TransformTo_0100, Function | SmallTest | Level0)
{
    nlohmann::json errorProfileJson = PATCH_JSON;
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_MODULE].erase(BUNDLE_PATCH_PROFILE_MODULE_KEY_NAME);
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_MODULE].emplace(BUNDLE_PATCH_PROFILE_MODULE_KEY_NAME, "");
    std::ostringstream profileFileBuffer;
    profileFileBuffer << errorProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR, ret);
}

/**
 * @tc.number: PatchProfile_TransformTo_0200
 * @tc.name: TransformTo
 * @tc.desc: 1. system running normally
 *           2. test TransformTo with bad profile
 */
HWTEST_F(BmsPatchParserTest, PatchProfile_TransformTo_0200, Function | SmallTest | Level0)
{
    std::ostringstream profileFileBuffer;
    profileFileBuffer << "";
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_BAD_PROFILE, ret);
}

/**
 * @tc.number: PatchProfile_GetQuickFixType_0100
 * @tc.name: GetQuickFixType
 * @tc.desc: 1. system running normally
 *           2. test GetQuickFixType with type == BUNDLE_PATCH_TYPE_HOT_RELOAD
 */
HWTEST_F(BmsPatchParserTest, PatchProfile_GetQuickFixType_0100, Function | SmallTest | Level0)
{
    nlohmann::json errorProfileJson = PATCH_JSON;
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_MODULE].erase(BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE);
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_MODULE].emplace(
        BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE, BUNDLE_PATCH_TYPE_HOT_RELOAD);
    std::ostringstream profileFileBuffer;
    profileFileBuffer << errorProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(QuickFixType::HOT_RELOAD, appQuickFix.deployingAppqfInfo.type);
}

/**
 * @tc.number: PatchProfile_GetQuickFixType_0200
 * @tc.name: GetQuickFixType
 * @tc.desc: 1. system running normally
 *           2. test GetQuickFixType with type == UNKNOWN
 */
HWTEST_F(BmsPatchParserTest, PatchProfile_GetQuickFixType_0200, Function | SmallTest | Level0)
{
    nlohmann::json errorProfileJson = PATCH_JSON;
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_MODULE].erase(BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE);
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_MODULE].emplace(BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE, "UNKNOWN");
    std::ostringstream profileFileBuffer;
    profileFileBuffer << errorProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(QuickFixType::UNKNOWN, appQuickFix.deployingAppqfInfo.type);
}

/**
 * @tc.number: PatchProfile_ToPatchInfo_0100
 * @tc.name: ToPatchInfo
 * @tc.desc: 1. system running normally
 *           2. test ToPatchInfo with bundle is not match
 */
HWTEST_F(BmsPatchParserTest, PatchProfile_ToPatchInfo_0100, Function | SmallTest | Level0)
{
    nlohmann::json errorProfileJson = PATCH_JSON;
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_APP].erase(BUNDLE_PATCH_PROFILE_APP_KEY_BUNDLE_NAME);
    errorProfileJson[BUNDLE_PATCH_PROFILE_KEY_APP].emplace(
        BUNDLE_PATCH_PROFILE_APP_KEY_BUNDLE_NAME, ServiceConstants::RELATIVE_PATH);
    std::ostringstream profileFileBuffer;
    profileFileBuffer << errorProfileJson.dump();
    PatchExtractor patchExtractor("");
    AppQuickFix appQuickFix;
    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(profileFileBuffer, patchExtractor, appQuickFix);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR, ret);
}
}