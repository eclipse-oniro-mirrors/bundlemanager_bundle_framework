/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "bundle_info.h"

#include "json_util.h"
#include "parcel_macro.h"
#include "string_ex.h"
#include <cstdint>
#include <string>
#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BundleInfoTest : public testing::Test {
public:
    BundleInfoTest() = default;
    ~BundleInfoTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleInfoTest::SetUpTestCase()
{}

void BundleInfoTest::TearDownTestCase()
{}

void BundleInfoTest::SetUp()
{}

void BundleInfoTest::TearDown()
{}

/**
 * @tc.number: Bundle_Info_Test_0100
 * @tc.name: test the Unmarshalling of SimpleAppInfo
 * @tc.desc: 1. Unmarshalling
 */
HWTEST_F(BundleInfoTest, Bundle_Info_Test_0100, Function | SmallTest | Level0)
{
    Parcel parcel;
    auto ret = SimpleAppInfo::Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: Json_Util_Test_0100
 * @tc.name: Json_Util_Test_0100
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0100, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA_STR = R"(
        {
            "parameters": {
                "shortCutKey": "CompanyPage",
                "flag": "3",
                "uri": "file://com.test.abc/data/test.pdf"
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA_STR.end();
    std::map<std::string, std::string> parameters;
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_OK);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "notfound", parameters, true, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "notfound", parameters, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_OK);
}

/**
 * @tc.number: Json_Util_Test_0200
 * @tc.name: Json_Util_Test_0200
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0200, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA_INT = R"(
        {
            "parameters": {
                "shortCutKey": 1,
                "flag": 2,
                "uri": 3
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA_INT.end();
    std::map<std::string, int> parameters;
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_OK);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "notfound", parameters, true, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "notfound", parameters, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_OK);
}

/**
 * @tc.number: Json_Util_Test_0300
 * @tc.name: Json_Util_Test_0300
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0300, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA_BOOL = R"(
        {
            "parameters": {
                "shortCutKey": true,
                "flag": false,
                "uri": true
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA_BOOL.end();
    std::map<std::string, bool> parameters;
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_OK);

    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "notfound", parameters, true, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "notfound", parameters, false, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_OK);
}

/**
 * @tc.number: Json_Util_Test_0400
 * @tc.name: Json_Util_Test_0400
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0400, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "parameters": {
                "shortCutKey": [1, 2, 3],
                "flag": [1, 2, 3],
                "uri": []
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA.end();
    std::map<std::string, std::vector<int>> parameters;
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::NUMBER);
    EXPECT_EQ(parseResult, ERR_OK);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::STRING);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::OBJECT);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: Json_Util_Test_0500
 * @tc.name: Json_Util_Test_0500
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0500, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "parameters": {
                "shortCutKey": ["ok", "err"],
                "flag": ["ok", "err"],
                "uri": []
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA.end();
    std::map<std::string, std::vector<std::string>> parameters;
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<std::string>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::NUMBER);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<std::string>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::STRING);
    EXPECT_EQ(parseResult, ERR_OK);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<std::string>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::OBJECT);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<std::string>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<std::string>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: Json_Util_Test_0600
 * @tc.name: Json_Util_Test_0600
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0600, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "parameters": {
                "shortCutKey": [],
                "flag": [],
                "uri": []
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA.end();
    std::map<std::string, std::vector<int>> parameters;
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::NUMBER);
    EXPECT_EQ(parseResult, ERR_OK);

    std::map<std::string, std::vector<std::string>> parameters2;
    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<std::string>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters2, false, parseResult, JsonType::ARRAY, ArrayType::STRING);
    EXPECT_EQ(parseResult, ERR_OK);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::OBJECT);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: Json_Util_Test_0700
 * @tc.name: Json_Util_Test_0700
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0700, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "parameters": {
                "shortCutKey": [1, 2, 3],
                "flag": 1,
                "uri": "test"
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA.end();
    std::map<std::string, std::vector<int>> parameters;
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<int>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::NUMBER);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    std::map<std::string, std::vector<std::string>> parametersStr;
    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::vector<std::string>>>(JSON_DATA, jsonObjectEnd,
        "parameters", parametersStr, false, parseResult, JsonType::ARRAY, ArrayType::STRING);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    const nlohmann::json JSON_DATA2 = R"(
        {
            "parameters": {
                "flag": 1,
                "uri": "test",
                "shortCutKey": [1, 2, 3]
            }
        }
    )"_json;

    const auto &jsonObjectEnd2 = JSON_DATA2.end();
    std::map<std::string, int> parameters2;
    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA2, jsonObjectEnd2,
        "parameters", parameters2, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: Json_Util_Test_0800
 * @tc.name: Json_Util_Test_0800
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0800, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA3 = R"(
        {
            "parameters": {
                "uri": "test",
                "flag": 1,
                "shortCutKey": [1, 2, 3]
            }
        }
    )"_json;
    const auto &jsonObjectEnd3 = JSON_DATA3.end();
    std::map<std::string, std::string> parameters3;
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA3, jsonObjectEnd3,
        "parameters", parameters3, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    const nlohmann::json JSON_DATA4 = R"(
        {
            "parameters": {
                "flag": true,
                "uri": 1,
                "shortCutKey": [1, 2, 3]
            }
        }
    )"_json;
    const auto &jsonObjectEnd4 = JSON_DATA4.end();
    std::map<std::string, bool> parameters4;
    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA4, jsonObjectEnd4,
        "parameters", parameters4, false, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: Json_Util_Test_0900
 * @tc.name: Json_Util_Test_0900
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0900, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "parameters": {
                "shortCutKey": true,
                "flag": 1,
                "uri": "https://test.abc"
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA.end();
    std::map<std::string, bool> parameters;
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::ARRAY, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: Json_Util_Test_1000
 * @tc.name: Json_Util_Test_1000
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_1000, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "parameters": {
                "shortCutKey": true,
                "flag": 1,
                "uri": "https://test.abc"
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA.end();
    int32_t parseResult = ERR_OK;
    std::map<std::string, int> parameters2;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters2, false, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters2, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters2, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters2, false, parseResult, JsonType::ARRAY, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: Json_Util_Test_1100
 * @tc.name: Json_Util_Test_1100
 * @tc.desc: test GetMapValueIfFindKey
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_1100, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "parameters": {
                "shortCutKey": true,
                "flag": 1,
                "uri": "https://test.abc"
            }
        }
    )"_json;

    const auto &jsonObjectEnd = JSON_DATA.end();
    int32_t parseResult = ERR_OK;
    std::map<std::string, std::string> parameters3;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters3, false, parseResult, JsonType::BOOLEAN, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters3, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters3, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA, jsonObjectEnd,
        "parameters", parameters3, false, parseResult, JsonType::ARRAY, ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: CheckMapValueType_0100
 * @tc.name: CheckMapValueType_0100
 * @tc.desc: test CheckMapValueType
 */
HWTEST_F(BundleInfoTest, CheckMapValueType_0100, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "boolValue": true,
            "boolValueF": false,
            "numberValue": 1,
            "stringValue": "test"
        }
    )"_json;
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValue"), JsonType::BOOLEAN, ArrayType::NOT_ARRAY));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValueF"), JsonType::BOOLEAN, ArrayType::NOT_ARRAY));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("numberValue"), JsonType::BOOLEAN, ArrayType::NOT_ARRAY));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("stringValue"), JsonType::BOOLEAN, ArrayType::NOT_ARRAY));

    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValue"), JsonType::NUMBER, ArrayType::NOT_ARRAY));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValueF"), JsonType::NUMBER, ArrayType::NOT_ARRAY));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("numberValue"), JsonType::NUMBER, ArrayType::NOT_ARRAY));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("stringValue"), JsonType::NUMBER, ArrayType::NOT_ARRAY));

    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValue"), JsonType::STRING, ArrayType::NOT_ARRAY));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValueF"), JsonType::STRING, ArrayType::NOT_ARRAY));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("numberValue"), JsonType::STRING, ArrayType::NOT_ARRAY));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("stringValue"), JsonType::STRING, ArrayType::NOT_ARRAY));

    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValue"), JsonType::ARRAY, ArrayType::NUMBER));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValueF"), JsonType::ARRAY, ArrayType::OBJECT));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("numberValue"), JsonType::ARRAY, ArrayType::STRING));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("stringValue"), JsonType::ARRAY, ArrayType::NOT_ARRAY));
}

/**
 * @tc.number: CheckMapValueType_0200
 * @tc.name: CheckMapValueType_0200
 * @tc.desc: test CheckMapValueType
 */
HWTEST_F(BundleInfoTest, CheckMapValueType_0200, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "boolValue": [true, false],
            "numberValue": [1, 2, 3],
            "stringValue": ["test", "test2"],
            "emptyArray": []
        }
    )"_json;
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValue"), JsonType::ARRAY, ArrayType::NOT_ARRAY));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("numberValue"), JsonType::ARRAY, ArrayType::NOT_ARRAY));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("stringValue"), JsonType::ARRAY, ArrayType::NOT_ARRAY));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("emptyArray"), JsonType::ARRAY, ArrayType::NOT_ARRAY));

    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValue"), JsonType::ARRAY, ArrayType::NUMBER));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("numberValue"), JsonType::ARRAY, ArrayType::NUMBER));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("stringValue"), JsonType::ARRAY, ArrayType::NUMBER));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("emptyArray"), JsonType::ARRAY, ArrayType::NUMBER));

    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValue"), JsonType::ARRAY, ArrayType::STRING));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("numberValue"), JsonType::ARRAY, ArrayType::STRING));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("stringValue"), JsonType::ARRAY, ArrayType::STRING));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("emptyArray"), JsonType::ARRAY, ArrayType::STRING));

    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("boolValue"), JsonType::ARRAY, ArrayType::OBJECT));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("numberValue"), JsonType::ARRAY, ArrayType::OBJECT));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("stringValue"), JsonType::ARRAY, ArrayType::OBJECT));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JSON_DATA.at("emptyArray"), JsonType::ARRAY, ArrayType::OBJECT));
}
/**
 * @tc.number: CheckMapValueType_0300
 * @tc.name: CheckMapValueType_0300
 * @tc.desc: test CheckMapValueType with JsonType::OBJECT
 */
HWTEST_F(BundleInfoTest, CheckMapValueType_0300, Function | SmallTest | Level0)
{
    nlohmann::json objVal = {{"name", "test"}};
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(objVal, JsonType::OBJECT, ArrayType::NOT_ARRAY));

    nlohmann::json nullVal = nullptr;
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(nullVal, JsonType::OBJECT, ArrayType::NOT_ARRAY));

    nlohmann::json strVal = "not_an_object";
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(strVal, JsonType::OBJECT, ArrayType::NOT_ARRAY));

    nlohmann::json numVal = 123;
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(numVal, JsonType::OBJECT, ArrayType::NOT_ARRAY));

    nlohmann::json boolVal = true;
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(boolVal, JsonType::OBJECT, ArrayType::NOT_ARRAY));
}

/**
 * @tc.number: GetMapObject_0100
 * @tc.name: GetMapObject_0100
 * @tc.desc: test GetMapObject with struct value type (JsonType::OBJECT)
 */
HWTEST_F(BundleInfoTest, GetMapObject_0100, Function | SmallTest | Level0)
{
    nlohmann::json jsonObj;
    jsonObj["abilities"] = {
        {"key1", {{"name", "ability1"}, {"label", "Label1"}}},
        {"key2", {{"name", "ability2"}, {"label", "Label2"}}}
    };
    int32_t parseResult = ERR_OK;
    const nlohmann::json *mapPtr = nullptr;
    BMSJsonUtil::GetMapObject(jsonObj, jsonObj.end(), "abilities", mapPtr,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, true, parseResult);
    EXPECT_EQ(parseResult, ERR_OK);
    EXPECT_NE(mapPtr, nullptr);
    EXPECT_EQ(mapPtr->size(), 2u);
}

/**
 * @tc.number: GetMapObject_0200
 * @tc.name: GetMapObject_0200
 * @tc.desc: test GetMapObject rejects null values (crash prevention)
 */
HWTEST_F(BundleInfoTest, GetMapObject_0200, Function | SmallTest | Level0)
{
    nlohmann::json jsonObj;
    jsonObj["data"] = {{"key1", nullptr}, {"key2", {{"name", "ok"}}}};
    int32_t parseResult = ERR_OK;
    const nlohmann::json *mapPtr = nullptr;
    BMSJsonUtil::GetMapObject(jsonObj, jsonObj.end(), "data", mapPtr,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, true, parseResult);
    EXPECT_NE(parseResult, ERR_OK);
    EXPECT_EQ(mapPtr, nullptr);
}

/**
 * @tc.number: GetMapObject_0300
 * @tc.name: GetMapObject_0300
 * @tc.desc: test GetMapObject with missing key (necessary vs optional)
 */
HWTEST_F(BundleInfoTest, GetMapObject_0300, Function | SmallTest | Level0)
{
    nlohmann::json jsonObj = nlohmann::json::object();
    int32_t parseResult = ERR_OK;
    const nlohmann::json *mapPtr = nullptr;

    // necessary key missing
    BMSJsonUtil::GetMapObject(jsonObj, jsonObj.end(), "nonexistent", mapPtr,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, true, parseResult);
    EXPECT_NE(parseResult, ERR_OK);
    EXPECT_EQ(mapPtr, nullptr);

    // optional key missing
    parseResult = ERR_OK;
    BMSJsonUtil::GetMapObject(jsonObj, jsonObj.end(), "nonexistent", mapPtr,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, false, parseResult);
    EXPECT_EQ(parseResult, ERR_OK);
    EXPECT_EQ(mapPtr, nullptr);
}

/**
 * @tc.number: GetMapObject_0400
 * @tc.name: GetMapObject_0400
 * @tc.desc: test GetMapObject with vector value type (JsonType::ARRAY, ArrayType::OBJECT)
 */
HWTEST_F(BundleInfoTest, GetMapObject_0400, Function | SmallTest | Level0)
{
    nlohmann::json jsonObj;
    nlohmann::json skillArr = nlohmann::json::array();
    skillArr.push_back({{"name", "skill1"}});
    skillArr.push_back({{"name", "skill2"}});
    jsonObj["skills"] = {{"key1", skillArr}, {"key2", skillArr}};
    int32_t parseResult = ERR_OK;
    const nlohmann::json *mapPtr = nullptr;
    BMSJsonUtil::GetMapObject(jsonObj, jsonObj.end(), "skills", mapPtr,
        JsonType::ARRAY, ArrayType::OBJECT, true, parseResult);
    EXPECT_EQ(parseResult, ERR_OK);
    EXPECT_NE(mapPtr, nullptr);
    EXPECT_EQ(mapPtr->size(), 2u);
}

/**
 * @tc.number: GetMapObject_0500
 * @tc.name: GetMapObject_0500
 * @tc.desc: test GetMapObject with vector type rejects null elements
 */
HWTEST_F(BundleInfoTest, GetMapObject_0500, Function | SmallTest | Level0)
{
    nlohmann::json jsonObj;
    nlohmann::json badArr = nlohmann::json::array();
    badArr.push_back({{"name", "skill1"}});
    badArr.push_back(nullptr);
    jsonObj["skills"] = {{"key1", badArr}};
    int32_t parseResult = ERR_OK;
    const nlohmann::json *mapPtr = nullptr;
    BMSJsonUtil::GetMapObject(jsonObj, jsonObj.end(), "skills", mapPtr,
        JsonType::ARRAY, ArrayType::OBJECT, true, parseResult);
    EXPECT_NE(parseResult, ERR_OK);
    EXPECT_EQ(mapPtr, nullptr);
}

/**
 * @tc.number: GetMapObject_0600
 * @tc.name: GetMapObject_0600
 * @tc.desc: test GetMapObject with non-object value
 */
HWTEST_F(BundleInfoTest, GetMapObject_0600, Function | SmallTest | Level0)
{
    nlohmann::json jsonObj;
    jsonObj["data"] = "not_an_object";
    int32_t parseResult = ERR_OK;
    const nlohmann::json *mapPtr = nullptr;
    BMSJsonUtil::GetMapObject(jsonObj, jsonObj.end(), "data", mapPtr,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, true, parseResult);
    EXPECT_NE(parseResult, ERR_OK);
    EXPECT_EQ(mapPtr, nullptr);
}

/**
 * @tc.number: GetMapObject_0700
 * @tc.name: GetMapObject_0700
 * @tc.desc: test GetMapObject early-returns when parseResult already has error
 */
HWTEST_F(BundleInfoTest, GetMapObject_0700, Function | SmallTest | Level0)
{
    nlohmann::json jsonObj;
    jsonObj["data"] = {{"key", {{"name", "test"}}}};
    int32_t parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    const nlohmann::json *mapPtr = nullptr;
    BMSJsonUtil::GetMapObject(jsonObj, jsonObj.end(), "data", mapPtr,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, true, parseResult);
    EXPECT_EQ(mapPtr, nullptr);
}

/**
 * @tc.number: GetMapObject_0800
 * @tc.name: GetMapObject_0800
 * @tc.desc: test GetMapObject roundtrip with get<T>
 */
HWTEST_F(BundleInfoTest, GetMapObject_0800, Function | SmallTest | Level0)
{
    nlohmann::json jsonObj;
    jsonObj["items"] = {
        {"a", {{"name", "itemA"}, {"label", "LabelA"}}},
        {"b", {{"name", "itemB"}, {"label", "LabelB"}}}
    };
    int32_t parseResult = ERR_OK;
    const nlohmann::json *mapPtr = nullptr;
    BMSJsonUtil::GetMapObject(jsonObj, jsonObj.end(), "items", mapPtr,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, true, parseResult);
    EXPECT_EQ(parseResult, ERR_OK);
    ASSERT_NE(mapPtr, nullptr);
    auto result = mapPtr->get<std::map<std::string, nlohmann::json>>();
    EXPECT_EQ(result.size(), 2u);
}

} // AppExecFwk
} // OHOS
