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
        "parameters", parameters, false, parseResult, JsonType::NUMBER);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING);
    EXPECT_EQ(parseResult, ERR_OK);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::BOOLEAN);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "notfound", parameters, true, parseResult, JsonType::STRING);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(JSON_DATA_STR, jsonObjectEnd,
        "notfound", parameters, false, parseResult, JsonType::STRING);
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
        "parameters", parameters, false, parseResult, JsonType::NUMBER);
    EXPECT_EQ(parseResult, ERR_OK);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::BOOLEAN);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::NUMBER);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "notfound", parameters, true, parseResult, JsonType::NUMBER);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, int>>(JSON_DATA_INT, jsonObjectEnd,
        "notfound", parameters, false, parseResult, JsonType::NUMBER);
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
        "parameters", parameters, false, parseResult, JsonType::NUMBER);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::STRING);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::BOOLEAN);
    EXPECT_EQ(parseResult, ERR_OK);

    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "parameters", parameters, false, parseResult, JsonType::BOOLEAN);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "notfound", parameters, true, parseResult, JsonType::BOOLEAN);
    EXPECT_EQ(parseResult, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);

    parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, bool>>(JSON_DATA_BOOL, jsonObjectEnd,
        "notfound", parameters, false, parseResult, JsonType::BOOLEAN);
    EXPECT_EQ(parseResult, ERR_OK);
}

/**
 * @tc.number: Json_Util_Test_0400
 * @tc.name: Json_Util_Test_0400
 * @tc.desc: test CheckMapValueType
 */
HWTEST_F(BundleInfoTest, Json_Util_Test_0400, Function | SmallTest | Level0)
{
    const nlohmann::json JSON_DATA = R"(
        {
            "boolValue": true,
            "boolValueF": false,
            "numberValue": 1,
            "stringValue": "test"
        }
    )"_json;
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JsonType::BOOLEAN, JSON_DATA.at("boolValue")));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JsonType::BOOLEAN, JSON_DATA.at("boolValueF")));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::BOOLEAN, JSON_DATA.at("numberValue")));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::BOOLEAN, JSON_DATA.at("stringValue")));

    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::NUMBER, JSON_DATA.at("boolValue")));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::NUMBER, JSON_DATA.at("boolValueF")));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JsonType::NUMBER, JSON_DATA.at("numberValue")));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::NUMBER, JSON_DATA.at("stringValue")));

    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::STRING, JSON_DATA.at("boolValue")));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::STRING, JSON_DATA.at("boolValueF")));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::STRING, JSON_DATA.at("numberValue")));
    EXPECT_TRUE(BMSJsonUtil::CheckMapValueType(JsonType::STRING, JSON_DATA.at("stringValue")));

    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::ARRAY, JSON_DATA.at("boolValue")));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::NULLABLE, JSON_DATA.at("boolValueF")));
    EXPECT_FALSE(BMSJsonUtil::CheckMapValueType(JsonType::OBJECT, JSON_DATA.at("numberValue")));
}
} // AppExecFwk
} // OHOS
