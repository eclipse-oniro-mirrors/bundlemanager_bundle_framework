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
#include "atm_recovery_record_decoder.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;

namespace OHOS::AppExecFwk::AtmRecovery {
namespace {
using Json = nlohmann::json;
const std::string BUNDLE_NAME = "com.example.app";
const std::string SECONDARY_KEY = "+clone-10000+" + BUNDLE_NAME;
Json Record(const std::string &name = BUNDLE_NAME)
{
    return Json {
        {"baseBundleInfo", {{"name", name}, {"isPreInstallApp", false}}},
        {"innerModuleInfos", {{"entry", {{"hapPath", "/data/app/entry.hap"}}}}},
        {"innerBundleUserInfos", {{name + "_0", {
            {"uid", 10000}, {"accessTokenId", 0}, {"accessTokenIdEx", 1},
            {"bundleUserInfo", {{"userId", Constants::DEFAULT_USERID}}}
        }}}}
    };
}
std::vector<AtmBundleRecoveryInfo> Decode(const Json &record, const std::string &key = BUNDLE_NAME)
{
    std::vector<AtmBundleRecoveryInfo> infos;
    EXPECT_TRUE(ParseAtmRecoveryRecord(key, record.dump(), infos));
    return infos;
}
}

class AtmRecoveryDecoderTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: AllUsersAndClonesKeepTheirOwnIdentity
 * @tc.desc: Keep each user and clone identity, module paths and package attributes.
 */
HWTEST_F(AtmRecoveryDecoderTest, AllUsersAndClonesKeepTheirOwnIdentity, Function | SmallTest | Level1)
{
    auto record = Record();
    auto &first = record["innerBundleUserInfos"]["com.example.app_0"];
    first["cloneInfos"] = {{"1", {{"userId", Constants::DEFAULT_USERID}, {"appIndex", 1},
        {"uid", 10001}, {"accessTokenId", 2147483648U}, {"accessTokenIdEx", 2147483648U}}}};
    record["innerBundleUserInfos"]["com.example.app_100"] = {
        {"uid", 20010000}, {"accessTokenId", 4294967295U}, {"accessTokenIdEx", 4294967295U},
        {"bundleUserInfo", {{"userId", Constants::START_USERID}}}};
    record["innerModuleInfos"]["feature"] = {{"hapPath", "/data/app/feature.hap"}};
    record["baseBundleInfo"]["isPreInstallApp"] = true;
    auto infos = Decode(record);
    ASSERT_EQ(infos.size(), 3U);
    EXPECT_EQ(infos[0].accessTokenId, 0U);
    EXPECT_EQ(infos[1].accessTokenId, 2147483648U);
    EXPECT_EQ(infos[2].accessTokenId, 4294967295U);
    EXPECT_EQ(infos[2].userId, Constants::START_USERID);
    for (const auto &info : infos) {
        EXPECT_EQ(info.hapPaths.size(), 2U);
        EXPECT_TRUE(info.isPreInstallApp);
        EXPECT_EQ(info.mode, -1);
    }
    record["baseBundleInfo"]["deviceModeDistributionPolicy"] = 4;
    for (const auto &info : Decode(record)) {
        EXPECT_EQ(info.mode, 0);
    }
}

/**
 * @tc.name: SandboxInstancesAreExcluded
 * @tc.desc: Ignore sandbox identities and malformed sandbox fields without losing main or clone identities.
 */
HWTEST_F(AtmRecoveryDecoderTest, SandboxInstancesAreExcluded, Function | SmallTest | Level1)
{
    auto record = Record();
    auto &user = record["innerBundleUserInfos"]["com.example.app_0"];
    user["cloneInfos"] = {{"1", {{"userId", Constants::DEFAULT_USERID}, {"appIndex", 1},
        {"uid", 10001}, {"accessTokenId", 73}, {"accessTokenIdEx", 73}}}};
    const Json sandbox = {{"2000", {{"userId", Constants::DEFAULT_USERID}, {"appIndex", 2000},
        {"uid", 10002}, {"accessTokenId", 74}, {"accessTokenIdEx", 74}}}};
    for (const Json &value : std::vector<Json>{sandbox, {{"2000", nullptr}}, nullptr, Json::array(), "invalid"}) {
        SCOPED_TRACE(value.dump());
        user["sandboxInfos"] = value;
        const auto infos = Decode(record);
        ASSERT_EQ(infos.size(), 2U);
        EXPECT_EQ(infos[0].appIndex, Constants::DEFAULT_APP_INDEX);
        EXPECT_EQ(infos[0].uid, 10000);
        EXPECT_EQ(infos[0].accessTokenId, 0U);
        EXPECT_EQ(infos[1].appIndex, 1);
        EXPECT_EQ(infos[1].uid, 10001);
        EXPECT_EQ(infos[1].accessTokenId, 73U);
    }
}

/**
 * @tc.name: InvalidJsonClearsOutputAndDoesNotAffectNextRecord
 * @tc.desc: Reject invalid JSON, clear its output and allow the next valid record.
 */
HWTEST_F(AtmRecoveryDecoderTest, InvalidJsonClearsOutputAndDoesNotAffectNextRecord, Function | SmallTest | Level1)
{
    std::vector<AtmBundleRecoveryInfo> infos;
    for (const char *value : {"", "{", "[]", "null", "true"}) {
        infos = Decode(Record());
        EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, value, infos));
        EXPECT_TRUE(infos.empty());
    }
    EXPECT_TRUE(ParseAtmRecoveryRecord(BUNDLE_NAME, Record().dump(), infos));
    ASSERT_EQ(infos.size(), 1U);
    EXPECT_EQ(infos[0].bundleName, BUNDLE_NAME);
}

/**
 * @tc.name: MissingOrInvalidRequiredObjectsAreRejected
 * @tc.desc: Reject missing or invalid required objects and clear the output without exceptions.
 */
HWTEST_F(AtmRecoveryDecoderTest, MissingOrInvalidRequiredObjectsAreRejected, Function | SmallTest | Level1)
{
    for (const char *path : {"/baseBundleInfo", "/innerModuleInfos", "/innerBundleUserInfos",
        "/innerBundleUserInfos/com.example.app_0/bundleUserInfo"}) {
        SCOPED_TRACE(path);
        const Json::json_pointer field(path);
        auto record = Record();
        record[field.parent_pointer()].erase(field.back());
        auto infos = Decode(Record());
        EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
        EXPECT_TRUE(infos.empty());
        for (const Json &value : std::vector<Json>{nullptr, Json::array(), Json::object(), "invalid", 1, true}) {
            record = Record();
            record[field] = value;
            infos = Decode(Record());
            EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
            EXPECT_TRUE(infos.empty());
        }
    }
}

/**
 * @tc.name: RejectsBadTokenTypesAndOverflow
 * @tc.desc: Reject access token IDs with invalid types or values outside uint32_t.
 */
HWTEST_F(AtmRecoveryDecoderTest, RejectsBadTokenTypesAndOverflow, Function | SmallTest | Level1)
{
    for (const Json &value : std::vector<Json>{-1, 4294967296ULL, 1.5, "1", nullptr, true}) {
        auto record = Record();
        record["innerBundleUserInfos"]["com.example.app_0"]["accessTokenId"] = value;
        std::vector<AtmBundleRecoveryInfo> infos;
        EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
        EXPECT_TRUE(infos.empty());
    }
}

/**
 * @tc.name: RejectsSentinelAndMissingIdentity
 * @tc.desc: Reject special user IDs and records without an access token ID.
 */
HWTEST_F(AtmRecoveryDecoderTest, RejectsSentinelAndMissingIdentity, Function | SmallTest | Level1)
{
    for (int32_t id : {Constants::INVALID_USERID, Constants::UNSPECIFIED_USERID,
        Constants::ALL_USERID, Constants::ANY_USERID}) {
        auto record = Record();
        record["innerBundleUserInfos"]["com.example.app_0"]["bundleUserInfo"]["userId"] = id;
        std::vector<AtmBundleRecoveryInfo> infos;
        EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
    }
    auto record = Record();
    record["innerBundleUserInfos"]["com.example.app_0"].erase("accessTokenId");
    std::vector<AtmBundleRecoveryInfo> infos;
    EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
}

/**
 * @tc.name: BrokenChildDiscardsEarlierInstancesOfTheSameRecord
 * @tc.desc: Discard a record with an invalid child while allowing later valid records.
 */
HWTEST_F(AtmRecoveryDecoderTest, BrokenChildDiscardsEarlierInstancesOfTheSameRecord, Function | SmallTest | Level1)
{
    auto record = Record();
    record["innerBundleUserInfos"]["com.example.app_0"]["cloneInfos"] = {{"1", {{"uid", 10}}}};
    std::vector<AtmBundleRecoveryInfo> infos;
    EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
    EXPECT_TRUE(infos.empty());
    EXPECT_TRUE(ParseAtmRecoveryRecord("com.example.other", Record("com.example.other").dump(), infos));
    ASSERT_EQ(infos.size(), 1U);
    EXPECT_EQ(infos[0].bundleName, "com.example.other");
}

/**
 * @tc.name: ModeUsesDifferentPackagePolicyAndPrimarySecondaryFlag
 * @tc.desc: Derive mode and app index from each policy and primary or secondary marker.
 */
HWTEST_F(AtmRecoveryDecoderTest, ModeUsesDifferentPackagePolicyAndPrimarySecondaryFlag, Function | SmallTest | Level1)
{
    for (int32_t policy = 0; policy <= 8; ++policy) {
        for (bool secondary : {false, true}) {
            SCOPED_TRACE(std::to_string(policy) + (secondary ? " secondary" : " primary"));
            auto record = Record();
            record["baseBundleInfo"]["deviceModeDistributionPolicy"] = policy;
            record["isDualModeCloneApp"] = secondary;
            const auto infos = Decode(record, secondary ? SECONDARY_KEY : BUNDLE_NAME);
            ASSERT_EQ(infos.size(), 1U);
            const bool differentPackage = policy == 4 || policy == 6 || policy == 8;
            EXPECT_EQ(infos[0].mode, differentPackage ? (secondary ? 1 : 0) : -1);
            EXPECT_EQ(infos[0].appIndex, secondary ? Constants::DUAL_MODE_CLONE_APP_INDEX :
                Constants::DEFAULT_APP_INDEX);
        }
    }
}

/**
 * @tc.name: IsolationDoesNotMakeAnIdenticalPackageDifferent
 * @tc.desc: Keep mode at -1 for an identical package with isolated data.
 */
HWTEST_F(AtmRecoveryDecoderTest, IsolationDoesNotMakeAnIdenticalPackageDifferent, Function | SmallTest | Level1)
{
    auto record = Record();
    record["baseBundleInfo"]["deviceModeDistributionPolicy"] = 3;
    record["baseBundleInfo"]["appSandboxPolicy"] = 1;
    const auto infos = Decode(record);
    ASSERT_EQ(infos.size(), 1U);
    EXPECT_EQ(infos[0].mode, -1);
}

/**
 * @tc.name: LegacyOptionalFieldsKeepTheirDefaults
 * @tc.desc: Preserve historical defaults when optional fields are absent.
 */
HWTEST_F(AtmRecoveryDecoderTest, LegacyOptionalFieldsKeepTheirDefaults, Function | SmallTest | Level1)
{
    auto record = Record();
    record["baseBundleInfo"].erase("isPreInstallApp");
    record["innerModuleInfos"]["entry"].erase("hapPath");
    const auto infos = Decode(record);
    ASSERT_EQ(infos.size(), 1U);
    EXPECT_FALSE(infos[0].isPreInstallApp);
    EXPECT_EQ(infos[0].hapPaths, std::vector<std::string>{""});
    EXPECT_EQ(infos[0].mode, -1);
}

/**
 * @tc.name: DuplicateFieldsAndConflictingUserKeyAreInvalid
 * @tc.desc: Reject duplicate JSON fields and user IDs that conflict with their storage keys.
 */
HWTEST_F(AtmRecoveryDecoderTest, DuplicateFieldsAndConflictingUserKeyAreInvalid, Function | SmallTest | Level1)
{
    auto value = Record().dump();
    const auto token = value.find("\"accessTokenId\":0");
    ASSERT_NE(token, std::string::npos);
    value.replace(token, std::string("\"accessTokenId\":0").size(), "\"accessTokenId\":1,\"accessTokenId\":0");
    std::vector<AtmBundleRecoveryInfo> infos;
    EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, value, infos));
    auto record = Record();
    record["innerBundleUserInfos"]["com.example.app_0"]["bundleUserInfo"]["userId"] = Constants::START_USERID;
    EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
}

/**
 * @tc.name: MalformedOptionalFieldsDoNotBecomeValidDefaults
 * @tc.desc: Reject malformed optional fields instead of replacing them with defaults.
 */
HWTEST_F(AtmRecoveryDecoderTest, MalformedOptionalFieldsDoNotBecomeValidDefaults, Function | SmallTest | Level1)
{
    const std::vector<std::pair<std::string, Json>> invalidFields = {
        {"/baseBundleInfo/isPreInstallApp", 1},
        {"/baseBundleInfo/deviceModeDistributionPolicy", 9},
        {"/baseBundleInfo/deviceModeDistributionPolicy", "4"},
        {"/isDualModeCloneApp", "false"},
        {"/innerModuleInfos/entry/hapPath", nullptr},
        {"/innerModuleInfos/entry", Json::array()},
        {"/innerBundleUserInfos/com.example.app_0/bundleName", false},
        {"/innerBundleUserInfos/com.example.app_0/cloneInfos", Json::array()},
    };
    for (const auto &[path, value] : invalidFields) {
        SCOPED_TRACE(path);
        auto record = Record();
        record[Json::json_pointer(path)] = value;
        std::vector<AtmBundleRecoveryInfo> infos;
        EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
        EXPECT_TRUE(infos.empty());
    }
}

/**
 * @tc.name: RecoveryIdentitiesRejectNumericConversion
 * @tc.desc: Reject identity values that would require conversion or overflow int32_t.
 */
HWTEST_F(AtmRecoveryDecoderTest, RecoveryIdentitiesRejectNumericConversion, Function | SmallTest | Level1)
{
    for (const auto &path : {"/appIndex", "/innerBundleUserInfos/com.example.app_0/uid",
        "/innerBundleUserInfos/com.example.app_0/bundleUserInfo/userId"}) {
        for (const Json &value : std::vector<Json>{-1, 2147483648ULL, 1.5, "1", nullptr, true}) {
            SCOPED_TRACE(path);
            auto record = Record();
            record[Json::json_pointer(path)] = value;
            std::vector<AtmBundleRecoveryInfo> infos;
            EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
        }
    }
}

/**
 * @tc.name: SecondaryMarkerMustMatchStorageKeyAndIndex
 * @tc.desc: Reject secondary markers that conflict with the storage key or app index.
 */
HWTEST_F(AtmRecoveryDecoderTest, SecondaryMarkerMustMatchStorageKeyAndIndex, Function | SmallTest | Level1)
{
    auto record = Record();
    record["baseBundleInfo"]["deviceModeDistributionPolicy"] = 4;
    std::vector<AtmBundleRecoveryInfo> infos;
    EXPECT_FALSE(ParseAtmRecoveryRecord(SECONDARY_KEY, record.dump(), infos));
    record["isDualModeCloneApp"] = true;
    EXPECT_FALSE(ParseAtmRecoveryRecord(BUNDLE_NAME, record.dump(), infos));
    record["appIndex"] = 1;
    EXPECT_FALSE(ParseAtmRecoveryRecord(SECONDARY_KEY, record.dump(), infos));
}
} // namespace OHOS::AppExecFwk::AtmRecovery
