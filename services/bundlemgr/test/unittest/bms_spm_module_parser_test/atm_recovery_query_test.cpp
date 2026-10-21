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
#include <map>
#include <memory>
#include "accesstoken_kit.h"
#include "appexecfwk_errors.h"
#include "atm_bundle_recovery_info.h"
#include "bundle_constants.h"
#include "nlohmann/json.hpp"
#include "read_only_installed_bundle_store.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace {
uint64_t selfToken;
int permissionResult;
uint32_t seenToken;
int verifyCalls;
bool openOk;
bool readOk;
int openCalls;
size_t cursor;
std::vector<std::pair<std::string, std::string>> records;
const char *GOOD = R"({"baseBundleInfo":{"name":"app"},
    "innerModuleInfos":{"entry":{"hapPath":"entry.hap"}},
    "innerBundleUserInfos":{"app_0":{"uid":10000,"accessTokenId":4294967295,
    "bundleUserInfo":{"userId":0}}}})";
}
extern "C" uint64_t GetSelfTokenID(void) { return selfToken; }
namespace OHOS::Security::AccessToken {
int AccessTokenKit::VerifyAccessToken(AccessTokenID token, const std::string &permissionName)
{
    EXPECT_EQ(permissionName, "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    seenToken = token;
    ++verifyCalls;
    return permissionResult;
}
} // namespace OHOS::Security::AccessToken

namespace OHOS::AppExecFwk::AtmRecovery {
ReadOnlyInstalledBundleStore::ReadOnlyInstalledBundleStore(const std::string &path) : path_(path) {}
ReadOnlyInstalledBundleStore::~ReadOnlyInstalledBundleStore() = default;
bool ReadOnlyInstalledBundleStore::Open() { ++openCalls; return openOk; }
bool ReadOnlyInstalledBundleStore::QueryAllData(std::map<std::string, std::string> &data)
{
    data.clear();
    for (const auto &record : records) {
        data.insert(record);
        ++cursor;
    }
    return readOk;
}
}
namespace OHOS::AppExecFwk {
using Security::AccessToken::PermissionState;

class AtmRecoveryQueryTest : public testing::Test {
    void SetUp() override
    {
        selfToken = 0x12345678FFFFFFFFULL;
        permissionResult = PermissionState::PERMISSION_GRANTED;
        seenToken = 0;
        verifyCalls = 0;
        openOk = readOk = true;
        openCalls = 0;
        cursor = 0;
        records.clear();
    }
};

/**
 * @tc.name: ChecksActualProcessEveryTime
 * @tc.desc: Accept an empty database and recheck the current process permission on every query.
 */
HWTEST_F(AtmRecoveryQueryTest, ChecksActualProcessEveryTime, Function | SmallTest | Level1)
{
    const auto emptyResult = QueryAtmBundleRecoveryInfo();
    EXPECT_EQ(emptyResult.code, ERR_OK);
    EXPECT_TRUE(emptyResult.infos.empty());
    EXPECT_EQ(seenToken, UINT32_MAX);
    selfToken = 42;
    permissionResult = PermissionState::PERMISSION_DENIED;
    auto result = QueryAtmBundleRecoveryInfo();
    EXPECT_EQ(result.code, ERR_APPEXECFWK_PERMISSION_DENIED);
    EXPECT_TRUE(result.infos.empty());
    EXPECT_EQ(seenToken, 42U);
    EXPECT_EQ(verifyCalls, 2);
    EXPECT_EQ(openCalls, 1);
}

/**
 * @tc.name: InvalidIdentityStopsBeforeVerification
 * @tc.desc: Reject an invalid process token before permission verification or database access.
 */
HWTEST_F(AtmRecoveryQueryTest, InvalidIdentityStopsBeforeVerification, Function | SmallTest | Level1)
{
    selfToken = 0;
    auto result = QueryAtmBundleRecoveryInfo();
    EXPECT_EQ(result.code, ERR_APPEXECFWK_PERMISSION_DENIED);
    EXPECT_TRUE(result.infos.empty());
    EXPECT_EQ(verifyCalls, 0);
    EXPECT_EQ(openCalls, 0);
}

/**
 * @tc.name: OnlyExplicitGrantAllows
 * @tc.desc: Reject permission states other than an explicit grant.
 */
HWTEST_F(AtmRecoveryQueryTest, OnlyExplicitGrantAllows, Function | SmallTest | Level1)
{
    for (int status : {-2, 1}) {
        permissionResult = status;
        auto result = QueryAtmBundleRecoveryInfo();
        EXPECT_EQ(result.code, ERR_APPEXECFWK_PERMISSION_DENIED);
        EXPECT_TRUE(result.infos.empty());
    }
    EXPECT_EQ(verifyCalls, 2);
    EXPECT_EQ(openCalls, 0);
}

/**
 * @tc.name: DenialPrecedesMissingDatabase
 * @tc.desc: Return permission denial before checking whether the database exists.
 */
HWTEST_F(AtmRecoveryQueryTest, DenialPrecedesMissingDatabase, Function | SmallTest | Level1)
{
    permissionResult = PermissionState::PERMISSION_DENIED;
    openOk = false;
    auto result = QueryAtmBundleRecoveryInfo();
    EXPECT_EQ(result.code, ERR_APPEXECFWK_PERMISSION_DENIED);
    EXPECT_TRUE(result.infos.empty());
    EXPECT_EQ(openCalls, 0);
}

/**
 * @tc.name: SameNameDifferentPackagesReturnTheirOwnModeAndIdentity
 * @tc.desc: Skip bad records and keep both packages with their own mode, identity and module paths.
 */
HWTEST_F(AtmRecoveryQueryTest, SameNameDifferentPackagesReturnTheirOwnModeAndIdentity, Function | SmallTest | Level1)
{
    auto primary = nlohmann::json::parse(GOOD);
    primary["baseBundleInfo"]["deviceModeDistributionPolicy"] = 4;
    auto secondary = primary;
    secondary["isDualModeCloneApp"] = true;
    secondary["appIndex"] = Constants::DUAL_MODE_CLONE_APP_INDEX;
    secondary["innerModuleInfos"]["entry"]["hapPath"] = "secondary.hap";
    secondary["innerBundleUserInfos"]["app_0"]["accessTokenId"] = 42;
    secondary["innerBundleUserInfos"]["app_0"]["uid"] = 10001;
    records = {{"0bad", "[]"}, {"app", primary.dump()}, {"+clone-10000+app", secondary.dump()}, {"bad", "{"}};
    const auto result = QueryAtmBundleRecoveryInfo();
    ASSERT_EQ(result.code, ERR_OK);
    ASSERT_EQ(result.infos.size(), 2U);
    EXPECT_EQ(cursor, records.size());
    for (const auto &info : result.infos) {
        EXPECT_EQ(info.bundleName, "app");
        if (info.appIndex == Constants::DUAL_MODE_CLONE_APP_INDEX) {
            EXPECT_EQ(info.mode, 1);
            EXPECT_EQ(info.accessTokenId, 42U);
            EXPECT_EQ(info.uid, 10001);
            EXPECT_EQ(info.hapPaths, std::vector<std::string>{"secondary.hap"});
        } else {
            EXPECT_EQ(info.appIndex, Constants::DEFAULT_APP_INDEX);
            EXPECT_EQ(info.mode, 0);
            EXPECT_EQ(info.accessTokenId, UINT32_MAX);
            EXPECT_EQ(info.uid, 10000);
            EXPECT_EQ(info.hapPaths, std::vector<std::string>{"entry.hap"});
        }
    }
}

/**
 * @tc.name: BadSecondaryDoesNotChangePrimaryMode
 * @tc.desc: Keep the primary record mode when its secondary record is malformed.
 */
HWTEST_F(AtmRecoveryQueryTest, BadSecondaryDoesNotChangePrimaryMode, Function | SmallTest | Level1)
{
    for (int32_t policy : {0, 4}) {
        auto primary = nlohmann::json::parse(GOOD);
        primary["baseBundleInfo"]["deviceModeDistributionPolicy"] = policy;
        records = {{"app", primary.dump()}, {"+clone-10000+app", "broken"}};
        const auto result = QueryAtmBundleRecoveryInfo();
        ASSERT_EQ(result.code, ERR_OK);
        ASSERT_EQ(result.infos.size(), 1U);
        EXPECT_EQ(result.infos[0].mode, policy == 4 ? 0 : -1);
    }
}

/**
 * @tc.name: AllBadIsNotEmptySuccess
 * @tc.desc: Return a database error when every stored record is malformed.
 */
HWTEST_F(AtmRecoveryQueryTest, AllBadIsNotEmptySuccess, Function | SmallTest | Level1)
{
    records = {{"a", "{}"}, {"b", "broken"}};
    auto result = QueryAtmBundleRecoveryInfo();
    EXPECT_EQ(result.code, ERR_APPEXECFWK_DB_GET_DATA_ERROR);
    EXPECT_TRUE(result.infos.empty());
}

/**
 * @tc.name: ReadFailureDiscardsEarlierGoodRows
 * @tc.desc: Return a database error without partial results when reading the database fails.
 */
HWTEST_F(AtmRecoveryQueryTest, ReadFailureDiscardsEarlierGoodRows, Function | SmallTest | Level1)
{
    records = {{"app", GOOD}};
    readOk = false;
    auto result = QueryAtmBundleRecoveryInfo();
    EXPECT_EQ(result.code, ERR_APPEXECFWK_DB_GET_DATA_ERROR);
    EXPECT_TRUE(result.infos.empty());
}

} // namespace OHOS::AppExecFwk
