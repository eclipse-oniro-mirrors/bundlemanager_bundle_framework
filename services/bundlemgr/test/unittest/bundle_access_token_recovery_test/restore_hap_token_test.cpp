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
#include <string>
#include <vector>

#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "appexecfwk_errors.h"
#include "bundle_permission_mgr.h"
#include "inner_bundle_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using namespace OHOS::Security::AccessToken;

namespace {
constexpr uint32_t TEST_RESTORE_TOKEN_ID = 0x53770001;
constexpr int32_t TEST_USERID = 100;
constexpr int32_t TEST_CLONE_APP_INDEX = 2;
const std::string TEST_BUNDLE = "com.test.restore.perms";
const std::string TEST_APP_ID = "com.test.restore.perms_123456";
constexpr int32_t TEST_API_TARGET_VERSION = 12;
const std::string TEST_REQ_PERMISSION_A = "ohos.permission.REQUEST_A";
const std::string TEST_REQ_PERMISSION_B = "ohos.permission.REQUEST_B";
const std::string TEST_REQ_FEATURE_B = "featB";
const std::string TEST_DEF_PERMISSION = "ohos.permission.DEFINE_TEST";
const std::string TEST_DEF_LABEL = "label";
const std::string TEST_ACL_PERMISSION = "ohos.permission.MOCK_ACL";
}  // namespace

class BmsRestoreHapTokenTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        ClearInitHapTokenMockStateForTest();
    }
    void TearDown() override {}

protected:
    // Build a bundle carrying the data the acceptance criteria care about: privilege level,
    // one definePermission, two requestPermissions (one with a requiredFeature) and an acl.
    static InnerBundleInfo MakePermissionRichBundleInfo()
    {
        InnerBundleInfo innerBundleInfo;
        BundleInfo baseInfo;
        baseInfo.name = TEST_BUNDLE;
        baseInfo.appId = TEST_APP_ID;
        innerBundleInfo.SetBaseBundleInfo(baseInfo);
        ApplicationInfo appInfo;
        appInfo.bundleName = TEST_BUNDLE;
        appInfo.apiTargetVersion = TEST_API_TARGET_VERSION;
        innerBundleInfo.SetBaseApplicationInfo(appInfo);
        innerBundleInfo.SetAppPrivilegeLevel(Profile::AVAILABLELEVEL_SYSTEM_BASIC);
        innerBundleInfo.SetAllowedAcls({TEST_ACL_PERMISSION});

        InnerModuleInfo moduleInfo;
        moduleInfo.moduleName = "entry";
        DefinePermission definePermission;
        definePermission.name = TEST_DEF_PERMISSION;
        definePermission.availableLevel = Profile::AVAILABLELEVEL_SYSTEM_BASIC;
        definePermission.label = TEST_DEF_LABEL;
        definePermission.description = "description";
        moduleInfo.definePermissions.push_back(definePermission);
        RequestPermission requestA;
        requestA.name = TEST_REQ_PERMISSION_A;
        moduleInfo.bundlePermissions.AddPermission(requestA);
        RequestPermission requestB;
        requestB.name = TEST_REQ_PERMISSION_B;
        requestB.requiredFeature = TEST_REQ_FEATURE_B;
        moduleInfo.bundlePermissions.AddPermission(requestB);
        std::map<std::string, InnerModuleInfo> moduleInfos;
        moduleInfos["entry"] = moduleInfo;
        innerBundleInfo.AddInnerModuleInfo(moduleInfos);
        return innerBundleInfo;
    }
};

/**
 * @tc.number: BmsRestoreHapTokenTest_0100
 * @tc.name: test RestoreHapToken passes persisted token id with isRestore
 * @tc.desc: 1.RestoreHapToken sets isRestore=true and original tokenID/userID
 */
HWTEST_F(BmsRestoreHapTokenTest, BmsRestoreHapTokenTest_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    AccessTokenIDEx tokenIdeEx;
    tokenIdeEx.tokenIdExStruct.tokenID = TEST_RESTORE_TOKEN_ID;
    HapInfoCheckResult checkResult;

    int32_t ret = BundlePermissionMgr::RestoreHapToken(innerBundleInfo, TEST_USERID,
        tokenIdeEx, checkResult, "{}");
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(GetInitHapTokenCallCountForTest(), 1U);
    HapInfoParams captured = GetInitHapInfoParamsForTest(0);
    EXPECT_TRUE(captured.isRestore);
    EXPECT_EQ(captured.tokenID, TEST_RESTORE_TOKEN_ID);
    EXPECT_EQ(captured.userID, TEST_USERID);
    EXPECT_EQ(captured.instIndex, 0);
    EXPECT_EQ(captured.dlpType, 0);
}

/**
 * @tc.number: BmsRestoreHapTokenTest_0200
 * @tc.name: test RestoreHapToken error passthrough
 * @tc.desc: RestoreHapToken passes through the access token error code without retry
 */
HWTEST_F(BmsRestoreHapTokenTest, BmsRestoreHapTokenTest_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    AccessTokenIDEx tokenIdeEx;
    tokenIdeEx.tokenIdExStruct.tokenID = TEST_RESTORE_TOKEN_ID;
    HapInfoCheckResult checkResult;
    PushInitHapTokenResultForTest(AccessTokenError::ERR_TOKENID_HAS_EXISTED);

    int32_t ret = BundlePermissionMgr::RestoreHapToken(innerBundleInfo, TEST_USERID,
        tokenIdeEx, checkResult, "{}");
    EXPECT_EQ(ret, AccessTokenError::ERR_TOKENID_HAS_EXISTED);
    EXPECT_EQ(GetInitHapTokenCallCountForTest(), 1U);
}

/**
 * @tc.number: BmsRestoreHapTokenTest_0300
 * @tc.name: test RestoreHapToken clone instIndex
 * @tc.desc: RestoreHapToken keeps clone appIndex as instIndex
 */
HWTEST_F(BmsRestoreHapTokenTest, BmsRestoreHapTokenTest_0300, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetAppIndex(TEST_CLONE_APP_INDEX);
    AccessTokenIDEx tokenIdeEx;
    tokenIdeEx.tokenIdExStruct.tokenID = TEST_RESTORE_TOKEN_ID;
    HapInfoCheckResult checkResult;

    int32_t ret = BundlePermissionMgr::RestoreHapToken(innerBundleInfo, TEST_USERID,
        tokenIdeEx, checkResult, "{}");
    EXPECT_EQ(ret, ERR_OK);
    HapInfoParams captured = GetInitHapInfoParamsForTest(0);
    EXPECT_EQ(captured.instIndex, TEST_CLONE_APP_INDEX);
}

/**
 * @tc.number: BmsRestoreHapTokenTest_0400
 * @tc.name: test appServiceCapabilities is passed through to aclExtendedMap
 * @tc.desc: RestoreHapToken forwards the provision capabilities to the policy aclExtendedMap
 */
HWTEST_F(BmsRestoreHapTokenTest, BmsRestoreHapTokenTest_0400, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    AccessTokenIDEx tokenIdeEx;
    tokenIdeEx.tokenIdExStruct.tokenID = TEST_RESTORE_TOKEN_ID;
    HapInfoCheckResult checkResult;

    int32_t ret = BundlePermissionMgr::RestoreHapToken(innerBundleInfo, TEST_USERID,
        tokenIdeEx, checkResult, "{\"location\":\"gps\"}");
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(1U, GetInitHapTokenCallCountForTest());
    HapPolicyParams policy = GetInitHapPolicyParamsForTest(0);
    ASSERT_EQ(1U, policy.aclExtendedMap.size());
    EXPECT_EQ("gps", policy.aclExtendedMap.at("location"));
}

/**
 * @tc.number: BmsRestoreHapTokenTest_0500
 * @tc.name: test empty capabilities degrade to empty aclExtendedMap
 * @tc.desc: empty appServiceCapabilities keeps aclExtendedMap empty (provision lookup failed path)
 */
HWTEST_F(BmsRestoreHapTokenTest, BmsRestoreHapTokenTest_0500, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    AccessTokenIDEx tokenIdeEx;
    tokenIdeEx.tokenIdExStruct.tokenID = TEST_RESTORE_TOKEN_ID;
    HapInfoCheckResult checkResult;

    int32_t ret = BundlePermissionMgr::RestoreHapToken(innerBundleInfo, TEST_USERID,
        tokenIdeEx, checkResult, "");
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(1U, GetInitHapTokenCallCountForTest());
    HapPolicyParams policy = GetInitHapPolicyParamsForTest(0);
    EXPECT_TRUE(policy.aclExtendedMap.empty());
}

/**
 * @tc.number: BmsRestoreHapTokenTest_0600
 * @tc.name: test restored policy keeps the whole permission scope of the bundle
 * @tc.desc: 1.a bundle with apl/definePermission/requestPermissions/acl/appId is restored
 *           2.permStateList covers both requested permissions with the DENIED initial state
 *              (user_grant is not over-granted) and keeps the requiredFeature,
 *              permList keeps the defined permission with its grantMode/level,
 *              acl/appId/apiVersion/apl are forwarded unchanged, isDebugGrant is false
 */
HWTEST_F(BmsRestoreHapTokenTest, BmsRestoreHapTokenTest_0600, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo = MakePermissionRichBundleInfo();
    AccessTokenIDEx tokenIdeEx;
    tokenIdeEx.tokenIdExStruct.tokenID = TEST_RESTORE_TOKEN_ID;
    HapInfoCheckResult checkResult;

    int32_t ret = BundlePermissionMgr::RestoreHapToken(innerBundleInfo, TEST_USERID,
        tokenIdeEx, checkResult, "{}");
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(1U, GetInitHapTokenCallCountForTest());

    HapInfoParams captured = GetInitHapInfoParamsForTest(0);
    EXPECT_TRUE(captured.isRestore);
    EXPECT_EQ(TEST_RESTORE_TOKEN_ID, captured.tokenID);
    EXPECT_EQ(TEST_BUNDLE, captured.bundleName);
    EXPECT_EQ(TEST_USERID, captured.userID);
    EXPECT_EQ(TEST_APP_ID, captured.appIDDesc);
    EXPECT_EQ(TEST_API_TARGET_VERSION, captured.apiVersion);

    HapPolicyParams policy = GetInitHapPolicyParamsForTest(0);
    EXPECT_EQ(ATokenAplEnum::APL_SYSTEM_BASIC, policy.apl);
    EXPECT_FALSE(policy.isDebugGrant);
    ASSERT_EQ(1U, policy.aclRequestedList.size());
    EXPECT_EQ(TEST_ACL_PERMISSION, policy.aclRequestedList[0]);

    ASSERT_EQ(2U, policy.permStateList.size());
    std::map<std::string, PermissionStateFull> statesByName;
    for (const auto &state : policy.permStateList) {
        statesByName[state.permissionName] = state;
    }
    EXPECT_EQ(1U, statesByName.count(TEST_REQ_PERMISSION_A));
    EXPECT_EQ(1U, statesByName.count(TEST_REQ_PERMISSION_B));
    for (const auto &nameAndState : statesByName) {
        EXPECT_TRUE(nameAndState.second.isGeneral);
        ASSERT_EQ(1U, nameAndState.second.grantStatus.size());
        EXPECT_EQ(nameAndState.second.grantStatus[0], AccessToken::PermissionState::PERMISSION_DENIED);
        ASSERT_EQ(1U, nameAndState.second.grantFlags.size());
        EXPECT_EQ(nameAndState.second.grantFlags[0], AccessToken::PermissionFlag::PERMISSION_DEFAULT_FLAG);
        ASSERT_EQ(1U, nameAndState.second.resDeviceID.size());
    }
    EXPECT_EQ(TEST_REQ_FEATURE_B, statesByName[TEST_REQ_PERMISSION_B].feature);

    ASSERT_EQ(1U, policy.permList.size());
    EXPECT_EQ(TEST_DEF_PERMISSION, policy.permList[0].permissionName);
    EXPECT_EQ(TEST_BUNDLE, policy.permList[0].bundleName);
    EXPECT_EQ(policy.permList[0].grantMode, AccessToken::GrantMode::SYSTEM_GRANT);
    EXPECT_EQ(ATokenAplEnum::APL_SYSTEM_BASIC, policy.permList[0].availableLevel);
    EXPECT_EQ(TEST_DEF_LABEL, policy.permList[0].label);
}

/**
 * @tc.number: BmsRestoreHapTokenTest_0700
 * @tc.name: test a bundle without any permission data restores with empty policy lists
 * @tc.desc: 1.a default InnerBundleInfo (no define/request permissions, no acl, no apl)
 *           2.permList/permStateList/aclRequestedList are empty and apl falls back to
 *              APL_NORMAL, so the restore of such an app still succeeds
 */
HWTEST_F(BmsRestoreHapTokenTest, BmsRestoreHapTokenTest_0700, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    AccessTokenIDEx tokenIdeEx;
    tokenIdeEx.tokenIdExStruct.tokenID = TEST_RESTORE_TOKEN_ID;
    HapInfoCheckResult checkResult;

    int32_t ret = BundlePermissionMgr::RestoreHapToken(innerBundleInfo, TEST_USERID,
        tokenIdeEx, checkResult, "{}");
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(1U, GetInitHapTokenCallCountForTest());
    HapPolicyParams policy = GetInitHapPolicyParamsForTest(0);
    EXPECT_TRUE(policy.permList.empty());
    EXPECT_TRUE(policy.permStateList.empty());
    EXPECT_TRUE(policy.aclRequestedList.empty());
    EXPECT_EQ(ATokenAplEnum::APL_NORMAL, policy.apl);
}
