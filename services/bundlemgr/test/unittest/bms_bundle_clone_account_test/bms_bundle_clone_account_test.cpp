/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <fstream>
#include <gtest/gtest.h>

#include "ability_info.h"
#include "access_token.h"
#include "application_info.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "clone_for_account_util.h"
#include "inner_bundle_clone_info.h"
#include "inner_bundle_user_info.h"
#include "inner_bundle_info.h"
#include "json_constants.h"
#include "json_serializer.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::JsonConstants;
namespace OHOS {
class BmsBundleCloneAccountTest : public testing::Test {
public:
    BmsBundleCloneAccountTest();
    ~BmsBundleCloneAccountTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleCloneAccountTest::BmsBundleCloneAccountTest()
{}

BmsBundleCloneAccountTest::~BmsBundleCloneAccountTest()
{}

void BmsBundleCloneAccountTest::SetUpTestCase()
{}

void BmsBundleCloneAccountTest::TearDownTestCase()
{}

void BmsBundleCloneAccountTest::SetUp()
{}

void BmsBundleCloneAccountTest::TearDown()
{}

/**
 * @tc.number: GetEnabledCloneAppIndex_0001
 * @tc.name: GetEnabledCloneAppIndex returns ALL_CLONE_APP_INDEX when state is invalid or disabled
 * @tc.desc: 1.system running normally
 *           2.INVALID_USERID, no user info, main app disabled with no clone, or all clones disabled
 *             return ALL_CLONE_APP_INDEX; main app enabled returns MAIN_APP_INDEX
 */
HWTEST_F(BmsBundleCloneAccountTest, GetEnabledCloneAppIndex_0001, Function | SmallTest | Level1)
{
    int32_t userId = 1001;
    InnerBundleInfo innerBundleInfo;

    // 1. INVALID_USERID returns ALL_CLONE_APP_INDEX
    int32_t result = CloneForAccountUtil::GetEnabledCloneAppIndex(innerBundleInfo,
        Constants::INVALID_USERID);
    EXPECT_EQ(result, Constants::ALL_CLONE_APP_INDEX);

    // 2. No user info for the given userId returns ALL_CLONE_APP_INDEX
    result = CloneForAccountUtil::GetEnabledCloneAppIndex(innerBundleInfo, userId);
    EXPECT_EQ(result, Constants::ALL_CLONE_APP_INDEX);

    // 3. Main app enabled returns MAIN_APP_INDEX
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = userId;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    result = CloneForAccountUtil::GetEnabledCloneAppIndex(innerBundleInfo, userId);
    EXPECT_EQ(result, Constants::MAIN_APP_INDEX);

    // 4. Main app disabled and no clones returns ALL_CLONE_APP_INDEX
    ErrCode ret = innerBundleInfo.SetApplicationEnabled(false, "test", userId);
    EXPECT_EQ(ret, ERR_OK);
    result = CloneForAccountUtil::GetEnabledCloneAppIndex(innerBundleInfo, userId);
    EXPECT_EQ(result, Constants::ALL_CLONE_APP_INDEX);

    // 5. All clones disabled returns ALL_CLONE_APP_INDEX
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.userId = userId;
    cloneInfo.appIndex = 1;
    cloneInfo.enabled = true;
    ret = innerBundleInfo.AddCloneBundle(cloneInfo);
    EXPECT_EQ(ret, ERR_OK);
    ret = innerBundleInfo.SetCloneApplicationEnabled(false, 1, "test", userId);
    EXPECT_EQ(ret, ERR_OK);
    result = CloneForAccountUtil::GetEnabledCloneAppIndex(innerBundleInfo, userId);
    EXPECT_EQ(result, Constants::ALL_CLONE_APP_INDEX);
}

/**
 * @tc.number: GetEnabledCloneAppIndex_0002
 * @tc.name: GetEnabledCloneAppIndex returns the enabled clone appIndex when main app is disabled
 * @tc.desc: 1.system running normally
 *           2.main app disabled and one enabled clone exists should return that clone's appIndex
 */
HWTEST_F(BmsBundleCloneAccountTest, GetEnabledCloneAppIndex_0002, Function | SmallTest | Level1)
{
    int32_t userId = 1001;
    int32_t appIndex = 1;
    InnerBundleInfo innerBundleInfo;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = userId;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    ErrCode ret = innerBundleInfo.SetApplicationEnabled(false, "test", userId);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleCloneInfo cloneInfo;
    cloneInfo.userId = userId;
    cloneInfo.appIndex = appIndex;
    cloneInfo.enabled = true;
    ret = innerBundleInfo.AddCloneBundle(cloneInfo);
    EXPECT_EQ(ret, ERR_OK);
    // AddCloneBundle copies enabled from userInfo.bundleUserInfo.enabled,
    // so re-enable the clone explicitly
    ret = innerBundleInfo.SetCloneApplicationEnabled(true, appIndex, "test", userId);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = CloneForAccountUtil::GetEnabledCloneAppIndex(innerBundleInfo, userId);
    EXPECT_EQ(result, appIndex);
}

/**
 * @tc.number: GetEnabledCloneAppIndex_0003
 * @tc.name: GetEnabledCloneAppIndex returns the first enabled clone with multiple clones
 * @tc.desc: 1.system running normally
 *           2.multiple clones exist, first one enabled should return its appIndex
 */
HWTEST_F(BmsBundleCloneAccountTest, GetEnabledCloneAppIndex_0003, Function | SmallTest | Level1)
{
    int32_t userId = 1001;
    InnerBundleInfo innerBundleInfo;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = userId;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    ErrCode ret = innerBundleInfo.SetApplicationEnabled(false, "test", userId);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleCloneInfo cloneInfo1;
    cloneInfo1.userId = userId;
    cloneInfo1.appIndex = 1;
    cloneInfo1.enabled = true;
    ret = innerBundleInfo.AddCloneBundle(cloneInfo1);
    EXPECT_EQ(ret, ERR_OK);
    // re-enable clone explicitly (AddCloneBundle copies from disabled main app)
    ret = innerBundleInfo.SetCloneApplicationEnabled(true, 1, "test", userId);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleCloneInfo cloneInfo2;
    cloneInfo2.userId = userId;
    cloneInfo2.appIndex = 2;
    cloneInfo2.enabled = true;
    ret = innerBundleInfo.AddCloneBundle(cloneInfo2);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = CloneForAccountUtil::GetEnabledCloneAppIndex(innerBundleInfo, userId);
    EXPECT_EQ(result, 1);
}

/**
 * @tc.number: GetEnabledCloneAppIndex_0004
 * @tc.name: GetEnabledCloneAppIndex skips disabled clones and returns the first enabled one
 * @tc.desc: 1.system running normally
 *           2.first clone disabled, second clone enabled should return second's appIndex
 */
HWTEST_F(BmsBundleCloneAccountTest, GetEnabledCloneAppIndex_0004, Function | SmallTest | Level1)
{
    int32_t userId = 1001;
    InnerBundleInfo innerBundleInfo;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = userId;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    ErrCode ret = innerBundleInfo.SetApplicationEnabled(false, "test", userId);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleCloneInfo cloneInfo1;
    cloneInfo1.userId = userId;
    cloneInfo1.appIndex = 1;
    cloneInfo1.enabled = true;
    ret = innerBundleInfo.AddCloneBundle(cloneInfo1);
    EXPECT_EQ(ret, ERR_OK);
    // re-enable clone1 explicitly (AddCloneBundle copies from disabled main app)
    ret = innerBundleInfo.SetCloneApplicationEnabled(true, 1, "test", userId);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleCloneInfo cloneInfo2;
    cloneInfo2.userId = userId;
    cloneInfo2.appIndex = 2;
    cloneInfo2.enabled = true;
    ret = innerBundleInfo.AddCloneBundle(cloneInfo2);
    EXPECT_EQ(ret, ERR_OK);
    // re-enable clone2 explicitly
    ret = innerBundleInfo.SetCloneApplicationEnabled(true, 2, "test", userId);
    EXPECT_EQ(ret, ERR_OK);

    ret = innerBundleInfo.SetCloneApplicationEnabled(false, 1, "test", userId);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = CloneForAccountUtil::GetEnabledCloneAppIndex(innerBundleInfo, userId);
    EXPECT_EQ(result, 2);
}
} // OHOS