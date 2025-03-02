/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hilog_tag_wrapper.h"
#define private public
#include "bundle_app_spawn_client.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string TEST_BUNDLE_NAME = "bundleName";
}

class BmsBundleAppSpawnClientTest : public testing::Test {
public:
    BmsBundleAppSpawnClientTest();
    ~BmsBundleAppSpawnClientTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    AppSpawnRemoveSandboxDirMsg createRemoveSandboxDirMsg(const std::string& bundleName, int32_t bundleIndex,
        int32_t uid, int32_t flagIndex);
};

BmsBundleAppSpawnClientTest::BmsBundleAppSpawnClientTest()
{}

BmsBundleAppSpawnClientTest::~BmsBundleAppSpawnClientTest()
{}

void BmsBundleAppSpawnClientTest::SetUpTestCase()
{}

void BmsBundleAppSpawnClientTest::TearDownTestCase()
{}

void BmsBundleAppSpawnClientTest::SetUp()
{}

void BmsBundleAppSpawnClientTest::TearDown()
{}

AppSpawnRemoveSandboxDirMsg BmsBundleAppSpawnClientTest::createRemoveSandboxDirMsg(const std::string& bundleName,
    int32_t bundleIndex, int32_t uid, int32_t flagIndex)
{
    AppSpawnRemoveSandboxDirMsg removeSandboxDirMsg;
    removeSandboxDirMsg.code = MSG_UNINSTALL_DEBUG_HAP;
    removeSandboxDirMsg.bundleName = bundleName;
    removeSandboxDirMsg.bundleIndex = bundleIndex;
    removeSandboxDirMsg.uid = uid;
    removeSandboxDirMsg.flags = static_cast<AppFlagsIndex>(flagIndex);
    return removeSandboxDirMsg;
}

/**
 * @tc.name: OpenConnection_001
 * @tc.desc: test OpenConnection
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleAppSpawnClientTest, OpenConnection_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "OpenConnection_001 start");
    auto ret = BundleAppSpawnClient::GetInstance().OpenConnection();
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "OpenConnection_001 end");
}

/**
 * @tc.name: AppspawnCreateDefaultMsg_001
 * @tc.desc: test AppspawnCreateDefaultMsg
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleAppSpawnClientTest, AppspawnCreateDefaultMsg_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "AppspawnCreateDefaultMsg_001 start");
    int32_t flagIndex = 0;
    int32_t bundleIndex = 0;
    int32_t uid = 1001;
    AppSpawnRemoveSandboxDirMsg removeSandboxDirMsg = createRemoveSandboxDirMsg(TEST_BUNDLE_NAME, bundleIndex,
        uid, flagIndex);
    int32_t ret = 0;
    AppSpawnReqMsgHandle reqHandle = nullptr;
    ret = BundleAppSpawnClient::GetInstance().OpenConnection();
    EXPECT_EQ(ret, ERR_OK);
    bool result = false;
    result = BundleAppSpawnClient::GetInstance().VerifyMsg(removeSandboxDirMsg);
    EXPECT_EQ(result, true);
    ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(removeSandboxDirMsg.code),
        removeSandboxDirMsg.bundleName.c_str(), &reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    ret = BundleAppSpawnClient::GetInstance().AppspawnCreateDefaultMsg(removeSandboxDirMsg, reqHandle);
    EXPECT_EQ(ret, ERR_OK);
    AppSpawnReqMsgFree(reqHandle);
    TAG_LOGI(AAFwkTag::TEST, "AppspawnCreateDefaultMsg_001 end");
}

/**
 * @tc.name: VerifyMsg_001
 * @tc.desc: test VerifyMsg
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleAppSpawnClientTest, VerifyMsg_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "VerifyMsg_001 start");
    int32_t flagIndex = 0;
    int32_t bundleIndex = 0;
    int32_t uid = 1001;
    AppSpawnRemoveSandboxDirMsg removeSandboxDirMsg = createRemoveSandboxDirMsg(TEST_BUNDLE_NAME, bundleIndex,
        uid, flagIndex);
    bool result = false;
    result = BundleAppSpawnClient::GetInstance().VerifyMsg(removeSandboxDirMsg);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "VerifyMsg_001 end");
}

/**
 * @tc.name: VerifyMsg_002
 * @tc.desc: test VerifyMsg
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleAppSpawnClientTest, VerifyMsg_002, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "VerifyMsg_002 start");
    int32_t flagIndex = 0;
    int32_t bundleIndex = 0;
    int32_t uid = -1;
    AppSpawnRemoveSandboxDirMsg removeSandboxDirMsg = createRemoveSandboxDirMsg(TEST_BUNDLE_NAME, bundleIndex,
        uid, flagIndex);
    bool result = false;
    result = BundleAppSpawnClient::GetInstance().VerifyMsg(removeSandboxDirMsg);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "VerifyMsg_002 end");
}

/**
 * @tc.name: VerifyMsg_003
 * @tc.desc: test VerifyMsg
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleAppSpawnClientTest, VerifyMsg_003, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "VerifyMsg_003 start");
    std::string bundleName("");
    int32_t flagIndex = 0;
    int32_t bundleIndex = 0;
    int32_t uid = 1001;
    AppSpawnRemoveSandboxDirMsg removeSandboxDirMsg = createRemoveSandboxDirMsg(bundleName, bundleIndex,
        uid, flagIndex);
    bool result = false;
    result = BundleAppSpawnClient::GetInstance().VerifyMsg(removeSandboxDirMsg);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "VerifyMsg_003 end");
}

/**
 * @tc.name: VerifyMsg_004
 * @tc.desc: test VerifyMsg
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleAppSpawnClientTest, VerifyMsg_004, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "VerifyMsg_004 start");
    int32_t flagIndex = 0;
    int32_t bundleIndex = -1;
    int32_t uid = 1001;
    AppSpawnRemoveSandboxDirMsg removeSandboxDirMsg = createRemoveSandboxDirMsg(TEST_BUNDLE_NAME, bundleIndex,
        uid, flagIndex);
    bool result = false;
    result = BundleAppSpawnClient::GetInstance().VerifyMsg(removeSandboxDirMsg);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "VerifyMsg_004 end");
}

/**
 * @tc.name: RemoveSandboxDir_001
 * @tc.desc: test RemoveSandboxDir
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleAppSpawnClientTest, RemoveSandboxDir_001, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "RemoveSandboxDir_001 start");
    int32_t flagIndex = 0;
    int32_t bundleIndex = 0;
    int32_t uid = 1001;
    AppSpawnRemoveSandboxDirMsg removeSandboxDirMsg = createRemoveSandboxDirMsg(TEST_BUNDLE_NAME, bundleIndex,
        uid, flagIndex);
    int32_t ret = 0;
    ret = BundleAppSpawnClient::GetInstance().RemoveSandboxDir(removeSandboxDirMsg);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "RemoveSandboxDir_001 end");
}

/**
 * @tc.name: RemoveSandboxDir_002
 * @tc.desc: test RemoveSandboxDir
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleAppSpawnClientTest, RemoveSandboxDir_002, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "RemoveSandboxDir_002 start");
    int32_t flagIndex = 0;
    int32_t bundleIndex = -1;
    int32_t uid = 1001;
    AppSpawnRemoveSandboxDirMsg removeSandboxDirMsg = createRemoveSandboxDirMsg(TEST_BUNDLE_NAME, bundleIndex,
        uid, flagIndex);
    int32_t ret = 0;
    ret = BundleAppSpawnClient::GetInstance().RemoveSandboxDir(removeSandboxDirMsg);
    EXPECT_NE(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "RemoveSandboxDir_002 end");
}
} // OHOS