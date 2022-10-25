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

#define private public

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "bundle_verify_mgr.h"
#include "inner_app_quick_fix.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "json_constants.h"
#include "mock_quick_fix_callback.h"
#include "mock_status_receiver.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string INSTALL_PATH = "/data/test/resource/bms/install_bundle/first_right.hap";
} // namespace
class BmsBundleHapVerifyTest : public testing::Test {
public:
    BmsBundleHapVerifyTest();
    ~BmsBundleHapVerifyTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleHapVerifyTest::BmsBundleHapVerifyTest()
{}

BmsBundleHapVerifyTest::~BmsBundleHapVerifyTest()
{}

void BmsBundleHapVerifyTest::SetUpTestCase()
{}

void BmsBundleHapVerifyTest::TearDownTestCase()
{}

void BmsBundleHapVerifyTest::SetUp()
{
}

void BmsBundleHapVerifyTest::TearDown()
{}

/**
 * @tc.number: BmsGetVersion_0100
 * Function: GetVersion
 * @tc.name: test GetVersion
 * @tc.desc: GetVersion
 */
HWTEST_F(BmsBundleHapVerifyTest, BmsGetVersion_0100, Function | SmallTest | Level0)
{
    Security::Verify::HapVerifyResult hapVerifyResult;
    auto ret = hapVerifyResult.GetVersion();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: BmsGetProperty_0100
 * Function: GetProperty
 * @tc.name: test GetProperty
 * @tc.desc: GetProperty
 */
HWTEST_F(BmsBundleHapVerifyTest, BmsGetProperty_0100, Function | SmallTest | Level0)
{
    Security::Verify::HapVerifyResult hapVerifyResult;
    std::string property;
    auto ret = hapVerifyResult.GetProperty(property);
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.number: BmsGetPublicKey_0100
 * Function: GetPublicKey
 * @tc.name: test GetPublicKey
 * @tc.desc: GetPublicKey
 */
HWTEST_F(BmsBundleHapVerifyTest, BmsGetPublicKey_0100, Function | SmallTest | Level0)
{
    Security::Verify::HapVerifyResult hapVerifyResult;
    auto ret = hapVerifyResult.GetPublicKey();
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.number: BmsGetSignature_0100
 * Function: GetSignature
 * @tc.name: test GetSignature
 * @tc.desc: GetSignature
 */
HWTEST_F(BmsBundleHapVerifyTest, BmsGetSignature_0100, Function | SmallTest | Level0)
{
    Security::Verify::HapVerifyResult hapVerifyResult;
    auto ret = hapVerifyResult.GetSignature();
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.number: BmsCopyPartialBuffer_0100
 * Function: CopyPartialBuffer
 * @tc.name: test CopyPartialBuffer
 * @tc.desc: CopyPartialBuffer
 */
HWTEST_F(BmsBundleHapVerifyTest, BmsCopyPartialBuffer_0100, Function | SmallTest | Level0)
{
    constexpr int TEST_HAPBYTEBUFFER_LENGTH = 15;
    constexpr int TEST_HAPBYTEBUFFER_LENGTH_2 = 8;
    constexpr int TEST_HAPBYTEBUFFER_INT32_DATA = 0xffffffff;
    constexpr int TEST_HAPBYTEBUFFER_INT32_DATA_2 = 100000;
    constexpr int TEST_HAPBYTEBUFFER_POSITION = 10;
    Security::Verify::HapByteBuffer hapByteBuffer(TEST_HAPBYTEBUFFER_LENGTH);
    hapByteBuffer.PutInt32(0, TEST_HAPBYTEBUFFER_INT32_DATA);
    hapByteBuffer.PutInt32(sizeof(int), TEST_HAPBYTEBUFFER_INT32_DATA_2);
    Security::Verify::HapByteBuffer hapByteBuffer2(TEST_HAPBYTEBUFFER_LENGTH);
    hapByteBuffer.SetPosition(TEST_HAPBYTEBUFFER_POSITION);
    EXPECT_FALSE(hapByteBuffer2.CopyPartialBuffer(hapByteBuffer, TEST_HAPBYTEBUFFER_LENGTH_2));
    hapByteBuffer.Clear();
    hapByteBuffer2.CopyPartialBuffer(hapByteBuffer, TEST_HAPBYTEBUFFER_LENGTH_2);
    int target1;
    EXPECT_TRUE(hapByteBuffer2.GetInt32(target1));
    EXPECT_EQ(target1, TEST_HAPBYTEBUFFER_INT32_DATA);
    int target2;
    EXPECT_TRUE(hapByteBuffer2.GetInt32(target2));
    EXPECT_EQ(target2, TEST_HAPBYTEBUFFER_INT32_DATA_2);
}

/**
 * @tc.number: EnableDebug_0100
 * Function: enableDebug
 * @tc.name: test enableDebug
 * @tc.desc: enableDebug
 */
HWTEST_F(BmsBundleHapVerifyTest, EnableDebug_0100, Function | SmallTest | Level0)
{
    BundleVerifyMgr::EnableDebug();
    EXPECT_TRUE(BundleVerifyMgr::isDebug_);
}

/**
 * @tc.number: DisableDebug_0100
 * Function: DisableDebug
 * @tc.name: test DisableDebug
 * @tc.desc: DisableDebug
 */
HWTEST_F(BmsBundleHapVerifyTest, DisableDebug_0100, Function | SmallTest | Level0)
{
    BundleVerifyMgr::DisableDebug();
    EXPECT_FALSE(BundleVerifyMgr::isDebug_);
}

/**
 * @tc.number: ParseHapProfile_0100
 * Function: ParseHapProfile
 * @tc.name: test ParseHapProfile
 * @tc.desc: ParseHapProfile
 */
HWTEST_F(BmsBundleHapVerifyTest, ParseHapProfile_0100, Function | SmallTest | Level0)
{
    Security::Verify::HapVerifyResult result;
    auto res = BundleVerifyMgr::ParseHapProfile(INSTALL_PATH, result);
    EXPECT_EQ(res, ERR_OK);
}
} // OHOS