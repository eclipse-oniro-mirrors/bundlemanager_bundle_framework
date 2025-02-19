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

#define private public

#include <gtest/gtest.h>

#include <fstream>

#include "ability_manager_helper.h"
#include "app_log_wrapper.h"
#include "bms_extension_client.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "status_receiver_proxy.h"
#include "installd/installd_permission_mgr.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::DelayedSingleton;

namespace OHOS {
class BmsServiceStartupEmulatorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsServiceStartupEmulatorTest::SetUpTestCase()
{}

void BmsServiceStartupEmulatorTest::TearDownTestCase()
{}

void BmsServiceStartupEmulatorTest::SetUp()
{}

void BmsServiceStartupEmulatorTest::TearDown()
{}

/**
 * @tc.number: EmulatorBundlePermissionMgrInitHapToken_001
 * @tc.name: test InitHapToken
 * @tc.desc: 1.test InitHapToken of BundlePermissionMgr in Emulator
 */
#ifdef X86_EMULATOR_MODE
HWTEST_F(BmsServiceStartupEmulatorTest, EmulatorBundlePermissionMgrInitHapToken_001, Function | SmallTest | Level1)
{
    bool ret = BundlePermissionMgr::Init();
    InnerBundleInfo innerBundleInfo;
    int32_t userId = 0;
    int32_t dlpType = 0;
    Security::AccessToken::AccessTokenIDEx tokenIdeEx;
    Security::AccessToken::HapInfoCheckResult checkResult;

    ret = BundlePermissionMgr::InitHapToken(innerBundleInfo, userId, dlpType, tokenIdeEx, checkResult);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number: EmulatorBundlePermissionMgrUpdateHapToken_002
 * @tc.name: test UpdateHapToken
 * @tc.desc: 1.test UpdateHapToken of BundlePermissionMgr in Emulator
 */
HWTEST_F(BmsServiceStartupEmulatorTest, EmulatorBundlePermissionMgrUpdateHapToken_002, Function | SmallTest | Level1)
{
    bool ret = BundlePermissionMgr::Init();
    InnerBundleInfo innerBundleInfo;
    int32_t userId = 0;
    Security::AccessToken::AccessTokenIDEx tokenIdeEx;
    Security::AccessToken::HapInfoCheckResult checkResult;
    ret = BundlePermissionMgr::UpdateHapToken(tokenIdeEx, innerBundleInfo, userId, checkResult);
    EXPECT_NE(ret, 0);
}
#endif // X86_EMULATOR_MODE
} // OHOS
