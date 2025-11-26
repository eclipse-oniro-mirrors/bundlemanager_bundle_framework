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
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_quick_fix_callback.h"
#include "permission_define.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {

class BmsBundlePermissionIpcSkeletonTest : public testing::Test {
public:
    BmsBundlePermissionIpcSkeletonTest();
    ~BmsBundlePermissionIpcSkeletonTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundlePermissionIpcSkeletonTest::BmsBundlePermissionIpcSkeletonTest()
{}

BmsBundlePermissionIpcSkeletonTest::~BmsBundlePermissionIpcSkeletonTest()
{}

void BmsBundlePermissionIpcSkeletonTest::SetUpTestCase()
{}

void BmsBundlePermissionIpcSkeletonTest::TearDownTestCase()
{}

void BmsBundlePermissionIpcSkeletonTest::SetUp()
{}

void BmsBundlePermissionIpcSkeletonTest::TearDown()
{}

/**
 * @tc.number: BmsBundlePermissionIpcSkeletonTest_0100
 * @tc.name: test VerifyAcrossUserPermission of BundlePermissionMgr
 * @tc.desc: 1. VerifyAcrossUserPermission true by UserId is 100
 */
HWTEST_F(BmsBundlePermissionIpcSkeletonTest, BmsBundlePermissionIpcSkeletonTest_0100, Function | SmallTest | Level0)
{
    int32_t userId = 100;
    bool ret = BundlePermissionMgr::VerifyAcrossUserPermission(userId);
    EXPECT_EQ(ret, true);
}


/**
 * @tc.number: BmsBundlePermissionIpcSkeletonTest_0200
 * @tc.name: test VerifyAcrossUserPermission of BundlePermissionMgr
 * @tc.desc: 1. VerifyAcrossUserPermission true by PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS
 */
HWTEST_F(BmsBundlePermissionIpcSkeletonTest, BmsBundlePermissionIpcSkeletonTest_0200, Function | SmallTest | Level0)
{
    int32_t userId = 101;
    bool ret = BundlePermissionMgr::VerifyAcrossUserPermission(userId);
    EXPECT_EQ(ret, true);
}
} // OHOS