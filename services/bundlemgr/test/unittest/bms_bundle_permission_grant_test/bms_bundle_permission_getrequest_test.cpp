/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string PERMISSION_NAME = "testName";
const std::string ERR_PERMISSION_NAME = "permission_name";
const std::string DEVICE_ID = "100";
const std::string ERR_DEVICE_ID = "101";
}  // namespace

class BmsBundlePermissionGetRequestTest : public testing::Test {
public:
    BmsBundlePermissionGetRequestTest();
    ~BmsBundlePermissionGetRequestTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundlePermissionGetRequestTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundlePermissionGetRequestTest::BmsBundlePermissionGetRequestTest()
{}

BmsBundlePermissionGetRequestTest::~BmsBundlePermissionGetRequestTest()
{}

void BmsBundlePermissionGetRequestTest::SetUpTestCase()
{}

void BmsBundlePermissionGetRequestTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundlePermissionGetRequestTest::SetUp()
{}

void BmsBundlePermissionGetRequestTest::TearDown()
{}

/**
 * @tc.number: BmsBundlePermissionGetRequestTest
 * Function: GetRequestPermissionStates
 * @tc.name: test GetRequestPermissionStates success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BmsBundlePermissionGetRequestTest_0300, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    BundleInfo bundleInfo;
    bundleInfo.reqPermissions.push_back(PERMISSION_NAME);
    uint32_t tokenId = 1;
    res = BundlePermissionMgr::GetRequestPermissionStates(bundleInfo, tokenId, DEVICE_ID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundlePermissionGetRequestTest
 * Function: GetRequestPermissionStates
 * @tc.name: test GetRequestPermissionStates success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BmsBundlePermissionGetRequestTest_0400, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    BundleInfo bundleInfo;
    bundleInfo.reqPermissions.push_back(ERR_PERMISSION_NAME);
    uint32_t tokenId = 1;
    res = BundlePermissionMgr::GetRequestPermissionStates(bundleInfo, tokenId, DEVICE_ID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundlePermissionGetRequestTest
 * Function: GetRequestPermissionStates
 * @tc.name: test GetRequestPermissionStates success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BmsBundlePermissionGetRequestTest_0500, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    BundleInfo bundleInfo;
    bundleInfo.reqPermissions.push_back(PERMISSION_NAME);
    uint32_t tokenId = 1;
    res = BundlePermissionMgr::GetRequestPermissionStates(bundleInfo, tokenId, ERR_DEVICE_ID);
    EXPECT_EQ(res, true);
}
} // OHOS