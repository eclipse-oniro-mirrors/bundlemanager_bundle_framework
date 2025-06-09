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
#include "bundle_mgr_host_impl.h"
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

/**
 * @tc.number: BundleMgrHostImpl_0001
 * @tc.name: BundleMgrHostImpl_0001
 * @tc.desc: test DumpInfos
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BundleMgrHostImpl_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    DumpFlag flag = DumpFlag::DUMP_DEBUG_BUNDLE_LIST;
    std::string bundleName;
    int32_t userId = 100;
    std::string result;
    bool ret = localBundleMgrHostImpl->DumpInfos(flag, bundleName, userId, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0002
 * @tc.name: BundleMgrHostImpl_0002
 * @tc.desc: test DumpInfos
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BundleMgrHostImpl_0002, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    DumpFlag flag = DumpFlag::DUMP_BUNDLE_LABEL;
    std::string bundleName;
    int32_t userId = 100;
    std::string result;
    bool ret = localBundleMgrHostImpl->DumpInfos(flag, bundleName, userId, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0003
 * @tc.name: BundleMgrHostImpl_0003
 * @tc.desc: test DumpInfos
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BundleMgrHostImpl_0003, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    DumpFlag flag = DumpFlag::DUMP_LABEL_LIST;
    std::string bundleName;
    int32_t userId = 9999;
    std::string result;
    bool ret = localBundleMgrHostImpl->DumpInfos(flag, bundleName, userId, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0004
 * @tc.name: BundleMgrHostImpl_0004
 * @tc.desc: test DumpInfos
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BundleMgrHostImpl_0004, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    DumpFlag flag = static_cast<DumpFlag>(9999);
    std::string bundleName;
    int32_t userId = 9999;
    std::string result;
    bool ret = localBundleMgrHostImpl->DumpInfos(flag, bundleName, userId, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0005
 * @tc.name: BundleMgrHostImpl_0005
 * @tc.desc: test DumpDebugBundleInfoNames
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BundleMgrHostImpl_0005, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    int32_t userId = Constants::ALL_USERID;
    std::string result;
    bool ret = localBundleMgrHostImpl->DumpDebugBundleInfoNames(userId, result);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundleMgrHostImpl_0006
 * @tc.name: BundleMgrHostImpl_0006
 * @tc.desc: test DumpDebugBundleInfoNames
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BundleMgrHostImpl_0006, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    int32_t userId = 100;
    std::string result;
    bool ret = localBundleMgrHostImpl->DumpDebugBundleInfoNames(userId, result);

    userId = 9999;
    ret = localBundleMgrHostImpl->DumpDebugBundleInfoNames(userId, result);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleMgrHostImpl_0007
 * @tc.name: BundleMgrHostImpl_0007
 * @tc.desc: test GetBundleStats
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BundleMgrHostImpl_0007, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    std::string bundleName;
    int32_t userId = 100;
    std::vector<int64_t> bundleStats;
    bool ret = localBundleMgrHostImpl->GetBundleStats(bundleName, userId, bundleStats);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleMgrHostImpl_0008
 * @tc.name: BundleMgrHostImpl_0008
 * @tc.desc: test GetBundleStats
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BundleMgrHostImpl_0008, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    int32_t userId = 100;
    std::vector<int64_t> bundleStats;
    bool ret = localBundleMgrHostImpl->GetAllBundleStats(userId, bundleStats);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleMgrHostImpl_0009
 * @tc.name: BundleMgrHostImpl_0009
 * @tc.desc: test GetBundleStats
 */
HWTEST_F(BmsBundlePermissionGetRequestTest, BundleMgrHostImpl_0009, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    std::string bundleName;
    int32_t userId = 100;
    std::vector<Metadata> provisionMetadatas;
    bool ret = localBundleMgrHostImpl->GetProvisionMetadata(bundleName, userId, provisionMetadatas);
    EXPECT_TRUE(ret);
}
} // OHOS
