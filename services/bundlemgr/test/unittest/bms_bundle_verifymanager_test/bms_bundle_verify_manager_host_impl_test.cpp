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
#define private public

#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

#include "bundle_mgr_service.h"
#include "mock_installd_proxy.h"
#include "mock_ipc_skeleton.h"
#include "verify_manager_host_impl.h"
#include "verify_util.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string FILE_PATH = "/data/app/el2/base/a.abc";
    const std::string INVALID_PATH = "/data/service/el1/public/bms/bundle_manager_service/../../a.abc";
    const std::string INVALID_SUFFIX = "/data/app/el2/base/a.so";
    const std::string ABC_FILE = "a.abc";
    const std::string ERR_FILE_PATH = "data";
    const std::string BUNDLE_NAME = "com.ohos.launcher";
    const std::string TEST_BUNDLE_NAME = "com.ohos.test.bundle";
    const std::string EMPTY_STRING = "";
    const int32_t USERID = 100;
    const std::string DATA_STORAGE_EL1_BUNDLE_ONE = "/data/storage/el1/bundle/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_EL1 =
        "/data/app/el1/100/base/com.ohos.launcher/testdir1/testdir2/test.abc";
}  // namespace

class BmsBundleVerifyManagerHostImplTest : public testing::Test {
public:
    BmsBundleVerifyManagerHostImplTest();
    ~BmsBundleVerifyManagerHostImplTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void SetBundleDataMgr();
    void SetDataMgrData();

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleVerifyManagerHostImplTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleVerifyManagerHostImplTest::BmsBundleVerifyManagerHostImplTest()
{}

BmsBundleVerifyManagerHostImplTest::~BmsBundleVerifyManagerHostImplTest()
{}

void BmsBundleVerifyManagerHostImplTest::SetUpTestCase()
{}

void BmsBundleVerifyManagerHostImplTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleVerifyManagerHostImplTest::SetUp()
{}

void BmsBundleVerifyManagerHostImplTest::TearDown()
{}

void BmsBundleVerifyManagerHostImplTest::SetBundleDataMgr()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<AppExecFwk::BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
}

void BmsBundleVerifyManagerHostImplTest::SetDataMgrData()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = dataMgr->GetUserIdByUid(callingUid);
    int32_t bundleId = callingUid - userId * Constants::BASE_USER_RANGE;
    dataMgr->bundleIdMap_.insert({bundleId, TEST_BUNDLE_NAME});
    InnerBundleInfo bundleInfo;
    bundleInfo.baseApplicationInfo_->bundleName = TEST_BUNDLE_NAME;

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = callingUid;
    std::string userKey = TEST_BUNDLE_NAME + Constants::FILE_UNDERLINE + std::to_string(userId);
    bundleInfo.innerBundleUserInfos_.insert({userKey, innerBundleUserInfo});
    dataMgr->bundleInfos_.insert({TEST_BUNDLE_NAME, bundleInfo});
}

/**
 * @tc.number: VerifyTest_0100
 * @tc.name: test Verify
 * @tc.desc: 1.Verify test
 */
HWTEST_F(BmsBundleVerifyManagerHostImplTest, VerifyTest_0100, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    SetBundleDataMgr();
    SetDataMgrData();
    
    int32_t funcResult = 0;
    impl.Verify(abcPaths, funcResult);
    EXPECT_EQ(funcResult, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);

    abcPaths.push_back(FILE_PATH);
    impl.Verify(abcPaths, funcResult);
    EXPECT_EQ(funcResult, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);

    abcPaths.push_back(ERR_FILE_PATH);
    abcPaths.push_back(EMPTY_STRING);
    impl.Verify(abcPaths, funcResult);
    EXPECT_EQ(funcResult, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);
}


/**
 * @tc.number: InnerVerify
 * @tc.name: test InnerVerify
 * @tc.desc: 1.InnerVerify test
 */
HWTEST_F(BmsBundleVerifyManagerHostImplTest, VerifyTest_0200, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    abcPaths.push_back(FILE_PATH);
    ErrCode funcResult = impl.InnerVerify(TEST_BUNDLE_NAME, abcPaths);
    EXPECT_EQ(funcResult, ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED);
}

/**
 * @tc.number: InnerVerify
 * @tc.name: test InnerVerify
 * @tc.desc: 1.InnerVerify test
 */
HWTEST_F(BmsBundleVerifyManagerHostImplTest, VerifyTest_0300, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    abcPaths.push_back(FILE_PATH);
    bool funcResult = impl.VerifyAbc(abcPaths);
    EXPECT_FALSE(funcResult);
}

/**
 * @tc.number: VerifyTest_0400
 * @tc.name: test Verify
 * @tc.desc: 1.Verify test
 */
HWTEST_F(BmsBundleVerifyManagerHostImplTest, VerifyTest_0400, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    SetBundleDataMgr();
    SetDataMgrData();

    int32_t funcResult = 0;
    abcPaths.push_back(DATA_STORAGE_EL1_BUNDLE_ONE);
    impl.Verify(abcPaths, funcResult);
    EXPECT_EQ(funcResult, ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED);
}

/**
 * @tc.number: VerifyTest_0500
 * @tc.name: test MoveAbc
 * @tc.desc: 1.MoveAbc test
 */
HWTEST_F(BmsBundleVerifyManagerHostImplTest, VerifyTest_0500, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    SetBundleDataMgr();
    abcPaths.push_back(DATA_STORAGE_EL1_BUNDLE_ONE);
    bool funcResult = impl.MoveAbc(TEST_BUNDLE_NAME, abcPaths);
    EXPECT_TRUE(funcResult);
}

/**
 * @tc.number: VerifyTest_0600
 * @tc.name: test DeleteAbc
 * @tc.desc: 1.DeleteAbc test
 */
HWTEST_F(BmsBundleVerifyManagerHostImplTest, VerifyTest_0600, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    SetBundleDataMgr();

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = dataMgr->GetUserIdByUid(callingUid);
    int32_t bundleId = callingUid - userId * Constants::BASE_USER_RANGE;
    dataMgr->bundleIdMap_.insert({bundleId, TEST_BUNDLE_NAME});
    InnerBundleInfo bundleInfo;
    bundleInfo.baseApplicationInfo_->bundleName = TEST_BUNDLE_NAME;

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = callingUid;
    std::string userKey = TEST_BUNDLE_NAME + Constants::FILE_UNDERLINE + std::to_string(userId);
    bundleInfo.innerBundleUserInfos_.insert({userKey, innerBundleUserInfo});
    dataMgr->bundleInfos_.insert({TEST_BUNDLE_NAME, bundleInfo});
    
    int32_t funcResult = 0;
    impl.DeleteAbc(DATA_STORAGE_EL1_BUNDLE_ONE, funcResult);
    EXPECT_EQ(funcResult, ERR_BUNDLE_MANAGER_DELETE_ABC_FAILED);
}
} // OHOS