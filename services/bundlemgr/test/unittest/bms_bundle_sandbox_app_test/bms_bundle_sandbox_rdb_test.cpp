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

#include <gtest/gtest.h>

#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_sandbox_installer.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "system_bundle_installer.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;
using namespace OHOS;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const int32_t WAIT_TIME = 5; // init mocked bms
} // namespace

class BmsSandboxRdbTest : public testing::Test {
public:
    BmsSandboxRdbTest();
    ~BmsSandboxRdbTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsSandboxRdbTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsSandboxRdbTest::installdService_ =
    std::make_shared<InstalldService>();

BmsSandboxRdbTest::BmsSandboxRdbTest()
{}

BmsSandboxRdbTest::~BmsSandboxRdbTest()
{}

void BmsSandboxRdbTest::SetUpTestCase()
{
}

void BmsSandboxRdbTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsSandboxRdbTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsSandboxRdbTest::TearDown()
{
}

/**
 * @tc.number: BmsSandboxRdbTest_0100
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the rdbDataManager_ is empty
 *           2.the SaveSandboxInnerBundleInfo failed
 */
HWTEST_F(BmsSandboxRdbTest, BmsSandboxRdbTest_0100, Function | SmallTest | Level0)
{
    SandboxManagerRdb sandboxManagerRdb;
    InnerBundleInfo innerBundleInfos;
    sandboxManagerRdb.rdbDataManager_ = nullptr;
    bool ret = sandboxManagerRdb.SaveSandboxInnerBundleInfo(BUNDLE_NAME, innerBundleInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsSandboxRdbTest_0200
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the rdbDataManager_ is empty
 *           2.the DeleteSandboxInnerBundleInfo failed
 */
HWTEST_F(BmsSandboxRdbTest, BmsSandboxRdbTest_0200, Function | SmallTest | Level0)
{
    SandboxManagerRdb sandboxManagerRdb;
    sandboxManagerRdb.rdbDataManager_ = nullptr;
    bool ret = sandboxManagerRdb.DeleteSandboxInnerBundleInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsSandboxRdbTest_0300
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the rdbDataManager_ is empty
 *           2.the GetAllDataFromDb failed
 */
HWTEST_F(BmsSandboxRdbTest, BmsSandboxRdbTest_0300, Function | SmallTest | Level0)
{
    SandboxManagerRdb sandboxManagerRdb;
    std::unordered_map<std::string, InnerBundleInfo> innerBundleInfos;
    sandboxManagerRdb.rdbDataManager_ = nullptr;
    bool ret = sandboxManagerRdb.GetAllDataFromDb(innerBundleInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsSandboxRdbTest_0400
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the rdbDataManager_ is empty
 *           2.the GetDataFromDb failed
 */
HWTEST_F(BmsSandboxRdbTest, BmsSandboxRdbTest_0400, Function | SmallTest | Level0)
{
    SandboxManagerRdb sandboxManagerRdb;
    InnerBundleInfo innerBundleInfos;
    sandboxManagerRdb.rdbDataManager_ = nullptr;
    bool ret = sandboxManagerRdb.GetDataFromDb(BUNDLE_NAME, innerBundleInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsSandboxRdbTest_0500
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the rdbDataManager_ is empty
 *           2.the GetDataFromDb failed
 */
HWTEST_F(BmsSandboxRdbTest, BmsSandboxRdbTest_0500, Function | SmallTest | Level0)
{
    BundleSandboxDataMgr sundleSandboxDataMgr;
    sundleSandboxDataMgr.sandboxManagerDb_ = nullptr;
    bool ret = sundleSandboxDataMgr.RestoreSandboxPersistentInnerBundleInfo();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsSandboxRdbTest_0600
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the rdbDataManager_ is empty
 *           2.the QuerySandboxInnerBundleInfo failed
 */
HWTEST_F(BmsSandboxRdbTest, BmsSandboxRdbTest_0600, Function | SmallTest | Level0)
{
    SandboxManagerRdb sandboxManagerRdb;
    InnerBundleInfo innerBundleInfos;
    sandboxManagerRdb.rdbDataManager_ = nullptr;
    bool ret = sandboxManagerRdb.QuerySandboxInnerBundleInfo(BUNDLE_NAME, innerBundleInfos);
    EXPECT_FALSE(ret);
}
}
