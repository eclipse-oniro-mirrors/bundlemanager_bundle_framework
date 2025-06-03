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
namespace {
const std::string BUNDLE_NAME = "bundlName";
const std::string ABILITY_NAME = "abilityName";
const std::string MOUDLE_NAME = "moduleName";
const std::string APPID = "appId";
const std::string HAP_FILE_PATH = "/data/test/resource/bms/permission_bundle/";
const int32_t USERID = 100;
const int32_t FLAGS = 0;
const int32_t UID = 0;
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundlePermissionTokenTest : public testing::Test {
public:
    BmsBundlePermissionTokenTest();
    ~BmsBundlePermissionTokenTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();
private:
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl_ = std::make_unique<BundleMgrHostImpl>();
    std::shared_ptr<BundleInstallerHost> bundleInstallerHost_ = std::make_unique<BundleInstallerHost>();
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundlePermissionTokenTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundlePermissionTokenTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundlePermissionTokenTest::BmsBundlePermissionTokenTest()
{}

BmsBundlePermissionTokenTest::~BmsBundlePermissionTokenTest()
{}

void BmsBundlePermissionTokenTest::SetUpTestCase()
{}

void BmsBundlePermissionTokenTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundlePermissionTokenTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundlePermissionTokenTest::TearDown()
{}

void BmsBundlePermissionTokenTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundlePermissionTokenTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundlePermissionTokenTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_0100
 * @tc.name: test InstallSandboxApp of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. InstallSandboxApp false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_0100, Function | SmallTest | Level0)
{
    int32_t dplType = 1;
    int32_t appIndex = 1;
    auto ret1 = bundleInstallerHost_->InstallSandboxApp(BUNDLE_NAME, dplType, USERID, appIndex);
    auto ret2 = bundleInstallerHost_->UninstallSandboxApp(BUNDLE_NAME, appIndex, USERID);
    EXPECT_EQ(ret1, ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED);
    EXPECT_EQ(ret2, ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_0200
 * @tc.name: test GetBundlesForUid of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundlesForUid false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> bundleNames;
    bool ret = bundleMgrHostImpl_->GetBundlesForUid(UID, bundleNames);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_0300
 * @tc.name: test GetBundleGids of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundleGids false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_0300, Function | SmallTest | Level0)
{
    std::vector<int> gids;
    bool ret = bundleMgrHostImpl_->GetBundleGids(BUNDLE_NAME, gids);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_0400
 * @tc.name: test CheckAbilityEnableInstall of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. CheckAbilityEnableInstall false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_0400, Function | SmallTest | Level0)
{
    AAFwk::Want want;
    bool ret = bundleMgrHostImpl_->CheckAbilityEnableInstall(want, FLAGS, USERID, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_0500
 * @tc.name: test GetHapModuleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetHapModuleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_0500, Function | SmallTest | Level0)
{
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = ABILITY_NAME;
    HapModuleInfo hapModuleInfo;
    bool ret = bundleMgrHostImpl_->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_0700
 * @tc.name: test GetUidByBundleName of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetUidByBundleName false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_0700, Function | SmallTest | Level0)
{
    auto res = bundleMgrHostImpl_->GetUidByBundleName("", USERID);
    EXPECT_EQ(res, Constants::INVALID_UID);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_0800
 * @tc.name: test GetStringById of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetStringById false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_0800, Function | SmallTest | Level0)
{
    std::string retString = bundleMgrHostImpl_->GetStringById("", "", FLAGS, USERID, "");
    EXPECT_EQ(retString, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_0900
 * @tc.name: test GetIconById of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetIconById false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_0900, Function | SmallTest | Level0)
{
    std::string retString = bundleMgrHostImpl_->GetIconById("", "", FLAGS, FLAGS, USERID);
    EXPECT_EQ(retString, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_1000
 * @tc.name: test GetSandboxAbilityInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxAbilityInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_1000, Function | SmallTest | Level0)
{
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    Want want;
    AbilityInfo info;
    ErrCode ret = bundleMgrHostImpl_->GetSandboxAbilityInfo(want, appIndex, FLAGS, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_1100
 * @tc.name: test GetSandboxExtAbilityInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxExtAbilityInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_1100, Function | SmallTest | Level0)
{
    int32_t appIndex = 1 + Constants::INITIAL_SANDBOX_APP_INDEX;
    Want want;
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode ret = bundleMgrHostImpl_->GetSandboxExtAbilityInfos(want, appIndex, FLAGS, USERID, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundlePermissionTokenTest_1200
 * @tc.name: test GetSandboxHapModuleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxHapModuleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionTokenTest, BmsBundlePermissionTokenTest_1200, Function | SmallTest | Level0)
{
    int32_t appIndex = 1 + Constants::INITIAL_SANDBOX_APP_INDEX;
    AbilityInfo abilityInfo;
    HapModuleInfo info;
    auto ret = bundleMgrHostImpl_->GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INVALID_USER_ID);
}
} // OHOS