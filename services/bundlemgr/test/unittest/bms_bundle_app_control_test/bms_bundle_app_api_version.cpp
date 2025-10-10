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
#define protected public
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "ability_info.h"
#include "app_control_constants.h"
#include "app_control_manager_rdb.h"
#include "app_control_manager_host_impl.h"
#include "app_jump_interceptor_manager_rdb.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "if_system_ability_manager.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "iservice_registry.h"
#include "mock_status_receiver.h"
#include "permission_define.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::AAFwk::Want;
namespace OHOS {
namespace {
const std::string INSTALL_PATH = "/data/test/resource/bms/app_control/bmsThirdBundle1.hap";
const std::string BUNDLE_NAME = "com.third.hiworld.example1";
const std::string CALLER_BUNDLE_NAME = "callerBundleName";
const std::string TARGET_BUNDLE_NAME = "targetBundleName";
const std::string APPID = "com.third.hiworld.example1_BNtg4JBClbl92Rgc3jm/"
    "RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=";
const std::string CONTROL_MESSAGE = "this is control message";
const std::string CALLING_NAME = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
const std::string APP_CONTROL_EDM_DEFAULT_MESSAGE = "The app has been disabled by EDM";
const std::string PERMISSION_DISPOSED_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
const std::string ABILITY_RUNNING_KEY = "ABILITY_RUNNING_KEY";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 1; // init mocked bms
const int NOT_EXIST_USERID = -5;
const int ALL_USERID = -3;
const int32_t MAIN_APP_INDEX = -1;
const int32_t CLONE_APP_INDEX_MAX = 6;
const int32_t APP_INDEX = 1;
}  // namespace

class BmsBundleAppApiVersionTest : public testing::Test {
public:
BmsBundleAppApiVersionTest();
    ~BmsBundleAppApiVersionTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static sptr<BundleMgrProxy> GetBundleMgrProxy();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleAppApiVersionTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleAppApiVersionTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleAppApiVersionTest::BmsBundleAppApiVersionTest()
{}

BmsBundleAppApiVersionTest::~BmsBundleAppApiVersionTest()
{}

void BmsBundleAppApiVersionTest::SetUpTestCase()
{}

void BmsBundleAppApiVersionTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleAppApiVersionTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundleAppApiVersionTest::TearDown()
{}

sptr<BundleMgrProxy> BmsBundleAppApiVersionTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        APP_LOGE("fail to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        APP_LOGE("fail to get bundle manager proxy.");
        return nullptr;
    }

    APP_LOGI("get bundle manager proxy success.");
    return iface_cast<BundleMgrProxy>(remoteObject);
}

void BmsBundleAppApiVersionTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleAppApiVersionTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
}

const std::shared_ptr<BundleDataMgr> BmsBundleAppApiVersionTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: GreatOrEqualTargetAPIVersionTest001_InvaliDate
 * @tc.name: test GreatOrEqualTargetAPIVersionTest001_InvaliDate
 * @tc.desc: Validate the incoming illegal data
 */

HWTEST_F(BmsBundleAppApiVersionTest, GreatOrEqualTargetAPIVersionTest001_InvaliDate, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    ASSERT_FALSE(dataMgr->bundleInfos_.empty());
    auto newUid = dataMgr->bundleInfos_.begin()->second.GetUid(Constants::ALL_USERID);
    
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    auto uid = getuid();
    setuid(newUid);
    // Validate illegal major version
    auto result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(0, 0, 0);
    EXPECT_EQ(result, false);
    
    result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(ServiceConstants::API_VERSION_MAX + 1, 0, 0);
    EXPECT_EQ(result, false);

    // Validate illegal minor version
    result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(2, -1, 0);
    EXPECT_EQ(result, false);
    
    result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(2, ServiceConstants::API_VERSION_MAX + 1, 0);
    EXPECT_EQ(result, false);

    // Validate illegal patch version
    result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(2, 1, -1);
    EXPECT_EQ(result, false);
    
    result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(2, 1, ServiceConstants::API_VERSION_MAX + 1);
    EXPECT_EQ(result, false);
    setuid(uid);
}

/**
 * @tc.number: GreatOrEqualTargetAPIVersionTest001_MajorApiVersion
 * @tc.name: test GreatOrEqualTargetAPIVersionTest001_MajorApiVersion
 * @tc.desc: major api version comparison
 */
HWTEST_F(BmsBundleAppApiVersionTest, GreatOrEqualTargetAPIVersionTest001_MajorApiVersion,
    Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    ASSERT_FALSE(dataMgr->bundleInfos_.empty());
    auto newUid = dataMgr->bundleInfos_.begin()->second.GetUid(Constants::ALL_USERID);

    int32_t majorVer = dataMgr->bundleInfos_.begin()->second.GetBaseBundleInfo().targetVersion;
    majorVer = (majorVer % ServiceConstants::API_VERSION_MOD);
    int32_t minorVer = dataMgr->bundleInfos_.begin()->second.GetBaseBundleInfo().targetMinorApiVersion;
    int32_t patchVer = dataMgr->bundleInfos_.begin()->second.GetBaseBundleInfo().targetPatchApiVersion;

    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    auto uid = getuid();
    setuid(newUid);
    // If the version number is equal, true is returned
    auto result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(majorVer, minorVer, patchVer);
    if (majorVer > ServiceConstants::API_VERSION_MAX || majorVer < 1) {
        EXPECT_EQ(result, false);
    } else {
        EXPECT_EQ(result, true);
    }

    // To verify that the major version + 1 returns false
    majorVer += 1;
    result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(majorVer, minorVer, patchVer);
    EXPECT_EQ(result, false);

    // To verify that the major version - 1 returns true
    majorVer -= 2;
    result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(majorVer, minorVer, patchVer);
    if (majorVer > ServiceConstants::API_VERSION_MAX || majorVer < 1) {
        EXPECT_EQ(result, false);
    } else {
        EXPECT_EQ(result, true);
    }
    setuid(uid);
}

/**
 * @tc.number: GreatOrEqualTargetAPIVersionTest002_MinorApiVersion
 * @tc.name: test GreatOrEqualTargetAPIVersionTest002_MinorApiVersion
 * @tc.desc: minor api version comparison
 */
HWTEST_F(BmsBundleAppApiVersionTest, GreatOrEqualTargetAPIVersionTest002_MinorApiVersion,
    Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    ASSERT_FALSE(dataMgr->bundleInfos_.empty());
    auto newUid = dataMgr->bundleInfos_.begin()->second.GetUid(Constants::ALL_USERID);

    int32_t majorVer = dataMgr->bundleInfos_.begin()->second.GetBaseBundleInfo().targetVersion;
    majorVer = (majorVer % ServiceConstants::API_VERSION_MOD);
    int32_t minorVer = dataMgr->bundleInfos_.begin()->second.GetBaseBundleInfo().targetMinorApiVersion;
    int32_t patchVer = dataMgr->bundleInfos_.begin()->second.GetBaseBundleInfo().targetPatchApiVersion;

    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    auto uid = getuid();
    setuid(newUid);
    // To verify the minor version + 1 returns false
    minorVer += 1;
    auto result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(majorVer, minorVer, patchVer);
    EXPECT_EQ(result, false);

    // To verify the minor version - 1 returns true
    minorVer -= 2;
    result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(majorVer, minorVer, patchVer);
    if (minorVer > ServiceConstants::API_VERSION_MAX || minorVer < 0) {
        EXPECT_EQ(result, false);
    } else {
        EXPECT_EQ(result, true);
    }
    setuid(uid);
}

/**
 * @tc.number: GreatOrEqualTargetAPIVersionTest003_PatchApiVersion
 * @tc.name: test GreatOrEqualTargetAPIVersionTest003_PatchApiVersion
 * @tc.desc: patch api Version comparison
 */
HWTEST_F(BmsBundleAppApiVersionTest, GreatOrEqualTargetAPIVersionTest003_PatchApiVersion,
    Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    ASSERT_FALSE(dataMgr->bundleInfos_.empty());
    auto newUid = dataMgr->bundleInfos_.begin()->second.GetUid(Constants::ALL_USERID);

    int32_t majorVer = dataMgr->bundleInfos_.begin()->second.GetBaseBundleInfo().targetVersion;
    majorVer = (majorVer % ServiceConstants::API_VERSION_MOD);
    int32_t minorVer = dataMgr->bundleInfos_.begin()->second.GetBaseBundleInfo().targetMinorApiVersion;
    int32_t patchVer = dataMgr->bundleInfos_.begin()->second.GetBaseBundleInfo().targetPatchApiVersion;
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    auto uid = getuid();
    setuid(newUid);
    // To verify the patch version + 1 returns false
    patchVer += 1;
    auto result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(majorVer, minorVer, patchVer);
    EXPECT_EQ(result, false);

    // To verify the patch version - 1 returns true
    patchVer -= 2;
    result = bundleMgrProxy->GreatOrEqualTargetAPIVersion(majorVer, minorVer, patchVer);
    if (patchVer > ServiceConstants::API_VERSION_MAX || patchVer < 0) {
        EXPECT_EQ(result, false);
    } else {
        EXPECT_EQ(result, true);
    }
    setuid(uid);
}
} // OHOS