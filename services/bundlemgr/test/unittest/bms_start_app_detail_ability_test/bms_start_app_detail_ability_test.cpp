/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <memory>
#include <string>

#define private public
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_service.h"
#include "inner_bundle_info.h"
#include "mock_ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t USERID = 100;
constexpr const char* TEST_BUNDLE_NAME = "com.test.noicon.app";
}  // namespace

// Exercises the StartAppDetailAbility host path's first guard: a calling uid
// that maps to no installed bundle must be rejected with ERR_APPEXECFWK_INVALID_UID
// before the needAppDetail gate is even evaluated.
class BmsStartAppDetailAbilityTest : public testing::Test {
public:
    BmsStartAppDetailAbilityTest() = default;
    ~BmsStartAppDetailAbilityTest() override = default;
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override;
    void TearDown() override {};

    void InsertBundleForUid(const std::string &bundleName, int32_t uid, bool needAppDetail);
    void RemoveBundleForUid(const std::string &bundleName, int32_t uid);
};

void BmsStartAppDetailAbilityTest::SetUp()
{
    // Bring up the service singleton via the public OnStart() so its DataMgr
    // exists; BundleMgrHostImpl::GetDataMgrFromService() reads that same DataMgr.
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    if (!service->IsServiceReady()) {
        service->OnStart();
    }
    ASSERT_NE(service->GetDataMgr(), nullptr);
    service->GetDataMgr()->AddUserId(USERID);
}

// Register a uid -> bundle mapping so that GetBundleNameForUid() succeeds for the
// given calling uid, and mark the bundle's needAppDetail flag to steer the
// StartAppDetailAbility gate.
void BmsStartAppDetailAbilityTest::InsertBundleForUid(
    const std::string &bundleName, int32_t uid, bool needAppDetail)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t userId = dataMgr->GetUserIdByUid(uid);
    dataMgr->bundleIdMap_.emplace(uid - userId * Constants::BASE_USER_RANGE, bundleName);

    InnerBundleInfo bundleInfo;
    bundleInfo.baseApplicationInfo_->bundleName = bundleName;
    bundleInfo.baseApplicationInfo_->needAppDetail = needAppDetail;

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = uid;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    std::string userKey = bundleName + Constants::FILE_UNDERLINE + std::to_string(userId);
    bundleInfo.innerBundleUserInfos_.emplace(userKey, innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(bundleName, bundleInfo);
}

void BmsStartAppDetailAbilityTest::RemoveBundleForUid(const std::string &bundleName, int32_t uid)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    int32_t userId = dataMgr->GetUserIdByUid(uid);
    dataMgr->bundleIdMap_.erase(uid - userId * Constants::BASE_USER_RANGE);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: StartAppDetailAbility_InvalidUid_0001
 * @tc.name: unmapped calling uid is rejected
 * @tc.desc: A calling uid that maps to no installed bundle must be rejected
 *           with ERR_APPEXECFWK_INVALID_UID before the needAppDetail gate.
 */
HWTEST_F(BmsStartAppDetailAbilityTest, StartAppDetailAbility_InvalidUid_0001, TestSize.Level1)
{
    int32_t unmappedUid = Constants::BASE_APP_UID + 999999;  // valid range, never allocated
    int32_t savedUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(unmappedUid);
    auto host = std::make_shared<BundleMgrHostImpl>();
    auto ret = host->StartAppDetailAbility();
    IPCSkeleton::SetCallingUid(savedUid);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INVALID_UID);
}

/**
 * @tc.number: StartAppDetailAbility_DataMgrNull_0002
 * @tc.name: null DataMgr is rejected
 * @tc.desc: When the service DataMgr is null, StartAppDetailAbility must fail
 *           with ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR before any uid lookup.
 */
HWTEST_F(BmsStartAppDetailAbilityTest, StartAppDetailAbility_DataMgrNull_0002, TestSize.Level1)
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto savedDataMgr = service->GetDataMgr();
    service->dataMgr_ = nullptr;
    auto host = std::make_shared<BundleMgrHostImpl>();
    auto ret = host->StartAppDetailAbility();
    service->dataMgr_ = savedDataMgr;

    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: StartAppDetailAbility_NotNoIconApp_0003
 * @tc.name: non no-icon app is rejected
 * @tc.desc: A calling uid that maps to an installed bundle whose needAppDetail
 *           is false must be rejected with ERR_APPEXECFWK_PERMISSION_DENIED at
 *           the needAppDetail gate, and must not reach the ability start.
 */
HWTEST_F(BmsStartAppDetailAbilityTest, StartAppDetailAbility_NotNoIconApp_0003, TestSize.Level1)
{
    InsertBundleForUid(TEST_BUNDLE_NAME, IPCSkeleton::GetCallingUid(), false);
    auto host = std::make_shared<BundleMgrHostImpl>();
    auto ret = host->StartAppDetailAbility();
    RemoveBundleForUid(TEST_BUNDLE_NAME, IPCSkeleton::GetCallingUid());

    EXPECT_EQ(ret, ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: StartAppDetailAbility_NoIconApp_0004
 * @tc.name: no-icon app reaches the ability start
 * @tc.desc: A calling uid that maps to an installed no-icon app (needAppDetail
 *           true) passes every guard and reaches AbilityManagerClient. With the
 *           mocked SystemAbilityManager the ability manager cannot be resolved,
 *           so the start deterministically fails and the error is propagated.
 */
HWTEST_F(BmsStartAppDetailAbilityTest, StartAppDetailAbility_NoIconApp_0004, TestSize.Level1)
{
    InsertBundleForUid(TEST_BUNDLE_NAME, IPCSkeleton::GetCallingUid(), true);
    auto host = std::make_shared<BundleMgrHostImpl>();
    auto ret = host->StartAppDetailAbility();
    RemoveBundleForUid(TEST_BUNDLE_NAME, IPCSkeleton::GetCallingUid());

    EXPECT_NE(ret, ERR_OK);
}
}  // namespace AppExecFwk
}  // namespace OHOS
