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

#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_service.h"
#include "mock_ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t USERID = 100;
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
}  // namespace AppExecFwk
}  // namespace OHOS
