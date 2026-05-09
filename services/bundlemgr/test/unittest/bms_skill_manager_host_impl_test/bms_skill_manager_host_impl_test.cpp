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
#include <gtest/gtest.h>
#include "bundle_skill/skill_manager_host_impl.h"
#include "bundle_mgr_service.h"
#include "installd/installd_service.h"
#include "bundle_data_mgr.h"
#include "bundle_skill/skill_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t SERVICE_START_WAIT_SEC = 3;
}

class BmsSkillManagerHostImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override {}
    void TearDown() override {}
    static std::shared_ptr<BundleMgrService> service_;
    static std::shared_ptr<InstalldService> installdService_;
};

std::shared_ptr<BundleMgrService> BmsSkillManagerHostImplTest::service_ =
    DelayedSingleton<BundleMgrService>::GetInstance();
std::shared_ptr<InstalldService> BmsSkillManagerHostImplTest::installdService_ =
    DelayedSingleton<InstalldService>::GetInstance();

void BmsSkillManagerHostImplTest::SetUpTestCase()
{
    if (!service_->IsServiceReady()) {
        service_->OnStart();
        service_->GetDataMgr()->AddUserId(TEST_USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(SERVICE_START_WAIT_SEC));
    }
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsSkillManagerHostImplTest::TearDownTestCase()
{
    service_->OnStop();
}

// === GetSkillInfoForSelf ===

TEST_F(BmsSkillManagerHostImplTest, GetSkillInfoForSelf_EmptyModuleName)
{
    SkillManagerHostImpl impl;
    SkillInfo skillInfo;
    ErrCode ret = impl.GetSkillInfoForSelf("", "skill", 0, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

TEST_F(BmsSkillManagerHostImplTest, GetSkillInfoForSelf_EmptySkillName)
{
    SkillManagerHostImpl impl;
    SkillInfo skillInfo;
    ErrCode ret = impl.GetSkillInfoForSelf("module", "", 0, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SKILL_INFO_NOT_EXIST);
}

TEST_F(BmsSkillManagerHostImplTest, GetSkillInfoForSelf_NullDataMgr)
{
    SkillManagerHostImpl impl;
    SkillInfo skillInfo;
    // Call with valid params but no data manager set up for skill info
    // Since we have a running service, dataMgr should be non-null
    ErrCode ret = impl.GetSkillInfoForSelf("module", "skill", 0, skillInfo);
    // Should not return null ptr error since service is running
    EXPECT_NE(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// === GetSkillInfosForSelf ===

TEST_F(BmsSkillManagerHostImplTest, GetSkillInfosForSelf_NullDataMgr)
{
    SkillManagerHostImpl impl;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = impl.GetSkillInfosForSelf(0, skillInfos);
    // Service is running so dataMgr is non-null
    EXPECT_NE(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// === GetSkillInfo ===

TEST_F(BmsSkillManagerHostImplTest, GetSkillInfo_EmptyBundleName)
{
    SkillManagerHostImpl impl;
    SkillInfo skillInfo;
    ErrCode ret = impl.GetSkillInfo("", "module", "skill", 0, 100, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

TEST_F(BmsSkillManagerHostImplTest, GetSkillInfo_EmptySkillName)
{
    SkillManagerHostImpl impl;
    SkillInfo skillInfo;
    ErrCode ret = impl.GetSkillInfo("com.test", "module", "", 0, 100, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SKILL_INFO_NOT_EXIST);
}

// === GetSkillInfos ===

TEST_F(BmsSkillManagerHostImplTest, GetSkillInfos_EmptyBundleName)
{
    SkillManagerHostImpl impl;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = impl.GetSkillInfos("", 0, 100, skillInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

// === GetAllSkillInfos ===

TEST_F(BmsSkillManagerHostImplTest, GetAllSkillInfos_WithDataMgr)
{
    SkillManagerHostImpl impl;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = impl.GetAllSkillInfos(0, 100, skillInfos);
    // Service is running, so should get past null check
    // May return ok with empty results or error depending on data
    EXPECT_NE(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}
