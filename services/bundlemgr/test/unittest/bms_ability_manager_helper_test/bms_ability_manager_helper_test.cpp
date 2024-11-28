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

#include <gtest/gtest.h>
#define private public
#define protected public
#include "ability_manager_helper.h"
#include "bundle_mgr_service.h"
#undef private
#undef protected
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;
namespace AppExecFwk {
namespace {
    const std::string BUNDLE_NAME = "bundleName";
}
class BmsAbilityManagerHelperTest : public testing::Test {
public:
    BmsAbilityManagerHelperTest();
    ~BmsAbilityManagerHelperTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityManagerHelper> abilityManagerHelper_ = nullptr;
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsAbilityManagerHelperTest::bundleMgrService_ =
    OHOS::DelayedSingleton<BundleMgrService>::GetInstance();

BmsAbilityManagerHelperTest::BmsAbilityManagerHelperTest()
{}

BmsAbilityManagerHelperTest::~BmsAbilityManagerHelperTest()
{}

void BmsAbilityManagerHelperTest::SetUpTestCase()
{}

void BmsAbilityManagerHelperTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsAbilityManagerHelperTest::SetUp()
{}

void BmsAbilityManagerHelperTest::TearDown()
{
    abilityManagerHelper_ = std::make_shared<AbilityManagerHelper>();
}

#ifdef ABILITY_RUNTIME_ENABLE
/**
 * @tc.number: UninstallApplicationProcesses_0100
 * @tc.name: UninstallApplicationProcesses
 * @tc.desc: 1. UninstallApp return 1
 */
HWTEST_F(BmsAbilityManagerHelperTest, UninstallApplicationProcesses_0100, Function | SmallTest | Level0)
{
    std::string bundleName = BUNDLE_NAME;
    int uid = -1;
    bool ret = abilityManagerHelper_->UninstallApplicationProcesses(bundleName, uid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UninstallApplicationProcesses_0200
 * @tc.name: UninstallApplicationProcesses
 * @tc.desc: 1. UninstallApp return 0
 */
HWTEST_F(BmsAbilityManagerHelperTest, UninstallApplicationProcesses_0200, Function | SmallTest | Level0)
{
    std::string bundleName = BUNDLE_NAME;
    int uid = 1;
    bool ret = abilityManagerHelper_->UninstallApplicationProcesses(bundleName, uid);
    EXPECT_TRUE(ret);
}
#endif

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
/**
 * @tc.number: IsRunning_moduleName_0100
 * @tc.name: IsRunning
 * @tc.desc: Return NOT_RUNNING
 */
HWTEST_F(BmsAbilityManagerHelperTest, IsRunning_moduleName_0100, Function | SmallTest | Level0)
{
    std::string bundleName = BUNDLE_NAME;
    int ret = abilityManagerHelper_->IsRunning(bundleName);
    EXPECT_EQ(ret, 0);
}
#endif
}