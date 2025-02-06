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

#include <gtest/gtest.h>

#include "bundle_mgr_client_impl.h"

#include <cerrno>
#include <fstream>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service_death_recipient.h"
#include "iservice_registry.h"
#include "nlohmann/json.hpp"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BundleMgrClientImplTest : public testing::Test {
public:
    BundleMgrClientImplTest() = default;
    ~BundleMgrClientImplTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleMgrClientImplTest::SetUpTestCase()
{}

void BundleMgrClientImplTest::TearDownTestCase()
{}

void BundleMgrClientImplTest::SetUp()
{}

void BundleMgrClientImplTest::TearDown()
{}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0100
 * @tc.name: test the CreateBundleDataDirWithEl
 * @tc.desc: 1. CreateBundleDataDirWithEl
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    int32_t userId = 0;
    DataDirEl dirEl = DataDirEl::EL5;
    EXPECT_NO_THROW(bundleMgrClientImpl->CreateBundleDataDirWithEl(userId, dirEl));
}
} // AppExecFwk
} // OHOS
