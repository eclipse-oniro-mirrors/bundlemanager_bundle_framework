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

#include <gtest/gtest.h>
#include <string>

#include "app_log_wrapper.h"
#include "bms_extension_data_mgr.h"
#include "bundle_mgr_ext_client.h"
#include "bundle_mgr_ext_host_impl.h"
#include "bundle_mgr_ext_proxy.h"
#include "bundle_mgr_ext_register.h"
#include "bundle_mgr_ext_stub.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
class BmsBundleMgrExtClientTest : public testing::Test {
public:
    BmsBundleMgrExtClientTest();
    ~BmsBundleMgrExtClientTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleMgrExtClientTest::BmsBundleMgrExtClientTest()
{}

BmsBundleMgrExtClientTest::~BmsBundleMgrExtClientTest()
{}

void BmsBundleMgrExtClientTest::SetUpTestCase()
{}

void BmsBundleMgrExtClientTest::TearDownTestCase()
{}

void BmsBundleMgrExtClientTest::SetUp()
{}

void BmsBundleMgrExtClientTest::TearDown()
{}

/**
 * @tc.number: GetBundleMgrExtProxy_0010
 * @tc.name: GetBundleMgrExtProxy_0010
 * @tc.desc: test GetBundleMgrExtProxy
 */
HWTEST_F(BmsBundleMgrExtClientTest, GetBundleMgrExtProxy_0010, Function | SmallTest | Level1)
{
    BundleMgrExtClient::GetInstance().bundleMgrExtProxy_ = nullptr;
    auto bundleMgrExtProxy = BundleMgrExtClient::GetInstance().GetBundleMgrExtProxy();
    EXPECT_EQ(bundleMgrExtProxy, nullptr);
    EXPECT_EQ(BundleMgrExtClient::GetInstance().bundleMgrExtProxy_, nullptr);
}

/**
 * @tc.number: GetBundleNamesForUidExtClient_0100
 * @tc.name: GetBundleNamesForUidExtClient_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtClientTest, GetBundleNamesForUidExtClient_0100, Function | SmallTest | Level1)
{
    int32_t uid = 111;
    std::vector<std::string> bundleNames;
    BundleMgrExtClient::GetInstance().bundleMgrExtProxy_ = nullptr;
    auto ret = BundleMgrExtClient::GetInstance().GetBundleNamesForUidExt(uid, bundleNames);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
    EXPECT_EQ(bundleNames.empty(), true);
}
}