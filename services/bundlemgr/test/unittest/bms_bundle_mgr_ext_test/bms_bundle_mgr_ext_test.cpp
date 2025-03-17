/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_ext_proxy.h"
#include "bundle_mgr_ext_host.h"
#include "bundle_mgr_ext_host_impl.h"
#include "bms_extension_data_mgr.h"
#include "bundle_permission_mgr.h"
#include "bundle_mgr_service.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
class BmsBundleMgrExtTest : public testing::Test {
public:
    BmsBundleMgrExtTest();
    ~BmsBundleMgrExtTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static sptr<BundleMgrProxy> GetBundleMgrProxy();
};

BmsBundleMgrExtTest::BmsBundleMgrExtTest()
{}

BmsBundleMgrExtTest::~BmsBundleMgrExtTest()
{}

void BmsBundleMgrExtTest::SetUpTestCase()
{}

void BmsBundleMgrExtTest::TearDownTestCase()
{}

void BmsBundleMgrExtTest::SetUp()
{}

void BmsBundleMgrExtTest::TearDown()
{}

sptr<BundleMgrProxy> BmsBundleMgrExtTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        APP_LOGE("fail to get system ability mgr");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        APP_LOGE("fail to get bundle manager proxy");
        return nullptr;
    }

    APP_LOGI("get bundle manager proxy success");
    return iface_cast<BundleMgrProxy>(remoteObject);
}

/**
 * @tc.number: GetBundleNamesForUidExtProxy_0100
 * @tc.name: GetBundleNamesForUidExtProxy_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtTest, GetBundleNamesForUidExtProxy_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IBundleMgrExt> bundleMgrExtProxy = bundleMgrProxy->GetBundleMgrExtProxy();
    ASSERT_NE(bundleMgrExtProxy, nullptr);

    int32_t uid = 111;
    std::vector<std::string> bundleNames;
    ErrCode ret = bundleMgrExtProxy->GetBundleNamesForUidExt(uid, bundleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
    EXPECT_EQ(bundleNames.empty(), true);
}

/**
 * @tc.number: GetBundleNamesForUidExtHost_0100
 * @tc.name: GetBundleNamesForUidExtHost_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtTest, GetBundleNamesForUidExtHost_0100, Function | SmallTest | Level1)
{
    BundleMgrExtHost host;
    MessageParcel data;
    data.WriteInt32(111);
    MessageParcel reply;
    ErrCode ret = host.HandleGetBundleNamesForUidExt(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetBundleNamesForUidExtImpl_0100
 * @tc.name: GetBundleNamesForUidExtImpl_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtTest, GetBundleNamesForUidExtImpl_0100, Function | SmallTest | Level1)
{
    BundleMgrExtHostImpl impl;
    int32_t uid = 111;
    std::vector<std::string> bundleNames;
    ErrCode ret = impl.GetBundleNamesForUidExt(uid, bundleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: GetBundleNamesForUidExt_0100
 * @tc.name: GetBundleNamesForUidExt_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtTest, GetBundleNamesForUidExt_0100, Function | SmallTest | Level1)
{
    int32_t uid = 111;
    std::vector<std::string> bundleNames;
    BmsExtensionDataMgr bmsExtensionDataMgr;
    ErrCode ret = bmsExtensionDataMgr.GetBundleNamesForUidExt(uid, bundleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}
} // OHOS