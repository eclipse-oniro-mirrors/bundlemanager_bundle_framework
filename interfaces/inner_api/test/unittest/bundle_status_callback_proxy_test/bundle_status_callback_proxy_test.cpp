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

#include "bundle_status_callback_proxy.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "parcel.h"
#include "string_ex.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BundleStatusCallbackProxyTest : public testing::Test {
public:
    BundleStatusCallbackProxyTest() = default;
    ~BundleStatusCallbackProxyTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleStatusCallbackProxyTest::SetUpTestCase()
{}

void BundleStatusCallbackProxyTest::TearDownTestCase()
{}

void BundleStatusCallbackProxyTest::SetUp()
{}

void BundleStatusCallbackProxyTest::TearDown()
{}

/**
 * @tc.number: Bundle_Status_Callback_Proxy_Test_0100
 * @tc.name: test the OnBundleStateChanged
 * @tc.desc: 1. OnBundleStateChanged
 */
HWTEST_F(BundleStatusCallbackProxyTest, Bundle_Status_Callback_Proxy_Test_0100, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> object = nullptr;
    BundleStatusCallbackProxy bundleStatusCallbackProxy(object);
    uint8_t installType = 0;
    int32_t resultCode = 0;
    std::string resultMsg;
    std::string bundleName;
    EXPECT_NO_THROW(bundleStatusCallbackProxy.OnBundleStateChanged(installType, resultCode, resultMsg, bundleName));
}

/**
 * @tc.number: Bundle_Status_Callback_Proxy_Test_0200
 * @tc.name: test the OnBundleAdded
 * @tc.desc: 1. OnBundleAdded with 2 params
 *           2. OnBundleAdded with 3 params
 */
HWTEST_F(BundleStatusCallbackProxyTest, Bundle_Status_Callback_Proxy_Test_0200, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> object = nullptr;
    BundleStatusCallbackProxy bundleStatusCallbackProxy(object);
    std::string bundleName;
    int userId = 0;
    EXPECT_NO_THROW(bundleStatusCallbackProxy.OnBundleAdded(bundleName, userId));
    int32_t appIndex = 0;
    EXPECT_NO_THROW(bundleStatusCallbackProxy.OnBundleAdded(bundleName, userId, appIndex));
}

/**
 * @tc.number: Bundle_Status_Callback_Proxy_Test_0300
 * @tc.name: test the OnBundleUpdated
 * @tc.desc: 1. OnBundleUpdated with 2 params
 *           2. OnBundleUpdated with 3 params
 */
HWTEST_F(BundleStatusCallbackProxyTest, Bundle_Status_Callback_Proxy_Test_0300, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> object = nullptr;
    BundleStatusCallbackProxy bundleStatusCallbackProxy(object);
    std::string bundleName;
    int userId = 0;
    EXPECT_NO_THROW(bundleStatusCallbackProxy.OnBundleUpdated(bundleName, userId));
    int32_t appIndex = 0;
    EXPECT_NO_THROW(bundleStatusCallbackProxy.OnBundleUpdated(bundleName, userId, appIndex));
}

/**
 * @tc.number: Bundle_Status_Callback_Proxy_Test_0400
 * @tc.name: test the OnBundleRemoved
 * @tc.desc: 1. OnBundleRemoved with 2 params
 *           2. OnBundleRemoved with 3 params
 */
HWTEST_F(BundleStatusCallbackProxyTest, Bundle_Status_Callback_Proxy_Test_0400, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> object = nullptr;
    BundleStatusCallbackProxy bundleStatusCallbackProxy(object);
    std::string bundleName;
    int userId = 0;
    EXPECT_NO_THROW(bundleStatusCallbackProxy.OnBundleRemoved(bundleName, userId));
    int32_t appIndex = 0;
    EXPECT_NO_THROW(bundleStatusCallbackProxy.OnBundleRemoved(bundleName, userId, appIndex));
}
} // AppExecFwk
} // OHOS
