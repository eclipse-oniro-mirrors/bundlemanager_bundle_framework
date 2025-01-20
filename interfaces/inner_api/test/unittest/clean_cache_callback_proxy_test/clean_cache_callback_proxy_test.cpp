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

#include "clean_cache_callback_proxy.h"

#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class CleanCacheCallbackProxyTest : public testing::Test {
public:
    CleanCacheCallbackProxyTest() = default;
    ~CleanCacheCallbackProxyTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void CleanCacheCallbackProxyTest::SetUpTestCase()
{}

void CleanCacheCallbackProxyTest::TearDownTestCase()
{}

void CleanCacheCallbackProxyTest::SetUp()
{}

void CleanCacheCallbackProxyTest::TearDown()
{}

/**
 * @tc.number: Clean_Cache_Callback_Proxy_Test_0100
 * @tc.name: test the OnCleanCacheFinished
 * @tc.desc: 1. OnCleanCacheFinished
 */
HWTEST_F(CleanCacheCallbackProxyTest, Clean_Cache_Callback_Proxy_Test_0100, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> object = nullptr;
    CleanCacheCallbackProxy cleanCacheCallbackProxy(object);
    bool succeeded = true;
    EXPECT_NO_THROW(cleanCacheCallbackProxy.OnCleanCacheFinished(succeeded));
}
} // AppExecFwk
} // OHOS
