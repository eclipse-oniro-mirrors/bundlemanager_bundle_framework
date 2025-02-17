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

#include "process_cache_callback_proxy.h"

#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include <cinttypes>
#include "ipc_types.h"
#include "parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class ProcessCacheCallbackProxyTest : public testing::Test {
public:
    ProcessCacheCallbackProxyTest() = default;
    ~ProcessCacheCallbackProxyTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void ProcessCacheCallbackProxyTest::SetUpTestCase()
{}

void ProcessCacheCallbackProxyTest::TearDownTestCase()
{}

void ProcessCacheCallbackProxyTest::SetUp()
{}

void ProcessCacheCallbackProxyTest::TearDown()
{}

/**
 * @tc.number: Process_Cache_Callback_Proxy_Test_0100
 * @tc.name: test the OnGetAllBundleCacheFinished
 * @tc.desc: 1. OnGetAllBundleCacheFinished
 */
HWTEST_F(ProcessCacheCallbackProxyTest, Process_Cache_Callback_Proxy_Test_0100, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> object = nullptr;
    ProcessCacheCallbackProxy processCacheCallbackProxy(object);
    uint64_t cacheStat = 0;
    EXPECT_NO_THROW(processCacheCallbackProxy.OnGetAllBundleCacheFinished(cacheStat));
}

/**
 * @tc.number: Process_Cache_Callback_Proxy_Test_0200
 * @tc.name: test the OnCleanAllBundleCacheFinished
 * @tc.desc: 1. OnCleanAllBundleCacheFinished
 */
HWTEST_F(ProcessCacheCallbackProxyTest, Process_Cache_Callback_Proxy_Test_0200, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> object = nullptr;
    ProcessCacheCallbackProxy processCacheCallbackProxy(object);
    int32_t result = 0;
    EXPECT_NO_THROW(processCacheCallbackProxy.OnCleanAllBundleCacheFinished(result));
}
} // AppExecFwk
} // OHOS
