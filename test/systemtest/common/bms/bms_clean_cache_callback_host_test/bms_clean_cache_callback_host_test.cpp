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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "appexecfwk_errors.h"
#define private public
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_user_mgr_host.h"
#include "clean_cache_callback_host.h"
#undef private

using namespace testing::ext;
using testing::_;
namespace OHOS {
namespace AppExecFwk {
class MockCleanCacheCallbackHost : public CleanCacheCallbackHost {
public:
    MockCleanCacheCallbackHost() = default;
    virtual ~MockCleanCacheCallbackHost() = default;
    void OnCleanCacheFinished(bool succeeded) override {};
};

class BmsCleanCacheCallbackHostTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsCleanCacheCallbackHostTest::SetUpTestCase() {}

void BmsCleanCacheCallbackHostTest::TearDownTestCase() {}

void BmsCleanCacheCallbackHostTest::SetUp() {}

void BmsCleanCacheCallbackHostTest::TearDown() {}

/**
 * @tc.number: CleanCacheCallbackHost_001
 * @tc.name: OnRemoteRequest
 * @tc.desc: data is not write interface token, failed to verify OnRemoteRequest.
 */
HWTEST_F(BmsCleanCacheCallbackHostTest, CleanCacheCallbackHost_001, TestSize.Level2)
{
    uint32_t code = static_cast<uint32_t>(CleanCacheCallbackInterfaceCode::ON_CLEAN_CACHE_CALLBACK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<MockCleanCacheCallbackHost> cleanCacheCallbackHost = new (std::nothrow) MockCleanCacheCallbackHost();
    auto result = cleanCacheCallbackHost->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, OBJECT_NULL);
}

/**
 * @tc.number: CleanCacheCallbackHost_002
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.code is Message::ON_CLEAN_CACHE_CALLBACK.
 *           2.data is write interface token.
 *           3.Execute as expected and exit without abnormal value.
 */
HWTEST_F(BmsCleanCacheCallbackHostTest, CleanCacheCallbackHost_002, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(CleanCacheCallbackInterfaceCode::ON_CLEAN_CACHE_CALLBACK);
    MessageParcel data;
    sptr<MockCleanCacheCallbackHost> cleanCacheCallbackHost = new (std::nothrow) MockCleanCacheCallbackHost();
    data.WriteInterfaceToken(CleanCacheCallbackHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option;

    auto result = cleanCacheCallbackHost->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, NO_ERROR);
}

/**
 * @tc.number: CleanCacheCallbackHost_003
 * @tc.name: OnRemoteRequest
 * @tc.desc: 1.code is not Message::ON_CLEAN_CACHE_CALLBACK.
 *           2.data is write interface token.
 *           3.Execute as expected and exit without abnormal value.
 */
HWTEST_F(BmsCleanCacheCallbackHostTest, CleanCacheCallbackHost_003, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(CleanCacheCallbackInterfaceCode::ON_CLEAN_CACHE_CALLBACK) + 1;
    MessageParcel data;
    sptr<MockCleanCacheCallbackHost> cleanCacheCallbackHost = new (std::nothrow) MockCleanCacheCallbackHost();
    data.WriteInterfaceToken(CleanCacheCallbackHost::GetDescriptor());
    MessageParcel reply;
    MessageOption option;

    auto result = cleanCacheCallbackHost->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}
} // namespace AppExecFwk
} // namespace OHOS