/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <fstream>
#include <future>
#include <gtest/gtest.h>
#include "verify_manager_stub.h"


using namespace testing::ext;
namespace {
const uint32_t CODE_VERIFY = 0;
const uint32_t CODE_DELETE_ABC = 2;
const uint32_t CODE_ERR = 3;
}

namespace OHOS {
namespace AppExecFwk {

class BmsVerifyManagerHostTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsVerifyManagerHostTest::SetUpTestCase()
{}

void BmsVerifyManagerHostTest::TearDownTestCase()
{}

void BmsVerifyManagerHostTest::SetUp()
{}

void BmsVerifyManagerHostTest::TearDown()
{}

class MockVerifyManagerStub : public VerifyManagerStub {
public:
    int32_t CallbackEnter(uint32_t code) override
    {
        return 0;
    }
    
    int32_t CallbackExit(uint32_t code, int32_t result) override
    {
        return 0;
    }
    
    ErrCode Verify(const std::vector<std::string>& abcPaths, int32_t& funcResult) override
    {
        return ERR_OK;
    }
	
    ErrCode DeleteAbc(const std::string& path, int32_t& funcResult) override
    {
        return ERR_OK;
    }
};
/**
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsVerifyManagerHostTest, OnRemoteRequest_0100, Function | MediumTest | Level1)
{
    MockVerifyManagerStub sub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ErrCode res = sub.OnRemoteRequest(CODE_VERIFY, data, reply, option);
    EXPECT_EQ(res, ERR_TRANSACTION_FAILED);

    res = sub.OnRemoteRequest(CODE_DELETE_ABC, data, reply, option);
    EXPECT_EQ(res, ERR_TRANSACTION_FAILED);

    res = sub.OnRemoteRequest(CODE_ERR, data, reply, option);
    EXPECT_EQ(res, ERR_TRANSACTION_FAILED);
}
} // AppExecFwk
} // OHOS