/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "default_app_host.h"
#include "bundle_framework_core_ipc_interface_code.h"

using namespace testing::ext;
namespace {
const uint32_t CODE_IS_DEFAULT_APPLICATION = 0;
const uint32_t CODE_GET_DEFAULT_APPLICATION = 1;
const uint32_t CODE_SET_DEFAULT_APPLICATION = 2;
const uint32_t CODE_RESET_DEFAULT_APPLICATION = 3;
const uint32_t CODE_ERR = 4;
}

namespace OHOS {
namespace AppExecFwk {

class BmsDefaultAppHostTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsDefaultAppHostTest::SetUpTestCase()
{}

void BmsDefaultAppHostTest::TearDownTestCase()
{}

void BmsDefaultAppHostTest::SetUp()
{}

void BmsDefaultAppHostTest::TearDown()
{}

/**
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsDefaultAppHostTest, OnRemoteRequest_0100, Function | MediumTest | Level1)
{
    DefaultAppHost defaultAppHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ErrCode res = defaultAppHost.OnRemoteRequest(CODE_IS_DEFAULT_APPLICATION, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);

    res = defaultAppHost.OnRemoteRequest(CODE_GET_DEFAULT_APPLICATION, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);

    res = defaultAppHost.OnRemoteRequest(CODE_SET_DEFAULT_APPLICATION, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);

    res = defaultAppHost.OnRemoteRequest(CODE_RESET_DEFAULT_APPLICATION, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);

    res = defaultAppHost.OnRemoteRequest(CODE_ERR, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);
}

/**
 * @tc.number: HandleIsDefaultApplication_0100
 * @tc.name: test the HandleIsDefaultApplication
 * @tc.desc: 1. system running normally
 *           2. test HandleIsDefaultApplication
 */
HWTEST_F(BmsDefaultAppHostTest, HandleIsDefaultApplication_0100, Function | MediumTest | Level1)
{
    DefaultAppHost defaultAppHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = defaultAppHost.HandleIsDefaultApplication(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetDefaultApplication_0100
 * @tc.name: test the HandleGetDefaultApplication
 * @tc.desc: 1. system running normally
 *           2. test HandleGetDefaultApplication
 */
HWTEST_F(BmsDefaultAppHostTest, HandleGetDefaultApplication_0100, Function | MediumTest | Level1)
{
    DefaultAppHost defaultAppHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = defaultAppHost.HandleGetDefaultApplication(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleSetDefaultApplication_0100
 * @tc.name: test the HandleSetDefaultApplication
 * @tc.desc: 1. system running normally
 *           2. test HandleSetDefaultApplication
 */
HWTEST_F(BmsDefaultAppHostTest, HandleSetDefaultApplication_0100, Function | MediumTest | Level1)
{
    DefaultAppHost defaultAppHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = defaultAppHost.HandleSetDefaultApplication(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleResetDefaultApplication_0100
 * @tc.name: test the HandleResetDefaultApplication
 * @tc.desc: 1. system running normally
 *           2. test HandleResetDefaultApplication
 */
HWTEST_F(BmsDefaultAppHostTest, HandleResetDefaultApplication_0100, Function | MediumTest | Level1)
{
    DefaultAppHost defaultAppHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = defaultAppHost.HandleResetDefaultApplication(data, reply);
    EXPECT_EQ(res, ERR_OK);
}
} // AppExecFwk
} // OHOS