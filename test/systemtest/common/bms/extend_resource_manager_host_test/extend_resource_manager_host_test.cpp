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
#include "extend_resource_manager_host.h"
#include "bundle_framework_core_ipc_interface_code.h"

using namespace testing::ext;
namespace {
const uint32_t ADD_EXT_RESOURCE = 0;
const uint32_t REMOVE_EXT_RESOURCE = 1;
const uint32_t GET_EXT_RESOURCE = 2;
const uint32_t ENABLE_DYNAMIC_ICON = 3;
const uint32_t DISABLE_DYNAMIC_ICON = 4;
const uint32_t GET_DYNAMIC_ICON = 5;
const uint32_t CREATE_FD = 6;
const uint32_t OTHER_CODE = 7;
const uint32_t ERROR_CODE = 305;
}
namespace OHOS {
namespace AppExecFwk {

class ExtendResourceManagerHostTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ExtendResourceManagerHostTest::SetUpTestCase()
{}

void ExtendResourceManagerHostTest::TearDownTestCase()
{}

void ExtendResourceManagerHostTest::SetUp()
{}

void ExtendResourceManagerHostTest::TearDown()
{}

/**
 * @tc.number: HandleAddAppInstallControlRule_0100
 * @tc.name: test the HandleAddAppInstallControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleAddAppInstallControlRule
 */
HWTEST_F(ExtendResourceManagerHostTest, OnRemoteRequest_0100, Function | MediumTest | Level1)
{
    ExtendResourceManagerHost extendResource;
    uint32_t code = ADD_EXT_RESOURCE;
    MessageParcel data;
    std::u16string descriptor = ExtendResourceManagerHost::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = extendResource.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);

    data.WriteInterfaceToken(descriptor);
    code = REMOVE_EXT_RESOURCE;
    res = extendResource.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);

    data.WriteInterfaceToken(descriptor);
    code = GET_EXT_RESOURCE;
    res = extendResource.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);

    data.WriteInterfaceToken(descriptor);
    code = ENABLE_DYNAMIC_ICON;
    res = extendResource.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);

    data.WriteInterfaceToken(descriptor);
    code = DISABLE_DYNAMIC_ICON;
    res = extendResource.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);

    data.WriteInterfaceToken(descriptor);
    code = GET_DYNAMIC_ICON;
    res = extendResource.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);

    data.WriteInterfaceToken(descriptor);
    code = CREATE_FD;
    res = extendResource.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_OK);

    data.WriteInterfaceToken(descriptor);
    code = OTHER_CODE;
    res = extendResource.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERROR_CODE);
}

/**
 * @tc.number: HandleAddExtResource_0100
 * @tc.name: test the HandleAddExtResource
 * @tc.desc: 1. system running normally
 *           2. test HandleAddExtResource
 */
HWTEST_F(ExtendResourceManagerHostTest, HandleAddExtResource_0100, Function | MediumTest | Level1)
{
    ExtendResourceManagerHost extendResource;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = extendResource.HandleAddExtResource(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleRemoveExtResource_0100
 * @tc.name: test the HandleRemoveExtResource
 * @tc.desc: 1. system running normally
 *           2. test HandleRemoveExtResource
 */
HWTEST_F(ExtendResourceManagerHostTest, HandleRemoveExtResource_0100, Function | MediumTest | Level1)
{
    ExtendResourceManagerHost extendResource;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = extendResource.HandleRemoveExtResource(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetExtResource_0100
 * @tc.name: test the HandleGetExtResource
 * @tc.desc: 1. system running normally
 *           2. test HandleGetExtResource
 */
HWTEST_F(ExtendResourceManagerHostTest, HandleGetExtResource_0100, Function | MediumTest | Level1)
{
    ExtendResourceManagerHost extendResource;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = extendResource.HandleGetExtResource(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleEnableDynamicIcon_0100
 * @tc.name: test the HandleEnableDynamicIcon
 * @tc.desc: 1. system running normally
 *           2. test HandleEnableDynamicIcon
 */
HWTEST_F(ExtendResourceManagerHostTest, HandleEnableDynamicIcon_0100, Function | MediumTest | Level1)
{
    ExtendResourceManagerHost extendResource;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = extendResource.HandleEnableDynamicIcon(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleDisableDynamicIcon_0100
 * @tc.name: test the HandleDisableDynamicIcon
 * @tc.desc: 1. system running normally
 *           2. test HandleDisableDynamicIcon
 */
HWTEST_F(ExtendResourceManagerHostTest, HandleDisableDynamicIcon_0100, Function | MediumTest | Level1)
{
    ExtendResourceManagerHost extendResource;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = extendResource.HandleDisableDynamicIcon(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetDynamicIcon_0100
 * @tc.name: test the HandleGetDynamicIcon
 * @tc.desc: 1. system running normally
 *           2. test HandleGetDynamicIcon
 */
HWTEST_F(ExtendResourceManagerHostTest, HandleGetDynamicIcon_0100, Function | MediumTest | Level1)
{
    ExtendResourceManagerHost extendResource;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = extendResource.HandleGetDynamicIcon(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleCreateFd_0100
 * @tc.name: test the HandleCreateFd
 * @tc.desc: 1. system running normally
 *           2. test HandleCreateFd
 */
HWTEST_F(ExtendResourceManagerHostTest, HandleCreateFd_0100, Function | MediumTest | Level1)
{
    ExtendResourceManagerHost extendResource;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = extendResource.HandleCreateFd(data, reply);
    EXPECT_EQ(res, ERR_OK);
}
} // AppExecFwk
} // OHOS