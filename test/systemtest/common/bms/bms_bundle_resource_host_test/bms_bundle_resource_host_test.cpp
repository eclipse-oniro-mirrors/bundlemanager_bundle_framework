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
#include "bundle_resource_host.h"

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

class BmsBundleResourceHostTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsBundleResourceHostTest::SetUpTestCase()
{}

void BmsBundleResourceHostTest::TearDownTestCase()
{}

void BmsBundleResourceHostTest::SetUp()
{}

void BmsBundleResourceHostTest::TearDown()
{}

/**
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsBundleResourceHostTest, OnRemoteRequest_0100, Function | MediumTest | Level1)
{
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ErrCode res = bundleResourceHost.OnRemoteRequest(CODE_IS_DEFAULT_APPLICATION, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);

    res = bundleResourceHost.OnRemoteRequest(CODE_GET_DEFAULT_APPLICATION, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);

    res = bundleResourceHost.OnRemoteRequest(CODE_SET_DEFAULT_APPLICATION, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);

    res = bundleResourceHost.OnRemoteRequest(CODE_RESET_DEFAULT_APPLICATION, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);

    res = bundleResourceHost.OnRemoteRequest(CODE_ERR, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);
}

/**
 * @tc.number: HandleGetBundleResourceInfo_0100
 * @tc.name: test the HandleGetBundleResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceHostTest, HandleGetBundleResourceInfo_0100, Function | MediumTest | Level1)
{
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleResourceHost.HandleGetBundleResourceInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetLauncherAbilityResourceInfo_0100
 * @tc.name: test the HandleGetLauncherAbilityResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceHostTest, HandleGetLauncherAbilityResourceInfo_0100, Function | MediumTest | Level1)
{
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleResourceHost.HandleGetLauncherAbilityResourceInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAllBundleResourceInfo_0100
 * @tc.name: test the HandleGetAllBundleResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceHostTest, HandleGetAllBundleResourceInfo_0100, Function | MediumTest | Level1)
{
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleResourceHost.HandleGetAllBundleResourceInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAllLauncherAbilityResourceInfo_0100
 * @tc.name: test the HandleGetAllLauncherAbilityResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceHostTest, HandleGetAllLauncherAbilityResourceInfo_0100, Function | MediumTest | Level1)
{
    BundleResourceHost bundleResourceHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleResourceHost.HandleGetAllLauncherAbilityResourceInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}
} // AppExecFwk
} // OHOS