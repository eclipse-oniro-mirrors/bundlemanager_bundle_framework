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
#include "app_control_host.h"
#include "bundle_framework_core_ipc_interface_code.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BmsAppControlHostTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsAppControlHostTest::SetUpTestCase()
{}

void BmsAppControlHostTest::TearDownTestCase()
{}

void BmsAppControlHostTest::SetUp()
{}

void BmsAppControlHostTest::TearDown()
{}

/**
 * @tc.number: HandleAddAppInstallControlRule_0100
 * @tc.name: test the HandleAddAppInstallControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleAddAppInstallControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleAddAppInstallControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleAddAppInstallControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleDeleteAppInstallControlRule_0100
 * @tc.name: test the HandleDeleteAppInstallControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleDeleteAppInstallControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleDeleteAppInstallControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleDeleteAppInstallControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleCleanAppInstallControlRule_0100
 * @tc.name: test the HandleCleanAppInstallControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleCleanAppInstallControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleCleanAppInstallControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleCleanAppInstallControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleGetAppInstallControlRule_0100
 * @tc.name: test the HandleGetAppInstallControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAppInstallControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleGetAppInstallControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleGetAppInstallControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleAddAppRunningControlRule_0100
 * @tc.name: test the HandleAddAppRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleAddAppRunningControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleAddAppRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleAddAppRunningControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleDeleteAppRunningControlRule_0100
 * @tc.name: test the HandleDeleteAppRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleDeleteAppRunningControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleDeleteAppRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleDeleteAppRunningControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleCleanAppRunningControlRule_0100
 * @tc.name: test the HandleCleanAppRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleCleanAppRunningControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleCleanAppRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleCleanAppRunningControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleGetAppRunningControlRule_0100
 * @tc.name: test the HandleGetAppRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAppRunningControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleGetAppRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleGetAppRunningControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleGetAppRunningControlRuleResult_0100
 * @tc.name: test the HandleGetAppRunningControlRuleResult
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAppRunningControlRuleResult
 */
HWTEST_F(BmsAppControlHostTest, HandleGetAppRunningControlRuleResult_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleGetAppRunningControlRuleResult(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleConfirmAppJumpControlRule_0100
 * @tc.name: test the HandleConfirmAppJumpControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleConfirmAppJumpControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleConfirmAppJumpControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleConfirmAppJumpControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleAddAppJumpControlRule_0100
 * @tc.name: test the HandleAddAppJumpControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleAddAppJumpControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleAddAppJumpControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleAddAppJumpControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleDeleteAppJumpControlRule_0100
 * @tc.name: test the HandleDeleteAppJumpControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleDeleteAppJumpControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleDeleteAppJumpControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleDeleteAppJumpControlRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleDeleteRuleByCallerBundleName_0100
 * @tc.name: test the HandleDeleteRuleByCallerBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleDeleteRuleByCallerBundleName
 */
HWTEST_F(BmsAppControlHostTest, HandleDeleteRuleByCallerBundleName_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleDeleteRuleByCallerBundleName(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleDeleteRuleByTargetBundleName_0100
 * @tc.name: test the HandleDeleteRuleByTargetBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleDeleteRuleByTargetBundleName
 */
HWTEST_F(BmsAppControlHostTest, HandleDeleteRuleByTargetBundleName_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleDeleteRuleByTargetBundleName(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleGetAppJumpControlRule_0100
 * @tc.name: test the HandleGetAppJumpControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAppJumpControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleGetAppJumpControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleGetAppJumpControlRule(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleSetDisposedStatus_0100
 * @tc.name: test the HandleSetDisposedStatus
 * @tc.desc: 1. system running normally
 *           2. test HandleSetDisposedStatus
 */
HWTEST_F(BmsAppControlHostTest, HandleSetDisposedStatus_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleSetDisposedStatus(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleDeleteDisposedStatus_0100
 * @tc.name: test the HandleDeleteDisposedStatus
 * @tc.desc: 1. system running normally
 *           2. test HandleDeleteDisposedStatus
 */
HWTEST_F(BmsAppControlHostTest, HandleDeleteDisposedStatus_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleDeleteDisposedStatus(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetDisposedStatus_0100
 * @tc.name: test the HandleGetDisposedStatus
 * @tc.desc: 1. system running normally
 *           2. test HandleGetDisposedStatus
 */
HWTEST_F(BmsAppControlHostTest, HandleGetDisposedStatus_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleGetDisposedStatus(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetDisposedRule_0100
 * @tc.name: test the HandleGetDisposedRule
 * @tc.desc: 1. system running normally
 *           2. test HandleGetDisposedRule
 */
HWTEST_F(BmsAppControlHostTest, HandleGetDisposedRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleGetDisposedRule(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleSetDisposedRule_0100
 * @tc.name: test the HandleSetDisposedRule
 * @tc.desc: 1. system running normally
 *           2. test HandleSetDisposedRule
 */
HWTEST_F(BmsAppControlHostTest, HandleSetDisposedRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleSetDisposedRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetAbilityRunningControlRule_0100
 * @tc.name: test the HandleGetAbilityRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAbilityRunningControlRule
 */
HWTEST_F(BmsAppControlHostTest, HandleGetAbilityRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleGetAbilityRunningControlRule(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleSetUninstallDisposedRule_0100
 * @tc.name: Test HandleSetUninstallDisposedRule by AppControlHost
 * @tc.desc: 1.HandleSetUninstallDisposedRule test
 */
HWTEST_F(BmsAppControlHostTest, HandleSetUninstallDisposedRule_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleSetUninstallDisposedRule(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetUninstallDisposedRule_0100
 * @tc.name: Test HandleGetUninstallDisposedRule by AppControlHost
 * @tc.desc: 1.HandleGetUninstallDisposedRule test
 */
HWTEST_F(BmsAppControlHostTest, HandleGetUninstallDisposedRule_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleGetUninstallDisposedRule(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleDeleteUninstallDisposedRule_0100
 * @tc.name: Test HandleDeleteUninstallDisposedRule by AppControlHost
 * @tc.desc: 1.HandleDeleteUninstallDisposedRule test
 */
HWTEST_F(BmsAppControlHostTest, HandleDeleteUninstallDisposedRule_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<AppControlHost> appControlHost = std::make_shared<AppControlHost>();
    ASSERT_NE(appControlHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlHost->HandleDeleteUninstallDisposedRule(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: test the OnRemoteRequest
 * @tc.desc: 1. system running normally
 *           2. test OnRemoteRequest
 */
HWTEST_F(BmsAppControlHostTest, OnRemoteRequest_0100, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ErrCode res = appControlHost.OnRemoteRequest(
        static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_DISPOSED_RULE_FOR_CLONE_APP), data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL);
}

/**
 * @tc.number: HandleDeleteDisposedRuleForCloneApp_0100
 * @tc.name: test the HandleDeleteDisposedRuleForCloneApp
 * @tc.desc: 1. system running normally
 *           2. test HandleDeleteDisposedRuleForCloneApp
 */
HWTEST_F(BmsAppControlHostTest, HandleDeleteDisposedRuleForCloneApp_0100, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleDeleteDisposedRuleForCloneApp(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: WriteStringVector_0100
 * @tc.name: test the WriteStringVector
 * @tc.desc: 1. system running normally
 *           2. test WriteStringVector
 */
HWTEST_F(BmsAppControlHostTest, WriteStringVector_0100, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    std::vector<std::string> stringVector;
    MessageParcel reply;
    ErrCode res = appControlHost.WriteStringVector(stringVector, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleGetDisposedRuleForCloneApp_0100
 * @tc.name: test the HandleGetDisposedRuleForCloneApp
 * @tc.desc: 1. system running normally
 *           2. test HandleGetDisposedRuleForCloneApp
 */
HWTEST_F(BmsAppControlHostTest, HandleGetDisposedRuleForCloneApp_0100, Function | MediumTest | Level0)
{
    AppControlHost appControlHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = appControlHost.HandleGetDisposedRuleForCloneApp(data, reply);
    EXPECT_EQ(res, ERR_OK);
}
} // AppExecFwk
} // OHOS