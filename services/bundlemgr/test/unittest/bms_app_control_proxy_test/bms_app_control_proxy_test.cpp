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

#include <fstream>
#include <future>
#include <gtest/gtest.h>
#define private public
#include "app_control_proxy.h"
#undef private
#include "want.h"

using namespace testing::ext;

using OHOS::AAFwk::Want;

namespace OHOS {

class MockRemoteObject : public IRemoteObject {
public:
    explicit MockRemoteObject(const std::u16string& descriptor = u"MockDescriptor")
        : IRemoteObject(descriptor) {}
    int32_t GetObjectRefCount()
    {
        return ERR_OK;
    }
    int32_t SendRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
    {
        return ERR_OK;
    }
    bool AddDeathRecipient(const sptr<DeathRecipient>& recipient)
    {
        return ERR_OK;
    }
    bool RemoveDeathRecipient(const sptr<DeathRecipient>& recipient)
    {
        return ERR_OK;
    }
    int Dump(int fd, const std::vector<std::u16string>& args)
    {
        return ERR_OK;
    }
};

namespace AppExecFwk {

class BmsAppControlProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsAppControlProxyTest::SetUpTestCase()
{}

void BmsAppControlProxyTest::TearDownTestCase()
{}

void BmsAppControlProxyTest::SetUp()
{}

void BmsAppControlProxyTest::TearDown()
{}

/**
 * @tc.number: AddAppInstallControlRule_0100
 * @tc.name: test the AddAppInstallControlRule
 * @tc.desc: 1. appIds is empty
 *           2. test AddAppInstallControlRule
 */
HWTEST_F(BmsAppControlProxyTest, AddAppInstallControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::vector<std::string> appIds;
    AppInstallControlRuleType controlRuleType = AppInstallControlRuleType::UNSPECIFIED;
    int32_t userId = 100;
    auto res = appControlProxy.AddAppInstallControlRule(appIds, controlRuleType, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AddAppInstallControlRule_0200
 * @tc.name: test the AddAppInstallControlRule
 * @tc.desc: 1. system running normally
 *           2. test AddAppInstallControlRule
 */
HWTEST_F(BmsAppControlProxyTest, AddAppInstallControlRule_0200, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::vector<std::string> appIds;
    std::string appId = "appId";
    appIds.emplace_back(appId);
    AppInstallControlRuleType controlRuleType = AppInstallControlRuleType::UNSPECIFIED;
    int32_t userId = 100;
    auto res = appControlProxy.AddAppInstallControlRule(appIds, controlRuleType, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: DeleteAppInstallControlRule_0100
 * @tc.name: test the DeleteAppInstallControlRule
 * @tc.desc: 1. appIds is empty
 *           2. test DeleteAppInstallControlRule
 */
HWTEST_F(BmsAppControlProxyTest, DeleteAppInstallControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::vector<std::string> appIds;
    AppInstallControlRuleType controlRuleType = AppInstallControlRuleType::UNSPECIFIED;
    int32_t userId = 100;
    auto res = appControlProxy.DeleteAppInstallControlRule(controlRuleType, appIds, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: DeleteAppInstallControlRule_0200
 * @tc.name: test the DeleteAppInstallControlRule
 * @tc.desc: 1. system running normally
 *           2. test DeleteAppInstallControlRule
 */
HWTEST_F(BmsAppControlProxyTest, DeleteAppInstallControlRule_0200, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::vector<std::string> appIds;
    std::string appId = "appId";
    appIds.emplace_back(appId);
    AppInstallControlRuleType controlRuleType = AppInstallControlRuleType::UNSPECIFIED;
    int32_t userId = 100;
    auto res = appControlProxy.DeleteAppInstallControlRule(controlRuleType, appIds, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsDeleteAppInstallControlRule_0100
 * @tc.name: test the DeleteAppInstallControlRule
 * @tc.desc: 1. system running normally
 *           2. test DeleteAppInstallControlRule
 */
HWTEST_F(BmsAppControlProxyTest, BmsDeleteAppInstallControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    AppInstallControlRuleType controlRuleType = AppInstallControlRuleType::UNSPECIFIED;
    int32_t userId = 100;
    auto res = appControlProxy.DeleteAppInstallControlRule(controlRuleType, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetAppInstallControlRule_0100
 * @tc.name: test the GetAppInstallControlRule
 * @tc.desc: 1. system running normally
 *           2. test GetAppInstallControlRule
 */
HWTEST_F(BmsAppControlProxyTest, GetAppInstallControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    AppInstallControlRuleType controlRuleType = AppInstallControlRuleType::UNSPECIFIED;
    int32_t userId = 100;
    std::vector<std::string> appIds;
    auto res = appControlProxy.GetAppInstallControlRule(controlRuleType, userId, appIds);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: AddAppRunningControlRule_0100
 * @tc.name: test the AddAppRunningControlRule
 * @tc.desc: 1. controlRules is empty
 *           2. test AddAppRunningControlRule
 */
HWTEST_F(BmsAppControlProxyTest, AddAppRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::vector<AppRunningControlRule> controlRules;
    int32_t userId = 100;
    auto res = appControlProxy.AddAppRunningControlRule(controlRules, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AddAppRunningControlRule_0200
 * @tc.name: test the AddAppRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test AddAppRunningControlRule
 */
HWTEST_F(BmsAppControlProxyTest, AddAppRunningControlRule_0200, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule appRunningControlRule;
    controlRules.emplace_back(appRunningControlRule);
    int32_t userId = 100;
    auto res = appControlProxy.AddAppRunningControlRule(controlRules, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: DeleteAppRunningControlRule_0100
 * @tc.name: test the DeleteAppRunningControlRule
 * @tc.desc: 1. controlRules is empty
 *           2. test DeleteAppRunningControlRule
 */
HWTEST_F(BmsAppControlProxyTest, DeleteAppRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::vector<AppRunningControlRule> controlRules;
    int32_t userId = 100;
    auto res = appControlProxy.DeleteAppRunningControlRule(controlRules, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: DeleteAppRunningControlRule_0200
 * @tc.name: test the DeleteAppRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test DeleteAppRunningControlRule
 */
HWTEST_F(BmsAppControlProxyTest, DeleteAppRunningControlRule_0200, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::vector<AppRunningControlRule> controlRules;
    AppRunningControlRule appRunningControlRule;
    controlRules.emplace_back(appRunningControlRule);
    int32_t userId = 100;
    auto res = appControlProxy.DeleteAppRunningControlRule(controlRules, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsDeleteAppRunningControlRule_0100
 * @tc.name: test the DeleteAppRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test DeleteAppRunningControlRule
 */
HWTEST_F(BmsAppControlProxyTest, BmsDeleteAppRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    auto res = appControlProxy.DeleteAppRunningControlRule(userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetAppRunningControlRule_0100
 * @tc.name: test the GetAppRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test GetAppRunningControlRule
 */
HWTEST_F(BmsAppControlProxyTest, GetAppRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::vector<std::string> appIds;
    auto res = appControlProxy.GetAppRunningControlRule(userId, appIds);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsGetAppRunningControlRule_0100
 * @tc.name: test the GetAppRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test GetAppRunningControlRule
 */
HWTEST_F(BmsAppControlProxyTest, BmsGetAppRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::string bundleName;
    AppRunningControlRuleResult controlRuleResult;
    auto res = appControlProxy.GetAppRunningControlRule(bundleName, userId, controlRuleResult);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: ConfirmAppJumpControlRule_0100
 * @tc.name: test the ConfirmAppJumpControlRule
 * @tc.desc: 1. bundleName is empty
 *           2. test ConfirmAppJumpControlRule
 */
HWTEST_F(BmsAppControlProxyTest, ConfirmAppJumpControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::string callerBundleName;
    const std::string targetBundleName;
    auto res = appControlProxy.ConfirmAppJumpControlRule(callerBundleName, targetBundleName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: ConfirmAppJumpControlRule_0200
 * @tc.name: test the ConfirmAppJumpControlRule
 * @tc.desc: 1. system running normally
 *           2. test ConfirmAppJumpControlRule
 */
HWTEST_F(BmsAppControlProxyTest, ConfirmAppJumpControlRule_0200, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::string callerBundleName = "callerBundleName";
    const std::string targetBundleName = "targetBundleName";
    auto res = appControlProxy.ConfirmAppJumpControlRule(callerBundleName, targetBundleName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: AddAppJumpControlRule_0100
 * @tc.name: test the AddAppJumpControlRule
 * @tc.desc: 1. bundleName is empty
 *           2. test AddAppJumpControlRule
 */
HWTEST_F(BmsAppControlProxyTest, AddAppJumpControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::vector<AppJumpControlRule> controlRules;
    auto res = appControlProxy.AddAppJumpControlRule(controlRules, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AddAppJumpControlRule_0200
 * @tc.name: test the AddAppJumpControlRule
 * @tc.desc: 1. system running normally
 *           2. test AddAppJumpControlRule
 */
HWTEST_F(BmsAppControlProxyTest, AddAppJumpControlRule_0200, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::vector<AppJumpControlRule> controlRules;
    AppJumpControlRule appJumpControlRule;
    controlRules.emplace_back(appJumpControlRule);
    auto res = appControlProxy.AddAppJumpControlRule(controlRules, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: DeleteAppJumpControlRule_0100
 * @tc.name: test the DeleteAppJumpControlRule
 * @tc.desc: 1. system running normally
 *           2. test DeleteAppJumpControlRule
 */
HWTEST_F(BmsAppControlProxyTest, DeleteAppJumpControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::vector<AppJumpControlRule> controlRules;
    AppJumpControlRule appJumpControlRule;
    controlRules.emplace_back(appJumpControlRule);
    auto res = appControlProxy.DeleteAppJumpControlRule(controlRules, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: DeleteRuleByCallerBundleName_0100
 * @tc.name: test the DeleteRuleByCallerBundleName
 * @tc.desc: 1. system running normally
 *           2. test DeleteRuleByCallerBundleName
 */
HWTEST_F(BmsAppControlProxyTest, DeleteRuleByCallerBundleName_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::string callerBundleName = "callerBundleName";
    auto res = appControlProxy.DeleteRuleByCallerBundleName(callerBundleName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: DeleteRuleByTargetBundleName_0100
 * @tc.name: test the DeleteRuleByTargetBundleName
 * @tc.desc: 1. system running normally
 *           2. test DeleteRuleByTargetBundleName
 */
HWTEST_F(BmsAppControlProxyTest, DeleteRuleByTargetBundleName_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::string targetBundleName = "targetBundleName";
    auto res = appControlProxy.DeleteRuleByTargetBundleName(targetBundleName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetAppJumpControlRule_0100
 * @tc.name: test the GetAppJumpControlRule
 * @tc.desc: 1. system running normally
 *           2. test GetAppJumpControlRule
 */
HWTEST_F(BmsAppControlProxyTest, GetAppJumpControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    int32_t userId = 100;
    std::string callerBundleName = "callerBundleName";
    std::string targetBundleName = "targetBundleName";
    std::vector<AppRunningControlRule> controlRules;
    AppJumpControlRule appJumpControlRule;
    auto res = appControlProxy.GetAppJumpControlRule(callerBundleName, targetBundleName, userId, appJumpControlRule);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: SetDisposedStatus_0100
 * @tc.name: test the SetDisposedStatus
 * @tc.desc: 1. system running normally
 *           2. test SetDisposedStatus
 */
HWTEST_F(BmsAppControlProxyTest, SetDisposedStatus_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::string appId = "appId";
    Want want;
    int32_t userId = 100;
    auto res = appControlProxy.SetDisposedStatus(appId, want, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: DeleteDisposedStatus_0100
 * @tc.name: test the DeleteDisposedStatus
 * @tc.desc: 1. system running normally
 *           2. test DeleteDisposedStatus
 */
HWTEST_F(BmsAppControlProxyTest, DeleteDisposedStatus_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::string appId = "appId";
    int32_t userId = 100;
    auto res = appControlProxy.DeleteDisposedStatus(appId, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetDisposedStatus_0100
 * @tc.name: test the GetDisposedStatus
 * @tc.desc: 1. system running normally
 *           2. test GetDisposedStatus
 */
HWTEST_F(BmsAppControlProxyTest, GetDisposedStatus_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::string appId = "appId";
    Want want;
    int32_t userId = 100;
    auto res = appControlProxy.GetDisposedStatus(appId, want, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: SetDisposedRule_0100
 * @tc.name: test the SetDisposedRule
 * @tc.desc: 1. system running normally
 *           2. test SetDisposedRule
 */
HWTEST_F(BmsAppControlProxyTest, SetDisposedRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::string appId = "appId";
    DisposedRule disposedRule;
    int32_t userId = 100;
    auto res = appControlProxy.SetDisposedRule(appId, disposedRule, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetDisposedRule_0100
 * @tc.name: test the GetDisposedRule
 * @tc.desc: 1. system running normally
 *           2. test GetDisposedRule
 */
HWTEST_F(BmsAppControlProxyTest, GetDisposedRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::string appId = "appId";
    DisposedRule disposedRule;
    int32_t userId = 100;
    auto res = appControlProxy.GetDisposedRule(appId, disposedRule, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetAbilityRunningControlRule_0100
 * @tc.name: test the GetAbilityRunningControlRule
 * @tc.desc: 1. system running normally
 *           2. test GetAbilityRunningControlRule
 */
HWTEST_F(BmsAppControlProxyTest, GetAbilityRunningControlRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    DisposedRule disposedRule;
    int32_t userId = 100;
    std::string bundleName = "bundleName";
    std::vector<DisposedRule> rules;
    rules.emplace_back(disposedRule);
    auto res = appControlProxy.GetAbilityRunningControlRule(bundleName, userId, rules);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: SetDisposedRuleForCloneApp_0100
 * @tc.name: test the SetDisposedRuleForCloneApp
 * @tc.desc: 1. system running normally
 *           2. test SetDisposedRuleForCloneApp
 */
HWTEST_F(BmsAppControlProxyTest, SetDisposedRuleForCloneApp_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    DisposedRule disposedRule;
    std::string appId = "appId";
    int32_t userId = 100;
    int32_t appIndex = 0;
    auto res = appControlProxy.SetDisposedRuleForCloneApp(appId, disposedRule, appIndex, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetDisposedRuleForCloneApp_0100
 * @tc.name: test the GetDisposedRuleForCloneApp
 * @tc.desc: 1. system running normally
 *           2. test GetDisposedRuleForCloneApp
 */
HWTEST_F(BmsAppControlProxyTest, GetDisposedRuleForCloneApp_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    DisposedRule disposedRule;
    std::string appId = "appId";
    int32_t userId = 100;
    int32_t appIndex = 0;
    auto res = appControlProxy.GetDisposedRuleForCloneApp(appId, disposedRule, appIndex, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: DeleteDisposedRuleForCloneApp_0100
 * @tc.name: test the DeleteDisposedRuleForCloneApp
 * @tc.desc: 1. system running normally
 *           2. test DeleteDisposedRuleForCloneApp
 */
HWTEST_F(BmsAppControlProxyTest, DeleteDisposedRuleForCloneApp_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::string appId = "appId";
    int32_t userId = 100;
    int32_t appIndex = 0;
    auto res = appControlProxy.DeleteDisposedRuleForCloneApp(appId, appIndex, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: WriteStringVector_0100
 * @tc.name: test the WriteStringVector
 * @tc.desc: 1. stringVector is empty
 *           2. test WriteStringVector
 */
HWTEST_F(BmsAppControlProxyTest, WriteStringVector_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::vector<std::string> stringVector;
    MessageParcel data;
    auto res = appControlProxy.WriteStringVector(stringVector, data);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetParcelableInfos_0100
 * @tc.name: test the GetParcelableInfos
 * @tc.desc: 1. system running normally
 *           2. test GetParcelableInfos
 */
HWTEST_F(BmsAppControlProxyTest, GetParcelableInfos_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    AppControlManagerInterfaceCode code = AppControlManagerInterfaceCode::DELETE_APP_INSTALL_CONTROL_RULE;
    MessageParcel data;
    std::vector<std::string> stringVector;
    auto res = appControlProxy.GetParcelableInfos(code, data, stringVector);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: SendRequest_0100
 * @tc.name: test the SendRequest
 * @tc.desc: 1. system running normally
 *           2. test SendRequest
 */
HWTEST_F(BmsAppControlProxyTest, SendRequest_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    AppControlManagerInterfaceCode code = AppControlManagerInterfaceCode::DELETE_APP_INSTALL_CONTROL_RULE;
    MessageParcel data;
    MessageParcel reply;
    auto res = appControlProxy.SendRequest(code, data, reply);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: DeleteUninstallDisposedRule_0100
 * @tc.name: test the DeleteUninstallDisposedRule
 * @tc.desc: 1. system running normally
 *           2. test DeleteUninstallDisposedRule
 */
HWTEST_F(BmsAppControlProxyTest, DeleteUninstallDisposedRule_0100, Function | MediumTest | Level1)
{
    AppControlProxy appControlProxy(nullptr);
    std::string appId = "DeleteUninstallDisposedRule";
    int32_t appIndex =  1234;
    int32_t userId = 1234;
    auto res = appControlProxy.DeleteUninstallDisposedRule(appId, appIndex, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: SetDisposedStatus_0200
 * @tc.name: test the SetDisposedStatus
 * @tc.desc: 1. system running normally
 *           2. test SetDisposedStatus
 */
HWTEST_F(BmsAppControlProxyTest, SetDisposedStatus_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> mockRemoteObject = new MockRemoteObject();
    AppControlProxy appControlProxy(mockRemoteObject);
    std::string appId = "appId";
    Want want;
    int32_t userId = 100;
    auto res = appControlProxy.SetDisposedStatus(appId, want, userId);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: DeleteDisposedStatus_0200
 * @tc.name: test the DeleteDisposedStatus
 * @tc.desc: 1. system running normally
 *           2. test DeleteDisposedStatus
 */
HWTEST_F(BmsAppControlProxyTest, DeleteDisposedStatus_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> mockRemoteObject = new MockRemoteObject();
    AppControlProxy appControlProxy(mockRemoteObject);
    std::string appId = "appId";
    Want want;
    int32_t userId = 100;
    auto res = appControlProxy.DeleteDisposedStatus(appId, userId);
    EXPECT_EQ(res, ERR_OK);
}
/**
 * @tc.number: SetDisposedRule_0200
 * @tc.name: test the SetDisposedRule
 * @tc.desc: 1. system running normally
 *           2. test SetDisposedRule
 */
HWTEST_F(BmsAppControlProxyTest, SetDisposedRule_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> mockRemoteObject = new MockRemoteObject();
    AppControlProxy appControlProxy(mockRemoteObject);
    std::string appId = "appId";
    DisposedRule disposedRule;
    int32_t userId = 100;
    auto res = appControlProxy.SetDisposedRule(appId, disposedRule, userId);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: SetDisposedRuleForCloneApp_0200
 * @tc.name: test the SetDisposedRuleForCloneApp
 * @tc.desc: 1. system running normally
 *           2. test SetDisposedRuleForCloneApp
 */
HWTEST_F(BmsAppControlProxyTest, SetDisposedRuleForCloneApp_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> mockRemoteObject = new MockRemoteObject();
    AppControlProxy appControlProxy(mockRemoteObject);
    std::string appId = "appId";
    DisposedRule disposedRule;
    int32_t appIndex = 0;
    int32_t userId = 100;
    auto result = appControlProxy.SetDisposedRuleForCloneApp(appId, disposedRule, appIndex, userId);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: DeleteDisposedRuleForCloneApp_0200
 * @tc.name: test the DeleteDisposedRuleForCloneApp
 * @tc.desc: 1. system running normally
 *           2. test DeleteDisposedRuleForCloneApp
 */
HWTEST_F(BmsAppControlProxyTest, DeleteDisposedRuleForCloneApp_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> mockRemoteObject = new MockRemoteObject();
    AppControlProxy appControlProxy(mockRemoteObject);
    std::string appId = "appId";
    int32_t appIndex = 0;
    int32_t userId = 100;
    auto result = appControlProxy.DeleteDisposedRuleForCloneApp(appId, appIndex, userId);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: SetUninstallDisposedRule_0200
 * @tc.name: test the SetUninstallDisposedRule
 * @tc.desc: 1. system running normally
 *           2. test SetUninstallDisposedRule
 */
HWTEST_F(BmsAppControlProxyTest, SetUninstallDisposedRule_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> mockRemoteObject = new MockRemoteObject();
    AppControlProxy appControlProxy(mockRemoteObject);
    std::string appId = "appId";
    UninstallDisposedRule rule;
    int32_t appIndex = 0;
    int32_t userId = 100;
    auto result = appControlProxy.SetUninstallDisposedRule(appId, rule, appIndex, userId);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: DeleteUninstallDisposedRule_0200
 * @tc.name: test the DeleteUninstallDisposedRule
 * @tc.desc: 1. system running normally
 *           2. test DeleteUninstallDisposedRule
 */
HWTEST_F(BmsAppControlProxyTest, DeleteUninstallDisposedRule_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> mockRemoteObject = new MockRemoteObject();
    AppControlProxy appControlProxy(mockRemoteObject);
    std::string appId = "appId";
    int32_t appIndex = 0;
    int32_t userId = 100;
    auto result = appControlProxy.DeleteUninstallDisposedRule(appId, appIndex, userId);
    EXPECT_EQ(result, ERR_OK);
}
} // AppExecFwk
} // OHOS