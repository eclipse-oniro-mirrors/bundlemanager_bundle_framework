/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>

#include "app_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_ext_client.h"
#include "bundle_mgr_ext_proxy.h"
#include "bundle_mgr_ext_stub.h"
#include "bundle_mgr_ext_host_impl.h"
#include "bundle_mgr_ext_register.h"
#include "bms_extension_data_mgr.h"
#include "bundle_permission_mgr.h"
#include "bundle_mgr_service.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
    constexpr int32_t REMOTE_RESULT = 8585601;
}

namespace OHOS {
class BmsBundleMgrExtTest : public testing::Test {
public:
    BmsBundleMgrExtTest();
    ~BmsBundleMgrExtTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static sptr<BundleMgrProxy> GetBundleMgrProxy();
};

BmsBundleMgrExtTest::BmsBundleMgrExtTest()
{}

BmsBundleMgrExtTest::~BmsBundleMgrExtTest()
{}

void BmsBundleMgrExtTest::SetUpTestCase()
{}

void BmsBundleMgrExtTest::TearDownTestCase()
{}

void BmsBundleMgrExtTest::SetUp()
{}

void BmsBundleMgrExtTest::TearDown()
{}

class MockBundleMgrExtStub : public BundleMgrExtStub {
public:
    int32_t CallbackEnter(uint32_t code) override
    {
        return 0;
    }
    int32_t CallbackExit(uint32_t code, int32_t result) override
    {
        return 0;
    }
    ErrCode GetBundleNamesForUidExt(const int32_t uid, std::vector<std::string> &bundleNames,
        int32_t &funcResult) override
    {
        return ERR_OK;
    }
};

sptr<BundleMgrProxy> BmsBundleMgrExtTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        APP_LOGE("fail to get system ability mgr");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        APP_LOGE("fail to get bundle manager proxy");
        return nullptr;
    }

    APP_LOGI("get bundle manager proxy success");
    return iface_cast<BundleMgrProxy>(remoteObject);
}

/**
 * @tc.number: IsMCFlagSet_0100
 * @tc.name: IsMCFlagSet_0100
 * @tc.desc: test IsMCFlagSet
 */
HWTEST_F(BmsBundleMgrExtTest, IsMCFlagSet_0100, Function | SmallTest | Level1)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    auto tmpMap = BundleMgrExtRegister::GetInstance().bundleMgrExts_;
    BundleMgrExtRegister::GetInstance().bundleMgrExts_.clear();

    bool ret = bmsExtensionDataMgr.IsMCFlagSet();
    EXPECT_FALSE(ret);

    BundleMgrExtRegister::GetInstance().bundleMgrExts_ = tmpMap;
}

/**
 * @tc.number: GetBundleNamesForUidExtProxy_0100
 * @tc.name: GetBundleNamesForUidExtProxy_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtTest, GetBundleNamesForUidExtProxy_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IBundleMgrExt> bundleMgrExtProxy = bundleMgrProxy->GetBundleMgrExtProxy();
    ASSERT_NE(bundleMgrExtProxy, nullptr);

    int32_t uid = 111;
    std::vector<std::string> bundleNames;
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    auto ret = bundleMgrExtProxy->GetBundleNamesForUidExt(uid, bundleNames, funcResult);
    EXPECT_EQ(ret, ERR_OK);
#if defined(USE_ARM64) && defined(CONTAIN_BROKER_CLIENT_ENABLED)
    EXPECT_THAT(ret, testing::AnyOf(ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY, REMOTE_RESULT));
#else
    EXPECT_EQ(funcResult, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
#endif
    EXPECT_EQ(bundleNames.empty(), true);
}

/**
 * @tc.number: GetBundleNamesForUidExtClient_0100
 * @tc.name: GetBundleNamesForUidExtClient_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtTest, GetBundleNamesForUidExtClient_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    sptr<IBundleMgrExt> bundleMgrExtProxy = bundleMgrProxy->GetBundleMgrExtProxy();
    ASSERT_NE(bundleMgrExtProxy, nullptr);
    BundleMgrExtClient::GetInstance().bundleMgrExtProxy_ = bundleMgrExtProxy;

    int32_t uid = 111;
    std::vector<std::string> bundleNames;
    auto ret = BundleMgrExtClient::GetInstance().GetBundleNamesForUidExt(uid, bundleNames);
#if defined(USE_ARM64) && defined(CONTAIN_BROKER_CLIENT_ENABLED)
    EXPECT_THAT(ret, testing::AnyOf(ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY, REMOTE_RESULT));
#else
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
#endif
    EXPECT_EQ(bundleNames.empty(), true);
}

/**
 * @tc.number: GetBundleNamesForUidExtStub_0100
 * @tc.name: GetBundleNamesForUidExtStub_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtTest, GetBundleNamesForUidExtStub_0100, Function | SmallTest | Level1)
{
    MockBundleMgrExtStub stub;
    MessageParcel data;
    data.WriteInt32(111);
    MessageParcel reply;

    MessageOption option(MessageOption::TF_SYNC);
    ErrCode ret = stub.OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, TRANSACTION_ERR);
}

/**
 * @tc.number: GetBundleNamesForUidExtImpl_0100
 * @tc.name: GetBundleNamesForUidExtImpl_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtTest, GetBundleNamesForUidExtImpl_0100, Function | SmallTest | Level1)
{
    BundleMgrExtHostImpl impl;
    int32_t uid = 111;
    std::vector<std::string> bundleNames;
    int32_t funcResult = 0;
    ErrCode ret = impl.GetBundleNamesForUidExt(uid, bundleNames, funcResult);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(funcResult, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: GetBundleNamesForUidExt_0100
 * @tc.name: GetBundleNamesForUidExt_0100
 * @tc.desc: test GetBundleNamesForUidExt
 */
HWTEST_F(BmsBundleMgrExtTest, GetBundleNamesForUidExt_0100, Function | SmallTest | Level1)
{
    int32_t uid = 111;
    std::vector<std::string> bundleNames;
    BmsExtensionDataMgr bmsExtensionDataMgr;
    ErrCode ret = bmsExtensionDataMgr.GetBundleNamesForUidExt(uid, bundleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: OnRemoteDied_0100
 * @tc.name: OnRemoteDied_0100
 * @tc.desc: test OnRemoteDied
 */
HWTEST_F(BmsBundleMgrExtTest, OnRemoteDied_0100, Function | SmallTest | Level1)
{
    BundleMgrExtClient::GetInstance().bundleMgrExtProxy_ = nullptr;
    BundleMgrExtClient::GetInstance().deathRecipient_ = nullptr;
    wptr<OHOS::IRemoteObject> remote = nullptr;
    BundleMgrExtClient::BundleMgrExtDeathRecipient deathRecipient;
    auto bundleMgrExtProxy = BundleMgrExtClient::GetInstance().GetBundleMgrExtProxy();
    EXPECT_NE(bundleMgrExtProxy, nullptr);
    deathRecipient.OnRemoteDied(remote);
    EXPECT_NE(BundleMgrExtClient::GetInstance().bundleMgrExtProxy_, nullptr);
    EXPECT_NE(BundleMgrExtClient::GetInstance().deathRecipient_, nullptr);

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    remote = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remote, nullptr);
    deathRecipient.OnRemoteDied(remote);
    EXPECT_EQ(BundleMgrExtClient::GetInstance().bundleMgrExtProxy_, nullptr);
    EXPECT_EQ(BundleMgrExtClient::GetInstance().deathRecipient_, nullptr);
}

/**
 * @tc.number: ResetBundleMgrExtProxy_0010
 * @tc.name: test ResetBundleMgrExtProxy
 * @tc.desc: 1.ResetBundleMgrExtProxy
 */
HWTEST_F(BmsBundleMgrExtTest, ResetBundleMgrExtProxy_0010, Function | SmallTest | Level1)
{
    BundleMgrExtClient::GetInstance().bundleMgrExtProxy_ = nullptr;
    wptr<IRemoteObject> remote;
    BundleMgrExtClient::GetInstance().ResetBundleMgrExtProxy(remote);
    EXPECT_NE(BundleMgrExtClient::GetInstance().GetBundleMgrExtProxy(), nullptr);
    BundleMgrExtClient::GetInstance().ResetBundleMgrExtProxy(remote);
    EXPECT_EQ(BundleMgrExtClient::GetInstance().deathRecipient_, nullptr);
}
} // OHOS