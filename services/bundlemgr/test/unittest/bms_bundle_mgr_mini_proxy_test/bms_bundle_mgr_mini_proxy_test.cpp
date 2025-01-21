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

#include <gtest/gtest.h>

#include "bundle_error.h"
#include "bundle_mgr_mini_proxy.h"
#include "appexecfwk_errors.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class MockBundleMgrMiniProxy : public BundleMgrMiniProxy {
public:
    explicit MockBundleMgrMiniProxy(const sptr<IRemoteObject>& impl) : BundleMgrMiniProxy(impl) {};

    ~MockBundleMgrMiniProxy() {};

    ErrCode GetNameForUid(const int uid, std::string& name) override
    {
        if (name == "nameTest" && uid == 0) {
            return CJSystemapi::BundleManager::SUCCESS_CODE;
        }
        return CJSystemapi::BundleManager::ERROR_PARAM_CHECK_ERROR;
    }

    std::string GetAppIdByBundleName(const std::string& bundleName, const int userId) override
    {
        std::string name = "";
        if (bundleName == "bundleNameTest" && userId == 0) {
            name = "GetAppIdByBundleNameTest";
        }
        return name;
    }

    int GetUidByBundleName(const std::string& bundleName, const int userId) override
    {
        int ret = 0;
        if (bundleName == "bundleNameTest" && userId == 0) {
            ret = 1;
        }
        return ret;
    }

    int32_t GetUidByBundleName(const std::string& bundleName, const int32_t userId, int32_t appIndex) override
    {
        int32_t ret = 0;
        if (bundleName == "bundleNameTest" && userId == 0 && appIndex == 0) {
            ret = 1;
        }

        return ret;
    }
};

class BundleMgrMiniProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    static sptr<BundleMgrMiniProxy> GetBundleMgrProxy();
    void SetUp() {};
    void TearDown() {};
};


sptr<BundleMgrMiniProxy> BundleMgrMiniProxyTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        std::cout << "fail to get system ability mgr" << std::endl;
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        std::cout << "fail to get bundle manager proxy" << std::endl;
        return nullptr;
    }

    std::cout << "get bundle manager min proxy success" << std::endl;
    return iface_cast<BundleMgrMiniProxy>(remoteObject);
}

/**
 * @tc.number: BundleMgrMiniProxy_0001
 * @tc.name: GetNameForUid
 * @tc.desc: GetNameForUid
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_0001, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    MockBundleMgrMiniProxy bundleleMgrMiniProxyTest(impl);
    int32_t uid = 0;
    std::string name = "nameTest";
    EXPECT_EQ(bundleleMgrMiniProxyTest.GetNameForUid(uid, name), CJSystemapi::BundleManager::SUCCESS_CODE);
}

/**
 * @tc.number: BundleMgrMiniProxy_0002
 * @tc.name: GetAppIdByBundleName
 * @tc.desc: GetAppIdByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_0002, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    MockBundleMgrMiniProxy bundleleMgrMiniProxyTest(impl);
    int32_t userId = 0;
    std::string bundleName = "bundleNameTest";
    std::string name = bundleleMgrMiniProxyTest.GetAppIdByBundleName(bundleName, userId);
    EXPECT_EQ(name, "GetAppIdByBundleNameTest");
}

/**
 * @tc.number: BundleMgrMiniProxy_0003
 * @tc.name: GetUidByBundleName
 * @tc.desc: GetUidByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_0003, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    MockBundleMgrMiniProxy bundleleMgrMiniProxyTest(impl);
    int32_t userId = 0;
    std::string bundleName = "bundleNameTest";
    int ret = bundleleMgrMiniProxyTest.GetUidByBundleName(bundleName, userId);
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.number: BundleMgrMiniProxy_0004
 * @tc.name: GetUidByBundleName
 * @tc.desc: GetUidByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_0004, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    MockBundleMgrMiniProxy bundleleMgrMiniProxyTest(impl);
    int32_t userId = 0;
    int32_t appIndex = 0;
    std::string bundleName = "bundleNameTest";
    int32_t ret = bundleleMgrMiniProxyTest.GetUidByBundleName(bundleName, userId, appIndex);
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.number: BundleMgrMiniProxy_0005
 * @tc.name: GetNameForUid
 * @tc.desc: GetNameForUid
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_0005, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    MockBundleMgrMiniProxy bundleMgr(impl);
    int uid = 10008;
    std::string name = "com.ohos.systemui";
    auto ret = bundleMgr.GetNameForUid(uid, name);
    EXPECT_NE(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: BundleMgrMiniProxy_0006
 * @tc.name: GetAppIdByBundleName
 * @tc.desc: GetAppIdByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_0006, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    MockBundleMgrMiniProxy bundleMgr(impl);
    std::string bundleName = "com.ohos.systemui";
    int userId = 100;
    auto ret = bundleMgr.GetAppIdByBundleName(bundleName, userId);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BundleMgrMiniProxy_0007
 * @tc.name: GetUidByBundleName
 * @tc.desc: GetUidByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_0007, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    MockBundleMgrMiniProxy bundleMgr(impl);
    std::string bundleName = "com.ohos.systemui";
    int userId = 10008;
    auto ret = bundleMgr.GetUidByBundleName(bundleName, userId);
    EXPECT_NE(ret, Constants::INVALID_UID);
}

/**
 * @tc.number: BundleMgrMiniProxy_1001
 * @tc.name: GetNameForUid
 * @tc.desc: GetNameForUid
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_1001, Function | SmallTest | Level0)
{
    sptr<BundleMgrMiniProxy> bundleMgrMiniProxy = GetBundleMgrProxy();
    if (!bundleMgrMiniProxy) {
        std::cout << "bundle mgr min proxy is nullptr" << std::endl;
        EXPECT_EQ(bundleMgrMiniProxy, nullptr);
    }
    int32_t uid = 0;
    std::string name = "nameTest";
    EXPECT_EQ(bundleMgrMiniProxy->GetNameForUid(uid, name), ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: BundleMgrMiniProxy_1002
 * @tc.name: GetAppIdByBundleName
 * @tc.desc: GetAppIdByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_1002, Function | SmallTest | Level0)
{
    sptr<BundleMgrMiniProxy> bundleMgrMiniProxy = GetBundleMgrProxy();
    if (!bundleMgrMiniProxy) {
        std::cout << "bundle mgr min proxy is nullptr" << std::endl;
        EXPECT_EQ(bundleMgrMiniProxy, nullptr);
    }
    int32_t userId = 0;
    std::string bundleName = "bundleNameTest";
    std::string name = bundleMgrMiniProxy->GetAppIdByBundleName(bundleName, userId);
    EXPECT_EQ(name, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BundleMgrMiniProxy_1003
 * @tc.name: GetUidByBundleName
 * @tc.desc: GetUidByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_1003, Function | SmallTest | Level0)
{
    sptr<BundleMgrMiniProxy> bundleMgrMiniProxy = GetBundleMgrProxy();
    if (!bundleMgrMiniProxy) {
        std::cout << "bundle mgr min proxy is nullptr" << std::endl;
        EXPECT_EQ(bundleMgrMiniProxy, nullptr);
    }
    int32_t userId = 0;
    std::string bundleName = "bundleNameTest";
    int ret = bundleMgrMiniProxy->GetUidByBundleName(bundleName, userId);
    EXPECT_EQ(ret, Constants::INVALID_UID);
}

/**
 * @tc.number: BundleMgrMiniProxy_1004
 * @tc.name: GetUidByBundleName
 * @tc.desc: GetUidByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_1004, Function | SmallTest | Level0)
{
    sptr<BundleMgrMiniProxy> bundleMgrMiniProxy = GetBundleMgrProxy();
    if (!bundleMgrMiniProxy) {
        std::cout << "bundle mgr min proxy is nullptr" << std::endl;
        EXPECT_EQ(bundleMgrMiniProxy, nullptr);
    }
    int32_t userId = 0;
    int32_t appIndex = 0;
    std::string bundleName = "bundleNameTest";
    int32_t ret = bundleMgrMiniProxy->GetUidByBundleName(bundleName, userId, appIndex);
    EXPECT_EQ(ret, Constants::INVALID_UID);
}

/**
 * @tc.number: BundleMgrMiniProxy_1005
 * @tc.name: GetNameForUid
 * @tc.desc: GetNameForUid
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_1005, Function | SmallTest | Level0)
{
    sptr<BundleMgrMiniProxy> bundleMgrMiniProxy = GetBundleMgrProxy();
    if (!bundleMgrMiniProxy) {
        std::cout << "bundle mgr min proxy is nullptr" << std::endl;
        EXPECT_EQ(bundleMgrMiniProxy, nullptr);
    }
    int uid = 100081;
    std::string name;
    auto ret = bundleMgrMiniProxy->GetNameForUid(uid, name);
    EXPECT_NE(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetAppIdByBundleName_1006
 * @tc.name: GetAppIdByBundleName
 * @tc.desc: GetAppIdByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, GetAppIdByBundleName_1006, Function | SmallTest | Level0)
{
    sptr<BundleMgrMiniProxy> bundleMgrMiniProxy = GetBundleMgrProxy();
    if (!bundleMgrMiniProxy) {
        std::cout << "bundle mgr min proxy is nullptr" << std::endl;
        EXPECT_EQ(bundleMgrMiniProxy, nullptr);
    }
    std::string bundleName = "com.ohos.systemui11";
    int userId = 100;
    auto ret = bundleMgrMiniProxy->GetAppIdByBundleName(bundleName, userId);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BundleMgrMiniProxy_1007
 * @tc.name: GetUidByBundleName
 * @tc.desc: GetUidByBundleName
 */
HWTEST_F(BundleMgrMiniProxyTest, BundleMgrMiniProxy_1007, Function | SmallTest | Level0)
{
    sptr<BundleMgrMiniProxy> bundleMgrMiniProxy = GetBundleMgrProxy();
    if (!bundleMgrMiniProxy) {
        std::cout << "bundle mgr min proxy is nullptr" << std::endl;
        EXPECT_EQ(bundleMgrMiniProxy, nullptr);
    }
    std::string bundleName = "com.ohos.systemui11";
    int userId = 100081;
    auto ret = bundleMgrMiniProxy->GetUidByBundleName(bundleName, userId);
    EXPECT_EQ(ret, Constants::INVALID_UID);
}
} // namespace AppExecFwk
} // namespace OHOS