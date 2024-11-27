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

#include <gtest/gtest.h>

#include "bundle_error.h"
#include "bundle_mgr_mini_proxy.h"

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
    void SetUp() {};
    void TearDown() {};
};

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
} // namespace AppExecFwk
} // namespace OHOS