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
#include <vector>

#include "bundle_resource_host.h"
#include "bundle_resource_interface.h"
#include "iremote_stub.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class MockBundleResourceHostImpl : public BundleResourceHost {
public:
    MockBundleResourceHostImpl() = default;
    virtual ~MockBundleResourceHostImpl() = default;

    virtual ErrCode GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
        BundleResourceInfo &bundleResourceInfo, const int32_t appIndex = 0) override
        {
            return ERR_OK;
        }

    virtual ErrCode GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo, const int32_t appIndex = 0) override
        {
            return ERR_OK;
        }

    virtual ErrCode GetAllBundleResourceInfo(const uint32_t flags,
        std::vector<BundleResourceInfo> &bundleResourceInfos) override
        {
            BundleResourceInfo temp;
            bundleResourceInfos.push_back(temp);
            bundleResourceInfos.push_back(temp);
            return ERR_OK;
        }

    virtual ErrCode GetAllLauncherAbilityResourceInfo(const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos) override
        {
            LauncherAbilityResourceInfo temp;
            launcherAbilityResourceInfos.push_back(temp);
            launcherAbilityResourceInfos.push_back(temp);
            return ERR_OK;
        }
};

class BundleResourceHostTest : public testing::Test {
public:
    BundleResourceHostTest() = default;
    ~BundleResourceHostTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleResourceHostTest::SetUpTestCase()
{}

void BundleResourceHostTest::TearDownTestCase()
{
}

void BundleResourceHostTest::SetUp()
{}

void BundleResourceHostTest::TearDown()
{
}

HWTEST_F(BundleResourceHostTest, GetBundleResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetBundleResourceInfo_0100 start";
    sptr<MockBundleResourceHostImpl> stub = new MockBundleResourceHostImpl();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    BundleResourceInfo info;
    ErrCode ret = proxy->GetBundleResourceInfo("com.test.empty", 0, info, 1);
    GTEST_LOG_(INFO) << "GetBundleResourceInfo_0100 end, " << ret;
    ASSERT_EQ(ret, ERR_OK);
}

HWTEST_F(BundleResourceHostTest, GetLauncherAbilityResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetLauncherAbilityResourceInfo_0100 start";
    sptr<MockBundleResourceHostImpl> stub = new MockBundleResourceHostImpl();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::vector<LauncherAbilityResourceInfo> info;
    ErrCode ret = proxy->GetLauncherAbilityResourceInfo("com.test.empty", 0, info, 1);
    GTEST_LOG_(INFO) << "GetLauncherAbilityResourceInfo_0100 end, " << ret;
    ASSERT_EQ(ret, ERR_OK);
}

HWTEST_F(BundleResourceHostTest, GetAllBundleResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetAllBundleResourceInfo_0100 start";
    sptr<MockBundleResourceHostImpl> stub = new MockBundleResourceHostImpl();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::vector<BundleResourceInfo> info;
    ErrCode ret = proxy->GetAllBundleResourceInfo(0, info);
    GTEST_LOG_(INFO) << "GetAllBundleResourceInfo_0100 end, " << ret;
    ASSERT_EQ(ret, ERR_OK);
}

HWTEST_F(BundleResourceHostTest, GetAllLauncherAbilityResourceInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetAllLauncherAbilityResourceInfo_0100 start";
    sptr<MockBundleResourceHostImpl> stub = new MockBundleResourceHostImpl();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::vector<LauncherAbilityResourceInfo> info;
    ErrCode ret = proxy->GetAllLauncherAbilityResourceInfo(0, info);
    GTEST_LOG_(INFO) << "GetAllLauncherAbilityResourceInfo_0100 end, " << ret;
    ASSERT_EQ(ret, ERR_OK);
}

}
}