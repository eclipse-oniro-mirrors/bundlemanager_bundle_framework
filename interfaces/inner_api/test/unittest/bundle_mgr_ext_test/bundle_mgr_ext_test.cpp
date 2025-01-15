/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <memory>

#include "bundle_mgr_ext.h"
#include "process_cache_callback_host.h"
#define private public
#include "bundle_mgr_host.h"
#undef private

#include "bundle_resource_interface.h"
#include "iremote_stub.h"
#include "ability_info.h"
#include "application_info.h"
#include "bundle_info.h"
#include "bundle_user_info.h"
#include "mime_type_mgr.h"
#include "json_serializer.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BundleMgrExtTest : public testing::Test {
public:
    BundleMgrExtTest() = default;
    ~BundleMgrExtTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleMgrExtTest::SetUpTestCase()
{}

void BundleMgrExtTest::TearDownTestCase()
{}

void BundleMgrExtTest::SetUp()
{}

void BundleMgrExtTest::TearDown()
{}

class BundleMgrExtToTest : public BundleMgrExt {
public:
    bool CheckApiInfo(const BundleInfo& bundleInfo) override;
};

bool BundleMgrExtToTest::CheckApiInfo(const BundleInfo& bundleInfo)
{
    return true;
}

/**
 * @tc.number: IsRdDevice_0100
 * @tc.name: test the IsRdDevice
 * @tc.desc: 1. system running normally
 *           2. test IsRdDevice
 */
HWTEST_F(BundleMgrExtTest, IsRdDevice_0100, Function | SmallTest | Level0)
{
    BundleMgrExtToTest bundleMgrExtToTest;
    auto ret = bundleMgrExtToTest.IsRdDevice();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CheckBundleNameAndStratAbility_0100
 * @tc.name: test the CheckBundleNameAndStratAbility
 * @tc.desc: 1. system running normally
 *           2. test CheckBundleNameAndStratAbility
 */
HWTEST_F(BundleMgrExtTest, CheckBundleNameAndStratAbility_0100, Function | SmallTest | Level0)
{
    BundleMgrExtToTest bundleMgrExtToTest;
    std::string bundleName = "com.ohos.systemui";
    std::string appID = "appID";
    bundleMgrExtToTest.CheckBundleNameAndStratAbility(bundleName, appID);
    auto ret = bundleMgrExtToTest.IsRdDevice();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetCompatibleDeviceType_0100
 * @tc.name: test the GetCompatibleDeviceType
 * @tc.desc: 1. system running normally
 *           2. test GetCompatibleDeviceType
 */
HWTEST_F(BundleMgrExtTest, GetCompatibleDeviceType_0100, Function | SmallTest | Level0)
{
    BundleMgrExtToTest bundleMgrExtToTest;
    std::string bundleName = "com.ohos.systemui";
    auto ret = bundleMgrExtToTest.GetCompatibleDeviceType(bundleName);
    EXPECT_NE(ret, "");
}

/**
 * @tc.number: OnGetAllBundleCacheFinished_0100
 * @tc.name: test the OnGetAllBundleCacheFinished
 * @tc.desc: 1. system running normally
 *           2. test OnGetAllBundleCacheFinished
 */
HWTEST_F(BundleMgrExtTest, OnGetAllBundleCacheFinished_0100, Function | SmallTest | Level0)
{
    ProcessCacheCallbackHost processCacheCallbackHost;
    uint64_t cacheStat = 1;
    MessageParcel data;
    MessageParcel reply;
    processCacheCallbackHost.OnGetAllBundleCacheFinished(cacheStat);
    BundleMgrHost bundleMgrHost;
    auto ret = bundleMgrHost.HandleGetAllBundleCacheStat(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}
}
}