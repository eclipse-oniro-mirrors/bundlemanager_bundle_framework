/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bundle_stream_installer_host_impl.h"
#include "bundle_stream_installer_proxy.h"
#include "bundle_installer_proxy.h"
#include "bundle_installer_host.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
constexpr int32_t TEST_INSTALLER_ID = 1024;
constexpr int32_t DEFAULT_INSTALLER_ID = 0;
constexpr int32_t TEST_INSTALLER_UID = 100;
}; // namespace
class BmsBundleInstallerIPCTest : public testing::Test {
public:
    BmsBundleInstallerIPCTest();
    ~BmsBundleInstallerIPCTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    sptr<BundleStreamInstallerProxy> GetStreamInstallerProxy();
    sptr<BundleInstallerProxy> GetInstallerProxy();
    void SetUp();
    void TearDown();

private:
    sptr<BundleStreamInstallerHostImpl> streamInstallerHostImpl_ = nullptr;
    sptr<BundleStreamInstallerProxy> streamInstallerProxy_ = nullptr;
    sptr<BundleInstallerHost> installerHost_ = nullptr;
    sptr<BundleInstallerProxy> installerProxy_ = nullptr;
};

BmsBundleInstallerIPCTest::BmsBundleInstallerIPCTest()
{}

BmsBundleInstallerIPCTest::~BmsBundleInstallerIPCTest()
{}

void BmsBundleInstallerIPCTest::SetUpTestCase()
{
}

void BmsBundleInstallerIPCTest::TearDownTestCase()
{}

void BmsBundleInstallerIPCTest::SetUp()
{}

void BmsBundleInstallerIPCTest::TearDown()
{}

sptr<BundleStreamInstallerProxy> BmsBundleInstallerIPCTest::GetStreamInstallerProxy()
{
    if ((streamInstallerHostImpl_ != nullptr) && (streamInstallerProxy_ != nullptr)) {
        return streamInstallerProxy_;
    }
    streamInstallerHostImpl_ = new (std::nothrow) BundleStreamInstallerHostImpl(TEST_INSTALLER_ID, TEST_INSTALLER_UID);
    if (streamInstallerHostImpl_ == nullptr || streamInstallerHostImpl_->AsObject() == nullptr) {
        return nullptr;
    }
    streamInstallerProxy_ = new (std::nothrow) BundleStreamInstallerProxy(streamInstallerHostImpl_->AsObject());
    if (streamInstallerProxy_ == nullptr) {
        return nullptr;
    }
    return streamInstallerProxy_;
}

sptr<BundleInstallerProxy> BmsBundleInstallerIPCTest::GetInstallerProxy()
{
    if ((installerHost_ != nullptr) && (installerProxy_ != nullptr)) {
        return installerProxy_;
    }
    installerHost_ = new (std::nothrow) BundleInstallerHost();
    if (installerHost_ == nullptr || installerHost_->AsObject() == nullptr) {
        return nullptr;
    }
    installerProxy_ = new (std::nothrow) BundleInstallerProxy(installerHost_->AsObject());
    if (installerProxy_ == nullptr) {
        return nullptr;
    }
    return installerProxy_;
}

/**
 * @tc.number: GetInstallerIdTest_0100
 * @tc.name: test GetInstallerId function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function GetInstallerId
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, GetInstallerIdTest_0100, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    EXPECT_NE(proxy, nullptr);
    proxy->SetInstallerId(TEST_INSTALLER_ID);

    auto id = proxy->GetInstallerId();
    EXPECT_EQ(id, TEST_INSTALLER_ID);
}

/**
 * @tc.number: UnInitTest_0100
 * @tc.name: test UnInit function of BundleStreamInstallerProxy
 * @tc.desc: 1. Obtain installerProxy
 *           2. Calling function UnInit
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, FileStatTest_0200, Function | SmallTest | Level0)
{
    auto proxy = GetStreamInstallerProxy();
    EXPECT_NE(proxy, nullptr);
    proxy->SetInstallerId(DEFAULT_INSTALLER_ID);

    proxy->UnInit();
    auto id = proxy->GetInstallerId();
    EXPECT_EQ(id, DEFAULT_INSTALLER_ID);
}

/**
 * @tc.number: DestoryBundleStreamInstallerTest_0300
 * @tc.name: test DestoryBundleStreamInstaller function of BundleInstallerProxy
 * @tc.desc: 1. Obtain bundleInstallerProxy
 *           2. Calling function DestoryBundleStreamInstaller
 * @tc.require: issueI5XD60
*/
HWTEST_F(BmsBundleInstallerIPCTest, FileStatTest_0300, Function | SmallTest | Level0)
{
    auto proxy = GetInstallerProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->DestoryBundleStreamInstaller(DEFAULT_INSTALLER_ID);
    EXPECT_TRUE(ret);
}
} // OHOS