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
#include <gmock/gmock.h>
#include "bundle_stream_installer_host_impl.h"
using namespace OHOS;
using namespace testing::ext;
using namespace AppExecFwk;

namespace OHOS {
namespace {
class bundle_stream_installer_host_impl_test : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<AppExecFwk::BundleStreamInstallerHostImpl> bundleStreamInstaller_;
};

void bundle_stream_installer_host_impl_test::SetUpTestCase()
{
}

void bundle_stream_installer_host_impl_test::TearDownTestCase()
{
}

void bundle_stream_installer_host_impl_test::SetUp()
{
}

void bundle_stream_installer_host_impl_test::TearDown()
{
}

/**
 * @tc.number: test_GetInstallerId_0100
 * @tc.name: test the GetInstallerId ID.
 * @tc.desc: test the GetInstallerId ID will be correct.
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_GetInstallerId_0100, Function | SmallTest | Level2)
{
    uint32_t installerId = 1;
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(1, 1);
    bundleStreamInstaller_->SetInstallerId(installerId);
    uint32_t result = bundleStreamInstaller_->GetInstallerId();
    EXPECT_EQ(installerId, result);
}

/**
 * @tc.number: test_CreateStream_0100
 * @tc.name: test the CreateStream is successful.
 * @tc.desc: create stream by install_file's haps
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateStream_0100, Function | SmallTest | Level2)
{
    std::string fileName = "/data/entry-default-signed.hap";
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    int32_t state = bundleStreamInstaller_->CreateStream(fileName);
    EXPECT_TRUE(state > 0);
}
}
}