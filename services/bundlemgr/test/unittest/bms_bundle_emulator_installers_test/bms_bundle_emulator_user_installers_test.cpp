/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "bundle_installer.h"
#include "bundle_mgr_service.h"
#include "base_bundle_installer.h"
#undef protected
#undef private

#include "mock_status_receiver.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
}  // namespace

class BmsBundleEmulatorUserInstallersTest : public testing::Test {
public:
    BmsBundleEmulatorUserInstallersTest()
    {}
    ~BmsBundleEmulatorUserInstallersTest()
    {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsBundleEmulatorUserInstallersTest::SetUpTestCase()
{}

void BmsBundleEmulatorUserInstallersTest::TearDownTestCase()
{}

void BmsBundleEmulatorUserInstallersTest::SetUp()
{}

void BmsBundleEmulatorUserInstallersTest::TearDown()
{}

/**
 * @tc.number: BmsBundleEmulatorUserInstallersTest_0100
 * @tc.name: test check emulator shell install
 * @tc.desc: test check emulator shell install
 */
HWTEST_F(BmsBundleEmulatorUserInstallersTest, BmsBundleEmulatorUserInstallersTest_0100, TestSize.Level2)
{
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::APP_GALLERY;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;

    Security::Verify::HapVerifyResult verifyRes;
    verifyRes.SetProvisionInfo(provisionInfo);

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    hapVerifyRes.emplace_back(verifyRes);

    BaseBundleInstaller baseBundleInstaller;
    ErrCode res = baseBundleInstaller.CheckShellInstallForEmulator(hapVerifyRes);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_RELEASE_BUNDLE_NOT_ALLOWED_FOR_SHELL);

    setuid(ServiceConstants::SHELL_UID);
    res = baseBundleInstaller.CheckShellInstallForEmulator(hapVerifyRes);
    setuid(Constants::ROOT_UID);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_RELEASE_BUNDLE_NOT_ALLOWED_FOR_SHELL);
}

/**
 * @tc.number: BmsBundleEmulatorUserInstallersTest_0200
 * @tc.name: test check emulator shell install
 * @tc.desc: test check emulator shell install
 */
HWTEST_F(BmsBundleEmulatorUserInstallersTest, BmsBundleEmulatorUserInstallersTest_0200, TestSize.Level1)
{
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::OS_INTEGRATION;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;

    Security::Verify::HapVerifyResult verifyRes;
    verifyRes.SetProvisionInfo(provisionInfo);

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    hapVerifyRes.emplace_back(verifyRes);

    BaseBundleInstaller baseBundleInstaller;
    ErrCode res = baseBundleInstaller.CheckShellInstallForEmulator(hapVerifyRes);
    EXPECT_EQ(res, ERR_OK);

    setuid(ServiceConstants::SHELL_UID);
    res = baseBundleInstaller.CheckShellInstallForEmulator(hapVerifyRes);
    setuid(Constants::ROOT_UID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: BmsBundleEmulatorUserInstallersTest_0300
 * @tc.name: test check emulator shell install
 * @tc.desc: test check emulator shell install
 */
HWTEST_F(BmsBundleEmulatorUserInstallersTest, BmsBundleEmulatorUserInstallersTest_0300, TestSize.Level1)
{
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::APP_GALLERY;
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;

    Security::Verify::HapVerifyResult verifyRes;
    verifyRes.SetProvisionInfo(provisionInfo);

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    hapVerifyRes.emplace_back(verifyRes);

    BaseBundleInstaller baseBundleInstaller;
    ErrCode res = baseBundleInstaller.CheckShellInstallForEmulator(hapVerifyRes);
    EXPECT_EQ(res, ERR_OK);

    setuid(ServiceConstants::SHELL_UID);
    res = baseBundleInstaller.CheckShellInstallForEmulator(hapVerifyRes);
    setuid(Constants::ROOT_UID);
    EXPECT_EQ(res, ERR_OK);
}
}  // namespace OHOS