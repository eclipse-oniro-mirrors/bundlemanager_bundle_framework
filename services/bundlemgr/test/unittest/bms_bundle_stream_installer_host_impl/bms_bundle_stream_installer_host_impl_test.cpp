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
#include <gmock/gmock.h>
#define private public
#include "bundle_stream_installer_host_impl.h"
#include "mock_ipc_skeleton.h"
#undef private
using namespace OHOS;
using namespace testing::ext;
using namespace AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "bundlename";
const std::string FILE_NAME = "fileName";

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
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    int32_t state = bundleStreamInstaller_->CreateStream(fileName);
    EXPECT_TRUE(state > 0);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
}

/**
 * @tc.number: test_CreateStream_0200
 * @tc.name: test the CreateStream is failing.
 * @tc.desc: create stream by install_file's haps
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateStream_0200, Function | SmallTest | Level2)
{
    std::string fileName = "";
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    int32_t state = bundleStreamInstaller_->CreateStream(fileName);
    EXPECT_TRUE(state == -1);
}

/**
 * @tc.number: test_CreateStream_0300
 * @tc.name: test the CreateStream is failing.
 * @tc.desc: create stream by install_file's haps
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateStream_0300, Function | SmallTest | Level2)
{
    std::string fileName = "fileName.hsp";
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    int32_t state = bundleStreamInstaller_->CreateStream(fileName);
    EXPECT_TRUE(state == -1);
}

/**
 * @tc.number: test_CreatePgoFileStream_0100
 * @tc.name: test BundleStreamInstallerHostImpl
 * @tc.desc: 1. test CreatePgoFileStream_0100
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreatePgoFileStream_0100, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    auto state = bundleStreamInstaller_->CreatePgoFileStream("", FILE_NAME);
    EXPECT_EQ(state, Constants::DEFAULT_STREAM_FD);
    state = bundleStreamInstaller_->CreatePgoFileStream(BUNDLE_NAME, "");
    EXPECT_EQ(state, Constants::DEFAULT_STREAM_FD);
    state = bundleStreamInstaller_->CreatePgoFileStream(BUNDLE_NAME, FILE_NAME);
    EXPECT_EQ(state, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: test_CreateSignatureFileStream_0100
 * @tc.name: test CreateSignatureFileStream
 * @tc.desc: 1. test CreateSignatureFileStream_0100
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSignatureFileStream_0100, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string moduleName = "moduleName";
    std::string fileName = "fileName";
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 1;
    EXPECT_EQ(bundleStreamInstaller_->CreateSignatureFileStream(moduleName, fileName), Constants::DEFAULT_STREAM_FD);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
}

/**
 * @tc.number: test_CreateSignatureFileStream_0200
 * @tc.name: test CreateSignatureFileStream
 * @tc.desc: 1. test CreateSignatureFileStream_0200
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSignatureFileStream_0200, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string moduleName = "moduleName_error_failed";
    std::string fileName = "fileNameError.sig";
    EXPECT_EQ(bundleStreamInstaller_->CreateSignatureFileStream(moduleName, fileName), Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: test_CreateSignatureFileStream_0300
 * @tc.name: test CreateSignatureFileStream
 * @tc.desc: 1. test CreateSignatureFileStream_0300
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSignatureFileStream_0300, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string moduleName = "moduleName";
    std::string fileName = "../fileName.sig";
    std::map<std::string, std::string> verifyCodeParamsOld = bundleStreamInstaller_->installParam_.verifyCodeParams;
    bundleStreamInstaller_->installParam_.verifyCodeParams = { { moduleName, moduleName }, { "test", "test" } };
    EXPECT_EQ(bundleStreamInstaller_->CreateSignatureFileStream(moduleName, fileName), Constants::DEFAULT_STREAM_FD);
    bundleStreamInstaller_->installParam_.verifyCodeParams = verifyCodeParamsOld;
}

/**
 * @tc.number: test_CreateSignatureFileStream_0400
 * @tc.name: test CreateSignatureFileStream
 * @tc.desc: 1. test CreateSignatureFileStream_0400
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSignatureFileStream_0400, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string moduleName = "moduleName";
    std::string fileName = "fileName.sig";
    std::string tempSignatureFileDirOld = bundleStreamInstaller_->tempSignatureFileDir_;
    bundleStreamInstaller_->tempSignatureFileDir_ = std::string(257, 'a');
    std::map<std::string, std::string> verifyCodeParamsOld = bundleStreamInstaller_->installParam_.verifyCodeParams;
    bundleStreamInstaller_->installParam_.verifyCodeParams = { { moduleName, moduleName }, { "test", "test" } };
    EXPECT_TRUE(bundleStreamInstaller_->CreateSignatureFileStream(moduleName, fileName) < 0);
    bundleStreamInstaller_->tempSignatureFileDir_ = tempSignatureFileDirOld;
    bundleStreamInstaller_->installParam_.verifyCodeParams = verifyCodeParamsOld;
}

/**
 * @tc.number: test_CreateSignatureFileStream_0500
 * @tc.name: test CreateSignatureFileStream
 * @tc.desc: 1. test CreateSignatureFileStream_0500
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSignatureFileStream_0500, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string moduleName = "moduleName_error_failed";
    std::string fileName = "fileName.sig";
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    std::map<std::string, std::string> verifyCodeParamsOld = bundleStreamInstaller_->installParam_.verifyCodeParams;
    bundleStreamInstaller_->installParam_.verifyCodeParams = { { moduleName, moduleName }, { "test", "test" } };
    EXPECT_TRUE(bundleStreamInstaller_->CreateSignatureFileStream(moduleName, fileName) > 0);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
    bundleStreamInstaller_->installParam_.verifyCodeParams = verifyCodeParamsOld;
}

/**
 * @tc.number: test_CreateSharedBundleStream_0100
 * @tc.name: test CreateSharedBundleStream
 * @tc.desc: 1. test CreateSharedBundleStream_0100
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSharedBundleStream_0100, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string hspName = "hspName";
    uint32_t index = 0;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    EXPECT_TRUE(bundleStreamInstaller_->CreateSharedBundleStream(hspName, index) == -1);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
}

/**
 * @tc.number: test_CreateSharedBundleStream_0200
 * @tc.name: test CreateSharedBundleStream
 * @tc.desc: 1. test CreateSharedBundleStream_0200
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSharedBundleStream_0200, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string hspName = "../hspName.hsp";
    uint32_t index = 0;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    EXPECT_TRUE(bundleStreamInstaller_->CreateSharedBundleStream(hspName, index) == -1);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
}

/**
 * @tc.number: test_CreateSharedBundleStream_0300
 * @tc.name: test CreateSharedBundleStream
 * @tc.desc: 1. test CreateSharedBundleStream_0300
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSharedBundleStream_0300, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string hspName = "hspName.hsp";
    uint32_t index = 10;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    std::vector<std::string> sharedBundleDirPathsOld = bundleStreamInstaller_->installParam_.sharedBundleDirPaths;
    bundleStreamInstaller_->installParam_.sharedBundleDirPaths = { { "test", "test" }, { "test", "test" } };
    EXPECT_TRUE(bundleStreamInstaller_->CreateSharedBundleStream(hspName, index) == -1);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
    bundleStreamInstaller_->installParam_.sharedBundleDirPaths = sharedBundleDirPathsOld;
}

/**
 * @tc.number: test_CreateSharedBundleStream_0400
 * @tc.name: test CreateSharedBundleStream
 * @tc.desc: 1. test CreateSharedBundleStream_0400
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSharedBundleStream_0400, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string hspName = "hspName.hsp";
    uint32_t index = 1;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    std::vector<std::string> sharedBundleDirPathsOld = bundleStreamInstaller_->installParam_.sharedBundleDirPaths;
    std::string longString(257, 'a');
    bundleStreamInstaller_->installParam_.sharedBundleDirPaths = { "test", longString };
    EXPECT_TRUE(bundleStreamInstaller_->CreateSharedBundleStream(hspName, index) < 0);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
    bundleStreamInstaller_->installParam_.sharedBundleDirPaths = sharedBundleDirPathsOld;
}

/**
 * @tc.number: test_CreateSharedBundleStream_0500
 * @tc.name: test CreateSharedBundleStream
 * @tc.desc: 1. test CreateSharedBundleStream_0500
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreateSharedBundleStream_0500, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string hspName = "hspName.hsp";
    uint32_t index = 1;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    std::vector<std::string> sharedBundleDirPathsOld = bundleStreamInstaller_->installParam_.sharedBundleDirPaths;
    std::string longString(257, 'a');
    bundleStreamInstaller_->installParam_.sharedBundleDirPaths = { { "test", "test" }, { "test", "test" } };
    EXPECT_TRUE(bundleStreamInstaller_->CreateSharedBundleStream(hspName, index) > 0);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
    bundleStreamInstaller_->installParam_.sharedBundleDirPaths = sharedBundleDirPathsOld;
}

/**
 * @tc.number: test_CreatePgoFileStream_0200
 * @tc.name: test CreatePgoFileStream
 * @tc.desc: 1. test CreatePgoFileStream_0200
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreatePgoFileStream_0200, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string moduleName = "moduleName";
    std::string fileName = "fileName.ap";
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 1;
    EXPECT_EQ(bundleStreamInstaller_->CreatePgoFileStream(moduleName, fileName), Constants::DEFAULT_STREAM_FD);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
}

/**
 * @tc.number: test_CreatePgoFileStream_0300
 * @tc.name: test CreatePgoFileStream
 * @tc.desc: 1. test CreatePgoFileStream_0300
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreatePgoFileStream_0300, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string moduleName = "../moduleName";
    std::string fileName = "fileName";
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    EXPECT_EQ(bundleStreamInstaller_->CreatePgoFileStream(moduleName, fileName), Constants::DEFAULT_STREAM_FD);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
}

/**
 * @tc.number: test_CreatePgoFileStream_0400
 * @tc.name: test CreatePgoFileStream
 * @tc.desc: 1. test CreatePgoFileStream_0400
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreatePgoFileStream_0400, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string moduleName = "moduleName";
    std::string fileName = "fileName.ap";
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    string tempPgoFileDirOld = bundleStreamInstaller_->tempPgoFileDir_;
    bundleStreamInstaller_->tempPgoFileDir_ = std::string(257, 'a');
    EXPECT_TRUE(bundleStreamInstaller_->CreatePgoFileStream(moduleName, fileName) < 0);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
    bundleStreamInstaller_->tempPgoFileDir_ = tempPgoFileDirOld;
}

/**
 * @tc.number: test_CreatePgoFileStream_0500
 * @tc.name: test CreatePgoFileStream
 * @tc.desc: 1. test CreatePgoFileStream_0500
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_CreatePgoFileStream_0500, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    std::string moduleName = "moduleName";
    std::string fileName = "fileName.ap";
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    IPCSkeleton::SetCallingUid(0);
    int32_t installedUidOld = bundleStreamInstaller_->installedUid_;
    bundleStreamInstaller_->installedUid_ = 0;
    EXPECT_TRUE(bundleStreamInstaller_->CreatePgoFileStream(moduleName, fileName) > 0);
    IPCSkeleton::SetCallingUid(callingUid);
    bundleStreamInstaller_->installedUid_ = installedUidOld;
}

/**
 * @tc.number: test_Install_0100
 * @tc.name: test Install
 * @tc.desc: 1. test Install_0100
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_Install_0100, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    if (bundleStreamInstaller_->receiver_ == nullptr) {
        bundleStreamInstaller_->receiver_ = sptr<IStatusReceiver>();
    }
    bundleStreamInstaller_->installParam_.parameters = {};
    EXPECT_FALSE(bundleStreamInstaller_->Install());
}

/**
 * @tc.number: test_Install_0200
 * @tc.name: test Install
 * @tc.desc: 1. test Install_0200
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_Install_0200, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    if (bundleStreamInstaller_->receiver_ == nullptr) {
        bundleStreamInstaller_->receiver_ = sptr<IStatusReceiver>();
    }
    bundleStreamInstaller_->installParam_.parameters = { { "ohos.bms.param.verifyUninstallRule",
        "ohos.bms.param.verifyUninstallRule" } };
    bundleStreamInstaller_->isInstallSharedBundlesOnly_ = false;
    EXPECT_FALSE(bundleStreamInstaller_->Install());
    bundleStreamInstaller_->isInstallSharedBundlesOnly_ = true;
}

/**
 * @tc.number: test_Install_0300
 * @tc.name: test Install
 * @tc.desc: 1. test Install_0300
 */
HWTEST_F(bundle_stream_installer_host_impl_test, test_Install_0300, Function | SmallTest | Level0)
{
    bundleStreamInstaller_ = std::make_shared<BundleStreamInstallerHostImpl>(0, 0);
    if (bundleStreamInstaller_->receiver_ == nullptr) {
        bundleStreamInstaller_->receiver_ = sptr<IStatusReceiver>();
    }
    bundleStreamInstaller_->installParam_.parameters = { { "ohos.bms.param.verifyUninstallRule",
        "ohos.bms.param.verifyUninstallRule" } };
    bool isInstallSharedBundlesOnlyOld = bundleStreamInstaller_->isInstallSharedBundlesOnly_;
    bundleStreamInstaller_->isInstallSharedBundlesOnly_ = false;
    bool isSelfUpdateOld = bundleStreamInstaller_->installParam_.isSelfUpdate;
    bundleStreamInstaller_->installParam_.isSelfUpdate = true;
    EXPECT_FALSE(bundleStreamInstaller_->Install());
    bundleStreamInstaller_->isInstallSharedBundlesOnly_ = isInstallSharedBundlesOnlyOld;
    bundleStreamInstaller_->installParam_.isSelfUpdate = isSelfUpdateOld;
}
}
}