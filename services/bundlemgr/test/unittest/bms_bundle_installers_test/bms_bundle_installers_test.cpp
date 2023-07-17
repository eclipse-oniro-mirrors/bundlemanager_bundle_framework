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
const std::string BUNDLE_NAME = "com.ohos.launcher";
const std::string PACKAGE_NAME = "launcher_settings";
const std::string BUNDLE_PATH = "/data/app/el1/bundle/public/";
const std::string BUNDLE_PATHS = "/data/app/el1/bundle/public/com.ohos.nweb/libs";
const std::int32_t FIRST_NUM = 1;
const std::int32_t ZERO_NUM = 0;
const std::string EMPTY_STRING = "";
}  // namespace

class BmsBundleInstallersTest : public testing::Test {
public:
    BmsBundleInstallersTest()
    {}
    ~BmsBundleInstallersTest()
    {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int64_t installerId_ = 1;
    sptr<MockStatusReceiver> receiver_ = new (std::nothrow) MockStatusReceiver();
    std::shared_ptr<BundleInstaller> bundleInstaller_ = nullptr;
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleInstallersTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsBundleInstallersTest::SetUpTestCase()
{}

void BmsBundleInstallersTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleInstallersTest::SetUp()
{
    bundleInstaller_ = std::make_shared<BundleInstaller>(installerId_, receiver_);
}

void BmsBundleInstallersTest::TearDown()
{}

/**
 * @tc.number: BmsBundleInstallersTest_0100
 * @tc.name: GetExistsCommonUserIds
 * @tc.desc: test Get Exists Common User Id (Add user ID)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0100 start";
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    std::set<int32_t> ret = bundleInstaller_->GetExistsCommonUserIds();
    EXPECT_TRUE(ret.size() > ZERO_NUM);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0100 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_0200
 * @tc.name: GetExistsCommonUserIds
 * @tc.desc: test Get Exists Common User Id (No user ID added)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0200 start";
    std::set<int32_t> ret = bundleInstaller_->GetExistsCommonUserIds();
    EXPECT_EQ(ret.size(), ZERO_NUM);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0200 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_0300
 * @tc.name: GetInstallerId
 * @tc.desc: test GetInstallerId
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0300 start";
    auto result = bundleInstaller_->GetInstallerId();
    EXPECT_EQ(result, FIRST_NUM);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0300 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_0400
 * @tc.name: Install
 * @tc.desc: test Install (The parameter input is normal)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0400 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    bundleInstaller_->Install(BUNDLE_PATH, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0400 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_0500
 * @tc.name: Install
 * @tc.desc: test Install (Input bundleFilePath parameter is EMPTY_STRING)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0500 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    bundleInstaller_->Install(EMPTY_STRING, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0500 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_0600
 * @tc.name: Install
 * @tc.desc: test Install (No user ID added)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0600 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    bundleInstaller_->Install(BUNDLE_PATH, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0600 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_0700
 * @tc.name: Recover
 * @tc.desc: test Recover (The parameter input is normal)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0700 start";
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    bundleInstaller_->Recover(BUNDLE_NAME, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0700 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_0800
 * @tc.name: Install
 * @tc.desc: test Install (The parameter input is normal)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0800 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.push_back(BUNDLE_PATHS);
    bundleInstaller_->Install(bundleFilePaths, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0800 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_0900
 * @tc.name: Install
 * @tc.desc: test Install (Input bundleFilePath parameter is EMPTY_STRING)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_0900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0900 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.push_back(EMPTY_STRING);
    bundleInstaller_->Install(bundleFilePaths, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_0900 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_1000
 * @tc.name: UpdateInstallerState
 * @tc.desc: test UpdateInstallerState (The parameter input is InstallerState::INSTALL_BUNDLE_CHECKED)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_1000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1000 start";
    bundleInstaller_->UpdateInstallerState(BaseBundleInstaller::InstallerState::INSTALL_BUNDLE_CHECKED);
    EXPECT_TRUE(bundleInstaller_->statusReceiver_);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1000 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_1100
 * @tc.name: Uninstall
 * @tc.desc: test Uninstall (Parameters are normal)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_1100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1100 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    bundleInstaller_->Uninstall(BUNDLE_PATH, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1100 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_1200
 * @tc.name: Uninstall
 * @tc.desc: test Uninstall (The bundlename parameter is EMPTY_STRING)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_1200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1200 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    bundleInstaller_->Uninstall(EMPTY_STRING, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1200 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_1300
 * @tc.name: Uninstall
 * @tc.desc: test Uninstall (No user ID added)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_1300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1300 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    bundleInstaller_->Uninstall(BUNDLE_PATH, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1300 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_1400
 * @tc.name: Uninstall
 * @tc.desc: test Uninstall (Parameters are normal)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_1400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1400 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    bundleInstaller_->Uninstall(BUNDLE_PATH, PACKAGE_NAME, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1400 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_1500
 * @tc.name: Uninstall
 * @tc.desc: test Uninstall (No user ID added)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_1500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1500 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    bundleInstaller_->Uninstall(BUNDLE_PATH, PACKAGE_NAME, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1500 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_1600
 * @tc.name: Uninstall
 * @tc.desc: test Uninstall (The bundlename parameter is EMPTY_STRING)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_1600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1600 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    bundleInstaller_->Uninstall(EMPTY_STRING, PACKAGE_NAME, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1600 end";
}

/**
 * @tc.number: BmsBundleInstallersTest_1700
 * @tc.name: Uninstall
 * @tc.desc: test Uninstall (The modulePackage parameter is EMPTY_STRING)
 */
HWTEST_F(BmsBundleInstallersTest, BmsBundleInstallersTest_1700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1700 start";
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(Constants::START_USERID);
    bundleInstaller_->Uninstall(BUNDLE_PATH, EMPTY_STRING, installParam);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ == nullptr);
    GTEST_LOG_(INFO) << "BmsBundleInstallersTest_1700 end";
}
}  // namespace OHOS