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

#define private public
#define protected public
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bundle_mgr_service.h"
#include "system_bundle_installer.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.test";
const std::string MODULE_NAME = "entry";
const int32_t WAIT_TIME = 5;
const std::string EMPTY_STRING = "";
}  // namespace

class BmsSystemBundleInstallerTest : public testing::Test {
public:
    BmsSystemBundleInstallerTest();
    ~BmsSystemBundleInstallerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool UninstallSystemBundle(const std::string &bundleName) const;
    bool UninstallSystemBundle(const std::string &bundleName, bool isKeepData) const;
    bool UninstallSystemBundle(const std::string &bundleName, const std::string &modulePackage) const;
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsSystemBundleInstallerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsSystemBundleInstallerTest::BmsSystemBundleInstallerTest()
{}

BmsSystemBundleInstallerTest::~BmsSystemBundleInstallerTest()
{}

bool BmsSystemBundleInstallerTest::UninstallSystemBundle(const std::string &bundleName) const
{
    auto installer = std::make_unique<SystemBundleInstaller>();
    return installer->UninstallSystemBundle(bundleName);
}

bool BmsSystemBundleInstallerTest::UninstallSystemBundle(const std::string &bundleName, bool isKeepData) const
{
    auto installer = std::make_unique<SystemBundleInstaller>();
    return installer->UninstallSystemBundle(bundleName, isKeepData);
}

bool BmsSystemBundleInstallerTest::UninstallSystemBundle(
    const std::string &bundleName, const std::string &modulePackage) const
{
    auto installer = std::make_unique<SystemBundleInstaller>();
    return installer->UninstallSystemBundle(bundleName, modulePackage);
}

void BmsSystemBundleInstallerTest::SetUpTestCase()
{}

void BmsSystemBundleInstallerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsSystemBundleInstallerTest::SetUp()
{}

void BmsSystemBundleInstallerTest::TearDown()
{}

/**
 * @tc.number: UninstallSystemBundle_0100
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_0100, Function | SmallTest | Level0)
{
    std::string bundleName = BUNDLE_NAME;
    bool result = UninstallSystemBundle(bundleName);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: UninstallSystemBundle_0200
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_0200, Function | SmallTest | Level0)
{
    std::string bundleName = EMPTY_STRING;
    bool result = UninstallSystemBundle(bundleName);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: UninstallSystemBundle_0300
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename and isKeepData is true to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_0300, Function | SmallTest | Level0)
{
    std::string bundleName = BUNDLE_NAME;
    bool isKeepData = true;
    bool result = UninstallSystemBundle(bundleName, isKeepData);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: UninstallSystemBundle_0400
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName and isKeepData is true to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_0400, Function | SmallTest | Level0)
{
    std::string bundleName = EMPTY_STRING;
    bool isKeepData = true;
    bool result = UninstallSystemBundle(bundleName, isKeepData);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: UninstallSystemBundle_0500
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename and isKeepData is false to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_0500, Function | SmallTest | Level0)
{
    std::string bundleName = BUNDLE_NAME;
    bool isKeepData = false;
    bool result = UninstallSystemBundle(bundleName, isKeepData);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: UninstallSystemBundle_0600
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName and isKeepData is false to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_0600, Function | SmallTest | Level0)
{
    std::string bundleName = EMPTY_STRING;
    bool isKeepData = false;
    bool result = UninstallSystemBundle(bundleName, isKeepData);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: UninstallSystemBundle_0700
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename and the correct modulePackage to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_0700, Function | SmallTest | Level0)
{
    std::string bundleName = BUNDLE_NAME;
    std::string modulePackage = MODULE_NAME;
    bool result = UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: UninstallSystemBundle_0800
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName and the correct modulePackage to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_0800, Function | SmallTest | Level0)
{
    std::string bundleName = EMPTY_STRING;
    std::string modulePackage = MODULE_NAME;
    bool result = UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: UninstallSystemBundle_0900
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName and an empty modulePackage to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_0900, Function | SmallTest | Level0)
{
    std::string bundleName = EMPTY_STRING;
    std::string modulePackage = EMPTY_STRING;
    bool result = UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: UninstallSystemBundle_1000
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename and an empty modulePackage to get the return false
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1000, Function | SmallTest | Level0)
{
    std::string bundleName = BUNDLE_NAME;
    std::string modulePackage = EMPTY_STRING;
    bool result = UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_EQ(result, false);
}


/**
 * @tc.number: UninstallSystemBundle_1100
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1100, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = BUNDLE_NAME;
    bool result = UninstallSystemBundle(bundleName);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: UninstallSystemBundle_1200
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1200, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = EMPTY_STRING;
    bool result = UninstallSystemBundle(bundleName);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: UninstallSystemBundle_1300
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename and isKeepData is true to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1300, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = BUNDLE_NAME;
    bool isKeepData = true;
    bool result = UninstallSystemBundle(bundleName, isKeepData);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: UninstallSystemBundle_1400
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName and isKeepData is true to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1400, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = EMPTY_STRING;
    bool isKeepData = true;
    bool result = UninstallSystemBundle(bundleName, isKeepData);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: UninstallSystemBundle_1500
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename and isKeepData is false to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1500, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = BUNDLE_NAME;
    bool isKeepData = false;
    bool result = UninstallSystemBundle(bundleName, isKeepData);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: UninstallSystemBundle_1600
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName and isKeepData is false to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1600, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = EMPTY_STRING;
    bool isKeepData = false;
    bool result = UninstallSystemBundle(bundleName, isKeepData);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: UninstallSystemBundle_1700
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename and the correct modulePackage to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1700, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = BUNDLE_NAME;
    std::string modulePackage = MODULE_NAME;
    bool result = UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: UninstallSystemBundle_1800
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName and the correct modulePackage to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1800, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = EMPTY_STRING;
    std::string modulePackage = MODULE_NAME;
    bool result = UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: UninstallSystemBundle_1900
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in an empty bundleName and an empty modulePackage to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_1900, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = EMPTY_STRING;
    std::string modulePackage = EMPTY_STRING;
    bool result = UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: UninstallSystemBundle_2000
 * @tc.name: UninstallSystemBundle
 * @tc.desc: Pass in the correct bundlename and an empty modulePackage to get the return true
 */
HWTEST_F(BmsSystemBundleInstallerTest, UninstallSystemBundle_2000, Function | SmallTest | Level0)
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    std::string bundleName = BUNDLE_NAME;
    std::string modulePackage = EMPTY_STRING;
    bool result = UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_EQ(result, true);
}
} // OHOS
