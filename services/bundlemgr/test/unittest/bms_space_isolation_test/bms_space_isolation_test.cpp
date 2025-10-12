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

#define private public
#define protected public
#include <gtest/gtest.h>
#include <map>
#include <set>
#include <string>

#include "account_helper.h"
#include "base_bundle_installer.h"
#include "bundle_multiuser_installer.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr int32_t USER_ID_100 = 100;
constexpr int32_t USER_ID_101 = 101;
constexpr int32_t USER_ID_102 = 102;
constexpr int32_t USER_ID_103 = 103;
constexpr const char* USER_ID_100_101 = "100,101";
}
class BmsSpaceIsolationTest : public testing::Test {
public:
    BmsSpaceIsolationTest();
    ~BmsSpaceIsolationTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    static void StartBundleService();
    void SetUp();
    void TearDown();
};

BmsSpaceIsolationTest::BmsSpaceIsolationTest()
{}

BmsSpaceIsolationTest::~BmsSpaceIsolationTest()
{}

void BmsSpaceIsolationTest::SetUpTestCase()
{}

void BmsSpaceIsolationTest::TearDownTestCase()
{}

void BmsSpaceIsolationTest::SetUp()
{}

void BmsSpaceIsolationTest::TearDown()
{}

/**
 * @tc.number: GetEnterpriseUserIds_0100
 * @tc.name: GetEnterpriseUserIds with multiple valid user IDs
 * @tc.desc: Test GetEnterpriseUserIds with multiple valid user IDs
 */
HWTEST_F(BmsSpaceIsolationTest, GetEnterpriseUserIds_0100, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, "100,101,102");
    std::set<int32_t> userIds = AccountHelper::GetEnterpriseUserIds();
    size_t expectSize = 3;
    EXPECT_EQ(userIds.size(), expectSize);
    EXPECT_NE(userIds.find(USER_ID_100), userIds.end());
    EXPECT_NE(userIds.find(USER_ID_101), userIds.end());
    EXPECT_NE(userIds.find(USER_ID_102), userIds.end());
}

/**
 * @tc.number: GetEnterpriseUserIds_0200
 * @tc.name: GetEnterpriseUserIds with empty parameter
 * @tc.desc: Test GetEnterpriseUserIds when parameter is empty
 */
HWTEST_F(BmsSpaceIsolationTest, GetEnterpriseUserIds_0200, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, "");
    std::set<int32_t> userIds = AccountHelper::GetEnterpriseUserIds();
    EXPECT_TRUE(userIds.empty());
}

/**
 * @tc.number: GetEnterpriseUserIds_0300
 * @tc.name: GetEnterpriseUserIds with only commas
 * @tc.desc: Test GetEnterpriseUserIds with only commas
 */
HWTEST_F(BmsSpaceIsolationTest, GetEnterpriseUserIds_0300, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, ",,");
    std::set<int32_t> userIds = AccountHelper::GetEnterpriseUserIds();
    EXPECT_TRUE(userIds.empty());
}

/**
 * @tc.number: GetEnterpriseUserIds_0400
 * @tc.name: GetEnterpriseUserIds with multiple valid and invalid user IDs
 * @tc.desc: Test GetEnterpriseUserIds with multiple valid and invalid user IDs
 */
HWTEST_F(BmsSpaceIsolationTest, GetEnterpriseUserIds_0400, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, "100,abc,102");
    std::set<int32_t> userIds = AccountHelper::GetEnterpriseUserIds();
    size_t expectSize = 2;
    EXPECT_EQ(userIds.size(), expectSize);
    EXPECT_NE(userIds.find(USER_ID_100), userIds.end());
    EXPECT_NE(userIds.find(USER_ID_102), userIds.end());
}

/**
 * @tc.number: CheckUserIsolation_0100
 * @tc.name: CheckUserIsolation with empty enterprise user IDs
 * @tc.desc: Test CheckUserIsolation when enterprise user IDs list is empty
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_0100, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, "");
    std::unordered_set<int32_t> installedUserIds = {USER_ID_100, USER_ID_101};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_102, installedUserIds);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIsolation_0200
 * @tc.name: CheckUserIsolation with target user in enterprise space
 * @tc.desc: Test CheckUserIsolation when target and installed users are in enterprise space
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_0200, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, "100,101,102");
    std::unordered_set<int32_t> installedUserIds = {USER_ID_100, USER_ID_101};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_102, installedUserIds);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIsolation_0300
 * @tc.name: CheckUserIsolation with target user in privacy space
 * @tc.desc: Test CheckUserIsolation when target and installed users are in privacy space
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_0300, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {USER_ID_102, USER_ID_103};
    bool result = AccountHelper::CheckUserIsolation(104, installedUserIds);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIsolation_0400
 * @tc.name: CheckUserIsolation with mixed space violation
 * @tc.desc: Test CheckUserIsolation when installed users are in both spaces
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_0400, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {USER_ID_100, USER_ID_102};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_103, installedUserIds);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckUserIsolation_0500
 * @tc.name: CheckUserIsolation with enterprise target but privacy installed
 * @tc.desc: Test CheckUserIsolation when target is enterprise but installed users are privacy
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_0500, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {USER_ID_102, USER_ID_103};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_100, installedUserIds);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckUserIsolation_0600
 * @tc.name: CheckUserIsolation with privacy target but enterprise installed
 * @tc.desc: Test CheckUserIsolation when target is privacy but installed users are enterprise
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_0600, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {USER_ID_100, USER_ID_101};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_102, installedUserIds);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckUserIsolation_0700
 * @tc.name: CheckUserIsolation with empty installed user IDs
 * @tc.desc: Test CheckUserIsolation when installed user IDs set is empty
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_0700, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_100, installedUserIds);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIsolation_0800
 * @tc.name: CheckUserIsolation with invalid installed user IDs
 * @tc.desc: Test CheckUserIsolation when installed user IDs are less than START_USERID
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_0800, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {0, 50};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_100, installedUserIds);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIsolation_0900
 * @tc.name: CheckUserIsolation with mixed valid and invalid installed user IDs
 * @tc.desc: Test CheckUserIsolation with both valid and invalid installed user IDs
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_0900, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {0, USER_ID_100, 50};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_101, installedUserIds);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIsolation_1000
 * @tc.name: CheckUserIsolation with single enterprise user
 * @tc.desc: Test CheckUserIsolation with single enterprise installed user
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_1000, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {USER_ID_100};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_101, installedUserIds);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIsolation_1100
 * @tc.name: CheckUserIsolation with single privacy user
 * @tc.desc: Test CheckUserIsolation with single privacy installed user
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_1100, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {USER_ID_102};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_103, installedUserIds);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIsolation_1200
 * @tc.name: CheckUserIsolation with target user equal to installed user
 * @tc.desc: Test CheckUserIsolation when target user ID equals installed user ID
 */
HWTEST_F(BmsSpaceIsolationTest, CheckUserIsolation_1200, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, USER_ID_100_101);
    std::unordered_set<int32_t> installedUserIds = {USER_ID_100};
    bool result = AccountHelper::CheckUserIsolation(USER_ID_100, installedUserIds);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_0100
 * @tc.name: CheckSpaceIsolation with preInstallApp
 * @tc.desc: Test CheckSpaceIsolation when isPreInstallApp is true
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_0100, Function | SmallTest | Level1)
{
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    BaseBundleInstaller installer;
    ErrCode result = installer.CheckSpaceIsolation(installParam, newInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CheckSpaceIsolation_0200
 * @tc.name: CheckSpaceIsolation with OTA install
 * @tc.desc: Test CheckSpaceIsolation when isOTA is true
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_0200, Function | SmallTest | Level1)
{
    InstallParam installParam;
    installParam.isOTA = true;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    BaseBundleInstaller installer;
    ErrCode result = installer.CheckSpaceIsolation(installParam, newInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CheckSpaceIsolation_0300
 * @tc.name: CheckSpaceIsolation with patch install
 * @tc.desc: Test CheckSpaceIsolation when isPatch is true
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_0300, Function | SmallTest | Level1)
{
    InstallParam installParam;
    installParam.isPatch = true;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    BaseBundleInstaller installer;
    ErrCode result = installer.CheckSpaceIsolation(installParam, newInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CheckSpaceIsolation_0400
 * @tc.name: CheckSpaceIsolation with allUser install
 * @tc.desc: Test CheckSpaceIsolation when allUser is true
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_0400, Function | SmallTest | Level1)
{
    InstallParam installParam;
    installParam.allUser = true;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    BaseBundleInstaller installer;
    ErrCode result = installer.CheckSpaceIsolation(installParam, newInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CheckSpaceIsolation_0500
 * @tc.name: CheckSpaceIsolation with otaInstall_ true
 * @tc.desc: Test CheckSpaceIsolation when otaInstall_ is true
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_0500, Function | SmallTest | Level1)
{
    InstallParam installParam;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    BaseBundleInstaller installer;
    installer.otaInstall_ = true;
    ErrCode result = installer.CheckSpaceIsolation(installParam, newInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CheckSpaceIsolation_0600
 * @tc.name: CheckSpaceIsolation with EnterpriseForAllUser true
 * @tc.desc: Test CheckSpaceIsolation when EnterpriseForAllUser is true
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_0600, Function | SmallTest | Level1)
{
    InstallParam installParam;
    installParam.parameters["ohos.bms.param.enterpriseForAllUser"] = "true";
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    BaseBundleInstaller installer;
    ErrCode result = installer.CheckSpaceIsolation(installParam, newInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CheckSpaceIsolation_0700
 * @tc.name: CheckSpaceIsolation with empty newInfos
 * @tc.desc: Test CheckSpaceIsolation when newInfos is empty
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_0700, Function | SmallTest | Level1)
{
    InstallParam installParam;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    BaseBundleInstaller installer;
    ErrCode result = installer.CheckSpaceIsolation(installParam, newInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_FAILED_CONTROLLED);
}

/**
 * @tc.number: CheckSpaceIsolation_0800
 * @tc.name: CheckSpaceIsolation with switch off
 * @tc.desc: Test CheckSpaceIsolation when switch is off
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_0800, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "false");
    InstallParam installParam;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos["path"] = InnerBundleInfo();
    BaseBundleInstaller installer;
    ErrCode result = installer.CheckSpaceIsolation(installParam, newInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CheckSpaceIsolation_0900
 * @tc.name: CheckSpaceIsolation with space isolation disabled
 * @tc.desc: Test CheckSpaceIsolation when enterprise space is disabled
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_0900, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "false");
    InnerBundleInfo info;
    bool result = BundleInstallChecker::CheckSpaceIsolation(USER_ID_100, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_1000
 * @tc.name: CheckSpaceIsolation with userId less than 100
 * @tc.desc: Test CheckSpaceIsolation when userId is less than 100
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1000, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    InnerBundleInfo info;
    bool result = BundleInstallChecker::CheckSpaceIsolation(0, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_1100
 * @tc.name: CheckSpaceIsolation with system app
 * @tc.desc: Test CheckSpaceIsolation when app is system app
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1100, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    InnerBundleInfo info;
    info.baseApplicationInfo_->isSystemApp = true;
    bool result = BundleInstallChecker::CheckSpaceIsolation(USER_ID_100, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_1200
 * @tc.name: CheckSpaceIsolation with shared bundle type
 * @tc.desc: Test CheckSpaceIsolation when bundle type is SHARED
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1200, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    InnerBundleInfo info;
    info.baseApplicationInfo_->isSystemApp = true;
    info.SetApplicationBundleType(BundleType::SHARED);
    bool result = BundleInstallChecker::CheckSpaceIsolation(USER_ID_100, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_1300
 * @tc.name: CheckSpaceIsolation with non-enterprise and non-debug app
 * @tc.desc: Test CheckSpaceIsolation when app is neither enterprise nor debug
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1300, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    InnerBundleInfo info;
    info.baseApplicationInfo_->isSystemApp = true;
    info.SetApplicationBundleType(BundleType::APP);
    info.SetAppProvisionType(Constants::APP_PROVISION_TYPE_RELEASE);
    info.baseApplicationInfo_->debug = false;
    info.SetAppDistributionType(Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY);
    bool result = BundleInstallChecker::CheckSpaceIsolation(USER_ID_100, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_1400
 * @tc.name: CheckSpaceIsolation with debug app
 * @tc.desc: Test CheckSpaceIsolation when app is debug
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1400, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    InnerBundleInfo info;
    info.baseApplicationInfo_->isSystemApp = true;
    info.SetApplicationBundleType(BundleType::APP);
    info.SetAppProvisionType(Constants::APP_PROVISION_TYPE_DEBUG);
    bool result = BundleInstallChecker::CheckSpaceIsolation(USER_ID_100, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_1500
 * @tc.name: CheckSpaceIsolation with enterprise app
 * @tc.desc: Test CheckSpaceIsolation when app is enterprise
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1500, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    InnerBundleInfo info;
    info.baseApplicationInfo_->isSystemApp = true;
    info.SetApplicationBundleType(BundleType::APP);
    info.SetAppDistributionType(Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE);
    bool result = BundleInstallChecker::CheckSpaceIsolation(USER_ID_100, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_1600
 * @tc.name: CheckSpaceIsolation with enterprise normal app
 * @tc.desc: Test CheckSpaceIsolation when app is enterprise normal
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1600, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    InnerBundleInfo info;
    info.baseApplicationInfo_->isSystemApp = true;
    info.SetApplicationBundleType(BundleType::APP);
    info.SetAppDistributionType(Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL);
    bool result = BundleInstallChecker::CheckSpaceIsolation(USER_ID_100, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_1700
 * @tc.name: CheckSpaceIsolation with enterprise mdm app
 * @tc.desc: Test CheckSpaceIsolation when app is enterprise mdm
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1700, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    InnerBundleInfo info;
    info.baseApplicationInfo_->isSystemApp = true;
    info.SetApplicationBundleType(BundleType::APP);
    info.SetAppDistributionType(Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM);
    bool result = BundleInstallChecker::CheckSpaceIsolation(USER_ID_100, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckSpaceIsolation_1800
 * @tc.name: CheckSpaceIsolation with atomic service
 * @tc.desc: Test CheckSpaceIsolation when bundle type is ATOMIC_SERVICE
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1800, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    InnerBundleInfo info;
    info.baseApplicationInfo_->isSystemApp = true;
    info.SetApplicationBundleType(BundleType::ATOMIC_SERVICE);
    info.SetAppProvisionType(Constants::APP_PROVISION_TYPE_DEBUG);
    info.baseApplicationInfo_->bundleName = "com.test.not.exist";
    bool result = BundleInstallChecker::CheckSpaceIsolation(USER_ID_100, info);
    EXPECT_TRUE(result);
}
}