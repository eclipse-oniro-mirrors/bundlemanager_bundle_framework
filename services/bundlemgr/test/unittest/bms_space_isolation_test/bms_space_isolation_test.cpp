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
#include "bundle_mgr_service.h"

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
    std::shared_ptr<BundleMgrService> bundleMgrService_;
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
{
    bundleMgrService_ = OHOS::DelayedSingleton<BundleMgrService>::GetInstance();
    bundleMgrService_->OnStart();
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "false");
}

void BmsSpaceIsolationTest::TearDown()
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "false");
    bundleMgrService_->OnStop();
    bundleMgrService_ = nullptr;
}

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

/**
 * @tc.number: CheckSpaceIsolation_1900
 * @tc.name: CheckSpaceIsolation with invalid bundleType
 * @tc.desc: bundleType is neither APP nor ATOMIC_SERVICE
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_1900, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    // -1 represents invalid BundleType
    info.SetApplicationBundleType(static_cast<BundleType>(-1));

    int32_t userId = Constants::START_USERID;
    BundleInstallChecker checker;
    EXPECT_TRUE(checker.CheckSpaceIsolation(userId, info));
}

/**
 * @tc.number: CheckSpaceIsolation_2000
 * @tc.name: CheckSpaceIsolation normal release app
 * @tc.desc: not debug and not enterprise app
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_2000, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.SetApplicationBundleType(BundleType::APP);
    info.SetAppProvisionType(Constants::APP_PROVISION_TYPE_RELEASE);
    info.SetAppDistributionType(Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY);

    ApplicationInfo appInfo;
    appInfo.debug = false;
    info.SetBaseApplicationInfo(appInfo);

    int32_t userId = Constants::START_USERID;
    BundleInstallChecker checker;
    EXPECT_TRUE(checker.CheckSpaceIsolation(userId, info));
}

/**
 * @tc.number: CheckSpaceIsolation_2100
 * @tc.name: CheckSpaceIsolation debug app not installed
 * @tc.desc: FetchInnerBundleInfo returns false
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSpaceIsolation_2100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.SetApplicationBundleType(BundleType::APP);
    info.SetAppProvisionType(Constants::APP_PROVISION_TYPE_DEBUG);

    int32_t userId = Constants::START_USERID;
    BundleInstallChecker checker;
    EXPECT_TRUE(checker.CheckSpaceIsolation(userId, info));
}

/**
 * @tc.number: CheckEnterpriseResign_0100
 * @tc.name: CheckEnterpriseResign enterprise resigned
 * @tc.desc: provisionInfo.isEnterpriseResigned is true
 */
HWTEST_F(BmsSpaceIsolationTest, CheckEnterpriseResign_0100, Function | SmallTest | Level1)
{
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    provisionInfo.isEnterpriseResigned = true;

    int32_t userId = Constants::START_USERID;
    BundleInstallChecker checker;
    EXPECT_TRUE(checker.CheckEnterpriseResign(provisionInfo, userId));
}

/**
 * @tc.number: CheckEnterpriseResign_0200
 * @tc.name: CheckEnterpriseResign non enterprise device
 * @tc.desc: IS_ENTERPRISE_DEVICE is false
 */
HWTEST_F(BmsSpaceIsolationTest, CheckEnterpriseResign_0200, Function | SmallTest | Level1)
{
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    provisionInfo.isEnterpriseResigned = false;

    // parameter mock 默认 IS_ENTERPRISE_DEVICE == false
    int32_t userId = Constants::START_USERID;
    BundleInstallChecker checker;
    EXPECT_TRUE(checker.CheckEnterpriseResign(provisionInfo, userId));
}

/**
 * @tc.number: ParseHapFiles_0100
 * @tc.name: test ParseHapFiles when ParseBundleInfo failed
 * @tc.desc: ParseBundleInfo returns error
 */
HWTEST_F(BmsSpaceIsolationTest, ParseHapFiles_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> bundlePaths;
    bundlePaths.emplace_back("parse_bundle_failed.hap");
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult verifyResult;
    hapVerifyRes.emplace_back(verifyResult);
    InstallCheckParam checkParam;
    checkParam.isPreInstallApp = false;

    std::unordered_map<std::string, InnerBundleInfo> infos;
    BundleInstallChecker checker;
    ErrCode ret = checker.ParseHapFiles(bundlePaths, checkParam, hapVerifyRes, infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: ParseHapFiles_0200
 * @tc.name: test ParseHapFiles CheckSystemSize failed
 * @tc.desc: insufficient disk memory
 */
HWTEST_F(BmsSpaceIsolationTest, ParseHapFiles_0200, Function | SmallTest | Level1)
{
    std::vector<std::string> bundlePaths;
    bundlePaths.emplace_back("system_size_failed.hap");

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    hapVerifyRes.emplace_back(Security::Verify::HapVerifyResult());

    InstallCheckParam checkParam;
    checkParam.isPreInstallApp = false;
    checkParam.appType = Constants::AppType::THIRD_PARTY_APP;

    std::unordered_map<std::string, InnerBundleInfo> infos;

    BundleInstallChecker checker;
    ErrCode ret = checker.ParseHapFiles(bundlePaths, checkParam, hapVerifyRes, infos);

    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: ParseHapFiles_0300
 * @tc.name: test ParseHapFiles CheckEnterpriseForAllUser failed
 * @tc.desc: enterprise install forbidden
 */
HWTEST_F(BmsSpaceIsolationTest, ParseHapFiles_0300, Function | SmallTest | Level1)
{
    std::vector<std::string> bundlePaths;
    bundlePaths.emplace_back("enterprise_forbidden.hap");

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    hapVerifyRes.emplace_back(Security::Verify::HapVerifyResult());

    InstallCheckParam checkParam;
    checkParam.isPreInstallApp = false;

    std::unordered_map<std::string, InnerBundleInfo> infos;

    BundleInstallChecker checker;
    ErrCode ret = checker.ParseHapFiles(bundlePaths, checkParam, hapVerifyRes, infos);

    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: ValidInstallPermissionForShare_0100
 * @tc.name: enterprise bundle permission denied
 * @tc.desc: non-shell caller without enterprise permission
 */
HWTEST_F(BmsSpaceIsolationTest, ValidInstallPermissionForShare_0100, Function | SmallTest | Level1)
{
    InstallCheckParam checkParam;
    checkParam.isCallByShell = false;
    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    checkParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installInternaltestingBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult verifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    verifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyRes.emplace_back(verifyResult);

    BundleInstallChecker checker;
    EXPECT_FALSE(checker.VaildInstallPermissionForShare(checkParam, hapVerifyRes));
}

/**
 * @tc.number: VaildInstallPermissionForShare_0200
 * @tc.name: internaltesting bundle permission denied
 * @tc.desc: non-shell caller without internaltesting permission
 */
HWTEST_F(BmsSpaceIsolationTest, VaildInstallPermissionForShare_0200, Function | SmallTest | Level1)
{
    InstallCheckParam checkParam;
    checkParam.isCallByShell = false;
    checkParam.installInternaltestingBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    checkParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult verifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::INTERNALTESTING;
    verifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyRes.emplace_back(verifyResult);

    BundleInstallChecker checker;
    EXPECT_FALSE(checker.VaildInstallPermissionForShare(checkParam, hapVerifyRes));
}

/**
 * @tc.number: VaildInstallPermissionForShare_0300
 * @tc.name: enterprise normal/mdm permission denied
 * @tc.desc: VaildEnterpriseInstallPermissionForShare returns false
 */
HWTEST_F(BmsSpaceIsolationTest, VaildInstallPermissionForShare_0300, Function | SmallTest | Level1)
{
    InstallCheckParam checkParam;
    checkParam.isCallByShell = false;
    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    checkParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installInternaltestingBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult verifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_MDM;
    verifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyRes.emplace_back(verifyResult);

    BundleInstallChecker checker;
    EXPECT_FALSE(checker.VaildInstallPermissionForShare(checkParam, hapVerifyRes));
}

/**
 * @tc.number: NeedCheckDependency_0100
 * @tc.name: NeedCheckDependency modules empty
 * @tc.desc: return true when bundle pack modules is empty
 */
HWTEST_F(BmsSpaceIsolationTest, NeedCheckDependency_0100, Function | SmallTest | Level1)
{
    Dependency dependency;
    dependency.moduleName = "entry";
    dependency.bundleName = "";

    InnerBundleInfo bundleInfo;
    bundleInfo.SetTargetBundleName("com.test.needcheck");
    BundleInstallChecker checker;
    bool result = checker.NeedCheckDependency(dependency, bundleInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckAppLabelInfo_0100
 * @tc.name: debug type not same with entry release
 * @tc.desc: entry module is release but other module is debug
 */
HWTEST_F(BmsSpaceIsolationTest, CheckAppLabelInfo_0100,
    Function | SmallTest | Level1)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo entryInfo;
    {
        InnerModuleInfo entryModule;
        entryModule.moduleName = "entry";
        entryModule.isEntry = true;

        std::map<std::string, InnerModuleInfo> modules;
        modules.emplace("entry", entryModule);
        entryInfo.AddInnerModuleInfo(modules);
        auto appInfo = entryInfo.GetBaseApplicationInfo();
        appInfo.debug = false;
        entryInfo.SetBaseApplicationInfo(appInfo);
    }
    InnerBundleInfo featureInfo;
    {
        InnerModuleInfo featureModule;
        featureModule.moduleName = "feature";
        featureModule.isEntry = false;

        std::map<std::string, InnerModuleInfo> modules;
        modules.emplace("feature", featureModule);
        featureInfo.AddInnerModuleInfo(modules);
        auto appInfo = featureInfo.GetBaseApplicationInfo();
        appInfo.debug = true;
        featureInfo.SetBaseApplicationInfo(appInfo);
    }
    infos.emplace("bundleA", entryInfo);
    infos.emplace("bundleB", featureInfo);

    BundleInstallChecker checker;
    ErrCode ret = checker.CheckAppLabelInfo(infos);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_DEBUG_NOT_SAME);
}

/**
 * @tc.number: CheckMultiArkNativeFile_0100
 * @tc.name: ark native abi init from later bundle
 * @tc.desc: first bundle abi empty, second bundle provides abi
 */
HWTEST_F(BmsSpaceIsolationTest, CheckMultiArkNativeFile_0100,
    Function | SmallTest | Level1)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;

    InnerBundleInfo infoA;
    infoA.SetArkNativeFileAbi("");
    infos.emplace("bundleA", infoA);
    InnerBundleInfo infoB;
    infoB.SetArkNativeFileAbi("arm64-v8a");
    infos.emplace("bundleB", infoB);

    BundleInstallChecker checker;
    ErrCode ret = checker.CheckMultiArkNativeFile(infos);

    EXPECT_EQ(ret, ERR_OK);
    for (const auto &item : infos) {
        EXPECT_EQ(item.second.GetArkNativeFileAbi(), "arm64-v8a");
    }
}

/**
 * @tc.number: CheckDeviceType_0100
 * @tc.name: support app types matched
 */
HWTEST_F(BmsSpaceIsolationTest, CheckDeviceType_0100, Function | SmallTest | Level1)
{
    constexpr const char *supportAppTypesKey = "persist.sys.support_app_types";
    OHOS::system::SetParameter(supportAppTypesKey, "system");

    std::unordered_map<std::string, InnerBundleInfo> infos;

    InnerBundleInfo info;
    info.SetAppType(Constants::AppType::SYSTEM_APP);

    infos.emplace("bundle", info);

    BundleInstallChecker checker;
    ErrCode ret = checker.CheckDeviceType(infos, ERR_OK);

    EXPECT_EQ(ret, ERR_OK);
    OHOS::system::SetParameter(supportAppTypesKey, "");
}

/**
 * @tc.number: CheckRequiredDeviceFeatures_0100
 * @tc.name: required device type not found
 */
HWTEST_F(BmsSpaceIsolationTest, CheckRequiredDeviceFeatures_0100, Function | SmallTest | Level1)
{
    constexpr const char *providedDeviceFeaturesKey =
        "persist.sys.provided_device_features";

    OHOS::system::SetParameter(providedDeviceFeaturesKey, "camera,bluetooth");

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo info;

    InnerModuleInfo moduleInfo;
    moduleInfo.name = "entry";
    moduleInfo.modulePackage = "entry";
    moduleInfo.requiredDeviceFeatures.emplace(
        "other_device", std::vector<std::string>{"camera"});

    std::map<std::string, InnerModuleInfo> moduleInfos;
    moduleInfos.emplace("entry", moduleInfo);
    info.AddInnerModuleInfo(moduleInfos);
    info.SetCurrentModulePackage("entry");

    infos.emplace("bundle", info);

    BundleInstallChecker checker;
    ErrCode ret = checker.CheckRequiredDeviceFeatures(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_DEVICE_TYPE_NOT_SUPPORTED);

    OHOS::system::SetParameter(providedDeviceFeaturesKey, "");
}

/**
 * @tc.number: CheckRequiredDeviceFeatures_0200
 * @tc.name: required features not subset of provided
 */
HWTEST_F(BmsSpaceIsolationTest, CheckRequiredDeviceFeatures_0200, Function | SmallTest | Level1)
{
    constexpr const char *providedDeviceFeaturesKey =
        "persist.sys.provided_device_features";
    constexpr const char *deviceTypeKey =
        "const.product.device_type";

    OHOS::system::SetParameter(providedDeviceFeaturesKey, "camera");

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo info;

    std::string deviceType =
        OHOS::system::GetParameter(deviceTypeKey, "");
    if (deviceType.empty()) {
        deviceType = "default";
    }

    InnerModuleInfo moduleInfo;
    moduleInfo.name = "entry";
    moduleInfo.modulePackage = "entry";

    moduleInfo.requiredDeviceFeatures.emplace(
        deviceType, std::vector<std::string>{"camera", "gps"});

    std::map<std::string, InnerModuleInfo> moduleInfos;
    moduleInfos.emplace("entry", moduleInfo);
    info.AddInnerModuleInfo(moduleInfos);
    info.SetCurrentModulePackage("entry");

    infos.emplace("bundle", info);

    BundleInstallChecker checker;
    ErrCode ret = checker.CheckRequiredDeviceFeatures(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_DEVICE_TYPE_NOT_SUPPORTED);

    OHOS::system::SetParameter(providedDeviceFeaturesKey, "");
}

/**
 * @tc.number: CheckProxyPermissionLevel_0200
 * @tc.name: permission level too low
 */
HWTEST_F(BmsSpaceIsolationTest, CheckProxyPermissionLevel_0200, Function | SmallTest | Level1)
{
    BundleInstallChecker checker;
    std::string permissionName = "ohos.permission.INTERNET";

    bool ret = checker.CheckProxyPermissionLevel(permissionName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckSignatureFileDir_0300
 * @tc.name: signature file dir contains relative path
 */
HWTEST_F(BmsSpaceIsolationTest, CheckSignatureFileDir_0300, Function | SmallTest | Level1)
{
    BundleInstallChecker checker;
    std::string signatureFileDir = "../codesign.sig";
    ErrCode ret = checker.CheckSignatureFileDir(signatureFileDir);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
}

/**
 * @tc.number: CheckAppDistributionType_0100
 * @tc.name: os integration distribution type allowed
 */
HWTEST_F(BmsSpaceIsolationTest, CheckAppDistributionType_0100, Function | SmallTest | Level1)
{
    BundleInstallChecker checker;
    ErrCode ret = checker.CheckAppDistributionType(
        Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppDistributionType_0200
 * @tc.name: distribution type not in whitelist
 */
HWTEST_F(BmsSpaceIsolationTest, CheckAppDistributionType_0200,
    Function | SmallTest | Level1)
{
    BundleInstallChecker checker;
    auto bmsPara =
        DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    ASSERT_NE(bmsPara, nullptr);
    bmsPara->SaveBmsParam(
        Constants::APP_DISTRIBUTION_TYPE_WHITE_LIST, "0");

    std::string distributionType = "enterprise";

    ErrCode ret = checker.CheckAppDistributionType(distributionType);

    EXPECT_EQ(ret, ERR_APP_DISTRIBUTION_TYPE_NOT_ALLOW_INSTALL);
    bmsPara->SaveBmsParam(
        Constants::APP_DISTRIBUTION_TYPE_WHITE_LIST, "");
}


/**
 * @tc.number: SetIsAbcCompressed_0100
 * @tc.name: set abc compressed flag
 */
HWTEST_F(BmsSpaceIsolationTest, SetIsAbcCompressed_0100,
    Function | SmallTest | Level1)
{
    BundleInstallChecker checker;

    checker.SetIsAbcCompressed(true);
    EXPECT_TRUE(checker.GetIsAbcCompressed());

    checker.SetIsAbcCompressed(false);
    EXPECT_FALSE(checker.GetIsAbcCompressed());
}

/**
 * @tc.number: CheckDriverIsolation_0100
 * @tc.name: CheckDriverIsolation with empty newInfos
 * @tc.desc: Test CheckDriverIsolation when newInfos is empty
 */
HWTEST_F(BmsSpaceIsolationTest, CheckDriverIsolation_0100, Function | SmallTest | Level1)
{
    Security::Verify::HapVerifyResult hapVerifyResult;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    bool result = BundleInstallChecker::CheckSaneDriverIsolation(hapVerifyResult, USER_ID_100, newInfos);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckDriverIsolation_0200
 * @tc.name: CheckDriverIsolation with switch off
 * @tc.desc: Test CheckDriverIsolation when switch is off
 */
HWTEST_F(BmsSpaceIsolationTest, CheckDriverIsolation_0200, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "false");
    Security::Verify::HapVerifyResult hapVerifyResult;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos["path"] = InnerBundleInfo();
    bool result = BundleInstallChecker::CheckSaneDriverIsolation(hapVerifyResult, USER_ID_100, newInfos);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckDriverIsolation_0300
 * @tc.name: CheckDriverIsolation with not sane driver properties
 * @tc.desc: Test CheckDriverIsolation when driver properties is not sane
 */
HWTEST_F(BmsSpaceIsolationTest, CheckDriverIsolation_0300, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    Metadata data;
    InnerExtensionInfo abilityInfo;
    std::map<std::string, InnerExtensionInfo> baseExtensionInfos;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;

    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyResult.provisionInfo = provisionInfo;

    data.name = "cupsFilter";
    std::vector<Metadata> metadata = { data };
    abilityInfo.metadata = metadata;
    baseExtensionInfos["testKey"] = abilityInfo;

    newInfos["path"] = InnerBundleInfo();
    newInfos.begin()->second.baseExtensionInfos_ = baseExtensionInfos;
    bool result = BundleInstallChecker::CheckSaneDriverIsolation(hapVerifyResult, USER_ID_100, newInfos);
    EXPECT_TRUE(result);

    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult.provisionInfo = provisionInfo;
    result = BundleInstallChecker::CheckSaneDriverIsolation(hapVerifyResult, USER_ID_100, newInfos);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckDriverIsolation_0400
 * @tc.name: CheckDriverIsolation with sane driver properties
 * @tc.desc: Test CheckDriverIsolation when driver properties is saneConfig
 */
HWTEST_F(BmsSpaceIsolationTest, CheckDriverIsolation_0400, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    Metadata data;
    InnerExtensionInfo abilityInfo;
    std::map<std::string, InnerExtensionInfo> baseExtensionInfos;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;

    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyResult.provisionInfo = provisionInfo;

    data.name = "saneConfig";
    std::vector<Metadata> metadata = { data };
    abilityInfo.metadata = metadata;
    abilityInfo.type = ExtensionAbilityType::DRIVER;
    baseExtensionInfos["testKey"] = abilityInfo;

    newInfos["path"] = InnerBundleInfo();
    newInfos.begin()->second.baseExtensionInfos_ = baseExtensionInfos;
    bool result = BundleInstallChecker::CheckSaneDriverIsolation(hapVerifyResult, USER_ID_100, newInfos);
    EXPECT_FALSE(result);

    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult.provisionInfo = provisionInfo;
    result = BundleInstallChecker::CheckSaneDriverIsolation(hapVerifyResult, USER_ID_100, newInfos);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckDriverIsolation_0500
 * @tc.name: CheckDriverIsolation with sane driver properties
 * @tc.desc: Test CheckDriverIsolation when driver properties is saneBackend
 */
HWTEST_F(BmsSpaceIsolationTest, CheckDriverIsolation_0500, Function | SmallTest | Level1)
{
    OHOS::system::SetParameter(ServiceConstants::ENTERPRISE_SPACE_ENABLE, "true");
    Metadata data;
    InnerExtensionInfo abilityInfo;
    std::map<std::string, InnerExtensionInfo> baseExtensionInfos;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyResult.provisionInfo = provisionInfo;
    
    data.name = "saneBackend";
    std::vector<Metadata> metadata = { data };
    abilityInfo.metadata = metadata;
    abilityInfo.type = ExtensionAbilityType::DRIVER;
    baseExtensionInfos["testKey"] = abilityInfo;
    
    newInfos["path"] = InnerBundleInfo();
    newInfos.begin()->second.baseExtensionInfos_ = baseExtensionInfos;
    bool result = BundleInstallChecker::CheckSaneDriverIsolation(hapVerifyResult, USER_ID_100, newInfos);
    EXPECT_FALSE(result);

    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult.provisionInfo = provisionInfo;
    result = BundleInstallChecker::CheckSaneDriverIsolation(hapVerifyResult, USER_ID_100, newInfos);
    EXPECT_TRUE(result);
}
}