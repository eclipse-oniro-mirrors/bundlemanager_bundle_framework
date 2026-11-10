/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <memory>
#include <string>
#include <utility>
#include <vector>

#define private public
#include "bundle_multiuser_installer.h"
#undef private

#include "accesstoken_kit.h"
#include "bundle_constants.h"
#include "bundle_installer_host.h"
#include "bundle_service_constants.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security::AccessToken;

void SetGetCallingUid(int32_t uid);
void ResetCallingUid();

namespace {
constexpr int32_t TEST_USER_ID = Constants::START_USERID;
constexpr uint64_t TEST_SPM_TOKEN_ID = 101;
constexpr int32_t TEST_SPM_UID = TEST_USER_ID * Constants::BASE_USER_RANGE + 102;
const std::string BUNDLE_NAME_PREFIX = "com.example.edm.installexisted.";
} // namespace

class BmsBundleMultiuserInstallEdmTest : public testing::Test {
public:
    void SetUp() override
    {
        ResetCallingUid();
        SetPermissionDeniedForTest(Constants::PERMISSION_INSTALL_BUNDLE, false);
        SetPermissionDeniedForTest(ServiceConstants::PERMISSION_MANAGE_EDM_POLICY, false);
        ClearInitHapTokenMockStateForTest();
        ResetSpmKitMockValuesForTest();
        SetSpmPrepareIdentityForTest(TEST_SPM_TOKEN_ID, TEST_SPM_UID);
    }

    void TearDown() override
    {
        ResetCallingUid();
        SetPermissionDeniedForTest(Constants::PERMISSION_INSTALL_BUNDLE, false);
        SetPermissionDeniedForTest(ServiceConstants::PERMISSION_MANAGE_EDM_POLICY, false);
        ClearInitHapTokenMockStateForTest();
        ResetSpmKitMockValuesForTest();
    }

protected:
    static std::unique_ptr<BundleMultiUserInstaller> CreateInstaller(const std::string& bundleName,
        const std::string& appDistributionType, BundleType bundleType = BundleType::APP, bool addUser = true)
    {
        auto installer = std::make_unique<BundleMultiUserInstaller>();
        installer->dataMgr_ = std::make_shared<BundleDataMgr>();

        BundleInfo bundleInfo;
        bundleInfo.name = bundleName;
        ApplicationInfo applicationInfo;
        applicationInfo.bundleName = bundleName;
        applicationInfo.appDistributionType = appDistributionType;
        applicationInfo.appProvisionType = Constants::APP_PROVISION_TYPE_RELEASE;
        applicationInfo.isSystemApp = true;

        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.SetBaseBundleInfo(bundleInfo);
        innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
        innerBundleInfo.SetApplicationBundleType(bundleType);
        installer->dataMgr_->bundleInfos_[bundleName] = innerBundleInfo;
        if (addUser) {
            installer->dataMgr_->AddUserId(TEST_USER_ID);
        }
        return installer;
    }

    static bool HasUserInfo(const BundleMultiUserInstaller& installer, const std::string& bundleName)
    {
        InnerBundleInfo innerBundleInfo;
        if (!installer.dataMgr_->FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
            return false;
        }
        InnerBundleUserInfo userInfo;
        return innerBundleInfo.GetInnerBundleUserInfo(TEST_USER_ID, userInfo);
    }

    static void VerifyDistributionMatrix(const std::string& namePrefix, bool isEdmCalling, bool hasInstallBundle,
        const std::vector<std::pair<std::string, ErrCode>>& cases)
    {
        for (size_t i = 0; i < cases.size(); ++i) {
            SCOPED_TRACE(cases[i].first);
            const std::string bundleName = BUNDLE_NAME_PREFIX + namePrefix + std::to_string(i);
            auto installer = CreateInstaller(bundleName, cases[i].first);

            EXPECT_EQ(installer->ProcessBundleInstall(
                bundleName, TEST_USER_ID, isEdmCalling, hasInstallBundle), cases[i].second);
            EXPECT_EQ(HasUserInfo(*installer, bundleName), cases[i].second == ERR_OK);
        }
    }
};

/**
 * @tc.number: ProcessBundleInstall_NonEdmMatrix_0100
 * @tc.name: Non-EDM caller keeps the existing distribution type behavior
 * @tc.desc: Enterprise and internal testing types remain rejected while normal types are allowed
 */
HWTEST_F(BmsBundleMultiuserInstallEdmTest, ProcessBundleInstall_NonEdmMatrix_0100,
    Function | SmallTest | Level0)
{
    const std::vector<std::pair<std::string, ErrCode>> cases = {
        { Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE,
            ERR_APPEXECFWK_INSTALL_EXISTED_ENTERPRISE_BUNDLE_NOT_ALLOWED },
        { Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL,
            ERR_APPEXECFWK_INSTALL_EXISTED_ENTERPRISE_BUNDLE_NOT_ALLOWED },
        { Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM,
            ERR_APPEXECFWK_INSTALL_EXISTED_ENTERPRISE_BUNDLE_NOT_ALLOWED },
        { Constants::APP_DISTRIBUTION_TYPE_INTERNALTESTING, ERR_APPEXECFWK_INSTALL_FAILED_CONTROLLED },
        { Constants::APP_DISTRIBUTION_TYPE_NONE, ERR_OK },
    };
    VerifyDistributionMatrix("nonedm.", false, true, cases);
}

/**
 * @tc.number: ProcessBundleInstall_EdmInstallBundleMatrix_0100
 * @tc.name: EDM caller with INSTALL_BUNDLE can install enterprise and normal types
 * @tc.desc: Internal testing remains controlled for the full install permission path
 */
HWTEST_F(BmsBundleMultiuserInstallEdmTest, ProcessBundleInstall_EdmInstallBundleMatrix_0100,
    Function | SmallTest | Level0)
{
    const std::vector<std::pair<std::string, ErrCode>> cases = {
        { Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE, ERR_OK },
        { Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL, ERR_OK },
        { Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM, ERR_OK },
        { Constants::APP_DISTRIBUTION_TYPE_INTERNALTESTING, ERR_APPEXECFWK_INSTALL_FAILED_CONTROLLED },
        { Constants::APP_DISTRIBUTION_TYPE_NONE, ERR_OK },
    };
    VerifyDistributionMatrix("edm.install.", true, true, cases);
}

/**
 * @tc.number: ProcessBundleInstall_EdmManagePolicyMatrix_0100
 * @tc.name: EDM caller with MANAGE_EDM_POLICY only can install enterprise types
 * @tc.desc: Normal types are permission denied and internal testing remains controlled
 */
HWTEST_F(BmsBundleMultiuserInstallEdmTest, ProcessBundleInstall_EdmManagePolicyMatrix_0100,
    Function | SmallTest | Level0)
{
    const std::vector<std::pair<std::string, ErrCode>> cases = {
        { Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE, ERR_OK },
        { Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL, ERR_OK },
        { Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM, ERR_OK },
        { Constants::APP_DISTRIBUTION_TYPE_INTERNALTESTING, ERR_APPEXECFWK_INSTALL_FAILED_CONTROLLED },
        { Constants::APP_DISTRIBUTION_TYPE_NONE, ERR_APPEXECFWK_PERMISSION_DENIED },
    };
    VerifyDistributionMatrix("edm.manage.", true, false, cases);
}

/**
 * @tc.number: ProcessBundleInstall_EdmInvalidUser_0100
 * @tc.name: EDM caller does not bypass user validation
 * @tc.desc: Invalid and nonexistent users preserve the existing exact error code
 */
HWTEST_F(BmsBundleMultiuserInstallEdmTest, ProcessBundleInstall_EdmInvalidUser_0100, Function | SmallTest | Level0)
{
    const std::string invalidUserBundle = BUNDLE_NAME_PREFIX + "edm.invaliduser";
    auto invalidUserInstaller = CreateInstaller(invalidUserBundle, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE);
    EXPECT_EQ(invalidUserInstaller->ProcessBundleInstall(
        invalidUserBundle, Constants::DEFAULT_USERID, true, true),
        ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    const std::string missingUserBundle = BUNDLE_NAME_PREFIX + "edm.missinguser";
    auto missingUserInstaller =
        CreateInstaller(missingUserBundle, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE, BundleType::APP, false);
    EXPECT_EQ(missingUserInstaller->ProcessBundleInstall(missingUserBundle, TEST_USER_ID, true, true),
        ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: ProcessBundleInstall_EdmSkillBundle_0100
 * @tc.name: EDM caller does not bypass the SKILL bundle restriction
 * @tc.desc: Distribution type allowance does not bypass the SKILL restriction
 */
HWTEST_F(BmsBundleMultiuserInstallEdmTest, ProcessBundleInstall_EdmSkillBundle_0100, Function | SmallTest | Level0)
{
    const std::string bundleName = BUNDLE_NAME_PREFIX + "edm.skill";
    auto installer = CreateInstaller(bundleName, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE, BundleType::SKILL);

    EXPECT_EQ(installer->ProcessBundleInstall(bundleName, TEST_USER_ID, true, true),
        ERR_APPEXECFWK_INSTALL_FAILED_CONTROLLED);
    EXPECT_FALSE(HasUserInfo(*installer, bundleName));
}

/**
 * @tc.number: ProcessBundleInstall_EdmAccessTokenFailure_0100
 * @tc.name: EDM caller preserves failures after distribution type validation
 * @tc.desc: AccessToken failure is not converted to success and user state is not committed
 */
HWTEST_F(
    BmsBundleMultiuserInstallEdmTest, ProcessBundleInstall_EdmAccessTokenFailure_0100, Function | SmallTest | Level0)
{
    PushInitHapTokenResultForTest(-1);
    SetSpmPrepareIdentityResultForTest(-1);
    const std::string bundleName = BUNDLE_NAME_PREFIX + "edm.tokenfailure";
    auto installer = CreateInstaller(bundleName, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE);

    EXPECT_EQ(installer->ProcessBundleInstall(bundleName, TEST_USER_ID, true, true),
        ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
    EXPECT_FALSE(HasUserInfo(*installer, bundleName));
}

/**
 * @tc.number: InstallExisted_HostEdmManagePolicy_0100
 * @tc.name: EDM caller with MANAGE_EDM_POLICY passes the Host permission gate
 * @tc.desc: Missing INSTALL_BUNDLE is allowed only for the verified EDM management path
 */
HWTEST_F(BmsBundleMultiuserInstallEdmTest, InstallExisted_HostEdmManagePolicy_0100,
    Function | SmallTest | Level0)
{
    SetGetCallingUid(Constants::EDM_UID);
    SetPermissionDeniedForTest(Constants::PERMISSION_INSTALL_BUNDLE, true);
    BundleInstallerHost installerHost;

    EXPECT_NE(installerHost.InstallExisted(BUNDLE_NAME_PREFIX + "missing", TEST_USER_ID),
        ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: InstallExisted_HostEdmNoPermission_0100
 * @tc.name: EDM caller without either permission is rejected
 * @tc.desc: EDM UID alone cannot bypass the Host permission gate
 */
HWTEST_F(BmsBundleMultiuserInstallEdmTest, InstallExisted_HostEdmNoPermission_0100,
    Function | SmallTest | Level0)
{
    SetGetCallingUid(Constants::EDM_UID);
    SetPermissionDeniedForTest(Constants::PERMISSION_INSTALL_BUNDLE, true);
    SetPermissionDeniedForTest(ServiceConstants::PERMISSION_MANAGE_EDM_POLICY, true);
    BundleInstallerHost installerHost;

    EXPECT_EQ(installerHost.InstallExisted(BUNDLE_NAME_PREFIX + "missing", TEST_USER_ID),
        ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: InstallExisted_HostNonEdmManagePolicy_0100
 * @tc.name: Non-EDM caller cannot use MANAGE_EDM_POLICY as an install permission
 * @tc.desc: The management permission bypass requires the EDM UID and permission together
 */
HWTEST_F(BmsBundleMultiuserInstallEdmTest, InstallExisted_HostNonEdmManagePolicy_0100,
    Function | SmallTest | Level0)
{
    SetGetCallingUid(Constants::FOUNDATION_UID);
    SetPermissionDeniedForTest(Constants::PERMISSION_INSTALL_BUNDLE, true);
    BundleInstallerHost installerHost;

    EXPECT_EQ(installerHost.InstallExisted(BUNDLE_NAME_PREFIX + "missing", TEST_USER_ID),
        ERR_APPEXECFWK_PERMISSION_DENIED);
}
