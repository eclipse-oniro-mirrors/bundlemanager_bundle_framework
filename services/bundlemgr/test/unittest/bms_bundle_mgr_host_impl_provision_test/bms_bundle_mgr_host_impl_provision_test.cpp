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

#define private public

#include <gtest/gtest.h>

#include "app_provision_info.h"
#include "bundle_constants.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_service_constants.h"
#include "inner_bundle_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

// Extern declarations for mock setter functions (defined in mock/src/bundle_permission_mgr.cpp)
void SetVerifyCallingPermissionForTest(bool value);
void SetSystemAppForTest(bool value);
void SetNativeTokenTypeForTest(bool value);
void SetPermissionResultForTest(const std::string &permissionName, bool granted);
void ResetTestValues();

namespace OHOS {
namespace AppExecFwk {

namespace {
const std::string TEST_BUNDLE_NAME = "com.example.provisiontest";
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t OTHER_USER_ID = 200;
}

class BmsBundleMgrHostImplProvisionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl_ = std::make_unique<BundleMgrHostImpl>();
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleMgrHostImplProvisionTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsBundleMgrHostImplProvisionTest::SetUpTestCase()
{
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(TEST_USER_ID);
}

void BmsBundleMgrHostImplProvisionTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleMgrHostImplProvisionTest::SetUp()
{
    ResetTestValues();
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
}

void BmsBundleMgrHostImplProvisionTest::TearDown()
{
    ResetTestValues();
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_HostImpl_0001
 * @tc.name: test GetAppProvisionInfoInDevice CheckAcrossUserPermission failed
 * @tc.desc: 1. system app with permission, but across user permission denied
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAppProvisionInfoInDevice_HostImpl_0001,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, true);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfoInDevice(
        TEST_BUNDLE_NAME, OTHER_USER_ID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_HostImpl_0002
 * @tc.name: test GetAppProvisionInfoInDevice with dataMgr nullptr
 * @tc.desc: 1. system app with permission, across user permission passed
 *           2. dataMgr is nullptr, returns ERR_APPEXECFWK_NULL_PTR
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAppProvisionInfoInDevice_HostImpl_0002,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(true);

    // set dataMgr to nullptr to simulate service not ready
    auto originalDataMgr = bundleMgrService_->GetDataMgr();
    bundleMgrService_->dataMgr_ = nullptr;

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfoInDevice(
        TEST_BUNDLE_NAME, Constants::UNSPECIFIED_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    //Restore dataMgr
    bundleMgrService_->dataMgr_ = originalDataMgr;
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_HostImpl_0001
 * @tc.name: test GetAllAppProvisionInfoInDevice CheckAcrossUserPermission failed
 * @tc.desc: 1. system app with permission, but across user permission denied
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllAppProvisionInfoInDevice_HostImpl_0001,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, true);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllAppProvisionInfoInDevice(OTHER_USER_ID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_HostImpl_0002
 * @tc.name: test GetAllAppProvisionInfoInDevice with dataMgr nullptr
 * @tc.desc: 1. system app with permission, native token (across user check bypassed)
 *           2. dataMgr is nullptr, returns ERR_APPEXECFWK_NULL_PTR
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllAppProvisionInfoInDevice_HostImpl_0002,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(true);
    SetPermissionResultForTest(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, true);

    // set dataMgr to nullptr to simulate service not ready
    auto originalDataMgr = bundleMgrService_->GetDataMgr();
    bundleMgrService_->dataMgr_ = nullptr;

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllAppProvisionInfoInDevice(OTHER_USER_ID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    //Restore dataMgr
    bundleMgrService_->dataMgr_ = originalDataMgr;
}

/**
 * @tc.number: SetAdditionalInfoByIndex_HostImpl_0001
 * @tc.name: test SetAdditionalInfoByIndex non-system app
 * @tc.desc: 1. non-system app calling
 *           2. returns ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, SetAdditionalInfoByIndex_HostImpl_0001,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(false);

    std::string additionalInfo = "additionalInfo";
    ErrCode ret = bundleMgrHostImpl_->SetAdditionalInfoByIndex(
        TEST_BUNDLE_NAME, additionalInfo, Constants::DEFAULT_APP_INDEX);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: SetAdditionalInfoByIndex_HostImpl_0002
 * @tc.name: test SetAdditionalInfoByIndex permission denied
 * @tc.desc: 1. system app but without GET_BUNDLE_INFO_PRIVILEGED permission
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, SetAdditionalInfoByIndex_HostImpl_0002,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(false);

    std::string additionalInfo = "additionalInfo";
    ErrCode ret = bundleMgrHostImpl_->SetAdditionalInfoByIndex(
        TEST_BUNDLE_NAME, additionalInfo, Constants::DEFAULT_APP_INDEX);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_HostImpl_0003
 * @tc.name: test GetAppProvisionInfoInDevice non-system app
 * @tc.desc: 1. non-system app calling
 *           2. return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAppProvisionInfoInDevice_HostImpl_0003,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfoInDevice(
        TEST_BUNDLE_NAME, Constants::UNSPECIFIED_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_HostImpl_0004
 * @tc.name: test GetAppProvisionInfoInDevice permission denied
 * @tc.desc: 1. system app but without GET_BUNDLE_INFO_PRIVILEGED permission
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAppProvisionInfoInDevice_HostImpl_0004,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfoInDevice(
        TEST_BUNDLE_NAME, Constants::UNSPECIFIED_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_HostImpl_0003
 * @tc.name: test GetAllAppProvisionInfoInDevice non-system app
 * @tc.desc: 1. non-system app calling
 *           2. return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllAppProvisionInfoInDevice_HostImpl_0003,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllAppProvisionInfoInDevice(OTHER_USER_ID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_HostImpl_0004
 * @tc.name: test GetAllAppProvisionInfoInDevice permission denied
 * @tc.desc: 1. system app but without GET_INSTALL_BUNDLE_LIST permission
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllAppProvisionInfoInDevice_HostImpl_0004,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllAppProvisionInfoInDevice(OTHER_USER_ID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SetAdditionalInfoByIndex_HostImpl_0003
 * @tc.name: test SetAdditionalInfoByIndex invalid appIndex
 * @tc.desc: 1. system app with permission
 *           2. appIndex is neither DEFAULT_APP_INDEX nor DUAL_MODE_CLONE_APP_INDEX
 *           3. returns ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, SetAdditionalInfoByIndex_HostImpl_0003,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetPermissionResultForTest(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, true);

    std::string additionalInfo = "additionalInfo";
    ErrCode ret = bundleMgrHostImpl_->SetAdditionalInfoByIndex(
        TEST_BUNDLE_NAME, additionalInfo, 999);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

/**
 * @tc.number: SetAdditionalInfoByIndex_HostImpl_0004
 * @tc.name: test SetAdditionalInfoByIndex not app gallery call
 * @tc.desc: 1. system app with permission, valied appIndex
 *           2. calling bundle is not app gallery
 *           3. returns ERR_BUNDLE_MANAGER_NOT_APP_GALLERY_CALL
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, SetAdditionalInfoByIndex_HostImpl_0004,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetPermissionResultForTest(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, true);
    SetNativeTokenTypeForTest(true);

    std::string additionalInfo = "additionalInfo";
    ErrCode ret = bundleMgrHostImpl_->SetAdditionalInfoByIndex(
        TEST_BUNDLE_NAME, additionalInfo, Constants::DEFAULT_APP_INDEX);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_NOT_APP_GALLERY_CALL);
}

}
}
