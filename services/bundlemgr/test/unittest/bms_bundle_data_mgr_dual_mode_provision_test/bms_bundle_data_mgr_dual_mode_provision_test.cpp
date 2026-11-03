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
#include "app_provision_info/app_provision_info_manager.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "dual_mode_helper.h"
#include "inner_bundle_info.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {

namespace {
constexpr int32_t TEST_USER_ID = 100;
}

class BmsBundleDataMgrDualModeProvisionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

protected:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleDataMgrDualModeProvisionTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsBundleDataMgrDualModeProvisionTest::SetUpTestCase()
{
    bundleMgrService_->InitFreeInstall();
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(TEST_USER_ID);
}

void BmsBundleDataMgrDualModeProvisionTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleDataMgrDualModeProvisionTest::SetUp()
{
    OHOS::system::RemoveParameter("persist.bms.test_dual_mode");
    OHOS::system::RemoveParameter("persist.bms.ispcmode");
    OHOS::system::RemoveParameter("persist.bms.mainmode");
}

void BmsBundleDataMgrDualModeProvisionTest::TearDown()
{
    OHOS::system::RemoveParameter("persist.bms.test_dual_mode");
    OHOS::system::RemoveParameter("persist.bms.ispcmode");
    OHOS::system::RemoveParameter("persist.bms.mainmode");
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr) {
        dataMgr->bundleInfos_.clear();
        dataMgr->tempBundleInfos_.clear();
        dataMgr->multiUserIdsSet_.clear();
    }
}

std::shared_ptr<BundleDataMgr> BmsBundleDataMgrDualModeProvisionTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

void SetDualModeCache(int32_t ispcmode, int32_t mainmode)
{
    OHOS::system::SetParameter("persist.bms.test_dual_mode", "true");
    OHOS::system::SetParameter("persist.bms.ispcmode", std::to_string(ispcmode));
    OHOS::system::SetParameter("persist.bms.mainmode", std::to_string(mainmode));
}

InnerBundleInfo CreateTestBundleInfo(const std::string &bundleName,
    BundleType bundleType, bool isDualModeCloneApp = false, int32_t userId = -1)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = bundleName;
    info.SetApplicationBundleType(bundleType);
    info.SetDualModeCloneApp(isDualModeCloneApp);
    if (userId >= Constants::START_USERID) {
        InnerBundleUserInfo userInfo;
        userInfo.bundleName = bundleName;
        userInfo.bundleUserInfo.userId = userId;
        info.AddInnerBundleUserInfo(userInfo);
    }
    return info;
}

/**
 * @tc.number: GetAppProvisionInfo_0200
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1.system run normally of dual mode
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAppProvisionInfo_0200, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    AppProvisionInfo appProvisionInfo;
    GetBundleDataMgr()->bundleInfos_["com.test.isshare"] = CreateTestBundleInfo(
        "com.test.isshare", BundleType::SHARED, false, Constants::START_USERID);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    ErrCode res = GetBundleDataMgr()->GetAppProvisionInfo(
        "com.test.isshare", Constants::START_USERID, appProvisionInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetListForBundleInfo_0100
 * @tc.name: Test GetListForBundleInfo
 * @tc.desc: empty bundleInfos_ and tempBundleInfos_ should be return empty list
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetListForBundleInfo_0100, Function | SmallTest | Level0)
{
    std::vector<std::pair<std::string, bool>> bundleInfoList;
    GetBundleDataMgr()->GetListForBundleInfo(Constants::START_USERID, true, bundleInfoList);
    EXPECT_TRUE(bundleInfoList.empty());
    GetBundleDataMgr()->GetListForBundleInfo(Constants::START_USERID, false, bundleInfoList);
    EXPECT_TRUE(bundleInfoList.empty());
}

/**
 * @tc.number: GetListForBundleInfo_0200
 * @tc.name: Test GetListForBundleInfo
 * @tc.desc: BundleType or UserId should be filtered out
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetListForBundleInfo_0200, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->bundleInfos_["com.test.share"] = CreateTestBundleInfo(
        "com.test.share", BundleType::SHARED, false, Constants::START_USERID);
    GetBundleDataMgr()->bundleInfos_["com.test.skill"] = CreateTestBundleInfo(
        "com.test.skill", BundleType::SKILL, false, Constants::START_USERID);
    GetBundleDataMgr()->bundleInfos_["com.test.nouser"] = CreateTestBundleInfo(
        "com.test.nouser", BundleType::APP);
    std::vector<std::pair<std::string, bool>> bundleInfoList;
    GetBundleDataMgr()->GetListForBundleInfo(Constants::START_USERID, false, bundleInfoList);
    EXPECT_TRUE(bundleInfoList.empty());
}

/**
 * @tc.number: GetListForBundleInfo_0300
 * @tc.name: Test GetListForBundleInfo
 * @tc.desc: BundleType or UserId should be filtered out
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetListForBundleInfo_0300, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->bundleInfos_["com.test.current"] = CreateTestBundleInfo(
        "com.test.current", BundleType::APP, false, Constants::START_USERID);
    GetBundleDataMgr()->bundleInfos_["com.test.temp"] = CreateTestBundleInfo(
        "com.test.temp", BundleType::APP, true, Constants::START_USERID);
    std::vector<std::pair<std::string, bool>> bundleInfoList;
    GetBundleDataMgr()->GetListForBundleInfo(Constants::START_USERID, false, bundleInfoList);
    ASSERT_EQ(bundleInfoList.size(), 2u);
    bool hasCurrent = false;
    bool hasTemp = false;
    for (const auto &[name, isDualModeApp] : bundleInfoList) {
        if (name == "com.test.current") {
            hasCurrent = true;
            EXPECT_FALSE(isDualModeApp);
        }
        if (name == "com.test.temp") {
            hasTemp = true;
            EXPECT_TRUE(isDualModeApp);
        }
    }
    EXPECT_TRUE(hasCurrent);
    EXPECT_TRUE(hasTemp);
}

/**
 * @tc.number: GetAdditionalInfo_0200
 * @tc.name: test GetAdditionalInfo
 * @tc.desc: 1.system run dualmode
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAdditionalInfo_0200, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    std::string additionalInfo = "";
    GetBundleDataMgr()->bundleInfos_["com.addition.isshare"] = CreateTestBundleInfo(
        "com.addition.isshare", BundleType::SHARED, false, Constants::START_USERID);
    ErrCode res = GetBundleDataMgr()->GetAdditionalInfo(
        "com.addition.isshare", additionalInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
    GetBundleDataMgr()->bundleInfos_.erase("com.addition.isshare");
}

/**
 * @tc.number: GetAdditionalInfoForAllUser_0100
 * @tc.name: test GetAdditionalInfoForAllUser
 * @tc.desc: 1.system run dualmode ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAdditionalInfoForAllUser_0100, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    std::string additionalInfo = "";
    ErrCode res = GetBundleDataMgr()->GetAdditionalInfoForAllUser(
        "com.addition.isshare", additionalInfo);
    EXPECT_EQ(res, ERR_APPEXECFWK_DUAL_MODE_DEVICE_NOT_SUPPORTED);
}

/**
 * @tc.number: SetAdditionalInfo_0100
 * @tc.name: test SetAdditionalInfoByIndex with bundle not installed
 * @tc.desc: 1.main mode and dual mode clone app are both not installed
 *           2.get ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, SetAdditionalInfo_0100, Function | SmallTest | Level0)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->bundleInfos_.clear();
    GetBundleDataMgr()->tempBundleInfos_.clear();
    std::string bundleName0 = "com.setaddition.current0";
    std::string bundleName1 = "com.setaddition.current1";
    std::string additionalInfo = "additionalInfo";
    ErrCode res = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName0, additionalInfo, Constants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    res = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName1, additionalInfo, Constants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    res = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName0, additionalInfo, Constants::DEFAULT_APP_INDEX);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SetAdditionalInfo_0200
 * @tc.name: test SetAdditionalInfoByIndex when the app of appIndex is not installed
 * @tc.desc: 1.only main mode app installed, appIndex is DUAL_MODE_CLONE_APP_INDEX
 *           2.only dual mode clone app installed, appIndex is DEFAULT_APP_INDEX
 *           3.dual mode clone app not installed for any user, appIndex is DUAL_MODE_CLONE_APP_INDEX
 *           4.case 1 and 2 get ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE, case 3 gets
 *             ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, SetAdditionalInfo_0200, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::ANY_USERID);
    std::string bundleName0 = "com.setaddition.current0";
    GetBundleDataMgr()->bundleInfos_[bundleName0] = CreateTestBundleInfo(
        bundleName0, BundleType::APP, false, Constants::START_USERID);
    std::string bundleName1 = "com.setaddition.current1";
    GetBundleDataMgr()->bundleInfos_[bundleName1] = CreateTestBundleInfo(
        bundleName1, BundleType::APP, true, Constants::START_USERID);
    std::string bundleName2 = "com.setaddition.current2";
    GetBundleDataMgr()->bundleInfos_[bundleName2] = CreateTestBundleInfo(
        bundleName2, BundleType::APP, true, Constants::INVALID_USERID);
    std::string additionalInfo = "additionalInfo";
    ErrCode res = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName0, additionalInfo, Constants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(res, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
    res = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName1, additionalInfo, Constants::DEFAULT_APP_INDEX);
    EXPECT_EQ(res, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
    res = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName2, additionalInfo, Constants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: SetAdditionalInfo_0300
 * @tc.name: test SetAdditionalInfo
 * @tc.desc: 1.system run dualmode
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, SetAdditionalInfo_0300, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::ANY_USERID);
    GetBundleDataMgr()->bundleInfos_.clear();
    std::string bundleName0 = "com.setaddition.current0";
    GetBundleDataMgr()->tempBundleInfos_[bundleName0] = CreateTestBundleInfo(
        bundleName0, BundleType::SHARED, true, Constants::START_USERID);
    std::string effectiveBundleName0 = DualModeHelper::GetDualModeBundleName(bundleName0);
    AppProvisionInfo appProvisionInfo;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        effectiveBundleName0, appProvisionInfo);
    std::string additionalInfo = "additionalInfo";
    ErrCode res = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName0, additionalInfo, Constants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(res, ERR_OK);
    GetBundleDataMgr()->tempBundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(
        effectiveBundleName0);
}

/**
 * @tc.number: GetAllAppProvisionInfo_1001
 * @tc.name: test GetAllAppProvisionInfo
 * @tc.desc: 1.Test the GetAllAppProvisionInfo by BundleMgrProxy  failed due to invalid userid
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAllAppProvisionInfo_1001, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::ANY_USERID);
    std::string bundleName0 = "com.test.current0";
    GetBundleDataMgr()->bundleInfos_[bundleName0] = CreateTestBundleInfo(
        bundleName0, BundleType::APP, false, Constants::START_USERID);
    AppProvisionInfo appProvisionInfo;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName0, appProvisionInfo);

    std::string bundleName1 = "com.test.current1";
    GetBundleDataMgr()->bundleInfos_[bundleName1] = CreateTestBundleInfo(
        bundleName1, BundleType::SHARED, false, Constants::START_USERID);

    int32_t userId = Constants::ANY_USERID;
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAllAppProvisionInfo(userId, appProvisionInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appProvisionInfos.size(), 1u);
    EXPECT_EQ(appProvisionInfos[0].bundleName, bundleName0);
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_0100
 * @tc.name: test GetAppProvisionInfoInDevice normal path with dual mode clone app
 * @tc.desc: 1. dual mode device, installed clone app in bundleInfos_ and tempBundleInfos_
 *           2. GetAppProvisionInfo succeeds, appIndex is DUAL_MODE_CLONE_APP_INDEX
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAppProvisionInfoInDevice_0100, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.provision.clone";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::APP, true, Constants::START_USERID);
    std::string effectiveBundleName = DualModeHelper::GetDualModeBundleName(bundleName);
    AppProvisionInfo appProvisionInfo;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        effectiveBundleName, appProvisionInfo);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAppProvisionInfoInDevice(bundleName, Constants::START_USERID,
        appProvisionInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appProvisionInfos.size(), 1u);
    EXPECT_EQ(appProvisionInfos[0].bundleName, bundleName);
    EXPECT_EQ(appProvisionInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(effectiveBundleName);
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_0200
 * @tc.name: test GetAppProvisionInfoInDevice filters SHARED/SKILL/INVALID_USERID
 * @tc.desc: 1. dual mode device, bundle in bundleInfos_ is SHARED, in tempInfos_ is APP with valid userId
 *           2. SHARED is filtered, only tempBundleInfos_ entry returns success
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAppProvisionInfoInDevice_0200, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.provision.filter";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, false, Constants::START_USERID);
    GetBundleDataMgr()->tempBundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::APP, false, Constants::START_USERID);
    AppProvisionInfo appProvisionInfo;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName, appProvisionInfo);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAppProvisionInfoInDevice(bundleName, Constants::START_USERID,
        appProvisionInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appProvisionInfos.size(), 1u);
    EXPECT_EQ(appProvisionInfos[0].bundleName, bundleName);
    EXPECT_EQ(appProvisionInfos[0].appIndex, 0);

    GetBundleDataMgr()->bundleInfos_.clear();
    GetBundleDataMgr()->tempBundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName);
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_0100
 * @tc.name: test GetAllAppProvisionInfoInDevice with dual mode clone app
 * @tc.desc: 1. dual mode device, has both normal app and clone app
 *           2. return both, clone app has DUAL_MODE_CLONE_APP_INDEX
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAllAppProvisionInfoInDevice_0100, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string normalName = "com.test.all.normal";
    GetBundleDataMgr()->bundleInfos_[normalName] = CreateTestBundleInfo(
        normalName, BundleType::APP, false, Constants::START_USERID);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(normalName, AppProvisionInfo{});

    std::string cloneName = "com.test.all.clone";
    GetBundleDataMgr()->bundleInfos_[cloneName] = CreateTestBundleInfo(
        cloneName, BundleType::APP, true, Constants::START_USERID);
    std::string effectiveBundleName = DualModeHelper::GetDualModeBundleName(cloneName);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        effectiveBundleName, AppProvisionInfo{});

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAllAppProvisionInfoInDevice(Constants::START_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appProvisionInfos.size(), 2u);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(normalName);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(effectiveBundleName);
}

/**
 * @tc.number: GetAllAppProvisionInfoForDualMode_0100
 * @tc.name: test GetAllAppProvisionInfoForDualMode with invalid userId
 * @tc.desc: 1. dual mode device, userId not in multiUserIdsSet_
 *           2. return ERR_BUNDLE_MANAGER_INALID_USER_ID
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAllAppProvisionInfoForDualMode_0100, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAllAppProvisionInfo(Constants::START_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INALID_USER_ID);
}

/**
 * @tc.number: GetAppProvisionInfo_0300
 * @tc.name: test GetAppProvisionInfo dual mode non-clone app
 * @tc.desc: 1. dual mode device, non-clone app with invalid userId
 *           2. effectiveBundleName equals bundleName, appIndex is 0
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAppProvisionInfo_0300, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.provision.nonclone";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::APP, false, Constants::START_USERID);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName, AppProvisionInfo{});

    AppProvisionInfo appProvisionInfo;
    ErrCode ret = GetBundleDataMgr()->GetAppProvisionInfo(bundleName, Constants::START_USERID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appProvisionInfo.bundleName, bundleName);
    EXPECT_EQ(appProvisionInfo.appIndex, 0);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName);
}

/**
 * @tc.number: GetAppProvisionInfo_0400
 * @tc.name: test GetAppProvisionInfo dual mode clone app success
 * @tc.desc: 1. dual mode device, clone app with invalid userId
 *           2. effectiveBundleName is dual mode bundle name, appIndex is DUAL_MODE_CLONE_APP_INDEX
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAppProvisionInfo_0400, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.provision.clonesuccess";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::APP, true, Constants::START_USERID);
    std::string effectiveBundleName = DualModeHelper::GetDualModeBundleName(bundleName);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        effectiveBundleName, AppProvisionInfo{});

    AppProvisionInfo appProvisionInfo;
    ErrCode ret = GetBundleDataMgr()->GetAppProvisionInfo(bundleName, Constants::START_USERID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appProvisionInfo.bundleName, bundleName);
    EXPECT_EQ(appProvisionInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(effectiveBundleName);
}

/**
 * @tc.number: GetSpecifiedDistributionType_0100
 * @tc.name: test GetSpecifiedDistributionType dual mode clone app
 * @tc.desc: 1. dual mode device, clone app
 *           2. effectiveBundleName is dual mode bundle name
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetSpecifiedDistributionType_0100, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.std.clone";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, true, Constants::START_USERID);
    std::string effectiveBundleName = DualModeHelper::GetDualModeBundleName(bundleName);
    std::string specifiedType = "testType";
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        effectiveBundleName, AppProvisionInfo{});
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetSpecifiedDistributionType(
        effectiveBundleName, specifiedType);

    std::string result;
    ErrCode ret = GetBundleDataMgr()->GetSpecifiedDistributionType(bundleName, result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(result, specifiedType);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(effectiveBundleName);
}

/**
 * @tc.number: GetAdditionalInfo_0300
 * @tc.name: test GetAdditionalInfo dual mode non-clone app
 * @tc.desc: 1. dual mode device, non-clone app with valid userId
 *           2. effectiveBundleName equals bundleName, return ERR_OK
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAdditionalInfo_0300, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.addinfo.nonclone";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, false, Constants::START_USERID);
    std::string additionalInfo = "testAdditional";
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName, AppProvisionInfo{});
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetAdditionalInfo(bundleName, additionalInfo);

    std::string result;
    ErrCode ret = GetBundleDataMgr()->GetAdditionalInfo(bundleName, result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(result, additionalInfo);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName);
}

/**
 * @tc.number: SetAdditionalInfo_0600
 * @tc.name: test SetAdditionalInfo dual mode clone app
 * @tc.desc: 1. dual mode device, clone app with valid userId
 *           2. SetAdditionalInfo succeeds with effectiveBundleName
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, SetAdditionalInfo_0600, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.setadd.clone";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, true, Constants::START_USERID);
    std::string effectiveBundleName = DualModeHelper::GetDualModeBundleName(bundleName);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        effectiveBundleName, AppProvisionInfo{});

    std::string additionalInfo = "newAdditionalInfo";
    ErrCode ret = GetBundleDataMgr()->SetAdditionalInfo(bundleName, additionalInfo);
    EXPECT_EQ(ret, ERR_OK);

    std::string result;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(effectiveBundleName, result);
    EXPECT_EQ(result, additionalInfo);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(effectiveBundleName);
}

/**
 * @tc.number: GetAllAppProvisionInfoForDualMode_0200
 * @tc.name: test GetAllAppProvisionInfoForDualMode GetAppProvisionInfo failed continue
 * @tc.desc: 1. dual mode device, bundle exists but provision not found
 *           2. continue skips, return ERR_OK with empty list
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAllAppProvisionInfoForDualMode_0200, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.provition.missing";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::APP, false, Constants::START_USERID);
    // No AppProvisionInfo added -> GetAppProvisionInfo fails -> continue

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAllAppProvisionInfo(Constants::START_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(appProvisionInfos.empty());
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetAppProvisionInfo_0500
 * @tc.name: test GetAppProvisionInfo dual mode non-SHARED with INVALID_USERID
 * @tc.desc: 1. dual mode device, APP type with userId not matching
 *           2. responseUserId is INVALID_USERID, return BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAppProvisionInfo_0500, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.provition.nouser";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::APP, false, Constants::START_USERID);

    AppProvisionInfo appProvisionInfo;
    ErrCode ret = GetBundleDataMgr()->GetAppProvisionInfo(
        bundleName, Constants::INVALID_USERID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_0300
 * @tc.name: test GetAppProvisionInfoInDevice all filtered out
 * @tc.desc: 1. dual mode device, only SHARED bundle in bundleInfos_
 *           2. all filtered out, return BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAppProvisionInfoInDevice_0300, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.provition.allshared";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, false, Constants::START_USERID);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAppProvisionInfoInDevice(
        bundleName, Constants::START_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_TRUE(appProvisionInfos.empty());
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_0400
 * @tc.name: test GetAppProvisionInfoInDevice GetAppProvisionInfo failed
 * @tc.desc: 1. dual mode device, bundle exists but provision not found
 *           2. all GetAppProvisionInfo fail, return INTERNAL_ERROR
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAppProvisionInfoInDevice_0400, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.provition.noprovision";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::APP, false, Constants::START_USERID);
    // No AppProvisionInfo added -> GetAppProvisionInfo fails -> continue -> empty -> INTERNAL_ERROR

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAppProvisionInfoInDevice(
        bundleName, Constants::START_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    EXPECT_TRUE(appProvisionInfos.empty());
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_0200
 * @tc.name: test GetAllAppProvisionInfoInDevice GetAppProvisionInfo failed continue
 * @tc.desc: 1. dual mode device, bundle exists but provision not found
 *           2. continue skips, return ERR_OK with empty list
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAllAppProvisionInfoInDevice_0200, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.allprovition.missing";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::APP, false, Constants::START_USERID);
    // No AppProvisionInfo added -> GetAppProvisionInfo fails -> continue

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAllAppProvisionInfoInDevice(Constants::START_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(appProvisionInfos.empty());
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetSpecifiedDistributionType_0200
 * @tc.name: test GetSpecifiedDistributionType dual mode non-clone app
 * @tc.desc: 1. dual mode device, non-clone app
 *           2. effectiveBundleName equals bundleName
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetSpecifiedDistributionType_0200, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.std.nonclone";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, false, Constants::START_USERID);
    std::string specifiedType = "testType";
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName, AppProvisionInfo{});
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetSpecifiedDistributionType(bundleName, specifiedType);

    std::string result;
    ErrCode ret = GetBundleDataMgr()->GetSpecifiedDistributionType(bundleName, result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(result, specifiedType);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName);
}

/**
 * @tc.number: GetAdditionalInfo_0400
 * @tc.name: test GetAdditionalInfo dual mode clone app
 * @tc.desc: 1. dual mode device, clone app
 *           2. effectiveBundleName is dual mode bundle Name
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetAdditionalInfo_0400, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.addinfo.clone";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, true, Constants::START_USERID);
    std::string effectiveBundleName = DualModeHelper::GetDualModeBundleName(bundleName);
    std::string additionalInfo = "cloneAdditional";
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        effectiveBundleName, AppProvisionInfo{});
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetAdditionalInfo(
        effectiveBundleName, additionalInfo);

    std::string result;
    ErrCode ret = GetBundleDataMgr()->GetAdditionalInfo(bundleName, result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(result, additionalInfo);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(effectiveBundleName);
}

/**
 * @tc.number: SetAdditionalInfo_0700
 * @tc.name: test SetAdditionalInfo dual mode non-clone app
 * @tc.desc: 1. dual mode device, non-clone app with valid userId
 *           2. effectiveBundleName equals bundleName, SetAdditionalInfo succeeds
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, SetAdditionalInfo_0700, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.setadd.nonclone";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, false, Constants::START_USERID);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName, AppProvisionInfo{});

    std::string additionalInfo = "nonCloneAdditional";
    ErrCode ret = GetBundleDataMgr()->SetAdditionalInfo(bundleName, additionalInfo);
    EXPECT_EQ(ret, ERR_OK);

    std::string result;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(bundleName, result);
    EXPECT_EQ(result, additionalInfo);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName);
}

/**
 * @tc.number: SetAdditionalInfoByIndex_0400
 * @tc.name: test SetAdditionalInfoByIndex bundleInfos_ found with DEFAULT_APP_INDEX success
 * @tc.desc: 1. dual mode device, normal app in bundleInfos_ with DEFAULT_APP_INDEX
 *           2. SetAdditionalInfo succeeds, return ERR_OK
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, SetAdditionalInfoByIndex_0400, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::ANY_USERID);
    GetBundleDataMgr()->bundleInfos_.clear();
    std::string bundleName = "com.test.setaddidx.normal";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, false, Constants::START_USERID);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName, AppProvisionInfo{});

    std::string additionalInfo = "normalAdditional";
    ErrCode ret = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName, additionalInfo, Constants::DEFAULT_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);

    std::string result;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(bundleName, result);
    EXPECT_EQ(result, additionalInfo);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName);
}

/**
 * @tc.number: GetSpecifiedDistributionType_0300
 * @tc.name: test GetSpecifiedDistributionType dual mode clone app provision not found
 * @tc.desc: 1. dual mode device, clone app, no provision in RDB
 *           2. GetSpecifiedDistributionType fails, return ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, GetSpecifiedDistributionType_0300, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::START_USERID);
    std::string bundleName = "com.test.std.noprovision";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, true, Constants::START_USERID);
    // No AppProvisionInfo added -> GetSpecifiedDistributionType fails

    std::string result;
    ErrCode ret = GetBundleDataMgr()->GetSpecifiedDistributionType(bundleName, result);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: SetAdditionalInfoByIndex_0500
 * @tc.name: test SetAdditionalInfoByIndex tempBundleInfos_ found with DUAL_MODE_CLONE_APP_INDEX
 * @tc.desc: 1. dual mode device, clone app in tempBundleInfos_ only
 *           2. SetAdditionalInfo succeeds, return ERR_OK
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, SetAdditionalInfoByIndex_0500, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::ANY_USERID);
    GetBundleDataMgr()->bundleInfos_.clear();
    GetBundleDataMgr()->tempBundleInfos_.clear();
    std::string bundleName = "com.test.setaddidx.tempclone";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, false, Constants::START_USERID);
    std::string effectiveBundleName = DualModeHelper::GetDualModeBundleName(bundleName);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        effectiveBundleName, AppProvisionInfo{});

    std::string additionalInfo = "tempCloneAdditional";
    ErrCode ret = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName, additionalInfo, Constants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);

    std::string result;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(effectiveBundleName, result);
    EXPECT_EQ(result, additionalInfo);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(effectiveBundleName);
}

/**
 * @tc.number: SetAdditionalInfoByIndex_0600
 * @tc.name: test SetAdditionalInfoByIndex with DEFAULT_APP_INDEX non-clone app success
 * @tc.desc: 1. dual mode device, SHARED app non-clone in bundleInfos_
 *           2. appIndex is DEFAULT_APP_INDEX, SetAdditionalInfo succeeds
 *           3. return ERR_OK
 */
HWTEST_F(BmsBundleDataMgrDualModeProvisionTest, SetAdditionalInfoByIndex_0600, Function | SmallTest | Level1)
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::ANY_USERID);
    GetBundleDataMgr()->bundleInfos_.clear();
    std::string bundleName = "com.test.setaddidx.default";
    GetBundleDataMgr()->bundleInfos_[bundleName] = CreateTestBundleInfo(
        bundleName, BundleType::SHARED, false, Constants::START_USERID);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName, AppProvisionInfo{});

    std::string additionalInfo = "defaultAdditional";
    ErrCode ret = GetBundleDataMgr()->SetAdditionalInfoByIndex(
        bundleName, additionalInfo, Constants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);

    std::string result;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(bundleName, result);
    EXPECT_EQ(result, additionalInfo);

    GetBundleDataMgr()->bundleInfos_.clear();
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName);
}
}
}
