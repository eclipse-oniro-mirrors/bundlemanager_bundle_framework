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
#include <fstream>

#include "app_log_wrapper.h"
#define private public
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_permission_mgr.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_subscriber.h"
#include "el5_filekey_callback.h"
#include "scope_guard.h"
#include "want.h"
#include "user_unlocked_event_subscriber.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace AppExecFwk {
    void SetTestReturnValue(const std::vector<int32_t> &list);
}

class BmsEventHandlerUnLockedTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId);
    bool OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data);

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsEventHandlerUnLockedTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsEventHandlerUnLockedTest::SetUpTestCase()
{}

void BmsEventHandlerUnLockedTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsEventHandlerUnLockedTest::SetUp()
{}

void BmsEventHandlerUnLockedTest::TearDown()
{}

bool BmsEventHandlerUnLockedTest::CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId)
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(userId);
    return UpdateAppDataMgr::CreateBundleDataDir(bundleInfo, userId, ServiceConstants::DIR_EL2);
}

bool BmsEventHandlerUnLockedTest::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    subscriberPtr->OnReceiveEvent(data);
    std::string action = data.GetWant().GetAction();
    return action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0100
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test CreateBundleDataDir true
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0100, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bool res = CreateBundleDataDir(bundleInfo, Constants::ALL_USERID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0200
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test CreateBundleDataDir true
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0200, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bool res = CreateBundleDataDir(bundleInfo, Constants::ALL_USERID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0300
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test OnReceiveEvent true
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0300, Function | SmallTest | Level0)
{
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventData commonData { want };

    bool res = OnReceiveEvent(commonData);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0400
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test OnReceiveEvent false
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0400, Function | SmallTest | Level0)
{
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventData commonData { want };

    bool res = OnReceiveEvent(commonData);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0500
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test CreateEl5Dir false
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0500, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    CreateDirParam createDirParam;
    createDirParam.userId = 10;
    bool res = updateAppDataMgr.CreateEl5Dir(createDirParam);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0600
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test CreateEl5Dir false
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0600, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    // test dataMgr is null
    BundleInfo bundleInfo;
    bool res = updateAppDataMgr.CheckU1EnableProcess(bundleInfo);
    EXPECT_EQ(res, false);

    // test no bundleinfo
    std::string testBudnleName = "com.example.u1Enable";
    bundleInfo.name = testBudnleName;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    res = updateAppDataMgr.CheckU1EnableProcess(bundleInfo);
    EXPECT_EQ(res, false);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = testBudnleName;

    // test !u1enable
    dataMgr->bundleInfos_.emplace(testBudnleName, info);
    res = updateAppDataMgr.CheckU1EnableProcess(bundleInfo);
    EXPECT_EQ(res, false);
    dataMgr->bundleInfos_.clear();

    // test u1enable and !singleton
    std::vector<std::string> acls;
    acls.push_back(std::string(Constants::PERMISSION_U1_ENABLED));
    info.SetAllowedAcls(acls);
    bundleInfo.singleton = false;
    dataMgr->bundleInfos_.emplace(testBudnleName, info);
    res = updateAppDataMgr.CheckU1EnableProcess(bundleInfo);
    EXPECT_EQ(res, true);
    dataMgr->bundleInfos_.clear();

    // test u1enable and singleton
    bundleInfo.singleton = true;
    dataMgr->bundleInfos_.emplace(testBudnleName, info);
    res = updateAppDataMgr.CheckU1EnableProcess(bundleInfo);
    EXPECT_EQ(res, false);
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0700
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test CreateEl5Dir false
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0700, Function | SmallTest | Level0)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::string testBudnleName = "com.example.u1Enable";
    std::vector<BundleInfo> bundleInfos;
    BundleInfo bundleInfo;
    bundleInfo.name = testBudnleName;
    bundleInfos.push_back(bundleInfo);

    // test userId != 1 and CheckU1EnableProcess failed
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = testBudnleName;
    info.SetSingleton(false);
    dataMgr->bundleInfos_.emplace(testBudnleName, info);
    std::string parentDir100 = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(100) + ServiceConstants::LOG;
    std::string bundleLogDir100 = parentDir100 + bundleInfo.name;
    UpdateAppDataMgr updateAppDataMgr1;
    updateAppDataMgr1.ProcessUpdateAppLogDir(bundleInfos, 100);
    bool isExist = false;
    (void)InstalldClient::GetInstance()->IsExistDir(bundleLogDir100, isExist);
    EXPECT_FALSE(isExist);
    (void)InstalldClient::GetInstance()->RemoveDir(bundleLogDir100);
    dataMgr->bundleInfos_.clear();

    // test userId != 1 and CheckU1EnableProcess succeed
    InnerBundleInfo info2;
    info2.baseApplicationInfo_->bundleName = testBudnleName;
    std::vector<std::string> acls1;
    acls1.push_back(std::string(Constants::PERMISSION_U1_ENABLED));
    info2.SetAllowedAcls(acls1);
    info2.SetSingleton(false);
    dataMgr->bundleInfos_.emplace(testBudnleName, info2);
    UpdateAppDataMgr updateAppDataMgr2;
    updateAppDataMgr2.ProcessUpdateAppLogDir(bundleInfos, 100);
    isExist = false;
    (void)InstalldClient::GetInstance()->IsExistDir(bundleLogDir100, isExist);
    EXPECT_FALSE(isExist);
    (void)InstalldClient::GetInstance()->RemoveDir(bundleLogDir100);
    dataMgr->bundleInfos_.clear();

    // test userId == 1 and CheckU1EnableProcess succeed
    InnerBundleInfo info3;
    info3.baseApplicationInfo_->bundleName = testBudnleName;
    std::vector<std::string> acls2;
    acls2.push_back(std::string(Constants::PERMISSION_U1_ENABLED));
    info3.SetAllowedAcls(acls2);
    info3.SetSingleton(false);
    dataMgr->bundleInfos_.emplace(testBudnleName, info3);
    UpdateAppDataMgr updateAppDataMgr3;
    updateAppDataMgr3.ProcessUpdateAppLogDir(bundleInfos, 1);
    std::string parentDir1 = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(1) + ServiceConstants::LOG;
    std::string bundleLogDir1 = parentDir1 + bundleInfo.name;
    isExist = false;
    (void)InstalldClient::GetInstance()->IsExistDir(bundleLogDir1, isExist);
    EXPECT_FALSE(isExist);
    (void)InstalldClient::GetInstance()->RemoveDir(bundleLogDir1);
    dataMgr->bundleInfos_.clear();

    // test userId == 1 and CheckU1EnableProcess failed
    InnerBundleInfo info4;
    info4.baseApplicationInfo_->bundleName = testBudnleName;
    info4.SetSingleton(true);
    dataMgr->bundleInfos_.emplace(testBudnleName, info4);
    UpdateAppDataMgr updateAppDataMgr4;
    updateAppDataMgr4.ProcessUpdateAppLogDir(bundleInfos, 1);
    isExist = false;
    (void)InstalldClient::GetInstance()->IsExistDir(bundleLogDir1, isExist);
    EXPECT_FALSE(isExist);
    (void)InstalldClient::GetInstance()->RemoveDir(bundleLogDir1);
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0800
 * @tc.name: GetBundleDataDirs and DeleteUninstallTmpDirs
 * @tc.desc: test GetBundleDataDirs and DeleteUninstallTmpDirs
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0800, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    std::vector<std::string> dirs = updateAppDataMgr.GetBundleDataDirs(100);
    updateAppDataMgr.DeleteUninstallTmpDirs({});
    updateAppDataMgr.DeleteUninstallTmpDirs({100});
    updateAppDataMgr.DeleteUninstallTmpDirs({0, 1});
    EXPECT_EQ(dirs.size(), ServiceConstants::BUNDLE_EL.size() * 2);
}

/**
 * @tc.number: CheckEl5Dir_0001
 * @tc.name: test CheckEl5Dir
 * @tc.desc: test CheckEl5Dir
 */
HWTEST_F(BmsEventHandlerUnLockedTest, CheckEl5Dir_0001, Function | SmallTest | Level0)
{
    El5FilekeyCallback callback;
    Security::AccessToken::AppKeyInfo info;
    info.userId = -1;
    InnerBundleInfo bundleInfo;
    SetTestReturnValue({1, 1});
    callback.CheckEl5Dir(info, bundleInfo, "com.test.test");
    EXPECT_EQ(info.userId, -1);
    SetTestReturnValue({0, 0});
    callback.CheckEl5Dir(info, bundleInfo, "com.test.test");
    EXPECT_EQ(info.userId, -1);
    SetTestReturnValue({0, 1, 0, 1});
    callback.CheckEl5Dir(info, bundleInfo, "com.test.test");
    EXPECT_EQ(info.userId, -1);
    SetTestReturnValue({0, 1, 0, 0, 1});
    callback.CheckEl5Dir(info, bundleInfo, "com.test.test");
    EXPECT_EQ(info.userId, -1);
    SetTestReturnValue({0, 1, 0, 0, 0, 1});
    callback.CheckEl5Dir(info, bundleInfo, "com.test.test");
    EXPECT_EQ(info.userId, -1);
    SetTestReturnValue({0, 1, 0, 0, 0, 0, 1});
    callback.CheckEl5Dir(info, bundleInfo, "com.test.test");
    EXPECT_EQ(info.userId, -1);
    SetTestReturnValue({0, 1, 0, 0, 0, 0, 0, 1});
    callback.CheckEl5Dir(info, bundleInfo, "com.test.test");
    EXPECT_EQ(info.userId, -1);
}

/**
 * @tc.number: ProcessGroupEl5Dir_0001
 * @tc.name: test ProcessGroupEl5Dir
 * @tc.desc: test ProcessGroupEl5Dir
 */
HWTEST_F(BmsEventHandlerUnLockedTest, ProcessGroupEl5Dir_0001, Function | SmallTest | Level0)
{
    El5FilekeyCallback callback;
    Security::AccessToken::AppKeyInfo info;
    info.type = Security::AccessToken::AppKeyType::APP;
    callback.ProcessGroupEl5Dir(info);
    EXPECT_EQ(info.type, Security::AccessToken::AppKeyType::APP);

    info.type = Security::AccessToken::AppKeyType::GROUPID;
    info.uid = 1;
    info.groupID = "123";
    callback.ProcessGroupEl5Dir(info);
    EXPECT_EQ(info.type, Security::AccessToken::AppKeyType::GROUPID);
    SetTestReturnValue({1, 1});
    callback.ProcessGroupEl5Dir(info);
    EXPECT_EQ(info.type, Security::AccessToken::AppKeyType::GROUPID);
    SetTestReturnValue({0, 0});
    callback.ProcessGroupEl5Dir(info);
    EXPECT_EQ(info.type, Security::AccessToken::AppKeyType::GROUPID);
    SetTestReturnValue({0, 1, 1});
    callback.ProcessGroupEl5Dir(info);
    EXPECT_EQ(info.type, Security::AccessToken::AppKeyType::GROUPID);
    SetTestReturnValue({0, 1, 0, 1});
    callback.ProcessGroupEl5Dir(info);
    EXPECT_EQ(info.type, Security::AccessToken::AppKeyType::GROUPID);
}
} // OHOS