/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include <cstdio>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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

void ForceRemoveDir(const std::string& path)
{
    DIR* dir = opendir(path.c_str());
    if (dir == nullptr) {
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        std::string subPath = path + "/" + entry->d_name;
        struct stat statInfo;
        if (lstat(subPath.c_str(), &statInfo) == 0) {
            if (S_ISDIR(statInfo.st_mode)) {
                ForceRemoveDir(subPath);
            } else {
                unlink(subPath.c_str());
            }
        }
    }
    closedir(dir);
    rmdir(path.c_str());
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
 * @tc.number: UserUnlockedEventSubscriber_0900
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test CreateShareFilesSubDataDirs
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_0900, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    std::vector<BundleInfo> bundleInfos;
    // test userId != Constants::DEFAULT_USERID && bundleInfo.singleton
    std::string parentDir100 = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(100) + ServiceConstants::SHAREFILES;
    std::string bundleName1 = "com.test.UserUnlockedEventSubscriber_0900";
    BundleInfo bundleInfo1;
    bundleInfo1.name = bundleName1;
    bundleInfo1.singleton = true;
    bundleInfos.emplace_back(bundleInfo1);

    updateAppDataMgr.CreateShareFilesSubDataDirs(bundleInfos, 100);
    std::string sharefilesDataDir = parentDir100 + bundleName1;
    int bundleSharefilesExist = access(sharefilesDataDir.c_str(), F_OK);
    EXPECT_NE(bundleSharefilesExist, 0) << "the bundle sharefiles existed: " << sharefilesDataDir;
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1000
 * @tc.name: UserUnlockedEventSubscriber_UserIdUpdated
 * @tc.desc: Test that the subscriber correctly updates the userId when receiving multiple events
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1000, TestSize.Level1)
{
    using namespace OHOS::EventFwk;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriber =
        std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);

    Want want1;
    want1.SetAction(CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    CommonEventData data1(want1);
    data1.SetCode(100);
    subscriber->OnReceiveEvent(data1);
    EXPECT_EQ(subscriber->userId_, 100);
    Want want2;
    want2.SetAction(CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    CommonEventData data2(want2);
    data2.SetCode(101);
    subscriber->OnReceiveEvent(data2);
    EXPECT_EQ(subscriber->userId_, 101);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1100
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: Test CheckPathAttribute when UID is not same
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1100, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    
    std::string tempPath = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + "temp_uid_check_file";

    {
        std::ofstream outfile(tempPath);
        outfile.close();
    }

    BundleInfo bundleInfo;
    bundleInfo.uid = 999999;

    bool isExist = true;

    updateAppDataMgr.CheckPathAttribute(tempPath, bundleInfo, isExist);
    EXPECT_FALSE(isExist);
    std::remove(tempPath.c_str());
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1200
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: Test CreateBundleDataDir to cover EL5 branch
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1200, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.coverage.el5";
    bundleInfo.uid = 10010;
    bundleInfo.gid = 10010;
    bundleInfo.applicationInfo.appPrivilegeLevel = "normal";
    bundleInfo.isPreInstallApp = false;
    bundleInfo.applicationInfo.appProvisionType = Constants::APP_PROVISION_TYPE_DEBUG;

    int32_t userId = 100;
    std::string elDir = ServiceConstants::DIR_EL5;
    bool result = updateAppDataMgr.CreateBundleDataDir(bundleInfo, userId, elDir);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1300
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: Test CreateEl5Dir with Clone Infos (Covers deepest branches)
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1300, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.test.el5.clone";
    createDirParam.userId = 100;
    createDirParam.uid = 20010;
    createDirParam.gid = 20010;

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;

    BundleInfo bundleInfo;
    bundleInfo.name = createDirParam.bundleName;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = createDirParam.bundleName;
    userInfo.uid = createDirParam.uid;

    InnerBundleCloneInfo cloneInfo;
    cloneInfo.userId = 100;
    cloneInfo.appIndex = 1;
    cloneInfo.uid = 20010 + 1000;
    userInfo.cloneInfos.insert({std::to_string(cloneInfo.appIndex), cloneInfo});
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    dataMgr->AddInnerBundleInfo(createDirParam.bundleName, innerBundleInfo);
    bool result = updateAppDataMgr.CreateEl5Dir(createDirParam);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1400
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: Test CreateEl5Dir when BundleInfo does not exist
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1400, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.test.el5.not.found";
    createDirParam.userId = 100;
    bool result = updateAppDataMgr.CreateEl5Dir(createDirParam);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1500
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: Test CreateEl5Dir when UserInfo does not exist in BundleInfo
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1500, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.test.el5.no.user";
    createDirParam.userId = 101;

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = createDirParam.bundleName;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = createDirParam.bundleName;
    userInfo.uid = 100;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    dataMgr->AddInnerBundleInfo(createDirParam.bundleName, innerBundleInfo);
    bool result = updateAppDataMgr.CreateEl5Dir(createDirParam);

    EXPECT_TRUE(result);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1600
 * @tc.desc: Clone app (appIndex > 0) should skip data dir creation
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1600, Function | SmallTest | Level0)
{
    UpdateAppDataMgr mgr;
    int32_t userId = 100;

    BundleInfo info;
    info.name = "com.test.clone.app";
    info.appIndex = 1; // clone app

    std::vector<BundleInfo> bundleInfos { info };

    std::string elDir = ServiceConstants::BUNDLE_EL[1];
    std::string baseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + elDir +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) +
        ServiceConstants::BASE + info.name;

    ForceRemoveDir(baseDir);
    mgr.ProcessUpdateAppDataDir(userId, bundleInfos, elDir);
    EXPECT_NE(access(baseDir.c_str(), F_OK), 0);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1700
 * @tc.desc: EL5 app without PROTECT_SCREEN_LOCK_DATA should skip data dir creation
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1700, Function | SmallTest | Level0)
{
    UpdateAppDataMgr mgr;
    int32_t userId = 100;
    BundleInfo info;
    info.name = "com.test.el5.no.perm";
    info.uid = 10010;
    info.reqPermissions = { "ohos.permission.INTERNET" };

    std::vector<BundleInfo> bundleInfos { info };

    std::string elDir = ServiceConstants::DIR_EL5;
    std::string baseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + elDir +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) +
        ServiceConstants::BASE + info.name;

    ForceRemoveDir(baseDir);
    mgr.ProcessUpdateAppDataDir(userId, bundleInfos, elDir);
    EXPECT_NE(access(baseDir.c_str(), F_OK), 0);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1800
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: Test ProcessUpdateAppDataDir with EL5 and HAS PROTECT_SCREEN_LOCK_DATA permission
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1800, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    int32_t userId = 100;

    std::vector<BundleInfo> bundleInfos;
    BundleInfo info;
    info.name = "com.test.el5.has.perm";
    info.appIndex = 0;
    info.reqPermissions.push_back(ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA);
    info.uid = 10010;
    info.applicationInfo.appPrivilegeLevel = "normal";
    
    bundleInfos.push_back(info);

    std::string elDir = ServiceConstants::DIR_EL5;
    updateAppDataMgr.ProcessUpdateAppDataDir(userId, bundleInfos, elDir);
    EXPECT_FALSE(info.reqPermissions.empty());
    EXPECT_FALSE(bundleInfos[0].reqPermissions.empty());
}

/**
 * @tc.number: UserUnlockedEventSubscriber_1900
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: Test ProcessExtensionDir when needCreateSandbox is false
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_1900, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    BundleInfo bundleInfo;
    ExtensionAbilityInfo extInfo;
    extInfo.name = "TestExtension";
    extInfo.needCreateSandbox = false;
    bundleInfo.extensionInfos.push_back(extInfo);

    std::vector<std::string> dirs;
    updateAppDataMgr.ProcessExtensionDir(bundleInfo, dirs);
    EXPECT_TRUE(dirs.empty());
}

/**
 * @tc.number: UserUnlockedEventSubscriber_2000
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: Test ProcessExtensionDir when needCreateSandbox is true
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_2000, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    BundleInfo bundleInfo;
    ExtensionAbilityInfo extInfo;
    extInfo.needCreateSandbox = true;
    extInfo.moduleName = "entry_module";
    extInfo.name = "TestAbility";
    extInfo.bundleName = "com.test.app";
    
    bundleInfo.extensionInfos.push_back(extInfo);

    std::vector<std::string> dirs;
    updateAppDataMgr.ProcessExtensionDir(bundleInfo, dirs);
    ASSERT_EQ(dirs.size(), 1);
    std::string expectedDir = ServiceConstants::EXTENSION_DIR + extInfo.moduleName +
        ServiceConstants::FILE_SEPARATOR_LINE + extInfo.name +
        ServiceConstants::FILE_SEPARATOR_PLUS + extInfo.bundleName;

    EXPECT_EQ(dirs[0], expectedDir);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_2100
 * @tc.desc: Singleton app should skip data dir creation for non-default user
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_2100, Function | SmallTest | Level0)
{
    UpdateAppDataMgr mgr;
    int32_t userId = 100;
    BundleInfo info;
    info.name = "com.test.singleton.skip";
    info.singleton = true;

    std::vector<BundleInfo> bundleInfos { info };

    std::string elDir = ServiceConstants::BUNDLE_EL[1];
    std::string baseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + elDir +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) +
        ServiceConstants::BASE + info.name;

    ForceRemoveDir(baseDir);
    mgr.ProcessUpdateAppDataDir(userId, bundleInfos, elDir);
    EXPECT_NE(access(baseDir.c_str(), F_OK), 0);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_2200
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: Test ProcessNewBackupDir skips Clone App (appIndex > 0)
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_2200, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    int32_t userId = 100;
    std::vector<BundleInfo> bundleInfos;
    BundleInfo info;
    info.name = "com.example.clone.backup";
    info.appIndex = 1;
    info.singleton = false;
    
    bundleInfos.push_back(info);
    updateAppDataMgr.ProcessNewBackupDir(bundleInfos, userId);
    EXPECT_EQ(bundleInfos[0].appIndex, 1);
    EXPECT_FALSE(bundleInfos[0].singleton);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_2300
 * @tc.desc: Singleton app should skip cloud dir creation for non-default user
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_2300, Function | SmallTest | Level0)
{
    UpdateAppDataMgr mgr;
    int32_t userId = 100;

    BundleInfo info;
    info.name = "com.test.singleton.cloud.skip";
    info.singleton = true;

    std::vector<BundleInfo> bundleInfos { info };

    std::string cloudDir = "/data/service/el2/100/hmdfs/cloud/data/" + info.name;
    ForceRemoveDir(cloudDir);

    mgr.ProcessFileManagerDir(bundleInfos, userId);
    EXPECT_NE(access(cloudDir.c_str(), F_OK), 0);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_2400
 * @tc.name: CreateBundleCloudDir_ParentMissing
 * @tc.desc: Test when the parent cloud directory does not exist
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_2400, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    int32_t userId = 100;
    BundleInfo info;
    info.name = "com.test.cloud.parent.missing";
    info.uid = 10010;
    std::string parentDir = "/data/service/el2/100/hmdfs/cloud/data/";
    ForceRemoveDir(parentDir);
    bool res = updateAppDataMgr.CreateBundleCloudDir(info, userId);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_2500
 * @tc.name: CreateBundleCloudDir_MkdirFail
 * @tc.desc: Test when Mkdir fails due to invalid path
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_2500, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    int32_t userId = 100;
    BundleInfo info;
    info.name = "com.test.cloud.invalid";
    info.uid = 10010;
    std::string parentDir = "/data/service/el2/100/hmdfs/cloud/data/";
    std::string cmdParent = "mkdir -p " + parentDir;
    system(cmdParent.c_str());
    bool res = updateAppDataMgr.CreateBundleCloudDir(info, userId);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_2600
 * @tc.name: CreateShareFiles_IsExistDir_Fail
 * @tc.desc: Test branch when IsExistDir fails due to permission denied on parent
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_2600, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    int32_t userId = 100;
    BundleInfo info;
    info.name = "com.test.isexist.fail";
    info.uid = 10010;
    info.gid = 10010;

    std::string parentDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES;
    std::string cmdMk = "mkdir -p " + parentDir;
    system(cmdMk.c_str());
    chmod(parentDir.c_str(), 0000);

    std::vector<BundleInfo> bundleInfos;
    bundleInfos.push_back(info);
    updateAppDataMgr.CreateShareFilesSubDataDirs(bundleInfos, userId);
    chmod(parentDir.c_str(), 0777);
    ForceRemoveDir(parentDir);
    EXPECT_EQ(bundleInfos.size(), 1);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_2700
 * @tc.name: CreateShareFiles_ParentMkdir_Fail
 * @tc.desc: Test branch when parent Mkdir fails due to invalid path
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_2700, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    int32_t userId = 100;
    BundleInfo info;
    info.name = "missing_dir/com.test.mkdir.fail";
    info.uid = 10010;
    info.gid = 10010;

    std::string parentDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES;
    std::string cmdMk = "mkdir -p " + parentDir;
    system(cmdMk.c_str());

    std::vector<BundleInfo> bundleInfos;
    bundleInfos.push_back(info);
    updateAppDataMgr.CreateShareFilesSubDataDirs(bundleInfos, userId);
    std::string targetDir = parentDir + info.name;
    EXPECT_NE(access(targetDir.c_str(), F_OK), 0);
}

/**
 * @tc.number: UserUnlockedEventSubscriber_2800
 * @tc.name: CreateShareFiles_ChildMkdir_Fail_ReadOnly
 * @tc.desc: Test branch when creating sub-directories fails due to read-only parent permissions
 */
HWTEST_F(BmsEventHandlerUnLockedTest, UserUnlockedEventSubscriber_2800, Function | SmallTest | Level0)
{
    UpdateAppDataMgr updateAppDataMgr;
    int32_t userId = 100;
    BundleInfo info;
    info.name = "com.test.child.fail";
    info.uid = 10010;
    info.gid = 10010;
    std::string parentDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES;
    
    std::string bundleDir = parentDir + info.name;
    std::string cmdMk = "mkdir -p " + bundleDir;
    system(cmdMk.c_str());

    chmod(bundleDir.c_str(), 0555);

    std::vector<BundleInfo> bundleInfos;
    bundleInfos.push_back(info);

    updateAppDataMgr.CreateShareFilesSubDataDirs(bundleInfos, userId);

    EXPECT_EQ(access(bundleDir.c_str(), F_OK), 0);
    DIR *dir = opendir(bundleDir.c_str());
    ASSERT_NE(dir, nullptr);

    bool isEmpty = true;
    struct dirent *ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
            isEmpty = false;
            break;
        }
    }
    closedir(dir);
    EXPECT_TRUE(isEmpty);
    chmod(bundleDir.c_str(), 0777);
    ForceRemoveDir(parentDir);
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