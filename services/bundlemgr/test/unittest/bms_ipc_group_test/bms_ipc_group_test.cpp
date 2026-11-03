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
#include <unordered_set>
#include <vector>

#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"
#include "inner_bundle_clone_info.h"
#include "ipc_group_info.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;

void SetGetCallingUid(int32_t uid);
void SetVerifyCallingPermissionForTest(bool value);
void ResetTestValues();

namespace OHOS {
void SetVerifyPermissionForTest(int32_t value);
namespace {
const std::string BUNDLE_NAME = "com.example.demo.testIpcGroup";
const std::string BUNDLE_NAME_TWO = "com.example.demo.testIpcGroup.two";
const std::string IPC_GROUP_ID_ONE = "teamA0001";
const std::string IPC_GROUP_ID_TWO = "teamB0002";
const std::string IPC_GROUP_ID_THREE = "my-long-team-id-xyz0003";
const std::string TEST_USER_KEY = "com.example.demo.testIpcGroup_100";
constexpr int32_t USERID = 100;
constexpr int32_t TEST_UID = 20010000;
constexpr int32_t BASE_USER_RANGE = 200000;
constexpr int32_t IPC_GROUP_UID_OFFSET = 150000;
constexpr int32_t IPC_GROUP_INDEX_START = 1;
constexpr int32_t TEST_GROUP_UID_FIRST = USERID * BASE_USER_RANGE + IPC_GROUP_INDEX_START + IPC_GROUP_UID_OFFSET;
constexpr size_t IPC_GROUP_ID_MAX_COUNT = 150;
constexpr size_t IPC_GROUP_ID_MAX_LEN = 1024;
}  // namespace

class BmsIpcGroupTest : public testing::Test {
public:
    BmsIpcGroupTest();
    ~BmsIpcGroupTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    std::shared_ptr<BundleMgrHostImpl> GetBundleMgrHostImpl() const;

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsIpcGroupTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsIpcGroupTest::BmsIpcGroupTest()
{}

BmsIpcGroupTest::~BmsIpcGroupTest()
{}

void BmsIpcGroupTest::SetUpTestCase()
{
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    bundleMgrService_->GetDataMgr()->LoadDataFromPersistentStorage();
}

void BmsIpcGroupTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsIpcGroupTest::SetUp()
{
    ResetTestValues();
    // QueryIpcGroupInfos is only open to the foundation process; the default mock UID is not it.
    SetGetCallingUid(Constants::FOUNDATION_UID);
    // Cross-user access is guarded by INTERACT_ACROSS_LOCAL_ACCOUNTS; grant it by default.
    SetVerifyCallingPermissionForTest(true);
}

void BmsIpcGroupTest::TearDown()
{}

const std::shared_ptr<BundleDataMgr> BmsIpcGroupTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

std::shared_ptr<BundleMgrHostImpl> BmsIpcGroupTest::GetBundleMgrHostImpl() const
{
    return std::make_shared<BundleMgrHostImpl>();
}

/**
 * @tc.number: ParseIpcGroupIds_0001
 * @tc.name: test ParseIpcGroupIds with format soft filter
 * @tc.desc: 1. legally formatted ids are kept, illegal ones dropped (AC-15/R-13)
 */
HWTEST_F(BmsIpcGroupTest, ParseIpcGroupIds_0001, Function | SmallTest | Level0)
{
    std::string capabilities = R"({"app-services-capabilities":{"ohos.permission.ALLOW_CROSS_APP_IPC":)"
        R"({"ipcGroupIds":["teamA0001","t0000","my-long-team-id-xyz0003","ipc-group-id-1","1234","teamA12"]}}})";
    std::vector<std::string> ids = BundleParser::ParseIpcGroupIds(capabilities);
    ASSERT_EQ(ids.size(), 3u);
    EXPECT_EQ(ids[0], IPC_GROUP_ID_ONE);
    EXPECT_EQ(ids[1], "t0000");
    EXPECT_EQ(ids[2], IPC_GROUP_ID_THREE);
}

/**
 * @tc.number: ParseIpcGroupIds_0002
 * @tc.name: test ParseIpcGroupIds count soft filter
 * @tc.desc: 1. more than 150 legal ids are truncated to 150 (AC-16/R-14)
 */
HWTEST_F(BmsIpcGroupTest, ParseIpcGroupIds_0002, Function | SmallTest | Level0)
{
    std::string idList = "[";
    for (int32_t i = 0; i <= static_cast<int32_t>(IPC_GROUP_ID_MAX_COUNT); i++) {
        if (i != 0) {
            idList += ",";
        }
        idList += "\"teamA" + std::to_string(1000 + i) + "\"";
    }
    idList += "]";
    std::string capabilities = "{\"app-services-capabilities\":{\"ohos.permission.ALLOW_CROSS_APP_IPC\":"
        "{\"ipcGroupIds\":" + idList + "}}}";
    std::vector<std::string> ids = BundleParser::ParseIpcGroupIds(capabilities);
    EXPECT_EQ(ids.size(), IPC_GROUP_ID_MAX_COUNT);
}

/**
 * @tc.number: ParseIpcGroupIds_0003
 * @tc.name: test ParseIpcGroupIds without declaration or grant
 * @tc.desc: 1. empty/unauthorized/malformed input yields empty list (AC-6/IG-F4)
 */
HWTEST_F(BmsIpcGroupTest, ParseIpcGroupIds_0003, Function | SmallTest | Level0)
{
    EXPECT_TRUE(BundleParser::ParseIpcGroupIds("").empty());
    EXPECT_TRUE(BundleParser::ParseIpcGroupIds("not a json").empty());
    std::string noGrant = R"({"app-services-capabilities":{"ohos.permission.OTHER":{"ipcGroupIds":)"
        R"(["teamA0001"]}}})";
    EXPECT_TRUE(BundleParser::ParseIpcGroupIds(noGrant).empty());
    std::string noIds = R"({"app-services-capabilities":{"ohos.permission.ALLOW_CROSS_APP_IPC":{}}})";
    EXPECT_TRUE(BundleParser::ParseIpcGroupIds(noIds).empty());
}

/**
 * @tc.number: ParseIpcGroupIds_0004
 * @tc.name: test ParseIpcGroupIds length boundary
 * @tc.desc: 1. total length <= 1024 is legal, > 1024 is dropped (AC-15/R-13)
 */
HWTEST_F(BmsIpcGroupTest, ParseIpcGroupIds_0004, Function | SmallTest | Level0)
{
    std::string maxLenId = std::string(IPC_GROUP_ID_MAX_LEN - 4, 'a') + "0001";
    ASSERT_EQ(maxLenId.size(), IPC_GROUP_ID_MAX_LEN);
    std::string tooLongId = std::string(IPC_GROUP_ID_MAX_LEN - 3, 'a') + "0001";
    std::string capabilities = "{\"app-services-capabilities\":{\"ohos.permission.ALLOW_CROSS_APP_IPC\":"
        "{\"ipcGroupIds\":[\"" + maxLenId + "\",\"" + tooLongId + "\"]}}}";
    std::vector<std::string> ids = BundleParser::ParseIpcGroupIds(capabilities);
    ASSERT_EQ(ids.size(), 1u);
    EXPECT_EQ(ids[0], maxLenId);
}

/**
 * @tc.number: IpcGroupInfoParcel_0001
 * @tc.name: test IpcGroupInfo marshalling and unmarshalling
 * @tc.desc: 1. parcel round-trip keeps all fields
 */
HWTEST_F(BmsIpcGroupTest, IpcGroupInfoParcel_0001, Function | SmallTest | Level0)
{
    IpcGroupInfo info;
    info.ipcGroupId = IPC_GROUP_ID_ONE;
    info.uid = TEST_GROUP_UID_FIRST;
    info.gid = TEST_GROUP_UID_FIRST;

    Parcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    std::unique_ptr<IpcGroupInfo> newInfo(IpcGroupInfo::Unmarshalling(parcel));
    ASSERT_NE(newInfo, nullptr);
    EXPECT_EQ(newInfo->ipcGroupId, info.ipcGroupId);
    EXPECT_EQ(newInfo->uid, info.uid);
    EXPECT_EQ(newInfo->gid, info.gid);
}

/**
 * @tc.number: IpcGroupInfoToString_0001
 * @tc.name: test ToString only keeps non-sensitive fields
 * @tc.desc: 1. ToString exposes ipcGroupId/uid/gid only
 */
HWTEST_F(BmsIpcGroupTest, IpcGroupInfoToString_0001, Function | SmallTest | Level0)
{
    IpcGroupInfo info;
    info.ipcGroupId = IPC_GROUP_ID_ONE;
    info.uid = TEST_GROUP_UID_FIRST;
    info.gid = TEST_GROUP_UID_FIRST;

    std::string text = info.ToString();
    EXPECT_NE(text.find(IPC_GROUP_ID_ONE), std::string::npos);
    EXPECT_NE(text.find(std::to_string(info.uid)), std::string::npos);
    EXPECT_NE(text.find(std::to_string(info.gid)), std::string::npos);
}

/**
 * @tc.number: GenerateIpcGroupInfos_0001
 * @tc.name: test GenerateIpcGroupInfos, bundleName not exist
 * @tc.desc: 1. bundle not found, query returns false
 */
HWTEST_F(BmsIpcGroupTest, GenerateIpcGroupInfos_0001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::unordered_set<std::string> ipcGroupIdList { IPC_GROUP_ID_ONE };
    dataMgr->GenerateIpcGroupInfos(BUNDLE_NAME, ipcGroupIdList, USERID);
    std::vector<IpcGroupInfo> infos;
    EXPECT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, USERID, infos), ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: GenerateIpcGroupInfos_0002
 * @tc.name: test GenerateIpcGroupInfos allocate uid/gid
 * @tc.desc: 1. install allocation: uid == gid, 200000 offset (AC-1)
 */
HWTEST_F(BmsIpcGroupTest, GenerateIpcGroupInfos_0002, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    std::unordered_set<std::string> ipcGroupIdList { IPC_GROUP_ID_ONE, IPC_GROUP_ID_TWO };
    dataMgr->GenerateIpcGroupInfos(BUNDLE_NAME, ipcGroupIdList, USERID);

    std::vector<IpcGroupInfo> infos;
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, USERID, infos), ERR_OK);
    ASSERT_EQ(infos.size(), 2u);
    for (const auto &ipcGroupInfo : infos) {
        EXPECT_EQ(ipcGroupInfo.uid, ipcGroupInfo.gid);
        EXPECT_GE(ipcGroupInfo.uid, USERID * BASE_USER_RANGE + IPC_GROUP_UID_OFFSET);
        EXPECT_LT(ipcGroupInfo.uid, USERID * BASE_USER_RANGE + 2 * IPC_GROUP_UID_OFFSET);
    }
}

/**
 * @tc.number: GenerateIpcGroupInfos_0003
 * @tc.name: test GenerateIpcGroupInfos update diff
 * @tc.desc: 1. ids not declared any more are deleted (AC-8)
 */
HWTEST_F(BmsIpcGroupTest, GenerateIpcGroupInfos_0003, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    std::unordered_set<std::string> ipcGroupIdList { IPC_GROUP_ID_ONE, IPC_GROUP_ID_TWO };
    dataMgr->GenerateIpcGroupInfos(BUNDLE_NAME, ipcGroupIdList, USERID);
    std::vector<IpcGroupInfo> infos;
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, USERID, infos), ERR_OK);
    ASSERT_EQ(infos.size(), 2u);

    std::unordered_set<std::string> newIpcGroupIdList { IPC_GROUP_ID_ONE };
    dataMgr->GenerateIpcGroupInfos(BUNDLE_NAME, newIpcGroupIdList, USERID);
    infos.clear();
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, USERID, infos), ERR_OK);
    ASSERT_EQ(infos.size(), 1u);
    EXPECT_EQ(infos[0].ipcGroupId, IPC_GROUP_ID_ONE);
}

/**
 * @tc.number: GenerateIpcGroupInfos_0004
 * @tc.name: test GenerateIpcGroupInfos reuse across bundles
 * @tc.desc: 1. same ipcGroupId declared by another bundle reuses uid/gid (AC-5)
 */
HWTEST_F(BmsIpcGroupTest, GenerateIpcGroupInfos_0004, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] {
        dataMgr->bundleInfos_.erase(BUNDLE_NAME);
        dataMgr->bundleInfos_.erase(BUNDLE_NAME_TWO);
    });

    std::unordered_set<std::string> ipcGroupIdList { IPC_GROUP_ID_ONE };
    dataMgr->GenerateIpcGroupInfos(BUNDLE_NAME, ipcGroupIdList, USERID);

    std::string testUserKeyTwo = BUNDLE_NAME_TWO + "_100";
    InnerBundleInfo infoTwo;
    infoTwo.baseApplicationInfo_->bundleName = BUNDLE_NAME_TWO;
    innerBundleUserInfo.bundleName = BUNDLE_NAME_TWO;
    infoTwo.innerBundleUserInfos_.emplace(testUserKeyTwo, innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TWO, infoTwo);
    dataMgr->GenerateIpcGroupInfos(BUNDLE_NAME_TWO, ipcGroupIdList, USERID);

    std::vector<IpcGroupInfo> infosOne;
    std::vector<IpcGroupInfo> infosTwo;
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, USERID, infosOne), ERR_OK);
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME_TWO, USERID, infosTwo), ERR_OK);
    ASSERT_EQ(infosOne.size(), 1u);
    ASSERT_EQ(infosTwo.size(), 1u);
    EXPECT_EQ(infosOne[0].uid, infosTwo[0].uid);
    EXPECT_EQ(infosOne[0].gid, infosTwo[0].gid);
}

/**
 * @tc.number: GenerateNewUserIpcGroupInfos_0001
 * @tc.name: test GenerateNewUserIpcGroupInfos
 * @tc.desc: 1. a newly added user inherits the existing ipcGroupIds (multi-user parity with DataGroup)
 */
HWTEST_F(BmsIpcGroupTest, GenerateNewUserIpcGroupInfos_0001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    constexpr int32_t newUserId = 101;
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
    InnerBundleUserInfo newUserInfo;
    newUserInfo.uid = TEST_UID + 1;
    newUserInfo.bundleName = BUNDLE_NAME;
    newUserInfo.bundleUserInfo.userId = newUserId;
    info.innerBundleUserInfos_.emplace(BUNDLE_NAME + "_" + std::to_string(newUserId), newUserInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    std::unordered_set<std::string> ipcGroupIdList { IPC_GROUP_ID_ONE, IPC_GROUP_ID_TWO };
    dataMgr->GenerateIpcGroupInfos(BUNDLE_NAME, ipcGroupIdList, USERID);

    dataMgr->GenerateNewUserIpcGroupInfos(BUNDLE_NAME, newUserId);
    std::vector<IpcGroupInfo> infos;
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, newUserId, infos), ERR_OK);
    ASSERT_EQ(infos.size(), 2u);
    for (const auto &ipcGroupInfo : infos) {
        EXPECT_EQ(ipcGroupInfo.uid, ipcGroupInfo.gid);
    }
}

/**
 * @tc.number: DeleteUserIpcGroupInfos_0001
 * @tc.name: test DeleteUserIpcGroupInfos
 * @tc.desc: 1. uninstall removes the user's records (AC-9)
 */
HWTEST_F(BmsIpcGroupTest, DeleteUserIpcGroupInfos_0001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    std::unordered_set<std::string> ipcGroupIdList { IPC_GROUP_ID_ONE };
    dataMgr->GenerateIpcGroupInfos(BUNDLE_NAME, ipcGroupIdList, USERID);
    std::vector<IpcGroupInfo> infos;
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, USERID, infos), ERR_OK);
    ASSERT_EQ(infos.size(), 1u);

    dataMgr->bundleInfos_.at(BUNDLE_NAME).RemoveInnerBundleUserInfo(USERID);
    infos.clear();
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, USERID, infos), ERR_OK);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: IpcGroupCloneShare_0001
 * @tc.name: test clone app shares ipc group uid/gid with main app
 * @tc.desc: 1. clone (appIndex) and main share one InnerBundleInfo, so the ipcGroup uid/gid is shared (AC-10)
 */
HWTEST_F(BmsIpcGroupTest, IpcGroupCloneShare_0001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    std::unordered_set<std::string> ipcGroupIdList { IPC_GROUP_ID_ONE };
    dataMgr->GenerateIpcGroupInfos(BUNDLE_NAME, ipcGroupIdList, USERID);

    std::vector<IpcGroupInfo> mainInfos;
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, USERID, mainInfos), ERR_OK);
    ASSERT_EQ(mainInfos.size(), 1u);

    // register a clone app (appIndex 1) in the same InnerBundleInfo; it keeps its own
    // process uid but shares the ipc group record with the main app.
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.appIndex = 1;
    cloneInfo.userId = USERID;
    cloneInfo.uid = TEST_UID + 1;
    dataMgr->bundleInfos_[BUNDLE_NAME].innerBundleUserInfos_[TEST_USER_KEY].cloneInfos.emplace("1", cloneInfo);

    std::vector<IpcGroupInfo> cloneInfos;
    ASSERT_EQ(dataMgr->QueryIpcGroupInfos(BUNDLE_NAME, USERID, cloneInfos), ERR_OK);
    ASSERT_EQ(cloneInfos.size(), 1u);
    EXPECT_EQ(cloneInfos[0].uid, mainInfos[0].uid);
    EXPECT_EQ(cloneInfos[0].gid, mainInfos[0].gid);
    EXPECT_EQ(cloneInfos[0].ipcGroupId, mainInfos[0].ipcGroupId);
}

/**
 * @tc.number: QueryIpcGroupInfos_0001
 * @tc.name: test QueryIpcGroupInfos, caller is not foundation
 * @tc.desc: 1. a non-foundation caller gets 8521226 (AC-12)
 */
HWTEST_F(BmsIpcGroupTest, QueryIpcGroupInfos_0001, Function | SmallTest | Level0)
{
    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);
    SetGetCallingUid(Constants::FOUNDATION_UID + 1);
    std::vector<IpcGroupInfo> infos;
    ErrCode ret = hostImpl->QueryIpcGroupInfos(BUNDLE_NAME, USERID, infos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: QueryIpcGroupInfos_0002
 * @tc.name: test QueryIpcGroupInfos, bundle not exist
 * @tc.desc: 1. bundleName not found returns 8521220 (AC-13)
 */
HWTEST_F(BmsIpcGroupTest, QueryIpcGroupInfos_0002, Function | SmallTest | Level0)
{
    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);
    SetGetCallingUid(Constants::FOUNDATION_UID);
    std::vector<IpcGroupInfo> infos;
    ErrCode ret = hostImpl->QueryIpcGroupInfos(BUNDLE_NAME, USERID, infos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: QueryIpcGroupInfos_0003
 * @tc.name: test QueryIpcGroupInfos, cross user without permission
 * @tc.desc: 1. foundation caller reading another user's group identity without the across-user
 *              permission returns 8521226 (AC-12)
 */
HWTEST_F(BmsIpcGroupTest, QueryIpcGroupInfos_0003, Function | SmallTest | Level0)
{
    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);
    SetGetCallingUid(Constants::FOUNDATION_UID);
    SetVerifyCallingPermissionForTest(false);
    std::vector<IpcGroupInfo> infos;
    ErrCode ret = hostImpl->QueryIpcGroupInfos(BUNDLE_NAME, USERID + 1, infos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: AllocateIpcGroupInfos_0001
 * @tc.name: test commit-time ipc group uid allocation
 * @tc.desc: 1. groups prepared with uid 0 get a uid at commit and are propagated to every user
 */
HWTEST_F(BmsIpcGroupTest, AllocateIpcGroupInfos_0001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    constexpr int32_t secondUserId = 101;
    InnerBundleInfo info;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);
    InnerBundleUserInfo secondUserInfo;
    secondUserInfo.uid = TEST_UID + 1;
    secondUserInfo.bundleName = BUNDLE_NAME;
    secondUserInfo.bundleUserInfo.userId = secondUserId;
    info.AddInnerBundleUserInfo(secondUserInfo);

    IpcGroupInfo prepared;
    prepared.ipcGroupId = IPC_GROUP_ID_ONE;   // uid/gid intentionally 0: allocated at commit
    ASSERT_TRUE(info.AddIpcGroupInfo(USERID, IPC_GROUP_ID_ONE, prepared));

    dataMgr->AllocateIpcGroupInfos(info);

    std::unordered_map<std::string, IpcGroupInfo> firstUserInfos;
    ASSERT_TRUE(info.GetIpcGroupInfos(USERID, firstUserInfos));
    ASSERT_EQ(firstUserInfos.size(), 1u);
    int32_t firstUid = firstUserInfos.at(IPC_GROUP_ID_ONE).uid;
    EXPECT_EQ(firstUid, firstUserInfos.at(IPC_GROUP_ID_ONE).gid);
    EXPECT_GE(firstUid, USERID * BASE_USER_RANGE + IPC_GROUP_UID_OFFSET + IPC_GROUP_INDEX_START);

    // The same group id must be propagated to the other user with the same index.
    std::unordered_map<std::string, IpcGroupInfo> secondUserInfos;
    ASSERT_TRUE(info.GetIpcGroupInfos(secondUserId, secondUserInfos));
    ASSERT_EQ(secondUserInfos.size(), 1u);
    EXPECT_EQ(secondUserInfos.at(IPC_GROUP_ID_ONE).uid - secondUserId * BASE_USER_RANGE,
        firstUid - USERID * BASE_USER_RANGE);
}

/**
 * @tc.number: UpdateIpcGroupInfos_0001
 * @tc.name: test UpdateIpcGroupInfos with empty map keeps records
 * @tc.desc: 1. module-update path passes an empty map; existing ipc groups must be preserved (AC-8)
 */
HWTEST_F(BmsIpcGroupTest, UpdateIpcGroupInfos_0001, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);

    IpcGroupInfo groupInfo;
    groupInfo.ipcGroupId = IPC_GROUP_ID_ONE;
    groupInfo.uid = TEST_GROUP_UID_FIRST;
    groupInfo.gid = TEST_GROUP_UID_FIRST;
    info.AddIpcGroupInfo(USERID, IPC_GROUP_ID_ONE, groupInfo);

    std::unordered_map<std::string, IpcGroupInfo> infos;
    ASSERT_TRUE(info.GetIpcGroupInfos(USERID, infos));
    ASSERT_EQ(infos.size(), 1u);

    // Module update restores only AppCodePath, so the new info carries an empty map.
    info.UpdateIpcGroupInfos(USERID, {});

    infos.clear();
    ASSERT_TRUE(info.GetIpcGroupInfos(USERID, infos));
    ASSERT_EQ(infos.size(), 1u);
    EXPECT_EQ(infos.at(IPC_GROUP_ID_ONE).uid, TEST_GROUP_UID_FIRST);
}
}  // namespace OHOS
