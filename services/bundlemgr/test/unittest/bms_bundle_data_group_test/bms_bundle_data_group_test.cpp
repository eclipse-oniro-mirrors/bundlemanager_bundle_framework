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

#include <fstream>
#include <gtest/gtest.h>

#include "app_provision_info_manager.h"
#include "base_bundle_installer.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "data_group_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "migrate_data_user_auth_callback.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.demo.testDataGroup";
const std::string BUNDLE_NAME_TEST = "com.example.demo.testDataGroup.test";
const std::string DATA_GROUP_ID_TEST_ONE = "data-group-id-1";
const std::string DATA_GROUP_ID_TEST_TWO = "data-group-id-2";
const std::string DATA_GROUP_ID_TEST_THREE = "data-group-id-3";
const std::string DATA_GROUP_UUID_ONE = "2105e98a-12ae-4a4f-8ed1-fc32e5f45416";
const std::string DATA_GROUP_UUID_TWO = "4f4b48a2-7c27-466b-8601-8e5e9965036d";
const std::string DATA_GROUP_DIR_TEST = "data/app/el2/100/group/2105e98a-12ae-4a4f-8ed1-fc32e5f45416";
const std::string TEST_HAP_PATH = "/data/test/test.hap";
const std::string TEST_USER_KEY = "com.example.demo.testDataGroup_100";
constexpr int32_t BMS_UID = 1000;
constexpr int32_t USERID = 100;
constexpr int32_t USERID_TWO = 101;
constexpr int32_t TEST_UID = 20019999;
constexpr int32_t TEST_UID_INVALID = 20019998;
constexpr int32_t TEST_GROUP_INDEX_ONE = 1;
constexpr int32_t TEST_GROUP_INDEX_TWO = 2;
constexpr int32_t TEST_GROUP_INDEX_THREE = 3;
constexpr int32_t TEST_GROUP_INDEX_FORE = 4;
const int32_t WAIT_TIME = 5;
constexpr int32_t DATA_GROUP_UID_OFFSET = 100000;
}  // namespace

class BmsBundleDataGroupTest : public testing::Test {
public:
    BmsBundleDataGroupTest();
    ~BmsBundleDataGroupTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleDataGroupTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleDataGroupTest::BmsBundleDataGroupTest()
{}

BmsBundleDataGroupTest::~BmsBundleDataGroupTest()
{}

void BmsBundleDataGroupTest::SetUpTestCase()
{}

void BmsBundleDataGroupTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleDataGroupTest::SetUp()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleDataGroupTest::TearDown()
{}

const std::shared_ptr<BundleDataMgr> BmsBundleDataGroupTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: RemoveDataGroupDirs_0010
 * @tc.name: test RemoveDataGroupDirs
 * @tc.desc: 1.RemoveDataGroupDirs
 */
HWTEST_F(BmsBundleDataGroupTest, RemoveDataGroupDirs_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    auto result = installer.RemoveDataGroupDirs(BUNDLE_NAME, USERID);
    EXPECT_EQ(result, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: RemoveDataGroupDirs_0020
 * @tc.name: test RemoveDataGroupDirs
 * @tc.desc: 1.RemoveDataGroupDirs
 */
HWTEST_F(BmsBundleDataGroupTest, RemoveDataGroupDirs_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    auto result = installer.RemoveDataGroupDirs(BUNDLE_NAME, USERID);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: RemoveDataGroupDirs_0030
 * @tc.name: test RemoveDataGroupDirs
 * @tc.desc: 1.RemoveDataGroupDirs
 */
HWTEST_F(BmsBundleDataGroupTest, RemoveDataGroupDirs_0030, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    InnerBundleInfo info;
    DataGroupInfo dataGroupInfo;
    dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
    dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
    dataGroupInfo.userId = USERID;
    info.AddDataGroupInfo(DATA_GROUP_ID_TEST_ONE, dataGroupInfo);

    auto &bundleInfos = installer.dataMgr_->bundleInfos_;
    auto iter = bundleInfos.find(BUNDLE_NAME);
    if (iter == bundleInfos.end()) {
        bundleInfos.emplace(BUNDLE_NAME, info);
    }
    setuid(Constants::FOUNDATION_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    ErrCode ret = installer.RemoveDataGroupDirs(BUNDLE_NAME, USERID);
    EXPECT_EQ(ret, ERR_OK);
    if (iter == bundleInfos.end()) {
        bundleInfos.erase(BUNDLE_NAME);
    }
}

/**
 * @tc.number: RemoveDataGroupDirs_0040
 * @tc.name: test RemoveDataGroupDirs
 * @tc.desc: 1.RemoveDataGroupDirs
 */
HWTEST_F(BmsBundleDataGroupTest, RemoveDataGroupDirs_0040, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    InnerBundleInfo info;
    DataGroupInfo dataGroupInfo;
    dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
    dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
    dataGroupInfo.userId = USERID;
    info.AddDataGroupInfo(DATA_GROUP_ID_TEST_ONE, dataGroupInfo);

    auto &bundleInfos = installer.dataMgr_->bundleInfos_;
    auto iter = bundleInfos.find(BUNDLE_NAME);
    if (iter == bundleInfos.end()) {
        bundleInfos.emplace(BUNDLE_NAME, info);
    }
    setuid(Constants::FOUNDATION_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    auto createDirRes = InstalldClient::GetInstance()->Mkdir(DATA_GROUP_DIR_TEST, S_IRWXU, BMS_UID, BMS_UID);
    EXPECT_EQ(createDirRes, ERR_OK);

    ErrCode ret = installer.RemoveDataGroupDirs(BUNDLE_NAME, USERID);
    EXPECT_EQ(ret, ERR_OK);
    if (iter == bundleInfos.end()) {
        bundleInfos.erase(BUNDLE_NAME);
    }
}

/**
 * @tc.number: QueryDataGroupInfos_0010
 * @tc.name: test QueryDataGroupInfos
 * @tc.desc: 1.QueryDataGroupInfos
 */
HWTEST_F(BmsBundleDataGroupTest, QueryDataGroupInfos_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<DataGroupInfo> infos;
    bool res = dataMgr->QueryDataGroupInfos(BUNDLE_NAME, USERID, infos);
    EXPECT_FALSE(res);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: QueryDataGroupInfos_0020
 * @tc.name: test QueryDataGroupInfos
 * @tc.desc: 1.QueryDataGroupInfos
 */
HWTEST_F(BmsBundleDataGroupTest, QueryDataGroupInfos_0020, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    std::vector<DataGroupInfo> infos;
    bool res = dataMgr->QueryDataGroupInfos(BUNDLE_NAME, USERID, infos);
    EXPECT_TRUE(res);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: QueryDataGroupInfos_0030
 * @tc.name: test QueryDataGroupInfos
 * @tc.desc: 1.QueryDataGroupInfos
 */
HWTEST_F(BmsBundleDataGroupTest, QueryDataGroupInfos_0030, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    DataGroupInfo dataGroupInfo;
    dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
    dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
    dataGroupInfo.userId = USERID;
    info.dataGroupInfos_.emplace(DATA_GROUP_ID_TEST_ONE, std::vector<DataGroupInfo> { dataGroupInfo });
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    std::vector<DataGroupInfo> infos;
    bool res = dataMgr->QueryDataGroupInfos(BUNDLE_NAME, USERID, infos);
    EXPECT_TRUE(res);
    EXPECT_FALSE(infos.empty());
}

/**
 * @tc.number: GetGroupDir_0010
 * @tc.name: test GetGroupDir
 * @tc.desc: 1.GetGroupDir
 */
HWTEST_F(BmsBundleDataGroupTest, GetGroupDir_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo info;
    DataGroupInfo dataGroupInfo;
    dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
    dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
    dataGroupInfo.userId = USERID;
    info.dataGroupInfos_.emplace(DATA_GROUP_ID_TEST_ONE, std::vector<DataGroupInfo> { dataGroupInfo });
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    std::string dir;
    bool res = dataMgr->GetGroupDir(DATA_GROUP_ID_TEST_ONE, dir, USERID);
    EXPECT_TRUE(res);
    EXPECT_FALSE(dir.empty());
}

/**
 * @tc.number: GetGroupDir_0020
 * @tc.name: test GetGroupDir
 * @tc.desc: 1.GetGroupDir
 */
HWTEST_F(BmsBundleDataGroupTest, GetGroupDir_0020, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo info;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);

    DataGroupInfo dataGroupInfo;
    dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
    dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
    dataGroupInfo.userId = USERID;
    info.dataGroupInfos_.emplace(DATA_GROUP_ID_TEST_ONE, std::vector<DataGroupInfo> { dataGroupInfo });
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    setuid(TEST_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    std::string dir;
    bool res = dataMgr->GetGroupDir(DATA_GROUP_ID_TEST_ONE, dir, Constants::UNSPECIFIED_USERID);
    EXPECT_TRUE(res);
    EXPECT_FALSE(dir.empty());
}

/**
 * @tc.number: GetGroupDir_0030
 * @tc.name: test GetGroupDir
 * @tc.desc: 1.GetGroupDir
 */
HWTEST_F(BmsBundleDataGroupTest, GetGroupDir_0030, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo info;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

    setuid(TEST_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    std::string dir;
    bool res = dataMgr->GetGroupDir(DATA_GROUP_ID_TEST_ONE, dir, Constants::UNSPECIFIED_USERID);
    EXPECT_FALSE(res);
    EXPECT_TRUE(dir.empty());
}

/**
 * @tc.number: GetGroupDir_0040
 * @tc.name: test GetGroupDir
 * @tc.desc: 1.GetGroupDir
 */
HWTEST_F(BmsBundleDataGroupTest, GetGroupDir_0040, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    setuid(TEST_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    std::string dir;
    bool res = dataMgr->GetGroupDir(DATA_GROUP_ID_TEST_ONE, dir, Constants::UNSPECIFIED_USERID);
    EXPECT_FALSE(res);
    EXPECT_TRUE(dir.empty());
}

/**
 * @tc.number: GetGroupDir_0050
 * @tc.name: test GetGroupDir
 * @tc.desc: 1.GetGroupDir
 */
HWTEST_F(BmsBundleDataGroupTest, GetGroupDir_0050, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string dir;
    bool res = dataMgr->GetGroupDir(DATA_GROUP_ID_TEST_ONE, dir, USERID);
    EXPECT_FALSE(res);
    EXPECT_TRUE(dir.empty());
}

/**
 * @tc.number: GenerateDataGroupInfos_0010
 * @tc.name: test GenerateDataGroupInfos
 * @tc.desc: 1.GenerateDataGroupInfos, bundleName not exist
 */
HWTEST_F(BmsBundleDataGroupTest, GenerateDataGroupInfos_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        std::unordered_set<std::string> dataGroupIdList;
        dataMgr->GenerateDataGroupInfos(BUNDLE_NAME, dataGroupIdList, USERID);
        std::vector<DataGroupInfo> dataGroupInfos;
        bool res = dataMgr->QueryDataGroupInfos(BUNDLE_NAME, USERID, dataGroupInfos);
        EXPECT_FALSE(res);
        EXPECT_TRUE(dataGroupInfos.empty());
    }
}

/**
 * @tc.number: GenerateDataGroupInfos_0020
 * @tc.name: test GenerateDataGroupInfos
 * @tc.desc: 1.GenerateDataGroupInfos, groupId empty
 */
HWTEST_F(BmsBundleDataGroupTest, GenerateDataGroupInfos_0020, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerBundleInfo info;
        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleUserInfo.uid = TEST_UID;
        info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
        dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
        ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

        std::unordered_set<std::string> dataGroupIdList;
        dataMgr->GenerateDataGroupInfos(BUNDLE_NAME, dataGroupIdList, USERID);

        std::vector<DataGroupInfo> dataGroupInfos;
        bool res = dataMgr->QueryDataGroupInfos(BUNDLE_NAME, USERID, dataGroupInfos);
        EXPECT_TRUE(res);
        EXPECT_TRUE(dataGroupInfos.empty());
    }
}

/**
 * @tc.number: GenerateDataGroupInfos_0030
 * @tc.name: test GenerateDataGroupInfos
 * @tc.desc: 1.GenerateDataGroupInfos
 */
HWTEST_F(BmsBundleDataGroupTest, GenerateDataGroupInfos_0030, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        DataGroupInfo dataGroupInfo;
        dataGroupInfo.userId = USERID;
        std::vector<DataGroupInfo> dataGroupVector;
        dataGroupVector.push_back(dataGroupInfo);

        InnerBundleInfo info;
        info.dataGroupInfos_[DATA_GROUP_ID_TEST_ONE] = dataGroupVector;
        info.dataGroupInfos_[DATA_GROUP_ID_TEST_TWO] = dataGroupVector;
        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleUserInfo.uid = TEST_UID;
        info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
        dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
        ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });
        std::vector<DataGroupInfo> dataGroupInfos;
        bool res = dataMgr->QueryDataGroupInfos(BUNDLE_NAME, USERID, dataGroupInfos);
        EXPECT_TRUE(res);
        EXPECT_FALSE(dataGroupInfos.empty());

        std::unordered_set<std::string> dataGroupIdList;
        dataMgr->GenerateDataGroupInfos(BUNDLE_NAME, dataGroupIdList, USERID);

        dataGroupInfos.clear();
        res = dataMgr->QueryDataGroupInfos(BUNDLE_NAME, USERID, dataGroupInfos);
        EXPECT_TRUE(res);
        EXPECT_TRUE(dataGroupInfos.empty());
    }
}

/**
 * @tc.number: GenerateDataGroupInfos_0040
 * @tc.name: test GenerateDataGroupInfos
 * @tc.desc: 1.GenerateDataGroupInfos
 */
HWTEST_F(BmsBundleDataGroupTest, GenerateDataGroupInfos_0040, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        DataGroupInfo dataGroupInfo;
        dataGroupInfo.userId = USERID;
        dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
        std::vector<DataGroupInfo> dataGroupVector;
        dataGroupVector.push_back(dataGroupInfo);

        InnerBundleInfo info;
        info.dataGroupInfos_[DATA_GROUP_ID_TEST_ONE] = dataGroupVector;
        info.dataGroupInfos_[DATA_GROUP_ID_TEST_TWO] = dataGroupVector;
        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleUserInfo.uid = TEST_UID;
        info.innerBundleUserInfos_.emplace(TEST_USER_KEY, innerBundleUserInfo);
        dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
        ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });
        std::vector<DataGroupInfo> dataGroupInfos;
        bool res = dataMgr->QueryDataGroupInfos(BUNDLE_NAME, USERID, dataGroupInfos);
        EXPECT_TRUE(res);
        EXPECT_FALSE(dataGroupInfos.empty());

        std::unordered_set<std::string> dataGroupIdList;
        dataGroupIdList.insert(DATA_GROUP_ID_TEST_ONE);
        dataMgr->GenerateDataGroupInfos(BUNDLE_NAME, dataGroupIdList, USERID);

        dataGroupInfos.clear();
        res = dataMgr->QueryDataGroupInfos(BUNDLE_NAME, USERID, dataGroupInfos);
        EXPECT_TRUE(res);
        EXPECT_FALSE(dataGroupInfos.empty());
    }
}

/**
 * @tc.number: GetDataGroupIndexMap_0010
 * @tc.name: test GetDataGroupIndexMap
 * @tc.desc: 1.GetDataGroupIndexMap
 */
HWTEST_F(BmsBundleDataGroupTest, GetDataGroupIndexMap_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        DataGroupInfo dataGroupInfo;
        dataGroupInfo.userId = USERID;
        dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
        dataGroupInfo.uid = TEST_UID;
        std::vector<DataGroupInfo> dataGroupVector;
        dataGroupVector.push_back(dataGroupInfo);

        InnerBundleInfo info;
        info.dataGroupInfos_[DATA_GROUP_ID_TEST_ONE] = dataGroupVector;
        dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
        ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

        std::map<std::string, std::pair<int32_t, std::string>> dataGroupIndexMap;
        std::unordered_set<int32_t> uniqueIdSet;
        dataMgr->GetDataGroupIndexMap(dataGroupIndexMap, uniqueIdSet);
        EXPECT_FALSE(dataGroupIndexMap.empty());
        EXPECT_FALSE(uniqueIdSet.empty());
    }
}

/**
 * @tc.number: IsShareDataGroupIdNoLock_0010
 * @tc.name: test IsShareDataGroupIdNoLock
 * @tc.desc: 1.IsShareDataGroupIdNoLock
 */
HWTEST_F(BmsBundleDataGroupTest, IsShareDataGroupIdNoLock_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        bool res = dataMgr->IsShareDataGroupIdNoLock(BUNDLE_NAME, USERID);
        EXPECT_FALSE(res);
    }
}

/**
 * @tc.number: IsShareDataGroupIdNoLock_0020
 * @tc.name: test IsShareDataGroupIdNoLock
 * @tc.desc: 1.IsShareDataGroupIdNoLock
 */
HWTEST_F(BmsBundleDataGroupTest, IsShareDataGroupIdNoLock_0020, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        DataGroupInfo dataGroupInfo;
        dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
        dataGroupInfo.userId = USERID;
        dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
        dataGroupInfo.uid = TEST_UID;
        std::vector<DataGroupInfo> dataGroupVector;
        dataGroupVector.push_back(dataGroupInfo);

        InnerBundleInfo info;
        info.dataGroupInfos_[DATA_GROUP_ID_TEST_ONE] = dataGroupVector;
        dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
        ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

        bool res = dataMgr->IsShareDataGroupIdNoLock(DATA_GROUP_ID_TEST_ONE, USERID);
        EXPECT_FALSE(res);
    }
}

/**
 * @tc.number: IsShareDataGroupIdNoLock_0030
 * @tc.name: test IsShareDataGroupIdNoLock
 * @tc.desc: 1.IsShareDataGroupIdNoLock
 */
HWTEST_F(BmsBundleDataGroupTest, IsShareDataGroupIdNoLock_0030, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        DataGroupInfo dataGroupInfo;
        dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
        dataGroupInfo.userId = USERID;
        dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
        dataGroupInfo.uid = TEST_UID;
        std::vector<DataGroupInfo> dataGroupVector;
        dataGroupVector.push_back(dataGroupInfo);

        InnerBundleInfo info;
        info.dataGroupInfos_[DATA_GROUP_ID_TEST_ONE] = dataGroupVector;
        dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
        dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, info);
        ScopeGuard bundleInfoGuard([&] {
            dataMgr->bundleInfos_.erase(BUNDLE_NAME);
            dataMgr->bundleInfos_.erase(BUNDLE_NAME_TEST);
        });

        bool res = dataMgr->IsShareDataGroupIdNoLock(DATA_GROUP_ID_TEST_ONE, USERID);
        EXPECT_TRUE(res);
    }
}

/**
 * @tc.number: IsDataGroupIdExistNoLock_0010
 * @tc.name: test IsDataGroupIdExistNoLock
 * @tc.desc: 1.IsDataGroupIdExistNoLock
 */
HWTEST_F(BmsBundleDataGroupTest, IsDataGroupIdExistNoLock_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        bool res = dataMgr->IsShareDataGroupIdNoLock(DATA_GROUP_ID_TEST_ONE, USERID);
        EXPECT_FALSE(res);
    }
}

/**
 * @tc.number: IsDataGroupIdExistNoLock_0020
 * @tc.name: test IsDataGroupIdExistNoLock
 * @tc.desc: 1.IsDataGroupIdExistNoLock
 */
HWTEST_F(BmsBundleDataGroupTest, IsDataGroupIdExistNoLock_0020, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        DataGroupInfo dataGroupInfo;
        dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
        dataGroupInfo.userId = USERID;
        dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
        dataGroupInfo.uid = TEST_UID;
        std::vector<DataGroupInfo> dataGroupVector;
        dataGroupVector.push_back(dataGroupInfo);

        InnerBundleInfo info;
        info.dataGroupInfos_[DATA_GROUP_ID_TEST_ONE] = dataGroupVector;
        dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
        ScopeGuard bundleInfoGuard([&] { dataMgr->bundleInfos_.erase(BUNDLE_NAME); });

        bool res = dataMgr->IsDataGroupIdExistNoLock(DATA_GROUP_ID_TEST_ONE, USERID);
        EXPECT_TRUE(res);
    }
}

/**
 * @tc.number: GenerateDataGroupUuidAndUid_0010
 * @tc.name: test GenerateDataGroupUuidAndUid
 * @tc.desc: 1.GenerateDataGroupUuidAndUid
 */
HWTEST_F(BmsBundleDataGroupTest, GenerateDataGroupUuidAndUid_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        DataGroupInfo dataGroupInfo;
        dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
        dataGroupInfo.userId = USERID;
        dataGroupInfo.uid = 0;
        dataGroupInfo.uuid = "";
        std::unordered_set<int32_t> uniqueIdSet;
        uniqueIdSet.insert(1);
        dataMgr->GenerateDataGroupUuidAndUid(dataGroupInfo, USERID, uniqueIdSet);
        EXPECT_NE(dataGroupInfo.uid, 0);
        EXPECT_EQ(dataGroupInfo.uid, dataGroupInfo.gid);
        EXPECT_NE(dataGroupInfo.uuid, "");
    }
}

/**
 * @tc.number: MigrateDataUserAuthCallback_0010
 * @tc.name: test OnResult
 * @tc.desc: 1.Test OnResult the MigrateDataUserAuthCallback
*/
HWTEST_F(BmsBundleDataGroupTest, MigrateDataUserAuthCallback_0010, Function | MediumTest | Level1)
{
    MigrateDataUserAuthCallback callback;
    int32_t result = 0;
    Attributes extraInfo;
    callback.OnResult(result, extraInfo);
    EXPECT_EQ(callback.result_, result);
}

/**
 * @tc.number: MigrateDataUserAuthCallback_0020
 * @tc.name: test OnResult
 * @tc.desc: 1.Test OnResult the MigrateDataUserAuthCallback
*/
HWTEST_F(BmsBundleDataGroupTest, MigrateDataUserAuthCallback_0020, Function | MediumTest | Level1)
{
    MigrateDataUserAuthCallback callback;
    callback.isComplete_.store(true);

    int32_t result = 0;
    Attributes extraInfo;
    callback.OnAcquireInfo(0, 1, extraInfo);
    callback.OnResult(result, extraInfo);
    EXPECT_EQ(callback.isComplete_, true);
}

/**
 * @tc.number: MigrateDataUserAuthCallback_0030
 * @tc.name: test GetUserAuthResult
 * @tc.desc: 1.Test GetUserAuthResult the MigrateDataUserAuthCallback
*/
HWTEST_F(BmsBundleDataGroupTest, MigrateDataUserAuthCallback_0030, Function | MediumTest | Level1)
{
    MigrateDataUserAuthCallback callback;
    callback.isComplete_.store(true);

    auto ret = callback.GetUserAuthResult();
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MIGRATE_DATA_USER_AUTHENTICATION_TIME_OUT);
}

/**
 * @tc.number: MigrateDataUserAuthCallback_0040
 * @tc.name: test GetUserAuthResult
 * @tc.desc: 1.Test GetUserAuthResult the MigrateDataUserAuthCallback
*/
HWTEST_F(BmsBundleDataGroupTest, MigrateDataUserAuthCallback_0040, Function | MediumTest | Level1)
{
    MigrateDataUserAuthCallback callback;
    callback.isComplete_.store(false);

    auto ret = callback.GetUserAuthResult();
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MIGRATE_DATA_USER_AUTHENTICATION_TIME_OUT);
}

/**
 * @tc.number: InnerBundleInfo_0001
 * @tc.name: test GetInternalDependentHspInfo
 * @tc.desc: 1.Test GetInternalDependentHspInfo in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0001, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo;

    std::string moduleName = "demo";
    std::vector<HspInfo> hspInfoVector;
    innerBundleInfo.GetInternalDependentHspInfo(moduleName, hspInfoVector);
    EXPECT_TRUE(hspInfoVector.empty());
}

/**
 * @tc.number: InnerBundleInfo_0002
 * @tc.name: test GetInternalDependentHspInfo
 * @tc.desc: 1.Test GetInternalDependentHspInfo in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0002, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";

    Dependency dependency;
    dependency.bundleName = "com.example.demo";
    dependency.moduleName = "demo";
    dependency.versionCode = 1;
    innerModuleInfo.dependencies.emplace_back(dependency);
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo;

    std::string moduleName = "entry";
    std::vector<HspInfo> hspInfoVector;
    innerBundleInfo.GetInternalDependentHspInfo(moduleName, hspInfoVector);
    EXPECT_TRUE(hspInfoVector.empty());
}

/**
 * @tc.number: InnerBundleInfo_0003
 * @tc.name: test GetInternalDependentHspInfo
 * @tc.desc: 1.Test GetInternalDependentHspInfo in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0003, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";

    Dependency dependency;
    dependency.bundleName = "com.example.demo";
    dependency.moduleName = "entry";
    dependency.versionCode = 1;
    innerModuleInfo.dependencies.emplace_back(dependency);
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo;

    std::string moduleName = "entry";
    std::vector<HspInfo> hspInfoVector;
    innerBundleInfo.GetInternalDependentHspInfo(moduleName, hspInfoVector);
    EXPECT_FALSE(hspInfoVector.empty());
}

/**
 * @tc.number: InnerBundleInfo_0004
 * @tc.name: test operator=
 * @tc.desc: 1.Test operator= in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0004, Function | MediumTest | Level1)
{
    InnerBundleInfo *innerBundleInfo = new InnerBundleInfo();
    EXPECT_NE(innerBundleInfo, nullptr);
    InnerBundleInfo *info2 = innerBundleInfo;
    InnerBundleInfo *info = innerBundleInfo;
    *info = *info2;
    EXPECT_TRUE(innerBundleInfo->GetBundleName().empty());
    delete(innerBundleInfo);
}

/**
 * @tc.number: InnerBundleInfo_0005
 * @tc.name: test GetPreInstallApplicationFlags
 * @tc.desc: 1.Test GetPreInstallApplicationFlags in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0005, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->isPreInstallApp = true;

    ApplicationInfo appInfo;
    innerBundleInfo.GetPreInstallApplicationFlags(appInfo);
    EXPECT_GT(appInfo.applicationFlags, 0);
}

/**
 * @tc.number: InnerBundleInfo_0006
 * @tc.name: test SetkeyId
 * @tc.desc: 1.Test SetkeyId in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0006, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "com.example.test";

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = "com.example.test";
    userInfo.uid = 100;
    innerBundleInfo.innerBundleUserInfos_["com.example.test_100"] = userInfo;

    int32_t userId = 100;
    std::string keyId = "test";
    int32_t appIndex = 1;
    innerBundleInfo.SetkeyId(userId, keyId, appIndex);
    EXPECT_EQ(innerBundleInfo.GetBundleName(), "com.example.test");
}

/**
 * @tc.number: InnerBundleInfo_0007
 * @tc.name: test SetkeyId
 * @tc.desc: 1.Test SetkeyId in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0007, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "com.example.test";

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = "com.example.test";
    userInfo.uid = 100;

    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back("ability");
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    userInfo.cloneInfos = cloneInfos;
    innerBundleInfo.innerBundleUserInfos_["com.example.test_100"] = userInfo;

    int32_t userId = 100;
    std::string keyId = "test";
    int32_t appIndex = 1;
    innerBundleInfo.SetkeyId(userId, keyId, appIndex);
    EXPECT_EQ(innerBundleInfo.GetBundleName(), "com.example.test");
}

/**
 * @tc.number: InnerBundleInfo_0008
 * @tc.name: test ShouldReplacePermission
 * @tc.desc: 1.Test ShouldReplacePermission in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0008, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    RequestPermission oldPermission;
    RequestPermission newPermission;
    newPermission.name = "test";
    std::unordered_map<std::string, std::string> moduleNameTypeMap;
    bool ret = innerBundleInfo.ShouldReplacePermission(oldPermission, newPermission, moduleNameTypeMap);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfo_0009
 * @tc.name: test AddModuleRemovableInfo
 * @tc.desc: 1.Test AddModuleRemovableInfo in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0009, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo info;
    std::string stringUserId;
    bool isEnable = false;
    bool ret = innerBundleInfo.AddModuleRemovableInfo(info, stringUserId, isEnable);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InnerBundleInfo_0010
 * @tc.name: test SetModuleHapPath
 * @tc.desc: 1.Test SetModuleHapPath in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0010, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.currentPackage_ = "entry";
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.compressNativeLibs = false;
    innerModuleInfo.nativeLibraryPath = "data";
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo;

    std::string hapPath;
    innerBundleInfo.SetModuleHapPath(hapPath);
    EXPECT_EQ(innerBundleInfo.innerModuleInfos_.at("entry").nativeLibraryPath.empty(), false);
}

/**
 * @tc.number: InnerBundleInfo_0011
 * @tc.name: test SetModuleHapPath
 * @tc.desc: 1.Test SetModuleHapPath in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0011, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.currentPackage_ = "entry";
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.compressNativeLibs = false;
    innerModuleInfo.nativeLibraryPath = "data/";
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo;

    std::string hapPath;
    innerBundleInfo.SetModuleHapPath(hapPath);
    EXPECT_EQ(innerBundleInfo.innerModuleInfos_.at("entry").nativeLibraryPath.empty(), false);
}

/**
 * @tc.number: InnerBundleInfo_0012
 * @tc.name: test SetExtName
 * @tc.desc: 1.Test SetExtName in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0012, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::string moduleName = "entry";
    std::string abilityName = "entryAbility";
    std::string extName = "testExt";

    AbilityInfo abilityInfo;
    abilityInfo.moduleName = moduleName;
    abilityInfo.supportExtNames.emplace_back(extName);
    innerBundleInfo.baseAbilityInfos_[abilityName] = abilityInfo;
    ErrCode ret = innerBundleInfo.SetExtName(moduleName, abilityName, extName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DUPLICATED_EXT_OR_TYPE);
}

/**
 * @tc.number: InnerBundleInfo_0013
 * @tc.name: test SetMimeType
 * @tc.desc: 1.Test SetMimeType in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0013, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::string moduleName = "entry";
    std::string abilityName = "entryAbility";
    std::string mimeType = "testMime";

    AbilityInfo abilityInfo;
    abilityInfo.moduleName = moduleName;
    abilityInfo.supportMimeTypes.emplace_back(mimeType);
    innerBundleInfo.baseAbilityInfos_[abilityName] = abilityInfo;
    ErrCode ret = innerBundleInfo.SetMimeType(moduleName, abilityName, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DUPLICATED_EXT_OR_TYPE);
}

/**
 * @tc.number: InnerBundleInfo_0014
 * @tc.name: test HandleOTACodeEncryption
 * @tc.desc: 1.Test HandleOTACodeEncryption in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0014, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    CheckEncryptionParam checkEncryptionParam;
    InnerModuleInfo moduleInfo;
    innerBundleInfo.CheckHapEncryption(checkEncryptionParam, moduleInfo);
    std::vector<std::string> withoutKeyBundles;
    std::vector<std::string> withKeyBundles;
    innerBundleInfo.baseApplicationInfo_->applicationReservedFlag = 1;
    innerBundleInfo.HandleOTACodeEncryption(withoutKeyBundles, withKeyBundles);
    innerBundleInfo.UpdateIsCompressNativeLibs();
    EXPECT_TRUE(withoutKeyBundles.empty());
    EXPECT_TRUE(withKeyBundles.empty());
}

/**
 * @tc.number: InnerBundleInfo_0015
 * @tc.name: test HandleOTACodeEncryption
 * @tc.desc: 1.Test HandleOTACodeEncryption in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0015, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test";
    std::vector<std::string> withoutKeyBundles;
    std::vector<std::string> withKeyBundles;
    innerBundleInfo.baseApplicationInfo_->applicationReservedFlag = 1;

    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.bundleUserInfo.userId = 100;
    innerBundleUserInfos["_100"] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    innerBundleInfo.HandleOTACodeEncryption(withoutKeyBundles, withKeyBundles);
    EXPECT_TRUE(withoutKeyBundles.empty());
    EXPECT_FALSE(withKeyBundles.empty());
}

/**
 * @tc.number: InnerBundleInfo_0016
 * @tc.name: test CheckSoEncryption
 * @tc.desc: 1.Test CheckSoEncryption in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0016, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    CheckEncryptionParam checkEncryptionParam;
    std::string requestPackage = "entry";
    InnerModuleInfo moduleInfo;

    moduleInfo.compressNativeLibs = false;
    innerBundleInfo.CheckSoEncryption(checkEncryptionParam, requestPackage, moduleInfo);
    EXPECT_FALSE(moduleInfo.compressNativeLibs);

    moduleInfo.compressNativeLibs = true;
    innerBundleInfo.CheckSoEncryption(checkEncryptionParam, requestPackage, moduleInfo);
    EXPECT_TRUE(moduleInfo.compressNativeLibs);
}

/**
 * @tc.number: InnerBundleInfo_0017
 * @tc.name: test CheckSoEncryption
 * @tc.desc: 1.Test CheckSoEncryption in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0017, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    CheckEncryptionParam checkEncryptionParam;
    std::string requestPackage = "entry";
    InnerModuleInfo moduleInfo;
    moduleInfo.compressNativeLibs = true;
    moduleInfo.isLibIsolated = true;
    moduleInfo.cpuAbi = "x86";
    moduleInfo.nativeLibraryPath = "data/";

    innerBundleInfo.innerModuleInfos_["entry"] = moduleInfo;

    innerBundleInfo.CheckSoEncryption(checkEncryptionParam, requestPackage, moduleInfo);
    EXPECT_TRUE(moduleInfo.compressNativeLibs);
}

/**
 * @tc.number: InnerBundleInfo_0018
 * @tc.name: test SetMoudleIsEncrpted
 * @tc.desc: 1.Test SetMoudleIsEncrpted in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0018, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    CheckEncryptionParam checkEncryptionParam;
    std::string requestPackage = "entry";
    InnerModuleInfo moduleInfo;
    moduleInfo.compressNativeLibs = true;
    moduleInfo.isLibIsolated = true;
    moduleInfo.cpuAbi = "x86";
    moduleInfo.nativeLibraryPath = "data/";
    innerBundleInfo.innerModuleInfos_["entry"] = moduleInfo;

    std::string packageName = "entry";
    bool isEncrypted = true;
    innerBundleInfo.SetMoudleIsEncrpted(packageName, isEncrypted);
    EXPECT_TRUE(innerBundleInfo.innerModuleInfos_["entry"].isEncrypted);
}

/**
 * @tc.number: InnerBundleInfo_0019
 * @tc.name: test IsContainEncryptedModule & GetAllEncryptedModuleNames
 * @tc.desc: 1.Test IsContainEncryptedModule & GetAllEncryptedModuleNames in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0019, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    CheckEncryptionParam checkEncryptionParam;
    std::string requestPackage = "entry";
    InnerModuleInfo moduleInfo;
    moduleInfo.compressNativeLibs = true;
    moduleInfo.isLibIsolated = true;
    moduleInfo.cpuAbi = "x86";
    moduleInfo.nativeLibraryPath = "data/";
    moduleInfo.isEncrypted = true;
    innerBundleInfo.innerModuleInfos_["entry"] = moduleInfo;

    std::vector<std::string> moduleNames;
    innerBundleInfo.GetAllEncryptedModuleNames(moduleNames);
    EXPECT_FALSE(moduleNames.empty());

    bool ret = innerBundleInfo.IsContainEncryptedModule();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InnerBundleInfo_0020
 * @tc.name: test AddAllowedAcls
 * @tc.desc: 1.Test AddAllowedAcls in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0020, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::vector<std::string> allowedAcls;
    allowedAcls.emplace_back("testAcl");
    innerBundleInfo.AddAllowedAcls(allowedAcls);
    EXPECT_FALSE(innerBundleInfo.allowedAcls_.empty());
}

/**
 * @tc.number: InnerBundleInfo_0021
 * @tc.name: test IsTsanEnabled
 * @tc.desc: 1.Test IsTsanEnabled in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0021, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.tsanEnabled = true;
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos;
    innerSharedModuleInfos["entry"].emplace_back(innerModuleInfo);
    innerBundleInfo.innerSharedModuleInfos_ = innerSharedModuleInfos;
    EXPECT_TRUE(innerBundleInfo.IsTsanEnabled());
}

/**
 * @tc.number: InnerBundleInfo_0022
 * @tc.name: test IsTsanEnabled
 * @tc.desc: 1.Test IsTsanEnabled in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0022, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.tsanEnabled = false;
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos;
    innerSharedModuleInfos["entry"].emplace_back(innerModuleInfo);
    innerBundleInfo.innerSharedModuleInfos_ = innerSharedModuleInfos;
    EXPECT_FALSE(innerBundleInfo.IsTsanEnabled());
}

/**
 * @tc.number: InnerBundleInfo_0023
 * @tc.name: test IsHwasanEnabled
 * @tc.desc: 1.Test IsHwasanEnabled in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0023, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.innerModuleInfoFlag =
        1 << (static_cast<uint8_t>(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_HWASANENABLED) - 1);
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos;
    innerSharedModuleInfos["entry"].emplace_back(innerModuleInfo);
    innerBundleInfo.innerSharedModuleInfos_ = innerSharedModuleInfos;
    EXPECT_TRUE(innerBundleInfo.IsHwasanEnabled());
}

/**
 * @tc.number: InnerBundleInfo_0024
 * @tc.name: test IsHwasanEnabled
 * @tc.desc: 1.Test IsHwasanEnabled in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0024, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.innerModuleInfoFlag = 0;
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos;
    innerSharedModuleInfos["entry"].emplace_back(innerModuleInfo);
    innerBundleInfo.innerSharedModuleInfos_ = innerSharedModuleInfos;
    EXPECT_FALSE(innerBundleInfo.IsHwasanEnabled());
}

/**
 * @tc.number: InnerBundleInfo_0025
 * @tc.name: test IsUbsanEnabled
 * @tc.desc: 1.Test IsUbsanEnabled in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0025, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.innerModuleInfoFlag =
        1 << (static_cast<uint8_t>(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_UBSANENABLED) - 1);
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo;
    EXPECT_TRUE(innerBundleInfo.IsUbsanEnabled());
}

/**
 * @tc.number: InnerBundleInfo_0026
 * @tc.name: test IsUbsanEnabled
 * @tc.desc: 1.Test IsUbsanEnabled in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0026, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.innerModuleInfoFlag =
        1 << (static_cast<uint8_t>(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_UBSANENABLED) - 1);
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos;
    innerSharedModuleInfos["entry"].emplace_back(innerModuleInfo);
    innerBundleInfo.innerSharedModuleInfos_ = innerSharedModuleInfos;
    EXPECT_TRUE(innerBundleInfo.IsUbsanEnabled());
}

/**
 * @tc.number: InnerBundleInfo_0027
 * @tc.name: test IsUbsanEnabled
 * @tc.desc: 1.Test IsUbsanEnabled in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0027, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.innerModuleInfoFlag = 0;
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos;
    innerSharedModuleInfos["entry"].emplace_back(innerModuleInfo);
    innerBundleInfo.innerSharedModuleInfos_ = innerSharedModuleInfos;
    EXPECT_FALSE(innerBundleInfo.IsUbsanEnabled());
}

/**
 * @tc.number: InnerBundleInfo_002
 * @tc.name: test IsUbsanEnabled
 * @tc.desc: 1.Test IsUbsanEnabled in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0028, Function | MediumTest | Level1)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.innerModuleInfoFlag = 0;
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos;
    innerSharedModuleInfos["entry"].emplace_back(innerModuleInfo);
    innerBundleInfo.innerSharedModuleInfos_ = innerSharedModuleInfos;
    EXPECT_FALSE(innerBundleInfo.IsUbsanEnabled());
}

/**
 * @tc.number: InnerBundleInfo_0029
 * @tc.name: test RemoveCloneBundle
 * @tc.desc: 1.Test RemoveCloneBundle in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0029, Function | MediumTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.name = "ABILITY_NAME";
    abilityInfo.moduleName = "MODULE_NAME_TEST";
    bundleInfo.baseAbilityInfos_.insert(std::make_pair("_1", abilityInfo));
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back("ABILITY_NAME");
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));

    int32_t userId = 1;
    int32_t appIndex = 6;
    auto ret = bundleInfo.RemoveCloneBundle(userId, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);
}

/**
 * @tc.number: InnerBundleInfo_0030
 * @tc.name: test RemoveCloneBundle
 * @tc.desc: 1.Test RemoveCloneBundle in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0030, Function | MediumTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.name = "ABILITY_NAME";
    abilityInfo.moduleName = "MODULE_NAME_TEST";
    bundleInfo.baseAbilityInfos_.insert(std::make_pair("_1", abilityInfo));
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back("ABILITY_NAME");
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));

    int32_t userId = 1;
    int32_t appIndex = 3;
    auto ret = bundleInfo.RemoveCloneBundle(userId, appIndex);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerBundleInfo_0031
 * @tc.name: test GetAvailableCloneAppIndex
 * @tc.desc: 1.Test GetAvailableCloneAppIndex in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0031, Function | MediumTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back("ABILITY_NAME");
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));

    int32_t userId = 100;
    int32_t appIndex = 3;
    auto ret = bundleInfo.GetAvailableCloneAppIndex(userId, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST);
}

/**
 * @tc.number: InnerBundleInfo_0032
 * @tc.name: test GetAvailableCloneAppIndex
 * @tc.desc: 1.Test GetAvailableCloneAppIndex in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0032, Function | MediumTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back("ABILITY_NAME");
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));

    int32_t userId = 100;
    int32_t appIndex = 3;
    bool res = false;
    auto ret = bundleInfo.IsCloneAppIndexExisted(userId, appIndex, res);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST);
}

/**
 * @tc.number: InnerBundleInfo_0033
 * @tc.name: test GetApplicationInfoAdaptBundleClone
 * @tc.desc: 1.Test GetApplicationInfoAdaptBundleClone in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0033, Function | MediumTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back("ABILITY_NAME");
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));

    int32_t appIndex = 0;
    ApplicationInfo appInfo;
    appInfo.removable = true;
    innerBundleUserInfo.isRemovable = false;
    auto ret = bundleInfo.GetApplicationInfoAdaptBundleClone(innerBundleUserInfo, appIndex, appInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(appInfo.removable, false);
}

/**
 * @tc.number: InnerBundleInfo_0034
 * @tc.name: test VerifyAndAckCloneAppIndex
 * @tc.desc: 1.Test VerifyAndAckCloneAppIndex in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0034, Function | MediumTest | Level1)
{
    InnerBundleInfo bundleInfo;
    bundleInfo.baseApplicationInfo_->multiAppMode.multiAppModeType = MultiAppModeType::APP_CLONE;

    int32_t userId = 100;
    int32_t appIndex = 0;
    auto ret = bundleInfo.VerifyAndAckCloneAppIndex(userId, appIndex);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: InnerBundleInfo_0035
 * @tc.name: test VerifyAndAckCloneAppIndex
 * @tc.desc: 1.Test VerifyAndAckCloneAppIndex in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0035, Function | MediumTest | Level1)
{
    InnerBundleInfo bundleInfo;
    bundleInfo.baseApplicationInfo_->multiAppMode.multiAppModeType = MultiAppModeType::APP_CLONE;

    int32_t userId = 100;
    int32_t appIndex = 1;
    auto ret = bundleInfo.VerifyAndAckCloneAppIndex(userId, appIndex);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: InnerBundleInfo_0036
 * @tc.name: test VerifyAndAckCloneAppIndex
 * @tc.desc: 1.Test VerifyAndAckCloneAppIndex in the InnerBundleInfo
*/
HWTEST_F(BmsBundleDataGroupTest, InnerBundleInfo_0036, Function | MediumTest | Level1)
{
    InnerBundleInfo bundleInfo;
    bundleInfo.baseApplicationInfo_->multiAppMode.multiAppModeType = MultiAppModeType::APP_CLONE;
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back("ABILITY_NAME");
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    innerBundleCloneInfo.appIndex = 1;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));

    std::set<int32_t> ret = bundleInfo.GetCloneBundleAppIndexes();
    EXPECT_NE(ret.empty(), true);
}

/**
 * @tc.number: BaseBundleInstaller_0001
 * @tc.name: test InstallBundleByBundleName
 * @tc.desc: 1.InstallBundleByBundleName
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0001, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    InstallParam installParam;
    installParam.needSendEvent = true;
    installParam.concentrateSendEvent = true;

    std::string bundleName = "test";
    auto result = installer.InstallBundleByBundleName(bundleName, installParam);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BaseBundleInstaller_0002
 * @tc.name: test InstallBundleByBundleName
 * @tc.desc: 1.InstallBundleByBundleName
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0002, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer.dataMgr_ = dataMgr;
    InnerBundleInfo innerBundleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.type = ExtensionAbilityType::DRIVER;
    innerBundleInfo.baseExtensionInfos_["testExt"] = extensionAbilityInfo;
    dataMgr->bundleInfos_["test.bundleName"] = innerBundleInfo;

    InstallParam installParam;
    installParam.needSendEvent = true;
    installParam.concentrateSendEvent = false;

    std::string bundleName = "test.bundleName";
    auto result = installer.InstallBundleByBundleName(bundleName, installParam);
    EXPECT_NE(result, ERR_OK);

    dataMgr->bundleInfos_.erase("test.bundleName");
}

/**
 * @tc.number: BaseBundleInstaller_0003
 * @tc.name: test InstallBundleByBundleName
 * @tc.desc: 1.InstallBundleByBundleName
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0003, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    InstallParam installParam;
    installParam.needSendEvent = true;
    installParam.concentrateSendEvent = false;

    std::string bundleName = "test";
    auto result = installer.InstallBundleByBundleName(bundleName, installParam);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BaseBundleInstaller_0004
 * @tc.name: test InstallBundleByBundleName
 * @tc.desc: 1.InstallBundleByBundleName
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0004, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string bundleName = "test.bundleName";
    auto dataMgr = GetBundleDataMgr();
    dataMgr->AddUserId(100);
    ASSERT_NE(dataMgr, nullptr);
    installer.dataMgr_ = dataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = bundleName;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
    innerBundleInfo.innerBundleUserInfos_["test.bundleName_100"] = InnerBundleUserInfo();
    innerBundleInfo.uninstallState_ = false;
    innerBundleInfo.baseApplicationInfo_->removable = true;

    dataMgr->bundleInfos_[bundleName] = innerBundleInfo;

    InstallParam installParam;
    installParam.userId = 100;
    installParam.forceExecuted = false;
    installParam.killProcess = true;
    installParam.isUninstallAndRecover = false;
    installParam.concentrateSendEvent = true;

    auto result = installer.UninstallBundle(bundleName, installParam);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_UNINSTALL);

    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: BaseBundleInstaller_0005
 * @tc.name: test MarkIsForceUninstall
 * @tc.desc: 1.MarkIsForceUninstall
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0005, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    std::string bundleName = "";
    bool isForceUninstalled = false;
    installer.MarkIsForceUninstall(bundleName, isForceUninstalled);
    EXPECT_TRUE(bundleName.empty());
}

/**
 * @tc.number: BaseBundleInstaller_0006
 * @tc.name: test CheckUninstallInnerBundleInfo
 * @tc.desc: 1.CheckUninstallInnerBundleInfo
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0006, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    InnerBundleInfo info;
    info.baseApplicationInfo_->removable = false;
    std::string bundleName;
    auto ret = installer.CheckUninstallInnerBundleInfo(info, bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_SYSTEM_APP_ERROR);
}

/**
 * @tc.number: BaseBundleInstaller_0007
 * @tc.name: test CheckUninstallInnerBundleInfo
 * @tc.desc: 1.CheckUninstallInnerBundleInfo
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0007, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    InnerBundleInfo info;
    info.baseApplicationInfo_->removable = true;
    info.uninstallState_ = false;
    std::string bundleName;
    auto ret = installer.CheckUninstallInnerBundleInfo(info, bundleName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_UNINSTALL);
}

/**
 * @tc.number: BaseBundleInstaller_0008
 * @tc.name: test CheckUninstallInnerBundleInfo
 * @tc.desc: 1.CheckUninstallInnerBundleInfo
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0008, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    InnerBundleInfo info;
    info.baseApplicationInfo_->removable = true;
    info.uninstallState_ = true;
    std::string bundleName;
    auto ret = installer.CheckUninstallInnerBundleInfo(info, bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST);
}

/**
 * @tc.number: BaseBundleInstaller_0009
 * @tc.name: test CheckUninstallInnerBundleInfo
 * @tc.desc: 1.CheckUninstallInnerBundleInfo
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0009, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    UninstallParam uninstallParam;
    uninstallParam.bundleName = "test.demo.wrong";
    auto ret = installer.UninstallBundleByUninstallParam(uninstallParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST);
}

/**
 * @tc.number: BaseBundleInstaller_0010
 * @tc.name: test InstallBundleByBundleName
 * @tc.desc: 1.InstallBundleByBundleName
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string bundleName = "test.bundleName";
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer.dataMgr_ = dataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = bundleName;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
    innerBundleInfo.innerBundleUserInfos_["test.bundleName_100"] = InnerBundleUserInfo();
    innerBundleInfo.uninstallState_ = false;
    innerBundleInfo.baseApplicationInfo_->removable = false;

    dataMgr->bundleInfos_[bundleName] = innerBundleInfo;

    UninstallParam uninstallParam;
    uninstallParam.bundleName = bundleName;
    auto ret = installer.UninstallBundleByUninstallParam(uninstallParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_SYSTEM_APP_ERROR);

    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: BaseBundleInstaller_0011
 * @tc.name: test RollBack
 * @tc.desc: 1.RollBack
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0011, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = false;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->isPreInstallApp = true;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos["test"] = innerBundleInfo;
    InnerBundleInfo oldInfo;
    installer.RollBack(newInfos, oldInfo);
    EXPECT_EQ(installer.isAppExist_, false);
}

/**
 * @tc.number: BaseBundleInstaller_0012
 * @tc.name: test RollBack
 * @tc.desc: 1.RollBack
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0012, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = false;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->isPreInstallApp = false;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::ATOMIC_SERVICE;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos["test"] = innerBundleInfo;
    InnerBundleInfo oldInfo;
    installer.RollBack(newInfos, oldInfo);
    EXPECT_EQ(installer.isAppExist_, false);
}

/**
 * @tc.number: BaseBundleInstaller_0013
 * @tc.name: test RollBack
 * @tc.desc: 1.RollBack
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0013, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = false;
    installer.userId_ = 100;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.baseBundleInfo_->isPreInstallApp = false;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::ATOMIC_SERVICE;

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = 1001;
    innerBundleInfo.innerBundleUserInfos_["test.bundle_100"] = innerBundleUserInfo;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos["test"] = innerBundleInfo;
    InnerBundleInfo oldInfo;
    installer.RollBack(newInfos, oldInfo);
    EXPECT_EQ(installer.isAppExist_, false);
}

/**
 * @tc.number: BaseBundleInstaller_0014
 * @tc.name: test RollBack
 * @tc.desc: 1.RollBack
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0014, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = false;
    installer.userId_ = 100;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.baseBundleInfo_->isPreInstallApp = false;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = 1001;
    innerBundleInfo.innerBundleUserInfos_["test.bundle_100"] = innerBundleUserInfo;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos["test"] = innerBundleInfo;
    InnerBundleInfo oldInfo;
    installer.RollBack(newInfos, oldInfo);
    EXPECT_EQ(installer.isAppExist_, false);
}

/**
 * @tc.number: BaseBundleInstaller_0015
 * @tc.name: test RemoveInfo
 * @tc.desc: 1.RemoveInfo
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0015, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;

    installer.bundleName_ = "test";
    std::string bundleName;
    std::string packageName = "test";
    installer.RemoveInfo(bundleName, packageName);
    EXPECT_EQ(installer.bundleName_, "test");
}

/**
 * @tc.number: BaseBundleInstaller_0016
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.ProcessBundleUpdateStatus
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0016, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->singleton = true;

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = "entry";
    newInfo.baseApplicationInfo_->singleton = false;
    newInfo.baseBundleInfo_->isPreInstallApp = true;
    newInfo.baseApplicationInfo_->bundleName = "com.ohos.sceneboard";

    bool isReplace = false;
    bool killProcess = false;
    installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(installer.singletonState_, AppExecFwk::BaseBundleInstaller::SingletonState::SINGLETON_TO_NON);
}

/**
 * @tc.number: BaseBundleInstaller_0017
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.ProcessBundleUpdateStatus
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0017, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->singleton = false;

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = "entry";
    newInfo.baseApplicationInfo_->singleton = true;
    newInfo.baseBundleInfo_->isPreInstallApp = true;
    newInfo.baseApplicationInfo_->bundleName = "com.ohos.sceneboard";

    bool isReplace = false;
    bool killProcess = false;
    installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(installer.singletonState_, AppExecFwk::BaseBundleInstaller::SingletonState::NON_TO_SINGLETON);
}

/**
 * @tc.number: BaseBundleInstaller_0018
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.ProcessBundleUpdateStatus
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0018, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->singleton = false;

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = "entry";
    newInfo.baseApplicationInfo_->singleton = true;
    newInfo.baseBundleInfo_->isPreInstallApp = false;
    newInfo.baseApplicationInfo_->bundleName = "com.ohos.sceneboard";

    bool isReplace = false;
    bool killProcess = false;
    auto ret = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_SINGLETON_INCOMPATIBLE);
}

/**
 * @tc.number: BaseBundleInstaller_0019
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.ProcessBundleUpdateStatus
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0019, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();

    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->singleton = false;
    oldInfo.overlayType_ = NON_OVERLAY_TYPE;
    oldInfo.currentPackage_ = "entry";
    oldInfo.innerModuleInfos_["entry"] = InnerModuleInfo();

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = "entry";
    newInfo.baseApplicationInfo_->singleton = false;
    newInfo.baseBundleInfo_->isPreInstallApp = false;
    newInfo.baseApplicationInfo_->bundleName = "com.ohos.sceneboard";
    newInfo.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    newInfo.innerModuleInfos_["entry"] = InnerModuleInfo();

    bool isReplace = false;
    bool killProcess = false;
    auto ret = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME);
#else
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
#endif
}

/**
 * @tc.number: BaseBundleInstaller_0020
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.ProcessBundleUpdateStatus
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer.dataMgr_ = dataMgr;

    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->singleton = false;
    oldInfo.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = "entry";
    newInfo.baseApplicationInfo_->singleton = false;
    newInfo.baseBundleInfo_->isPreInstallApp = false;
    newInfo.baseApplicationInfo_->bundleName = "com.ohos.sceneboard";
    newInfo.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;

    bool isReplace = false;
    bool killProcess = false;

    dataMgr->installStates_["entry"] = InstallState::ROLL_BACK;
    installer.bundleName_ = "entry";
    auto ret = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_STATE_ERROR);

    dataMgr->installStates_.erase("entry");
}

/**
 * @tc.number: BaseBundleInstaller_0021
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.ProcessBundleUpdateStatus
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0021, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer.dataMgr_ = dataMgr;

    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->singleton = false;
    oldInfo.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    oldInfo.baseBundleInfo_->signatureInfo.appIdentifier = "test1";
    oldInfo.baseBundleInfo_->appId = "_123";

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = "entry";
    newInfo.baseApplicationInfo_->singleton = false;
    newInfo.baseBundleInfo_->isPreInstallApp = false;
    newInfo.baseApplicationInfo_->bundleName = "com.ohos.sceneboard";
    newInfo.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    newInfo.baseBundleInfo_->signatureInfo.appIdentifier = "test2";
    newInfo.baseBundleInfo_->appId = "_1234";

    bool isReplace = false;
    bool killProcess = false;

    dataMgr->installStates_["entry"] = InstallState::INSTALL_START;
    installer.bundleName_ = "entry";
    auto checkRes = installer.CheckAppIdentifier(oldInfo.GetAppIdentifier(), newInfo.GetAppIdentifier(),
        oldInfo.GetProvisionId(), newInfo.GetProvisionId());
    EXPECT_FALSE(checkRes);
    auto ret = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INCONSISTENT_SIGNATURE);

    dataMgr->installStates_.erase("entry");
}

/**
 * @tc.number: BaseBundleInstaller_0022
 * @tc.name: test RemovePluginOnlyInCurrentUser
 * @tc.desc: 1.RemovePluginOnlyInCurrentUser
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0022, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.userId_ = 100;
    InnerBundleInfo info;
    InnerBundleUserInfo userInfo;
    info.baseApplicationInfo_->bundleName = "com.example.test";

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = 20022222;
    innerBundleUserInfo.installedPluginSet.insert("testPlugin");

    info.innerBundleUserInfos_["com.example.test_100"] = innerBundleUserInfo;

    PluginBundleInfo pluginBundleInfo;
    info.pluginBundleInfos_["testPlugin"] = pluginBundleInfo;

    EXPECT_TRUE(info.GetInnerBundleUserInfo(installer.userId_, userInfo));
    installer.RemovePluginOnlyInCurrentUser(info);

    info.innerBundleUserInfos_["com.example.test_101"] = innerBundleUserInfo;
    EXPECT_TRUE(info.HasMultiUserPlugin("testPlugin"));
    installer.RemovePluginOnlyInCurrentUser(info);
}

/**
 * @tc.number: BaseBundleInstaller_0023
 * @tc.name: test UninstallDebugAppSandbox
 * @tc.desc: 1.UninstallDebugAppSandbox
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0023, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;

    ErrCode result = ERR_OK;
    installer.isPreBundleRecovered_ = false;
    installer.CheckPreBundleRecoverResult(result);
    EXPECT_EQ(result, ERR_OK);

    installer.isPreBundleRecovered_ = true;
    installer.CheckPreBundleRecoverResult(result);
    EXPECT_EQ(result, ERR_OK);

    result = -1;
    installer.sysEventInfo_.callingUid = AppExecFwk::ServiceConstants::SHELL_UID;
    installer.CheckPreBundleRecoverResult(result);
    EXPECT_EQ(result, -1);

    installer.sysEventInfo_.callingUid = 0;
    installer.CheckPreBundleRecoverResult(result);
    EXPECT_EQ(result, -1);

    installer.sysEventInfo_.callingUid = 5523;
    installer.CheckPreBundleRecoverResult(result);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_FAILED_AND_RESTORE_TO_PREINSTALLED);
}

/**
 * @tc.number: BaseBundleInstaller_0024
 * @tc.name: test installerCheckPreAppAllowHdcInstall
 * @tc.desc: 1.installerCheckPreAppAllowHdcInstall
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0024, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.sysEventInfo_.callingUid = 1;

    InstallParam installParam;
    installParam.isCallByShell = true;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;

    ErrCode result = installer.CheckPreAppAllowHdcInstall(installParam, hapVerifyRes);
    EXPECT_EQ(result, ERR_APPEXECFWK_HAP_VERIFY_RES_EMPTY);
}

/**
 * @tc.number: BaseBundleInstaller_0025
 * @tc.name: test installerCheckPreAppAllowHdcInstall
 * @tc.desc: 1.installerCheckPreAppAllowHdcInstall
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0025, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;

    InstallParam installParam;
    installParam.isCallByShell = true;
    Security::Verify::HapVerifyResult hapVerifyResult;
    hapVerifyResult.provisionInfo.isOpenHarmony = true;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes { hapVerifyResult };

    ErrCode result = installer.CheckPreAppAllowHdcInstall(installParam, hapVerifyRes);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BaseBundleInstaller_0026
 * @tc.name: test CheckShellCanInstallPreApp
 * @tc.desc: 1.CheckShellCanInstallPreApp
 */
HWTEST_F(BmsBundleDataGroupTest, BaseBundleInstaller_0026, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    BaseBundleInstaller installer;
    installer.dataMgr_ = dataMgr;

    installer.sysEventInfo_.callingUid = AppExecFwk::ServiceConstants::SHELL_UID;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    auto result = installer.CheckShellCanInstallPreApp(newInfos);
    EXPECT_EQ(result, ERR_OK);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    dataMgr->bundleInfos_["test.bundle"] = innerBundleInfo;
    newInfos["test.bundle"] = innerBundleInfo;

    auto result2 = installer.CheckShellCanInstallPreApp(newInfos);
    EXPECT_EQ(result2, ERR_OK);

    dataMgr->bundleInfos_.erase("test.bundle");

    auto result3 = installer.CheckShellCanInstallPreApp(newInfos);
    EXPECT_EQ(result3, ERR_OK);

    ASSERT_NE(dataMgr->preInstallDataStorage_, nullptr);
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.bundleName_ = "test.bundle";
    EXPECT_TRUE(dataMgr->preInstallDataStorage_->SavePreInstallStorageBundleInfo(preInstallBundleInfo));
    auto result4 = installer.CheckShellCanInstallPreApp(newInfos);
    EXPECT_EQ(result4, ERR_OK);

    preInstallBundleInfo.bundlePaths_.emplace_back("data/");
    EXPECT_TRUE(dataMgr->preInstallDataStorage_->SavePreInstallStorageBundleInfo(preInstallBundleInfo));
    auto result5 = installer.CheckShellCanInstallPreApp(newInfos);
    EXPECT_EQ(result5, ERR_OK);
}
} // OHOS