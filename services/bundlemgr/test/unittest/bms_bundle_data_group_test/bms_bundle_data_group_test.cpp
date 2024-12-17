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

#include <fstream>
#include <gtest/gtest.h>

#include "app_provision_info_manager.h"
#include "base_bundle_installer.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "data_group_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
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
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
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
} // OHOS