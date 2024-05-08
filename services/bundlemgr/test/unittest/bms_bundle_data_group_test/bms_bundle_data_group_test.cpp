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
 * @tc.number: DeleteGroupDirsForException_0010
 * @tc.name: test DeleteGroupDirsForException
 * @tc.desc: 1.DeleteGroupDirsForException
 */
HWTEST_F(BmsBundleDataGroupTest, DeleteGroupDirsForException_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    DataGroupInfo dataGroupInfo;
    dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
    dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
    dataGroupInfo.userId = USERID;
    installer.createGroupDirs_.emplace_back(dataGroupInfo);
    installer.userId_ = USERID;

    installer.DeleteGroupDirsForException();
    EXPECT_FALSE(installer.createGroupDirs_.empty());
}

/**
 * @tc.number: CreateDataGroupDirs_0010
 * @tc.name: test CreateDataGroupDirs
 * @tc.desc: 1.CreateDataGroupDirs
 */
HWTEST_F(BmsBundleDataGroupTest, CreateDataGroupDirs_0010, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    DataGroupInfo dataGroupInfo;
    dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_ONE;
    dataGroupInfo.uuid = DATA_GROUP_UUID_ONE;
    dataGroupInfo.userId = USERID;
    info.AddDataGroupInfo(DATA_GROUP_ID_TEST_ONE, dataGroupInfo);
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.emplace(TEST_HAP_PATH, info);

    BaseBundleInstaller installer;
    installer.userId_ = USERID;
    installer.isAppExist_ = true;
    installer.dataMgr_ = GetBundleDataMgr();

    InnerBundleInfo oldInfo;
    DataGroupInfo oldDataGroupInfo;
    oldDataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_TWO;
    oldDataGroupInfo.uuid = DATA_GROUP_UUID_TWO;
    oldDataGroupInfo.userId = USERID;
    oldInfo.AddDataGroupInfo(DATA_GROUP_ID_TEST_TWO, oldDataGroupInfo);
    installer.dataMgr_->bundleInfos_.emplace(BUNDLE_NAME, oldInfo);

    setuid(Constants::FOUNDATION_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    auto result = installer.CreateDataGroupDirs(newInfos, oldInfo);
    EXPECT_FALSE(installer.removeGroupDirs_.empty());
    EXPECT_FALSE(installer.createGroupDirs_.empty());
    ASSERT_EQ(result, ERR_OK);

    std::string dir = DATA_GROUP_DIR_TEST;
    auto createDirRes = InstalldClient::GetInstance()->RemoveDir(dir);
    EXPECT_EQ(createDirRes, ERR_OK);
    installer.dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: GetRemoveDataGroupDirs_0010
 * @tc.name: test GetRemoveDataGroupDirs
 * @tc.desc: 1.GetRemoveDataGroupDirs
 */
HWTEST_F(BmsBundleDataGroupTest, GetRemoveDataGroupDirs_0010, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    InnerBundleInfo oldInfo;
    BaseBundleInstaller installer;

    auto result = installer.GetRemoveDataGroupDirs(oldInfo, info);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: RemoveOldGroupDirs_0010
 * @tc.name: test RemoveOldGroupDirs
 * @tc.desc: 1.RemoveOldGroupDirs
 */
HWTEST_F(BmsBundleDataGroupTest, RemoveOldGroupDirs_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string dir = DATA_GROUP_DIR_TEST;
    setuid(Constants::FOUNDATION_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    auto createDirRes = InstalldClient::GetInstance()->Mkdir(dir, S_IRWXU, BMS_UID, BMS_UID);
    ASSERT_EQ(createDirRes, ERR_OK);

    installer.removeGroupDirs_.emplace_back(dir);
    auto result = installer.RemoveOldGroupDirs();
    EXPECT_EQ(result, ERR_OK);
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
 * @tc.number: ProcessDataGroupInfo_0010
 * @tc.name: test ProcessDataGroupInfo
 * @tc.desc: 1.ProcessDataGroupInfo
 */
HWTEST_F(BmsBundleDataGroupTest, ProcessDataGroupInfo_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    std::vector<std::string> bundlePaths;
    bundlePaths.emplace_back(TEST_HAP_PATH);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    installer.ProcessDataGroupInfo(bundlePaths, infos, USERID, hapVerifyRes);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: ProcessDataGroupInfo_0020
 * @tc.name: test ProcessDataGroupInfo
 * @tc.desc: 1.ProcessDataGroupInfo
 */
HWTEST_F(BmsBundleDataGroupTest, ProcessDataGroupInfo_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    Security::Verify::HapVerifyResult hapVerifyResult;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    hapVerifyRes.emplace_back(hapVerifyResult);
    std::vector<std::string> bundlePaths;
    bundlePaths.emplace_back(TEST_HAP_PATH);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    installer.ProcessDataGroupInfo(bundlePaths, infos, USERID, hapVerifyRes);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: ProcessDataGroupInfo_0030
 * @tc.name: test ProcessDataGroupInfo
 * @tc.desc: 1.ProcessDataGroupInfo
 */
HWTEST_F(BmsBundleDataGroupTest, ProcessDataGroupInfo_0030, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    Security::Verify::HapVerifyResult hapVerifyResult;
    hapVerifyResult.provisionInfo.bundleInfo.dataGroupIds.emplace_back(DATA_GROUP_ID_TEST_ONE);
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    hapVerifyRes.emplace_back(hapVerifyResult);
    std::vector<std::string> bundlePaths;
    bundlePaths.emplace_back(TEST_HAP_PATH);

    InnerBundleInfo info;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace(TEST_HAP_PATH, info);
    installer.ProcessDataGroupInfo(bundlePaths, infos, USERID, hapVerifyRes);
    const auto &dataGroupInfos = infos[TEST_HAP_PATH].GetDataGroupInfos();
    EXPECT_FALSE(dataGroupInfos.empty());
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
 * @tc.number: GenerateDataGroupUuidAndUid_0010
 * @tc.name: test GenerateDataGroupUuidAndUid
 * @tc.desc: 1.GenerateDataGroupUuidAndUid
 */
HWTEST_F(BmsBundleDataGroupTest, GenerateDataGroupUuidAndUid_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    DataGroupInfo dataGroupInfo;
    dataGroupInfo.dataGroupId = DATA_GROUP_ID_TEST_THREE;
    std::map<std::string, std::pair<int32_t, std::string>> dataGroupIndexMap;
    dataGroupIndexMap.emplace(DATA_GROUP_ID_TEST_ONE, std::make_pair(TEST_GROUP_INDEX_ONE, DATA_GROUP_UUID_ONE));
    dataGroupIndexMap.emplace(DATA_GROUP_ID_TEST_TWO, std::make_pair(TEST_GROUP_INDEX_TWO, DATA_GROUP_UUID_TWO));

    int32_t uid = USERID * Constants::BASE_USER_RANGE + TEST_GROUP_INDEX_THREE + DATA_GROUP_UID_OFFSET;
    dataMgr->GenerateDataGroupUuidAndUid(dataGroupInfo, USERID, dataGroupIndexMap);
    EXPECT_EQ(dataGroupInfo.uid, uid);
    EXPECT_EQ(dataGroupInfo.gid, uid);
}

/**
 * @tc.number: GenerateDataGroupInfos_0010
 * @tc.name: test GenerateDataGroupInfos
 * @tc.desc: 1.GenerateDataGroupInfos
 */
HWTEST_F(BmsBundleDataGroupTest, GenerateDataGroupInfos_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<std::string> dataGroupIdList;
    InnerBundleInfo info;
    dataMgr->GenerateDataGroupInfos(info, dataGroupIdList, USERID);
    const auto &dataGroupInfos = info.GetDataGroupInfos();
    EXPECT_TRUE(dataGroupInfos.empty());
}

/**
 * @tc.number: GenerateDataGroupInfos_0020
 * @tc.name: test GenerateDataGroupInfos
 * @tc.desc: 1.GenerateDataGroupInfos
 */
HWTEST_F(BmsBundleDataGroupTest, GenerateDataGroupInfos_0020, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<std::string> dataGroupIdList;
    dataGroupIdList.emplace_back(DATA_GROUP_ID_TEST_ONE);
    InnerBundleInfo info;
    dataMgr->GenerateDataGroupInfos(info, dataGroupIdList, USERID);
    const auto &dataGroupInfos = info.GetDataGroupInfos();
    EXPECT_FALSE(dataGroupInfos.empty());
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

    std::vector<std::string> dataGroupIdList;
    dataGroupIdList.emplace_back(DATA_GROUP_ID_TEST_ONE);
    InnerBundleInfo info;
    dataMgr->GenerateDataGroupInfos(info, dataGroupIdList, USERID);
    auto dataGroupInfos = info.GetDataGroupInfos();
    EXPECT_FALSE(dataGroupInfos.empty());

    dataMgr->GenerateDataGroupInfos(info, dataGroupIdList, USERID_TWO);
    dataGroupInfos = info.GetDataGroupInfos();
    auto iter = dataGroupInfos.find(DATA_GROUP_ID_TEST_ONE);
    ASSERT_NE(iter, dataGroupInfos.end());
    EXPECT_EQ(iter->second.size(), 2);
}
} // OHOS