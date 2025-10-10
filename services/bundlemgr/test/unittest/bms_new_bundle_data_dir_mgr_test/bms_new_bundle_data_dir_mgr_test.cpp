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
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "base_bundle_installer.h"
#include "bundle_mgr_host.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "directory_ex.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "new_bundle_data_dir_mgr.h"
#include "nlohmann/json.hpp"

namespace OHOS {
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {
const std::string BUNDLE_NAME = "com.test.new_bundle_data_dir_mgr";
const std::string BUNDLE_NAME_NOT_EXIST = "com.test.not_exist_name";
const int32_t USER_ID = 100;
const int32_t USER_ID_2 = 200;
const int32_t WAIT_TIME_SECONDS = 5;
const std::string EL2_DATABASE_PATH = "/data/app/el2/100/database/com.test.new_bundle_data_dir_mgr";
const std::string EL5_DATABASE_PATH = "/data/app/el5/100/database/com.test.new_bundle_data_dir_mgr";
}  // namespace

class BmsNewBundleDataDirMgrTest : public testing::Test {
public:
    BmsNewBundleDataDirMgrTest();
    ~BmsNewBundleDataDirMgrTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    static void StartBundleService();
    static void StartInstalldService();
    static void InstallBundle(const std::string &bundlePath);
    static void UnInstallBundle(const std::string &bundleName);
    static std::vector<Skill> BuildSkillsVector(const size_t size);
    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<InstalldService> installdService_;
};

std::shared_ptr<BundleMgrService> BmsNewBundleDataDirMgrTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsNewBundleDataDirMgrTest::installdService_ =
    DelayedSingleton<InstalldService>::GetInstance();

BmsNewBundleDataDirMgrTest::BmsNewBundleDataDirMgrTest()
{}

BmsNewBundleDataDirMgrTest::~BmsNewBundleDataDirMgrTest()
{}

void BmsNewBundleDataDirMgrTest::SetUpTestCase()
{
    StartBundleService();
    StartInstalldService();
}

void BmsNewBundleDataDirMgrTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsNewBundleDataDirMgrTest::SetUp()
{}

void BmsNewBundleDataDirMgrTest::TearDown()
{}

void BmsNewBundleDataDirMgrTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME_SECONDS));
    }
}

void BmsNewBundleDataDirMgrTest::StartInstalldService()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsNewBundleDataDirMgrTest::InstallBundle(const std::string &bundlePath)
{
    if (!bundleMgrService_) {
        GTEST_FAIL() << "bundleMgrService_ is nullptr";
        return;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        GTEST_FAIL() << "installer is nullptr";
        return;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        GTEST_FAIL() << "receiver is nullptr";
        return;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USER_ID;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    receiver->GetResultCode();
}

void BmsNewBundleDataDirMgrTest::UnInstallBundle(const std::string &bundleName)
{
    if (!bundleMgrService_) {
        GTEST_FAIL() << "bundleMgrService_ is nullptr";
        return;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        GTEST_FAIL() << "installer is nullptr";
        return;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        GTEST_FAIL() << "installer is nullptr";
        return;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USER_ID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    receiver->GetResultCode();
}

std::vector<Skill> BmsNewBundleDataDirMgrTest::BuildSkillsVector(const size_t size)
{
    std::vector<Skill> skills;
    for (size_t i = 0; i < size; ++i) {
        Skill skill;
        skills.emplace_back(skill);
    }
    return skills;
}

/**
 * @tc.number: GetAllNewBundleDataDirBundleName_0001
 * @tc.name: GetAllNewBundleDataDirBundleName_0001
 * @tc.desc: 1.test GetAllNewBundleDataDirBundleName
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, GetAllNewBundleDataDirBundleName_0001, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        auto names = newBundleDirMgr->GetAllNewBundleDataDirBundleName();
        EXPECT_TRUE(names.empty());
    }
}

/**
 * @tc.number: AddAllUserId_0001
 * @tc.name: AddAllUserId_0001
 * @tc.desc: 1.test AddAllUserId
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, AddAllUserId_0001, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        std::set<int32_t> userIds;
        userIds.insert(0);
        userIds.insert(USER_ID);
        auto ret = newBundleDirMgr->AddAllUserId(userIds);
        EXPECT_TRUE(ret);
        newBundleDirMgr->hasInit_ = false;
        ret = newBundleDirMgr->AddAllUserId(userIds);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: DeleteUserId_0001
 * @tc.name: DeleteUserId_0001
 * @tc.desc: 1.test DeleteUserId
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, DeleteUserId_0001, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        std::set<int32_t> userIds;
        userIds.insert(0);
        userIds.insert(USER_ID);
        auto ret = newBundleDirMgr->AddAllUserId(userIds);
        EXPECT_TRUE(ret);
        newBundleDirMgr->hasInit_ = false;
        ret = newBundleDirMgr->DeleteUserId(0);
        EXPECT_TRUE(ret);
        ret = newBundleDirMgr->DeleteUserId(USER_ID);
        EXPECT_TRUE(ret);

        userIds.insert(USER_ID_2);
        ret = newBundleDirMgr->AddAllUserId(userIds);
        EXPECT_TRUE(ret);
        ret = newBundleDirMgr->DeleteUserId(USER_ID_2);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: AddNewBundleDirInfo_0001
 * @tc.name: AddNewBundleDirInfo_0001
 * @tc.desc: 1.test AddNewBundleDirInfo
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, AddNewBundleDirInfo_0001, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        std::set<int32_t> userIds;
        userIds.insert(USER_ID);
        auto ret = newBundleDirMgr->AddAllUserId(userIds);
        EXPECT_TRUE(ret);
        ret = newBundleDirMgr->AddNewBundleDirInfo("", 0);
        EXPECT_FALSE(ret);

        newBundleDirMgr->hasInit_ = false;
        ret = newBundleDirMgr->AddNewBundleDirInfo(BUNDLE_NAME,
            static_cast<uint32_t>(CreateBundleDirType::CREATE_ALL_DIR));
        EXPECT_TRUE(ret);

        ret = newBundleDirMgr->AddNewBundleDirInfo(BUNDLE_NAME,
            static_cast<uint32_t>(CreateBundleDirType::CREATE_EL5_DIR));
        EXPECT_TRUE(ret);

        uint32_t type = newBundleDirMgr->GetNewBundleDataDirType(BUNDLE_NAME, 0);
        EXPECT_EQ(type, 0);
        newBundleDirMgr->hasInit_ = false;
        type = newBundleDirMgr->GetNewBundleDataDirType(BUNDLE_NAME_NOT_EXIST, USER_ID);
        EXPECT_EQ(type, 0);

        type = newBundleDirMgr->GetNewBundleDataDirType(BUNDLE_NAME, USER_ID);
        EXPECT_EQ(type, static_cast<uint32_t>(CreateBundleDirType::CREATE_ALL_DIR) |
            static_cast<uint32_t>(CreateBundleDirType::CREATE_EL5_DIR));
        ret = newBundleDirMgr->DeleteUserId(USER_ID);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: InnerProcessOtaNewInstallBundleDir_0001
 * @tc.name: InnerProcessOtaNewInstallBundleDir
 * @tc.desc: 1.test InnerProcessOtaNewInstallBundleDir, path exist
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, InnerProcessOtaNewInstallBundleDir_0001, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        bool ret = OHOS::ForceCreateDirectory(EL2_DATABASE_PATH);
        EXPECT_TRUE(ret);
        ret = newBundleDirMgr->InnerProcessOtaNewInstallBundleDir(BUNDLE_NAME, USER_ID);
        EXPECT_TRUE(ret);
        ret = OHOS::ForceRemoveDirectory(EL2_DATABASE_PATH);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: InnerProcessOtaNewInstallBundleDir_0002
 * @tc.name: InnerProcessOtaNewInstallBundleDir
 * @tc.desc: 1.test InnerProcessOtaNewInstallBundleDir, path not exist
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, InnerProcessOtaNewInstallBundleDir_0002, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        bundleMgrService_->RegisterDataMgr(nullptr);
        bool ret = newBundleDirMgr->InnerProcessOtaNewInstallBundleDir(BUNDLE_NAME, USER_ID);
        EXPECT_FALSE(ret);
        bundleMgrService_->RegisterDataMgr(savedDataMgr);
    }
}

/**
 * @tc.number: InnerProcessOtaNewInstallBundleDir_0003
 * @tc.name: InnerProcessOtaNewInstallBundleDir
 * @tc.desc: 1.test InnerProcessOtaNewInstallBundleDir, path not exist
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, InnerProcessOtaNewInstallBundleDir_0003, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        bool ret = newBundleDirMgr->InnerProcessOtaNewInstallBundleDir(BUNDLE_NAME, USER_ID);
        EXPECT_FALSE(ret);
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        InnerBundleInfo bundleInfo;
        savedDataMgr->bundleInfos_[BUNDLE_NAME] = bundleInfo;
        ret = newBundleDirMgr->InnerProcessOtaNewInstallBundleDir(BUNDLE_NAME, USER_ID);
        EXPECT_FALSE(ret);
        InnerBundleUserInfo userInfo;
        userInfo.uid = 0;
        userInfo.gids.emplace_back(0);
        userInfo.bundleUserInfo.userId = USER_ID;
        bundleInfo.AddInnerBundleUserInfo(userInfo);
        savedDataMgr->bundleInfos_[BUNDLE_NAME] = bundleInfo;
        ret = newBundleDirMgr->InnerProcessOtaNewInstallBundleDir(BUNDLE_NAME, USER_ID);
        EXPECT_TRUE(ret);
        // create el5 and group
        InnerModuleInfo moduleInfo;
        RequestPermission requestPermission;
        requestPermission.name = ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA;
        moduleInfo.requestPermissions.emplace_back(requestPermission);
        bundleInfo.innerModuleInfos_[BUNDLE_NAME] = moduleInfo;
        bundleInfo.dataGroupInfos_[BUNDLE_NAME] = {};
        savedDataMgr->bundleInfos_[BUNDLE_NAME] = bundleInfo;
        ret = newBundleDirMgr->InnerProcessOtaNewInstallBundleDir(BUNDLE_NAME, USER_ID);
        EXPECT_TRUE(ret);
        auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME);
        EXPECT_TRUE(iter != savedDataMgr->bundleInfos_.end());
        if (iter != savedDataMgr->bundleInfos_.end()) {
            savedDataMgr->bundleInfos_.erase(iter);
        }
        auto errCode = InstalldClient::GetInstance()->RemoveBundleDataDir(BUNDLE_NAME, USER_ID);
        EXPECT_EQ(errCode, ERR_OK);
    }
}


/**
 * @tc.number: InnerProcessOtaBundleDataDirEl5_0001
 * @tc.name: InnerProcessOtaBundleDataDirEl5
 * @tc.desc: 1.test InnerProcessOtaBundleDataDirEl5, path exist
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, InnerProcessOtaBundleDataDirEl5_0001, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        bool ret = OHOS::ForceCreateDirectory(EL5_DATABASE_PATH);
        EXPECT_TRUE(ret);
        ret = newBundleDirMgr->InnerProcessOtaBundleDataDirEl5(BUNDLE_NAME, USER_ID);
        EXPECT_TRUE(ret);
        ret = OHOS::ForceRemoveDirectory(EL5_DATABASE_PATH);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: InnerProcessOtaBundleDataDirEl5_0002
 * @tc.name: InnerProcessOtaBundleDataDirEl5
 * @tc.desc: 1.test InnerProcessOtaBundleDataDirEl5, path not exist
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, InnerProcessOtaBundleDataDirEl5_0002, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        bundleMgrService_->RegisterDataMgr(nullptr);
        bool ret = newBundleDirMgr->InnerProcessOtaBundleDataDirEl5(BUNDLE_NAME, USER_ID);
        EXPECT_FALSE(ret);
        bundleMgrService_->RegisterDataMgr(savedDataMgr);
    }
}

/**
 * @tc.number: InnerProcessOtaBundleDataDirEl5_0003
 * @tc.name: InnerProcessOtaBundleDataDirEl5
 * @tc.desc: 1.test InnerProcessOtaBundleDataDirEl5, bundle not exist
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, InnerProcessOtaBundleDataDirEl5_0003, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        bool ret = newBundleDirMgr->InnerProcessOtaBundleDataDirEl5(BUNDLE_NAME, USER_ID);
        EXPECT_FALSE(ret);
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        InnerBundleInfo bundleInfo;
        savedDataMgr->bundleInfos_[BUNDLE_NAME] = bundleInfo;
        ret = newBundleDirMgr->InnerProcessOtaBundleDataDirEl5(BUNDLE_NAME, USER_ID);
        EXPECT_TRUE(ret);
        auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME);
        EXPECT_TRUE(iter != savedDataMgr->bundleInfos_.end());
        if (iter != savedDataMgr->bundleInfos_.end()) {
            savedDataMgr->bundleInfos_.erase(iter);
        }
    }
}

/**
 * @tc.number: InnerProcessOtaBundleDataDirEl5_0004
 * @tc.name: InnerProcessOtaBundleDataDirEl5
 * @tc.desc: 1.test InnerProcessOtaBundleDataDirEl5, user not exist
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, InnerProcessOtaBundleDataDirEl5_0004, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        InnerBundleInfo bundleInfo;
        InnerModuleInfo moduleInfo;
        RequestPermission requestPermission;
        requestPermission.name = ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA;
        moduleInfo.requestPermissions.emplace_back(requestPermission);
        bundleInfo.innerModuleInfos_[BUNDLE_NAME] = moduleInfo;
        savedDataMgr->bundleInfos_[BUNDLE_NAME] = bundleInfo;
        bool ret = newBundleDirMgr->InnerProcessOtaBundleDataDirEl5(BUNDLE_NAME, USER_ID);
        EXPECT_FALSE(ret);
        auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME);
        EXPECT_TRUE(iter != savedDataMgr->bundleInfos_.end());
        if (iter != savedDataMgr->bundleInfos_.end()) {
            savedDataMgr->bundleInfos_.erase(iter);
        }
    }
}

/**
 * @tc.number: InnerProcessOtaBundleDataDirEl5_0005
 * @tc.name: InnerProcessOtaBundleDataDirEl5
 * @tc.desc: 1.test InnerProcessOtaBundleDataDirEl5
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, InnerProcessOtaBundleDataDirEl5_0005, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        InnerBundleInfo bundleInfo;
        InnerModuleInfo moduleInfo;
        RequestPermission requestPermission;
        requestPermission.name = ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA;
        moduleInfo.requestPermissions.emplace_back(requestPermission);
        bundleInfo.innerModuleInfos_[BUNDLE_NAME] = moduleInfo;
        InnerBundleUserInfo userInfo;
        userInfo.uid = 0;
        userInfo.gids.emplace_back(0);
        userInfo.bundleUserInfo.userId = USER_ID;
        bundleInfo.AddInnerBundleUserInfo(userInfo);
        savedDataMgr->bundleInfos_[BUNDLE_NAME] = bundleInfo;
        bool ret = newBundleDirMgr->InnerProcessOtaBundleDataDirEl5(BUNDLE_NAME, USER_ID);
        EXPECT_TRUE(ret);
        auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME);
        EXPECT_TRUE(iter != savedDataMgr->bundleInfos_.end());
        if (iter != savedDataMgr->bundleInfos_.end()) {
            savedDataMgr->bundleInfos_.erase(iter);
        }
        ret = OHOS::ForceRemoveDirectory(EL5_DATABASE_PATH);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: InnerProcessOtaBundleDataDirGroup_0001
 * @tc.name: InnerProcessOtaBundleDataDirGroup
 * @tc.desc: 1.test InnerProcessOtaBundleDataDirGroup
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, InnerProcessOtaBundleDataDirGroup_0001, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        bundleMgrService_->RegisterDataMgr(nullptr);
        bool ret = newBundleDirMgr->InnerProcessOtaBundleDataDirGroup(BUNDLE_NAME_NOT_EXIST, USER_ID);
        EXPECT_FALSE(ret);
        bundleMgrService_->RegisterDataMgr(savedDataMgr);
        ret = newBundleDirMgr->InnerProcessOtaBundleDataDirGroup(BUNDLE_NAME_NOT_EXIST, USER_ID);
        EXPECT_FALSE(ret);
        InnerBundleInfo bundleInfo;
        savedDataMgr->bundleInfos_[BUNDLE_NAME] = bundleInfo;
        ret = newBundleDirMgr->InnerProcessOtaBundleDataDirGroup(BUNDLE_NAME, USER_ID);
        EXPECT_TRUE(ret);
        auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME);
        EXPECT_TRUE(iter != savedDataMgr->bundleInfos_.end());
        if (iter != savedDataMgr->bundleInfos_.end()) {
            savedDataMgr->bundleInfos_.erase(iter);
        }
    }
}

/**
 * @tc.number: IProcessOtaBundleDataDir_0001
 * @tc.name: ProcessOtaBundleDataDir
 * @tc.desc: 1.test ProcessOtaBundleDataDir
 */
HWTEST_F(BmsNewBundleDataDirMgrTest, ProcessOtaBundleDataDir_0001, Function | SmallTest | Level1)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    EXPECT_NE(newBundleDirMgr, nullptr);
    if (newBundleDirMgr != nullptr) {
        bool ret = newBundleDirMgr->ProcessOtaBundleDataDir(BUNDLE_NAME, USER_ID);
        EXPECT_TRUE(ret);
        std::set<int32_t> userIds;
        userIds.insert(USER_ID);
        ret = newBundleDirMgr->AddAllUserId(userIds);
        EXPECT_TRUE(ret);
        ret = newBundleDirMgr->AddNewBundleDirInfo(BUNDLE_NAME,
            static_cast<uint32_t>(CreateBundleDirType::CREATE_ALL_DIR) |
            static_cast<uint32_t>(CreateBundleDirType::CREATE_EL5_DIR) |
            static_cast<uint32_t>(CreateBundleDirType::CREATE_GROUP_DIR));
        EXPECT_TRUE(ret);
        ret = newBundleDirMgr->ProcessOtaBundleDataDir(BUNDLE_NAME, USER_ID);
        EXPECT_FALSE(ret);
    }
}
}
