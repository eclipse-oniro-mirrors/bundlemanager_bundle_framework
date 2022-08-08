/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>

#include "app_log_wrapper.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "if_system_ability_manager.h"

using namespace OHOS::AppExecFwk;
using namespace testing::ext;

namespace OHOS {
namespace {
const std::string FILE1_PATH = "/data/test/hello.hqf";
const std::string FILE2_PATH = "/data/test/world.hqf";
const std::string INVALID_FILE_SUFFIX_PATH = "/data/test/invalidSuffix.txt";
const std::string NOT_EXIST_FILE_PATH = "/data/test/notExist.hqf";
}

class BmsBundleQuickFixManagerTest : public testing::Test {
public:
    BmsBundleQuickFixManagerTest();
    ~BmsBundleQuickFixManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    sptr<IQuickFixManager> GetQuickFixManagerProxy();
    void CreateFiles(const std::vector<std::string>& sourceFiles);
    void DeleteFiles(const std::vector<std::string>& destFiles);
    static std::vector<std::string> sourceFiles;
};

BmsBundleQuickFixManagerTest::BmsBundleQuickFixManagerTest()
{}

BmsBundleQuickFixManagerTest::~BmsBundleQuickFixManagerTest()
{}

void BmsBundleQuickFixManagerTest::SetUpTestCase()
{}

void BmsBundleQuickFixManagerTest::TearDownTestCase()
{}

void BmsBundleQuickFixManagerTest::SetUp()
{}

void BmsBundleQuickFixManagerTest::TearDown()
{}

sptr<IQuickFixManager> BmsBundleQuickFixManagerTest::GetQuickFixManagerProxy()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("GetSystemAbilityManager failed.");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        APP_LOGE("GetSystemAbility failed.");
        return nullptr;
    }
    auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
    if (bundleMgr == nullptr) {
        APP_LOGE("iface_cast failed.");
        return nullptr;
    }
    return bundleMgr->GetQuickFixManagerProxy();
}

void BmsBundleQuickFixManagerTest::CreateFiles(const std::vector<std::string>& sourceFiles)
{
    for (const auto& path : sourceFiles) {
        SaveStringToFile(path, path);
    }
}

void BmsBundleQuickFixManagerTest::DeleteFiles(const std::vector<std::string>& destFiles)
{
    for (const auto& path : destFiles) {
        RemoveFile(path);
    }
}

/**
 * @tc.number: BmsBundleQuickFixManager_0100
 * @tc.name: test CopyFiles
 * @tc.desc: 1. call CopyFiles, files copy to dest path, return true
 * @tc.require: AR000H036M
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0100.");
    auto quickFixManagerProxy = GetQuickFixManagerProxy();
    ASSERT_NE(quickFixManagerProxy, nullptr);
    std::vector<std::string> sourceFiles {FILE1_PATH, FILE2_PATH};
    CreateFiles(sourceFiles);
    std::vector<std::string> destFiles;
    bool ret = quickFixManagerProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_TRUE(ret);
    ASSERT_EQ(destFiles.size(), sourceFiles.size());
    EXPECT_TRUE(FileExists(destFiles[0]));
    EXPECT_TRUE(FileExists(destFiles[1]));
    EXPECT_EQ(LoadStringFromFile(FILE1_PATH), FILE1_PATH);
    EXPECT_EQ(LoadStringFromFile(FILE2_PATH), FILE2_PATH);
    DeleteFiles(sourceFiles);
    DeleteFiles(destFiles);
    APP_LOGI("end of BmsBundleQuickFixManager_0100.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0200
 * @tc.name: test CopyFiles
 * @tc.desc: 1. call CopyFiles with invalid file suffix, return false
 * @tc.require: AR000H036M
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0200.");
    auto quickFixManagerProxy = GetQuickFixManagerProxy();
    ASSERT_NE(quickFixManagerProxy, nullptr);
    std::vector<std::string> sourceFiles {INVALID_FILE_SUFFIX_PATH};
    CreateFiles(sourceFiles);
    std::vector<std::string> destFiles;
    bool ret = quickFixManagerProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_FALSE(ret);
    DeleteFiles(sourceFiles);
    APP_LOGI("end of BmsBundleQuickFixManager_0200.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0300
 * @tc.name: test CopyFiles
 * @tc.desc: 1. call CopyFiles with not exist file, return false
 * @tc.require: AR000H036M
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0300, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0300.");
    auto quickFixManagerProxy = GetQuickFixManagerProxy();
    ASSERT_NE(quickFixManagerProxy, nullptr);
    std::vector<std::string> sourceFiles {NOT_EXIST_FILE_PATH};
    std::vector<std::string> destFiles;
    bool ret = quickFixManagerProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_FALSE(ret);
    APP_LOGI("end of BmsBundleQuickFixManager_0300.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0400
 * @tc.name: test CopyFiles
 * @tc.desc: 1. call CopyFiles with empty vector, return false
 * @tc.require: AR000H036M
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0400, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0400.");
    auto quickFixManagerProxy = GetQuickFixManagerProxy();
    ASSERT_NE(quickFixManagerProxy, nullptr);
    std::vector<std::string> sourceFiles;
    std::vector<std::string> destFiles;
    bool ret = quickFixManagerProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_FALSE(ret);
    APP_LOGI("end of BmsBundleQuickFixManager_0400.");
}
}