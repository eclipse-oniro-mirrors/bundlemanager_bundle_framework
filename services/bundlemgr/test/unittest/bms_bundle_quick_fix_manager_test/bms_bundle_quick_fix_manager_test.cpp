/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "inner_app_quick_fix.h"
#include "iservice_registry.h"
#include "quick_fix_data_mgr.h"
#include "quick_fix_manager_rdb.h"
#include "system_ability_definition.h"

#define private public

using namespace OHOS::AppExecFwk;
using namespace testing::ext;

namespace OHOS {
namespace {
const std::string FILE1_PATH = "/data/test/hello.hqf";
const std::string FILE2_PATH = "/data/test/world.hqf";
const std::string INVALID_FILE_SUFFIX_PATH = "/data/test/invalidSuffix.txt";
const std::string NOT_EXIST_FILE_PATH = "/data/test/notExist.hqf";
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const uint32_t QUICK_FIX_VERSION_CODE = 1;
const uint32_t BUNDLE_VERSION_CODE = 1;
const std::string QUICK_FIX_VERSION_NAME = "1.0";
const std::string BUNDLE_VERSION_NAME = "1.0";
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
    AppQuickFix CreateAppQuickFix();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleQuickFixManagerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleQuickFixManagerTest::BmsBundleQuickFixManagerTest()
{}

BmsBundleQuickFixManagerTest::~BmsBundleQuickFixManagerTest()
{}

void BmsBundleQuickFixManagerTest::SetUpTestCase()
{}

void BmsBundleQuickFixManagerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleQuickFixManagerTest::SetUp()
{}

void BmsBundleQuickFixManagerTest::TearDown()
{}

AppQuickFix BmsBundleQuickFixManagerTest::CreateAppQuickFix()
{
    AppqfInfo appInfo;
    appInfo.versionCode = QUICK_FIX_VERSION_CODE;
    appInfo.versionName = QUICK_FIX_VERSION_NAME;
    appInfo.type = QuickFixType::PATCH;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "entry";
    hqfInfo.type = QuickFixType::PATCH;
    appInfo.hqfInfos.push_back(hqfInfo);
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    appQuickFix.versionCode = BUNDLE_VERSION_CODE;
    appQuickFix.versionName = BUNDLE_VERSION_NAME;
    appQuickFix.deployingAppqfInfo = appInfo;
    return appQuickFix;
}

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
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0100.");
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    auto quickFixManagerProxy = GetQuickFixManagerProxy();
    ASSERT_NE(quickFixManagerProxy, nullptr);
    std::vector<std::string> sourceFiles {FILE1_PATH, FILE2_PATH};
    CreateFiles(sourceFiles);
    std::vector<std::string> destFiles;
    auto ret = quickFixManagerProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(destFiles.size(), sourceFiles.size());
    EXPECT_TRUE(FileExists(destFiles[0]));
    EXPECT_TRUE(FileExists(destFiles[1]));
    std::string content1;
    LoadStringFromFile(FILE1_PATH, content1);
    EXPECT_EQ(content1, FILE1_PATH);
    std::string content2;
    LoadStringFromFile(FILE2_PATH, content2);
    EXPECT_EQ(content2, FILE2_PATH);
    DeleteFiles(sourceFiles);
    DeleteFiles(destFiles);
#else
    ASSERT_TRUE(true);
#endif
    APP_LOGI("end of BmsBundleQuickFixManager_0100.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0200
 * @tc.name: test CopyFiles
 * @tc.desc: 1. call CopyFiles with invalid file suffix, return false
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0200.");
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    auto quickFixManagerProxy = GetQuickFixManagerProxy();
    ASSERT_NE(quickFixManagerProxy, nullptr);
    std::vector<std::string> sourceFiles {INVALID_FILE_SUFFIX_PATH};
    CreateFiles(sourceFiles);
    std::vector<std::string> destFiles;
    auto ret = quickFixManagerProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    DeleteFiles(sourceFiles);
#else
    ASSERT_TRUE(true);
#endif
    APP_LOGI("end of BmsBundleQuickFixManager_0200.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0300
 * @tc.name: test CopyFiles
 * @tc.desc: 1. call CopyFiles with not exist file, return false
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0300, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0300.");
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    auto quickFixManagerProxy = GetQuickFixManagerProxy();
    ASSERT_NE(quickFixManagerProxy, nullptr);
    std::vector<std::string> sourceFiles {NOT_EXIST_FILE_PATH};
    std::vector<std::string> destFiles;
    auto ret = quickFixManagerProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
#else
     ASSERT_TRUE(true);
#endif
    APP_LOGI("end of BmsBundleQuickFixManager_0300.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0400
 * @tc.name: test CopyFiles
 * @tc.desc: 1. call CopyFiles with empty vector, return false
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0400, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0400.");
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    auto quickFixManagerProxy = GetQuickFixManagerProxy();
    ASSERT_NE(quickFixManagerProxy, nullptr);
    std::vector<std::string> sourceFiles;
    std::vector<std::string> destFiles;
    auto ret = quickFixManagerProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
#else
    ASSERT_TRUE(true);
#endif
    APP_LOGI("end of BmsBundleQuickFixManager_0400.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0500
 * @tc.name: test SaveInnerAppQuickFix
 * @tc.desc: SaveInnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0500, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0500.");
    auto dataMgr = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerAppQuickFix innerAppQuickFix;
        innerAppQuickFix.SetAppQuickFix(CreateAppQuickFix());
        auto ret = dataMgr->SaveInnerAppQuickFix(innerAppQuickFix);
        EXPECT_TRUE(ret);
        ret = dataMgr->DeleteInnerAppQuickFix(BUNDLE_NAME);
        EXPECT_TRUE(ret);
    }
    APP_LOGI("end of BmsBundleQuickFixManager_0500.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0600
 * @tc.name: test QueryInnerAppQuickFix
 * @tc.desc: QueryInnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0600, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0600.");
    auto dataMgr = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerAppQuickFix innerAppQuickFix;
        innerAppQuickFix.SetAppQuickFix(CreateAppQuickFix());
        auto ret = dataMgr->SaveInnerAppQuickFix(innerAppQuickFix);
        EXPECT_TRUE(ret);
        InnerAppQuickFix newInnerAppQuickFix;
        ret = dataMgr->QueryInnerAppQuickFix(BUNDLE_NAME, newInnerAppQuickFix);
        EXPECT_TRUE(ret);
        EXPECT_EQ(BUNDLE_NAME, newInnerAppQuickFix.GetAppQuickFix().bundleName);
        ret = dataMgr->DeleteInnerAppQuickFix(BUNDLE_NAME);
        EXPECT_TRUE(ret);
    }
    APP_LOGI("end of BmsBundleQuickFixManager_0600.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0700
 * @tc.name: test QueryAllInnerAppQuickFix
 * @tc.desc: QueryAllInnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0700, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0700.");
    auto dataMgr = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerAppQuickFix innerAppQuickFix;
        innerAppQuickFix.SetAppQuickFix(CreateAppQuickFix());
        auto ret = dataMgr->SaveInnerAppQuickFix(innerAppQuickFix);
        EXPECT_TRUE(ret);
        std::map<std::string, InnerAppQuickFix> newInnerAppQuickFixes;
        ret = dataMgr->QueryAllInnerAppQuickFix(newInnerAppQuickFixes);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(newInnerAppQuickFixes.empty());
        ret = dataMgr->DeleteInnerAppQuickFix(BUNDLE_NAME);
        EXPECT_TRUE(ret);
    }
    APP_LOGI("end of BmsBundleQuickFixManager_0700.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0800
 * @tc.name: test QueryAllInnerAppQuickFix
 * @tc.desc: QueryAllInnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0800, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0800.");
    auto dataMgr = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        std::map<std::string, InnerAppQuickFix> newInnerAppQuickFixes;
        bool ret = dataMgr->QueryAllInnerAppQuickFix(newInnerAppQuickFixes);
        EXPECT_FALSE(ret);
        EXPECT_TRUE(newInnerAppQuickFixes.empty());
    }
    APP_LOGI("end of BmsBundleQuickFixManager_0800.");
}

/**
 * @tc.number: BmsBundleQuickFixManager_0900
 * @tc.name: test UpdateQuickFixStatus
 * @tc.desc: UpdateQuickFixStatus
 */
HWTEST_F(BmsBundleQuickFixManagerTest, BmsBundleQuickFixManager_0900, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BmsBundleQuickFixManager_0900.");
    auto dataMgr = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        QuickFixStatus nextStatus = QuickFixStatus::DEFAULT_STATUS;
        InnerAppQuickFix innerAppQuickFix;
        QuickFixMark mark;
        mark.status = QuickFixStatus::DEFAULT_STATUS;
        innerAppQuickFix.SetQuickFixMark(mark);
        bool ret = dataMgr->UpdateQuickFixStatus(nextStatus, innerAppQuickFix);
        EXPECT_FALSE(ret);

        mark.status = QuickFixStatus::DELETE_START;
        innerAppQuickFix.SetQuickFixMark(mark);
        nextStatus = QuickFixStatus::DEFAULT_STATUS;
        ret = dataMgr->UpdateQuickFixStatus(nextStatus, innerAppQuickFix);
        EXPECT_FALSE(ret);
    }
    APP_LOGI("end of BmsBundleQuickFixManager_0900.");
}
}