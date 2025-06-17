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
#include <gtest/gtest.h>
#include <string>
#include <sys/stat.h>

#include "aot_handler.h"
#include "aot_sign_data_cache_mgr.h"
#include "app_log_wrapper.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "installd_client.h"
#include "installd_service.h"
#include "mock_status_receiver.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_PATH = "/data/test/resource/bms/aot_handler_bundle/bmsThirdBundle1.hap";
const std::string BUNDLE_NAME = "com.third.hiworld.example1";
constexpr int32_t USER_ID = 100;
constexpr uint8_t WAIT_TIME_SECONDS = 5;
}  // namespace

class BmsAOTHandlerTest : public testing::Test {
public:
    BmsAOTHandlerTest();
    ~BmsAOTHandlerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void InstallBundle(const std::string &bundlePath) const;
    void UninstallBundle(const std::string &bundleName) const;
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<InstalldService> installdService_;
};

std::shared_ptr<BundleMgrService> BmsAOTHandlerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsAOTHandlerTest::installdService_ =
    std::make_shared<InstalldService>();

BmsAOTHandlerTest::BmsAOTHandlerTest()
{}

BmsAOTHandlerTest::~BmsAOTHandlerTest()
{}

void BmsAOTHandlerTest::SetUpTestCase()
{
    bundleMgrService_->OnStart();
    bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME_SECONDS));
    installdService_->Start();
}

void BmsAOTHandlerTest::TearDownTestCase()
{
    AOTHandler::GetInstance().serialQueue_ = nullptr;
    bundleMgrService_->OnStop();
}

void BmsAOTHandlerTest::SetUp()
{
    InstallBundle(BUNDLE_PATH);
}

void BmsAOTHandlerTest::TearDown()
{
    UninstallBundle(BUNDLE_NAME);
}

void BmsAOTHandlerTest::InstallBundle(const std::string &bundlePath) const
{
    auto installer = bundleMgrService_->GetBundleInstaller();
    ASSERT_NE(installer, nullptr);
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    ASSERT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USER_ID;
    installParam.withCopyHaps = true;
    bool ret = installer->Install(bundlePath, installParam, receiver);
    ASSERT_TRUE(ret);
    (void)receiver->GetResultCode();
}

void BmsAOTHandlerTest::UninstallBundle(const std::string &bundleName) const
{
    auto installer = bundleMgrService_->GetBundleInstaller();
    ASSERT_NE(installer, nullptr);
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    ASSERT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USER_ID;
    bool ret = installer->Uninstall(bundleName, installParam, receiver);
    ASSERT_TRUE(ret);
    (void)receiver->GetResultCode();
}

/**
 * @tc.number: BuildArkProfilePath_0100
 * @tc.name: test BuildArkProfilePath
 * @tc.desc: 1.param is userId, expect return userPath
 *           2.param is userId and bundleName, expect return bundlePath
 *           3.param is userId, bundleName and moduleName, expect return modulePath
 */
HWTEST_F(BmsAOTHandlerTest, BuildArkProfilePath_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    std::string moduleName = "moduleName";
    std::string userPath = "/data/app/el1/" + std::to_string(USER_ID) + "/aot_compiler/ark_profile";
    std::string bundlePath = userPath + "/" + bundleName;
    std::string modulePath = bundlePath + "/" + moduleName;

    std::string path = AOTHandler::BuildArkProfilePath(USER_ID);
    EXPECT_EQ(path, userPath);
    path = AOTHandler::BuildArkProfilePath(USER_ID, "", moduleName);
    EXPECT_EQ(path, userPath);
    path = AOTHandler::BuildArkProfilePath(USER_ID, bundleName);
    EXPECT_EQ(path, bundlePath);
    path = AOTHandler::BuildArkProfilePath(USER_ID, bundleName, moduleName);
    EXPECT_EQ(path, modulePath);
}

/**
 * @tc.number: HandleArkPathsChange_0100
 * @tc.name: test HandleArkPathsChange
 * @tc.desc: 1.call HandleArkPathsChange, call CheckOtaFlag, expect isHandled is true
 */
HWTEST_F(BmsAOTHandlerTest, HandleArkPathsChange_0100, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().HandleArkPathsChange();
    bool isHandled = false;
    (void)BMSEventHandler::CheckOtaFlag(OTAFlag::DELETE_DEPRECATED_ARK_PATHS, isHandled);
    EXPECT_FALSE(isHandled);
}

/**
 * @tc.number: DelDeprecatedArkPaths_0100
 * @tc.name: test DelDeprecatedArkPaths
 * @tc.desc: 1.call DelDeprecatedArkPaths, expect dirs not exist
 */
HWTEST_F(BmsAOTHandlerTest, DelDeprecatedArkPaths_0100, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().DelDeprecatedArkPaths();
    bool isExist = true;
    (void)InstalldClient::GetInstance()->IsExistDir("/data/local/ark-cache", isExist);
    EXPECT_FALSE(isExist);
    isExist = true;
    (void)InstalldClient::GetInstance()->IsExistDir("/data/local/ark-profile", isExist);
    EXPECT_FALSE(isExist);
}

/**
 * @tc.number: CreateArkProfilePaths_0100
 * @tc.name: test CreateArkProfilePaths
 * @tc.desc: 1.call CreateArkProfilePaths, expect dirs exist
 */
HWTEST_F(BmsAOTHandlerTest, CreateArkProfilePaths_0100, Function | SmallTest | Level1)
{
    std::string path = AOTHandler::BuildArkProfilePath(USER_ID, BUNDLE_NAME);
    (void)InstalldClient::GetInstance()->RemoveDir(path);
    bool isExist = true;
    (void)InstalldClient::GetInstance()->IsExistDir(path, isExist);
    EXPECT_FALSE(isExist);

    AOTHandler::GetInstance().CreateArkProfilePaths();
    (void)InstalldClient::GetInstance()->IsExistDir(path, isExist);
    EXPECT_TRUE(isExist);
}

/**
 * @tc.number: HandleIdleWithSingleSysComp_0100
 * @tc.name: test HandleIdleWithSingleSysComp
 * @tc.desc: 1.call HandleIdleWithSingleSysComp, expect sysCompSignDataMap_ size is 0
 */
HWTEST_F(BmsAOTHandlerTest, HandleIdleWithSingleSysComp_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.clear();

    std::string path;
    AOTHandler::GetInstance().HandleIdleWithSingleSysComp(path);
    size_t sysCompSignDataMapSize = AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.size();
    EXPECT_EQ(sysCompSignDataMapSize, 0);
}

/**
 * @tc.number: IdleForSysComp_0100
 * @tc.name: test IdleForSysComp
 * @tc.desc: 1.call IdleForSysComp, expect sysCompSignDataMap_ size is 0
 */
HWTEST_F(BmsAOTHandlerTest, IdleForSysComp_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.clear();

    AOTHandler::GetInstance().IdleForSysComp();
    size_t sysCompSignDataMapSize = AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.size();
    EXPECT_EQ(sysCompSignDataMapSize, 0);
}

/**
 * @tc.number: IdleForHap_0100
 * @tc.name: test IdleForHap
 * @tc.desc: 1.call IdleForHap, expect sysCompSignDataMap_ size is 0
 */
HWTEST_F(BmsAOTHandlerTest, IdleForHap_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.clear();

    std::string compilePartial = "partial";
    AOTHandler::GetInstance().IdleForHap(compilePartial);
    size_t sysCompSignDataMapSize = AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.size();
    EXPECT_EQ(sysCompSignDataMapSize, 0);
}

/**
 * @tc.number: GetSysCompList_0100
 * @tc.name: test GetSysCompList
 * @tc.desc: 1.call GetSysCompList, if file exist and not empty, expect sysCompList not empty
 *           2.call GetSysCompList, if file not exist, expect sysCompList empty
 */
HWTEST_F(BmsAOTHandlerTest, GetSysCompList_0100, Function | SmallTest | Level1)
{
    std::string sysCompConfigPath = "/system/etc/ark/system_framework_aot_enable_list.conf";
    std::vector<std::string> sysCompList = AOTHandler::GetInstance().GetSysCompList();
    struct stat st;
    int32_t ret = stat(sysCompConfigPath.c_str(), &st);
    if (ret == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
        EXPECT_FALSE(sysCompList.empty());
    } else {
        EXPECT_TRUE(sysCompList.empty());
    }
}
} // OHOS