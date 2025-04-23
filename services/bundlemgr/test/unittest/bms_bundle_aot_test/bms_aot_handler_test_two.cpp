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

#include "aot_handler.h"
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

class BmsAOTHandlerTest2 : public testing::Test {
public:
    BmsAOTHandlerTest2();
    ~BmsAOTHandlerTest2();
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

std::shared_ptr<BundleMgrService> BmsAOTHandlerTest2::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsAOTHandlerTest2::installdService_ =
    std::make_shared<InstalldService>();

BmsAOTHandlerTest2::BmsAOTHandlerTest2()
{}

BmsAOTHandlerTest2::~BmsAOTHandlerTest2()
{}

void BmsAOTHandlerTest2::SetUpTestCase()
{
    bundleMgrService_->OnStart();
    bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME_SECONDS));
    installdService_->Start();
}

void BmsAOTHandlerTest2::TearDownTestCase()
{
    AOTHandler::GetInstance().serialQueue_ = nullptr;
    bundleMgrService_->OnStop();
}

void BmsAOTHandlerTest2::SetUp()
{
    InstallBundle(BUNDLE_PATH);
}

void BmsAOTHandlerTest2::TearDown()
{
    UninstallBundle(BUNDLE_NAME);
}

void BmsAOTHandlerTest2::InstallBundle(const std::string &bundlePath) const
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

void BmsAOTHandlerTest2::UninstallBundle(const std::string &bundleName) const
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
HWTEST_F(BmsAOTHandlerTest2, BuildArkProfilePath_0100, Function | SmallTest | Level1)
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
HWTEST_F(BmsAOTHandlerTest2, HandleArkPathsChange_0100, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().HandleArkPathsChange();
    bool isHandled = false;
    (void)BMSEventHandler::CheckOtaFlag(OTAFlag::DELETE_DEPRECATED_ARK_PATHS, isHandled);
    EXPECT_TRUE(isHandled);
}
} // OHOS
