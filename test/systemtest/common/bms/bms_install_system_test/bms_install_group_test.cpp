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

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <future>
#include <gtest/gtest.h>

#include "bundle_constants.h"
#include "bundle_installer_interface.h"
#include "bundle_mgr_interface.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_tool.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "status_receiver_host.h"

using namespace testing::ext;
using namespace std::chrono_literals;
namespace {
const std::string THIRD_BUNDLE_PATH = "/data/test/bms_bundle/";
const std::string THIRD_BASE_BUNDLE_NAME = "com.third.hiworld.example";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILURE = "Failure";
const std::string OPERATION_SUCCESS = "Success";
const std::string BUNDLE_EL1 = "el1";
const std::string BUNDLE_EL2 = "el2";
const std::string BUNDLE_EL3 = "el3";
const std::string BUNDLE_EL4 = "el4";
const std::string BUNDLE_EL5 = "el5";
constexpr const char* BUNDLE_APP_DATA_BASE_DIR = "/data/app/";
constexpr const char* PATH_SEPARATOR = "/";
const int TIMEOUT = 10;
const int32_t USERID = 100;
}  // namespace

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::EventFwk;
class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    ~StatusReceiverImpl() override;
    void OnStatusNotify(const int progress) override;
    void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    std::string GetResultMsg() const;

private:
    mutable std::promise<std::string> resultMsgSignal_;
    int iProgress_ = 0;

    DISALLOW_COPY_AND_MOVE(StatusReceiverImpl);
};

StatusReceiverImpl::StatusReceiverImpl()
{}

StatusReceiverImpl::~StatusReceiverImpl()
{}

void StatusReceiverImpl::OnStatusNotify(const int progress)
{
    EXPECT_GT(progress, iProgress_);
    iProgress_ = progress;
}

void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    resultMsgSignal_.set_value(resultMsg);
}

std::string StatusReceiverImpl::GetResultMsg() const
{
    auto future = resultMsgSignal_.get_future();
    std::chrono::seconds timeout(TIMEOUT);
    if (future.wait_for(timeout) == std::future_status::timeout) {
        return OPERATION_FAILURE + " timeout";
    }
    std::string resultMsg = future.get();
    if (resultMsg == MSG_SUCCESS) {
        return OPERATION_SUCCESS;
    }
    return OPERATION_FAILURE + resultMsg;
}

class BmsInstallGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static int32_t ExcuteMaintainCmd(const std::string &cmd, std::vector<std::string> &cmdRes);
    static void InstallBundle(
        const std::string &bundleFilePath, const InstallFlag installFlag, std::string &installMsg);
    static void UninstallBundle(const std::string &bundleName, std::string &uninstallMsg);
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
    static uint32_t GetDirectoryCount(const std::string& path);
    static uint32_t GetGroupDirsCount(const std::string &el, int32_t userId);
    static void UpdateDirsCount(int32_t userId);

    static uint32_t el2GroupDirsCount_;
    static uint32_t el3GroupDirsCount_;
    static uint32_t el4GroupDirsCount_ ;
    static uint32_t el5GroupDirsCount_;
};

uint32_t BmsInstallGroupTest::el2GroupDirsCount_;
uint32_t BmsInstallGroupTest::el3GroupDirsCount_;
uint32_t BmsInstallGroupTest::el4GroupDirsCount_;
uint32_t BmsInstallGroupTest::el5GroupDirsCount_;

sptr<IBundleMgr> BmsInstallGroupTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        return nullptr;
    }

    return iface_cast<IBundleMgr>(remoteObject);
}

sptr<IBundleInstaller> BmsInstallGroupTest::GetInstallerProxy()
{
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        return nullptr;
    }

    sptr<IBundleInstaller> installerProxy = bundleMgrProxy->GetBundleInstaller();
    if (!installerProxy) {
        return nullptr;
    }

    return installerProxy;
}

void BmsInstallGroupTest::InstallBundle(
    const std::string &bundleFilePath, const InstallFlag installFlag, std::string &installMsg)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        installMsg = "Failure";
        return;
    }

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = installFlag;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    bool installResult = installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    EXPECT_TRUE(installResult);
    installMsg = statusReceiver->GetResultMsg();
}

void BmsInstallGroupTest::UninstallBundle(
    const std::string &bundleName, std::string &uninstallMsg)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        uninstallMsg = "Failure";
        return;
    }

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;

    bool uninstallResult = installerProxy->Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    uninstallMsg = statusReceiver->GetResultMsg();
}

uint32_t BmsInstallGroupTest::GetDirectoryCount(const std::string& path)
{
    std::filesystem::path dirPath(path);
    uint32_t count = 0;
    if (std::filesystem::exists(dirPath) && std::filesystem::is_directory(dirPath)) {
        for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
            if (std::filesystem::is_directory(entry)) {
                count++;
            }
        }
    }
    return count;
}

uint32_t BmsInstallGroupTest::GetGroupDirsCount(const std::string &el, int32_t userId)
{
    std::string dir = BUNDLE_APP_DATA_BASE_DIR + el + PATH_SEPARATOR + std::to_string(userId);
    return GetDirectoryCount(dir);
}

void BmsInstallGroupTest::UpdateDirsCount(int32_t userId)
{
    el2GroupDirsCount_ = GetGroupDirsCount(BUNDLE_EL2, userId);
    el3GroupDirsCount_ = GetGroupDirsCount(BUNDLE_EL3, userId);
    el4GroupDirsCount_ = GetGroupDirsCount(BUNDLE_EL4, userId);
    el5GroupDirsCount_ = GetGroupDirsCount(BUNDLE_EL5, userId);
}

void BmsInstallGroupTest::SetUpTestCase()
{
    UpdateDirsCount(USERID);
}

void BmsInstallGroupTest::TearDownTestCase()
{}

void BmsInstallGroupTest::SetUp()
{}

void BmsInstallGroupTest::TearDown()
{}

/**
 * @tc.number: BMS_Install_0100
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.install the bundle
 *           2.no group id so no new group dir
 */
HWTEST_F(BmsInstallGroupTest, BMS_Install_0100, Function | MediumTest | Level1)
{
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "bmsThirdBundle1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::NORMAL, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;
    EXPECT_EQ(GetGroupDirsCount(BUNDLE_EL2, USERID), el2GroupDirsCount_);
    EXPECT_EQ(GetGroupDirsCount(BUNDLE_EL3, USERID), el3GroupDirsCount_);
    EXPECT_EQ(GetGroupDirsCount(BUNDLE_EL4, USERID), el4GroupDirsCount_);
    EXPECT_EQ(GetGroupDirsCount(BUNDLE_EL5, USERID), el5GroupDirsCount_);

    std::string bundleName = THIRD_BASE_BUNDLE_NAME + "1";
    std::string uninstallMsg;
    UninstallBundle(bundleName, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
    EXPECT_EQ(GetGroupDirsCount(BUNDLE_EL2, USERID), el2GroupDirsCount_);
    EXPECT_EQ(GetGroupDirsCount(BUNDLE_EL3, USERID), el3GroupDirsCount_);
    EXPECT_EQ(GetGroupDirsCount(BUNDLE_EL4, USERID), el4GroupDirsCount_);
    EXPECT_EQ(GetGroupDirsCount(BUNDLE_EL5, USERID), el5GroupDirsCount_);
}
}  // namespace AppExecFwk
}  // namespace OHOS