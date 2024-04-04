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
#define private public

#include <fstream>
#include <future>
#include <vector>

#include <gtest/gtest.h>

#include "ability_info.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_installer_interface.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_client_impl.h"
#include "bundle_user_mgr_proxy.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_tool.h"
#include "extension_ability_info.h"
#include "hap_module_info.h"
#include "iservice_registry.h"
#include "status_receiver_host.h"
#include "system_ability_definition.h"
#include "verify_manager_proxy.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string HAP_PATH =
    "/data/app/el1/bundle/public/com.example.ohosproject.hmservice/entry_phone.hap";
const std::string RESOURCE_PATH =
    "/data/app/el1/bundle/public/com.example.ohosproject.hmservice/entry_phone/resources.index";
const std::string RESOURCE_PATH_TEST =
    "/com.example.ohosproject.hmservice/entry_phone/resources.index";
const std::string THIRD_PATH = "/data/test/bms_bundle/";
const std::string BUNDLE_NAME = "com.example.ohosproject.hmservice";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILURE = "Failure";
const std::string OPERATION_SUCCESS = "Success";
const std::string EMPTY_STRING = "";
const int TIMEOUT = 10;
const int DEFAULT_USERID = 100;
} // namespace

class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    virtual ~StatusReceiverImpl() override;
    virtual void OnStatusNotify(const int progress) override;
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    std::string GetResultMsg() const;

private:
    mutable std::promise<std::string> resultMsgSignal_;
    int iProgress_ = 0;

    DISALLOW_COPY_AND_MOVE(StatusReceiverImpl);
};

StatusReceiverImpl::StatusReceiverImpl()
{
    APP_LOGI("create status receiver instance");
}

StatusReceiverImpl::~StatusReceiverImpl()
{
    APP_LOGI("destroy status receiver instance");
}

void StatusReceiverImpl::OnStatusNotify(const int progress)
{
    iProgress_ = progress;
    APP_LOGI("OnStatusNotify progress:%{public}d", progress);
}

void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    APP_LOGD("on finished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
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

class BundleMgrClientSystemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static void InstallBundle(
        const std::string &bundleFilePath, const InstallFlag installFlag, std::string &installMsg, const int userId);
    static void UninstallBundle(const std::string &bundleName, std::string &uninstallMsg, const int userId);
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
    bool GetProfileFromAbility(const AbilityInfo &info, const std::string &metadataName,
        std::vector<std::string> &profiles);
    bool GetProfileFromExtension(const ExtensionAbilityInfo &info, const std::string &metadataName,
        std::vector<std::string> &profiles);

    template<typename... Args>
    static bool GetResConfigFile(Args&&...args);
};

void BundleMgrClientSystemTest::SetUpTestCase()
{}

void BundleMgrClientSystemTest::TearDownTestCase()
{}

void BundleMgrClientSystemTest::SetUp()
{}

void BundleMgrClientSystemTest::TearDown()
{}

sptr<IBundleMgr> BundleMgrClientSystemTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        APP_LOGE("fail to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        APP_LOGE("fail to get bundle manager proxy.");
        return nullptr;
    }

    APP_LOGI("get bundle manager proxy success.");
    return iface_cast<IBundleMgr>(remoteObject);
}

sptr<IBundleInstaller> BundleMgrClientSystemTest::GetInstallerProxy()
{
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        return nullptr;
    }

    sptr<IBundleInstaller> installerProxy = bundleMgrProxy->GetBundleInstaller();
    if (!installerProxy) {
        APP_LOGE("fail to get bundle installer proxy");
        return nullptr;
    }

    APP_LOGI("get bundle installer proxy success.");
    return installerProxy;
}

void BundleMgrClientSystemTest::InstallBundle(
    const std::string &bundleFilePath, const InstallFlag installFlag, std::string &installMsg,
    const int userId = Constants::ALL_USERID)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        installMsg = "Failure";
        return;
    }

    InstallParam installParam;
    installParam.installFlag = installFlag;
    if (userId != 0) {
        installParam.userId = userId;
    }
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    bool installResult = installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    EXPECT_TRUE(installResult);
    installMsg = statusReceiver->GetResultMsg();
}

void BundleMgrClientSystemTest::UninstallBundle(
    const std::string &bundleName, std::string &uninstallMsg, const int userId = Constants::ALL_USERID)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        uninstallMsg = "Failure";
        return;
    }

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    if (userId != 0) {
        installParam.userId = userId;
    }
    bool uninstallResult = installerProxy->Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    uninstallMsg = statusReceiver->GetResultMsg();
}

template<typename... Args>
bool BundleMgrClientSystemTest::GetResConfigFile(Args&&...args)
{
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    BundleMgrClient bundleMgrClient;
    auto ret = bundleMgrClient.GetResConfigFile(std::forward<Args>(args)...);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
    return ret;
}

bool BundleMgrClientSystemTest::GetProfileFromAbility(const AbilityInfo &info,
    const std::string &metadataName, std::vector<std::string> &profiles)
{
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    BundleMgrClient bundleMgrClient;
    auto ret = bundleMgrClient.GetProfileFromAbility(info, metadataName, profiles);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
    return ret;
}

bool BundleMgrClientSystemTest::GetProfileFromExtension(const ExtensionAbilityInfo &info,
    const std::string &metadataName, std::vector<std::string> &profiles)
{
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    BundleMgrClient bundleMgrClient;
    auto ret = bundleMgrClient.GetProfileFromExtension(info, metadataName, profiles);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
    return ret;
}

/**
 * @tc.number: GetResourceConfigFile_001
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. extensionAbilityInfo is invalid, resourcePath is empty
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_001, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_001");
    GTEST_LOG_(INFO) << name << " start";
    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = "";
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_002
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. extensionAbilityInfo is invalid, resourcePath is not existed
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_002, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_002");
    GTEST_LOG_(INFO) << name << " start";
    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = "resourcePath";
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_003
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. extensionAbilityInfo is invalid, metadata is not existed
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_003, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_003");
    GTEST_LOG_(INFO) << name << " start";
    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "extensionName";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_004
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. extensionAbilityInfo is valid
 *           2. metadataName is not empty
 *           3. extensionAbilityInfo does not have metadata
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_004, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_004");
    GTEST_LOG_(INFO) << name << " start";
    ExtensionAbilityInfo info;
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_005
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. extensionAbilityInfo is valid
 *           2. metadataName is not empty
 *           3. metadataName cannot be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_005, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_005");
    GTEST_LOG_(INFO) << name << " start";
    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms1";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_006
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. extensionAbilityInfo is valid and has only one metadata
 *           2. metadataName is not empty
 *           3. metadataName can be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_006, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_006");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.hapPath = HAP_PATH;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;

    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    
    std::cout << "END GetResourceConfigFile_006" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_007
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. extensionAbilityInfo is valid and has multiple metadata
 *           2. metadataName is not empty
 *           3. metadataName can be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_007, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_007");
    GTEST_LOG_(INFO) << name << " start";
    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    Metadata data1;
    data1.name = "ohos.extension.forms1";
    data1.resource = "$profile:shortcuts_config";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    std::cout << "END GetResourceConfigFile_007" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_008
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. extensionAbilityInfo is valid and has multiple metadata
 *           2. metadataName is not empty
 *           3. metadataName can be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_008, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_008");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    Metadata data1;
    data1.name = "ohos.extension.forms";
    data1.resource = "$profile:shortcuts_config";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(profileInfo.size(), 2);

    std::cout << "END GetResourceConfigFile_008" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_009
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadataName is empty
 *           2. extensionAbilityInfo has only one metadata
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_009, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_009");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.hapPath = HAP_PATH;

    std::string metadataName;
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    
    std::cout << "END GetResourceConfigFile_009" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_010
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadataName is empty
 *           2. extensionAbilityInfo has only multiple metadata
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_010, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_010");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    Metadata data1;
    data1.name = "ohos.extension.forms1";
    data1.resource = "$profile:shortcuts_config";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;

    std::string metadataName;
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(profileInfo.size(), 2);

    std::cout << "END GetResourceConfigFile_010" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_011
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profile's suffix is not .json
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_011, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_011");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config1";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_011" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_012
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profile is empty file
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_012, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_012");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config2";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_013
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profile is not json-format
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_013, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_013");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config3";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_013" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_014
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profiles both have json-format file and non-json-format file
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_014, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_014");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    Metadata data1;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config1";

    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_014" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_015
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. AbilityInfo is invalid, resourcePath is empty
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_015, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_015");
    GTEST_LOG_(INFO) << name << " start";
    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = "";
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_016
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. AbilityInfo is invalid, resourcePath is not existed
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_016, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_016");
    GTEST_LOG_(INFO) << name << " start";
    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = "resourcePath";
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_017
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. AbilityInfo is invalid, metadata is not existed
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_017, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_017");
    GTEST_LOG_(INFO) << name << " start";
    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "extensionName";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_018
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. AbilityInfo is valid
 *           2. metadataName is not empty
 *           3. AbilityInfo does not have metadata
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_018, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_018");
    GTEST_LOG_(INFO) << name << " start";
    AbilityInfo info;
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_019
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. AbilityInfo is valid
 *           2. metadataName is not empty
 *           3. metadataName cannot be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_019, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_019");
    GTEST_LOG_(INFO) << name << " start";
    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms1";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_020
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. AbilityInfo is valid and has only one metadata
 *           2. metadataName is not empty
 *           3. metadataName can be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_020, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_020");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.hapPath = HAP_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    
    std::cout << "END GetResourceConfigFile_020" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_021
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. AbilityInfo is valid and has multiple metadata
 *           2. metadataName is not empty
 *           3. metadataName can be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_021, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_021");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    Metadata data1;
    data1.name = "ohos.extension.forms1";
    data1.resource = "$profile:shortcuts_config";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    
    std::cout << "END GetResourceConfigFile_021" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_022
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. AbilityInfo is valid and has multiple metadata
 *           2. metadataName is not empty
 *           3. metadataName can be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_022, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_022");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    Metadata data1;
    data1.name = "ohos.extension.forms";
    data1.resource = "$profile:shortcuts_config";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(profileInfo.size(), 2);

    std::cout << "END GetResourceConfigFile_022" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_023
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadataName is empty
 *           2. AbilityInfo has only one metadata
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_023, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_023");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.hapPath = HAP_PATH;

    std::string metadataName;
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    
    std::cout << "END GetResourceConfigFile_023" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_024
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadataName is empty
 *           2. AbilityInfo has only multiple metadata
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_024, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_024");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    Metadata data1;
    data1.name = "ohos.extension.forms1";
    data1.resource = "$profile:shortcuts_config";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;

    std::string metadataName;
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(profileInfo.size(), 2);

    std::cout << "END GetResourceConfigFile_024" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_025
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profile's suffix is not .json
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_025, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_025");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config1";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_025" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_026
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profile is empty file
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_026, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_026");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config2";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_026" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_027
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profile is not json-format
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_027, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_027");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config3";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_027" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_028
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profiles both have json-format file and non-json-format file
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_028, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_028");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    Metadata data1;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config1";

    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_028" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_029
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. HapModuleInfo is invalid, resourcePath is empty
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_029, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_029");
    GTEST_LOG_(INFO) << name << " start";
    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = "";
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_030
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. HapModuleInfo is invalid, resourcePath is not existed
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_030, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_030");
    GTEST_LOG_(INFO) << name << " start";
    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = "resourcePath";
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_031
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. HapModuleInfo is invalid, metadata is not existed
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_031, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_031");
    GTEST_LOG_(INFO) << name << " start";
    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "extensionName";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_032
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. HapModuleInfo is valid
 *           2. metadataName is not empty
 *           3. HapModuleInfo does not have metadata
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_032, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_032");
    GTEST_LOG_(INFO) << name << " start";
    HapModuleInfo info;
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_033
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. HapModuleInfo is valid
 *           2. metadataName is not empty
 *           3. metadataName cannot be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_033, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_033");
    GTEST_LOG_(INFO) << name << " start";
    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms1";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_034
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. HapModuleInfo is valid and has only one metadata
 *           2. metadataName is not empty
 *           3. metadataName can be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_034, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_034");
    GTEST_LOG_(INFO) << name << " start";

    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.hapPath = HAP_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    
    std::cout << "END GetResourceConfigFile_034" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_035
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. HapModuleInfo is valid and has multiple metadata
 *           2. metadataName is not empty
 *           3. metadataName can be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_035, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_035");
    GTEST_LOG_(INFO) << name << " start";

    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    Metadata data1;
    data1.name = "ohos.extension.forms1";
    data1.resource = "$profile:shortcuts_config";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    
    std::cout << "END GetResourceConfigFile_035" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_036
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. HapModuleInfo is valid and has multiple metadata
 *           2. metadataName is not empty
 *           3. metadataName can be found
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_036, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_036");
    GTEST_LOG_(INFO) << name << " start";

    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    Metadata data1;
    data1.name = "ohos.extension.forms";
    data1.resource = "$profile:shortcuts_config";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(profileInfo.size(), 2);

    std::cout << "END GetResourceConfigFile_036" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_037
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadataName is empty
 *           2. HapModuleInfo has only one metadata
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_037, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_037");
    GTEST_LOG_(INFO) << name << " start";

    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    metadata.emplace_back(data);
    info.hapPath = HAP_PATH;
    std::string metadataName;
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    
    std::cout << "END GetResourceConfigFile_037" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_038
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadataName is empty
 *           2. HapModuleInfo has only multiple metadata
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_038, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_038");
    GTEST_LOG_(INFO) << name << " start";

    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    Metadata data1;
    data1.name = "ohos.extension.forms1";
    data1.resource = "$profile:shortcuts_config";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;

    std::string metadataName;
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(profileInfo.size(), 2);

    std::cout << "END GetResourceConfigFile_038" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_039
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profile's suffix is not .json
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_039, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_039");
    GTEST_LOG_(INFO) << name << " start";

    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config1";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_039" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_040
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profile is empty file
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_040, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_040");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";

    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config2";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_040" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_041
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profile is not json-format
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_041, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_041");
    GTEST_LOG_(INFO) << name << " start";

    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config3";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::cout << "END GetResourceConfigFile_041" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_042
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. profiles both have json-format file and non-json-format file
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_042, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_042");
    GTEST_LOG_(INFO) << name << " start";

    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";
    Metadata data1;
    data1.name = "ohos.extension.forms";
    data1.resource = "$profile:form_config1";

    metadata.emplace_back(data);
    metadata.emplace_back(data1);
    info.hapPath = HAP_PATH;

    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_TRUE(ret);

    std::cout << "END GetResourceConfigFile_042" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_043
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadata has incorrect resource without '$profile'
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_043, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_043");
    GTEST_LOG_(INFO) << name << " start";
    HapModuleInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "@profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    std::vector<std::string> profileInfo;
    std::string metadataName = "ohos.extension.forms";
    bool ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_044
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadata has incorrect resource without '$profile'
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_044, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_044");
    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "@profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_045
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadata has incorrect resource without '$profile'
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_045, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_045");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "@profile:form_config";
    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetResourceConfigFile_046
 * @tc.name: GetResConfigFile
 * @tc.desc: Test the interface of GetResConfigFile
 *           1. metadataName is not empty
 */
HWTEST_F(BundleMgrClientSystemTest, GetResourceConfigFile_046, TestSize.Level1)
{
    auto name = std::string("GetResourceConfigFile_046");
    GTEST_LOG_(INFO) << name << " start";
    AbilityInfo info;
    info.resourcePath = RESOURCE_PATH;
    std::string metadataName = "";
    std::vector<std::string> profileInfo;
    auto ret = GetResConfigFile(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    std::cout << "END GetResourceConfigFile_046" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetProfileFromAbility_001
 * @tc.name: GetProfileFromAbility
 * @tc.desc: Test the interface of GetProfileFromAbility
 *           1. AbilityInfo without resource path
 */
HWTEST_F(BundleMgrClientSystemTest, GetProfileFromAbility_001, TestSize.Level1)
{
    auto name = std::string("GetProfileFromAbility_001");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    metadata.emplace_back(data);
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetProfileFromAbility(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetProfileFromAbility_002
 * @tc.name: GetProfileFromAbility
 * @tc.desc: Test the interface of GetProfileFromAbility
 *           1. AbilityInfo has incorrect resource path
 */
HWTEST_F(BundleMgrClientSystemTest, GetProfileFromAbility_002, TestSize.Level1)
{
    auto name = std::string("GetProfileFromAbility_002");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH_TEST;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetProfileFromAbility(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetProfileFromAbility_003
 * @tc.name: GetProfileFromAbility
 * @tc.desc: Test the interface of GetProfileFromAbility
 *           1. AbilityInfo has incorrect resource path
 */
HWTEST_F(BundleMgrClientSystemTest, GetProfileFromAbility_003, TestSize.Level1)
{
    auto name = std::string("GetProfileFromAbility_003");
    GTEST_LOG_(INFO) << name << " start";

    AbilityInfo info;
    info.hapPath = "/data/app";
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetProfileFromAbility(info, metadataName, profileInfo);
    EXPECT_EQ(ret, false);
    info.hapPath = "";
    info.resourcePath = RESOURCE_PATH;
    ret = GetProfileFromAbility(info, metadataName, profileInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetProfileFromExtension_003
 * @tc.name: GetProfileFromExtension
 * @tc.desc: Test the interface of GetProfileFromExtension
 *           1. ExtensionAbilityInfo without resource path
 */
HWTEST_F(BundleMgrClientSystemTest, GetProfileFromExtension_003, TestSize.Level1)
{
    auto name = std::string("GetProfileFromExtension_003");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    metadata.emplace_back(data);
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetProfileFromExtension(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetProfileFromExtension_004
 * @tc.name: GetProfileFromExtension
 * @tc.desc: Test the interface of GetProfileFromExtension
 *           1. ExtensionAbilityInfo has incorrect resource path
 */
HWTEST_F(BundleMgrClientSystemTest, GetProfileFromExtension_004, TestSize.Level1)
{
    auto name = std::string("GetProfileFromExtensionr_004");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    std::vector<Metadata> &metadata = info.metadata;
    Metadata data;
    data.name = "ohos.extension.forms";
    data.resource = "$profile:form_config";

    metadata.emplace_back(data);
    info.resourcePath = RESOURCE_PATH_TEST;
    BundleMgrClient bundleMgrClient;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetProfileFromExtension(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetProfileFromExtension_005
 * @tc.name: GetProfileFromExtension
 * @tc.desc: Test the interface of GetProfileFromExtension
 *           1. ExtensionAbilityInfo has incorrect resource path
 */
HWTEST_F(BundleMgrClientSystemTest, GetProfileFromExtension_005, TestSize.Level1)
{
    auto name = std::string("GetProfileFromExtensionr_005");
    GTEST_LOG_(INFO) << name << " start";

    ExtensionAbilityInfo info;
    info.hapPath = "/data/app";
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = GetProfileFromExtension(info, metadataName, profileInfo);
    EXPECT_EQ(ret, false);
    info.hapPath = "";
    info.resourcePath = RESOURCE_PATH;
    ret = GetProfileFromExtension(info, metadataName, profileInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0001
 * @tc.name: QueryExtensionAbilityInfos
 * @tc.desc: Test the interface of QueryExtensionAbilityInfos
 */
HWTEST_F(BundleMgrClientSystemTest, QueryExtensionAbilityInfos_0001, TestSize.Level1)
{
    auto name = std::string("QueryExtensionAbilityInfos_0001");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    std::vector<ExtensionAbilityInfo> infos;
    OHOS::AAFwk::Want want;
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    element.SetModuleName("entry_phone");
    element.SetAbilityName("Form");
    want.SetElement(element);
    bool ret = GetBundleMgrProxy()->QueryExtensionAbilityInfos(want, ExtensionAbilityType::FORM,
        ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_DEFAULT, DEFAULT_USERID, infos);
    EXPECT_TRUE(ret);
    EXPECT_EQ(1, infos.size());

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
    std::cout << "END QueryExtensionAbilityInfos_0001" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_000
 * @tc.name: QueryExtensionAbilityInfosV9
 * @tc.desc: Test the interface of QueryExtensionAbilityInfosV9
 */
HWTEST_F(BundleMgrClientSystemTest, QueryExtensionAbilityInfosV9_0001, TestSize.Level1)
{
    auto name = std::string("QueryExtensionAbilityInfos_0001");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    std::vector<ExtensionAbilityInfo> infos;
    OHOS::AAFwk::Want want;
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    element.SetModuleName("entry_phone");
    element.SetAbilityName("Form");
    want.SetElement(element);
    ErrCode ret = GetBundleMgrProxy()->QueryExtensionAbilityInfosV9(want, ExtensionAbilityType::FORM,
        ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_DEFAULT, DEFAULT_USERID, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(1, infos.size());

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
    std::cout << "END QueryExtensionAbilityInfos_0001" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0002
 * @tc.name: QueryExtensionAbilityInfosV9
 * @tc.desc: Test the interface of QueryExtensionAbilityInfosV9
 */
HWTEST_F(BundleMgrClientSystemTest, QueryExtensionAbilityInfosV9_0002, TestSize.Level1)
{
    std::vector<ExtensionAbilityInfo> infos;
    OHOS::AAFwk::Want want;
    ErrCode ret = GetBundleMgrProxy()->QueryExtensionAbilityInfosV9(want, ExtensionAbilityType::FORM,
        ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_DEFAULT, DEFAULT_USERID, infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0003
 * @tc.name: QueryExtensionAbilityInfosV9
 * @tc.desc: Test the interface of QueryExtensionAbilityInfosV9
 */
HWTEST_F(BundleMgrClientSystemTest, QueryExtensionAbilityInfosV9_0003, TestSize.Level1)
{
    auto name = std::string("QueryExtensionAbilityInfos_0001");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    std::vector<ExtensionAbilityInfo> infos;
    OHOS::AAFwk::Want want;
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    element.SetModuleName("entry_phone");
    element.SetAbilityName("Form");
    want.SetElement(element);

    ErrCode ret = GetBundleMgrProxy()->QueryExtensionAbilityInfosV9(want, ExtensionAbilityType::FORM,
        ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_DEFAULT, -1, infos);
    EXPECT_NE(ret, ERR_OK);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
    std::cout << "END QueryExtensionAbilityInfos_0001" << std::endl;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetProfileFromHap001
 * @tc.name: GetProfileFromHap
 * @tc.desc: 1.Test the interface of GetSandboxAbilityInfo
 *           2.Install application
 */
HWTEST_F(BundleMgrClientSystemTest, GetProfileFromHap001, TestSize.Level1)
{
    auto name = std::string("GetProfileFromHap001");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    BundleMgrClient bundleMgrClient;
    HapModuleInfo info;
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetProfileFromHap(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetProfileFromHap002
 * @tc.name: GetProfileFromHap
 * @tc.desc: 1.Test the interface of GetProfileFromHap
 *           2.Install application
 */
HWTEST_F(BundleMgrClientSystemTest, GetProfileFromHap002, TestSize.Level1)
{
    auto name = std::string("GetProfileFromHap002");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    BundleMgrClient bundleMgrClient;
    HapModuleInfo info;
    info.hapPath = "/data/app";
    std::string metadataName = "ohos.extension.forms";
    std::vector<std::string> profileInfo;
    auto ret = bundleMgrClient.GetProfileFromHap(info, metadataName, profileInfo);
    EXPECT_FALSE(ret);
    info.hapPath = "";
    info.resourcePath = RESOURCE_PATH;
    ret = bundleMgrClient.GetProfileFromHap(info, metadataName, profileInfo);
    EXPECT_EQ(ret, false);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetHapModuleInfo001
 * @tc.name: GetHapModuleInfo
 * @tc.desc: 1.Test the interface of GetSandboxAbilityInfo
 *           2.Install application
 */
HWTEST_F(BundleMgrClientSystemTest, GetHapModuleInfo001, TestSize.Level1)
{
    auto name = std::string("GetHapModuleInfo001");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    BundleMgrClient bundleMgrClient;
    AbilityInfo abilityInfo;
    HapModuleInfo info;
    std::string hapName = "sandboxTest";
    auto ret = bundleMgrClient.GetHapModuleInfo(BUNDLE_NAME, hapName, info);
    EXPECT_FALSE(ret);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: GetBundlePackInfo001
 * @tc.name: GetBundlePackInfo
 * @tc.desc: 1.Test the interface of GetSandboxAbilityInfo
 *           2.Install application
 */
HWTEST_F(BundleMgrClientSystemTest, GetBundlePackInfo001, TestSize.Level1)
{
    auto name = std::string("GetBundlePackInfo001");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    BundleMgrClient bundleMgrClient;
    AbilityInfo abilityInfo;
    BundlePackInfo info;
    std::string hapName = "sandboxTest";
    auto ret = bundleMgrClient.GetBundlePackInfo(BUNDLE_NAME, BundlePackFlag::GET_PACK_INFO_ALL, info, DEFAULT_USERID);
    EXPECT_TRUE(ret == ERR_OK);

    ret = bundleMgrClient.GetBundlePackInfo("", BundlePackFlag::GET_PACK_INFO_ALL, info, DEFAULT_USERID);
    EXPECT_FALSE(ret == ERR_OK);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;

    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: client GetNameForUid test
 * @tc.name: client GetNameForUid test
 * @tc.desc: 1.install
 *           2.get uid by bundleName, then get bundleName by uid
 */
HWTEST_F(BundleMgrClientSystemTest, GetNameForUid001, TestSize.Level1)
{
    auto name = std::string("GetNameForUid001");
    GTEST_LOG_(INFO) << name << " start";
    std::string bundleFilePath = THIRD_PATH + "bundleClient1.hap";
    std::string installMsg;
    InstallBundle(bundleFilePath, InstallFlag::REPLACE_EXISTING, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << bundleFilePath;

    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    int uid = bundleMgrProxy->GetUidByBundleName(BUNDLE_NAME, DEFAULT_USERID);

    std::string bundleName;
    BundleMgrClient bundleMgrClient;
    auto ret = bundleMgrClient.GetNameForUid(uid, bundleName);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(bundleName, BUNDLE_NAME);

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success") << "uninstall fail!" << bundleFilePath;
    GTEST_LOG_(INFO) << name << " end";
}

/**
 * @tc.number: CreateNewUser_001
 * @tc.name: CreateNewUser
 * @tc.desc: 1.Test CreateNewUser and then remove it
 */
HWTEST_F(BundleMgrClientSystemTest, CreateNewUser_001, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    APP_LOGI("get bundle usermgr proxy success.");
    int userId = 10001;
    auto bundleUserMgrProxy = iface_cast<BundleUserMgrProxy>(remoteObject);
    ApplicationInfo appInfo;
    bundleUserMgrProxy->CreateNewUser(userId);
    bool ret = GetBundleMgrProxy()->GetApplicationInfo(BUNDLE_NAME,
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo);
    EXPECT_FALSE(ret);
    bundleUserMgrProxy->RemoveUser(userId);
    ret = GetBundleMgrProxy()->GetApplicationInfo(BUNDLE_NAME,
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CreateNewUser_002
 * @tc.name: CreateNewUser
 * @tc.desc: 1.Test CreateNewUser and then remove it
 */
HWTEST_F(BundleMgrClientSystemTest, CreateNewUser_002, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    APP_LOGI("get bundle usermgr proxy success.");
    constexpr int userId = 10001;
    const std::vector<std::string> &disallowList = {"com.example.actsregisterjserrorrely"};
    auto bundleUserMgrProxy = iface_cast<BundleUserMgrProxy>(remoteObject);
    ApplicationInfo appInfo;
    bundleUserMgrProxy->CreateNewUser(userId, disallowList);
    bool ret = GetBundleMgrProxy()->GetApplicationInfo(BUNDLE_NAME,
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo);
    EXPECT_FALSE(ret);
    bundleUserMgrProxy->RemoveUser(userId);
    ret = GetBundleMgrProxy()->GetApplicationInfo(BUNDLE_NAME,
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleMgrClientImpl_001
 * @tc.name: TransformFileToJsonString
 * @tc.desc: 1.Test the interface of GetSandboxAbilityInfo
 *           2.Install application
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_001, TestSize.Level1)
{
    BundleMgrClientImpl bundleMgrClientImpl;
    std::string profile = "[]";
    bool res = bundleMgrClientImpl.TransformFileToJsonString("notExisted", profile);
    EXPECT_EQ(res, false);
    res = bundleMgrClientImpl.TransformFileToJsonString("data/test", profile);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BundleMgrClientImpl_002
 * @tc.name: IsFileExisted
 * @tc.desc: 1.Test the interface of GetSandboxAbilityInfo
 *           2.Install application
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_002, TestSize.Level1)
{
    BundleMgrClientImpl bundleMgrClientImpl;
    bool res = bundleMgrClientImpl.IsFileExisted("");
    bundleMgrClientImpl.OnDeath();
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BundleMgrClientImpl_003
 * @tc.name: ConvertResourcePath
 * @tc.desc: 1.Test the interface of ConvertResourcePath
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_003, TestSize.Level1)
{
    BundleMgrClientImpl impl;
    bool isCompressed = true;
    std::string resPath = "/data/test";
    bool res = impl.ConvertResourcePath(BUNDLE_NAME, resPath, isCompressed);
    EXPECT_EQ(res, true);
    isCompressed = false;
    resPath = RESOURCE_PATH;
    res = impl.ConvertResourcePath(BUNDLE_NAME, resPath, isCompressed);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BundleMgrClientImpl_004
 * @tc.name: GetResFromResMgr
 * @tc.desc: 1.Test the interface of GetResFromResMgr
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_004, TestSize.Level1)
{
    BundleMgrClientImpl impl;
    std::string resName = "";
    std::shared_ptr<Global::Resource::ResourceManager> resMgr
        = impl.InitResMgr(RESOURCE_PATH);
    bool isCompressed = true;
    std::vector<std::string> profileInfos;
    bool res = impl.GetResFromResMgr(resName, resMgr, isCompressed, profileInfos);
    EXPECT_EQ(res, false);

    resName = "$profile:file1";
    res = impl.GetResFromResMgr(BUNDLE_NAME, resMgr, isCompressed, profileInfos);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BundleMgrClientImpl_005
 * @tc.name: IsFileExisted
 * @tc.desc: 1.Test the interface of IsFileExisted
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_005, TestSize.Level1)
{
    BundleMgrClientImpl impl;
    std::string filePath = "/error/path";
    bool res = impl.IsFileExisted(filePath);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BundleMgrClientImpl_006
 * @tc.name: UninstallSandboxApp
 * @tc.desc: 1.Test the interface of UninstallSandboxApp
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_006, TestSize.Level1)
{
    BundleMgrClientImpl impl;
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    impl.bundleMgr_ = proxy;
    impl.Connect();
    EXPECT_NE(impl.bundleInstaller_, nullptr);
    std::string bundleName = "";
    int32_t dlpType = 0;
    int32_t userId = 0;
    int32_t appIndex = 0;
    ErrCode ret = impl.InstallSandboxApp(
        bundleName, dlpType, userId, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    bundleName = BUNDLE_NAME;
    appIndex = Constants::INITIAL_APP_INDEX - 1;
    ret = impl.UninstallSandboxApp(bundleName, appIndex, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    appIndex = Constants::MAX_APP_INDEX;
    ret = impl.UninstallSandboxApp(bundleName, appIndex, userId);
    EXPECT_NE(ret, ERR_OK);
    impl.OnDeath();
}

/**
 * @tc.number: BundleMgrClientImpl_007
 * @tc.name: GetSandboxAbilityInfo
 * @tc.desc: 1.Test the interface of GetSandboxAbilityInfo
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_007, TestSize.Level1)
{
    BundleMgrClientImpl impl;
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    impl.bundleMgr_ = proxy;
    impl.Connect();
    OHOS::AAFwk::Want want;
    AbilityInfo abilityInfo;
    int32_t flags = 0;
    int32_t appIndex = Constants::INITIAL_APP_INDEX - 1;
    ErrCode ret = impl.GetSandboxAbilityInfo(
        want, appIndex, flags, DEFAULT_USERID, abilityInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    appIndex = Constants::MAX_APP_INDEX + 1;
    ret = impl.GetSandboxAbilityInfo(
        want, appIndex, flags, DEFAULT_USERID, abilityInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    appIndex = Constants::MAX_APP_INDEX;
    ret = impl.GetSandboxAbilityInfo(
        want, appIndex, flags, DEFAULT_USERID, abilityInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);
    impl.OnDeath();
}

/**
 * @tc.number: BundleMgrClientImpl_008
 * @tc.name: GetSandboxExtAbilityInfos
 * @tc.desc: 1.Test the interface of GetSandboxExtAbilityInfos
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_008, TestSize.Level1)
{
    BundleMgrClientImpl impl;
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    impl.bundleMgr_ = proxy;
    impl.Connect();
    OHOS::AAFwk::Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t flags = 0;
    int32_t appIndex = Constants::INITIAL_APP_INDEX - 1;
    ErrCode ret = impl.GetSandboxExtAbilityInfos(
        want, appIndex, flags, DEFAULT_USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    appIndex = Constants::MAX_APP_INDEX + 1;
    ret = impl.GetSandboxExtAbilityInfos(
        want, appIndex, flags, DEFAULT_USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    appIndex = Constants::MAX_APP_INDEX;
    ret = impl.GetSandboxExtAbilityInfos(
        want, appIndex, flags, DEFAULT_USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);
    impl.OnDeath();
}

/**
 * @tc.number: BundleMgrClientImpl_009
 * @tc.name: GetSandboxHapModuleInfo
 * @tc.desc: 1.Test the interface of GetSandboxHapModuleInfo
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_009, TestSize.Level1)
{
    BundleMgrClientImpl impl;
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    impl.bundleMgr_ = proxy;
    impl.Connect();
    AbilityInfo abilityInfo;
    HapModuleInfo hapModuleInfo;
    int32_t appIndex = Constants::INITIAL_APP_INDEX - 1;
    ErrCode ret = impl.GetSandboxHapModuleInfo(
        abilityInfo, appIndex, DEFAULT_USERID, hapModuleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    appIndex = Constants::MAX_APP_INDEX + 1;
    ret = impl.GetSandboxHapModuleInfo(
        abilityInfo, appIndex, DEFAULT_USERID, hapModuleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    appIndex = Constants::MAX_APP_INDEX;
    ret = impl.GetSandboxHapModuleInfo(
        abilityInfo, appIndex, DEFAULT_USERID, hapModuleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_NO_SANDBOX_APP);
    impl.OnDeath();
}


/**
 * @tc.number: BundleMgrClientImpl_0011
 * @tc.name: GetResFromResMgr
 * @tc.desc: 1.Test the interface of GetResFromResMgr
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImpl_0011, TestSize.Level1)
{
    BundleMgrClientImpl impl;
    std::shared_ptr<Global::Resource::ResourceManager> resMgr
        = impl.InitResMgr("");
    EXPECT_EQ(resMgr, nullptr);
}

/**
 * @tc.number: BundleMgrClientImplIsNull_0400
 * @tc.name: 1.test BundleMgrClient with impl_ is nullptr
 * @tc.desc: 1. test is failed
 */
HWTEST_F(BundleMgrClientSystemTest, BundleMgrClientImplIsNull_0400, Function | MediumTest | Level1)
{
    std::cout << "begin to test bundle_installer_0700" << std::endl;
    BundleMgrClient client;
    client.impl_ = nullptr;
    std::string bundleName = "";

    auto ret = client.GetNameForUid(DEFAULT_USERID, bundleName);
    EXPECT_NE(ret, ERR_OK);

    BundleInfo bundleInfo;
    auto res = client.GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, DEFAULT_USERID);
    EXPECT_FALSE(res);

    BundlePackInfo bundlePackInfo;
    auto res1 = client.GetBundlePackInfo(
        BUNDLE_NAME, BundlePackFlag::GET_PACK_INFO_ALL, bundlePackInfo, DEFAULT_USERID);
    EXPECT_NE(res1, ERR_OK);

    HapModuleInfo hapModuleInfo;
    res = client.GetHapModuleInfo(BUNDLE_NAME, "", hapModuleInfo);
    EXPECT_FALSE(res);

    std::string metadataName = BUNDLE_NAME;
    std::vector<std::string> profileInfos;
    res = client.GetResConfigFile(hapModuleInfo, metadataName, profileInfos);
    EXPECT_FALSE(res);

    ExtensionAbilityInfo extensionInfo;
    res = client.GetResConfigFile(extensionInfo, metadataName, profileInfos);
    EXPECT_FALSE(res);

    AbilityInfo abilityInfo;
    res = client.GetResConfigFile(abilityInfo, metadataName, profileInfos);
    EXPECT_FALSE(res);

    res = client.GetProfileFromExtension(extensionInfo, metadataName, profileInfos);
    EXPECT_FALSE(res);

    res = client.GetProfileFromAbility(abilityInfo, metadataName, profileInfos);
    EXPECT_FALSE(res);

    res = client.GetResConfigFile(hapModuleInfo, metadataName, profileInfos);
    EXPECT_FALSE(res);

    int32_t dlpType = 0;
    int32_t appIndex = 0;
    res1 = client.InstallSandboxApp(BUNDLE_NAME, dlpType, DEFAULT_USERID, appIndex);
    EXPECT_NE(res1, ERR_OK);

    res1 = client.UninstallSandboxApp(BUNDLE_NAME, appIndex, DEFAULT_USERID);
    EXPECT_NE(res1, ERR_OK);

    res1 = client.GetSandboxBundleInfo(BUNDLE_NAME, appIndex, DEFAULT_USERID, bundleInfo);
    EXPECT_NE(res1, ERR_OK);

    int32_t flags = 0;
    OHOS::AAFwk::Want want;
    res1 = client.GetSandboxAbilityInfo(want, appIndex, flags, DEFAULT_USERID, abilityInfo);
    EXPECT_NE(res1, ERR_OK);

    std::vector<ExtensionAbilityInfo> extensionInfos;
    res1 = client.GetSandboxExtAbilityInfos(want, appIndex, flags, DEFAULT_USERID, extensionInfos);
    EXPECT_NE(res1, ERR_OK);

    res1 = client.GetSandboxHapModuleInfo(abilityInfo, appIndex, DEFAULT_USERID, hapModuleInfo);
    EXPECT_NE(res1, ERR_OK);
    std::cout << "test bundle_installer_0700 done" << std::endl;
}

/**
 * @tc.number: VerifyManagerProxy_0100
 * @tc.name: Verify
 * @tc.desc: 1.Test the interface of Verify
 */
HWTEST_F(BundleMgrClientSystemTest, VerifyManagerProxy_0100, TestSize.Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_NE(systemAbilityManager, nullptr);

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    VerifyManagerProxy verifyManagerProxy(remoteObject);
    std::vector<std::string> abcPaths;
    ErrCode ret = verifyManagerProxy.Verify(abcPaths);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);
    abcPaths.push_back(HAP_PATH);
    ret = verifyManagerProxy.Verify(abcPaths);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_VERIFY_SEND_REQUEST_FAILED);
}

/**
 * @tc.number: VerifyManagerProxy_0200
 * @tc.name: RemoveFiles
 * @tc.desc: 1.Test the interface of RemoveFiles
 */
HWTEST_F(BundleMgrClientSystemTest, VerifyManagerProxy_0200, TestSize.Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_NE(systemAbilityManager, nullptr);

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    VerifyManagerProxy verifyManagerProxy(remoteObject);
    std::vector<std::string> abcPaths;
    std::string abcPath = HAP_PATH;
    abcPaths.push_back(abcPath);
    ErrCode ret = verifyManagerProxy.RemoveFiles(abcPaths);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);
}

/**
 * @tc.number: VerifyManagerProxy_0300
 * @tc.name: CopyFiles
 * @tc.desc: 1.Test the interface of CopyFiles
 */
HWTEST_F(BundleMgrClientSystemTest, VerifyManagerProxy_0300, TestSize.Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_NE(systemAbilityManager, nullptr);

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    VerifyManagerProxy verifyManagerProxy(remoteObject);

    ErrCode ret = verifyManagerProxy.DeleteAbc(EMPTY_STRING);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR);

    ret = verifyManagerProxy.DeleteAbc(HAP_PATH);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DELETE_ABC_SEND_REQUEST_FAILED);
}

/**
 * @tc.number: CreateBundleDataDir_0100
 * @tc.name: CreateBundleDataDir
 * @tc.desc: Test whether CreateBundleDataDir is called normally.
 */
HWTEST_F(BundleMgrClientSystemTest, CreateBundleDataDir_0100, TestSize.Level1)
{
    BundleMgrClient bundleMgrClient;
    int32_t userId = -100;
    auto result = bundleMgrClient.CreateBundleDataDir(userId);
    EXPECT_EQ(result, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}
}  // namespace AppExecFwk
}  // namespace OHOS