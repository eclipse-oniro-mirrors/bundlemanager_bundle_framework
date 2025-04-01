/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "app_log_wrapper.h"
#include "bundle_installer_proxy.h"
#include "bundle_mgr_proxy.h"
#include "common_tool.h"
#include "extend_resource_manager_proxy.h"
#include "iservice_registry.h"
#include "nativetoken_kit.h"
#include "permission_define.h"
#include "status_receiver_host.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace {
const std::string BUNDLE_NAME = "ExtendResourceManagerProxyTest";
const std::string EMPTY_STRING = "";
const std::string MODULE_NAME = "entry";
const int32_t FD = 0;
const std::string FILE_PATH = "data/test";
const int32_t PERMS_INDEX_ZERO = 0;
const int32_t PERMS_INDEX_ONE = 1;
const int32_t PERMS_INDEX_TWO = 2;
const int32_t PERMS_INDEX_THREE = 3;
const std::string BUNDLE_PATH_1 = "/data/test/resource/bms/resource_manager/hapNotIncludeso5.hap";
const std::string BUNDLE_PATH_2 = "/data/test/resource/bms/resource_manager/hapNotIncludesoFeature1Hsp.hsp";
const std::string BUNDLE_NAME_DEMO = "com.example.hapNotIncludeso5";
const std::string DYNAMIC_NAME = "feature1";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILED = "Failure";
const std::string OPERATION_SUCCESS = "Success";
const int32_t USERID = 100;
}

namespace OHOS {
namespace AppExecFwk {
class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    virtual ~StatusReceiverImpl();
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

void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    APP_LOGD("OnFinished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
    resultMsgSignal_.set_value(resultMsg);
}

void StatusReceiverImpl::OnStatusNotify(const int progress)
{
    EXPECT_GT(progress, iProgress_);
    iProgress_ = progress;
    APP_LOGI("OnStatusNotify progress:%{public}d", progress);
}

std::string StatusReceiverImpl::GetResultMsg() const
{
    auto future = resultMsgSignal_.get_future();
    future.wait();
    std::string resultMsg = future.get();
    if (resultMsg == MSG_SUCCESS) {
        return OPERATION_SUCCESS;
    } else {
        return OPERATION_FAILED + resultMsg;
    }
}

class ExtendResourceManagerProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void StartProcess();
    static void InstallBundle(const std::string &bundleFilePath, std::string &installMsg);
    static void UninstallBundle(const std::string &bundleName, std::string &uninstallMsg);
    static sptr<BundleMgrProxy> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
};

void ExtendResourceManagerProxyTest::SetUpTestCase()
{}

void ExtendResourceManagerProxyTest::TearDownTestCase()
{}

void ExtendResourceManagerProxyTest::SetUp()
{}

void ExtendResourceManagerProxyTest::TearDown()
{}

void ExtendResourceManagerProxyTest::StartProcess()
{
    const int32_t permsNum = 4;
    uint64_t tokenId;
    const char *perms[permsNum];
    perms[PERMS_INDEX_ZERO] = "ohos.permission.GET_BUNDLE_INFO";
    perms[PERMS_INDEX_ONE] = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
    perms[PERMS_INDEX_TWO] = "ohos.permission.ACCESS_DYNAMIC_ICON";
    perms[PERMS_INDEX_THREE] = "ohos.permission.INSTALL_BUNDLE";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsNum,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "kit_system_test",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void ExtendResourceManagerProxyTest::InstallBundle(const std::string &bundleFilePath, std::string &installMsg)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        installMsg = "Failure";
        return;
    }

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    bool installResult = installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    EXPECT_TRUE(installResult);
    installMsg = statusReceiver->GetResultMsg();
}

void ExtendResourceManagerProxyTest::UninstallBundle(
    const std::string &bundleName, std::string &uninstallMsg)
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
    installParam.userId = USERID;

    bool uninstallResult = installerProxy->Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    uninstallMsg = statusReceiver->GetResultMsg();
}

sptr<BundleMgrProxy> ExtendResourceManagerProxyTest::GetBundleMgrProxy()
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
    return iface_cast<BundleMgrProxy>(remoteObject);
}

sptr<IBundleInstaller> ExtendResourceManagerProxyTest::GetInstallerProxy()
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        return nullptr;
    }

    sptr<IBundleInstaller> installerProxy = bundleMgrProxy->GetBundleInstaller();
    if (!installerProxy) {
        APP_LOGE("fail to get bundle installer proxy.");
        return nullptr;
    }

    APP_LOGI("get bundle installer proxy success.");
    return installerProxy;
}

/**
 * @tc.number: AddExtResource_0100
 * @tc.name: test the AddExtResource
 * @tc.desc: 1. system running normally
 *           2. test AddExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, AddExtResource_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> filePaths;
    ErrCode res = extendResource.AddExtResource(EMPTY_STRING, filePaths);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.AddExtResource(BUNDLE_NAME, filePaths);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED);

    filePaths.push_back(BUNDLE_NAME);
    res = extendResource.AddExtResource(BUNDLE_NAME, filePaths);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: RemoveExtResource_0100
 * @tc.name: test the RemoveExtResource
 * @tc.desc: 1. system running normally
 *           2. test RemoveExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, RemoveExtResource_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> moduleNames;
    ErrCode res = extendResource.RemoveExtResource(EMPTY_STRING, moduleNames);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.RemoveExtResource(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_REMOVE_EXT_RESOURCE_FAILED);

    moduleNames.push_back(BUNDLE_NAME);
    res = extendResource.RemoveExtResource(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetExtResource_0100
 * @tc.name: test the GetExtResource
 * @tc.desc: 1. system running normally
 *           2. test GetExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, GetExtResource_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> moduleNames;
    ErrCode res = extendResource.GetExtResource(EMPTY_STRING, moduleNames);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.GetExtResource(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: EnableDynamicIcon_0100
 * @tc.name: test the EnableDynamicIcon
 * @tc.desc: 1. system running normally
 *           2. test EnableDynamicIcon
 */
HWTEST_F(ExtendResourceManagerProxyTest, EnableDynamicIcon_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> moduleNames;
    ErrCode res = extendResource.EnableDynamicIcon(EMPTY_STRING, EMPTY_STRING);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.EnableDynamicIcon(BUNDLE_NAME, EMPTY_STRING);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    moduleNames.push_back(BUNDLE_NAME);
    res = extendResource.EnableDynamicIcon(BUNDLE_NAME, MODULE_NAME);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: DisableDynamicIcon_0100
 * @tc.name: test the DisableDynamicIcon
 * @tc.desc: 1. system running normally
 *           2. test DisableDynamicIcon
 */
HWTEST_F(ExtendResourceManagerProxyTest, DisableDynamicIcon_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    ErrCode res = extendResource.DisableDynamicIcon(EMPTY_STRING);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.DisableDynamicIcon(BUNDLE_NAME);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetDynamicIcon_0100
 * @tc.name: test the GetDynamicIcon
 * @tc.desc: 1. system running normally
 *           2. test GetDynamicIcon
 */
HWTEST_F(ExtendResourceManagerProxyTest, GetDynamicIcon_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::string moduleName = FILE_PATH;
    ErrCode res = extendResource.GetDynamicIcon(EMPTY_STRING, moduleName);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.GetDynamicIcon(BUNDLE_NAME, moduleName);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: CreateFd_0100
 * @tc.name: test the CreateFd
 * @tc.desc: 1. system running normally
 *           2. test CreateFd
 */
HWTEST_F(ExtendResourceManagerProxyTest, CreateFd_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    int32_t fd = FD;
    std::string path = FILE_PATH;
    ErrCode res = extendResource.CreateFd(EMPTY_STRING, fd, path);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED);

    res = extendResource.CreateFd(BUNDLE_NAME, fd, path);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: CopyFiles_0100
 * @tc.name: test the CopyFiles
 * @tc.desc: 1. system running normally
 *           2. test CopyFiles
 */
HWTEST_F(ExtendResourceManagerProxyTest, CopyFiles_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> sourceFiles;
    std::vector<std::string> destFiles;
    ErrCode res = extendResource.CopyFiles(sourceFiles, destFiles);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED);

    sourceFiles.push_back(BUNDLE_NAME);
    res = extendResource.CopyFiles(sourceFiles, destFiles);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED);
}

/**
 * @tc.number: AddExtResource_0001
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call AddExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, AddExtResource_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> filePath;
            filePath.push_back(BUNDLE_PATH_2);
            std::vector<std::string> destFiles;
            ErrCode ret = proxy->CopyFiles(filePath, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            ret = proxy->AddExtResource(BUNDLE_NAME_DEMO, destFiles);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
        }
    }
}

/**
 * @tc.number: AddExtResource_0002
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call AddExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, AddExtResource_0002, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> filePath;
            filePath.push_back(BUNDLE_PATH_1);
            ErrCode ret = proxy->AddExtResource(BUNDLE_NAME_DEMO, filePath);
            EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED);
        }
    }
}

/**
 * @tc.number: AddExtResource_0003
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call AddExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, AddExtResource_0003, Function | SmallTest | Level1)
{
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> filePath;
            filePath.push_back(BUNDLE_PATH_2);
            std::vector<std::string> destFiles;
            ErrCode ret = proxy->CopyFiles(filePath, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            ret = proxy->AddExtResource(BUNDLE_NAME_DEMO, destFiles);
            EXPECT_EQ(ret, ERR_OK);
        }
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME_DEMO, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
}

/**
 * @tc.number: RemoveExtResource_0001
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call RemoveExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, RemoveExtResource_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> moduleNames;
            moduleNames.push_back(DYNAMIC_NAME);
            ErrCode ret = proxy->RemoveExtResource(BUNDLE_NAME_DEMO, moduleNames);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
        }
    }
}

/**
 * @tc.number: RemoveExtResource_0002
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call RemoveExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, RemoveExtResource_0002, Function | SmallTest | Level1)
{
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> moduleNames;
            moduleNames.push_back(DYNAMIC_NAME);
            ErrCode ret = proxy->RemoveExtResource(BUNDLE_NAME_DEMO, moduleNames);
            EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_REMOVE_EXT_RESOURCE_FAILED);
        }
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME_DEMO, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
}

/**
 * @tc.number: RemoveExtResource_0003
 * @tc.name: test BundleMgrProxy
 * @tc.desc: 1.call RemoveExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, RemoveExtResource_0003, Function | SmallTest | Level1)
{
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> filePath;
            filePath.push_back(BUNDLE_PATH_2);
            std::vector<std::string> destFiles;
            ErrCode ret = proxy->CopyFiles(filePath, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            ret = proxy->AddExtResource(BUNDLE_NAME_DEMO, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            std::vector<std::string> moduleNames;
            moduleNames.push_back(DYNAMIC_NAME);
            ret = proxy->RemoveExtResource(BUNDLE_NAME_DEMO, moduleNames);
            EXPECT_EQ(ret, ERR_OK);
        }
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME_DEMO, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
}

/**
 * @tc.number: GetExtResource_0001
 * @tc.name: test GetExtResource
 * @tc.desc: 1.call GetExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, GetExtResource_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> moduleNames;
            ErrCode ret = proxy->GetExtResource(BUNDLE_NAME_DEMO, moduleNames);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
        }
    }
}

/**
 * @tc.number: GetExtResource_0002
 * @tc.name: test GetExtResource
 * @tc.desc: 1.call GetExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, GetExtResource_0002, Function | SmallTest | Level1)
{
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> moduleNames;
            ErrCode ret = proxy->GetExtResource(BUNDLE_NAME_DEMO, moduleNames);
            EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_GET_EXT_RESOURCE_FAILED);
            EXPECT_TRUE(moduleNames.empty());
        }
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME_DEMO, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
}

/**
 * @tc.number: GetExtResource_0003
 * @tc.name: test GetExtResource
 * @tc.desc: 1.call GetExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, GetExtResource_0003, Function | SmallTest | Level1)
{
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> filePath;
            filePath.push_back(BUNDLE_PATH_2);
            std::vector<std::string> destFiles;
            ErrCode ret = proxy->CopyFiles(filePath, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            ret = proxy->AddExtResource(BUNDLE_NAME_DEMO, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            std::vector<std::string> moduleNames;
            ret = proxy->GetExtResource(BUNDLE_NAME_DEMO, moduleNames);
            EXPECT_EQ(ret, ERR_OK);
            EXPECT_FALSE(moduleNames.empty());
            if (!moduleNames.empty()) {
                EXPECT_EQ(moduleNames[0], DYNAMIC_NAME);
            }
        }
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME_DEMO, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
}

/**
 * @tc.number: EnableDynamicIcon_0001
 * @tc.name: test EnableDynamicIcon
 * @tc.desc: 1.call EnableDynamicIcon
 */
HWTEST_F(ExtendResourceManagerProxyTest, EnableDynamicIcon_0001, Function | SmallTest | Level1)
{
    StartProcess();
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> filePath;
            filePath.push_back(BUNDLE_PATH_2);
            std::vector<std::string> destFiles;
            ErrCode ret = proxy->CopyFiles(filePath, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            ret = proxy->AddExtResource(BUNDLE_NAME_DEMO, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            ret = proxy->EnableDynamicIcon(BUNDLE_NAME_DEMO, BUNDLE_NAME);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

            ret = proxy->EnableDynamicIcon(BUNDLE_NAME_DEMO, DYNAMIC_NAME);
            EXPECT_EQ(ret, ERR_OK);
        }
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME_DEMO, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
}

/**
 * @tc.number: DisableDynamicIcon_0001
 * @tc.name: test DisableDynamicIcon
 * @tc.desc: 1.call DisableDynamicIcon
 */
HWTEST_F(ExtendResourceManagerProxyTest, DisableDynamicIcon_0001, Function | SmallTest | Level1)
{
    StartProcess();
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            ErrCode ret = proxy->DisableDynamicIcon(DYNAMIC_NAME);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

            ret = proxy->DisableDynamicIcon(BUNDLE_NAME_DEMO);
            EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_DISABLE_DYNAMIC_ICON_FAILED);
        }
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME_DEMO, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
}

/**
 * @tc.number: GetDynamicIcon_0001
 * @tc.name: test GetDynamicIcon
 * @tc.desc: 1.call GetDynamicIcon
 */
HWTEST_F(ExtendResourceManagerProxyTest, GetDynamicIcon_0001, Function | SmallTest | Level1)
{
    StartProcess();
    std::string installMsg;
    InstallBundle(BUNDLE_PATH_1, installMsg);
    EXPECT_EQ(installMsg, "Success") << "install fail!" << BUNDLE_PATH_1;

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto proxy = bundleMgrProxy->GetExtendResourceManager();
        EXPECT_NE(proxy, nullptr);
        if (proxy != nullptr) {
            std::vector<std::string> filePath;
            filePath.push_back(BUNDLE_PATH_2);
            std::vector<std::string> destFiles;
            ErrCode ret = proxy->CopyFiles(filePath, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            ret = proxy->AddExtResource(BUNDLE_NAME_DEMO, destFiles);
            EXPECT_EQ(ret, ERR_OK);

            ret = proxy->EnableDynamicIcon(BUNDLE_NAME_DEMO, DYNAMIC_NAME);
            EXPECT_EQ(ret, ERR_OK);

            std::string key;
            ret = proxy->GetDynamicIcon(BUNDLE_NAME_DEMO, key);
            EXPECT_EQ(ret, ERR_OK);
            EXPECT_EQ(key, DYNAMIC_NAME);
        }
    }

    std::string uninstallMsg;
    UninstallBundle(BUNDLE_NAME_DEMO, uninstallMsg);
    EXPECT_EQ(uninstallMsg, "Success");
}
} // AppExecFwk
} // OHOS