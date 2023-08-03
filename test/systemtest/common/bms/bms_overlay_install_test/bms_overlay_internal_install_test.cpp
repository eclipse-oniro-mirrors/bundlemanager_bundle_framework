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

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TIMEOUT = 5;
constexpr int32_t USERID = 100;
constexpr std::string INTERNAL_OVERLAY_TEST1_PATH = "/data/test/internalOverlayTest/internalOverlayTest1.hsp";
constexpr std::string BUNDLE_NAME_OF_OVERLAY_TEST1 = "com.example.internalOverlayTest1";
} // namespace
class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    virtual ~StatusReceiverImpl() override;
    virtual void OnStatusNotify(const int progress) override;
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    ErrCode GetResultCode() const;

private:
    mutable std::promise<int32_t> resultMsgCode_;
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
    EXPECT_GT(progress, iProgress_);
    iProgress_ = progress;
    APP_LOGI("OnStatusNotify progress:%{public}d", progress);
}

void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    APP_LOGD("on finished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
    resultMsgCode_.set_value(resultCode);
}

ErrCode StatusReceiverImpl::GetResultCode() const
{
    auto future = resultMsgCode_.get_future();
    std::chrono::seconds timeout(TIMEOUT);
    if (future.wait_for(timeout) == std::future_status::timeout) {
        return ERR_APPEXECFWK_OPERATION_TIME_OUT;
    }
    return future.get();
}

class BmsOverlayInternalInstallTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static ErrCode InstallOverlayBundle(const std::vector<std::string> &bundleFilePaths);
    static ErrCode UninstallBundle(const std::string &bundleName);
    static sptr<IBundleMgr> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
};

sptr<IBundleMgr> BmsInstallSystemTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BmsInstallSystemTest::GetInstallerProxy()
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

ErrCode BmsOverlayInternalInstallTest::InstallOverlayBundle(const std::vector<std::string> &bundleFilePaths)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    EXPECT_NE(installerProxy, nullptr);
    InstallParam installParam;
    installParam.userId = USERID
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    bool installResult = installerProxy->Install(bundleFilePaths, installParam, statusReceiver);
    EXPECT_TRUE(installResult);
    return statusReceiver->GetResultCode();
}

ErrCode BmsOverlayInternalInstallTest::UninstallBundle(const std::string &bundleName)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    EXPECT_NE(installerProxy, nullptr);

    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;

    bool uninstallResult = installerProxy->Uninstall(bundleName, installParam, statusReceiver);
    EXPECT_TRUE(uninstallResult);
    return statusReceiver->GetResultCode();
}

/**
 * @tc.number: Bms_Overlay_Internal_Install_0100
 * @tc.name:  test the installation of a third-party bundle
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a third-party bundle
 *           2.install the bundle
 *           3.check the bundle info
 */
HWTEST_F(BmsOverlayInternalInstallTest, Bms_Overlay_Internal_Install_0100, Function | MediumTest | Level1)
{
    std::cout << "START Bms_Overlay_Internal_Install_0100" << std::endl;
    std::vector<std::string> bundlePaths = { INTERNAL_OVERLAY_TEST1_PATH };
    ErrCode ret = InstallOverlayBundle(bundlePaths, InstallFlag::NORMAL, installMsg);
    EXPECT_EQ(ret, ERR_OK) << "install fail!" << INTERNAL_OVERLAY_TEST1_PATH;

    ret = UninstallBundle(BUNDLE_NAME_OF_OVERLAY_TEST1);
    EXPECT_EQ(ret, ERR_OK) << "uninstall fail!" << BUNDLE_NAME_OF_OVERLAY_TEST1;
    std::cout << "END Bms_Overlay_Internal_Install_0100" << std::endl;
}
} // AppExecFwk
} // OHOS