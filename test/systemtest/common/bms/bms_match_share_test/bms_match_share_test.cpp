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

#include <fcntl.h>
#include <fstream>
#include <future>
#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_event_callback_host.h"
#include "bundle_installer_proxy.h"
#include "bundle_mgr_proxy.h"
#include "bundle_resource_info.h"
#include "bundle_resource_proxy.h"
#include "bundle_status_callback_host.h"
#include "bundle_pack_info.h"
#include "bundle_user_info.h"
#include "clean_cache_callback_host.h"
#include "common_tool.h"
#include "extension_ability_info.h"
#include "form_info.h"
#include "permission_define.h"
#include "int_wrapper.h"
#include "iservice_registry.h"
#include "launcher_ability_resource_info.h"
#include "nativetoken_kit.h"
#include "nlohmann/json.hpp"
#include "status_receiver_host.h"
#include "system_ability_definition.h"
#include "token_setproc.h"
#include "want_params_wrapper.h"

using OHOS::AAFwk::Want;
using namespace testing::ext;
using namespace std::chrono_literals;

namespace {
const std::string THIRD_BUNDLE_PATH = "/data/test/bms_bundle/";
const std::string BASE_BUNDLE_NAME = "com.example.matchshare.test";
const std::string ERROR_INSTALL_FAILED = "install failed!";
const std::string ERROR_UNINSTALL_FAILED = "uninstall failed!";
const std::string MSG_SUCCESS = "[SUCCESS]";
const std::string OPERATION_FAILED = "Failure";
const std::string OPERATION_SUCCESS = "Success";
constexpr const char* SHARE_ACTION_VALUE = "ohos.want.action.sendData";
constexpr const char* WANT_PARAM_PICKER_SUMMARY = "ability.picker.summary";
constexpr const char* WANT_PARAM_SUMMARY = "summary";
constexpr const char* SUMMARY_TOTAL_COUNT = "totalCount";
const int32_t USERID = 100;
const int32_t PERMS_INDEX_ZERO = 0;
const int32_t PERMS_INDEX_ONE = 1;
const int32_t PERMS_INDEX_TWO = 2;
const int32_t PERMS_INDEX_THREE = 3;
const int32_t PERMS_INDEX_FORE = 4;
const int32_t PERMS_INDEX_FIVE = 5;
const int32_t PERMS_INDEX_SIX = 6;
const int32_t PERMS_INDEX_SEVEN = 7;
const int32_t PERMS_INDEX_EIGHT = 8;
const int32_t PERMS_INDEX_NINE = 9;
}  // namespace
namespace OHOS {
namespace AppExecFwk {
class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    virtual ~StatusReceiverImpl();
    void OnStatusNotify(const int progress) override;
    void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
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

class BmsMatchShareTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void StartProcess();
    static void Install(
        const std::string &bundleFilePath, const InstallFlag installFlag, std::vector<std::string> &resvec);
    static void Install(
        const std::string &bundleFilePath, const InstallParam &installParam, std::vector<std::string> &resvec);
    static void Uninstall(const std::string &bundleName, std::vector<std::string> &resvec);
    static sptr<BundleMgrProxy> GetBundleMgrProxy();
    static sptr<IBundleInstaller> GetInstallerProxy();
    AAFwk::Want CreateWantForMatchShareTest(std::map<std::string, int32_t> &utds);
};

void BmsMatchShareTest::SetUpTestCase()
{}

void BmsMatchShareTest::TearDownTestCase()
{}

void BmsMatchShareTest::SetUp()
{}

void BmsMatchShareTest::TearDown()
{}

void BmsMatchShareTest::StartProcess()
{
    const int32_t permsNum = 10;
    uint64_t tokenId;
    const char *perms[permsNum];
    perms[PERMS_INDEX_ZERO] = "ohos.permission.GET_DEFAULT_APPLICATION";
    perms[PERMS_INDEX_ONE] = "ohos.permission.INSTALL_BUNDLE";
    perms[PERMS_INDEX_TWO] = "ohos.permission.SET_DEFAULT_APPLICATION";
    perms[PERMS_INDEX_THREE] = "ohos.permission.GET_INSTALLED_BUNDLE_LIST";
    perms[PERMS_INDEX_FORE] = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
    perms[PERMS_INDEX_FIVE] = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
    perms[PERMS_INDEX_SIX] = "ohos.permission.CHANGE_BUNDLE_UNINSTALL_STATE";
    perms[PERMS_INDEX_SEVEN] = "ohos.permission.INSTALL_CLONE_BUNDLE";
    perms[PERMS_INDEX_EIGHT] = "ohos.permission.UNINSTALL_CLONE_BUNDLE";
    perms[PERMS_INDEX_NINE] = "ohos.permission.LISTEN_BUNDLE_CHANGE";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsNum,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "match_share_test",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void BmsMatchShareTest::Install(
    const std::string &bundleFilePath, const InstallFlag installFlag, std::vector<std::string> &resvec)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        resvec.push_back(ERROR_INSTALL_FAILED);
        return;
    }
    InstallParam installParam;
    installParam.installFlag = installFlag;
    installParam.userId = USERID;
    sptr<StatusReceiverImpl> statusReceiver = (new (std::nothrow) StatusReceiverImpl());
    EXPECT_NE(statusReceiver, nullptr);
    installerProxy->Install(bundleFilePath, installParam, statusReceiver);
    resvec.push_back(statusReceiver->GetResultMsg());
}

void BmsMatchShareTest::Uninstall(const std::string &bundleName, std::vector<std::string> &resvec)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer failed.");
        resvec.push_back(ERROR_UNINSTALL_FAILED);
        return;
    }

    if (bundleName.empty()) {
        APP_LOGE("bundelname is null.");
        resvec.push_back(ERROR_UNINSTALL_FAILED);
    } else {
        InstallParam installParam;
        installParam.userId = USERID;
        sptr<StatusReceiverImpl> statusReceiver = (new (std::nothrow) StatusReceiverImpl());
        EXPECT_NE(statusReceiver, nullptr);
        installerProxy->Uninstall(bundleName, installParam, statusReceiver);
        resvec.push_back(statusReceiver->GetResultMsg());
    }
}

sptr<BundleMgrProxy> BmsMatchShareTest::GetBundleMgrProxy()
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

sptr<IBundleInstaller> BmsMatchShareTest::GetInstallerProxy()
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

AAFwk::Want BmsMatchShareTest::CreateWantForMatchShareTest(std::map<std::string, int32_t> &utds)
{
    AAFwk::WantParams summaryWp;
    int32_t totalCount = 0;
    for (const auto &pair : utds) {
        totalCount += pair.second;
        summaryWp.SetParam(pair.first, AAFwk::Integer::Box(pair.second));
    }

    AAFwk::WantParams pickerWp;
    pickerWp.SetParam(WANT_PARAM_SUMMARY, AAFwk::WantParamWrapper::Box(summaryWp));
    pickerWp.SetParam(SUMMARY_TOTAL_COUNT, AAFwk::Integer::Box(totalCount));

    AAFwk::WantParams wp;
    wp.SetParam(WANT_PARAM_PICKER_SUMMARY, AAFwk::WantParamWrapper::Box(pickerWp));

    AAFwk::Want want;
    want.SetAction(SHARE_ACTION_VALUE);
    want.SetParams(wp);

    return want;
}

/**
 * @tc.number: MatchShareTest_0100
 * @tc.name: test match skill
 * @tc.desc: test match skill
 */
HWTEST_F(BmsMatchShareTest, MatchShareTest_0100, Function | MediumTest | Level1)
{
    std::cout << "START MatchShareTest_0100" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "matchShareBundle1.hap";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::map<std::string, int32_t> utds = {{"general.png", 10}};
    AAFwk::Want want = CreateWantForMatchShareTest(utds);
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = bundleMgrProxy->QueryAbilityInfosV9(
        want, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(abilityInfos.empty());

    std::map<std::string, int32_t> utds2 = {{"general.jpeg", 15}};
    AAFwk::Want want2 = CreateWantForMatchShareTest(utds2);
    std::vector<AbilityInfo> abilityInfos2;
    ErrCode ret2 = bundleMgrProxy->QueryAbilityInfosV9(
        want2, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos2);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_FALSE(abilityInfos2.empty());

    std::map<std::string, int32_t> utds3 = {{"general.image", 20}};
    AAFwk::Want want3 = CreateWantForMatchShareTest(utds3);
    std::vector<AbilityInfo> abilityInfos3;
    ErrCode ret3 = bundleMgrProxy->QueryAbilityInfosV9(
        want3, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos3);
    EXPECT_EQ(ret3, ERR_OK);
    EXPECT_FALSE(abilityInfos3.empty());

    std::map<std::string, int32_t> utds4 = {{"general.png", 18}};
    AAFwk::Want want4 = CreateWantForMatchShareTest(utds4);
    std::vector<AbilityInfo> abilityInfos4;
    ErrCode ret4 = bundleMgrProxy->QueryAbilityInfosV9(
        want4, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos4);
    EXPECT_NE(ret4, ERR_OK);
    EXPECT_TRUE(abilityInfos4.empty());
    
    resvec.clear();
    std::string appName = BASE_BUNDLE_NAME;
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END MatchShareTest_0100" << std::endl;
}

/**
 * @tc.number: MatchShareTest_0200
 * @tc.name: test match skill
 * @tc.desc: test match skill
 */
HWTEST_F(BmsMatchShareTest, MatchShareTest_0200, Function | MediumTest | Level1)
{
    std::cout << "START MatchShareTest_0200" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "matchShareBundle2.hap";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::map<std::string, int32_t> utds = {{"general.text", 20}};
    AAFwk::Want want = CreateWantForMatchShareTest(utds);
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = bundleMgrProxy->QueryAbilityInfosV9(
        want, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(abilityInfos.empty());

    std::map<std::string, int32_t> utds2 = {{"general.object", 30}};
    AAFwk::Want want2 = CreateWantForMatchShareTest(utds2);
    std::vector<AbilityInfo> abilityInfos2;
    ErrCode ret2 = bundleMgrProxy->QueryAbilityInfosV9(
        want2, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos2);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_FALSE(abilityInfos2.empty());

    std::map<std::string, int32_t> utds3 = {{"general.text", 10}};
    AAFwk::Want want3 = CreateWantForMatchShareTest(utds3);
    std::vector<AbilityInfo> abilityInfos3;
    ErrCode ret3 = bundleMgrProxy->QueryAbilityInfosV9(
        want3, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos3);
    EXPECT_EQ(ret3, ERR_OK);
    EXPECT_FALSE(abilityInfos3.empty());

    std::map<std::string, int32_t> utds4 = {{"general.object", 40}};
    AAFwk::Want want4 = CreateWantForMatchShareTest(utds4);
    std::vector<AbilityInfo> abilityInfos4;
    ErrCode ret4 = bundleMgrProxy->QueryAbilityInfosV9(
        want4, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos4);
    EXPECT_NE(ret4, ERR_OK);
    EXPECT_TRUE(abilityInfos4.empty());
    
    resvec.clear();
    std::string appName = BASE_BUNDLE_NAME + "2";
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END MatchShareTest_0200" << std::endl;
}

/**
 * @tc.number: MatchShareTest_0300
 * @tc.name: test match skill
 * @tc.desc: test match skill
 */
HWTEST_F(BmsMatchShareTest, MatchShareTest_0300, Function | MediumTest | Level1)
{
    std::cout << "START MatchShareTest_0300" << std::endl;
    std::vector<std::string> resvec;
    std::string bundleFilePath = THIRD_BUNDLE_PATH + "matchShareBundle3.hap";
    Install(bundleFilePath, InstallFlag::REPLACE_EXISTING, resvec);
    CommonTool commonTool;
    std::string installResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(installResult, "Success") << "install fail!";

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::map<std::string, int32_t> utds = {{"general.audio", 1}};
    AAFwk::Want want = CreateWantForMatchShareTest(utds);
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = bundleMgrProxy->QueryAbilityInfosV9(
        want, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(abilityInfos.empty());

    std::map<std::string, int32_t> utds2 = {{"general.media", 2}};
    AAFwk::Want want2 = CreateWantForMatchShareTest(utds2);
    std::vector<AbilityInfo> abilityInfos2;
    ErrCode ret2 = bundleMgrProxy->QueryAbilityInfosV9(
        want2, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos2);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_FALSE(abilityInfos2.empty());

    std::map<std::string, int32_t> utds3 = {{"general.media", 5}};
    AAFwk::Want want3 = CreateWantForMatchShareTest(utds3);
    std::vector<AbilityInfo> abilityInfos3;
    ErrCode ret3 = bundleMgrProxy->QueryAbilityInfosV9(
        want3, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos3);
    EXPECT_EQ(ret3, ERR_OK);
    EXPECT_FALSE(abilityInfos3.empty());

    std::map<std::string, int32_t> utds4 = {{"general.media", 70}};
    AAFwk::Want want4 = CreateWantForMatchShareTest(utds4);
    std::vector<AbilityInfo> abilityInfos4;
    ErrCode ret4 = bundleMgrProxy->QueryAbilityInfosV9(
        want4, static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), USERID, abilityInfos4);
    EXPECT_NE(ret4, ERR_OK);
    EXPECT_TRUE(abilityInfos4.empty());
    
    resvec.clear();
    std::string appName = BASE_BUNDLE_NAME + "3";
    Uninstall(appName, resvec);
    std::string uninstallResult = commonTool.VectorToStr(resvec);
    EXPECT_EQ(uninstallResult, "Success") << "uninstall fail!";

    std::cout << "END MatchShareTest_0300" << std::endl;
}

}  // namespace AppExecFwk
}  // namespace OHOS