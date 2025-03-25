/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <set>
#include <sstream>
#include <string>

#include "aot/aot_executor.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "scope_guard.h"
#include "permission_define.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string BUNDLE_PATH = "/data/test/resource/bms/default_app_bundle/defaultAppTest.hap";
const std::string BUNDLE_NAME = "com.test.defaultApp";
const std::string MODULE_NAME = "module01";
const std::string ABILITY_NAME = "BROWSER";
const std::string DEFAULT_APP_VIDEO = "VIDEO";
const std::string DEFAULT_FILE_TYPE_VIDEO_MP4 = "video/mp4";
const std::string DEFAULT_APP_IMAGE = "IMAGE";
const std::string DEFAULT_APP_BROWSER = "BROWSER";
const std::string DEFAULT_APP_EMAIL = "EMAIL";
const std::string DEFAULT_APP_AUDIO = "AUDIO";
const std::string DEFAULT_APP_PDF = "PDF";
const std::string DEFAULT_APP_WORD = "WORD";
const std::string DEFAULT_FILE_TYPE_WORD = "application/msword";
const std::string DEFAULT_APP_EXCEL = "EXCEL";
const std::string DEFAULT_APP_PPT = "PPT";
const std::string ABILITY_VIDEO = "VIDEO";
const std::string ABILITY_VIDEO_ERROR = "VIDEO-ERROR";
const std::string ABILITY_VIDEO_MP4 = "VideoMp4";
const std::string ABILITY_IMAGE = "IMAGE";
const std::string ABILITY_IMAGE_ERROR = "IMAGE-ERROR";
const std::string ABILITY_BROWSER = "BROWSER";
const std::string ABILITY_BROWSER_ERROR = "BROWSER-ERROR";
const std::string ABILITY_EMAIL = "EMAIL";
const std::string ABILITY_EMAIL_ERROR = "EMAIL-ERROR";
const std::string ABILITY_AUDIO = "AUDIO";
const std::string ABILITY_AUDIO_ERROR = "AUDIO-ERROR";
const std::string ABILITY_PDF = "PDF";
const std::string ABILITY_PDF_ERROR = "PDF-ERROR";
const std::string ABILITY_WORD = "WORD";
const std::string ABILITY_WORD_ERROR = "WORD-ERROR";
const std::string ABILITY_EXCEL = "EXCEL";
const std::string ABILITY_EXCEL_ERROR = "EXCEL-ERROR";
const std::string ABILITY_PPT = "PPT";
const std::string ABILITY_PPT_ERROR = "PPT-ERROR";
const std::string ABILITY_GENERAL_VIDEO = "GeneralVideo";
const std::string ABILITY_GENERAL_AVI = "GeneralAvi";
const std::string ABILITY_VIDEO_MS_VIDEO = "VideoMsVideo";
const std::string UTD_GENERAL_AVI = "general.avi";
const std::string LABEL = "$string:MainAbility_label";
const std::string ICON = "$media:icon";
const std::string DESCRIPTION = "$string:MainAbility_desc";
const std::string INVALID_TYPE1 = "abc";
const std::string INVALID_TYPE2 = "abc/";
const std::string INVALID_TYPE3 = "/abc";
const std::string INVALID_TYPE4 = "*/abc";
const std::string INVALID_TYPE5 = "abc/*";
const std::string INVALID_TYPE6 = "*/*";
const std::string EMAIL_ACTION = "ohos.want.action.sendToData";
const std::string EMAIL_SCHEME = "mailto";
constexpr const char* ACTION_VIEW_DATA = "ohos.want.action.viewData";
const std::string PDF_MIME_TYPE = "application/pdf";
const std::string PDF_UTD = "com.adobe.pdf";
const std::string PDF_SUFFIX = ".pdf";

const nlohmann::json DEFAULT_CONFIG = R"(
[{
    "bundleName": "bundleName",
    "moduleName": "moduleName",
    "abilityName": "abilityName",
    "extensionName": "extensionName",
    "type": "type",
    "appType": "appType"
}]
)"_json;
const int32_t LABEL_ID = 16777218;
const int32_t ICON_ID = 16777222;
const int32_t DESCRIPTION_ID = 16777217;
const int32_t USER_ID = 100;
const int32_t INVALID_USER_ID = 200;
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundleDefaultAppTest : public testing::Test {
public:
    BmsBundleDefaultAppTest();
    ~BmsBundleDefaultAppTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    sptr<IDefaultApp> GetDefaultAppProxy();
    void StartInstalldService() const;
    void StartBundleService();
    ErrCode SetDefaultApplicationWrap(sptr<IDefaultApp> defaultAppProxy, const std::string& type,
        const std::string& abilityName) const;
    static std::set<std::string> invalidTypeSet;
    void ClearDataMgr();
    void ResetDataMgr();
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleDefaultAppTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleDefaultAppTest::installdService_ =
    std::make_shared<InstalldService>();

std::set<std::string> BmsBundleDefaultAppTest::invalidTypeSet = {INVALID_TYPE1, INVALID_TYPE2,
    INVALID_TYPE3, INVALID_TYPE4, INVALID_TYPE5, INVALID_TYPE6};

BmsBundleDefaultAppTest::BmsBundleDefaultAppTest()
{}

BmsBundleDefaultAppTest::~BmsBundleDefaultAppTest()
{}

void BmsBundleDefaultAppTest::SetUpTestCase()
{}

void BmsBundleDefaultAppTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleDefaultAppTest::SetUp()
{
    StartBundleService();
    StartInstalldService();
    InstallBundle(BUNDLE_PATH);
}

void BmsBundleDefaultAppTest::TearDown()
{
    UnInstallBundle(BUNDLE_NAME);
}

void BmsBundleDefaultAppTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleDefaultAppTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

ErrCode BmsBundleDefaultAppTest::InstallBundle(const std::string &bundlePath) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USER_ID;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleDefaultAppTest::UnInstallBundle(const std::string &bundleName) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USER_ID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleDefaultAppTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleDefaultAppTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

sptr<IDefaultApp> BmsBundleDefaultAppTest::GetDefaultAppProxy()
{
    if (!bundleMgrService_) {
        return nullptr;
    }
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    bool res = dataMgr->HasUserId(USER_ID);
    if (!res) {
        dataMgr->AddUserId(USER_ID);
    }
    return bundleMgrService_->GetDefaultAppProxy();
}

ErrCode BmsBundleDefaultAppTest::SetDefaultApplicationWrap(sptr<IDefaultApp> defaultAppProxy, const std::string& type,
    const std::string& abilityName) const
{
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, abilityName, MODULE_NAME);
    want.SetElement(elementName);
    return defaultAppProxy->SetDefaultApplication(USER_ID, type, want);
}


/**
 * @tc.number: UTD_0100
 * @tc.name: test SetDefaultApplication and GetDefaultApplication, param is general.avi, config is general.avi
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, UTD_0100, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, UTD_GENERAL_AVI, ABILITY_GENERAL_AVI);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, UTD_GENERAL_AVI, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.name, ABILITY_GENERAL_AVI);
    }

    result = defaultAppProxy->ResetDefaultApplication(USER_ID, UTD_GENERAL_AVI);
    EXPECT_EQ(result, ERR_OK);
    result = defaultAppProxy->GetDefaultApplication(USER_ID, UTD_GENERAL_AVI, bundleInfo);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: UTD_0200
 * @tc.name: test SetDefaultApplication and GetDefaultApplication, param is general.avi, config is general.video
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, UTD_0200, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, UTD_GENERAL_AVI, ABILITY_GENERAL_VIDEO);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, UTD_GENERAL_AVI, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.name, ABILITY_GENERAL_VIDEO);
    }

    result = defaultAppProxy->ResetDefaultApplication(USER_ID, UTD_GENERAL_AVI);
    EXPECT_EQ(result, ERR_OK);
    result = defaultAppProxy->GetDefaultApplication(USER_ID, UTD_GENERAL_AVI, bundleInfo);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: UTD_0300
 * @tc.name: test SetDefaultApplication, param is general.avi, config is video/x-msvideo
 * @tc.desc: 1. call SetDefaultApplication, return error
 *           2. call GetDefaultApplication, return error
 */
HWTEST_F(BmsBundleDefaultAppTest, UTD_0300, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, UTD_GENERAL_AVI, ABILITY_VIDEO_MS_VIDEO);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, UTD_GENERAL_AVI, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_0100
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1. call IsDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_0100, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    bool isDefaultApp = false;
    ErrCode result = defaultAppProxy->IsDefaultApplication(DEFAULT_APP_VIDEO, isDefaultApp);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: BmsBundleDefaultApp_0200
 * @tc.name: test SetDefaultApplication, app type normal test
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_0200, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_VIDEO, ABILITY_VIDEO);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.name, BUNDLE_NAME);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.bundleName, BUNDLE_NAME);
        EXPECT_EQ(abilityInfo.moduleName, MODULE_NAME);
        EXPECT_EQ(abilityInfo.name, ABILITY_VIDEO);
        EXPECT_EQ(abilityInfo.label, LABEL);
        EXPECT_EQ(abilityInfo.iconPath, ICON);
        EXPECT_EQ(abilityInfo.description, DESCRIPTION);
        EXPECT_EQ(abilityInfo.labelId, LABEL_ID);
        EXPECT_EQ(abilityInfo.iconId, ICON_ID);
        EXPECT_EQ(abilityInfo.descriptionId, DESCRIPTION_ID);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_0300
 * @tc.name: test SetDefaultApplication, set empty
 * @tc.desc: 1. call SetDefaultApplication not empty, GetDefaultApplication return true
 *           2. call SetDefaultApplication empty, GetDefaultApplication return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_0300, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_VIDEO, ABILITY_VIDEO);
    EXPECT_EQ(result, ERR_OK);
    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.name, BUNDLE_NAME);

    AAFwk::Want want;
    result = defaultAppProxy->SetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_EQ(result, ERR_OK);
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_0400
 * @tc.name: test SetDefaultApplication, both app type and file type exists
 * @tc.desc: 1. call SetDefaultApplication set app type, return true
 *           2. call SetDefaultApplication set file type, return true
 *           3. call GetDefaultApplication query file type, ability name is app type
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_0400, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_VIDEO, ABILITY_VIDEO);
    EXPECT_EQ(result, ERR_OK);
    result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_FILE_TYPE_VIDEO_MP4, ABILITY_VIDEO_MP4);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.bundleName, BUNDLE_NAME);
        EXPECT_EQ(abilityInfo.moduleName, MODULE_NAME);
        EXPECT_EQ(abilityInfo.name, ABILITY_VIDEO);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_0500
 * @tc.name: test SetDefaultApplication, file type normal test
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_0500, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    AAFwk::Want want;
    ErrCode result = defaultAppProxy->SetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_EQ(result, ERR_OK);
    result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_FILE_TYPE_VIDEO_MP4, ABILITY_VIDEO_MP4);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.name, BUNDLE_NAME);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.bundleName, BUNDLE_NAME);
        EXPECT_EQ(abilityInfo.moduleName, MODULE_NAME);
        EXPECT_EQ(abilityInfo.name, ABILITY_VIDEO_MP4);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_0600
 * @tc.name: test ResetDefaultApplication, app type test
 * @tc.desc: 1. call SetDefaultApplication then call GetDefaultApplication, return not empty
 *           2. call ResetDefaultApplication then call GetDefaultApplication, return empty
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_0600, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_VIDEO, ABILITY_VIDEO);
    EXPECT_EQ(result, ERR_OK);
    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.name, BUNDLE_NAME);

    result = defaultAppProxy->ResetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO);
    EXPECT_EQ(result, ERR_OK);
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_0700
 * @tc.name: test ResetDefaultApplication, file type test
 * @tc.desc: 1. call SetDefaultApplication then call GetDefaultApplication, return not empty
 *           2. call ResetDefaultApplication then call GetDefaultApplication, return empty
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_0700, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    AAFwk::Want want;
    ErrCode result = defaultAppProxy->SetDefaultApplication(USER_ID, DEFAULT_APP_WORD, want);
    EXPECT_EQ(result, ERR_OK);
    result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_FILE_TYPE_WORD, DEFAULT_APP_WORD);
    EXPECT_EQ(result, ERR_OK);
    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_WORD, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.name, BUNDLE_NAME);

    result = defaultAppProxy->ResetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_WORD);
    EXPECT_EQ(result, ERR_OK);
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_WORD, bundleInfo);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_0800
 * @tc.name: test SetDefaultApplication, app type IMAGE
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_0800, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_IMAGE, ABILITY_IMAGE);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_IMAGE, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.name, ABILITY_IMAGE);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_0900
 * @tc.name: test SetDefaultApplication, app type BROWSER
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_0900, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_BROWSER, ABILITY_BROWSER);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_BROWSER, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.name, ABILITY_BROWSER);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1000
 * @tc.name: test SetDefaultApplication, app type AUDIO
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1000, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_AUDIO, ABILITY_AUDIO);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_AUDIO, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.name, ABILITY_AUDIO);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1100
 * @tc.name: test SetDefaultApplication, app type PDF
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1100, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_PDF, ABILITY_PDF);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_PDF, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.name, ABILITY_PDF);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1200
 * @tc.name: test SetDefaultApplication, app type WORD
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1200, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_WORD, ABILITY_WORD);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_WORD, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.name, ABILITY_WORD);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1300
 * @tc.name: test SetDefaultApplication, app type EXCEL
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1300, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_EXCEL, ABILITY_EXCEL);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_EXCEL, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.name, ABILITY_EXCEL);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1400
 * @tc.name: test SetDefaultApplication, app type PPT
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1400, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_PPT, ABILITY_PPT);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_PPT, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.abilityInfos.size(), 1);
    if (bundleInfo.abilityInfos.size() == 1) {
        auto abilityInfo = bundleInfo.abilityInfos[0];
        EXPECT_EQ(abilityInfo.name, ABILITY_PPT);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1500
 * @tc.name: test IsDefaultApplication, invalid type
 * @tc.desc: 1. call IsDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1500, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    for (const std::string& invalidType : invalidTypeSet) {
        bool isDefaultApp = false;
        ErrCode result = defaultAppProxy->IsDefaultApplication(invalidType, isDefaultApp);
        EXPECT_EQ(result, ERR_OK);
        EXPECT_FALSE(isDefaultApp);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1600
 * @tc.name: test SetDefaultApplication, invalid type
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1600, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    for (const std::string& invalidType : invalidTypeSet) {
        ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, invalidType, ABILITY_VIDEO);
        EXPECT_NE(result, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1700
 * @tc.name: test GetDefaultApplication, invalid type
 * @tc.desc: 1. call GetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1700, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    BundleInfo bundleInfo;
    for (const std::string& invalidType : invalidTypeSet) {
        ErrCode result = defaultAppProxy->GetDefaultApplication(USER_ID, invalidType, bundleInfo);
        EXPECT_NE(result, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1800
 * @tc.name: test ResetDefaultApplication, invalid type
 * @tc.desc: 1. call ResetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1800, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    for (const std::string& invalidType : invalidTypeSet) {
        ErrCode result = defaultAppProxy->ResetDefaultApplication(USER_ID, invalidType);
        EXPECT_NE(result, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleDefaultApp_1900
 * @tc.name: test SetDefaultApplication, invalid userId
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_1900, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, ABILITY_VIDEO, MODULE_NAME);
    want.SetElement(elementName);
    ErrCode result = defaultAppProxy->SetDefaultApplication(INVALID_USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2000
 * @tc.name: test GetDefaultApplication, invalid userId
 * @tc.desc: 1. call GetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2000, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    BundleInfo bundleInfo;
    ErrCode result = defaultAppProxy->GetDefaultApplication(INVALID_USER_ID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2100
 * @tc.name: test ResetDefaultApplication, invalid userId
 * @tc.desc: 1. call ResetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2100, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = defaultAppProxy->ResetDefaultApplication(INVALID_USER_ID, DEFAULT_APP_VIDEO);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2200
 * @tc.name: test SetDefaultApplication, lack bundleName
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2200, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    AAFwk::Want want;
    ElementName elementName("", "", ABILITY_VIDEO, MODULE_NAME);
    want.SetElement(elementName);
    ErrCode result = defaultAppProxy->SetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2300
 * @tc.name: test SetDefaultApplication, lack moduleName
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2300, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, ABILITY_VIDEO, "");
    want.SetElement(elementName);
    ErrCode result = defaultAppProxy->SetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2400
 * @tc.name: test SetDefaultApplication, lack abilityName
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2400, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, "", MODULE_NAME);
    want.SetElement(elementName);
    ErrCode result = defaultAppProxy->SetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2500
 * @tc.name: test SetDefaultApplication, error browser
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2500, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_BROWSER, ABILITY_BROWSER_ERROR);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2600
 * @tc.name: test SetDefaultApplication, error video
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2600, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_VIDEO, ABILITY_VIDEO_ERROR);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2700
 * @tc.name: test SetDefaultApplication, error image
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2700, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_IMAGE, ABILITY_IMAGE_ERROR);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2800
 * @tc.name: test SetDefaultApplication, error audio
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2800, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_AUDIO, ABILITY_AUDIO_ERROR);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_2900
 * @tc.name: test SetDefaultApplication, error pdf
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_2900, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_PDF, ABILITY_PDF_ERROR);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_3000
 * @tc.name: test SetDefaultApplication, error word
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3000, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_WORD, ABILITY_WORD_ERROR);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_3100
 * @tc.name: test SetDefaultApplication, error excel
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3100, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_EXCEL, ABILITY_EXCEL_ERROR);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_3200
 * @tc.name: test SetDefaultApplication, error ppt
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3200, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_PPT, ABILITY_PPT_ERROR);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_3300
 * @tc.name: test GetDefaultApplication, param type is empty
 * @tc.desc: 1. call GetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3300, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    BundleInfo bundleInfo;
    std::string emptyType = "";
    ErrCode result = defaultAppProxy->GetDefaultApplication(USER_ID, emptyType, bundleInfo);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

/**
 * @tc.number: BmsBundleDefaultApp_3400
 * @tc.name: test ResetDefaultApplication, param type is empty
 * @tc.desc: 1. call ResetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3400, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    std::string emptyType = "";
    ErrCode result = defaultAppProxy->ResetDefaultApplication(USER_ID, emptyType);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

/**
 * @tc.number: BmsBundleDefaultApp_3500
 * @tc.name: test ResetDefaultApplication, param type is empty
 * @tc.desc: 1. call ResetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3500, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppData;
    nlohmann::json jsonObject;
    defaultAppData.ToJson(jsonObject);
    EXPECT_EQ(defaultAppData.FromJson(jsonObject), ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_3600
 * @tc.name: test IsMatch, param is a failed type
 * @tc.desc: 1. call IsMatch, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3600, Function | SmallTest | Level1)
{
    const std::string type = "error";
    const std::vector<Skill> skills;
    bool ret = DefaultAppMgr::GetInstance().IsMatch(type, skills);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_3700
 * @tc.name: test MatchAppType, param is a failed type
 * @tc.desc: 1. call MatchAppType, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3700, Function | SmallTest | Level1)
{
    const std::string type = "error";
    const std::vector<Skill> skills;
    bool ret = DefaultAppMgr::GetInstance().MatchAppType(type, skills);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_3800
 * @tc.name: test IsAppType, param is a failed type
 * @tc.desc: 1. call IsAppType, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3800, Function | SmallTest | Level1)
{
    const std::string type = "error";
    bool ret = DefaultAppMgr::GetInstance().IsAppType(type);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_3900
 * @tc.name: test VerifyElementFormat, set bundleName is empty
 * @tc.desc: 1. call VerifyElementFormat, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_3900, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = "";
    bool ret = DefaultAppMgr::GetInstance().VerifyElementFormat(element);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_4000
 * @tc.name: test VerifyElementFormat, set moduleName is empty
 * @tc.desc: 1. call VerifyElementFormat, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4000, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = "com.ohos.setting";
    element.moduleName = "";
    bool ret = DefaultAppMgr::GetInstance().VerifyElementFormat(element);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_4100
 * @tc.name: test VerifyElementFormat, set abilityName is empty
 * @tc.desc: 1. call VerifyElementFormat, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4100, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = "com.ohos.setting";
    element.moduleName = "entry";
    element.abilityName= "";
    bool ret = DefaultAppMgr::GetInstance().VerifyElementFormat(element);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_4200
 * @tc.name: test VerifyElementFormat, set extensionName is empty
 * @tc.desc: 1. call VerifyElementFormat, return true
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4200, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = "com.ohos.setting";
    element.moduleName = "entry";
    element.abilityName= "com.ohos.setting.MainAbility";
    element.extensionName= "";
    bool ret = DefaultAppMgr::GetInstance().VerifyElementFormat(element);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BmsBundleDefaultApp_4300
 * @tc.name: test VerifyElementFormat, set extensionName and abilityName empty
 * @tc.desc: 1. call VerifyElementFormat, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4300, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = "com.ohos.setting";
    element.moduleName = "entry";
    element.abilityName= "";
    element.extensionName= "";
    bool ret = DefaultAppMgr::GetInstance().VerifyElementFormat(element);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_4400
 * @tc.name: test VerifyElementFormat, set param is not empty
 * @tc.desc: 1. call VerifyElementFormat, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4400, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = "com.ohos.setting";
    element.moduleName = "entry";
    element.abilityName= "com.ohos.setting.MainAbility";
    element.extensionName= "form";
    bool ret = DefaultAppMgr::GetInstance().VerifyElementFormat(element);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_4500
 * @tc.name: test VerifyElementFormat, set abilityName is empty
 * @tc.desc: 1. call VerifyElementFormat, return true
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4500, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = "com.ohos.setting";
    element.moduleName = "entry";
    element.abilityName= "";
    element.extensionName= "form";
    bool ret = DefaultAppMgr::GetInstance().VerifyElementFormat(element);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BmsBundleDefaultApp_4600
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1. return ERR_OK
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4600, Function | SmallTest | Level1)
{
    bool isDefaultApp = false;
    ErrCode ret = DefaultAppMgr::GetInstance().IsDefaultApplication(
        USER_ID, DEFAULT_APP_VIDEO, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_4700
 * @tc.name: test GetDefaultApplication
 * @tc.desc: 1. GetDefaultApplication failed
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4700, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    ErrCode ret = DefaultAppMgr::GetInstance().GetDefaultApplication(
        USER_ID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleDefaultApp_4800
 * @tc.name: test GetDefaultApplication
 * @tc.desc: 1. create new user and test it
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4800, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    int32_t newUserId = 1000;
    DefaultAppMgr::GetInstance().HandleCreateUser(newUserId);
    ErrCode ret = DefaultAppMgr::GetInstance().GetDefaultApplication(
        newUserId, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    DefaultAppMgr::GetInstance().HandleRemoveUser(newUserId);
}

/**
 * @tc.number: BmsBundleDefaultApp_4900
 * @tc.name: test GetBundleInfoByUtd
 * @tc.desc: 1. test GetBundleInfoByUtd failed
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4900, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    ErrCode ret = DefaultAppMgr::GetInstance().GetBundleInfoByUtd(
        Constants::INVALID_USERID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleDefaultApp_5000
 * @tc.name: test GetBundleInfo
 * @tc.desc: 1. test GetBundleInfo false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5000, Function | SmallTest | Level1)
{
    Element element;
    BundleInfo bundleInfo;
    element.bundleName = "";
    bool ret = DefaultAppMgr::GetInstance().GetBundleInfo(
        USER_ID, DEFAULT_APP_VIDEO, element, bundleInfo);
    EXPECT_EQ(ret, false);
    element.bundleName = "bundleName";
    ret = DefaultAppMgr::GetInstance().GetBundleInfo(
        USER_ID, DEFAULT_APP_VIDEO, element, bundleInfo);
    EXPECT_EQ(ret, false);
    ret = DefaultAppMgr::GetInstance().GetBundleInfo(
        Constants::INVALID_USERID, DEFAULT_APP_VIDEO, element, bundleInfo);
    EXPECT_EQ(ret, false);
    ret = DefaultAppMgr::GetInstance().GetBundleInfo(
        USER_ID, INVALID_TYPE6, element, bundleInfo);
    EXPECT_EQ(ret, false);
    element.bundleName = BUNDLE_NAME;
    element.abilityName = "abilityName";
    ret = DefaultAppMgr::GetInstance().GetBundleInfo(
        USER_ID, DEFAULT_APP_VIDEO, element, bundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_5100
 * @tc.name: test ImplicitQueryInfos
 * @tc.desc: 1. test ImplicitQueryInfos false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5100, Function | SmallTest | Level1)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetType(DEFAULT_FILE_TYPE_VIDEO_MP4);
    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool findDefaultApp = false;
    auto ret = dataMgr->ImplicitQueryInfos(want, flags, USER_ID, true, abilityInfos, extensionInfos, findDefaultApp);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BmsBundleDefaultApp_5200
 * @tc.name: test QueryInfoAndSkillsByElement
 * @tc.desc: 1. test QueryInfoAndSkillsByElement false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5200, Function | SmallTest | Level1)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Element element;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    std::vector<Skill> skills;
    auto ret = dataMgr->QueryInfoAndSkillsByElement(USER_ID, element, abilityInfo, extensionInfo, skills);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_5300
 * @tc.name: test QueryInfoAndSkillsByElement
 * @tc.desc: 1. test QueryInfoAndSkillsByElement false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5300, Function | SmallTest | Level1)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = MODULE_NAME;
    element.abilityName= ABILITY_NAME;
    element.extensionName= "";

    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    std::vector<Skill> skills;
    auto ret = dataMgr->QueryInfoAndSkillsByElement(USER_ID, element, abilityInfo, extensionInfo, skills);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BmsBundleDefaultApp_5400
 * @tc.name: test QueryInfoAndSkillsByElement
 * @tc.desc: 1. test QueryInfoAndSkillsByElement false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5400, Function | SmallTest | Level1)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = MODULE_NAME;
    element.abilityName = ABILITY_NAME;
    element.extensionName= "";

    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    std::vector<Skill> skills;
    auto ret = dataMgr->QueryInfoAndSkillsByElement(USER_ID, element, abilityInfo, extensionInfo, skills);
    EXPECT_EQ(ret, true);

    element.bundleName = BUNDLE_NAME + "1";
    ret = dataMgr->QueryInfoAndSkillsByElement(USER_ID, element, abilityInfo, extensionInfo, skills);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleDefaultApp_5500
 * @tc.name: test GetElement
 * @tc.desc: 1. test GetElement false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5500, Function | SmallTest | Level1)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ElementName elementName;
    Element element;
    auto ret = dataMgr->GetElement(USER_ID, elementName, element);
    EXPECT_EQ(ret, false);

    elementName.SetBundleName(BUNDLE_NAME);
    elementName.SetModuleName(MODULE_NAME);
    elementName.SetAbilityName(ABILITY_NAME);

    ret = dataMgr->GetElement(USER_ID, elementName, element);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BmsBundleDefaultApp_5600
 * @tc.name: test ImplicitQueryInfos
 * @tc.desc: 1. test ImplicitQueryInfos true
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5600, Function | SmallTest | Level1)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    AAFwk::Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetType(UTD_GENERAL_AVI);

    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_VIDEO, ABILITY_VIDEO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool findDefaultApp = false;
    bool testRet = dataMgr->ImplicitQueryInfos(
        want, 1, USER_ID, true, abilityInfos, extensionInfos, findDefaultApp);
    EXPECT_EQ(testRet, true);
}

/**
 * @tc.number: BmsBundleDefaultApp_5700
 * @tc.name: test ParseDefaultApplicationConfig
 * @tc.desc: 1. call ParseDefaultApplicationConfig
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5700, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppData;
    defaultAppData.ParseDefaultApplicationConfig(DEFAULT_CONFIG);
    EXPECT_EQ(defaultAppData.infos.size(), 0);
}

/**
 * @tc.number: BmsBundleDefaultApp_5800
 * @tc.name: test ParseDefaultApplicationConfig
 * @tc.desc: 1. call ParseDefaultApplicationConfig
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5800, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppData;
    nlohmann::json errorTypeJson = DEFAULT_CONFIG;
    errorTypeJson[0]["type"] = "";
    defaultAppData.ParseDefaultApplicationConfig(errorTypeJson);
    EXPECT_EQ(defaultAppData.infos.size(), 0);
}

/**
 * @tc.number: BmsBundleDefaultApp_5900
 * @tc.name: test ParseDefaultApplicationConfig
 * @tc.desc: 1. call ParseDefaultApplicationConfig
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_5900, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppData;
    nlohmann::json errorTypeJson = DEFAULT_CONFIG;
    errorTypeJson[0]["bundleName"] = "";
    defaultAppData.ParseDefaultApplicationConfig(errorTypeJson);
    EXPECT_EQ(defaultAppData.infos.size(), 0);
}

/**
 * @tc.number: BmsBundleDefaultApp_6000
 * @tc.name: test ParseDefaultApplicationConfig
 * @tc.desc: 1. call ParseDefaultApplicationConfig
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6000, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppData;
    nlohmann::json errorTypeJson = DEFAULT_CONFIG;
    errorTypeJson[0]["moduleName"] = "";
    defaultAppData.ParseDefaultApplicationConfig(errorTypeJson);
    EXPECT_EQ(defaultAppData.infos.size(), 0);
}

/**
 * @tc.number: BmsBundleDefaultApp_6100
 * @tc.name: test ParseDefaultApplicationConfig
 * @tc.desc: 1. call ParseDefaultApplicationConfig
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6100, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppData;
    nlohmann::json errorTypeJson = DEFAULT_CONFIG;
    errorTypeJson[0]["abilityName"] = "";
    errorTypeJson[0]["extensionName"] = "";
    defaultAppData.ParseDefaultApplicationConfig(errorTypeJson);
    EXPECT_EQ(defaultAppData.infos.size(), 0);
}

/**
 * @tc.number: BmsBundleDefaultApp_6200
 * @tc.name: test ParseDefaultApplicationConfig
 * @tc.desc: 1. call ParseDefaultApplicationConfig
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6200, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppData;
    nlohmann::json rightTypeJson = DEFAULT_CONFIG;
    rightTypeJson[0]["extensionName"] = "";
    defaultAppData.ParseDefaultApplicationConfig(rightTypeJson);
    EXPECT_EQ(defaultAppData.infos.size(), 0);
}

/**
 * @tc.number: BmsBundleDefaultApp_6300
 * @tc.name: test ParseDefaultApplicationConfig
 * @tc.desc: 1. call ParseDefaultApplicationConfig
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6300, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppData;
    nlohmann::json rightTypeJson = DEFAULT_CONFIG;
    rightTypeJson[0]["abilityName"] = "";
    defaultAppData.ParseDefaultApplicationConfig(rightTypeJson);
    EXPECT_EQ(defaultAppData.infos.size(), 0);
}

/**
 * @tc.number: BmsBundleDefaultApp_6400
 * @tc.name: test ResetDefaultApplication, param type is empty
 * @tc.desc: 1. call ResetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6400, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppData;
    Element element;
    defaultAppData.infos.insert(std::pair<std::string, Element>("1", element));
    nlohmann::json jsonObject;
    defaultAppData.ToJson(jsonObject);
    defaultAppData.ParseDefaultApplicationConfig(jsonObject);
    EXPECT_EQ(0, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_6500
 * @tc.name: test SetDefaultApplication, app type EMAIL
 * @tc.desc: 1. call SetDefaultApplication, return true
 *           2. call GetDefaultApplication, return true and the ability is same with SetDefaultApplication's ability
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6500, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_EMAIL, ABILITY_EMAIL);
    EXPECT_EQ(result, ERR_OK);

    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_APP_EMAIL, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(bundleInfo.abilityInfos.size(), 1);
    EXPECT_EQ(bundleInfo.abilityInfos[0].name, ABILITY_EMAIL);

    ASSERT_NE(bundleMgrService_, nullptr);
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    Want want;
    want.SetAction(EMAIL_ACTION);
    want.SetUri(EMAIL_SCHEME + ":test@test.com");
    int32_t flags = 0;
    int32_t userId = 100;
    bool withDefault = true;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool findDefaultApp = false;
    bool ret = dataMgr->ImplicitQueryInfos(
        want, flags, userId, withDefault, abilityInfos, extensionInfos, findDefaultApp);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(findDefaultApp, true);
    ASSERT_EQ(abilityInfos.size(), 1);
    EXPECT_EQ(abilityInfos[0].name, ABILITY_EMAIL);
}

/**
 * @tc.number: BmsBundleDefaultApp_6600
 * @tc.name: test SetDefaultApplication, error EMAIL
 * @tc.desc: 1. call SetDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6600, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    ErrCode result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_APP_EMAIL, ABILITY_EMAIL_ERROR);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_6700
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1. call IsDefaultApplication, return false
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6700, Function | SmallTest | Level1)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    EXPECT_NE(defaultAppProxy, nullptr);
    bool isDefaultApp = false;
    ErrCode result = defaultAppProxy->IsDefaultApplication("general.video", isDefaultApp);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: BmsBundleDefaultApp_6800
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1. return ERR_OK
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6800, Function | SmallTest | Level1)
{
    bool isDefaultApp = false;
    std::string errorType =
        "abcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcde"
        "fgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdef";
    ErrCode ret = DefaultAppMgr::GetInstance().IsDefaultApplication(USER_ID, errorType, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: BmsBundleDefaultApp_6900
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1. return ERR_OK
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_6900, Function | SmallTest | Level1)
{
    bool isDefaultApp = false;
    ErrCode ret = DefaultAppMgr::GetInstance().IsDefaultApplication(USER_ID, INVALID_TYPE5, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: BmsBundleDefaultApp_7000
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1. return ERR_OK
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7000, Function | SmallTest | Level1)
{
    bool isDefaultApp = false;
    DefaultAppMgr::GetInstance().Init();
    ErrCode ret = DefaultAppMgr::GetInstance().IsDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: BmsBundleDefaultApp_7100
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1. return ERR_OK
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7100, Function | SmallTest | Level1)
{
    bool isDefaultApp = false;
    DefaultAppMgr::GetInstance().Init();
    ASSERT_NE(DefaultAppMgr::GetInstance().defaultAppDb_, nullptr);

    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = MODULE_NAME;
    element.abilityName= "";

    DefaultAppMgr::GetInstance().defaultAppDb_->SetDefaultApplicationInfo(USER_ID, DEFAULT_APP_VIDEO, element);
    ErrCode ret = DefaultAppMgr::GetInstance().IsDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: BmsBundleDefaultApp_7200
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1. return ERR_OK
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7200, Function | SmallTest | Level1)
{
    bool isDefaultApp = false;
    DefaultAppMgr::GetInstance().Init();
    ASSERT_NE(DefaultAppMgr::GetInstance().defaultAppDb_, nullptr);

    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = MODULE_NAME;
    element.abilityName = ABILITY_NAME;

    DefaultAppMgr::GetInstance().defaultAppDb_->SetDefaultApplicationInfo(USER_ID, DEFAULT_APP_BROWSER, element);
    ErrCode ret = DefaultAppMgr::GetInstance().IsDefaultApplication(USER_ID, DEFAULT_APP_BROWSER, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: BmsBundleDefaultApp_7300
 * @tc.name: test GetDefaultApplication
 * @tc.desc: 1. GetDefaultApplication failed
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7300, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    ErrCode ret = DefaultAppMgr::GetInstance().GetDefaultApplication(USER_ID, INVALID_TYPE5, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

/**
 * @tc.number: BmsBundleDefaultApp_7400
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1. SetDefaultApplication failed
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7400, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = MODULE_NAME;
    element.abilityName = ABILITY_NAME;
    ErrCode ret = DefaultAppMgr::GetInstance().SetDefaultApplication(INVALID_USER_ID, DEFAULT_APP_VIDEO, element);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BmsBundleDefaultApp_7500
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1. SetDefaultApplication failed
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7500, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = MODULE_NAME;
    element.abilityName = ABILITY_NAME;
    ErrCode ret = DefaultAppMgr::GetInstance().SetDefaultApplication(USER_ID, INVALID_TYPE5, element);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

/**
 * @tc.number: BmsBundleDefaultApp_7600
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1. SetDefaultApplication success
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7600, Function | SmallTest | Level1)
{
    Element element;
    Element elementSave;
    elementSave.bundleName = BUNDLE_NAME;
    elementSave.moduleName = MODULE_NAME;
    elementSave.abilityName = ABILITY_NAME;
    ASSERT_NE(DefaultAppMgr::GetInstance().defaultAppDb_, nullptr);
    DefaultAppMgr::GetInstance().defaultAppDb_->SetDefaultApplicationInfo(USER_ID, DEFAULT_APP_BROWSER, elementSave);
    ErrCode ret = DefaultAppMgr::GetInstance().SetDefaultApplication(USER_ID, DEFAULT_APP_BROWSER, element);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_7700
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1. SetDefaultApplication failed
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7700, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = MODULE_NAME;
    element.abilityName = "";
    ErrCode ret = DefaultAppMgr::GetInstance().SetDefaultApplication(USER_ID, DEFAULT_APP_BROWSER, element);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH);
}

/**
 * @tc.number: BmsBundleDefaultApp_7800
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1. SetDefaultApplication success
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7800, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = MODULE_NAME;
    element.abilityName = ABILITY_NAME;
    ErrCode ret = DefaultAppMgr::GetInstance().SetDefaultApplication(USER_ID, DEFAULT_APP_BROWSER, element);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_7900
 * @tc.name: test ResetDefaultApplication
 * @tc.desc: 1. ResetDefaultApplication failed
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_7900, Function | SmallTest | Level1)
{
    ErrCode ret = DefaultAppMgr::GetInstance().ResetDefaultApplication(INVALID_USER_ID, DEFAULT_APP_BROWSER);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BmsBundleDefaultApp_8000
 * @tc.name: test ResetDefaultApplication
 * @tc.desc: 1. ResetDefaultApplication failed
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_8000, Function | SmallTest | Level1)
{
    ErrCode ret = DefaultAppMgr::GetInstance().ResetDefaultApplication(USER_ID, INVALID_TYPE5);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

/**
 * @tc.number: BmsBundleDefaultApp_8100
 * @tc.name: test ResetDefaultApplication
 * @tc.desc: 1. ResetDefaultApplication success
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_8100, Function | SmallTest | Level1)
{
    ErrCode ret = DefaultAppMgr::GetInstance().ResetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleDefaultApp_8200
 * @tc.name: test ResetDefaultApplication
 * @tc.desc: 1. ResetDefaultApplication success
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_8200, Function | SmallTest | Level1)
{
    DefaultAppMgr::GetInstance().Init();
    ASSERT_NE(DefaultAppMgr::GetInstance().defaultAppDb_, nullptr);
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = MODULE_NAME;
    element.abilityName = ABILITY_NAME;
    DefaultAppMgr::GetInstance().defaultAppDb_->SetDefaultApplicationInfo(USER_ID, DEFAULT_APP_BROWSER, element);
    ErrCode ret = DefaultAppMgr::GetInstance().ResetDefaultApplication(USER_ID, DEFAULT_APP_BROWSER);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AOT_EXECUTOR_0100
 * @tc.name: test AOTExecutor
 * @tc.desc: decimal convert to correct hex
 */
HWTEST_F(BmsBundleDefaultAppTest, AOT_EXECUTOR_0100, Function | SmallTest | Level1)
{
    uint32_t decimal = 16;
    std::string hex = AOTExecutor::GetInstance().DecToHex(decimal);
    EXPECT_EQ(hex, "0x10");

    AOTArgs aotArgs;
    bool ret = AOTExecutor::GetInstance().CheckArgs(aotArgs);
    EXPECT_EQ(ret, false);

    std::string hapPath = "/data/test.hap";
    uint32_t offset = 0;
    uint32_t length = 0;
    ret = AOTExecutor::GetInstance().GetAbcFileInfo(hapPath, Constants::CODE_LANGUAGE_1_1, offset, length);
    EXPECT_EQ(ret, false);

    AOTArgs completeArgs;
    ErrCode retCode = AOTExecutor::GetInstance().PrepareArgs(aotArgs, completeArgs);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: IsUserIdExist_0100
 * @tc.name: test dataMgr_ is nullptr
 * @tc.desc: 1.IsUserIdExist false
 */
HWTEST_F(BmsBundleDefaultAppTest, IsUserIdExist_0100, Function | MediumTest | Level1)
{
    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    bool ret = DefaultAppMgr::GetInstance().IsUserIdExist(USER_ID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IsElementValid_0100
 * @tc.name: test dataMgr_ is nullptr
 * @tc.desc: 1.IsElementValid false
 */
HWTEST_F(BmsBundleDefaultAppTest, IsElementValid_0100, Function | MediumTest | Level1)
{
    Element element;
    element.bundleName = "entry";
    element.moduleName = "entry";
    element.extensionName= "form";
    bool ret = DefaultAppMgr::GetInstance().VerifyElementFormat(element);
    EXPECT_EQ(ret, true);

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    ret = DefaultAppMgr::GetInstance().IsElementValid(USER_ID, "", element);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: MatchFileType_0100
 * @tc.name: test MatchUtd
 * @tc.desc: 1.MatchUtd is false
 */
HWTEST_F(BmsBundleDefaultAppTest, MatchFileType_0100, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    Skill skill;
    skill.actions.clear();

    SkillUri uris;
    uris.type = "application/msword";
    skill.uris.push_back(uris);

    skills.push_back(skill);
    bool res = DefaultAppMgr::GetInstance().MatchUtd("application/msword", skills);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: MatchFileType_0100
 * @tc.name: test MatchUtd
 * @tc.desc: 1.MatchUtd is true
 */
HWTEST_F(BmsBundleDefaultAppTest, MatchFileType_0200, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    Skill skill;
    skill.actions.push_back(ACTION_VIEW_DATA);

    SkillUri uris;
    uris.type = "application/msword";
    skill.uris.push_back(uris);

    skills.push_back(skill);
    bool res = DefaultAppMgr::GetInstance().MatchUtd("application/msword", skills);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: MatchFileType_0300
 * @tc.name: test MatchUtd
 * @tc.desc: 1.MatchUtd is false
 */
HWTEST_F(BmsBundleDefaultAppTest, MatchFileType_0300, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    bool res = DefaultAppMgr::GetInstance().MatchUtd("", skills);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetBrokerBundleInfo_0100
 * @tc.name: test GetBrokerBundleInfo
 * @tc.desc: 1.expect return false
 */
HWTEST_F(BmsBundleDefaultAppTest, GetBrokerBundleInfo_0100, Function | SmallTest | Level1)
{
    Element element;
    BundleInfo bundleInfo;
    bool ret = DefaultAppMgr::GetInstance().GetBrokerBundleInfo(element, bundleInfo);
    EXPECT_EQ(ret, false);
    element.bundleName = "bundleName";
    ret = DefaultAppMgr::GetInstance().GetBrokerBundleInfo(element, bundleInfo);
    EXPECT_EQ(ret, false);
    element.abilityName = "abilityName";
    ret = DefaultAppMgr::GetInstance().GetBrokerBundleInfo(element, bundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IsDefaultApplication_0100
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.IsDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppTest, IsDefaultApplication_0100, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    bool isDefaultApp = false;
    ClearDataMgr();
    auto res = impl.IsDefaultApplication(DEFAULT_FILE_TYPE_VIDEO_MP4, isDefaultApp);
    EXPECT_EQ(isDefaultApp, false);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: SetDefaultApplication_0100
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppTest, SetDefaultApplication_0100, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, "", MODULE_NAME);
    want.SetElement(elementName);
    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    auto res = impl.SetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: SetDefaultApplication_0200
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppTest, SetDefaultApplication_0200, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, ABILITY_VIDEO, "");
    want.SetElement(elementName);
    ErrCode result = impl.SetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: SetDefaultApplication_0300
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppTest, SetDefaultApplication_0300, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, "", MODULE_NAME);
    want.SetElement(elementName);
    ErrCode result = impl.SetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: SetDefaultApplication_0400
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppTest, SetDefaultApplication_0400, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, ABILITY_PDF_ERROR, MODULE_NAME);
    want.SetElement(elementName);
    ErrCode result = impl.SetDefaultApplication(USER_ID, DEFAULT_APP_PDF, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: SetDefaultApplication_0500
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppTest, SetDefaultApplication_0500, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, ABILITY_WORD_ERROR, MODULE_NAME);
    want.SetElement(elementName);
    ErrCode result = impl.SetDefaultApplication(USER_ID, DEFAULT_APP_WORD, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: SetDefaultApplication_0600
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppTest, SetDefaultApplication_0600, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, ABILITY_EXCEL_ERROR, MODULE_NAME);
    want.SetElement(elementName);
    ErrCode result = impl.SetDefaultApplication(USER_ID, DEFAULT_APP_EXCEL, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: SetDefaultApplication_0700
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppTest, SetDefaultApplication_0700, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, ABILITY_NAME, MODULE_NAME);
    want.SetElement(elementName);

    EXPECT_NE(bundleMgrService_, nullptr);
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool res = dataMgr->HasUserId(USER_ID);
    if (!res) {
        dataMgr->AddUserId(USER_ID);
    }
    ErrCode result = impl.SetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: ResetDefaultApplication_0100
 * @tc.name: test ResetDefaultApplication
 * @tc.desc: 1.ResetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppTest, ResetDefaultApplication_0100, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    std::string emptyType = "";
    ErrCode result = impl.ResetDefaultApplication(USER_ID, emptyType);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

/**
 * @tc.number: Normalize_0100
 * @tc.name: test Normalize success test case
 * @tc.desc: 1.mimeType convert to utd, suffix convert to utd
 *           2.utd and appType no need to convert
 */
HWTEST_F(BmsBundleDefaultAppTest, Normalize_0100, Function | SmallTest | Level1)
{
    auto normalizedTypeVector = DefaultAppMgr::Normalize(PDF_MIME_TYPE);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], PDF_UTD);

    normalizedTypeVector = DefaultAppMgr::Normalize(PDF_SUFFIX);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], PDF_UTD);

    normalizedTypeVector = DefaultAppMgr::Normalize(PDF_UTD);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], PDF_UTD);

    normalizedTypeVector = DefaultAppMgr::Normalize(DEFAULT_APP_VIDEO);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], DEFAULT_APP_VIDEO);
    normalizedTypeVector = DefaultAppMgr::Normalize(DEFAULT_APP_IMAGE);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], DEFAULT_APP_IMAGE);
    normalizedTypeVector = DefaultAppMgr::Normalize(DEFAULT_APP_BROWSER);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], DEFAULT_APP_BROWSER);
    normalizedTypeVector = DefaultAppMgr::Normalize(DEFAULT_APP_EMAIL);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], DEFAULT_APP_EMAIL);
    normalizedTypeVector = DefaultAppMgr::Normalize(DEFAULT_APP_AUDIO);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], DEFAULT_APP_AUDIO);
    normalizedTypeVector = DefaultAppMgr::Normalize(DEFAULT_APP_PDF);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], DEFAULT_APP_PDF);
    normalizedTypeVector = DefaultAppMgr::Normalize(DEFAULT_APP_WORD);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], DEFAULT_APP_WORD);
    normalizedTypeVector = DefaultAppMgr::Normalize(DEFAULT_APP_EXCEL);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], DEFAULT_APP_EXCEL);
    normalizedTypeVector = DefaultAppMgr::Normalize(DEFAULT_APP_PPT);
    ASSERT_EQ(normalizedTypeVector.size(), 1);
    EXPECT_EQ(normalizedTypeVector[0], DEFAULT_APP_PPT);
}

/**
 * @tc.number: Normalize_0200
 * @tc.name: test Normalize failed test case
 * @tc.desc: 1.mimeType convert to utd, suffix convert to utd
 */
HWTEST_F(BmsBundleDefaultAppTest, Normalize_0200, Function | SmallTest | Level1)
{
    std::string notSpecificMimeType = "mainType/*";
    auto normalizedTypeVector = DefaultAppMgr::Normalize(notSpecificMimeType);
    EXPECT_EQ(normalizedTypeVector.size(), 0);

    std::string wrongSuffix = "abc";
    normalizedTypeVector = DefaultAppMgr::Normalize(wrongSuffix);
    EXPECT_EQ(normalizedTypeVector.size(), 0);
}

/**
 * @tc.number: IsAppType_0100
 * @tc.name: test IsAppType
 * @tc.desc: 1.appType return true, others return false
 */
HWTEST_F(BmsBundleDefaultAppTest, IsAppType_0100, Function | SmallTest | Level1)
{
    bool ret = DefaultAppMgr::IsAppType(DEFAULT_APP_VIDEO);
    EXPECT_TRUE(ret);
    ret = DefaultAppMgr::IsAppType(DEFAULT_APP_IMAGE);
    EXPECT_TRUE(ret);
    ret = DefaultAppMgr::IsAppType(DEFAULT_APP_BROWSER);
    EXPECT_TRUE(ret);
    ret = DefaultAppMgr::IsAppType(DEFAULT_APP_EMAIL);
    EXPECT_TRUE(ret);
    ret = DefaultAppMgr::IsAppType(DEFAULT_APP_AUDIO);
    EXPECT_TRUE(ret);
    ret = DefaultAppMgr::IsAppType(DEFAULT_APP_PDF);
    EXPECT_TRUE(ret);
    ret = DefaultAppMgr::IsAppType(DEFAULT_APP_WORD);
    EXPECT_TRUE(ret);
    ret = DefaultAppMgr::IsAppType(DEFAULT_APP_EXCEL);
    EXPECT_TRUE(ret);
    ret = DefaultAppMgr::IsAppType(DEFAULT_APP_PPT);
    EXPECT_TRUE(ret);

    ret = DefaultAppMgr::IsAppType("abc");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsSpecificMimeType_0100
 * @tc.name: test IsSpecificMimeType
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppTest, IsSpecificMimeType_0100, Function | SmallTest | Level1)
{
    bool ret = DefaultAppMgr::IsSpecificMimeType(PDF_MIME_TYPE);
    EXPECT_TRUE(ret);

    std::string notSpecificMimeType = "mainType/*";
    ret = DefaultAppMgr::IsSpecificMimeType(notSpecificMimeType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetDefaultApplicationInternal_0100
 * @tc.name: GetDefaultApplicationInternal
 * @tc.desc: Test GetDefaultApplicationInternal the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, GetDefaultApplicationInternal_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;
    
    int32_t userId = 100;
    std::string normalizedType = "AUDIO";
    BundleInfo bundleInfo;
    bool backup = true;
    ErrCode ret = defaultAppMgr.GetDefaultApplicationInternal(userId, normalizedType, bundleInfo, backup);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST);

    normalizedType = "";
    ret = defaultAppMgr.GetDefaultApplicationInternal(userId, normalizedType, bundleInfo, backup);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST);
}

/**
 * @tc.number: SetDefaultApplicationInternal_0100
 * @tc.name: SetDefaultApplicationInternal
 * @tc.desc: Test SetDefaultApplicationInternal the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, SetDefaultApplicationInternal_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;
    
    int32_t userId = 100;
    std::string normalizedType;
    Element element;
    ErrCode ret = defaultAppMgr.SetDefaultApplicationInternal(userId, normalizedType, element);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ResetDefaultApplicationInternal_0100
 * @tc.name: ResetDefaultApplicationInternal
 * @tc.desc: Test ResetDefaultApplicationInternal the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, ResetDefaultApplicationInternal_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;
    
    int32_t userId = 100;
    std::string normalizedType;
    ErrCode ret = defaultAppMgr.ResetDefaultApplicationInternal(userId, normalizedType);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IsEmailWant_0100
 * @tc.name: IsEmailWant
 * @tc.desc: Test IsEmailWant the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, IsEmailWant_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;
    
    Want want;
    want.SetAction("ohos.want.action.sendToData1");
    bool ret = defaultAppMgr.IsEmailWant(want);
    EXPECT_FALSE(ret);

    want.SetAction("ohos.want.action.sendToData");
    want.SetUri("1mailto");
    ret = defaultAppMgr.IsEmailWant(want);
    EXPECT_FALSE(ret);

    want.SetAction("ohos.want.action.sendToData");
    want.SetUri("mailto");
    ret = defaultAppMgr.IsEmailWant(want);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetTypeFromWant_0100
 * @tc.name: GetTypeFromWant
 * @tc.desc: Test GetTypeFromWant the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, GetTypeFromWant_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;
    
    Want want;
    want.SetAction("ohos.want.action.viewData");
    want.SetUri("http://");
    std::string ret = defaultAppMgr.GetTypeFromWant(want);
    EXPECT_EQ(ret, "BROWSER");

    want.SetAction("ohos.want.action.sendToData");
    want.SetUri("mailto");
    ret = defaultAppMgr.GetTypeFromWant(want);
    EXPECT_EQ(ret, "EMAIL");

    want.SetAction("ohos.want.action.viewData");
    want.SetUri("");
    ret = defaultAppMgr.GetTypeFromWant(want);
    EXPECT_EQ(ret, "");

    want.SetAction("ohos.want.action.viewData");
    want.SetUri("aabbcc.zip");
    want.SetType("");
    ret = defaultAppMgr.GetTypeFromWant(want);
    EXPECT_EQ(ret, ".zip");
}

/**
 * @tc.number: GetDefaultApplication_0100
 * @tc.name: GetDefaultApplication
 * @tc.desc: Test GetDefaultApplication the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, GetDefaultApplication_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;

    Want want;
    want.SetAction("ohos.want.action.viewData1");
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool backup = true;
    ErrCode ret = defaultAppMgr.GetDefaultApplication(want, userId, abilityInfos, extensionInfos, backup);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBundleInfoByUtd_0100
 * @tc.name: GetBundleInfoByUtd
 * @tc.desc: Test GetBundleInfoByUtd the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, GetBundleInfoByUtd_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;

    int32_t userId = 100;
    const std::string utd;
    BundleInfo bundleInfo;
    bool backup = true;
    ErrCode ret = defaultAppMgr.GetBundleInfoByUtd(userId, utd, bundleInfo, backup);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST);
}

/**
 * @tc.number: MatchAppType_0100
 * @tc.name: MatchAppType
 * @tc.desc: Test MatchAppType the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, MatchAppType_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;

    std::string type = "BROWSER";
    std::vector<Skill> skills;
    bool ret = defaultAppMgr.MatchAppType(type, skills);
    EXPECT_FALSE(ret);

    type = "EMAIL";
    ret = defaultAppMgr.MatchAppType(type, skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsBrowserSkillsValid_0100
 * @tc.name: IsBrowserSkillsValid
 * @tc.desc: Test IsBrowserSkillsValid the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, IsBrowserSkillsValid_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;

    std::vector<Skill> skills;
    bool ret = defaultAppMgr.IsBrowserSkillsValid(skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MatchUtd_0100
 * @tc.name: MatchUtd
 * @tc.desc: Test MatchUtd the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, MatchUtd_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;

    std::string utd = "type";
    std::vector<Skill> skills;
    Skill skill;
    skill.actions.push_back("ohos.want.action.viewData");
    SkillUri skillUri;
    skillUri.type = "type";
    skill.uris.push_back(skillUri);
    skills.push_back(skill);
    bool ret = defaultAppMgr.MatchUtd(utd, skills);
    EXPECT_TRUE(ret);

    utd = "";
    skills.clear();
    ret = defaultAppMgr.MatchUtd(utd, skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsElementEmpty_0100
 * @tc.name: IsElementEmpty
 * @tc.desc: Test IsElementEmpty the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, IsElementEmpty_0100, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;

    Element element;
    bool ret = defaultAppMgr.IsElementEmpty(element);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetBrokerBundleInfo_0200
 * @tc.name: GetBrokerBundleInfo
 * @tc.desc: Test GetBrokerBundleInfo the DefaultAppMgr
 */
HWTEST_F(BmsBundleDefaultAppTest, GetBrokerBundleInfo_0200, Function | SmallTest | Level1)
{
    DefaultAppMgr defaultAppMgr;

    Element element;
    BundleInfo bundleInfo;
    bool ret = defaultAppMgr.GetBrokerBundleInfo(element, bundleInfo);
    EXPECT_FALSE(ret);
}
} // OHOS