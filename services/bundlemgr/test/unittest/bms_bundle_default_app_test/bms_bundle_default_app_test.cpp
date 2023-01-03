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

#define private public
#include <fstream>
#include <gtest/gtest.h>
#include <set>
#include <sstream>
#include <string>

#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
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
const std::string DEFAULT_APP_VIDEO = "VIDEO";
const std::string DEFAULT_FILE_TYPE_VIDEO_MP4 = "video/mp4";
const std::string DEFAULT_APP_IMAGE = "IMAGE";
const std::string DEFAULT_APP_BROWSER = "BROWSER";
const std::string DEFAULT_APP_AUDIO = "AUDIO";
const std::string DEFAULT_APP_PDF = "PDF";
const std::string DEFAULT_APP_WORD = "WORD";
const std::string DEFAULT_APP_EXCEL = "EXCEL";
const std::string DEFAULT_APP_PPT = "PPT";
const std::string ABILITY_VIDEO = "VIDEO";
const std::string ABILITY_VIDEO_ERROR = "VIDEO-ERROR";
const std::string ABILITY_VIDEO_MP4 = "VideoMp4";
const std::string ABILITY_IMAGE = "IMAGE";
const std::string ABILITY_IMAGE_ERROR = "IMAGE-ERROR";
const std::string ABILITY_BROWSER = "BROWSER";
const std::string ABILITY_BROWSER_ERROR = "BROWSER-ERROR";
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
const std::string LABEL = "$string:MainAbility_label";
const std::string ICON = "$media:icon";
const std::string DESCRIPTION = "$string:MainAbility_desc";
const std::string INVALID_TYPE1 = "abc";
const std::string INVALID_TYPE2 = "abc/";
const std::string INVALID_TYPE3 = "/abc";
const std::string INVALID_TYPE4 = "*/abc";
const std::string INVALID_TYPE5 = "abc/*";
const std::string INVALID_TYPE6 = "*/*";
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
private:
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
};

std::set<std::string> BmsBundleDefaultAppTest::invalidTypeSet = {INVALID_TYPE1, INVALID_TYPE2,
    INVALID_TYPE3, INVALID_TYPE4, INVALID_TYPE5, INVALID_TYPE6};

BmsBundleDefaultAppTest::BmsBundleDefaultAppTest()
{}

BmsBundleDefaultAppTest::~BmsBundleDefaultAppTest()
{}

void BmsBundleDefaultAppTest::SetUpTestCase()
{}

void BmsBundleDefaultAppTest::TearDownTestCase()
{}

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
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

sptr<IDefaultApp> BmsBundleDefaultAppTest::GetDefaultAppProxy()
{
    if (!bundleMgrService_) {
        return nullptr;
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
    auto abilityInfo = bundleInfo.abilityInfos[0];
    EXPECT_EQ(abilityInfo.bundleName, BUNDLE_NAME);
    EXPECT_EQ(abilityInfo.moduleName, MODULE_NAME);
    EXPECT_EQ(abilityInfo.name, ABILITY_VIDEO);
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
    auto abilityInfo = bundleInfo.abilityInfos[0];
    EXPECT_EQ(abilityInfo.bundleName, BUNDLE_NAME);
    EXPECT_EQ(abilityInfo.moduleName, MODULE_NAME);
    EXPECT_EQ(abilityInfo.name, ABILITY_VIDEO_MP4);
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
    ErrCode result = defaultAppProxy->SetDefaultApplication(USER_ID, DEFAULT_APP_VIDEO, want);
    EXPECT_EQ(result, ERR_OK);
    result = SetDefaultApplicationWrap(defaultAppProxy, DEFAULT_FILE_TYPE_VIDEO_MP4, ABILITY_VIDEO_MP4);
    EXPECT_EQ(result, ERR_OK);
    BundleInfo bundleInfo;
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleInfo.name, BUNDLE_NAME);

    result = defaultAppProxy->ResetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4);
    EXPECT_EQ(result, ERR_OK);
    result = defaultAppProxy->GetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, bundleInfo);
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
    auto abilityInfo = bundleInfo.abilityInfos[0];
    EXPECT_EQ(abilityInfo.name, ABILITY_IMAGE);
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
    auto abilityInfo = bundleInfo.abilityInfos[0];
    EXPECT_EQ(abilityInfo.name, ABILITY_BROWSER);
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
    auto abilityInfo = bundleInfo.abilityInfos[0];
    EXPECT_EQ(abilityInfo.name, ABILITY_AUDIO);
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
    auto abilityInfo = bundleInfo.abilityInfos[0];
    EXPECT_EQ(abilityInfo.name, ABILITY_PDF);
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
    auto abilityInfo = bundleInfo.abilityInfos[0];
    EXPECT_EQ(abilityInfo.name, ABILITY_WORD);
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
    auto abilityInfo = bundleInfo.abilityInfos[0];
    EXPECT_EQ(abilityInfo.name, ABILITY_EXCEL);
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
    auto abilityInfo = bundleInfo.abilityInfos[0];
    EXPECT_EQ(abilityInfo.name, ABILITY_PPT);
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
 * @tc.name: test GetBundleInfoByFileType
 * @tc.desc: 1. test GetBundleInfoByFileType failed
 */
HWTEST_F(BmsBundleDefaultAppTest, BmsBundleDefaultApp_4900, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    ErrCode ret = DefaultAppMgr::GetInstance().GetBundleInfoByFileType(
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
} // OHOS