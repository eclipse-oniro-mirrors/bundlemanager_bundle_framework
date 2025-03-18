/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <nlohmann/json.hpp>

#include "ability_manager_helper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_data_storage_interface.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "int_wrapper.h"
#include "json_constants.h"
#include "json_serializer.h"
#include "mime_type_mgr.h"
#include "parcel.h"
#include "shortcut_data_storage_rdb.h"
#include "uninstall_data_mgr_storage_rdb.h"
#include "want_params_wrapper.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string APP_NAME = "com.example.l3jsdemo";
const std::string ABILITY_NAME = "com.example.l3jsdemo.MainAbility";
const std::string PACKAGE_NAME = "com.example.l3jsdemo";
const std::string EMPTY_STRING = "";
const std::string MODULE_NAME = "entry";
const std::string DEVICE_ID = "PHONE-001";
const std::string LABEL = "hello";
const std::string DESCRIPTION = "mainEntry";
const std::string ICON_PATH = "/data/data/icon.png";
const std::string KIND = "test";
const AbilityType ABILITY_TYPE = AbilityType::PAGE;
const DisplayOrientation ORIENTATION = DisplayOrientation::PORTRAIT;
const LaunchMode LAUNCH_MODE = LaunchMode::SINGLETON;
const std::string CODE_PATH = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const std::string RESOURCE_PATH = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const std::string LIB_PATH = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const bool VISIBLE = true;
const int32_t USERID = 100;
const std::string ACTION = "action.system.home";
const std::string ENTITY = "entity.system.home";
const std::string ISOLATION_ONLY = "isolationOnly";
constexpr const char* SHARE_ACTION_VALUE = "ohos.want.action.sendData";
constexpr const char* WANT_PARAM_PICKER_SUMMARY = "ability.picker.summary";
constexpr const char* WANT_PARAM_SUMMARY = "summary";
constexpr const char* SUMMARY_TOTAL_COUNT = "totalCount";
const int32_t ICON_ID = 2222;
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest1.hap";
}  // namespace

class BmsDataMgrTest : public testing::Test {
public:
    BmsDataMgrTest();
    ~BmsDataMgrTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetDataMgr() const;
    AbilityInfo GetDefaultAbilityInfo() const;
    ShortcutInfo InitShortcutInfo();

private:
    std::shared_ptr<BundleDataMgr> dataMgr_ = std::make_shared<BundleDataMgr>();
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    std::vector<Skill> CreateSkillsForMatchShareTest();
    AAFwk::Want CreateWantForMatchShareTest(std::map<std::string, int32_t> &utds);
    bool MatchShare(std::map<std::string, int32_t> &utds, std::vector<Skill> &skills);
};

std::shared_ptr<BundleMgrService> BmsDataMgrTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsDataMgrTest::BmsDataMgrTest()
{}

BmsDataMgrTest::~BmsDataMgrTest()
{}

void BmsDataMgrTest::SetUpTestCase()
{}

void BmsDataMgrTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}


void BmsDataMgrTest::SetUp()
{}

void BmsDataMgrTest::TearDown()
{
    dataMgr_->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

AbilityInfo BmsDataMgrTest::GetDefaultAbilityInfo() const
{
    AbilityInfo abilityInfo;
    abilityInfo.package = PACKAGE_NAME;
    abilityInfo.name = ABILITY_NAME;
    abilityInfo.bundleName = BUNDLE_NAME;
    abilityInfo.applicationName = APP_NAME;
    abilityInfo.deviceId = DEVICE_ID;
    abilityInfo.label = LABEL;
    abilityInfo.description = DESCRIPTION;
    abilityInfo.iconPath = ICON_PATH;
    abilityInfo.visible = VISIBLE;
    abilityInfo.kind = KIND;
    abilityInfo.type = ABILITY_TYPE;
    abilityInfo.orientation = ORIENTATION;
    abilityInfo.launchMode = LAUNCH_MODE;
    abilityInfo.codePath = CODE_PATH;
    abilityInfo.resourcePath = RESOURCE_PATH;
    abilityInfo.libPath = LIB_PATH;
    return abilityInfo;
}

const std::shared_ptr<BundleDataMgr> BmsDataMgrTest::GetDataMgr() const
{
    return dataMgr_;
}

ShortcutInfo BmsDataMgrTest::InitShortcutInfo()
{
    ShortcutInfo shortcutInfos;
    shortcutInfos.id = "id_test1";
    shortcutInfos.bundleName = "com.ohos.hello";
    shortcutInfos.hostAbility = "hostAbility";
    shortcutInfos.icon = "$media:16777224";
    shortcutInfos.label = "shortcutLabel";
    shortcutInfos.disableMessage = "shortcutDisableMessage";
    shortcutInfos.isStatic = true;
    shortcutInfos.isHomeShortcut = true;
    shortcutInfos.isEnables = true;
    return shortcutInfos;
}

std::vector<Skill> BmsDataMgrTest::CreateSkillsForMatchShareTest()
{
    std::vector<Skill> skills;

    Skill skill;
    skill.actions.push_back(SHARE_ACTION_VALUE);

    SkillUri uriPng;
    uriPng.scheme = "file";
    uriPng.utd = "general.png";
    uriPng.maxFileSupported = 3;
    skill.uris.push_back(uriPng);

    SkillUri uriImage;
    uriImage.scheme = "file";
    uriImage.utd = "general.image";
    uriImage.maxFileSupported = 6;
    skill.uris.push_back(uriImage);

    SkillUri uriMedia;
    uriMedia.scheme = "file";
    uriMedia.utd = "general.media";
    uriMedia.maxFileSupported = 9;
    skill.uris.push_back(uriMedia); 

    skills.push_back(skill);

    return skills;
}

AAFwk::Want BmsDataMgrTest::CreateWantForMatchShareTest(std::map<std::string, int32_t> &utds)
{
    AAFwk::WantParams summaryWp;
    int32_t totalCount = 0;
    for (const auto &pair : utds) {
        totalCount += pair.second;
        summaryWp.SetParam(pair.first, Integer::Box(pair.second));
    }

    AAFwk::WantParams pickerWp;
    pickerWp.SetParam(WANT_PARAM_SUMMARY, AAFwk::WantParamWrapper::Box(summaryWp));
    pickerWp.SetParam(SUMMARY_TOTAL_COUNT, Integer::Box(totalCount));

    AAFwk::WantParams wp;
    wp.SetParam(WANT_PARAM_PICKER_SUMMARY, AAFwk::WantParamWrapper::Box(pickerWp));

    AAFwk::Want want;
    want.SetAction(SHARE_ACTION_VALUE);
    want.SetParams(wp);

    return want;
}

bool BmsDataMgrTest::MatchShare(std::map<std::string, int32_t> &utds, std::vector<Skill> &skills)
{
    auto dataMgr = GetDataMgr();
    AAFwk::Want want = CreateWantForMatchShareTest(utds);
    return dataMgr->MatchShare(want, skills);
}

/**
 * @tc.number: UpdateInstallState_0100
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. correct status transfer INSTALL_START->INSTALL_FAIL
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_0100, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.number: UpdateInstallState_0200
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. correct status transfer INSTALL_START->INSTALL_SUCCESS->UPDATING_START->UPDATING_FAIL
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_0200, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
    bool ret4 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_FAIL);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
    EXPECT_TRUE(ret4);
}

/**
 * @tc.number: UpdateInstallState_0300
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. correct status transfer INSTALL_START->INSTALL_SUCCESS->UPDATING_START->UPDATING_SUCCESS
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_0300, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
    bool ret4 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
    EXPECT_TRUE(ret4);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: UpdateInstallState_0400
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. correct status transfer INSTALL_START->INSTALL_SUCCESS->UNINSTALL_START->UNINSTALL_SUCCESS
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_0400, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    bool ret4 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
    EXPECT_TRUE(ret4);
}

/**
 * @tc.number: UpdateInstallState_0500
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. correct status transfer INSTALL_START->INSTALL_SUCCESS->UNINSTALL_START->UNINSTALL_FAIL
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_0500, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    bool ret4 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_FAIL);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
    EXPECT_TRUE(ret4);
}

/**
 * @tc.number: UpdateInstallState_0600
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->INSTALL_START
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_0600, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    EXPECT_TRUE(ret1);
    EXPECT_FALSE(ret2);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
}

/**
 * @tc.number: UpdateInstallState_0700
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->UNINSTALL_START
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_0700, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
}

/**
 * @tc.number: UpdateInstallState_0800
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->UNINSTALL_SUCCESS
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_0800, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
    EXPECT_TRUE(ret1);
    EXPECT_FALSE(ret2);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
}

/**
 * @tc.number: UpdateInstallState_0900
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->UNINSTALL_FAIL
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_0900, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_FAIL);
    EXPECT_TRUE(ret1);
    EXPECT_FALSE(ret2);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
}

/**
 * @tc.number: UpdateInstallState_1000
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->UPDATING_STAR
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1000, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
}

/**
 * @tc.number: UpdateInstallState_1100
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->UPDATING_SUCCESS
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1100, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
    EXPECT_TRUE(ret1);
    EXPECT_FALSE(ret2);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
}

/**
 * @tc.number: UpdateInstallState_1200
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->UPDATING_FAIL
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1200, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_FAIL);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
}

/**
 * @tc.number: UpdateInstallState_1300
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->INSTALL_SUCCESS->INSTALL_SUCCESS
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1300, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_FALSE(ret3);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: UpdateInstallState_1400
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->INSTALL_SUCCESS->INSTALL_START
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1400, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_FALSE(ret3);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: UpdateInstallState_1500
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->INSTALL_SUCCESS->INSTALL_FAIL
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1500, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_FALSE(ret3);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: UpdateInstallState_1600
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->INSTALL_SUCCESS->UNINSTALL_SUCCESS
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1600, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_FALSE(ret3);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: UpdateInstallState_1700
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->INSTALL_SUCCESS->UNINSTALL_FAIL
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1700, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_FAIL);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_FALSE(ret3);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: UpdateInstallState_1800
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->INSTALL_SUCCESS->UPDATING_FAIL
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1800, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_FAIL);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_FALSE(ret3);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: UpdateInstallState_1900
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. NOT correct status transfer INSTALL_START->INSTALL_SUCCESS->UPDATING_SUCCESS
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_1900, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_FALSE(ret3);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: UpdateInstallState_2000
 * @tc.name: UpdateInstallState
 * @tc.desc: 1. empty bundle name
 *           2. verify function return value
 */
HWTEST_F(BmsDataMgrTest, UpdateInstallState_2000, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState("", InstallState::INSTALL_START);
    EXPECT_FALSE(ret1);
}

/**
 * @tc.number: AddBundleInfo_0100
 * @tc.name: AddBundleInfo
 * @tc.desc: 1. add info to the data manager
 *           2. query data then verify
 */
HWTEST_F(BmsDataMgrTest, AddBundleInfo_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo info1;
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    bool ret3 = dataMgr->GetInnerBundleInfoWithDisable(BUNDLE_NAME, info1);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: AddBundleInfo_0200
 * @tc.name: AddBundleInfo
 * @tc.desc: 1. add info to the data manager
 *           2. query data then verify
 */
HWTEST_F(BmsDataMgrTest, AddBundleInfo_0200, Function | SmallTest | Level0)
{
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;

    InnerBundleInfo info1;
    BundleInfo bundleInfo1;
    bundleInfo1.name = BUNDLE_NAME;
    bundleInfo1.applicationInfo.name = APP_NAME;
    bundleInfo1.applicationInfo.bundleName = BUNDLE_NAME;
    ApplicationInfo applicationInfo1;
    applicationInfo1.name = BUNDLE_NAME;
    applicationInfo1.bundleName = BUNDLE_NAME;
    applicationInfo1.deviceId = DEVICE_ID;
    info1.SetBaseBundleInfo(bundleInfo1);
    info1.SetBaseApplicationInfo(applicationInfo1);
    info1.AddInnerBundleUserInfo(innerBundleUserInfo);

    InnerBundleInfo info2;
    BundleInfo bundleInfo2;
    bundleInfo2.name = BUNDLE_NAME;
    bundleInfo2.applicationInfo.name = APP_NAME;
    bundleInfo2.applicationInfo.bundleName = BUNDLE_NAME;
    ApplicationInfo applicationInfo2;
    applicationInfo2.name = BUNDLE_NAME;
    applicationInfo2.bundleName = BUNDLE_NAME;
    applicationInfo2.deviceId = DEVICE_ID;
    info2.SetBaseBundleInfo(bundleInfo2);
    info2.SetBaseApplicationInfo(applicationInfo2);
    info2.AddInnerBundleUserInfo(innerBundleUserInfo);

    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(USERID);

    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info1);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
    bool ret4 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
    bool ret5 = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, info2, info1);
    bool ret6 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
    EXPECT_TRUE(ret4);
    EXPECT_TRUE(ret5);
    EXPECT_TRUE(ret6);

    ApplicationInfo appInfo;
    bool ret7 = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, appInfo);
    EXPECT_TRUE(ret7);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: AddBundleInfo_0300
 * @tc.name: AddBundleInfo
 * @tc.desc: 1. scan dir not exist
 *           2. verify scan result file number is 0
 */
HWTEST_F(BmsDataMgrTest, AddBundleInfo_0300, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    InnerBundleInfo info1;
    bool ret = dataMgr->AddInnerBundleInfo("", info);
    bool ret1 = dataMgr->GetInnerBundleInfoWithDisable("", info1);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(ret1);
}

/**
 * @tc.number: AddBundleInfo_0400
 * @tc.name: AddBundleInfo
 * @tc.desc: 1. add info to the data manager, then uninstall, then reinstall
 *           2. query data then verify
 */
HWTEST_F(BmsDataMgrTest, AddBundleInfo_0400, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret4 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_TRUE(ret3);
    EXPECT_TRUE(ret4);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: AddBundleInfo_0500
 * @tc.name: AddBundleInfo
 * @tc.desc: 1. add module info to the data manager
 *           2. query data then verify
 */
HWTEST_F(BmsDataMgrTest, AddBundleInfo_0500, Function | SmallTest | Level0)
{
    InnerBundleInfo info1;
    BundleInfo bundleInfo1;
    bundleInfo1.name = BUNDLE_NAME;
    bundleInfo1.applicationInfo.name = APP_NAME;
    bundleInfo1.applicationInfo.bundleName = BUNDLE_NAME;
    ApplicationInfo applicationInfo1;
    applicationInfo1.name = BUNDLE_NAME;
    applicationInfo1.deviceId = DEVICE_ID;
    applicationInfo1.bundleName = BUNDLE_NAME;
    info1.SetBaseBundleInfo(bundleInfo1);
    info1.SetBaseApplicationInfo(applicationInfo1);

    InnerBundleInfo info2;
    BundleInfo bundleInfo2;
    bundleInfo2.name = BUNDLE_NAME;
    bundleInfo2.applicationInfo.name = APP_NAME;
    bundleInfo2.applicationInfo.bundleName = BUNDLE_NAME;
    ApplicationInfo applicationInfo2;
    applicationInfo2.name = BUNDLE_NAME;
    applicationInfo2.deviceId = DEVICE_ID;
    applicationInfo2.bundleName = BUNDLE_NAME;
    info2.SetBaseBundleInfo(bundleInfo2);
    info2.SetBaseApplicationInfo(applicationInfo2);

    InnerBundleInfo info3;
    InnerBundleInfo info4;
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info1);
    bool ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
    bool ret4 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
    bool ret5 = dataMgr->AddNewModuleInfo(BUNDLE_NAME, info2, info1);
    bool ret6 = dataMgr->GetInnerBundleInfoWithDisable(BUNDLE_NAME, info3);
    bool ret7 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret8 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
    bool ret9 = dataMgr->RemoveModuleInfo(BUNDLE_NAME, PACKAGE_NAME, info1);
    bool ret10 = dataMgr->GetInnerBundleInfoWithDisable(BUNDLE_NAME, info4);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
    EXPECT_TRUE(ret4);
    EXPECT_TRUE(ret5);
    EXPECT_TRUE(ret6);
    EXPECT_TRUE(ret7);
    EXPECT_TRUE(ret8);
    EXPECT_TRUE(ret9);
    EXPECT_TRUE(ret10);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
}

/**
 * @tc.number: GenerateUidAndGid_0100
 * @tc.name: GenerateUidAndGid
 * @tc.desc: 1. app type is system app
 *           2. generate uid and gid then verify
 */
HWTEST_F(BmsDataMgrTest, GenerateUidAndGid_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    info.SetAppType(Constants::AppType::SYSTEM_APP);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 0;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    bool ret3 = dataMgr->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: GenerateUidAndGid_0200
 * @tc.name: GenerateUidAndGid
 * @tc.desc: 1. app type is third party app
 *           2. generate uid and gid then verify
 */
HWTEST_F(BmsDataMgrTest, GenerateUidAndGid_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = BUNDLE_NAME;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 0;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    info.SetAppType(Constants::AppType::THIRD_SYSTEM_APP);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    bool ret3 = dataMgr->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: GenerateUidAndGid_0300
 * @tc.name: GenerateUidAndGid
 * @tc.desc: 1. app type is third party app
 *           2. generate uid and gid then verify
 */
HWTEST_F(BmsDataMgrTest, GenerateUidAndGid_0300, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = BUNDLE_NAME;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 0;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    info.SetAppType(Constants::AppType::THIRD_PARTY_APP);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(USERID);

    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    bool ret3 = dataMgr->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: GenerateUidAndGid_0400
 * @tc.name: GenerateUidAndGid
 * @tc.desc: 1. app type is third party app
 *           2. test GenerateUidAndGid failed by empty params
 */
HWTEST_F(BmsDataMgrTest, GenerateUidAndGid_0400, Function | SmallTest | Level0)
{
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = "";

    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(USERID);

    bool ret = dataMgr->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_FALSE(ret);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: QueryAbilityInfo_0100
 * @tc.name: QueryAbilityInfo
 * @tc.desc: 1. add info to the data manager
 *           2. query data then verify
 */
HWTEST_F(BmsDataMgrTest, QueryAbilityInfo_0100, Function | SmallTest | Level0)
{
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;

    InnerBundleInfo info1;
    BundleInfo bundleInfo1;
    bundleInfo1.name = BUNDLE_NAME;
    bundleInfo1.applicationInfo.name = APP_NAME;
    bundleInfo1.applicationInfo.bundleName = BUNDLE_NAME;
    ApplicationInfo applicationInfo1;
    applicationInfo1.name = BUNDLE_NAME;
    applicationInfo1.bundleName = BUNDLE_NAME;

    AbilityInfo abilityInfo = GetDefaultAbilityInfo();
    bundleInfo1.abilityInfos.push_back(abilityInfo);
    info1.SetBaseBundleInfo(bundleInfo1);
    info1.SetBaseApplicationInfo(applicationInfo1);
    info1.InsertAbilitiesInfo(BUNDLE_NAME + PACKAGE_NAME + ABILITY_NAME, abilityInfo);
    info1.AddInnerBundleUserInfo(innerBundleUserInfo);
    info1.SetAbilityEnabled(Constants::EMPTY_STRING, ABILITY_NAME, true, USERID);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(USERID);

    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    EXPECT_TRUE(ret1);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info1);
    EXPECT_TRUE(ret2);

    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);

    AbilityInfo abilityInfo2;
    bool ret3 = dataMgr->QueryAbilityInfo(want, 0, USERID, abilityInfo2);
    EXPECT_TRUE(ret3);

    EXPECT_EQ(abilityInfo2.package, abilityInfo.package);
    EXPECT_EQ(abilityInfo2.name, abilityInfo.name);
    EXPECT_EQ(abilityInfo2.bundleName, abilityInfo.bundleName);
    EXPECT_EQ(abilityInfo2.applicationName, abilityInfo.applicationName);
    EXPECT_EQ(abilityInfo2.deviceId, abilityInfo.deviceId);
    EXPECT_EQ(abilityInfo2.label, abilityInfo.label);
    EXPECT_EQ(abilityInfo2.description, abilityInfo.description);
    EXPECT_EQ(abilityInfo2.iconPath, abilityInfo.iconPath);
    EXPECT_EQ(abilityInfo2.visible, abilityInfo.visible);
    EXPECT_EQ(abilityInfo2.kind, abilityInfo.kind);
    EXPECT_EQ(abilityInfo2.type, abilityInfo.type);
    EXPECT_EQ(abilityInfo2.orientation, abilityInfo.orientation);
    EXPECT_EQ(abilityInfo2.launchMode, abilityInfo.launchMode);
    EXPECT_EQ(abilityInfo2.codePath, abilityInfo.codePath);
    EXPECT_EQ(abilityInfo2.resourcePath, abilityInfo.resourcePath);
    EXPECT_EQ(abilityInfo2.libPath, abilityInfo.libPath);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: QueryAbilityInfo_0200
 * @tc.name: QueryAbilityInfo
 * @tc.desc: 1. add info to the data manager
 *           2. query data then verify
 */
HWTEST_F(BmsDataMgrTest, QueryAbilityInfo_0200, Function | SmallTest | Level0)
{
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    want.SetElement(name);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AbilityInfo abilityInfo;
    bool ret = dataMgr->QueryAbilityInfo(want, 0, 0, abilityInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: QueryAbilityInfo_0300
 * @tc.name: QueryAbilityInfo
 * @tc.desc: 1. add info to the data manager
 *           2. query data then verify
 */
HWTEST_F(BmsDataMgrTest, QueryAbilityInfo_0300, Function | SmallTest | Level0)
{
    Want want;
    ElementName element1;
    EXPECT_EQ("///", element1.GetURI());

    element1.SetDeviceID(DEVICE_ID);
    EXPECT_EQ(DEVICE_ID, element1.GetDeviceID());

    element1.SetBundleName(BUNDLE_NAME);
    EXPECT_EQ(BUNDLE_NAME, element1.GetBundleName());

    element1.SetAbilityName(ABILITY_NAME);
    EXPECT_EQ(ABILITY_NAME, element1.GetAbilityName());
    EXPECT_EQ(DEVICE_ID + "/" + BUNDLE_NAME + "//" + ABILITY_NAME, element1.GetURI());

    ElementName element2(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    EXPECT_EQ(DEVICE_ID + "/" + BUNDLE_NAME + "//" + ABILITY_NAME, element2.GetURI());

    bool equal = (element2 == element1);
    EXPECT_TRUE(equal);

    Parcel parcel;
    parcel.WriteParcelable(&element1);
    std::unique_ptr<ElementName> newElement;
    newElement.reset(parcel.ReadParcelable<ElementName>());
    EXPECT_EQ(newElement->GetDeviceID(), element1.GetDeviceID());
    EXPECT_EQ(newElement->GetBundleName(), element1.GetBundleName());
    EXPECT_EQ(newElement->GetAbilityName(), element1.GetAbilityName());

    want.SetElement(element1);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AbilityInfo abilityInfo;
    bool ret = dataMgr->QueryAbilityInfo(want, 0, 0, abilityInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetApplicationInfo_0100
 * @tc.name: GetApplicationInfo
 * @tc.desc: 1. add info to the data manager
 *           2. query data then verify
 */
HWTEST_F(BmsDataMgrTest, GetApplicationInfo_0100, Function | SmallTest | Level0)
{
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;

    InnerBundleInfo info1;
    BundleInfo bundleInfo1;
    bundleInfo1.name = BUNDLE_NAME;
    bundleInfo1.applicationInfo.name = APP_NAME;
    bundleInfo1.applicationInfo.bundleName = BUNDLE_NAME;
    ApplicationInfo applicationInfo1;
    applicationInfo1.name = BUNDLE_NAME;
    applicationInfo1.bundleName = BUNDLE_NAME;
    info1.SetBaseBundleInfo(bundleInfo1);
    info1.SetBaseApplicationInfo(applicationInfo1);
    info1.AddInnerBundleUserInfo(innerBundleUserInfo);

    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(USERID);

    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info1);

    ApplicationInfo appInfo;
    bool ret3 = dataMgr->GetApplicationInfo(APP_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, appInfo);
    std::string name = appInfo.name;
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
    EXPECT_EQ(name, APP_NAME);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: GetApplicationInfo_0200
 * @tc.name: GetApplicationInfo
 * @tc.desc: 1. add info to the data manager
 *           2. query data then verify
 */
HWTEST_F(BmsDataMgrTest, GetApplicationInfo_0200, Function | SmallTest | Level0)
{
    ApplicationInfo appInfo;
    appInfo.name = APP_NAME;
    appInfo.bundleName = BUNDLE_NAME;
    appInfo.deviceId = DEVICE_ID;

    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(USERID);

    ApplicationInfo appInfo3;
    bool ret = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, appInfo3);
    EXPECT_FALSE(ret);

    EXPECT_NE(appInfo.name, appInfo3.name);
    EXPECT_NE(appInfo.bundleName, appInfo3.bundleName);
    EXPECT_NE(appInfo.deviceId, appInfo3.deviceId);
}

/**
 * @tc.number: BundleStateStorage_0100
 * @tc.name: Test DeleteBundleState, a param is error
 * @tc.desc: 1.Test the DeleteBundleState of BundleStateStorage
*/
HWTEST_F(BmsDataMgrTest, BundleStateStorage_0100, Function | SmallTest | Level0)
{
    BundleStateStorage bundleStateStorage;
    bool ret = bundleStateStorage.DeleteBundleState("", USERID);
    EXPECT_EQ(ret, false);
    ret = bundleStateStorage.DeleteBundleState(BUNDLE_NAME, -1);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleStateStorage_0200
 * @tc.name: Test GetBundleStateStorage, a param is error
 * @tc.desc: 1.Test the GetBundleStateStorage of BundleStateStorage
*/
HWTEST_F(BmsDataMgrTest, BundleStateStorage_0200, Function | SmallTest | Level0)
{
    BundleStateStorage bundleStateStorage;
    BundleUserInfo bundleUserInfo;
    bundleStateStorage.GetBundleStateStorage(BUNDLE_NAME, USERID, bundleUserInfo);
    bool ret = bundleStateStorage.GetBundleStateStorage(
        "", USERID, bundleUserInfo);
    EXPECT_EQ(ret, false);
    ret = bundleStateStorage.GetBundleStateStorage(
        BUNDLE_NAME, -1, bundleUserInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: AbilityManager_0100
 * @tc.name: Test GetBundleStateStorage, a param is error
 * @tc.desc: 1.Test the GetBundleStateStorage of BundleStateStorage
*/
HWTEST_F(BmsDataMgrTest, AbilityManager_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    bool res = AbilityManagerHelper::UninstallApplicationProcesses("", 0);
    EXPECT_EQ(res, true);
#endif
}

/**
 * @tc.number: AbilityManager_0200
 * @tc.name: test IsRunning
 * @tc.desc: 1.test IsRunning of AbilityManagerHelper
 */
HWTEST_F(BmsDataMgrTest, AbilityManager_0200, Function | SmallTest | Level0)
{
    AbilityManagerHelper helper;
    int failed = -1;
    int ret = helper.IsRunning("");
    EXPECT_EQ(ret, failed);
    ret = helper.IsRunning("com.ohos.tes1");
    EXPECT_EQ(ret, failed);
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
/**
 * @tc.number: GetFreeInstallModules_0100
 * @tc.name: test GetFreeInstallModules
 * @tc.desc: 1.test GetFreeInstallModules of BundleDataMgr
 */
HWTEST_F(BmsDataMgrTest, GetFreeInstallModules_0100, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    std::map<std::string, std::vector<std::string>> freeInstallModules;
    bool ret = dataMgr->GetFreeInstallModules(freeInstallModules);
    EXPECT_EQ(ret, false);
    InnerBundleInfo info1;
    dataMgr->bundleInfos_.try_emplace("com.ohos.tes1", info1);
    ret = dataMgr->GetFreeInstallModules(freeInstallModules);
    EXPECT_EQ(ret, false);
    freeInstallModules.clear();
    InnerBundleInfo info2;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.installationFree = true;
    innerModuleInfo.moduleName = "entry";
    innerModuleInfos.try_emplace("module", innerModuleInfo);
    info2.innerModuleInfos_ = innerModuleInfos;
    dataMgr->bundleInfos_.try_emplace("com.ohos.tes2", info2);
    ret = dataMgr->GetFreeInstallModules(freeInstallModules);
    EXPECT_EQ(ret, true);
}
#endif

/**
 * @tc.number: InnerBundleInfo_0100
 * @tc.name: Test GetBundleStateStorage, a param is error
 * @tc.desc: 1.Test the GetBundleStateStorage of BundleStateStorage
*/
HWTEST_F(BmsDataMgrTest, InnerBundleInfo_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo newInfo;
    bool res = innerBundleInfo.AddModuleInfo(newInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: UpdateInnerBundleInfo_0001
 * @tc.name: UpdateInnerBundleInfo
 * @tc.desc: UpdateInnerBundleInfo, bundleName is empty
 */
HWTEST_F(BmsDataMgrTest, UpdateInnerBundleInfo_0001, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerBundleInfo info;
        bool ret = dataMgr->UpdateInnerBundleInfo(info);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: UpdateInnerBundleInfo_0002
 * @tc.name: UpdateInnerBundleInfo
 * @tc.desc: UpdateInnerBundleInfo, bundleInfos_ is empty
 */
HWTEST_F(BmsDataMgrTest, UpdateInnerBundleInfo_0002, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        ApplicationInfo applicationInfo;
        applicationInfo.bundleName = BUNDLE_NAME;
        InnerBundleInfo info;
        info.SetBaseApplicationInfo(applicationInfo);
        bool ret = dataMgr->UpdateInnerBundleInfo(info);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: UpdateInnerBundleInfo_0003
 * @tc.name: UpdateInnerBundleInfo
 * @tc.desc: 1. add info to the data manager
 *           2. UpdateInnerBundleInfo, bundleInfos_ is not empty
 */
HWTEST_F(BmsDataMgrTest, UpdateInnerBundleInfo_0003, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        BundleInfo bundleInfo;
        bundleInfo.name = BUNDLE_NAME;
        bundleInfo.applicationInfo.name = APP_NAME;
        ApplicationInfo applicationInfo;
        applicationInfo.name = BUNDLE_NAME;
        applicationInfo.deviceId = DEVICE_ID;
        applicationInfo.bundleName = BUNDLE_NAME;
        InnerBundleInfo info;
        info.SetBaseBundleInfo(bundleInfo);
        info.SetBaseApplicationInfo(applicationInfo);
        bool ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
        EXPECT_TRUE(ret);
        ret = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateInnerBundleInfo(info);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: UpdateInnerBundleInfo_0004
 * @tc.name: UpdateInnerBundleInfo
 * @tc.desc: 1. add info to the data manager
 *           2. UpdateInnerBundleInfo
 */
HWTEST_F(BmsDataMgrTest, UpdateInnerBundleInfo_0004, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        BundleInfo bundleInfo;
        bundleInfo.name = BUNDLE_NAME;
        bundleInfo.applicationInfo.name = APP_NAME;
        ApplicationInfo applicationInfo;
        applicationInfo.name = BUNDLE_NAME;
        applicationInfo.deviceId = DEVICE_ID;
        applicationInfo.bundleName = BUNDLE_NAME;
        applicationInfo.needAppDetail = false;
        InnerBundleInfo info;
        info.SetBaseBundleInfo(bundleInfo);
        info.SetBaseApplicationInfo(applicationInfo);
        bool ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
        EXPECT_TRUE(ret);
        ret = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, info, info);
        EXPECT_TRUE(ret);
        InnerBundleInfo newInfo = info;
        applicationInfo.needAppDetail = true;
        newInfo.SetBaseApplicationInfo(applicationInfo);
        ret = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, newInfo, info);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: UpdateInnerBundleInfo_0005
 * @tc.name: UpdateInnerBundleInfo
 * @tc.desc: 1. add info to the data manager
 *           2. UpdateInnerBundleInfo
 */
HWTEST_F(BmsDataMgrTest, UpdateInnerBundleInfo_0005, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        BundleInfo bundleInfo;
        bundleInfo.name = BUNDLE_NAME;
        bundleInfo.applicationInfo.name = APP_NAME;
        ApplicationInfo applicationInfo;
        applicationInfo.name = BUNDLE_NAME;
        applicationInfo.deviceId = DEVICE_ID;
        applicationInfo.bundleName = BUNDLE_NAME;
        applicationInfo.needAppDetail = true;
        InnerBundleInfo info;
        info.SetBaseBundleInfo(bundleInfo);
        info.SetBaseApplicationInfo(applicationInfo);
        bool ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
        EXPECT_TRUE(ret);
        ret = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, info, info);
        EXPECT_TRUE(ret);
        InnerBundleInfo newInfo = info;
        applicationInfo.needAppDetail = false;
        newInfo.SetBaseApplicationInfo(applicationInfo);
        ret = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, newInfo, info);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: UpdateInnerBundleInfo_0006
 * @tc.name: UpdateInnerBundleInfo
 * @tc.desc: 1. add info to the data manager
 *           2. UpdateInnerBundleInfo
 */
HWTEST_F(BmsDataMgrTest, UpdateInnerBundleInfo_0006, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        BundleInfo bundleInfo;
        bundleInfo.name = BUNDLE_NAME;
        bundleInfo.applicationInfo.name = APP_NAME;
        ApplicationInfo applicationInfo;
        applicationInfo.name = BUNDLE_NAME;
        applicationInfo.deviceId = DEVICE_ID;
        applicationInfo.bundleName = BUNDLE_NAME;
        InnerBundleInfo info;
        info.SetBaseBundleInfo(bundleInfo);
        info.SetBaseApplicationInfo(applicationInfo);
        bool ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
        EXPECT_TRUE(ret);
        ret = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
        EXPECT_TRUE(ret);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_SUCCESS);
        EXPECT_TRUE(ret);
        InnerBundleInfo newInfo = info;
        newInfo.baseApplicationInfo_->multiAppMode.multiAppModeType = MultiAppModeType::MULTI_INSTANCE;
        newInfo.baseApplicationInfo_->multiAppMode.maxCount = 100;
        newInfo.baseApplicationInfo_->multiProjects = true;
        ret = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, newInfo, info);
        EXPECT_TRUE(ret);
        EXPECT_EQ(info.baseApplicationInfo_->multiAppMode.multiAppModeType,
            newInfo.baseApplicationInfo_->multiAppMode.multiAppModeType);
        EXPECT_EQ(info.baseApplicationInfo_->multiAppMode.maxCount,
            newInfo.baseApplicationInfo_->multiAppMode.maxCount);
        EXPECT_EQ(info.baseApplicationInfo_->multiProjects, newInfo.baseApplicationInfo_->multiProjects);
        ret = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: AddInnerBundleInfo_0001
 * @tc.name: AddInnerBundleInfo
 * @tc.desc: AddInnerBundleInfo, needAppDetail is true
 */
HWTEST_F(BmsDataMgrTest, AddInnerBundleInfo_0001, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.needAppDetail = true;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: AddInnerBundleInfo_0002
 * @tc.name: AddInnerBundleInfo
 * @tc.desc: AddInnerBundleInfo, needAppDetail is false
 */
HWTEST_F(BmsDataMgrTest, AddInnerBundleInfo_0002, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.needAppDetail = false;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: AddInnerBundleInfo_0003
 * @tc.name: AddInnerBundleInfo
 * @tc.desc: AddInnerBundleInfo, needAppDetail is false
 */
HWTEST_F(BmsDataMgrTest, AddInnerBundleInfo_0003, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.needAppDetail = false;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: GetMatchLauncherAbilityInfos_0001
 * @tc.name: GetMatchLauncherAbilityInfos
 * @tc.desc: GetMatchLauncherAbilityInfos, needAppDetail is false
 */
HWTEST_F(BmsDataMgrTest, GetMatchLauncherAbilityInfos_0001, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.needAppDetail = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    BundleUserInfo userInfo;
    userInfo.userId = 100;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo = userInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    Skill skill;
    skill.actions = {ACTION};
    skill.entities = {ENTITY};
    std::vector<Skill> skills;
    skills.emplace_back(skill);
    innerBundleInfo.InsertSkillInfo(BUNDLE_NAME, skills);
    AbilityInfo abilityInfo;
    abilityInfo.name = BUNDLE_NAME;
    abilityInfo.type = AbilityType::PAGE;
    innerBundleInfo.InsertAbilitiesInfo(BUNDLE_NAME, abilityInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.entryAbilityKey = BUNDLE_NAME;
    moduleInfo.isEntry = true;
    innerBundleInfo.innerModuleInfos_.try_emplace(BUNDLE_NAME, moduleInfo);

    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::AAFwk::Want::ACTION_HOME);
    want.AddEntity(OHOS::AAFwk::Want::ENTITY_HOME);
    std::vector<AbilityInfo> abilityInfos;
    int64_t installTime = 0;
    dataMgr->GetMatchLauncherAbilityInfos(want, innerBundleInfo, abilityInfos, installTime, Constants::ANY_USERID);
    EXPECT_FALSE(abilityInfos.empty());

    applicationInfo.needAppDetail = true;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    dataMgr->GetMatchLauncherAbilityInfos(want, innerBundleInfo, abilityInfos, installTime, Constants::ANY_USERID);
    EXPECT_FALSE(abilityInfos.empty());
}

/**
 * @tc.number: GetMatchLauncherAbilityInfos_0002
 * @tc.name: GetMatchLauncherAbilityInfos
 * @tc.desc: GetMatchLauncherAbilityInfos, needAppDetail is true
 */
HWTEST_F(BmsDataMgrTest, GetMatchLauncherAbilityInfos_0002, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.needAppDetail = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    BundleUserInfo userInfo;
    userInfo.userId = 100;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo = userInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::AAFwk::Want::ACTION_HOME);
    want.AddEntity(OHOS::AAFwk::Want::ENTITY_HOME);
    std::vector<AbilityInfo> abilityInfos;
    int64_t installTime = 0;
    dataMgr->GetMatchLauncherAbilityInfos(want, innerBundleInfo, abilityInfos, installTime, Constants::ANY_USERID);
    EXPECT_TRUE(abilityInfos.empty());

    applicationInfo.needAppDetail = true;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    dataMgr->GetMatchLauncherAbilityInfos(want, innerBundleInfo, abilityInfos, installTime, Constants::ANY_USERID);
    EXPECT_TRUE(abilityInfos.empty());

    AbilityInfo abilityInfo;
    abilityInfo.name = ServiceConstants::APP_DETAIL_ABILITY;
    innerBundleInfo.InsertAbilitiesInfo(BUNDLE_NAME, abilityInfo);
    dataMgr->GetMatchLauncherAbilityInfos(want, innerBundleInfo, abilityInfos, installTime, Constants::ANY_USERID);
    EXPECT_FALSE(abilityInfos.empty());

    abilityInfos.clear();
    innerBundleInfo.SetIsNewVersion(true);
    dataMgr->GetMatchLauncherAbilityInfos(want, innerBundleInfo, abilityInfos, installTime, Constants::ANY_USERID);
    EXPECT_FALSE(abilityInfos.empty());
}

/**
 * @tc.number: AddAppDetailAbilityInfo_0001
 * @tc.name: AddAppDetailAbilityInfo
 * @tc.desc: AddAppDetailAbilityInfo, needAppDetail is true
 */
HWTEST_F(BmsDataMgrTest, AddAppDetailAbilityInfo_0001, Function | SmallTest | Level0)
{
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.iconId = 1;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->AddAppDetailAbilityInfo(innerBundleInfo);
    auto ability = innerBundleInfo.FindAbilityInfo(Constants::EMPTY_STRING,
        ServiceConstants::APP_DETAIL_ABILITY, USERID);
    if (ability) {
        EXPECT_EQ(ability->name, ServiceConstants::APP_DETAIL_ABILITY);
    }

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = BUNDLE_NAME;
    innerModuleInfo.moduleName = BUNDLE_NAME;
    innerBundleInfo.InsertInnerModuleInfo(BUNDLE_NAME, innerModuleInfo);
    applicationInfo.iconId = 0;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetCurrentModulePackage(BUNDLE_NAME);
    innerBundleInfo.SetIsNewVersion(true);
    dataMgr->AddAppDetailAbilityInfo(innerBundleInfo);

    ability = innerBundleInfo.FindAbilityInfo(BUNDLE_NAME, ServiceConstants::APP_DETAIL_ABILITY, USERID);
    if (ability) {
        EXPECT_EQ(ability->name, ServiceConstants::APP_DETAIL_ABILITY);
    }
}

/**
 * @tc.number: ModifyLauncherAbilityInfo_0001
 * @tc.name: ModifyLauncherAbilityInfo
 * @tc.desc: 1. ModifyLauncherAbilityInfo, labelId is equal 0
 *           2. stage mode
 */
HWTEST_F(BmsDataMgrTest, ModifyLauncherAbilityInfo_0001, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr) {
        AbilityInfo abilityInfo;
        abilityInfo.applicationInfo.label = "$string:label";
        abilityInfo.applicationInfo.labelId = 1111;
        abilityInfo.label = "";
        abilityInfo.labelId = 0;
        dataMgr->ModifyLauncherAbilityInfo(true, abilityInfo);
        EXPECT_EQ(abilityInfo.label, abilityInfo.applicationInfo.label);
        EXPECT_EQ(abilityInfo.labelId, abilityInfo.applicationInfo.labelId);
    }
}

/**
 * @tc.number: ModifyLauncherAbilityInfo_0002
 * @tc.name: ModifyLauncherAbilityInfo
 * @tc.desc: 1. ModifyLauncherAbilityInfo, labelId is not equal 0
 *           2. stage mode
 */
HWTEST_F(BmsDataMgrTest, ModifyLauncherAbilityInfo_0002, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr) {
        AbilityInfo abilityInfo;
        abilityInfo.applicationInfo.label = "$string:label";
        abilityInfo.applicationInfo.labelId = 1111;
        abilityInfo.label = "#string:aaa";
        abilityInfo.labelId = 2222;
        dataMgr->ModifyLauncherAbilityInfo(true, abilityInfo);
        EXPECT_NE(abilityInfo.label, abilityInfo.applicationInfo.label);
        EXPECT_NE(abilityInfo.labelId, abilityInfo.applicationInfo.labelId);
    }
}

/**
 * @tc.number: ModifyLauncherAbilityInfo_0003
 * @tc.name: ModifyLauncherAbilityInfo
 * @tc.desc: 1. ModifyLauncherAbilityInfo, labelId is equal 0
 *           2. FA mode
 */
HWTEST_F(BmsDataMgrTest, ModifyLauncherAbilityInfo_0003, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr) {
        AbilityInfo abilityInfo;
        abilityInfo.bundleName = "test";
        abilityInfo.applicationInfo.label = "$string:label";
        abilityInfo.applicationInfo.labelId = 1111;
        abilityInfo.label = "";
        abilityInfo.labelId = 0;
        dataMgr->ModifyLauncherAbilityInfo(false, abilityInfo);
        EXPECT_EQ(abilityInfo.applicationInfo.label, abilityInfo.bundleName);
        EXPECT_EQ(abilityInfo.label, abilityInfo.bundleName);
    }
}

/**
 * @tc.number: ModifyLauncherAbilityInfo_0004
 * @tc.name: ModifyLauncherAbilityInfo
 * @tc.desc: 1. ModifyLauncherAbilityInfo, labelId is not equal 0
 *           2. FA mode
 */
HWTEST_F(BmsDataMgrTest, ModifyLauncherAbilityInfo_0004, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr) {
        AbilityInfo abilityInfo;
        abilityInfo.applicationInfo.label = "$string:label";
        abilityInfo.applicationInfo.labelId = 1111;
        abilityInfo.label = "#string:aaa";
        abilityInfo.labelId = 2222;
        dataMgr->ModifyLauncherAbilityInfo(false, abilityInfo);
        EXPECT_NE(abilityInfo.label, abilityInfo.applicationInfo.label);
        EXPECT_NE(abilityInfo.labelId, abilityInfo.applicationInfo.labelId);
    }
}

/**
 * @tc.number: ModifyLauncherAbilityInfo_0005
 * @tc.name: ModifyLauncherAbilityInfo
 * @tc.desc: 1. ModifyLauncherAbilityInfo, iconId is equal 0
 *           2. stage mode
 */
HWTEST_F(BmsDataMgrTest, ModifyLauncherAbilityInfo_0005, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr) {
        AbilityInfo abilityInfo;
        abilityInfo.iconId = 0;
        abilityInfo.applicationInfo.iconId = 1111;

        dataMgr->ModifyLauncherAbilityInfo(true, abilityInfo);
        EXPECT_EQ(abilityInfo.iconId, abilityInfo.applicationInfo.iconId);
    }
}

/**
 * @tc.number: ModifyLauncherAbilityInfo_0006
 * @tc.name: ModifyLauncherAbilityInfo
 * @tc.desc: 1. ModifyLauncherAbilityInfo, iconId is not equal 0
 *           2. stage mode
 */
HWTEST_F(BmsDataMgrTest, ModifyLauncherAbilityInfo_0006, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr) {
        AbilityInfo abilityInfo;
        abilityInfo.iconId = ICON_ID;
        dataMgr->ModifyLauncherAbilityInfo(true, abilityInfo);
        EXPECT_EQ(abilityInfo.iconId, ICON_ID);
    }
}

/**
 * @tc.number: ModifyLauncherAbilityInfo_0007
 * @tc.name: ModifyLauncherAbilityInfo
 * @tc.desc: 1. ModifyLauncherAbilityInfo, iconId is equal 0
 *           2. FA mode
 */
HWTEST_F(BmsDataMgrTest, ModifyLauncherAbilityInfo_0007, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr) {
        AbilityInfo abilityInfo;
        abilityInfo.iconId = 0;

        ApplicationInfo applicationInfo;
        applicationInfo.iconId = 222;
        abilityInfo.applicationInfo = applicationInfo;

        dataMgr->ModifyLauncherAbilityInfo(false, abilityInfo);
        EXPECT_EQ(abilityInfo.iconId, applicationInfo.iconId);
    }
}

/**
 * @tc.number: ModifyLauncherAbilityInfo_0008
 * @tc.name: ModifyLauncherAbilityInfo
 * @tc.desc: 1. ModifyLauncherAbilityInfo, iconId is not equal 0
 *           2. FA mode
 */
HWTEST_F(BmsDataMgrTest, ModifyLauncherAbilityInfo_0008, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr) {
        AbilityInfo abilityInfo;
        abilityInfo.iconId = ICON_ID;
        dataMgr->ModifyLauncherAbilityInfo(false, abilityInfo);
        EXPECT_EQ(abilityInfo.iconId, ICON_ID);
    }
}

/**
 * @tc.number: GetProxyDataInfos_0001
 * @tc.name: GetProxyDataInfos
 * @tc.desc: GetProxyDataInfos, return is true
 */
HWTEST_F(BmsDataMgrTest, GetProxyDataInfos_0001, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME;
    innerBundleInfo.InsertInnerModuleInfo(BUNDLE_NAME, innerModuleInfo);
    std::vector<ProxyData> proxyDatas;

    auto res = innerBundleInfo.GetProxyDataInfos(EMPTY_STRING, proxyDatas);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetProxyDataInfos_0002
 * @tc.name: GetProxyDataInfos
 * @tc.desc: GetProxyDataInfos, return is ERR_OK
 */
HWTEST_F(BmsDataMgrTest, GetProxyDataInfos_0002, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    std::vector<ProxyData> proxyDatas;
    auto res = innerBundleInfo.GetProxyDataInfos(EMPTY_STRING, proxyDatas);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetProxyDataInfos_0003
 * @tc.name: GetProxyDataInfos
 * @tc.desc: GetProxyDataInfos, return is ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST
 */
HWTEST_F(BmsDataMgrTest, GetProxyDataInfos_0003, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME;
    innerBundleInfo.InsertInnerModuleInfo(BUNDLE_NAME, innerModuleInfo);
    std::vector<ProxyData> proxyDatas;

    auto res = innerBundleInfo.GetProxyDataInfos(BUNDLE_NAME, proxyDatas);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: GetIsolationMode_0001
 * @tc.name: GetIsolationMode
 * @tc.desc: GetIsolationMode
 */
HWTEST_F(BmsDataMgrTest, GetIsolationMode_0001, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    IsolationMode res = innerBundleInfo.GetIsolationMode("");
    EXPECT_EQ(res, IsolationMode::NONISOLATION_FIRST);
}

/**
 * @tc.number: GetIsolationMode_0002
 * @tc.name: GetIsolationMode
 * @tc.desc: GetIsolationMode
 */
HWTEST_F(BmsDataMgrTest, GetIsolationMode_0002, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    IsolationMode res = innerBundleInfo.GetIsolationMode(ISOLATION_ONLY);
    EXPECT_EQ(res, IsolationMode::ISOLATION_ONLY);
}

/**
 * @tc.number: MatchPrivateType_0001
 * @tc.name: MatchPrivateType
 * @tc.desc: 1. MatchPrivateType
 */
HWTEST_F(BmsDataMgrTest, MatchPrivateType_0001, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    Want want;
    want.SetUri("/test/test.book");
    std::vector<std::string> supportExtNames;
    supportExtNames.emplace_back("book");
    std::vector<std::string> supportMimeTypes;
    std::vector<std::string> mimeTypes;
    MimeTypeMgr::GetMimeTypeByUri(want.GetUriString(), mimeTypes);
    bool ret = dataMgr->MatchPrivateType(want, supportExtNames, supportMimeTypes, mimeTypes);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: MatchPrivateType_0002
 * @tc.name: MatchPrivateType
 * @tc.desc: 1. MatchPrivateType
 */
HWTEST_F(BmsDataMgrTest, MatchPrivateType_0002, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    Want want;
    want.SetUri("/test/test.book");
    std::vector<std::string> supportExtNames;
    std::vector<std::string> supportMimeTypes;
    std::vector<std::string> mimeTypes;
    MimeTypeMgr::GetMimeTypeByUri(want.GetUriString(), mimeTypes);
    bool ret = dataMgr->MatchPrivateType(want, supportExtNames, supportMimeTypes, mimeTypes);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MatchPrivateType_0003
 * @tc.name: MatchPrivateType
 * @tc.desc: 1. MatchPrivateType
 */
HWTEST_F(BmsDataMgrTest, MatchPrivateType_0003, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    Want want;
    want.SetUri("/test/test");
    std::vector<std::string> supportExtNames;
    std::vector<std::string> supportMimeTypes;
    std::vector<std::string> mimeTypes;
    MimeTypeMgr::GetMimeTypeByUri(want.GetUriString(), mimeTypes);
    bool ret = dataMgr->MatchPrivateType(want, supportExtNames, supportMimeTypes, mimeTypes);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MatchPrivateType_0004
 * @tc.name: MatchPrivateType
 * @tc.desc: 1. MatchPrivateType
 */
HWTEST_F(BmsDataMgrTest, MatchPrivateType_0004, Function | SmallTest | Level0)
{
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    Want want;
    want.SetUri("/test/test.jpg");
    std::vector<std::string> supportExtNames;
    std::vector<std::string> supportMimeTypes;
    supportMimeTypes.emplace_back("image/jpeg");
    std::vector<std::string> mimeTypes;
    MimeTypeMgr::GetMimeTypeByUri(want.GetUriString(), mimeTypes);
    bool ret = dataMgr->MatchPrivateType(want, supportExtNames, supportMimeTypes, mimeTypes);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: MatchShare_0100
 * @tc.name: test MatchShare
 * @tc.desc: 1.test match share based on want and skill
 */
HWTEST_F(BmsDataMgrTest, MatchShare_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction(OHOS::AAFwk::Want::ACTION_HOME);
    want.AddEntity(OHOS::AAFwk::Want::ENTITY_HOME);
    want.SetElementName("", BUNDLE_NAME, "", MODULE_NAME);
    std::vector<Skill> skills;
    bool result = dataMgr->MatchShare(want, skills);
    EXPECT_EQ(result, false);
    want.SetAction(SHARE_ACTION_VALUE);
    result = dataMgr->MatchShare(want, skills);
    EXPECT_EQ(result, false);
    struct Skill skill;
    skills.emplace_back(skill);
    result = dataMgr->MatchShare(want, skills);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: MatchShare_0200
 * @tc.name: test MatchShare
 * @tc.desc: 1.test match share based on want and skill
 */
HWTEST_F(BmsDataMgrTest, MatchShare_0200, Function | SmallTest | Level1)
{
    std::vector<Skill> skills = CreateSkillsForMatchShareTest();

    std::map<std::string, int32_t> utds1 = {{"general.png", 2}};
    EXPECT_EQ(MatchShare(utds1, skills), true);

    std::map<std::string, int32_t> utds2 = {{"general.png", 3}};
    EXPECT_EQ(MatchShare(utds2, skills), true);
    
    std::map<std::string, int32_t> utds3 = {{"general.png", 4}};
    EXPECT_EQ(MatchShare(utds3, skills), false);

    std::map<std::string, int32_t> utds4 = {{"general.jpeg", 5}};
    EXPECT_EQ(MatchShare(utds4, skills), true);

    std::map<std::string, int32_t> utds5 = {{"general.jpeg", 6}};
    EXPECT_EQ(MatchShare(utds5, skills), true);

    std::map<std::string, int32_t> utds6 = {{"general.jpeg", 7}};
    EXPECT_EQ(MatchShare(utds6, skills), false);

    std::map<std::string, int32_t> utds7 = {{"general.png", 3}, {"general.image", 2}};
    EXPECT_EQ(MatchShare(utds7, skills), true);

    std::map<std::string, int32_t> utds8 = {{"general.png", 3}, {"general.image", 3}};
    EXPECT_EQ(MatchShare(utds8, skills), true);

    std::map<std::string, int32_t> utds9 = {{"general.png", 3}, {"general.image", 4}};
    EXPECT_EQ(MatchShare(utds9, skills), false);

    std::map<std::string, int32_t> utds10 = {{"general.png", 2}, {"general.image", 4}};
    EXPECT_EQ(MatchShare(utds10, skills), true);

    std::map<std::string, int32_t> utds11 = {{"general.png", 1}, {"general.image", 6}};
    EXPECT_EQ(MatchShare(utds11, skills), false);

    std::map<std::string, int32_t> utds12 = {{"general.image", 6}};
    EXPECT_EQ(MatchShare(utds12, skills), true);

    std::map<std::string, int32_t> utds13 = {{"general.media", 8}};
    EXPECT_EQ(MatchShare(utds13, skills), true);

    std::map<std::string, int32_t> utds14 = {{"general.media", 9}};
    EXPECT_EQ(MatchShare(utds14, skills), true);

    std::map<std::string, int32_t> utds15 = {{"general.media", 10}};
    EXPECT_EQ(MatchShare(utds15, skills), false);

    std::map<std::string, int32_t> utds16 = {{"general.png", 1}, {"general.media", 9}};
    EXPECT_EQ(MatchShare(utds16, skills), false);

    std::map<std::string, int32_t> utds17 = {{"general.png", 1}, {"general.media", 8}};
    EXPECT_EQ(MatchShare(utds17, skills), true);

    std::map<std::string, int32_t> utds18 = {{"general.image", 1}, {"general.media", 8}};
    EXPECT_EQ(MatchShare(utds18, skills), true);

    std::map<std::string, int32_t> utds19 = {{"general.png", 2}, {"general.image", 1}, {"general.media", 7}};
    EXPECT_EQ(MatchShare(utds19, skills), false);
    
    std::map<std::string, int32_t> utds20 = {{"general.png", 3}, {"general.image", 3}, {"general.media", 3}};
    EXPECT_EQ(MatchShare(utds20, skills), true);

    std::map<std::string, int32_t> utds21 = {{"general.png", 1}, {"general.image", 4}, {"general.media", 4}};
    EXPECT_EQ(MatchShare(utds21, skills), true);

    std::map<std::string, int32_t> utds22 = {{"general.jpeg", 9}};
    EXPECT_EQ(MatchShare(utds22, skills), false);

    std::map<std::string, int32_t> utds23 = {{"general.text", 3}};
    EXPECT_EQ(MatchShare(utds23, skills), false);
}

/**
 * @tc.number: MatchUtd_0100
 * @tc.name: test MatchUtd
 * @tc.desc: 1.test match utd
 */
HWTEST_F(BmsDataMgrTest, MatchUtd_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    struct Skill skill;
    std::string utd = "";
    int32_t count = 0;
    bool result = dataMgr->MatchUtd(skill, utd, count);
    EXPECT_EQ(result, false);

    SkillUri skillUri;
    skillUri.type = "image/*";
    skill.uris.emplace_back(skillUri);
    result = dataMgr->MatchUtd(skill, utd, count);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: MatchUtd_0200
 * @tc.name: test MatchUtd
 * @tc.desc: 1.test match utd without count
 */
HWTEST_F(BmsDataMgrTest, MatchUtd_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string skillUtd = "";
    std::string wantUtd = "";
    bool result = dataMgr->MatchUtd(skillUtd, wantUtd);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: MatchTypeWithUtd_0100
 * @tc.name: test MatchTypeWithUtd
 * @tc.desc: 1.test match type with utd
 */
HWTEST_F(BmsDataMgrTest, MatchTypeWithUtd_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    struct Skill skill;
    std::string mimeType = "";
    std::string wantUtd = "";
    bool ret = dataMgr->MatchTypeWithUtd(wantUtd, mimeType);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: FindSkillsContainShareAction_0200
 * @tc.name: test FindSkillsContainShareAction
 * @tc.desc: 1.test find skills that include sharing action
 */
HWTEST_F(BmsDataMgrTest, FindSkillsContainShareAction_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<Skill> skills;
    auto result = dataMgr->FindSkillsContainShareAction(skills);
    EXPECT_EQ(result.empty(), true);

    struct Skill skill;
    skill.actions.emplace_back(SHARE_ACTION_VALUE);
    skills.emplace_back(skill);
    result = dataMgr->FindSkillsContainShareAction(skills);
    EXPECT_EQ(result.empty(), false);
}

/**
 * @tc.number: LoadDataFromPersistentStorage_0100
 * @tc.name: test CompatibleOldBundleStateInKvDb
 * @tc.desc: 1.compatible old bundle status in Kvdb
 */
HWTEST_F(BmsDataMgrTest, LoadDataFromPersistentStorage_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    auto ret = dataMgr->LoadDataFromPersistentStorage();
    dataMgr->CompatibleOldBundleStateInKvDb();
    std::map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace("", innerBundleInfo);
    dataMgr->bundleInfos_.swap(infos);
    dataMgr->CompatibleOldBundleStateInKvDb();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: GetMatchLauncherAbilityInfosForCloneInfos_0100
 * @tc.name: test GetMatchLauncherAbilityInfosForCloneInfos
 * @tc.desc: 1.obtain matching launcher ability information for clone information
 */
HWTEST_F(BmsDataMgrTest, GetMatchLauncherAbilityInfosForCloneInfos_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.iconId = 0;
    ApplicationInfo applicationInfo;
    applicationInfo.iconId = 200;
    abilityInfo.applicationInfo = applicationInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    std::vector<AbilityInfo> abilityInfos;
    dataMgr->GetMatchLauncherAbilityInfosForCloneInfos(innerBundleInfo, abilityInfo, innerBundleUserInfo, abilityInfos);
    EXPECT_EQ(abilityInfos.empty(), true);
    InnerBundleCloneInfo cloneInfo;
    innerBundleUserInfo.cloneInfos.emplace("", cloneInfo);
    dataMgr->GetMatchLauncherAbilityInfosForCloneInfos(innerBundleInfo, abilityInfo, innerBundleUserInfo, abilityInfos);
    EXPECT_EQ(abilityInfos.empty(), false);
}

/**
 * @tc.number: ModifyBundleInfoByCloneInfo_0100
 * @tc.name: test ModifyBundleInfoByCloneInfo
 * @tc.desc: 1.modify bundle information based on clone information
 */
HWTEST_F(BmsDataMgrTest, ModifyBundleInfoByCloneInfo_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleCloneInfo cloneInfo;
    BundleInfo bundleInfo;
    dataMgr->ModifyBundleInfoByCloneInfo(cloneInfo, bundleInfo);
    bundleInfo.applicationInfo.bundleName = BUNDLE_NAME;
    dataMgr->ModifyBundleInfoByCloneInfo(cloneInfo, bundleInfo);
    EXPECT_EQ(bundleInfo.uid, cloneInfo.uid);
}

/**
 * @tc.number: ModifyApplicationInfoByCloneInfo_0100
 * @tc.name: test ModifyApplicationInfoByCloneInfo
 * @tc.desc: 1.modify application information based on clone information
 */
HWTEST_F(BmsDataMgrTest, ModifyApplicationInfoByCloneInfo_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleCloneInfo cloneInfo;
    ApplicationInfo applicationInfo;
    dataMgr->ModifyApplicationInfoByCloneInfo(cloneInfo, applicationInfo);
    EXPECT_EQ(applicationInfo.enabled, cloneInfo.enabled);
}

/**
 * @tc.number: UpateExtResources_0100
 * @tc.name: test UpateExtResources
 * @tc.desc: 1.test update external resources
 */
HWTEST_F(BmsDataMgrTest, UpateExtResources_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    std::vector<ExtendResourceInfo> extendResourceInfos;
    bool ret = dataMgr->UpateExtResources(bundleName, extendResourceInfos);
    EXPECT_EQ(ret, false);

    std::map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(BUNDLE_NAME, innerBundleInfo);
    dataMgr->bundleInfos_.swap(infos);
    ret = dataMgr->UpateExtResources(BUNDLE_NAME, extendResourceInfos);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: RemoveExtResources_0100
 * @tc.name: test RemoveExtResources
 * @tc.desc: 1.test remove external resources
 */
HWTEST_F(BmsDataMgrTest, RemoveExtResources_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    std::vector<std::string> moduleNames;
    bool ret = dataMgr->RemoveExtResources(bundleName, moduleNames);
    EXPECT_EQ(ret, false);
    std::map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(BUNDLE_NAME, innerBundleInfo);
    dataMgr->bundleInfos_.swap(infos);
    ret = dataMgr->RemoveExtResources(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: IsBundleExist_0100
 * @tc.name: test IsBundleExist
 * @tc.desc: 1.judge bundle exist
 */
HWTEST_F(BmsDataMgrTest, IsBundleExist_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    bool ret = dataMgr->IsBundleExist(bundleName);
    EXPECT_EQ(ret, false);

    std::map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(BUNDLE_NAME, innerBundleInfo);
    dataMgr->bundleInfos_.swap(infos);
    ret = dataMgr->IsBundleExist(BUNDLE_NAME);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: GetAllBundleStats_0100
 * @tc.name: test GetAllBundleStats
 * @tc.desc: 1.test get all bundle stats
 */
HWTEST_F(BmsDataMgrTest, GetAllBundleStats_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t userId = -1;
    std::vector<int64_t> bundleStats;
    bool ret = dataMgr->GetAllBundleStats(userId, bundleStats);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IsApplicationEnabled_0100
 * @tc.name: test IsApplicationEnabled
 * @tc.desc: 1.test enable application
 */
HWTEST_F(BmsDataMgrTest, IsApplicationEnabled_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    const std::string bundleName = BUNDLE_NAME;
    int32_t appIndex = 1;
    bool isEnabled = false;
    bool ret = dataMgr->IsApplicationEnabled(bundleName, appIndex, isEnabled);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: ImplicitQueryAllExtensionInfos_0100
 * @tc.name: test ImplicitQueryAllExtensionInfos
 * @tc.desc: 1.test implicit query of all extended information
 */
HWTEST_F(BmsDataMgrTest, ImplicitQueryAllExtensionInfos_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    uint32_t flags = 0;
    int32_t userId = 0;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    ErrCode ret = dataMgr->ImplicitQueryAllExtensionInfos(flags, userId, infos, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    appIndex = -1;
    ret = dataMgr->ImplicitQueryAllExtensionInfos(flags, userId, infos, appIndex);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: UpateCurDynamicIconModule_0100
 * @tc.name: test UpateCurDynamicIconModule
 * @tc.desc: 1.test update dynamic icon module
 */
HWTEST_F(BmsDataMgrTest, UpateCurDynamicIconModule_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    std::string moduleName = MODULE_NAME;
    bool ret = dataMgr->UpateCurDynamicIconModule(bundleName, moduleName);
    EXPECT_EQ(ret, false);
    ret = dataMgr->UpateCurDynamicIconModule(BUNDLE_NAME, moduleName);
    EXPECT_EQ(ret, false);
    std::map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(BUNDLE_NAME, innerBundleInfo);
    dataMgr->bundleInfos_.swap(infos);
    ret = dataMgr->UpateCurDynamicIconModule(BUNDLE_NAME, moduleName);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: GetInnerBundleInfoUsers_0100
 * @tc.name: test GetInnerBundleInfoUsers
 * @tc.desc: 1.test obtain internal bundle information for users
 */
HWTEST_F(BmsDataMgrTest, GetInnerBundleInfoUsers_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    std::set<int32_t> userIds;
    bool ret = dataMgr->GetInnerBundleInfoUsers(bundleName, userIds);
    EXPECT_EQ(ret, false);
    std::map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(BUNDLE_NAME, innerBundleInfo);
    dataMgr->bundleInfos_.swap(infos);
    ret = dataMgr->GetInnerBundleInfoUsers(BUNDLE_NAME, userIds);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: ResetAOTCompileStatus_0100
 * @tc.name: test ResetAOTCompileStatus
 * @tc.desc: 1.test reset AOT compilation status
 */
HWTEST_F(BmsDataMgrTest, ResetAOTCompileStatus_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    std::string moduleName = "";
    int32_t triggerMode = 0;
    ErrCode ret = dataMgr->ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    dataMgr->ResetAOTFlagsCommand(bundleName);
    std::map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(BUNDLE_NAME, innerBundleInfo);
    dataMgr->bundleInfos_.swap(infos);
    dataMgr->ResetAOTFlagsCommand(BUNDLE_NAME);
    ret = dataMgr->ResetAOTCompileStatus(BUNDLE_NAME, moduleName, triggerMode);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetAllExtensionInfos_0100
 * @tc.name: test GetAllExtensionInfos
 * @tc.desc: 1.test get all extended information
 */
HWTEST_F(BmsDataMgrTest, GetAllExtensionInfos_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    uint32_t flags = 0;
    int32_t userId = 0;
    InnerBundleInfo info;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    dataMgr->GetAllExtensionInfos(flags, userId, info, infos, appIndex);
    EXPECT_EQ(infos.empty(), true);
    ExtensionAbilityInfo extensionAbilityInfo;
    info.InsertExtensionInfo("", extensionAbilityInfo);
    dataMgr->GetAllExtensionInfos(flags, userId, info, infos, appIndex);
    EXPECT_EQ(infos.empty(), false);
    flags = 1;
    dataMgr->GetAllExtensionInfos(flags, userId, info, infos, appIndex);
    EXPECT_EQ(infos.empty(), false);
}

/**
 * @tc.number: GetOneExtensionInfosByExtensionTypeName_0100
 * @tc.name: test GetAllExtensionInfosForAms
 * @tc.desc: 1.test get all extended information
 */
HWTEST_F(BmsDataMgrTest, GetOneExtensionInfosByExtensionTypeName_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    uint32_t flags = 0;
    int32_t userId = 0;
    InnerBundleInfo info;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    std::string typeName = "";
    dataMgr->GetOneExtensionInfosByExtensionTypeName(typeName, flags, userId, info, infos, appIndex);
    EXPECT_EQ(infos.empty(), true);
    ExtensionAbilityInfo extensionAbilityInfo;
    info.InsertExtensionInfo("", extensionAbilityInfo);
    dataMgr->GetOneExtensionInfosByExtensionTypeName(typeName, flags, userId, info, infos, appIndex);
    EXPECT_EQ(infos.empty(), false);
    flags = 1;
    dataMgr->GetOneExtensionInfosByExtensionTypeName(typeName, flags, userId, info, infos, appIndex);
    EXPECT_EQ(infos.empty(), false);
}

/**
 * @tc.number: GetAppServiceHspBundleInfo_0100
 * @tc.name: test GetAppServiceHspBundleInfo
 * @tc.desc: 1.obtain information on the Hsp bundle for application service
 */
HWTEST_F(BmsDataMgrTest, GetAppServiceHspBundleInfo_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    BundleInfo bundleInfo;
    ErrCode ret = dataMgr->GetAppServiceHspBundleInfo(bundleName, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    std::map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(BUNDLE_NAME, innerBundleInfo);
    dataMgr->bundleInfos_.swap(infos);
    ret = dataMgr->GetAppServiceHspBundleInfo(BUNDLE_NAME, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: CanOpenLink_0100
 * @tc.name: test CanOpenLink
 * @tc.desc: 1.judge open link
 */
HWTEST_F(BmsDataMgrTest, CanOpenLink_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string link = "";
    bool canOpen = false;
    ErrCode ret = dataMgr->CanOpenLink(link, canOpen);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SCHEME_NOT_IN_QUERYSCHEMES);
}

/**
 * @tc.number:GetOdid_0100
 * @tc.name: test GetOdid
 * @tc.desc: 1.test get odid
 */
HWTEST_F(BmsDataMgrTest, GetOdid_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string odid = "";
    std::string developerId = "";
    dataMgr->GenerateOdid(developerId, odid);
    ErrCode ret = dataMgr->GetOdid(odid);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number:GetDeveloperIds_0100
 * @tc.name: test GetDeveloperIds
 * @tc.desc: 1.test get developer ids
 */
HWTEST_F(BmsDataMgrTest, GetDeveloperIds_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string appDistributionType = "";
    std::vector<std::string> developerIdList;
    int32_t userId = -1;
    ErrCode ret = dataMgr->GetDeveloperIds(appDistributionType, developerIdList, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    userId = Constants::ANY_USERID;
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    ret = dataMgr->GetDeveloperIds(appDistributionType, developerIdList, userId);
    EXPECT_EQ(ret, ERR_OK);
    dataMgr->bundleInfos_.clear();
    ret = dataMgr->GetDeveloperIds(appDistributionType, developerIdList, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number:AddCloneBundle_0100
 * @tc.name: test AddCloneBundle
 * @tc.desc: 1.test add clone bundle
 */
HWTEST_F(BmsDataMgrTest, AddCloneBundle_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    InnerBundleCloneInfo attr;
    ErrCode ret = dataMgr->AddCloneBundle(bundleName, attr);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    ret = dataMgr->AddCloneBundle(BUNDLE_NAME, attr);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number:RemoveCloneBundle_0100
 * @tc.name: test RemoveCloneBundle
 * @tc.desc: 1.test remove clone bundle
 */
HWTEST_F(BmsDataMgrTest, RemoveCloneBundle_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    int32_t userId = -1;
    int32_t appIndex = 0;
    ErrCode ret = dataMgr->RemoveCloneBundle(bundleName, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    ret = dataMgr->RemoveCloneBundle(BUNDLE_NAME, userId, appIndex);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number:QueryAbilityInfoByContinueType_0100
 * @tc.name: test QueryAbilityInfoByContinueType
 * @tc.desc: 1.query capability information by continuous type
 */
HWTEST_F(BmsDataMgrTest, QueryAbilityInfoByContinueType_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    std::string continueType = "";
    AbilityInfo abilityInfo;
    int32_t userId = -1;
    int32_t appIndex = 0;
    ErrCode ret = dataMgr->QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    userId = Constants::ANY_USERID;
    ret = dataMgr->QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo, userId, appIndex);
    EXPECT_NE(ret, ERR_OK);
    appIndex = 1;
    ret = dataMgr->QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo, userId, appIndex);
    EXPECT_NE(ret, ERR_OK);
    dataMgr->bundleInfos_.clear();
    ret = dataMgr->QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number:QueryAbilityInfoByContinueType_0200
 * @tc.name: test QueryAbilityInfoByContinueType
 * @tc.desc: 1.query capability information by continuous type
 */
HWTEST_F(BmsDataMgrTest, QueryAbilityInfoByContinueType_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    int32_t userId = Constants::ALL_USERID;
    BundleUserInfo userInfo;
    userInfo.userId = userId;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo = userInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    dataMgr->multiUserIdsSet_.insert(userId);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    std::string bundleName = "";
    std::string continueType = "";
    AbilityInfo abilityInfo;
    int32_t appIndex = 0;
    ErrCode ret = dataMgr->QueryAbilityInfoByContinueType(BUNDLE_NAME, continueType, abilityInfo, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number:QueryCloneAbilityInfo_0100
 * @tc.name: test QueryCloneAbilityInfo
 * @tc.desc: 1.query cloning capability information
 */
HWTEST_F(BmsDataMgrTest, QueryCloneAbilityInfo_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    ElementName element;
    int32_t flags = 0;
    int32_t userId = -1;
    int32_t appIndex = 0;
    AbilityInfo abilityInfo;
    ErrCode ret = dataMgr->QueryCloneAbilityInfo(element, flags, userId, appIndex, abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    userId = Constants::ANY_USERID;
    ret = dataMgr->QueryCloneAbilityInfo(element, flags, userId, appIndex, abilityInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number:ExplicitQueryCloneAbilityInfo_0100
 * @tc.name: test ExplicitQueryCloneAbilityInfo
 * @tc.desc: 1.explicitly query cloning capability information
 */
HWTEST_F(BmsDataMgrTest, ExplicitQueryCloneAbilityInfo_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    ElementName element;
    int32_t flags = 0;
    int32_t userId = -1;
    int32_t appIndex = 0;
    AbilityInfo abilityInfo;
    ErrCode ret = dataMgr->ExplicitQueryCloneAbilityInfoV9(element, flags, userId, appIndex, abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number:GetCloneBundleInfo_0100
 * @tc.name: test GetCloneBundleInfo
 * @tc.desc: 1.get clone bundle information
 */
HWTEST_F(BmsDataMgrTest, GetCloneBundleInfo_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    int32_t flags = 0;
    int32_t appIndex = 0;
    BundleInfo bundleInfo;
    int32_t userId = -1;
    ErrCode ret = dataMgr->GetCloneBundleInfo(bundleName, flags, appIndex, bundleInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    userId = Constants::ANY_USERID;
    ret = dataMgr->GetCloneBundleInfo(bundleName, flags, appIndex, bundleInfo, userId);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number:GetInnerBundleInfoWithFlags_0100
 * @tc.name: test GetInnerBundleInfoWithFlags
 * @tc.desc: 1.test using flags to obtain internal bundling information
 */
HWTEST_F(BmsDataMgrTest, GetInnerBundleInfoWithFlags_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    int32_t userId = Constants::ALL_USERID;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    BundleUserInfo userInfo;
    userInfo.userId = userId;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo = userInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    dataMgr->multiUserIdsSet_.insert(userId);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    ErrCode res =
        dataMgr->GetInnerBundleInfoWithFlagsV9(BUNDLE_NAME, GET_ABILITY_INFO_DEFAULT, innerBundleInfo, userId);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AddDesktopShortcutInfo_0001
 * @tc.name: AddDesktopShortcutInfo
 * @tc.desc: test AddDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId, bool &isIdIllegal)
 */
HWTEST_F(BmsDataMgrTest, AddDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    bool isIdIllegal = false;

    bool ret = shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);
    EXPECT_TRUE(ret);

    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_TRUE(ret);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    ret = shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AddDesktopShortcutInfo_0002
 * @tc.name: AddDesktopShortcutInfo
 * @tc.desc: test AddDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId, bool &isIdIllegal)
 */
HWTEST_F(BmsDataMgrTest, AddDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    bool isIdIllegal = false;

    bool ret = shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);
    EXPECT_TRUE(ret);

    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_TRUE(ret);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    ret = shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteDesktopShortcutInfo_0001
 * @tc.name: DeleteDesktopShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, DeleteDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    bool isIdIllegal = false;

    shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);

    bool ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_TRUE(ret);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;

    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteDesktopShortcutInfo_0002
 * @tc.name: DeleteDesktopShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, DeleteDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    bool isIdIllegal = false;
    shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);

    bool ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_TRUE(ret);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;

    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteDesktopShortcutInfo_0003
 * @tc.name: DeleteDesktopShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo(const std::string &bundleName)
 */
HWTEST_F(BmsDataMgrTest, DeleteDesktopShortcutInfo_0003, Function | SmallTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    std::string bundleName = "bundleName";
    shortcutDataStorageRdb->rdbDataManager_->bmsRdbConfig_.dbName = "bundleName";

    bool ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(bundleName);
    EXPECT_TRUE(ret);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(bundleName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteDesktopShortcutInfo_0004
 * @tc.name: DeleteDesktopShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo(const std::string &bundleName)
 */
HWTEST_F(BmsDataMgrTest, DeleteDesktopShortcutInfo_0004, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    std::string bundleName = "bundleName";
    shortcutDataStorageRdb->rdbDataManager_->bmsRdbConfig_.dbName = "bundleName";

    bool ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(bundleName);
    EXPECT_TRUE(ret);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(bundleName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteDesktopShortcutInfo_0005
 * @tc.name: DeleteDesktopShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo(const std::string &bundleName, int32_t userId, int32_t appIndex)
 */
HWTEST_F(BmsDataMgrTest, DeleteDesktopShortcutInfo_0005, Function | SmallTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    std::string bundleName = "bundleName";
    int32_t appIndex = 100;
    shortcutDataStorageRdb->rdbDataManager_->bmsRdbConfig_.dbName = "bundleName";

    bool ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(bundleName, USERID, appIndex);
    EXPECT_TRUE(ret);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(bundleName, USERID, appIndex);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteDesktopShortcutInfo_0006
 * @tc.name: DeleteDesktopShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo(const std::string &bundleName, int32_t userId, int32_t appIndex)
 */
HWTEST_F(BmsDataMgrTest, DeleteDesktopShortcutInfo_0006, Function | SmallTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    std::string bundleName = "bundleName";
    int32_t appIndex = 100;
    shortcutDataStorageRdb->rdbDataManager_->bmsRdbConfig_.dbName = "bundleName";

    bool ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(bundleName, USERID, appIndex);
    EXPECT_TRUE(ret);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(bundleName, USERID, appIndex);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetAllDesktopShortcutInfo_0001
 * @tc.name: GetAllDesktopShortcutInfo
 * @tc.desc: test GetAllDesktopShortcutInfo(int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
 */
HWTEST_F(BmsDataMgrTest, GetAllDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    std::vector<ShortcutInfo> vecShortcutInfo;
    vecShortcutInfo.push_back(shortcutInfo);
    shortcutDataStorageRdb->rdbDataManager_->rdbStore_ = nullptr;

    shortcutDataStorageRdb->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    EXPECT_NE(shortcutDataStorageRdb->rdbDataManager_, nullptr);

    shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);

    vecShortcutInfo.clear();
    shortcutDataStorageRdb->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    EXPECT_GE(vecShortcutInfo.size(), 0);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    shortcutDataStorageRdb->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    EXPECT_EQ(shortcutDataStorageRdb->rdbDataManager_, nullptr);
}

/**
 * @tc.number: GetAllDesktopShortcutInfo_0002
 * @tc.name: GetAllDesktopShortcutInfo
 * @tc.desc: test GetAllDesktopShortcutInfo(int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
 */
HWTEST_F(BmsDataMgrTest, GetAllDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    std::vector<ShortcutInfo> vecShortcutInfo;
    vecShortcutInfo.push_back(shortcutInfo);
    shortcutDataStorageRdb->rdbDataManager_->rdbStore_ = nullptr;

    shortcutDataStorageRdb->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    EXPECT_NE(shortcutDataStorageRdb->rdbDataManager_, nullptr);

    shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);

    vecShortcutInfo.clear();
    shortcutDataStorageRdb->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    EXPECT_GE(vecShortcutInfo.size(), 0);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    shortcutDataStorageRdb->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    EXPECT_EQ(shortcutDataStorageRdb->rdbDataManager_, nullptr);
}

/**
 * @tc.number: GetSignatureInfoByBundleName_0001
 * @tc.name: GetSignatureInfoByBundleName
 * @tc.desc: test GetSignatureInfoByBundleName(const std::string &bundleName, SignatureInfo &signatureInfo)
 */
HWTEST_F(BmsDataMgrTest, GetSignatureInfoByBundleName_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "bundleName";
    SignatureInfo signatureInfo;
    auto ret = bundleDataMgr.GetSignatureInfoByBundleName(bundleName, signatureInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetOdidByBundleName_0001
 * @tc.name: GetOdidByBundleName
 * @tc.desc: test GetOdidByBundleName(const std::string &bundleName, std::string &odid)
 */
HWTEST_F(BmsDataMgrTest, GetOdidByBundleName_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "bundleName";
    std::string odid = "odid";
    auto ret = bundleDataMgr.GetOdidByBundleName(bundleName, odid);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: CreateBundleDataDir_0001
 * @tc.name: CreateBundleDataDir
 * @tc.desc: test CreateBundleDataDir(int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, CreateBundleDataDir_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = Constants::INVALID_USERID;
    auto ret = bundleDataMgr.CreateBundleDataDir(userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0001
 * @tc.name: QueryExtensionAbilityInfos
 * @tc.desc: test QueryExtensionAbilityInfos(uint32_t flags, int32_t userId,
 *  std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex)
 */
HWTEST_F(BmsDataMgrTest, QueryExtensionAbilityInfos_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    uint32_t flags = 20;
    int32_t userId = Constants::INVALID_USERID;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 30;
    auto ret = bundleDataMgr.QueryExtensionAbilityInfos(flags, userId, extensionInfos, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TryGetRawDataByExtractor_0001
 * @tc.name: TryGetRawDataByExtractor
 * @tc.desc: test TryGetRawDataByExtractor(const std::string &hapPath, const std::string &profileName,
 *  const AbilityInfo &abilityInfo)
 */
HWTEST_F(BmsDataMgrTest, TryGetRawDataByExtractor_0001, Function | MediumTest | Level1)
{
    std::string hapPath;
    std::string profileName;
    AbilityInfo abilityInfo = GetDefaultAbilityInfo();
    std::string result = dataMgr_->TryGetRawDataByExtractor(hapPath, profileName, abilityInfo);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.number: FromJson_001
 * @tc.name: FromJson
 * @tc.desc: test FromJson(const nlohmann::json& jsonObject,
 *  UninstallBundleInfo& uninstallBundleInfo)
 */
HWTEST_F(BmsDataMgrTest, FromJson_001, Function | MediumTest | Level1)
{
    int32_t parseResult = 0;
    nlohmann::json jsonObject = {};
    UninstallDataUserInfo uninstallDataUserInfo;
    from_json(jsonObject, uninstallDataUserInfo);
    EXPECT_EQ(parseResult, ERR_OK);
}

/**
 * @tc.number: InnerProcessShortcutId_0001
 * @tc.name: InnerProcessShortcutId
 * @tc.desc: test InnerProcessShortcutId
 */
HWTEST_F(BmsDataMgrTest, InnerProcessShortcutId_0001, Function | MediumTest | Level1)
{
    std::string hapPath;
    std::vector<ShortcutInfo> shortcutInfos;
    bool result = dataMgr_->InnerProcessShortcutId(hapPath, shortcutInfos);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: InnerProcessShortcutId_0002
 * @tc.name: InnerProcessShortcutId
 * @tc.desc: test InnerProcessShortcutId
 */
HWTEST_F(BmsDataMgrTest, InnerProcessShortcutId_0002, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo;
    shortcutInfo.id = "id_1";
    shortcutInfos.emplace_back(shortcutInfo);
    std::string hapPath;
    bool result = dataMgr_->InnerProcessShortcutId(hapPath, shortcutInfos);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: InnerProcessShortcutId_0003
 * @tc.name: InnerProcessShortcutId
 * @tc.desc: test InnerProcessShortcutId
 */
HWTEST_F(BmsDataMgrTest, InnerProcessShortcutId_0003, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo;
    shortcutInfo.id = "$string:11111";
    shortcutInfos.emplace_back(shortcutInfo);
    std::string hapPath;
    bool result = dataMgr_->InnerProcessShortcutId(hapPath, shortcutInfos);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: InnerProcessShortcutId_0004
 * @tc.name: InnerProcessShortcutId
 * @tc.desc: test InnerProcessShortcutId
 */
HWTEST_F(BmsDataMgrTest, InnerProcessShortcutId_0004, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo_1;
    shortcutInfo_1.id = "$string:11111";
    shortcutInfos.emplace_back(shortcutInfo_1);
    ShortcutInfo shortcutInfo_2;
    shortcutInfo_2.id = "id";
    shortcutInfos.emplace_back(shortcutInfo_2);
    ShortcutInfo shortcutInfo_3;
    shortcutInfo_3.id = "$string:xxxx";
    shortcutInfos.emplace_back(shortcutInfo_3);

    std::string hapPath = HAP_FILE_PATH1;
    bool result = dataMgr_->InnerProcessShortcutId(hapPath, shortcutInfos);
    EXPECT_TRUE(result);
    if (!shortcutInfos.empty()) {
        EXPECT_EQ(shortcutInfos[0].id, shortcutInfo_1.id);
        EXPECT_EQ(shortcutInfos[1].id, shortcutInfo_2.id);
        EXPECT_EQ(shortcutInfos[2].id, shortcutInfo_3.id);
    }
}

/**
 * @tc.number: InnerProcessShortcutId_0005
 * @tc.name: InnerProcessShortcutId
 * @tc.desc: test InnerProcessShortcutId
 */
HWTEST_F(BmsDataMgrTest, InnerProcessShortcutId_0005, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo;
    shortcutInfo.id = "$string:16777216";
    shortcutInfos.emplace_back(shortcutInfo);

    std::string hapPath = HAP_FILE_PATH1;
    bool result = dataMgr_->InnerProcessShortcutId(hapPath, shortcutInfos);
    EXPECT_TRUE(result);
    if (!shortcutInfos.empty()) {
        EXPECT_NE(shortcutInfos[0].id, shortcutInfo.id);
    }
}

/**
 * @tc.number: CreateAppInstallDir_0001
 * @tc.name: CreateAppInstallDir
 * @tc.desc: test CreateAppInstallDir(int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, CreateAppInstallDir_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = USERID;
    bundleDataMgr.CreateAppInstallDir(userId);
    std::string path = std::string(ServiceConstants::HAP_COPY_PATH) +
        ServiceConstants::GALLERY_DOWNLOAD_PATH + std::to_string(userId);
    EXPECT_EQ(BundleUtil::IsExistDir(path), true);
    std::string appClonePath = path + ServiceConstants::GALLERY_CLONE_PATH;
    EXPECT_EQ(BundleUtil::IsExistDir(appClonePath), true);
}
} // OHOS