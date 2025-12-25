/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "access_token.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "app_provision_info_manager.h"
#include "bundle_backup_mgr.h"
#include "bundle_backup_service.h"
#include "bundle_data_storage_interface.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "int_wrapper.h"
#include "json_constants.h"
#include "json_serializer.h"
#include "mime_type_mgr.h"
#include "mock_ipc_skeleton.h"
#include "parcel.h"
#include "shortcut_data_storage_rdb.h"
#include "shortcut_visible_data_storage_rdb.h"
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
const uint32_t ACCESS_TOKEN_ID = 1765341;
const std::string TOKEN_BUNDLE = "tokenBundle";
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
    InnerAbilityInfo GetDefaultInnerAbilityInfo() const;
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

InnerAbilityInfo BmsDataMgrTest::GetDefaultInnerAbilityInfo() const
{
    InnerAbilityInfo abilityInfo;
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
    shortcutInfos.moduleName = "test_entry";
    shortcutInfos.isStatic = true;
    shortcutInfos.isHomeShortcut = true;
    shortcutInfos.isEnables = true;
    return shortcutInfos;
}

InnerBundleInfo CreateAddDynamicShortcutInfosInnerBundleInfo(const ShortcutInfo &shortcutInfo)
{
    std::string bundleName = "com.ohos.hello";
    std::string moduleName = "test_entry";
    std::string hostAbility = "hostAbility";
    std::string shortcutId = "id_test1";
    int32_t userId = 100;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = moduleName;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    innerBundleInfo.InsertInnerModuleInfo(bundleName, innerModuleInfo);
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = hostAbility;
    innerAbilityInfo.moduleName = moduleName;
    innerBundleInfo.InsertAbilitiesInfo(hostAbility, innerAbilityInfo);
    return innerBundleInfo;
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
    bool ret3 = dataMgr->FetchInnerBundleInfo(BUNDLE_NAME, info1);
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
    bool ret1 = dataMgr->FetchInnerBundleInfo("", info1);
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
    bool ret6 = dataMgr->FetchInnerBundleInfo(BUNDLE_NAME, info3);
    bool ret7 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS);
    bool ret8 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UPDATING_START);
    bool ret9 = dataMgr->RemoveModuleInfo(BUNDLE_NAME, PACKAGE_NAME, info1);
    bool ret10 = dataMgr->FetchInnerBundleInfo(BUNDLE_NAME, info4);
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
    ErrCode ret3 = dataMgr->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_EQ(ret3, ERR_OK);

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
    ErrCode ret3 = dataMgr->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_EQ(ret3, ERR_OK);

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
    ErrCode ret3 = dataMgr->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_EQ(ret3, ERR_OK);
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

    ErrCode ret = dataMgr->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_BUNDLENAME_IS_EMPTY);

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

    InnerAbilityInfo innerAbilityInfo = GetDefaultInnerAbilityInfo();
    info1.SetBaseBundleInfo(bundleInfo1);
    info1.SetBaseApplicationInfo(applicationInfo1);
    info1.InsertAbilitiesInfo(BUNDLE_NAME + PACKAGE_NAME + ABILITY_NAME, innerAbilityInfo);
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

    EXPECT_EQ(abilityInfo2.package, innerAbilityInfo.package);
    EXPECT_EQ(abilityInfo2.name, innerAbilityInfo.name);
    EXPECT_EQ(abilityInfo2.bundleName, innerAbilityInfo.bundleName);
    EXPECT_EQ(abilityInfo2.applicationName, innerAbilityInfo.applicationName);
    EXPECT_EQ(abilityInfo2.deviceId, innerAbilityInfo.deviceId);
    EXPECT_EQ(abilityInfo2.label, innerAbilityInfo.label);
    EXPECT_EQ(abilityInfo2.description, innerAbilityInfo.description);
    EXPECT_EQ(abilityInfo2.iconPath, innerAbilityInfo.iconPath);
    EXPECT_EQ(abilityInfo2.visible, innerAbilityInfo.visible);
    EXPECT_EQ(abilityInfo2.kind, innerAbilityInfo.kind);
    EXPECT_EQ(abilityInfo2.type, innerAbilityInfo.type);
    EXPECT_EQ(abilityInfo2.orientation, innerAbilityInfo.orientation);
    EXPECT_EQ(abilityInfo2.launchMode, innerAbilityInfo.launchMode);
    EXPECT_EQ(abilityInfo2.codePath, innerAbilityInfo.codePath);
    EXPECT_EQ(abilityInfo2.resourcePath, innerAbilityInfo.resourcePath);
    EXPECT_EQ(abilityInfo2.libPath, innerAbilityInfo.libPath);

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
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = BUNDLE_NAME;
    innerAbilityInfo.type = AbilityType::PAGE;
    innerBundleInfo.InsertAbilitiesInfo(BUNDLE_NAME, innerAbilityInfo);
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

    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = ServiceConstants::APP_DETAIL_ABILITY;
    innerBundleInfo.InsertAbilitiesInfo(BUNDLE_NAME, innerAbilityInfo);
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
        EXPECT_EQ(abilityInfo.label, abilityInfo.applicationInfo.label);
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
        EXPECT_EQ(abilityInfo.label, abilityInfo.bundleName);
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
 * @tc.number: UpdateExtResources_0100
 * @tc.name: test UpdateExtResources
 * @tc.desc: 1.test update external resources
 */
HWTEST_F(BmsDataMgrTest, UpdateExtResources_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "";
    std::vector<ExtendResourceInfo> extendResourceInfos;
    bool ret = dataMgr->UpdateExtResources(bundleName, extendResourceInfos);
    EXPECT_EQ(ret, false);

    std::map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(BUNDLE_NAME, innerBundleInfo);
    dataMgr->bundleInfos_.swap(infos);
    ret = dataMgr->UpdateExtResources(BUNDLE_NAME, extendResourceInfos);
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
 * @tc.number: IsDebuggableApplication_0100
 * @tc.name: test IsDebuggableApplication
 * @tc.desc: 1.test is debug application
 */
HWTEST_F(BmsDataMgrTest, IsDebuggableApplication_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    const std::string bundleName = BUNDLE_NAME;
    bool isDebuggable = false;
    bool ret = dataMgr->IsDebuggableApplication(bundleName, isDebuggable);
    EXPECT_EQ(isDebuggable, false);
}

/**
 * @tc.number: IsDebuggableApplication_0200
 * @tc.name: test IsDebuggableApplication
 * @tc.desc: 1.test is debug application
 */
HWTEST_F(BmsDataMgrTest, IsDebuggableApplication_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    const std::string bundleName = "";
    bool isDebuggable = false;
    auto ret = dataMgr->IsDebuggableApplication(bundleName, isDebuggable);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IsDebuggableApplication_0300
 * @tc.name: test IsDebuggableApplication
 * @tc.desc: 1.test is debug application
 */
HWTEST_F(BmsDataMgrTest, IsDebuggableApplication_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    const std::string bundleName = "ohos.global.systemres";
    bool isDebuggable = false;
    auto ret = dataMgr->IsDebuggableApplication(bundleName, isDebuggable);
    EXPECT_EQ(ret, ERR_OK);
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
    InnerExtensionInfo innerExtensionInfo;
    info.InsertExtensionInfo("", innerExtensionInfo);
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
    InnerExtensionInfo innerExtensionInfo;
    info.InsertExtensionInfo("", innerExtensionInfo);
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
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
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
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
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
 * @tc.number:ExplicitQueryCloneAbilityInfo_0200
 * @tc.name: test ExplicitQueryCloneAbilityInfo
 * @tc.desc: 1.explicitly query cloning capability information
 */
HWTEST_F(BmsDataMgrTest, ExplicitQueryCloneAbilityInfo_0200, Function | SmallTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(USERID);
    ElementName element;
    AbilityInfo abilityInfo;
    auto ret = bundleDataMgr.ExplicitQueryCloneAbilityInfoV9(element,  0, USERID, 0, abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
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
    const InnerBundleInfo* innerPtr = &innerBundleInfo;
    ErrCode res =
        dataMgr->GetInnerBundleInfoWithFlagsV9(BUNDLE_NAME, GET_ABILITY_INFO_DEFAULT, innerPtr, userId);
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
 * @tc.number: AddDesktopShortcutInfo_0003
 * @tc.name: AddDesktopShortcutInfo
 * @tc.desc: test AddDesktopShortcutInfo
 */
HWTEST_F(BmsDataMgrTest, AddDesktopShortcutInfo_0003, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = 10;
    ShortcutInfo shortcutInfo;
    auto ret1 = bundleDataMgr.AddDesktopShortcutInfo(shortcutInfo, userId);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    userId = Constants::ANY_USERID;
    auto ret2 = bundleDataMgr.AddDesktopShortcutInfo(shortcutInfo, userId);
    EXPECT_NE(ret2, ERR_OK);
}

/**
 * @tc.number: AddDesktopShortcutInfo_0004
 * @tc.name: AddDesktopShortcutInfo
 * @tc.desc: test AddDesktopShortcutInfo
 */
HWTEST_F(BmsDataMgrTest, AddDesktopShortcutInfo_0004, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    bundleDataMgr.AddUserId(USERID);
    auto ret1 = bundleDataMgr.AddDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_NE(ret1, ERR_OK);
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
 * @tc.number: GetSignatureInfoByBundleName_0002
 * @tc.name: GetSignatureInfoByBundleName
 * @tc.desc: test GetSignatureInfoByBundleName(const std::string &bundleName, SignatureInfo &signatureInfo)
 */
HWTEST_F(BmsDataMgrTest, GetSignatureInfoByBundleName_0002, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    SignatureInfo signatureInfo;
    auto ret = dataMgr->GetSignatureInfoByBundleName(BUNDLE_NAME, signatureInfo);
    EXPECT_EQ(ret, ERR_OK);
    dataMgr->bundleInfos_.erase(BUNDLE_NAME);
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
 * @tc.number: GetAppIdentifierAndAppIndex_0001
 * @tc.name: GetAppIdentifierAndAppIndex
 * @tc.desc: test GetAppIdentifierAndAppIndex(const uint32_t accessTokenId,
    std::string &appIdentifier, int32_t &appIndex)
 */
HWTEST_F(BmsDataMgrTest, GetAppIdentifierAndAppIndex_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string appIdentifier;
    int32_t appIndex;
    auto ret = bundleDataMgr.GetAppIdentifierAndAppIndex(ACCESS_TOKEN_ID, appIdentifier, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAppIdentifierAndAppIndex_0002
 * @tc.name: GetAppIdentifierAndAppIndex
 * @tc.desc: test GetAppIdentifierAndAppIndex(const uint32_t accessTokenId,
    std::string &appIdentifier, int32_t &appIndex)
 */
HWTEST_F(BmsDataMgrTest, GetAppIdentifierAndAppIndex_0002, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    std::string appIdentifier;
    int32_t appIndex;
    bundleDataMgr.bundleInfos_.emplace(TOKEN_BUNDLE, innerBundleInfo);
    auto ret = bundleDataMgr.GetAppIdentifierAndAppIndex(ACCESS_TOKEN_ID, appIdentifier, appIndex);
    EXPECT_EQ(ret, ERR_OK);
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
 * @tc.number: GetLabel_0001
 * @tc.name: GetLabel_0001
 * @tc.desc: test HasAppOrAtomicServiceInUser
 */
HWTEST_F(BmsDataMgrTest, GetLabel_0001, Function | MediumTest | Level1)
{
    std::string bundleName;
    int32_t userId = 999;
    auto res = dataMgr_->HasAppOrAtomicServiceInUser(bundleName, userId);
    EXPECT_EQ(res, false);

    std::vector<std::string> bundleList;
    bool result =  dataMgr_->GetAllAppAndAtomicServiceInUser(userId, bundleList);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: GetLabel_0002
 * @tc.name: GetLabel_0002
 * @tc.desc: test HasAppOrAtomicServiceInUser
 */
HWTEST_F(BmsDataMgrTest, GetLabel_0002, Function | MediumTest | Level1)
{
    std::string bundleName;
    int32_t userId = 100;
    dataMgr_->AddUserId(userId);
    auto res = dataMgr_->HasAppOrAtomicServiceInUser(bundleName, userId);
    EXPECT_EQ(res, false);

    std::vector<std::string> bundleList;
    bool result =  dataMgr_->GetAllAppAndAtomicServiceInUser(userId, bundleList);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: GetLabel_0003
 * @tc.name: GetLabel_0003
 * @tc.desc: test HasAppOrAtomicServiceInUser
 */
HWTEST_F(BmsDataMgrTest, GetLabel_0003, Function | MediumTest | Level1)
{
    std::string bundleName = "wrong.bundleName";
    int32_t userId = 100;
    dataMgr_->AddUserId(userId);
    auto res = dataMgr_->HasAppOrAtomicServiceInUser(bundleName, userId);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetLabel_0004
 * @tc.name: GetLabel_0004
 * @tc.desc: test GetAllAppAndAtomicServiceInUser
 */
HWTEST_F(BmsDataMgrTest, GetLabel_0004, Function | MediumTest | Level1)
{
    int32_t userId = 100;
    dataMgr_->AddUserId(userId);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::SHARED;
    dataMgr_->bundleInfos_.emplace("test.bundle", innerBundleInfo);

    std::vector<std::string> bundleList;
    bool result =  dataMgr_->GetAllAppAndAtomicServiceInUser(userId, bundleList);
    EXPECT_FALSE(result);

    auto res = dataMgr_->HasAppOrAtomicServiceInUser("test.bundle", userId);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetLabel_0005
 * @tc.name: GetLabel_0005
 * @tc.desc: test GetAllAppAndAtomicServiceInUser
 */
HWTEST_F(BmsDataMgrTest, GetLabel_0005, Function | MediumTest | Level1)
{
    int32_t userId = 100;
    dataMgr_->AddUserId(userId);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
    dataMgr_->bundleInfos_.emplace("test.bundle", innerBundleInfo);

    std::vector<std::string> bundleList;
    bool result =  dataMgr_->GetAllAppAndAtomicServiceInUser(userId, bundleList);
    EXPECT_FALSE(result);

    auto res = dataMgr_->HasAppOrAtomicServiceInUser("test.bundle", userId);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetLabel_0006
 * @tc.name: GetLabel_0006
 * @tc.desc: test GetAllAppAndAtomicServiceInUser
 */
HWTEST_F(BmsDataMgrTest, GetLabel_0006, Function | MediumTest | Level1)
{
    int32_t userId = 100;
    dataMgr_->AddUserId(userId);
    std::string bundleName = "test.bundle";

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
    innerBundleInfo.baseApplicationInfo_->bundleName = bundleName;

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleInfo.innerBundleUserInfos_["test.bundle_100"] = innerBundleUserInfo;
    dataMgr_->bundleInfos_.emplace(bundleName, innerBundleInfo);

    std::vector<std::string> bundleList;
    bool result =  dataMgr_->GetAllAppAndAtomicServiceInUser(userId, bundleList);
    EXPECT_TRUE(result);
    EXPECT_FALSE(bundleList.empty());

    auto res = dataMgr_->HasAppOrAtomicServiceInUser(bundleName, userId);
    EXPECT_EQ(res, true);
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
    bool result = dataMgr_->InnerProcessShortcutId(0, hapPath, shortcutInfos);
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
    bool result = dataMgr_->InnerProcessShortcutId(0, hapPath, shortcutInfos);
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
    auto bmsPara = std::make_shared<BmsParam>();
    EXPECT_NE(bmsPara, nullptr);
    if (bmsPara) {
        bundleMgrService_->bmsParam_ = bmsPara;
        bool ret = bmsPara->SaveBmsParam(ServiceConstants::BMS_SYSTEM_TIME_FOR_SHORTCUT, "100");
        EXPECT_TRUE(ret);
    }
    std::string hapPath;
    bool result = dataMgr_->InnerProcessShortcutId(101, hapPath, shortcutInfos);
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
    auto bmsPara = std::make_shared<BmsParam>();
    EXPECT_NE(bmsPara, nullptr);
    if (bmsPara) {
        bundleMgrService_->bmsParam_ = bmsPara;
        bool ret = bmsPara->SaveBmsParam(ServiceConstants::BMS_SYSTEM_TIME_FOR_SHORTCUT, "100");
        EXPECT_TRUE(ret);
    }
    std::string hapPath = HAP_FILE_PATH1;
    bool result = dataMgr_->InnerProcessShortcutId(101, hapPath, shortcutInfos);
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
    auto bmsPara = std::make_shared<BmsParam>();
    EXPECT_NE(bmsPara, nullptr);
    if (bmsPara) {
        bundleMgrService_->bmsParam_ = bmsPara;
        bool ret = bmsPara->SaveBmsParam(ServiceConstants::BMS_SYSTEM_TIME_FOR_SHORTCUT, "100");
        EXPECT_TRUE(ret);
    }
    std::string hapPath = HAP_FILE_PATH1;
    bool result = dataMgr_->InnerProcessShortcutId(101, hapPath, shortcutInfos);
    EXPECT_TRUE(result);
    if (!shortcutInfos.empty()) {
        EXPECT_NE(shortcutInfos[0].id, shortcutInfo.id);
    }
}

/**
 * @tc.number: InnerProcessShortcutId_0006
 * @tc.name: InnerProcessShortcutId
 * @tc.desc: test InnerProcessShortcutId
 */
HWTEST_F(BmsDataMgrTest, InnerProcessShortcutId_0006, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo;
    shortcutInfo.id = "$string:11111";
    shortcutInfos.emplace_back(shortcutInfo);
    auto bmsPara = std::make_shared<BmsParam>();
    EXPECT_NE(bmsPara, nullptr);
    if (bmsPara) {
        bundleMgrService_->bmsParam_ = bmsPara;
        bool ret = bmsPara->SaveBmsParam(ServiceConstants::BMS_SYSTEM_TIME_FOR_SHORTCUT, "100");
        EXPECT_TRUE(ret);
    }
    std::string hapPath;
    bool result = dataMgr_->InnerProcessShortcutId(0, hapPath, shortcutInfos);
    EXPECT_FALSE(result);
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

/**
 * @tc.number: GetFirstInstallBundleInfo_0001
 * @tc.name: GetFirstInstallBundleInfo
 * @tc.desc: test GetFirstInstallBundleInfo(const std::string &bundleName, const int32_t userId,
    FirstInstallBundleInfo &firstInstallBundleInfo)
 */
HWTEST_F(BmsDataMgrTest, GetFirstInstallBundleInfo_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "";
    int32_t userId = 100;
    FirstInstallBundleInfo firstInstallBundleInfo;
    auto ret = bundleDataMgr.GetFirstInstallBundleInfo(bundleName, userId, firstInstallBundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: DeleteFirstInstallBundleInfo_0001
 * @tc.name: DeleteFirstInstallBundleInfo
 * @tc.desc: test DeleteFirstInstallBundleInfo(int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, DeleteFirstInstallBundleInfo_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = 100;
    auto ret = bundleDataMgr.DeleteFirstInstallBundleInfo(userId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: RemoveHspModuleByVersionCode_0001
 * @tc.name: RemoveHspModuleByVersionCode
 * @tc.desc: test RemoveHspModuleByVersionCode(int32_t versionCode, InnerBundleInfo &info)
 */
HWTEST_F(BmsDataMgrTest, RemoveHspModuleByVersionCode_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t versionCode = 100;
    InnerBundleInfo info;
    auto ret = bundleDataMgr.RemoveHspModuleByVersionCode(versionCode, info);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetCloneAppIndexes_0001
 * @tc.name: GetCloneAppIndexes
 * @tc.desc: test GetCloneAppIndexes(const std::string &bundleName, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, GetCloneAppIndexes_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::vector<int32_t> cloneAppIndexes;
    std::string bundleName = "";
    int32_t userId = Constants::ANY_USERID;
    auto ret = bundleDataMgr.GetCloneAppIndexes(bundleName, userId);
    EXPECT_EQ(ret, cloneAppIndexes);
}

/**
 * @tc.number: QueryLauncherAbilityInfos_0001
 * @tc.name: QueryLauncherAbilityInfos
 * @tc.desc: test QueryLauncherAbilityInfos(
    const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
 */
HWTEST_F(BmsDataMgrTest, QueryLauncherAbilityInfos_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bundleDataMgr.QueryLauncherAbilityInfos(want, userId, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.QueryLauncherAbilityInfos(want, userId, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetLauncherAbilityInfoSync_0001
 * @tc.name: GetLauncherAbilityInfoSync
 * @tc.desc: test GetLauncherAbilityInfoSync(const Want &want, const int32_t userId,
    std::vector<AbilityInfo> &abilityInfos)
 */
HWTEST_F(BmsDataMgrTest, GetLauncherAbilityInfoSync_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bundleDataMgr.GetLauncherAbilityInfoSync(want, userId, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.GetLauncherAbilityInfoSync(want, userId, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: UpdateRouterInfo_0001
 * @tc.name: UpdateRouterInfo
 * @tc.desc: test UpdateRouterInfo(const std::string &bundleName)
 */
HWTEST_F(BmsDataMgrTest, UpdateRouterInfo_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "bundleName";
    bundleDataMgr.UpdateRouterInfo(bundleName);
    EXPECT_EQ(bundleDataMgr.bundleInfos_.find(bundleName),  bundleDataMgr.bundleInfos_.end());
}

/**
 * @tc.number: GetInnerBundleInfoWithSandboxByUid_0001
 * @tc.name: GetInnerBundleInfoWithSandboxByUid
 * @tc.desc: test GetInnerBundleInfoWithSandboxByUid(const std::string &bundleName)
 */
HWTEST_F(BmsDataMgrTest, GetInnerBundleInfoWithSandboxByUid_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int uid = 0;
    InnerBundleInfo innerBundleInfo;
    std::string bundleName = "bundleName";
    ErrCode ret = bundleDataMgr.GetInnerBundleInfoWithSandboxByUid(uid, innerBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: IsDisableState_0001
 * @tc.name: IsDisableState
 * @tc.desc: test IsDisableState(const InstallState state)
 */
HWTEST_F(BmsDataMgrTest, IsDisableState_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    bool ret = bundleDataMgr.IsDisableState(InstallState::UPDATING_START);
    EXPECT_EQ(ret, true);

    ret = bundleDataMgr.IsDisableState(InstallState::UNINSTALL_START);
    EXPECT_EQ(ret, true);

    ret = bundleDataMgr.IsDisableState(InstallState::INSTALL_SUCCESS);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: UnregisterBundleEventCallback_0001
 * @tc.name: UnregisterBundleEventCallback
 * @tc.desc: test UnregisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback)
 */
HWTEST_F(BmsDataMgrTest, UnregisterBundleEventCallback_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    sptr<IBundleEventCallback> bundleEventCallback = nullptr;
    bool ret = bundleDataMgr.UnregisterBundleEventCallback(bundleEventCallback);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: RemoveAppInstallDir_0001
 * @tc.name: RemoveAppInstallDir
 * @tc.desc: test RemoveAppInstallDir(int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, RemoveAppInstallDir_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = 0;
    std::string path = std::string(ServiceConstants::HAP_COPY_PATH) +
    ServiceConstants::GALLERY_DOWNLOAD_PATH + std::to_string(userId);
    bundleDataMgr.RemoveAppInstallDir(userId);
    EXPECT_NE(InstalldClient::GetInstance()->RemoveDir(path), ERR_OK);
}

/**
 * @tc.number: GetAppPrivilegeLevel_0001
 * @tc.name: GetAppPrivilegeLevel
 * @tc.desc: test GetAppPrivilegeLevel(const std::string &bundleName, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, GetAppPrivilegeLevel_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "bundleName";
    int32_t userId = 0;
    std::string result = bundleDataMgr.GetAppPrivilegeLevel(bundleName, userId);
    EXPECT_EQ(result, "");
}

/**
 * @tc.number: ImplicitQueryExtensionInfos_0001
 * @tc.name: ImplicitQueryExtensionInfos
 * @tc.desc: test ImplicitQueryExtensionInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex)
 */
HWTEST_F(BmsDataMgrTest, ImplicitQueryExtensionInfos_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    int32_t flags = 0;
    int32_t userId = Constants::INVALID_USERID;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    bool result = bundleDataMgr.ImplicitQueryExtensionInfos(want, flags, userId, infos, appIndex);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0002
 * @tc.name: QueryExtensionAbilityInfos
 * @tc.desc: test QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
 */
HWTEST_F(BmsDataMgrTest, QueryExtensionAbilityInfos_0002, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = Constants::INVALID_USERID;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool result = bundleDataMgr.QueryExtensionAbilityInfos(ExtensionAbilityType::FORM, userId, extensionInfos);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0003
 * @tc.name: QueryExtensionAbilityInfos
 * @tc.desc: test QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
 */
HWTEST_F(BmsDataMgrTest, QueryExtensionAbilityInfos_0003, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = Constants::ANY_USERID;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool result = bundleDataMgr.QueryExtensionAbilityInfos(ExtensionAbilityType::FORM, userId, extensionInfos);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: QueryExtensionAbilityInfoByUri_0001
 * @tc.name: QueryExtensionAbilityInfoByUri
 * @tc.desc: test QueryExtensionAbilityInfoByUri(const std::string &uri, int32_t userId,
    ExtensionAbilityInfo &extensionAbilityInfo)
 */
HWTEST_F(BmsDataMgrTest, QueryExtensionAbilityInfoByUri_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string uri = "uri";
    int32_t userId = Constants::INVALID_USERID;
    ExtensionAbilityInfo extensionAbilityInfo;
    bool result = bundleDataMgr.QueryExtensionAbilityInfoByUri(uri, userId, extensionAbilityInfo);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: QueryExtensionAbilityInfoByUri_0002
 * @tc.name: QueryExtensionAbilityInfoByUri
 * @tc.desc: test QueryExtensionAbilityInfoByUri(const std::string &uri, int32_t userId,
    ExtensionAbilityInfo &extensionAbilityInfo)
 */
HWTEST_F(BmsDataMgrTest, QueryExtensionAbilityInfoByUri_0002, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string uri = "";
    int32_t userId = Constants::ANY_USERID;
    ExtensionAbilityInfo extensionAbilityInfo;
    bool result = bundleDataMgr.QueryExtensionAbilityInfoByUri(uri, userId, extensionAbilityInfo);
    EXPECT_EQ(result, false);

    uri = "uri";
    result = bundleDataMgr.QueryExtensionAbilityInfoByUri(uri, userId, extensionAbilityInfo);
    EXPECT_EQ(result, false);

    uri = "uri:///";
    result = bundleDataMgr.QueryExtensionAbilityInfoByUri(uri, userId, extensionAbilityInfo);
    EXPECT_EQ(result, false);
}
/**
 * @tc.number: AddNewModuleInfo_0001
 * @tc.name: AddNewModuleInfo
 * @tc.desc: test AddNewModuleInfo(
    const std::string &bundleName, const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
 */
HWTEST_F(BmsDataMgrTest, AddNewModuleInfo_0001, Function | SmallTest | Level0)
{
    std::string bundleName = "test";
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    auto ret = dataMgr->AddNewModuleInfo(bundleName, newInfo, oldInfo);
    EXPECT_FALSE(ret);

    InnerBundleInfo info;
    int32_t versionCode = 10;
    BundleInfo bundleInfo;
    ApplicationInfo applicationInfo;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);
    dataMgr->installStates_.erase(bundleName);
    ret = dataMgr->AddNewModuleInfo(bundleName, newInfo, oldInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RemoveModuleInfo_0001
 * @tc.name: RemoveModuleInfo
 * @tc.desc: test RemoveModuleInfo(
    const std::string &bundleName, const std::string &modulePackage, InnerBundleInfo &oldInfo,
    bool needSaveStorage)
 */
HWTEST_F(BmsDataMgrTest, RemoveModuleInfo_0001, Function | SmallTest | Level0)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "test";
    std::string modulePackage = "";
    InnerBundleInfo oldInfo;
    auto ret = bundleDataMgr.RemoveModuleInfo(bundleName, modulePackage, oldInfo, false);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RemoveModuleInfo_0002
 * @tc.name: AddNewModuleInfo
 * @tc.desc: test AddNewModuleInfo(
    const std::string &bundleName, const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
 */
HWTEST_F(BmsDataMgrTest, RemoveModuleInfo_0002, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    std::string modulePackage = "";
    std::string bundleName = "test";
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    ApplicationInfo applicationInfo;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);
    auto ret = dataMgr->RemoveModuleInfo(bundleName, modulePackage, oldInfo, false);
    EXPECT_TRUE(ret);

    dataMgr->installStates_.erase(bundleName);
    ret = dataMgr->RemoveModuleInfo(bundleName, modulePackage, oldInfo, false);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RemoveHspModuleByVersionCode_0002
 * @tc.name: RemoveHspModuleByVersionCode
 * @tc.desc: test RemoveHspModuleByVersionCode(int32_t versionCode, InnerBundleInfo &info)
 */
HWTEST_F(BmsDataMgrTest, RemoveHspModuleByVersionCode_0002, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    int32_t versionCode = 10;
    std::string bundleName = "test";
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    BundleInfo bundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.name = bundleName;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = bundleName;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);
    auto ret = dataMgr->RemoveHspModuleByVersionCode(versionCode, info);
    EXPECT_TRUE(ret);

    dataMgr->installStates_.erase(bundleName);
    ret = dataMgr->RemoveHspModuleByVersionCode(versionCode, info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ImplicitQueryCurAbilityInfos_0001
 * @tc.name: ImplicitQueryCurAbilityInfos
 * @tc.desc: test ImplicitQueryCurAbilityInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, int32_t appIndex)
 */
HWTEST_F(BmsDataMgrTest, ImplicitQueryCurAbilityInfos_0001, Function | SmallTest | Level0)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    int32_t flags = 10;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 10;
    auto ret = bundleDataMgr.ImplicitQueryCurAbilityInfos(want, flags, userId, abilityInfos, appIndex);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ImplicitQueryCurAbilityInfosV9_0001
 * @tc.name: ImplicitQueryCurAbilityInfosV9
 * @tc.desc: test ImplicitQueryCurAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, int32_t appIndex)
 */
HWTEST_F(BmsDataMgrTest, ImplicitQueryCurAbilityInfosV9_0001, Function | SmallTest | Level0)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    int32_t flags = 10;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 10;
    auto ret = bundleDataMgr.ImplicitQueryCurAbilityInfosV9(want, flags, userId, abilityInfos, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: ImplicitQueryCurCloneExtensionAbilityInfosV9_0001
 * @tc.name: ImplicitQueryCurCloneExtensionAbilityInfosV9
 * @tc.desc: test ImplicitQueryCurCloneExtensionAbilityInfosV9
 */
HWTEST_F(BmsDataMgrTest, ImplicitQueryCurCloneExtensionAbilityInfosV9_0001, Function | SmallTest | Level0)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    std::vector<ExtensionAbilityInfo> abilityInfos;
    auto ret = bundleDataMgr.ImplicitQueryCurCloneExtensionAbilityInfosV9(want, 0, USERID, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: PreProcessAnyUserFlag_0001
 * @tc.name: PreProcessAnyUserFlag
 * @tc.desc: test PreProcessAnyUserFlag(const std::string &bundleName,
    int32_t& flags, int32_t &userId) const
 */
HWTEST_F(BmsDataMgrTest, PreProcessAnyUserFlag_0001, Function | SmallTest | Level0)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "test";
    std::vector<BundleInfo> bundleInfos;
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_OF_ANY_USER);
    int32_t userId = 101;
    bundleDataMgr.PreProcessAnyUserFlag(bundleName, flags, userId);
    bool ret = bundleDataMgr.GetBundleInfos(flags, bundleInfos, userId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: PostProcessAnyUserFlags_0001
 * @tc.name: PostProcessAnyUserFlags
 * @tc.desc: test PostProcessAnyUserFlags(
    int32_t flags, int32_t userId, int32_t originalUserId, BundleInfo &bundleInfo,
    const InnerBundleInfo &innerBundleInfo)
 */
HWTEST_F(BmsDataMgrTest, PostProcessAnyUserFlags_0001, Function | SmallTest | Level0)
{
    BundleDataMgr bundleDataMgr;
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    int32_t userId = 1000;
    int32_t originalUserId = 100;
    BundleInfo bundleInfo;
    bundleInfo.applicationInfo.applicationFlags = static_cast<int32_t>(ApplicationInfoFlag::FLAG_INSTALLED);
    InnerBundleInfo innerBundleInfo;
    bundleDataMgr.PostProcessAnyUserFlags(flags, userId, originalUserId, bundleInfo, innerBundleInfo);

    flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
                    static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_OF_ANY_USER);
    bundleDataMgr.PostProcessAnyUserFlags(flags, userId, originalUserId, bundleInfo, innerBundleInfo);
    EXPECT_FALSE(innerBundleInfo.HasInnerBundleUserInfo(originalUserId));
}

/**
 * @tc.number: DeleteSharedBundleInfo_0001
 * @tc.name: DeleteSharedBundleInfo
 * @tc.desc: test DeleteSharedBundleInfo(const std::string &bundleName)
 */
HWTEST_F(BmsDataMgrTest, DeleteSharedBundleInfo_0001, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    std::string bundleName = "test";
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = bundleName;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = bundleName;

    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);
    auto ret = dataMgr->DeleteSharedBundleInfo(bundleName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetModuleUpgradeFlag_0001
 * @tc.name: GetModuleUpgradeFlag
 * @tc.desc: test GetModuleUpgradeFlag(const std::string &bundleName,
    const std::string &moduleName)
 */
HWTEST_F(BmsDataMgrTest, GetModuleUpgradeFlag_0001, Function | SmallTest | Level0)
{
    std::string bundleName = "";
    std::string moduleName = "";
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    auto ret = dataMgr->GetModuleUpgradeFlag(bundleName, moduleName);
    EXPECT_FALSE(ret);

    InnerBundleInfo info;
    bundleName = "test";
    moduleName = "test";
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);
    bool ret1 = dataMgr->GetModuleUpgradeFlag(bundleName, moduleName);
    EXPECT_FALSE(ret1);

    dataMgr->bundleInfos_.erase(bundleName);
    bool ret2 = dataMgr->GetModuleUpgradeFlag(bundleName, moduleName);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.number: GetBundleStats_0001
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats(const std::string &bundleName,
    const int32_t userId, std::vector<int64_t> &bundleStats, const int32_t appIndex,
    const uint32_t statFlag) const
 */
HWTEST_F(BmsDataMgrTest, GetBundleStats_0001, Function | SmallTest | Level0)
{
    std::string bundleName = "test";
    int32_t userId = 100;
    std::vector<int64_t> bundleStats;
    int32_t appIndex = 10;
    uint32_t statFlag = 20;
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo info;
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);
    auto ret = dataMgr->GetBundleStats(bundleName, userId, bundleStats, appIndex, statFlag);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: SetAbilityEnabled_0001
 * @tc.name: SetAbilityEnabled
 * @tc.desc: test SetAbilityEnabled(const AbilityInfo &abilityInfo, int32_t appIndex,
    bool isEnabled, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, SetAbilityEnabled_0001, Function | SmallTest | Level0)
{
    ApplicationInfo applicationInfo;
    BundleInfo bundleInfo;
    InnerBundleInfo info;
    std::string bundleName = "test";
    bundleInfo.name = bundleName;
    bundleInfo.applicationInfo.name = APP_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    AbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    int32_t appIndex = 100;
    int32_t userId = 10;
    auto ret = dataMgr->SetAbilityEnabled(abilityInfo, appIndex, false, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    userId = Constants::ANY_USERID;
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);
    ret = dataMgr->SetAbilityEnabled(abilityInfo, appIndex, false, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: GetShortcutInfoV9_0001
 * @tc.name: GetShortcutInfoV9
 * @tc.desc: test GetShortcutInfoV9(
    const std::string &bundleName, int32_t userId, std::vector<ShortcutInfo> &shortcutInfos) const
 */
HWTEST_F(BmsDataMgrTest, GetShortcutInfoV9_0001, Function | SmallTest | Level0)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "";
    int32_t userId = 10;
    std::vector<ShortcutInfo> shortcutInfos;
    auto ret = bundleDataMgr.GetShortcutInfoV9(bundleName, userId, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.GetShortcutInfoV9(bundleName, userId, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: UpdatePrivilegeCapability_0001
 * @tc.name: UpdatePrivilegeCapability
 * @tc.desc: test UpdatePrivilegeCapability(
    const std::string &bundleName, const ApplicationInfo &appInfo)
 */
HWTEST_F(BmsDataMgrTest, UpdatePrivilegeCapability_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "";
    ApplicationInfo appInfo;
    bundleDataMgr.UpdatePrivilegeCapability(bundleName, appInfo);
    EXPECT_EQ(bundleName.empty(), true);

    bundleName = "bundleName";
    bundleDataMgr.UpdatePrivilegeCapability(bundleName, appInfo);
    EXPECT_EQ(bundleName.empty(), false);
    EXPECT_EQ(bundleDataMgr.bundleInfos_.find(bundleName), bundleDataMgr.bundleInfos_.end());
}

/**
 * @tc.number: UpdateQuickFixInnerBundleInfo_0001
 * @tc.name: UpdateQuickFixInnerBundleInfo
 * @tc.desc: test UpdateQuickFixInnerBundleInfo(const std::string &bundleName,
    const InnerBundleInfo &innerBundleInfo)
 */
HWTEST_F(BmsDataMgrTest, UpdateQuickFixInnerBundleInfo_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "";
    InnerBundleInfo innerBundleInfo;
    bool ret = bundleDataMgr.UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetSharedBundleInfo_0001
 * @tc.name: GetSharedBundleInfo
 * @tc.desc: test GetSharedBundleInfo(const std::string &bundleName,
    const InnerBundleInfo &innerBundleInfo)
 */
HWTEST_F(BmsDataMgrTest, GetSharedBundleInfo_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "bundleName";
    std::string moduleName = "moduleName";
    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = bundleDataMgr.GetSharedBundleInfo(bundleName, moduleName, sharedBundles);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetSharedBundleInfo_0101
 * @tc.name: GetSharedBundleInfo
 * @tc.desc: test GetSharedBundleInfo(const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo)
 */
HWTEST_F(BmsDataMgrTest, GetSharedBundleInfo_0101, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "";
    int32_t flags = 0;
    BundleInfo bundleInfo;
    ErrCode ret = bundleDataMgr.GetSharedBundleInfo(bundleName, flags, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);

    bundleName = "bundleName";
    ret = bundleDataMgr.GetSharedBundleInfo(bundleName, flags, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}
/**
 * @tc.number: IsPreInstallApp_0001
 * @tc.name: IsPreInstallApp
 * @tc.desc: test IsPreInstallApp(const std::string &bundleName)
 */
HWTEST_F(BmsDataMgrTest, IsPreInstallApp_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "bundleName";
    bool ret = bundleDataMgr.IsPreInstallApp(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetProxyDataInfos_0101
 * @tc.name: GetProxyDataInfos
 * @tc.desc: test GetProxyDataInfos(const std::string &bundleName, const std::string &moduleName,
    int32_t userId, std::vector<ProxyData> &proxyDatas)
 */
HWTEST_F(BmsDataMgrTest, GetProxyDataInfos_0101, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "bundleName";
    std::string moduleName = "moduleName";
    int32_t userId = Constants::ANY_USERID;
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = bundleDataMgr.GetProxyDataInfos(bundleName, moduleName, userId, proxyDatas);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetAllProxyDataInfos_0001
 * @tc.name: GetAllProxyDataInfos
 * @tc.desc: test GetAllProxyDataInfos(int32_t userId, std::vector<ProxyData> &proxyDatas)
 */
HWTEST_F(BmsDataMgrTest, GetAllProxyDataInfos_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = Constants::INVALID_USERID;
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = bundleDataMgr.GetAllProxyDataInfos(userId, proxyDatas);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetAllBundleStats_0001
 * @tc.name: GetAllBundleStats
 * @tc.desc: test BundleDataMgr::GetAllBundleStats(const int32_t userId, std::vector<int64_t> &bundleStats)
 */
HWTEST_F(BmsDataMgrTest, GetAllBundleStats_0001, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t userId = Constants::ANY_USERID;
    std::vector<int64_t> bundleStats;
    bool ret = dataMgr->GetAllBundleStats(userId, bundleStats);
    EXPECT_EQ(ret, false);

    std::string bundleName = "test";
    InnerBundleInfo info;
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);
    ret = dataMgr->GetAllBundleStats(userId, bundleStats);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ImplicitQueryCurExtensionInfos_0001
 * @tc.name: ImplicitQueryCurExtensionInfos
 * @tc.desc: test BundleDataMgr::ImplicitQueryCurExtensionInfos(const Want &want, int32_t flags,
    int32_t userId, std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const
 */
HWTEST_F(BmsDataMgrTest, ImplicitQueryCurExtensionInfos_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    uint32_t flags = 0;
    int32_t userId = 100;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    auto ret = bundleDataMgr.ImplicitQueryCurExtensionInfos(want, flags, userId, infos, appIndex);
    EXPECT_FALSE(ret);

    appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    ret = bundleDataMgr.ImplicitQueryCurExtensionInfos(want, flags, userId, infos, appIndex);
    EXPECT_FALSE(ret);

    appIndex = Constants::INITIAL_SANDBOX_APP_INDEX;
    ret = bundleDataMgr.ImplicitQueryCurExtensionInfos(want, flags, userId, infos, appIndex);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ImplicitQueryAllExtensionInfos_0001
 * @tc.name: ImplicitQueryAllExtensionInfos
 * @tc.desc: test BundleDataMgr::ImplicitQueryAllExtensionInfos(const Want &want, int32_t flags,
    int32_t userId, std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const
 */
HWTEST_F(BmsDataMgrTest, ImplicitQueryAllExtensionInfos_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    uint32_t flags = 0;
    int32_t userId = 100;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    bundleDataMgr.ImplicitQueryAllExtensionInfos(want, flags, userId, infos, appIndex);
    EXPECT_TRUE(bundleDataMgr.GetUserId(userId) == Constants::INVALID_USERID);

    userId = Constants::ANY_USERID;
    appIndex = 1001;
    bundleDataMgr.ImplicitQueryAllExtensionInfos(want, flags, userId, infos, appIndex);

    appIndex = 100;
    std::string bundleName = "test";
    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    bundleDataMgr.ImplicitQueryAllExtensionInfos(want, flags, userId, infos, appIndex);
    EXPECT_TRUE(bundleDataMgr.GetUserId(userId) != Constants::INVALID_USERID);
}

/**
 * @tc.number: GetExtensionAbilityInfoByTypeName_0001
 * @tc.name: GetExtensionAbilityInfoByTypeName
 * @tc.desc: test BundleDataMgr::GetExtensionAbilityInfoByTypeName(uint32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &infos, const std::string &typeName) const
 */
HWTEST_F(BmsDataMgrTest, GetExtensionAbilityInfoByTypeName_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    uint32_t flags = static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_BY_TYPE_NAME);
    int32_t userId = 100;
    std::vector<ExtensionAbilityInfo> infos;
    std::string typeName = "type_test";
    std::string bundleName = "test";
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.isSystemApp = true;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    bundleDataMgr.GetExtensionAbilityInfoByTypeName(flags, userId, infos, typeName);

    InnerExtensionInfo innerExtensionInfo;
    innerExtensionInfo.name = "test_innerExtensionInfo";
    info.InsertExtensionInfo("test_key", innerExtensionInfo);
    bundleDataMgr.GetExtensionAbilityInfoByTypeName(flags, userId, infos, typeName);
    EXPECT_FALSE(bundleDataMgr.bundleInfos_.empty());
}

/**
 * @tc.number: GetBundleNamesForNewUser_0001
 * @tc.name: GetBundleNamesForNewUser
 * @tc.desc: test GetBundleNamesForNewUser()
 */
HWTEST_F(BmsDataMgrTest, GetBundleNamesForNewUser_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::vector<std::string> result = bundleDataMgr.GetBundleNamesForNewUser();
    EXPECT_EQ(result.empty(), true);
}

/**
 * @tc.number: CreateAppEl5GroupDir_0001
 * @tc.name: CreateAppEl5GroupDir
 * @tc.desc: test CreateAppEl5GroupDir(const std::string &bundleName, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, CreateAppEl5GroupDir_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = Constants::INVALID_USERID;
    bundleDataMgr.CreateAppEl5GroupDir(BUNDLE_NAME, userId);
    EXPECT_EQ(bundleDataMgr.bundleInfos_.find(BUNDLE_NAME), bundleDataMgr.bundleInfos_.end());

    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.needAppDetail = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    bundleDataMgr.UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    bundleDataMgr.CreateAppEl5GroupDir(BUNDLE_NAME, userId);
    EXPECT_NE(bundleDataMgr.bundleInfos_.find(BUNDLE_NAME),  bundleDataMgr.bundleInfos_.end());
    bundleDataMgr.UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: SetExtNameOrMIMEToApp_0001
 * @tc.name: SetExtNameOrMIMEToApp
 * @tc.desc: test SetExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const std::string &extName, const std::string &mimeType)
 */
HWTEST_F(BmsDataMgrTest, SetExtNameOrMIMEToApp_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string moduleName = "moduleName";
    std::string abilityName = "abilityName";
    std::string extName = "";
    std::string mimeType = "";
    ErrCode ret = bundleDataMgr.SetExtNameOrMIMEToApp(BUNDLE_NAME, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.needAppDetail = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    bundleDataMgr.UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    ret = bundleDataMgr.SetExtNameOrMIMEToApp(BUNDLE_NAME, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_OK);

    extName = "extName";
    ret = bundleDataMgr.SetExtNameOrMIMEToApp(BUNDLE_NAME, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    extName = "";
    mimeType = "mimeType";
    ret = bundleDataMgr.SetExtNameOrMIMEToApp(BUNDLE_NAME, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    bundleDataMgr.UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: DelExtNameOrMIMEToApp_0001
 * @tc.name: DelExtNameOrMIMEToApp
 * @tc.desc: test DelExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const std::string &extName, const std::string &mimeType)
 */
HWTEST_F(BmsDataMgrTest, DelExtNameOrMIMEToApp_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string moduleName = "moduleName";
    std::string abilityName = "abilityName";
    std::string extName = "";
    std::string mimeType = "";
    ErrCode ret = bundleDataMgr.DelExtNameOrMIMEToApp(BUNDLE_NAME, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.needAppDetail = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    bundleDataMgr.UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
    ret = bundleDataMgr.DelExtNameOrMIMEToApp(BUNDLE_NAME, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_OK);

    extName = "extName";
    ret = bundleDataMgr.DelExtNameOrMIMEToApp(BUNDLE_NAME, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    extName = "";
    mimeType = "mimeType";
    ret = bundleDataMgr.DelExtNameOrMIMEToApp(BUNDLE_NAME, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    bundleDataMgr.UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}


/**
 * @tc.number: GetJsonProfile_0001
 * @tc.name: GetJsonProfile
 * @tc.desc: test GetJsonProfile(ProfileType profileType, const std::string &bundleName,
    const std::string &moduleName, std::string &profile, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, GetJsonProfile_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string moduleName = "moduleName";
    std::string profile = "profile";
    int32_t userId = Constants::INVALID_USERID;
    ErrCode ret = bundleDataMgr.GetJsonProfile(ProfileType::INTENT_PROFILE, BUNDLE_NAME,
        moduleName, profile, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.needAppDetail = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    bundleDataMgr.UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.GetJsonProfile(ProfileType::INTENT_PROFILE, BUNDLE_NAME,
        moduleName, profile, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    bundleDataMgr.UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: GenerateNewUserDataGroupInfos_0001
 * @tc.name: GenerateNewUserDataGroupInfos
 * @tc.desc: test GenerateNewUserDataGroupInfos(const std::string &bundleName, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, GenerateNewUserDataGroupInfos_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "bundleName_test";
    int32_t userId = Constants::INVALID_USERID;
    bundleDataMgr.GenerateNewUserDataGroupInfos(bundleName, userId);
    EXPECT_EQ(bundleDataMgr.bundleInfos_.find(bundleName), bundleDataMgr.bundleInfos_.end());
}

/**
 * @tc.number: GenerateNewUserDataGroupInfos_0002
 * @tc.name: GenerateNewUserDataGroupInfos
 * @tc.desc: test GenerateNewUserDataGroupInfos(const std::string &bundleName, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, GenerateNewUserDataGroupInfos_0002, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    std::string bundleName = "bundleName_test";
    std::string appName = "appName_test";
    bundleInfo.name = bundleName;
    bundleInfo.applicationInfo.name = appName;
    ApplicationInfo applicationInfo;
    std::string dataGroupId = "dataGroupId_test";
    DataGroupInfo dataGroupInfo;
    applicationInfo.name = bundleName;
    applicationInfo.bundleName = bundleName;
    applicationInfo.needAppDetail = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.AddDataGroupInfo(dataGroupId, dataGroupInfo);
    int32_t userId = Constants::ANY_USERID;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, innerBundleInfo);
    bundleDataMgr.GenerateNewUserDataGroupInfos(bundleName, userId);

    auto dataGroupInfos = bundleDataMgr.bundleInfos_.find(bundleName)->second.GetDataGroupInfos();
    EXPECT_EQ(dataGroupInfos.empty(), false);
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: DeleteGroupDirsForException_0001
 * @tc.name: DeleteGroupDirsForException
 * @tc.desc: test DeleteGroupDirsForException(const InnerBundleInfo &oldInfo, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, DeleteGroupDirsForException_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo oldInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = "bundleInfoName";
    bundleInfo.applicationInfo.name = APP_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = "bundleInfoName";
    applicationInfo.bundleName = "bundleInfoName";
    applicationInfo.needAppDetail = false;
    int32_t userId = Constants::ANY_USERID;
    oldInfo.SetBaseBundleInfo(bundleInfo);
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    bundleDataMgr.UpdateBundleInstallState("bundleInfoName", InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo("bundleInfoName", oldInfo);
    bundleDataMgr.DeleteGroupDirsForException(oldInfo, userId);
    EXPECT_NE(bundleDataMgr.bundleInfos_.find(oldInfo.GetBundleName()), bundleDataMgr.bundleInfos_.end());
    bundleDataMgr.UpdateBundleInstallState("bundleInfoName", InstallState::UNINSTALL_START);
}

/**
 * @tc.number: DeleteGroupDirsForException_0002
 * @tc.name: DeleteGroupDirsForException
 * @tc.desc: test DeleteGroupDirsForException(const InnerBundleInfo &oldInfo, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, DeleteGroupDirsForException_0002, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo oldInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = "bundleInfoName";
    bundleInfo.applicationInfo.name = APP_NAME;
    std::string dataGroupId = "dataGroupId";
    DataGroupInfo dataGroupInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.name = "bundleInfoName";
    applicationInfo.bundleName = "bundleInfoName";
    applicationInfo.needAppDetail = false;
    int32_t userId = Constants::ANY_USERID;
    oldInfo.SetBaseBundleInfo(bundleInfo);
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    oldInfo.AddDataGroupInfo(dataGroupId, dataGroupInfo);
    bundleDataMgr.UpdateBundleInstallState("bundleInfoName", InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo("bundleInfoName", oldInfo);

    bundleDataMgr.DeleteGroupDirsForException(oldInfo, userId);
    auto ret = bundleDataMgr.bundleInfos_.find(oldInfo.GetBundleName())->second.GetDataGroupInfos();
    EXPECT_EQ(ret.empty(), false);
    bundleDataMgr.UpdateBundleInstallState("bundleInfoName", InstallState::UNINSTALL_START);
}

/**
 * @tc.number: HandleGroupIdAndIndex_0001
 * @tc.name: HandleGroupIdAndIndex
 * @tc.desc: test HandleGroupIdAndIndex(const std::string &bundleName, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, HandleGroupIdAndIndex_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    constexpr int8_t DATA_GROUP_INDEX_START = 1;
    constexpr int32_t DATA_GROUP_UID_OFFSET = 100000;
    std::set<std::string> errorGroupIds = {"group1", "group2"};
    std::map<int32_t, std::string> indexMap = {{100, "existing_group"}};
    std::map<std::string, int32_t> groupIdMap = {{"existing_group", 100}};
    bundleDataMgr.HandleGroupIdAndIndex(errorGroupIds, indexMap, groupIdMap);
    EXPECT_EQ(groupIdMap["existing_group"], 100);

    bundleDataMgr.HandleGroupIdAndIndex(errorGroupIds, indexMap, groupIdMap);
    EXPECT_NE(groupIdMap.find("group1"), groupIdMap.end());
    EXPECT_NE(groupIdMap.find("group2"), groupIdMap.end());

    for (int i = DATA_GROUP_INDEX_START; i < DATA_GROUP_UID_OFFSET; ++i) {
        indexMap[i] = "dummy_group";
    }
    bundleDataMgr.HandleGroupIdAndIndex(errorGroupIds, indexMap, groupIdMap);
    EXPECT_EQ(groupIdMap["group1"], DATA_GROUP_INDEX_START);
}

/**
 * @tc.number: HandleErrorDataGroupInfos_0001
 * @tc.name: HandleErrorDataGroupInfos
 * @tc.desc: test HandleErrorDataGroupInfos(
    const std::map<std::string, int32_t> &groupIdMap,
    const std::map<std::string, std::set<std::string>> &needProcessGroupInfoBundleNames)
 */
HWTEST_F(BmsDataMgrTest, HandleErrorDataGroupInfos_0001, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::map<std::string, int32_t> groupIdMap = {{"group1", 100}};
    std::map<std::string, std::set<std::string>> needBundleNames = {{"invalid_bundle", {"group1"}}};
    bool ret = dataMgr->HandleErrorDataGroupInfos(groupIdMap, needBundleNames);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: HandleErrorDataGroupInfos_0002
 * @tc.name: HandleErrorDataGroupInfos
 * @tc.desc: test HandleErrorDataGroupInfos(
    const std::map<std::string, int32_t> &groupIdMap,
    const std::map<std::string, std::set<std::string>> &needProcessGroupInfoBundleNames)
 */
HWTEST_F(BmsDataMgrTest, HandleErrorDataGroupInfos_0002, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "empty_bundle";
    InnerBundleInfo emptyInfo;
    bool ret1 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret1, true);
    bool ret2 = dataMgr->AddInnerBundleInfo(bundleName, emptyInfo);
    EXPECT_EQ(ret2, true);

    std::map<std::string, int32_t> groupIdMap = {{"group1", 100}};
    std::map<std::string, std::set<std::string>> needBundleNames = {{bundleName, {"group1"}}};
    bool ret3 = dataMgr->HandleErrorDataGroupInfos(groupIdMap, needBundleNames);
    EXPECT_EQ(ret3, true);
    dataMgr->bundleInfos_.erase(bundleName);
    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: HandleErrorDataGroupInfos_0003
 * @tc.name: HandleErrorDataGroupInfos
 * @tc.desc: test HandleErrorDataGroupInfos(
    const std::map<std::string, int32_t> &groupIdMap,
    const std::map<std::string, std::set<std::string>> &needProcessGroupInfoBundleNames)
 */
HWTEST_F(BmsDataMgrTest, HandleErrorDataGroupInfos_0003, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "empty_bundle";
    InnerBundleInfo innerBundleInfo;
    std::string dataGroupId = "dataGroupId";
    DataGroupInfo dataGroupInfo;
    innerBundleInfo.AddDataGroupInfo(dataGroupId, dataGroupInfo);
    bool ret1 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret1, true);
    bool ret2 = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret2, true);

    std::map<std::string, int32_t> groupIdMap = {{"group1", 100}};
    std::map<std::string, std::set<std::string>> needBundleNames = {{bundleName, {"group1"}}};
    bool ret3 = dataMgr->HandleErrorDataGroupInfos(groupIdMap, needBundleNames);
    EXPECT_EQ(ret3, true);

    needBundleNames[bundleName].erase("group1");
    needBundleNames[bundleName].insert("group2");
    bool ret4 = dataMgr->HandleErrorDataGroupInfos(groupIdMap, needBundleNames);
    EXPECT_EQ(ret4, false);
    dataMgr->bundleInfos_.erase(bundleName);
    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: HandleErrorDataGroupInfos_0004
 * @tc.name: HandleErrorDataGroupInfos
 * @tc.desc: test HandleErrorDataGroupInfos(
    const std::map<std::string, int32_t> &groupIdMap,
    const std::map<std::string, std::set<std::string>> &needProcessGroupInfoBundleNames)
 */
HWTEST_F(BmsDataMgrTest, HandleErrorDataGroupInfos_0004, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "empty_bundle";
    InnerBundleInfo innerBundleInfo;
    std::string dataGroupId = "dataGroupId";
    DataGroupInfo dataGroupInfo;
    innerBundleInfo.AddDataGroupInfo(dataGroupId, dataGroupInfo);
    bool ret1 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret1, true);
    bool ret2 = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret2, true);

    std::map<std::string, int32_t> groupIdMap = {{"dataGroupId", 100}};
    std::map<std::string, std::set<std::string>> needBundleNames = {{bundleName, {"dataGroupId"}}};
    bool ret3 = dataMgr->HandleErrorDataGroupInfos(groupIdMap, needBundleNames);
    EXPECT_EQ(ret3, true);
    dataMgr->bundleInfos_.erase(bundleName);
    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: GetOldAppIds_0001
 * @tc.name: GetOldAppIds
 * @tc.desc: test GetOldAppIds(const std::string &bundleName, std::vector<std::string> &appIds)
 */
HWTEST_F(BmsDataMgrTest, GetOldAppIds_0001, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "bundleName";
    std::vector<std::string> appIds;
    bool ret1 = dataMgr->GetOldAppIds(bundleName, appIds);
    EXPECT_EQ(ret1, false);
}

/**
 * @tc.number: GetOldAppIds_0002
 * @tc.name: GetOldAppIds
 * @tc.desc: test GetOldAppIds(const std::string &bundleName, std::vector<std::string> &appIds)
 */
HWTEST_F(BmsDataMgrTest, GetOldAppIds_0002, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "bundleName";
    InnerBundleInfo innerBundleInfo;
    std::string dataGroupId = "dataGroupId";
    DataGroupInfo dataGroupInfo;
    innerBundleInfo.AddDataGroupInfo(dataGroupId, dataGroupInfo);
    bool ret1 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret1, true);
    bool ret2 = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret2, true);

    std::vector<std::string> appIds;
    bool ret3 = dataMgr->GetOldAppIds(bundleName, appIds);
    EXPECT_EQ(ret3, true);
    dataMgr->bundleInfos_.erase(bundleName);
    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: GetBundleNameByAppId_0001
 * @tc.name: GetBundleNameByAppId
 * @tc.desc: test BundleDataMgr::GetBundleNameByAppId(const std::string &appId) const
 */
HWTEST_F(BmsDataMgrTest, GetBundleNameByAppId_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string appId = "";
    std::string bundleName = "";
    auto ret = bundleDataMgr.GetBundleNameByAppId(appId, bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);

    appId = "test";
    bundleName = "test";
    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.GetBundleNameByAppId(appId, bundleName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetDirForAtomicService_0001
 * @tc.name: GetDirForAtomicService
 * @tc.desc: test BundleDataMgr::GetDirForAtomicService(const std::string &bundleName, std::string &dataDir) const
 */
HWTEST_F(BmsDataMgrTest, GetDirForAtomicService_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "";
    std::string dataDir = "";
    auto ret = bundleDataMgr.GetDirForAtomicService(bundleName, dataDir);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_GET_ACCOUNT_INFO_FAILED);
    #else
    EXPECT_EQ(ret, ERR_OK);
    #endif
}

/**
 * @tc.number: GetDirForAtomicServiceByUserId_0001
 * @tc.name: GetDirForAtomicServiceByUserId
 * @tc.desc: test BundleDataMgr::GetDirForAtomicServiceByUserId(const std::string &bundleName, int32_t userId,
    AccountSA::OhosAccountInfo &accountInfo, std::string &dataDir) const
 */
HWTEST_F(BmsDataMgrTest, GetDirForAtomicServiceByUserId_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "";
    int32_t userId = 10;
    AccountSA::OhosAccountInfo accountInfo;
    std::string dataDir = "";
    auto ret = bundleDataMgr.GetDirForAtomicServiceByUserId(bundleName, userId, accountInfo, dataDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_GET_ACCOUNT_INFO_FAILED);
}

/**
 * @tc.number: GetDirForApp_0001
 * @tc.name: GetDirForApp
 * @tc.desc: test BundleDataMgr::GetDirForApp(const std::string &bundleName, const int32_t appIndex) const
 */
HWTEST_F(BmsDataMgrTest, GetDirForApp_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "";
    int32_t appIndex = 0;
    auto ret = bundleDataMgr.GetDirForApp(bundleName, appIndex);
    EXPECT_EQ(ret, bundleName);

    appIndex = 1;
    ret = bundleDataMgr.GetDirForApp(bundleName, appIndex);
    EXPECT_EQ(ret, "+clone-1+");
}

/**
 * @tc.number: GetDirByBundleNameAndAppIndex_0001
 * @tc.name: GetDirByBundleNameAndAppIndex
 * @tc.desc: test BundleDataMgr::GetDirByBundleNameAndAppIndex(const std::string &bundleName,
    const int32_t appIndex, std::string &dataDir) const
 */
HWTEST_F(BmsDataMgrTest, GetDirByBundleNameAndAppIndex_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "";
    int32_t appIndex = -1;
    std::string dataDir = "";
    auto ret = bundleDataMgr.GetDirByBundleNameAndAppIndex(bundleName, appIndex, dataDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_GET_DIR_INVALID_APP_INDEX);

    appIndex = 1;
    ret = bundleDataMgr.GetDirByBundleNameAndAppIndex(bundleName, appIndex, dataDir);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetBundleDir_0001
 * @tc.name: GetBundleDir
 * @tc.desc: test BundleDataMgr::GetBundleDir(int32_t userId, BundleType type,
    AccountSA::OhosAccountInfo &accountInfo, BundleDir &bundleDir) const
 */
HWTEST_F(BmsDataMgrTest, GetBundleDir_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = 10;
    BundleType type = BundleType::ATOMIC_SERVICE;
    AccountSA::OhosAccountInfo accountInfo;
    BundleDir bundleDir;
    auto ret = bundleDataMgr.GetBundleDir(userId, type, accountInfo, bundleDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_GET_ACCOUNT_INFO_FAILED);

    type = BundleType::APP;
    ret = bundleDataMgr.GetBundleDir(userId, type, accountInfo, bundleDir);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetAllBundleDirs_0001
 * @tc.name: GetAllBundleDirs
 * @tc.desc: test BundleDataMgr::GetAllBundleDirs(int32_t userId, std::vector<BundleDir> &bundleDirs)
 */
HWTEST_F(BmsDataMgrTest, GetAllBundleDirs_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = 10;
    std::vector<BundleDir> bundleDirs;
    auto ret = bundleDataMgr.GetAllBundleDirs(userId, bundleDirs);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    std::string bundleName = "test";
    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.GetAllBundleDirs(userId, bundleDirs);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GreatOrEqualTargetAPIVersion_0001
 * @tc.name: GreatOrEqualTargetAPIVersion
 * @tc.desc: test GreatOrEqualTargetAPIVersion
 */
HWTEST_F(BmsDataMgrTest, GreatOrEqualTargetAPIVersion_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    bool ret = bundleDataMgr.GreatOrEqualTargetAPIVersion(ServiceConstants::API_VERSION_MAX + 1, 0, 0);
    EXPECT_FALSE(ret);
    ret = bundleDataMgr.GreatOrEqualTargetAPIVersion(0, 0, 0);
    EXPECT_FALSE(ret);
    ret = bundleDataMgr.GreatOrEqualTargetAPIVersion(ServiceConstants::API_VERSION_MAX,
        ServiceConstants::API_VERSION_MAX + 1, 0);
    EXPECT_FALSE(ret);
    ret = bundleDataMgr.GreatOrEqualTargetAPIVersion(ServiceConstants::API_VERSION_MAX, -1, 0);
    EXPECT_FALSE(ret);
    ret = bundleDataMgr.GreatOrEqualTargetAPIVersion(ServiceConstants::API_VERSION_MAX,
            ServiceConstants::API_VERSION_MAX, ServiceConstants::API_VERSION_MAX + 1);
    EXPECT_FALSE(ret);
    ret = bundleDataMgr.GreatOrEqualTargetAPIVersion(ServiceConstants::API_VERSION_MAX,
        ServiceConstants::API_VERSION_MAX, -1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsObtainAbilityInfo_0001
 * @tc.name: IsObtainAbilityInfo
 * @tc.desc: test BundleDataMgr::IsObtainAbilityInfo(const Want &want, int32_t userId, AbilityInfo &abilityInfo)
 */
HWTEST_F(BmsDataMgrTest, IsObtainAbilityInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    int32_t userId = 10;
    AbilityInfo abilityInfo;
    auto ret = bundleDataMgr.IsObtainAbilityInfo(want, userId, abilityInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsObtainAbilityInfo_0002
 * @tc.name: IsObtainAbilityInfo
 * @tc.desc: test BundleDataMgr::IsObtainAbilityInfo(const Want &want, int32_t userId, AbilityInfo &abilityInfo)
 */
HWTEST_F(BmsDataMgrTest, IsObtainAbilityInfo_0002, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    Want want;
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    want.SetElement(element);
    AbilityInfo abilityInfo;
    auto ret = bundleDataMgr.IsObtainAbilityInfo(want, USERID, abilityInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsObtainAbilityInfo_0003
 * @tc.name: IsObtainAbilityInfo
 * @tc.desc: test BundleDataMgr::IsObtainAbilityInfo(const Want &want, int32_t userId, AbilityInfo &abilityInfo)
 */
HWTEST_F(BmsDataMgrTest, IsObtainAbilityInfo_0003, TestSize.Level1)
{
    InnerBundleInfo info;
    auto dataMgr = GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    Want want;
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    want.SetElement(element);
    AbilityInfo abilityInfo;
    bool ret = dataMgr->IsObtainAbilityInfo(want, USERID, abilityInfo);
    EXPECT_TRUE(ret);
    dataMgr->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: IsObtainAbilityInfo_0004
 * @tc.name: IsObtainAbilityInfo
 * @tc.desc: test BundleDataMgr::IsObtainAbilityInfo(const Want &want, int32_t userId, AbilityInfo &abilityInfo)
 */
HWTEST_F(BmsDataMgrTest, IsObtainAbilityInfo_0004, TestSize.Level1)
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
    Want want;
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    element.SetAbilityName(ABILITY_NAME);
    want.SetElement(element);
    AbilityInfo abilityInfo;
    auto ret3 = dataMgr->IsObtainAbilityInfo(want, USERID, abilityInfo);
    EXPECT_FALSE(ret3);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: GetAllPluginInfo_0001
 * @tc.name: GetAllPluginInfo
 * @tc.desc: test BundleDataMgr::GetAllPluginInfo(const std::string &hostBundleName, int32_t userId,
    std::vector<PluginBundleInfo> &pluginBundleInfos)
 */
HWTEST_F(BmsDataMgrTest, GetAllPluginInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string hostBundleName = "test1";
    int32_t userId = 10;
    std::vector<PluginBundleInfo> pluginBundleInfos;
    auto ret = bundleDataMgr.GetAllPluginInfo(hostBundleName, userId, pluginBundleInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.GetAllPluginInfo(hostBundleName, userId, pluginBundleInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(hostBundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(hostBundleName, info);
    ret = bundleDataMgr.GetAllPluginInfo(hostBundleName, userId, pluginBundleInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: AddPluginInfo_0001
 * @tc.name: AddPluginInfo
 * @tc.desc: test BundleDataMgr::AddPluginInfo(const std::string &bundleName,
    const PluginBundleInfo &pluginBundleInfo, const int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, AddPluginInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "test1";
    PluginBundleInfo pluginBundleInfo;
    int32_t userId = 10;
    auto ret = bundleDataMgr.AddPluginInfo(bundleName, pluginBundleInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.AddPluginInfo(bundleName, pluginBundleInfo, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_ADD_PLUGIN_INFO_ERROR);
}

/**
 * @tc.number: RemovePluginInfo_0001
 * @tc.name: RemovePluginInfo
 * @tc.desc: test RemovePluginInfo(const std::string &bundleName,
    const std::string &pluginBundleName, const int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, RemovePluginInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "test1";
    std::string pluginBundleName = "test2";
    int32_t userId = 10;
    auto ret = bundleDataMgr.RemovePluginInfo(bundleName, pluginBundleName, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.RemovePluginInfo(bundleName, pluginBundleName, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_REMOVE_PLUGIN_INFO_ERROR);
}

/**
 * @tc.number: GetPluginBundleInfo_0001
 * @tc.name: GetPluginBundleInfo
 * @tc.desc: test BundleDataMgr::GetPluginBundleInfo(const std::string &hostBundleName,
    const std::string &pluginBundleName, const int32_t userId, PluginBundleInfo &pluginBundleInfo)
 */
HWTEST_F(BmsDataMgrTest, GetPluginBundleInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string hostBundleName = "";
    std::string pluginBundleName = "test2";
    int32_t userId = 10;
    PluginBundleInfo pluginBundleInfo;
    auto ret = bundleDataMgr.GetPluginBundleInfo(hostBundleName, pluginBundleName, userId, pluginBundleInfo);
    EXPECT_EQ(ret, false);

    hostBundleName = "test1";
    ret = bundleDataMgr.GetPluginBundleInfo(hostBundleName, pluginBundleName, userId, pluginBundleInfo);
    EXPECT_EQ(ret, false);

    std::string bundleName = "test1";
    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.GetPluginBundleInfo(hostBundleName, pluginBundleName, userId, pluginBundleInfo);
    EXPECT_EQ(ret, false);

    userId = ServiceConstants::NOT_EXIST_USERID;
    ret = bundleDataMgr.GetPluginBundleInfo(hostBundleName, pluginBundleName, userId, pluginBundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: FetchPluginBundleInfo_0001
 * @tc.name: FetchPluginBundleInfo
 * @tc.desc: test BundleDataMgr::FetchPluginBundleInfo(const std::string &hostBundleName,
    const std::string &pluginBundleName, PluginBundleInfo &pluginBundleInfo)
 */
HWTEST_F(BmsDataMgrTest, FetchPluginBundleInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string hostBundleName = "";
    std::string pluginBundleName = "test2";
    PluginBundleInfo pluginBundleInfo;
    auto ret = bundleDataMgr.FetchPluginBundleInfo(hostBundleName, pluginBundleName, pluginBundleInfo);
    EXPECT_EQ(ret, false);

    hostBundleName = "test1";
    ret = bundleDataMgr.FetchPluginBundleInfo(hostBundleName, pluginBundleName, pluginBundleInfo);
    EXPECT_EQ(ret, false);

    std::string bundleName = "test1";
    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.FetchPluginBundleInfo(hostBundleName, pluginBundleName, pluginBundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: UpdatePluginBundleInfo_0001
 * @tc.name: UpdatePluginBundleInfo
 * @tc.desc: test BundleDataMgr::UpdatePluginBundleInfo(const std::string &hostBundleName,
    const PluginBundleInfo &pluginBundleInfo)
 */
HWTEST_F(BmsDataMgrTest, UpdatePluginBundleInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string hostBundleName = "test1";
    PluginBundleInfo pluginBundleInfo;
    auto ret = bundleDataMgr.UpdatePluginBundleInfo(hostBundleName, pluginBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    std::string bundleName = "test1";
    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.UpdatePluginBundleInfo(hostBundleName, pluginBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_ADD_PLUGIN_INFO_ERROR);
}

/**
 * @tc.number: RemovePluginFromUserInfo_0001
 * @tc.name: RemovePluginFromUserInfo
 * @tc.desc: test BundleDataMgr::RemovePluginFromUserInfo(const std::string &hostBundleName,
    const std::string &pluginBundleName, const int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, RemovePluginFromUserInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string hostBundleName = "test1";
    std::string pluginBundleName = "test2";
    int32_t userId = 10;
    auto ret = bundleDataMgr.RemovePluginFromUserInfo(hostBundleName, pluginBundleName, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    std::string bundleName = "test1";
    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.RemovePluginFromUserInfo(hostBundleName, pluginBundleName, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_REMOVE_PLUGIN_INFO_ERROR);
}

/**
 * @tc.number: GetPluginAbilityInfo_0001
 * @tc.name: GetPluginAbilityInfo
 * @tc.desc: test BundleDataMgr::GetPluginAbilityInfo(const std::string &hostBundleName,
    const std::string &pluginBundleName, const std::string &pluginModuleName,
    const std::string &pluginAbilityName, const int32_t userId, AbilityInfo &abilityInfo)
 */
HWTEST_F(BmsDataMgrTest, GetPluginAbilityInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string hostBundleName = "test1";
    std::string pluginBundleName = "test2";
    std::string pluginModuleName = "test3";
    std::string pluginAbilityName = "test4";
    int32_t userId = 10;
    AbilityInfo abilityInfo;
    auto ret = bundleDataMgr.GetPluginAbilityInfo(hostBundleName, pluginBundleName,
        pluginModuleName, pluginAbilityName, userId, abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    std::string bundleName = "test1";
    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.GetPluginAbilityInfo(hostBundleName, pluginBundleName,
        pluginModuleName, pluginAbilityName, userId, abilityInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_GET_PLUGIN_INFO_ERROR);

    userId = ServiceConstants::NOT_EXIST_USERID;
    ret = bundleDataMgr.GetPluginAbilityInfo(hostBundleName, pluginBundleName,
        pluginModuleName, pluginAbilityName, userId, abilityInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_NOT_FOUND);
}

/**
 * @tc.number: GetPluginHapModuleInfo_0001
 * @tc.name: GetPluginHapModuleInfo
 * @tc.desc: test BundleDataMgr::GetPluginHapModuleInfo(const std::string &hostBundleName,
    const std::string &pluginBundleName, const std::string &pluginModuleName, const int32_t userId,
     HapModuleInfo &hapModuleInfo)
 */
HWTEST_F(BmsDataMgrTest, GetPluginHapModuleInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string hostBundleName = "test1";
    std::string pluginBundleName = "test2";
    std::string pluginModuleName = "test3";
    int32_t userId = 10;
    HapModuleInfo hapModuleInfo;
    auto ret = bundleDataMgr.GetPluginHapModuleInfo(hostBundleName, pluginBundleName,
        pluginModuleName, userId, hapModuleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.GetPluginHapModuleInfo(hostBundleName, pluginBundleName,
        pluginModuleName, userId, hapModuleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    std::string bundleName = "test1";
    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.GetPluginHapModuleInfo(hostBundleName, pluginBundleName,
        pluginModuleName, userId, hapModuleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_GET_PLUGIN_INFO_ERROR);
}

/**
 * @tc.number: UnregisterPluginEventCallback_0001
 * @tc.name: UnregisterPluginEventCallback
 * @tc.desc: test BundleDataMgr::UnregisterPluginEventCallback(const sptr<IBundleEventCallback> &pluginEventCallback)
 */
HWTEST_F(BmsDataMgrTest, UnregisterPluginEventCallback_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName;
    auto ret = bundleDataMgr.UnregisterPluginEventCallback(nullptr, bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: GetModuleNameByBundleAndAbility_0001
 * @tc.name: GetModuleNameByBundleAndAbility
 * @tc.desc: test GetModuleNameByBundleAndAbility(
    const std::string& bundleName, const std::string& abilityName)
 */
HWTEST_F(BmsDataMgrTest, GetModuleNameByBundleAndAbility_0001, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::string bundleName = "";
    std::string abilityName = "";
    auto ret = dataMgr->GetModuleNameByBundleAndAbility(bundleName, abilityName);
    EXPECT_EQ(ret, "");

    bundleName = "bundleName";
    abilityName = "abilityName";
    auto ret1 = dataMgr->GetModuleNameByBundleAndAbility(bundleName, abilityName);
    EXPECT_EQ(ret1, "");

    InnerBundleInfo innerBundleInfo;
    std::string dataGroupId = "dataGroupId";
    DataGroupInfo dataGroupInfo;
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = abilityName;
    innerAbilityInfo.moduleName = "moduleName";
    std::map<std::string, InnerAbilityInfo> abilityInfos = {{abilityName, innerAbilityInfo}};
    innerBundleInfo.AddModuleAbilityInfo(abilityInfos);
    innerBundleInfo.AddDataGroupInfo(dataGroupId, dataGroupInfo);
    bool ret2 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret2, true);
    bool ret3 = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret3, true);
    auto ret4 = dataMgr->GetModuleNameByBundleAndAbility(bundleName, "noAbilityName");
    EXPECT_EQ(ret4, "");

    auto ret5 = dataMgr->GetModuleNameByBundleAndAbility(bundleName, abilityName);
    EXPECT_EQ(ret5, "moduleName");
    dataMgr->bundleInfos_.erase(bundleName);
    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: SetAdditionalInfo_0001
 * @tc.name: SetAdditionalInfo
 * @tc.desc: test SetAdditionalInfo(
    const std::string& bundleName, const std::string& additionalInfo)
 */
HWTEST_F(BmsDataMgrTest, SetAdditionalInfo_0001, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string additionalInfo;
    auto ret = dataMgr->SetAdditionalInfo(bundleName, additionalInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    InnerBundleInfo innerBundleInfo;
    std::string dataGroupId = "dataGroupId";
    DataGroupInfo dataGroupInfo;
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = abilityName;
    innerAbilityInfo.moduleName = "moduleName";
    std::map<std::string, InnerAbilityInfo> abilityInfos = {{abilityName, innerAbilityInfo}};
    innerBundleInfo.AddModuleAbilityInfo(abilityInfos);
    innerBundleInfo.AddDataGroupInfo(dataGroupId, dataGroupInfo);
    bool ret2 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret2, true);
    bool ret3 = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret3, true);
    auto ret4 = dataMgr->SetAdditionalInfo(bundleName, additionalInfo);
    EXPECT_EQ(ret4, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    auto ret6 = dataMgr->SetAdditionalInfo(bundleName, additionalInfo);
    EXPECT_EQ(ret6, ERR_OK);
    dataMgr->bundleInfos_.erase(bundleName);
    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: ConvertServiceHspToSharedBundleInfo_0001
 * @tc.name: ConvertServiceHspToSharedBundleInfo
 * @tc.desc: test ConvertServiceHspToSharedBundleInfo(const InnerBundleInfo &innerBundleInfo,
    std::vector<BaseSharedBundleInfo> &baseSharedBundleInfos)
 */
HWTEST_F(BmsDataMgrTest, ConvertServiceHspToSharedBundleInfo_0001, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo innerBundleInfo;
    std::vector<BaseSharedBundleInfo> baseSharedBundleInfos;
    BundleInfo bundleInfo;
    dataMgr->ConvertServiceHspToSharedBundleInfo(innerBundleInfo, baseSharedBundleInfos);
    auto ret1 = innerBundleInfo.GetAppServiceHspInfo(bundleInfo);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: CreateBundleDataDir_0002
 * @tc.name: CreateBundleDataDir
 * @tc.desc: test CreateBundleDataDir(const InnerBundleInfo &innerBundleInfo,
    std::vector<BaseSharedBundleInfo> &baseSharedBundleInfos)
 */
HWTEST_F(BmsDataMgrTest, CreateBundleDataDir_0002, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    int32_t userId = Constants::INVALID_USERID;
    std::string bundleName = "bundleName";
    InnerBundleInfo innerBundleInfo;
    std::string dataGroupId = "dataGroupId";
    DataGroupInfo dataGroupInfo;
    innerBundleInfo.AddDataGroupInfo(dataGroupId, dataGroupInfo);
    bool ret1 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret1, true);
    bool ret2 = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret2, true);
    ErrCode ret3 = dataMgr->CreateBundleDataDir(userId);

    EXPECT_EQ(ret3, ERR_OK);
    dataMgr->bundleInfos_.erase(bundleName);
    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: DeleteDesktopShortcutInfo_0007
 * @tc.name: DeleteDesktopShortcutInfo
 * @tc.desc: test ErrCode BundleDataMgr::DeleteDesktopShortcutInfo
    (const ShortcutInfo &shortcutInfo, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, DeleteDesktopShortcutInfo_0007, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    ShortcutInfo shortcutInfo;
    int32_t userId = 10;
    auto ret = bundleDataMgr.DeleteDesktopShortcutInfo(shortcutInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.DeleteDesktopShortcutInfo(shortcutInfo, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetAllDesktopShortcutInfo_0003
 * @tc.name: GetAllDesktopShortcutInfo
 * @tc.desc: test ErrCode BundleDataMgr::GetAllDesktopShortcutInfo
    (int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
 */
HWTEST_F(BmsDataMgrTest, GetAllDesktopShortcutInfo_0003, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    int32_t userId = 10;
    std::vector<ShortcutInfo> shortcutInfos;
    auto ret = bundleDataMgr.GetAllDesktopShortcutInfo(userId, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.GetAllDesktopShortcutInfo(userId, shortcutInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetAllDesktopShortcutInfo_0004
 * @tc.name: GetAllDesktopShortcutInfo
 * @tc.desc: test ErrCode GetAllDesktopShortcutInfo
 */
HWTEST_F(BmsDataMgrTest, GetAllDesktopShortcutInfo_0004, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(USERID);
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    bool isIdIllegal = false;
    shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);
    std::vector<ShortcutInfo> shortcutInfos;
    auto ret = bundleDataMgr.GetAllDesktopShortcutInfo(USERID, shortcutInfos);
    EXPECT_EQ(ret, ERR_OK);
    shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
}

/**
 * @tc.number: GetBundleInfosForContinuation_0001
 * @tc.name: GetBundleInfosForContinuation
 * @tc.desc: test oid BundleDataMgr::GetBundleInfosForContinuation
    (std::vector<BundleInfo> &bundleInfos) const
 */
HWTEST_F(BmsDataMgrTest, GetBundleInfosForContinuation_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::vector<BundleInfo> bundleInfos;
    bundleDataMgr.GetBundleInfosForContinuation(bundleInfos);
    EXPECT_TRUE(bundleInfos.empty());

    BundleInfo bundleInfo;
    bundleInfos.push_back(bundleInfo);
    bundleDataMgr.GetBundleInfosForContinuation(bundleInfos);
    EXPECT_TRUE(bundleInfos.empty());
}

/**
 * @tc.number: GetContinueBundleNames_0001
 * @tc.name: GetContinueBundleNames
 * @tc.desc: test ErrCode BundleDataMgr::GetContinueBundleNames(
    const std::string &continueBundleName, std::vector<std::string> &bundleNames, int32_t userId)
 */
HWTEST_F(BmsDataMgrTest, GetContinueBundleNames_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string continueBundleName = "";
    std::vector<std::string> bundleNames;
    int32_t userId = 10;
    auto ret = bundleDataMgr.GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);

    continueBundleName = "test";
    ret = bundleDataMgr.GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(continueBundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(continueBundleName, info);
    ret = bundleDataMgr.GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_OK);

    bundleDataMgr.bundleInfos_.erase(continueBundleName);
    bundleDataMgr.installStates_.erase(continueBundleName);
}

/**
 * @tc.number: IsBundleInstalled_0001
 * @tc.name: IsBundleInstalled
 * @tc.desc: test ErrCode BundleDataMgr::IsBundleInstalled
    (const std::string &bundleName, int32_t userId, int32_t appIndex, bool &isInstalled)
 */
HWTEST_F(BmsDataMgrTest, IsBundleInstalled_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "test";
    int32_t userId = 10;
    int32_t appIndex = 1000;
    bool isInstalled = false;
    auto ret = bundleDataMgr.IsBundleInstalled(bundleName, userId, appIndex, isInstalled);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.IsBundleInstalled(bundleName, userId, appIndex, isInstalled);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);

    appIndex = 1;
    ret = bundleDataMgr.IsBundleInstalled(bundleName, userId, appIndex, isInstalled);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleInfo info;
    ApplicationInfo applicationInfo;
    applicationInfo.name = bundleName;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = bundleName;
    info.SetBaseApplicationInfo(applicationInfo);
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    ret = bundleDataMgr.IsBundleInstalled(bundleName, userId, appIndex, isInstalled);
    EXPECT_EQ(ret, ERR_OK);

    applicationInfo.bundleType = BundleType::SHARED;;
    info.SetBaseApplicationInfo(applicationInfo);
    appIndex = 0;
    info.CleanInnerBundleUserInfos();
    auto ret1 = bundleDataMgr.IsBundleInstalled(bundleName, userId, appIndex, isInstalled);
    EXPECT_EQ(ret1, ERR_OK);

    bundleDataMgr.bundleInfos_.erase(bundleName);
    bundleDataMgr.installStates_.erase(bundleName);
}

/**
 * @tc.number: IsBundleInstalled_0002
 * @tc.name: IsBundleInstalled
 * @tc.desc: test ErrCode BundleDataMgr::IsBundleInstalled
    (const std::string &bundleName, int32_t userId, int32_t appIndex, bool &isInstalled)
 */
HWTEST_F(BmsDataMgrTest, IsBundleInstalled_0002, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "test";
    int32_t userId = Constants::ANY_USERID;
    int32_t appIndex = 0;
    bool isInstalled = false;

    InnerBundleInfo info;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 10;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    auto ret = bundleDataMgr.IsBundleInstalled(bundleName, userId, appIndex, isInstalled);
    EXPECT_EQ(ret, ERR_OK);

    info.CleanInnerBundleUserInfos();
    appIndex = 1;
    ret = bundleDataMgr.IsBundleInstalled(bundleName, userId, appIndex, isInstalled);
    EXPECT_EQ(ret, ERR_OK);

    bundleDataMgr.bundleInfos_.erase(bundleName);
    bundleDataMgr.installStates_.erase(bundleName);
}

/**
 * @tc.number: UpdateIsPreInstallApp_0001
 * @tc.name: UpdateIsPreInstallApp
 * @tc.desc: test void BundleDataMgr::UpdateIsPreInstallApp
    (const std::string &bundleName, bool isPreInstallApp)
 */
HWTEST_F(BmsDataMgrTest, UpdateIsPreInstallApp_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "test";
    bundleDataMgr.UpdateIsPreInstallApp(bundleName, false);
    EXPECT_TRUE(bundleDataMgr.bundleInfos_.empty());

    InnerBundleInfo info;
    bundleDataMgr.UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bundleDataMgr.AddInnerBundleInfo(bundleName, info);
    bundleDataMgr.UpdateIsPreInstallApp(bundleName, true);
    EXPECT_FALSE(bundleDataMgr.bundleInfos_.empty());

    bundleDataMgr.bundleInfos_.erase(bundleName);
    bundleDataMgr.installStates_.erase(bundleName);
}

/**
 * @tc.number: CreateBundleDataDir_0003
 * @tc.name: CreateBundleDataDir
 * @tc.desc: test CreateBundleDataDir(const InnerBundleInfo &innerBundleInfo,
    std::vector<BaseSharedBundleInfo> &baseSharedBundleInfos)
 */
HWTEST_F(BmsDataMgrTest, CreateBundleDataDir_0003, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    int32_t userId = Constants::ANY_USERID;
    std::string bundleName = "bundleName";
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = Constants::ANY_USERID;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    bool ret1 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret1, true);
    bool ret2 = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret2, true);
    ErrCode ret3 = dataMgr->CreateBundleDataDir(userId);

    EXPECT_EQ(ret3, ERR_OK);
    dataMgr->bundleInfos_.erase(bundleName);
    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: CreateBundleDataDirWithEl_0001
 * @tc.name: CreateBundleDataDirWithEl
 * @tc.desc: test CreateBundleDataDirWithEl(int32_t userId, DataDirEl dirEl)
 */
HWTEST_F(BmsDataMgrTest, CreateBundleDataDirWithEl_0001, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    int32_t userId = Constants::ANY_USERID;;
    DataDirEl dirEl = DataDirEl::NONE;
    std::string bundleName = "bundleName";
    InnerBundleInfo innerBundleInfo;
    bool ret1 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret1, true);
    bool ret2 = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret2, true);
    ErrCode ret3 = dataMgr->CreateBundleDataDirWithEl(userId, dirEl);
    EXPECT_EQ(ret3, ERR_OK);

    dirEl = DataDirEl::EL5;
    ErrCode ret4 = dataMgr->CreateBundleDataDirWithEl(userId, dirEl);
    EXPECT_EQ(ret4, ERR_OK);
    dataMgr -> bundleInfos_.erase(bundleName);
    dataMgr -> installStates_.erase(bundleName);
}

/**
 * @tc.number: CreateBundleDataDirWithEl_0002
 * @tc.name: CreateBundleDataDirWithEl
 * @tc.desc: test CreateBundleDataDirWithEl(int32_t userId, DataDirEl dirEl)
 */
HWTEST_F(BmsDataMgrTest, CreateBundleDataDirWithEl_0002, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    int32_t userId = Constants::ALL_USERID;;
    DataDirEl dirEl = DataDirEl::NONE;
    std::string bundleName = "bundleName";
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    bool ret1 = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    EXPECT_EQ(ret1, true);
    bool ret2 = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    EXPECT_EQ(ret2, true);
    ErrCode ret3 = dataMgr->CreateBundleDataDirWithEl(userId, dirEl);
    EXPECT_EQ(ret3, ERR_OK);

    dirEl = DataDirEl::EL5;
    ErrCode ret4 = dataMgr->CreateBundleDataDirWithEl(userId, dirEl);
    EXPECT_EQ(ret4, ERR_OK);
    dataMgr -> bundleInfos_.erase(bundleName);
    dataMgr -> installStates_.erase(bundleName);
}

/**
 * @tc.number: SetShortcutVisibleForSelf_0001
 * @tc.name: SetShortcutVisibleForSelf
 * @tc.desc: test SetShortcutVisibleForSelf(const std::string &shortcutId, bool visible)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutVisible_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutVisibleDataStorageRdb> shortcutVisibleDataStorageRdb =
        std::make_shared<ShortcutVisibleDataStorageRdb>();
    ASSERT_NE(shortcutVisibleDataStorageRdb, nullptr);
    std::string bundleName = "TestShortcut";
    std::string shortcutId = "shortcutId";
    int32_t appIndex = 0;
    int32_t userId = 100;
    bool visible = true;
    BundleDataMgr bundleDataMgr;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    auto result = bundleDataMgr.SetShortcutVisibleForSelf(shortcutId, visible);
    EXPECT_NE(result, ERR_OK);

    bool ret = shortcutVisibleDataStorageRdb->SaveStorageShortcutVisibleInfo(
        bundleName, shortcutId, appIndex, userId, shortcutInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SetShortcutVisibleForSelf_0002
 * @tc.name: SetShortcutVisibleForSelf
 * @tc.desc: test SetShortcutVisibleForSelf(const std::string &shortcutId, bool visible)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutVisibleForSelf_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutVisibleDataStorageRdb> shortcutVisibleDataStorageRdb =
        std::make_shared<ShortcutVisibleDataStorageRdb>();
    ASSERT_NE(shortcutVisibleDataStorageRdb, nullptr);
    std::string bundleName = "TestShortcut";
    std::string shortcutId = "shortcutId";
    int32_t appIndex = 0;
    int32_t userId = 100;
    bool visible = true;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutVisibleDataStorageRdb->rdbDataManager_ = nullptr;
    auto ret = shortcutVisibleDataStorageRdb->
        SaveStorageShortcutVisibleInfo(bundleName, shortcutId, appIndex, userId, shortcutInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: SetShortcutVisibleForSelf_0003
 * @tc.name: SetShortcutVisibleForSelf
 * @tc.desc: test SetShortcutVisibleForSelf(const std::string &shortcutId, bool visible)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutVisibleForSelf_0003, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool visible = true;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.SetShortcutVisibleForSelf(shortcutId, visible);
    EXPECT_EQ(result, ERR_OK);
    bundleDataMgr.shortcutVisibleStorage_->rdbDataManager_ = nullptr;
    result = bundleDataMgr.SetShortcutVisibleForSelf(shortcutId, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_DB_INSERT_ERROR);
}

/**
 * @tc.number: SetShortcutVisibleForSelf_0004
 * @tc.name: SetShortcutVisibleForSelf
 * @tc.desc: test SetShortcutVisibleForSelf(const std::string &shortcutId, bool visible)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutVisibleForSelf_0004, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string bundleName2 = "com.ohos.test";
    std::string shortcutId = "id_test1";
    bool visible = true;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName2, innerBundleInfo);
    auto result = bundleDataMgr.SetShortcutVisibleForSelf(shortcutId, visible);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SetShortcutVisibleForSelf_0005
 * @tc.name: SetShortcutVisibleForSelf
 * @tc.desc: test SetShortcutVisibleForSelf(const std::string &shortcutId, bool visible)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutVisibleForSelf_0005, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test2";
    bool visible = true;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.SetShortcutVisibleForSelf(shortcutId, visible);
    EXPECT_EQ(result, ERR_SHORTCUT_MANAGER_SHORTCUT_ID_ILLEGAL);
}

/**
 * @tc.number: SetShortcutVisibleForSelf_0006
 * @tc.name: SetShortcutVisibleForSelf
 * @tc.desc: test SetShortcutVisibleForSelf(const std::string &shortcutId, bool visible)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutVisibleForSelf_0006, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool visible = true;
    int32_t appIndex = 0;
    int32_t userId = 100;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    bundleDataMgr.shortcutVisibleStorage_->
        SaveStorageShortcutVisibleInfo(bundleName, shortcutId, appIndex, userId, shortcutInfo);
    auto result = bundleDataMgr.SetShortcutVisibleForSelf(shortcutId, visible);
    EXPECT_EQ(result, ERR_OK);
    auto ret = bundleDataMgr.DeleteShortcutVisibleInfo(bundleName, userId, appIndex);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SetShortcutVisibleForSelf_0007
 * @tc.name: SetShortcutVisibleForSelf
 * @tc.desc: test SetShortcutVisibleForSelf(const std::string &shortcutId, bool visible)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutVisibleForSelf_0007, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool visible = false;
    int32_t appIndex = 0;
    int32_t userId = 100;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    bundleDataMgr.shortcutVisibleStorage_->
        SaveStorageShortcutVisibleInfo(bundleName, shortcutId, appIndex, userId, shortcutInfo);
    auto result = bundleDataMgr.SetShortcutVisibleForSelf(shortcutId, visible);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: DeleteShortcutVisibleInfo_0001
 * @tc.name: DeleteShortcutVisibleInfo
 * @tc.desc: test DeleteShortcutVisibleInfo(const std::string &bundleName, int32_t userId, int32_t appIndex)
 */
HWTEST_F(BmsDataMgrTest, DeleteShortcutVisibleInfo_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutVisibleDataStorageRdb> shortcutVisibleDataStorageRdb =
        std::make_shared<ShortcutVisibleDataStorageRdb>();
    ASSERT_NE(shortcutVisibleDataStorageRdb, nullptr);
    std::string bundleName = "TestShortcut";
    std::string shortcutId = "shortcutId";
    int32_t appIndex = 0;
    int32_t userId = 100;
    bool visible = true;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    BundleDataMgr bundleDataMgr;

    bool boolRet = shortcutVisibleDataStorageRdb->SaveStorageShortcutVisibleInfo(
        bundleName, shortcutId, appIndex, userId, shortcutInfo);
    EXPECT_EQ(boolRet, true);

    auto ret = bundleDataMgr.DeleteShortcutVisibleInfo(bundleName, userId, appIndex);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeleteShortcutVisibleInfo_0002
 * @tc.name: DeleteShortcutVisibleInfo
 * @tc.desc: test DeleteShortcutVisibleInfo(const std::string &bundleName, int32_t userId, int32_t appIndex)
 */
HWTEST_F(BmsDataMgrTest, DeleteShortcutVisibleInfo_0002, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    int32_t appIndex = 0;
    int32_t userId = 100;
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.shortcutVisibleStorage_->rdbDataManager_ = nullptr;
    auto ret = bundleDataMgr.DeleteShortcutVisibleInfo(bundleName, userId, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_DB_DELETE_ERROR);
}

/**
 * @tc.number: SetShortcutsEnabled_0001
 * @tc.name: SetShortcutsEnabled
 * @tc.desc: test SetShortcutsEnabled(const std::vector<ShortcutInfo> &shortcutInfos, bool isEnabled)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutsEnabled_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    bool isEnabled = true;
    auto result = bundleDataMgr.SetShortcutsEnabled(shortcutInfos, isEnabled);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SetShortcutsEnabled_0002
 * @tc.name: SetShortcutsEnabled
 * @tc.desc: test SetShortcutsEnabled(const std::vector<ShortcutInfo> &shortcutInfos, bool isEnabled)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutsEnabled_0002, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool isEnabled = true;
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.SetShortcutsEnabled(shortcutInfos, isEnabled);
    EXPECT_EQ(result, ERR_OK);
    bundleDataMgr.shortcutEnabledStorage_->rdbDataManager_ = nullptr;
    result = bundleDataMgr.SetShortcutsEnabled(shortcutInfos, isEnabled);
    EXPECT_EQ(result, ERR_APPEXECFWK_DB_INSERT_ERROR);
}

/**
 * @tc.number: SetShortcutsEnabled_0003
 * @tc.name: SetShortcutsEnabled
 * @tc.desc: test SetShortcutsEnabled(const std::vector<ShortcutInfo> &shortcutInfos, bool isEnabled)
 */
HWTEST_F(BmsDataMgrTest, SetShortcutsEnabled_0003, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool isEnabled = true;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    std::vector<ShortcutInfo> shortcutInfos;
    shortcutInfo.id = "error_id";
    shortcutInfos.push_back(shortcutInfo);
    auto result = bundleDataMgr.SetShortcutsEnabled(shortcutInfos, isEnabled);
    EXPECT_EQ(result, ERR_SHORTCUT_MANAGER_SHORTCUT_ID_ILLEGAL);
}

/**
 * @tc.number: DeleteShortcutEnabledInfo_0001
 * @tc.name: DeleteShortcutEnabledInfo
 * @tc.desc: test DeleteShortcutEnabledInfo(const std::string &bundleName)
 */
HWTEST_F(BmsDataMgrTest, DeleteShortcutEnabledInfo_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    bool isEnabled = false;
    bool boolRet = bundleDataMgr.shortcutEnabledStorage_->SaveStorageShortcutEnabledInfos(shortcutInfos, isEnabled);
    EXPECT_EQ(boolRet, true);

    auto ret = bundleDataMgr.DeleteShortcutEnabledInfo(shortcutInfo.bundleName);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeleteShortcutEnabledInfo_0002
 * @tc.name: DeleteShortcutEnabledInfo
 * @tc.desc: test DeleteShortcutEnabledInfo(const std::string &bundleName)
 */
HWTEST_F(BmsDataMgrTest, DeleteShortcutEnabledInfo_0002, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.shortcutEnabledStorage_->rdbDataManager_ = nullptr;
    auto ret = bundleDataMgr.DeleteShortcutEnabledInfo(bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_DB_DELETE_ERROR);
}

/**
 * @tc.number: DeleteShortcutEnabledInfo_0003
 * @tc.name: DeleteShortcutEnabledInfo
 * @tc.desc: test DeleteShortcutEnabledInfo(const std::string &bundleName)
 */
HWTEST_F(BmsDataMgrTest, DeleteShortcutEnabledInfo_0003, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);

    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    bool isEnabled = false;
    bool boolRet = shortcutEnabledStorageRdb->SaveStorageShortcutEnabledInfos(shortcutInfos, isEnabled);
    EXPECT_EQ(boolRet, true);

    std::vector<std::string> shortcutIds;
    shortcutIds.push_back(shortcutInfo.id);
    boolRet = shortcutEnabledStorageRdb->DeleteShortcutEnabledInfo(shortcutInfo.bundleName, shortcutIds);
    EXPECT_EQ(boolRet, true);
}

/**
 * @tc.number: DeleteShortcutEnabledInfo_0004
 * @tc.name: DeleteShortcutEnabledInfo
 * @tc.desc: test DeleteShortcutEnabledInfo(const std::string &bundleName,
        const std::vector<std::string> &shortcutIdList)
 */
HWTEST_F(BmsDataMgrTest, DeleteShortcutEnabledInfo_0004, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::vector<std::string> shortcutIdList;
    shortcutIdList.clear();
    auto ret = shortcutEnabledStorageRdb->DeleteShortcutEnabledInfo(bundleName, shortcutIdList);
    EXPECT_EQ(ret, true);
    shortcutEnabledStorageRdb->rdbDataManager_ = nullptr;
    ret = shortcutEnabledStorageRdb->DeleteShortcutEnabledInfo(bundleName, shortcutIdList);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: UpdateShortcutEnabledInfo_0001
 * @tc.name: UpdateShortcutEnabledInfo
 * @tc.desc: test UpdateShortcutEnabledInfo
 */
HWTEST_F(BmsDataMgrTest, UpdateShortcutEnabledInfo_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    shortcutEnabledStorageRdb->rdbDataManager_ = nullptr;
    auto ret = shortcutEnabledStorageRdb->UpdateShortcutEnabledInfo(bundleName, shortcutInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: UpdateShortcutEnabledInfo_0002
 * @tc.name: UpdateShortcutEnabledInfo
 * @tc.desc: test UpdateShortcutEnabledInfo
 */
HWTEST_F(BmsDataMgrTest, UpdateShortcutEnabledInfo_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    ASSERT_NE(shortcutEnabledStorageRdb->rdbDataManager_, nullptr);
    shortcutEnabledStorageRdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";

    std::string bundleName = "com.ohos.hello";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    auto ret = shortcutEnabledStorageRdb->UpdateShortcutEnabledInfo(bundleName, shortcutInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: UpdateShortcutEnabledInfo_0003
 * @tc.name: UpdateShortcutEnabledInfo
 * @tc.desc: test UpdateShortcutEnabledInfo
 */
HWTEST_F(BmsDataMgrTest, UpdateShortcutEnabledInfo_0003, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    bool isEnabled = false;
    auto ret = shortcutEnabledStorageRdb->SaveStorageShortcutEnabledInfos(shortcutInfos, isEnabled);
    EXPECT_EQ(ret, true);
    ret = shortcutEnabledStorageRdb->UpdateShortcutEnabledInfo(bundleName, shortcutInfos);
    EXPECT_EQ(ret, true);
    shortcutInfos.clear();
    ret = shortcutEnabledStorageRdb->UpdateShortcutEnabledInfo(bundleName, shortcutInfos);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: UpdateShortcutEnabledInfo_0004
 * @tc.name: UpdateShortcutEnabledInfo
 * @tc.desc: test UpdateShortcutEnabledInfo
 */
HWTEST_F(BmsDataMgrTest, UpdateShortcutEnabledInfo_0004, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    auto ret = shortcutEnabledStorageRdb->UpdateShortcutEnabledInfo(bundleName, shortcutInfos);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: GetShortcutEnabledStatus_0001
 * @tc.name: GetShortcutEnabledStatus
 * @tc.desc: test GetShortcutEnabledStatus
 */
HWTEST_F(BmsDataMgrTest, GetShortcutEnabledStatus_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool isEnabled = true;
    shortcutEnabledStorageRdb->rdbDataManager_ = nullptr;
    auto ret = shortcutEnabledStorageRdb->GetShortcutEnabledStatus(bundleName, shortcutId, isEnabled);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: GetShortcutEnabledStatus_0002
 * @tc.name: GetShortcutEnabledStatus
 * @tc.desc: test GetShortcutEnabledStatus
 */
HWTEST_F(BmsDataMgrTest, GetShortcutEnabledStatus_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    ASSERT_NE(shortcutEnabledStorageRdb->rdbDataManager_, nullptr);
    shortcutEnabledStorageRdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool isEnabled = true;
    auto ret = shortcutEnabledStorageRdb->GetShortcutEnabledStatus(bundleName, shortcutId, isEnabled);
    EXPECT_EQ(ret, ERR_APPEXECFWK_DB_RESULT_SET_EMPTY);
}

/**
 * @tc.number: GetShortcutEnabledStatus_0003
 * @tc.name: GetShortcutEnabledStatus
 * @tc.desc: test GetShortcutEnabledStatus
 */
HWTEST_F(BmsDataMgrTest, GetShortcutEnabledStatus_0003, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool isEnabled = false;
    auto ret = shortcutEnabledStorageRdb->GetShortcutEnabledStatus(bundleName, shortcutId, isEnabled);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(isEnabled, true);
}

/**
 * @tc.number: GetShortcutEnabledStatus_0004
 * @tc.name: GetShortcutEnabledStatus
 * @tc.desc: test GetShortcutEnabledStatus
 */
HWTEST_F(BmsDataMgrTest, GetShortcutEnabledStatus_0004, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool isEnabled = false;
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    auto ret = shortcutEnabledStorageRdb->SaveStorageShortcutEnabledInfos(shortcutInfos, isEnabled);
    EXPECT_EQ(ret, true);
    isEnabled = true;
    ret = shortcutEnabledStorageRdb->GetShortcutEnabledStatus(bundleName, shortcutId, isEnabled);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(isEnabled, false);
    auto boolRet = shortcutEnabledStorageRdb->DeleteShortcutEnabledInfo(bundleName);
    EXPECT_EQ(boolRet, true);
}

/**
 * @tc.number: FilterShortcutInfosEnabled_0001
 * @tc.name: FilterShortcutInfosEnabled
 * @tc.desc: test FilterShortcutInfosEnabled
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutInfosEnabled_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    shortcutEnabledStorageRdb->rdbDataManager_ = nullptr;
    shortcutEnabledStorageRdb->FilterShortcutInfosEnabled(bundleName, shortcutInfos);
    EXPECT_EQ(shortcutInfos.empty(), false);
}

/**
 * @tc.number: FilterShortcutInfosEnabled_0002
 * @tc.name: FilterShortcutInfosEnabled
 * @tc.desc: test FilterShortcutInfosEnabled
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutInfosEnabled_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    ASSERT_NE(shortcutEnabledStorageRdb->rdbDataManager_, nullptr);
    shortcutEnabledStorageRdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";
    std::string bundleName = "com.ohos.hello";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    shortcutEnabledStorageRdb->FilterShortcutInfosEnabled(bundleName, shortcutInfos);
    EXPECT_EQ(shortcutInfos.empty(), false);
}

/**
 * @tc.number: FilterShortcutInfosEnabled_0003
 * @tc.name: FilterShortcutInfosEnabled
 * @tc.desc: test FilterShortcutInfosEnabled
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutInfosEnabled_0003, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    shortcutEnabledStorageRdb->FilterShortcutInfosEnabled(bundleName, shortcutInfos);
    EXPECT_EQ(shortcutInfos.empty(), false);
}

/**
 * @tc.number: FilterShortcutInfosEnabled_0004
 * @tc.name: FilterShortcutInfosEnabled
 * @tc.desc: test FilterShortcutInfosEnabled
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutInfosEnabled_0004, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    bool isEnabled = false;
    auto boolRet = shortcutEnabledStorageRdb->SaveStorageShortcutEnabledInfos(shortcutInfos, isEnabled);
    EXPECT_EQ(boolRet, true);
    shortcutEnabledStorageRdb->FilterShortcutInfosEnabled(bundleName, shortcutInfos);
    EXPECT_EQ(shortcutInfos.empty(), true);
    boolRet = shortcutEnabledStorageRdb->DeleteShortcutEnabledInfo(bundleName);
    EXPECT_EQ(boolRet, true);
}

/**
 * @tc.number: SaveStorageShortcutEnabledInfos_0001
 * @tc.name: SaveStorageShortcutEnabledInfos
 * @tc.desc: test SaveStorageShortcutEnabledInfos
 */
HWTEST_F(BmsDataMgrTest, SaveStorageShortcutEnabledInfos_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    shortcutEnabledStorageRdb->rdbDataManager_ = nullptr;
    bool isEnabled = false;
    auto ret = shortcutEnabledStorageRdb->SaveStorageShortcutEnabledInfos(shortcutInfos, isEnabled);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: SaveStorageShortcutEnabledInfos_0002
 * @tc.name: SaveStorageShortcutEnabledInfos
 * @tc.desc: test SaveStorageShortcutEnabledInfos
 */
HWTEST_F(BmsDataMgrTest, SaveStorageShortcutEnabledInfos_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
    ASSERT_NE(shortcutEnabledStorageRdb->rdbDataManager_, nullptr);
    shortcutEnabledStorageRdb->rdbDataManager_->bmsRdbConfig_.tableName = "name";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    shortcutEnabledStorageRdb->rdbDataManager_ = nullptr;
    bool isEnabled = false;
    auto ret = shortcutEnabledStorageRdb->SaveStorageShortcutEnabledInfos(shortcutInfos, isEnabled);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetTargetShortcutInfo_0001
 * @tc.name: GetTargetShortcutInfo
 * @tc.desc: test GetTargetShortcutInfo
 */
HWTEST_F(BmsDataMgrTest, GetTargetShortcutInfo_0001, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo.sourceType = Constants::ShortcutSourceType::STATIC_SHORTCUT;
    shortcutInfos.push_back(shortcutInfo);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    ShortcutInfo targetShortcutInfo;
    bool isEnabled = false;
    auto result = bundleDataMgr.shortcutEnabledStorage_->GetShortcutEnabledStatus(bundleName, shortcutId, isEnabled);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isEnabled, true);
    isEnabled = false;
    result = bundleDataMgr.GetTargetShortcutInfo(bundleName, shortcutId, shortcutInfos, targetShortcutInfo);
    EXPECT_EQ(result, ERR_OK);
    result = bundleDataMgr.SetShortcutsEnabled(shortcutInfos, isEnabled);
    EXPECT_EQ(result, ERR_OK);
    result = bundleDataMgr.GetTargetShortcutInfo(bundleName, shortcutId, shortcutInfos, targetShortcutInfo);
    EXPECT_EQ(result, ERR_SHORTCUT_MANAGER_SHORTCUT_ID_ILLEGAL);
    std::string errorId = "error_id";
    result = bundleDataMgr.GetTargetShortcutInfo(bundleName, errorId, shortcutInfos, targetShortcutInfo);
    EXPECT_EQ(result, ERR_SHORTCUT_MANAGER_SHORTCUT_ID_ILLEGAL);
    shortcutInfo.sourceType = Constants::ShortcutSourceType::DYNAMIC_SHORTCUT;
    shortcutInfos.clear();
    shortcutInfos.push_back(shortcutInfo);
    result = bundleDataMgr.GetTargetShortcutInfo(bundleName, shortcutId, shortcutInfos, targetShortcutInfo);
    EXPECT_EQ(result, ERR_OK);
    bundleDataMgr.shortcutEnabledStorage_->rdbDataManager_ = nullptr;
    result = bundleDataMgr.GetTargetShortcutInfo(bundleName, shortcutId, shortcutInfos, targetShortcutInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: OnExtension_0010
 * @tc.name: OnExtension
 * @tc.desc: test OnExtension can backup and restore
 */
HWTEST_F(BmsDataMgrTest, OnExtension_0010, Function | SmallTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    int32_t USERID = 100;
    bool isIdIllegal = false;
    bool ret = shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);
    EXPECT_TRUE(ret);

    nlohmann::json backupJson = nlohmann::json::array();
    ret = shortcutDataStorageRdb->GetAllTableDataToJson(backupJson);
    EXPECT_TRUE(ret);

    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_TRUE(ret);

    ret = shortcutDataStorageRdb->UpdateAllShortcuts(backupJson);
    EXPECT_TRUE(ret);

    std::vector<ShortcutInfo> vecShortcutInfo;
    shortcutDataStorageRdb->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    EXPECT_GE(vecShortcutInfo.size(), 0);

    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: OnExtension_0020
 * @tc.name: test OnExtension
 * @tc.desc: 1.test OnExtension get dbdata failed
 */
HWTEST_F(BmsDataMgrTest, OnExtension_0020, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    nlohmann::json backupJson;
    NativeRdb::AbsRdbPredicates absRdbPredicates("shortcut_info");
    shortcutDataStorageRdb->rdbDataManager_->DeleteData(absRdbPredicates);
    std::shared_ptr<BundleBackupService> bundleBackupService = DelayedSingleton<BundleBackupService>::GetInstance();
    ASSERT_NE(bundleBackupService, nullptr);
    auto ret = bundleBackupService->OnBackup(backupJson);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(shortcutDataStorageRdb->GetAllTableDataToJson(backupJson), true);
    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    EXPECT_EQ(shortcutDataStorageRdb->GetAllTableDataToJson(backupJson), false);
}

/**
 * @tc.number: OnExtension_0030
 * @tc.name: test OnExtension
 * @tc.desc: 1.test OnExtension update dbdata failed
 */
HWTEST_F(BmsDataMgrTest, OnExtension_0030, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    std::shared_ptr<BundleBackupService> bundleBackupService = DelayedSingleton<BundleBackupService>::GetInstance();
    ASSERT_NE(bundleBackupService, nullptr);
    bundleBackupService->dataMgr_ = std::make_shared<BundleDataMgr>();
    nlohmann::json backupJson;
    auto ret = bundleBackupService->OnRestore(backupJson);
    EXPECT_EQ(ret, ERR_APPEXECFWK_DB_UPDATE_ERROR);
    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    backupJson = nlohmann::json::array();
    EXPECT_EQ(shortcutDataStorageRdb->UpdateAllShortcuts(backupJson), false);
}

/**
 * @tc.number: BundleBackupMgr_0100
 * @tc.name: test BundleBackupMgr
 * @tc.desc: 1.test OnExtension backup
 */
HWTEST_F(BmsDataMgrTest, BundleBackupMgr_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    int32_t USERID = 100;
    bool isIdIllegal = false;
    shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);

    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<BundleBackupMgr> bundleBackupMgr = DelayedSingleton<BundleBackupMgr>::GetInstance();
    ASSERT_NE(bundleBackupMgr, nullptr);
    auto ret = bundleBackupMgr->OnBackup(data, reply);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GE(reply.ReadFileDescriptor(), 0);

    bool result = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: BundleBackupMgr_0200
 * @tc.name: test BundleBackupMgr
 * @tc.desc: 1.test OnExtension restore with invalid fd
 */
HWTEST_F(BmsDataMgrTest, BundleBackupMgr_0200, Function | MediumTest | Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteFileDescriptor(-1);
    std::shared_ptr<BundleBackupMgr> bundleBackupMgr = DelayedSingleton<BundleBackupMgr>::GetInstance();
    ASSERT_NE(bundleBackupMgr, nullptr);
    auto ret = bundleBackupMgr->OnRestore(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_BACKUP_INVALID_PARAMETER);
}

/**
 * @tc.number: BundleBackupMgr_0300
 * @tc.name: test BundleBackupMgr
 * @tc.desc: 1.test OnExtension restore with valid fd
 */
HWTEST_F(BmsDataMgrTest, BundleBackupMgr_0300, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    int32_t USERID = 100;
    bool isIdIllegal = false;
    shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);

    std::shared_ptr<BundleBackupService> bundleBackupService = DelayedSingleton<BundleBackupService>::GetInstance();
    ASSERT_NE(bundleBackupService, nullptr);
    bundleBackupService->dataMgr_ = std::make_shared<BundleDataMgr>();
    const char* BACKUP_FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/backup_config.conf";
    MessageParcel data;
    MessageParcel reply;
    FILE* filePtr = fopen(BACKUP_FILE_PATH, "r");
    EXPECT_NE(filePtr, nullptr);
    int32_t fd = fileno(filePtr);
    data.WriteFileDescriptor(fd);
    std::shared_ptr<BundleBackupMgr> bundleBackupMgr = DelayedSingleton<BundleBackupMgr>::GetInstance();
    ASSERT_NE(bundleBackupMgr, nullptr);
    auto ret = bundleBackupMgr->OnRestore(data, reply);
    (void)fclose(filePtr);
    EXPECT_EQ(ret, ERR_OK);
    bool result = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: GetAllExtensionBundleNames_0001
 * @tc.name: GetAllExtensionBundleNames
 * @tc.desc: test GetAllExtensionBundleNames
 */
HWTEST_F(BmsDataMgrTest, GetAllExtensionBundleNames_0001, Function | MediumTest | Level1)
{
    std::vector<ExtensionAbilityType> types = {
        ExtensionAbilityType::INPUTMETHOD,
        ExtensionAbilityType::SHARE,
        ExtensionAbilityType::ACTION
    };
    BundleDataMgr bundleDataMgr;
    auto bundleNames = bundleDataMgr.GetAllExtensionBundleNames(types);
    EXPECT_EQ(bundleNames.size(), 0);
}

/**
 * @tc.number: GetAllExtensionBundleNames_0002
 * @tc.name: GetAllExtensionBundleNames
 * @tc.desc: test GetAllExtensionBundleNames
 */
HWTEST_F(BmsDataMgrTest, GetAllExtensionBundleNames_0002, Function | MediumTest | Level1)
{
    // Create test data
    InnerBundleInfo info;
    InnerExtensionInfo innerExtensionInfo;
    innerExtensionInfo.type = ExtensionAbilityType::INPUTMETHOD;
    info.InsertExtensionInfo("test.extension", innerExtensionInfo);
    std::shared_lock<std::shared_mutex> lock(dataMgr_->bundleInfoMutex_);
    dataMgr_->bundleInfos_.emplace("test.bundle", info);
    std::vector<ExtensionAbilityType> types = {
        ExtensionAbilityType::INPUTMETHOD,
        ExtensionAbilityType::SHARE,
        ExtensionAbilityType::ACTION
    };
    auto bundleNames = dataMgr_->GetAllExtensionBundleNames(types);
    EXPECT_EQ(bundleNames.size(), 1);
    EXPECT_EQ(bundleNames[0], "test.bundle");
}

/**
 * @tc.number: GetAllShortcutInfoForSelf_0010
 * @tc.name: test GetAllShortcutInfoForSelf
 * @tc.desc: 1.test GetAllShortcutInfoForSelf get bundleName and appIndex failed
 */
HWTEST_F(BmsDataMgrTest, GetAllShortcutInfoForSelf_0010, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    BundleDataMgr bundleDataMgr;
    auto ret = bundleDataMgr.GetAllShortcutInfoForSelf(shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: GetAllShortcutInfoForSelf_0020
 * @tc.name: test GetAllShortcutInfoForSelf
 * @tc.desc: 1.test GetAllShortcutInfoForSelf get bundleInfo failed
 */
HWTEST_F(BmsDataMgrTest, GetAllShortcutInfoForSelf_0020, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    auto ret = bundleDataMgr.GetAllShortcutInfoForSelf(shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAllShortcutInfoForSelf_0030
 * @tc.name: test GetAllShortcutInfoForSelf
 * @tc.desc: 1.test GetAllShortcutInfoForSelf get shortcut info failed
 */
HWTEST_F(BmsDataMgrTest, GetAllShortcutInfoForSelf_0030, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleInfos_.emplace("fake_bundle", innerBundleInfo);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    auto ret = bundleDataMgr.GetAllShortcutInfoForSelf(shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAllShortcutInfoForSelf_0040
 * @tc.name: test GetAllShortcutInfoForSelf
 * @tc.desc: 1.test GetAllShortcutInfoForSelf success
 */
HWTEST_F(BmsDataMgrTest, GetAllShortcutInfoForSelf_0040, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    auto ret = bundleDataMgr.GetAllShortcutInfoForSelf(shortcutInfos);
    EXPECT_EQ(ret, ERR_OK);

    std::shared_ptr<ShortcutVisibleDataStorageRdb> shortcutVisibleDataStorageRdb =
        std::make_shared<ShortcutVisibleDataStorageRdb>();
    ASSERT_NE(shortcutVisibleDataStorageRdb, nullptr);
    shortcutInfo.visible = false;
    shortcutVisibleDataStorageRdb->SaveStorageShortcutVisibleInfo(
        bundleName, shortcutId, 0, 100, shortcutInfo);
    ret = bundleDataMgr.GetAllShortcutInfoForSelf(shortcutInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(shortcutInfos[0].visible);
}

/**
 * @tc.number: FilterShortcutJson_0010
 * @tc.name: test FilterShortcutJson
 * @tc.desc: 1.test FilterShortcutJson json which is not array
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutJson_0010, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    nlohmann::json backupJson;
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_FALSE(backupJson.is_object());
}

/**
 * @tc.number: FilterShortcutJson_0020
 * @tc.name: test FilterShortcutJson
 * @tc.desc: 1.test FilterShortcutJson with invalid bundle name
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutJson_0020, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    nlohmann::json backupJson;
    backupJson.push_back({{"BUNDLE_NAME", "com.invalid.bundle"}, {"APP_INDEX", 0}, {"USER_ID", 100}});
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 1);
    nlohmann::json backupJson2;
    backupJson2.push_back({{"BUNDLE_NAME", "com.invalid.bundle"}, {"APP_INDEX", 0}, {"USER_ID", 101}});
    bundleDataMgr.FilterShortcutJson(backupJson2);
    EXPECT_EQ(backupJson2.size(), 0);
}

/**
 * @tc.number: FilterShortcutJson_0030
 * @tc.name: test FilterShortcutJson
 * @tc.desc: 1.test FilterShortcutJson with invalid userId
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutJson_0030, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    nlohmann::json backupJson;
    std::string bundleName = "com.valid.bundle";
    backupJson.push_back({{"BUNDLE_NAME", "com.valid.bundle"}, {"APP_INDEX", 0}, {"USER_ID", 100}});
    InnerBundleInfo innerBundleInfo;
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 1);
}

/**
 * @tc.number: FilterShortcutJson_0040
 * @tc.name: test FilterShortcutJson
 * @tc.desc: 1.test FilterShortcutJson with invalid userId
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutJson_0040, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    nlohmann::json backupJson;
    std::string bundleName = "com.valid.bundle";
    backupJson.push_back({{"BUNDLE_NAME", "com.valid.bundle"}, {"APP_INDEX", 0}, {"USER_ID", 100}});
    InnerBundleInfo innerBundleInfo;
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.multiUserIdsSet_.insert(100);
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 1);
}

/**
 * @tc.number: FilterShortcutJson_0050
 * @tc.name: test FilterShortcutJson
 * @tc.desc: 1.test FilterShortcutJson
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutJson_0050, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    nlohmann::json backupJson;
    std::string bundleName = "com.valid.bundle";
    backupJson.push_back({{"BUNDLE_NAME", "com.valid.bundle"}, {"APP_INDEX", 0}, {"USER_ID", -5}});
    InnerBundleInfo innerBundleInfo;
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.multiUserIdsSet_.insert(-5);
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 0);
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    bool result = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(bundleName);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: FilterShortcutJson_0060
 * @tc.name: test FilterShortcutJson
 * @tc.desc: 1.test FilterShortcutJson with invalid appIndex
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutJson_0060, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    nlohmann::json backupJson;
    std::string bundleName = "com.valid.bundle";
    backupJson.push_back({{"BUNDLE_NAME", "com.valid.bundle"}, {"APP_INDEX", 1}, {"USER_ID", 100}});
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.bundleUserInfo.userId = 100;
    InnerBundleCloneInfo cloneInfo;
    info.cloneInfos.emplace(bundleName, cloneInfo);
    innerBundleUserInfos["_100"] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.multiUserIdsSet_.insert(100);
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 1);
}

/**
 * @tc.number: FilterShortcutJson_0070
 * @tc.name: test FilterShortcutJson
 * @tc.desc: 1.test FilterShortcutJson with invalid json
 */
HWTEST_F(BmsDataMgrTest, FilterShortcutJson_0130, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    nlohmann::json backupJson;
    backupJson.push_back({{"APP_INDEX", 0}, {"USER_ID", 100}});
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 0);

    backupJson.clear();
    backupJson.push_back({{"BUNDLE_NAME", "com.valid.bundle"}, {"USER_ID", 100}});
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 0);

    backupJson.clear();
    backupJson.push_back({{"BUNDLE_NAME", "com.valid.bundle"}, {"APP_INDEX", 0}});
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 0);

    backupJson.clear();
    backupJson.push_back({{"BUNDLE_NAME", 1}, {"APP_INDEX", 0}, {"USER_ID", 100}});
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 0);

    backupJson.clear();
    backupJson.push_back({{"BUNDLE_NAME", "com.valid.bundle"}, {"APP_INDEX", "appIndex"}, {"USER_ID", 100}});
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 0);

    backupJson.clear();
    backupJson.push_back({{"BUNDLE_NAME", "com.valid.bundle"}, {"APP_INDEX", 0}, {"USER_ID", "userId"}});
    bundleDataMgr.FilterShortcutJson(backupJson);
    EXPECT_EQ(backupJson.size(), 0);
}

/**
 * @tc.number: ProcessCertificate_0001
 * @tc.name: ProcessCertificate
 * @tc.desc: test ProcessCertificate(BundleInfo& bundleInfo, const std::string &bundleName, int32_t flags)
 */
HWTEST_F(BmsDataMgrTest, ProcessCertificate_0001, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO);
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->
        DeleteAppProvisionInfo(BUNDLE_NAME);
    dataMgr->ProcessCertificate(bundleInfo, BUNDLE_NAME, flags);
    EXPECT_TRUE(bundleInfo.signatureInfo.certificate.empty());
}

/**
 * @tc.number: ProcessCertificate_0002
 * @tc.name: ProcessCertificate
 * @tc.desc: test ProcessCertificate(BundleInfo& bundleInfo, const std::string &bundleName, int32_t flags)
 */
HWTEST_F(BmsDataMgrTest, ProcessCertificate_0002, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    BundleInfo bundleInfo;
    int32_t flags = 0;
    DelayedSingleton<AppProvisionInfoManager>::GetInstance()->
        DeleteAppProvisionInfo(BUNDLE_NAME);
    dataMgr->ProcessCertificate(bundleInfo, BUNDLE_NAME, flags);
    EXPECT_TRUE(bundleInfo.signatureInfo.certificate.empty());
}

/**
 * @tc.number: GenerateUuid_0001
 * @tc.name: GenerateUuid
 * @tc.desc: test GenerateUuid
 */
HWTEST_F(BmsDataMgrTest, GenerateUuid_0001, TestSize.Level1)
{
    auto dataMgr = GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::string uuid1 = dataMgr->GenerateUuid();
    EXPECT_EQ(uuid1.size(), 36);

    std::string uuid2 = dataMgr->GenerateUuid();
    EXPECT_EQ(uuid2.size(), 36);

    EXPECT_NE(uuid1, uuid2);

    std::string key1 = "test";
    std::string uuid3 = dataMgr->GenerateUuidByKey(key1);
    EXPECT_EQ(uuid3.size(), 36);

    std::string key2 = "test";
    std::string uuid4 = dataMgr->GenerateUuidByKey(key2);
    EXPECT_EQ(uuid4.size(), 36);

    EXPECT_EQ(uuid3, uuid4);

    std::string key3 = "test3";
    std::string uuid5 = dataMgr->GenerateUuidByKey(key3);
    EXPECT_EQ(uuid5.size(), 36);
    EXPECT_NE(uuid3, uuid5);
}

/**
 * @tc.number: UpdateDesktopShortcutInfo_0001
 * @tc.name: UpdateDesktopShortcutInfo
 * @tc.desc: test UpdateDesktopShortcutInfo
 */
HWTEST_F(BmsDataMgrTest, UpdateDesktopShortcutInfo_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ASSERT_NE(shortcutDataStorageRdb, nullptr);
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    std::vector<ShortcutInfo> vecShortcutInfo;
    vecShortcutInfo.push_back(shortcutInfo);

    auto ret = shortcutDataStorageRdb->UpdateDesktopShortcutInfo(BUNDLE_NAME, vecShortcutInfo);
    EXPECT_TRUE(ret);

    bool isIdIllegal = false;
    ret = shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);
    EXPECT_TRUE(ret);

    ret = shortcutDataStorageRdb->UpdateDesktopShortcutInfo(shortcutInfo.bundleName, vecShortcutInfo);
    EXPECT_TRUE(ret);

    vecShortcutInfo.clear();
    shortcutInfo.id = "test2";
    vecShortcutInfo.push_back(shortcutInfo);
    ret = shortcutDataStorageRdb->UpdateDesktopShortcutInfo(shortcutInfo.bundleName, vecShortcutInfo);
    EXPECT_TRUE(ret);

    ret = shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo.bundleName);
    EXPECT_TRUE(ret);

    shortcutDataStorageRdb->rdbDataManager_ = nullptr;
    ret = shortcutDataStorageRdb->UpdateDesktopShortcutInfo(shortcutInfo.bundleName, vecShortcutInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UpdateShortcutInfos_0002
 * @tc.name: UpdateShortcutInfos
 * @tc.desc: test UpdateShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, UpdateShortcutInfos_0002, Function | MediumTest | Level1)
{
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.UpdateShortcutInfos(BUNDLE_NAME);

    std::vector<ShortcutInfo> shortcutInfos;
    bundleDataMgr.GetAllDesktopShortcutInfo(USERID, shortcutInfos);
    EXPECT_EQ(shortcutInfos.size(), 0);

    InnerBundleInfo info;
    bundleDataMgr.bundleInfos_.emplace(BUNDLE_NAME, info);
    bundleDataMgr.UpdateShortcutInfos(BUNDLE_NAME);
    bundleDataMgr.GetAllDesktopShortcutInfo(USERID, shortcutInfos);
    EXPECT_EQ(shortcutInfos.size(), 0);
}

/**
 * @tc.number: UpdateShortcutInfos_0003
 * @tc.name: UpdateShortcutInfos
 * @tc.desc: test UpdateShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, UpdateShortcutInfos_0003, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool isEnabled = false;
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.UpdateShortcutInfos(bundleName);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsNewVersion(false);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    std::shared_ptr<ShortcutEnabledDataStorageRdb> shortcutEnabledStorageRdb =
        std::make_shared<ShortcutEnabledDataStorageRdb>();
    ASSERT_NE(shortcutEnabledStorageRdb, nullptr);
   
    auto boolRet = shortcutEnabledStorageRdb->SaveStorageShortcutEnabledInfos(shortcutInfos, isEnabled);
    EXPECT_EQ(boolRet, true);
    auto ret = shortcutEnabledStorageRdb->GetShortcutEnabledStatus(bundleName, shortcutId, isEnabled);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(isEnabled, false);
    bundleDataMgr.UpdateShortcutInfos(bundleName);
    ret = shortcutEnabledStorageRdb->GetShortcutEnabledStatus(bundleName, shortcutId, isEnabled);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(isEnabled, true);
    innerBundleInfo.InsertShortcutInfos(shortcutId, shortcutInfo);
    bundleDataMgr.bundleInfos_[bundleName] = innerBundleInfo;
    bundleDataMgr.UpdateShortcutInfos(BUNDLE_NAME);
}

/**
 * @tc.number: GetPluginInfo_0001
 * @tc.name: GetPluginInfo
 * @tc.desc: test BundleDataMgr::GetPluginInfo
 */
HWTEST_F(BmsDataMgrTest, GetPluginInfo_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string hostBundleName = "test1";
    std::string pluginBundleName = "test2";
    int32_t userId = 10;
    PluginBundleInfo pluginBundleInfo;
    pluginBundleInfo.pluginBundleName = pluginBundleName;
    auto ret = bundleDataMgr.GetPluginInfo(hostBundleName, pluginBundleName, userId, pluginBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userId = Constants::ANY_USERID;
    ret = bundleDataMgr.GetPluginInfo(hostBundleName, pluginBundleName, userId, pluginBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    userId = 100;
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = hostBundleName;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = userId;
    userInfo.bundleName = hostBundleName;
    info.AddInnerBundleUserInfo(userInfo);
    bundleDataMgr.bundleInfos_.emplace(hostBundleName, info);
    bundleDataMgr.AddUserId(userId);
    ret = bundleDataMgr.GetPluginInfo(hostBundleName, pluginBundleName, userId, pluginBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_NOT_FOUND);

    ret = bundleDataMgr.AddPluginInfo(hostBundleName, pluginBundleInfo, userId);
    EXPECT_EQ(ret, ERR_OK);

    PluginBundleInfo newPluginInfo;
    ret = bundleDataMgr.GetPluginInfo(hostBundleName, pluginBundleName, userId, newPluginInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(newPluginInfo.pluginBundleName, pluginBundleName);
}

/**
 * @tc.number: SetBundleUserInfoRemovable_0001
 * @tc.name: SetBundleUserInfoRemovable
 * @tc.desc: test BundleDataMgr::SetBundleUserInfoRemovable
 */
HWTEST_F(BmsDataMgrTest, SetBundleUserInfoRemovable_0001, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string bundleName = "com.test.bundleName";
    int32_t userId = 100;
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = bundleName;
    InnerBundleUserInfo innerUserInfo;
    BundleUserInfo userInfo;
    userInfo.userId = userId;
    innerUserInfo.bundleUserInfo = userInfo;
    innerUserInfo.bundleName = bundleName;
    innerUserInfo.isRemovable = true;
    info.AddInnerBundleUserInfo(innerUserInfo);
    bundleDataMgr.bundleInfos_.emplace(bundleName, info);
    bundleDataMgr.AddUserId(userId);

    bool ret = bundleDataMgr.SetBundleUserInfoRemovable(bundleName, userId, false);
    EXPECT_TRUE(ret);

    InnerBundleUserInfo getUserInfo;
    bundleDataMgr.GetInnerBundleUserInfoByUserId(bundleName, userId, getUserInfo);
    EXPECT_FALSE(getUserInfo.isRemovable);
}

/**
 * @tc.number: GetPluginBundlePathForSelf_0010
 * @tc.name: GetPluginBundlePathForSelf
 * @tc.desc: test BundleDataMgr::GetPluginBundlePathForSelf
 */
HWTEST_F(BmsDataMgrTest, GetPluginBundlePathForSelf_0010, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string pluginBundleName = "test2";
    std::string codePath;
    auto ret = bundleDataMgr.GetPluginBundlePathForSelf(pluginBundleName, codePath);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: GetPluginBundlePathForSelf_0020
 * @tc.name: GetPluginBundlePathForSelf
 * @tc.desc: test BundleDataMgr::GetPluginBundlePathForSelf
 */
HWTEST_F(BmsDataMgrTest, GetPluginBundlePathForSelf_0020, TestSize.Level1)
{
    BundleDataMgr bundleDataMgr;
    std::string hostBundleName = "test1";
    std::string pluginBundleName = "test2";
    std::string codePath = "/data/app/el1/bundle/com.example.test1/public/+plugins/com.example.test2.123456";
    std::string sandboxPath = "/data/storage/el1/bundle/+plugins/com.example.test2.123456";
    int32_t userId = 100;

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = hostBundleName;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = userId;
    userInfo.bundleName = hostBundleName;
    userInfo.uid = 20000001;
    info.AddInnerBundleUserInfo(userInfo);
    bundleDataMgr.bundleInfos_.emplace(hostBundleName, info);
    bundleDataMgr.bundleIdMap_.emplace(1, hostBundleName);
    bundleDataMgr.AddUserId(userId);

    std::string pluginCodePath;
    auto ret = bundleDataMgr.GetPluginBundlePathForSelf(pluginBundleName, pluginCodePath);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetPluginBundlePathForSelf_0030
 * @tc.name: GetPluginBundlePathForSelf
 * @tc.desc: test BundleDataMgr::GetPluginBundlePathForSelf
 */
HWTEST_F(BmsDataMgrTest, GetPluginBundlePathForSelf_0030, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl = std::make_unique<BundleMgrHostImpl>();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    auto bundleDataMgr = bundleMgrHostImpl->GetDataMgrFromService();
    ASSERT_NE(bundleDataMgr, nullptr);
    std::string hostBundleName = "test1";
    std::string pluginBundleName = "test2";
    std::string codePath = "/data/app/el1/bundle/public/com.example.test1/+plugins/com.example.test2.123456";
    std::string sandboxPath = "/data/storage/el1/bundle/+plugins/com.example.test2.123456";
    PluginBundleInfo pluginBundleInfo;
    pluginBundleInfo.pluginBundleName = pluginBundleName;
    pluginBundleInfo.codePath = codePath;

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = hostBundleName;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.uid = 20000001;
    userInfo.bundleName = hostBundleName;
    info.AddInnerBundleUserInfo(userInfo);
    bundleDataMgr->bundleInfos_.emplace(hostBundleName, info);
    bundleDataMgr->bundleIdMap_.emplace(1, hostBundleName);
    bundleDataMgr->AddUserId(USERID);

    auto ret = bundleDataMgr->AddPluginInfo(hostBundleName, pluginBundleInfo, USERID);
    EXPECT_EQ(ret, ERR_OK);

    std::string pluginCodePath;
    ret = bundleMgrHostImpl->GetPluginBundlePathForSelf(pluginBundleName, pluginCodePath);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(pluginCodePath, sandboxPath);
}

/**
 * @tc.number: GetPluginBundlePathForSelf_0040
 * @tc.name: GetPluginBundlePathForSelf
 * @tc.desc: test BundleDataMgr::GetPluginBundlePathForSelf
 */
HWTEST_F(BmsDataMgrTest, GetPluginBundlePathForSelf_0040, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl = std::make_unique<BundleMgrHostImpl>();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    auto bundleDataMgr = bundleMgrHostImpl->GetDataMgrFromService();
    ASSERT_NE(bundleDataMgr, nullptr);
    std::string hostBundleName = "test1";
    std::string pluginBundleName = "test2";
    std::string codePath = "/com.example.test1/public/+plugins/com.example.test2.123456";
    PluginBundleInfo pluginBundleInfo;
    pluginBundleInfo.pluginBundleName = pluginBundleName;
    pluginBundleInfo.codePath = codePath;

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = hostBundleName;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.uid = 20000001;
    userInfo.bundleName = hostBundleName;
    info.AddInnerBundleUserInfo(userInfo);
    bundleDataMgr->bundleInfos_.emplace(hostBundleName, info);
    bundleDataMgr->bundleIdMap_.emplace(1, hostBundleName);
    bundleDataMgr->AddUserId(USERID);

    auto ret = bundleDataMgr->AddPluginInfo(hostBundleName, pluginBundleInfo, USERID);
    EXPECT_EQ(ret, ERR_OK);
    std::string pluginCodePath;
    ret = bundleMgrHostImpl->GetPluginBundlePathForSelf(pluginBundleName, pluginCodePath);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(pluginCodePath, codePath);

    pluginBundleInfo.codePath = "/data/app/el1/bundle/public/";
    ret = bundleDataMgr->AddPluginInfo(hostBundleName, pluginBundleInfo, USERID);
    EXPECT_EQ(ret, ERR_OK);
    ret = bundleMgrHostImpl->GetPluginBundlePathForSelf(pluginBundleName, pluginCodePath);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(pluginCodePath, pluginBundleInfo.codePath);
}

/**
 * @tc.number: AddDynamicShortcutInfos_0001
 * @tc.name: AddDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::AddDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, AddDynamicShortcutInfos_0001, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    int32_t userId = -1;
    BundleDataMgr bundleDataMgr;
    auto result = bundleDataMgr.AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: AddDynamicShortcutInfos_0002
 * @tc.name: AddDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::AddDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, AddDynamicShortcutInfos_0002, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    int32_t userId = 100;
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    auto result = bundleDataMgr.AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: AddDynamicShortcutInfos_0003
 * @tc.name: AddDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::AddDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, AddDynamicShortcutInfos_0003, Function | MediumTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    int32_t userId = 100;
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    auto result = bundleDataMgr.AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: AddDynamicShortcutInfos_0004
 * @tc.name: AddDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::AddDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, AddDynamicShortcutInfos_0004, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    int32_t userId = 100;
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetIsNewVersion(false);

    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: AddDynamicShortcutInfos_0005
 * @tc.name: AddDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::AddDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, AddDynamicShortcutInfos_0005, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    int32_t userId = 100;
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    auto innerBundleInfo = CreateAddDynamicShortcutInfosInnerBundleInfo(shortcutInfo);

    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_EQ(result, ERR_SHORTCUT_MANAGER_SHORTCUT_ID_ILLEGAL);
}

/**
 * @tc.number: AddDynamicShortcutInfos_0006
 * @tc.name: AddDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::AddDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, AddDynamicShortcutInfos_0006, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    int32_t userId = 100;
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    ShortcutInfo shortcutInfo2 = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo2.id = "id_test2";
    shortcutInfo2.sourceType = 2;
    shortcutInfos.push_back(shortcutInfo2);
    auto innerBundleInfo = CreateAddDynamicShortcutInfosInnerBundleInfo(shortcutInfo);

    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    bool boolRet = bundleDataMgr.shortcutVisibleStorage_->AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_TRUE(boolRet);
    auto result = bundleDataMgr.AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_EQ(result, ERR_SHORTCUT_MANAGER_SHORTCUT_ID_ILLEGAL);

    result = bundleDataMgr.DeleteShortcutVisibleInfo(bundleName, userId, 0);
    EXPECT_EQ(result, ERR_OK);
    bundleDataMgr.bundleInfos_.clear();
}

/**
 * @tc.number: AddDynamicShortcutInfos_0007
 * @tc.name: AddDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::AddDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, AddDynamicShortcutInfos_0007, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    int32_t userId = 100;
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    ShortcutInfo shortcutInfo2 = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo2.id = "id_test2";
    shortcutInfo2.iconId = 1;
    shortcutInfo2.labelId = 1;
    shortcutInfos.push_back(shortcutInfo2);
    auto innerBundleInfo = CreateAddDynamicShortcutInfosInnerBundleInfo(shortcutInfo);

    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_EQ(result, ERR_OK);

    result = bundleDataMgr.DeleteShortcutVisibleInfo(bundleName, userId, 0);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: DeleteDynamicShortcutInfos_0001
 * @tc.name: DeleteDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::DeleteDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, DeleteDynamicShortcutInfos_0001, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    int32_t appIndex = 0;
    int32_t userId = -1;
    BundleDataMgr bundleDataMgr;
    auto result = bundleDataMgr.DeleteDynamicShortcutInfos(bundleName, appIndex, userId, {shortcutId});
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: DeleteDynamicShortcutInfos_0002
 * @tc.name: DeleteDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::DeleteDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, DeleteDynamicShortcutInfos_0002, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    int32_t appIndex = 0;
    int32_t userId = 100;
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    auto result = bundleDataMgr.DeleteDynamicShortcutInfos(bundleName, appIndex, userId, {shortcutId});
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: DeleteDynamicShortcutInfos_0003
 * @tc.name: DeleteDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::DeleteDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, DeleteDynamicShortcutInfos_0003, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool visible = true;
    int32_t appIndex = 0;
    int32_t userId = 100;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.enabled = false;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsNewVersion(false);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.DeleteDynamicShortcutInfos(bundleName, appIndex, userId, {shortcutId});
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_APPLICATION_DISABLED);
}

/**
 * @tc.number: DeleteDynamicShortcutInfos_0004
 * @tc.name: DeleteDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::DeleteDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, DeleteDynamicShortcutInfos_0004, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    bool visible = true;
    int32_t appIndex = 0;
    int32_t userId = 100;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetIsNewVersion(false);

    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.DeleteDynamicShortcutInfos(bundleName, appIndex, userId, {});
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: DeleteDynamicShortcutInfos_0005
 * @tc.name: DeleteDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::DeleteDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, DeleteDynamicShortcutInfos_0005, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool visible = true;
    int32_t appIndex = 0;
    int32_t userId = 100;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetIsNewVersion(false);

    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.DeleteDynamicShortcutInfos(bundleName, appIndex, userId, {shortcutId});
    EXPECT_EQ(result, ERR_SHORTCUT_MANAGER_SHORTCUT_ID_ILLEGAL);
}

/**
 * @tc.number: DeleteDynamicShortcutInfos_0006
 * @tc.name: DeleteDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::DeleteDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, DeleteDynamicShortcutInfos_0006, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test2";
    bool visible = true;
    int32_t appIndex = 0;
    int32_t userId = 100;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetIsNewVersion(false);

    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo.sourceType = 2;
    shortcutInfos.push_back(shortcutInfo);
    bool boolRet = bundleDataMgr.shortcutVisibleStorage_->AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_TRUE(boolRet);

    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.DeleteDynamicShortcutInfos(bundleName, appIndex, userId, {shortcutId});
    EXPECT_EQ(result, ERR_SHORTCUT_MANAGER_SHORTCUT_ID_ILLEGAL);

    result = bundleDataMgr.DeleteShortcutVisibleInfo(bundleName, userId, 0);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: DeleteDynamicShortcutInfos_0007
 * @tc.name: DeleteDynamicShortcutInfos
 * @tc.desc: test BundleDataMgr::DeleteDynamicShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, DeleteDynamicShortcutInfos_0007, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    bool visible = true;
    int32_t appIndex = 0;
    int32_t userId = 100;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetIsNewVersion(false);

    BundleDataMgr bundleDataMgr;
    bundleDataMgr.AddUserId(userId);
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo.sourceType = 2;
    ShortcutInfo shortcutInfo2 = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo2.id = "id_test2";
    shortcutInfo2.sourceType = 2;
    shortcutInfos.push_back(shortcutInfo);
    shortcutInfos.push_back(shortcutInfo2);
    bool boolRet = bundleDataMgr.shortcutVisibleStorage_->AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_TRUE(boolRet);

    bundleDataMgr.bundleIdMap_.emplace(1, bundleName);
    bundleDataMgr.bundleInfos_.emplace(bundleName, innerBundleInfo);
    auto result = bundleDataMgr.DeleteDynamicShortcutInfos(bundleName, appIndex, userId, {shortcutId, "id_test2"});
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: GetStorageShortcutInfos_0001
 * @tc.name: test GetStorageShortcutInfos
 * @tc.desc: test GetStorageShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, GetStorageShortcutInfos_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutVisibleDataStorageRdb> shortcutVisibleDataStorageRdb =
        std::make_shared<ShortcutVisibleDataStorageRdb>();
    ASSERT_NE(shortcutVisibleDataStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    int32_t appIndex = 0;
    int32_t userId = 100;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    std::vector<ShortcutInfo> shortcutInfos;
    shortcutInfos.push_back(shortcutInfo);
    shortcutVisibleDataStorageRdb->rdbDataManager_ = nullptr;
    auto ret = shortcutVisibleDataStorageRdb->AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_FALSE(ret);

    ret = shortcutVisibleDataStorageRdb->DeleteDynamicShortcutInfos(bundleName, appIndex, userId, {shortcutId});
    EXPECT_FALSE(ret);

    shortcutVisibleDataStorageRdb->GetStorageShortcutInfos(bundleName, appIndex, userId, shortcutInfos);
    EXPECT_FALSE(shortcutInfos.empty());
}

/**
 * @tc.number: GetStorageShortcutInfos_0002
 * @tc.name: test GetStorageShortcutInfos
 * @tc.desc: test GetStorageShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, GetStorageShortcutInfos_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutVisibleDataStorageRdb> shortcutVisibleDataStorageRdb =
        std::make_shared<ShortcutVisibleDataStorageRdb>();
    ASSERT_NE(shortcutVisibleDataStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    int32_t appIndex = 0;
    int32_t userId = 100;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo.sourceType = 2;
    shortcutInfo.icon = "iconString";
    shortcutInfo.label = "labelString";
    std::vector<ShortcutInfo> shortcutInfos;
    shortcutInfos.push_back(shortcutInfo);

    auto ret = shortcutVisibleDataStorageRdb->AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_TRUE(ret);
    std::vector<ShortcutInfo> storgeShortcutInfos;
    shortcutVisibleDataStorageRdb->GetStorageShortcutInfos(bundleName, appIndex, userId, storgeShortcutInfos, true);
    EXPECT_EQ(storgeShortcutInfos.size(), 1);

    std::vector<ShortcutInfo> storgeShortcutInfos2;
    ret = shortcutVisibleDataStorageRdb->DeleteDynamicShortcutInfos(bundleName, appIndex, userId, {shortcutId});
    EXPECT_TRUE(ret);
    shortcutVisibleDataStorageRdb->GetStorageShortcutInfos(bundleName, appIndex, userId, storgeShortcutInfos2);
    EXPECT_TRUE(storgeShortcutInfos2.empty());
}

/**
 * @tc.number: GetStorageShortcutInfos_0003
 * @tc.name: test GetStorageShortcutInfos
 * @tc.desc: test GetStorageShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, GetStorageShortcutInfos_0003, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutVisibleDataStorageRdb> shortcutVisibleDataStorageRdb =
        std::make_shared<ShortcutVisibleDataStorageRdb>();
    ASSERT_NE(shortcutVisibleDataStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    int32_t appIndex = 0;
    int32_t userId = 100;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo.icon = "$iconString:123456";
    shortcutInfo.label = "$labelString:123456";
    std::vector<ShortcutInfo> shortcutInfos;
    shortcutInfos.push_back(shortcutInfo);

    auto ret = shortcutVisibleDataStorageRdb->AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_TRUE(ret);
    std::vector<ShortcutInfo> storgeShortcutInfos;
    shortcutInfo.visible = false;
    storgeShortcutInfos.push_back(shortcutInfo);
    shortcutVisibleDataStorageRdb->GetStorageShortcutInfos(bundleName, appIndex, userId, storgeShortcutInfos);
    ASSERT_EQ(storgeShortcutInfos.size(), 1);
    EXPECT_EQ(storgeShortcutInfos[0].visible, true);

    std::vector<ShortcutInfo> storgeShortcutInfos2;
    shortcutVisibleDataStorageRdb->GetStorageShortcutInfos(bundleName, appIndex, userId, storgeShortcutInfos2);
    EXPECT_TRUE(storgeShortcutInfos2.empty());
}

/**
 * @tc.number: GetStorageShortcutInfos_0004
 * @tc.name: test GetStorageShortcutInfos
 * @tc.desc: test GetStorageShortcutInfos
 */
HWTEST_F(BmsDataMgrTest, GetStorageShortcutInfos_0004, Function | MediumTest | Level1)
{
    std::shared_ptr<ShortcutVisibleDataStorageRdb> shortcutVisibleDataStorageRdb =
        std::make_shared<ShortcutVisibleDataStorageRdb>();
    ASSERT_NE(shortcutVisibleDataStorageRdb, nullptr);
    std::string bundleName = "com.ohos.hello";
    std::string shortcutId = "id_test1";
    int32_t appIndex = 0;
    int32_t userId = 100;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo.sourceType = 2;
    shortcutInfo.icon = "$iconString:123456";
    shortcutInfo.label = "$labelString:123456";
    std::vector<ShortcutInfo> shortcutInfos;
    shortcutInfos.push_back(shortcutInfo);

    auto ret = shortcutVisibleDataStorageRdb->AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_TRUE(ret);
    shortcutInfo.sourceType = 1;
    std::vector<ShortcutInfo> storgeShortcutInfos;
    storgeShortcutInfos.push_back(shortcutInfo);
    shortcutVisibleDataStorageRdb->GetStorageShortcutInfos(bundleName, appIndex, userId, storgeShortcutInfos);
    ASSERT_EQ(storgeShortcutInfos.size(), 1);
    EXPECT_EQ(storgeShortcutInfos[0].sourceType, 2);

    bool result = shortcutVisibleDataStorageRdb->DeleteShortcutVisibleInfo(bundleName, userId, 0);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckModuleNameAndAbilityName_0001
 * @tc.name: CheckModuleNameAndAbilityName
 * @tc.desc: test BundleDataMgr::CheckModuleNameAndAbilityName
 */
HWTEST_F(BmsDataMgrTest, CheckModuleNameAndAbilityName_0001, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string hostAbility = "hostAbility";
    std::string moduleName = "test_entry";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    ShortcutInfo shortcutInfo2 = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    shortcutInfos.push_back(shortcutInfo2);
    BundleDataMgr bundleDataMgr;
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = hostAbility;
    innerAbilityInfo.moduleName = moduleName;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = moduleName;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertInnerModuleInfo(bundleName, innerModuleInfo);
    innerBundleInfo.InsertAbilitiesInfo(hostAbility, innerAbilityInfo);
    auto result = bundleDataMgr.CheckModuleNameAndAbilityName(shortcutInfos, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CheckModuleNameAndAbilityName_0002
 * @tc.name: CheckModuleNameAndAbilityName
 * @tc.desc: test BundleDataMgr::CheckModuleNameAndAbilityName
 */
HWTEST_F(BmsDataMgrTest, CheckModuleNameAndAbilityName_0002, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string hostAbility = "hostAbility";
    std::string moduleName = "test_entry";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo.hostAbility = "";
    shortcutInfos.push_back(shortcutInfo);
    BundleDataMgr bundleDataMgr;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = moduleName;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertInnerModuleInfo(bundleName, innerModuleInfo);
    auto result = bundleDataMgr.CheckModuleNameAndAbilityName(shortcutInfos, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: CheckModuleNameAndAbilityName_0003
 * @tc.name: CheckModuleNameAndAbilityName
 * @tc.desc: test BundleDataMgr::CheckModuleNameAndAbilityName
 */
HWTEST_F(BmsDataMgrTest, CheckModuleNameAndAbilityName_0003, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    std::string hostAbility = "hostAbility";
    std::string invalidKey = "invalidKey";
    std::string moduleName = "test_entry";
    std::vector<ShortcutInfo> shortcutInfos;
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfos.push_back(shortcutInfo);
    BundleDataMgr bundleDataMgr;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = moduleName;
    innerBundleInfo.InsertInnerModuleInfo(bundleName, innerModuleInfo);

    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = invalidKey;
    innerAbilityInfo.moduleName = moduleName;
    innerBundleInfo.InsertAbilitiesInfo(hostAbility, innerAbilityInfo);
    innerAbilityInfo.name = hostAbility;
    innerAbilityInfo.moduleName = invalidKey;
    innerBundleInfo.InsertAbilitiesInfo(hostAbility, innerAbilityInfo);

    auto result = bundleDataMgr.CheckModuleNameAndAbilityName(shortcutInfos, innerBundleInfo);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: UpdateShortcutInfoResId_0001
 * @tc.name: UpdateShortcutInfoResId
 * @tc.desc: test BundleDataMgr::UpdateShortcutInfoResId
 */
HWTEST_F(BmsDataMgrTest, UpdateShortcutInfoResId_0001, Function | MediumTest | Level1)
{
    std::string bundleName = "com.ohos.hello";
    int32_t userId = 100;
    std::vector<ShortcutInfo> shortcutInfos;
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.UpdateShortcutInfoResId(bundleName, userId);
    bundleDataMgr.shortcutVisibleStorage_->GetStorageShortcutInfos(bundleName, -1, userId, shortcutInfos, true);
    EXPECT_TRUE(shortcutInfos.empty());
}

/**
 * @tc.number: UpdateShortcutInfoResId_0002
 * @tc.name: UpdateShortcutInfoResId
 * @tc.desc: test BundleDataMgr::UpdateShortcutInfoResId
 */
HWTEST_F(BmsDataMgrTest, UpdateShortcutInfoResId_0002, Function | MediumTest | Level1)
{
    int32_t userId = 100;
    std::string bundleName = "com.ohos.hello";
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo.sourceType = 2;
    std::vector<ShortcutInfo> shortcutInfos;
    shortcutInfos.push_back(shortcutInfo);
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.shortcutVisibleStorage_->AddDynamicShortcutInfos(shortcutInfos, userId);

    bundleDataMgr.UpdateShortcutInfoResId("", userId);
    bundleDataMgr.shortcutVisibleStorage_->GetStorageShortcutInfos(bundleName, -1, userId, shortcutInfos, true);
    ASSERT_FALSE(shortcutInfos.empty());
    EXPECT_EQ(shortcutInfos[0].iconId, 0);
    EXPECT_EQ(shortcutInfos[0].labelId, 0);
    bool result = bundleDataMgr.shortcutVisibleStorage_->DeleteShortcutVisibleInfo(bundleName, userId, 0);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: UpdateShortcutInfoResId_0003
 * @tc.name: UpdateShortcutInfoResId
 * @tc.desc: test BundleDataMgr::UpdateShortcutInfoResId
 */
HWTEST_F(BmsDataMgrTest, UpdateShortcutInfoResId_0003, Function | MediumTest | Level1)
{
    int32_t userId = 100;
    std::string bundleName = "com.ohos.hello";
    ShortcutInfo shortcutInfo = BmsDataMgrTest::InitShortcutInfo();
    shortcutInfo.sourceType = 2;
    shortcutInfo.labelId = 1;
    shortcutInfo.iconId = 1;
    std::vector<ShortcutInfo> shortcutInfos;
    shortcutInfos.push_back(shortcutInfo);
    BundleDataMgr bundleDataMgr;
    bundleDataMgr.shortcutVisibleStorage_->AddDynamicShortcutInfos(shortcutInfos, userId);

    bundleDataMgr.UpdateShortcutInfoResId(bundleName, userId);
    bundleDataMgr.shortcutVisibleStorage_->GetStorageShortcutInfos(bundleName, -1, userId, shortcutInfos, true);
    ASSERT_FALSE(shortcutInfos.empty());
    EXPECT_EQ(shortcutInfos[0].iconId, 1);
    EXPECT_EQ(shortcutInfos[0].labelId, 1);

    shortcutInfos.clear();
    shortcutInfo.icon = "";
    shortcutInfo.labelId = 0;
    shortcutInfos.push_back(shortcutInfo);
    bundleDataMgr.shortcutVisibleStorage_->AddDynamicShortcutInfos(shortcutInfos, userId);
    bundleDataMgr.UpdateShortcutInfoResId(bundleName, userId);
    bundleDataMgr.shortcutVisibleStorage_->GetStorageShortcutInfos(bundleName, -1, userId, shortcutInfos, true);
    EXPECT_EQ(shortcutInfos[0].iconId, 1);
    EXPECT_EQ(shortcutInfos[0].labelId, 0);
    bool result = bundleDataMgr.shortcutVisibleStorage_->DeleteShortcutVisibleInfo(bundleName, userId, 0);
    EXPECT_TRUE(result);
}
} // OHOS
