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
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "base_bundle_installer.h"
#include "bundle_mgr_host.h"
#include "bundle_mgr_service.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "mock_status_receiver.h"
#include "nlohmann/json.hpp"
#include "param_validator.h"

namespace OHOS {
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {
const std::string BUNDLE_PATH = "/data/test/resource/bms/default_app_bundle/defaultAppTest.hap";
const std::string BUNDLE_NAME = "com.test.defaultApp";
const std::string MODULE_NAME = "module01";
const std::string ABILITY_NAME = "EMAIL";
const std::string KEY = "key";
const std::string KEY2 = "key2";
const std::vector<std::string> FILE_TYPES = {"general.png", "general.jpeg"};
const std::string URI = "file://dir/test.png";
const std::string INVALID_FILE_TYPE = "\xC4\xE3\xBA\xCA";
const int32_t USER_ID = 100;
const int32_t WAIT_TIME_SECONDS = 5;
}  // namespace

class BmsDynamicSkillsTest : public testing::Test {
public:
    BmsDynamicSkillsTest();
    ~BmsDynamicSkillsTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    static void StartBundleService();
    static void StartInstalldService();
    static void InstallBundle(const std::string &bundlePath);
    static void UnInstallBundle(const std::string &bundleName);
    static std::vector<Skill> BuildSkillsVector(const size_t size);
    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<InstalldService> installdService_;
};

std::shared_ptr<BundleMgrService> BmsDynamicSkillsTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsDynamicSkillsTest::installdService_ =
    DelayedSingleton<InstalldService>::GetInstance();

BmsDynamicSkillsTest::BmsDynamicSkillsTest()
{}

BmsDynamicSkillsTest::~BmsDynamicSkillsTest()
{}

void BmsDynamicSkillsTest::SetUpTestCase()
{
    StartBundleService();
    StartInstalldService();
}

void BmsDynamicSkillsTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsDynamicSkillsTest::SetUp()
{}

void BmsDynamicSkillsTest::TearDown()
{}

void BmsDynamicSkillsTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME_SECONDS));
    }
}

void BmsDynamicSkillsTest::StartInstalldService()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsDynamicSkillsTest::InstallBundle(const std::string &bundlePath)
{
    if (!bundleMgrService_) {
        GTEST_FAIL() << "bundleMgrService_ is nullptr";
        return;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        GTEST_FAIL() << "installer is nullptr";
        return;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        GTEST_FAIL() << "receiver is nullptr";
        return;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USER_ID;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    receiver->GetResultCode();
}

void BmsDynamicSkillsTest::UnInstallBundle(const std::string &bundleName)
{
    if (!bundleMgrService_) {
        GTEST_FAIL() << "bundleMgrService_ is nullptr";
        return;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        GTEST_FAIL() << "installer is nullptr";
        return;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        GTEST_FAIL() << "installer is nullptr";
        return;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USER_ID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    receiver->GetResultCode();
}

std::vector<Skill> BmsDynamicSkillsTest::BuildSkillsVector(const size_t size)
{
    std::vector<Skill> skills;
    for (size_t i = 0; i < size; ++i) {
        Skill skill;
        skills.emplace_back(skill);
    }
    return skills;
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0100
 * @tc.name: SetAbilityFileTypesForSelf_0100
 * @tc.desc: 1.moduleName is empty, expect return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_0100, Function | SmallTest | Level1)
{
    BundleMgrHostImpl hostImpl;
    std::string moduleName;
    std::string abilityName = ABILITY_NAME;
    std::vector<std::string> fileTypes = FILE_TYPES;
    ErrCode ret = hostImpl.SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0200
 * @tc.name: SetAbilityFileTypesForSelf_0200
 * @tc.desc: 1.expect return ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_0200, Function | SmallTest | Level1)
{
    BundleMgrHostImpl hostImpl;
    std::string moduleName = MODULE_NAME;
    std::string abilityName = ABILITY_NAME;
    std::vector<std::string> fileTypes = FILE_TYPES;
    ErrCode ret = hostImpl.SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0300
 * @tc.name: SetAbilityFileTypesForSelf_0300
 * @tc.desc: 1.not exist bundle, expect return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_0300, Function | SmallTest | Level1)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "notExistBundle";
    ErrCode ret = dataMgr->SetAbilityFileTypes(bundleName, MODULE_NAME, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0400
 * @tc.name: SetAbilityFileTypesForSelf_0400
 * @tc.desc: 1.not exist module, expect return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_0400, Function | SmallTest | Level1)
{
    InstallBundle(BUNDLE_PATH);
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string moduleName = "notExistModule";
    ErrCode ret = dataMgr->SetAbilityFileTypes(BUNDLE_NAME, moduleName, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    UnInstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0500
 * @tc.name: SetAbilityFileTypesForSelf_0500
 * @tc.desc: 1.valid param, expect set success and query success
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_0500, Function | SmallTest | Level1)
{
    InstallBundle(BUNDLE_PATH);
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    ErrCode ret = dataMgr->SetAbilityFileTypes(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_OK);
    OHOS::AAFwk::Want want;
    want.SetAction(ServiceConstants::ACTION_VIEW_DATA);
    want.SetUri(URI);
    std::vector<AbilityInfo> abilityInfos;
    dataMgr->QueryAbilityInfosV9(want, 0, USER_ID, abilityInfos);
    bool find = false;
    for (const auto &abilityInfo : abilityInfos) {
        if (abilityInfo.name == ABILITY_NAME && abilityInfo.moduleName == MODULE_NAME) {
            find = true;
            break;
        }
    }
    EXPECT_TRUE(find);
    UnInstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0600
 * @tc.name: SetAbilityFileTypesForSelf_0600
 * @tc.desc: 1.test operator=
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_0600, Function | SmallTest | Level1)
{
    InnerBundleInfo origin;
    origin.dynamicSkills_ = {{KEY, BuildSkillsVector(1)}};
    InnerBundleInfo target;
    target = origin;
    EXPECT_EQ(target.dynamicSkills_.size(), 1);
    auto item = target.dynamicSkills_.find(KEY);
    EXPECT_NE(item, target.dynamicSkills_.end());
    EXPECT_EQ(item->second.size(), 1);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0700
 * @tc.name: SetAbilityFileTypesForSelf_0700
 * @tc.desc: 1.test FromJson and ToJson
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_0700, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.dynamicSkills_ = {{KEY, BuildSkillsVector(1)}};
    nlohmann::json jsonObj;
    info.ToJson(jsonObj);
    InnerBundleInfo newInfo;
    int32_t ret = newInfo.FromJson(jsonObj);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(newInfo.dynamicSkills_.size(), 1);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0800
 * @tc.name: SetAbilityFileTypesForSelf_0800
 * @tc.desc: 1.test GetInnerSkillInfos
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_0800, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.skillInfos_ = {{KEY, BuildSkillsVector(1)}};
    auto skillInfos = info.GetInnerSkillInfos();
    EXPECT_EQ(skillInfos.size(), 1);
    auto item = skillInfos.begin();
    EXPECT_EQ(item->first, KEY);
    EXPECT_EQ(item->second.size(), 1);

    info.dynamicSkills_ = {{KEY, BuildSkillsVector(1)}};
    skillInfos = info.GetInnerSkillInfos();
    EXPECT_EQ(skillInfos.size(), 1);
    item = skillInfos.begin();
    EXPECT_EQ(item->first, KEY);
    size_t expectSize = 2;
    EXPECT_EQ(item->second.size(), expectSize);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0900
 * @tc.name: SetAbilityFileTypesForSelf_0900
 * @tc.desc: 1.test UpdateDynamicSkills
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_0900, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.baseAbilityInfos_ = {{KEY, InnerAbilityInfo()}};
    info.dynamicSkills_ = {{KEY, BuildSkillsVector(1)}, {KEY2, BuildSkillsVector(1)}};
    info.UpdateDynamicSkills();
    EXPECT_EQ(info.dynamicSkills_.size(), 1);
    auto item = info.dynamicSkills_.begin();
    EXPECT_EQ(item->first, KEY);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1000
 * @tc.name: SetAbilityFileTypesForSelf_1000
 * @tc.desc: 1.test AppendDynamicSkillsToAbilityIfExist
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1000, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    abilityInfo.skills = BuildSkillsVector(1);
    abilityInfo.bundleName = BUNDLE_NAME;
    abilityInfo.moduleName = MODULE_NAME;
    abilityInfo.name = ABILITY_NAME;

    InnerBundleInfo info;
    info.AppendDynamicSkillsToAbilityIfExist(abilityInfo);

    std::string key = BundleUtil::GetAbilityKey(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME);
    info.dynamicSkills_ = {{key, BuildSkillsVector(1)}};
    info.AppendDynamicSkillsToAbilityIfExist(abilityInfo);
    size_t expectSize = 2;
    EXPECT_EQ(abilityInfo.skills.size(), expectSize);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1100
 * @tc.name: SetAbilityFileTypesForSelf_1100
 * @tc.desc: 1.test ValidateDynamicSkills
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1100, Function | SmallTest | Level1)
{
    std::map<std::string, std::vector<Skill>> dynamicSkills = {{KEY, BuildSkillsVector(1)}};
    InnerBundleInfo info;
    bool ret = info.ValidateDynamicSkills(dynamicSkills);
    EXPECT_TRUE(ret);

    std::vector<Skill> skills;
    Skill skill;
    SkillUri skillUri;
    skillUri.type = INVALID_FILE_TYPE;
    skill.uris = {skillUri};
    skills.emplace_back(skill);
    dynamicSkills = {{KEY, skills}};
    ret = info.ValidateDynamicSkills(dynamicSkills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1200
 * @tc.name: SetAbilityFileTypesForSelf_1200
 * @tc.desc: 1.test SetAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string moduleName = "notExistModule";
    ErrCode ret = info.SetAbilityFileTypes(moduleName, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1300
 * @tc.name: SetAbilityFileTypesForSelf_1300
 * @tc.desc: 1.test SetAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1300, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.innerModuleInfos_ = {{MODULE_NAME, InnerModuleInfo()}};
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    std::string abilityName = "notExistAbility";
    ErrCode ret = info.SetAbilityFileTypes(MODULE_NAME, abilityName, FILE_TYPES);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1400
 * @tc.name: SetAbilityFileTypesForSelf_1400
 * @tc.desc: 1.test SetAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1400, Function | SmallTest | Level1)
{
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.bundleName = BUNDLE_NAME;
    innerAbilityInfo.moduleName = "wrongModule";
    innerAbilityInfo.name = ABILITY_NAME;

    std::string key = BundleUtil::GetAbilityKey(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.innerModuleInfos_ = {{MODULE_NAME, InnerModuleInfo()}};
    info.baseAbilityInfos_ = {{key, innerAbilityInfo}};
    ErrCode ret = info.SetAbilityFileTypes(MODULE_NAME, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1500
 * @tc.name: SetAbilityFileTypesForSelf_1500
 * @tc.desc: 1.test SetAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1500, Function | SmallTest | Level1)
{
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.bundleName = BUNDLE_NAME;
    innerAbilityInfo.moduleName = MODULE_NAME;
    innerAbilityInfo.name = "wrongAbility";

    std::string key = BundleUtil::GetAbilityKey(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.innerModuleInfos_ = {{MODULE_NAME, InnerModuleInfo()}};
    info.baseAbilityInfos_ = {{key, innerAbilityInfo}};
    ErrCode ret = info.SetAbilityFileTypes(MODULE_NAME, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1600
 * @tc.name: SetAbilityFileTypesForSelf_1600
 * @tc.desc: 1.test SetAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1600, Function | SmallTest | Level1)
{
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.bundleName = BUNDLE_NAME;
    innerAbilityInfo.moduleName = MODULE_NAME;
    innerAbilityInfo.name = ABILITY_NAME;

    std::string key = BundleUtil::GetAbilityKey(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.innerModuleInfos_ = {{MODULE_NAME, InnerModuleInfo()}};
    info.baseAbilityInfos_ = {{key, innerAbilityInfo}};
    ErrCode ret = info.SetAbilityFileTypes(MODULE_NAME, ABILITY_NAME, {});
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1700
 * @tc.name: SetAbilityFileTypesForSelf_1700
 * @tc.desc: 1.test SetAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1700, Function | SmallTest | Level1)
{
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.bundleName = BUNDLE_NAME;
    innerAbilityInfo.moduleName = MODULE_NAME;
    innerAbilityInfo.name = ABILITY_NAME;

    std::string key = BundleUtil::GetAbilityKey(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.innerModuleInfos_ = {{MODULE_NAME, InnerModuleInfo()}};
    info.baseAbilityInfos_ = {{key, innerAbilityInfo}};
    info.dynamicSkills_ = {{key, BuildSkillsVector(1)}};
    ErrCode ret = info.SetAbilityFileTypes(MODULE_NAME, ABILITY_NAME, {});
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.dynamicSkills_.size(), 0);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1800
 * @tc.name: SetAbilityFileTypesForSelf_1800
 * @tc.desc: 1.test SetAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1800, Function | SmallTest | Level1)
{
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.bundleName = BUNDLE_NAME;
    innerAbilityInfo.moduleName = MODULE_NAME;
    innerAbilityInfo.name = ABILITY_NAME;

    std::string key = BundleUtil::GetAbilityKey(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.innerModuleInfos_ = {{MODULE_NAME, InnerModuleInfo()}};
    info.baseAbilityInfos_ = {{key, innerAbilityInfo}};
    ErrCode ret = info.SetAbilityFileTypes(MODULE_NAME, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.dynamicSkills_.size(), 1);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_1900
 * @tc.name: SetAbilityFileTypesForSelf_1900
 * @tc.desc: 1.test SetAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_1900, Function | SmallTest | Level1)
{
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.bundleName = BUNDLE_NAME;
    innerAbilityInfo.moduleName = MODULE_NAME;
    innerAbilityInfo.name = ABILITY_NAME;

    std::string key = BundleUtil::GetAbilityKey(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.innerModuleInfos_ = {{MODULE_NAME, InnerModuleInfo()}};
    info.baseAbilityInfos_ = {{key, innerAbilityInfo}};
    info.dynamicSkills_ = {{key, BuildSkillsVector(1)}};
    ErrCode ret = info.SetAbilityFileTypes(MODULE_NAME, ABILITY_NAME, {INVALID_FILE_TYPE});
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_2000
 * @tc.name: SetAbilityFileTypesForSelf_2000
 * @tc.desc: 1.test HandleSetAbilityFileTypesForSelf
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_2000, Function | SmallTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(MODULE_NAME);
    data.WriteString(ABILITY_NAME);
    data.WriteStringVector(FILE_TYPES);
    ErrCode ret = bundleMgrHost.HandleSetAbilityFileTypesForSelf(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_2100
 * @tc.name: SetAbilityFileTypesForSelf_2100
 * @tc.desc: 1.test ValidateAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_2100, Function | SmallTest | Level1)
{
    ErrCode ret = ParamValidator::ValidateAbilityFileTypes(MODULE_NAME, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_OK);
    ret = ParamValidator::ValidateAbilityFileTypes("", ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_2200
 * @tc.name: SetAbilityFileTypesForSelf_2200
 * @tc.desc: 1.test ValidateAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_2200, Function | SmallTest | Level1)
{
    ErrCode ret = ParamValidator::ValidateAbilityFileTypes(MODULE_NAME, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_OK);
    ret = ParamValidator::ValidateAbilityFileTypes("", ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_2300
 * @tc.name: SetAbilityFileTypesForSelf_2300
 * @tc.desc: 1.test ValidateAbilityFileTypes
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_2300, Function | SmallTest | Level1)
{
    ErrCode ret = ParamValidator::ValidateAbilityFileTypes(MODULE_NAME, ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_OK);
    ret = ParamValidator::ValidateAbilityFileTypes("", ABILITY_NAME, FILE_TYPES);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_2400
 * @tc.name: SetAbilityFileTypesForSelf_2400
 * @tc.desc: 1.test UpdateDynamicSkills
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_2400, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    installer.UpdateDynamicSkills();
    InnerBundleInfo tmpInfo;
    bool ret = installer.GetTempBundleInfo(tmpInfo);
    EXPECT_FALSE(ret);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    installer.tempInfo_.SetTempBundleInfo(info);
    installer.UpdateDynamicSkills();
    ret = installer.GetTempBundleInfo(tmpInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_2500
 * @tc.name: SetAbilityFileTypesForSelf_2500
 * @tc.desc: 1.test UpdateDynamicSkills
 */
HWTEST_F(BmsDynamicSkillsTest, SetAbilityFileTypesForSelf_2500, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    installer.UpdateDynamicSkills();
    InnerBundleInfo tmpInfo;
    bool ret = installer.GetTempBundleInfo(tmpInfo);
    EXPECT_FALSE(ret);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    installer.tempInfo_.SetTempBundleInfo(info);
    installer.UpdateDynamicSkills();
    ret = installer.GetTempBundleInfo(tmpInfo);
    EXPECT_TRUE(ret);
}
}