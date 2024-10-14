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

#include <gtest/gtest.h>

#define private public
#include "aot/aot_executor.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "default_app_rdb.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_ipc_skeleton.h"
#include "mock_rdb_data_manager.h"
#include "mock_status_receiver.h"
#include "permission_define.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.test.defaultApp";
const std::string MODULE_NAME = "module01";
const std::string ABILITY_NAME = "BROWSER";
const std::string DEFAULT_FILE_TYPE_VIDEO_MP4 = "video/mp4";
const std::string DEFAULT_APP_VIDEO = "VIDEO";
const std::string ACTION_VIEW_DATA = "ohos.want.action.viewData";
const std::string HTTP_SCHEME = "http://";
const std::string EMAIL_ACTION = "ohos.want.action.sendToData";
const std::string EMAIL_SCHEME = "mailto";
const std::string EMAIL = "EMAIL";
const int32_t USER_ID = 100;
const int32_t ALL_USER_ID = -4;
const int32_t UID = 20000001;
} // namespace

class BmsBundleDefaultAppMgrTest : public testing::Test {
public:
    BmsBundleDefaultAppMgrTest();
    ~BmsBundleDefaultAppMgrTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void ClearDataMgr();
    void ResetDataMgr();
    void AddInnerBundleInfo(const std::string bundleName, int32_t flag);
    void UninstallBundleInfo(const std::string bundleName);

    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
};

BmsBundleDefaultAppMgrTest::BmsBundleDefaultAppMgrTest() {}

BmsBundleDefaultAppMgrTest::~BmsBundleDefaultAppMgrTest() {}

void BmsBundleDefaultAppMgrTest::SetUpTestCase() {}

void BmsBundleDefaultAppMgrTest::TearDownTestCase() {}

void BmsBundleDefaultAppMgrTest::SetUp() {}

void BmsBundleDefaultAppMgrTest::TearDown() {}

void BmsBundleDefaultAppMgrTest::ClearDataMgr()
{
    if (bundleMgrService_) {
        bundleMgrService_->dataMgr_ = nullptr;
    }
}

void BmsBundleDefaultAppMgrTest::ResetDataMgr()
{
    if (bundleMgrService_ == nullptr) {
        return;
    }
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    ASSERT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleDefaultAppMgrTest::AddInnerBundleInfo(const std::string bundleName, int32_t flag)
{
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME;
    abilityInfo.moduleName = MODULE_NAME;
    abilityInfo.bundleName = bundleName;
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.abilityInfos.emplace_back(abilityInfo);
    ApplicationInfo application;
    application.name = bundleName;
    application.bundleName = bundleName;
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = bundleName;
    userInfo.bundleUserInfo.userId = ALL_USER_ID;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;
    moduleInfo.name = MODULE_NAME;
    moduleInfo.modulePackage = MODULE_NAME;

    std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
    innerModuleInfoMap[MODULE_NAME] = moduleInfo;
    std::map<std::string, AbilityInfo> innerAbilityMap;
    innerAbilityMap[MODULE_NAME] = abilityInfo;

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = UID;
    innerBundleUserInfo.bundleUserInfo.userId = USER_ID;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(application);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    innerBundleInfo.AddInnerModuleInfo(innerModuleInfoMap);
    innerBundleInfo.AddModuleAbilityInfo(innerAbilityMap);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    Skill skill;
    SkillUri uri;
    uri.type = "image/*";
    skill.actions.emplace_back("image/*");
    skill.actions.emplace_back("ohos.want.action.viewData");
    skill.uris.emplace_back(uri);
    std::vector skills{ skill };
    std::string key;
    key.append(bundleName).append(".").append(abilityInfo.package).append(".").append(ABILITY_NAME);
    innerBundleInfo.InsertSkillInfo(key, skills);

    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bool addRet = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    bool endRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS);
    EXPECT_TRUE(startRet);
    EXPECT_TRUE(addRet);
    EXPECT_TRUE(endRet);
}

void BmsBundleDefaultAppMgrTest::UninstallBundleInfo(const std::string bundleName)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

/**
 * @tc.number: SetDefaultApplication_0010
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplication_0010, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", "", "", "");
    want.SetElement(elementName);
    auto res = impl.SetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: SetDefaultApplication_0020
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplication_0020, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    ClearDataMgr();
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, "", MODULE_NAME);
    want.SetElement(elementName);
    auto res = impl.SetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: SetDefaultApplication_0030
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplication_0030, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, "", MODULE_NAME);
    want.SetElement(elementName);
    auto res = impl.SetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: SetDefaultApplication_0040
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplication_0040, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(101);

    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, ABILITY_NAME, MODULE_NAME);
    want.SetElement(elementName);
    auto res = impl.SetDefaultApplication(101, DEFAULT_APP_VIDEO, want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH);
}

/**
 * @tc.number: SetDefaultApplication_0050
 * @tc.name: test SetDefaultApplication
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplication_0050, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo info;
    dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, "", MODULE_NAME);
    want.SetElement(elementName);
    auto res = impl.SetDefaultApplication(101, DEFAULT_APP_VIDEO, want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH);
}

/**
 * @tc.number: IsDefaultApplication_0100
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.IsDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsDefaultApplication_0100, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    bool isDefaultApp = false;
    auto res = impl.IsDefaultApplication("IMAGE", isDefaultApp);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: ResetDefaultApplication_0010
 * @tc.name: test ResetDefaultApplication
 * @tc.desc: 1.ResetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, ResetDefaultApplication_0010, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    auto res = impl.ResetDefaultApplication(100, "IMAGE");
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: IsDefaultApplication_0010
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsDefaultApplication_0010, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string type(201, '1');
    bool isDefaultApp = false;
    auto ret = DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: IsDefaultApplication_0020
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsDefaultApplication_0020, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string type{ "IMAGE" };
    bool isDefaultApp = false;
    auto ret = DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: IsDefaultApplication_0030
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsDefaultApplication_0030, Function | SmallTest | Level1)
{
    int32_t userId = ALL_USER_ID;
    std::string type{ "NON" };
    bool isDefaultApp = false;

    auto dataMgr = OHOS::BmsBundleDefaultAppMgrTest::bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(userId);

    auto ret = DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: IsDefaultApplication_0040
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsDefaultApplication_0040, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string type{ "IMAGE" };
    bool isDefaultApp = false;

    auto dataMgr = OHOS::BmsBundleDefaultAppMgrTest::bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(userId);
    dataMgr->AddUserId(ALL_USER_ID);

    auto ret = DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: IsDefaultApplication_0040
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsDefaultApplication_0050, Function | SmallTest | Level1)
{
    int32_t userId = ALL_USER_ID;
    std::string type{ "IMAGE" };
    bool isDefaultApp = false;

    auto ret = DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: IsDefaultApplication_0060
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsDefaultApplication_0060, Function | SmallTest | Level1)
{
    int32_t userId = ALL_USER_ID;
    std::string type{ "IMAGE" };
    bool isDefaultApp = false;

    auto dataMgr = OHOS::BmsBundleDefaultAppMgrTest::bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(ALL_USER_ID);
    AddInnerBundleInfo(BUNDLE_NAME, 0);

    auto ret = DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: IsDefaultApplication_0060
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsDefaultApplication_0070, Function | SmallTest | Level1)
{
    int32_t userId = ALL_USER_ID;
    std::string type{ "IMAGE" };
    bool isDefaultApp = false;

    auto dataMgr = OHOS::BmsBundleDefaultAppMgrTest::bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    int32_t uid = 20000001;
    int32_t bundleId = uid - 100 * Constants::BASE_USER_RANGE;
    dataMgr->bundleIdMap_.emplace(bundleId, BUNDLE_NAME);

    auto ret = DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isDefaultApp);
}

/**
 * @tc.number: IsEmailSkillsValid_0010
 * @tc.name: test IsEmailSkillsValid
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsEmailSkillsValid_0010, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    auto ret = DefaultAppMgr::GetInstance().IsEmailSkillsValid(skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsEmailSkillsValid_0020
 * @tc.name: test IsEmailSkillsValid
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsEmailSkillsValid_0020, Function | SmallTest | Level1)
{
    Skill skill;
    std::vector<Skill> skills{ skill };
    auto ret = DefaultAppMgr::GetInstance().IsEmailSkillsValid(skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsEmailSkillsValid_0030
 * @tc.name: test IsEmailSkillsValid
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsEmailSkillsValid_0030, Function | SmallTest | Level1)
{
    Skill skill;
    SkillUri uri;
    uri.scheme = "mailto";
    skill.actions.emplace_back("ohos.want.action.sendToData");
    skill.uris.emplace_back(uri);

    std::vector<Skill> skills{ skill };
    auto ret = DefaultAppMgr::GetInstance().IsEmailSkillsValid(skills);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetBundleInfo_0010
 * @tc.name: test GetBundleInfo
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBundleInfo_0010, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string type{ "AUDIO" };
    Element element;
    BundleInfo bundleInfo;

    auto ret = DefaultAppMgr::GetInstance().GetBundleInfo(userId, type, element, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBundleInfo_0020
 * @tc.name: test GetBundleInfo
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBundleInfo_0020, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string type{ "AUDIO" };
    Element element{ "Test_bundle", MODULE_NAME, ABILITY_NAME, "", "" };
    BundleInfo bundleInfo;

    auto ret = DefaultAppMgr::GetInstance().GetBundleInfo(userId, type, element, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBundleInfo_0030
 * @tc.name: test GetBundleInfo
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBundleInfo_0030, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string type{ "AUDIO" };
    Element element{ BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, "", "" };
    BundleInfo bundleInfo;

    auto ret = DefaultAppMgr::GetInstance().GetBundleInfo(userId, type, element, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBundleInfo_0040
 * @tc.name: test GetBundleInfo
 * @tc.desc: 1.is mimeType format and not contains *, return true. Otherwise return false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBundleInfo_0040, Function | SmallTest | Level1)
{
    int32_t userId = ALL_USER_ID;
    std::string type{ "IMAGE" };
    Element element{ BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, "", "" };
    BundleInfo bundleInfo;

    auto ret = DefaultAppMgr::GetInstance().GetBundleInfo(userId, type, element, bundleInfo);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(bundleInfo.abilityInfos.size() != 0);
}

/**
 * @tc.number: GetDefaultApplicationInternal_0100
 * @tc.name: Test GetDefaultApplicationInternal by DefaultAppMgr
 * @tc.desc: 1.GetDefaultApplicationInternal
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationInternal_0100, Function | SmallTest | Level1)
{
    BundleInfo info;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationInternal(
        USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, info, false);
    EXPECT_EQ(ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST, ret);
}

/**
 * @tc.number: GetDefaultApplicationInternal_0200
 * @tc.name: Test GetDefaultApplicationInternal by DefaultAppMgr
 * @tc.desc: 1.GetDefaultApplicationInternal
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationInternal_0200, Function | SmallTest | Level1)
{
    BundleInfo info;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationInternal(USER_ID, ABILITY_NAME, info, false);
    EXPECT_EQ(ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST, ret);
}

/**
 * @tc.number: GetDefaultApplication_0100
 * @tc.name: Test GetDefaultApplication by DefaultAppMgr
 * @tc.desc: 1.GetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplication_0100, Function | SmallTest | Level1)
{
    BundleInfo info;
    auto ptr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplication(USER_ID, ABILITY_NAME, info, false);
    EXPECT_EQ(ERR_BUNDLE_MANAGER_INVALID_USER_ID, ret);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = ptr;
}

/**
 * @tc.number: GetDefaultApplication_0200
 * @tc.name: Test GetDefaultApplication by DefaultAppMgr
 * @tc.desc: 1.GetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplication_0200, Function | SmallTest | Level1)
{
    BundleInfo info;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplication(USER_ID, ABILITY_NAME, info, false);
    EXPECT_EQ(ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST, ret);
}

/**
 * @tc.number: GetDefaultApplication_0300
 * @tc.name: Test GetDefaultApplication by DefaultAppMgr
 * @tc.desc: 1.GetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplication_0300, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetUri(MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplication(want, USER_ID, abilityInfos, extensionInfos, false);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetDefaultApplication_0400
 * @tc.name: Test GetDefaultApplication by DefaultAppMgr
 * @tc.desc: 1.GetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplication_0400, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetUri(HTTP_SCHEME);
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    auto ptr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplication(want, USER_ID, abilityInfos, extensionInfos, false);
    EXPECT_FALSE(ret);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = ptr;
}

/**
 * @tc.number: SetDefaultApplication_0100
 * @tc.name: Test SetDefaultApplication by DefaultAppMgr
 * @tc.desc: 1.SetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplication_0100, Function | SmallTest | Level1)
{
    Element element;
    auto ret = DefaultAppMgr::GetInstance().SetDefaultApplication(USER_ID, ABILITY_NAME, element);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.number: SetDefaultApplicationInternal_0100
 * @tc.name: Test SetDefaultApplicationInternal by DefaultAppMgr
 * @tc.desc: 1.SetDefaultApplicationInternal
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationInternal_0100, Function | SmallTest | Level1)
{
    Element element;
    auto ret = DefaultAppMgr::GetInstance().SetDefaultApplicationInternal(
        USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, element);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.number: SetDefaultApplicationInternal_0200
 * @tc.name: Test SetDefaultApplicationInternal by DefaultAppMgr
 * @tc.desc: 1.SetDefaultApplicationInternal
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationInternal_0200, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = BUNDLE_NAME;
    auto ret = DefaultAppMgr::GetInstance().SetDefaultApplicationInternal(
        USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, element);
    EXPECT_EQ(ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH, ret);
}

/**
 * @tc.number: ResetDefaultApplication_0100
 * @tc.name: Test ResetDefaultApplication by DefaultAppMgr
 * @tc.desc: 1.ResetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, ResetDefaultApplication_0100, Function | SmallTest | Level1)
{
    auto ret = DefaultAppMgr::GetInstance().ResetDefaultApplication(USER_ID, ABILITY_NAME);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.number: ResetDefaultApplicationInternal_0100
 * @tc.name: Test ResetDefaultApplicationInternal by DefaultAppMgr
 * @tc.desc: 1.ResetDefaultApplicationInternal
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, ResetDefaultApplicationInternal_0100, Function | SmallTest | Level1)
{
    auto ret = DefaultAppMgr::GetInstance().ResetDefaultApplicationInternal(USER_ID, ABILITY_NAME);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.number: IsBrowserWant_0100
 * @tc.name: Test IsBrowserWant by DefaultAppMgr
 * @tc.desc: 1.IsBrowserWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsBrowserWant_0100, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    auto ret = DefaultAppMgr::GetInstance().IsBrowserWant(want);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsBrowserWant_0200
 * @tc.name: Test IsBrowserWant by DefaultAppMgr
 * @tc.desc: 1.IsBrowserWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsBrowserWant_0200, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(DEFAULT_APP_VIDEO);
    auto ret = DefaultAppMgr::GetInstance().IsBrowserWant(want);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsBrowserWant_0300
 * @tc.name: Test IsBrowserWant by DefaultAppMgr
 * @tc.desc: 1.IsBrowserWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsBrowserWant_0300, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetUri(HTTP_SCHEME);
    auto ret = DefaultAppMgr::GetInstance().IsBrowserWant(want);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsEmailWant_0100
 * @tc.name: Test IsEmailWant by DefaultAppMgr
 * @tc.desc: 1.IsEmailWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsEmailWant_0100, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(EMAIL_ACTION);
    auto ret = DefaultAppMgr::GetInstance().IsEmailWant(want);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsEmailWant_0200
 * @tc.name: Test IsEmailWant by DefaultAppMgr
 * @tc.desc: 1.IsEmailWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsEmailWant_0200, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(DEFAULT_APP_VIDEO);
    auto ret = DefaultAppMgr::GetInstance().IsEmailWant(want);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsEmailWant_0300
 * @tc.name: Test IsEmailWant by DefaultAppMgr
 * @tc.desc: 1.IsEmailWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsEmailWant_0300, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(EMAIL_ACTION);
    want.SetUri(EMAIL_SCHEME);
    auto ret = DefaultAppMgr::GetInstance().IsEmailWant(want);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetTypeFromWant_0100
 * @tc.name: Test GetTypeFromWant by DefaultAppMgr
 * @tc.desc: 1.GetTypeFromWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetTypeFromWant_0100, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetUri(HTTP_SCHEME);
    auto ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, ABILITY_NAME);
}

/**
 * @tc.number: GetTypeFromWant_0200
 * @tc.name: Test GetTypeFromWant by DefaultAppMgr
 * @tc.desc: 1.GetTypeFromWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetTypeFromWant_0200, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(EMAIL_ACTION);
    want.SetUri(EMAIL_SCHEME);
    auto ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, EMAIL);
}

/**
 * @tc.number: GetTypeFromWant_0300
 * @tc.name: Test GetTypeFromWant by DefaultAppMgr
 * @tc.desc: 1.GetTypeFromWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetTypeFromWant_0300, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(EMAIL_ACTION);
    auto ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetTypeFromWant_0400
 * @tc.name: Test GetTypeFromWant by DefaultAppMgr
 * @tc.desc: 1.GetTypeFromWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetTypeFromWant_0400, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    std::string uri = "httsadasp://";
    want.SetUri(uri);
    auto ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetTypeFromWant_0500
 * @tc.name: Test GetTypeFromWant by DefaultAppMgr
 * @tc.desc: 1.GetTypeFromWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetTypeFromWant_0500, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetUri(MODULE_NAME);
    auto ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetTypeFromWant_0600
 * @tc.name: Test GetTypeFromWant by DefaultAppMgr
 * @tc.desc: 1.GetTypeFromWant
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetTypeFromWant_0600, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetUri(MODULE_NAME);
    want.SetType(MODULE_NAME);
    auto ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, MODULE_NAME);
}

/**
 * @tc.number: GetBundleInfoByUtd_0100
 * @tc.name: Test GetBundleInfoByUtd by DefaultAppMgr
 * @tc.desc: 1.GetBundleInfoByUtd
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBundleInfoByUtd_0100, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    auto ret = DefaultAppMgr::GetInstance().GetBundleInfoByUtd(ALL_USER_ID, EMAIL, bundleInfo, false);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST);
}

/**
 * @tc.number: MatchActionAndType_0100
 * @tc.name: Test MatchActionAndType by DefaultAppMgr
 * @tc.desc: 1.MatchActionAndType
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, MatchActionAndType_0100, Function | SmallTest | Level1)
{
    std::string type;
    std::vector<Skill> skills;
    Skill skill;
    skills.push_back(skill);
    auto ret = DefaultAppMgr::GetInstance().MatchActionAndType(EMAIL_SCHEME, type, skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsMatch_0100
 * @tc.name: Test IsMatch by DefaultAppMgr
 * @tc.desc: 1.IsMatch
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsMatch_0100, Function | SmallTest | Level1)
{
    std::string type;
    std::vector<Skill> skills;
    Skill skill;
    skills.push_back(skill);
    auto ret = DefaultAppMgr::GetInstance().IsMatch(HTTP_SCHEME, skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MatchAppType_0100
 * @tc.name: Test MatchAppType by DefaultAppMgr
 * @tc.desc: 1.MatchAppType
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, MatchAppType_0100, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    Skill skill;
    skills.push_back(skill);
    auto ret = DefaultAppMgr::GetInstance().MatchAppType(ABILITY_NAME, skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MatchAppType_0200
 * @tc.name: Test MatchAppType by DefaultAppMgr
 * @tc.desc: 1.MatchAppType
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, MatchAppType_0200, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    Skill skill;
    skills.push_back(skill);
    auto ret = DefaultAppMgr::GetInstance().MatchAppType(EMAIL, skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MatchAppType_0300
 * @tc.name: Test MatchAppType by DefaultAppMgr
 * @tc.desc: 1.MatchAppType
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, MatchAppType_0300, Function | SmallTest | Level1)
{
    std::string type;
    std::vector<Skill> skills;
    Skill skill;
    skills.push_back(skill);
    auto ret = DefaultAppMgr::GetInstance().MatchAppType(type, skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsBrowserSkillsValid_0100
 * @tc.name: Test IsBrowserSkillsValid by DefaultAppMgr
 * @tc.desc: 1.IsBrowserSkillsValid
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsBrowserSkillsValid_0100, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    Skill skill;
    skills.push_back(skill);
    auto ret = DefaultAppMgr::GetInstance().IsBrowserSkillsValid(skills);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MatchUtd_0100
 * @tc.name: Test MatchUtd by DefaultAppMgr
 * @tc.desc: 1.MatchUtd
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, MatchUtd_0100, Function | SmallTest | Level1)
{
    std::string type;
    std::vector<Skill> skills;
    SkillUri Uri;
    Skill skill;
    skill.uris.push_back(Uri);
    skill.actions.push_back(ACTION_VIEW_DATA);
    skills.push_back(skill);
    auto ret = DefaultAppMgr::GetInstance().MatchUtd(type, skills);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetBrokerBundleInfo_0100
 * @tc.name: Test GetBrokerBundleInfo by DefaultAppMgr
 * @tc.desc: 1.GetBrokerBundleInfo
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBrokerBundleInfo_0100, Function | SmallTest | Level1)
{
    Element element;
    BundleInfo bundleInfo;
    auto ret = DefaultAppMgr::GetInstance().GetBrokerBundleInfo(element, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBrokerBundleInfo_0200
 * @tc.name: Test GetBrokerBundleInfo by DefaultAppMgr
 * @tc.desc: 1.GetBrokerBundleInfo
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBrokerBundleInfo_0200, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    BundleInfo bundleInfo;
    auto ret = DefaultAppMgr::GetInstance().GetBrokerBundleInfo(element, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBrokerBundleInfo_0300
 * @tc.name: Test GetBrokerBundleInfo by DefaultAppMgr
 * @tc.desc: 1.GetBrokerBundleInfo
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBrokerBundleInfo_0300, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    BundleInfo bundleInfo;
    DelayedSingleton<BundleMgrService>::GetInstance()->isBrokerServiceStarted_ = true;
    auto ret = DefaultAppMgr::GetInstance().GetBrokerBundleInfo(element, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsSpecificMimeType_0100
 * @tc.name: Test IsSpecificMimeType by DefaultAppMgr
 * @tc.desc: 1.IsSpecificMimeType
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsSpecificMimeType_0100, Function | SmallTest | Level1)
{
    std::string param = "***";
    auto ret = DefaultAppMgr::GetInstance().IsSpecificMimeType(param);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetDefaultApplicationInfo_0100
 * @tc.name: Test GetDefaultApplicationInfo by DefaultAppMgr
 * @tc.desc: 1.GetDefaultApplicationInfo
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationInfo_0100, Function | SmallTest | Level1)
{
    DefaultAppRdb defaultAppRdb;
    Element element;
    auto ret = defaultAppRdb.GetDefaultApplicationInfo(ALL_USER_ID, EMAIL_ACTION, element);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteDefaultApplicationInfo_0100
 * @tc.name: Test DeleteDefaultApplicationInfo by DefaultAppRdb
 * @tc.desc: 1.DeleteDefaultApplicationInfo
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, DeleteDefaultApplicationInfo_0100, Function | SmallTest | Level1)
{
    DefaultAppRdb defaultAppRdb;
    auto ret = defaultAppRdb.DeleteDefaultApplicationInfo(ALL_USER_ID, EMAIL_ACTION);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ToJson_0100
 * @tc.name: Test ToJson by DefaultAppData
 * @tc.desc: 1.ToJson
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, ToJson_0100, Function | SmallTest | Level1)
{
    DefaultAppData defaultAppRdb;
    Element element;
    defaultAppRdb.infos.emplace(EMAIL, element);
    nlohmann::json jsonObject;
    defaultAppRdb.ToJson(jsonObject);
    EXPECT_NE(jsonObject.find("infos"), jsonObject.end());
}

/**
 * @tc.number: GetDefaultApplication_0500
 * @tc.name: test GetDefaultApplication by DefaultAppHostImpl
 * @tc.desc: 1.GetDefaultApplication
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplication_0500, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    BundleInfo bundleInfo;
    std::string type;
    auto res = impl.GetDefaultApplication(USER_ID, type, bundleInfo);
    EXPECT_NE(res, ERR_OK);
}
} // namespace OHOS