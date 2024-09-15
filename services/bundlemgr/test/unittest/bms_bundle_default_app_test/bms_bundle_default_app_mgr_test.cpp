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
    innerBundleInfo.SetInstallMark(bundleName, MODULE_NAME, InstallExceptionStatus::INSTALL_FINISH);

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
} // namespace OHOS