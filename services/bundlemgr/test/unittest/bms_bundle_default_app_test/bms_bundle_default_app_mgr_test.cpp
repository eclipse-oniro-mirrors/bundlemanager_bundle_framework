/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include "default_app_host_impl.h"
#include "default_app_rdb.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_ipc_skeleton.h"
#include "mock_browser_permission_config.h"
#include "mock_rdb_data_manager.h"
#include "mock_status_receiver.h"
#include "permission_define.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

// test seams defined in test/mock/src/bundle_permission_mgr.cpp in the global namespace
void SetVerifyPermissionByCallingTokenIdForTest(bool value);
void SetVerifyCallingPermissionForTest(bool value);
void SetIsSelfCalling(bool value);

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.test.defaultApp";
const std::string MODULE_NAME = "module01";
const std::string ABILITY_NAME = "BROWSER";
const std::string DEFAULT_FILE_TYPE_VIDEO_MP4 = "video/mp4";
const std::string DEFAULT_APP_VIDEO = "VIDEO";
const std::string ACTION_VIEW_DATA = "ohos.want.action.viewData";
const std::string ENTITY_BROWSER = "entity.system.browsable";
const std::string HTTP = "http";
const std::string HTTP_SCHEME = "http://";
const std::string EMAIL_ACTION = "ohos.want.action.sendToData";
const std::string EMAIL_SCHEME = "mailto";
const std::string EMAIL = "EMAIL";
const int32_t USER_ID = 100;
const int32_t ALL_USER_ID = -4;
const int32_t UID = 20000001;
const int32_t WAIT_TIME = 2;
const int32_t EDC_DEFAULT_USER_ID = -100;
const std::string IMAGE_UTD_ID = "general.image";
const std::string PNG_UTD_ID = "general.png";
const std::string WORD = "WORD";
const std::string WORD_DOC_UTD_ID = "com.microsoft.word.doc";
const std::string WORD_DOT_UTD_ID = "com.microsoft.word.dot";
const std::string WORD_DOCUMENT_UTD_ID = "org.openxmlformats.wordprocessingml.document";
const std::string WORD_TEMPLATE_UTD_ID = "org.openxmlformats.wordprocessingml.template";
const std::string PDF_UTD_ID = "com.adobe.pdf";
const std::string MP4_UTD_ID = "general.mpeg-4";
const std::string BROWSER = "BROWSER";
const std::string DEFAULT_APPLICATION_CHANGED_EVENT = "usual.event.DEFAULT_APPLICATION_CHANGED";
const std::string UTD_IDS = "utdIds";
const std::string USER_ID_STRING = "userId";
const std::string TEST_UTD_ID = "testUidId";
constexpr uint16_t TYPE_MAX_SIZE = 512;
constexpr uint32_t BROWSER_TOKEN_ID = 1001;
constexpr int32_t BROWSER_USER_ID = 100;

// Build an InnerBundleInfo whose clone bundle info carries a non-zero accessTokenId for the given
// userId, so HasDefaultAppPermission can proceed past step 3/4 to the permission query (step 5).
InnerBundleInfo MakeGrantedBundle(const std::string &bundleName, int32_t userId)
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
    userInfo.bundleUserInfo.userId = userId;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(application);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    innerBundleInfo.SetAccessTokenId(BROWSER_TOKEN_ID, userId);
    return innerBundleInfo;
}

// A browser-typed skill that matches the http want built for BROWSER:
// action=viewData + entity=entity.system.browsable + scheme=http.
Skill MakeBrowserSkill()
{
    Skill skill;
    skill.actions.emplace_back(ACTION_VIEW_DATA);
    skill.entities.emplace_back(ENTITY_BROWSER);
    SkillUri httpUri;
    httpUri.scheme = HTTP;
    skill.uris.emplace_back(httpUri);
    return skill;
}

// Install a granted browser bundle that carries a matching skill so QueryAbilityInfosV9 can find it
// for the BROWSER want, exercising the candidate happy path of GetDefaultApplicationCandidates.
void InstallGrantedBrowser(const std::shared_ptr<BundleDataMgr> &dataMgr, const std::string &bundleName,
    int32_t userId)
{
    auto info = MakeGrantedBundle(bundleName, userId);
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = ABILITY_NAME;
    innerAbilityInfo.moduleName = MODULE_NAME;
    innerAbilityInfo.bundleName = bundleName;
    innerAbilityInfo.skills.emplace_back(MakeBrowserSkill());
    std::string key;
    key.append(bundleName).append(".").append("").append(".").append(ABILITY_NAME);
    info.InsertAbilitiesInfo(key, innerAbilityInfo);
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START));
    EXPECT_TRUE(dataMgr->AddInnerBundleInfo(bundleName, info));
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS));
}

// A fully in-memory IDefaultAppDb for service-layer coverage tests. Each public flag controls the
// return value of the corresponding db method (default true), and an in-memory store keyed by userId
// backs the Get/Set/Delete info calls so preset slots (EDC -userId / INITIAL_USER_ID -1) can be
// pre-populated by a test. Toggling a flag to false forces the matching branch in
// Set/Reset/HandleUninstall to take its failure arm.
class FakeDefaultAppDb : public IDefaultAppDb {
public:
    bool getInfosRet = true;
    bool getInfoRet = true;
    bool setInfosRet = true;
    bool setInfoRet = true;
    bool deleteInfosRet = true;
    bool deleteInfoRet = true;

    // Pre-populate a slot exactly as a real rdb would store it.
    void Put(int32_t userId, const std::string& type, const Element& element)
    {
        store_[userId][type] = element;
    }

    bool GetDefaultApplicationInfos(int32_t userId, std::map<std::string, Element>& infos) override
    {
        if (!getInfosRet) {
            return false;
        }
        auto it = store_.find(userId);
        infos = (it != store_.end()) ? it->second : std::map<std::string, Element>{};
        return true;
    }

    bool GetDefaultApplicationInfo(int32_t userId, const std::string& type, Element& element) override
    {
        if (!getInfoRet) {
            return false;
        }
        auto it = store_.find(userId);
        if (it == store_.end()) {
            return false;
        }
        auto typeIt = it->second.find(type);
        if (typeIt == it->second.end()) {
            return false;
        }
        element = typeIt->second;
        return true;
    }

    bool SetDefaultApplicationInfos(int32_t userId, const std::map<std::string, Element>& infos) override
    {
        if (!setInfosRet) {
            return false;
        }
        store_[userId] = infos;
        return true;
    }

    bool SetDefaultApplicationInfo(int32_t userId, const std::string& type, const Element& element) override
    {
        if (!setInfoRet) {
            return false;
        }
        store_[userId][type] = element;
        return true;
    }

    bool DeleteDefaultApplicationInfos(int32_t userId) override
    {
        if (!deleteInfosRet) {
            return false;
        }
        store_.erase(userId);
        return true;
    }

    bool DeleteDefaultApplicationInfo(int32_t userId, const std::string& type) override
    {
        if (!deleteInfoRet) {
            return false;
        }
        auto it = store_.find(userId);
        if (it != store_.end()) {
            it->second.erase(type);
        }
        return true;
    }

    void RegisterDeathListener() override {}
    void UnRegisterDeathListener() override {}

private:
    std::map<int32_t, std::map<std::string, Element>> store_;
};
} // namespace

class DefaultAppChangedTestEventSubscriber;
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
    void SubscribeDefaultAppChangedEvent();
    void UnSubscribeDefaultAppChangedEvent();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<DefaultAppChangedTestEventSubscriber> subscriber_ = nullptr;
    static std::condition_variable cv_;
    static std::mutex mutex_;
};

class DefaultAppChangedTestEventSubscriber final : public EventFwk::CommonEventSubscriber {
public:
    explicit DefaultAppChangedTestEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
        :CommonEventSubscriber(subscribeInfo) {}

    void OnReceiveEvent(const EventFwk::CommonEventData &data)
    {
        auto want = data.GetWant();
        if (want.GetAction() == DEFAULT_APPLICATION_CHANGED_EVENT) {
            utdId = want.GetStringArrayParam(UTD_IDS);
            userId = want.GetParams().GetIntParam(USER_ID_STRING, -1);
        }
        BmsBundleDefaultAppMgrTest::cv_.notify_one();
    }
    std::vector<std::string> utdId;
    int32_t userId;
};

std::condition_variable BmsBundleDefaultAppMgrTest::cv_;
std::mutex BmsBundleDefaultAppMgrTest::mutex_;

BmsBundleDefaultAppMgrTest::BmsBundleDefaultAppMgrTest() {}

BmsBundleDefaultAppMgrTest::~BmsBundleDefaultAppMgrTest() {}

void BmsBundleDefaultAppMgrTest::SetUpTestCase() {}

void BmsBundleDefaultAppMgrTest::TearDownTestCase() {}

void BmsBundleDefaultAppMgrTest::SetUp()
{
    // reset the preset cache so cases with different -1 slot contents stay isolated
    DefaultAppMgr::GetInstance().presetCacheLoaded_ = false;
}

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
    std::map<std::string, InnerAbilityInfo> innerAbilityMap;
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = ABILITY_NAME;
    innerAbilityInfo.moduleName = MODULE_NAME;
    innerAbilityInfo.bundleName = bundleName;
    innerAbilityMap[MODULE_NAME] = innerAbilityInfo;

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
    skill.actions.emplace_back(ACTION_VIEW_DATA);
    skill.uris.emplace_back(uri);
    std::vector skills{ skill };
    std::string key;
    key.append(bundleName).append(".").append(abilityInfo.package).append(".").append(ABILITY_NAME);
    innerAbilityInfo.skills = skills;
    innerBundleInfo.InsertAbilitiesInfo(key, innerAbilityInfo);

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

void BmsBundleDefaultAppMgrTest::SubscribeDefaultAppChangedEvent()
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(DEFAULT_APPLICATION_CHANGED_EVENT);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscriber_ = std::make_shared<DefaultAppChangedTestEventSubscriber>(subscribeInfo);
    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
}

void BmsBundleDefaultAppMgrTest::UnSubscribeDefaultAppChangedEvent()
{
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
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
 * @tc.number: GetBundleInfo_0050
 * @tc.name: Test GetBundleInfo by DefaultAppMgr
 * @tc.desc: 1.GetBundleInfo
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBundleInfo_0050, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string type{ "AUDIO" };
    Element element{ BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, "", "", 1 };
    BundleInfo bundleInfo;

    auto ret = DefaultAppMgr::GetInstance().GetBundleInfo(userId, type, element, bundleInfo);
    EXPECT_FALSE(ret);
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
 * @tc.number: GetDefaultInfo_0100
 * @tc.name: Test GetDefaultInfo by DefaultAppMgr
 * @tc.desc: 1.GetDefaultInfo, because there is no content corresponding to utdId in the database, it is false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultInfo_0100, Function | SmallTest | Level1)
{
    std::unordered_map<std::string, std::pair<bool, Element>> defaultInfo;
    DefaultAppMgr::GetInstance().GetDefaultInfo(USER_ID, {WORD_DOC_UTD_ID, WORD_DOT_UTD_ID}, defaultInfo);
    EXPECT_FALSE(defaultInfo.empty());
}

/**
 * @tc.number: SendDefaultAppChangeEventIfNeeded_0100
 * @tc.name: Test SendDefaultAppChangeEventIfNeeded by DefaultAppMgr
 * @tc.desc: 1.SendDefaultAppChangeEventIfNeeded, because the last parameter is empty, it is false
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SendDefaultAppChangeEventIfNeeded_0100, Function | SmallTest | Level1)
{
    bool ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEventIfNeeded(
        USER_ID, {WORD_DOC_UTD_ID, WORD_DOT_UTD_ID}, {});
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ShouldSendEvent_0100
 * @tc.name: Test ShouldSendEvent by DefaultAppMgr
 * @tc.desc: 1.ShouldSendEvent, covering the combined state of originalResult and current Result Boolean parameters
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, ShouldSendEvent_0100, Function | SmallTest | Level1)
{
    bool originalResult = true;
    Element originalElement;
    originalElement.bundleName = BUNDLE_NAME;
    originalElement.moduleName = MODULE_NAME;
    originalElement.abilityName = ABILITY_NAME;
    bool currentResult = true;
    Element currentElement;
    currentElement.bundleName = BUNDLE_NAME;
    currentElement.moduleName = MODULE_NAME;
    currentElement.abilityName = ABILITY_NAME;
    auto ret = DefaultAppMgr::GetInstance().ShouldSendEvent(
        originalResult, originalElement, currentResult, currentElement);
    EXPECT_FALSE(ret);

    currentElement.abilityName ="";
    ret = DefaultAppMgr::GetInstance().ShouldSendEvent(originalResult, originalElement, currentResult, currentElement);
    EXPECT_TRUE(ret);

    currentResult = false;
    ret = DefaultAppMgr::GetInstance().ShouldSendEvent(originalResult, originalElement, currentResult, currentElement);
    EXPECT_TRUE(ret);

    originalResult = false;
    ret = DefaultAppMgr::GetInstance().ShouldSendEvent(originalResult, originalElement, currentResult, currentElement);
    EXPECT_FALSE(ret);

    currentResult = true;
    ret = DefaultAppMgr::GetInstance().ShouldSendEvent(originalResult, originalElement, currentResult, currentElement);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: SendDefaultAppChangeEvent_0100
 * @tc.name: Test SendDefaultAppChangeEvent by DefaultAppMgr
 * @tc.desc: 1.SendDefaultAppChangeEvent, type is set to 'general.image', no permission to send event
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SendDefaultAppChangeEvent_0100, Function | SmallTest | Level1)
{
    SubscribeDefaultAppChangedEvent();
    auto ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEvent(USER_ID, {IMAGE_UTD_ID});
    EXPECT_TRUE(ret);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto waitRet = cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [lockCallback = subscriber_]() {
            return (!lockCallback->utdId.empty() &&
                lockCallback->utdId.at(0) == IMAGE_UTD_ID &&
                lockCallback->userId == USER_ID);
        });
        EXPECT_FALSE(waitRet);
    }
    UnSubscribeDefaultAppChangedEvent();
}

/**
 * @tc.number: SendDefaultAppChangeEvent_0200
 * @tc.name: Test SendDefaultAppChangeEvent by DefaultAppMgr
 * @tc.desc: 1.SendDefaultAppChangeEvent, type is set to 'general.png', no permission to send event
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SendDefaultAppChangeEvent_0200, Function | SmallTest | Level1)
{
    SubscribeDefaultAppChangedEvent();
    auto ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEvent(USER_ID, {PNG_UTD_ID});
    EXPECT_TRUE(ret);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto waitRet = cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [lockCallback = subscriber_]() {
            return (!lockCallback->utdId.empty() &&
                lockCallback->utdId.at(0) == PNG_UTD_ID &&
                lockCallback->userId == USER_ID);
        });
        EXPECT_FALSE(waitRet);
    }
    UnSubscribeDefaultAppChangedEvent();
}

/**
 * @tc.number: SendDefaultAppChangeEvent_0300
 * @tc.name: Test SendDefaultAppChangeEvent by DefaultAppMgr
 * @tc.desc: 1.SendDefaultAppChangeEvent, type is set to 'WORD', no permission to send event
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SendDefaultAppChangeEvent_0300, Function | SmallTest | Level1)
{
    SubscribeDefaultAppChangedEvent();
    auto ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEvent(USER_ID, {WORD});
    EXPECT_TRUE(ret);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto waitRet = cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [lockCallback = subscriber_]() {
            return (!lockCallback->utdId.empty() &&
                (lockCallback->utdId.at(0) == WORD_DOC_UTD_ID ||
                lockCallback->utdId.at(0) == WORD_DOT_UTD_ID ||
                lockCallback->utdId.at(0) == WORD_DOCUMENT_UTD_ID ||
                lockCallback->utdId.at(0) == WORD_TEMPLATE_UTD_ID) &&
                lockCallback->userId == USER_ID);
        });
        EXPECT_FALSE(waitRet);
    }
    UnSubscribeDefaultAppChangedEvent();
}

/**
 * @tc.number: SendDefaultAppChangeEvent_0400
 * @tc.name: Test SendDefaultAppChangeEvent by DefaultAppMgr
 * @tc.desc: 1.SendDefaultAppChangeEvent, type is set to com.microsoft.word.dot, no permission to send event
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SendDefaultAppChangeEvent_0400, Function | SmallTest | Level1)
{
    SubscribeDefaultAppChangedEvent();
    auto ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEvent(USER_ID, {WORD_DOT_UTD_ID});
    EXPECT_TRUE(ret);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto waitRet = cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [lockCallback = subscriber_]() {
            return (!lockCallback->utdId.empty() &&
                lockCallback->utdId.at(0) == WORD_DOT_UTD_ID &&
                lockCallback->userId == USER_ID);
        });
        EXPECT_FALSE(waitRet);
    }
    UnSubscribeDefaultAppChangedEvent();
}

/**
 * @tc.number: SendDefaultAppChangeEvent_0500
 * @tc.name: Test SendDefaultAppChangeEvent by DefaultAppMgr
 * @tc.desc: 1.SendDefaultAppChangeEvent, type is set to '"com.adobe.pdf', no permission to send event
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SendDefaultAppChangeEvent_0500, Function | SmallTest | Level1)
{
    SubscribeDefaultAppChangedEvent();
    auto ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEvent(USER_ID, {PDF_UTD_ID});
    EXPECT_TRUE(ret);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto waitRet = cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [lockCallback = subscriber_]() {
            return (!lockCallback->utdId.empty() &&
                lockCallback->utdId.at(0) == PDF_UTD_ID &&
                lockCallback->userId == USER_ID);
        });
        EXPECT_FALSE(waitRet);
    }
    UnSubscribeDefaultAppChangedEvent();
}

/**
 * @tc.number: SendDefaultAppChangeEvent_0600
 * @tc.name: Test SendDefaultAppChangeEvent by DefaultAppMgr
 * @tc.desc: 1.SendDefaultAppChangeEvent
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SendDefaultAppChangeEvent_0600, Function | SmallTest | Level1)
{
    auto ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEvent(USER_ID, {BROWSER});
    EXPECT_FALSE(ret);

    ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEvent(USER_ID, {EMAIL});
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SendDefaultAppChangeEvent_0700
 * @tc.name: Test SendDefaultAppChangeEvent by DefaultAppMgr
 * @tc.desc: 1.SendDefaultAppChangeEvent, type is set to 'general.png, WORD', no permission to send event
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SendDefaultAppChangeEvent_0700, Function | SmallTest | Level1)
{
    SubscribeDefaultAppChangedEvent();
    auto ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEvent(USER_ID, {WORD, PNG_UTD_ID});
    EXPECT_TRUE(ret);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto waitRet = cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [lockCallback = subscriber_]() {
            return (!lockCallback->utdId.empty() &&
                (lockCallback->utdId.at(0) == WORD_DOC_UTD_ID ||
                lockCallback->utdId.at(0) == WORD_DOT_UTD_ID ||
                lockCallback->utdId.at(0) == WORD_DOCUMENT_UTD_ID ||
                lockCallback->utdId.at(0) == WORD_TEMPLATE_UTD_ID ||
                lockCallback->utdId.at(0) == PNG_UTD_ID) &&
                lockCallback->userId == USER_ID);
        });
        EXPECT_FALSE(waitRet);
    }
    UnSubscribeDefaultAppChangedEvent();
}

/**
 * @tc.number: SendDefaultAppChangeEvent_0800
 * @tc.name: Test SendDefaultAppChangeEvent by DefaultAppMgr
 * @tc.desc: 1.SendDefaultAppChangeEvent, typeVec is empty, send event failed
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SendDefaultAppChangeEvent_0800, Function | SmallTest | Level1)
{
    SubscribeDefaultAppChangedEvent();
    auto ret = DefaultAppMgr::GetInstance().SendDefaultAppChangeEvent(USER_ID, {});
    EXPECT_FALSE(ret);
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
 * @tc.number: GetTypeFromWant_0700
 * @tc.name: Test GetTypeFromWant by DefaultAppMgr
 * @tc.desc: 1.mailto is an opaque uri, its suffix must not be used to infer the type
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetTypeFromWant_0700, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetUri("mailto:support@xxx.zip");
    auto ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);

    // the mail address is followed by params
    want.SetUri("mailto:support@xxx.zip?subject=test");
    ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetTypeFromWant_0800
 * @tc.name: Test GetTypeFromWant by DefaultAppMgr
 * @tc.desc: 1.the mailto prefix is not over matched, file path is not affected
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetTypeFromWant_0800, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(ACTION_VIEW_DATA);
    want.SetUri("mailto.zip");
    auto ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, ".zip");

    want.SetUri("mailtoxxx.zip");
    ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, ".zip");

    want.SetUri("/data/test/mailto/a.zip");
    ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, ".zip");
}

/**
 * @tc.number: GetTypeFromWant_0900
 * @tc.name: Test GetTypeFromWant by DefaultAppMgr
 * @tc.desc: 1.email want is matched before the mailto uri is filtered out
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetTypeFromWant_0900, Function | SmallTest | Level1)
{
    Want want;
    want.SetAction(EMAIL_ACTION);
    want.SetUri("mailto:support@xxx.zip");
    auto ret = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
    EXPECT_EQ(ret, EMAIL);
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

/**
 * @tc.number: HandleUninstallBundle_0001
 * @tc.name: Test HandleUninstallBundle by DefaultAppMgr
 * @tc.desc: 1.HandleUninstallBundle
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HandleUninstallBundle_0001, Function | SmallTest | Level1)
{
    int32_t userId = 0;
    const std::string bundleName = "testname";
    std::map<std::string, Element> currentInfos;
    DefaultAppMgr::GetInstance().HandleUninstallBundle(userId, bundleName, 0);
    ASSERT_FALSE(DefaultAppMgr::GetInstance().defaultAppDb_->GetDefaultApplicationInfos(userId, currentInfos));
    DefaultAppMgr::GetInstance().HandleUninstallBundle(userId, bundleName, 1);
    ASSERT_FALSE(DefaultAppMgr::GetInstance().defaultAppDb_->GetDefaultApplicationInfos(userId, currentInfos));
}

/**
 * @tc.number: HandleCreateUser_0001
 * @tc.name: Test HandleCreateUser by DefaultAppMgr
 * @tc.desc: 1.HandleCreateUser
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HandleCreateUser_0001, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::map<std::string, Element> infos;
    DefaultAppMgr::GetInstance().HandleCreateUser(userId);
    ASSERT_FALSE(DefaultAppMgr::GetInstance().defaultAppDb_->GetDefaultApplicationInfos(-1, infos));
}

/**
 * @tc.number: GetBundleInfoByUtd_0001
 * @tc.name: Test GetBundleInfoByUtd by DefaultAppMgr
 * @tc.desc: 1.GetBundleInfoByUtd
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetBundleInfoByUtd_0001, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    int32_t userId = 100;
    auto ret = DefaultAppMgr::GetInstance().GetBundleInfoByUtd(userId, EMAIL, bundleInfo, false);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST);
}

/**
 * @tc.number: SetDefaultApplication_0010
 * @tc.name: test SetDefaultApplicationForAppClone
 * @tc.desc: 1.SetDefaultApplicationForAppClone
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationForAppClone_0010, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", "", "", "");
    want.SetElement(elementName);
    int32_t appIndex = 6;
    auto res = impl.SetDefaultApplicationForAppClone(USER_ID, appIndex, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    EXPECT_EQ(res, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

/**
 * @tc.number: SetDefaultApplication_0020
 * @tc.name: test SetDefaultApplicationForAppClone
 * @tc.desc: 1.SetDefaultApplicationForAppClone
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationForAppClone_0020, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", "", "", "");
    want.SetElement(elementName);
    int32_t appIndex = 0;
    auto res = impl.SetDefaultApplicationForAppClone(USER_ID, appIndex, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    EXPECT_EQ(res, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

/**
 * @tc.number: SetDefaultApplication_0030
 * @tc.name: test SetDefaultApplicationForAppClone
 * @tc.desc: 1.SetDefaultApplicationForAppClone
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationForAppClone_0030, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", "", "", "");
    want.SetElement(elementName);
    int32_t appIndex = 1;
    auto res = impl.SetDefaultApplicationForAppClone(USER_ID+20, appIndex, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: SetDefaultApplication_0040
 * @tc.name: test SetDefaultApplicationForAppClone
 * @tc.desc: 1.SetDefaultApplicationForAppClone
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationForAppClone_0040, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    ClearDataMgr();
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, "", MODULE_NAME);
    want.SetElement(elementName);
    int32_t appIndex = 1;
    auto res = impl.SetDefaultApplicationForAppClone(USER_ID, appIndex, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: SetDefaultApplication_0050
 * @tc.name: test SetDefaultApplicationForAppClone
 * @tc.desc: 1.SetDefaultApplicationForAppClone
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationForAppClone_0050, Function | SmallTest | Level1)
{
    auto dataMgr = OHOS::BmsBundleDefaultAppMgrTest::bundleMgrService_->GetDataMgr();
    dataMgr->AddUserId(USER_ID);
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, "", MODULE_NAME);
    want.SetElement(elementName);
    int32_t appIndex = 2;
    auto res = impl.SetDefaultApplicationForAppClone(USER_ID, appIndex, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    EXPECT_EQ(res, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

/**
 * @tc.number: SetDefaultApplication_0060
 * @tc.name: test SetDefaultApplication dataMgr null
 * @tc.desc: non-empty element but DataMgr is nullptr → ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplication_0060, Function | SmallTest | Level1)
{
    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_NAME, ABILITY_NAME, MODULE_NAME);
    want.SetElement(elementName);
    auto res = impl.SetDefaultApplication(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: IsDefaultApplication_0080
 * @tc.name: test IsDefaultApplication
 * @tc.desc: 1.when type > TYPE_MAX_SIZE, isDefaultApp = false;
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsDefaultApplication_0080, Function | SmallTest | Level1)
{
    int32_t userId = ALL_USER_ID;
    std::string type(TYPE_MAX_SIZE + 1, 'a');
    bool isDefaultApp = true;

    auto ret = DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isDefaultApp);
}

/**
 * @tc.number: SetDefaultApplicationForCustom_0010
 * @tc.name: test SetDefaultApplicationForCustom
 * @tc.desc: 1.SetDefaultApplicationForCustom
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationForCustom_0010, Function | SmallTest | Level1)
{
    DefaultAppHostImpl impl;
    AAFwk::Want want;
    ElementName elementName("", "", "", "");
    want.SetElement(elementName);
    auto res = impl.SetDefaultApplicationForCustom(USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, want);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: HandleInstallBundle_1000
 * @tc.name: Test HandleInstallBundle by DefaultAppMgr
 * @tc.desc: 1.HandleInstallBundle with failed GetDefaultApplicationInfos for custom config
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HandleInstallBundle_1000, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    const std::string bundleName = "test.bundle";
    DefaultAppMgr::GetInstance().HandleInstallBundle(userId, bundleName);
    std::map<std::string, Element> currentInfos;
    ASSERT_FALSE(DefaultAppMgr::GetInstance().defaultAppDb_->GetDefaultApplicationInfos(userId, currentInfos));
}

/**
 * @tc.number: HandleUninstallBundle_1000
 * @tc.name: Test HandleUninstallBundle by DefaultAppMgr
 * @tc.desc: 1.HandleUninstallBundle with appIndex not matching
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HandleUninstallBundle_1000, Function | SmallTest | Level1)
{
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(100);
    int32_t userId = 100;
    const std::string bundleName = "test.bundle";
    int32_t appIndex = 0;
    Element currentElement;
    currentElement.bundleName = bundleName;
    currentElement.moduleName = MODULE_NAME;
    currentElement.abilityName = ABILITY_NAME;
    currentElement.appIndex = 1;
    DefaultAppMgr::GetInstance().defaultAppDb_->SetDefaultApplicationInfo(userId, TEST_UTD_ID, currentElement);
    DefaultAppMgr::GetInstance().HandleUninstallBundle(userId, bundleName, appIndex);
    bool res =
        DefaultAppMgr::GetInstance().defaultAppDb_->GetDefaultApplicationInfo(userId, TEST_UTD_ID, currentElement);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: SetDefaultApplicationInternalForCustom_0100
 * @tc.name: test SetDefaultApplicationInternalForCustom db write failed
 * @tc.desc: rdbDataManager is nullptr → SetDefaultApplicationInfo failed → ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationInternalForCustom_0100, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = BUNDLE_NAME;
    auto mockDb = std::make_shared<DefaultAppRdb>();
    ASSERT_NE(mockDb, nullptr);
    mockDb->rdbDataManager_ = nullptr;
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = mockDb;
    ScopeGuard stateGuard([&] { DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb; });
    auto ret = DefaultAppMgr::GetInstance().SetDefaultApplicationInternalForCustom(
        USER_ID, DEFAULT_FILE_TYPE_VIDEO_MP4, element);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetEdcUserId_0001
 * @tc.name: Test GetEdcUserId by DefaultAppMgr
 * @tc.desc: 1.GetEdcUserId
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetEdcUserId_0001, Function | SmallTest | Level1)
{
    int32_t userId = -1;
    int32_t EdcUserId = DefaultAppMgr::GetInstance().GetEdcUserId(userId);
    EXPECT_EQ(EdcUserId, EDC_DEFAULT_USER_ID);

    userId = 0;
    EdcUserId = DefaultAppMgr::GetInstance().GetEdcUserId(userId);
    EXPECT_EQ(EdcUserId, EDC_DEFAULT_USER_ID);

    userId = 1;
    EdcUserId = DefaultAppMgr::GetInstance().GetEdcUserId(userId);
    EXPECT_EQ(EdcUserId, EDC_DEFAULT_USER_ID);

    userId = 2;
    EdcUserId = DefaultAppMgr::GetInstance().GetEdcUserId(userId);
    EXPECT_EQ(EdcUserId, EDC_DEFAULT_USER_ID);

    userId = 100;
    EdcUserId = DefaultAppMgr::GetInstance().GetEdcUserId(userId);
    EXPECT_EQ(EdcUserId, EDC_DEFAULT_USER_ID);
}

/**
 * @tc.number: HasDefaultAppPermission_SwitchOff_0001
 * @tc.name: cloud-push switch off (default) short-circuits to true for BROWSER
 * @tc.desc: invariant I4: when IsPermissionCheckEnabled() is false the permission check is skipped
 *           and BROWSER writes are allowed exactly as before.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HasDefaultAppPermission_SwitchOff_0001, Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    // switch is off by default (no conf file in sandbox) => check skipped => true
    EXPECT_TRUE(DefaultAppMgr::HasDefaultAppPermission(BROWSER_USER_ID, BROWSER, element));
}

/**
 * @tc.number: HasDefaultAppPermission_NonBrowser_0001
 * @tc.name: non-BROWSER types bypass the permission check even when switch is on
 * @tc.desc: invariant I3: only BROWSER is gated; IMAGE / utd / mimeType behave unchanged.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HasDefaultAppPermission_NonBrowser_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    ResetDataMgr();
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    // permission explicitly denied, yet non-BROWSER must still be allowed
    EXPECT_TRUE(DefaultAppMgr::HasDefaultAppPermission(BROWSER_USER_ID, DEFAULT_APP_VIDEO, element));
}

/**
 * @tc.number: HasDefaultAppPermission_DataMgrNull_0001
 * @tc.name: BROWSER with switch on but BundleDataMgr missing is denied (fail-closed)
 * @tc.desc: step 2 of HasDefaultAppPermission: dataMgr == nullptr => return false.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HasDefaultAppPermission_DataMgrNull_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    ScopeGuard guard([&] { ResetBrowserPermissionConfigForTest(); });
    ClearDataMgr();
    Element element;
    element.bundleName = BUNDLE_NAME;
    EXPECT_FALSE(DefaultAppMgr::HasDefaultAppPermission(BROWSER_USER_ID, BROWSER, element));
}

/**
 * @tc.number: HasDefaultAppPermission_NotInstalled_0001
 * @tc.name: BROWSER with switch on but target app not installed is denied (fail-closed)
 * @tc.desc: step 3 of HasDefaultAppPermission: GetCloneBundleInfo fails => return false.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HasDefaultAppPermission_NotInstalled_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    ScopeGuard guard([&] { ResetBrowserPermissionConfigForTest(); });
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    // bundle never registered => GetCloneBundleInfo fails => fail-closed
    EXPECT_FALSE(DefaultAppMgr::HasDefaultAppPermission(BROWSER_USER_ID, BROWSER, element));
}

/**
 * @tc.number: HasDefaultAppPermission_Granted_0001
 * @tc.name: BROWSER with switch on, app installed with valid token, permission granted => true
 * @tc.desc: step 5 happy path: VerifyPermissionByCallingTokenId returns true => allow.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HasDefaultAppPermission_Granted_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(true);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    auto info = MakeGrantedBundle(BUNDLE_NAME, BROWSER_USER_ID);
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START));
    EXPECT_TRUE(dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info));
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS));
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    EXPECT_TRUE(DefaultAppMgr::HasDefaultAppPermission(BROWSER_USER_ID, BROWSER, element));
}

/**
 * @tc.number: HasDefaultAppPermission_Denied_0001
 * @tc.name: BROWSER with switch on, app installed with valid token, permission denied => false
 * @tc.desc: step 5 denied path: VerifyPermissionByCallingTokenId returns false => deny (fail-closed).
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HasDefaultAppPermission_Denied_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    auto info = MakeGrantedBundle(BUNDLE_NAME, BROWSER_USER_ID);
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START));
    EXPECT_TRUE(dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info));
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS));
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    EXPECT_FALSE(DefaultAppMgr::HasDefaultAppPermission(BROWSER_USER_ID, BROWSER, element));
}

/**
 * @tc.number: SetDefaultApplicationInternal_BrowserDenied_0001
 * @tc.name: BROWSER set blocked by missing permission returns the dedicated error code
 * @tc.desc: W1 contract: SetDefaultApplicationInternal maps a denied permission check to
 *           ERR_BUNDLE_MANAGER_DEFAULT_APP_PERMISSION_DENIED (not the generic mismatch code).
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationInternal_BrowserDenied_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    auto ret = DefaultAppMgr::GetInstance().SetDefaultApplicationInternal(BROWSER_USER_ID, BROWSER, element);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEFAULT_APP_PERMISSION_DENIED);
}

/**
 * @tc.number: SetDefaultApplicationInternalForCustom_NotPermissionChecked_0001
 * @tc.name: EDC write (SetDefaultApplicationForCustom) is not gated by the browser permission
 * @tc.desc: W8: the EDC slot (negative userId) deliberately allows pre-configuring apps that are
 *           not yet installed, so it must not be blocked by HasDefaultAppPermission even when the
 *           switch is on and the permission is denied.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationInternalForCustom_NotPermissionChecked_0001,
    Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    // inject a working rdb (mock UpdateData returns true) so the EDC write succeeds
    auto mockDb = std::make_shared<DefaultAppRdb>();
    ASSERT_NE(mockDb, nullptr);
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = mockDb;
    ScopeGuard dbGuard([&] { DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb; });
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    auto ret = DefaultAppMgr::GetInstance().SetDefaultApplicationInternalForCustom(
        BROWSER_USER_ID, BROWSER, element);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HasDefaultAppPermission_InvalidToken_0001
 * @tc.name: BROWSER with switch on, app installed but accessTokenId is 0 is denied (fail-closed)
 * @tc.desc: step 4 of HasDefaultAppPermission: tokenId == 0 => return false. A bundle whose clone
 *           info carries a zero token (e.g. pre-token-assignment phase) must not be allowed.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HasDefaultAppPermission_InvalidToken_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    ScopeGuard guard([&] { ResetBrowserPermissionConfigForTest(); });
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    // register a bundle whose accessTokenId is deliberately left at the default 0
    auto info = MakeGrantedBundle(BUNDLE_NAME, BROWSER_USER_ID);
    info.SetAccessTokenId(0, BROWSER_USER_ID);
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START));
    EXPECT_TRUE(dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info));
    EXPECT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_SUCCESS));
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    EXPECT_FALSE(DefaultAppMgr::HasDefaultAppPermission(BROWSER_USER_ID, BROWSER, element));
}

/**
 * @tc.number: GetDefaultApplicationCandidates_EmptyType_0001
 * @tc.name: empty type is rejected before any query
 * @tc.desc: Normalize("") returns empty => ERR_BUNDLE_MANAGER_INVALID_TYPE, no dataMgr touch.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationCandidates_EmptyType_0001, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfos;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationCandidates(
        BROWSER_USER_ID, "", 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
    EXPECT_TRUE(abilityInfos.empty());
}

/**
 * @tc.number: GetDefaultApplicationCandidates_PermissionDenied_0001
 * @tc.name: caller without GET_BUNDLE_INFO_PRIVILEGED is rejected
 * @tc.desc: VerifyPermission fails => the dedicated permission error, no candidate enumeration.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationCandidates_PermissionDenied_0001,
    Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(false);
    SetIsSelfCalling(false);
    ScopeGuard guard([&] {
        SetVerifyCallingPermissionForTest(true);
        SetIsSelfCalling(true);
    });
    DefaultAppHostImpl hostImpl;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = hostImpl.GetDefaultApplicationCandidates(
        BROWSER_USER_ID, BROWSER, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    EXPECT_TRUE(abilityInfos.empty());
}

/**
 * @tc.number: GetDefaultApplicationCandidates_BrowserGranted_0001
 * @tc.name: installed browser with the DEFAULT_WEB_BROWSER permission is listed as a candidate
 * @tc.desc: switch off (default) => HasDefaultAppPermission short-circuits true, so a registered
 *           browser ability that matches the http want is returned.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationCandidates_BrowserGranted_0001,
    Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    ScopeGuard guard([&] { ResetDataMgr(); });
    std::vector<AbilityInfo> abilityInfos;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationCandidates(
        BROWSER_USER_ID, BROWSER, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    // the single registered browser matches the http want and is returned once
    EXPECT_EQ(abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(abilityInfos.front().bundleName, BUNDLE_NAME);
    EXPECT_EQ(abilityInfos.front().name, ABILITY_NAME);
}

/**
 * @tc.number: GetDefaultApplicationCandidates_BrowserDenied_0001
 * @tc.name: a browser lacking the DEFAULT_WEB_BROWSER permission is filtered out when the switch is on
 * @tc.desc: switch on + VerifyPermissionByCallingTokenId false => HasDefaultAppPermission false => the
 *           registered browser ability is dropped, candidates stay empty though the app is installed.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationCandidates_BrowserDenied_0001,
    Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    ScopeGuard dataGuard([&] { ResetDataMgr(); });
    std::vector<AbilityInfo> abilityInfos;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationCandidates(
        BROWSER_USER_ID, BROWSER, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(abilityInfos.empty());
}

/**
 * @tc.number: GetDefaultApplicationCandidates_NonBrowserRejected_0001
 * @tc.name: non-BROWSER types are rejected before any query
 * @tc.desc: only BROWSER is supported (see the @param note in the d.ts); a VIDEO type must be
 *           rejected with ERR_BUNDLE_MANAGER_INVALID_TYPE without consulting the permission seam.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationCandidates_NonBrowserRejected_0001,
    Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    ScopeGuard dataGuard([&] { ResetDataMgr(); });
    std::vector<AbilityInfo> abilityInfos;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationCandidates(
        BROWSER_USER_ID, DEFAULT_APP_VIDEO, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
    EXPECT_TRUE(abilityInfos.empty());
}

/**
 * @tc.number: GetDefaultApplicationCandidates_EmailType_0001
 * @tc.name: the EMAIL type is rejected
 * @tc.desc: only BROWSER is supported (see the @param note in the d.ts); the EMAIL type must be
 *           rejected up front with ERR_BUNDLE_MANAGER_INVALID_TYPE and must not reach the want query.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationCandidates_EmailType_0001,
    Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    ScopeGuard dataGuard([&] { ResetDataMgr(); });
    std::vector<AbilityInfo> abilityInfos;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationCandidates(
        BROWSER_USER_ID, EMAIL, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
    EXPECT_TRUE(abilityInfos.empty());
}

/**
 * @tc.number: GetDefaultApplicationCandidates_SpecificUtdType_0001
 * @tc.name: a specific utd identifier is rejected
 * @tc.desc: only BROWSER is supported (see the @param note in the d.ts); a specific utd like
 *           general.image must be rejected with ERR_BUNDLE_MANAGER_INVALID_TYPE at the entry check
 *           and must not reach the want query.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationCandidates_SpecificUtdType_0001,
    Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    ScopeGuard dataGuard([&] { ResetDataMgr(); });
    std::vector<AbilityInfo> abilityInfos;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationCandidates(
        BROWSER_USER_ID, IMAGE_UTD_ID, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
    EXPECT_TRUE(abilityInfos.empty());
}

/**
 * @tc.number: ResetDefaultApplicationInternal_BrowserPresetDenied_0001
 * @tc.name: reset falls through to priority-3 deletion when no system preset exists
 * @tc.desc: with the -1 slot empty (no default_app.json loaded in the sandbox), priority 2 finds no
 *           preset and reset falls through to priority 3 DeleteDefaultApplicationInfo => ERR_OK.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, ResetDefaultApplicationInternal_BrowserPresetDenied_0001,
    Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    auto mockDb = std::make_shared<DefaultAppRdb>();
    ASSERT_NE(mockDb, nullptr);
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = mockDb;
    ScopeGuard dbGuard([&] { DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb; });
    auto ret = DefaultAppMgr::GetInstance().ResetDefaultApplicationInternal(BROWSER_USER_ID, BROWSER);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HostImpl_GetCandidates_InvalidUserId_0001
 * @tc.name: host rejects an unknown userId before delegating to the manager
 * @tc.desc: the entry layer checks HasUserId so an unregistered user yields
 *           ERR_BUNDLE_MANAGER_INVALID_USER_ID without touching the candidate enumeration.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HostImpl_GetCandidates_InvalidUserId_0001, Function | SmallTest | Level1)
{
    ResetDataMgr();
    ScopeGuard guard([&] { ResetDataMgr(); });
    DefaultAppHostImpl hostImpl;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = hostImpl.GetDefaultApplicationCandidates(BROWSER_USER_ID, BROWSER, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    EXPECT_TRUE(abilityInfos.empty());
}

/**
 * @tc.number: HostImpl_GetCandidates_DataMgrNull_0001
 * @tc.name: host aborts with an internal error when the data manager is missing
 * @tc.desc: a null dataMgr is caught at the host entry, returning ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 *           and never reaching the manager's candidate enumeration.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HostImpl_GetCandidates_DataMgrNull_0001, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    ClearDataMgr();
    ScopeGuard guard([&] { ResetDataMgr(); });
    DefaultAppHostImpl hostImpl;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = hostImpl.GetDefaultApplicationCandidates(BROWSER_USER_ID, BROWSER, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    EXPECT_TRUE(abilityInfos.empty());
}

/**
 * @tc.number: HostImpl_GetCandidates_Delegates_0001
 * @tc.name: host delegates a valid request to the manager and returns its candidates
 * @tc.desc: with a registered user and an installed browser, the host's cross-user permission
 *           short-circuits (native token) and the call resolves to the manager's happy path.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HostImpl_GetCandidates_Delegates_0001, Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    ScopeGuard guard([&] { ResetDataMgr(); });
    DefaultAppHostImpl hostImpl;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = hostImpl.GetDefaultApplicationCandidates(BROWSER_USER_ID, BROWSER, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(abilityInfos.front().bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: IsElementValid_DataMgrNull_0001
 * @tc.name: IsElementValid returns MISMATCH when BundleDataMgr is missing
 * @tc.desc: default_app_mgr.cpp IsElementValid: after VerifyElementFormat passes, GetDataMgr() returns
 *           nullptr => ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH (the step-2 dataMgr==null arm).
 *           Use a non-BROWSER type so the earlier HasDefaultAppPermission short-circuit does not
 *           pre-empt this entry point.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsElementValid_DataMgrNull_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    ScopeGuard guard([&] { ResetBrowserPermissionConfigForTest(); });
    ClearDataMgr();
    ScopeGuard dataGuard([&] { ResetDataMgr(); });
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    EXPECT_EQ(ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH,
        DefaultAppMgr::GetInstance().IsElementValid(BROWSER_USER_ID, DEFAULT_APP_VIDEO, element));
}

/**
 * @tc.number: IsElementValid_BrowserDenied_0001
 * @tc.name: IsElementValid returns PERMISSION_DENIED when the browser lacks DEFAULT_WEB_BROWSER permission
 * @tc.desc: default_app_mgr.cpp IsElementValid step5: VerifyElementFormat(ok) -> GetDataMgr(ok) ->
 *           QueryInfoAndSkillByElement(ok, bundle installed with matching element) -> IsMatch(ok,
 *           browser skill matches http want) -> HasDefaultAppPermission fails (switch on, token
 *           permission denied) => ERR_BUNDLE_MANAGER_DEFAULT_APP_PERMISSION_DENIED. Covers the step5
 *           denial arm and proves step3/step4 pass.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsElementValid_BrowserDenied_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    ScopeGuard dataGuard([&] { ResetDataMgr(); });
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    EXPECT_EQ(ERR_BUNDLE_MANAGER_DEFAULT_APP_PERMISSION_DENIED,
        DefaultAppMgr::GetInstance().IsElementValid(BROWSER_USER_ID, BROWSER, element));
}

/**
 * @tc.number: IsElementValid_BrowserGranted_0001
 * @tc.name: IsElementValid returns ERR_OK on the fully valid browser path
 * @tc.desc: default_app_mgr.cpp IsElementValid happy path: switch off =>
 *           HasDefaultAppPermission short-circuits true, so all of step2..step5 pass and the element is
 *           reported valid (ERR_OK). This is the positive counterpart of IsElementValid_BrowserDenied_0001.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, IsElementValid_BrowserGranted_0001, Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    ScopeGuard dataGuard([&] { ResetDataMgr(); });
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    EXPECT_EQ(ERR_OK,
        DefaultAppMgr::GetInstance().IsElementValid(BROWSER_USER_ID, BROWSER, element));
}

/**
 * @tc.number: CollectBrowserCandidates_Dedup_0001
 * @tc.name: CollectBrowserCandidates reports each distinct browser once
 * @tc.desc: default_app_mgr.cpp CollectBrowserCandidates: a single http want is built for BROWSER, and
 *           each registered browser ability matching it is reported once => size==2.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, CollectBrowserCandidates_Dedup_0001, Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME + "2", BROWSER_USER_ID);
    ScopeGuard dataGuard([&] { ResetDataMgr(); });
    std::vector<AbilityInfo> abilityInfos;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationCandidates(
        BROWSER_USER_ID, BROWSER, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    // two distinct browsers, each matched by the http want and reported once
    EXPECT_EQ(abilityInfos.size(), static_cast<size_t>(2));
}

/**
 * @tc.number: GetDefaultApplicationCandidates_AllReturned_0001
 * @tc.name: candidate list returns all matched browsers without a size limit
 * @tc.desc: default_app_mgr.cpp GetDefaultApplicationCandidates: installing 1001 distinct browsers
 *           yields 1001 candidates (after dedup) and all of them are returned, with no truncation.
 *           Each bundle has a unique bundleName so dedup keys differ.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, GetDefaultApplicationCandidates_AllReturned_0001,
    Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    for (int32_t i = 0; i <= 1000; ++i) { // 1001 browsers
        InstallGrantedBrowser(dataMgr, "com.test.browser" + std::to_string(i), BROWSER_USER_ID);
    }
    ScopeGuard dataGuard([&] { ResetDataMgr(); });
    std::vector<AbilityInfo> abilityInfos;
    auto ret = DefaultAppMgr::GetInstance().GetDefaultApplicationCandidates(
        BROWSER_USER_ID, BROWSER, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(abilityInfos.size(), static_cast<size_t>(1001));
}

/**
 * @tc.number: SetDefaultApplicationInternal_BrowserGranted_0001
 * @tc.name: SetDefaultApplicationInternal succeeds for a granted browser and writes the db
 * @tc.desc: default_app_mgr.cpp SetDefaultApplicationInternal line 340-341: switch off =>
 *           HasDefaultAppPermission short-circuits true, IsElementValid passes (bundle installed with
 *           matching browser skill), SetDefaultApplicationInfo returns true => ERR_OK.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationInternal_BrowserGranted_0001,
    Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    auto mockDb = std::make_shared<DefaultAppRdb>();
    ASSERT_NE(mockDb, nullptr);
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = mockDb;
    ScopeGuard guard([&] {
        DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb;
        ResetDataMgr();
    });
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    auto ret = DefaultAppMgr::GetInstance().SetDefaultApplicationInternal(BROWSER_USER_ID, BROWSER, element);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SetDefaultApplicationInternal_DeleteFailed_0001
 * @tc.name: SetDefaultApplicationInternal maps a failed db delete to ABILITY_AND_TYPE_MISMATCH
 * @tc.desc: default_app_mgr.cpp SetDefaultApplicationInternal line 319-322: an empty element takes the
 *           clear branch (IsElementEmpty true), and DeleteDefaultApplicationInfo returning false =>
 *           ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH. FakeDefaultAppDb.deleteInfoRet=false forces it.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationInternal_DeleteFailed_0001,
    Function | SmallTest | Level1)
{
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    fakeDb->deleteInfoRet = false;
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard guard([&] { DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb; });
    Element element; // empty => IsElementEmpty true => clear branch
    auto ret = DefaultAppMgr::GetInstance().SetDefaultApplicationInternal(BROWSER_USER_ID, BROWSER, element);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH);
}

/**
 * @tc.number: SetDefaultApplicationInternal_SetInfoFailed_0001
 * @tc.name: SetDefaultApplicationInternal maps a failed db set to ABILITY_AND_TYPE_MISMATCH
 * @tc.desc: default_app_mgr.cpp SetDefaultApplicationInternal line 335-339: switch off => permission
 *           short-circuits true, IsElementValid passes (installed matching browser), but
 *           SetDefaultApplicationInfo returns false => ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH.
 *           FakeDefaultAppDb.setInfoRet=false forces the failure arm.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, SetDefaultApplicationInternal_SetInfoFailed_0001,
    Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    fakeDb->setInfoRet = false;
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard guard([&] {
        DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb;
        ResetDataMgr();
    });
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.abilityName = ABILITY_NAME;
    element.moduleName = MODULE_NAME;
    auto ret = DefaultAppMgr::GetInstance().SetDefaultApplicationInternal(BROWSER_USER_ID, BROWSER, element);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH);
}

/**
 * @tc.number: ResetDefaultApplicationInternal_EdcFallback_0001
 * @tc.name: reset promotes a valid EDC preset element to the user slot (priority 1)
 * @tc.desc: default_app_mgr.cpp ResetDefaultApplicationInternal line 399-409: an EDC slot
 *           (GetEdcUserId=-100) holds a valid BROWSER element, IsElementValid passes, and
 *           SetDefaultApplicationInfo succeeds => ERR_OK with the EDC element copied to the user slot.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, ResetDefaultApplicationInternal_EdcFallback_0001,
    Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    Element preset;
    preset.bundleName = BUNDLE_NAME;
    preset.abilityName = ABILITY_NAME;
    preset.moduleName = MODULE_NAME;
    fakeDb->Put(DefaultAppMgr::GetInstance().GetEdcUserId(BROWSER_USER_ID), BROWSER, preset);
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard guard([&] {
        DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb;
        ResetDataMgr();
    });
    auto ret = DefaultAppMgr::GetInstance().ResetDefaultApplicationInternal(BROWSER_USER_ID, BROWSER);
    EXPECT_EQ(ret, ERR_OK);
    Element got;
    EXPECT_TRUE(fakeDb->GetDefaultApplicationInfo(BROWSER_USER_ID, BROWSER, got));
    EXPECT_EQ(got.bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: ResetDefaultApplicationInternal_PresetFallback_0001
 * @tc.name: reset falls back to a valid system preset element when no EDC config exists (priority 2)
 * @tc.desc: default_app_mgr.cpp ResetDefaultApplicationInternal line 413-428: EDC slot empty (priority 1
 *           skipped), the INITIAL_USER_ID=-1 slot holds a valid BROWSER element, HasDefaultAppPermission
 *           passes (switch off), IsElementValid passes, SetDefaultApplicationInfo succeeds => ERR_OK.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, ResetDefaultApplicationInternal_PresetFallback_0001,
    Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    Element preset;
    preset.bundleName = BUNDLE_NAME;
    preset.abilityName = ABILITY_NAME;
    preset.moduleName = MODULE_NAME;
    fakeDb->Put(-1, BROWSER, preset); // INITIAL_USER_ID = -1 system preset slot
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard guard([&] {
        DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb;
        ResetDataMgr();
    });
    auto ret = DefaultAppMgr::GetInstance().ResetDefaultApplicationInternal(BROWSER_USER_ID, BROWSER);
    EXPECT_EQ(ret, ERR_OK);
    Element got;
    EXPECT_TRUE(fakeDb->GetDefaultApplicationInfo(BROWSER_USER_ID, BROWSER, got));
    EXPECT_EQ(got.bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: ResetDefaultApplicationInternal_PresetExempted_0001
 * @tc.name: reset promotes a preset browser that hits the system-preset exemption to the user slot
 * @tc.desc: default_app_mgr.cpp ResetDefaultApplicationInternal line 408-421: the INITIAL_USER_ID=-1 slot
 *           holds a BROWSER element equal to the system preset, so HasDefaultAppPermission is bypassed by
 *           the IsPresetDefaultApp exemption even with the switch on and the token denied; IsElementValid
 *           passes (bundle installed), SetDefaultApplicationInfo succeeds => ERR_OK with the preset promoted
 *           to the user slot.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, ResetDefaultApplicationInternal_PresetExempted_0001,
    Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    Element preset;
    preset.bundleName = BUNDLE_NAME;
    preset.abilityName = ABILITY_NAME;
    preset.moduleName = MODULE_NAME;
    fakeDb->Put(-1, BROWSER, preset); // preset registered in the -1 slot => exemption applies
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard dbGuard([&] {
        DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb;
        ResetDataMgr();
    });
    auto ret = DefaultAppMgr::GetInstance().ResetDefaultApplicationInternal(BROWSER_USER_ID, BROWSER);
    EXPECT_EQ(ret, ERR_OK);
    Element got;
    EXPECT_TRUE(fakeDb->GetDefaultApplicationInfo(BROWSER_USER_ID, BROWSER, got));
    EXPECT_EQ(got.bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: HandleCreateUser_PresetExempted_0001
 * @tc.name: HandleCreateUser inherits the system preset browser unconditionally for the new user
 * @tc.desc: default_app_mgr.cpp HandleCreateUser line 525-530: a BROWSER element exists in the
 *           INITIAL_USER_ID=-1 slot and is copied verbatim into the new user slot regardless of the
 *           permission switch/token, so the new user slot holds BROWSER afterwards.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HandleCreateUser_PresetExempted_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    Element preset;
    preset.bundleName = BUNDLE_NAME;
    preset.abilityName = ABILITY_NAME;
    preset.moduleName = MODULE_NAME;
    fakeDb->Put(-1, BROWSER, preset);
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard dbGuard([&] { DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb; });
    DefaultAppMgr::GetInstance().HandleCreateUser(BROWSER_USER_ID);
    Element got;
    EXPECT_TRUE(fakeDb->GetDefaultApplicationInfo(BROWSER_USER_ID, BROWSER, got));
    EXPECT_EQ(got.bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: HandleCreateUser_PresetGranted_0001
 * @tc.name: HandleCreateUser retains a preset browser that passes the permission check for the new user
 * @tc.desc: default_app_mgr.cpp HandleCreateUser line 541-543: a preset BROWSER element exists in the
 *           INITIAL_USER_ID=-1 slot and HasDefaultAppPermission passes (switch off => short-circuit
 *           true; bundle installed so even the step3..5 path passes) => preserved into the new user slot.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HandleCreateUser_PresetGranted_0001, Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    Element preset;
    preset.bundleName = BUNDLE_NAME;
    preset.abilityName = ABILITY_NAME;
    preset.moduleName = MODULE_NAME;
    fakeDb->Put(-1, BROWSER, preset);
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard guard([&] {
        DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb;
        ResetDataMgr();
    });
    DefaultAppMgr::GetInstance().HandleCreateUser(BROWSER_USER_ID);
    Element got;
    EXPECT_TRUE(fakeDb->GetDefaultApplicationInfo(BROWSER_USER_ID, BROWSER, got));
    EXPECT_EQ(got.bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: HandleUninstallBundle_PresetFallback_0001
 * @tc.name: HandleUninstallBundle falls back to a valid system preset when the uninstalled app is default
 * @tc.desc: default_app_mgr.cpp HandleUninstallBundle line 463-466: the user slot holds a BROWSER element
 *           pointing at the bundle being uninstalled; no EDC fallback exists; the INITIAL_USER_ID=-1
 *           slot holds a valid preset that passes IsElementValid => the preset element replaces the
 *           uninstalled one in the user slot (not erased).
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HandleUninstallBundle_PresetFallback_0001,
    Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    Element userElement;
    userElement.bundleName = BUNDLE_NAME; // the bundle being uninstalled
    userElement.abilityName = ABILITY_NAME;
    userElement.moduleName = MODULE_NAME;
    fakeDb->Put(BROWSER_USER_ID, BROWSER, userElement);
    Element preset;
    preset.bundleName = BUNDLE_NAME;
    preset.abilityName = ABILITY_NAME;
    preset.moduleName = MODULE_NAME;
    fakeDb->Put(-1, BROWSER, preset); // system preset fallback
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard guard([&] {
        DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb;
        ResetDataMgr();
    });
    DefaultAppMgr::GetInstance().HandleUninstallBundle(BROWSER_USER_ID, BUNDLE_NAME, 0);
    Element got;
    EXPECT_TRUE(fakeDb->GetDefaultApplicationInfo(BROWSER_USER_ID, BROWSER, got));
    EXPECT_EQ(got.bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: HandleUninstallBundle_EdcFallback_0001
 * @tc.name: HandleUninstallBundle falls back to the EDC preset when the uninstalled app is default
 * @tc.desc: default_app_mgr.cpp HandleUninstallBundle line 459-462: the user slot holds a BROWSER element
 *           pointing at the bundle being uninstalled; the EDC slot (GetEdcUserId=-100) holds a valid
 *           element that passes IsElementValid => the EDC element replaces the uninstalled one.
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HandleUninstallBundle_EdcFallback_0001,
    Function | SmallTest | Level1)
{
    ResetBrowserPermissionConfigForTest();
    ResetDataMgr();
    auto dataMgr = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(BROWSER_USER_ID);
    InstallGrantedBrowser(dataMgr, BUNDLE_NAME, BROWSER_USER_ID);
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    Element userElement;
    userElement.bundleName = BUNDLE_NAME; // the bundle being uninstalled
    userElement.abilityName = ABILITY_NAME;
    userElement.moduleName = MODULE_NAME;
    fakeDb->Put(BROWSER_USER_ID, BROWSER, userElement);
    Element edcElement;
    edcElement.bundleName = BUNDLE_NAME;
    edcElement.abilityName = ABILITY_NAME;
    edcElement.moduleName = MODULE_NAME;
    fakeDb->Put(DefaultAppMgr::GetInstance().GetEdcUserId(BROWSER_USER_ID), BROWSER, edcElement);
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard guard([&] {
        DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb;
        ResetDataMgr();
    });
    DefaultAppMgr::GetInstance().HandleUninstallBundle(BROWSER_USER_ID, BUNDLE_NAME, 0);
    Element got;
    EXPECT_TRUE(fakeDb->GetDefaultApplicationInfo(BROWSER_USER_ID, BROWSER, got));
    EXPECT_EQ(got.bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: HandleUninstallBundle_PresetExempted_0001
 * @tc.name: HandleUninstallBundle falls back to the system preset unconditionally when the uninstalled app is default
 * @tc.desc: default_app_mgr.cpp HandleUninstallBundle line 457-459: the user slot holds a BROWSER element
 *           pointing at the uninstalled bundle; the INITIAL preset exists, so it replaces the uninstalled
 *           element in the user slot regardless of the permission switch/token (not erased).
 */
HWTEST_F(BmsBundleDefaultAppMgrTest, HandleUninstallBundle_PresetExempted_0001, Function | SmallTest | Level1)
{
    SetBrowserPermissionCheckEnabledForTest(true);
    SetVerifyPermissionByCallingTokenIdForTest(false);
    ScopeGuard guard([&] {
        SetVerifyPermissionByCallingTokenIdForTest(true);
        ResetBrowserPermissionConfigForTest();
    });
    auto fakeDb = std::make_shared<FakeDefaultAppDb>();
    ASSERT_NE(fakeDb, nullptr);
    Element userElement;
    userElement.bundleName = BUNDLE_NAME; // the bundle being uninstalled
    userElement.abilityName = ABILITY_NAME;
    userElement.moduleName = MODULE_NAME;
    fakeDb->Put(BROWSER_USER_ID, BROWSER, userElement);
    Element preset;
    preset.bundleName = BUNDLE_NAME;
    preset.abilityName = ABILITY_NAME;
    preset.moduleName = MODULE_NAME;
    fakeDb->Put(-1, BROWSER, preset); // preset exists => unconditional fallback
    auto savedDb = DefaultAppMgr::GetInstance().defaultAppDb_;
    DefaultAppMgr::GetInstance().defaultAppDb_ = fakeDb;
    ScopeGuard dbGuard([&] { DefaultAppMgr::GetInstance().defaultAppDb_ = savedDb; });
    DefaultAppMgr::GetInstance().HandleUninstallBundle(BROWSER_USER_ID, BUNDLE_NAME, 0);
    Element got;
    EXPECT_TRUE(fakeDb->GetDefaultApplicationInfo(BROWSER_USER_ID, BROWSER, got));
    EXPECT_EQ(got.bundleName, BUNDLE_NAME);
}
} // namespace OHOS
