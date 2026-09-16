/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <list>
#include <string>
#include <vector>

#include "bundle_errors.h"
#include "bundle_mgr_proxy.h"
#include "bundle_skill/skill_manager_interface.h"
#include "if_system_ability_manager.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "skill_manager_helper.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
// knobs shared with the SystemAbilityManagerClient link mock below
bool g_samgrValid = true;
sptr<IRemoteObject> g_mockBundleMgrSa;
sptr<IRemoteBroker> g_mockBundleMgr;
sptr<IBundleSkillManager> g_mockSkillManager;
sptr<IRemoteObject::DeathRecipient> g_lastDeathRecipient;

// Receives only direct virtual calls from the helper. It must never be flattened
// into a MessageParcel: a bare IRemoteObject loses identity across
// WriteRemoteObject/ReadRemoteObject (BINDER_TYPE_HANDLE is re-minted through
// FindOrNewObject and the flatten path reads IPCObjectProxy members off it), so
// the proxy below hands out a broker directly instead.
class MockSkillManagerRemote : public IRemoteObject {
public:
    MockSkillManagerRemote() : IRemoteObject(u"ohos.bundleManager.SkillManager") {}
    ~MockSkillManagerRemote() override = default;
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return NO_ERROR;
    }
    sptr<IRemoteBroker> AsInterface() override { return nullptr; }
    int32_t GetObjectRefCount() override { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        ++addDeathRecipientCount_;
        g_lastDeathRecipient = recipient;
        return addDeathRecipientOk_;
    }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }
    bool IsProxyObject() const override { return isProxyObject_; }

    // test knobs
    bool addDeathRecipientOk_ = true;
    bool isProxyObject_ = true;
    int addDeathRecipientCount_ = 0;
};

// Returned by MockBundleMgrProxy::GetSkillManagerProxy, i.e. it also never goes
// through BundleMgrProxy's parcel round-trip.
class MockSkillManager : public IBundleSkillManager {
public:
    MockSkillManager() = default;
    ~MockSkillManager() override = default;

    sptr<IRemoteObject> AsObject() override
    {
        return asObjectNull_ ? nullptr : inner_;
    }

    ErrCode GetSkillInfoForSelf(const std::string &moduleName, const std::string &skillName,
        uint32_t flags, SkillInfo &skillInfo) override
    {
        return FillSkillInfo(skillInfo);
    }

    ErrCode GetSkillInfosForSelf(uint32_t flags, std::vector<SkillInfo> &skillInfos) override
    {
        return FillSkillInfos(skillInfos);
    }

    ErrCode GetSkillInfo(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, uint32_t flags, int32_t userId, SkillInfo &skillInfo) override
    {
        return FillSkillInfo(skillInfo);
    }

    ErrCode GetSkillInfos(const std::string &bundleName, uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos) override
    {
        return FillSkillInfos(skillInfos);
    }

    ErrCode GetAllSkillInfos(uint32_t flags, int32_t userId, std::vector<SkillInfo> &skillInfos) override
    {
        return FillSkillInfos(skillInfos);
    }

    ErrCode FillSkillInfo(SkillInfo &skillInfo)
    {
        if (innerErrCode_ != ERR_OK) {
            return innerErrCode_;
        }
        skillInfo.bundleName = "com.example.skill";
        skillInfo.skillName = "testSkill";
        return ERR_OK;
    }

    ErrCode FillSkillInfos(std::vector<SkillInfo> &skillInfos)
    {
        if (innerErrCode_ != ERR_OK) {
            return innerErrCode_;
        }
        SkillInfo skillInfo;
        skillInfo.bundleName = "com.example.skill";
        skillInfos.push_back(skillInfo);
        return ERR_OK;
    }

    // test knobs
    sptr<MockSkillManagerRemote> inner_;
    bool asObjectNull_ = false;
    ErrCode innerErrCode_ = ERR_OK;
};

// Overrides the only two seams the helper uses on IBundleMgr, so the production
// BundleMgrProxy parcel path (SendTransactCmd/ReadRemoteObject/iface_cast) is
// bypassed deterministically.
class MockBundleMgrProxy : public BundleMgrProxy {
public:
    explicit MockBundleMgrProxy(const sptr<IRemoteObject> &impl) : BundleMgrProxy(impl) {}
    ~MockBundleMgrProxy() override = default;

    sptr<IBundleSkillManager> GetSkillManagerProxy() override
    {
        ++getSkillManagerProxyCount_;
        return returnNullSkillManager_ ? nullptr : g_mockSkillManager;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return asObjectNull_ ? nullptr : BundleMgrProxy::AsObject();
    }

    // test knobs
    bool returnNullSkillManager_ = false;
    bool asObjectNull_ = false;
    int getSkillManagerProxyCount_ = 0;
};

// The object the samgr mock hands to iface_cast<IBundleMgr>. It is resolved
// through BrokerRegistration::NewInstance's local branch (descriptor match +
// AsInterface), so it must never be flattened into a parcel either.
class MockBundleMgrSa : public IRemoteObject {
public:
    MockBundleMgrSa() : IRemoteObject(u"ohos.appexecfwk.BundleMgr") {}
    ~MockBundleMgrSa() override = default;
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return NO_ERROR;
    }
    sptr<IRemoteBroker> AsInterface() override
    {
        return asInterfaceNull_ ? nullptr : g_mockBundleMgr;
    }
    int32_t GetObjectRefCount() override { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }
    bool IsProxyObject() const override { return false; }

    // test knobs
    bool asInterfaceNull_ = false;
};

class MockSystemAbilityManager : public ISystemAbilityManager {
public:
    ~MockSystemAbilityManager() override = default;
    sptr<IRemoteObject> AsObject() override { return nullptr; }
    std::vector<std::u16string> ListSystemAbilities(unsigned int dumpFlags) override
    {
        return {};
    }
    sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId) override
    {
        return g_mockBundleMgrSa;
    }
    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId) override { return nullptr; }
    int32_t RemoveSystemAbility(int32_t systemAbilityId) override { return 0; }
    int32_t SubscribeSystemAbility(int32_t systemAbilityId,
        const sptr<ISystemAbilityStatusChange> &listener) override
    {
        return 0;
    }
    int32_t UnSubscribeSystemAbility(int32_t systemAbilityId,
        const sptr<ISystemAbilityStatusChange> &listener) override
    {
        return 0;
    }
    sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override
    {
        return nullptr;
    }
    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override
    {
        return nullptr;
    }
    int32_t AddOnDemandSystemAbilityInfo(int32_t systemAbilityId,
        const std::u16string &localAbilityManagerName) override
    {
        return 0;
    }
    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, bool &isExist) override
    {
        return nullptr;
    }
    int32_t AddSystemAbility(int32_t systemAbilityId, const sptr<IRemoteObject> &ability,
        const SAExtraProp &extraProp) override
    {
        return 0;
    }
    int32_t AddSystemProcess(const std::u16string &procName, const sptr<IRemoteObject> &procObject) override
    {
        return 0;
    }
    sptr<IRemoteObject> LoadSystemAbility(int32_t systemAbilityId, int32_t timeout) override
    {
        return nullptr;
    }
    int32_t LoadSystemAbility(int32_t systemAbilityId,
        const sptr<ISystemAbilityLoadCallback> &callback) override
    {
        return 0;
    }
    int32_t LoadSystemAbility(int32_t systemAbilityId, const std::string &deviceId,
        const sptr<ISystemAbilityLoadCallback> &callback) override
    {
        return 0;
    }
    int32_t UnloadSystemAbility(int32_t systemAbilityId) override { return 0; }
    int32_t CancelUnloadSystemAbility(int32_t systemAbilityId) override { return 0; }
    int32_t UnloadAllIdleSystemAbility() override { return 0; }
    int32_t GetSystemProcessInfo(int32_t systemAbilityId, SystemProcessInfo &systemProcessInfo) override
    {
        return 0;
    }
    int32_t GetRunningSystemProcess(std::list<SystemProcessInfo> &systemProcessInfos) override { return 0; }
    int32_t SubscribeSystemProcess(const sptr<ISystemProcessStatusChange> &listener) override { return 0; }
    int32_t SendStrategy(int32_t type, std::vector<int32_t> &systemAbilityIds, int32_t level,
        std::string &action) override
    {
        return 0;
    }
    int32_t UnSubscribeSystemProcess(const sptr<ISystemProcessStatusChange> &listener) override { return 0; }
    int32_t GetExtensionSaIds(const std::string &extension, std::vector<int32_t> &saIds) override
    {
        return 0;
    }
    int32_t GetExtensionRunningSaList(const std::string &extension,
        std::vector<sptr<IRemoteObject>> &saList) override
    {
        return 0;
    }
    int32_t GetRunningSaExtensionInfoList(const std::string &extension,
        std::vector<SaExtensionInfo> &infoList) override
    {
        return 0;
    }
    int32_t GetCommonEventExtraDataIdlist(int32_t saId, std::vector<int64_t> &extraDataIdList,
        const std::string &eventName) override
    {
        return 0;
    }
    int32_t GetOnDemandReasonExtraData(int64_t extraDataId, MessageParcel &extraDataParcel) override
    {
        return 0;
    }
    int32_t GetOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType type,
        std::vector<SystemAbilityOnDemandEvent> &abilityOnDemandEvents) override
    {
        return 0;
    }
    int32_t UpdateOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType type,
        const std::vector<SystemAbilityOnDemandEvent> &abilityOnDemandEvents) override
    {
        return 0;
    }
    int32_t GetOnDemandSystemAbilityIds(std::vector<int32_t> &systemAbilityIds) override { return 0; }
};
} // namespace

namespace OHOS {
// link-time mock of SystemAbilityManagerClient (same pattern as mock_iservice_registry.cpp,
// but returning a controllable mock manager instead of nullptr)
SystemAbilityManagerClient &SystemAbilityManagerClient::GetInstance()
{
    static auto instance = new SystemAbilityManagerClient();
    return *instance;
}

sptr<ISystemAbilityManager> SystemAbilityManagerClient::GetSystemAbilityManager()
{
    if (!g_samgrValid) {
        return nullptr;
    }
    static sptr<MockSystemAbilityManager> manager = new MockSystemAbilityManager();
    return manager;
}

void SystemAbilityManagerClient::DestroySystemAbilityManagerObject() {}
} // namespace OHOS

class BmsSkillManagerHelperTest : public testing::Test {
public:
    void SetUp() override
    {
        if (g_lastDeathRecipient == nullptr) {
            // cold process: the helper's static deathRecipient_ is only reachable through a
            // successful proxy-flavored fetch; do one, then clear the cache it leaves behind
            CreateMocks();
            EXPECT_NE(SkillManagerHelper::GetSkillManager(), nullptr);
            ASSERT_NE(g_lastDeathRecipient, nullptr);
            g_lastDeathRecipient->OnRemoteDied(wptr<IRemoteObject>(bundleMgrSa_));
            CreateMocks(); // drop the call counts consumed by the priming fetch
            return;
        }
        // deterministic reset for any execution order (also --gtest_filter/shuffle):
        // OnRemoteDied clears skillManager_ regardless of the remote argument
        CreateMocks();
        g_lastDeathRecipient->OnRemoteDied(wptr<IRemoteObject>(bundleMgrSa_));
    }

    void TearDown() override {}

protected:
    void CreateMocks()
    {
        g_samgrValid = true;
        skillManagerRemote_ = new MockSkillManagerRemote();
        skillManagerMock_ = new MockSkillManager();
        skillManagerMock_->inner_ = skillManagerRemote_;
        bundleMgrSa_ = new MockBundleMgrSa();
        bundleMgrMock_ = new MockBundleMgrProxy(bundleMgrSa_);
        g_mockBundleMgrSa = bundleMgrSa_;
        g_mockBundleMgr = bundleMgrMock_;
        g_mockSkillManager = skillManagerMock_;
    }

    sptr<MockSkillManagerRemote> skillManagerRemote_;
    sptr<MockSkillManager> skillManagerMock_;
    sptr<MockBundleMgrSa> bundleMgrSa_;
    sptr<MockBundleMgrProxy> bundleMgrMock_;
};

/**
 * @tc.number: GetSkillManager_0100
 * @tc.name: Test GetSkillManager when system ability manager is null
 * @tc.desc: 1.system ability manager is null, GetSkillManager returns nullptr
 */
HWTEST_F(BmsSkillManagerHelperTest, GetSkillManager_0100, Function | SmallTest | Level1)
{
    g_samgrValid = false;
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_EQ(skillManager, nullptr);
    auto skillManagerAgain = SkillManagerHelper::GetSkillManager();
    EXPECT_EQ(skillManagerAgain, nullptr);
    // no proxy is attempted when the manager itself is unavailable
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 0);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 0);
}

/**
 * @tc.number: GetSkillManager_0200
 * @tc.name: Test GetSkillManager when bundle manager sa is null
 * @tc.desc: 1.GetSystemAbility returns null, GetSkillManager returns nullptr
 */
HWTEST_F(BmsSkillManagerHelperTest, GetSkillManager_0200, Function | SmallTest | Level1)
{
    g_mockBundleMgrSa = nullptr;
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_EQ(skillManager, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 0);

    // sa-null failure is not cached: restoring the sa makes the next call succeed
    g_mockBundleMgrSa = bundleMgrSa_;
    auto skillManagerRetry = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManagerRetry, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 1);
}

/**
 * @tc.number: GetSkillManager_0300
 * @tc.name: Test GetSkillManager when GetSkillManagerProxy returns null
 * @tc.desc: 1.GetSkillManagerProxy returns null, GetSkillManager returns nullptr and
 *           nothing stale is cached
 */
HWTEST_F(BmsSkillManagerHelperTest, GetSkillManager_0300, Function | SmallTest | Level1)
{
    bundleMgrMock_->returnNullSkillManager_ = true;
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_EQ(skillManager, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 1);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 0);

    // failure is not cached: next call refetches the proxy and succeeds
    bundleMgrMock_->returnNullSkillManager_ = false;
    auto skillManagerRetry = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManagerRetry, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 2);
}

/**
 * @tc.number: GetSkillManager_0400
 * @tc.name: Test GetSkillManager when the skill manager proxy has no remote object
 * @tc.desc: 1.skillManager->AsObject() is null, GetSkillManager returns nullptr
 */
HWTEST_F(BmsSkillManagerHelperTest, GetSkillManager_0400, Function | SmallTest | Level1)
{
    skillManagerMock_->asObjectNull_ = true;
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_EQ(skillManager, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 1);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 0);

    // failure is not cached: next call refetches the proxy and succeeds
    skillManagerMock_->asObjectNull_ = false;
    auto skillManagerRetry = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManagerRetry, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 2);
}

/**
 * @tc.number: GetSkillManager_0500
 * @tc.name: Test GetSkillManager when AddDeathRecipient fails
 * @tc.desc: 1.AddDeathRecipient fails, GetSkillManager returns nullptr without caching,
 *           next call retries and succeeds once the recipient can be added
 */
HWTEST_F(BmsSkillManagerHelperTest, GetSkillManager_0500, Function | SmallTest | Level1)
{
    skillManagerRemote_->addDeathRecipientOk_ = false;
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_EQ(skillManager, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 1);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 1);

    // proxy obtained but death registration failed: not cached, retry refetches it
    skillManagerRemote_->addDeathRecipientOk_ = true;
    auto skillManagerRetry = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManagerRetry, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 2);
}

/**
 * @tc.number: GetSkillManager_0600
 * @tc.name: Test GetSkillManager caches the proxy on success
 * @tc.desc: 1.success path caches skillManager_, second call hits the cache
 */
HWTEST_F(BmsSkillManagerHelperTest, GetSkillManager_0600, Function | SmallTest | Level1)
{
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManager, nullptr);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 1);
    ASSERT_NE(g_lastDeathRecipient, nullptr);

    auto skillManagerCached = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManagerCached, nullptr);
    EXPECT_EQ(skillManagerCached.GetRefPtr(), skillManager.GetRefPtr());
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 1);
}

/**
 * @tc.number: GetSkillManager_0700
 * @tc.name: Test GetSkillManager skips death recipient for non proxy object
 * @tc.desc: 1.skillManager is a local stub, AddDeathRecipient is skipped and proxy is still cached
 */
HWTEST_F(BmsSkillManagerHelperTest, GetSkillManager_0700, Function | SmallTest | Level1)
{
    skillManagerRemote_->isProxyObject_ = false;
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManager, nullptr);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 0);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 1);

    // stub branch still caches: the second call is served without new ipc
    auto skillManagerCached = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManagerCached, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 1);
}

/**
 * @tc.number: OnRemoteDied_0800
 * @tc.name: Test OnRemoteDied with null remote still clears the cache
 * @tc.desc: 1.death notification clears skillManager_ regardless of remote, next call refetches
 */
HWTEST_F(BmsSkillManagerHelperTest, OnRemoteDied_0800, Function | SmallTest | Level1)
{
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManager, nullptr);
    ASSERT_NE(g_lastDeathRecipient, nullptr);

    wptr<IRemoteObject> nullRemote;
    g_lastDeathRecipient->OnRemoteDied(nullRemote);
    auto skillManagerRefetched = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManagerRefetched, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 2);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 2);
}

/**
 * @tc.number: OnRemoteDied_0900
 * @tc.name: Test OnRemoteDied clears the cached proxy
 * @tc.desc: 1.death notification clears skillManager_, next call refetches the proxy
 */
HWTEST_F(BmsSkillManagerHelperTest, OnRemoteDied_0900, Function | SmallTest | Level1)
{
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManager, nullptr);
    ASSERT_NE(g_lastDeathRecipient, nullptr);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 1);

    g_lastDeathRecipient->OnRemoteDied(wptr<IRemoteObject>(g_mockBundleMgrSa));
    auto skillManagerAfterDeath = SkillManagerHelper::GetSkillManager();
    EXPECT_NE(skillManagerAfterDeath, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 2);
    // refetch after death registers the death recipient again
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 2);
}

/**
 * @tc.number: GetSkillManager_1000
 * @tc.name: Test GetSkillManager when iface_cast cannot resolve a broker
 * @tc.desc: 1.AsInterface returns null, iface_cast yields null and GetSkillManager returns nullptr
 */
HWTEST_F(BmsSkillManagerHelperTest, GetSkillManager_1000, Function | SmallTest | Level1)
{
    bundleMgrSa_->asInterfaceNull_ = true;
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_EQ(skillManager, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 0);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 0);
}

/**
 * @tc.number: GetSkillManager_1100
 * @tc.name: Test GetSkillManager when the bundle manager proxy has no remote object
 * @tc.desc: 1.bundleMgr->AsObject() is null, GetSkillManager returns nullptr before any skill ipc
 */
HWTEST_F(BmsSkillManagerHelperTest, GetSkillManager_1100, Function | SmallTest | Level1)
{
    bundleMgrMock_->asObjectNull_ = true;
    auto skillManager = SkillManagerHelper::GetSkillManager();
    EXPECT_EQ(skillManager, nullptr);
    EXPECT_EQ(bundleMgrMock_->getSkillManagerProxyCount_, 0);
    EXPECT_EQ(skillManagerRemote_->addDeathRecipientCount_, 0);
}

/**
 * @tc.number: InnerGetSkillInfoForSelf_1200
 * @tc.name: Test all Inner entry points when helper cannot get the proxy
 * @tc.desc: 1.system ability manager is null, every Inner entry returns service exception
 */
HWTEST_F(BmsSkillManagerHelperTest, InnerGetSkillInfoForSelf_1200, Function | SmallTest | Level1)
{
    g_samgrValid = false;
    SkillInfo skillInfo;
    ErrCode ret = SkillManagerHelper::InnerGetSkillInfoForSelf("module", "skill", 0, skillInfo);
    EXPECT_EQ(ret, ERROR_BUNDLE_SERVICE_EXCEPTION);

    std::vector<SkillInfo> skillInfos;
    ErrCode retInfos = SkillManagerHelper::InnerGetSkillInfosForSelf(0, skillInfos);
    EXPECT_EQ(retInfos, ERROR_BUNDLE_SERVICE_EXCEPTION);
    EXPECT_TRUE(skillInfos.empty());

    ErrCode retInfo = SkillManagerHelper::InnerGetSkillInfo("bundle", "module", "skill", 0, 0, skillInfo);
    EXPECT_EQ(retInfo, ERROR_BUNDLE_SERVICE_EXCEPTION);
    ErrCode retBundleInfos = SkillManagerHelper::InnerGetSkillInfos("bundle", 0, 0, skillInfos);
    EXPECT_EQ(retBundleInfos, ERROR_BUNDLE_SERVICE_EXCEPTION);
    EXPECT_TRUE(skillInfos.empty());
    ErrCode retAll = SkillManagerHelper::InnerGetAllSkillInfos(0, 0, skillInfos);
    EXPECT_EQ(retAll, ERROR_BUNDLE_SERVICE_EXCEPTION);
    EXPECT_TRUE(skillInfos.empty());
}

/**
 * @tc.number: InnerGetSkillInfoForSelf_1300
 * @tc.name: Test Inner entry points on the success path
 * @tc.desc: 1.proxy returns ERR_OK with filled results, Inner entries forward them unchanged
 */
HWTEST_F(BmsSkillManagerHelperTest, InnerGetSkillInfoForSelf_1300, Function | SmallTest | Level1)
{
    SkillInfo skillInfo;
    ErrCode ret = SkillManagerHelper::InnerGetSkillInfoForSelf("module", "skill", 0, skillInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfo.bundleName, "com.example.skill");
    EXPECT_EQ(skillInfo.skillName, "testSkill");

    std::vector<SkillInfo> skillInfos;
    ErrCode retInfos = SkillManagerHelper::InnerGetSkillInfosForSelf(0, skillInfos);
    EXPECT_EQ(retInfos, ERR_OK);
    ASSERT_EQ(skillInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(skillInfos[0].bundleName, "com.example.skill");
}
