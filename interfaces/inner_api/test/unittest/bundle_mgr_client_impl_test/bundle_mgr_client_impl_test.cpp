/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#define protected public

#include <gtest/gtest.h>

#include "bundle_mgr_client.h"
#include "bundle_mgr_client_impl.h"

#include <cerrno>
#include <fstream>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_death_recipient.h"
#include "iservice_registry.h"
#include "nlohmann/json.hpp"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
const int32_t USERID = 100;

class BundleMgrClientImplTest : public testing::Test {
public:
    BundleMgrClientImplTest() = default;
    ~BundleMgrClientImplTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

class MockEventCallback : public BundleEventCallbackHost {
public:
    MockEventCallback() = default;
    virtual ~MockEventCallback() = default;
    void OnReceiveEvent(const EventFwk::CommonEventData eventData) override;
    bool IsCalled() const { return isCalled_; }
    void Reset() { isCalled_ = false; }
private:
    bool isCalled_ = false;
};

void MockEventCallback::OnReceiveEvent(const EventFwk::CommonEventData eventData)
{
    isCalled_ = true;
    std::cout << "MockEventCallback::OnReceiveEvent" << std::endl;
}

const std::shared_ptr<BundleDataMgr> BundleMgrClientImplTest::GetBundleDataMgr() const
{
    EXPECT_NE(bundleMgrService_->GetDataMgr(), nullptr);
    return bundleMgrService_->GetDataMgr();
}

std::shared_ptr<BundleMgrService> BundleMgrClientImplTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BundleMgrClientImplTest::SetUpTestCase()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    }
}

void BundleMgrClientImplTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
    sleep(1);
}

void BundleMgrClientImplTest::SetUp()
{
}

void BundleMgrClientImplTest::TearDown()
{
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0100
 * @tc.name: test the CreateBundleDataDirWithEl
 * @tc.desc: 1. CreateBundleDataDirWithEl
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    int32_t userId = 0;
    DataDirEl dirEl = DataDirEl::EL5;
    auto ret = bundleMgrClientImpl->CreateBundleDataDirWithEl(userId, dirEl);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0200
 * @tc.name: test the GetBundlePackInfo
 * @tc.desc: 1. GetBundlePackInfo
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    std::string bundleName = "com.example.bundle.wrong";
    BundlePackFlag flag = BundlePackFlag::GET_PACK_INFO_ALL;
    BundlePackInfo bundlePackInfo;
    int32_t userId = 101;
    auto ret = bundleMgrClientImpl->GetBundlePackInfo(bundleName, flag, bundlePackInfo, userId);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0300
 * @tc.name: test the GetHapModuleInfo
 * @tc.desc: 1. GetHapModuleInfo
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    std::string bundleName = "com.example.bundle.wrong";
    std::string hapName = "entry";
    HapModuleInfo hapModuleInfo;
    auto ret = bundleMgrClientImpl->GetHapModuleInfo(bundleName, hapName, hapModuleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0400
 * @tc.name: test the GetProfileFromExtension
 * @tc.desc: 1. GetProfileFromExtension
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0400, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    ExtensionAbilityInfo extensionInfo;
    std::string metadataName = "profile";
    std::vector<std::string> profileInfos;
    auto ret = bundleMgrClientImpl->GetProfileFromExtension(extensionInfo, metadataName, profileInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0500
 * @tc.name: test the GetProfileFromAbility
 * @tc.desc: 1. GetProfileFromAbility
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0500, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    AbilityInfo abilityInfo;
    std::string metadataName = "profile";
    std::vector<std::string> profileInfos;
    auto ret = bundleMgrClientImpl->GetProfileFromAbility(abilityInfo, metadataName, profileInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0600
 * @tc.name: test the GetProfileFromHap
 * @tc.desc: 1. GetProfileFromHap
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0600, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    HapModuleInfo hapModuleInfo;
    std::string metadataName = "profile";
    std::vector<std::string> profileInfos;
    auto ret = bundleMgrClientImpl->GetProfileFromHap(hapModuleInfo, metadataName, profileInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0700
 * @tc.name: test the CreateBundleDataDir
 * @tc.desc: 1. CreateBundleDataDir
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0700, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    int32_t userId = 1111;
    auto ret = bundleMgrClientImpl->CreateBundleDataDir(userId);
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED);
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0800
 * @tc.name: test the GetDirByBundleNameAndAppIndex
 * @tc.desc: 1. GetDirByBundleNameAndAppIndex
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0800, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    std::string bundleName;
    int32_t appIndex = -1;
    std::string dataDir;
    auto ret = bundleMgrClientImpl->GetDirByBundleNameAndAppIndex(bundleName, appIndex, dataDir);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetProfileFromSharedHap_0100
 * @tc.name: GetProfileFromSharedHap_0100
 * @tc.desc: Test GetProfileFromSharedHap with undef GLOBAL_RESMGR_ENABLE
 */
HWTEST_F(BundleMgrClientImplTest, GetProfileFromSharedHap_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    HapModuleInfo hapModuleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    std::vector<std::string> profileInfos = {};
    EXPECT_FALSE(bundleMgrClientImpl->GetProfileFromSharedHap(hapModuleInfo, extensionAbilityInfo, profileInfos, true));
}

/**
 * @tc.number: RegisterAndUnregisterPluginEventCallback_0100
 * @tc.name: RegisterAndUnregisterPluginEventCallback_0100
 * @tc.desc: Test RegisterPluginEventCallback and UnregisterPluginEventCallback
 */
HWTEST_F(BundleMgrClientImplTest, RegisterAndUnregisterPluginEventCallback_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();

    auto ret = bundleMgrClientImpl->RegisterPluginEventCallback(nullptr);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    ret = bundleMgrClientImpl->UnregisterPluginEventCallback(nullptr);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    std::vector<BundleInfo> bundleInfos;
    ret = GetBundleDataMgr()->GetBundleInfosV9(1, bundleInfos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(bundleInfos.size(), 0);
    int uid = getuid();
    std::cout << "current uid is " << getuid() << std::endl;
    if (bundleInfos.size() > 0) {
        setuid(bundleInfos[0].applicationInfo.uid);
        std::cout << "set uid to " << bundleInfos[0].applicationInfo.uid << std::endl;
    }

    sptr<MockEventCallback> mockCallback = new MockEventCallback();
    sptr<MockEventCallback> mockCallback2 = new MockEventCallback();

    ret = bundleMgrClientImpl->RegisterPluginEventCallback(mockCallback);
    EXPECT_EQ(ret, ERR_OK);

    ret = bundleMgrClientImpl->RegisterPluginEventCallback(mockCallback2);
    EXPECT_EQ(ret, ERR_OK);

    ret = bundleMgrClientImpl->UnregisterPluginEventCallback(mockCallback);
    EXPECT_EQ(ret, ERR_OK);

    ret = bundleMgrClientImpl->UnregisterPluginEventCallback(mockCallback2);
    EXPECT_EQ(ret, ERR_OK);

    ret = bundleMgrClientImpl->UnregisterPluginEventCallback(mockCallback2);
    EXPECT_EQ(ret, ERR_OK);

    setuid(uid);
}

/**
 * @tc.number: RegisterAndUnregisterPluginEventCallback_0200
 * @tc.name: RegisterAndUnregisterPluginEventCallback_0200
 * @tc.desc: Test RegisterPluginEventCallback and UnregisterPluginEventCallback
 */
HWTEST_F(BundleMgrClientImplTest, RegisterAndUnregisterPluginEventCallback_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClient> bundleMgrClient = std::make_shared<BundleMgrClient>();

    auto ret = bundleMgrClient->RegisterPluginEventCallback(nullptr);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    ret = bundleMgrClient->UnregisterPluginEventCallback(nullptr);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    std::vector<BundleInfo> bundleInfos;
    ret = GetBundleDataMgr()->GetBundleInfosV9(1, bundleInfos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(bundleInfos.size(), 0);
    int uid = getuid();
    std::cout << "current uid is " << getuid() << std::endl;
    if (bundleInfos.size() > 0) {
        setuid(bundleInfos[0].applicationInfo.uid);
        std::cout << "set uid to " << bundleInfos[0].applicationInfo.uid << std::endl;
    }

    sptr<MockEventCallback> pluginCallback = new MockEventCallback();
    sptr<MockEventCallback> pluginCallback2 = new MockEventCallback();

    ret = bundleMgrClient->RegisterPluginEventCallback(pluginCallback);
    EXPECT_EQ(ret, ERR_OK);

    ret = bundleMgrClient->RegisterPluginEventCallback(pluginCallback2);
    EXPECT_EQ(ret, ERR_OK);

    ret = bundleMgrClient->UnregisterPluginEventCallback(pluginCallback);
    EXPECT_EQ(ret, ERR_OK);

    ret = bundleMgrClient->UnregisterPluginEventCallback(pluginCallback2);
    EXPECT_EQ(ret, ERR_OK);

    ret = bundleMgrClient->UnregisterPluginEventCallback(pluginCallback2);
    EXPECT_EQ(ret, ERR_OK);

    setuid(uid);
}

/**
 * @tc.number: OnPluginEventCallback_0100
 * @tc.name: OnPluginEventCallback_0100
 * @tc.desc: Test OnPluginEventCallback with empty callback list
 */
HWTEST_F(BundleMgrClientImplTest, OnPluginEventCallback_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();

    EventFwk::CommonEventData eventData;
    EXPECT_NO_THROW(bundleMgrClientImpl->OnPluginEventCallback(eventData));
}

/**
 * @tc.number: OnPluginEventCallback_0200
 * @tc.name: OnPluginEventCallback_0200
 * @tc.desc: Test OnPluginEventCallback with multiple callbacks
 */
HWTEST_F(BundleMgrClientImplTest, OnPluginEventCallback_0200, Function | SmallTest | Level0)
{
    std::vector<BundleInfo> bundleInfos;
    auto ret = GetBundleDataMgr()->GetBundleInfosV9(1, bundleInfos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(bundleInfos.size(), 0);
    int uid = getuid();
    std::cout << "current uid is " << getuid() << std::endl;
    if (bundleInfos.size() > 0) {
        setuid(bundleInfos[0].applicationInfo.uid);
        std::cout << "set uid to " << bundleInfos[0].applicationInfo.uid << std::endl;
    }

    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();

    sptr<MockEventCallback> mockCallback1 = new MockEventCallback();
    sptr<MockEventCallback> mockCallback2 = new MockEventCallback();
    sptr<MockEventCallback> mockCallback3 = new MockEventCallback();

    ret = bundleMgrClientImpl->RegisterPluginEventCallback(mockCallback1);
    EXPECT_EQ(ret, ERR_OK);
    ret = bundleMgrClientImpl->RegisterPluginEventCallback(mockCallback2);
    EXPECT_EQ(ret, ERR_OK);
    ret = bundleMgrClientImpl->RegisterPluginEventCallback(mockCallback3);
    EXPECT_EQ(ret, ERR_OK);

    EventFwk::CommonEventData eventData;
    EXPECT_NO_THROW(bundleMgrClientImpl->OnPluginEventCallback(eventData));

    EXPECT_TRUE(mockCallback1->IsCalled());
    EXPECT_TRUE(mockCallback2->IsCalled());
    EXPECT_TRUE(mockCallback3->IsCalled());

    bundleMgrClientImpl->UnregisterPluginEventCallback(mockCallback1);
    bundleMgrClientImpl->UnregisterPluginEventCallback(mockCallback2);
    bundleMgrClientImpl->UnregisterPluginEventCallback(mockCallback3);
    setuid(uid);
}

/**
 * @tc.number: OnPluginEventCallback_0300
 * @tc.name: OnPluginEventCallback_0300
 * @tc.desc: Test PluginEventCallback::OnReceiveEvent with expired weak_ptr
 */
HWTEST_F(BundleMgrClientImplTest, OnPluginEventCallback_0300, Function | SmallTest | Level0)
{
    auto bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    sptr<PluginEventCallback> pluginEventCallback = new PluginEventCallback(bundleMgrClientImpl);

    bundleMgrClientImpl.reset();

    EventFwk::CommonEventData eventData;
    EXPECT_NO_THROW(pluginEventCallback->OnReceiveEvent(eventData));
}

/**
 * @tc.number: OnPluginEventCallback_0400
 * @tc.name: OnPluginEventCallback_0400
 * @tc.desc: Test OnPluginEventCallback with event data containing bundle name
 */
HWTEST_F(BundleMgrClientImplTest, OnPluginEventCallback_0400, Function | SmallTest | Level0)
{
    std::vector<BundleInfo> bundleInfos;
    auto ret = GetBundleDataMgr()->GetBundleInfosV9(1, bundleInfos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(bundleInfos.size(), 0);
    int uid = getuid();
    std::cout << "current uid is " << getuid() << std::endl;
    if (bundleInfos.size() > 0) {
        setuid(bundleInfos[0].applicationInfo.uid);
        std::cout << "set uid to " << bundleInfos[0].applicationInfo.uid << std::endl;
    }

    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();

    sptr<MockEventCallback> mockCallback = new MockEventCallback();
    ret = bundleMgrClientImpl->RegisterPluginEventCallback(mockCallback);
    EXPECT_EQ(ret, ERR_OK);

    EventFwk::CommonEventData eventData;
    AAFwk::Want want;
    want.SetParam("bundleName", std::string("com.example.test"));
    eventData.SetWant(want);

    EXPECT_NO_THROW(bundleMgrClientImpl->OnPluginEventCallback(eventData));

    EXPECT_TRUE(mockCallback->IsCalled());

    bundleMgrClientImpl->UnregisterPluginEventCallback(mockCallback);
    setuid(uid);
}

/**
 * @tc.number: OnPluginEventCallback_0500
 * @tc.name: OnPluginEventCallback_0500
 * @tc.desc: Test OnPluginEventCallback concurrent calls
 */
HWTEST_F(BundleMgrClientImplTest, OnPluginEventCallback_0500, Function | SmallTest | Level0)
{
    std::vector<BundleInfo> bundleInfos;
    auto ret = GetBundleDataMgr()->GetBundleInfosV9(1, bundleInfos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(bundleInfos.size(), 0);
    int uid = getuid();
    std::cout << "current uid is " << getuid() << std::endl;
    if (bundleInfos.size() > 0) {
        setuid(bundleInfos[0].applicationInfo.uid);
        std::cout << "set uid to " << bundleInfos[0].applicationInfo.uid << std::endl;
    }

    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();

    sptr<MockEventCallback> mockCallback = new MockEventCallback();
    ret = bundleMgrClientImpl->RegisterPluginEventCallback(mockCallback);
    EXPECT_EQ(ret, ERR_OK);

    EventFwk::CommonEventData eventData;
    EXPECT_NO_THROW(bundleMgrClientImpl->OnPluginEventCallback(eventData));
    EXPECT_NO_THROW(bundleMgrClientImpl->OnPluginEventCallback(eventData));
    EXPECT_NO_THROW(bundleMgrClientImpl->OnPluginEventCallback(eventData));

    EXPECT_TRUE(mockCallback->IsCalled());

    bundleMgrClientImpl->UnregisterPluginEventCallback(mockCallback);
    setuid(uid);
}

/**
 * @tc.number: OnPluginEventCallback_0600
 * @tc.name: OnPluginEventCallback_0600
 * @tc.desc: Test PluginEventCallback::OnReceiveEvent with valid weak_ptr
 */
HWTEST_F(BundleMgrClientImplTest, OnPluginEventCallback_0600, Function | SmallTest | Level0)
{
    std::vector<BundleInfo> bundleInfos;
    auto ret = GetBundleDataMgr()->GetBundleInfosV9(1, bundleInfos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(bundleInfos.size(), 0);
    int uid = getuid();
    std::cout << "current uid is " << getuid() << std::endl;
    if (bundleInfos.size() > 0) {
        setuid(bundleInfos[0].applicationInfo.uid);
        std::cout << "set uid to " << bundleInfos[0].applicationInfo.uid << std::endl;
    }

    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    sptr<PluginEventCallback> pluginEventCallback = new PluginEventCallback(bundleMgrClientImpl);

    sptr<MockEventCallback> mockCallback = new MockEventCallback();
    ret = bundleMgrClientImpl->RegisterPluginEventCallback(mockCallback);
    EXPECT_EQ(ret, ERR_OK);

    EventFwk::CommonEventData eventData;
    EXPECT_NO_THROW(pluginEventCallback->OnReceiveEvent(eventData));

    EXPECT_TRUE(mockCallback->IsCalled());

    bundleMgrClientImpl->UnregisterPluginEventCallback(mockCallback);
    setuid(uid);
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_0900
 * @tc.name: test the StartAppDetailAbility
 * @tc.desc: 1. the test process uid is not a registered no-icon bundle
 *           2. verify StartAppDetailAbility is rejected by the host and does not return success
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_0900, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    auto ret = bundleMgrClientImpl->StartAppDetailAbility();
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: Bundle_Mgr_Client_Impl_Test_1000
 * @tc.name: test the StartAppDetailAbility security path
 * @tc.desc: Impersonate an installed non-no-icon app and walk the full path
 *           client -> proxy -> host: the calling uid resolves to a bundle, the
 *           bundle is not a no-icon app, so the host must reject at the
 *           needAppDetail gate with ERR_APPEXECFWK_PERMISSION_DENIED. This is
 *           the security boundary added by the StartAppDetailAbility fix.
 *           NOTE: real coverage requires the host GetCallingUid() to honor the
 *           setuid impersonation; if it does not, this test fails loudly rather
 *           than silently passing.
 */
HWTEST_F(BundleMgrClientImplTest, Bundle_Mgr_Client_Impl_Test_1000, Function | SmallTest | Level0)
{
    // 1. enumerate installed bundles; fail loud when none are installed
    std::vector<BundleInfo> bundleInfos;
    auto ret = GetBundleDataMgr()->GetBundleInfosV9(1, bundleInfos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(bundleInfos.empty());
    if (bundleInfos.empty()) {
        return;
    }

    // 2. find a bundle we can impersonate: its uid must reverse-map to a bundle
    //    AND that bundle must NOT be a no-icon app (needAppDetail == false).
    //    Scan the whole list rather than only [0], so a single unsuitable entry
    //    cannot turn this test into a silent no-op.
    int32_t targetUid = -1;
    for (const auto &info : bundleInfos) {
        std::string mappedName;
        if (!GetBundleDataMgr()->GetBundleNameForUid(info.applicationInfo.uid, mappedName)) {
            continue;
        }
        bool needAppDetail = false;
        if (!GetBundleDataMgr()->GetNeedAppDetail(mappedName, needAppDetail) || needAppDetail) {
            continue;
        }
        targetUid = info.applicationInfo.uid;
        break;
    }
    // fail loud if no qualifying target exists, so coverage never silently drops
    EXPECT_NE(targetUid, -1);
    if (targetUid == -1) {
        return;
    }

    // 3. impersonate the installed app; skip if the harness lacks CAP_SETUID
    int savedUid = getuid();
    if (setuid(targetUid) != 0) {
        return;
    }
    std::shared_ptr<BundleMgrClientImpl> bundleMgrClientImpl = std::make_shared<BundleMgrClientImpl>();
    ret = bundleMgrClientImpl->StartAppDetailAbility();
    setuid(savedUid);

    // 4. host resolves the uid, finds the bundle, sees needAppDetail == false,
    //    and must reject at the needAppDetail gate with PERMISSION_DENIED
    EXPECT_EQ(ret, ERR_APPEXECFWK_PERMISSION_DENIED);
}
} // AppExecFwk
} // OHOS
