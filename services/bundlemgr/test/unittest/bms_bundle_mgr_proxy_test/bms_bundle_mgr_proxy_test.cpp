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

#include <fstream>
#include <future>
#include <gtest/gtest.h>

#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "want.h"

using namespace testing::ext;

using OHOS::AAFwk::Want;

namespace OHOS {
namespace AppExecFwk {

class ICleanCacheCallbackTest : public ICleanCacheCallback {
public:
    void OnCleanCacheFinished(bool succeeded);
    sptr<IRemoteObject> AsObject();
};

void ICleanCacheCallbackTest::OnCleanCacheFinished(bool succeeded) {}

sptr<IRemoteObject> ICleanCacheCallbackTest::AsObject()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    return systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
}

class IBundleStatusCallbackTest : public IBundleStatusCallback {
public:
    void OnBundleStateChanged(const uint8_t installType, const int32_t resultCode, const std::string &resultMsg,
        const std::string &bundleName);
    void OnBundleAdded(const std::string &bundleName, const int userId);
    void OnBundleUpdated(const std::string &bundleName, const int userId);
    void OnBundleRemoved(const std::string &bundleName, const int userId);
    sptr<IRemoteObject> AsObject();
};

void IBundleStatusCallbackTest::OnBundleStateChanged(const uint8_t installType,
    const int32_t resultCode, const std::string &resultMsg, const std::string &bundleName)
{}

void IBundleStatusCallbackTest::OnBundleAdded(const std::string &bundleName, const int userId)
{}

void IBundleStatusCallbackTest::OnBundleUpdated(const std::string &bundleName, const int userId)
{}

void IBundleStatusCallbackTest::OnBundleRemoved(const std::string &bundleName, const int userId)
{}

sptr<IRemoteObject> IBundleStatusCallbackTest::AsObject()
{
    return nullptr;
}

class IBundleEventCallbackTest : public IBundleEventCallback {
    void OnReceiveEvent(const EventFwk::CommonEventData eventData);
    sptr<IRemoteObject> AsObject();
};

void IBundleEventCallbackTest::OnReceiveEvent(const EventFwk::CommonEventData eventData)
{}

sptr<IRemoteObject> IBundleEventCallbackTest::AsObject()
{
    return nullptr;
}

class BmsBundleMgrProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsBundleMgrProxyTest::SetUpTestCase()
{}

void BmsBundleMgrProxyTest::TearDownTestCase()
{}

void BmsBundleMgrProxyTest::SetUp()
{}

void BmsBundleMgrProxyTest::TearDown()
{}

bool ParseStr(const char *buf, const int itemLen, int index, std::string &result);

/**
 * @tc.number: GetApplicationInfo_0100
 * @tc.name: test the GetApplicationInfo
 * @tc.desc: 1. system running normally
 *           2. test GetApplicationInfo
 */
HWTEST_F(BmsBundleMgrProxyTest, GetApplicationInfo_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    string appName = "";
    ApplicationFlag flag = ApplicationFlag::GET_BASIC_APPLICATION_INFO;
    int userId = 100;
    ApplicationInfo appInfo;
    EXPECT_TRUE(appName.empty());
    auto res = bundleMgrProxy.GetApplicationInfo(appName, flag, userId, appInfo);
    EXPECT_FALSE(res);
    appName = "appName";
    res = bundleMgrProxy.GetApplicationInfo(appName, flag, userId, appInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetApplicationInfo_0200
 * @tc.name: test the GetApplicationInfo
 * @tc.desc: 1. system running normally
 *           2. test GetApplicationInfo
 */
HWTEST_F(BmsBundleMgrProxyTest, GetApplicationInfo_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    string appName = "";
    int32_t flags = 1;
    int userId = 100;
    ApplicationInfo appInfo;
    EXPECT_TRUE(appName.empty());
    auto res = bundleMgrProxy.GetApplicationInfo(appName, flags, userId, appInfo);
    EXPECT_FALSE(res);
    appName = "appName";
    res = bundleMgrProxy.GetApplicationInfo(appName, flags, userId, appInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetApplicationInfoV9_0100
 * @tc.name: test the GetApplicationInfoV9
 * @tc.desc: 1. system running normally
 *           2. test GetApplicationInfoV9
 */
HWTEST_F(BmsBundleMgrProxyTest, GetApplicationInfoV9_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    string appName = "";
    int32_t flags = 1;
    int userId = 100;
    ApplicationInfo appInfo;
    EXPECT_TRUE(appName.empty());
    auto res = bundleMgrProxy.GetApplicationInfoV9(appName, flags, userId, appInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    appName = "appName";
    res = bundleMgrProxy.GetApplicationInfoV9(appName, flags, userId, appInfo);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetApplicationInfos_0100
 * @tc.name: test the GetApplicationInfos
 * @tc.desc: 1. system running normally
 *           2. test GetApplicationInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, GetApplicationInfos_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    int userId = 100;
    ApplicationFlag flag = ApplicationFlag::GET_BASIC_APPLICATION_INFO;
    std::vector<ApplicationInfo> appInfos;
    auto res = bundleMgrProxy.GetApplicationInfos(flag, userId, appInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetApplicationInfos_0200
 * @tc.name: test the GetApplicationInfos
 * @tc.desc: 1. system running normally
 *           2. test GetApplicationInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, GetApplicationInfos_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    int userId = 100;
    int32_t flags = 1;
    std::vector<ApplicationInfo> appInfos;
    auto res = bundleMgrProxy.GetApplicationInfos(flags, userId, appInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetApplicationInfosV9_0100
 * @tc.name: test the GetApplicationInfosV9
 * @tc.desc: 1. system running normally
 *           2. test GetApplicationInfosV9
 */
HWTEST_F(BmsBundleMgrProxyTest, GetApplicationInfosV9_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    int userId = 100;
    int32_t flags = 1;
    std::vector<ApplicationInfo> appInfos;
    auto res = bundleMgrProxy.GetApplicationInfosV9(flags, userId, appInfos);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: BatchGetBundleInfo_0100
 * @tc.name: test the BatchGetBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test BatchGetBundleInfo
 */
HWTEST_F(BmsBundleMgrProxyTest, BatchGetBundleInfo_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::vector<Want> wants;
    EXPECT_EQ(wants.size(), 0);
    int32_t flags = 1;
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = 100;
    auto res = bundleMgrProxy.BatchGetBundleInfo(wants, flags, bundleInfos, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    Want want;
    std::string bundleName = "bundleName";
    want.GetElement().SetBundleName(bundleName);
    wants.emplace_back(want);
    res = bundleMgrProxy.BatchGetBundleInfo(wants, flags, bundleInfos, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BatchGetBundleInfo_0200
 * @tc.name: test the BatchGetBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test BatchGetBundleInfo
 */
HWTEST_F(BmsBundleMgrProxyTest, BatchGetBundleInfo_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::vector<std::string> bundleNames;
    EXPECT_EQ(bundleNames.size(), 0);
    int32_t flags = 1;
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = 100;
    auto res = bundleMgrProxy.BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    std::string bundleName = "bundleName";
    bundleNames.emplace_back(bundleName);
    res = bundleMgrProxy.BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetBundlePackInfo_0100
 * @tc.name: test the GetBundlePackInfo
 * @tc.desc: 1. system running normally
 *           2. test GetBundlePackInfo
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundlePackInfo_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    BundlePackFlag flag = BundlePackFlag::GET_PACK_INFO_ALL;
    BundlePackInfo bundlePackInfo;
    int32_t userId = 100;
    auto res = bundleMgrProxy.GetBundlePackInfo(bundleName, flag, bundlePackInfo, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    bundleName = "bundleName";
    res = bundleMgrProxy.GetBundlePackInfo(bundleName, flag, bundlePackInfo, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}


/**
 * @tc.number: GetBundlePackInfo_0200
 * @tc.name: test the GetBundlePackInfo
 * @tc.desc: 1. system running normally
 *           2. test GetBundlePackInfo
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundlePackInfo_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    int32_t flags = 1;
    BundlePackInfo bundlePackInfo;
    int32_t userId = 100;
    auto res = bundleMgrProxy.GetBundlePackInfo(bundleName, flags, bundlePackInfo, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    bundleName = "bundleName";
    res = bundleMgrProxy.GetBundlePackInfo(bundleName, flags, bundlePackInfo, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetBundleInfos_0100
 * @tc.name: test the GetBundleInfos
 * @tc.desc: 1. system running normally
 *           2. test GetBundleInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundleInfos_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    BundleFlag flag = BundleFlag::GET_BUNDLE_DEFAULT;
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = 100;
    auto res = bundleMgrProxy.GetBundleInfos(flag, bundleInfos, userId);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetBundleInfos_0200
 * @tc.name: test the GetBundleInfos
 * @tc.desc: 1. system running normally
 *           2. test GetBundleInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundleInfos_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    int32_t flag = 1;
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = 100;
    auto res = bundleMgrProxy.GetBundleInfos(flag, bundleInfos, userId);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetBundleInfosV9_0100
 * @tc.name: test the GetBundleInfosV9
 * @tc.desc: 1. system running normally
 *           2. test GetBundleInfosV9
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundleInfosV9_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    BundleFlag flag = BundleFlag::GET_BUNDLE_DEFAULT;
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = 100;
    auto res = bundleMgrProxy.GetBundleInfosV9(flag, bundleInfos, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetUidByBundleName_0100
 * @tc.name: test the GetUidByBundleName
 * @tc.desc: 1. system running normally
 *           2. test GetUidByBundleName
 */
HWTEST_F(BmsBundleMgrProxyTest, GetUidByBundleName_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    int32_t userId = 100;
    auto res = bundleMgrProxy.GetUidByBundleName(bundleName, userId);
    EXPECT_EQ(res, Constants::INVALID_UID);
    bundleName = "bundleName";
    res = bundleMgrProxy.GetUidByBundleName(bundleName, userId);
    EXPECT_EQ(res, Constants::INVALID_UID);
}

/**
 * @tc.number: GetUidByBundleName_0200
 * @tc.name: test the GetUidByBundleName
 * @tc.desc: 1. system running normally
 *           2. test GetUidByBundleName
 */
HWTEST_F(BmsBundleMgrProxyTest, GetUidByBundleName_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    int32_t userId = 100;
    int32_t appIndex = 0;
    auto res = bundleMgrProxy.GetUidByBundleName(bundleName, userId, appIndex);
    EXPECT_EQ(res, Constants::INVALID_UID);
    bundleName = "bundleName";
    res = bundleMgrProxy.GetUidByBundleName(bundleName, userId, appIndex);
    EXPECT_EQ(res, Constants::INVALID_UID);
}

/**
 * @tc.number: GetUidByDebugBundleName_0100
 * @tc.name: test the GetUidByDebugBundleName
 * @tc.desc: 1. system running normally
 *           2. test GetUidByDebugBundleName
 */
HWTEST_F(BmsBundleMgrProxyTest, GetUidByDebugBundleName_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    int32_t userId = 100;
    auto res = bundleMgrProxy.GetUidByDebugBundleName(bundleName, userId);
    EXPECT_EQ(res, Constants::INVALID_UID);
    bundleName = "bundleName";
    res = bundleMgrProxy.GetUidByDebugBundleName(bundleName, userId);
    EXPECT_EQ(res, Constants::INVALID_UID);
}

/**
 * @tc.number: GetAppIdByBundleName_0100
 * @tc.name: test the GetAppIdByBundleName
 * @tc.desc: 1. system running normally
 *           2. test GetAppIdByBundleName
 */
HWTEST_F(BmsBundleMgrProxyTest, GetAppIdByBundleName_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    int32_t userId = 100;
    auto res = bundleMgrProxy.GetAppIdByBundleName(bundleName, userId);
    EXPECT_EQ(res, Constants::EMPTY_STRING);
    bundleName = "bundleName";
    res = bundleMgrProxy.GetAppIdByBundleName(bundleName, userId);
    EXPECT_EQ(res, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetBundleNameForUid_0100
 * @tc.name: test the GetBundleNameForUid
 * @tc.desc: 1. system running normally
 *           2. test GetBundleNameForUid
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundleNameForUid_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    int uid = 100;
    auto res = bundleMgrProxy.GetBundleNameForUid(uid, bundleName);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetBundleNameForUid_0200
 * @tc.name: test the GetBundleNameForUid
 * @tc.desc: 1. system running normally
 *           2. test GetBundleNameForUid
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundleNameForUid_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    int uid = 100;
    std::string bundleName = "";
    auto res = bundleMgrProxy.GetBundleNameForUid(uid, bundleName);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetNameForUid_0100
 * @tc.name: test the GetNameForUid
 * @tc.desc: 1. system running normally
 *           2. test GetNameForUid
 */
HWTEST_F(BmsBundleMgrProxyTest, GetNameForUid_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    int uid = 100;
    std::string name;
    auto res = bundleMgrProxy.GetNameForUid(uid, name);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetNameAndIndexForUid_0100
 * @tc.name: test the GetNameAndIndexForUid
 * @tc.desc: 1. system running normally
 *           2. test GetNameAndIndexForUid
 */
HWTEST_F(BmsBundleMgrProxyTest, GetNameAndIndexForUid_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    int uid = 100;
    std::string bundleName = "";
    int32_t appIndex = 1;
    auto res = bundleMgrProxy.GetNameAndIndexForUid(uid, bundleName, appIndex);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetBundleGids_0100
 * @tc.name: test the GetBundleGids
 * @tc.desc: 1. system running normally
 *           2. test GetBundleGids
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundleGids_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::vector<int> gids;
    std::string bundleName = "";
    auto res = bundleMgrProxy.GetBundleGids(bundleName, gids);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetBundleGidsByUid_0100
 * @tc.name: test the GetBundleGidsByUid
 * @tc.desc: 1. system running normally
 *           2. test GetBundleGidsByUid
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundleGidsByUid_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::vector<int> gids;
    std::string bundleName = "";
    int uid = 100;
    auto res = bundleMgrProxy.GetBundleGidsByUid(bundleName, uid, gids);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetAppType_0100
 * @tc.name: test the GetAppType
 * @tc.desc: 1. system running normally
 *           2. test GetAppType
 */
HWTEST_F(BmsBundleMgrProxyTest, GetAppType_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    auto res = bundleMgrProxy.GetAppType(bundleName);
    EXPECT_EQ(res, Constants::EMPTY_STRING);
    bundleName = "bundleName";
    res = bundleMgrProxy.GetAppType(bundleName);
    EXPECT_EQ(res, Constants::EMPTY_STRING);
}

/**
 * @tc.number: CheckIsSystemAppByUid_0100
 * @tc.name: test the CheckIsSystemAppByUid
 * @tc.desc: 1. system running normally
 *           2. test CheckIsSystemAppByUid
 */
HWTEST_F(BmsBundleMgrProxyTest, CheckIsSystemAppByUid_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    int uid = 100;
    auto res = bundleMgrProxy.CheckIsSystemAppByUid(uid);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetBundleInfosByMetaData_0100
 * @tc.name: test the GetBundleInfosByMetaData
 * @tc.desc: 1. system running normally
 *           2. test GetBundleInfosByMetaData
 */
HWTEST_F(BmsBundleMgrProxyTest, GetBundleInfosByMetaData_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string metaData;
    EXPECT_TRUE(metaData.empty());
    std::vector<BundleInfo> bundleInfos;
    auto res = bundleMgrProxy.GetBundleInfosByMetaData(metaData, bundleInfos);
    EXPECT_FALSE(res);
    metaData = "metaData";
    res = bundleMgrProxy.GetBundleInfosByMetaData(metaData, bundleInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryAbilityInfo_0100
 * @tc.name: test the QueryAbilityInfo
 * @tc.desc: 1. system running normally
 *           2. test QueryAbilityInfo
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAbilityInfo_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    AbilityInfo abilityInfo;
    auto res = bundleMgrProxy.QueryAbilityInfo(want, abilityInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryAbilityInfo_0200
 * @tc.name: test the QueryAbilityInfo
 * @tc.desc: 1. system running normally
 *           2. test QueryAbilityInfo
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAbilityInfo_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    AbilityInfo abilityInfo;
    int32_t flag = 1;
    int32_t userId = 100;
    sptr<IRemoteObject> callBack;
    auto res = bundleMgrProxy.QueryAbilityInfo(want, flag, userId, abilityInfo, callBack);
    EXPECT_FALSE(res);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    callBack = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    res = bundleMgrProxy.QueryAbilityInfo(want, flag, userId, abilityInfo, callBack);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: SilentInstall_0100
 * @tc.name: test the SilentInstall
 * @tc.desc: 1. system running normally
 *           2. test SilentInstall
 */
HWTEST_F(BmsBundleMgrProxyTest, SilentInstall_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    int32_t userId = 100;
    sptr<IRemoteObject> callBack;
    auto res = bundleMgrProxy.SilentInstall(want, userId, callBack);
    EXPECT_FALSE(res);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    callBack = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    res = bundleMgrProxy.SilentInstall(want, userId, callBack);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryAbilityInfo_0300
 * @tc.name: test the QueryAbilityInfo
 * @tc.desc: 1. system running normally
 *           2. test QueryAbilityInfo
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAbilityInfo_0300, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    int32_t flags = 1;
    int32_t userId = 100;
    AbilityInfo abilityInfo;
    auto res = bundleMgrProxy.QueryAbilityInfo(want, flags, userId, abilityInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryAbilityInfos_0100
 * @tc.name: test the QueryAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test QueryAbilityInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAbilityInfos_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    std::vector<AbilityInfo> abilityInfos;
    auto res = bundleMgrProxy.QueryAbilityInfos(want, abilityInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryAbilityInfos_0200
 * @tc.name: test the QueryAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test QueryAbilityInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAbilityInfos_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    int32_t flags = 1;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    auto res = bundleMgrProxy.QueryAbilityInfos(want, flags, userId, abilityInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryAbilityInfosV9_0100
 * @tc.name: test the QueryAbilityInfosV9
 * @tc.desc: 1. system running normally
 *           2. test QueryAbilityInfosV9
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAbilityInfosV9_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    int32_t flags = 1;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    auto res = bundleMgrProxy.QueryAbilityInfosV9(want, flags, userId, abilityInfos);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: BatchQueryAbilityInfos_0100
 * @tc.name: test the BatchQueryAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test BatchQueryAbilityInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, BatchQueryAbilityInfos_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::vector<Want> wants;
    int32_t flags = 1;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    auto res = bundleMgrProxy.BatchQueryAbilityInfos(wants, flags, userId, abilityInfos);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: QueryLauncherAbilityInfos_0100
 * @tc.name: test the QueryLauncherAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test QueryLauncherAbilityInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryLauncherAbilityInfos_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    auto res = bundleMgrProxy.QueryLauncherAbilityInfos(want, userId, abilityInfos);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: QueryAllAbilityInfos_0100
 * @tc.name: test the QueryAllAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test QueryAllAbilityInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAllAbilityInfos_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    auto res = bundleMgrProxy.QueryAllAbilityInfos(want, userId, abilityInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0100
 * @tc.name: test the QueryAbilityInfoByUri
 * @tc.desc: 1. system running normally
 *           2. test QueryAbilityInfoByUri
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAbilityInfoByUri_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string abilityUri = "abilityUri";
    AbilityInfo abilityInfos;
    auto res = bundleMgrProxy.QueryAbilityInfoByUri(abilityUri, abilityInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryAbilityInfosByUri_0100
 * @tc.name: test the QueryAbilityInfosByUri
 * @tc.desc: 1. system running normally
 *           2. test QueryAbilityInfosByUri
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAbilityInfosByUri_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string abilityUri = "abilityUri";
    std::vector<AbilityInfo> abilityInfos;
    auto res = bundleMgrProxy.QueryAbilityInfosByUri(abilityUri, abilityInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0200
 * @tc.name: test the QueryAbilityInfoByUri
 * @tc.desc: 1. system running normally
 *           2. test QueryAbilityInfoByUri
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryAbilityInfoByUri_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string abilityUri = "abilityUri";
    AbilityInfo abilityInfos;
    int32_t userId = 100;
    auto res = bundleMgrProxy.QueryAbilityInfoByUri(abilityUri, userId, abilityInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: QueryKeepAliveBundleInfos_0100
 * @tc.name: test the QueryKeepAliveBundleInfos
 * @tc.desc: 1. system running normally
 *           2. test QueryKeepAliveBundleInfos
 */
HWTEST_F(BmsBundleMgrProxyTest, QueryKeepAliveBundleInfos_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::vector<BundleInfo> bundleInfos;
    auto res = bundleMgrProxy.QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetAbilityLabel_0100
 * @tc.name: test the GetAbilityLabel
 * @tc.desc: 1. system running normally
 *           2. test GetAbilityLabel
 */
HWTEST_F(BmsBundleMgrProxyTest, GetAbilityLabel_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName ="";
    std::string abilityName = "abilityName";
    auto res = bundleMgrProxy.GetAbilityLabel(bundleName, abilityName);
    EXPECT_EQ(res, Constants::EMPTY_STRING);
    bundleName ="bundleName";
    res = bundleMgrProxy.GetAbilityLabel(bundleName, abilityName);
    EXPECT_EQ(res, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetAbilityLabel_0200
 * @tc.name: test the GetAbilityLabel
 * @tc.desc: 1. system running normally
 *           2. test GetAbilityLabel
 */
HWTEST_F(BmsBundleMgrProxyTest, GetAbilityLabel_0200, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName ="";
    std::string moduleName = "moduleName";
    std::string abilityName = "abilityName";
    std::string label = "label";
    auto res = bundleMgrProxy.GetAbilityLabel(bundleName, moduleName, abilityName, label);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    bundleName ="bundleName";
    res = bundleMgrProxy.GetAbilityLabel(bundleName, moduleName, abilityName, label);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_IPC_TRANSACTION);
}

/**
 * @tc.number: GetLaunchWantForBundle_0100
 * @tc.name: test the GetLaunchWantForBundle
 * @tc.desc: 1. system running normally
 *           2. test GetLaunchWantForBundle
 */
HWTEST_F(BmsBundleMgrProxyTest, GetLaunchWantForBundle_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    int32_t userId = 100;
    Want want;
    auto res = bundleMgrProxy.GetLaunchWantForBundle(bundleName, want, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    bundleName = "com.example.bundleName.test";
    res = bundleMgrProxy.GetLaunchWantForBundle(bundleName, want, userId);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetPermissionDef_0100
 * @tc.name: test the GetPermissionDef
 * @tc.desc: 1. system running normally
 *           2. test GetPermissionDef
 */
HWTEST_F(BmsBundleMgrProxyTest, GetPermissionDef_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string permissionName = "";
    PermissionDef permissionDef;
    auto res = bundleMgrProxy.GetPermissionDef(permissionName, permissionDef);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: CleanBundleCacheFilesAutomatic_0100
 * @tc.name: test the CleanBundleCacheFilesAutomatic
 * @tc.desc: 1. system running normally
 *           2. test CleanBundleCacheFilesAutomatic
 */
HWTEST_F(BmsBundleMgrProxyTest, CleanBundleCacheFilesAutomatic_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    uint64_t cacheSize = 0;
    auto res = bundleMgrProxy.CleanBundleCacheFilesAutomatic(cacheSize);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    cacheSize = 1;
    res = bundleMgrProxy.CleanBundleCacheFilesAutomatic(cacheSize);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_IPC_TRANSACTION);
}

/**
 * @tc.number: CleanBundleCacheFiles_0100
 * @tc.name: test the CleanBundleCacheFiles
 * @tc.desc: 1. system running normally
 *           2. test CleanBundleCacheFiles
 */
HWTEST_F(BmsBundleMgrProxyTest, CleanBundleCacheFiles_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    sptr<ICleanCacheCallback> cleanCacheCallback;
    int32_t userId = 100;
    int32_t appIndex = 1;
    auto res = bundleMgrProxy.CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId, appIndex);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    bundleName = "bundleName";
    res = bundleMgrProxy.CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId, appIndex);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    cleanCacheCallback =  new (std::nothrow) ICleanCacheCallbackTest();
    res = bundleMgrProxy.CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId, appIndex);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_IPC_TRANSACTION);
}

/**
 * @tc.number: CleanBundleDataFiles_0100
 * @tc.name: test the CleanBundleDataFiles
 * @tc.desc: 1. system running normally
 *           2. test CleanBundleDataFiles
 */
HWTEST_F(BmsBundleMgrProxyTest, CleanBundleDataFiles_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName = "";
    int32_t userId = 100;
    int32_t appIndex = 1;
    auto res = bundleMgrProxy.CleanBundleDataFiles(bundleName, userId, appIndex);
    EXPECT_FALSE(res);
    bundleName = "com.example.bundleName.test";
    res = bundleMgrProxy.CleanBundleDataFiles(bundleName, userId, appIndex);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: RegisterBundleStatusCallback_0100
 * @tc.name: test the RegisterBundleStatusCallback
 * @tc.desc: 1. system running normally
 *           2. test RegisterBundleStatusCallback
 */
HWTEST_F(BmsBundleMgrProxyTest, RegisterBundleStatusCallback_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    sptr<IBundleStatusCallback> bundleStatusCallback = nullptr;
    auto res = bundleMgrProxy.RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_FALSE(res);
    bundleStatusCallback = new (std::nothrow) IBundleStatusCallbackTest();
    res = bundleMgrProxy.RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_FALSE(res);
    bundleStatusCallback->SetBundleName("com.example.bundleName.demo");
    EXPECT_FALSE(res);
}

/**
 * @tc.number: RegisterBundleEventCallback_0100
 * @tc.name: test the RegisterBundleEventCallback
 * @tc.desc: 1. system running normally
 *           2. test RegisterBundleEventCallback
 */
HWTEST_F(BmsBundleMgrProxyTest, RegisterBundleEventCallback_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    sptr<IBundleEventCallback> bundleEventCallback = nullptr;
    auto res = bundleMgrProxy.RegisterBundleEventCallback(bundleEventCallback);
    EXPECT_FALSE(res);
    bundleEventCallback = new (std::nothrow) IBundleEventCallbackTest();
    res = bundleMgrProxy.RegisterBundleEventCallback(bundleEventCallback);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: IsBundleInstalled_0100
 * @tc.name: test the IsBundleInstalled
 * @tc.desc: 1. system running normally
 *           2. test IsBundleInstalled
 */
HWTEST_F(BmsBundleMgrProxyTest, IsBundleInstalled_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    BundleMgrProxy bundleMgrProxy(impl);
    bool isBundleInstalled = false;
    ErrCode res = bundleMgrProxy.IsBundleInstalled("", 100, 0, isBundleInstalled);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_IPC_TRANSACTION);
    EXPECT_FALSE(isBundleInstalled);
}

/**
 * @tc.number: ParseStr_0100
 * @tc.name: test the ParseStr
 * @tc.desc: 1. system running normally
 *           2. test ParseStr
 */
HWTEST_F(BmsBundleMgrProxyTest, ParseStr_0100, Function | MediumTest | Level0)
{
    const char *buf = "hello";
    int itemLen = 1;
    int index = 2;
    std::string result;
    auto res = ParseStr(buf, itemLen, index, result);
    EXPECT_TRUE(res);
}
}
}