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

#include <gtest/gtest.h>

#include "bundle_mgr_proxy.h"

#include <numeric>
#include <set>
#include <unistd.h>

#include "ipc_types.h"
#include "parcel.h"
#include "string_ex.h"
#include "parcel_macro.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
#include "default_app_proxy.h"
#endif
#include "hitrace_meter.h"
#include "json_util.h"
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
#include "quick_fix_manager_proxy.h"
#endif
#include "securec.h"

using namespace testing::ext;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace AppExecFwk {

class BundleMgrProxyTest : public testing::Test {
public:
    BundleMgrProxyTest() = default;
    ~BundleMgrProxyTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleMgrProxyTest::SetUpTestCase()
{}

void BundleMgrProxyTest::TearDownTestCase()
{}

void BundleMgrProxyTest::SetUp()
{}

void BundleMgrProxyTest::TearDown()
{}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_0100
 * @tc.name: test the GetBundleArchiveInfoV9
 * @tc.desc: 1. hapFilePath is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_0100, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string hapFilePath;
    int32_t flags = 0;
    BundleInfo bundleInfo;
    auto ret = bundleMgrProxy.GetBundleArchiveInfoV9(hapFilePath, flags, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_0200
 * @tc.name: test the IsCloneApplicationEnabled
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_0200, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    int32_t appIndex = 0;
    bool isEnable = true;
    auto ret = bundleMgrProxy.IsCloneApplicationEnabled(bundleName, appIndex, isEnable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_0300
 * @tc.name: test the SetCloneApplicationEnabled
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_0300, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    int32_t appIndex = 0;
    bool isEnable = true;
    int32_t userId = 0;
    auto ret = bundleMgrProxy.SetCloneApplicationEnabled(bundleName, appIndex, isEnable, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_0400
 * @tc.name: test the IsAbilityEnabled
 * @tc.desc: 1. abilityInfo.bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_0400, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    AbilityInfo abilityInfo;
    bool isEnable = true;
    auto ret = bundleMgrProxy.IsAbilityEnabled(abilityInfo, isEnable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_0500
 * @tc.name: test the IsCloneAbilityEnabled
 * @tc.desc: 1. abilityInfo.bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_0500, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    AbilityInfo abilityInfo;
    int32_t appIndex = 0;
    bool isEnable = true;
    auto ret = bundleMgrProxy.IsCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_0600
 * @tc.name: test the SetAbilityEnabled
 * @tc.desc: 1. abilityInfo.bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_0600, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    AbilityInfo abilityInfo;
    bool isEnable = true;
    int32_t userId = 0;
    auto ret = bundleMgrProxy.SetAbilityEnabled(abilityInfo, isEnable, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_0700
 * @tc.name: test the SetCloneAbilityEnabled
 * @tc.desc: 1. abilityInfo.bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_0700, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    AbilityInfo abilityInfo;
    int32_t appIndex = 0;
    bool isEnable = true;
    int32_t userId = 0;
    auto ret = bundleMgrProxy.SetCloneAbilityEnabled(abilityInfo, appIndex, isEnable, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_0800
 * @tc.name: test the GetBundleUserMgr
 * @tc.desc: 1. GetBundleUserMgr
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_0800, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    auto ret = bundleMgrProxy.GetBundleUserMgr();
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_0900
 * @tc.name: test the GetAppPrivilegeLevel
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_0900, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    int32_t userId = 0;
    auto ret = bundleMgrProxy.GetAppPrivilegeLevel(bundleName, userId);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1000
 * @tc.name: test the IsModuleRemovable
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1000, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string moduleName;
    bool isRemovable = true;
    auto ret = bundleMgrProxy.IsModuleRemovable(bundleName, moduleName, isRemovable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1100
 * @tc.name: test the GetAllDependentModuleNames
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1100, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string moduleName;
    std::vector<std::string> dependentModuleNames;
    auto ret = bundleMgrProxy.GetAllDependentModuleNames(bundleName, moduleName, dependentModuleNames);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1200
 * @tc.name: test the GetModuleUpgradeFlag
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1200, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string moduleName;
    auto ret = bundleMgrProxy.GetModuleUpgradeFlag(bundleName, moduleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1300
 * @tc.name: test the SetModuleUpgradeFlag
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1300, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string moduleName;
    int32_t upgradeFlag = 0;
    auto ret = bundleMgrProxy.SetModuleUpgradeFlag(bundleName, moduleName, upgradeFlag);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1400
 * @tc.name: test the ObtainCallingBundleName
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1400, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    auto ret = bundleMgrProxy.ObtainCallingBundleName(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1500
 * @tc.name: test the GetAllBundleCacheStat
 * @tc.desc: 1. processCacheCallback is nullptr
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1500, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    sptr<IProcessCacheCallback> processCacheCallback = nullptr;
    auto ret = bundleMgrProxy.GetAllBundleCacheStat(processCacheCallback);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1600
 * @tc.name: test the GetExtendResourceManager
 * @tc.desc: 1. GetExtendResourceManager
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1600, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    auto ret = bundleMgrProxy.GetExtendResourceManager();
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1700
 * @tc.name: test the CheckAbilityEnableInstall
 * @tc.desc: 1. CheckAbilityEnableInstall
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1700, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    int32_t missionId = 0;
    int32_t userId = 0;
    sptr<IRemoteObject> callback = nullptr;
    auto ret = bundleMgrProxy.CheckAbilityEnableInstall(want, missionId, userId, callback);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1800
 * @tc.name: test the GetIconById
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1800, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string moduleName;
    uint32_t resId = 0;
    uint32_t density = 0;
    int32_t userId = 0;
    auto ret = bundleMgrProxy.GetIconById(bundleName, moduleName, resId, density, userId);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_1900
 * @tc.name: test the GetAllSharedBundleInfo
 * @tc.desc: 1. GetAllSharedBundleInfo
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_1900, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::vector<SharedBundleInfo> sharedBundles;
    auto ret = bundleMgrProxy.GetAllSharedBundleInfo(sharedBundles);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2000
 * @tc.name: test the GetSharedBundleInfo
 * @tc.desc: 1. GetSharedBundleInfo
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2000, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string moduleName;
    std::vector<SharedBundleInfo> sharedBundles;
    auto ret = bundleMgrProxy.GetSharedBundleInfo(bundleName, moduleName, sharedBundles);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2100
 * @tc.name: test the GetAllProxyDataInfos
 * @tc.desc: 1. GetAllProxyDataInfos
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2100, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::vector<ProxyData> proxyDatas;
    int32_t userId = 0;
    auto ret = bundleMgrProxy.GetAllProxyDataInfos(proxyDatas, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2200
 * @tc.name: test the GetProxyDataInfos
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2200, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string moduleName;
    std::vector<ProxyData> proxyDatas;
    int32_t userId = 0;
    auto ret = bundleMgrProxy.GetProxyDataInfos(bundleName, moduleName, proxyDatas, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2300
 * @tc.name: test the QueryExtensionAbilityInfosWithTypeName
 * @tc.desc: 1. QueryExtensionAbilityInfosWithTypeName
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2300, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    Want want;
    std::string extensionTypeName;
    int32_t flag = 0;
    int32_t userId = 0;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    auto ret = bundleMgrProxy.QueryExtensionAbilityInfosWithTypeName(
        want, extensionTypeName, flag, userId, extensionInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2400
 * @tc.name: test the ResetAOTCompileStatus
 * @tc.desc: 1. bundleName is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2400, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string moduleName;
    int32_t triggerMode = 0;
    auto ret = bundleMgrProxy.ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2500
 * @tc.name: test the UpdateAppEncryptedStatus
 * @tc.desc: 1. UpdateAppEncryptedStatus
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2500, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    bool isExisted = true;
    int32_t appIndex = 0;
    auto ret = bundleMgrProxy.UpdateAppEncryptedStatus(bundleName, isExisted, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_IPC_TRANSACTION);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2600
 * @tc.name: test the GetOdid
 * @tc.desc: 1. GetOdid
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2600, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string odid;
    auto ret = bundleMgrProxy.GetOdid(odid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2700
 * @tc.name: test the QueryAbilityInfoByContinueType
 * @tc.desc: 1. QueryAbilityInfoByContinueType
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2700, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string continueType;
    AbilityInfo abilityInfo;
    int32_t userId = 0;
    auto ret = bundleMgrProxy.QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2800
 * @tc.name: test the GetOdidByBundleName
 * @tc.desc: 1. GetOdidByBundleName
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2800, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string odid;
    auto ret = bundleMgrProxy.GetOdidByBundleName(bundleName, odid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_2900
 * @tc.name: test the GetCompatibleDeviceType
 * @tc.desc: 1. GetCompatibleDeviceType
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_2900, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string bundleName;
    std::string deviceType;
    auto ret = bundleMgrProxy.GetCompatibleDeviceType(bundleName, deviceType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_IPC_TRANSACTION);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_3000
 * @tc.name: test the GetBundleNameByAppId
 * @tc.desc: 1. appId is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_3000, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string appId;
    std::string bundleName;
    auto ret = bundleMgrProxy.GetBundleNameByAppId(appId, bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_3100
 * @tc.name: test the GetBundleArchiveInfoExt
 * @tc.desc: 1. params valid
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_3100, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string hapFilePath = "test.hap";
    int32_t fd = 123;
    int flags = 0;
    BundleInfo bundleInfo;
    auto result = bundleMgrProxy.GetBundleArchiveInfoExt(hapFilePath, fd, flags, bundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: Bundle_Mgr_Proxy_Test_3200
 * @tc.name: test the GetBundleArchiveInfoExt
 * @tc.desc: 1. hapPath is empty
 */
HWTEST_F(BundleMgrProxyTest, Bundle_Mgr_Proxy_Test_3200, Function | SmallTest | Level0)
{
    sptr<IRemoteObject> impl = nullptr;
    BundleMgrProxy bundleMgrProxy(impl);
    std::string hapFilePath;
    int32_t fd = 123;
    int flags = 0;
    BundleInfo bundleInfo;
    auto result = bundleMgrProxy.GetBundleArchiveInfoExt(hapFilePath, fd, flags, bundleInfo);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
}
} // AppExecFwk
} // OHOS
