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

#include <gtest/gtest.h>

#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_service.h"
#include "bundle_option.h"
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_resource_host_impl.h"
#endif

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
class BmsSystemAppPermissionDeniedTest : public testing::Test {
public:
    BmsSystemAppPermissionDeniedTest();
    ~BmsSystemAppPermissionDeniedTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

BmsSystemAppPermissionDeniedTest::BmsSystemAppPermissionDeniedTest()
{}

BmsSystemAppPermissionDeniedTest::~BmsSystemAppPermissionDeniedTest()
{}

void BmsSystemAppPermissionDeniedTest::SetUpTestCase()
{}

void BmsSystemAppPermissionDeniedTest::TearDownTestCase()
{}

void BmsSystemAppPermissionDeniedTest::SetUp()
{}

void BmsSystemAppPermissionDeniedTest::TearDown()
{}

/**
 * @tc.number: BundleMgrHostImpl_0001
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: ProcessCloneBundleInstall SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0001, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames;
    int uid = 1000;
    auto ret = localBundleMgrHostImpl->GetBundlesForUid(uid, bundleNames);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0002
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: ProcessCloneBundleInstall VerifyCallingPermissionsForAll access
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0002, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string appIdentifier = "wrong.app.identifier"; // Example app identifier
    int32_t appIndex = 0;
    uint32_t accessTokenId = 1000; // Example access token ID
    auto ret = localBundleMgrHostImpl->GetAppIdentifierAndAppIndex(accessTokenId, appIdentifier, appIndex);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BundleMgrHostImpl_0003
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: CheckIsSystemAppByUid SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0003, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    int uid = 1000;
    auto ret = localBundleMgrHostImpl->CheckIsSystemAppByUid(uid);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0004
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: QueryAbilityInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0004, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    Want want;
    AbilityInfo abilityInfo;
    int32_t flags = 0;
    int32_t userId = 0;
    sptr<IRemoteObject> callBack = nullptr;

    auto ret = localBundleMgrHostImpl->QueryAbilityInfo(want, flags, userId, abilityInfo, callBack);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0005
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: QueryAbilityInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0005, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    Want want;
    AbilityInfo abilityInfo;
    int32_t flags = 0;
    int32_t userId = 0;
    sptr<IRemoteObject> callBack = nullptr;

    auto ret = localBundleMgrHostImpl->QueryAbilityInfo(want, flags, userId, abilityInfo, callBack);
    EXPECT_EQ(ret, false);
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
/**
 * @tc.number: BundleMgrHostImpl_0006
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: CallAbilityManager callback nullptr
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0006, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    Want want;
    int32_t userId = 0;
    sptr<IRemoteObject> callBack = nullptr;
    int32_t resultCode = 0; // Example result code

    EXPECT_NO_THROW(localBundleMgrHostImpl->CallAbilityManager(resultCode, want, userId, callBack));
    EXPECT_NO_THROW(localBundleMgrHostImpl->SilentInstall(want, userId, callBack));
}

/**
 * @tc.number: BundleMgrHostImpl_0007
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: UpgradeAtomicService SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0007, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    Want want;
    int32_t userId = 0;
    EXPECT_NO_THROW(localBundleMgrHostImpl->UpgradeAtomicService(want, userId));
    int32_t missionId = 0;
    sptr<IRemoteObject> callback = nullptr;
    EXPECT_NO_THROW(localBundleMgrHostImpl->CheckAbilityEnableInstall(want, missionId, userId, callback));
}
#endif // BUNDLE_FRAMEWORK_FREE_INSTALL

/**
 * @tc.number: BundleMgrHostImpl_0008
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: BatchQueryAbilityInfos SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0008, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<Want> wants;
    int32_t flags = 0;
    int32_t userId = 0;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = localBundleMgrHostImpl->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0009
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: CleanBundleCacheFilesGetCleanSize SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0009, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test";
    int32_t userId = 0;
    uint64_t cleanCacheSize = 0;
    auto ret = localBundleMgrHostImpl->CleanBundleCacheFilesGetCleanSize(bundleName, userId, cleanCacheSize);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0010
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: DumpInfos
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0010, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    DumpFlag flag = DumpFlag::DUMP_BUNDLE_LIST;
    std::string bundleName = "com.example.test";
    int32_t userId = 0;
    std::string result;
    EXPECT_NO_THROW(localBundleMgrHostImpl->DumpInfos(flag, bundleName, userId, result));
    EXPECT_NO_THROW(localBundleMgrHostImpl->DumpDebugBundleInfoNames(userId, result));
}

/**
 * @tc.number: BundleMgrHostImpl_0012
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: IsCloneApplicationEnabled SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0012, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t appIndex = 0; // Example app index
    bool isEnable = false;
    auto ret = localBundleMgrHostImpl->IsCloneApplicationEnabled(bundleName, appIndex, isEnable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0013
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: SetCloneApplicationEnabled SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0013, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t appIndex = 0; // Example app index
    bool isEnable = true; // Enable the clone application
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->SetCloneApplicationEnabled(bundleName, appIndex, isEnable, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0014
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: IsCloneAbilityEnabled SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0014, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    AbilityInfo abilityInfo;
    int32_t appIndex = 0; // Example app index
    bool isEnable = false;
    auto ret = localBundleMgrHostImpl->IsCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0015
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: SetCloneAbilityEnabled SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0015, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    AbilityInfo abilityInfo;
    int32_t appIndex = 0; // Example app index
    bool isEnable = true; // Enable the clone ability
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->SetCloneAbilityEnabled(abilityInfo, appIndex, isEnable, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0016
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: BatchGetBundleStats SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0016, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames = {"com.example.test"}; // Example bundle names
    int32_t userId = 0; // Example user ID
    std::vector<BundleStorageStats> bundleStats;
    auto ret = localBundleMgrHostImpl->BatchGetBundleStats(bundleNames, userId, bundleStats);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0017
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetAllBundleCacheStat SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0017, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    sptr<IProcessCacheCallback> processCacheCallback = nullptr;
    auto ret = localBundleMgrHostImpl->GetAllBundleCacheStat(processCacheCallback);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0018
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: CleanAllBundleCache SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0018, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    sptr<IProcessCacheCallback> processCacheCallback = nullptr;
    auto ret = localBundleMgrHostImpl->CleanAllBundleCache(processCacheCallback);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0019
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: BatchGetSpecifiedDistributionType SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0019, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames = {"com.example.test"}; // Example bundle names
    std::vector<BundleDistributionType> specifiedDistributionTypes;
    auto ret = localBundleMgrHostImpl->BatchGetSpecifiedDistributionType(bundleNames, specifiedDistributionTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0020
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: BatchGetAdditionalInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0020, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames = {"com.example.test"}; // Example bundle names
    std::vector<BundleAdditionalInfo> additionalInfos;
    auto ret = localBundleMgrHostImpl->BatchGetAdditionalInfo(bundleNames, additionalInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0021
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetLabelByBundleName SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0021, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t userId = 0; // Example user ID
    std::string result;
    auto ret = localBundleMgrHostImpl->GetLabelByBundleName(bundleName, userId, result);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.number: BundleMgrHostImpl_0022
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetAllBundleLabel SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0022, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    int32_t userId = 0; // Example user ID
    std::string labels;
    auto ret = localBundleMgrHostImpl->GetAllBundleLabel(userId, labels);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0023
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: QueryExtensionAbilityInfosWithTypeName SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0023, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    Want want;
    std::string typeName = "example.type"; // Example type name
    int32_t flags = 0; // Example flags
    int32_t userId = 0; // Example user ID
    std::vector<ExtensionAbilityInfo> extensionInfos;
    auto ret = localBundleMgrHostImpl->QueryExtensionAbilityInfosWithTypeName(
        want, typeName, flags, userId, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0024
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: QueryExtensionAbilityInfosOnlyWithTypeName SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0024, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string typeName = "example.type"; // Example type name
    uint32_t flags = 0; // Example flags
    int32_t userId = 0; // Example user ID
    std::vector<ExtensionAbilityInfo> extensionInfos;
    auto ret = localBundleMgrHostImpl->QueryExtensionAbilityInfosOnlyWithTypeName(
        typeName, flags, userId, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0025
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetRecoverableApplicationInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0025, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<RecoverableApplicationInfo> recoverableApplications;
    auto ret = localBundleMgrHostImpl->GetRecoverableApplicationInfo(recoverableApplications);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0026
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetUninstalledBundleInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0026, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    BundleInfo bundleInfo;
    auto ret = localBundleMgrHostImpl->GetUninstalledBundleInfo(bundleName, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0027
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetAllBundleInfoByDeveloperId SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0027, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string developerId = "example.developer"; // Example developer ID
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetAllBundleInfoByDeveloperId(developerId, bundleInfos, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0028
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetDeveloperIds SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0028, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string appDistributionType = "example.type"; // Example distribution type
    std::vector<std::string> developerIdList;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetDeveloperIds(appDistributionType, developerIdList, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0029
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: SwitchUninstallState SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0029, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    bool state = true; // Example state
    bool isNeedSendNotify = false; // Example notification flag
    auto ret = localBundleMgrHostImpl->SwitchUninstallState(bundleName, state, isNeedSendNotify);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0030
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: QueryAbilityInfoByContinueType SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0030, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    std::string continueType = "example.type"; // Example continue type
    AbilityInfo abilityInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0031
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: QueryCloneAbilityInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0031, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    ElementName element;
    element.SetBundleName("com.example.test");
    element.SetModuleName("entry");
    element.SetAbilityName("com.example.test.MainAbility");
    int32_t flags = 0; // Example flags
    int32_t appIndex = 0; // Example app index
    AbilityInfo abilityInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->QueryCloneAbilityInfo(element, flags, appIndex, abilityInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0032
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetCloneBundleInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0032, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t flags = 0; // Example flags
    int32_t appIndex = 0; // Example app index
    BundleInfo bundleInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetCloneBundleInfo(bundleName, flags, appIndex, bundleInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0033
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetCloneAppIndexes SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0033, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    std::vector<int32_t> appIndexes;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetCloneAppIndexes(bundleName, appIndexes, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0034
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: AddDesktopShortcutInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0034, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    ShortcutInfo shortcutInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->AddDesktopShortcutInfo(shortcutInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0035
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: DeleteDesktopShortcutInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0035, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    ShortcutInfo shortcutInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->DeleteDesktopShortcutInfo(shortcutInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0036
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetAllDesktopShortcutInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0036, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    int32_t userId = 0; // Example user ID
    std::vector<ShortcutInfo> shortcutInfos;
    auto ret = localBundleMgrHostImpl->GetAllDesktopShortcutInfo(userId, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0037
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: IsBundleInstalled SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0037, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t userId = 0; // Example user ID
    int32_t appIndex = 0; // Example app index
    bool isInstalled = false;
    auto ret = localBundleMgrHostImpl->IsBundleInstalled(bundleName, userId, appIndex, isInstalled);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0038
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetCompatibleDeviceType SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0038, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    std::string deviceType;
    auto ret = localBundleMgrHostImpl->GetCompatibleDeviceType(bundleName, deviceType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0039
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetBundleNameByAppId SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0039, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string appId = "com.example.test"; // Example app ID
    std::string bundleName;
    auto ret = localBundleMgrHostImpl->GetBundleNameByAppId(appId, bundleName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0040
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetAllBundleDirs SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0040, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    int32_t userId = 0; // Example user ID
    std::vector<BundleDir> bundleDirs;
    auto ret = localBundleMgrHostImpl->GetAllBundleDirs(userId, bundleDirs);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0041
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: SetAppDistributionTypes SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0041, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::set<AppDistributionTypeEnum> appDistributionTypeEnums;
    auto ret = localBundleMgrHostImpl->SetAppDistributionTypes(appDistributionTypeEnums);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0042
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetPluginAbilityInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0042, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string hostBundleName = "com.example.host"; // Example host bundle name
    std::string pluginBundleName = "com.example.plugin"; // Example plugin bundle name
    std::string pluginModuleName = "PluginModule"; // Example plugin module name
    std::string pluginAbilityName = "PluginAbility"; // Example plugin ability name
    int32_t userId = 0; // Example user ID
    AbilityInfo abilityInfo;
    auto ret = localBundleMgrHostImpl->GetPluginAbilityInfo(
        hostBundleName, pluginBundleName, pluginModuleName, pluginAbilityName, userId, abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0043
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetPluginHapModuleInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0043, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string hostBundleName = "com.example.host"; // Example host bundle name
    std::string pluginBundleName = "com.example.plugin"; // Example plugin bundle name
    std::string pluginModuleName = "PluginModule"; // Example plugin module name
    int32_t userId = 0; // Example user ID
    HapModuleInfo hapModuleInfo;
    auto ret = localBundleMgrHostImpl->GetPluginHapModuleInfo(hostBundleName,
        pluginBundleName, pluginModuleName, userId, hapModuleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0044
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetSandboxDataDir SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0044, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t appIndex = 0; // Example app index
    std::string sandboxDataDir;
    auto ret = localBundleMgrHostImpl->GetSandboxDataDir(bundleName, appIndex, sandboxDataDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0045
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetPluginInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0045, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string hostBundleName = "com.example.host"; // Example host bundle name
    std::string pluginBundleName = "com.example.plugin"; // Example plugin bundle name
    int32_t userId = 0; // Example user ID
    PluginBundleInfo pluginBundleInfo;
    auto ret = localBundleMgrHostImpl->GetPluginInfo(hostBundleName, pluginBundleName, userId, pluginBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0046
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: SwitchUninstallState SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0046, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    bool state = true; // Example state
    auto ret = localBundleMgrHostImpl->SwitchUninstallStateByUserId(bundleName, state, 100);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0047
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: RecoverBackupBundleData SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0047, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "bundle";
    int32_t userId = 100;
    int32_t appIndex = 0;
    auto ret = localBundleMgrHostImpl->RecoverBackupBundleData(bundleName, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0048
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: RemoveBackupBundleData SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0048, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "bundle";
    int32_t userId = 100;
    int32_t appIndex = 0;
    auto ret = localBundleMgrHostImpl->RemoveBackupBundleData(bundleName, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0049
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetBundleInstallStatus SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0049, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "bundle";
    int32_t userId = 100;
    BundleInstallStatus status = BundleInstallStatus::UNKNOWN_STATUS;
    auto ret = localBundleMgrHostImpl->GetBundleInstallStatus(bundleName, userId, status);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
    EXPECT_EQ(status, BundleInstallStatus::UNKNOWN_STATUS);
}

/*
 * @tc.number: BundleMgrHostImpl_0050
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetAllJsonProfile SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0050, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    std::vector<JsonProfileInfo> profileInfos;
    int32_t userId = 100;
    auto ret = localBundleMgrHostImpl->GetAllJsonProfile(ProfileType::EASY_GO_PROFILE, userId, profileInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0051
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: BatchGetCompatibleDeviceType SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0051, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames = {"com.example.test"};
    std::vector<BundleCompatibleDeviceType> compatibleDeviceTypes;
    auto ret = localBundleMgrHostImpl->BatchGetCompatibleDeviceType(bundleNames, compatibleDeviceTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0052
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: AddDynamicShortcutInfos SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0052, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<ShortcutInfo> shortcutInfos;
    int32_t userId = 100;
    auto ret = localBundleMgrHostImpl->AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0053
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: DeleteDynamicShortcutInfos SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0053, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "bundle";
    int32_t userId = 100;
    int32_t appIndex = 0;
    std::vector<std::string> ids;
    auto ret = localBundleMgrHostImpl->DeleteDynamicShortcutInfos(bundleName, appIndex, userId, ids);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0054
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: SetShortcutsEnabled SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleMgrHostImpl_0054, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<ShortcutInfo> shortcutInfos;
    bool isEnabled = false;
    auto ret = localBundleMgrHostImpl->SetShortcutsEnabled(shortcutInfos, isEnabled);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
/**
 * @tc.number: BundleResourceHostImpl_0001
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetBundleResourceInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleResourceHostImpl_0001, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    uint32_t flags = 0; // Example flags
    BundleResourceInfo bundleResourceInfo;
    int32_t appIndex = 0; // Example app index
    auto ret = localBundleResourceHostImpl->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0002
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetLauncherAbilityResourceInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleResourceHostImpl_0002, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    uint32_t flags = 0; // Example flags
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    int32_t appIndex = 0; // Example app index
    auto ret = localBundleResourceHostImpl->GetLauncherAbilityResourceInfo(
        bundleName, flags, launcherAbilityResourceInfo, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0003
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetAllBundleResourceInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleResourceHostImpl_0003, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    uint32_t flags = 0; // Example flags
    std::vector<BundleResourceInfo> bundleResourceInfos;
    auto ret = localBundleResourceHostImpl->GetAllBundleResourceInfo(flags, bundleResourceInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0004
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetAllLauncherAbilityResourceInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleResourceHostImpl_0004, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    uint32_t flags = 0; // Example flags
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    auto ret = localBundleResourceHostImpl->GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0005
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: AddResourceInfoByBundleName SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleResourceHostImpl_0005, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(bundleMgrService, nullptr);
    bundleMgrService->dataMgr_ = std::make_shared<BundleDataMgr>();
    bundleMgrService->dataMgr_->AddUserId(100);

    std::string bundleName = "com.example.test";
    int32_t userId = 100;
    auto ret = localBundleResourceHostImpl->AddResourceInfoByBundleName(bundleName, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0006
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: AddResourceInfoByAbility SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleResourceHostImpl_0006, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(bundleMgrService, nullptr);
    bundleMgrService->dataMgr_ = std::make_shared<BundleDataMgr>();
    bundleMgrService->dataMgr_->AddUserId(100);

    std::string bundleName = "com.example.test"; // Example bundle name
    std::string moduleName = "exampleModule"; // Example module name
    std::string abilityName = "exampleAbility"; // Example ability name
    int32_t userId = 100; // Example user ID
    auto ret = localBundleResourceHostImpl->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0007
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: DeleteResourceInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleResourceHostImpl_0007, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::string key = "exampleKey"; // Example key
    auto ret = localBundleResourceHostImpl->DeleteResourceInfo(key);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0009
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetExtensionAbilityResourceInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleResourceHostImpl_0009, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    ExtensionAbilityType extensionAbilityType = ExtensionAbilityType::INPUTMETHOD; // Example type
    uint32_t flags = 0; // Example flags
    std::vector<LauncherAbilityResourceInfo> extensionAbilityResourceInfo;
    int32_t appIndex = 0; // Example app index
    auto ret = localBundleResourceHostImpl->GetExtensionAbilityResourceInfo(bundleName, extensionAbilityType, flags,
        extensionAbilityResourceInfo, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0010
 * @tc.name: BmsSystemAppPermissionDeniedTest
 * @tc.desc: GetLauncherAbilityResourceInfoList SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, BundleResourceHostImpl_0010, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::vector<BundleOptionInfo> optiontList;
    BundleOptionInfo optiont;
    optiont.bundleName = "com.example.test";
    optiont.abilityName = "com.example.test.MainAbility";
    optiontList.push_back(optiont);

    uint32_t flags = 0; // Example flags
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    auto ret = localBundleResourceHostImpl->GetLauncherAbilityResourceInfoList(
        optiontList, flags, launcherAbilityResourceInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}
#endif

/**
 * @tc.number: GetPluginExtensionInfo_0001
 * @tc.name: GetPluginExtensionInfo
 * @tc.desc: GetPluginExtensionInfo SystemAppPermission Denied
 */
HWTEST_F(BmsSystemAppPermissionDeniedTest, GetPluginExtensionInfo_0001, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string hostBundleName = "com.example.host"; // Example host bundle name
    Want want;
    int32_t userId = 0; // Example user ID
    ExtensionAbilityInfo extensionInfo;
    auto ret = localBundleMgrHostImpl->GetPluginExtensionInfo(hostBundleName, want, userId, extensionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}
}  // namespace OHOS