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
#include "verify_manager_host_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
class VerifyCallingPermissionsForAllDeniedTest : public testing::Test {
public:
    VerifyCallingPermissionsForAllDeniedTest();
    ~VerifyCallingPermissionsForAllDeniedTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

VerifyCallingPermissionsForAllDeniedTest::VerifyCallingPermissionsForAllDeniedTest()
{}

VerifyCallingPermissionsForAllDeniedTest::~VerifyCallingPermissionsForAllDeniedTest()
{}

void VerifyCallingPermissionsForAllDeniedTest::SetUpTestCase()
{}

void VerifyCallingPermissionsForAllDeniedTest::TearDownTestCase()
{}

void VerifyCallingPermissionsForAllDeniedTest::SetUp()
{}

void VerifyCallingPermissionsForAllDeniedTest::TearDown()
{}

/**
 * @tc.number: BundleMgrHostImpl_0001
 * @tc.name: BatchGetBundleInfo
 * @tc.desc: BatchGetBundleInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0001, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames;
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = 0;
    int32_t flags = 0;

    auto ret = localBundleMgrHostImpl->BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0002
 * @tc.name: GetBundlesForUid
 * @tc.desc: GetBundlesForUid VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0002, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames;
    int uid = 1000;
    auto ret = localBundleMgrHostImpl->GetBundlesForUid(uid, bundleNames);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0003
 * @tc.name: GetBundleGids
 * @tc.desc: GetBundleGids VerifyCallingPermissionsForAll & IsBundleSelfCalling denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0003, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<int> gids;
    std::string bundleName = "com.example.test";
    auto ret = localBundleMgrHostImpl->GetBundleGids(bundleName, gids);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0004
 * @tc.name: GetBundleGidsByUid
 * @tc.desc: GetBundleGidsByUid VerifyCallingPermissionsForAll & IsBundleSelfCalling denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0004, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<int> gids;
    std::string bundleName = "com.example.test";
    int uid = 1000;
    auto ret = localBundleMgrHostImpl->GetBundleGidsByUid(bundleName, uid, gids);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0005
 * @tc.name: CheckIsSystemAppByUid
 * @tc.desc: CheckIsSystemAppByUid VerifyCallingPermissionsForAll & IsBundleSelfCalling denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0005, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    int uid = 1000;
    auto ret = localBundleMgrHostImpl->CheckIsSystemAppByUid(uid);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0006
 * @tc.name: GetAbilityInfos
 * @tc.desc: GetAbilityInfos VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0006, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string uri = "com.example.test";
    uint32_t flags = 0;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = localBundleMgrHostImpl->GetAbilityInfos(uri, flags, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0007
 * @tc.name: CleanBundleCacheFilesAutomatic
 * @tc.desc: CleanBundleCacheFilesAutomatic VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0007, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    uint64_t cacheSize = 1024 * 1024; // 1MB
    auto ret = localBundleMgrHostImpl->CleanBundleCacheFilesAutomatic(cacheSize);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0008
 * @tc.name: CompileProcessAOT
 * @tc.desc: CompileProcessAOT VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0008, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test";
    std::string compileMode = "release";
    bool isAllBundle = false;
    std::vector<std::string> compileResults;
    auto ret = localBundleMgrHostImpl->CompileProcessAOT(bundleName, compileMode, isAllBundle, compileResults);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0009
 * @tc.name: CopyAp
 * @tc.desc: CopyAp VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0009, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test";
    bool isAllBundle = false;
    std::vector<std::string> results;
    auto ret = localBundleMgrHostImpl->CopyAp(bundleName, isAllBundle, results);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0011
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: BatchQueryAbilityInfos VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0011, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t appIndex = 0; // Example app index
    bool isEnable = true; // Enable the clone application
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->SetCloneApplicationEnabled(bundleName, appIndex, isEnable, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0012
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: SetCloneAbilityEnabled SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0012, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    AbilityInfo abilityInfo;
    int32_t appIndex = 0; // Example app index
    bool isEnable = true; // Enable the clone ability
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->SetCloneAbilityEnabled(abilityInfo, appIndex, isEnable, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0013
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetBundleInstaller
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0013, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    EXPECT_NO_THROW(localBundleMgrHostImpl->GetBundleInstaller());
}

/*
 * @tc.number: BundleMgrHostImpl_0014
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetUidByDebugBundleName VerifyCallingPermissionsForAll & IsBundleSelfCalling denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0014, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int userId = 0; // Example user ID
    int ret = localBundleMgrHostImpl->GetUidByDebugBundleName(bundleName, userId);
    EXPECT_EQ(ret,  Constants::INVALID_UID);
}

/*
 * @tc.number: BundleMgrHostImpl_0015
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: BatchGetBundleStats VerifyCallingPermissionsForAll & IsBundleSelfCalling denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0015, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames = {"com.example.test"}; // Example bundle names
    int32_t userId = 0; // Example user ID
    std::vector<BundleStorageStats> bundleStats;
    auto ret = localBundleMgrHostImpl->BatchGetBundleStats(bundleNames, userId, bundleStats);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0016
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetAllBundleCacheStat VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0016, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    sptr<IProcessCacheCallback> processCacheCallback = nullptr;
    auto ret = localBundleMgrHostImpl->GetAllBundleCacheStat(processCacheCallback);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0017
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: CleanAllBundleCache VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0017, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    sptr<IProcessCacheCallback> processCacheCallback = nullptr;
    auto ret = localBundleMgrHostImpl->CleanAllBundleCache(processCacheCallback);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/*
 * @tc.number: BundleMgrHostImpl_0018
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetStringById VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0018, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    std::string moduleName = "module"; // Example module name
    uint32_t resId = 100; // Example resource ID
    int32_t userId = 0; // Example user ID
    std::string localeInfo = "en-US"; // Example locale info

    auto ret = localBundleMgrHostImpl->GetStringById(bundleName, moduleName, resId, userId, localeInfo);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.number: BundleMgrHostImpl_0019
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: BatchGetSpecifiedDistributionType VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0019, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames = {"com.example.test"}; // Example bundle names
    std::vector<BundleDistributionType> specifiedDistributionTypes;
    auto ret = localBundleMgrHostImpl->BatchGetSpecifiedDistributionType(bundleNames, specifiedDistributionTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0020
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: BatchGetAdditionalInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0020, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames = {"com.example.test"}; // Example bundle names
    std::vector<BundleAdditionalInfo> additionalInfos;
    auto ret = localBundleMgrHostImpl->BatchGetAdditionalInfo(bundleNames, additionalInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0021
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: QueryExtensionAbilityInfosWithTypeName VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0021, TestSize.Level1)
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
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0022
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: QueryExtensionAbilityInfosOnlyWithTypeName VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0022, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string typeName = "example.type"; // Example type name
    uint32_t flags = 0; // Example flags
    int32_t userId = 0; // Example user ID
    std::vector<ExtensionAbilityInfo> extensionInfos;
    auto ret = localBundleMgrHostImpl->QueryExtensionAbilityInfosOnlyWithTypeName(
        typeName, flags, userId, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0023
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetJsonProfile VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0023, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    ProfileType profileType = ProfileType::INTENT_PROFILE;
    std::string bundleName = "com.example.test"; // Example bundle name
    std::string moduleName = "module"; // Example module name
    std::string profile;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetJsonProfile(profileType, bundleName, moduleName, profile, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0024
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: MigrateData VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0024, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> sourcePaths = {"/data/data/com.example.test"}; // Example source paths
    std::string destinationPath = "/data/data/destination"; // Example destination path
    auto ret = localBundleMgrHostImpl->MigrateData(sourcePaths, destinationPath);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0025
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: MigrateDataParameterCheck VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0025, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> sourcePaths = {"/data/data/com.example.test"}; // Example source paths
    std::string destinationPath = "/data/data/destination"; // Example destination path
    EXPECT_NO_THROW(localBundleMgrHostImpl->MigrateDataParameterCheck(sourcePaths, destinationPath));
}

/**
 * @tc.number: BundleMgrHostImpl_0026
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: CheckSandboxPath VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0026, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> sourcePaths = {"/data/data/com.example.test"}; // Example source paths
    std::string destinationPath = "/data/data/destination"; // Example destination path
    EXPECT_NO_THROW(localBundleMgrHostImpl->CheckSandboxPath(sourcePaths, destinationPath));
}

/**
 * @tc.number: BundleMgrHostImpl_0027
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: MigrateDataUserAuthentication VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0027, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    EXPECT_NO_THROW(localBundleMgrHostImpl->MigrateDataUserAuthentication());
    EXPECT_NO_THROW(localBundleMgrHostImpl->GetBundleResourceProxy());
}

/**
 * @tc.number: BundleMgrHostImpl_0028
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetPreferableBundleInfoFromHapPaths VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0028, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> hapPaths = {"/data/app/com.example.test.hap"}; // Example hap paths
    BundleInfo bundleInfo;
    auto ret = localBundleMgrHostImpl->GetPreferableBundleInfoFromHapPaths(hapPaths, bundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0029
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetRecoverableApplicationInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0029, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<RecoverableApplicationInfo> recoverableApplications;
    auto ret = localBundleMgrHostImpl->GetRecoverableApplicationInfo(recoverableApplications);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0030
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetUninstalledBundleInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0030, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    BundleInfo bundleInfo;
    auto ret = localBundleMgrHostImpl->GetUninstalledBundleInfo(bundleName, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0031
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetAllBundleInfoByDeveloperId VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0031, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string developerId = "example.developer"; // Example developer ID
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetAllBundleInfoByDeveloperId(developerId, bundleInfos, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0032
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetDeveloperIds VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0032, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string appDistributionType = "example.type"; // Example distribution type
    std::vector<std::string> developerIdList;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetDeveloperIds(appDistributionType, developerIdList, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0033
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: SwitchUninstallState VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0033, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    bool state = true; // Example state
    bool isNeedSendNotify = false; // Example notification flag
    auto ret = localBundleMgrHostImpl->SwitchUninstallState(bundleName, state, isNeedSendNotify);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0034
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: QueryAbilityInfoByContinueType VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0034, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    std::string continueType = "example.type"; // Example continue type
    AbilityInfo abilityInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0035
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: QueryCloneAbilityInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0035, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    ElementName optiont;
    optiont.SetBundleName("com.example.test");
    optiont.SetModuleName("entry");
    optiont.SetAbilityName("com.example.test.MainAbility");
    int32_t flags = 0; // Example flags
    int32_t appIndex = 0; // Example app index
    AbilityInfo abilityInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->QueryCloneAbilityInfo(optiont, flags, appIndex, abilityInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0036
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetCloneBundleInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0036, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t flags = 0; // Example flags
    int32_t appIndex = 0; // Example app index
    BundleInfo bundleInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetCloneBundleInfo(bundleName, flags, appIndex, bundleInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0037
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetCloneBundleInfoExt VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0037, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    uint32_t flags = 0; // Example flags
    int32_t appIndex = 0; // Example app index
    int32_t userId = 0; // Example user ID
    BundleInfo bundleInfo;
    EXPECT_NO_THROW(localBundleMgrHostImpl->GetCloneBundleInfoExt(bundleName, flags, appIndex, userId, bundleInfo));
}

/**
 * @tc.number: BundleMgrHostImpl_0038
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetCloneAppIndexes VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0038, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    std::vector<int32_t> appIndexes;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetCloneAppIndexes(bundleName, appIndexes, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0039
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: QueryCloneExtensionAbilityInfoWithAppIndex VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0039, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    ElementName optiont;
    optiont.SetBundleName("com.example.test");
    optiont.SetModuleName("entry");
    optiont.SetAbilityName("com.example.test.MainAbility");
    int32_t flags = 0; // Example flags
    int32_t appIndex = 0; // Example app index
    ExtensionAbilityInfo extensionAbilityInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->QueryCloneExtensionAbilityInfoWithAppIndex(
        optiont, flags, appIndex, extensionAbilityInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0040
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetSignatureInfoByBundleName VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0040, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    SignatureInfo signatureInfo;
    EXPECT_NO_THROW(localBundleMgrHostImpl->GetSignatureInfoByBundleName(bundleName, signatureInfo));
}

/**
 * @tc.number: BundleMgrHostImpl_0041
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetSignatureInfoByUid VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0041, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    int32_t uid = 1000; // Example UID
    SignatureInfo signatureInfo;
    auto ret = localBundleMgrHostImpl->GetSignatureInfoByUid(uid, signatureInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0042
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: AddDesktopShortcutInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0042, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    ShortcutInfo shortcutInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->AddDesktopShortcutInfo(shortcutInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0043
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: DeleteDesktopShortcutInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0043, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    ShortcutInfo shortcutInfo;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->DeleteDesktopShortcutInfo(shortcutInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0044
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetAllDesktopShortcutInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0044, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    int32_t userId = 0; // Example user ID
    std::vector<ShortcutInfo> shortcutInfos;
    auto ret = localBundleMgrHostImpl->GetAllDesktopShortcutInfo(userId, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0045
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetOdidByBundleName VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0045, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    std::string odid;
    auto ret = localBundleMgrHostImpl->GetOdidByBundleName(bundleName, odid);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0046
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetContinueBundleNames VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0046, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string continueBundleName = "com.example.test"; // Example continue bundle name
    std::vector<std::string> bundleNames;
    int32_t userId = 0; // Example user ID
    auto ret = localBundleMgrHostImpl->GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0047
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetCompatibleDeviceType VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0047, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    std::string deviceType;
    auto ret = localBundleMgrHostImpl->GetCompatibleDeviceType(bundleName, deviceType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0048
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetBundleNameByAppId VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0048, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string appId = "com.example.test"; // Example app ID
    std::string bundleName;
    auto ret = localBundleMgrHostImpl->GetBundleNameByAppId(appId, bundleName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0049
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetDirByBundleNameAndAppIndex VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0049, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t appIndex = 0; // Example app index
    std::string dataDir;
    EXPECT_NO_THROW(localBundleMgrHostImpl->GetDirByBundleNameAndAppIndex(bundleName, appIndex, dataDir));
}

/**
 * @tc.number: BundleMgrHostImpl_0050
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetAllBundleDirs VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0050, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    int32_t userId = 0; // Example user ID
    std::vector<BundleDir> bundleDirs;
    auto ret = localBundleMgrHostImpl->GetAllBundleDirs(userId, bundleDirs);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0051
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: SetAppDistributionTypes VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0051, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::set<AppDistributionTypeEnum> appDistributionTypeEnums =
        { AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_APP_GALLERY };
    auto ret = localBundleMgrHostImpl->SetAppDistributionTypes(appDistributionTypeEnums);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0052
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetPluginAbilityInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0052, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string hostBundleName = "com.example.host"; // Example host bundle name
    std::string pluginBundleName = "com.example.plugin"; // Example plugin bundle name
    std::string pluginModuleName = "pluginModule"; // Example plugin module name
    std::string pluginAbilityName = "PluginAbility"; // Example plugin ability name
    int32_t userId = 0; // Example user ID
    AbilityInfo abilityInfo;
    auto ret = localBundleMgrHostImpl->GetPluginAbilityInfo(
        hostBundleName, pluginBundleName, pluginModuleName, pluginAbilityName, userId, abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0053
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetPluginHapModuleInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0053, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string hostBundleName = "com.example.host"; // Example host bundle name
    std::string pluginBundleName = "com.example.plugin"; // Example plugin bundle name
    std::string pluginModuleName = "pluginModule"; // Example plugin module name
    int32_t userId = 0; // Example user ID
    HapModuleInfo hapModuleInfo;
    auto ret = localBundleMgrHostImpl->GetPluginHapModuleInfo(hostBundleName,
        pluginBundleName, pluginModuleName, userId, hapModuleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0054
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: RegisterPluginEventCallback VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0054, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    sptr<IBundleEventCallback> pluginEventCallback = nullptr; // Example callback
    EXPECT_NO_THROW(localBundleMgrHostImpl->RegisterPluginEventCallback(pluginEventCallback));
    EXPECT_NO_THROW(localBundleMgrHostImpl->UnregisterPluginEventCallback(pluginEventCallback));
}

/**
 * @tc.number: BundleMgrHostImpl_0055
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetSandboxDataDir VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0055, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    int32_t appIndex = 0; // Example app index
    std::string sandboxDataDir;
    auto ret = localBundleMgrHostImpl->GetSandboxDataDir(bundleName, appIndex, sandboxDataDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0056
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GreatOrEqualTargetAPIVersion VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0056, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    int32_t platformVersion = 10; // Example platform version
    int32_t minorVersion = 0; // Example minor version
    int32_t patchVersion = 0; // Example patch version
    EXPECT_NO_THROW(localBundleMgrHostImpl->GreatOrEqualTargetAPIVersion(platformVersion, minorVersion, patchVersion));
}

/**
 * @tc.number: BundleMgrHostImpl_0057
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetPluginInfo VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0057, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string hostBundleName = "com.example.host"; // Example host bundle name
    std::string pluginBundleName = "com.example.plugin"; // Example plugin bundle name
    int32_t userId = 0; // Example user ID
    PluginBundleInfo pluginBundleInfo;
    auto ret = localBundleMgrHostImpl->GetPluginInfo(hostBundleName, pluginBundleName, userId, pluginBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0058
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: SwitchUninstallStateByUserId VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0058, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    bool state = true; // Example state
    auto ret = localBundleMgrHostImpl->SwitchUninstallStateByUserId(bundleName, state, 100);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0059
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: BatchGetCompatibleDeviceType VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0059, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<std::string> bundleNames = {"com.example.test"};
    std::vector<BundleCompatibleDeviceType> compatibleDeviceTypes;
    auto ret = localBundleMgrHostImpl->BatchGetCompatibleDeviceType(bundleNames, compatibleDeviceTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0060
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: AddDynamicShortcutInfos VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0060, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<ShortcutInfo> shortcutInfos;
    int32_t userId = 100;
    auto ret = localBundleMgrHostImpl->AddDynamicShortcutInfos(shortcutInfos, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0061
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: DeleteDynamicShortcutInfos VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0061, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::string bundleName = "bundle";
    int32_t userId = 100;
    int32_t appIndex = 0;
    std::vector<std::string> ids;
    auto ret = localBundleMgrHostImpl->DeleteDynamicShortcutInfos(bundleName, appIndex, userId, ids);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_0062
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: SetShortcutsEnabled VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleMgrHostImpl_0062, TestSize.Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);

    std::vector<ShortcutInfo> shortcutInfos;
    bool isEnabled = false;
    auto ret = localBundleMgrHostImpl->SetShortcutsEnabled(shortcutInfos, isEnabled);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
/**
 * @tc.number: VerifyManagerHostImpl_0001
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: Verify VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, VerifyManagerHostImpl_0001, TestSize.Level1)
{
    std::shared_ptr<VerifyManagerHostImpl> localVerifyManagerHostImpl = std::make_shared<VerifyManagerHostImpl>();
    ASSERT_NE(localVerifyManagerHostImpl, nullptr);

    uint32_t code = 100; // Example code
    EXPECT_NO_THROW(localVerifyManagerHostImpl->CallbackEnter(code));
    int32_t result = 0;
    EXPECT_NO_THROW(localVerifyManagerHostImpl->CallbackExit(code, result));

    // test ErrCode VerifyManagerHostImpl::Verify(const std::vector<std::string> &abcPaths, int32_t &funcResult)
    std::vector<std::string> abcPaths = {"/data/abc/example.abc"};
    int32_t funcResult = 0;
    auto ret = localVerifyManagerHostImpl->Verify(abcPaths, funcResult);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(funcResult, ERR_BUNDLE_MANAGER_VERIFY_PERMISSION_DENIED);
}

/**
 * @tc.number: VerifyManagerHostImpl_0002
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: VerifyDeleteAbcPermission VerifyCallingPermissionsForAll denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, VerifyManagerHostImpl_0002, TestSize.Level1)
{
    std::shared_ptr<VerifyManagerHostImpl> localVerifyManagerHostImpl = std::make_shared<VerifyManagerHostImpl>();
    ASSERT_NE(localVerifyManagerHostImpl, nullptr);

    std::string path = "/data/abc/example.abc"; // Example path
    auto ret = localVerifyManagerHostImpl->VerifyDeleteAbcPermission(path);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_VERIFY_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0001
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetBundleResourceInfo SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0001, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    uint32_t flags = 0; // Example flags
    BundleResourceInfo bundleResourceInfo;
    int32_t appIndex = 0; // Example app index
    auto ret = localBundleResourceHostImpl->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0002
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetLauncherAbilityResourceInfo SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0002, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    uint32_t flags = 0; // Example flags
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    int32_t appIndex = 0; // Example app index
    auto ret = localBundleResourceHostImpl->GetLauncherAbilityResourceInfo(
        bundleName, flags, launcherAbilityResourceInfo, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0003
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetAllBundleResourceInfo SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0003, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    uint32_t flags = 0; // Example flags
    std::vector<BundleResourceInfo> bundleResourceInfos;
    auto ret = localBundleResourceHostImpl->GetAllBundleResourceInfo(flags, bundleResourceInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0004
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetAllLauncherAbilityResourceInfo SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0004, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    uint32_t flags = 0; // Example flags
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    auto ret = localBundleResourceHostImpl->GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0005
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: AddResourceInfoByBundleName SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0005, TestSize.Level1)
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
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0006
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: AddResourceInfoByAbility SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0006, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(bundleMgrService, nullptr);
    bundleMgrService->dataMgr_ = std::make_shared<BundleDataMgr>();
    bundleMgrService->dataMgr_->AddUserId(100);

    std::string bundleName = "com.example.test";
    std::string moduleName = "exampleModule";
    std::string abilityName = "MainAbility";
    int32_t userId = 100;
    auto ret = localBundleResourceHostImpl->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0007
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: userId invalid
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0007, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(bundleMgrService, nullptr);
    bundleMgrService->dataMgr_ = std::make_shared<BundleDataMgr>();

    std::string bundleName = "com.example.test";
    std::string moduleName = "exampleModule";
    std::string abilityName = "MainAbility";
    int32_t userId = 1234567; // Invalid user ID
    auto ret = localBundleResourceHostImpl->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BundleResourceHostImpl_0008
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: DeleteResourceInfo SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0008, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::string key = "exampleKey"; // Example key
    auto ret = localBundleResourceHostImpl->DeleteResourceInfo(key);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0009
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetExtensionAbilityResourceInfo SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0009, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::string bundleName = "com.example.test"; // Example bundle name
    ExtensionAbilityType extensionAbilityType = ExtensionAbilityType::INPUTMETHOD; // Example extension ability type
    uint32_t flags = 0; // Example flags
    std::vector<LauncherAbilityResourceInfo> extensionAbilityResourceInfo;
    int32_t appIndex = 0; // Example app index
    auto ret = localBundleResourceHostImpl->GetExtensionAbilityResourceInfo(bundleName, extensionAbilityType, flags,
        extensionAbilityResourceInfo, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleResourceHostImpl_0010
 * @tc.name: VerifyCallingPermissionsForAllDeniedTest
 * @tc.desc: GetLauncherAbilityResourceInfoList SystemAppPermission Denied
 */
HWTEST_F(VerifyCallingPermissionsForAllDeniedTest, BundleResourceHostImpl_0010, TestSize.Level1)
{
    std::shared_ptr<BundleResourceHostImpl> localBundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(localBundleResourceHostImpl, nullptr);

    std::vector<BundleOptionInfo> optiontList;
    BundleOptionInfo optiont;
    optiont.bundleName = "com.example.test";
    optiont.abilityName = "com.example.test.MainAbility";
    optiontList.push_back(optiont);
    uint32_t flags = 0; // Example flags
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    auto ret = localBundleResourceHostImpl->GetLauncherAbilityResourceInfoList(
        optiontList, flags, launcherAbilityResourceInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}
#endif
} // namespace OHOS