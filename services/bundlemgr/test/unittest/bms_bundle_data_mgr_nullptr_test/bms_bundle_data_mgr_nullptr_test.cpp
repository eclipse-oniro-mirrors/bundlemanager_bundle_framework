/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>

#include "app_provision_info_manager.h"
#include "base_bundle_installer.h"
#include "bundle_cache_mgr.h"
#include "bundle_clone_installer.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_sandbox_installer.h"
#include "data_group_info.h"
#include "hmp_bundle_installer.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "parameters.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;

namespace OHOS {
namespace {
}  // namespace

class BmsBundleDataMgrNullptrTest : public testing::Test {
public:
    BmsBundleDataMgrNullptrTest();
    ~BmsBundleDataMgrNullptrTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleDataMgrNullptrTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleDataMgrNullptrTest::BmsBundleDataMgrNullptrTest()
{}

BmsBundleDataMgrNullptrTest::~BmsBundleDataMgrNullptrTest()
{}

void BmsBundleDataMgrNullptrTest::SetUpTestCase()
{}

void BmsBundleDataMgrNullptrTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleDataMgrNullptrTest::SetUp()
{
}

void BmsBundleDataMgrNullptrTest::TearDown()
{
}

/**
 * @tc.number: HmpBundleInstaller_0001
 * @tc.name: test GetRequiredUserIds
 * @tc.desc: 1.Test GetRequiredUserIds the HmpBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, HmpBundleInstaller_0001, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::string bundleName;
    std::set<int32_t> userIds;
    bool ret = installer.GetRequiredUserIds(bundleName, userIds);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: HmpBundleInstaller_0002
 * @tc.name: test InstallNormalAppInHmp
 * @tc.desc: 1.Test InstallNormalAppInHmp the HmpBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, HmpBundleInstaller_0002, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::string bundleDir = "/module_update/xxx";
    auto ret = installer.InstallNormalAppInHmp(bundleDir, true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HmpBundleInstaller_0003
 * @tc.name: test CheckAppIsUpdatedByUser
 * @tc.desc: 1.Test CheckAppIsUpdatedByUser the HmpBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, HmpBundleInstaller_0003, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::string bundleName = "";
    auto ret = installer.CheckAppIsUpdatedByUser(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: HmpBundleInstaller_0004
 * @tc.name: test CheckAppIsUpdatedByUser
 * @tc.desc: 1.Test CheckAppIsUpdatedByUser the HmpBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, HmpBundleInstaller_0004, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::string bundleName = "xxx";
    auto ret = installer.CheckAppIsUpdatedByUser(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: HmpBundleInstaller_0005
 * @tc.name: test UpdateInnerBundleInfo
 * @tc.desc: 1.Test UpdateInnerBundleInfo the HmpBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, HmpBundleInstaller_0005, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::string bundleName = "xxx";
    std::unordered_map<std::string, InnerBundleInfo> infos;
    installer.UpdateInnerBundleInfo(bundleName, infos);
    EXPECT_EQ(infos.empty(), true);
}

/**
 * @tc.number: HmpBundleInstaller_0006
 * @tc.name: test UninstallSystemBundle
 * @tc.desc: 1.Test UninstallSystemBundle the HmpBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, HmpBundleInstaller_0006, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::string bundleName = "xxx";
    std::string modulePackage = "";
    auto ret = installer.UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: HmpBundleInstaller_0007
 * @tc.name: test CheckUninstallSystemHsp
 * @tc.desc: 1.Test CheckUninstallSystemHsp the HmpBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, HmpBundleInstaller_0007, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::string bundleName = "xxx";
    installer.CheckUninstallSystemHsp(bundleName);
    EXPECT_EQ(bundleName.empty(), false);
}

/**
 * @tc.number: HmpBundleInstaller_0008
 * @tc.name: test UpdatePreInfoInDb
 * @tc.desc: 1.Test UpdatePreInfoInDb the HmpBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, HmpBundleInstaller_0008, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::string bundleName = "xxx";
    std::unordered_map<std::string, InnerBundleInfo> infos;
    installer.UpdatePreInfoInDb(bundleName, infos);
    EXPECT_EQ(infos.empty(), true);
}

/**
 * @tc.number: HmpBundleInstaller_0009
 * @tc.name: test GetIsRemovable
 * @tc.desc: 1.Test GetIsRemovable the HmpBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, HmpBundleInstaller_0009, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::string bundleName = "xxx";
    auto ret = installer.GetIsRemovable(bundleName);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundleCacheMgr_0001
 * @tc.name: test GetBundleCachePath
 * @tc.desc: 1.Test GetBundleCachePath the BundleCacheMgr
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BundleCacheMgr_0001, Function | MediumTest | Level1)
{
    BundleCacheMgr bundleCacheMgr;
    int32_t userId = 0;
    int32_t appIndex = 1;
    std::string bundleName = "xxx";
    std::vector<std::string> moduleNameList;
    auto pathVec = bundleCacheMgr.GetBundleCachePath(bundleName, userId, appIndex, moduleNameList);
    EXPECT_EQ(pathVec.empty(), false);
}

/**
 * @tc.number: BundleCacheMgr_0002
 * @tc.name: test GetAllBundleCacheStat
 * @tc.desc: 1.Test GetAllBundleCacheStat the BundleCacheMgr
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BundleCacheMgr_0002, Function | MediumTest | Level1)
{
    BundleCacheMgr bundleCacheMgr;
    sptr<IProcessCacheCallback> processCacheCallback;
    auto ret = bundleCacheMgr.GetAllBundleCacheStat(processCacheCallback);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleCacheMgr_0002
 * @tc.name: test CleanAllBundleCache
 * @tc.desc: 1.Test CleanAllBundleCache the BundleCacheMgr
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BundleCacheMgr_0003, Function | MediumTest | Level1)
{
    BundleCacheMgr bundleCacheMgr;
    sptr<IProcessCacheCallback> processCacheCallback;
    auto ret = bundleCacheMgr.CleanAllBundleCache(processCacheCallback);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BaseBundleInstaller_0001
 * @tc.name: test UninstallHspBundle
 * @tc.desc: 1.Test UninstallHspBundle the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0001, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    std::string uninstallDir;
    std::string bundleName = "xxx";
    auto ret = installer.UninstallHspBundle(uninstallDir, bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BaseBundleInstaller_0002
 * @tc.name: test RemoveInfo
 * @tc.desc: 1.Test RemoveInfo the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0002, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    std::string bundleName;
    std::string packageName;
    installer.RemoveInfo(bundleName, packageName);
    EXPECT_TRUE(bundleName.empty());
    EXPECT_TRUE(packageName.empty());
}

/**
 * @tc.number: BaseBundleInstaller_0003
 * @tc.name: test RollBackModuleInfo
 * @tc.desc: 1.Test RollBackModuleInfo the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0003, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    std::string bundleName;
    InnerBundleInfo oldInfo;
    installer.RollBackModuleInfo(bundleName, oldInfo);
    EXPECT_TRUE(bundleName.empty());
    EXPECT_TRUE(oldInfo.GetBundleName().empty());
}

/**
 * @tc.number: BaseBundleInstaller_0004
 * @tc.name: test DeleteRouterInfo
 * @tc.desc: 1.Test DeleteRouterInfo the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0004, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    std::string bundleName;
    std::string moduleName;
    installer.DeleteRouterInfo(bundleName, moduleName);
    EXPECT_TRUE(bundleName.empty());
    EXPECT_TRUE(moduleName.empty());
}

/**
 * @tc.number: BaseBundleInstaller_0005
 * @tc.name: test RemoveBundle
 * @tc.desc: 1.Test RemoveBundle the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0005, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    bool isKeepData = false;
    bool async = false;
    installer.RemoveBundle(info, isKeepData, async);
    EXPECT_TRUE(info.GetBundleName().empty());
}

/**
 * @tc.number: BaseBundleInstaller_0006
 * @tc.name: test ProcessBundleInstallStatus
 * @tc.desc: 1.Test ProcessBundleInstallStatus the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0006, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    int32_t uid = -1;
    auto ret = installer.ProcessBundleInstallStatus(info, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BaseBundleInstaller_0007
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test ProcessBundleUpdateStatus the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0007, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    bool isReplace = false;
    bool killProcess = false;
    auto ret = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: BaseBundleInstaller_0008
 * @tc.name: test ProcessNewModuleInstall
 * @tc.desc: 1.Test ProcessNewModuleInstall the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0008, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    auto ret = installer.ProcessNewModuleInstall(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BaseBundleInstaller_0009
 * @tc.name: test ProcessModuleUpdate
 * @tc.desc: 1.Test ProcessModuleUpdate the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0009, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    bool isReplace = false;
    bool killProcess = false;
    auto ret = installer.ProcessModuleUpdate(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BaseBundleInstaller_0010
 * @tc.name: test CreateEl5AndSetPolicy
 * @tc.desc: 1.Test CreateEl5AndSetPolicy the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0010, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    installer.CreateEl5AndSetPolicy(newInfo);
    EXPECT_EQ(newInfo.GetBundleName().empty(), true);
}

/**
 * @tc.number: BaseBundleInstaller_0011
 * @tc.name: test CreateScreenLockProtectionDir
 * @tc.desc: 1.Test CreateScreenLockProtectionDir the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0011, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.tempInfo_.bundleInit_ = false;

    installer.CreateScreenLockProtectionDir();
    EXPECT_FALSE(installer.tempInfo_.bundleInit_);
}

/**
 * @tc.number: BaseBundleInstaller_0012
 * @tc.name: test CreateScreenLockProtectionDir
 * @tc.desc: 1.Test CreateScreenLockProtectionDir the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0012, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    installer.CreateEl5AndSetPolicy(newInfo);
    EXPECT_EQ(newInfo.GetBundleName().empty(), true);
}

/**
 * @tc.number: BaseBundleInstaller_0013
 * @tc.name: test CreateScreenLockProtectionDir
 * @tc.desc: 1.Test CreateScreenLockProtectionDir the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0013, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    std::string bundleName;
    installer.DeleteUninstallBundleInfo(bundleName);
    EXPECT_EQ(bundleName.empty(), true);
}

/**
 * @tc.number: BaseBundleInstaller_0014
 * @tc.name: test CreateScreenLockProtectionDir
 * @tc.desc: 1.Test CreateScreenLockProtectionDir the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0014, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    std::string bundleName;
    bool ret = installer.DeleteUninstallBundleInfoFromDb(bundleName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BaseBundleInstaller_0015
 * @tc.name: test SetFirstInstallTime
 * @tc.desc: 1.Test SetFirstInstallTime the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0015, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = 100;
    std::string bundleName;
    int64_t time = 0;
    InnerBundleInfo info;
    installer.SetFirstInstallTime(bundleName, time, info);
    EXPECT_TRUE(info.innerBundleUserInfos_.empty());
}

/**
 * @tc.number: BaseBundleInstaller_0016
 * @tc.name: test SaveFirstInstallBundleInfo
 * @tc.desc: 1.Test SaveFirstInstallBundleInfo the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0016, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = 100;
    std::string bundleName;
    int32_t userId = 100;
    bool isPreInstallApp = true;
    InnerBundleUserInfo innerBundleUserInfo;
    bool ret = installer.SaveFirstInstallBundleInfo(bundleName, userId, isPreInstallApp, innerBundleUserInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BaseBundleInstaller_0017
 * @tc.name: test CheckInstallOnKeepData
 * @tc.desc: 1.Test CheckInstallOnKeepData the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0017, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = 100;

    std::string bundleName;
    bool isOTA = false;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    bool ret = installer.CheckInstallOnKeepData(bundleName, isOTA, infos);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BaseBundleInstaller_0018
 * @tc.name: test DeleteGroupDirsForException
 * @tc.desc: 1.Test DeleteGroupDirsForException the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0018, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = 100;

    InnerBundleInfo info;
    installer.DeleteGroupDirsForException(info);
    EXPECT_TRUE(info.GetBundleName().empty());
}

/**
 * @tc.number: BaseBundleInstaller_0019
 * @tc.name: test InitTempBundleFromCache
 * @tc.desc: 1.Test InitTempBundleFromCache the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0019, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = 100;

    InnerBundleInfo info;
    bool isAppExist = false;
    std::string bundleName;
    bool ret = installer.InitTempBundleFromCache(info, isAppExist, bundleName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BaseBundleInstaller_0020
 * @tc.name: test UninstallLowerVersionFeature
 * @tc.desc: 1.Test UninstallLowerVersionFeature the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0020, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = 100;

    std::vector<std::string> packageVec;
    bool killProcess = false;
    auto ret = installer.UninstallLowerVersionFeature(packageVec, killProcess);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BaseBundleInstaller_0021
 * @tc.name: test CheckUserId
 * @tc.desc: 1.Test CheckUserId the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0021, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = 100;

    auto ret = installer.CheckUserId(100);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BaseBundleInstaller_0022
 * @tc.name: test CreateBundleUserData
 * @tc.desc: 1.Test CreateBundleUserData the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0022, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = Constants::ALL_USERID;

    InnerBundleInfo newInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = 20022222;

    InnerBundleCloneInfo innerBundleCloneInfo;
    innerBundleCloneInfo.userId = Constants::ALL_USERID;
    innerBundleCloneInfo.appIndex = 1;

    innerBundleUserInfo.cloneInfos["1"] = innerBundleCloneInfo;
    newInfo.innerBundleUserInfos_["com.example.test_100"] = innerBundleUserInfo;
    auto ret = installer.CreateBundleUserData(newInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BaseBundleInstaller_0023
 * @tc.name: test UpdateEncryptedStatus
 * @tc.desc: 1.Test UpdateEncryptedStatus the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0023, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = Constants::ALL_USERID;

    InnerBundleInfo newInfo;
    auto ret = installer.UpdateEncryptedStatus(newInfo);
    EXPECT_NE(ret, true);
}

/**
 * @tc.number: BaseBundleInstaller_0024
 * @tc.name: test RemoveBundleUserData
 * @tc.desc: 1.Test RemoveBundleUserData the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0024, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = Constants::ALL_USERID;

    InnerBundleInfo newInfo;
    auto ret = installer.RemoveBundleUserData(newInfo, false, false);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BaseBundleInstaller_0025
 * @tc.name: test OnSingletonChange
 * @tc.desc: 1.Test OnSingletonChange the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0025, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.userId_ = Constants::ALL_USERID;
    installer.singletonState_ = AppExecFwk::BaseBundleInstaller::SingletonState::SINGLETON_TO_NON;

    installer.OnSingletonChange(false);
    EXPECT_EQ(installer.singletonState_, AppExecFwk::BaseBundleInstaller::SingletonState::SINGLETON_TO_NON);
}

/**
* @tc.number: BaseBundleInstaller_0026
 * @tc.name: test UpdateHapToken
 * @tc.desc: 1.Test UpdateHapToken the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0026, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;

    InnerBundleInfo newInfo;
    auto ret = installer.UpdateHapToken(false, newInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BaseBundleInstaller_0027
 * @tc.name: test RollbackHmpUserInfo
 * @tc.desc: 1.Test RollbackHmpUserInfo the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0027, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;

    std::string bundleName = "test";
    auto ret = installer.RollbackHmpUserInfo(bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
}

/**
 * @tc.number: BaseBundleInstaller_0028
 * @tc.name: test RollbackHmpUserInfo
 * @tc.desc: 1.Test RollbackHmpUserInfo the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0028, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;

    std::string bundleName = "test";
    auto ret = installer.RollbackHmpUserInfo(bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
}

/**
 * @tc.number: BaseBundleInstaller_0029
 * @tc.name: test IsEnterpriseForAllUser
 * @tc.desc: 1.Test IsEnterpriseForAllUser the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0029, Function | MediumTest | Level1)
{
    EXPECT_TRUE(system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "true"));
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.parameters["ohos.bms.param.enterpriseForAllUser"] = "true";

    std::string bundleName = "test";
    auto ret = installer.IsEnterpriseForAllUser(installParam, bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BaseBundleInstaller_0030
 * @tc.name: test UpdateKillApplicationProcess
 * @tc.desc: 1.Test UpdateKillApplicationProcess the BaseBundleInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BaseBundleInstaller_0030, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    installer.UpdateKillApplicationProcess(oldInfo);
    EXPECT_EQ(oldInfo.GetBundleName().empty(), true);
}

/**
 * @tc.number: BundleSandboxInstaller_0010
 * @tc.name: test GetInnerBundleInfoWithDisable
 * @tc.desc: 1.Test GetInnerBundleInfoWithDisable the BundleSandboxInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BundleSandboxInstaller_0010, Function | MediumTest | Level1)
{
    BundleSandboxInstaller installer;
    InnerBundleInfo oldInfo;
    bool isAppExist = false;
    auto ret = installer.GetInnerBundleInfoWithDisable(oldInfo, isAppExist);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleCloneInstaller_0010
 * @tc.name: test UninstallAllCloneApps
 * @tc.desc: 1.Test UninstallAllCloneApps the BundleCloneInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BundleCloneInstaller_0010, Function | MediumTest | Level1)
{
    BundleCloneInstaller installer;
    std::string bundleName = "test";
    bool sync = false;
    int32_t userId = 100;
    auto ret = installer.UninstallAllCloneApps(bundleName, sync, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleCloneInstaller_0020
 * @tc.name: test CreateEl5Dir
 * @tc.desc: 1.Test CreateEl5Dir the BundleCloneInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BundleCloneInstaller_0020, Function | MediumTest | Level1)
{
    BundleCloneInstaller installer;
    InnerBundleInfo innerBundleInfo;
    int32_t uid = 100;
    int32_t userId = 101;
    int32_t appIndex = 102;
    RequestPermission requestPermission;
    requestPermission.name = ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "testname";
    innerModuleInfo.requestPermissions.emplace_back(requestPermission);
    innerBundleInfo.innerModuleInfos_.try_emplace("test", innerModuleInfo);
    installer.CreateEl5Dir(innerBundleInfo, uid, userId, appIndex);
    EXPECT_NE(installer.GetDataMgr(), ERR_OK);
}

/**
 * @tc.number: BundleCloneInstaller_0030
 * @tc.name: test GetAssetAccessGroups
 * @tc.desc: 1.Test GetAssetAccessGroups the BundleCloneInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BundleCloneInstaller_0030, Function | MediumTest | Level1)
{
    BundleCloneInstaller installer;
    std::string bundleName = "test";
    auto ret = installer.GetAssetAccessGroups(bundleName);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BundleCloneInstaller_0040
 * @tc.name: test GetDeveloperId
 * @tc.desc: 1.Test GetDeveloperId the BundleCloneInstaller
*/
HWTEST_F(BmsBundleDataMgrNullptrTest, BundleCloneInstaller_0040, Function | MediumTest | Level1)
{
    BundleCloneInstaller installer;
    std::string bundleName = "test";
    auto ret = installer.GetDeveloperId(bundleName);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}
} // OHOS