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

#include <fstream>
#include <gtest/gtest.h>

#include "app_provision_info_manager.h"
#include "base_bundle_installer.h"
#include "bundle_cache_mgr.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "data_group_info.h"
#include "hmp_bundle_installer.h"
#include "installd/installd_service.h"
#include "installd_client.h"
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
} // OHOS