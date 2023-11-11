/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <fstream>

#include "ability_manager_helper.h"
#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const int32_t WAIT_TIME = 5; // init mocked bms
const int32_t TOKENID = 100;
const std::string BUNDLE_TEMP_NAME = "temp_bundle_name";
const std::string AVAILABLE_TYPE_NORMAL = "normal";
const std::string AVAILABLE_TYPE_MDM = "MDM";
const std::string AVAILABLE_TYPE_EMPTY = "";
const std::string BUNDLE_PATH = "test.hap";
} // namespace

class BmsServiceStartupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsServiceStartupTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsServiceStartupTest::SetUpTestCase()
{}

void BmsServiceStartupTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsServiceStartupTest::SetUp()
{
    bundleMgrService_->InitBmsParam();
    bundleMgrService_->InitPreInstallExceptionMgr();
}

void BmsServiceStartupTest::TearDown()
{
    DelayedSingleton<BundleMgrService>::DestroyInstance();
}

/**
* @tc.number: GuardAgainst_002
* @tc.name: Guard against install infos lossed strategy
* @tc.desc: 1. ScanAndAnalyzeUserDatas
* @tc.require: issueI56WA0
*/
HWTEST_F(BmsServiceStartupTest, GuardAgainst_002, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::map<std::string, std::vector<InnerBundleUserInfo>> innerBundleUserInfoMaps;
    handler->ScanAndAnalyzeUserDatas(innerBundleUserInfoMaps);
    EXPECT_EQ(true, innerBundleUserInfoMaps.empty());
}

/**
* @tc.number: GuardAgainst_003
* @tc.name: Guard against install infos lossed strategy
* @tc.desc: 1. ScanAndAnalyzeInstallInfos
* @tc.require: issueI56WA0
*/
HWTEST_F(BmsServiceStartupTest, GuardAgainst_003, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    handler->ScanAndAnalyzeInstallInfos(installInfos);
    EXPECT_EQ(false, installInfos.empty());
}

/**
* @tc.number: PreInstall_001
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. GetBundleDirFromScan
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::list<std::string> bundleDirs;
    handler->GetBundleDirFromScan(bundleDirs);
    EXPECT_EQ(false, bundleDirs.empty());
}

/**
* @tc.number: PreInstall_002
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_002, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    bool ret = handler->LoadPreInstallProFile();
    EXPECT_EQ(true, ret);
    ret = BMSEventHandler::HasPreInstallProfile();
    EXPECT_EQ(true, ret);
}

/**
* @tc.number: ReInstallAllInstallDirApps_001
* @tc.name: test ReInstallAllInstallDirApps
* @tc.desc: 1. test gets SYSTEM_ERROR
*/
HWTEST_F(BmsServiceStartupTest, ReInstallAllInstallDirApps_001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto res = handler->ReInstallAllInstallDirApps();
    EXPECT_EQ(res, ResultCode::SYSTEM_ERROR);
}

/**
* @tc.number: GuardAgainstInstallInfosLossedStrategy_001
* @tc.name: test GuardAgainstInstallInfosLossedStrategy
* @tc.desc: test gets NO_INSTALLED_DATA
*/
HWTEST_F(BmsServiceStartupTest, GuardAgainstInstallInfosLossedStrategy_001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto res = handler->GuardAgainstInstallInfosLossedStrategy();
    EXPECT_EQ(res, ResultCode::NO_INSTALLED_DATA);
}

/**
* @tc.number: AnalyzeUserData_001
* @tc.name: test AnalyzeUserData
* @tc.desc: 1. test is failed
*/
HWTEST_F(BmsServiceStartupTest, AnalyzeUserData_001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    int32_t userId = 0;
    const std::string userDataDir = "/data/test";
    const std::string userDataBundleName = "com.user.test";
    const std::string userDataDir1 = "";
    const std::string userDataBundleName1 = "";
    std::map<std::string, std::vector<InnerBundleUserInfo>> userMaps;
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfos.push_back(innerBundleUserInfo);
    userMaps.insert(pair<std::string, std::vector<InnerBundleUserInfo>>("1", innerBundleUserInfos));
    auto res = handler->AnalyzeUserData(userId, userDataDir, userDataBundleName, userMaps);
    EXPECT_FALSE(res);

    res = handler->AnalyzeUserData(userId, userDataDir1, userDataBundleName, userMaps);
    EXPECT_FALSE(res);

    res = handler->AnalyzeUserData(userId, userDataDir, userDataBundleName1, userMaps);
    EXPECT_FALSE(res);

    res = handler->AnalyzeUserData(userId, userDataDir1, userDataBundleName1, userMaps);
    EXPECT_FALSE(res);
}

/**
* @tc.number: CheckHapPaths_0001
* @tc.name: test CheckHapPaths
* @tc.desc: 1. test is valid input
*/
HWTEST_F(BmsServiceStartupTest, CheckHapPaths_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back("test1.hap");
    hapPaths.emplace_back("test2.ha");
    std::vector<std::string> checkPaths = handler->CheckHapPaths(hapPaths);
    EXPECT_EQ(checkPaths[0], "test1.hap");
}

/**
* @tc.number: CombineBundleInfoAndUserInfo_001
* @tc.name: test CombineBundleInfoAndUserInfo
* @tc.desc: 1. test is failed
*/
HWTEST_F(BmsServiceStartupTest, CombineBundleInfoAndUserInfo_001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    InnerBundleInfo innerBundleInfo;
    std::vector<InnerBundleInfo> innerBundleInfos;
    innerBundleInfos.push_back(innerBundleInfo);
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    installInfos.insert(pair<std::string, std::vector<InnerBundleInfo>>("1", innerBundleInfos));
    InnerBundleUserInfo innerBundleUserInfo;
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    innerBundleUserInfos.push_back(innerBundleUserInfo);
    std::map<std::string, std::vector<InnerBundleUserInfo>> userInfoMaps;
    userInfoMaps.insert(pair<std::string, std::vector<InnerBundleUserInfo>>("1", innerBundleUserInfos));
    auto res = handler->CombineBundleInfoAndUserInfo(installInfos, userInfoMaps);
    EXPECT_FALSE(res);

    std::map<std::string, std::vector<InnerBundleInfo>> installInfos1;
    std::map<std::string, std::vector<InnerBundleUserInfo>> userInfoMaps1;
    res = handler->CombineBundleInfoAndUserInfo(installInfos1, userInfoMaps);
    EXPECT_FALSE(res);

    res = handler->CombineBundleInfoAndUserInfo(installInfos, userInfoMaps1);
    EXPECT_FALSE(res);

    res = handler->CombineBundleInfoAndUserInfo(installInfos1, userInfoMaps1);
    EXPECT_FALSE(res);
}

/**
* @tc.number: CombineBundleInfoAndUserInfo_002
* @tc.name: test CombineBundleInfoAndUserInfo
* @tc.desc: 1. test empty installinfos and userInfoMaps
*/
HWTEST_F(BmsServiceStartupTest, CombineBundleInfoAndUserInfo_002, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    std::map<std::string, std::vector<InnerBundleUserInfo>> userInfoMaps;
    bool res = handler->CombineBundleInfoAndUserInfo(installInfos, userInfoMaps);
    EXPECT_FALSE(res);
}

/**
* @tc.number: IsHotPatchApp_00001
* @tc.name: test IsHotPatchApp
* @tc.desc: 1. test empty installinfos and userInfoMaps
*/
HWTEST_F(BmsServiceStartupTest, InnerProcessBootPreBundleProFileInstall_001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::string bundleName = "com.ohos.tes1";
    bool ret = handler->IsHotPatchApp(bundleName);
    EXPECT_EQ(ret, false);
}

/**
* @tc.number: OTAInstallSystemBundle_001
* @tc.name: test OTAInstallSystemBundle_001
* @tc.desc: 1. test is failed
*/
HWTEST_F(BmsServiceStartupTest, OTAInstallSystemBundle_001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::string filePath = "/data/test";
    std::vector<std::string> filePaths;
    filePaths.push_back(filePath);
    std::vector<std::string> filePaths1;
    Constants::AppType appType = Constants::AppType::THIRD_PARTY_APP;
    bool removable = false;
    auto res = handler->OTAInstallSystemBundle(filePaths, appType, removable);
    EXPECT_FALSE(res);
    res = handler->OTAInstallSystemBundle(filePaths1, appType, removable);
    EXPECT_FALSE(res);
}

/**
* @tc.number: PreInstall_003
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_003, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    ResultCode ret = handler->GuardAgainstInstallInfosLossedStrategy();
    EXPECT_EQ(ret, ResultCode::NO_INSTALLED_DATA);
}

/**
* @tc.number: PreInstall_004
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_004, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    std::map<std::string, std::vector<InnerBundleUserInfo>> userMaps;
    ScanResultCode ret = handler->ScanAndAnalyzeUserDatas(userMaps);
    EXPECT_EQ(ret, ScanResultCode::SCAN_NO_DATA);
}

/**
* @tc.number: PreInstall_004
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_005, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    ResultCode ret = handler->ReInstallAllInstallDirApps();
    EXPECT_EQ(ret, ResultCode::SYSTEM_ERROR);
}

/**
* @tc.number: PreInstall_006
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_006, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    std::vector<std::string> bundleDirs;
    handler->GetPreInstallDirFromLoadProFile(bundleDirs);
    EXPECT_EQ(bundleDirs.size(), 0);
}

/**
* @tc.number: PreInstall_007
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_007, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    std::map<std::string, std::vector<InnerBundleUserInfo>> userInfoMaps;
    bool res = handler->CombineBundleInfoAndUserInfo(installInfos, userInfoMaps);
    EXPECT_EQ(res, false);
    handler->ScanAndAnalyzeInstallInfos(installInfos);
    handler->ScanAndAnalyzeUserDatas(userInfoMaps);
    res = handler->CombineBundleInfoAndUserInfo(installInfos, userInfoMaps);
    EXPECT_EQ(res, false);
}

/**
* @tc.number: PreInstall_008
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_008, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    std::vector<std::string> filePaths;
    bool removabl = false;
    bool res = handler->OTAInstallSystemBundle(
        filePaths, Constants::AppType::SYSTEM_APP, removabl);
    EXPECT_EQ(res, false);
}

/**
* @tc.number: PreInstall_009
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_009, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    bool res = handler->IsPreInstallRemovable("");
    EXPECT_EQ(res, false);
}

/**
* @tc.number: PreInstall_0010
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_0010, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    PreBundleConfigInfo preBundleConfigInfo;
    bool res = handler->GetPreInstallCapability(preBundleConfigInfo);
    EXPECT_EQ(res, false);
    preBundleConfigInfo.bundleName = "bundlName";
    res = handler->GetPreInstallCapability(preBundleConfigInfo);
    EXPECT_EQ(res, false);
}

/**
* @tc.number: PreInstall_0011
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. IsPreInstallRemovable
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_0011, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    std::string filePath = "/data/test";
    bool res = handler->IsPreInstallRemovable("");
    EXPECT_EQ(res, false);
    res = handler->IsPreInstallRemovable(filePath);
    EXPECT_EQ(res, false);
}

/**
* @tc.number: PreInstall_0012
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. ParseHapFiles
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_0012, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->ClearPreInstallCache();
    std::string filePath = "/data/test";
    std::unordered_map<std::string, InnerBundleInfo> infos;
    bool res = handler->ParseHapFiles("", infos);
    EXPECT_EQ(res, false);
    res = handler->ParseHapFiles(filePath, infos);
    EXPECT_EQ(res, false);
}

/**
* @tc.number: PreInstall_0013
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_0013, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    InnerBundleInfo info;
    std::list<std::string> scanPathList;
    handler->LoadAllPreInstallBundleInfos();
    handler->ProcessRebootBundleInstall();
    handler->ProcessRebootBundleUninstall();
    handler->ProcessReBootPreBundleProFileInstall();
    handler->InnerProcessRebootBundleInstall(scanPathList, Constants::AppType::SYSTEM_APP);
    handler->ProcessReBootPreBundleProFileInstall();
    handler->SaveInstallInfoToCache(info);
    EXPECT_EQ(info.GetBundleName(), "");
}

/**
* @tc.number: PreInstall_0014
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_0014, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::vector<std::string> hapPaths;
    std::vector<std::string> res = handler->CheckHapPaths(hapPaths);
    EXPECT_EQ(res.size(), 0);
}

/**
 * @tc.number: BundlePermissionMgr_0100
 * @tc.name: test ConvertPermissionDef
 * @tc.desc: 1.test ConvertPermissionDef of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0100, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);
    AccessToken::PermissionDef permDef;
    OHOS::AppExecFwk::PermissionDef permissionDef;
    permissionDef.label = "$string: entry_MainAbility";
    BundlePermissionMgr::ConvertPermissionDef(permDef, permissionDef);
    EXPECT_TRUE(permissionDef.label == permDef.label);
}

/**
 * @tc.number: BundlePermissionMgr_0200
 * @tc.name: test GrantPermission
 * @tc.desc: 1.test GrantPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0200, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    AccessToken::AccessTokenID tokenId = 0;
    std::string permissionName;
    AccessToken::PermissionFlag flag =
        AccessToken::PermissionFlag::PERMISSION_DEFAULT_FLAG;
    std::string bundleName;
    ret = BundlePermissionMgr::GrantPermission(
        tokenId, permissionName, flag, bundleName);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundlePermissionMgr_0300
 * @tc.name: test CheckGrantPermission
 * @tc.desc: 1.test CheckGrantPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0300, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    AccessToken::PermissionDef permDef;
    std::string apl;
    std::vector<std::string> acls;
    permDef.provisionEnable = true;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, false);

    permDef.availableLevel = AccessToken::ATokenAplEnum::APL_NORMAL;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, true);

    permDef.availableLevel = AccessToken::ATokenAplEnum::APL_SYSTEM_BASIC;
    apl = Profile::AVAILABLELEVEL_SYSTEM_BASIC;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, true);
    apl = Profile::AVAILABLELEVEL_SYSTEM_CORE;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, true);
    apl = "";
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, false);

    permDef.availableLevel = AccessToken::ATokenAplEnum::APL_SYSTEM_CORE;
    apl = Profile::AVAILABLELEVEL_SYSTEM_CORE;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, true);
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    apl = "";
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundlePermissionMgr_0400
 * @tc.name: test VerifyPermission
 * @tc.desc: 1.test VerifyPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0400, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);
    std::string bundleName;
    std::string permissionName;
    int32_t userId = 100;
    int32_t ret = BundlePermissionMgr::VerifyPermission(bundleName, permissionName, userId);
    EXPECT_EQ(ret, OHOS::ERR_OK);
}

/**
 * @tc.number: BundlePermissionMgr_0500
 * @tc.name: test CheckPermissionInDefaultPermissions
 * @tc.desc: 1.test CheckPermissionInDefaultPermissions of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0500, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    DefaultPermission defaultPermission;
    PermissionInfo info;
    info.name = "default";
    defaultPermission.grantPermission.emplace_back(info);
    auto permissionName = info.name;
    bool userCancellable;
    ret = BundlePermissionMgr::CheckPermissionInDefaultPermissions(
        defaultPermission, permissionName, userCancellable);
    EXPECT_EQ(ret, true);

    permissionName = "";
    ret = BundlePermissionMgr::CheckPermissionInDefaultPermissions(
        defaultPermission, permissionName, userCancellable);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundlePermissionMgr_0600
 * @tc.name: test GetDefaultPermission
 * @tc.desc: 1.test GetDefaultPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0600, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    std::string bundleName = "com.ohos.tes1";
    DefaultPermission permission;
    ret = BundlePermissionMgr::GetDefaultPermission(bundleName, permission);
    EXPECT_EQ(ret, false);
    BundlePermissionMgr::defaultPermissions_.try_emplace("com.ohos.tes1", permission);
    ret = BundlePermissionMgr::GetDefaultPermission(bundleName, permission);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundlePermissionMgr_0700
 * @tc.name: test MatchSignature
 * @tc.desc: 1.test MatchSignature of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0700, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    DefaultPermission defaultPermission;
    PermissionInfo info;
    info.name = "default";
    defaultPermission.grantPermission.emplace_back(info);
    std::string signature = "";
    std::vector<std::string> signatures;
    signatures.insert(signatures.end(), signature);
    ret = BundlePermissionMgr::MatchSignature(defaultPermission, signatures);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundlePermissionMgr_0800
 * @tc.name: test GetHapApiVersion
 * @tc.desc: 1.test Get BundlePermissionMgr of HapApiVersion
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0800, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    ret = BundlePermissionMgr::GetHapApiVersion();
    EXPECT_EQ(ret, Constants::INVALID_API_VERSION);
}

/**
 * @tc.number: BundlePermissionMgr_0900
 * @tc.name: test GetAvailableType
 * @tc.desc: 1.test Get BundlePermissionMgr of AvailableType
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0900, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    auto result = BundlePermissionMgr::GetAvailableType(AVAILABLE_TYPE_EMPTY);
    EXPECT_EQ(ret, AccessToken::ATokenAvailableTypeEnum::NORMAL);

    result = BundlePermissionMgr::GetAvailableType(AVAILABLE_TYPE_NORMAL);
    EXPECT_EQ(ret, AccessToken::ATokenAvailableTypeEnum::NORMAL);
}

/**
 * @tc.number: AbilityManagerHelper_0100
 * @tc.name: test IsRunning
 * @tc.desc: 1.test IsRunning of AbilityManagerHelper
 */
HWTEST_F(BmsServiceStartupTest, AbilityManagerHelper_0100, Function | SmallTest | Level0)
{
    AbilityManagerHelper helper;
    int bundleUid = -1;
    int ret = helper.IsRunning("com.ohos.tes1", bundleUid);
    EXPECT_EQ(ret, -1);
    bundleUid = 100;
    ret = helper.IsRunning("com.ohos.tes1", bundleUid);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: BundleStateStorage_0100
 * @tc.name: test SaveBundleStateStorage
 * @tc.desc: 1.test SaveBundleStateStorage of BundleStateStorage
 */
HWTEST_F(BmsServiceStartupTest, BundleStateStorage_0100, Function | SmallTest | Level0)
{
    BundleStateStorage bundleStateStorage;
    BundleUserInfo info;
    int32_t userId = -1;
    bool ret = bundleStateStorage.SaveBundleStateStorage("", userId, info);
    EXPECT_EQ(ret, false);
    ret = bundleStateStorage.SaveBundleStateStorage("com.ohos.tes1", userId, info);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsParam_0100
 * @tc.name: test GetBmsParam
 * @tc.desc: 1.test GetBmsParam of BmsParam
 */
HWTEST_F(BmsServiceStartupTest, BmsParam_0100, Function | SmallTest | Level0)
{
    BmsParam param;
    std::string value = "";
    bool ret = param.GetBmsParam("", value);
    EXPECT_EQ(ret, false);
    param.rdbDataManager_.reset();
    ret = param.GetBmsParam("bms_param", value);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsParam_0200
 * @tc.name: test SaveBmsParam
 * @tc.desc: 1.test SaveBmsParam of BmsParam
 */
HWTEST_F(BmsServiceStartupTest, BmsParam_0200, Function | SmallTest | Level0)
{
    BmsParam param;
    bool ret = param.SaveBmsParam("bms_param", "bms_value");
    EXPECT_EQ(ret, true);
    ret = param.SaveBmsParam("", "bms_value");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ConvertPermissionDef_0100
 * @tc.name: test ConvertPermissionDef
 * @tc.desc: 1.test ConvertPermissionDef of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, ConvertPermissionDef_0100, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);
    AccessToken::PermissionDef permDef;
    OHOS::AppExecFwk::DefinePermission definePermission;
    definePermission.grantMode = Profile::DEFINEPERMISSION_GRANT_MODE_SYSTEM_GRANT;
    BundlePermissionMgr::ConvertPermissionDef(permDef, definePermission, BUNDLE_TEMP_NAME);
    EXPECT_EQ(permDef.grantMode, AccessToken::GrantMode::SYSTEM_GRANT);
}

/**
 * @tc.number: ConvertPermissionDef_0200
 * @tc.name: test ConvertPermissionDef
 * @tc.desc: 1.test ConvertPermissionDef of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, ConvertPermissionDef_0200, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);
    AccessToken::PermissionDef permDef;
    OHOS::AppExecFwk::DefinePermission definePermission;
    definePermission.grantMode = Profile::DEFINEPERMISSION_PROVISION_ENABLE;
    BundlePermissionMgr::ConvertPermissionDef(permDef, definePermission, BUNDLE_TEMP_NAME);
    EXPECT_EQ(permDef.grantMode, AccessToken::GrantMode::USER_GRANT);
}

/**
 * @tc.number: GetNeedDeleteDefinePermissionName_0100
 * @tc.name: test GetNeedDeleteDefinePermissionName
 * @tc.desc: 1.test GetNeedDeleteDefinePermissionName of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, GetNeedDeleteDefinePermissionName_0100, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = BUNDLE_TEMP_NAME;
    newInfo.innerModuleInfos_.insert(std::pair<std::string, InnerModuleInfo>("1", innerModuleInfo));
    oldInfo.innerModuleInfos_.insert(std::pair<std::string, InnerModuleInfo>("1", innerModuleInfo));
    auto ret = BundlePermissionMgr::GetNeedDeleteDefinePermissionName(oldInfo, newInfo);
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.number: GetNewPermissionDefList_0100
 * @tc.name: test GetNewPermissionDefList
 * @tc.desc: 1.test GetNewPermissionDefList of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, GetNewPermissionDefList_0100, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);
    AccessToken::AccessTokenID tokenId = TOKENID;
    std::vector<AccessToken::PermissionDef> permissionDef;
    std::vector<AccessToken::PermissionDef> newPermissionDef;
    auto ret = BundlePermissionMgr::GetNewPermissionDefList(tokenId, permissionDef, newPermissionDef);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number: CheckPermissionAvailableType_0100
 * @tc.name: test CheckPermissionAvailableType
 * @tc.desc: 1.test CheckPermissionAvailableType of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, CheckPermissionAvailableType_0100, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);
    AccessToken::PermissionDef permissionDef;
    std::string appDistributionType = AppExecFwk::Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM;
    bool result = BundlePermissionMgr::CheckPermissionAvailableType(appDistributionType, permissionDef);
    EXPECT_TRUE(result);
}

/**
* @tc.number: PreInstallExceptionMgr_0001
* @tc.name: test PreInstallExceptionMgr
* @tc.desc: 1. test is valid input
*/
HWTEST_F(BmsServiceStartupTest, PreInstallExceptionMgr_0001, Function | SmallTest | Level0)
{
    if (bundleMgrService_ == nullptr) {
        return;
    }

    auto preInstallExceptionMgr = bundleMgrService_->GetPreInstallExceptionMgr();
    bool ret = preInstallExceptionMgr != nullptr;
    EXPECT_EQ(ret, true);

    ret = (bundleMgrService_->GetBmsParam() != nullptr);
    EXPECT_EQ(ret, true);

    std::set<std::string> oldExceptionPaths;
    std::set<std::string> oldExceptionBundleNames;
    preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        oldExceptionPaths, oldExceptionBundleNames);

    preInstallExceptionMgr->ClearAll();
    std::set<std::string> exceptionPaths;
    std::set<std::string> exceptionBundleNames;
    ret = preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        exceptionPaths, exceptionBundleNames);
    EXPECT_EQ(ret, false);

    preInstallExceptionMgr->SavePreInstallExceptionBundleName(BUNDLE_TEMP_NAME);
    preInstallExceptionMgr->SavePreInstallExceptionPath(BUNDLE_PATH);
    preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        exceptionPaths, exceptionBundleNames);
    preInstallExceptionMgr->DeletePreInstallExceptionBundleName(BUNDLE_TEMP_NAME);
    preInstallExceptionMgr->DeletePreInstallExceptionPath(BUNDLE_PATH);
    ret = preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        exceptionPaths, exceptionBundleNames);
    EXPECT_EQ(ret, false);

    if (oldExceptionPaths.size() > 0) {
        for (const auto &pathIter : oldExceptionPaths) {
            preInstallExceptionMgr->SavePreInstallExceptionPath(pathIter);
        }
    }

    if (oldExceptionBundleNames.size() > 0) {
        for (const auto &bundleNameIter : oldExceptionBundleNames) {
            preInstallExceptionMgr->SavePreInstallExceptionPath(bundleNameIter);
        }
    }
}
} // OHOS