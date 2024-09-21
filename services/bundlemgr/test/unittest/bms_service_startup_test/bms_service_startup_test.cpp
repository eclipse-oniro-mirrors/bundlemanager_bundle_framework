/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "bms_extension_client.h"
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
const int32_t FLAG = 0;
const std::string BUNDLE_TEMP_NAME = "temp_bundle_name";
const std::string AVAILABLE_TYPE_NORMAL = "normal";
const std::string AVAILABLE_TYPE_MDM = "MDM";
const std::string AVAILABLE_TYPE_EMPTY = "";
const std::string AVAILABLELEVEL_SYSTEM_CORE = "system_core";
const std::string AVAILABLELEVEL_SYSTEM_BASIC = "system_basic";
const std::string BUNDLE_PATH = "test.hap";
const std::string STRING_TYPE = "string";
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

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_TEMP_NAME;
    BundleInfo bundleInfo;
    bundleInfo.versionCode = 1;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        BUNDLE_TEMP_NAME, innerBundleInfo);
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
 * @tc.number: BundlePermissionMgr_1000
 * @tc.name: test MatchSignature
 * @tc.desc: 1.test MatchSignature of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1000, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    DefaultPermission defaultPermission;
    std::vector<std::string> signatures = { STRING_TYPE };
    ret = BundlePermissionMgr::MatchSignature(defaultPermission, signatures);
    EXPECT_EQ(ret, false);

    defaultPermission.appSignature = { STRING_TYPE };
    ret = BundlePermissionMgr::MatchSignature(defaultPermission, signatures);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundlePermissionMgr_1100
 * @tc.name: test MatchSignature
 * @tc.desc: 1.test MatchSignature of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1100, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    DefaultPermission defaultPermission;
    ret = BundlePermissionMgr::MatchSignature(defaultPermission, STRING_TYPE);
    EXPECT_EQ(ret, false);

    defaultPermission.appSignature = { STRING_TYPE };
    ret = BundlePermissionMgr::MatchSignature(defaultPermission, "");
    EXPECT_EQ(ret, false);

    ret = BundlePermissionMgr::MatchSignature(defaultPermission, STRING_TYPE);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundlePermissionMgr_1200
 * @tc.name: test IsCallingUidValid
 * @tc.desc: 1.test IsCallingUidValid of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1200, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    ret = BundlePermissionMgr::IsCallingUidValid(callingUid);
    EXPECT_EQ(ret, true);

    callingUid = -100;
    ret = BundlePermissionMgr::IsCallingUidValid(callingUid);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundlePermissionMgr_1300
 * @tc.name: test IsBundleSelfCalling
 * @tc.desc: 1.test IsBundleSelfCalling of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1300, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    ret = BundlePermissionMgr::IsBundleSelfCalling("");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundlePermissionMgr_1400
 * @tc.name: test VerifyCallingBundleSdkVersion
 * @tc.desc: 1.test VerifyCallingBundleSdkVersion of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1400, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    ret = BundlePermissionMgr::VerifyCallingBundleSdkVersion(Constants::INVALID_API_VERSION);
    EXPECT_EQ(ret, false);
}


/**
 * @tc.number: BundlePermissionMgr_1500
 * @tc.name: test IsBundleSelfCalling
 * @tc.desc: 1.test IsBundleSelfCalling of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1500, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    std::string bundleName;
    ret = BundlePermissionMgr::IsBundleSelfCalling(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundlePermissionMgr_1600
 * @tc.name: test CreateHapInfoParams
 * @tc.desc: 1.test CreateHapInfoParams of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1600, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    int32_t userId = 100;
    int32_t dlpType = 0;
    auto hapInfo = BundlePermissionMgr::CreateHapInfoParams(innerBundleInfo, userId, dlpType);
    EXPECT_EQ(hapInfo.userID, userId);
}

/**
 * @tc.number: BundlePermissionMgr_1700
 * @tc.name: test InitHapToken
 * @tc.desc: 1.test InitHapToken of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1700, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    InnerBundleInfo innerBundleInfo;
    int32_t userId = 0;
    int32_t dlpType = 0;
    Security::AccessToken::AccessTokenIDEx tokenIdeEx;

    ret = BundlePermissionMgr::InitHapToken(innerBundleInfo, userId, dlpType, tokenIdeEx);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundlePermissionMgr_1800
 * @tc.name: test UpdateHapToken
 * @tc.desc: 1.test UpdateHapToken of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1800, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    InnerBundleInfo innerBundleInfo;
    Security::AccessToken::AccessTokenIDEx tokenIdeEx;
    ret = BundlePermissionMgr::UpdateHapToken(tokenIdeEx, innerBundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundlePermissionMgr_1900
 * @tc.name: test VerifyCallingBundleSdkVersion
 * @tc.desc: 1.test VerifyCallingBundleSdkVersion of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_1900, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    int32_t beginApiVersion = 0;
    ret = BundlePermissionMgr::VerifyCallingBundleSdkVersion(beginApiVersion);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundlePermissionMgr_2000
 * @tc.name: test CreateHapPolicyParam
 * @tc.desc: 1.test CreateHapPolicyParam of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2000, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    auto hapPolicy = BundlePermissionMgr::CreateHapPolicyParam(innerBundleInfo);
    EXPECT_EQ(hapPolicy.domain, "domain");
}

/**
 * @tc.number: BundlePermissionMgr_2100
 * @tc.name: test GetTokenApl
 * @tc.desc: 1.test GetTokenApl of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2100, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    auto result = BundlePermissionMgr::GetTokenApl(AVAILABLELEVEL_SYSTEM_CORE);
    EXPECT_EQ(result, AccessToken::ATokenAplEnum::APL_SYSTEM_CORE);
    result = BundlePermissionMgr::GetTokenApl(AVAILABLELEVEL_SYSTEM_BASIC);
    EXPECT_EQ(result, AccessToken::ATokenAplEnum::APL_SYSTEM_BASIC);
    std::string apl = "";
    result = BundlePermissionMgr::GetTokenApl(apl);
    EXPECT_EQ(result, AccessToken::ATokenAplEnum::APL_NORMAL);
    BundlePermissionMgr::UnInit();
}

/**
 * @tc.number: BundlePermissionMgr_2200
 * @tc.name: test GetPermissionDefList
 * @tc.desc: 1.test GetPermissionDefList of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2200, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    InnerBundleInfo innerBundleInfo;
    std::vector<AccessToken::PermissionDef> permDef = BundlePermissionMgr::GetPermissionDefList(innerBundleInfo);
    EXPECT_EQ(permDef.size(), 0);
}

/**
 * @tc.number: BundlePermissionMgr_2300
 * @tc.name: test GetPermissionStateFullList
 * @tc.desc: 1.test GetPermissionStateFullList of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2300, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    InnerBundleInfo innerBundleInfo;
    std::vector<AccessToken::PermissionStateFull> permFull
        = BundlePermissionMgr::GetPermissionStateFullList(innerBundleInfo);
    EXPECT_EQ(permFull.size(), 0);
}

/**
 * @tc.number: BundlePermissionMgr_2400
 * @tc.name: test GetAllReqPermissionStateFull
 * @tc.desc: 1.test GetAllReqPermissionStateFull of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2400, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    InnerBundleInfo innerBundleInfo;
    AccessToken::AccessTokenID callerToken = 0;
    std::vector<AccessToken::PermissionStateFull> newPermissionState;
    bool result = BundlePermissionMgr::GetAllReqPermissionStateFull(callerToken, newPermissionState);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: BundlePermissionMgr_2500
 * @tc.name: test GetPermissionDefList
 * @tc.desc: 1.test AddPermissionUsedRecord of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2500, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    std::string permission = "";
    int32_t successCount = 0;
    int32_t failCount = 0;
    BundlePermissionMgr::AddPermissionUsedRecord(permission, successCount, failCount);
    EXPECT_EQ(failCount, 0);
}

/**
 * @tc.number: BundlePermissionMgr_2600
 * @tc.name: test VerifyRecoverPermission
 * @tc.desc: 1.test VerifyRecoverPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2600, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    bool result = BundlePermissionMgr::VerifyRecoverPermission();
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: BundlePermissionMgr_2700
 * @tc.name: test VerifyUninstallPermission
 * @tc.desc: 1.test VerifyUninstallPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2700, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    bool result = BundlePermissionMgr::VerifyUninstallPermission();
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: BundlePermissionMgr_2800
 * @tc.name: test IsSelfCalling
 * @tc.desc: 1.test IsSelfCalling of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2800, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    bool result = BundlePermissionMgr::IsSelfCalling();
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: BundlePermissionMgr_2900
 * @tc.name: test IsCallingUidValid
 * @tc.desc: 1.test IsCallingUidValid of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_2900, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    int32_t uid = 100;
    bool result = BundlePermissionMgr::IsCallingUidValid(uid);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: BundlePermissionMgr_3000
 * @tc.name: test IsCallingUidValid
 * @tc.desc: 1.test VerifyCallingUid of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_3000, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    bool result = BundlePermissionMgr::VerifyCallingUid();
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: BundlePermissionMgr_3100
 * @tc.name: test IsNativeTokenType
 * @tc.desc: 1.test IsNativeTokenType of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_3100, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    bool result = BundlePermissionMgr::IsNativeTokenType();
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: BundlePermissionMgr_3200
 * @tc.name: test IsSystemApp
 * @tc.desc: 1.test IsSystemApp of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_3200, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    bool result = BundlePermissionMgr::IsSystemApp();
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: BundlePermissionMgr_3300
 * @tc.name: test ClearUserGrantedPermissionState
 * @tc.desc: 1.test ClearUserGrantedPermissionState of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_3300, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    AccessToken::AccessTokenID tokenId = 100;
    int32_t result = BundlePermissionMgr::ClearUserGrantedPermissionState(tokenId);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.number: BundlePermissionMgr_3400
 * @tc.name: test DeleteAccessTokenId
 * @tc.desc: 1.test DeleteAccessTokenId of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_3400, Function | SmallTest | Level0)
{
    int32_t ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    AccessToken::AccessTokenID tokenId = 100;
    int32_t result = BundlePermissionMgr::DeleteAccessTokenId(tokenId);
    EXPECT_EQ(result, 0);
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
    std::set<std::string> exceptionAppServicePaths;
    std::set<std::string> exceptionAppServiceBundleNames;
    preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        oldExceptionPaths, oldExceptionBundleNames, exceptionAppServicePaths, exceptionAppServiceBundleNames);

    preInstallExceptionMgr->ClearAll();
    std::set<std::string> exceptionPaths;
    std::set<std::string> exceptionBundleNames;
    ret = preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        exceptionPaths, exceptionBundleNames, exceptionAppServicePaths, exceptionAppServiceBundleNames);
    EXPECT_EQ(ret, false);

    preInstallExceptionMgr->SavePreInstallExceptionBundleName(BUNDLE_TEMP_NAME);
    preInstallExceptionMgr->SavePreInstallExceptionPath(BUNDLE_PATH);
    preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        exceptionPaths, exceptionBundleNames, exceptionAppServicePaths, exceptionAppServiceBundleNames);
    preInstallExceptionMgr->DeletePreInstallExceptionBundleName(BUNDLE_TEMP_NAME);
    preInstallExceptionMgr->DeletePreInstallExceptionPath(BUNDLE_PATH);
    ret = preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        exceptionPaths, exceptionBundleNames, exceptionAppServicePaths, exceptionAppServiceBundleNames);
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

/**
* @tc.number: PreInstallExceptionMgr_0002
* @tc.name: test PreInstallExceptionMgr
* @tc.desc: 1. test LoadPreInstallExceptionInfosFromDb
*/
HWTEST_F(BmsServiceStartupTest, PreInstallExceptionMgr_0002, Function | SmallTest | Level0)
{
    if (bundleMgrService_ == nullptr) {
        return;
    }

    auto preInstallExceptionMgr = bundleMgrService_->GetPreInstallExceptionMgr();
    bool ret = preInstallExceptionMgr != nullptr;
    EXPECT_EQ(ret, true);

    ret = preInstallExceptionMgr->LoadPreInstallExceptionInfosFromDb();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CreateStream_0100
 * @tc.name: CreateStream
 * @tc.desc: CreateStream when param is empty.
 */
HWTEST_F(BmsServiceStartupTest, CreateStream_0100, Function | SmallTest | Level1)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    auto res = impl.CreateStream("");
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: CreateStream_0200
 * @tc.name: CreateSignatureFileStream
 * @tc.desc: CreateSignatureFileStream when param is empty.
 */
HWTEST_F(BmsServiceStartupTest, CreateStream_0200, Function | SmallTest | Level1)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    std::string name = "test";
    auto res = impl.CreateSignatureFileStream(name, "");
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);

    res = impl.CreateSignatureFileStream("", name);
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);

    res = impl.CreateSignatureFileStream(name, name);
    EXPECT_EQ(res, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: Marshalling_0100
 * @tc.name: Marshalling
 * @tc.desc: test Marshalling of DisposedRule
 */
HWTEST_F(BmsServiceStartupTest, Marshalling_0100, Function | SmallTest | Level1)
{
    DisposedRule rule;
    std::vector<ElementName> elementList;
    ElementName elementName(STRING_TYPE, STRING_TYPE, STRING_TYPE, STRING_TYPE);
    elementList.emplace_back(elementName);
    Parcel parcel;
    bool res = rule.Marshalling(parcel);
    EXPECT_EQ(res, true);

    auto ptr = rule.Unmarshalling(parcel);
    ASSERT_NE(ptr, nullptr);
    delete(ptr);
}

/**
 * @tc.number: Marshalling_0200
 * @tc.name: Marshalling
 * @tc.desc: test Marshalling of BundlePackInfo
 */
HWTEST_F(BmsServiceStartupTest, Marshalling_0200, Function | SmallTest | Level1)
{
    BundlePackInfo info;
    Parcel parcel;
    bool res = info.Marshalling(parcel);
    EXPECT_EQ(res, true);

    auto ptr = info.Unmarshalling(parcel);
    ASSERT_NE(ptr, nullptr);
    delete(ptr);
}

/**
 * @tc.number: Marshalling_0300
 * @tc.name: Marshalling
 * @tc.desc: test Marshalling of BmsExperienceRule
 */
HWTEST_F(BmsServiceStartupTest, Marshalling_0300, Function | SmallTest | Level1)
{
    BmsExperienceRule rule;
    Parcel parcel;
    bool res = rule.Marshalling(parcel);
    EXPECT_EQ(res, true);

    auto ptr = rule.Unmarshalling(parcel);
    ASSERT_NE(ptr, nullptr);
    delete(ptr);
}

/**
 * @tc.number: Marshalling_0400
 * @tc.name: Marshalling
 * @tc.desc: test Marshalling of BmsCallerInfo
 */
HWTEST_F(BmsServiceStartupTest, Marshalling_0400, Function | SmallTest | Level1)
{
    BmsCallerInfo info;
    Parcel parcel;
    bool res = info.Marshalling(parcel);
    EXPECT_EQ(res, true);

    auto ptr = info.Unmarshalling(parcel);
    ASSERT_NE(ptr, nullptr);
    delete(ptr);
}

/**
 * @tc.number: CheckConnectService_0100
 * @tc.name: CheckConnectService
 * @tc.desc: test CheckConnectService of BmsEcologicalRuleMgrServiceClient
 */
HWTEST_F(BmsServiceStartupTest, CheckConnectService_0100, Function | SmallTest | Level1)
{
    auto client = BmsEcologicalRuleMgrServiceClient::GetInstance();
    bool ret = client->CheckConnectService();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: QueryFreeInstallExperience_0100
 * @tc.name: QueryFreeInstallExperience
 * @tc.desc: test QueryFreeInstallExperience of BmsEcologicalRuleMgrServiceClient
 */
HWTEST_F(BmsServiceStartupTest, QueryFreeInstallExperience_0100, Function | SmallTest | Level1)
{
    auto client = BmsEcologicalRuleMgrServiceClient::GetInstance();
    Want want;
    BmsCallerInfo callerInfo;
    BmsExperienceRule rule;
    auto ret = client->QueryFreeInstallExperience(want, callerInfo, rule);
    EXPECT_EQ(ret, OHOS::AppExecFwk::IBmsEcologicalRuleMgrService::ErrCode::ERR_FAILED);
}

/**
 * @tc.number: BatchQueryAbilityInfosTest
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsServiceStartupTest, BatchQueryAbilityInfosTest, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    Want want;
    std::vector<Want> wants = { want };
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bmsExtensionClient->BatchQueryAbilityInfos(wants, FLAG, FLAG, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryAbilityInfoTest
 * @tc.name: QueryAbilityInfo
 * @tc.desc: test QueryAbilityInfoTest of BmsExtensionClient
 */
HWTEST_F(BmsServiceStartupTest, QueryAbilityInfoTest, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    Want want;
    AbilityInfo abilityInfo;
    auto ret = bmsExtensionClient->QueryAbilityInfo(want, FLAG, FLAG, abilityInfo, false);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetBundleInfosTest
 * @tc.name: GetBundleInfos
 * @tc.desc: test GetBundleInfos of BmsExtensionClient
 */
HWTEST_F(BmsServiceStartupTest, GetBundleInfosTest, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    std::vector<BundleInfo> bundleInfos;
    auto ret1 = bmsExtensionClient->GetBundleInfos(FLAG, bundleInfos, FLAG, false);
    EXPECT_NE(ret1, ERR_OK);

    BundleInfo info;
    auto ret2 = bmsExtensionClient->GetBundleInfo(STRING_TYPE, FLAG, info, FLAG, false);
    EXPECT_NE(ret2, ERR_OK);
}

/**
 * @tc.number: BatchGetBundleInfoTest
 * @tc.name: BatchGetBundleInfo
 * @tc.desc: test BatchGetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsServiceStartupTest, BatchGetBundleInfoTest, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    std::vector<std::string> bundleNames;
    std::vector<BundleInfo> bundleInfos;
    auto ret = bmsExtensionClient->BatchGetBundleInfo(bundleNames, FLAG, bundleInfos, false);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: ImplicitQueryAbilityInfosTest
 * @tc.name: ImplicitQueryAbilityInfos
 * @tc.desc: test ImplicitQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsServiceStartupTest, ImplicitQueryAbilityInfosTest, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bmsExtensionClient->ImplicitQueryAbilityInfos(want, FLAG, FLAG, abilityInfos, false);
    EXPECT_NE(ret, ERR_OK);
}
} // OHOS