/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <sstream>
#include <string>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "if_system_ability_manager.h"
#include "inner_app_quick_fix.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "iservice_registry.h"
#include "mock_quick_fix_callback.h"
#include "mock_status_receiver.h"
#include "quick_fix_data_mgr.h"
#include "quick_fix_deleter.h"
#include "quick_fix_deployer.h"
#include "quick_fix_switcher.h"
#include "quick_fix_checker.h"
#include "quick_fix_status_callback_proxy.h"
#include "quick_fix/patch_parser.h"
#include "quick_fix/patch_profile.h"
#include "quick_fix/quick_fix_boot_scanner.h"
#include "quick_fix/quick_fix_manager_rdb.h"
#include "quick_fix/quick_fix_mgr.h"
#include "quick_fix/quick_fixer.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const std::string BUNDLE_NAME_DEMO = "com.example.demo.bmsaccesstoken1";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/quick_fix/bmsAccessTokentest1.hap";
const std::string HAP_FILE_PATH2 = "/data/test/resource/bms/quick_fix/bmsAccessTokentest3.hap";
const std::string HQF_FILE_PATH1 = "/data/test/resource/bms/quick_fix/bmsAccessTokentest1.hqf";
const std::string HAP_PATH_TEST_RAW_FILE = "/data/test/resource/bms/quick_fix/driver_feature_hap.hap";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string QUICK_FIX_ABI = "arms";
const std::string QUICK_FIX_SO_PATH = "libs/arms";
const uint32_t QUICK_FIX_VERSION_CODE = 1;
const uint32_t BUNDLE_VERSION_CODE = 1;
const std::string QUICK_FIX_VERSION_NAME = "1.0";
const std::string BUNDLE_VERSION_NAME = "1.0";
const std::string PROVISION_TYPE_DEBUG = "debug";
const std::string PROVISION_TYPE_RELEASE = "release";
const std::string RESULT_CODE = "resultCode";
const std::string PATCH_PATH = "patch_1";
const std::string MODULE_NAME = "entry";
const std::string FILE1_PATH = "/data/test/hello.hqf";
const std::string FILE2_PATH = "/data/test/world.hqf";
const std::string FILE3_PATH = "/data/test/world.hap";
const std::string INVALID_FILE_SUFFIX_PATH = "/data/test/invalidSuffix.txt";
const std::string INVALID_FILE_PATH_1 = "/data/service/el1/public/bms/bundle_manager_service/hello.hqf";
const std::string INVALID_FILE_PATH_2 = "/data/service/el1/public/bms/bundle_manager_service/quick_fix/../hello.hqf";
const std::string VALID_FILE_PATH_3 = "/data/service/el1/public/bms/bundle_manager_service/quick_fix/hello.hqf";
}  // namespace

class BmsBundleQuickFixTest : public testing::Test {
public:
    BmsBundleQuickFixTest();
    ~BmsBundleQuickFixTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UpdateBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    void AddInnerBundleInfo(const std::string bundleName, const std::string provisionType = PROVISION_TYPE_RELEASE,
        QuickFixType type = QuickFixType::PATCH);
    void UninstallBundleInfo(const std::string bundleName);
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    const std::shared_ptr<QuickFixDeployer> GetQuickFixDeployer(bool isDebug = false);
    const std::shared_ptr<QuickFixDeleter> GetQuickFixDeleter();
    const std::shared_ptr<QuickFixSwitcher> GetQuickFixSwitcher();
    const std::shared_ptr<QuickFixDataMgr> GetQuickFixDataMgr() const;
    AppQuickFix CreateAppQuickFix();
    void StartInstalldService() const;
    void StartBundleService();
    sptr<IQuickFixManager> GetQuickFixManagerProxy();
    void CreateFiles(const std::vector<std::string>& sourceFiles);
    void DeleteFiles(const std::vector<std::string>& destFiles);
    void ClearDataMgr();
    void ResetDataMgr();

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    std::shared_ptr<QuickFixDeployer> deployer_ = nullptr;
    std::shared_ptr<QuickFixDeleter> deleter_ = nullptr;
    std::shared_ptr<QuickFixSwitcher> switcher_ = nullptr;
    static std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_;
};

std::shared_ptr<BundleMgrService> BmsBundleQuickFixTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleQuickFixTest::installdService_ =
    std::make_shared<InstalldService>();

std::shared_ptr<QuickFixDataMgr> BmsBundleQuickFixTest::quickFixDataMgr_ =
    DelayedSingleton<QuickFixDataMgr>::GetInstance();

BmsBundleQuickFixTest::BmsBundleQuickFixTest()
{}

BmsBundleQuickFixTest::~BmsBundleQuickFixTest()
{}

void BmsBundleQuickFixTest::SetUpTestCase()
{}

void BmsBundleQuickFixTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleQuickFixTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr != nullptr) {
        dataMgr->AddUserId(USERID);
    }
}

void BmsBundleQuickFixTest::TearDown()
{}

void BmsBundleQuickFixTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleQuickFixTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

ErrCode BmsBundleQuickFixTest::InstallBundle(const std::string &bundlePath) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleQuickFixTest::UpdateBundle(const std::string &bundlePath) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USERID;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleQuickFixTest::UnInstallBundle(const std::string &bundleName) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleQuickFixTest::AddInnerBundleInfo(const std::string bundleName,
    const std::string provisionType,
    QuickFixType type)
{
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    deployedAppqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    deployedAppqfInfo.cpuAbi = QUICK_FIX_ABI;
    deployedAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    deployedAppqfInfo.type = type;
    bundleInfo.versionCode = BUNDLE_VERSION_CODE;
    bundleInfo.versionName = BUNDLE_VERSION_NAME;

    ApplicationInfo applicationInfo;
    applicationInfo.name = bundleName;
    if (provisionType == PROVISION_TYPE_DEBUG) {
        applicationInfo.debug = true;
        applicationInfo.appProvisionType = PROVISION_TYPE_DEBUG;
        deployedAppqfInfo.hqfInfos.push_back(HqfInfo());
    }
    applicationInfo.appQuickFix.deployedAppqfInfo = deployedAppqfInfo;
    applicationInfo.appQuickFix.deployingAppqfInfo = deployedAppqfInfo;
    applicationInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = bundleName;
    userInfo.bundleUserInfo.userId = USERID;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = bundleName;
    moduleInfo.name = bundleName;
    moduleInfo.modulePackage = bundleName;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    innerBundleInfo.InsertInnerModuleInfo(bundleName, moduleInfo);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bool addRet = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    bool endRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(addRet);
    EXPECT_TRUE(endRet);
}

void BmsBundleQuickFixTest::UninstallBundleInfo(const std::string bundleName)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

void BmsBundleQuickFixTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleQuickFixTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleQuickFixTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

const std::shared_ptr<QuickFixDeployer> BmsBundleQuickFixTest::GetQuickFixDeployer(bool isDebug)
{
    if (deployer_ == nullptr) {
        std::vector<std::string> path;
        deployer_ = std::make_shared<QuickFixDeployer>(path, isDebug);
    }
    return deployer_;
}

const std::shared_ptr<QuickFixDeleter> BmsBundleQuickFixTest::GetQuickFixDeleter()
{
    if (deleter_ == nullptr) {
        deleter_ = std::make_shared<QuickFixDeleter>(BUNDLE_NAME);
    }
    return deleter_;
}

const std::shared_ptr<QuickFixSwitcher> BmsBundleQuickFixTest::GetQuickFixSwitcher()
{
    if (switcher_ == nullptr) {
        switcher_ = std::make_shared<QuickFixSwitcher>(BUNDLE_NAME, true);
    }
    return switcher_;
}

const std::shared_ptr<QuickFixDataMgr> BmsBundleQuickFixTest::GetQuickFixDataMgr() const
{
    return quickFixDataMgr_;
}

AppQuickFix BmsBundleQuickFixTest::CreateAppQuickFix()
{
    AppqfInfo appInfo;
    appInfo.versionCode = QUICK_FIX_VERSION_CODE;
    appInfo.versionName = QUICK_FIX_VERSION_NAME;
    appInfo.type = QuickFixType::PATCH;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "entry";
    hqfInfo.type = QuickFixType::PATCH;
    appInfo.hqfInfos.push_back(hqfInfo);
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    appQuickFix.versionCode = BUNDLE_VERSION_CODE;
    appQuickFix.versionName = BUNDLE_VERSION_NAME;
    appQuickFix.deployingAppqfInfo = appInfo;
    return appQuickFix;
}

sptr<IQuickFixManager> BmsBundleQuickFixTest::GetQuickFixManagerProxy()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("GetSystemAbilityManager failed.");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        APP_LOGE("GetSystemAbility failed.");
        return nullptr;
    }
    auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
    if (bundleMgr == nullptr) {
        APP_LOGE("iface_cast failed.");
        return nullptr;
    }
    return bundleMgr->GetQuickFixManagerProxy();
}

void BmsBundleQuickFixTest::CreateFiles(const std::vector<std::string>& sourceFiles)
{
    for (const auto& path : sourceFiles) {
        SaveStringToFile(path, path);
    }
}

void BmsBundleQuickFixTest::DeleteFiles(const std::vector<std::string>& destFiles)
{
    for (const auto& path : destFiles) {
        RemoveFile(path);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0001
 * Function: CheckAppQuickFixInfos
 * @tc.name: test QuickFixChecker
 * @tc.require: issueI5N7AD
 * @tc.desc: 1. check bundle name not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0001, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);

    appQuickFix.bundleName = "wrong_name";
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfos(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_SAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0002
 * Function: CheckAppQuickFixInfos
 * @tc.name: test QuickFixChecker
 * @tc.require: issueI5N7AD
 * @tc.desc: 1. check bundle version code not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0002, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);

    appQuickFix.deployingAppqfInfo.hqfInfos[0].moduleName = "feature";
    appQuickFix.versionCode = 20000;
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfos(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_NOT_SAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0004
 * Function: CheckAppQuickFixInfos
 * @tc.name: test QuickFixChecker
 * @tc.require: issueI5N7AD
 * @tc.desc: 1. check patch version code not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0004, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);

    appQuickFix.deployingAppqfInfo.versionCode = 20000;
    appQuickFix.deployingAppqfInfo.hqfInfos[0].moduleName = "feature";
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfos(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_VERSION_CODE_NOT_SAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0006
 * Function: CheckAppQuickFixInfos
 * @tc.name: test QuickFixChecker
 * @tc.require: issueI5N7AD
 * @tc.desc: 1. check patch version code not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0006, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);

    appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
    appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
    appQuickFix.deployingAppqfInfo.hqfInfos[0].moduleName = "feature";
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfos(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_TYPE_NOT_SAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0007
 * Function: CheckAppQuickFixInfos
 * @tc.name: test QuickFixChecker
 * @tc.require: issueI5N7AD
 * @tc.desc: 1. check module not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0007, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfos(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_SAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0008
 * Function: CheckAppQuickFixInfos
 * @tc.name: test QuickFixChecker
 * @tc.require: issueI5N7AD
 * @tc.desc: 1. check module not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0008, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);

    appQuickFix.deployingAppqfInfo.hqfInfos[0].moduleName = "feature";
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfos(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0009
 * Function: Query inner app quick fix
 * @tc.name: test QuickFixDataMgr
 * @tc.require: issueI5N7AD
 * @tc.desc: 1. check module not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0009, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix = CreateAppQuickFix();
    QuickFixMark mark;
    mark.bundleName = appQuickFix.bundleName;
    mark.status = QuickFixStatus::DEPLOY_START;
    InnerAppQuickFix innerAppQuickFix(appQuickFix, mark);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    ErrCode ret = ERR_OK;
    if (deployer != nullptr) {
        ret = deployer->SaveAppQuickFix(innerAppQuickFix);
        EXPECT_EQ(ret, ERR_OK);
        auto quickFixMgr = GetQuickFixDataMgr();
        EXPECT_FALSE(quickFixMgr == nullptr);
        InnerAppQuickFix tempInnerAppQuickFix;
        bool query = quickFixMgr->QueryInnerAppQuickFix(appQuickFix.bundleName, tempInnerAppQuickFix);
        EXPECT_EQ(query, true);
        EXPECT_EQ(tempInnerAppQuickFix.GetAppQuickFix().bundleName, appQuickFix.bundleName);
        EXPECT_EQ(tempInnerAppQuickFix.GetAppQuickFix().versionCode, appQuickFix.versionCode);
        query = quickFixMgr->DeleteInnerAppQuickFix(appQuickFix.bundleName);
        EXPECT_EQ(query, true);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0010
 * Function: Query DeployQuickFixResult
 * @tc.name: test ToDeployQuickFixResult
 * @tc.require: issueI5N7AD
 * @tc.desc: parse and check ToDeployQuickFixResult
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0010, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        deployer->ToDeployQuickFixResult(appQuickFix);
        DeployQuickFixResult result = deployer->GetDeployQuickFixResult();
        EXPECT_EQ(result.bundleName, appQuickFix.bundleName);
        EXPECT_EQ(result.bundleVersionCode, appQuickFix.versionCode);
        EXPECT_EQ(result.patchVersionCode, appQuickFix.deployingAppqfInfo.versionCode);
        EXPECT_EQ(result.type, appQuickFix.deployingAppqfInfo.type);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0011
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: GetBundleInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0011, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0012
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: GetBundleInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0012, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0013
 * Function: GetBundleInfo
 * @tc.name: test GetBundleInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: GetBundleInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0013, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0014
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckCommonWithInstalledBundle
 * @tc.require: issueI5MZ5L
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0014, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        QuickFixChecker checker;
        ret = checker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0015
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckCommonWithInstalledBundle
 * @tc.require: issueI5MZ5L
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0015, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.versionCode = 200005;
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        QuickFixChecker checker;
        ret = checker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_NOT_SAME);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0016
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckCommonWithInstalledBundle
 * @tc.require: issueI5MZ5D
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0016, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.versionCode = 2;
        bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.hqfInfos.emplace_back(HqfInfo());
        QuickFixChecker checker;
        ret = checker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_ERROR);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0017
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckHotReloadWithInstalledBundle
 * @tc.require: issueI5MZ5D
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0017, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.versionCode = 2;
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        QuickFixChecker checker;
        ret = checker.CheckHotReloadWithInstalledBundle(appQuickFix, bundleInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_HOT_RELOAD_NOT_SUPPORT_RELEASE_BUNDLE);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0018
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckHotReloadWithInstalledBundle
 * @tc.require: issueI5MZ7R
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0018, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.versionCode = 2;
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        QuickFixChecker checker;
        ret = checker.CheckHotReloadWithInstalledBundle(appQuickFix, bundleInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_ALREADY_EXISTED);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0019
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckHotReloadWithInstalledBundle
 * @tc.require: issueI5MZ7R
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0019, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG, QuickFixType::HOT_RELOAD);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.versionCode = 2;
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        QuickFixChecker checker;
        ret = checker.CheckHotReloadWithInstalledBundle(appQuickFix, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0020
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckPatchWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0020, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG, QuickFixType::HOT_RELOAD);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.versionCode = 2;
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        Security::Verify::ProvisionInfo provisionInfo;
        QuickFixChecker checker;
        ret = checker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_HOT_RELOAD_ALREADY_EXISTED);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0021
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckPatchWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0021, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.versionCode = 2;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "libs/armeabi-v7a";
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        Security::Verify::ProvisionInfo provisionInfo;
        QuickFixChecker checker;
        ret = checker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0022
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckPatchWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckPatchWithInstalledBundle, signature info not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0022, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.versionCode = 2;
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        Security::Verify::ProvisionInfo provisionInfo;
        QuickFixChecker checker;
        ret = checker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0023
 * Function: SaveInnerAppQuickFix
 * @tc.name: test update
 * @tc.require: issueI5N7AD
 * @tc.desc: update hap, app quick fix info will be deleted
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0023, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto quickFixMgr = GetQuickFixDataMgr();
    EXPECT_FALSE(quickFixMgr == nullptr);
    if (quickFixMgr != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        QuickFixMark mark;
        mark.bundleName = appQuickFix.bundleName;
        mark.status = QuickFixStatus::DEPLOY_END;
        InnerAppQuickFix innerAppQuickFix(appQuickFix, mark);
        bool ret = quickFixMgr->SaveInnerAppQuickFix(innerAppQuickFix);
        EXPECT_TRUE(ret);
        ErrCode updateResult = UpdateBundle(HAP_FILE_PATH1);
        EXPECT_EQ(updateResult, ERR_OK);
        ret = quickFixMgr->QueryInnerAppQuickFix(appQuickFix.bundleName, innerAppQuickFix);
        EXPECT_FALSE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0024
 * Function: SaveInnerAppQuickFix
 * @tc.name: test add new module
 * @tc.require: issueI5N7AD
 * @tc.desc: update hap, app quick fix info will not be deleted
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0024, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto quickFixMgr = GetQuickFixDataMgr();
    EXPECT_FALSE(quickFixMgr == nullptr);
    if (quickFixMgr != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        QuickFixMark mark;
        mark.bundleName = appQuickFix.bundleName;
        mark.status = QuickFixStatus::DEPLOY_END;
        InnerAppQuickFix innerAppQuickFix(appQuickFix, mark);
        bool ret = quickFixMgr->SaveInnerAppQuickFix(innerAppQuickFix);
        EXPECT_TRUE(ret);
        ErrCode installResult = InstallBundle(HAP_FILE_PATH2);
        EXPECT_EQ(installResult, ERR_OK);
        ret = quickFixMgr->QueryInnerAppQuickFix(appQuickFix.bundleName, innerAppQuickFix);
        EXPECT_TRUE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0025
 * Function: SaveInnerAppQuickFix
 * @tc.name: test uninstall
 * @tc.require: issueI5N7AD
 * @tc.desc: uninstall hap, app quick fix info will be deleted
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0025, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto quickFixMgr = GetQuickFixDataMgr();
    EXPECT_FALSE(quickFixMgr == nullptr);
    if (quickFixMgr != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        QuickFixMark mark;
        mark.bundleName = appQuickFix.bundleName;
        mark.status = QuickFixStatus::DEPLOY_END;
        InnerAppQuickFix innerAppQuickFix(appQuickFix, mark);
        bool ret = quickFixMgr->SaveInnerAppQuickFix(innerAppQuickFix);
        EXPECT_TRUE(ret);
    }
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
    if (quickFixMgr != nullptr) {
        InnerAppQuickFix innerAppQuickFix;
        bool ret = quickFixMgr->QueryInnerAppQuickFix(BUNDLE_NAME, innerAppQuickFix);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0026
 * Function: GetDeployQuickFixResult
 * @tc.name: test GetDeployQuickFixResult
 * @tc.require: issueI5N7AD
 * @tc.desc: deploy hqf, GetDeployQuickFixResult.
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0026, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        deployer->ToDeployQuickFixResult(appQuickFix);
        DeployQuickFixResult result = deployer->GetDeployQuickFixResult();
        EXPECT_EQ(result.bundleName, appQuickFix.bundleName);
        EXPECT_EQ(result.bundleVersionCode, appQuickFix.versionCode);
        EXPECT_EQ(result.patchVersionCode, appQuickFix.deployingAppqfInfo.versionCode);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0027
 * Function: DeployQuickFix
 * @tc.name: test DeployQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: empty path, DeployQuickFix.
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0027, Function | SmallTest | Level0)
{
    auto quickFixProxy= GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    std::vector<std::string> path;
    ErrCode ret = quickFixProxy->DeployQuickFix(path, callback);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    callback = nullptr;
    ret = quickFixProxy->DeployQuickFix(path, callback);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0028
 * Function: DeployQuickFix
 * @tc.name: test DeployQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: not hqf file, DeployQuickFix.
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0028, Function | SmallTest | Level0)
{
    auto quickFixProxy= GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    std::vector<std::string> path {HAP_FILE_PATH1};
    ErrCode ret = quickFixProxy->DeployQuickFix(path, callback);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0029
 * Function: DeployQuickFix
 * @tc.name: test DeployQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: not exist hqf file, DeployQuickFix.
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0029, Function | SmallTest | Level0)
{
    auto quickFixProxy= GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    std::vector<std::string> path {HQF_FILE_PATH1};
    ErrCode ret = quickFixProxy->DeployQuickFix(path, callback);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0030
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckCommonWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckCommonWithInstalledBundle, bundleInfo has no patch info
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0030, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        QuickFixChecker checker;
        ret = checker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0031
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckCommonWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckCommonWithInstalledBundle, bundleInfo patchVersionCode is
 *           equal to new patchVersionCode
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0031, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.versionCode = 1;
        bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.hqfInfos.push_back(HqfInfo());
        EXPECT_EQ(ret, ERR_OK);
        QuickFixChecker checker;
        ret = checker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_ERROR);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0032
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckCommonWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0032, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.versionCode = 0;
        bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.hqfInfos.push_back(HqfInfo());
        EXPECT_EQ(ret, ERR_OK);
        QuickFixChecker checker;
        ret = checker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0033
 * Function: ProcessNativeLibraryPath
 * @tc.name: test ProcessNativeLibraryPath
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessNativeLibraryPath, bundleInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0033, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        InnerAppQuickFix innerAppQuickFix;
        innerAppQuickFix.SetAppQuickFix(appQuickFix);
        deployer->ProcessNativeLibraryPath(PATCH_PATH, innerAppQuickFix);

        appQuickFix = innerAppQuickFix.GetAppQuickFix();
        deployer->ToDeployQuickFixResult(appQuickFix);
        DeployQuickFixResult result = deployer->GetDeployQuickFixResult();
        EXPECT_EQ(result.bundleName, appQuickFix.bundleName);
        EXPECT_FALSE(result.isSoContained);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0034
 * Function: ProcessNativeLibraryPath
 * @tc.name: test ProcessNativeLibraryPath
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessNativeLibraryPath, bundleInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0034, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].nativeLibraryPath = QUICK_FIX_SO_PATH;
        InnerAppQuickFix innerAppQuickFix;
        innerAppQuickFix.SetAppQuickFix(appQuickFix);
        deployer->ProcessNativeLibraryPath(PATCH_PATH, innerAppQuickFix);

        appQuickFix = innerAppQuickFix.GetAppQuickFix();
        deployer->ToDeployQuickFixResult(appQuickFix);
        DeployQuickFixResult result = deployer->GetDeployQuickFixResult();
        EXPECT_EQ(result.bundleName, appQuickFix.bundleName);
        EXPECT_FALSE(result.isSoContained);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0035
 * Function: ProcessNativeLibraryPath
 * @tc.name: test ProcessNativeLibraryPath
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessNativeLibraryPath, both empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0035, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        InnerAppQuickFix innerAppQuickFix;
        innerAppQuickFix.SetAppQuickFix(appQuickFix);
        deployer->ProcessNativeLibraryPath(PATCH_PATH, innerAppQuickFix);

        appQuickFix = innerAppQuickFix.GetAppQuickFix();
        deployer->ToDeployQuickFixResult(appQuickFix);
        DeployQuickFixResult result = deployer->GetDeployQuickFixResult();
        EXPECT_EQ(result.bundleName, appQuickFix.bundleName);
        EXPECT_FALSE(result.isSoContained);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0036
 * Function: SaveToInnerBundleInfo
 * @tc.name: test SaveToInnerBundleInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: SaveToInnerBundleInfo, bundleName is not exist in bundleInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0036, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        InnerAppQuickFix innerAppQuickFix;
        innerAppQuickFix.SetAppQuickFix(appQuickFix);
        ErrCode ret = deployer->SaveToInnerBundleInfo(innerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0037
 * Function: SaveToInnerBundleInfo
 * @tc.name: test SaveToInnerBundleInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: SaveToInnerBundleInfo, bundleName exists in bundleInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0037, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        InnerAppQuickFix innerAppQuickFix;
        innerAppQuickFix.SetAppQuickFix(appQuickFix);
        ErrCode ret = deployer->SaveToInnerBundleInfo(innerAppQuickFix);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0038
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessBundleFilePaths, .hap
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0038, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> paths {HAP_FILE_PATH1};
        std::vector<std::string> realPaths;
        ErrCode ret = deployer->ProcessBundleFilePaths(paths, realPaths);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0039
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessBundleFilePaths, empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0039, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> paths;
        std::vector<std::string> realPaths;
        ErrCode ret = deployer->ProcessBundleFilePaths(paths, realPaths);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0040
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessBundleFilePaths, path not exit
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0040, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> paths {HQF_FILE_PATH1};
        std::vector<std::string> realPaths;
        ErrCode ret = deployer->ProcessBundleFilePaths(paths, realPaths);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0041
 * Function: RemoveDeployingInfo
 * @tc.name: test RemoveDeployingInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: RemoveDeployingInfo, bundleName is not existed
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0041, Function | SmallTest | Level0)
{
    auto deleter = GetQuickFixDeleter();
    EXPECT_FALSE(deleter == nullptr);
    if (deleter != nullptr) {
        ErrCode ret = deleter->RemoveDeployingInfo(BUNDLE_NAME);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0042
 * Function: RemoveDeployingInfo
 * @tc.name: test RemoveDeployingInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: RemoveDeployingInfo, bundleName exists, hqfInfos empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0042, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    auto deleter = GetQuickFixDeleter();
    EXPECT_FALSE(deleter == nullptr);
    if (deleter != nullptr) {
        ErrCode ret = deleter->RemoveDeployingInfo(BUNDLE_NAME);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0043
 * Function: RemoveDeployingInfo
 * @tc.name: test RemoveDeployingInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: RemoveDeployingInfo, bundleName exists, hqfInfos not empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0043, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG);
    auto deleter = GetQuickFixDeleter();
    EXPECT_FALSE(deleter == nullptr);
    if (deleter != nullptr) {
        ErrCode ret = deleter->RemoveDeployingInfo(BUNDLE_NAME);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0044
 * Function: InnerSwitchQuickFix
 * @tc.name: test InnerSwitchQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: InnerSwitchQuickFix, bundleName not exists
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0044, Function | SmallTest | Level0)
{
    auto switcher = GetQuickFixSwitcher();
    EXPECT_FALSE(switcher == nullptr);
    if (switcher != nullptr) {
        InnerAppQuickFix innerAppQuickFix;
        ErrCode ret = switcher->InnerSwitchQuickFix(BUNDLE_NAME, innerAppQuickFix, true);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0045
 * Function: InnerSwitchQuickFix
 * @tc.name: test InnerSwitchQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: InnerSwitchQuickFix, bundleName exists, hqfInfos empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0045, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);

    auto switcher = GetQuickFixSwitcher();
    EXPECT_FALSE(switcher == nullptr);
    if (switcher != nullptr) {
        InnerAppQuickFix innerAppQuickFix;
        ErrCode ret = switcher->InnerSwitchQuickFix(BUNDLE_NAME, innerAppQuickFix, false);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_INFO_IN_BUNDLE_INFO);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0046
 * Function: ToDeployEndStatus
 * @tc.name: test ToDeployEndStatus
 * @tc.require: issueI5N7AD
 * @tc.desc: ToDeployEndStatus nativeLibraryPath empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0046, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        InnerAppQuickFix newInnerAppQuickFix;
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        InnerAppQuickFix oldInnerAppQuickFix;
        ErrCode ret = deployer->ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0047
 * Function: ToDeployEndStatus
 * @tc.name: test ToDeployEndStatus
 * @tc.require: issueI5N7AD
 * @tc.desc: ToDeployEndStatus nativeLibraryPath not empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0047, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        InnerAppQuickFix newInnerAppQuickFix;
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        InnerAppQuickFix oldInnerAppQuickFix;
        ErrCode ret = deployer->ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0048
 * Function: ToDeployEndStatus
 * @tc.name: test ToDeployEndStatus
 * @tc.require: issueI5N7AD
 * @tc.desc: ToDeployEndStatus nativeLibraryPath not empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0048, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        InnerAppQuickFix newInnerAppQuickFix;
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        InnerAppQuickFix oldInnerAppQuickFix;
        ErrCode ret = deployer->ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0049
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessBundleFilePaths
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0049, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        QuickFixManagerHostImpl quickFixManagerHostImpl;
        std::string fileName = "test.hqf";
        int32_t fd = -1;
        std::string path = "";
        auto res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
        EXPECT_EQ(res, ERR_OK);
        const std::vector<std::string> sourceFiles {path};
        std::vector<std::string> secureDirs;
        res = quickFixManagerHostImpl.CopyHqfToSecurityDir(sourceFiles, secureDirs);
        EXPECT_EQ(res, ERR_OK);
        std::vector<std::string> realFilePaths;
        auto ret = deployer->ProcessBundleFilePaths(secureDirs, realFilePaths);
        EXPECT_EQ(ret, ERR_OK);
        DeleteFiles(sourceFiles);
        DeleteFiles(secureDirs);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0050
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessBundleFilePaths
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0050, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> sourceFiles {FILE1_PATH, FILE2_PATH, INVALID_FILE_SUFFIX_PATH};
        CreateFiles(sourceFiles);
        std::vector<std::string> realFilePaths;
        ErrCode ret = deployer->ProcessBundleFilePaths(sourceFiles, realFilePaths);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
        DeleteFiles(sourceFiles);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0051
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessBundleFilePaths
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0051, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> sourceFiles {FILE1_PATH, FILE2_PATH, FILE3_PATH};
        CreateFiles(sourceFiles);
        std::vector<std::string> realFilePaths;
        ErrCode ret = deployer->ProcessBundleFilePaths(sourceFiles, realFilePaths);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
        DeleteFiles(sourceFiles);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0052
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckPatchWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckPatchWithInstalledBundle, signature info not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0052, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.versionCode = 2;
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        Security::Verify::ProvisionInfo provisionInfo;
        QuickFixChecker checker;
        ret = checker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0053
 * Function: ToDeployEndStatus
 * @tc.name: test ToDeployEndStatus
 * @tc.require: issueI5N7AD
 * @tc.desc: ToDeployEndStatus
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0053, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> sourcePath {FILE1_PATH};
        CreateFiles(sourcePath);
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        std::vector<HqfInfo> hqfInfo;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        appQuickFix.deployingAppqfInfo.hqfInfos= hqfInfo;
        InnerAppQuickFix newInnerAppQuickFix;
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        InnerAppQuickFix oldInnerAppQuickFix;
        ErrCode ret = deployer->ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO);
        DeleteFiles(sourcePath);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0054
 * Function: ToDeployEndStatus
 * @tc.name: test ToDeployEndStatus
 * @tc.require: issueI5N7AD
 * @tc.desc: ToDeployEndStatus
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0054, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG, QuickFixType::HOT_RELOAD);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> sourcePath {FILE1_PATH};
        CreateFiles(sourcePath);
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.versionCode = 2;
        std::vector<HqfInfo> hqfInfo;
        appQuickFix.deployingAppqfInfo.hqfInfos= hqfInfo;
        InnerAppQuickFix newInnerAppQuickFix;
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        InnerAppQuickFix oldInnerAppQuickFix;
        ErrCode ret = deployer->ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_OK);
        DeleteFiles(sourcePath);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0055
 * Function: RemoveDeployingInfo
 * @tc.name: test RemoveDeployingInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: RemoveDeployingInfo, bundleName exists, hqfInfos not empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0055, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG);
    auto deleter = GetQuickFixDeleter();
    EXPECT_FALSE(deleter == nullptr);
    if (deleter != nullptr) {
        ErrCode ret = deleter->RemoveDeployingInfo(BUNDLE_NAME);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0056
 * Function: GetAppProvisionType
 * @tc.name: test GetAppProvisionType
 * @tc.require: issueI5N7AD
 * @tc.desc: GetAppProvisionType, debug
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0056, Function | SmallTest | Level0)
{
    QuickFixChecker checker;
    std::string type = checker.GetAppProvisionType(Security::Verify::ProvisionType::DEBUG);
    EXPECT_EQ(type, PROVISION_TYPE_DEBUG);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0057
 * Function: GetAppProvisionType
 * @tc.name: test GetAppProvisionType
 * @tc.require: issueI5N7AD
 * @tc.desc: GetAppProvisionType release
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0057, Function | SmallTest | Level0)
{
    QuickFixChecker checker;
    std::string type = checker.GetAppProvisionType(Security::Verify::ProvisionType::RELEASE);
    EXPECT_EQ(type, PROVISION_TYPE_RELEASE);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0058
 * Function: GetAppDistributionType
 * @tc.name: test GetAppDistributionType
 * @tc.require: issueI5N7AD
 * @tc.desc: GetAppDistributionType app_gallery
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0058, Function | SmallTest | Level0)
{
    QuickFixChecker checker;
    std::string type = checker.GetAppDistributionType(Security::Verify::AppDistType::APP_GALLERY);
    EXPECT_EQ(type, "app_gallery");
}

/**
 * @tc.number: BmsBundleQuickFixTest_0059
 * Function: GetAppDistributionType
 * @tc.name: test GetAppDistributionType
 * @tc.require: issueI5N7AD
 * @tc.desc: GetAppDistributionType none
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0059, Function | SmallTest | Level0)
{
    QuickFixChecker checker;
    std::string type = checker.GetAppDistributionType(static_cast<Security::Verify::AppDistType>(7));
    EXPECT_EQ(type, "none");
}

/**
 * @tc.number: BmsBundleQuickFixTest_0060
 * Function: CheckMultiNativeSo
 * @tc.name: test CheckMultiNativeSo
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckMultiNativeSo empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0060, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    QuickFixChecker checker;
    auto ret = checker.CheckMultiNativeSo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0061
 * Function: CheckMultiNativeSo
 * @tc.name: test CheckMultiNativeSo
 * @tc.require: issueI5N7AD
 * @tc.desc: nativeLibraryPath empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0061, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);

    QuickFixChecker checker;
    auto ret = checker.CheckMultiNativeSo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0062
 * Function: CheckMultiNativeSo
 * @tc.name: test CheckMultiNativeSo
 * @tc.require: issueI5N7AD
 * @tc.desc: nativeLibraryPath
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0062, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);

    appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    infos.emplace("appQuickFix_2", appQuickFix);
    infos.emplace("appQuickFix_3", appQuickFix);

    QuickFixChecker checker;
    auto ret = checker.CheckMultiNativeSo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0063
 * Function: CheckMultiNativeSo
 * @tc.name: test CheckMultiNativeSo
 * @tc.require: issueI5N7AD
 * @tc.desc: nativeLibraryPath
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0063, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    infos.emplace("appQuickFix_1", appQuickFix);
    appQuickFix.deployingAppqfInfo.nativeLibraryPath = "wrong";
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    auto ret = checker.CheckMultiNativeSo(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0064
 * Function: CheckMultiNativeSo
 * @tc.name: test CheckMultiNativeSo
 * @tc.require: issueI5N7AD
 * @tc.desc: nativeLibraryPath
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0064, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    infos.emplace("appQuickFix_1", appQuickFix);
    appQuickFix.deployingAppqfInfo.nativeLibraryPath = "wrong";
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    auto ret = checker.CheckMultiNativeSo(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0065
 * Function: CheckMultiNativeSo
 * @tc.name: test CheckMultiNativeSo
 * @tc.require: issueI5N7AD
 * @tc.desc: nativeLibraryPath
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0065, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    infos.emplace("appQuickFix_1", appQuickFix);
    appQuickFix.deployingAppqfInfo.cpuAbi = "wrong";
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    auto ret = checker.CheckMultiNativeSo(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0066
 * Function: CheckSignatureInfo
 * @tc.name: test CheckSignatureInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckSignatureInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0066, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    Security::Verify::ProvisionInfo provisionInfo;
    QuickFixChecker checker;
    auto ret = checker.CheckSignatureInfo(bundleInfo, provisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0067
 * Function: CheckSignatureInfo
 * @tc.name: test CheckSignatureInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckSignatureInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0067, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bundleInfo.name = "bundleName";
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.appId = "1";
    QuickFixChecker checker;
    auto ret = checker.CheckSignatureInfo(bundleInfo, provisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0068
 * Function: CheckSignatureInfo
 * @tc.name: test CheckSignatureInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckSignatureInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0068, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bundleInfo.appId = "_";
    bundleInfo.applicationInfo.appPrivilegeLevel = "normal";
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.bundleInfo.apl = "system_basic";
    QuickFixChecker checker;
    auto ret = checker.CheckSignatureInfo(bundleInfo, provisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0069
 * Function: CheckModuleNameExist
 * @tc.name: test CheckModuleNameExist
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckModuleNameExist
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0069, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix;
    infos.emplace("appQuickFix_1", appQuickFix);

    BundleInfo bundleInfo;
    QuickFixChecker checker;
    auto ret = checker.CheckModuleNameExist(bundleInfo, infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0070
 * Function: CheckModuleNameExist
 * @tc.name: test CheckModuleNameExist
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckModuleNameExist
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0070, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);

    BundleInfo bundleInfo;
    QuickFixChecker checker;
    auto ret = checker.CheckModuleNameExist(bundleInfo, infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0071
 * Function: CheckModuleNameExist
 * @tc.name: test CheckModuleNameExist
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckModuleNameExist
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0071, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);

    BundleInfo bundleInfo;
    bundleInfo.moduleNames.emplace_back("entry");
    QuickFixChecker checker;
    auto ret = checker.CheckModuleNameExist(bundleInfo, infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0072
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckCommonWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0072, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix = CreateAppQuickFix();
    BundleInfo bundleInfo;
    QuickFixChecker checker;
    auto ret = checker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0073
 * Function: CheckCommonWithInstalledBundle
 * @tc.name: test CheckCommonWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckCommonWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0073, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppqfInfo appInfo;
    appInfo.versionCode = QUICK_FIX_VERSION_CODE;
    appInfo.versionName = QUICK_FIX_VERSION_NAME;
    appInfo.type = QuickFixType::PATCH;
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    appQuickFix.versionCode = BUNDLE_VERSION_CODE;
    appQuickFix.versionName = BUNDLE_VERSION_NAME;
    appQuickFix.deployingAppqfInfo = appInfo;
    infos.emplace("appQuickFix_1", appQuickFix);
    infos.emplace("appQuickFix_2", appQuickFix);

    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfos(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0074
 * Function: CheckHotReloadWithInstalledBundle
 * @tc.name: test CheckHotReloadWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckHotReloadWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0074, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix = CreateAppQuickFix();
    BundleInfo bundleInfo;
    QuickFixChecker checker;
    auto ret = checker.CheckHotReloadWithInstalledBundle(appQuickFix, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0075
 * Function: CheckPatchWithInstalledBundle
 * @tc.name: test CheckPatchWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckPatchWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0075, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix = CreateAppQuickFix();
    BundleInfo bundleInfo;
    Security::Verify::ProvisionInfo provisionInfo;
    QuickFixChecker checker;
    auto ret = checker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0077
 * Function: CheckAppQuickFixInfos
 * @tc.name: test CheckAppQuickFixInfos
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckAppQuickFixInfos
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0077, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;

    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfos(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0078
 * Function: CheckAppQuickFixInfos
 * @tc.name: test CheckAppQuickFixInfos
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckAppQuickFixInfos
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0078, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    std::vector<HqfInfo> hqfInfo;
    appQuickFix.deployingAppqfInfo.hqfInfos = hqfInfo;
    infos.emplace("appQuickFix_1", appQuickFix);

    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfos(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0079
 * Function: CheckMultipleHqfsSignInfo
 * @tc.name: test CheckMultipleHqfsSignInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckMultipleHqfsSignInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0079, Function | SmallTest | Level0)
{
    std::vector<std::string> bundlePaths;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    QuickFixChecker checker;
    ErrCode ret = checker.CheckMultipleHqfsSignInfo(bundlePaths, hapVerifyRes);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0080
 * Function: ParseAndCheckAppQuickFixInfos
 * @tc.name: test ParseAndCheckAppQuickFixInfos
 * @tc.require: issueI5N7AD
 * @tc.desc: ParseAndCheckAppQuickFixInfos
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0080, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> bundleFilePaths;
        std::unordered_map<std::string, AppQuickFix> infos;
        ErrCode ret = deployer->ParseAndCheckAppQuickFixInfos(bundleFilePaths, infos);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0081
 * Function: AddHqfInfo
 * @tc.name: test AddHqfInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: AddHqfInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0081, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix;
    auto ret = innerAppQuickFix.AddHqfInfo(appQuickFix);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0082
 * Function: AddHqfInfo
 * @tc.name: test AddHqfInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: AddHqfInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0082, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    auto ret = innerAppQuickFix.AddHqfInfo(appQuickFix);
    EXPECT_TRUE(ret);
    ret = innerAppQuickFix.AddHqfInfo(appQuickFix);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0083
 * Function: AddHqfInfo
 * @tc.name: test AddHqfInfo
 * @tc.require: issueI5N7AD
 * @tc.desc: AddHqfInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0083, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    auto ret = innerAppQuickFix.AddHqfInfo(appQuickFix);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0084
 * Function: ProcessPatchDeployStart
 * @tc.name: test ProcessPatchDeployStart
 * @tc.require: issueI5MZ5D
 * @tc.desc: ProcessPatchDeployStart
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0084, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> bundleFilePaths;
        BundleInfo bundleInfo;
        std::unordered_map<std::string, AppQuickFix> infos;
        ErrCode ret = deployer->ProcessPatchDeployStart(bundleFilePaths, bundleInfo, infos);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0085
 * Function: ProcessPatchDeployStart
 * @tc.name: test ProcessPatchDeployStart
 * @tc.require: issueI5MZ5D
 * @tc.desc: ProcessPatchDeployStart
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0085, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> bundleFilePaths;
        BundleInfo bundleInfo;
        std::unordered_map<std::string, AppQuickFix> infos;
        AppQuickFix appQuickFix;
        infos.emplace("appQuickFix_1", appQuickFix);
        ErrCode ret = deployer->ProcessPatchDeployStart(bundleFilePaths, bundleInfo, infos);
        EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0086
 * Function: ProcessPatchDeployStart
 * @tc.name: test ProcessPatchDeployStart
 * @tc.require: issueI5MZ5D
 * @tc.desc: ProcessPatchDeployStart
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0086, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> bundleFilePaths;
        BundleInfo bundleInfo;
        std::unordered_map<std::string, AppQuickFix> infos;
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        infos.emplace("appQuickFix_1", appQuickFix);
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "wrong";
        infos.emplace("appQuickFix_2", appQuickFix);
        ErrCode ret = deployer->ProcessPatchDeployStart(bundleFilePaths, bundleInfo, infos);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0087
 * Function: ProcessPatchDeployStart
 * @tc.name: test ProcessPatchDeployStart
 * @tc.require: issueI5MZ5D
 * @tc.desc: ProcessPatchDeployStart
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0087, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG, QuickFixType::HOT_RELOAD);
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.versionCode = 2;
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(appQuickFix.bundleName, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        ret = deployer->ProcessHotReloadDeployStart(bundleInfo, appQuickFix);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0088
 * Function: ProcessPatchDeployStart
 * @tc.name: test ProcessPatchDeployStart
 * @tc.require: issueI5MZ5D
 * @tc.desc: ProcessPatchDeployStart
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0088, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        auto ret = deployer->ProcessHotReloadDeployStart(bundleInfo, appQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0089
 * Function: ProcessPatchDeployStart
 * @tc.name: test ProcessPatchDeployStart
 * @tc.require: issueI5MZ5D
 * @tc.desc: ProcessPatchDeployStart
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0089, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        BundleInfo bundleInfo;
        auto ret = deployer->ProcessHotReloadDeployStart(bundleInfo, appQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST);
        std::unordered_map<std::string, AppQuickFix> infos;
        deployer->ResetNativeSoAttrs(infos);
        std::vector<HqfInfo> hqfInfo;
        appQuickFix.deployingAppqfInfo.hqfInfos = hqfInfo;
        deployer->ResetNativeSoAttrs(appQuickFix);
        appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(HqfInfo());
        deployer->ResetNativeSoAttrs(appQuickFix);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0090
 * Function: FetchPatchNativeSoAttrs
 * @tc.name: test FetchPatchNativeSoAttrs
 * @tc.require: issueI5MZ5D
 * @tc.desc: FetchPatchNativeSoAttrs
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0090, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppqfInfo appqfInfo;
        HqfInfo hqfInfo;
        bool isLibIsolated = false;
        std::string nativeLibraryPath;
        std::string cpuAbi;
        auto ret = deployer->FetchPatchNativeSoAttrs(appqfInfo, hqfInfo, isLibIsolated,
            nativeLibraryPath, cpuAbi);
        EXPECT_FALSE(ret);

        isLibIsolated = true;
        ret = deployer->FetchPatchNativeSoAttrs(appqfInfo, hqfInfo, isLibIsolated,
            nativeLibraryPath, cpuAbi);
        EXPECT_FALSE(ret);

        AppQuickFix appQuickFix;
        ret = deployer->HasNativeSoInBundle(appQuickFix);
        EXPECT_FALSE(ret);

        appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        hqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(hqfInfo);
        ret = deployer->HasNativeSoInBundle(appQuickFix);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0091
 * Function: ToInnerAppQuickFix
 * @tc.name: test ToInnerAppQuickFix
 * @tc.require: issueI5MZ5D
 * @tc.desc: ToInnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0091, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::unordered_map<std::string, AppQuickFix> infos;
        InnerAppQuickFix oldInnerAppQuickFix;
        InnerAppQuickFix newInnerAppQuickFix;
        auto ret = deployer->ToInnerAppQuickFix(infos, oldInnerAppQuickFix, newInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR);

        AppQuickFix appQuickFix = CreateAppQuickFix();
        infos.emplace("aaaa", appQuickFix);
        ret = deployer->ToInnerAppQuickFix(infos, oldInnerAppQuickFix, newInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0092
 * Function: CheckPatchVersionCode
 * @tc.name: test CheckPatchVersionCode
 * @tc.require: issueI5MZ5D
 * @tc.desc: CheckPatchVersionCode
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0092, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix newAppQuickFix;
        AppQuickFix oldAppQuickFix;
        auto ret = deployer->CheckPatchVersionCode(newAppQuickFix, oldAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_ERROR);

        newAppQuickFix.deployingAppqfInfo.versionCode = 1;
        ret = deployer->CheckPatchVersionCode(newAppQuickFix, oldAppQuickFix);
        EXPECT_EQ(ret, ERR_OK);

        oldAppQuickFix.deployingAppqfInfo.versionCode = 2;
        ret = deployer->CheckPatchVersionCode(newAppQuickFix, oldAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_ERROR);

        oldAppQuickFix.deployedAppqfInfo.versionCode = 2;
        ret = deployer->CheckPatchVersionCode(newAppQuickFix, oldAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_ERROR);

        InnerAppQuickFix innerAppQuickFix;
        std::string targetPath;
        ret = deployer->MoveHqfFiles(innerAppQuickFix, targetPath);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0093
 * Function: MoveHqfFiles
 * @tc.name: test MoveHqfFiles
 * @tc.require: issueI5MZ5D
 * @tc.desc: MoveHqfFiles
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0093, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        InnerAppQuickFix innerAppQuickFix;
        std::string targetPath;
        auto ret = deployer->MoveHqfFiles(innerAppQuickFix, targetPath);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0094
 * Function: ToDeployEndStatus
 * @tc.name: test ToDeployEndStatus
 * @tc.require: issueI5N7AD
 * @tc.desc: ToDeployEndStatus nativeLibraryPath empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0094, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        InnerAppQuickFix newInnerAppQuickFix;
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        InnerAppQuickFix oldInnerAppQuickFix;
        ErrCode ret = deployer->ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0095
 * Function: ProcessPatchDeployEnd
 * @tc.name: test ProcessPatchDeployEnd
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessPatchDeployEnd nativeLibraryPath empty
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0095, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        std::string patchPath = "data/test";
        ErrCode ret = deployer->ProcessPatchDeployEnd(appQuickFix, patchPath);
        EXPECT_EQ(ret, ERR_OK);
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        ret = deployer->ProcessPatchDeployEnd(appQuickFix, patchPath); // hap has no so file
        EXPECT_EQ(ret, ERR_OK);
    }
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0097
 * Function: DeployQuickFix
 * @tc.name: test DeployQuickFix
 * @tc.require: issueI5MZ5D
 * @tc.desc: DeployQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0097, Function | SmallTest | Level0)
{
    QuickFixManagerHostImpl quickFixManagerHostImpl;
    std::vector<std::string> path;
    sptr<MockQuickFixCallback> callback = nullptr;
    auto res = quickFixManagerHostImpl.DeployQuickFix(path, callback);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    callback = new (std::nothrow) MockQuickFixCallback();
    res = quickFixManagerHostImpl.DeployQuickFix(path, callback);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    callback = nullptr;
    path.push_back("data/test");
    res = quickFixManagerHostImpl.DeployQuickFix(path, callback);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0098
 * Function: CreateFd
 * @tc.name: test CreateFd
 * @tc.require: issueI5MZ5D
 * @tc.desc: CreateFd
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0098, Function | SmallTest | Level0)
{
    QuickFixManagerHostImpl quickFixManagerHostImpl;
    std::string fileName = "test.hqf";
    int32_t fd = -1;
    std::string path = "";
    auto res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_OK);
    fd = 8;
    res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_OK);
    path = "data/test";
    res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_OK);
    fileName = "";
    res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);

    fileName = "../test.hqf";
    res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);

    fileName = "/test.hqf";
    res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);

    fileName = "\\test.hqf";
    res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);

    fileName = "%test.hqf";
    res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0099
 * Function: DefaultNativeSo
 * @tc.name: test DefaultNativeSo
 * @tc.require: issueI5MZ5D
 * @tc.desc: DefaultNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0099, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor(Constants::LIBS + Constants::ARM64_V8A);
    bool isSystemLib64Exist = true;
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    deployedAppqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    deployedAppqfInfo.cpuAbi = QUICK_FIX_ABI;
    deployedAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    deployedAppqfInfo.type = QuickFixType::HOT_RELOAD;
    bool res = patchProfile.DefaultNativeSo(patchExtractor, isSystemLib64Exist, deployedAppqfInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0100
 * Function: DefaultNativeSo
 * @tc.name: test DefaultNativeSo
 * @tc.require: issueI5MZ5D
 * @tc.desc: DefaultNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0100, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor("");
    bool isSystemLib64Exist = true;
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    deployedAppqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    deployedAppqfInfo.cpuAbi = QUICK_FIX_ABI;
    deployedAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    deployedAppqfInfo.type = QuickFixType::HOT_RELOAD;
    bool res = patchProfile.DefaultNativeSo(patchExtractor, isSystemLib64Exist, deployedAppqfInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0101
 * Function: ProcessPatchDeployEnd
 * @tc.name: test ProcessPatchDeployEnd
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessPatchDeployEnd isDebug is true, provisionType is release
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0101, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    std::vector<std::string> bundleFilePaths;
    auto deployer = std::make_shared<QuickFixDeployer>(bundleFilePaths, true);
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        std::string patchPath = "data/test";
        ErrCode ret = deployer->ProcessPatchDeployEnd(appQuickFix, patchPath);
        EXPECT_EQ(ret, ERR_OK);
    }
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0102
 * Function: ProcessPatchDeployEnd
 * @tc.name: test ProcessPatchDeployEnd
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessPatchDeployEnd isDebug is true, provisionType is debug
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0102, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG);
    std::vector<std::string> bundleFilePaths;
    auto deployer = std::make_shared<QuickFixDeployer>(bundleFilePaths, true);
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        std::string patchPath = "data/test";
        ErrCode ret = deployer->ProcessPatchDeployEnd(appQuickFix, patchPath);
        EXPECT_EQ(ret, ERR_OK);
    }
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0103
 * Function: ProcessPatchDeployEnd
 * @tc.name: test ProcessPatchDeployEnd
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessPatchDeployEnd isDebug is true, provisionType is release
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0103, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    std::vector<std::string> bundleFilePaths;
    auto deployer = std::make_shared<QuickFixDeployer>(bundleFilePaths, true);
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        std::string patchPath = "data/test";
        ErrCode ret = deployer->ProcessPatchDeployEnd(appQuickFix, patchPath);
        EXPECT_EQ(ret, ERR_OK);
    }
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0104
 * Function: ExtractQuickFixSoFile
 * @tc.name: test ExtractQuickFixSoFile
 * @tc.require: issueI5N7AD
 * @tc.desc: ExtractQuickFixSoFile
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0104, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix;
        std::string patchPath = "data/test";
        BundleInfo bundleInfo;
        auto ret = deployer->ExtractQuickFixSoFile(appQuickFix, patchPath, bundleInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED);

        appQuickFix = CreateAppQuickFix();
        // moduleName not exist
        ret = deployer->ExtractQuickFixSoFile(appQuickFix, patchPath, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);

        HapModuleInfo info;
        info.moduleName = "entry";
        bundleInfo.hapModuleInfos.emplace_back(info);
        // moduleName exist, so not exist
        ret = deployer->ExtractQuickFixSoFile(appQuickFix, patchPath, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        // so exist
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        ret = deployer->ExtractQuickFixSoFile(appQuickFix, patchPath, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
    }
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0110
 * Function: DefaultNativeSo
 * @tc.name: test DefaultNativeSo
 * @tc.require: issueI5MZ5D
 * @tc.desc: DefaultNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0110, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor(Constants::LIBS + Constants::ARM_EABI_V7A);
    bool isSystemLib64Exist = false;
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    deployedAppqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    deployedAppqfInfo.cpuAbi = QUICK_FIX_ABI;
    deployedAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    deployedAppqfInfo.type = QuickFixType::HOT_RELOAD;
    bool res = patchProfile.DefaultNativeSo(patchExtractor, isSystemLib64Exist, deployedAppqfInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0120
 * Function: DefaultNativeSo
 * @tc.name: test DefaultNativeSo
 * @tc.require: issueI5MZ5D
 * @tc.desc: DefaultNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0120, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor(Constants::LIBS + Constants::ARM_EABI);
    bool isSystemLib64Exist = false;
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    deployedAppqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    deployedAppqfInfo.cpuAbi = QUICK_FIX_ABI;
    deployedAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    deployedAppqfInfo.type = QuickFixType::HOT_RELOAD;
    bool res = patchProfile.DefaultNativeSo(patchExtractor, isSystemLib64Exist, deployedAppqfInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0130
 * Function: DefaultNativeSo
 * @tc.name: test DefaultNativeSo
 * @tc.require: issueI5MZ5D
 * @tc.desc: DefaultNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0130, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor("");
    bool isSystemLib64Exist = false;
    AppqfInfo deployedAppqfInfo;
    bool res = patchProfile.DefaultNativeSo(patchExtractor, isSystemLib64Exist, deployedAppqfInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0140
 * Function: ParseNativeSo
 * @tc.name: test ParseNativeSo
 * @tc.require: issueI5MZ5D
 * @tc.desc: ParseNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0140, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor("");
    AppqfInfo deployedAppqfInfo;
    bool res = patchProfile.ParseNativeSo(patchExtractor, deployedAppqfInfo);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0150
 * Function: ParseNativeSo
 * @tc.name: test ParseNativeSo
 * @tc.require: issueI5MZ5D
 * @tc.desc: ParseNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0150, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor("");
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    deployedAppqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    deployedAppqfInfo.cpuAbi = QUICK_FIX_ABI;
    deployedAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    deployedAppqfInfo.type = QuickFixType::HOT_RELOAD;
    bool res = patchProfile.ParseNativeSo(patchExtractor, deployedAppqfInfo);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0160
 * Function: ParseNativeSo
 * @tc.name: test ParseNativeSo
 * @tc.require: issueI5MZ5D
 * @tc.desc: ParseNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0160, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor(Constants::LIBS);
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    deployedAppqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    deployedAppqfInfo.cpuAbi = QUICK_FIX_ABI;
    deployedAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    deployedAppqfInfo.type = QuickFixType::HOT_RELOAD;
    bool res = patchProfile.ParseNativeSo(patchExtractor, deployedAppqfInfo);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0170
 * Function: ParseNativeSo
 * @tc.name: test ParseNativeSo
 * @tc.require: issueI5MZ5D
 * @tc.desc: ParseNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0170, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor(Constants::LIBS);
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    deployedAppqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
    deployedAppqfInfo.cpuAbi = "arm";
    deployedAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    deployedAppqfInfo.type = QuickFixType::HOT_RELOAD;
    bool res = patchProfile.ParseNativeSo(patchExtractor, deployedAppqfInfo);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0180
 * Function: ParsePatchInfo
 * @tc.name: test ParsePatchInfo
 * @tc.require: issueI5MZ5D
 * @tc.desc: ParsePatchInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0180, Function | SmallTest | Level0)
{
    PatchParser patchParser;
    const std::string pathName = "";
    AppQuickFix appQuickFix = CreateAppQuickFix();
    ErrCode res = patchParser.ParsePatchInfo(pathName, appQuickFix);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARSE_NO_PROFILE);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0190
 * Function: ParsePatchInfo
 * @tc.name: test ParsePatchInfo
 * @tc.require: issueI5MZ5D
 * @tc.desc: ParsePatchInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0190, Function | SmallTest | Level0)
{
    PatchParser patchParser;
    const std::string pathName = "wrong";
    AppQuickFix appQuickFix = CreateAppQuickFix();
    ErrCode res = patchParser.ParsePatchInfo(pathName, appQuickFix);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARSE_UNEXPECTED);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0200
 * Function: InnerDeletePatchDir
 * @tc.name: test InnerDeletePatchDir
 * @tc.require: issueI5N7AD
 * @tc.desc: InnerDeletePatchDir, bundleName is not existed
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0200, Function | SmallTest | Level0)
{
    auto deleter = GetQuickFixDeleter();
    EXPECT_FALSE(deleter == nullptr);
    if (deleter != nullptr) {
        AppqfInfo deployedAppqfInfo;
        deployedAppqfInfo.type = QuickFixType::UNKNOWN;
        ErrCode ret = deleter->InnerDeletePatchDir(deployedAppqfInfo, BUNDLE_NAME);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0210
 * Function: InnerDeletePatchDir
 * @tc.name: test InnerDeletePatchDir
 * @tc.require: issueI5N7AD
 * @tc.desc: InnerDeletePatchDir, bundleName is not existed
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0210, Function | SmallTest | Level0)
{
    auto deleter = GetQuickFixDeleter();
    EXPECT_FALSE(deleter == nullptr);
    if (deleter != nullptr) {
        AppqfInfo deployedAppqfInfo;
        deployedAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
        deployedAppqfInfo.versionName =  QUICK_FIX_VERSION_NAME;
        deployedAppqfInfo.cpuAbi = "arm";
        deployedAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        deployedAppqfInfo.type = QuickFixType::HOT_RELOAD;
        ErrCode ret = deleter->InnerDeletePatchDir(deployedAppqfInfo, BUNDLE_NAME);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0220
 * Function: QueryInnerAppQuickFix
 * @tc.name: test QueryInnerAppQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: QueryInnerAppQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0220, Function | SmallTest | Level0)
{
    auto quickFixMgr = GetQuickFixDataMgr()->quickFixManagerDb_;
    if (quickFixMgr != nullptr) {
        InnerAppQuickFix innerAppQuickFix;
        bool ret = quickFixMgr->QueryInnerAppQuickFix("", innerAppQuickFix);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0230
 * Function: EnableQuickFix
 * @tc.name: test EnableQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: EnableQuickFix, bundleName not exists
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0230, Function | SmallTest | Level0)
{
    auto switcher = GetQuickFixSwitcher();
    EXPECT_FALSE(switcher == nullptr);
    if (switcher != nullptr) {
        ErrCode ret = switcher->EnableQuickFix("");
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0240
 * Function: DisableQuickFix
 * @tc.name: test DisableQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: DisableQuickFix, bundleName not exists
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0240, Function | SmallTest | Level0)
{
    auto switcher = GetQuickFixSwitcher();
    EXPECT_FALSE(switcher == nullptr);
    if (switcher != nullptr) {
        ErrCode ret = switcher->DisableQuickFix("");
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0250
 * Function: InnerSwitchQuickFix
 * @tc.name: test InnerSwitchQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: InnerSwitchQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0250, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG, QuickFixType::HOT_RELOAD);

    auto switcher = GetQuickFixSwitcher();
    EXPECT_FALSE(switcher == nullptr);
    if (switcher != nullptr) {
        InnerAppQuickFix innerAppQuickFix;
        ErrCode ret = switcher->InnerSwitchQuickFix("", innerAppQuickFix, false);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        InnerAppQuickFix newInnerAppQuickFix;
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        ret = switcher->InnerSwitchQuickFix(BUNDLE_NAME, newInnerAppQuickFix, true);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0260
 * Function: InnerSwitchQuickFix
 * @tc.name: test InnerSwitchQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: InnerSwitchQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0260, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG, QuickFixType::HOT_RELOAD);

    auto switcher = GetQuickFixSwitcher();
    EXPECT_FALSE(switcher == nullptr);
    if (switcher != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::HOT_RELOAD;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        InnerAppQuickFix newInnerAppQuickFix;
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        InnerBundleInfo innerBundleInfo;
        ErrCode ret = switcher->CreateInnerAppqf(innerBundleInfo, true, newInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_OLD_PATCH_OR_HOT_RELOAD_IN_DB);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0270
 * Function: CheckPatchNativeSoWithInstalledBundle
 * @tc.name: test CheckPatchNativeSoWithInstalledBundle
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckPatchNativeSoWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0270, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        BundleInfo bundleInfo;
        ErrCode ret = deployer->GetBundleInfo(BUNDLE_NAME, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);
        AppqfInfo deployedAppqfInfo;
        deployedAppqfInfo.cpuAbi = bundleInfo.applicationInfo.cpuAbi;
        QuickFixChecker checker;
        ret = checker.CheckPatchNativeSoWithInstalledBundle(bundleInfo, deployedAppqfInfo);
        EXPECT_EQ(ret, ERR_OK);
    }

    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0280
 * Function: CheckMultiNativeSo
 * @tc.name: test CheckMultiNativeSo
 * @tc.require: issueI5N7AD
 * @tc.desc: CheckMultiNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0280, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);
    appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";

    QuickFixChecker checker;
    auto ret = checker.CheckMultiNativeSo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0500
 * Function: VerifyCodeSignatureForHqf
 * @tc.name: test VerifyCodeSignatureForHqf
 * @tc.require: issueI8ZR55
 * @tc.desc: VerifyCodeSignatureForHqf not existed bundleInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0500, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer(true);
    EXPECT_FALSE(deployer == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    appQuickFix.bundleName = BUNDLE_NAME;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    std::string patchPath = "data/test";
    auto ret = deployer->VerifyCodeSignatureForHqf(innerAppQuickFix, patchPath);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0510
 * Function: VerifyCodeSignatureForHqf
 * @tc.name: test VerifyCodeSignatureForHqf
 * @tc.require: issueI8ZR55
 * @tc.desc: VerifyCodeSignatureForHqf ok
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0510, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG);
    auto deployer = GetQuickFixDeployer(true);
    EXPECT_FALSE(deployer == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    appQuickFix.bundleName = BUNDLE_NAME;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    std::string patchPath = "data/test";
    auto ret = deployer->VerifyCodeSignatureForHqf(innerAppQuickFix, patchPath);
    UninstallBundleInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0520
 * Function: VerifyCodeSignatureForHqf
 * @tc.name: test VerifyCodeSignatureForHqf
 * @tc.require: issueI8ZR55
 * @tc.desc: VerifyCodeSignatureForHqf release hap
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0520, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_RELEASE);
    auto deployer = GetQuickFixDeployer(true);
    EXPECT_FALSE(deployer == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    appQuickFix.bundleName = BUNDLE_NAME;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    std::string patchPath = "data/test";
    auto ret = deployer->VerifyCodeSignatureForHqf(innerAppQuickFix, patchPath);
    UninstallBundleInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0530
 * Function: VerifyCodeSignatureForHqf
 * @tc.name: test VerifyCodeSignatureForHqf
 * @tc.require: issueI8ZR55
 * @tc.desc: VerifyCodeSignatureForHqf not debug hqf
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0530, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME, PROVISION_TYPE_DEBUG);
    auto deployer = GetQuickFixDeployer(false);
    EXPECT_FALSE(deployer == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    appQuickFix.bundleName = BUNDLE_NAME;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    std::string patchPath = "data/test";
    auto ret = deployer->VerifyCodeSignatureForHqf(innerAppQuickFix, patchPath);
    UninstallBundleInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0540
 * Function: ExtractQuickFixResFile
 * @tc.name: test ExtractQuickFixResFile
 * @tc.require: issueI9CPVJ
 * @tc.desc: ExtractQuickFixResFile empty hqfInfos
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0540, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    AppQuickFix appQuickFix = CreateAppQuickFix();
    std::vector<HqfInfo> hqfInfo;
    appQuickFix.deployingAppqfInfo.hqfInfos = hqfInfo;
    BundleInfo bundleInfo;
    auto ret = deployer->ExtractQuickFixResFile(appQuickFix, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0550
 * Function: ExtractQuickFixResFile
 * @tc.name: test ExtractQuickFixResFile
 * @tc.require: issueI9CPVJ
 * @tc.desc: ExtractQuickFixResFile ok
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0550, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    BundleInfo bundleInfo;
    ErrCode ret = deployer->GetBundleInfo(BUNDLE_NAME, bundleInfo);
    AppQuickFix appQuickFix = CreateAppQuickFix();
    ret = deployer->ExtractQuickFixResFile(appQuickFix, bundleInfo);
    UninstallBundleInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0096
 * Function: ParseAndCheckAppQuickFixInfos
 * @tc.name: test ParseAndCheckAppQuickFixInfos
 * @tc.require: issueI5MZ5D
 * @tc.desc: ParseAndCheckAppQuickFixInfos
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0290, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        const std::vector<std::string> bundleFilePaths;
        std::unordered_map<std::string, AppQuickFix> infos;
        ErrCode ret = deployer->ParseAndCheckAppQuickFixInfos(bundleFilePaths, infos);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0300
 * @tc.name: test CheckPatchNativeSoWithInstalledBundle
 * @tc.desc: test failed scene of CheckPatchNativeSoWithInstalledBundle
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0300, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    BundleInfo bundleInfo;
    bundleInfo.applicationInfo.nativeLibraryPath = "libs/armeabi-v7a";
    bundleInfo.applicationInfo.cpuAbi = "x86";
    AppqfInfo qfInfo;
    qfInfo.cpuAbi = "arm";
    qfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    QuickFixChecker checker;
    auto ret = checker.CheckPatchNativeSoWithInstalledBundle(bundleInfo, qfInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE);
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0310
 * @tc.name: test CheckSignatureInfo
 * @tc.desc: test success scene of CheckSignatureInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0310, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    BundleInfo bundleInfo;
    bundleInfo.name = "Device";
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.appId = "001";
    bundleInfo.appId = "Device_001";
    bundleInfo.applicationInfo.appPrivilegeLevel = provisionInfo.bundleInfo.apl;
    provisionInfo.bundleInfo.bundleName = bundleInfo.name;
    QuickFixChecker checker;
    auto ret = checker.CheckSignatureInfo(bundleInfo, provisionInfo);
    EXPECT_EQ(ret, ERR_OK);
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0320
 * @tc.name: test CheckMultiNativeSo
 * @tc.desc: test failed scene of CheckMultiNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0320, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix info1;
    info1.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
    AppQuickFix info2;
    infos["path1"] = info1;
    infos["path2"] = info2;
    QuickFixChecker checker;
    auto ret = checker.CheckMultiNativeSo(infos);
    EXPECT_EQ(ret, ERR_OK);
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0330
 * Function: InnerDeletePatchDir
 * @tc.name: test InnerDeletePatchDir
 * @tc.desc: InnerDeletePatchDir with different typr
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0330, Function | SmallTest | Level0)
{
    auto deleter = GetQuickFixDeleter();
    EXPECT_FALSE(deleter == nullptr);
    if (deleter != nullptr) {
        AppqfInfo appqfInfo;
        appqfInfo.type = QuickFixType::UNKNOWN;
        std::vector<HqfInfo> hqfInfos;
        HqfInfo info;
        hqfInfos.emplace_back(info);
        appqfInfo.hqfInfos = hqfInfos;
        ErrCode ret = deleter->InnerDeletePatchDir(appqfInfo, BUNDLE_NAME);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_UNKNOWN_QUICK_FIX_TYPE);
        appqfInfo.type = QuickFixType::HOT_RELOAD;
        ret = deleter->InnerDeletePatchDir(appqfInfo, BUNDLE_NAME);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0340
 * Function: Query inner app quick fix
 * @tc.name: test QuickFixDataMgr
 * @tc.require: issueI5N7AD
 * @tc.desc: 1. check module not same
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0340, Function | SmallTest | Level0)
{
    AppQuickFix appQuickFix = CreateAppQuickFix();
    QuickFixMark mark;
    mark.bundleName = appQuickFix.bundleName;
    mark.status = QuickFixStatus::DEPLOY_START;
    InnerAppQuickFix innerAppQuickFix(appQuickFix, mark);
    auto quickFixMgr = GetQuickFixDataMgr();
    quickFixMgr->quickFixManagerDb_ = nullptr;
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    ErrCode ret = ERR_OK;
    if (deployer != nullptr) {
        ret = deployer->SaveAppQuickFix(innerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SAVE_APP_QUICK_FIX_FAILED);
    }
    quickFixMgr->quickFixManagerDb_ = std::make_shared<QuickFixManagerRdb>();
}

/**
 * @tc.number: BmsBundleQuickFixTest_0350
 * @tc.name: test CheckSignatureInfo
 * @tc.desc: test success scene of CheckSignatureInfo
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0350, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    BundleInfo bundleInfo;
    bundleInfo.name = "Device";
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.appId = "001";
    bundleInfo.appId = "Device_001";
    bundleInfo.applicationInfo.appPrivilegeLevel = provisionInfo.bundleInfo.apl;
    QuickFixChecker checker;
    auto ret = checker.CheckSignatureInfo(bundleInfo, provisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME);
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: PatchParser_0100
 * Function: ParsePatchInfo
 * @tc.name: test ParsePatchInfo
 */
HWTEST_F(BmsBundleQuickFixTest, PatchParser_0100, Function | SmallTest | Level0)
{
    PatchParser patchParser;
    std::vector<std::string> filePaths = {HAP_FILE_PATH1};
    std::unordered_map<std::string, AppQuickFix> appQuickFixes;
    ErrCode res = patchParser.ParsePatchInfo(filePaths, appQuickFixes);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: DefaultNativeSo_0100
 * Function: DefaultNativeSo
 * @tc.name: test DefaultNativeSo
 */
HWTEST_F(BmsBundleQuickFixTest, DefaultNativeSo_0100, Function | SmallTest | Level0)
{
    PatchProfile patchProfile;
    PatchExtractor patchExtractor(Constants::LIBS + Constants::ARM64_V8A);
    patchExtractor.Init();
    bool isSystemLib64Exist = true;
    AppqfInfo appqfInfo;
    bool res = patchProfile.DefaultNativeSo(patchExtractor, isSystemLib64Exist, appqfInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundleSwitchQuickFix_0001
 * Function: SwitchQuickFix
 * @tc.name: test SwitchQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: SwitchQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleSwitchQuickFix_0001, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto quickFixProxy = GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode ret = quickFixProxy->SwitchQuickFix(BUNDLE_NAME, true, callback);
    EXPECT_EQ(ret, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleSwitchQuickFix_0002
 * Function: SwitchQuickFix
 * @tc.name: test SwitchQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: SwitchQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleSwitchQuickFix_0002, Function | SmallTest | Level0)
{
    auto quickFixProxy = GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode ret = quickFixProxy->SwitchQuickFix("", true, callback);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleDeleteQuickFix_0001
 * Function: DeleteQuickFix
 * @tc.name: test DeleteQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: DeleteQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleDeleteQuickFix_0001, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto quickFixProxy = GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode ret = quickFixProxy->DeleteQuickFix(BUNDLE_NAME, callback);
    EXPECT_EQ(ret, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleDeleteQuickFix_0002
 * Function: DeleteQuickFix
 * @tc.name: test DeleteQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: DeleteQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleDeleteQuickFix_0002, Function | SmallTest | Level0)
{
    auto quickFixProxy = GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    sptr<MockQuickFixCallback> callback = new (std::nothrow) MockQuickFixCallback();
    EXPECT_NE(callback, nullptr) << "the callback is nullptr";
    ErrCode ret = quickFixProxy->DeleteQuickFix("", callback);
    EXPECT_NE(ret, ERR_OK);
    ErrCode res = quickFixProxy->DeleteQuickFix("wrong", nullptr);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}


/**
 * @tc.number: FixDeployer_0001
 * @tc.name: test ParseAndCheckAppQuickFixInfos
 * @tc.desc: ParseAndCheckAppQuickFixInfos
 */
HWTEST_F(BmsBundleQuickFixTest, FixDeployer_0001, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        std::vector<std::string> bundleFilePaths;
        bundleFilePaths.push_back(HAP_FILE_PATH1);
        std::unordered_map<std::string, AppQuickFix> infos;
        infos.emplace("AppQuickFix", appQuickFix);
        ErrCode ret = deployer->ParseAndCheckAppQuickFixInfos(bundleFilePaths, infos);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: FixDeployer_0002
 * @tc.name: test ParseAndCheckAppQuickFixInfos
 * @tc.desc: ParseAndCheckAppQuickFixInfos
 */
HWTEST_F(BmsBundleQuickFixTest, FixDeployer_0002, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        std::vector<std::string> bundleFilePaths;
        bundleFilePaths.push_back(HAP_FILE_PATH1);
        InnerAppQuickFix newInnerAppQuickFix;
        InnerAppQuickFix oldInnerAppQuickFix;
        ErrCode ret = deployer->ToDeployStartStatus(bundleFilePaths, newInnerAppQuickFix, oldInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED);
        appQuickFix.deployingAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        ret = deployer->ToDeployStartStatus(bundleFilePaths, newInnerAppQuickFix, oldInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: FixDeployer_0003
 * @tc.name: test SaveToInnerBundleInfo
 * @tc.desc: SaveToInnerBundleInfo
 */
HWTEST_F(BmsBundleQuickFixTest, FixDeployer_0003, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        ClearDataMgr();
        InnerBundleInfo innerBundleInfo;
        bool ret = deployer->FetchInnerBundleInfo("", innerBundleInfo);
        EXPECT_EQ(ret, false);
        BundleInfo bundleInfo;
        ErrCode res = deployer->GetBundleInfo("", bundleInfo);
        EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR);
        InnerAppQuickFix newInnerAppQuickFix;
        res = deployer->SaveToInnerBundleInfo(newInnerAppQuickFix);
        EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR);
        ResetDataMgr();
    }
}

/**
 * @tc.number: BmsBundleCopyFiles_0001
 * Function: CopyFiles
 * @tc.name: test CopyFiles
 * @tc.require: issueI5N7AD
 * @tc.desc: CopyFiles
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleCopyFiles_0001, Function | SmallTest | Level0)
{
    auto quickFixProxy = GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    const std::vector<std::string> sourceFiles {FILE1_PATH, FILE2_PATH};
    CreateFiles(sourceFiles);
    std::vector<std::string> destFiles;
    ErrCode ret = quickFixProxy->CopyFiles(sourceFiles, destFiles);
    if (!ret) {
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleCopyFiles_0002
 * Function: CopyFiles
 * @tc.name: test CopyFiles
 * @tc.require: issueI5N7AD
 * @tc.desc: CopyFiles
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleCopyFiles_0002, Function | SmallTest | Level0)
{
    auto quickFixProxy = GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    const std::vector<std::string> sourceFiles {"", ""};
    std::vector<std::string> destFiles;
    ErrCode ret = quickFixProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleCopyFiles_0003
 * Function: CopyFiles
 * @tc.name: test CopyFiles
 * @tc.require: issueI5N7AD
 * @tc.desc: CopyFiles
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleCopyFiles_0003, Function | SmallTest | Level0)
{
    auto quickFixProxy = GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    const std::vector<std::string> sourceFiles {FILE1_PATH, ""};
    CreateFiles(sourceFiles);
    std::vector<std::string> destFiles = {"hello.hqf"};
    ErrCode ret = quickFixProxy->CopyFiles(sourceFiles, destFiles);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    DeleteFiles(sourceFiles);
    DeleteFiles(destFiles);
}

/**
 * @tc.number: CreateFd_0100
 * @tc.name: Test CreateFd
 * @tc.desc: 1.Test the CreateFd of QuickFixManagerProxy
 */
HWTEST_F(BmsBundleQuickFixTest, CreateFd_0100, Function | SmallTest | Level0)
{
    auto quickFixProxy = GetQuickFixManagerProxy();
    EXPECT_NE(quickFixProxy, nullptr) << "the quickFixProxy is nullptr";
    std::string fileName = "";
    int32_t fd = 0;
    std::string path;
    ErrCode ret = quickFixProxy->CreateFd(fileName, fd, path);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: DeployQuickFixResult_0100
 * @tc.name: Test Marshalling
 * @tc.desc: 1.Test the Marshalling of DeployQuickFixResult
 */
HWTEST_F(BmsBundleQuickFixTest, DeployQuickFixResult_0100, Function | SmallTest | Level0)
{
    DeployQuickFixResult result;
    std::vector<std::string> moduleNames = {"entry1", "entry2"};
    result.moduleNames = moduleNames;
    Parcel parcel;
    bool ret = result.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: DeployQuickFixResult_0200
 * @tc.name: Test GetResCode
 * @tc.desc: 1.Test the GetResCode of DeployQuickFixResult
 */
HWTEST_F(BmsBundleQuickFixTest, DeployQuickFixResult_0200, Function | SmallTest | Level0)
{
    DeployQuickFixResult result;
    int32_t resCode = 100;
    result.SetResCode(resCode);
    int32_t ret = result.GetResCode();
    EXPECT_EQ(ret, resCode);
}

/**
 * @tc.number: SwitchQuickFixResult_0100
 * @tc.name: Test Marshalling
 * @tc.desc: 1.Test the Marshalling of SwitchQuickFixResult
 */
HWTEST_F(BmsBundleQuickFixTest, SwitchQuickFixResult_0100, Function | SmallTest | Level0)
{
    SwitchQuickFixResult result;
    result.resultCode = 100;
    Parcel parcel;
    bool ret = result.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SwitchQuickFixResult_0200
 * @tc.name: Test GetResCode
 * @tc.desc: 1.Test the GetResCode of SwitchQuickFixResult
 */
HWTEST_F(BmsBundleQuickFixTest, SwitchQuickFixResult_0200, Function | SmallTest | Level0)
{
    SwitchQuickFixResult result;
    int32_t resCode = 100;
    result.SetResCode(resCode);
    int32_t ret = result.GetResCode();
    EXPECT_EQ(ret, resCode);
}

/**
 * @tc.number: DeleteQuickFixResult_0100
 * @tc.name: Test Marshalling
 * @tc.desc: 1.Test the Marshalling of DeleteQuickFixResult
 */
HWTEST_F(BmsBundleQuickFixTest, DeleteQuickFixResult_0100, Function | SmallTest | Level0)
{
    DeleteQuickFixResult result;
    result.resultCode = 100;
    Parcel parcel;
    bool ret = result.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: DeleteQuickFixResult_0200
 * @tc.name: Test ToString
 * @tc.desc: 1.Test the ToString of DeleteQuickFixResult
 */
HWTEST_F(BmsBundleQuickFixTest, DeleteQuickFixResult_0200, Function | SmallTest | Level0)
{
    DeleteQuickFixResult result;
    result.resultCode = 100;
    result.bundleName = "com.ohos.test";
    std::string ret = "";
    ret = result.ToString();
    EXPECT_NE(ret, "");
}

/**
 * @tc.number: DeleteQuickFixResult_0300
 * @tc.name: Test GetResCode
 * @tc.desc: 1.Test the GetResCode of DeleteQuickFixResult
 */
HWTEST_F(BmsBundleQuickFixTest, DeleteQuickFixResult_0300, Function | SmallTest | Level0)
{
    DeleteQuickFixResult result;
    int32_t resCode = 100;
    result.SetResCode(resCode);
    int32_t ret = result.GetResCode();
    EXPECT_EQ(ret, resCode);
}

/**
 * @tc.number: QuickFixStatusCallbackProxy_0100
 * @tc.name: Test OnPatchDeployed
 * @tc.desc: 1.Test the OnPatchDeployed of QuickFixStatusCallbackProxy
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixStatusCallbackProxy_0100, Function | SmallTest | Level0)
{
    const sptr<IRemoteObject> object;
    QuickFixStatusCallbackProxy proxy(object);
    std::shared_ptr<QuickFixResult> result = std::make_shared<DeployQuickFixResult>();
    uint32_t resultCode = 1;
    result->SetResCode(resultCode);
    proxy.OnPatchDeployed(result);
    EXPECT_EQ(result->GetResCode(), resultCode);
}

/**
 * @tc.number: QuickFixStatusCallbackProxy_0200
 * @tc.name: Test OnPatchSwitched
 * @tc.desc: 1.Test the OnPatchSwitched of QuickFixStatusCallbackProxy
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixStatusCallbackProxy_0200, Function | SmallTest | Level0)
{
    const sptr<IRemoteObject> object;
    QuickFixStatusCallbackProxy proxy(object);
    std::shared_ptr<QuickFixResult> result = std::make_shared<SwitchQuickFixResult>();
    uint32_t resultCode = 1;
    result->SetResCode(resultCode);
    proxy.OnPatchSwitched(result);
    EXPECT_EQ(result->GetResCode(), resultCode);
}

/**
 * @tc.number: QuickFixStatusCallbackProxy_0300
 * @tc.name: Test OnPatchDeleted
 * @tc.desc: 1.Test the OnPatchDeleted of QuickFixStatusCallbackProxy
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixStatusCallbackProxy_0300, Function | SmallTest | Level0)
{
    const sptr<IRemoteObject> object;
    QuickFixStatusCallbackProxy proxy(object);
    std::shared_ptr<QuickFixResult> result = std::make_shared<DeleteQuickFixResult>();
    uint32_t resultCode = 1;
    result->SetResCode(resultCode);
    proxy.OnPatchDeleted(result);
    EXPECT_EQ(result->GetResCode(), resultCode);
}

/**
 * @tc.number: QuickFixDeployer_0100
 * @tc.name: Test DeployQuickFix with Execute
 * @tc.desc: 1.Test the DeployQuickFix of QuickFixDeployer
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixDeployer_0100, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        ErrCode ret = deployer->Execute();
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
        ret = deployer->DeployQuickFix();
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: QuickFixDeployer_0200
 * @tc.name: Test ProcessPatchDeployEnd with Execute
 * @tc.desc: 1.Test the ProcessPatchDeployEnd of QuickFixDeployer
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixDeployer_0200, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME);
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix;
        appQuickFix.deployingAppqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
        appQuickFix.bundleName = BUNDLE_NAME;
        HqfInfo info;
        info.hqfFilePath = "/data/test/hello.hqf";
        appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(info);
        std::string patchPath = "diff.patch";
        ErrCode ret = deployer->ProcessPatchDeployEnd(appQuickFix, patchPath);
        EXPECT_EQ(ret, ERR_OK);
    }
    UninstallBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: QuickFixDeployer_0300
 * @tc.name: Test FetchInnerBundleInfo with Execute
 * @tc.desc: 1.Test the FetchInnerBundleInfo of QuickFixDeployer
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixDeployer_0300, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        InnerBundleInfo innerBundleInfo;
        auto dataMgr = GetBundleDataMgr();
        EXPECT_NE(dataMgr, nullptr);
        dataMgr->bundleInfos_.try_emplace(BUNDLE_NAME, innerBundleInfo);
        bool ret = deployer->FetchInnerBundleInfo(BUNDLE_NAME, innerBundleInfo);
        EXPECT_EQ(ret, true);

        ret = deployer->IsLibIsolated(BUNDLE_NAME, "entry");
        EXPECT_EQ(ret, false);
    }
}

/**
 * @tc.number: QuickFixManagerRdb_0100
 * @tc.name: Test QuickFixManagerRdb
 * @tc.desc: 1.Test the failed scene of QuickFixManagerRdb
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixManagerRdb_0100, Function | SmallTest | Level0)
{
    QuickFixDataMgr rdb;
    rdb.quickFixManagerDb_ = nullptr;
    EXPECT_EQ(rdb.quickFixManagerDb_, nullptr);
    bool ret = rdb.DeleteInnerAppQuickFix("");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: QuickFixBootScanner_0100
 * @tc.name: Test QuickFixBootScanner
 * @tc.desc: 1.Test the failed scene of ReprocessQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixBootScanner_0100, Function | SmallTest | Level0)
{
    QuickFixBootScanner scanner;
    bool ret = scanner.ReprocessQuickFix("", "");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: QuickFixer_0100
 * @tc.name: Test QuickFixer
 * @tc.desc: 1.Test the failed scene of QuickFixer
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixer_0100, Function | SmallTest | Level0)
{
    sptr<IQuickFixStatusCallback> statusCallback;
    QuickFixer fixer(statusCallback);
    const std::vector<std::string> bundleFilePaths;
    fixer.DeployQuickFix(bundleFilePaths);
    EXPECT_EQ(fixer.statusCallback_, nullptr);
    EXPECT_EQ(bundleFilePaths.empty(), true);
    fixer.SwitchQuickFix("", false);
    EXPECT_EQ(fixer.statusCallback_, nullptr);
    fixer.DeleteQuickFix("");
    EXPECT_EQ(fixer.statusCallback_, nullptr);
}

/**
 * @tc.number: QuickFixDataMgr_0100
 * @tc.name: Test QuickFixDataMgr
 * @tc.desc: 1.Test the failed scene of QuickFixDataMgr
 */
HWTEST_F(BmsBundleQuickFixTest, QuickFixDataMgr_0100, Function | SmallTest | Level0)
{
    QuickFixDataMgr dataMgr;
    dataMgr.quickFixManagerDb_.reset();
    EXPECT_EQ(dataMgr.quickFixManagerDb_, nullptr);
    std::map<std::string, InnerAppQuickFix> innerAppQuickFixes;
    bool ret = dataMgr.QueryAllInnerAppQuickFix(innerAppQuickFixes);
    EXPECT_EQ(ret, false);

    InnerAppQuickFix innerAppQuickFix;
    ret = dataMgr.QueryInnerAppQuickFix("", innerAppQuickFix);
    EXPECT_EQ(ret, false);

    ret = dataMgr.SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_EQ(ret, false);

    ret = dataMgr.DeleteInnerAppQuickFix("");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: AddHqfInfo_0100
 * @tc.name: test AddHqfInfo
 * @tc.desc: AddHqfInfo return false
 */
HWTEST_F(BmsBundleQuickFixTest, AddHqfInfo_0100, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix;
    auto ret = innerAppQuickFix.AddHqfInfo(appQuickFix);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AddHqfInfo_0200
 * @tc.name: test AddHqfInfo
 * @tc.desc: AddHqfInfo return true
 */
HWTEST_F(BmsBundleQuickFixTest, AddHqfInfo_0200, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix;
    HqfInfo info;
    info.hapSha256 = "hapSha256";
    appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(info);
    auto ret = innerAppQuickFix.AddHqfInfo(appQuickFix);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AddHqfInfo_0300
 * @tc.name: test AddHqfInfo
 * @tc.desc: AddHqfInfo return true
 */
HWTEST_F(BmsBundleQuickFixTest, AddHqfInfo_0300, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix;
    HqfInfo info;
    info.moduleName = "com.example.bmsaccesstoken.MyApplication1";
    appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(info);
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    auto ret = innerAppQuickFix.AddHqfInfo(appQuickFix);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number:RemoveHqfInfo_0100
 * @tc.name: test RemoveHqfInfo
 * @tc.desc: RemoveHqfInfo return true
 */
HWTEST_F(BmsBundleQuickFixTest, RemoveHqfInfo_0100, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix;
    HqfInfo info;
    info.moduleName = "com.example.bmsaccesstoken.MyApplication1";
    appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(info);
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    auto ret = innerAppQuickFix.RemoveHqfInfo("com.example.bmsaccesstoken.MyApplication1");
    EXPECT_TRUE(ret);
}

/**
 * @tc.number:RemoveHqfInfo_0200
 * @tc.name: test RemoveHqfInfo
 * @tc.desc: RemoveHqfInfo return false
 */
HWTEST_F(BmsBundleQuickFixTest, RemoveHqfInfo_0200, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    auto ret = innerAppQuickFix.RemoveHqfInfo("com.example.bmsaccesstoken.MyApplication1");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number:RemoveHqfInfo_0300
 * @tc.name: test RemoveHqfInfo
 * @tc.desc: RemoveHqfInfo return false
 */
HWTEST_F(BmsBundleQuickFixTest, RemoveHqfInfo_0300, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    auto ret = innerAppQuickFix.RemoveHqfInfo("");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number:SwitchQuickFix_0100
 * @tc.name: test SwitchQuickFix
 * @tc.desc: SwitchQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, SwitchQuickFix_0100, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    innerAppQuickFix.appQuickFix_.deployedAppqfInfo.versionCode = 1001;
    innerAppQuickFix.appQuickFix_.deployingAppqfInfo.versionCode = 1002;
    innerAppQuickFix.appQuickFix_.deployedAppqfInfo.versionName = "test";
    innerAppQuickFix.appQuickFix_.deployingAppqfInfo.versionName = "test1";
    innerAppQuickFix.SwitchQuickFix();
    EXPECT_EQ(innerAppQuickFix.appQuickFix_.deployedAppqfInfo.versionCode, 1002);
    EXPECT_EQ(innerAppQuickFix.appQuickFix_.deployedAppqfInfo.versionName, "test1");
    EXPECT_EQ(innerAppQuickFix.appQuickFix_.deployingAppqfInfo.versionCode, 1001);
    EXPECT_EQ(innerAppQuickFix.appQuickFix_.deployingAppqfInfo.versionName, "test");
}

/**
 * @tc.number: GetQuickFixMark_0100
 * @tc.name: test GetQuickFixMark
 * @tc.desc: GetQuickFixMark return bundleName
 */
HWTEST_F(BmsBundleQuickFixTest, GetQuickFixMark_0100, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    QuickFixMark quickFixMark;
    quickFixMark.bundleName = "bundle";
    innerAppQuickFix.SetQuickFixMark(quickFixMark);
    auto ret = innerAppQuickFix.GetQuickFixMark();
    EXPECT_EQ(ret.bundleName, "bundle");
}

/**
 * @tc.number: GetQuickFixMark_0200
 * @tc.name: test GetQuickFixMark
 * @tc.desc: GetQuickFixMark return bundleName is null string
 */
HWTEST_F(BmsBundleQuickFixTest, GetQuickFixMark_0200, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    QuickFixMark quickFixMark;
    auto ret = innerAppQuickFix.GetQuickFixMark();
    EXPECT_EQ(ret.bundleName, "");
}

/**
 * @tc.number: ToString_0100
 * @tc.name: test ToString
 * @tc.desc: ToString return string
 */
HWTEST_F(BmsBundleQuickFixTest, ToString_0100, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    auto ret = innerAppQuickFix.ToString();
    EXPECT_EQ(ret.empty(), false);
}

/**
 * @tc.number: ToJson_0100
 * @tc.name: test ToJson
 * @tc.desc: ToJson
 */
HWTEST_F(BmsBundleQuickFixTest, ToJson_0100, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    nlohmann::json jsonObject;
    AppQuickFix appQuickFix;
    QuickFixMark quickFixMark;
    innerAppQuickFix.ToJson(jsonObject);
    EXPECT_EQ(jsonObject["appQuickFix"], appQuickFix);
    EXPECT_EQ(jsonObject["quickFixMark"], quickFixMark);
}

/**
 * @tc.number: FromJson_0100
 * @tc.name: test FromJson
 * @tc.desc: Parse json to C++ return ERR_OK
 */
HWTEST_F(BmsBundleQuickFixTest, FromJson_0100, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    nlohmann::json jsonObject =  nlohmann::json {
        {Constants::BUNDLE_NAME, "com.example.MyApplication1"},
        {"versionCode", 0},
        {"versionName", "versionName"}
    };
    auto ret = innerAppQuickFix.FromJson(jsonObject);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: FromJson_0200
 * @tc.name: test FromJson
 * @tc.desc: Parse json to C++ return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR
 */
HWTEST_F(BmsBundleQuickFixTest, FromJson_0200, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    nlohmann::json jsonObject = R"(
        {
            "appQuickFix" : "appQuickFix",
            "quickFixMark" : "quickFixMark"
        }
    )"_json;
    auto ret = innerAppQuickFix.FromJson(jsonObject);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: FromJson_0300
 * @tc.name: test FromJson
 * @tc.desc: Parse json to C++ return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR
 */
HWTEST_F(BmsBundleQuickFixTest, FromJson_0300, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    nlohmann::json jsonObject = R"(
        {
            "appQuickFix" : "appQuickFix",
            "quickFixMark" : {}
        }
    )"_json;
    auto ret = innerAppQuickFix.FromJson(jsonObject);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: FromJson_0400
 * @tc.name: test FromJson
 * @tc.desc: Parse json to C++ return ERR_OK
 */
HWTEST_F(BmsBundleQuickFixTest, FromJson_0400, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    nlohmann::json jsonObject;
    auto ret = innerAppQuickFix.FromJson(jsonObject);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: FromJson_0500
 * @tc.name: test FromJson
 * @tc.desc: Parse json to C++ return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR
 */
HWTEST_F(BmsBundleQuickFixTest, FromJson_0500, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    nlohmann::json jsonObject = R"(
        {
            "appQuickFix" : {},
            "quickFixMark" : "quickFixMark"
        }
    )"_json;
    auto ret = innerAppQuickFix.FromJson(jsonObject);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: FromJson_0600
 * @tc.name: test FromJson
 * @tc.desc: Parse json to C++ return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR
 */
HWTEST_F(BmsBundleQuickFixTest, FromJson_0600, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    nlohmann::json jsonObject = R"(
        {
            "appQuickFix" : "!@#$%^&*",
            "quickFixMark" : "%^&*&^"
        }
    )"_json;
    auto ret = innerAppQuickFix.FromJson(jsonObject);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: FromJson_0700
 * @tc.name: test FromJson
 * @tc.desc: Parse json to C++ return ERR_OK
 */
HWTEST_F(BmsBundleQuickFixTest, FromJson_0700, Function | SmallTest | Level0)
{
    InnerAppQuickFix innerAppQuickFix;
    nlohmann::json jsonObject = R"(
        {
            "appQuickFix" : {},
            "quickFixMark" : {}
        }
    )"_json;
    auto ret = innerAppQuickFix.FromJson(jsonObject);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: to_json_0100
 * @tc.name: test to_json
 * @tc.desc: to_json return ERR_OK
 */
HWTEST_F(BmsBundleQuickFixTest, to_json_0100, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject;
    QuickFixMark quickFixMark;
    quickFixMark.bundleName = "bundleName";
    quickFixMark.status = QuickFixStatus::DEPLOY_START;
    to_json(jsonObject, quickFixMark);
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        quickFixMark.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_OK);
}

/**
 * @tc.number: to_json_0200
 * @tc.name: test to_json
 * @tc.desc: to_json return ERR_OK
 */
HWTEST_F(BmsBundleQuickFixTest, to_json_0200, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject;
    QuickFixMark quickFixMark;
    to_json(jsonObject, quickFixMark);
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        quickFixMark.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    EXPECT_EQ(parseResult, ERR_OK);
}

/**
 * @tc.number: from_json_0100
 * @tc.name: test from_json
 * @tc.desc: parse json to c++ return QuickFixMark
 */
HWTEST_F(BmsBundleQuickFixTest, from_json_0100, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject;
    QuickFixMark quickFixMark;
    from_json(jsonObject, quickFixMark);
    EXPECT_EQ(quickFixMark.bundleName, "");
    EXPECT_EQ(quickFixMark.status, QuickFixStatus::DEFAULT_STATUS);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0360
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessBundleFilePaths
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0360, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> sourceFiles {INVALID_FILE_PATH_1};
        std::vector<std::string> realFilePaths;
        ErrCode ret = deployer->ProcessBundleFilePaths(sourceFiles, realFilePaths);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0370
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessBundleFilePaths
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0370, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> sourceFiles {INVALID_FILE_PATH_2};
        std::vector<std::string> realFilePaths;
        ErrCode ret = deployer->ProcessBundleFilePaths(sourceFiles, realFilePaths);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0380
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessBundleFilePaths
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0380, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> sourceFiles {VALID_FILE_PATH_3};
        std::vector<std::string> realFilePaths;
        ErrCode ret = deployer->ProcessBundleFilePaths(sourceFiles, realFilePaths);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0390
 * Function: ToDeployEndStatus
 * @tc.name: test ToDeployEndStatus
 * @tc.require: issueI5N7AD
 * @tc.desc: ToDeployEndStatus, bundleName not exist
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0390, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.deployingAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.hqfInfos[0].type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = "";
        InnerAppQuickFix newInnerAppQuickFix;
        newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
        InnerAppQuickFix oldInnerAppQuickFix;
        ErrCode ret = deployer->ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0400
 * Function: ExtractSoFiles
 * @tc.name: test ExtractSoFiles
 * @tc.require: issueI5N7AD
 * @tc.desc: ExtractSoFiles
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0400, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        BundleInfo bundleInfo;
        bundleInfo.applicationInfo.nativeLibraryPath = "";
        std::string tmpSoPath = "";
        std::string moduleName = "entry";

        HapModuleInfo moduleInfo;
        moduleInfo.nativeLibraryPath = "";
        moduleInfo.moduleName = moduleName;
        bundleInfo.hapModuleInfos.push_back(moduleInfo);
        bool ret = deployer->ExtractSoFiles(bundleInfo, "feature", tmpSoPath);
        EXPECT_FALSE(ret);

        ret = deployer->ExtractSoFiles(bundleInfo, moduleName, tmpSoPath);
        EXPECT_FALSE(ret);

        bundleInfo.applicationInfo.nativeLibraryPath = "libs/arm";
        ret = deployer->ExtractSoFiles(bundleInfo, moduleName, tmpSoPath);
        EXPECT_FALSE(ret);

        bundleInfo.applicationInfo.nativeLibraryPath = "";
        bundleInfo.hapModuleInfos[0].nativeLibraryPath = "libs/arm";
        ret = deployer->ExtractSoFiles(bundleInfo, moduleName, tmpSoPath);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0410
 * Function: ProcessApplyDiffPatch
 * @tc.name: test ProcessApplyDiffPatch
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessApplyDiffPatch
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0410, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        auto ret = deployer->ProcessApplyDiffPatch(appQuickFix,
            appQuickFix.deployingAppqfInfo.hqfInfos[0], "", "");
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: BmsBundleQuickFixTest_0420
 * Function: ProcessApplyDiffPatch
 * @tc.name: test ProcessApplyDiffPatch
 * @tc.require: issueI5N7AD
 * @tc.desc: ProcessApplyDiffPatch
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0420, Function | SmallTest | Level0)
{
    AddInnerBundleInfo(BUNDLE_NAME_DEMO);

    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        AppQuickFix appQuickFix = CreateAppQuickFix();
        appQuickFix.bundleName = BUNDLE_NAME_DEMO;
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = QUICK_FIX_SO_PATH;
        auto ret = deployer->ProcessApplyDiffPatch(appQuickFix,
            appQuickFix.deployingAppqfInfo.hqfInfos[0], "/data/test/", "/data/test/");
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED);
    }
    UninstallBundleInfo(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0430
 * Function: ProcessBundleFilePaths
 * @tc.name: test ProcessBundleFilePaths
 * @tc.desc: ProcessBundleFilePaths
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0430, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    ASSERT_FALSE(deployer == nullptr);
    QuickFixManagerHostImpl quickFixManagerHostImpl;
    std::string fileName = "test.hqf";
    int32_t fd = -1;
    std::string path = "";
    auto res = quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_OK);
    const std::vector<std::string> sourceFiles {path};
    std::vector<std::string> realFilePaths;
    auto ret = deployer->ProcessBundleFilePaths(sourceFiles, realFilePaths);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
    deployer->DeployQuickFix();
    DeleteFiles(sourceFiles);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0440
 * Function: MoveHqfFiles
 * @tc.name: test MoveHqfFiles
 * @tc.desc: MoveHqfFiles
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0440, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    ASSERT_FALSE(deployer == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "entry";
    hqfInfo.hqfFilePath = "data/test";
    appQuickFix.deployingAppqfInfo.hqfInfos.push_back(hqfInfo);
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    std::string targetPath = "data/test";
    auto ret = deployer->MoveHqfFiles(innerAppQuickFix, targetPath);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_MOVE_PATCH_FILE_FAILED);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0460
 * Function: ToDeletePatchDir
 * @tc.name: test ToDeletePatchDir
 * @tc.desc: ToDeletePatchDir
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0460, Function | SmallTest | Level0)
{
    auto deleter = GetQuickFixDeleter();
    ASSERT_FALSE(deleter == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "entry";
    appQuickFix.deployingAppqfInfo.hqfInfos.push_back(hqfInfo);
    appQuickFix.deployedAppqfInfo.type = QuickFixType::UNKNOWN;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    ErrCode ret = deleter->ToDeletePatchDir(innerAppQuickFix);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_UNKNOWN_QUICK_FIX_TYPE);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0470
 * Function: ToDeletePatchDir
 * @tc.name: test ToDeletePatchDir
 * @tc.desc: ToDeletePatchDir
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0470, Function | SmallTest | Level0)
{
    auto deleter = GetQuickFixDeleter();
    ASSERT_FALSE(deleter == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    AppQuickFix appQuickFix;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "entry";
    appQuickFix.deployingAppqfInfo.hqfInfos.push_back(hqfInfo);
    appQuickFix.deployingAppqfInfo.type = QuickFixType::UNKNOWN;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    ErrCode ret = deleter->ToDeletePatchDir(innerAppQuickFix);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_UNKNOWN_QUICK_FIX_TYPE);
}

/**
 * @tc.number: BmsBundleQuickFixTest_0480
 * Function: RemoveDeployingInfo
 * @tc.name: test RemoveDeployingInfo
 * @tc.desc: RemoveDeployingInfo with dataMgr_ is nullptr
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0480, Function | SmallTest | Level0)
{
    auto deleter = GetQuickFixDeleter();
    ASSERT_FALSE(deleter == nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    ErrCode ret = deleter->RemoveDeployingInfo("");
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = dataMgr;
}

/**
 * @tc.number: BmsBundleQuickFixTest_0490
 * Function: InnerSwitchQuickFix
 * @tc.name: test InnerSwitchQuickFix
 * @tc.desc: InnerSwitchQuickFix, dataMgr_ is nullptr
 */
HWTEST_F(BmsBundleQuickFixTest, BmsBundleQuickFixTest_0490, Function | SmallTest | Level0)
{
    auto switcher = GetQuickFixSwitcher();
    ASSERT_FALSE(switcher == nullptr);
    InnerAppQuickFix innerAppQuickFix;

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    ErrCode ret = switcher->InnerSwitchQuickFix(BUNDLE_NAME, innerAppQuickFix, true);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR);

    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = dataMgr;
}

/**
 * @tc.number: DeployQuickFix_0001
 * Function: DeployQuickFix
 * @tc.name: test DeployQuickFix
 * @tc.require: issueI5N7AD
 * @tc.desc: DeployQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, DeployQuickFix_0001, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    std::string path = VALID_FILE_PATH_3;
    deployer->patchPaths_.push_back(path);
    ErrCode ret = deployer->DeployQuickFix();
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: DeployQuickFix_0002
 * Function: DeployQuickFix
 * @tc.name: test DeployQuickFix
 * @tc.desc: DeployQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, DeployQuickFix_0002, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> paths;
        PatchParser patchParser;
        bool hasResourceFile = patchParser.HasResourceFile(paths);
        EXPECT_FALSE(hasResourceFile);
        paths.emplace_back("");
        paths.emplace_back(BUNDLE_NAME);
        hasResourceFile = patchParser.HasResourceFile(paths);
        EXPECT_FALSE(hasResourceFile);
        paths.emplace_back(HAP_PATH_TEST_RAW_FILE);
        hasResourceFile = patchParser.HasResourceFile(paths);
        EXPECT_TRUE(hasResourceFile);
    }
}

/**
 * @tc.number: DeployQuickFix_0003
 * Function: DeployQuickFix
 * @tc.name: test DeployQuickFix
 * @tc.desc: DeployQuickFix
 */
HWTEST_F(BmsBundleQuickFixTest, DeployQuickFix_0003, Function | SmallTest | Level0)
{
    auto deployer = GetQuickFixDeployer();
    EXPECT_FALSE(deployer == nullptr);
    if (deployer != nullptr) {
        std::vector<std::string> paths;
        BundleInfo bundleInfo;
        bundleInfo.applicationInfo.debug = true;
        bundleInfo.applicationInfo.appProvisionType = Constants::APP_PROVISION_TYPE_DEBUG;
        auto ret = deployer->CheckHqfResourceIsValid(paths, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);

        bundleInfo.applicationInfo.debug = false;
        ret = deployer->CheckHqfResourceIsValid(paths, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);

        bundleInfo.applicationInfo.appProvisionType = Constants::APP_PROVISION_TYPE_RELEASE;
        ret = deployer->CheckHqfResourceIsValid(paths, bundleInfo);
        EXPECT_EQ(ret, ERR_OK);

        paths.emplace_back(HAP_PATH_TEST_RAW_FILE);
        ret = deployer->CheckHqfResourceIsValid(paths, bundleInfo);
        EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_RELEASE_HAP_HAS_RESOURCES_FILE_FAILED);
    }
}
} // OHOS