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
#include <sstream>
#include <string>

#include "appexecfwk_errors.h"
#include "appqf_info.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "inner_app_quick_fix.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_quick_fix_callback.h"
#include "mock_status_receiver.h"
#include "quick_fix_checker.h"
#include "quick_fix_data_mgr.h"
#include "quick_fix_deleter.h"
#include "quick_fix_deployer.h"
#define private public
#include "quick_fix_manager_host_impl.h"
#include "quick_fix_status_callback_proxy.h"
#include "quick_fix_switcher.h"
#include "quick_fix/patch_parser.h"
#include "quick_fix/patch_profile.h"
#include "quick_fix/quick_fix_boot_scanner.h"
#include "quick_fix/quick_fix_manager_rdb.h"
#undef private
#include "quick_fix/quick_fix_mgr.h"
#include "quick_fix/quick_fixer.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string BUNDLE_PATH = "/data/test/resource/bms/quick_fix/first_right.hap";
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const int32_t USERID = 100;
const std::string HAP_FILE_PATH = "/data/app/el1/bundle/public/com.example.l3jsdemo/patch_1000001/entry.hqf";
const int32_t VERSION_CODE = 1000001;
const int32_t WAIT_TIME = 1;
const uint32_t QUICK_FIX_VERSION_CODE = 1;
const std::string QUICK_FIX_VERSION_NAME = "1.0";
const uint32_t BUNDLE_VERSION_CODE = 1;
const std::string BUNDLE_VERSION_NAME = "1.0";
const std::string PATCH_PATH = "/data/app/el1/bundle/public/com.example.l3jsdemo/patch_1000001";
} // namespace

class BmsBundleQuickFixMgrRdbTest : public testing::Test {
public:
    BmsBundleQuickFixMgrRdbTest() {}
    ~BmsBundleQuickFixMgrRdbTest() {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;
    InnerAppQuickFix GenerateAppQuickFixInfo(
        const std::string &bundleName, const QuickFixStatus &status, bool flag = true) const;
    void CheckQuickFixInfo(const std::string &bundleName, size_t size) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartService();
    AppQuickFix CreateAppQuickFix();
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleQuickFixMgrRdbTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleQuickFixMgrRdbTest::installdService_ =
    std::make_shared<InstalldService>();

const std::shared_ptr<BundleDataMgr> BmsBundleQuickFixMgrRdbTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

ErrCode BmsBundleQuickFixMgrRdbTest::InstallBundle(const std::string &bundlePath) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleQuickFixMgrRdbTest::UninstallBundle(const std::string &bundleName) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleQuickFixMgrRdbTest::CheckQuickFixInfo(const std::string &bundleName, size_t size) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr) << "the data mgr is nullptr";

    InnerBundleInfo innerBundleInfo;
    bool result = dataMgr->GetInnerBundleInfoWithDisable(bundleName, innerBundleInfo);
    EXPECT_TRUE(result);
    auto appqfInof = innerBundleInfo.GetAppQuickFix();
    size_t ret = appqfInof.deployedAppqfInfo.hqfInfos.size();
    EXPECT_EQ(ret, size);

    result = dataMgr->EnableBundle(bundleName);
    EXPECT_TRUE(result);
}

InnerAppQuickFix BmsBundleQuickFixMgrRdbTest::GenerateAppQuickFixInfo(const std::string &bundleName,
    const QuickFixStatus &status, bool flag) const
{
    InnerAppQuickFix innerAppQuickFix;
    HqfInfo hqfInfo;
    hqfInfo.hqfFilePath = HAP_FILE_PATH;
    AppQuickFix appQuickFix;
    if (flag) {
        appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(hqfInfo);
        appQuickFix.deployingAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployingAppqfInfo.versionCode = VERSION_CODE;
    } else {
        appQuickFix.deployedAppqfInfo.hqfInfos.emplace_back(hqfInfo);
        appQuickFix.deployedAppqfInfo.type = QuickFixType::PATCH;
        appQuickFix.deployedAppqfInfo.versionCode = VERSION_CODE;
    }

    appQuickFix.bundleName = bundleName;
    QuickFixMark quickFixMark = { .status = status };
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    innerAppQuickFix.SetQuickFixMark(quickFixMark);
    return innerAppQuickFix;
}

AppQuickFix BmsBundleQuickFixMgrRdbTest::CreateAppQuickFix()
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

void BmsBundleQuickFixMgrRdbTest::StartService()
{
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bundleMgrService_ != nullptr && !bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleQuickFixMgrRdbTest::SetUpTestCase()
{}

void BmsBundleQuickFixMgrRdbTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleQuickFixMgrRdbTest::SetUp()
{
    if (installdService_ != nullptr && !installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    StartService();
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr != nullptr) {
        dataMgr->AddUserId(USERID);
    }
}

void BmsBundleQuickFixMgrRdbTest::TearDown()
{}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0001
 * @tc.name: Constructor
 * @tc.desc: Verify constructor succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0001, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0002
 * @tc.name: QueryAllInnerAppQuickFix
 * @tc.desc: rdbDataManager_ is nullptr, verify QueryAllInnerAppQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0002, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);
    rdb->rdbDataManager_ = nullptr;
    std::map<std::string, InnerAppQuickFix> innerAppQuickFixes;
    auto result = rdb->QueryAllInnerAppQuickFix(innerAppQuickFixes);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0003
 * @tc.name: QueryAllInnerAppQuickFix
 * @tc.desc: Empty quick fix info, verify QueryAllInnerAppQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0003, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    auto result = rdb->QueryAllInnerAppQuickFix(innerQuickFixInfos);
    EXPECT_FALSE(result);
    EXPECT_EQ(0, innerQuickFixInfos.size());
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0004
 * @tc.name: QueryAllInnerAppQuickFix
 * @tc.desc: Verify QueryAllInnerAppQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0004, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    CheckQuickFixInfo(BUNDLE_NAME, 0);

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END);
    bool result = rdb->SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_TRUE(result);

    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    result = rdb->QueryAllInnerAppQuickFix(innerQuickFixInfos);
    EXPECT_TRUE(result);
    EXPECT_EQ(1, innerQuickFixInfos.size());

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0005
 * @tc.name: SaveInnerAppQuickFix
 * @tc.desc: Verify SaveInnerAppQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0005, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    InnerAppQuickFix innerAppQuickFix;
    bool result = rdb->SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0006
 * @tc.name: SaveInnerAppQuickFix
 * @tc.desc: rdbDataManager_ is nullptr, verify SaveInnerAppQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0006, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    rdb->rdbDataManager_ = nullptr;
    InnerAppQuickFix innerAppQuickFix;
    bool result = rdb->SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0007
 * @tc.name: QueryAllInnerAppQuickFix
 * @tc.desc: rdbDataManager_ is nullptr, verify QueryAllInnerAppQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0007, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    rdb->rdbDataManager_ = nullptr;
    std::map<std::string, InnerAppQuickFix> innerQuickFixInfos;
    auto result = rdb->QueryAllInnerAppQuickFix(innerQuickFixInfos);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0008
 * @tc.name: QueryInnerAppQuickFix
 * @tc.desc: Verify QueryInnerAppQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0008, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    CheckQuickFixInfo(BUNDLE_NAME, 0);

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END);
    bool result = rdb->SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_TRUE(result);

    InnerAppQuickFix fixInfo;
    result = rdb->QueryInnerAppQuickFix(BUNDLE_NAME, fixInfo);
    EXPECT_TRUE(result);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0009
 * @tc.name: QueryInnerAppQuickFix
 * @tc.desc: Bunlde is not exist, Verify QueryInnerAppQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0009, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    InnerAppQuickFix fixInfo;
    auto result = rdb->QueryInnerAppQuickFix("NotExistBundle", fixInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0010
 * @tc.name: QueryInnerAppQuickFix
 * @tc.desc: rdbDataManager_ is nullptr, verify QueryInnerAppQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0010, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    rdb->rdbDataManager_ = nullptr;
    InnerAppQuickFix fixInfo;
    auto result = rdb->QueryInnerAppQuickFix("NotExistBundle", fixInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0011
 * @tc.name: DeleteInnerAppQuickFix
 * @tc.desc: rdbDataManager_is nullptr, verify DeleteInnerAppQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0011, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    rdb->rdbDataManager_ = nullptr;
    auto result = rdb->DeleteInnerAppQuickFix(BUNDLE_NAME);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0012
 * @tc.name: DeleteInnerAppQuickFix
 * @tc.desc: Verify DeleteInnerAppQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0012, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);

    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    CheckQuickFixInfo(BUNDLE_NAME, 0);

    InnerAppQuickFix innerAppQuickFix = GenerateAppQuickFixInfo(BUNDLE_NAME, QuickFixStatus::DEPLOY_END);
    bool result = rdb->SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_TRUE(result);

    InnerAppQuickFix fixInfo;
    result = rdb->QueryInnerAppQuickFix(BUNDLE_NAME, fixInfo);
    EXPECT_TRUE(result);

    result = rdb->DeleteInnerAppQuickFix(BUNDLE_NAME);
    EXPECT_TRUE(result);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixMgrTest_0001
 * @tc.name: DeployQuickFix
 * @tc.desc: Verify DeployQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrTest_0001, Function | SmallTest | Level0)
{
    auto quickFixMgr = std::make_shared<QuickFixMgr>();
    std::vector<std::string> bundleFilePaths;
    sptr<IQuickFixStatusCallback> statusCallback;
    auto result = quickFixMgr->DeployQuickFix(bundleFilePaths, statusCallback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixMgrTest_0002
 * @tc.name: SwitchQuickFix
 * @tc.desc: Verify SwitchQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrTest_0002, Function | SmallTest | Level0)
{
    auto quickFixMgr = std::make_shared<QuickFixMgr>();
    std::string bundleName;
    bool enable = false;
    sptr<IQuickFixStatusCallback> statusCallback;
    auto result = quickFixMgr->SwitchQuickFix(bundleName, enable, statusCallback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixMgrTest_0003
 * @tc.name: DeleteQuickFix
 * @tc.desc: Verify DeleteQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrTest_0003, Function | SmallTest | Level0)
{
    auto quickFixMgr = std::make_shared<QuickFixMgr>();
    std::string bundleName;
    sptr<IQuickFixStatusCallback> statusCallback;
    auto result = quickFixMgr->DeleteQuickFix(bundleName, statusCallback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0001
 * @tc.name: DeployQuickFix
 * @tc.desc: bundleFilePaths is empty, verify DeployQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0001, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::vector<std::string> bundleFilePaths;
    sptr<IQuickFixStatusCallback> statusCallback = nullptr;
    auto result = impl->DeployQuickFix(bundleFilePaths, statusCallback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0002
 * @tc.name: DeployQuickFix
 * @tc.desc: statusCallback is nullptr, verify DeployQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0002, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.emplace_back("/etc/path");
    sptr<IQuickFixStatusCallback> statusCallback = nullptr;
    auto result = impl->DeployQuickFix(bundleFilePaths, statusCallback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0003
 * @tc.name: DeployQuickFix
 * @tc.desc: Verify DeployQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0003, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.emplace_back("/etc/path");
    sptr<IRemoteObject> object = nullptr;
    sptr<IQuickFixStatusCallback> statusCallback = new (std::nothrow) QuickFixStatusCallbackProxy(object);
    auto result = impl->DeployQuickFix(bundleFilePaths, statusCallback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0004
 * @tc.name: SwitchQuickFix
 * @tc.desc: bundleName is empty, verify SwitchQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0004, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::string bundleName;
    bool enable = false;
    std::vector<std::string> bundleFilePaths;
    sptr<IQuickFixStatusCallback> statusCallback = nullptr;
    auto result = impl->SwitchQuickFix(bundleName, enable, statusCallback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0005
 * @tc.name: SwitchQuickFix
 * @tc.desc: statusCallback is nullptr, verify SwitchQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0005, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::string bundleName = "bundle";
    bool enable = false;
    sptr<IQuickFixStatusCallback> statusCallback = nullptr;
    auto result = impl->SwitchQuickFix(bundleName, enable, statusCallback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0006
 * @tc.name: SwitchQuickFix
 * @tc.desc: Verify SwitchQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0006, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::string bundleName = "bundle";
    bool enable = false;
    sptr<IRemoteObject> object = nullptr;
    sptr<IQuickFixStatusCallback> statusCallback = new (std::nothrow) QuickFixStatusCallbackProxy(object);
    auto result = impl->SwitchQuickFix(bundleName, enable, statusCallback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0007
 * @tc.name: DeleteQuickFix
 * @tc.desc: bundleName is empty, verify DeleteQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0007, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::string bundleName;
    sptr<IQuickFixStatusCallback> statusCallback = nullptr;
    auto result = impl->DeleteQuickFix(bundleName, statusCallback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0008
 * @tc.name: DeleteQuickFix
 * @tc.desc: statusCallback is nullptr, verify DeleteQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0008, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::string bundleName = "bundle";
    sptr<IQuickFixStatusCallback> statusCallback = nullptr;
    auto result = impl->DeleteQuickFix(bundleName, statusCallback);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0009
 * @tc.name: DeleteQuickFix
 * @tc.desc: Verify DeleteQuickFix succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0009, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::string bundleName = "bundle";
    sptr<IRemoteObject> object = nullptr;
    sptr<IQuickFixStatusCallback> statusCallback = new (std::nothrow) QuickFixStatusCallbackProxy(object);
    auto result = impl->DeleteQuickFix(bundleName, statusCallback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0010
 * @tc.name: CreateFd
 * @tc.desc: Verify CreateFd failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0010, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::string fileName;
    int32_t fd;
    std::string path;
    auto result = impl->CreateFd(fileName, fd, path);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0011
 * @tc.name: CreateFd
 * @tc.desc: Verify CreateFd succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0011, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    std::string fileName = "entry.hqf";
    int32_t fd;
    std::string path = "/data/app/el1/bundle/public/com.example.l3jsdemo/patch_1000001/";
    auto result = impl->CreateFd(fileName, fd, path);
    EXPECT_EQ(result, ERR_OK);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0012
 * @tc.name: GetQuickFixMgr
 * @tc.desc: Verify GetQuickFixMgr succeeded.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0012, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    auto result = impl->GetQuickFixMgr();
    EXPECT_TRUE(result);
    EXPECT_TRUE(impl->quickFixMgr_ != nullptr);
}

/**
 * @tc.number: BmsBundleQuickFixManagerHostImplTest_0013
 * @tc.name: CreateFd
 * @tc.desc: Verify CreateFd failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixManagerHostImplTest_0013, Function | SmallTest | Level0)
{
    auto ret = InstallBundle(BUNDLE_PATH);
    EXPECT_EQ(ret, ERR_OK) << "Install bundle failed";

    auto impl = std::make_shared<QuickFixManagerHostImpl>();
    ASSERT_NE(impl, nullptr);
    std::string fileName = "entry.hqf";
    int32_t fd;
    std::string path = "/data/app/el1/bundle/public/com.example.l3jsdemo/patch_1000001/";
    auto result = impl->CreateFd(fileName, fd, path);
    EXPECT_EQ(result, ERR_OK);

    ret = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK) << "Uninstall bundle com.example.l3jsdemo failed";
}

/**
 * @tc.number: UpdateQuickFixStatus_0100
 * @tc.name: UpdateQuickFixStatus
 * @tc.desc: Verification function UpdateQuickFixStatus.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, UpdateQuickFixStatus_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of UpdateQuickFixStatus_0100.");
    QuickFixDataMgr dataMgr;
    QuickFixStatus nextStatus = QuickFixStatus::DELETE_START;
    QuickFixMark mark;
    mark.status = QuickFixStatus::DEFAULT_STATUS;
    InnerAppQuickFix innerAppQuickFix;
    auto result = dataMgr.UpdateQuickFixStatus(nextStatus, innerAppQuickFix);
    EXPECT_TRUE(result);
    APP_LOGI("end of UpdateQuickFixStatus_0100.");
}

/**
 * @tc.number: UpdateQuickFixStatus_0200
 * @tc.name: UpdateQuickFixStatus
 * @tc.desc: Verification function UpdateQuickFixStatus.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, UpdateQuickFixStatus_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of UpdateQuickFixStatus_0200.");
    QuickFixDataMgr dataMgr;
    QuickFixStatus nextStatus = QuickFixStatus::DEFAULT_STATUS;
    QuickFixMark mark;
    mark.status = QuickFixStatus::DEFAULT_STATUS;
    InnerAppQuickFix innerAppQuickFix;
    auto result = dataMgr.UpdateQuickFixStatus(nextStatus, innerAppQuickFix);
    EXPECT_FALSE(result);
    APP_LOGI("end of UpdateQuickFixStatus_0200.");
}

/**
 * @tc.number: UpdateQuickFixStatus_0300
 * @tc.name: UpdateQuickFixStatus
 * @tc.desc: Verification function UpdateQuickFixStatus.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, UpdateQuickFixStatus_0300, Function | SmallTest | Level1)
{
    APP_LOGI("begin of UpdateQuickFixStatus_0300.");
    QuickFixDataMgr dataMgr;
    QuickFixStatus nextStatus = QuickFixStatus::DELETE_END;
    QuickFixMark mark;
    mark.status = QuickFixStatus::DEFAULT_STATUS;
    InnerAppQuickFix innerAppQuickFix;
    auto result = dataMgr.UpdateQuickFixStatus(nextStatus, innerAppQuickFix);
    EXPECT_FALSE(result);
    APP_LOGI("end of UpdateQuickFixStatus_0300.");
    std::vector<HqfInfo> hqfInfos;
}

/**
 * @tc.number: CheckPatchNativeSoWithInstalledBundle_0100
 * @tc.name: CheckPatchNativeSoWithInstalledBundle
 * @tc.desc: Verification function CheckPatchNativeSoWithInstalledBundle.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, CheckPatchNativeSoWithInstalledBundle_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of CheckPatchNativeSoWithInstalledBundle_0100.");
    BundleInfo bundleInfo;
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.cpuAbi = bundleInfo.applicationInfo.cpuAbi;
    QuickFixChecker checker;
    HapModuleInfo hapModuleInfo;
    Parcel parcel;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "name";
    hqfInfo.hapSha256 = "hapSha256";
    hapModuleInfo.moduleName = "name";
    bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
    auto result = hqfInfo.Unmarshalling(parcel);
    deployedAppqfInfo.hqfInfos.emplace_back(hqfInfo);
    deployedAppqfInfo.hqfInfos.emplace_back(*result);
    auto ret = checker.CheckPatchNativeSoWithInstalledBundle(bundleInfo, deployedAppqfInfo);
    EXPECT_EQ(ret, ERR_OK);
    APP_LOGI("end of CheckPatchNativeSoWithInstalledBundle_0100.");
}

/**
 * @tc.number: CheckPatchNativeSoWithInstalledBundle_0200
 * @tc.name: CheckPatchNativeSoWithInstalledBundle
 * @tc.desc: Verification function CheckPatchNativeSoWithInstalledBundle.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, CheckPatchNativeSoWithInstalledBundle_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of CheckPatchNativeSoWithInstalledBundle_0200.");
    BundleInfo bundleInfo;
    AppqfInfo deployedAppqfInfo;
    deployedAppqfInfo.cpuAbi = bundleInfo.applicationInfo.cpuAbi;
    QuickFixChecker checker;
    HapModuleInfo hapModuleInfo;
    Parcel parcel;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "name";
    hqfInfo.hapSha256 = "hapSha256";
    hapModuleInfo.moduleName = "name";
    bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
    hapModuleInfo.nativeLibraryPath = "nativeLibraryPath";
    auto result = hqfInfo.Unmarshalling(parcel);
    deployedAppqfInfo.hqfInfos.emplace_back(hqfInfo);
    deployedAppqfInfo.hqfInfos.emplace_back(*result);
    auto ret = checker.CheckPatchNativeSoWithInstalledBundle(bundleInfo, deployedAppqfInfo);
    EXPECT_EQ(ret, ERR_OK);
    APP_LOGI("end of CheckPatchNativeSoWithInstalledBundle_0200.");
}

/**
 * @tc.number: CheckMultiNativeSo_0010
 * @tc.name: CheckMultiNativeSo
 * @tc.desc: Verification function CheckMultiNativeSo.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, CheckMultiNativeSo_0010, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);
    infos.emplace("appQuickFix_2", appQuickFix);
    infos.emplace("appQuickFix_3", appQuickFix);
    QuickFixChecker checker;
    auto ret = checker.CheckMultiNativeSo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ProcessQuickFixDir_0010
 * @tc.name: ProcessQuickFixDir
 * @tc.desc: Verification function ProcessQuickFixDir.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, ProcessQuickFixDir_0010, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->quickFixInfoMap_.clear();
        std::vector<std::string> dirs;
        dirs.push_back("wrong");
        dirs.push_back("bundleName_10");
        dirs.push_back("bund/bundleName_10");
        scanner->ProcessQuickFixDir(dirs);
        EXPECT_TRUE(scanner->quickFixInfoMap_.empty());
    }
}

/**
 * @tc.number: ProcessQuickFixDir_0020
 * @tc.name: ProcessQuickFixDir
 * @tc.desc: Verification function ProcessQuickFixDir.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, ProcessQuickFixDir_0020, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        scanner->quickFixInfoMap_.clear();
        std::vector<std::string> dirs;
        auto pair = std::pair<int32_t, std::string>(1, "a");
        scanner->quickFixInfoMap_.emplace("a", pair);
        scanner->quickFixInfoMap_.emplace("/n", pair);
        scanner->quickFixInfoMap_.emplace("n", pair);
        scanner->quickFixInfoMap_.emplace("nd", pair);
        dirs.push_back("bu/nd/bundleName_10");
        scanner->ProcessQuickFixDir(dirs);
        EXPECT_FALSE(scanner->quickFixInfoMap_.empty());
    }
}

/**
 * @tc.number: ReprocessQuickFix_0010
 * @tc.name: ReprocessQuickFix
 * @tc.desc: Verification function ReprocessQuickFix.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, ReprocessQuickFix_0010, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        std::string realPath = "/data/service/el1/public/bms/bundle_manager_service/bundle_user_info.json";
        std::string bundlePath = "/data/service/el1/public/bms/bundle_manager_service/bundle_user_info.hqf";
        std::string pathpatch = "/data/service/el1/public/bms/bundle_manager_service/quick_fix_tmp";
        std::vector<std::string> pathVec;
        pathVec.emplace_back(pathpatch);
        std::shared_ptr<QuickFixDeployer> quickFixDeployer = std::make_shared<QuickFixDeployer>(pathVec);
        quickFixDeployer->quickFixDataMgr_ = std::make_shared<QuickFixDataMgr>();
        quickFixDeployer->patchPaths_.emplace_back(pathpatch);
        auto ret = scanner->ReprocessQuickFix(realPath, bundlePath);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: GetApplicationInfo_0010
 * @tc.name: GetApplicationInfo
 * @tc.desc: Verification function GetApplicationInfo.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, GetApplicationInfo_0010, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
        ApplicationInfo info;
        auto ret = scanner->GetApplicationInfo(BUNDLE_NAME, HAP_FILE_PATH, info);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: RestoreQuickFix_0010
 * @tc.name: RestoreQuickFix
 * @tc.desc: Verification function RestoreQuickFix.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, RestoreQuickFix_0010, Function | SmallTest | Level0)
{
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    EXPECT_FALSE(scanner == nullptr);
    if (scanner != nullptr) {
        HqfInfo hqfInfo;
        AppqfInfo app;
        app.hqfInfos.emplace_back(hqfInfo);
        scanner->RestoreQuickFix();
        EXPECT_EQ(scanner->state_, nullptr);
    }
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0013
 * @tc.name: SaveInnerAppQuickFix
 * @tc.desc: rdbDataManager_ is nullptr, verify SaveInnerAppQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0013, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    rdb->rdbDataManager_ = nullptr;
    EXPECT_TRUE(rdb->rdbDataManager_ == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    bool result = rdb->SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0014
 * @tc.name: DeleteInnerAppQuickFix
 * @tc.desc: rdbDataManager_is nullptr, verify DeleteInnerAppQuickFix failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0014, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    EXPECT_TRUE(rdb->rdbDataManager_ != nullptr);
    auto result = rdb->DeleteInnerAppQuickFix(BUNDLE_NAME);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0015
 * @tc.name: GetAllDataFromDb
 * @tc.desc: rdbDataManager_is nullptr, verify GetAllDataFromDb failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0015, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    rdb->rdbDataManager_ = nullptr;
    EXPECT_TRUE(rdb->rdbDataManager_ == nullptr);
    std::map<std::string, InnerAppQuickFix> innerAppQuickFixes;
    auto result = rdb->GetAllDataFromDb(innerAppQuickFixes);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0016
 * @tc.name: SaveDataToDb
 * @tc.desc: rdbDataManager_is nullptr, verify SaveDataToDb failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0016, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    rdb->rdbDataManager_ = nullptr;
    EXPECT_TRUE(rdb->rdbDataManager_ == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    auto result = rdb->SaveDataToDb(innerAppQuickFix);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0017
 * @tc.name: DeleteDataFromDb
 * @tc.desc: rdbDataManager_is nullptr, verify DeleteDataFromDb failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0017, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    rdb->rdbDataManager_ = nullptr;
    EXPECT_TRUE(rdb->rdbDataManager_ == nullptr);
    auto result = rdb->DeleteDataFromDb(BUNDLE_NAME);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundleQuickFixMgrRdbTest_0018
 * @tc.name: GetDataFromDb
 * @tc.desc: rdbDataManager_is nullptr, verify GetDataFromDb failed.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixMgrRdbTest_0018, Function | SmallTest | Level0)
{
    auto rdb = std::make_shared<QuickFixManagerRdb>();
    rdb->rdbDataManager_ = nullptr;
    EXPECT_TRUE(rdb->rdbDataManager_ == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    auto result = rdb->GetDataFromDb(BUNDLE_NAME, innerAppQuickFix);
    EXPECT_FALSE(result);
}

/*
 * @tc.number: BmsBundleQuickFixDataMgrTest_0019
 * @tc.name: QueryInnerAppQuickFix
 * @tc.desc: DataManager_is nullptr.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixDataMgrTest_0019, Function | SmallTest | Level0)
{
    QuickFixDataMgr dataMgr;
    dataMgr.quickFixManagerDb_ = nullptr;
    EXPECT_TRUE(dataMgr.quickFixManagerDb_ == nullptr);
    InnerAppQuickFix fixInfo;
    auto result = dataMgr.QueryInnerAppQuickFix(BUNDLE_NAME, fixInfo);
    EXPECT_FALSE(result);
}

/*
 * @tc.number: BmsBundleQuickFixDataMgrTest_0020
 * @tc.name: SaveInnerAppQuickFix
 * @tc.desc: DataManager_is nullptr.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixDataMgrTest_0020, Function | SmallTest | Level0)
{
    QuickFixDataMgr dataMgr;
    dataMgr.quickFixManagerDb_ = nullptr;
    EXPECT_TRUE(dataMgr.quickFixManagerDb_ == nullptr);
    InnerAppQuickFix innerAppQuickFix;
    auto result = dataMgr.SaveInnerAppQuickFix(innerAppQuickFix);
    EXPECT_FALSE(result);
}

/*
 * @tc.number: BmsBundleQuickFixDataMgrTest_0021
 * @tc.name: DeleteInnerAppQuickFix
 * @tc.desc: DataManager_is nullptr.
 */
HWTEST_F(BmsBundleQuickFixMgrRdbTest, BmsBundleQuickFixDataMgrTest_0021, Function | SmallTest | Level0)
{
    QuickFixDataMgr dataMgr;
    dataMgr.quickFixManagerDb_ = nullptr;
    EXPECT_TRUE(dataMgr.quickFixManagerDb_ == nullptr);
    auto result = dataMgr.DeleteInnerAppQuickFix(BUNDLE_NAME);
    EXPECT_FALSE(result);
}
} // OHOS