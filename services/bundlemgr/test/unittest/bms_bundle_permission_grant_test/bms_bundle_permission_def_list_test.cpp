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

#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "permission_define.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string APPID = "appId";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string PERMISSION_TEST = "ohos.permission.test";
const std::string MODULE_ENTRY_NAME = "entry";
}  // namespace

class BmsBundlePermissionDefListTest : public testing::Test {
public:
    BmsBundlePermissionDefListTest();
    ~BmsBundlePermissionDefListTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();
    void InitInnerBundleInfo(InnerBundleInfo &innerBundleInfo);
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundlePermissionDefListTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundlePermissionDefListTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundlePermissionDefListTest::BmsBundlePermissionDefListTest()
{}

BmsBundlePermissionDefListTest::~BmsBundlePermissionDefListTest()
{}

void BmsBundlePermissionDefListTest::SetUpTestCase()
{}

void BmsBundlePermissionDefListTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundlePermissionDefListTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundlePermissionDefListTest::InitInnerBundleInfo(InnerBundleInfo &innerBundleInfo)
{
    innerBundleInfo.SetAppPrivilegeLevel(Profile::AVAILABLELEVEL_SYSTEM_CORE);
    InnerModuleInfo innerModuleInfo;
    RequestPermission requestPermission;
    requestPermission.name = PERMISSION_TEST;
    innerModuleInfo.requestPermissions.emplace_back(requestPermission);
    innerBundleInfo.InsertInnerModuleInfo(MODULE_ENTRY_NAME, innerModuleInfo);
}

void BmsBundlePermissionDefListTest::TearDown()
{}
ErrCode BmsBundlePermissionDefListTest::InstallBundle(const std::string &bundlePath) const
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

ErrCode BmsBundlePermissionDefListTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundlePermissionDefListTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundlePermissionDefListTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundlePermissionDefListTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: BmsBundlePermissionDefListTest
 * Function: UpdateDefineAndRequestPermissions
 * @tc.name: test UpdateDefineAndRequestPermissions verify false
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionDefListTest, BmsBundlePermissionDefListTest_0100, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    Security::AccessToken::AccessTokenIDEx tokenIdEx;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    std::vector<std::string> newRequestPermName;
    res = BundlePermissionMgr::UpdateDefineAndRequestPermissions(tokenIdEx, oldInfo, newInfo, newRequestPermName);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundlePermissionDefListTest
 * Function: AddDefineAndRequestPermissions
 * @tc.name: test AddDefineAndRequestPermissions verify false
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionDefListTest, BmsBundlePermissionDefListTest_0200, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    Security::AccessToken::AccessTokenIDEx tokenIdEx;
    InnerBundleInfo innerBundleInfo;
    std::vector<std::string> newRequestPermName;
    res = BundlePermissionMgr::AddDefineAndRequestPermissions(tokenIdEx, innerBundleInfo, newRequestPermName);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundlePermissionDefListTest
 * Function: InnerGrantRequestPermissions
 * @tc.name: test InnerGrantRequestPermissions false
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionDefListTest, BmsBundlePermissionDefListTest_0300, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    Security::AccessToken::AccessTokenID tokenId = 0;
    InnerBundleInfo innerBundleInfo;
    std::vector<std::string> systemGrantPermList;
    std::vector<std::string> userGrantPermList;
    res = BundlePermissionMgr::InnerGrantRequestPermissions(
        tokenId, innerBundleInfo, systemGrantPermList, userGrantPermList);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundlePermissionDefListTest
 * Function: CheckGrantPermission
 * @tc.name: test CheckGrantPermission verify success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionDefListTest, BmsBundlePermissionDefListTest_0400, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    AccessToken::PermissionDef permDef;
    std::vector<std::string> acls;
    permDef.availableLevel = AccessToken::ATokenAplEnum::APL_SYSTEM_CORE;
    res = BundlePermissionMgr::CheckGrantPermission(permDef, Profile::AVAILABLELEVEL_SYSTEM_CORE, acls);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundlePermissionDefListTest
 * Function: CheckGrantPermission
 * @tc.name: test CheckGrantPermission false
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionDefListTest, BmsBundlePermissionDefListTest_0500, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    AccessToken::PermissionDef permDef;
    std::vector<std::string> acls;
    permDef.availableLevel = AccessToken::ATokenAplEnum::APL_SYSTEM_CORE;
    permDef.provisionEnable = true;
    res = BundlePermissionMgr::CheckGrantPermission(permDef, Profile::AVAILABLELEVEL_SYSTEM_BASIC, acls);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundlePermissionDefListTest
 * Function: GetRequestPermissionStates
 * @tc.name: test GetRequestPermissionStates success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionDefListTest, BmsBundlePermissionDefListTest_0600, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    BundleInfo bundleInfo;
    bundleInfo.reqPermissions.push_back("1");
    uint32_t tokenId = 1;
    res = BundlePermissionMgr::GetRequestPermissionStates(bundleInfo, tokenId, "");
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundlePermissionDefListTest
 * Function: GetPermissionDef
 * @tc.name: test GetPermissionDef verify success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionDefListTest, BmsBundlePermissionDefListTest_0700, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    PermissionDef permissionDef;
    ErrCode ret = BundlePermissionMgr::GetPermissionDef("", permissionDef);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundlePermissionDefListTest
 * Function: VerifySystemApp
 * @tc.name: test VerifySystemApp verify success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionDefListTest, BmsBundlePermissionDefListTest_0800, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    int32_t beginSystemApiVersion = 1;
    res = BundlePermissionMgr::VerifySystemApp(beginSystemApiVersion);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsBundlePermissionDefListTest
 * Function: InnerFilterRequestPermissions
 * @tc.name: test InnerFilterRequestPermissions verify success
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionDefListTest, InnerFilterRequestPermissions_0100, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    InnerBundleInfo innerBundleInfo;
    InitInnerBundleInfo(innerBundleInfo);
    std::vector<std::string> systemGrantPermList;
    std::vector<std::string> userGrantPermList;
    bool result = BundlePermissionMgr::InnerFilterRequestPermissions(
        innerBundleInfo, systemGrantPermList, userGrantPermList);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsBundlePermissionDefListTest_0900
 * @tc.name: test AppControlManagerHostImpl
 * @tc.desc: 1.SetDisposedStatus test
 *           2.GetDisposedStatus test
 */
HWTEST_F(BmsBundlePermissionDefListTest, BmsBundlePermissionDefListTest_0900, Function | SmallTest | Level1)
{
    AppControlManagerHostImpl impl;
    DisposedRule rule;
    ErrCode res = impl.SetDisposedRule(APPID, rule, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);

    res = impl.GetDisposedRule(APPID, rule, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}
} // OHOS