/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "application_info.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "module_usage_record.h"
#include "permission_define.h"
#include "remote_ability_info.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME_SYSTEM_RESOURCE = "ohos.global.systemres";
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const std::string WRONG_BUNDLE_NAME = "wrong_bundle_name.ha";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest1.hap";
const std::string HAP_FILE_PATH2 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest2.hap";
const std::string HAP_FILE_PATH3 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest3.hap";
const std::string WRONG_HAP_FILE_PATH = "/data/test/resource/bms/accesstoken_bundle/wrong_bundle_name.ha";
const std::string HAP_NO_ICON = "/data/test/resource/bms/accesstoken_bundle/bmsThirdBundle2.hap";
const std::string HAP_HAS_ICON = "/data/test/resource/bms/accesstoken_bundle/bmsThirdBundle1.hap";
const std::string BUNDLE_NAME_ICON = "com.third.hiworld.example1";
const std::string HAP_NO_ICON_STAGE = "/data/test/resource/bms/accesstoken_bundle/thumbnail2.hap";
const std::string HAP_HAS_ICON_STAGE = "/data/test/resource/bms/accesstoken_bundle/thumbnail.hap";
const std::string BUNDLE_NAME_ICON_STAGE = "com.example.thumbnailtest";
const int32_t USERID = 100;
const uint32_t ZERO = 0;
const uint32_t INVALID_ACCESSTOKENID = 0;
const int32_t WAIT_TIME = 5; // init mocked bms
const int32_t ABILITYID = 1;
}  // namespace

class BmsBundleAccessTokenIdTest : public testing::Test {
public:
    BmsBundleAccessTokenIdTest();
    ~BmsBundleAccessTokenIdTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UpdateBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();

private:
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
};

BmsBundleAccessTokenIdTest::BmsBundleAccessTokenIdTest()
{}

BmsBundleAccessTokenIdTest::~BmsBundleAccessTokenIdTest()
{}

void BmsBundleAccessTokenIdTest::SetUpTestCase()
{}

void BmsBundleAccessTokenIdTest::TearDownTestCase()
{}

void BmsBundleAccessTokenIdTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundleAccessTokenIdTest::TearDown()
{}

ErrCode BmsBundleAccessTokenIdTest::InstallBundle(const std::string &bundlePath) const
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

ErrCode BmsBundleAccessTokenIdTest::UpdateBundle(const std::string &bundlePath) const
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

ErrCode BmsBundleAccessTokenIdTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleAccessTokenIdTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleAccessTokenIdTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleAccessTokenIdTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. test bundle accessTokenId
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_0100, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);
    EXPECT_EQ(info.accessTokenId, INVALID_ACCESSTOKENID);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install a hap
 *           3. test bundle accessTokenId
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_0200, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    EXPECT_NE(info.accessTokenId, INVALID_ACCESSTOKENID);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install a hap, install failed
 *           3. test bundle accessTokenId
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_0300, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(WRONG_HAP_FILE_PATH);
    EXPECT_NE(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);
    EXPECT_EQ(info.accessTokenId, INVALID_ACCESSTOKENID);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install a hap, install failed, install again
 *           3. test the failed
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_0400, Function | SmallTest | Level0)
{
    ErrCode installResult1 = InstallBundle(WRONG_HAP_FILE_PATH);
    EXPECT_NE(installResult1, ERR_OK);
    ErrCode installResult2 = InstallBundle(WRONG_HAP_FILE_PATH);
    EXPECT_NE(installResult2, ERR_OK);
    EXPECT_EQ(installResult1, installResult2);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install a hap, update it
 *           3. test the accessTokenId
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_0500, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    ErrCode updateResult = UpdateBundle(HAP_FILE_PATH2);
    EXPECT_EQ(updateResult, ERR_OK);
    ApplicationInfo info2;
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info2);
    EXPECT_TRUE(result);
    EXPECT_EQ(info.accessTokenId, info2.accessTokenId);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install multi-hap
 *           3. test the accessTokenId
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_0600, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    installResult = InstallBundle(HAP_FILE_PATH3);
    EXPECT_EQ(installResult, ERR_OK);
    ApplicationInfo info2;
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info2);
    EXPECT_TRUE(result);
    EXPECT_EQ(info.accessTokenId, info2.accessTokenId);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetBundleInfo
 * @tc.name: test can create accessTokenId and system permissions
 * @tc.desc: 1. system running normally
 *           2. install a hap
 *           3. check defPermission
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_0700, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    BundleInfo bundleInfo;
    bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
        bundleInfo, USERID);
    EXPECT_TRUE(result);
    EXPECT_EQ(bundleInfo.defPermissions.size(), ZERO);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetBundleInfo
 * @tc.name: test can create accessTokenId and system permissions
 * @tc.desc: 1. system running normally
 *           2. check ohos.global.systemres accessTokenId and defpermissions
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_0800, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_SYSTEM_RESOURCE, ApplicationFlag::GET_BASIC_APPLICATION_INFO,
        USERID, info);
    EXPECT_TRUE(result);
    EXPECT_NE(info.accessTokenId, INVALID_ACCESSTOKENID);
    BundleInfo bundleInfo;
    result = dataMgr->GetBundleInfo(BUNDLE_NAME_SYSTEM_RESOURCE, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
        bundleInfo, USERID);
    EXPECT_NE(bundleInfo.defPermissions.size(), ZERO);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetBundleInfo
 * @tc.name: test can create accessTokenId and system permissions
 * @tc.desc: 1. system running normally
 *           2. install a hap
 *           3. check reqPermissionStates
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_0900, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    BundleInfo bundleInfo;
    bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
        bundleInfo, USERID);
    EXPECT_TRUE(result);
    EXPECT_NE(bundleInfo.reqPermissionStates.size(), ZERO);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetBundleInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install a hap, update it
 *           3. check reqPermissionStates
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_1000, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ErrCode updateResult = UpdateBundle(HAP_FILE_PATH2);
    EXPECT_EQ(updateResult, ERR_OK);
    BundleInfo bundleInfo;
    bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
        bundleInfo, USERID);
    EXPECT_TRUE(result);
    EXPECT_NE(bundleInfo.reqPermissionStates.size(), ZERO);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleAccessTokenIdTest
 * Function: GetBundleInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install multi-hap
 *           3. check reqPermissionStates
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_1100, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    installResult = InstallBundle(HAP_FILE_PATH3);
    EXPECT_EQ(installResult, ERR_OK);
    BundleInfo bundleInfo;
    bool result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
        bundleInfo, USERID);
    EXPECT_TRUE(result);
    EXPECT_NE(bundleInfo.reqPermissionStates.size(), ZERO);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleAccessTokenId_1200
 * Function: ReadMetaDataFromParcel
 * @tc.name: test ResultJson
 * @tc.desc: ReadMetaDataFromParcel
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleAccessTokenId_1200, Function | SmallTest | Level0)
{
    ApplicationInfo info;
    info.accessTokenId = INVALID_ACCESSTOKENID;
    Parcel parcel;
    auto result = info.ReadMetaDataFromParcel(parcel);
    EXPECT_NE(result, false);
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    result = info.ReadMetaDataFromParcel(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number: ModuleUsageRecord_0001
 * @tc.name: test FromJsonString
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test FromJsonString and ToString
 */
HWTEST_F(BmsBundleAccessTokenIdTest, ModuleUsageRecord_0001, Function | SmallTest | Level0)
{
    ModuleUsageRecord moduleUsageRecord;
    std::string value = moduleUsageRecord.ToString();
    auto res = moduleUsageRecord.FromJsonString(value);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: DbmsServicesKitTest_0022
 * @tc.name: test ModuleUsageRecord
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleAccessTokenIdTest, ModuleUsageRecord_0002, Function | SmallTest | Level0)
{
    ModuleUsageRecord moduleUsageRecord;
    moduleUsageRecord.bundleName = "bundleName";
    moduleUsageRecord.appLabelId = ABILITYID;
    moduleUsageRecord.name = "name";
    moduleUsageRecord.abilityLabelId = ABILITYID;
    moduleUsageRecord.abilityDescriptionId = ABILITYID;
    moduleUsageRecord.abilityIconId = ABILITYID;
    moduleUsageRecord.installationFreeSupported = false;

    Parcel parcel;
    auto unmarshalledResult = ModuleUsageRecord::Unmarshalling(parcel);
    EXPECT_NE(unmarshalledResult->bundleName, "bundleName");
    bool ret = moduleUsageRecord.Marshalling(parcel);
    EXPECT_TRUE(ret);
    unmarshalledResult = ModuleUsageRecord::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->bundleName, "bundleName");
    EXPECT_EQ(unmarshalledResult->appLabelId, ABILITYID);
    EXPECT_EQ(unmarshalledResult->name, "name");
    EXPECT_EQ(unmarshalledResult->abilityLabelId, ABILITYID);
    EXPECT_EQ(unmarshalledResult->abilityDescriptionId, ABILITYID);
    EXPECT_EQ(unmarshalledResult->abilityIconId, ABILITYID);
    EXPECT_EQ(unmarshalledResult->installationFreeSupported, false);
}

/**
 * @tc.number: BundleUserInfoMarshalling_0001
 * @tc.name: test BundleUserInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BundleUserInfoMarshalling_0001, Function | SmallTest | Level0)
{
    BundleUserInfo bundleUserInfo;
    bundleUserInfo.userId = Constants::START_USERID;
    bundleUserInfo.enabled = false;

    Parcel parcel;
    auto unmarshalledResult = BundleUserInfo::Unmarshalling(parcel);
    bool ret = bundleUserInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
    unmarshalledResult = BundleUserInfo::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->userId, Constants::START_USERID);
    EXPECT_EQ(unmarshalledResult->enabled, false);
}

/**
 * @tc.number: RemoteAbilityInfo_0001
 * @tc.name: test RemoteAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleAccessTokenIdTest, RemoteAbilityInfo_0001, Function | SmallTest | Level0)
{
    RemoteAbilityInfo remoteAbilityInfo;
    remoteAbilityInfo.label = "label";
    remoteAbilityInfo.icon = "icon";

    Parcel parcel;
    auto unmarshalledResult = remoteAbilityInfo.Unmarshalling(parcel);
    bool ret = remoteAbilityInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
    unmarshalledResult = remoteAbilityInfo.Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->label, "label");
    EXPECT_EQ(unmarshalledResult->icon, "icon");
}

/**
 * @tc.number: DbmsServicesKitTest_0001
 * @tc.name: test DistributedAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test to_json and from_json
 */
HWTEST_F(BmsBundleAccessTokenIdTest, DbmsServicesKitTest_0001, Function | SmallTest | Level0)
{
    DistributedAbilityInfo distributedAbilityInfo;
    distributedAbilityInfo.abilityName = "abilityName";
    nlohmann::json jsonObject;
    to_json(jsonObject, distributedAbilityInfo);
    DistributedAbilityInfo result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.abilityName, "abilityName");
}

/**
 * @tc.number: DbmsServicesKitTest_0002
 * @tc.name: test DistributedAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test Dump
 */
HWTEST_F(BmsBundleAccessTokenIdTest, DbmsServicesKitTest_0002, Function | SmallTest | Level0)
{
    DistributedAbilityInfo distributedAbilityInfo;
    std::string path = "/data/test/abilityInfo.txt";
    std::ofstream file(path);
    file.close();
    int fd = 8;
    std::string prefix = "[ability]";
    distributedAbilityInfo.Dump(prefix, fd);
    long length = lseek(fd, ZERO, SEEK_END);
    EXPECT_NE(length, -1);
}

/**
 * @tc.number: DbmsServicesKitTest_0003
 * @tc.name: test DistributedBundleInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test FromJsonString and ToString
 */
HWTEST_F(BmsBundleAccessTokenIdTest, DbmsServicesKitTest_0003, Function | SmallTest | Level0)
{
    DistributedBundleInfo distributedBundleInfo;
    std::string value = distributedBundleInfo.ToString();
    std::string jsonString;
    auto res = distributedBundleInfo.FromJsonString(value);
    EXPECT_EQ(res, true);
    res = distributedBundleInfo.FromJsonString(jsonString);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: DbmsServicesKitTest_0004
 * @tc.name: test DistributedBundleInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleAccessTokenIdTest, DbmsServicesKitTest_0004, Function | SmallTest | Level0)
{
    DistributedBundleInfo distributedBundleInfo;
    distributedBundleInfo.version = Constants::BUNDLE_RDB_VERSION;
    distributedBundleInfo.bundleName = "bundleName";
    distributedBundleInfo.versionCode = Constants::BUNDLE_RDB_VERSION;
    distributedBundleInfo.versionName = "versionName";
    distributedBundleInfo.minCompatibleVersion = Constants::BUNDLE_RDB_VERSION;
    distributedBundleInfo.targetVersionCode = Constants::BUNDLE_RDB_VERSION;
    distributedBundleInfo.compatibleVersionCode = Constants::BUNDLE_RDB_VERSION;
    distributedBundleInfo.appId = "appId";
    distributedBundleInfo.enabled = false;

    Parcel parcel;
    bool ret = distributedBundleInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
    auto unmarshalledResult = DistributedBundleInfo::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->version, Constants::BUNDLE_RDB_VERSION);
    EXPECT_EQ(unmarshalledResult->bundleName, "bundleName");
    EXPECT_EQ(unmarshalledResult->versionCode, Constants::BUNDLE_RDB_VERSION);
    EXPECT_EQ(unmarshalledResult->versionName, "versionName");
    EXPECT_EQ(unmarshalledResult->minCompatibleVersion, Constants::BUNDLE_RDB_VERSION);
    EXPECT_EQ(unmarshalledResult->targetVersionCode, Constants::BUNDLE_RDB_VERSION);
    EXPECT_EQ(unmarshalledResult->compatibleVersionCode, Constants::BUNDLE_RDB_VERSION);
    EXPECT_EQ(unmarshalledResult->appId, "appId");
    EXPECT_EQ(unmarshalledResult->enabled, false);
}

/**
 * @tc.number: DbmsServicesKitTest_0005
 * @tc.name: test DistributedModuleInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test to_json and from_json
 */
HWTEST_F(BmsBundleAccessTokenIdTest, DbmsServicesKitTest_0005, Function | SmallTest | Level0)
{
    DistributedModuleInfo distributedModuleInfo;
    distributedModuleInfo.moduleName = "moduleName";
    nlohmann::json jsonObject;
    to_json(jsonObject, distributedModuleInfo);
    DistributedModuleInfo result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.moduleName, "moduleName");
}

/**
 * @tc.number: DbmsServicesKitTest_0006
 * @tc.name: test DistributedModuleInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test Dump
 */
HWTEST_F(BmsBundleAccessTokenIdTest, DbmsServicesKitTest_0006, Function | SmallTest | Level0)
{
    DistributedModuleInfo distributedModuleInfo;
    std::string path = "/data/test/abilityInfo.txt";
    std::ofstream file(path);
    file.close();
    int fd = 8;
    std::string prefix = "[ability]";
    distributedModuleInfo.Dump(prefix, fd);
    long length = lseek(fd, ZERO, SEEK_END);
    EXPECT_NE(length, -1);
}

/**
 * @tc.number: DbmsServicesKitTest_0007
 * @tc.name: test SummaryAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleAccessTokenIdTest, DbmsServicesKitTest_0007, Function | SmallTest | Level0)
{
    SummaryAbilityInfo summaryAbilityInfo;
    summaryAbilityInfo.bundleName = "bundleName";
    summaryAbilityInfo.moduleName = "moduleName";
    summaryAbilityInfo.abilityName = "abilityName";
    summaryAbilityInfo.logoUrl = "logoUrl";
    summaryAbilityInfo.label = "label";
    summaryAbilityInfo.deviceType.push_back("deviceType");
    summaryAbilityInfo.rpcId.push_back("rpcId");

    Parcel parcel;
    bool ret = summaryAbilityInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
    auto unmarshalledResult = SummaryAbilityInfo::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->bundleName, "bundleName");
    EXPECT_EQ(unmarshalledResult->moduleName, "moduleName");
    EXPECT_EQ(unmarshalledResult->abilityName, "abilityName");
    EXPECT_EQ(unmarshalledResult->logoUrl, "logoUrl");
    EXPECT_EQ(unmarshalledResult->label, "label");
    EXPECT_EQ(unmarshalledResult->deviceType.size(), 1);
    EXPECT_EQ(unmarshalledResult->rpcId.size(), 1);
}

/**
 * @tc.number: DbmsServicesKitTest_0008
 * @tc.name: test SummaryAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test to_json and from_json
 */
HWTEST_F(BmsBundleAccessTokenIdTest, DbmsServicesKitTest_0008, Function | SmallTest | Level0)
{
    SummaryAbilityInfo summaryAbilityInfo;
    summaryAbilityInfo.abilityName = "abilityName";
    nlohmann::json jsonObject;
    to_json(jsonObject, summaryAbilityInfo);
    SummaryAbilityInfo result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.abilityName, "abilityName");
}

/**
 * @tc.number: DbmsServicesKitTest_0009
 * @tc.name: test RpcIdResult
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test to_json and from_json
 */
HWTEST_F(BmsBundleAccessTokenIdTest, DbmsServicesKitTest_0009, Function | SmallTest | Level0)
{
    RpcIdResult rpcIdResult;
    rpcIdResult.version = "version";
    rpcIdResult.transactId = "transactId";
    rpcIdResult.retCode = 1;
    rpcIdResult.resultMsg = "resultMsg";
    nlohmann::json jsonObject;
    to_json(jsonObject, rpcIdResult);
    RpcIdResult result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.version, "version");
    EXPECT_EQ(result.transactId, "transactId");
    EXPECT_EQ(result.retCode, 1);
    EXPECT_EQ(result.resultMsg, "resultMsg");
}

/**
 * @tc.number: BmsBundleHideIconTest_0001
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install no icon hap
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleHideIconTest_0001, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_NO_ICON);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON, 0, USERID, applicationInfo);
    EXPECT_TRUE(result);
    EXPECT_TRUE(applicationInfo.needAppDetail);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_ICON);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHideIconTest_0002
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install no icon hap, update it with has icon hap
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleHideIconTest_0002, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_NO_ICON);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON, 0, USERID, applicationInfo);
    EXPECT_TRUE(result);
    EXPECT_TRUE(applicationInfo.needAppDetail);

    installResult = UpdateBundle(HAP_HAS_ICON);
    EXPECT_EQ(installResult, ERR_OK);
    ApplicationInfo applicationInfo2;
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON, 0, USERID, applicationInfo2);
    EXPECT_TRUE(result);
    EXPECT_FALSE(applicationInfo2.needAppDetail);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_ICON);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHideIconTest_0003
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install has icon hap, update it with no icon hap
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleHideIconTest_0003, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_HAS_ICON);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON, 0, USERID, applicationInfo);
    EXPECT_TRUE(result);
    EXPECT_FALSE(applicationInfo.needAppDetail);

    installResult = UpdateBundle(HAP_NO_ICON);
    EXPECT_EQ(installResult, ERR_OK);
    ApplicationInfo applicationInfo2;
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON, 0, USERID, applicationInfo2);
    EXPECT_TRUE(result);
    EXPECT_TRUE(applicationInfo2.needAppDetail);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_ICON);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHideIconTest_0004
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install no icon hap
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleHideIconTest_0004, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_NO_ICON_STAGE);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON_STAGE, 0, USERID, applicationInfo);
    EXPECT_TRUE(result);
    EXPECT_TRUE(applicationInfo.needAppDetail);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_ICON_STAGE);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHideIconTest_0005
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install no icon hap, update it with has icon hap
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleHideIconTest_0005, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_NO_ICON_STAGE);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON_STAGE, 0, USERID, applicationInfo);
    EXPECT_TRUE(result);
    EXPECT_TRUE(applicationInfo.needAppDetail);

    installResult = UpdateBundle(HAP_HAS_ICON_STAGE);
    EXPECT_EQ(installResult, ERR_OK);
    ApplicationInfo applicationInfo2;
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON_STAGE, 0, USERID, applicationInfo2);
    EXPECT_TRUE(result);
    EXPECT_FALSE(applicationInfo2.needAppDetail);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_ICON_STAGE);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleHideIconTest_0006
 * Function: GetApplicationInfo
 * @tc.name: test can create accessTokenId
 * @tc.desc: 1. system running normally
 *           2. install has icon hap, update it with no icon hap
 */
HWTEST_F(BmsBundleAccessTokenIdTest, BmsBundleHideIconTest_0006, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_HAS_ICON_STAGE);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON_STAGE, 0, USERID, applicationInfo);
    EXPECT_TRUE(result);
    EXPECT_FALSE(applicationInfo.needAppDetail);

    installResult = UpdateBundle(HAP_NO_ICON_STAGE);
    EXPECT_EQ(installResult, ERR_OK);
    ApplicationInfo applicationInfo2;
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME_ICON_STAGE, 0, USERID, applicationInfo2);
    EXPECT_TRUE(result);
    EXPECT_TRUE(applicationInfo2.needAppDetail);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_ICON_STAGE);
    EXPECT_EQ(unInstallResult, ERR_OK);
}
} // OHOS