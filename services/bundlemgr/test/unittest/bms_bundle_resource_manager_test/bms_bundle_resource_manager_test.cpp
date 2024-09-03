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
#include <set>
#include <sstream>
#include <string>

#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string BUNDLE_PATH = "/data/test/resource/bms/resource_manager/resourceManagerTest.hap";
const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
const std::string MODULE_NAME = "entry";
const std::string APP_LABEL = "ResourceDemo";
const std::string DESCRIPTION = "description";
const std::string ABILITY_LABEL = "label";
const int32_t APP_LABEL_ID = 16777216;
const int32_t DESCRIPTION_ID = 16777218;
const int32_t ABILITY_LABEL_ID = 16777219;
const int32_t APP_ICON_ID = 16777217;
const int32_t ABILITY_ICON_ID = 16777222;
const int32_t USER_ID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const uint32_t DENSITY_120_STR = 120; // sdpi
const uint32_t DENSITY_160_STR = 160; // mdpi
const uint32_t DENSITY_240_STR = 240; // ldpi
const uint32_t DENSITY_320_STR = 320; // xldpi
const uint32_t DENSITY_480_STR = 480; // xxldpi
const uint32_t DENSITY_640_STR = 640; // xxxldpi

class BmsBundleResourceManagerTest : public testing::Test {
public:
    BmsBundleResourceManagerTest();
    ~BmsBundleResourceManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    void StartInstalldService() const;
    void StartBundleService();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleResourceManagerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleResourceManagerTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleResourceManagerTest::BmsBundleResourceManagerTest()
{}

BmsBundleResourceManagerTest::~BmsBundleResourceManagerTest()
{}

void BmsBundleResourceManagerTest::SetUpTestCase()
{}

void BmsBundleResourceManagerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleResourceManagerTest::SetUp()
{
    StartBundleService();
    StartInstalldService();
    InstallBundle(BUNDLE_PATH);
}

void BmsBundleResourceManagerTest::TearDown()
{
    UnInstallBundle(BUNDLE_NAME);
}

ErrCode BmsBundleResourceManagerTest::InstallBundle(const std::string &bundlePath) const
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
    installParam.userId = USER_ID;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleResourceManagerTest::UnInstallBundle(const std::string &bundleName) const
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
    installParam.userId = USER_ID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

const std::shared_ptr<BundleDataMgr> BmsBundleResourceManagerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}


void BmsBundleResourceManagerTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleResourceManagerTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

/**
 * @tc.name: GetStringById_001
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string label = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, APP_LABEL_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(label, APP_LABEL);
}

/**
 * @tc.name: GetStringById_002
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_002, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string label = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, ABILITY_LABEL_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(label, ABILITY_LABEL);

    std::string description = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, DESCRIPTION_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(description, DESCRIPTION);
}

/**
 * @tc.name: GetStringById_003
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_003, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::string description = dataMgr->GetStringById(
        "", MODULE_NAME, ABILITY_LABEL_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(description, "");
}

/**
 * @tc.name: GetStringById_004
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_004, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::string abilityLabel = dataMgr->GetStringById(
        BUNDLE_NAME, "", ABILITY_LABEL_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(abilityLabel, ABILITY_LABEL);
}

/**
 * @tc.name: GetStringById_005
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_005, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::string description = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, 0, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(description, "");
}

/**
 * @tc.name: GetStringById_006
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_006, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::string description = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, ABILITY_LABEL_ID, 0, Constants::EMPTY_STRING);
    EXPECT_EQ(description, "");
}

/**
 * @tc.name: GetIconById_001
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, APP_ICON_ID, 0, USER_ID);
    EXPECT_NE(iconBase64, "");
}

/**
 * @tc.name: GetIconById_002
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_002, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon120Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_120_STR, USER_ID);
    EXPECT_NE(icon120Base64, "");
}

/**
 * @tc.name: GetIconById_003
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_003, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon160Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_160_STR, USER_ID);
    EXPECT_NE(icon160Base64, "");
}

/**
 * @tc.name: GetIconById_004
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_004, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon240Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_240_STR, USER_ID);
    EXPECT_NE(icon240Base64, "");
}

/**
 * @tc.name: GetIconById_005
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_005, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon320Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_320_STR, USER_ID);
    EXPECT_NE(icon320Base64, "");
}

/**
 * @tc.name: GetIconById_007
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_006, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon480Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_480_STR, USER_ID);
    EXPECT_NE(icon480Base64, "");
}

/**
 * @tc.name: GetIconById_008
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_007, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon640Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_640_STR, USER_ID);
    EXPECT_NE(icon640Base64, "");
}

/**
 * @tc.name: GetIconById_009
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_008, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconDefaultBase64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, 0, USER_ID);
    EXPECT_NE(iconDefaultBase64, "");
}

/**
 * @tc.name: GetIconById_009
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_009, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, 0, -1);
    EXPECT_EQ(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0010
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, 0, USER_ID);
    EXPECT_NE(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0011
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0011, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById("", MODULE_NAME, ABILITY_ICON_ID, 0, USER_ID);
    EXPECT_EQ(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0012
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0012, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById(BUNDLE_NAME, "", ABILITY_ICON_ID, 0, USER_ID);
    EXPECT_NE(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0013
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0013, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, 0, 0, USER_ID);
    EXPECT_EQ(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0014
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0014, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, 0, 0);
    EXPECT_EQ(iconBase64, "");
}
}
} // OHOS