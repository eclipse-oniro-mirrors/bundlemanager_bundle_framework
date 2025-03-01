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

#include <chrono>
#include <fstream>
#include <gtest/gtest.h>
#include <unordered_map>
#include <vector>

#include "ability_info.h"
#include "bundle_data_mgr.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_host.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME_TEST = "com.example.ohosproject.hmservice";
const std::string ABILITY_NAME_TEST = "MainAbility";
const std::string ABILITY_NAME_TEST_1 = "MainAbility1";
const std::string ABILITY_NAME_TEST_2 = "MainAbility2";
const std::string ABILITY_NAME_TEST_3 = "MainAbility3";
const std::string ABILITY_NAME_TEST_4 = "MainAbility4";
const std::string ABILITY_NAME_TEST_5 = "MainAbility5";
const std::string ABILITY_NAME_TEST_6 = "MainAbility6";
const std::string ABILITY_NAME_TEST_7 = "MainAbility7";
const std::string ABILITY_NAME_TEST_8 = "MainAbility8";
const std::string ABILITY_NAME_TEST_9 = "MainAbility9";
const std::string ABILITY_NAME_TEST_10 = "MainAbility10";
const std::string ABILITY_NAME_TEST_11 = "MainAbility11";
const std::string ABILITY_NAME_TEST_12 = "MainAbility12";
const std::string BUNLDE_FILE_PATH = "/data/test/resource/bms/install_bundle/sandboxTest.hap";
const std::string ORIENTATION = "orientation";
const std::string MAX_WINDOW_RATIO = "maxWindowRatio";
const std::string MIN_WINDOW_RATIO = "minWindowRatio";
const std::string MAX_WINDOW_WIDTH = "maxWindowWidth";
const std::string MIN_WINDOW_WIDTH = "minWindowWidth";
const std::string MAX_WINDOW_HEIGHT = "maxWindowHeight";
const std::string MIN_WINDOW_HEIGHT = "minWindowHeight";
const int32_t UNSPECIFIED = 0;
const int32_t LANDSCAPE = 1;
const int32_t PORTRAIT = 2;
const int32_t LANDSCAPE_INVERTED = 4;
const int32_t PORTRAIT_INVERTED = 5;
const int32_t AUTO_ROTATION = 6;
const int32_t AUTO_ROTATION_LANDSCAPE = 7;
const int32_t AUTO_ROTATION_PORTRAIT = 8;
const int32_t AUTO_ROTATION_RESTRICTED = 9;
const int32_t AUTO_ROTATION_LANDSCAPE_RESTRICTED = 10;
const int32_t AUTO_ROTATION_PORTRAIT_RESTRICTED = 11;
const int32_t LOCKED = 12;
const double MAX_WINDOW_RATIO_VALUE = 3.5;
const double MIN_WINDOW_RATIO_VALUE = 0.5;
const int32_t MAX_WINDOW_WIDTH_VALUE = 2560;
const int32_t MIN_WINDOW_WIDTH_VALUE = 1400;
const int32_t MAX_WINDOW_HEIGHT_VALUE = 300;
const int32_t MIN_WINDOW_HEIGHT_VALUE = 200;
const int32_t DEFAULT_USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
} // namespace

class BmsBundleGetWindowPropertiesTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::vector<std::string> &filePaths);
    ErrCode UninstallBundle(const std::string &bundleName);
    std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    bool CheckWindowProperty1(const std::string &abilityName, double expectedValue, const std::string &option);
    void CheckWindowProperty2(const std::string &abilityName, std::vector<int32_t> modeVec);

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleGetWindowPropertiesTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleGetWindowPropertiesTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundleGetWindowPropertiesTest::SetUpTestCase()
{}

void BmsBundleGetWindowPropertiesTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleGetWindowPropertiesTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(DEFAULT_USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    // install test hap
    std::vector<std::string> pathVec {BUNLDE_FILE_PATH};
    auto err = InstallBundle(pathVec);
    EXPECT_EQ(err, ERR_OK);
}

void BmsBundleGetWindowPropertiesTest::TearDown()
{
    auto err = UninstallBundle(BUNDLE_NAME_TEST);
    EXPECT_EQ(err, ERR_OK);
}

std::shared_ptr<BundleDataMgr> BmsBundleGetWindowPropertiesTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

ErrCode BmsBundleGetWindowPropertiesTest::InstallBundle(const std::vector<std::string> &filePaths)
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
    installParam.userId = DEFAULT_USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.withCopyHaps = true;
    bool result = installer->Install(filePaths, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleGetWindowPropertiesTest::UninstallBundle(const std::string &bundleName)
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
    installParam.userId = DEFAULT_USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

bool BmsBundleGetWindowPropertiesTest::CheckWindowProperty1(const std::string &abilityName, double expectedValue,
    const std::string &option)
{
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, abilityName);
    AbilityInfo result;

    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, flags, DEFAULT_USERID, result);
    if (!testRet) {
        return false;
    }

    std::unordered_map<std::string, double> resultMap;
    resultMap.emplace(ORIENTATION, static_cast<double>(result.orientation));
    resultMap.emplace(MAX_WINDOW_RATIO, result.maxWindowRatio);
    resultMap.emplace(MIN_WINDOW_RATIO, result.minWindowRatio);
    resultMap.emplace(MAX_WINDOW_WIDTH, static_cast<double>(result.maxWindowWidth));
    resultMap.emplace(MIN_WINDOW_WIDTH, static_cast<double>(result.minWindowWidth));
    resultMap.emplace(MAX_WINDOW_HEIGHT, static_cast<double>(result.maxWindowHeight));
    resultMap.emplace(MIN_WINDOW_HEIGHT, static_cast<double>(result.minWindowHeight));
    if (resultMap.find(option) != resultMap.end() && resultMap.at(option) == expectedValue) {
        return true;
    }
    return false;
}

void BmsBundleGetWindowPropertiesTest::CheckWindowProperty2(const std::string &abilityName,
    std::vector<int32_t> modeVec)
{
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, abilityName);
    AbilityInfo result;

    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, flags, DEFAULT_USERID, result);
    EXPECT_EQ(true, testRet);
    std::vector<int32_t> innerVec;
    for_each(result.windowModes.begin(), result.windowModes.end(), [&innerVec](const auto &mode)->decltype(auto) {
        innerVec.emplace_back(static_cast<int32_t>(mode));
    });
    sort(innerVec.begin(), innerVec.end());
    sort(modeVec.begin(), modeVec.end());
    auto isSame = innerVec == modeVec;
    EXPECT_TRUE(isSame);
}


/**
 * @tc.number: GetWindowProperties_0100
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to default value
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_0100, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST, 0, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_0200
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 0 (UNSPECIFIED)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_0200, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_1, UNSPECIFIED, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_0300
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 1 (LANDSCAPE)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_0300, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_2, LANDSCAPE, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_0400
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 2 (PORTRAIT)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_0400, Function | SmallTest | Level2)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_3, PORTRAIT, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_0500
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 4 (LANDSCAPE_INVERTED)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_0500, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_4, LANDSCAPE_INVERTED, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_0600
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 5 (PORTRAIT_INVERTED)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_0600, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_5, PORTRAIT_INVERTED, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_0700
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 6 (AUTO_ROTATION)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_0700, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_6, AUTO_ROTATION, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_0800
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 7 (AUTO_ROTATION_LANDSCAPE)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_0800, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_7, AUTO_ROTATION_LANDSCAPE, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_0900
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 8 (AUTO_ROTATION_PORTRAIT)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_0900, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_8, AUTO_ROTATION_PORTRAIT, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_1000
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 9 (AUTO_ROTATION_RESTRICTED)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1000, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_9, AUTO_ROTATION_RESTRICTED, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_1100
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 10 (AUTO_ROTATION_LANDSCAPE_RESTRICTED)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1100, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_10, AUTO_ROTATION_LANDSCAPE_RESTRICTED, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_1200
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 11 (AUTO_ROTATION_PORTRAIT_RESTRICTED)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1200, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_11, AUTO_ROTATION_PORTRAIT_RESTRICTED, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_1300
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 12 (LOCKED)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1300, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_12, LOCKED, ORIENTATION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_1400
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.orientation equals to 12 (LOCKED)
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1400, Function | SmallTest | Level1)
{
    std::vector<int32_t> vec {0, 1, 2};
    CheckWindowProperty2(ABILITY_NAME_TEST, vec);
}

/**
 * @tc.number: GetWindowProperties_1500
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.supportWindowMode equals to default value
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1500, Function | SmallTest | Level1)
{
    std::vector<int32_t> vec {0, 1, 2};
    CheckWindowProperty2(ABILITY_NAME_TEST, vec);
}

/**
 * @tc.number: GetWindowProperties_1600
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.supportWindowMode equals to {0}
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1600, Function | SmallTest | Level1)
{
    std::vector<int32_t> vec {0};
    CheckWindowProperty2(ABILITY_NAME_TEST_1, vec);
}

/**
 * @tc.number: GetWindowProperties_1700
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.supportWindowMode equals to {1}
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1700, Function | SmallTest | Level1)
{
    std::vector<int32_t> vec {1};
    CheckWindowProperty2(ABILITY_NAME_TEST_2, vec);
}

/**
 * @tc.number: GetWindowProperties_1800
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.supportWindowMode equals to {2}
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1800, Function | SmallTest | Level2)
{
    std::vector<int32_t> vec {2};
    CheckWindowProperty2(ABILITY_NAME_TEST_3, vec);
}

/**
 * @tc.number: GetWindowProperties_1900
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.supportWindowMode equals to {0, 1, 2}
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_1900, Function | SmallTest | Level1)
{
    std::vector<int32_t> vec {0, 1, 2};
    CheckWindowProperty2(ABILITY_NAME_TEST_4, vec);
}

/**
 * @tc.number: GetWindowProperties_2000
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.maxWindowRatio equals to default value
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2000, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST, UNSPECIFIED, MAX_WINDOW_RATIO);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_2100
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.maxWindowRatio equals to 3.5
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2100, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_5, MAX_WINDOW_RATIO_VALUE, MAX_WINDOW_RATIO);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_2200
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.minWindowRatio equals to default value
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2200, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST, UNSPECIFIED, MIN_WINDOW_RATIO);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_2300
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.minWindowRatio equals to 0.5
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2300, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_6, MIN_WINDOW_RATIO_VALUE, MIN_WINDOW_RATIO);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_2400
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.maxWindowWidth equals to default value
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2400, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST, UNSPECIFIED, MAX_WINDOW_WIDTH);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_2500
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.maxWindowWidth equals to 2560
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2500, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_7, MAX_WINDOW_WIDTH_VALUE, MAX_WINDOW_WIDTH);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_2600
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.minWindowWidth equals to default value
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2600, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST, UNSPECIFIED, MIN_WINDOW_WIDTH);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_2700
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.minWindowWidth equals to 1400
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2700, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_8, MIN_WINDOW_WIDTH_VALUE, MIN_WINDOW_WIDTH);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_2800
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.maxWindowHeight equals to default value
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2800, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST, UNSPECIFIED, MAX_WINDOW_HEIGHT);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_2900
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.maxWindowHeight equals to 300
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_2900, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_9, MAX_WINDOW_HEIGHT_VALUE, MAX_WINDOW_HEIGHT);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_3000
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.minWindowHeight equals to default value
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_3000, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST, UNSPECIFIED, MIN_WINDOW_HEIGHT);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetWindowProperties_3100
 * @tc.name: test can get the window property of orientation
 * @tc.desc: 1.install bundle successfully
 *           2.get ability info successfully
 *           3.maxWindowHeight equals to 200
 */
HWTEST_F(BmsBundleGetWindowPropertiesTest, GetWindowProperties_3100, Function | SmallTest | Level1)
{
    auto res = CheckWindowProperty1(ABILITY_NAME_TEST_10, MIN_WINDOW_HEIGHT_VALUE, MIN_WINDOW_HEIGHT);
    EXPECT_TRUE(res);
}
} // OHOS