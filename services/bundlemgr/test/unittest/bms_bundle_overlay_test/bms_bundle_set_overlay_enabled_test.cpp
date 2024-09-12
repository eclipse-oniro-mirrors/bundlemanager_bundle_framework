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

#include <gtest/gtest.h>

#include "appexecfwk_errors.h"
#include "bundle_overlay_data_manager.h"
#include "bundle_overlay_install_checker.h"
#include "bundle_overlay_manager.h"
#include "bundle_mgr_service.h"

#include <map>

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string TEST_MODULE_NAME = "testModuleName";
const std::string TEST_MODULE_NAME_SECOND = "testModuleNameSecond";
const std::string TEST_MODULE_NAME_THIRD = "testModuleNameThird";
const std::string TARGET_MODULE_NAME = "targetModuleName";
const std::string TEST_BUNDLE_NAME = "testBundleName";
const int32_t DEFAULT_TARGET_PRIORITY_SECOND = 1;
const int32_t USERID = 100;
const int32_t TEST_USERID = 101;
const int32_t WAIT_TIME = 5; // init mocked bms
} // namespace

class BmsBundleSetOverlayEnabledTest : public testing::Test {
public:
    BmsBundleSetOverlayEnabledTest();
    ~BmsBundleSetOverlayEnabledTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void AddOverlayInnerBundleInfo();
    void AddNonOverlayInnerBundleInfo();
    void RemoveBundleInfo();
    void CheckEnabledState(int32_t state);

    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    static std::shared_ptr<OverlayManagerHostImpl> overlayHostImpl_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleSetOverlayEnabledTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleSetOverlayEnabledTest::BmsBundleSetOverlayEnabledTest()
{}

BmsBundleSetOverlayEnabledTest::~BmsBundleSetOverlayEnabledTest()
{}

void BmsBundleSetOverlayEnabledTest::SetUpTestCase()
{}

void BmsBundleSetOverlayEnabledTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleSetOverlayEnabledTest::SetUp()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleSetOverlayEnabledTest::TearDown()
{}

void BmsBundleSetOverlayEnabledTest::AddOverlayInnerBundleInfo()
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    InnerModuleInfo secondInnerModuleInfo;
    secondInnerModuleInfo.name = TEST_MODULE_NAME_SECOND;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME_SECOND, secondInnerModuleInfo);

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    std::string state = TEST_MODULE_NAME + Constants::FILE_UNDERLINE + std::to_string(OVERLAY_ENABLE);
    userInfo.bundleUserInfo.overlayModulesState.emplace_back(state);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, innerBundleInfo);
}

void BmsBundleSetOverlayEnabledTest::AddNonOverlayInnerBundleInfo()
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_BUNDLE_NAME, innerBundleInfo);
}

void BmsBundleSetOverlayEnabledTest::RemoveBundleInfo()
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(TEST_BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

void BmsBundleSetOverlayEnabledTest::CheckEnabledState(int32_t state)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    InnerBundleInfo innerBundleInfo;
    auto ret = dataMgr->GetInnerBundleInfoWithDisable(TEST_BUNDLE_NAME, innerBundleInfo);
    EXPECT_TRUE(ret);

    InnerBundleUserInfo userInfo;
    ret = innerBundleInfo.GetInnerBundleUserInfo(USERID, userInfo);
    EXPECT_TRUE(ret);
    std::string overlayState = TEST_MODULE_NAME + Constants::FILE_UNDERLINE + std::to_string(state);
    const auto &stateVec = userInfo.bundleUserInfo.overlayModulesState;
    ret = find(stateVec.begin(), stateVec.end(), overlayState) != stateVec.end();
    EXPECT_TRUE(ret);
}

const std::shared_ptr<BundleDataMgr> BmsBundleSetOverlayEnabledTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: SetOverlayEnabledTest_0100
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.param check and bundleName is empty.
 *           2.set failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_0100, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    auto res = hostImpl->SetOverlayEnabled("", TEST_MODULE_NAME, true);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);
}

/**
 * @tc.number: SetOverlayEnabledTest_0200
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.param check and bundleName is empty.
 *           2.set failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_0200, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    auto res = hostImpl->SetOverlayEnabled("", TEST_MODULE_NAME, false);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);
}

/**
 * @tc.number: SetOverlayEnabledTest_0300
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.param check and moduleName is empty.
 *           2.set failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_0300, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, "", true);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);
}

/**
 * @tc.number: SetOverlayEnabledTest_0400
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.param check and moduleName is empty.
 *           2.set failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_0400, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, "", false);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);
}

/**
 * @tc.number: SetOverlayEnabledTest_500
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.verify userId.
 *           2.invalid userId and set failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_500, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, true, Constants::INVALID_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);
}

/**
 * @tc.number: SetOverlayEnabledTest_0600
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.verify bundleName.
 *           2.bundleName is not existed and set failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_0600, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, true);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
}

/**
 * @tc.number: SetOverlayEnabledTest_0700
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.verify innerBundleUserInfo.
 *           2.bundle is not installed at specified userId.
 *           3.set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_0700, Function | SmallTest | Level0)
{
    // add innerBundleInfo
    AddOverlayInnerBundleInfo();

    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, true, TEST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);
    RemoveBundleInfo();
}

/**
 * @tc.number: SetOverlayEnabledTest_0800
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.verify innerBundleUserInfo.
 *           2.the specified bundle is not overlay bundle.
 *           3.set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_0800, Function | SmallTest | Level0)
{
    // add innerBundleInfo
    AddNonOverlayInnerBundleInfo();

    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, true, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);
    RemoveBundleInfo();
}

/**
 * @tc.number: SetOverlayEnabledTest_0900
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.verify innerBundleUserInfo.
 *           2.the specified module is not existed.
 *           3.set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_0900, Function | SmallTest | Level0)
{
    // add innerBundleInfo
    AddOverlayInnerBundleInfo();

    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME_THIRD, true, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_MODULE);
    RemoveBundleInfo();
}

/**
 * @tc.number: SetOverlayEnabledTest_1000
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.verify innerBundleUserInfo.
 *           2.the specified module is not overlay module.
 *           3.set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_1000, Function | SmallTest | Level0)
{
    // add innerBundleInfo
    AddOverlayInnerBundleInfo();

    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME_SECOND, true, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_MODULE);
    RemoveBundleInfo();
}

/**
 * @tc.number: SetOverlayEnabledTest_1100
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.verify innerBundleUserInfo.
 *           2.the specified module is overlay module.
 *           3.set successfully
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_1100, Function | SmallTest | Level0)
{
    // add innerBundleInfo
    AddOverlayInnerBundleInfo();

    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, true, USERID);
    EXPECT_EQ(res, ERR_OK);

    CheckEnabledState(OVERLAY_ENABLE);
    RemoveBundleInfo();
}

/**
 * @tc.number: SetOverlayEnabledTest_1200
 * @tc.name: test CheckInternalBundle interface in OverlayManagerHostImpl.
 * @tc.desc: 1.verify innerBundleUserInfo.
 *           2.the specified module is overlay module.
 *           3.set successfully
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleSetOverlayEnabledTest, SetOverlayEnabledTest_1200, Function | SmallTest | Level0)
{
    // add innerBundleInfo
    AddOverlayInnerBundleInfo();

    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, false, USERID);
    EXPECT_EQ(res, ERR_OK);

    CheckEnabledState(OVERLAY_DISABLED);
    RemoveBundleInfo();
}
} // OHOS