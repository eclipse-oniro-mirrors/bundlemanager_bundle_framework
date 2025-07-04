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

#include <gtest/gtest.h>

#include "appexecfwk_errors.h"
#include "bundle_overlay_data_manager.h"
#include "bundle_overlay_install_checker.h"
#include "bundle_overlay_manager.h"
#include "bundle_mgr_service.h"

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
const std::string TEST_HAP_PATH = "testHapPath";
const std::string TEST_TARGET_BUNDLE_NAME = "testTargetBundleName";
const std::string TEST_OVERLAY_BUNDLE_DIR = "testBundleDir";
const int32_t DEFAULT_TARGET_PRIORITY_SECOND = 1;
const int32_t USERID = 100;
const int32_t UNSPECIFIED_USERID = -2;
const int32_t TEST_USERID = 101;
const int32_t OVERLAY_MODULE_INFO_SIZE = 1;
const int32_t DEFAULT_OVERLAY_MODULE_INFO_SIZE = 0;
const int32_t WAIT_TIME = 5; // init mocked bms
} // namespace

class BmsBundleGetOverlayModuleInfoTest : public testing::Test {
public:
    BmsBundleGetOverlayModuleInfoTest();
    ~BmsBundleGetOverlayModuleInfoTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void AddOverlayInnerBundleInfo(int32_t overlayType);
    void AddNonOverlayInnerBundleInfo();
    void AddOverlayBundleInfo();
    void RemoveBundleInfo(const std::string &bundleName);
    void CheckEnabledState(int32_t state);
    void CheckOverlayModuleInfo(const OverlayModuleInfo &info);
    void CheckOverlayBundleInfo(const OverlayBundleInfo &info);

    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleGetOverlayModuleInfoTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleGetOverlayModuleInfoTest::BmsBundleGetOverlayModuleInfoTest()
{}

BmsBundleGetOverlayModuleInfoTest::~BmsBundleGetOverlayModuleInfoTest()
{}

void BmsBundleGetOverlayModuleInfoTest::SetUpTestCase()
{}

void BmsBundleGetOverlayModuleInfoTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}
void BmsBundleGetOverlayModuleInfoTest::SetUp()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleGetOverlayModuleInfoTest::TearDown()
{}

void BmsBundleGetOverlayModuleInfoTest::AddOverlayInnerBundleInfo(int32_t overlayType)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = TEST_MODULE_NAME;
    innerModuleInfo.moduleName = TEST_MODULE_NAME;
    innerModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    innerModuleInfo.targetPriority = DEFAULT_TARGET_PRIORITY_SECOND;
    innerModuleInfo.hapPath = TEST_HAP_PATH;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, innerModuleInfo);
    innerBundleInfo.SetCurrentModulePackage(TEST_MODULE_NAME);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetOverlayType(overlayType);

    InnerModuleInfo secondInnerModuleInfo;
    secondInnerModuleInfo.name = TEST_MODULE_NAME_SECOND;
    secondInnerModuleInfo.moduleName = TEST_MODULE_NAME_SECOND;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME_SECOND, secondInnerModuleInfo);

    InnerModuleInfo targetModuleInfo;
    targetModuleInfo.name = TARGET_MODULE_NAME;
    targetModuleInfo.moduleName = TARGET_MODULE_NAME;
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.bundleName = TEST_BUNDLE_NAME;
    overlayModuleInfo.moduleName = TEST_MODULE_NAME;
    overlayModuleInfo.targetModuleName = TARGET_MODULE_NAME;
    overlayModuleInfo.hapPath = TEST_HAP_PATH;
    overlayModuleInfo.priority = DEFAULT_TARGET_PRIORITY_SECOND;
    targetModuleInfo.overlayModuleInfo.emplace_back(overlayModuleInfo);
    innerBundleInfo.InsertInnerModuleInfo(TARGET_MODULE_NAME, targetModuleInfo);

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

void BmsBundleGetOverlayModuleInfoTest::AddNonOverlayInnerBundleInfo()
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

void BmsBundleGetOverlayModuleInfoTest::RemoveBundleInfo(const std::string &bundleName)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

void BmsBundleGetOverlayModuleInfoTest::CheckOverlayModuleInfo(const OverlayModuleInfo &info)
{
    EXPECT_EQ(info.bundleName, TEST_BUNDLE_NAME);
    EXPECT_EQ(info.moduleName, TEST_MODULE_NAME);
    EXPECT_EQ(info.hapPath, TEST_HAP_PATH);
    EXPECT_EQ(info.targetModuleName, TARGET_MODULE_NAME);
    EXPECT_EQ(info.state, OVERLAY_ENABLE);
    EXPECT_EQ(info.priority, DEFAULT_TARGET_PRIORITY_SECOND);
}

void BmsBundleGetOverlayModuleInfoTest::CheckOverlayBundleInfo(const OverlayBundleInfo &info)
{
    EXPECT_EQ(info.bundleName, TEST_BUNDLE_NAME);
    EXPECT_EQ(info.bundleDir, TEST_OVERLAY_BUNDLE_DIR);
    EXPECT_EQ(info.state, OVERLAY_ENABLE);
    EXPECT_EQ(info.priority, DEFAULT_TARGET_PRIORITY_SECOND);
}

void BmsBundleGetOverlayModuleInfoTest::AddOverlayBundleInfo()
{
    InnerBundleInfo innerBundleInfo;
    OverlayBundleInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.bundleDir = TEST_OVERLAY_BUNDLE_DIR;
    info.state = OVERLAY_ENABLE;
    info.priority = DEFAULT_TARGET_PRIORITY_SECOND;
    innerBundleInfo.AddOverlayBundleInfo(info);

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->UpdateBundleInstallState(TEST_TARGET_BUNDLE_NAME, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(TEST_TARGET_BUNDLE_NAME, innerBundleInfo);
}

const std::shared_ptr<BundleDataMgr> BmsBundleGetOverlayModuleInfoTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: GetOverlayModuleInfoTest_0100
 * @tc.name: test GetAllOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundleName is not existed.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_0100, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    std::vector<OverlayModuleInfo> vec;
    auto res = hostImpl->GetAllOverlayModuleInfo(TEST_BUNDLE_NAME, vec);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_0200
 * @tc.name: test GetAllOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundle is not installed at specified user.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_0200, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    std::vector<OverlayModuleInfo> vec;
    auto res = hostImpl->GetAllOverlayModuleInfo(TEST_BUNDLE_NAME, vec, TEST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_0300
 * @tc.name: test GetAllOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundle does not contain any overlay module.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_0300, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddNonOverlayInnerBundleInfo();

    std::vector<OverlayModuleInfo> vec;
    auto res = hostImpl->GetAllOverlayModuleInfo(TEST_BUNDLE_NAME, vec, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_0400
 * @tc.name: test GetAllOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundle is valid bundle
 *           2.get successfully.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_0400, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    std::vector<OverlayModuleInfo> vec;
    auto res = hostImpl->GetAllOverlayModuleInfo(TEST_BUNDLE_NAME, vec, USERID);
    EXPECT_EQ(res, ERR_OK);

    EXPECT_EQ(vec.size(), OVERLAY_MODULE_INFO_SIZE);
    CheckOverlayModuleInfo(vec[0]);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_0500
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundleName is not existed.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_0500, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    OverlayModuleInfo overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_0600
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundle is not installed at specified user.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_0600, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    OverlayModuleInfo overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo, TEST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_0700
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundle is not overlay bundle
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_0700, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddNonOverlayInnerBundleInfo();

    OverlayModuleInfo overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_0800
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified module is not existed.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_0800, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    OverlayModuleInfo overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME_THIRD, overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_MODULE);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_0900
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundle is not overlay bundle
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_0900, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    OverlayModuleInfo overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME_SECOND, overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_MODULE);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1000
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundle is not overlay bundle
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1000, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    OverlayModuleInfo overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME_SECOND, overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_MODULE);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1100
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified bundle and module are valid
 *           2.get successfully.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1100, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    OverlayModuleInfo overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_OK);

    CheckOverlayModuleInfo(overlayModuleInfo);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1200
 * @tc.name: test GetOverlayBundleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target bundle name is not existed.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1200, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    std::vector<OverlayBundleInfo> overlayBundleInfo;
    auto res = hostImpl->GetOverlayBundleInfoForTarget(TEST_BUNDLE_NAME, overlayBundleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_NOT_EXISTED);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1300
 * @tc.name: test GetOverlayBundleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target bundle does not installed at specified user.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1300, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayBundleInfo();

    std::vector<OverlayBundleInfo> overlayBundleInfo;
    auto res = hostImpl->GetOverlayBundleInfoForTarget(TEST_TARGET_BUNDLE_NAME, overlayBundleInfo, TEST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);
    RemoveBundleInfo(TEST_TARGET_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1400
 * @tc.name: test GetOverlayBundleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target bundle is valid.
 *           2.get successfully.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1400, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayBundleInfo();

    std::vector<OverlayBundleInfo> overlayBundleInfo;
    auto res = hostImpl->GetOverlayBundleInfoForTarget(TEST_TARGET_BUNDLE_NAME, overlayBundleInfo, USERID);
    EXPECT_EQ(res, ERR_OK);

    EXPECT_EQ(overlayBundleInfo.size(), OVERLAY_MODULE_INFO_SIZE);
    CheckOverlayBundleInfo(overlayBundleInfo[0]);
    RemoveBundleInfo(TEST_TARGET_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1500
 * @tc.name: test GetOverlayBundleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target bundle is valid.
 *           2.get successfully.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1500, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddNonOverlayInnerBundleInfo();

    std::vector<OverlayBundleInfo> overlayBundleInfo;
    auto res = hostImpl->GetOverlayBundleInfoForTarget(TEST_BUNDLE_NAME, overlayBundleInfo, USERID);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(overlayBundleInfo.size(), DEFAULT_OVERLAY_MODULE_INFO_SIZE);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1600
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target bundle is not existed.
 *           2.get successfully.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1600, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    std::vector<OverlayModuleInfo> overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfoForTarget(TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_NOT_EXISTED);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1700
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target bundle is external overlay bundle.
 *           2.get successfully.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1700, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_EXTERNAL_BUNDLE);

    std::vector<OverlayModuleInfo> overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfoForTarget(TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_IS_OVERLAY_BUNDLE);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1800
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target bundle is not installed at specified user.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1800, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    std::vector<OverlayModuleInfo> overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfoForTarget(TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo,
        TEST_USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_1900
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target module is not existed.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_1900, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    std::vector<OverlayModuleInfo> overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfoForTarget(TEST_BUNDLE_NAME, TEST_MODULE_NAME_THIRD, overlayModuleInfo,
        USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_MODULE_NOT_EXISTED);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_2000
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target module is overlay module.
 *           2.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_2000, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    std::vector<OverlayModuleInfo> overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfoForTarget(TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_MODULE_IS_OVERLAY_MODULE);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_2100
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target bundle is valid.
 *           2.get successfully.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_2100, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    std::vector<OverlayModuleInfo> overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfoForTarget(TEST_BUNDLE_NAME, TEST_MODULE_NAME_SECOND, overlayModuleInfo,
        USERID);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(overlayModuleInfo.size(), DEFAULT_OVERLAY_MODULE_INFO_SIZE);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_2200
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.the specified target bundle is valid.
 *           2.get successfully.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_2200, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    AddOverlayInnerBundleInfo(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    std::vector<OverlayModuleInfo> overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfoForTarget(TEST_BUNDLE_NAME, TARGET_MODULE_NAME, overlayModuleInfo,
        USERID);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(overlayModuleInfo.size(), OVERLAY_MODULE_INFO_SIZE);

    CheckOverlayModuleInfo(overlayModuleInfo[0]);
    RemoveBundleInfo(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_2300
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl
 * @tc.desc: 1.the specified bundle is valid bundle
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_2300, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    OverlayModuleInfo overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfo("", overlayModuleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_2400
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl
 * @tc.desc: 1.the specified bundle is valid bundle
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_2400, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    OverlayModuleInfo overlayModuleInfo;
    auto res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, overlayModuleInfo, UNSPECIFIED_USERID);
    EXPECT_NE(res, ERR_OK);

    res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, overlayModuleInfo, USERID);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_2500
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl
 * @tc.desc: 1.the specified bundle is valid bundle
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_2500, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto res = hostImpl->GetTargetOverlayModuleInfo(TARGET_MODULE_NAME, overlayModuleInfos, UNSPECIFIED_USERID);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: GetOverlayModuleInfoTest_2600
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl
 * @tc.desc: 1.the specified bundle is valid bundle
 */
HWTEST_F(BmsBundleGetOverlayModuleInfoTest, GetOverlayModuleInfoTest_2600, Function | SmallTest | Level0)
{
    // get OverlayManagerHostImpl instance
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    auto res = hostImpl->SetOverlayEnabledForSelf(TARGET_MODULE_NAME, false, UNSPECIFIED_USERID);
    EXPECT_NE(res, ERR_OK);
}
} // OHOS
