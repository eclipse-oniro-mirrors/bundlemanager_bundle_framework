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

#include <fstream>
#include <gtest/gtest.h>

#include "ability_manager_helper.h"
#include "aot/aot_executor.h"
#include "aot/aot_handler.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "base_bundle_installer.h"
#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "json_constants.h"
#include "json_serializer.h"
#include "parameters.h"
#include "parcel.h"
#include "scope_guard.h"
#include "installd/installd_service.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;

namespace OHOS {
namespace {
const std::string HAP_PATH = "/system/etc/graphic/bootpic.zip";
const std::string NOHAP_PATH = "/data/test/resource/bms/aot_bundle/....right.hap";
const std::string OUT_PUT_PATH = "/data/test/resource/bms/aot_bundle/";
const std::string ABC_RELATIVE_PATH = "ets/modules.abc";
const std::string AOT_BUNDLE_NAME = "aotBundleName";
const std::string AOT_MODULE_NAME = "aotModuleName";
const std::string STRING_TYPE_ONE = "string1";
const std::string STRING_TYPE_TWO = "string2";
const std::string STRING_EMPTY = "";
const int32_t USERID_ONE = 100;
const int32_t USERID_TWO = -1;
constexpr uint32_t VERSION_CODE = 3;
constexpr uint32_t OFFSET = 1001;
constexpr uint32_t LENGTH = 2002;
constexpr uint32_t SLEEP_INTERVAL_MILLI_SECONDS = 100;
constexpr uint32_t VIRTUAL_CHILD_PID = 12345678;

constexpr const char* OTA_COMPILE_TIME = "persist.bms.optimizing_apps.timing";
constexpr const char* OTA_COMPILE_SWITCH = "const.bms.optimizing_apps.switch";
constexpr const char* OTA_COMPILE_MODE = "persist.bm.ota.arkopt";
constexpr const char* UPDATE_TYPE = "persist.dupdate_engine.update_type";
constexpr const char* COMPILE_NONE = "none";
constexpr const char* COMPILE_FULL = "full";
}  // namespace

class BmsAOTMgrTest : public testing::Test {
public:
    BmsAOTMgrTest();
    ~BmsAOTMgrTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void ClearDataMgr();
    void ResetDataMgr();

private:
    HspInfo CreateHspInfo() const;
    void CheckHspInfo(HspInfo &sourceHspInfo, HspInfo &targetHspInfo) const;
    std::shared_ptr<BundleDataMgr> dataMgr_ = std::make_shared<BundleDataMgr>();
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<InstalldService> installdService_;
};

std::shared_ptr<BundleMgrService> BmsAOTMgrTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsAOTMgrTest::installdService_ =
    std::make_shared<InstalldService>();

BmsAOTMgrTest::BmsAOTMgrTest()
{}

BmsAOTMgrTest::~BmsAOTMgrTest()
{}

void BmsAOTMgrTest::SetUpTestCase()
{}

void BmsAOTMgrTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsAOTMgrTest::SetUp()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
}

void BmsAOTMgrTest::TearDown()
{}

const std::shared_ptr<BundleDataMgr> BmsAOTMgrTest::GetBundleDataMgr() const
{
    return dataMgr_;
}

HspInfo BmsAOTMgrTest::CreateHspInfo() const
{
    HspInfo hspInfo;
    hspInfo.bundleName = "bundleName";
    hspInfo.moduleName = "moduleName";
    hspInfo.versionCode = VERSION_CODE;
    hspInfo.hapPath = "hapPath";
    hspInfo.offset = OFFSET;
    hspInfo.length = LENGTH;
    return hspInfo;
}

void BmsAOTMgrTest::CheckHspInfo(HspInfo &sourceHspInfo, HspInfo &targetHspInfo) const
{
    EXPECT_EQ(sourceHspInfo.bundleName, targetHspInfo.bundleName);
    EXPECT_EQ(sourceHspInfo.moduleName, targetHspInfo.moduleName);
    EXPECT_EQ(sourceHspInfo.versionCode, targetHspInfo.versionCode);
    EXPECT_EQ(sourceHspInfo.hapPath, targetHspInfo.hapPath);
    EXPECT_EQ(sourceHspInfo.offset, targetHspInfo.offset);
    EXPECT_EQ(sourceHspInfo.length, targetHspInfo.length);
}

void BmsAOTMgrTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsAOTMgrTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    ASSERT_NE(bundleMgrService_->dataMgr_, nullptr);
}

/**
 * @tc.number: AOTExecutor_0100
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0100, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    ErrCode ret;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0200
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0200, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    ErrCode ret;
    aotArgs.compileMode = ServiceConstants::COMPILE_PARTIAL;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0300
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0300, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    ErrCode ret;
    aotArgs.hapPath = HAP_PATH;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0400
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0400, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    ErrCode ret;
    aotArgs.outputPath = OUT_PUT_PATH;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0500
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0500, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    ErrCode ret;
    aotArgs.compileMode = ServiceConstants::COMPILE_PARTIAL;
    aotArgs.hapPath = ABC_RELATIVE_PATH;
    aotArgs.outputPath = OUT_PUT_PATH;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0600
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0600, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    ErrCode ret;
    aotArgs.compileMode = COMPILE_FULL;
    aotArgs.hapPath = NOHAP_PATH;
    aotArgs.outputPath = OUT_PUT_PATH;
    aotArgs.arkProfilePath = OUT_PUT_PATH;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0700
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0700, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    ErrCode ret;
    aotArgs.compileMode = COMPILE_FULL;
    aotArgs.hapPath = HAP_PATH;
    aotArgs.outputPath = OUT_PUT_PATH;
    aotArgs.arkProfilePath = OUT_PUT_PATH;

    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0800
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0800, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    ErrCode ret;
    aotArgs.compileMode = COMPILE_FULL;
    aotArgs.hapPath = HAP_PATH;
    aotArgs.outputPath = OUT_PUT_PATH;
    aotArgs.arkProfilePath = OUT_PUT_PATH;

    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0900
 * @tc.name: test StopAOT
 * @tc.desc: 1. ResetState
 *           2. call StopAOT
 *           3. return ERR_OK
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0900, Function | SmallTest | Level0)
{
    AOTExecutor::GetInstance().ResetState();
    ErrCode ret = AOTExecutor::GetInstance().StopAOT();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_1000
 * @tc.name: test StopAOT
 * @tc.desc: 1. InitState
 *           2. call StopAOT
 *           3. return ERR_OK
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1000, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    AOTExecutor::GetInstance().InitState(aotArgs);
    ErrCode ret = AOTExecutor::GetInstance().StopAOT();
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_STOP_AOT_FAILED);
    AOTExecutor::GetInstance().ResetState();
}

/**
 * @tc.number: AOTExecutor_1100
 * @tc.name: test InitState and ResetState
 * @tc.desc: 1. call InitState, expect get set value
 *           1. call ResetState, expect get default value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1100, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    aotArgs.outputPath = OUT_PUT_PATH;

    AOTExecutor::GetInstance().InitState(aotArgs);
    EXPECT_EQ(AOTExecutor::GetInstance().state_.running, true);
    EXPECT_EQ(AOTExecutor::GetInstance().state_.outputPath, OUT_PUT_PATH);

    AOTExecutor::GetInstance().ResetState();
    EXPECT_EQ(AOTExecutor::GetInstance().state_.running, false);
    EXPECT_EQ(AOTExecutor::GetInstance().state_.outputPath, "");
}

/**
 * @tc.number: AOTHandler_0100
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    bool isOTA = true;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo newInfo;
    infos.emplace("", newInfo);
    installer.ProcessAOT(isOTA, infos);
    bool res = newInfo.GetIsNewVersion();
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: AOTHandler_0100
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    bool isOTA = false;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo newInfo;
    installer.ProcessAOT(isOTA, infos);

    newInfo.SetIsNewVersion(isOTA);
    infos.emplace("", newInfo);
    installer.ProcessAOT(isOTA, infos);
    bool res = newInfo.GetIsNewVersion();
    EXPECT_EQ(res, isOTA);
    AOTHandler::GetInstance().HandleIdle();
}

/**
 * @tc.number: AOTHandler_0100
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0300, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    bool isOTA = false;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo newInfo;
    installer.ProcessAOT(isOTA, infos);

    newInfo.SetIsNewVersion(true);
    infos.emplace("", newInfo);
    installer.ProcessAOT(isOTA, infos);
    bool res = newInfo.GetIsNewVersion();
    EXPECT_EQ(res, true);
    AOTHandler::GetInstance().HandleOTA();
}

/**
 * @tc.number: AOTHandler_0100
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0400, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    AOTHandler::GetInstance().HandleInstallWithSingleHap(info, "");
    std::string res = info.GetBundleName();
    EXPECT_EQ(res, Constants::EMPTY_STRING);
}

/**
 * @tc.number: AOTHandler_0100
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0500, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    AOTHandler::GetInstance().HandleInstallWithSingleHap(info, ServiceConstants::COMPILE_PARTIAL);
    std::string res = info.GetBundleName();
    EXPECT_EQ(res, Constants::EMPTY_STRING);
}

/**
 * @tc.number: AOTHandler_0100
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0600, Function | SmallTest | Level0)
{
    std::optional<AOTArgs> aotArgs;
    uint32_t versionCode = 1;
    AOTArgs aotArg;
    aotArg.bundleName = AOT_BUNDLE_NAME;
    aotArg.moduleName = AOT_MODULE_NAME;
    aotArgs = aotArg;
    AOTHandler::GetInstance().AOTInternal(aotArgs, versionCode);
    auto item = GetBundleDataMgr()->bundleInfos_.find(AOT_BUNDLE_NAME);
    EXPECT_EQ(item, GetBundleDataMgr()->bundleInfos_.end());
}

/**
 * @tc.number: AOTHandler_0100
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0700, Function | SmallTest | Level0)
{
    std::optional<AOTArgs> aotArgs;
    uint32_t versionCode = 1;
    AOTArgs aotArg;
    aotArg.bundleName = AOT_BUNDLE_NAME;
    aotArg.moduleName = AOT_MODULE_NAME;
    aotArgs = aotArg;

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    BundleInfo bundleInfo;
    bundleInfo.versionCode = versionCode;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        AOT_BUNDLE_NAME, innerBundleInfo);
    AOTHandler::GetInstance().AOTInternal(aotArgs, versionCode);
    auto item = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.find(AOT_BUNDLE_NAME);
    EXPECT_NE(item, DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.end());

    versionCode = 2;
    AOTHandler::GetInstance().AOTInternal(aotArgs, versionCode);
    EXPECT_NE(item->second.GetVersionCode(), versionCode);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: AOTHandler_0100
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0800, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    info.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    AOTHandler::GetInstance().HandleIdleWithSingleHap(info, AOT_MODULE_NAME, "");

    info.SetAOTCompileStatus(AOT_MODULE_NAME, AOTCompileStatus::COMPILE_SUCCESS);
    AOTHandler::GetInstance().HandleIdleWithSingleHap(info, AOT_MODULE_NAME, "");
    AOTCompileStatus ret = info.GetAOTCompileStatus(AOT_MODULE_NAME);
    EXPECT_EQ(ret, AOTCompileStatus::COMPILE_SUCCESS);
}

/**
 * @tc.number: AOTHandler_0900
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0900, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.bundleUserInfo.userId = USERID_ONE;
    innerBundleUserInfos[STRING_TYPE_ONE] = info;
    info.bundleUserInfo.userId = USERID_TWO;
    innerBundleUserInfos[STRING_TYPE_TWO] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);
    ClearDataMgr();
    auto ret = AOTHandler::GetInstance().GetArkProfilePath(AOT_BUNDLE_NAME, AOT_MODULE_NAME);
    EXPECT_EQ(ret, "");
    ResetDataMgr();
    ret = AOTHandler::GetInstance().GetArkProfilePath(AOT_BUNDLE_NAME, AOT_MODULE_NAME);
    EXPECT_EQ(ret, "");
    auto iterator = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    if (iterator != dataMgr->bundleInfos_.end()) {
        dataMgr->bundleInfos_.erase(iterator);
    }
}

/**
 * @tc.number: AOTHandler_1000
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1000, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    BundleInfo bundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ClearDataMgr();
    auto ret = AOTHandler::GetInstance().BuildAOTArgs(innerBundleInfo,
        AOT_MODULE_NAME, ServiceConstants::COMPILE_PARTIAL);
    EXPECT_EQ(ret, std::nullopt);
    AOTHandler::GetInstance().ClearArkCacheDir();
    ResetDataMgr();
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);
    ret = AOTHandler::GetInstance().BuildAOTArgs(innerBundleInfo,
        AOT_MODULE_NAME, ServiceConstants::COMPILE_PARTIAL);
    EXPECT_EQ(ret, std::nullopt);
    ret = AOTHandler::GetInstance().BuildAOTArgs(innerBundleInfo,
        AOT_MODULE_NAME, ServiceConstants::COMPILE_PARTIAL);
    EXPECT_EQ(ret, std::nullopt);
    auto iterator = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    if (iterator != dataMgr->bundleInfos_.end()) {
        dataMgr->bundleInfos_.erase(iterator);
    }
}

/**
 * @tc.number: AOTHandler_1100
 * @tc.name: test AOTHandler
 * @tc.desc: bundle not exist, return std::nullopt
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    auto ret = AOTHandler::GetInstance().BuildAOTArgs(innerBundleInfo, AOT_MODULE_NAME, "");
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: AOTHandler_1200
 * @tc.name: test AOTHandler
 * @tc.desc: bundle not exist, return std::nullopt
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1200, Function | SmallTest | Level0)
{
    std::string bundleName = "";
    std::vector<std::string> results;
    ClearDataMgr();
    AOTHandler::GetInstance().HandleCompile(bundleName, COMPILE_NONE, true, results);
    EXPECT_EQ(bundleName, "");
    ResetDataMgr();

    AOTHandler::GetInstance().HandleCompile(bundleName, ServiceConstants::COMPILE_PARTIAL, true, results);
    EXPECT_EQ(bundleName, "");

    AOTHandler::GetInstance().HandleCompile(bundleName, ServiceConstants::COMPILE_PARTIAL, false, results);
    EXPECT_EQ(bundleName, "");
}

/**
 * @tc.number: AOTHandler_1300
 * @tc.name: test AOTHandler
 * @tc.desc: bundle not exist, return std::nullopt
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1300, Function | SmallTest | Level0)
{
    std::string bundleName = "";
    ClearDataMgr();
    AOTHandler::GetInstance().HandleResetAOT(bundleName, true);
    EXPECT_EQ(bundleName, "");
    ResetDataMgr();

    AOTHandler::GetInstance().HandleResetAOT(bundleName, true);
    EXPECT_EQ(bundleName, "");

    AOTHandler::GetInstance().HandleResetAOT(bundleName, false);
    EXPECT_EQ(bundleName, "");
}

/**
 * @tc.number: AOTHandler_1400
 * @tc.name: test IsOTACompileSwitchOn
 * @tc.desc: expect return set val
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1400, Function | SmallTest | Level0)
{
    system::SetParameter(OTA_COMPILE_SWITCH, "on");
    bool ret = AOTHandler::GetInstance().IsOTACompileSwitchOn();
    EXPECT_EQ(ret, true);

    system::SetParameter(OTA_COMPILE_SWITCH, "off");
    ret = AOTHandler::GetInstance().IsOTACompileSwitchOn();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: AOTHandler_1500
 * @tc.name: test BeforeOTACompile
 * @tc.desc: 1.set time to 10, expect OTACompileDeadline_ = true
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1500, Function | SmallTest | Level0)
{
    std::string compileTimeSeconds = "10";
    system::SetParameter(OTA_COMPILE_TIME, compileTimeSeconds);
    AOTHandler::GetInstance().OTACompileDeadline_ = false;
    AOTHandler::GetInstance().BeforeOTACompile();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL_MILLI_SECONDS));
    EXPECT_EQ(AOTHandler::GetInstance().OTACompileDeadline_, true);
}

/**
 * @tc.number: AOTHandler_1600
 * @tc.name: test GetOTACompileList
 * @tc.desc: 1.expect return false;
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1600, Function | SmallTest | Level0)
{
    system::SetParameter(UPDATE_TYPE, "");
    std::vector<std::string> bundleNames;
    bool ret = AOTHandler::GetInstance().GetOTACompileList(bundleNames);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: AOTArgs_0100
 * @tc.name: test HspInfo Marshalling and Unmarshalling
 * @tc.desc: Marshalling and Unmarshalling success
 */
HWTEST_F(BmsAOTMgrTest, AOTArgs_0100, Function | SmallTest | Level1)
{
    APP_LOGI("AOTArgs_0100 begin");
    HspInfo hspInfo = CreateHspInfo();
    Parcel parcel;
    bool ret = hspInfo.Marshalling(parcel);
    EXPECT_EQ(ret, true);
    std::shared_ptr<HspInfo> hspInfoPtr(hspInfo.Unmarshalling(parcel));
    ASSERT_NE(hspInfoPtr, nullptr);
    CheckHspInfo(*hspInfoPtr, hspInfo);
    APP_LOGI("AOTArgs_0100 end");
}

/**
 * @tc.number: AOTArgs_0200
 * @tc.name: test AOTArgs Marshalling and Unmarshalling
 * @tc.desc: Marshalling and Unmarshalling success
 */
HWTEST_F(BmsAOTMgrTest, AOTArgs_0200, Function | SmallTest | Level1)
{
    APP_LOGI("AOTArgs_0200 begin");
    AOTArgs aotArgs;
    aotArgs.bundleName = "bundleName";
    aotArgs.moduleName = "moduleName";
    aotArgs.compileMode = "compileMode";
    aotArgs.hapPath = "hapPath";
    aotArgs.coreLibPath = "coreLibPath";
    aotArgs.outputPath = "outputPath";
    aotArgs.arkProfilePath = "arkProfilePath";
    aotArgs.offset = OFFSET;
    aotArgs.length = LENGTH;
    aotArgs.hspVector.emplace_back(CreateHspInfo());
    aotArgs.hspVector.emplace_back(CreateHspInfo());

    Parcel parcel;
    bool ret = aotArgs.Marshalling(parcel);
    EXPECT_EQ(ret, true);
    std::shared_ptr<AOTArgs> aotArgsPtr(aotArgs.Unmarshalling(parcel));
    ASSERT_NE(aotArgsPtr, nullptr);
    EXPECT_EQ(aotArgsPtr->bundleName, aotArgs.bundleName);
    EXPECT_EQ(aotArgsPtr->moduleName, aotArgs.moduleName);
    EXPECT_EQ(aotArgsPtr->compileMode, aotArgs.compileMode);
    EXPECT_EQ(aotArgsPtr->hapPath, aotArgs.hapPath);
    EXPECT_EQ(aotArgsPtr->coreLibPath, aotArgs.coreLibPath);
    EXPECT_EQ(aotArgsPtr->outputPath, aotArgs.outputPath);
    EXPECT_EQ(aotArgsPtr->arkProfilePath, aotArgs.arkProfilePath);
    EXPECT_EQ(aotArgsPtr->offset, aotArgs.offset);
    EXPECT_EQ(aotArgsPtr->length, aotArgs.length);
    size_t expectVectorSize = 2;
    EXPECT_EQ(aotArgsPtr->hspVector.size(), expectVectorSize);
    for (size_t i = 0; i < aotArgsPtr->hspVector.size(); ++i) {
        CheckHspInfo(aotArgsPtr->hspVector[i], aotArgs.hspVector[i]);
    }
    APP_LOGI("AOTArgs_0200 end");
}

/**
 * @tc.number: AOTHandler_1300
 * @tc.name: test AOTHandler
 * @tc.desc: bundle not exist, return std::nullopt
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1700, Function | SmallTest | Level0)
{
    std::string compileMode;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    auto res = AOTHandler::GetInstance().HandleCompileWithBundle(STRING_EMPTY, compileMode, dataMgr);
    EXPECT_EQ(res.bundleName, STRING_EMPTY);

    std::map<std::string, EventInfo> sysEventMap;
    AOTHandler::GetInstance().ReportSysEvent(sysEventMap);

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    AOTHandler::GetInstance().ResetAOTFlags();
    AOTHandler::GetInstance().OTACompileInternal();
}

/**
 * @tc.number: AOTHandler_1800
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleIdle function running normally if isOTA is false
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1800, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    bool isOTA = false;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo newInfo;
    installer.ProcessAOT(isOTA, infos);

    newInfo.SetIsNewVersion(isOTA);
    infos.emplace("", newInfo);
    installer.ProcessAOT(isOTA, infos);
    bool res = newInfo.GetIsNewVersion();
    EXPECT_EQ(res, isOTA);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        "", newInfo);
    AOTHandler::GetInstance().HandleIdle();
}

/**
 * @tc.number: AOTHandler_1900
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleIdle function running normally if isOTA is true
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1900, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    bool isOTA = true;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo newInfo;
    installer.ProcessAOT(isOTA, infos);

    newInfo.SetIsNewVersion(isOTA);
    infos.emplace("", newInfo);
    installer.ProcessAOT(isOTA, infos);
    bool res = newInfo.GetIsNewVersion();
    EXPECT_EQ(res, isOTA);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        "", newInfo);
    AOTHandler::GetInstance().HandleIdle();
}

/**
 * @tc.number: AOTHandler_2000
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleIdleWithSingleHap function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2000, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    info.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        "", info);
    AOTHandler::GetInstance().HandleIdleWithSingleHap(info, AOT_MODULE_NAME, "");
}

/**
 * @tc.number: AOTHandler_2100
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCopyAp function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2100, Function | SmallTest | Level0)
{
    std::string bundleName = "bundleName";
    std::vector<std::string> results;
    installdService_->Start();
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->AddUserId(USERID_ONE);
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.bundleUserInfo.userId = 100;
    innerBundleUserInfos["_100"] = info;
    info.bundleUserInfo.userId = 1;
    innerBundleUserInfos["_1"] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;

    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        bundleName, innerBundleInfo);
    auto ans = AOTHandler::GetInstance().HandleCopyAp(bundleName, false, results);
    EXPECT_EQ(ans, ERR_OK);
}

/**
 * @tc.number: AOTHandler_2200
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleOTA function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    bool isOTA = false;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo newInfo;
    installer.ProcessAOT(isOTA, infos);

    newInfo.SetIsNewVersion(true);
    infos.emplace("", newInfo);
    installer.ProcessAOT(isOTA, infos);
    bool res = newInfo.GetIsNewVersion();
    EXPECT_EQ(res, true);
    system::SetParameter(OTA_COMPILE_SWITCH, "on");
    system::SetParameter(OTA_COMPILE_MODE, "on");
    system::SetParameter(UPDATE_TYPE, "manual");
    AOTHandler::GetInstance().HandleOTA();
}

/**
 * @tc.number: AOTHandler_2300
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileWithBundle function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2300, Function | SmallTest | Level0)
{
    std::string bundleName = "bundleName";
    string compileMode = ServiceConstants::COMPILE_PARTIAL;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    AOTHandler::GetInstance().OTACompileDeadline_ = false;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.bundleUserInfo.userId = 100;
    innerBundleUserInfos["_100"] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    innerBundleInfo.SetIsNewVersion(true);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        bundleName, innerBundleInfo);
    std::map<std::string, EventInfo> sysEventMap;
    EventInfo eventInfo = AOTHandler::GetInstance().HandleCompileWithBundle(bundleName, compileMode, dataMgr);
    sysEventMap.emplace(bundleName, eventInfo);
    AOTHandler::GetInstance().ReportSysEvent(sysEventMap);
}

} // OHOS
