/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#define protected public

#include <dlfcn.h>
#include <fstream>
#include <gtest/gtest.h>

#include "ability_manager_helper.h"
#include "aot/aot_executor.h"
#include "aot/aot_handler.h"
#include "aot/aot_sign_data_cache_mgr.h"
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
#include "installd_client.h"
#include "mock_installd_proxy.h"
#include "shared_bundle_installer.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;

void SetIsExistFileCode(OHOS::ErrCode isExistFileCode);
void SetIsExistDirCode(OHOS::ErrCode isExistFileCode);
void SetMkdirCode(OHOS::ErrCode mkdir);
void SetPendSignAOTCode(OHOS::ErrCode pendSignAOT);

namespace OHOS {
namespace {
const std::string HAP_PATH = "/system/etc/graphic/bootpic.zip";
const std::string NOHAP_PATH = "/data/test/resource/bms/aot_bundle/....right.hap";
const std::string OUT_PUT_PATH = "/data/test/resource/bms/aot_bundle/";
const std::string ABC_RELATIVE_PATH = "ets/modules.abc";
const std::string STATIC_ABC_RELATIVE_PATH = "ets/modules_static.abc";
const std::string AOT_BUNDLE_NAME = "aotBundleName";
const std::string AOT_MODULE_NAME = "aotModuleName";
const std::string STRING_TYPE_ONE = "string1";
const std::string STRING_TYPE_TWO = "string2";
const std::string STRING_EMPTY = "";
const std::string AOT_VERSION = "aot_version";
const std::string AN_FILE_NAME = "anFileName";
const std::string IS_SYS_COMP = "isSysComp";
const std::string IS_SYS_COMP_FALSE = "0";
const std::string IS_SYS_COMP_TRUE = "1";
const int32_t USERID_ONE = 100;
const int32_t USERID_TWO = -1;
constexpr uint32_t VERSION_CODE = 3;
constexpr uint32_t OFFSET = 1001;
constexpr uint32_t LENGTH = 2002;
constexpr uint32_t SLEEP_INTERVAL_MILLI_SECONDS = 100;
constexpr uint32_t ASYNC_WAIT_MILLI_SECONDS = 100;
constexpr uint32_t VIRTUAL_CHILD_PID = 12345678;
const int32_t TEST_U0 = 0;
const int32_t TEST_U1 = 1;

constexpr const char* OTA_COMPILE_TIME = "persist.bms.optimizing_apps.timing";
constexpr const char* OTA_COMPILE_SWITCH = "const.bms.optimizing_apps.switch";
constexpr const char* OTA_COMPILE_MODE = "persist.bm.ota.arkopt";
constexpr const char* UPDATE_TYPE = "persist.dupdate_engine.update_type";
constexpr const char* INSTALL_COMPILE_MODE = "persist.bm.install.arkopt";
constexpr const char* COMPILE_NONE = "none";
constexpr const char* COMPILE_FULL = "full";
constexpr const char* USER_STATUS_SO_NAME = "libuser_status_client.z.so";
constexpr const char* FAILURE_REASON_BUNDLE_NOT_EXIST = "bundle not exist";
constexpr const char* UPDATE_TYPE_NIGHT = "night";
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
    hspInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
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
    EXPECT_EQ(sourceHspInfo.moduleArkTSMode, targetHspInfo.moduleArkTSMode);
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0100, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    ErrCode ret;
    std::vector<uint8_t> pendSignData;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0200
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0200, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    ErrCode ret;
    std::vector<uint8_t> pendSignData;
    aotArgs.compileMode = ServiceConstants::COMPILE_PARTIAL;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0300
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0300, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    ErrCode ret;
    std::vector<uint8_t> pendSignData;
    aotArgs.hapPath = HAP_PATH;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0400
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0400, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    ErrCode ret;
    std::vector<uint8_t> pendSignData;
    aotArgs.outputPath = OUT_PUT_PATH;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0500
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0500, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    ErrCode ret;
    std::vector<uint8_t> pendSignData;
    aotArgs.compileMode = ServiceConstants::COMPILE_PARTIAL;
    aotArgs.hapPath = ABC_RELATIVE_PATH;
    aotArgs.outputPath = OUT_PUT_PATH;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0600
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0600, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    ErrCode ret;
    std::vector<uint8_t> pendSignData;
    aotArgs.compileMode = COMPILE_FULL;
    aotArgs.hapPath = NOHAP_PATH;
    aotArgs.outputPath = OUT_PUT_PATH;
    aotArgs.arkProfilePath = OUT_PUT_PATH;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0700
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0700, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    ErrCode ret;
    std::vector<uint8_t> pendSignData;
    aotArgs.compileMode = COMPILE_FULL;
    aotArgs.hapPath = HAP_PATH;
    aotArgs.outputPath = OUT_PUT_PATH;
    aotArgs.arkProfilePath = OUT_PUT_PATH;

    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_0900
 * @tc.name: test StopAOT
 * @tc.desc: 1. ResetState
 *           2. call StopAOT
 *           3. return ERR_OK
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0900, Function | SmallTest | Level1)
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1000, Function | SmallTest | Level1)
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1100, Function | SmallTest | Level1)
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
 * @tc.number: MapSysCompArgs_0100
 * @tc.name: test MapSysCompArgs
 * @tc.desc: 1. call MapSysCompArgs, expect get set value
 */
HWTEST_F(BmsAOTMgrTest, MapSysCompArgs_0100, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.anFileName = "anFileName";
    std::unordered_map<std::string, std::string> argsMap;

    AOTExecutor::GetInstance().MapSysCompArgs(aotArgs, argsMap);
    EXPECT_EQ(argsMap[IS_SYS_COMP], IS_SYS_COMP_TRUE);
    EXPECT_EQ(argsMap[AN_FILE_NAME], aotArgs.anFileName);
}

/**
 * @tc.number: MapBundleArgs_0100
 * @tc.name: test MapBundleArgs
 * @tc.desc: 1. call MapBundleArgs, expect get set value
 */
HWTEST_F(BmsAOTMgrTest, MapBundleArgs_0100, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.anFileName = "anFileName";
    std::unordered_map<std::string, std::string> argsMap;

    AOTExecutor::GetInstance().MapBundleArgs(aotArgs, argsMap);
    EXPECT_EQ(argsMap[IS_SYS_COMP], IS_SYS_COMP_FALSE);
    EXPECT_EQ(argsMap[AN_FILE_NAME], aotArgs.anFileName);
}

/**
 * @tc.number: AOTHandler_0100
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0600, Function | SmallTest | Level1)
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_0700, Function | SmallTest | Level1)
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_0800, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    info.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    AOTHandler::GetInstance().HandleIdleWithSingleModule(info, AOT_MODULE_NAME, "");

    info.SetAOTCompileStatus(AOT_MODULE_NAME, AOTCompileStatus::IDLE_COMPILE_SUCCESS);
    AOTHandler::GetInstance().HandleIdleWithSingleModule(info, AOT_MODULE_NAME, "");
    AOTCompileStatus ret = info.GetAOTCompileStatus(AOT_MODULE_NAME);
    EXPECT_EQ(ret, AOTCompileStatus::IDLE_COMPILE_SUCCESS);
}

/**
 * @tc.number: AOTHandler_0900
 * @tc.name: test AOTHandler
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_0900, Function | SmallTest | Level1)
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
    auto ret = AOTHandler::GetInstance().FindArkProfilePath(AOT_BUNDLE_NAME, AOT_MODULE_NAME);
    EXPECT_EQ(ret, "");
    ResetDataMgr();
    ret = AOTHandler::GetInstance().FindArkProfilePath(AOT_BUNDLE_NAME, AOT_MODULE_NAME);
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_1000, Function | SmallTest | Level1)
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
        AOT_MODULE_NAME, ServiceConstants::COMPILE_PARTIAL, false, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_EQ(ret, std::nullopt);
    AOTHandler::GetInstance().HandleResetAllAOT();
    ResetDataMgr();
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);
    ret = AOTHandler::GetInstance().BuildAOTArgs(innerBundleInfo,
        AOT_MODULE_NAME, ServiceConstants::COMPILE_PARTIAL, false, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_EQ(ret, std::nullopt);
    ret = AOTHandler::GetInstance().BuildAOTArgs(innerBundleInfo,
        AOT_MODULE_NAME, ServiceConstants::COMPILE_PARTIAL, false, ServiceConstants::AOT_TRIGGER_IDLE);
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_1100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, AOT_MODULE_NAME, "", false, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: AOTHandler_1400
 * @tc.name: test IsOTACompileSwitchOn
 * @tc.desc: expect return set val
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1400, Function | SmallTest | Level1)
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_1500, Function | SmallTest | Level1)
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_1600, Function | SmallTest | Level1)
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
    aotArgs.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    aotArgs.isSysComp = true;
    aotArgs.sysCompPath = "sysCompPath";
    aotArgs.bundleType = 1;

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
    EXPECT_EQ(aotArgsPtr->moduleArkTSMode, aotArgs.moduleArkTSMode);
    EXPECT_EQ(aotArgsPtr->isSysComp, aotArgs.isSysComp);
    EXPECT_EQ(aotArgsPtr->sysCompPath, aotArgs.sysCompPath);
    EXPECT_EQ(aotArgsPtr->bundleType, aotArgs.bundleType);
    APP_LOGI("AOTArgs_0200 end");
}

/**
 * @tc.number: AOTHandler_1700
 * @tc.name: test HandleCompileWithBundle
 * @tc.desc: HandleCompileWithBundle with empty bundleName returns FAILURE_REASON_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1700, Function | SmallTest | Level1)
{
    std::string compileMode;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AOTHandler::GetInstance().OTACompileDeadline_ = false;
    auto res = AOTHandler::GetInstance().HandleCompileWithBundle(STRING_EMPTY, compileMode, dataMgr);
    EXPECT_EQ(res.bundleName, STRING_EMPTY);
    EXPECT_EQ(res.failureReason, FAILURE_REASON_BUNDLE_NOT_EXIST);
    EXPECT_FALSE(res.compileResult);
}

/**
 * @tc.number: AOTHandler_1800
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleIdle function running normally if isOTA is false
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1800, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installer.ProcessAOT(installParam);
    EXPECT_TRUE(installer.bundleName_.empty());

    InnerBundleInfo newInfo;
    newInfo.SetIsNewVersion(false);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        "", newInfo);
    AOTHandler::GetInstance().HandleIdle();
    EXPECT_FALSE(newInfo.GetIsNewVersion());
}

/**
 * @tc.number: AOTHandler_1900
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleIdle function running normally if isOTA is true
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_1900, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.isOTA = true;
    installer.ProcessAOT(installParam);
    EXPECT_TRUE(installer.bundleName_.empty());

    InnerBundleInfo newInfo;
    newInfo.SetIsNewVersion(true);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        "", newInfo);
    AOTHandler::GetInstance().HandleIdle();
    EXPECT_TRUE(newInfo.GetIsNewVersion());
}

/**
 * @tc.number: AOTHandler_2100
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCopyAp function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2100, Function | SmallTest | Level1)
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
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_2300
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileWithBundle function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2300, Function | SmallTest | Level1)
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
    EXPECT_EQ(eventInfo.failureReason, "compile failed");
    sysEventMap.emplace(bundleName, eventInfo);
    AOTHandler::GetInstance().ReportSysEvent(sysEventMap);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_2400
 * @tc.name: test AOTHandler
 * @tc.desc: test BuildAOTArgs function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2400, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    std::vector<std::string> results;
    ASSERT_NE(installdService_, nullptr);
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
        "", innerBundleInfo);
    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, AOT_MODULE_NAME, "", false, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_NE(ret, std::nullopt);
}

/**
 * @tc.number: AOTHandler_2600
 * @tc.name: test AOTHandler
 * @tc.desc: test CopyApWithBundle function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2600, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    std::vector<std::string> results;
    ASSERT_NE(installdService_, nullptr);
    installdService_->Start();
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->AddUserId(USERID_ONE);
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.bundleUserInfo.userId = 100;
    innerBundleUserInfos["_100"] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    BundleInfo bundleInfo;
    bundleInfo.moduleNames.push_back(bundleName);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        bundleName, innerBundleInfo);
    AOTHandler::GetInstance().CopyApWithBundle(bundleName, bundleInfo, 100, results);
    EXPECT_EQ(results.empty(), false);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_2700
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileWithBundle function running with OTACompileDeadline true
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2700, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    string compileMode = ServiceConstants::COMPILE_PARTIAL;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleInfo innerBundleInfo;
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(bundleName, innerBundleInfo);
    AOTHandler::GetInstance().OTACompileDeadline_ = true;
    EventInfo eventInfo = AOTHandler::GetInstance().HandleCompileWithBundle(bundleName, compileMode, dataMgr);
    EXPECT_EQ(eventInfo.costTimeSeconds, 0);
    EXPECT_EQ(eventInfo.failureReason, "timeout");
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
    AOTHandler::GetInstance().OTACompileDeadline_ = false;
}

/**
 * @tc.number: AOTHandler_2800
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileWithBundle function running with IsNewVersion false
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2800, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    string compileMode = ServiceConstants::COMPILE_PARTIAL;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
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
    innerBundleInfo.SetIsNewVersion(false);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(bundleName, innerBundleInfo);
    EventInfo eventInfo = AOTHandler::GetInstance().HandleCompileWithBundle(bundleName, compileMode, dataMgr);
    EXPECT_EQ(eventInfo.costTimeSeconds, 0);
    EXPECT_EQ(eventInfo.failureReason, "not stage model");
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_2900
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileBundles function running with compile fail
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2900, Function | SmallTest | Level1)
{
    std::vector<std::string> results;
    std::string bundleName = "bundleName";
    std::vector<std::string> bundleNames = { bundleName };
    string compileMode = ServiceConstants::COMPILE_PARTIAL;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
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
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(bundleName, innerBundleInfo);

    ErrCode ret = AOTHandler::GetInstance().HandleCompileBundles(
        bundleNames, ServiceConstants::COMPILE_PARTIAL, dataMgr, results);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_3000
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileBundles function running with IsNewVersion false
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3000, Function | SmallTest | Level1)
{
    std::vector<std::string> results;
    std::string bundleName = "bundleName";
    std::vector<std::string> bundleNames = { bundleName };
    string compileMode = ServiceConstants::COMPILE_PARTIAL;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsNewVersion(false);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(bundleName, innerBundleInfo);

    ErrCode ret = AOTHandler::GetInstance().HandleCompileBundles(
        bundleNames, ServiceConstants::COMPILE_PARTIAL, dataMgr, results);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTExecutor_1200
 * @tc.name: test GetSubjectInfo
 * @tc.desc: test GetSubjectInfo function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1200, Function | SmallTest | Level1)
{
    std::optional<AOTArgs> aotArgs;
    AOTArgs aotArg;
    aotArg.bundleName = "bundleName";
    aotArg.moduleName = "moduleName";
    auto json = AOTExecutor::GetInstance().GetSubjectInfo(aotArg);
    EXPECT_EQ(json.empty(), false);
}

/**
 * @tc.number: AOTExecutor_1300
 * @tc.name: test MapBundleArgs
 * @tc.desc: test MapBundleArgs function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1300, Function | SmallTest | Level1)
{
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
    std::unordered_map<std::string, std::string> argsMap;
    AOTExecutor::GetInstance().MapBundleArgs(aotArgs, argsMap);
    EXPECT_EQ(argsMap.empty(), false);
}

/**
 * @tc.number: AOTExecutor_1400
 * @tc.name: test PendSignAOT
 * @tc.desc: test PendSignAOT function running with exception parameter
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1400, Function | SmallTest | Level1)
{
    std::string anFileName = "anFileName";
    std::vector<uint8_t> signData(HAP_PATH.begin(), HAP_PATH.end());
    ErrCode ret = AOTExecutor::GetInstance().PendSignAOT(anFileName, signData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0100
 * @tc.name: test AOTSignDataCacheMgr
 * @tc.desc: test AddSignDataForModule function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0100, Function | SmallTest | Level1)
{
    std::optional<AOTArgs> aotArgs;
    AOTArgs aotArg;
    aotArg.bundleName = "bundleName";
    aotArg.moduleName = "moduleName";
    aotArgs = aotArg;
    int32_t versionCode = 1;
    std::vector<uint8_t> pendSignData(HAP_PATH.begin(), HAP_PATH.end());
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    AOTSignDataCacheMgr::GetInstance().AddSignDataForModule(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.empty(), false);
    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();
}

/**
 * @tc.number: AOTSignDataCacheMgr_0200
 * @tc.name: test AOTSignDataCacheMgr
 * @tc.desc: test AddSignDataForModule function running with exception parameter
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0200, Function | SmallTest | Level1)
{
    std::optional<AOTArgs> aotArgs;
    std::optional<AOTArgs> aotArgs2;
    std::optional<AOTArgs> aotArgs3;
    AOTArgs aotArg;
    aotArg.bundleName = "bundleName";
    aotArg.moduleName = "moduleName";
    aotArgs = aotArg;
    AOTArgs aotArg2;
    aotArg2.bundleName = "bundleName";
    aotArgs2 = aotArg2;
    AOTArgs aotArg3;
    aotArg3.moduleName = "moduleName";
    aotArgs3 = aotArg3;
    int32_t versionCode = 1;
    std::vector<uint8_t> pendSignData;
    std::vector<uint8_t> pendSignData2(HAP_PATH.begin(), HAP_PATH.end());
    ErrCode ret = ERR_OK;
    AOTSignDataCacheMgr& signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.isLocked_ = false;
    signDataCacheMgr.AddSignDataForModule(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(signDataCacheMgr.moduleSignDataVector_.empty(), true);
    signDataCacheMgr.isLocked_ = true;
    signDataCacheMgr.AddSignDataForModule(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(signDataCacheMgr.moduleSignDataVector_.empty(), true);
    ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    signDataCacheMgr.AddSignDataForModule(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(signDataCacheMgr.moduleSignDataVector_.empty(), true);
    signDataCacheMgr.isLocked_ = false;
    signDataCacheMgr.AddSignDataForModule(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(signDataCacheMgr.moduleSignDataVector_.empty(), true);
    ret = ERR_OK;
    signDataCacheMgr.AddSignDataForModule(*aotArgs, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.moduleSignDataVector_.empty(), true);
    ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    signDataCacheMgr.AddSignDataForModule(*aotArgs, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.moduleSignDataVector_.empty(), true);
    ret = ERR_OK;
    signDataCacheMgr.isLocked_ = true;
    signDataCacheMgr.AddSignDataForModule(*aotArgs, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.moduleSignDataVector_.empty(), true);
    ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    signDataCacheMgr.AddSignDataForModule(*aotArgs2, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.moduleSignDataVector_.empty(), true);
    signDataCacheMgr.AddSignDataForModule(*aotArgs3, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.moduleSignDataVector_.empty(), true);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0300
 * @tc.name: test RegisterScreenUnlockListener and UnregisterScreenUnlockEvent
 * @tc.desc: test RegisterScreenUnlockListener function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0300, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr& signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.RegisterScreenUnlockListener();
    signDataCacheMgr.UnregisterScreenUnlockEvent();
    EXPECT_NE(signDataCacheMgr.unlockEventSubscriber_, nullptr);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0400
 * @tc.name: test HandleUnlockEvent
 * @tc.desc: test HandleUnlockEvent function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0400, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr& signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.HandleUnlockEvent();
    EXPECT_EQ(signDataCacheMgr.isLocked_, false);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0500
 * @tc.name: test EnforceCodeSign
 * @tc.desc: test EnforceCodeSign function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0500, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr& signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    bool ret = signDataCacheMgr.EnforceCodeSign();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AOTExecutor_1500
 * @tc.name: test DecToHex
 * @tc.desc: test DecToHex function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1500, Function | SmallTest | Level1)
{
    std::string result = AOTExecutor::GetInstance().DecToHex(50);
    EXPECT_EQ(result, "0x32");
}

/**
 * @tc.number: AOTExecutor_1600
 * @tc.name: test CheckArgs
 * @tc.desc: test CheckArgs function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1600, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    bool result = AOTExecutor::GetInstance().CheckArgs(aotArgs);
    EXPECT_FALSE(result);

    aotArgs.hapPath = "hapPath";
    result = AOTExecutor::GetInstance().CheckArgs(aotArgs);
    EXPECT_FALSE(result);

    aotArgs.outputPath = "outputPath";
    result = AOTExecutor::GetInstance().CheckArgs(aotArgs);
    EXPECT_TRUE(result);

    AOTArgs aotArgs2;
    aotArgs2.outputPath = "outputPath";
    result = AOTExecutor::GetInstance().CheckArgs(aotArgs2);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: AOTExecutor_1700
 * @tc.name: test GetAbcFileInfo
 * @tc.desc: test GetAbcFileInfo function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1700, Function | SmallTest | Level1)
{
    std::string hapPath = "";
    uint32_t offset = OFFSET;
    uint32_t length = LENGTH;
    bool result = AOTExecutor::GetInstance().GetAbcFileInfo(hapPath, Constants::ARKTS_MODE_DYNAMIC, offset, length);
    EXPECT_FALSE(result);
    hapPath = HAP_PATH;
    result = AOTExecutor::GetInstance().GetAbcFileInfo(hapPath, Constants::ARKTS_MODE_DYNAMIC, offset, length);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: AOTExecutor_1800
 * @tc.name: test PrepareArgs
 * @tc.desc: test PrepareArgs function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1800, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.hapPath = HAP_PATH;
    aotArgs.compileMode = "compileMode";
    aotArgs.outputPath = "outputPath";
    aotArgs.arkProfilePath = "arkProfilePath";
    aotArgs.offset = OFFSET;
    aotArgs.length = LENGTH;
    AOTArgs completeArgs;
    ErrCode result = ERR_OK;
    result = AOTExecutor::GetInstance().PrepareArgs(aotArgs, completeArgs);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_AOT_ABC_NOT_EXIST);
}

/**
 * @tc.number: AOTExecutor_1900
 * @tc.name: test InitState
 * @tc.desc: system running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1900, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.outputPath = OUT_PUT_PATH;
    AOTExecutor::GetInstance().InitState(aotArgs);
    EXPECT_TRUE(AOTExecutor::GetInstance().state_.running);
    EXPECT_EQ(AOTExecutor::GetInstance().state_.outputPath, aotArgs.outputPath);
}

/**
 * @tc.number: AOTExecutor_2000
 * @tc.name: test ResetState
 * @tc.desc: system running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_2000, Function | SmallTest | Level1)
{
    AOTExecutor::GetInstance().ResetState();
    EXPECT_FALSE(AOTExecutor::GetInstance().state_.running);
}

/**
 * @tc.number: AOTExecutor_2100
 * @tc.name: test StartAOTCompiler
 * @tc.desc: system running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_2100, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    std::vector<uint8_t> signData;
    auto res = AOTExecutor::GetInstance().StartAOTCompiler(aotArgs, signData);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
}

/**
 * @tc.number: AOTExecutor_2200
 * @tc.name: test GetAbcRelativePath
 * @tc.desc: system running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_2200, Function | SmallTest | Level1)
{
    EXPECT_EQ(AOTExecutor::GetInstance().GetAbcRelativePath(Constants::ARKTS_MODE_DYNAMIC), ABC_RELATIVE_PATH);
    EXPECT_EQ(AOTExecutor::GetInstance().GetAbcRelativePath(Constants::ARKTS_MODE_STATIC), STATIC_ABC_RELATIVE_PATH);
    EXPECT_EQ(AOTExecutor::GetInstance().GetAbcRelativePath(Constants::EMPTY_STRING), Constants::EMPTY_STRING);
}

/**
 * @tc.number: AOTHandler_3200
 * @tc.name: test MkApDestDirIfNotExist
 * @tc.desc: test MkApDestDirIfNotExist function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3200, Function | SmallTest | Level1)
{
    ErrCode ret = AOTHandler::GetInstance().MkApDestDirIfNotExist();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AOTHandler_3300
 * @tc.name: test AOTHandler
 * @tc.desc: test GetSouceAp function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3300, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string bundleName = "bundleName";
    std::string arkProfilePath = AOTHandler::BuildArkProfilePath(userId, bundleName) + ServiceConstants::PATH_SEPARATOR;
    std::string mergedAp = arkProfilePath + "merged_" + bundleName + ServiceConstants::AP_SUFFIX;
    std::string rtAp = arkProfilePath + "rt_" + bundleName + ServiceConstants::AP_SUFFIX;
    std::string result = AOTHandler::GetInstance().GetSouceAp(mergedAp, rtAp);
    EXPECT_EQ(result.empty(), true);
}

/**
 * @tc.number: AOTHandler_3400
 * @tc.name: test AOTHandler
 * @tc.desc: test IsSupportARM64 function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3400, Function | SmallTest | Level1)
{
    bool result = AOTHandler::GetInstance().IsSupportARM64();
    EXPECT_TRUE(result);
}

/**
 * @tc.number: AOTHandler_3500
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileWithSingleModule function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3500, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string bundleName = "bundleName";
    std::string compileMode;
    ErrCode ret = AOTHandler::GetInstance().HandleCompileWithSingleModule(info, bundleName, compileMode, true);
    EXPECT_EQ(ret, ERR_APPEXECFWK_AOT_ARGS_EMPTY);
}

/**
 * @tc.number: AOTHandler_3600
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileModules function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3600, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string moduleName = "moduleName";
    std::vector<std::string> moduleNames = {moduleName};
    string compileMode = ServiceConstants::COMPILE_PARTIAL;
    std::string compileResult;
    ErrCode ret = AOTHandler::GetInstance().HandleCompileModules(
        moduleNames, compileMode, info, compileResult);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
}

/**
 * @tc.number: AOTHandler_3700
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleResetAllAOT resets AOT flags of all bundles to NOT_COMPILED
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3700, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.aotCompileStatus = AOTCompileStatus::IDLE_COMPILE_SUCCESS;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);

    AOTHandler::GetInstance().HandleResetAllAOT();

    auto item = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: AOTHandler_3800
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleOTACompile function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3800, Function | SmallTest | Level1)
{
    system::SetParameter(OTA_COMPILE_SWITCH, "on");
    system::SetParameter(OTA_COMPILE_TIME, "0");
    AOTHandler::GetInstance().HandleOTACompile();
    sleep(1);
    EXPECT_EQ(AOTHandler::GetInstance().OTACompileDeadline_, true);
}

/**
 * @tc.number: AOTHandler_3900
 * @tc.name: test AOTHandler
 * @tc.desc: test GetUserBehaviourAppList function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3900, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleNames;
    bool result = AOTHandler::GetInstance().GetUserBehaviourAppList(bundleNames, 0);
    void* handle = dlopen(USER_STATUS_SO_NAME, RTLD_NOW);
    if (handle == nullptr) {
        EXPECT_FALSE(result);
    } else {
        dlclose(handle);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number: AOTHandler_4400
 * @tc.name: Test HandleCompileWithBundle
 * @tc.desc: 1.HandleCompileWithBundle
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4400, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().OTACompileDeadline_ = false;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto result = AOTHandler::GetInstance().HandleCompileWithBundle(AOT_BUNDLE_NAME, AOT_MODULE_NAME, dataMgr);
    EXPECT_EQ(result.failureReason, FAILURE_REASON_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: AOTHandler_4000
 * @tc.name: test DeleteArkAp
 * @tc.desc: test DeleteArkAp with modules exercises the removal loop,
 *           verify the expected ark-profile path is well-formed
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4000, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    bundleInfo.name = AOT_BUNDLE_NAME;
    bundleInfo.moduleNames.push_back(AOT_MODULE_NAME);
    bundleInfo.moduleNames.push_back("secondModule");
    AOTHandler::GetInstance().DeleteArkAp(bundleInfo, USERID_ONE);

    std::string expectedPath = AOTHandler::BuildArkProfilePath(USERID_ONE, AOT_BUNDLE_NAME);
    EXPECT_FALSE(expectedPath.empty());
    EXPECT_NE(expectedPath.find(std::to_string(USERID_ONE)), std::string::npos);
    EXPECT_NE(expectedPath.find("aot_compiler/ark_profile"), std::string::npos);
}

/**
 * @tc.number: AOTHandler_4500
 * @tc.name: Test HandleCompileWithBundle
 * @tc.desc: 1.HandleCompileWithBundle
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4500, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().OTACompileDeadline_ = false;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.isNewVersion_ = true;
    info.innerModuleInfos_.clear();
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, info);
    auto result = AOTHandler::GetInstance().HandleCompileWithBundle(AOT_BUNDLE_NAME, AOT_MODULE_NAME, dataMgr);
    EXPECT_EQ(result.failureReason, "");
}

/**
 * @tc.number: AOTHandler_4600
 * @tc.name: Test HandleCompile
 * @tc.desc: 1.HandleCompile
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4600, Function | SmallTest | Level1)
{
    std::vector<std::string> compileResults;
    auto result = AOTHandler::GetInstance().HandleCompile(AOT_BUNDLE_NAME, COMPILE_NONE, false, compileResults);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
}

/**
 * @tc.number: AOTHandler_4700
 * @tc.name: Test HandleCompile
 * @tc.desc: 1.HandleCompile
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4700, Function | SmallTest | Level1)
{
    std::vector<std::string> compileResults;
    system::SetParameter("BM_AOT_TEST", AOT_MODULE_NAME);
    auto result = AOTHandler::GetInstance().HandleCompile(AOT_BUNDLE_NAME, AOT_MODULE_NAME, true, compileResults);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AOTHandler_5000
 * @tc.name: Test GetOTACompileList
 * @tc.desc: 1.GetOTACompileList
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_5000, Function | SmallTest | Level1)
{
    system::SetParameter(UPDATE_TYPE, UPDATE_TYPE_NIGHT);
    std::vector<std::string> bundleNames;
    bool ret = AOTHandler::GetInstance().GetOTACompileList(bundleNames);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AOTHandler_5100
 * @tc.name: Test GetSouceAp
 * @tc.desc: 1.GetSouceAp
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_5100, Function | SmallTest | Level1)
{
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    SetIsExistFileCode(ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
    auto ret = AOTHandler::GetInstance().GetSouceAp(AOT_BUNDLE_NAME, AOT_MODULE_NAME);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: AOTHandler_5200
 * @tc.name: Test MkApDestDirIfNotExist
 * @tc.desc: 1.MkApDestDirIfNotExist
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_5200, Function | SmallTest | Level1)
{
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    SetIsExistDirCode(ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
    SetMkdirCode(ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
    auto ret = AOTHandler::GetInstance().MkApDestDirIfNotExist();
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
    InstalldClient::GetInstance()->installdProxy_ = nullptr;
    InstalldClient::GetInstance()->GetInstalldProxy();
}

/**
 * @tc.number: AOTArgs_0300
 * @tc.name: test Unmarshalling
 * @tc.desc: Marshalling and Unmarshalling false
 */
HWTEST_F(BmsAOTMgrTest, AOTArgs_0300, Function | SmallTest | Level1)
{
    HspInfo hspInfo = CreateHspInfo();
    Parcel parcel;
    std::shared_ptr<HspInfo> hspInfoPtr(hspInfo.Unmarshalling(parcel));
    EXPECT_EQ(hspInfoPtr, nullptr);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0600
 * @tc.name: test EnforceCodeSign
 * @tc.desc: test EnforceCodeSign function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0600, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    std::optional<AOTArgs> aotArgs;
    AOTArgs aotArg;
    aotArg.bundleName = "bundleName";
    aotArg.moduleName = "moduleName";
    aotArgs = aotArg;
    int32_t versionCode = 1;
    std::vector<uint8_t> pendSignData(HAP_PATH.begin(), HAP_PATH.end());
    ErrCode result = ERR_OK;
    AOTSignDataCacheMgr::GetInstance().AddSignDataForModule(*aotArgs, versionCode, pendSignData, result);
    bool ret = signDataCacheMgr.EnforceCodeSign();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0700
 * @tc.name: Test HandleUnlockEvent
 * @tc.desc: 1.HandleUnlockEvent
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0700, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    AOTSignDataCacheMgr::GetInstance().HandleUnlockEvent();
    EXPECT_FALSE(AOTSignDataCacheMgr::GetInstance().isLocked_);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0800
 * @tc.name: Test EnforceCodeSign
 * @tc.desc: 1.EnforceCodeSign
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0800, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    AppExecFwk::AOTSignDataCacheMgr::ModuleSignData data;
    signDataCacheMgr.moduleSignDataVector_.emplace_back(data);
    SetPendSignAOTCode(ERR_OK);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    bool ret = signDataCacheMgr.EnforceCodeSign();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0900
 * @tc.name: Test EnforceCodeSign
 * @tc.desc: 1.EnforceCodeSign
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0900, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    AppExecFwk::AOTSignDataCacheMgr::ModuleSignData data;
    signDataCacheMgr.moduleSignDataVector_.emplace_back(data);
    SetPendSignAOTCode(ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    bool ret = signDataCacheMgr.EnforceCodeSign();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AOTSignDataCacheMgr_1000
 * @tc.name: Test EnforceCodeSign
 * @tc.desc: 1.EnforceCodeSign
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_1000, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    AppExecFwk::AOTSignDataCacheMgr::ModuleSignData data;
    signDataCacheMgr.moduleSignDataVector_.emplace_back(data);
    SetPendSignAOTCode(ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    bool ret = signDataCacheMgr.EnforceCodeSign();
    EXPECT_TRUE(ret);
    InstalldClient::GetInstance()->installdProxy_ = nullptr;
    InstalldClient::GetInstance()->GetInstalldProxy();
}

/**
 * @tc.number: AOTExecutor_2300
 * @tc.name: test StartAOTCompiler success scenario without using mock
 * @tc.desc: verify the behavior of StartAOTCompiler when all prerequisites are satisfied for successful execution.
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_2300, TestSize.Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleName = "aotBundleName";
    aotArgs.bundleUid = -1;
    aotArgs.bundleGid = -1;

    std::vector<uint8_t> signData;

#if defined(CODE_SIGNATURE_ENABLE)
    auto res = AOTExecutor::GetInstance().StartAOTCompiler(aotArgs, signData);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
#else
    auto res = AOTExecutor::GetInstance().StartAOTCompiler(aotArgs, signData);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
#endif
}

/**
 * @tc.number: AOTExecutor_3000
 * @tc.name: test ExecuteAOT when AOT is already running
 * @tc.desc: verify the behavior of ExecuteAOT when another AOT compilation is in progress.
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_3000, TestSize.Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleName = "aotBundleName";
    aotArgs.bundleUid = -1;
    aotArgs.bundleGid = -1;

    ErrCode ret;
    std::vector<uint8_t> pendSignData;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: AOTExecutor_4000
 * @tc.name: test ExecuteAOT when AOT is already running
 * @tc.desc: verify the behavior of ExecuteAOT when another AOT compilation is in progress.
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_4000, TestSize.Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleName = "aotBundleName";
    aotArgs.bundleUid = -1;
    aotArgs.bundleGid = -1;

    ErrCode ret;
    std::vector<uint8_t> pendSignData;
#ifndef CODE_SIGNATURE_ENABLE
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
#endif
}

/**
 * @tc.number: HandleCompileModules_1000
 * @tc.name: test IsSupportARM64 function running normally
 * @tc.desc: verify the behavior of IsSupportARM64 when it should return true.
 */
HWTEST_F(BmsAOTMgrTest, HandleCompileModules_1000, TestSize.Level1)
{
    std::vector<std::string> moduleNames = {"module1", "module2"};
    std::string compileMode = "compileMode";
    InnerBundleInfo info;
    std::string compileResult;

    ErrCode ret = AOTHandler::GetInstance().HandleCompileModules(moduleNames, compileMode, info, compileResult);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
}

/**
 * @tc.number: HandleCompile_4000
 * @tc.name: test IsSupportARM64 function running normally
 * @tc.desc: verify the behavior of IsSupportARM64 when it should return true.
 */
HWTEST_F(BmsAOTMgrTest, HandleCompile_4000, TestSize.Level1)
{
    system::SetParameter("BM_AOT_TEST", "");

    std::string bundleName = "test_bundle";
    std::string compileMode = "test_mode";
    bool isAllBundle = true;
    std::vector<std::string> compileResults;

    ErrCode ret = AOTHandler::GetInstance().HandleCompile(bundleName, compileMode, isAllBundle, compileResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
    EXPECT_EQ(compileResults.size(), 0);
}

/**
 * @tc.number: IsDriverForAllUser_0100
 * @tc.name: test IsDriverForAllUser
 * @tc.desc: 1.Test the IsDriverForAllUser
*/
HWTEST_F(BmsAOTMgrTest, IsDriverForAllUser_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    installer.InitDataMgr();

    InnerBundleInfo info;
    InnerExtensionInfo innerExtensionInfo;
    innerExtensionInfo.type = ExtensionAbilityType::DRIVER;
    info.InsertExtensionInfo("key", innerExtensionInfo);
    installer.dataMgr_->bundleInfos_.try_emplace(AOT_BUNDLE_NAME, info);
    bool ret = installer.IsDriverForAllUser(AOT_BUNDLE_NAME);
    EXPECT_TRUE(ret);
    OHOS::system::SetParameter(ServiceConstants::IS_DRIVER_FOR_ALL_USERS, "false");
    ret = installer.IsDriverForAllUser(AOT_BUNDLE_NAME);
    EXPECT_FALSE(ret);
    installer.dataMgr_->bundleInfos_.clear();
    OHOS::system::SetParameter(ServiceConstants::IS_DRIVER_FOR_ALL_USERS, "true");
}

/**
 * @tc.number: GetBundleNamesForNewUser_0100
 * @tc.name: test GetBundleNamesForNewUser
 */
HWTEST_F(BmsAOTMgrTest, GetBundleNamesForNewUser_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    InnerExtensionInfo innerExtensionInfo;
    innerExtensionInfo.type = ExtensionAbilityType::DRIVER;
    info.InsertExtensionInfo("key", innerExtensionInfo);
    dataMgr->bundleInfos_.try_emplace(AOT_BUNDLE_NAME, info);
    OHOS::system::SetParameter(ServiceConstants::IS_DRIVER_FOR_ALL_USERS, "false");
    std::vector<std::string> ret = dataMgr->GetBundleNamesForNewUser();
    EXPECT_EQ(ret.size(), 0);
    dataMgr->bundleInfos_.clear();
    OHOS::system::SetParameter(ServiceConstants::IS_DRIVER_FOR_ALL_USERS, "true");
}

/**
 * @tc.number: AddSignDataForSysComp_0100
 * @tc.name: Test AddSignDataForSysComp
 * @tc.desc: 1.AddSignDataForSysComp success testcase
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForSysComp_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.clear();

    std::string anFileName = "anFileName";
    std::vector<uint8_t> signData = {0};
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    AOTSignDataCacheMgr::GetInstance().AddSignDataForSysComp(anFileName, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.size();
    EXPECT_NE(size, 0);

    AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.clear();
}

/**
 * @tc.number: AddSignDataForSysComp_0200
 * @tc.name: Test AddSignDataForSysComp
 * @tc.desc: 1.AddSignDataForSysComp, anFileName is empty
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForSysComp_0200, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.clear();

    std::string anFileName;
    std::vector<uint8_t> signData = {0};
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    AOTSignDataCacheMgr::GetInstance().AddSignDataForSysComp(anFileName, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.number: AddSignDataForSysComp_0300
 * @tc.name: Test AddSignDataForSysComp
 * @tc.desc: 1.AddSignDataForSysComp, signData is empty
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForSysComp_0300, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.clear();

    std::string anFileName = "anFileName";
    std::vector<uint8_t> signData;
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    AOTSignDataCacheMgr::GetInstance().AddSignDataForSysComp(anFileName, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.number: AddSignDataForSysComp_0400
 * @tc.name: Test AddSignDataForSysComp
 * @tc.desc: 1.AddSignDataForSysComp, isLocked_ is false
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForSysComp_0400, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.clear();

    std::string anFileName = "anFileName";
    std::vector<uint8_t> signData = {0};
    AOTSignDataCacheMgr::GetInstance().isLocked_ = false;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    AOTSignDataCacheMgr::GetInstance().AddSignDataForSysComp(anFileName, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.number: AddSignDataForSysComp_0500
 * @tc.name: Test AddSignDataForSysComp
 * @tc.desc: 1.AddSignDataForSysComp, ret is ERR_OK
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForSysComp_0500, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.clear();

    std::string anFileName = "anFileName";
    std::vector<uint8_t> signData = {0};
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_OK;
    AOTSignDataCacheMgr::GetInstance().AddSignDataForSysComp(anFileName, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().sysCompSignDataMap_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.number: AddSignDataForModule_0100
 * @tc.name: Test AddSignDataForModule
 * @tc.desc: 1.AddSignDataForModule success testcase
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForModule_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();

    AOTArgs aotArgs;
    aotArgs.bundleName = "bundleName";
    aotArgs.moduleName = "moduleName";
    std::vector<uint8_t> signData = {0};
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;

    AOTSignDataCacheMgr::GetInstance().AddSignDataForModule(aotArgs, 0, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.size();
    EXPECT_NE(size, 0);

    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();
}

/**
 * @tc.number: AddSignDataForModule_0200
 * @tc.name: Test AddSignDataForModule
 * @tc.desc: 1.AddSignDataForModule failed testcase, bundleName is empty
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForModule_0200, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();

    AOTArgs aotArgs;
    aotArgs.bundleName;
    aotArgs.moduleName = "moduleName";
    std::vector<uint8_t> signData = {0};
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;

    AOTSignDataCacheMgr::GetInstance().AddSignDataForModule(aotArgs, 0, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.number: AddSignDataForModule_0300
 * @tc.name: Test AddSignDataForModule
 * @tc.desc: 1.AddSignDataForModule failed testcase, moduleName is empty
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForModule_0300, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();

    AOTArgs aotArgs;
    aotArgs.bundleName = "bundleName";
    aotArgs.moduleName;
    std::vector<uint8_t> signData = {0};
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;

    AOTSignDataCacheMgr::GetInstance().AddSignDataForModule(aotArgs, 0, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.number: AddSignDataForModule_0400
 * @tc.name: Test AddSignDataForModule
 * @tc.desc: 1.AddSignDataForModule failed testcase, signData is empty
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForModule_0400, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();

    AOTArgs aotArgs;
    aotArgs.bundleName = "bundleName";
    aotArgs.moduleName = "moduleName";
    std::vector<uint8_t> signData;
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;

    AOTSignDataCacheMgr::GetInstance().AddSignDataForModule(aotArgs, 0, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.number: AddSignDataForModule_0500
 * @tc.name: Test AddSignDataForModule
 * @tc.desc: 1.AddSignDataForModule failed testcase, isLocked_ is false
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForModule_0500, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();

    AOTArgs aotArgs;
    aotArgs.bundleName = "bundleName";
    aotArgs.moduleName = "moduleName";
    std::vector<uint8_t> signData = {0};
    AOTSignDataCacheMgr::GetInstance().isLocked_ = false;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;

    AOTSignDataCacheMgr::GetInstance().AddSignDataForModule(aotArgs, 0, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.number: AddSignDataForModule_0600
 * @tc.name: Test AddSignDataForModule
 * @tc.desc: 1.AddSignDataForModule failed testcase, ret is ERR_OK
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForModule_0600, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();

    AOTArgs aotArgs;
    aotArgs.bundleName = "bundleName";
    aotArgs.moduleName = "moduleName";
    std::vector<uint8_t> signData = {0};
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_OK;

    AOTSignDataCacheMgr::GetInstance().AddSignDataForModule(aotArgs, 0, signData, ret);
    size_t size = AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.size();
    EXPECT_EQ(size, 0);
}

/**
 * @tc.number: AddSignDataForModule_0700
 * @tc.name: Test AddSignDataForModule
 * @tc.desc: 1.verify new fields are cached for pending sign data
 */
HWTEST_F(BmsAOTMgrTest, AddSignDataForModule_0700, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();

    AOTArgs aotArgs;
    aotArgs.bundleName = "bundleName";
    aotArgs.moduleName = "moduleName";
    aotArgs.bundleType = static_cast<uint8_t>(BundleType::SHARED);
    aotArgs.triggerType = ServiceConstants::AOT_TRIGGER_INSTALL;
    std::vector<uint8_t> signData = {0x01, 0x02};
    uint32_t versionCode = VERSION_CODE;
    AOTSignDataCacheMgr::GetInstance().isLocked_ = true;
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;

    AOTSignDataCacheMgr::GetInstance().AddSignDataForModule(aotArgs, versionCode, signData, ret);
    ASSERT_EQ(AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.size(), 1);
    const auto &cacheData = AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.back();
    EXPECT_EQ(cacheData.bundleType, aotArgs.bundleType);
    EXPECT_EQ(cacheData.triggerType, aotArgs.triggerType);
    EXPECT_EQ(cacheData.versionCode, versionCode);
    EXPECT_EQ(cacheData.bundleName, aotArgs.bundleName);
    EXPECT_EQ(cacheData.moduleName, aotArgs.moduleName);
    EXPECT_EQ(cacheData.signData, signData);

    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();
}

/**
 * @tc.number: EnforceCodeSign_0100
 * @tc.name: Test EnforceCodeSign
 * @tc.desc: 1.EnforceCodeSign success testcase
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSign_0100, Function | SmallTest | Level1)
{
    bool ret = AOTSignDataCacheMgr::GetInstance().EnforceCodeSign();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: EnforceCodeSignForSysComp_0100
 * @tc.name: Test EnforceCodeSignForSysComp
 * @tc.desc: 1.EnforceCodeSignForSysComp success testcase
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSignForSysComp_0100, Function | SmallTest | Level1)
{
    bool ret = AOTSignDataCacheMgr::GetInstance().EnforceCodeSignForSysComp();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: EnforceCodeSignForModule_0100
 * @tc.name: Test EnforceCodeSignForModule
 * @tc.desc: 1.EnforceCodeSignForModule success testcase - empty vector returns true
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSignForModule_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr::GetInstance().moduleSignDataVector_.clear();
    bool ret = AOTSignDataCacheMgr::GetInstance().EnforceCodeSignForModule();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: EnforceCodeSignForModule_0200
 * @tc.name: Test EnforceCodeSignForModule sign disabled branch
 * @tc.desc: verify EnforceCodeSignForModule returns false when PendSignAOT returns
 *           ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE, exercising the early-return branch
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSignForModule_0200, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.moduleSignDataVector_.clear();

    AppExecFwk::AOTSignDataCacheMgr::ModuleSignData data;
    data.bundleType = static_cast<uint8_t>(BundleType::APP);
    data.triggerType = ServiceConstants::AOT_TRIGGER_IDLE;
    data.versionCode = VERSION_CODE;
    data.bundleName = AOT_BUNDLE_NAME;
    data.moduleName = AOT_MODULE_NAME;
    data.signData = {0x01};
    signDataCacheMgr.moduleSignDataVector_.emplace_back(data);

    SetPendSignAOTCode(ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    bool ret = signDataCacheMgr.EnforceCodeSignForModule();
    EXPECT_FALSE(ret);

    InstalldClient::GetInstance()->installdProxy_ = nullptr;
    InstalldClient::GetInstance()->GetInstalldProxy();
    signDataCacheMgr.moduleSignDataVector_.clear();
}

/**
 * @tc.number: IsAOTFlagsInitial_0100
 * @tc.name: Test IsAOTFlagsInitial
 * @tc.desc: 1.IsAOTFlagsInitial testcase
 */
HWTEST_F(BmsAOTMgrTest, IsAOTFlagsInitial_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_ = std::make_shared<ApplicationInfo>();

    bool ret = info.IsAOTFlagsInitial();
    EXPECT_TRUE(ret);

    info.baseApplicationInfo_->arkNativeFilePath = "arkNativeFilePath";
    ret = info.IsAOTFlagsInitial();
    EXPECT_FALSE(ret);
    info.baseApplicationInfo_->arkNativeFilePath = "";

    info.baseApplicationInfo_->arkNativeFileAbi = "arkNativeFileAbi";
    ret = info.IsAOTFlagsInitial();
    EXPECT_FALSE(ret);
    info.baseApplicationInfo_->arkNativeFileAbi = "";

    std::string bundleName = "bundleName";
    info.innerModuleInfos_[bundleName].aotCompileStatus = AOTCompileStatus::IDLE_COMPILE_SUCCESS;
    ret = info.IsAOTFlagsInitial();
    EXPECT_FALSE(ret);

    info.innerModuleInfos_[bundleName].aotCompileStatus = AOTCompileStatus::COMPILE_FAILED;
    ret = info.IsAOTFlagsInitial();
    EXPECT_FALSE(ret);

    info.innerModuleInfos_[bundleName].aotCompileStatus = AOTCompileStatus::COMPILE_CRASH;
    ret = info.IsAOTFlagsInitial();
    EXPECT_FALSE(ret);

    info.innerModuleInfos_[bundleName].aotCompileStatus = AOTCompileStatus::COMPILE_CANCELLED;
    ret = info.IsAOTFlagsInitial();
    EXPECT_FALSE(ret);

    info.baseApplicationInfo_->arkNativeFilePath.clear();
    info.baseApplicationInfo_->arkNativeFileAbi.clear();
    info.innerModuleInfos_[bundleName].aotCompileStatus = AOTCompileStatus::NOT_COMPILED;
    ret = info.IsAOTFlagsInitial();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AOTHandler_SharedHsp_BuildAOTArgs_0100
 * @tc.name: test BuildAOTArgs for shared bundle
 * @tc.desc: verify BuildAOTArgs builds correct shared args when bundleType is SHARED
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_SharedHsp_BuildAOTArgs_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, AOT_MODULE_NAME, "", false, ServiceConstants::AOT_TRIGGER_INSTALL);
    ASSERT_NE(ret, std::nullopt);
    EXPECT_EQ(ret->bundleType, static_cast<uint8_t>(BundleType::SHARED));
    EXPECT_EQ(ret->compileMode, ServiceConstants::COMPILE_FULL);
    EXPECT_EQ(ret->bundleUid, ServiceConstants::SYSTEM_UID);
    EXPECT_EQ(ret->bundleGid, ServiceConstants::SYSTEM_UID);
    EXPECT_EQ(ret->triggerType, ServiceConstants::AOT_TRIGGER_INSTALL);

    std::string expectedOutputPath = AOTHandler::BuildSharedArkCachePath(AOT_BUNDLE_NAME, VERSION_CODE);
    EXPECT_EQ(ret->outputPath, expectedOutputPath);
}

/**
 * @tc.number: AOTHandler_SharedHsp_HandleInstallAOT_0100
 * @tc.name: test HandleInstallAOTAsync for shared bundle
 * @tc.desc: verify HandleInstallAOTAsync processes shared bundle correctly
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_SharedHsp_HandleInstallAOT_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.sharedhsp";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    AOTHandler::GetInstance().HandleInstallAOTAsync(bundleName);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MILLI_SECONDS));

    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_TRUE(item->second.GetIsNewVersion());
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_SharedHsp_HandleInstallAOT_0200
 * @tc.name: test HandleInstallAOTAsync skips dynamic ArkTS shared bundle
 * @tc.desc: verify HandleInstallAOTAsync returns early for dynamic ArkTS mode shared bundle
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_SharedHsp_HandleInstallAOT_0200, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.sharedhsp.dynamic";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    AOTHandler::GetInstance().HandleInstallAOTAsync(bundleName);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MILLI_SECONDS));

    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: SharedBundleInstaller_ProcessAOT_0100
 * @tc.name: test ProcessAOT skips AOT for first boot install
 * @tc.desc: verify ProcessAOT returns early when isFirstBootInstall is true
 */
HWTEST_F(BmsAOTMgrTest, SharedBundleInstaller_ProcessAOT_0100, Function | SmallTest | Level1)
{
    InstallParam installParam;
    installParam.isFirstBootInstall = true;
    SharedBundleInstaller installer(installParam, Constants::AppType::THIRD_PARTY_APP);
    installer.ProcessAOT();
    EXPECT_TRUE(installer.innerInstallers_.empty());
}

/**
 * @tc.number: SharedBundleInstaller_ProcessAOT_0200
 * @tc.name: test ProcessAOT skips AOT for OTA install
 * @tc.desc: verify ProcessAOT returns early when isOTA is true
 */
HWTEST_F(BmsAOTMgrTest, SharedBundleInstaller_ProcessAOT_0200, Function | SmallTest | Level1)
{
    InstallParam installParam;
    installParam.isOTA = true;
    SharedBundleInstaller installer(installParam, Constants::AppType::THIRD_PARTY_APP);
    installer.ProcessAOT();
    EXPECT_TRUE(installer.innerInstallers_.empty());
}

/**
 * @tc.number: SharedBundleInstaller_ProcessAOT_0300
 * @tc.name: test ProcessAOT skips AOT for create user
 * @tc.desc: verify ProcessAOT returns early when isCreateUser is true
 */
HWTEST_F(BmsAOTMgrTest, SharedBundleInstaller_ProcessAOT_0300, Function | SmallTest | Level1)
{
    InstallParam installParam;
    installParam.isCreateUser = true;
    SharedBundleInstaller installer(installParam, Constants::AppType::THIRD_PARTY_APP);
    installer.ProcessAOT();
    EXPECT_TRUE(installer.innerInstallers_.empty());
}

/**
 * @tc.number: SharedBundleInstaller_ProcessAOT_0400
 * @tc.name: test ProcessAOT triggers AOT for normal install
 * @tc.desc: verify ProcessAOT calls HandleInstallAOTAsync for each shared bundle during normal install
 */
HWTEST_F(BmsAOTMgrTest, SharedBundleInstaller_ProcessAOT_0400, Function | SmallTest | Level1)
{
    InstallParam installParam;
    SharedBundleInstaller installer(installParam, Constants::AppType::THIRD_PARTY_APP);

    std::string bundleName = "com.example.sharedhsp.normal";
    auto innerInstaller = std::make_shared<InnerSharedBundleInstaller>("/data/test");
    innerInstaller->bundleName_ = bundleName;
    installer.innerInstallers_.emplace(bundleName, innerInstaller);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        bundleName, innerBundleInfo);

    installer.ProcessAOT();
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MILLI_SECONDS));

    EXPECT_FALSE(installer.innerInstallers_.empty());
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: SharedBundleInstaller_ProcessAOT_0500
 * @tc.name: test ProcessAOT with empty shared installer list
 * @tc.desc: verify ProcessAOT runs normal path and exits when innerInstallers_ is empty
 */
HWTEST_F(BmsAOTMgrTest, SharedBundleInstaller_ProcessAOT_0500, Function | SmallTest | Level1)
{
    InstallParam installParam;
    SharedBundleInstaller installer(installParam, Constants::AppType::THIRD_PARTY_APP);
    installer.innerInstallers_.clear();
    installer.ProcessAOT();
    EXPECT_TRUE(installer.innerInstallers_.empty());
}

/**
 * @tc.number: ConvertToAOTCompileStatus_0100
 * @tc.name: test ConvertToAOTCompileStatus all branches
 * @tc.desc: 1.ERR_OK + AOT_TRIGGER_INSTALL → INSTALL_COMPILE_SUCCESS
 *           2.ERR_OK + AOT_TRIGGER_IDLE → IDLE_COMPILE_SUCCESS
 *           3.CRASH → COMPILE_CRASH
 *           4.CANCELLED → COMPILE_CANCELLED
 *           5.Other error → COMPILE_FAILED
 */
HWTEST_F(BmsAOTMgrTest, ConvertToAOTCompileStatus_0100, Function | SmallTest | Level1)
{
    auto status = AOTHandler::ConvertToAOTCompileStatus(ERR_OK, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_EQ(status, AOTCompileStatus::INSTALL_COMPILE_SUCCESS);

    status = AOTHandler::ConvertToAOTCompileStatus(ERR_OK, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_EQ(status, AOTCompileStatus::IDLE_COMPILE_SUCCESS);

    status = AOTHandler::ConvertToAOTCompileStatus(
        ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_CRASH, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_EQ(status, AOTCompileStatus::COMPILE_CRASH);

    status = AOTHandler::ConvertToAOTCompileStatus(
        ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_CRASH, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_EQ(status, AOTCompileStatus::COMPILE_CRASH);

    status = AOTHandler::ConvertToAOTCompileStatus(
        ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_CANCELLED, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_EQ(status, AOTCompileStatus::COMPILE_CANCELLED);

    status = AOTHandler::ConvertToAOTCompileStatus(
        ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_CANCELLED, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_EQ(status, AOTCompileStatus::COMPILE_CANCELLED);

    status = AOTHandler::ConvertToAOTCompileStatus(
        ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_EQ(status, AOTCompileStatus::COMPILE_FAILED);

    status = AOTHandler::ConvertToAOTCompileStatus(
        ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_EQ(status, AOTCompileStatus::COMPILE_FAILED);
}

/**
 * @tc.number: NeedCompile_0100
 * @tc.name: test NeedCompile with all AOTCompileStatus values
 * @tc.desc: NOT_COMPILED, COMPILE_CANCELLED, INSTALL_COMPILE_SUCCESS → true;
 *           IDLE_COMPILE_SUCCESS, COMPILE_FAILED, COMPILE_CRASH → false
 */
HWTEST_F(BmsAOTMgrTest, NeedCompile_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    info.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    info.SetAOTCompileStatus(AOT_MODULE_NAME, AOTCompileStatus::NOT_COMPILED);
    EXPECT_TRUE(AOTHandler::GetInstance().NeedCompile(info, AOT_MODULE_NAME));

    info.SetAOTCompileStatus(AOT_MODULE_NAME, AOTCompileStatus::COMPILE_CANCELLED);
    EXPECT_TRUE(AOTHandler::GetInstance().NeedCompile(info, AOT_MODULE_NAME));

    info.SetAOTCompileStatus(AOT_MODULE_NAME, AOTCompileStatus::INSTALL_COMPILE_SUCCESS);
    EXPECT_TRUE(AOTHandler::GetInstance().NeedCompile(info, AOT_MODULE_NAME));

    info.SetAOTCompileStatus(AOT_MODULE_NAME, AOTCompileStatus::IDLE_COMPILE_SUCCESS);
    EXPECT_FALSE(AOTHandler::GetInstance().NeedCompile(info, AOT_MODULE_NAME));

    info.SetAOTCompileStatus(AOT_MODULE_NAME, AOTCompileStatus::COMPILE_FAILED);
    EXPECT_FALSE(AOTHandler::GetInstance().NeedCompile(info, AOT_MODULE_NAME));

    info.SetAOTCompileStatus(AOT_MODULE_NAME, AOTCompileStatus::COMPILE_CRASH);
    EXPECT_FALSE(AOTHandler::GetInstance().NeedCompile(info, AOT_MODULE_NAME));
}

/**
 * @tc.number: GetAOTCompileStatusWithVersion_0100
 * @tc.name: test GetAOTCompileStatusWithVersion
 * @tc.desc: 1.module found with matching versionCode → return actual status
 *           2.module found with mismatching versionCode → return NOT_COMPILED
 *           3.module not found → return NOT_COMPILED
 */
HWTEST_F(BmsAOTMgrTest, GetAOTCompileStatusWithVersion_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.versionCode = VERSION_CODE;
    moduleInfo.aotCompileStatus = AOTCompileStatus::IDLE_COMPILE_SUCCESS;
    info.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto status = info.GetAOTCompileStatusWithVersion(AOT_MODULE_NAME, VERSION_CODE);
    EXPECT_EQ(status, AOTCompileStatus::IDLE_COMPILE_SUCCESS);

    status = info.GetAOTCompileStatusWithVersion(AOT_MODULE_NAME, VERSION_CODE + 1);
    EXPECT_EQ(status, AOTCompileStatus::NOT_COMPILED);

    status = info.GetAOTCompileStatusWithVersion("nonExistModule", VERSION_CODE);
    EXPECT_EQ(status, AOTCompileStatus::NOT_COMPILED);
}

/**
 * @tc.number: GetAOTCompileStatusWithVersion_0200
 * @tc.name: test GetAOTCompileStatusWithVersion with INSTALL_COMPILE_SUCCESS
 * @tc.desc: verify INSTALL_COMPILE_SUCCESS is returned when version matches
 */
HWTEST_F(BmsAOTMgrTest, GetAOTCompileStatusWithVersion_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.versionCode = VERSION_CODE;
    moduleInfo.aotCompileStatus = AOTCompileStatus::INSTALL_COMPILE_SUCCESS;
    info.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto status = info.GetAOTCompileStatusWithVersion(AOT_MODULE_NAME, VERSION_CODE);
    EXPECT_EQ(status, AOTCompileStatus::INSTALL_COMPILE_SUCCESS);
}

/**
 * @tc.number: BuildAppArgs_0100
 * @tc.name: test BuildAppArgs idle partial with empty profile
 * @tc.desc: verify BuildAOTArgs returns nullopt when triggerType is idle,
 *           compileMode is partial, and arkProfilePath is empty
 */
HWTEST_F(BmsAOTMgrTest, BuildAppArgs_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, AOT_MODULE_NAME, ServiceConstants::COMPILE_PARTIAL,
        false, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: BuildAppArgs_0200
 * @tc.name: test BuildAppArgs with install trigger skips profile check
 * @tc.desc: verify BuildAppArgs does not check arkProfilePath when triggerType is install,
 *           but fails because no user info exists
 */
HWTEST_F(BmsAOTMgrTest, BuildAppArgs_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, AOT_MODULE_NAME, ServiceConstants::COMPILE_PARTIAL,
        false, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: BuildAppArgs_0400
 * @tc.name: test BuildAOTArgs returns nullopt when moduleArkTSMode is empty
 * @tc.desc: verify nullopt when module has empty moduleArkTSMode
 */
HWTEST_F(BmsAOTMgrTest, BuildAppArgs_0400, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, "nonExistModule", "", false, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: HandleInstallAOT_0100
 * @tc.name: test HandleInstallAOT with not stage model
 * @tc.desc: verify HandleInstallAOT returns early if IsNewVersion is false
 */
HWTEST_F(BmsAOTMgrTest, HandleInstallAOT_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.oldmodel";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(false);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);
    AOTHandler::GetInstance().HandleInstallAOT(bundleName);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_FALSE(item->second.GetIsNewVersion());
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleInstallAOT_0200
 * @tc.name: test HandleInstallAOT with all-dynamic ArkTS app
 * @tc.desc: verify HandleInstallAOT returns early if app ArkTS mode is dynamic
 */
HWTEST_F(BmsAOTMgrTest, HandleInstallAOT_0200, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.dynamicapp";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);
    AOTHandler::GetInstance().HandleInstallAOT(bundleName);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleInstallAOT_0300
 * @tc.name: test HandleInstallAOT with dataMgr null
 * @tc.desc: verify HandleInstallAOT returns early if dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, HandleInstallAOT_0300, Function | SmallTest | Level1)
{
    ClearDataMgr();
    AOTHandler::GetInstance().HandleInstallAOT(AOT_BUNDLE_NAME);
    ResetDataMgr();
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: HandleInstallAOT_0400
 * @tc.name: test HandleInstallAOT with bundle not found
 * @tc.desc: verify HandleInstallAOT returns early if QueryInnerBundleInfo fails
 */
HWTEST_F(BmsAOTMgrTest, HandleInstallAOT_0400, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().HandleInstallAOT("nonExistentBundle");
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.count("nonExistentBundle"), 0);
}

/**
 * @tc.number: HandleInstallAOT_0500
 * @tc.name: test HandleInstallAOT returns early when bundle is not in AOT enable list
 * @tc.desc: verify HandleInstallAOT returns early when the bundle is absent from
 *           the AOT compile enable list (config file not present in test environment),
 *           regardless of the ArkTS mode of individual modules
 */
HWTEST_F(BmsAOTMgrTest, HandleInstallAOT_0500, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.mixedmodules";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerModuleInfo staticModule;
    staticModule.moduleName = "staticModule";
    staticModule.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("staticModule", staticModule);

    InnerModuleInfo dynamicModule;
    dynamicModule.moduleName = "dynamicModule";
    dynamicModule.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("dynamicModule", dynamicModule);

    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        bundleName, innerBundleInfo);
    AOTHandler::GetInstance().HandleInstallAOT(bundleName);
    // AOT flags must remain NOT_COMPILED because the bundle is not in the enable list
    auto item = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.find(bundleName);
    ASSERT_NE(item, DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus("staticModule"), AOTCompileStatus::NOT_COMPILED);
    EXPECT_EQ(item->second.GetAOTCompileStatus("dynamicModule"), AOTCompileStatus::NOT_COMPILED);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleResetBundleAOT_0100
 * @tc.name: test HandleResetBundleAOT isAllBundle with bm.aot.test param set
 * @tc.desc: verify ResetAllBundleAOT is called when isAllBundle and bm.aot.test is non-empty
 */
HWTEST_F(BmsAOTMgrTest, HandleResetBundleAOT_0100, Function | SmallTest | Level1)
{
    system::SetParameter("bm.aot.test", "test");
    AOTHandler::GetInstance().HandleResetBundleAOT("", true);
    std::string param = system::GetParameter("bm.aot.test", "");
    EXPECT_EQ(param, "test");
    system::SetParameter("bm.aot.test", "");
}

/**
 * @tc.number: HandleResetBundleAOT_0200
 * @tc.name: test HandleResetBundleAOT for single SHARED bundle
 * @tc.desc: verify HandleResetBundleAOT removes shared ark cache for SHARED bundle type
 */
HWTEST_F(BmsAOTMgrTest, HandleResetBundleAOT_0200, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.shared.reset";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.aotCompileStatus = AOTCompileStatus::IDLE_COMPILE_SUCCESS;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);
    AOTHandler::GetInstance().HandleResetBundleAOT(bundleName, false);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleResetBundleAOT_0300
 * @tc.name: test HandleResetBundleAOT for single APP bundle
 * @tc.desc: verify HandleResetBundleAOT removes hap ark cache for APP bundle type
 */
HWTEST_F(BmsAOTMgrTest, HandleResetBundleAOT_0300, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app.reset";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.aotCompileStatus = AOTCompileStatus::IDLE_COMPILE_SUCCESS;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);
    AOTHandler::GetInstance().HandleResetBundleAOT(bundleName, false);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleResetBundleAOT_0400
 * @tc.name: test HandleResetBundleAOT for non-existent single bundle
 * @tc.desc: verify HandleResetBundleAOT returns early when GetBundleType fails
 */
HWTEST_F(BmsAOTMgrTest, HandleResetBundleAOT_0400, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().HandleResetBundleAOT("nonExistentBundle", false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.count("nonExistentBundle"), 0);
}

/**
 * @tc.number: HandleResetBundleAOT_0500
 * @tc.name: test HandleResetBundleAOT with dataMgr null for single bundle
 * @tc.desc: verify HandleResetBundleAOT returns early when dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, HandleResetBundleAOT_0500, Function | SmallTest | Level1)
{
    ClearDataMgr();
    AOTHandler::GetInstance().HandleResetBundleAOT("bundleName", false);
    ResetDataMgr();
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: ResetAllSysCompAOT_0100
 * @tc.name: test ResetAllSysCompAOT
 * @tc.desc: verify ResetAllSysCompAOT runs without error
 */
HWTEST_F(BmsAOTMgrTest, ResetAllSysCompAOT_0100, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().ResetAllSysCompAOT();
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: ResetAllBundleAOT_0100
 * @tc.name: test ResetAllBundleAOT with dataMgr null
 * @tc.desc: verify ResetAllBundleAOT returns early when dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, ResetAllBundleAOT_0100, Function | SmallTest | Level1)
{
    ClearDataMgr();
    AOTHandler::GetInstance().ResetAllBundleAOT();
    ResetDataMgr();
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: ResetAllBundleAOT_0200
 * @tc.name: test ResetAllBundleAOT with valid dataMgr
 * @tc.desc: verify ResetAllBundleAOT resets AOT flags and clears cache dirs
 */
HWTEST_F(BmsAOTMgrTest, ResetAllBundleAOT_0200, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.aotCompileStatus = AOTCompileStatus::IDLE_COMPILE_SUCCESS;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);

    AOTHandler::GetInstance().ResetAllBundleAOT();

    auto item = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: ProcessAOT_FirstBootInstall_0100
 * @tc.name: test BaseBundleInstaller ProcessAOT with isFirstBootInstall
 * @tc.desc: verify ProcessAOT returns early when isFirstBootInstall is true
 */
HWTEST_F(BmsAOTMgrTest, ProcessAOT_FirstBootInstall_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.isFirstBootInstall = true;
    installer.ProcessAOT(installParam);
    EXPECT_TRUE(installer.bundleName_.empty());
}

/**
 * @tc.number: ProcessAOT_CreateUser_0100
 * @tc.name: test BaseBundleInstaller ProcessAOT with isCreateUser
 * @tc.desc: verify ProcessAOT returns early when isCreateUser is true
 */
HWTEST_F(BmsAOTMgrTest, ProcessAOT_CreateUser_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.isCreateUser = true;
    installer.ProcessAOT(installParam);
    EXPECT_TRUE(installer.bundleName_.empty());
}

/**
 * @tc.number: ProcessAOT_OtaInstall_0100
 * @tc.name: test BaseBundleInstaller ProcessAOT with otaInstall_
 * @tc.desc: verify ProcessAOT returns early when otaInstall_ is true
 */
HWTEST_F(BmsAOTMgrTest, ProcessAOT_OtaInstall_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installer.otaInstall_ = true;
    installer.ProcessAOT(installParam);
    EXPECT_TRUE(installer.otaInstall_);
    EXPECT_TRUE(installer.bundleName_.empty());
}

/**
 * @tc.number: ProcessAOT_InstallParamOTA_0100
 * @tc.name: test BaseBundleInstaller ProcessAOT with installParam.isOTA
 * @tc.desc: verify ProcessAOT returns early when installParam.isOTA is true
 */
HWTEST_F(BmsAOTMgrTest, ProcessAOT_InstallParamOTA_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.isOTA = true;
    installer.ProcessAOT(installParam);
    EXPECT_TRUE(installer.bundleName_.empty());
}

/**
 * @tc.number: EnforceCodeSignForModule_DataMgrNull_0100
 * @tc.name: test EnforceCodeSignForModule with dataMgr null
 * @tc.desc: verify EnforceCodeSignForModule returns false when dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSignForModule_DataMgrNull_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.moduleSignDataVector_.clear();
    ClearDataMgr();
    bool ret = signDataCacheMgr.EnforceCodeSignForModule();
    EXPECT_FALSE(ret);
    ResetDataMgr();
}

/**
 * @tc.number: EnforceCodeSignForModule_SharedPath_0100
 * @tc.name: test EnforceCodeSignForModule with SHARED bundleType
 * @tc.desc: verify EnforceCodeSignForModule uses shared ark cache path for SHARED bundleType
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSignForModule_SharedPath_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.moduleSignDataVector_.clear();

    AppExecFwk::AOTSignDataCacheMgr::ModuleSignData data;
    data.bundleType = static_cast<uint8_t>(BundleType::SHARED);
    data.triggerType = ServiceConstants::AOT_TRIGGER_INSTALL;
    data.versionCode = VERSION_CODE;
    data.bundleName = "com.example.shared.sign";
    data.moduleName = AOT_MODULE_NAME;
    data.signData = {0x01, 0x02};
    signDataCacheMgr.moduleSignDataVector_.emplace_back(data);

    SetPendSignAOTCode(ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    bool ret = signDataCacheMgr.EnforceCodeSignForModule();
    EXPECT_TRUE(ret);
    InstalldClient::GetInstance()->installdProxy_ = nullptr;
    InstalldClient::GetInstance()->GetInstalldProxy();
}

/**
 * @tc.number: EnforceCodeSignForModule_AppPath_0100
 * @tc.name: test EnforceCodeSignForModule with APP bundleType
 * @tc.desc: verify EnforceCodeSignForModule uses hap ark cache path for APP bundleType
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSignForModule_AppPath_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.moduleSignDataVector_.clear();

    AppExecFwk::AOTSignDataCacheMgr::ModuleSignData data;
    data.bundleType = static_cast<uint8_t>(BundleType::APP);
    data.triggerType = ServiceConstants::AOT_TRIGGER_IDLE;
    data.versionCode = VERSION_CODE;
    data.bundleName = "com.example.app.sign";
    data.moduleName = AOT_MODULE_NAME;
    data.signData = {0x01, 0x02};
    signDataCacheMgr.moduleSignDataVector_.emplace_back(data);

    SetPendSignAOTCode(ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    bool ret = signDataCacheMgr.EnforceCodeSignForModule();
    EXPECT_TRUE(ret);
    InstalldClient::GetInstance()->installdProxy_ = nullptr;
    InstalldClient::GetInstance()->GetInstalldProxy();
}

/**
 * @tc.number: EnforceCodeSignForModule_SignOK_Install_0100
 * @tc.name: test EnforceCodeSignForModule sets INSTALL_COMPILE_SUCCESS on sign success
 * @tc.desc: verify triggerType is used in ConvertToAOTCompileStatus during code sign
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSignForModule_SignOK_Install_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.moduleSignDataVector_.clear();

    AppExecFwk::AOTSignDataCacheMgr::ModuleSignData data;
    data.bundleType = static_cast<uint8_t>(BundleType::APP);
    data.triggerType = ServiceConstants::AOT_TRIGGER_INSTALL;
    data.versionCode = VERSION_CODE;
    data.bundleName = AOT_BUNDLE_NAME;
    data.moduleName = AOT_MODULE_NAME;
    data.signData = {0x01};
    signDataCacheMgr.moduleSignDataVector_.emplace_back(data);

    InnerBundleInfo innerBundleInfo;
    BundleInfo bInfo;
    bInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        AOT_BUNDLE_NAME, innerBundleInfo);

    SetPendSignAOTCode(ERR_OK);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    bool ret = signDataCacheMgr.EnforceCodeSignForModule();
    EXPECT_TRUE(ret);

    auto item = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.find(AOT_BUNDLE_NAME);
    if (item != DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.end()) {
        EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::INSTALL_COMPILE_SUCCESS);
    }

    InstalldClient::GetInstance()->installdProxy_ = nullptr;
    InstalldClient::GetInstance()->GetInstalldProxy();
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: EnforceCodeSignForModule_SignOK_Idle_0100
 * @tc.name: test EnforceCodeSignForModule sets IDLE_COMPILE_SUCCESS on sign success
 * @tc.desc: verify idle triggerType produces IDLE_COMPILE_SUCCESS
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSignForModule_SignOK_Idle_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.moduleSignDataVector_.clear();

    AppExecFwk::AOTSignDataCacheMgr::ModuleSignData data;
    data.bundleType = static_cast<uint8_t>(BundleType::APP);
    data.triggerType = ServiceConstants::AOT_TRIGGER_IDLE;
    data.versionCode = VERSION_CODE;
    data.bundleName = AOT_BUNDLE_NAME;
    data.moduleName = AOT_MODULE_NAME;
    data.signData = {0x01};
    signDataCacheMgr.moduleSignDataVector_.emplace_back(data);

    InnerBundleInfo innerBundleInfo;
    BundleInfo bInfo;
    bInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        AOT_BUNDLE_NAME, innerBundleInfo);

    SetPendSignAOTCode(ERR_OK);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    bool ret = signDataCacheMgr.EnforceCodeSignForModule();
    EXPECT_TRUE(ret);

    auto item = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.find(AOT_BUNDLE_NAME);
    if (item != DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.end()) {
        EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::IDLE_COMPILE_SUCCESS);
    }

    InstalldClient::GetInstance()->installdProxy_ = nullptr;
    InstalldClient::GetInstance()->GetInstalldProxy();
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: AOTArgs_0400
 * @tc.name: test AOTArgs new fields Marshalling and Unmarshalling
 * @tc.desc: verify bundleType, triggerType and staticAndHybridModuleCnt survive marshalling
 */
HWTEST_F(BmsAOTMgrTest, AOTArgs_0400, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleType = static_cast<uint8_t>(BundleType::SHARED);
    aotArgs.triggerType = ServiceConstants::AOT_TRIGGER_INSTALL;
    aotArgs.staticAndHybridModuleCnt = 5;
    aotArgs.bundleName = "bundleName";
    aotArgs.moduleName = "moduleName";
    aotArgs.hapPath = "hapPath";
    aotArgs.outputPath = "outputPath";

    Parcel parcel;
    bool ret = aotArgs.Marshalling(parcel);
    EXPECT_TRUE(ret);
    std::shared_ptr<AOTArgs> aotArgsPtr(aotArgs.Unmarshalling(parcel));
    ASSERT_NE(aotArgsPtr, nullptr);
    EXPECT_EQ(aotArgsPtr->bundleType, aotArgs.bundleType);
    EXPECT_EQ(aotArgsPtr->triggerType, aotArgs.triggerType);
    EXPECT_EQ(aotArgsPtr->staticAndHybridModuleCnt, aotArgs.staticAndHybridModuleCnt);
    EXPECT_EQ(aotArgsPtr->bundleName, aotArgs.bundleName);
    EXPECT_EQ(aotArgsPtr->moduleName, aotArgs.moduleName);
}

/**
 * @tc.number: AOTArgs_0500
 * @tc.name: test AOTArgs default values for new fields
 * @tc.desc: verify default values of bundleType, triggerType and staticAndHybridModuleCnt
 */
HWTEST_F(BmsAOTMgrTest, AOTArgs_0500, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    EXPECT_EQ(aotArgs.bundleType, 0);
    EXPECT_EQ(aotArgs.triggerType, ServiceConstants::AOT_TRIGGER_IDLE);
    EXPECT_EQ(aotArgs.staticAndHybridModuleCnt, 0u);
}

/**
 * @tc.number: AOTArgs_0600
 * @tc.name: test AOTArgs ToString includes new fields
 * @tc.desc: verify ToString contains bundleType, triggerType and staticAndHybridModuleCnt values
 */
HWTEST_F(BmsAOTMgrTest, AOTArgs_0600, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleType = static_cast<uint8_t>(BundleType::SHARED);
    aotArgs.triggerType = ServiceConstants::AOT_TRIGGER_INSTALL;
    aotArgs.staticAndHybridModuleCnt = 7;
    std::string ret = aotArgs.ToString();
    EXPECT_NE(ret.find("bundleType = " + std::to_string(aotArgs.bundleType)), std::string::npos);
    EXPECT_NE(ret.find("triggerType = " + std::to_string(aotArgs.triggerType)), std::string::npos);
    EXPECT_NE(ret.find("staticAndHybridModuleCnt = " + std::to_string(aotArgs.staticAndHybridModuleCnt)),
        std::string::npos);
}

/**
 * @tc.number: MapBundleArgs_0200
 * @tc.name: test MapBundleArgs emits new fields
 * @tc.desc: verify MapBundleArgs adds bundleType, triggerType, staticAndHybridModuleCnt to argsMap
 */
HWTEST_F(BmsAOTMgrTest, MapBundleArgs_0200, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleName = "bundleName";
    aotArgs.moduleName = "moduleName";
    aotArgs.bundleType = static_cast<uint8_t>(BundleType::SHARED);
    aotArgs.triggerType = ServiceConstants::AOT_TRIGGER_INSTALL;
    aotArgs.staticAndHybridModuleCnt = 3;
    aotArgs.outputPath = "outputPath";
    aotArgs.compileMode = COMPILE_FULL;

    std::unordered_map<std::string, std::string> argsMap;
    AOTExecutor::GetInstance().MapBundleArgs(aotArgs, argsMap);
    EXPECT_EQ(argsMap["bundleType"], std::to_string(aotArgs.bundleType));
    EXPECT_EQ(argsMap["triggerType"], std::to_string(aotArgs.triggerType));
    EXPECT_EQ(argsMap["staticAndHybridModuleCnt"], std::to_string(aotArgs.staticAndHybridModuleCnt));
    EXPECT_EQ(argsMap["target-compiler-mode"], aotArgs.compileMode);
}

/**
 * @tc.number: MkAOTOutputDir_SharedType_0100
 * @tc.name: test MkAOTOutputDir with SHARED bundleType
 * @tc.desc: verify MkAOTOutputDir uses SHARED_HSP_ARK_CACHE_PATH as basePath for shared bundle
 */
HWTEST_F(BmsAOTMgrTest, MkAOTOutputDir_SharedType_0100, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleName = "com.example.shared.mkdir";
    aotArgs.bundleType = 2;
    aotArgs.outputPath = std::string(ServiceConstants::SHARED_HSP_ARK_CACHE_PATH) + aotArgs.bundleName;
    aotArgs.bundleUid = ServiceConstants::SYSTEM_UID;
    aotArgs.bundleGid = ServiceConstants::SYSTEM_UID;
    bool ret = AOTExecutor::GetInstance().MkAOTOutputDir(aotArgs);
    struct stat st;
    bool baseExists = (stat(ServiceConstants::SHARED_HSP_ARK_CACHE_PATH, &st) == 0);
    if (!baseExists) {
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: MkAOTOutputDir_AppType_0100
 * @tc.name: test MkAOTOutputDir with APP bundleType
 * @tc.desc: verify MkAOTOutputDir uses HAP_ARK_CACHE_PATH as basePath for app bundle
 */
HWTEST_F(BmsAOTMgrTest, MkAOTOutputDir_AppType_0100, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleName = "com.example.app.mkdir";
    aotArgs.bundleType = 0;
    aotArgs.bundleUid = ServiceConstants::SYSTEM_UID;
    aotArgs.bundleGid = ServiceConstants::SYSTEM_UID;
    bool ret = AOTExecutor::GetInstance().MkAOTOutputDir(aotArgs);
    struct stat st;
    bool baseExists = (stat(ServiceConstants::HAP_ARK_CACHE_PATH, &st) == 0);
    if (!baseExists) {
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: MkdirWithAuth_0100
 * @tc.name: test MkdirWithAuth with invalid base path
 * @tc.desc: verify MkdirWithAuth returns false when base path is not a directory
 */
HWTEST_F(BmsAOTMgrTest, MkdirWithAuth_0100, Function | SmallTest | Level1)
{
    std::filesystem::path basePath = std::filesystem::temp_directory_path() / "bms_aot_non_exist_base";
    std::error_code ec;
    std::filesystem::remove_all(basePath, ec);
    std::filesystem::path targetPath = basePath / "child";
    bool ret = AOTExecutor::GetInstance().MkdirWithAuth(basePath, targetPath, 0, 0, 0755);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MkdirWithAuth_0200
 * @tc.name: test MkdirWithAuth target equals base
 * @tc.desc: verify MkdirWithAuth returns true when targetPath equals basePath
 */
HWTEST_F(BmsAOTMgrTest, MkdirWithAuth_0200, Function | SmallTest | Level1)
{
    std::filesystem::path basePath = std::filesystem::temp_directory_path() / "bms_aot_same_base";
    std::error_code ec;
    std::filesystem::create_directories(basePath, ec);
    bool ret = AOTExecutor::GetInstance().MkdirWithAuth(basePath, basePath, 0, 0, 0755);
    EXPECT_TRUE(ret);
    std::filesystem::remove_all(basePath, ec);
}

/**
 * @tc.number: MkdirWithAuth_0300
 * @tc.name: test MkdirWithAuth with parent traversal
 * @tc.desc: verify MkdirWithAuth returns false when target escapes base with ".."
 */
HWTEST_F(BmsAOTMgrTest, MkdirWithAuth_0300, Function | SmallTest | Level1)
{
    std::filesystem::path basePath = std::filesystem::temp_directory_path() / "bms_aot_escape_base";
    std::error_code ec;
    std::filesystem::create_directories(basePath, ec);
    std::filesystem::path targetPath = basePath / ".." / "escape";
    bool ret = AOTExecutor::GetInstance().MkdirWithAuth(basePath, targetPath, 0, 0, 0755);
    EXPECT_FALSE(ret);
    std::filesystem::remove_all(basePath, ec);
}

/**
 * @tc.number: MkAOTOutputDir_Traversal_0100
 * @tc.name: test MkAOTOutputDir path traversal protection
 * @tc.desc: verify MkAOTOutputDir returns false when shared/app target path escapes base
 */
HWTEST_F(BmsAOTMgrTest, MkAOTOutputDir_Traversal_0100, Function | SmallTest | Level1)
{
    AOTArgs sharedArgs;
    sharedArgs.bundleType = static_cast<uint8_t>(BundleType::SHARED);
    sharedArgs.outputPath = std::string(ServiceConstants::SHARED_HSP_ARK_CACHE_PATH) + "../escape";
    sharedArgs.bundleUid = ServiceConstants::SYSTEM_UID;
    sharedArgs.bundleGid = ServiceConstants::SYSTEM_UID;
    EXPECT_FALSE(AOTExecutor::GetInstance().MkAOTOutputDir(sharedArgs));

    AOTArgs appArgs;
    appArgs.bundleType = static_cast<uint8_t>(BundleType::APP);
    appArgs.bundleName = "../escape";
    appArgs.bundleUid = ServiceConstants::SYSTEM_UID;
    appArgs.bundleGid = ServiceConstants::SYSTEM_UID;
    EXPECT_FALSE(AOTExecutor::GetInstance().MkAOTOutputDir(appArgs));
}

/**
 * @tc.number: StaticAndHybridModuleCnt_0100
 * @tc.name: test staticAndHybridModuleCnt calculation in BuildAOTArgs
 * @tc.desc: verify staticAndHybridModuleCnt counts non-dynamic modules correctly
 */
HWTEST_F(BmsAOTMgrTest, StaticAndHybridModuleCnt_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerModuleInfo staticModule;
    staticModule.moduleName = "staticModule";
    staticModule.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("staticModule", staticModule);

    InnerModuleInfo dynamicModule;
    dynamicModule.moduleName = "dynamicModule";
    dynamicModule.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("dynamicModule", dynamicModule);

    InnerModuleInfo hybridModule;
    hybridModule.moduleName = "hybridModule";
    hybridModule.moduleArkTSMode = Constants::ARKTS_MODE_HYBRID;
    innerBundleInfo.innerModuleInfos_.try_emplace("hybridModule", hybridModule);

    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, "staticModule", "", false, ServiceConstants::AOT_TRIGGER_INSTALL);
    ASSERT_NE(ret, std::nullopt);
    EXPECT_EQ(ret->staticAndHybridModuleCnt, 2u);
}

/**
 * @tc.number: StaticAndHybridModuleCnt_0200
 * @tc.name: test staticAndHybridModuleCnt when all modules are non-dynamic
 * @tc.desc: verify staticAndHybridModuleCnt equals total module count when no dynamic modules
 */
HWTEST_F(BmsAOTMgrTest, StaticAndHybridModuleCnt_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerModuleInfo moduleA;
    moduleA.moduleName = "moduleA";
    moduleA.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("moduleA", moduleA);

    InnerModuleInfo moduleB;
    moduleB.moduleName = "moduleB";
    moduleB.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("moduleB", moduleB);

    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, "moduleA", "", false, ServiceConstants::AOT_TRIGGER_INSTALL);
    ASSERT_NE(ret, std::nullopt);
    EXPECT_EQ(ret->staticAndHybridModuleCnt, 2u);
}

/**
 * @tc.number: SetAOTCompileStatus_InstallSuccess_0100
 * @tc.name: test SetAOTCompileStatus with INSTALL_COMPILE_SUCCESS
 * @tc.desc: verify abi and path are set for INSTALL_COMPILE_SUCCESS
 */
HWTEST_F(BmsAOTMgrTest, SetAOTCompileStatus_InstallSuccess_0100, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);

    dataMgr->SetAOTCompileStatus(AOT_BUNDLE_NAME, AOT_MODULE_NAME,
        AOTCompileStatus::INSTALL_COMPILE_SUCCESS, VERSION_CODE);
    auto item = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::INSTALL_COMPILE_SUCCESS);

    dataMgr->SetAOTCompileStatus(AOT_BUNDLE_NAME, AOT_MODULE_NAME,
        AOTCompileStatus::IDLE_COMPILE_SUCCESS, VERSION_CODE);
    item = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::IDLE_COMPILE_SUCCESS);

    dataMgr->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: SetAOTCompileStatus_BundleNotExist_0100
 * @tc.name: test SetAOTCompileStatus when bundle not in bundleInfos
 * @tc.desc: verify RemoveDir is called for both HAP and SHARED cache paths
 */
HWTEST_F(BmsAOTMgrTest, SetAOTCompileStatus_BundleNotExist_0100, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->SetAOTCompileStatus("nonExistBundle", AOT_MODULE_NAME,
        AOTCompileStatus::IDLE_COMPILE_SUCCESS, VERSION_CODE);
    EXPECT_EQ(dataMgr->bundleInfos_.count("nonExistBundle"), 0);
}

/**
 * @tc.number: SetAOTCompileStatus_VersionMismatch_0100
 * @tc.name: test SetAOTCompileStatus when versionCode does not match
 * @tc.desc: verify status is not set when versionCode differs
 */
HWTEST_F(BmsAOTMgrTest, SetAOTCompileStatus_VersionMismatch_0100, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);

    dataMgr->SetAOTCompileStatus(AOT_BUNDLE_NAME, AOT_MODULE_NAME,
        AOTCompileStatus::IDLE_COMPILE_SUCCESS, VERSION_CODE + 1);
    auto item = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);

    dataMgr->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: ResetAOTFlags_SingleBundle_0100
 * @tc.name: test BundleDataMgr::ResetAOTFlags for single bundle
 * @tc.desc: verify ResetAOTFlags resets AOT status for a specific bundle
 */
HWTEST_F(BmsAOTMgrTest, ResetAOTFlags_SingleBundle_0100, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.aotCompileStatus = AOTCompileStatus::IDLE_COMPILE_SUCCESS;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);

    dataMgr->ResetAOTFlags(AOT_BUNDLE_NAME);
    auto item = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);

    dataMgr->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: ResetAOTFlags_NonExistBundle_0100
 * @tc.name: test BundleDataMgr::ResetAOTFlags for non-existent bundle
 * @tc.desc: verify ResetAOTFlags handles non-existent bundle gracefully
 */
HWTEST_F(BmsAOTMgrTest, ResetAOTFlags_NonExistBundle_0100, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->ResetAOTFlags("nonExistentBundle");
    EXPECT_EQ(dataMgr->bundleInfos_.count("nonExistentBundle"), 0);
}

/**
 * @tc.number: ResetAllBundleAOTFlags_0100
 * @tc.name: test BundleDataMgr::ResetAllBundleAOTFlags
 * @tc.desc: verify ResetAllBundleAOTFlags resets AOT flags for all bundles
 */
HWTEST_F(BmsAOTMgrTest, ResetAllBundleAOTFlags_0100, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.aotCompileStatus = AOTCompileStatus::IDLE_COMPILE_SUCCESS;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);

    dataMgr->ResetAllBundleAOTFlags();
    auto item = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);

    dataMgr->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: IsAOTFlagsInitial_InstallCompileSuccess_0100
 * @tc.name: test IsAOTFlagsInitial with INSTALL_COMPILE_SUCCESS
 * @tc.desc: verify INSTALL_COMPILE_SUCCESS makes IsAOTFlagsInitial return false
 */
HWTEST_F(BmsAOTMgrTest, IsAOTFlagsInitial_InstallCompileSuccess_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    std::string moduleName = "testModule";
    info.innerModuleInfos_[moduleName].aotCompileStatus = AOTCompileStatus::INSTALL_COMPILE_SUCCESS;
    bool ret = info.IsAOTFlagsInitial();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BuildSharedArgs_0100
 * @tc.name: test BuildSharedArgs sets correct fields
 * @tc.desc: verify BuildSharedArgs sets uid/gid to SYSTEM_UID, compileMode to full,
 *           and outputPath to shared cache path
 */
HWTEST_F(BmsAOTMgrTest, BuildSharedArgs_0100, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleName = AOT_BUNDLE_NAME;
    aotArgs.moduleName = AOT_MODULE_NAME;
    AOTHandler::GetInstance().BuildSharedArgs(VERSION_CODE, aotArgs);

    EXPECT_EQ(aotArgs.bundleUid, ServiceConstants::SYSTEM_UID);
    EXPECT_EQ(aotArgs.bundleGid, ServiceConstants::SYSTEM_UID);
    EXPECT_EQ(aotArgs.bundleType, static_cast<uint8_t>(BundleType::SHARED));
    EXPECT_EQ(aotArgs.compileMode, ServiceConstants::COMPILE_FULL);
    std::string expectedPath = AOTHandler::BuildSharedArkCachePath(AOT_BUNDLE_NAME, VERSION_CODE);
    EXPECT_EQ(aotArgs.outputPath, expectedPath);
}

/**
 * @tc.number: BuildSharedArkCachePath_0100
 * @tc.name: test BuildSharedArkCachePath all branches
 * @tc.desc: verify empty bundleName, no-version and with-version branches
 */
HWTEST_F(BmsAOTMgrTest, BuildSharedArkCachePath_0100, Function | SmallTest | Level1)
{
    std::string emptyPath = AOTHandler::BuildSharedArkCachePath("");
    EXPECT_EQ(emptyPath, Constants::EMPTY_STRING);

    std::string bundleName = "com.example.shared";
    std::filesystem::path basePath(ServiceConstants::SHARED_HSP_ARK_CACHE_PATH);
    basePath /= bundleName;
    std::string noVersionPath = AOTHandler::BuildSharedArkCachePath(bundleName);
    EXPECT_EQ(noVersionPath, basePath.string());

    std::filesystem::path withVersionPath(basePath);
    withVersionPath /= std::to_string(VERSION_CODE);
    withVersionPath /= ServiceConstants::ARM64;
    std::string builtWithVersionPath = AOTHandler::BuildSharedArkCachePath(bundleName, VERSION_CODE);
    EXPECT_EQ(builtWithVersionPath, withVersionPath.string());
}

/**
 * @tc.number: HandleIdleWithSingleModule_InstallCompileSuccess_0100
 * @tc.name: test HandleIdleWithSingleModule recompiles INSTALL_COMPILE_SUCCESS
 * @tc.desc: verify NeedCompile returns true for INSTALL_COMPILE_SUCCESS so idle recompile occurs
 */
HWTEST_F(BmsAOTMgrTest, HandleIdleWithSingleModule_InstallCompileSuccess_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    info.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    info.SetAOTCompileStatus(AOT_MODULE_NAME, AOTCompileStatus::INSTALL_COMPILE_SUCCESS);

    AOTHandler::GetInstance().HandleIdleWithSingleModule(info, AOT_MODULE_NAME, "");
    AOTCompileStatus ret = info.GetAOTCompileStatus(AOT_MODULE_NAME);
    EXPECT_EQ(ret, AOTCompileStatus::INSTALL_COMPILE_SUCCESS);
}

/**
 * @tc.number: HandleCompile_NullDataMgr_0100
 * @tc.name: test HandleCompile with null dataMgr
 * @tc.desc: verify HandleCompile returns error and populates compileResults
 *           when dataMgr is null and isAllBundle is false
 */
HWTEST_F(BmsAOTMgrTest, HandleCompile_NullDataMgr_0100, Function | SmallTest | Level1)
{
    ClearDataMgr();
    ScopeGuard guard([&] { ResetDataMgr(); });
    std::vector<std::string> compileResults;
    ErrCode ret = AOTHandler::GetInstance().HandleCompile(
        AOT_BUNDLE_NAME, ServiceConstants::COMPILE_PARTIAL, false, compileResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
    ASSERT_FALSE(compileResults.empty());
    EXPECT_NE(compileResults[0].find("dataMgr is null"), std::string::npos);
}

/**
 * @tc.number: HandleCompile_SingleBundleNotExist_0100
 * @tc.name: test HandleCompile with non-existent single bundle
 * @tc.desc: verify HandleCompile returns FAILED and records error when
 *           QueryInnerBundleInfo fails for the given bundle name
 */
HWTEST_F(BmsAOTMgrTest, HandleCompile_SingleBundleNotExist_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> compileResults;
    ErrCode ret = AOTHandler::GetInstance().HandleCompile(
        "nonExistentBundle", ServiceConstants::COMPILE_PARTIAL, false, compileResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
    EXPECT_FALSE(compileResults.empty());
}

/**
 * @tc.number: HandleResetBundleAOT_AllBundleEmptyParam_0100
 * @tc.name: test HandleResetBundleAOT isAllBundle with empty bm.aot.test
 * @tc.desc: verify HandleResetBundleAOT returns early without resetting AOT flags
 *           when isAllBundle is true but bm.aot.test system parameter is empty
 */
HWTEST_F(BmsAOTMgrTest, HandleResetBundleAOT_AllBundleEmptyParam_0100, Function | SmallTest | Level1)
{
    system::SetParameter("bm.aot.test", "");

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.aotCompileStatus = AOTCompileStatus::IDLE_COMPILE_SUCCESS;
    innerBundleInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);

    AOTHandler::GetInstance().HandleResetBundleAOT("", true);

    auto item = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::IDLE_COMPILE_SUCCESS);
    dataMgr->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: ClearArkAp_ValidData_0100
 * @tc.name: test ClearArkAp with valid bundles in dataMgr
 * @tc.desc: verify ClearArkAp iterates bundles without corrupting bundle data
 */
HWTEST_F(BmsAOTMgrTest, ClearArkAp_ValidData_0100, Function | SmallTest | Level1)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.moduleNames.push_back(AOT_MODULE_NAME);
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    dataMgr->AddUserId(USERID_ONE);
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);

    AOTHandler::GetInstance().ClearArkAp();

    auto item = dataMgr->bundleInfos_.find(AOT_BUNDLE_NAME);
    EXPECT_NE(item, dataMgr->bundleInfos_.end());
    dataMgr->bundleInfos_.erase(AOT_BUNDLE_NAME);
}

/**
 * @tc.number: ClearArkAp_NullDataMgr_0100
 * @tc.name: test ClearArkAp with null dataMgr
 * @tc.desc: verify ClearArkAp returns early without crash when dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, ClearArkAp_NullDataMgr_0100, Function | SmallTest | Level1)
{
    ClearDataMgr();
    AOTHandler::GetInstance().ClearArkAp();
    ResetDataMgr();
    ASSERT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: ReportSysEvent_WithEvents_0100
 * @tc.name: test ReportSysEvent with populated event map
 * @tc.desc: verify ReportSysEvent processes event map containing compile records
 *           without corrupting the input data
 */
HWTEST_F(BmsAOTMgrTest, ReportSysEvent_WithEvents_0100, Function | SmallTest | Level1)
{
    std::map<std::string, EventInfo> sysEventMap;
    EventInfo info;
    info.bundleName = AOT_BUNDLE_NAME;
    info.compileResult = true;
    info.costTimeSeconds = 5;
    sysEventMap.emplace(AOT_BUNDLE_NAME, info);
    EXPECT_EQ(sysEventMap.size(), 1);
    AOTHandler::GetInstance().ReportSysEvent(sysEventMap);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL_MILLI_SECONDS));
    EXPECT_EQ(sysEventMap.size(), 1);
    EXPECT_EQ(sysEventMap[AOT_BUNDLE_NAME].compileResult, true);
}

/**
 * @tc.number: OTACompileInternal_StatusSet_0100
 * @tc.name: test OTACompileInternal sets compile status
 * @tc.desc: verify OTACompileInternal sets OTA compile status to END via ScopeGuard
 *           regardless of which branch causes early exit
 */
HWTEST_F(BmsAOTMgrTest, OTACompileInternal_StatusSet_0100, Function | SmallTest | Level1)
{
    system::SetParameter(OTA_COMPILE_MODE, COMPILE_FULL);
    system::SetParameter(UPDATE_TYPE, UPDATE_TYPE_NIGHT);
    AOTHandler::GetInstance().OTACompileInternal();
    std::string status = system::GetParameter("bms.optimizing_apps.status", "");
    EXPECT_EQ(status, "1");
}
} // OHOS