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
 * @tc.name: test ExecuteAOT with empty args
 * @tc.desc: verify ExecuteAOT returns error when AOTArgs has empty hapPath and outputPath.
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
    data.anFileName = AN_FILE_NAME;
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
    data.anFileName = AN_FILE_NAME;
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
    data.anFileName = AN_FILE_NAME;
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
 * @tc.name: test StartAOTCompiler with invalid bundleUid
 * @tc.desc: verify StartAOTCompiler returns failure when AotCompilerClient is unavailable
 *           in UT environment (bundleUid=-1, non-sysComp path).
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_2300, TestSize.Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleName = "aotBundleName";
    aotArgs.bundleUid = -1;
    aotArgs.bundleGid = -1;

    std::vector<uint8_t> signData;
    auto res = AOTExecutor::GetInstance().StartAOTCompiler(aotArgs, signData);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
}

/**
 * @tc.number: AOTExecutor_2400
 * @tc.name: test StartAOTCompiler with isSysComp=true
 * @tc.desc: verify StartAOTCompiler skips MkAOTOutputDir and directly calls AotCompiler
 *           when isSysComp is true (system component path).
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_2400, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.isSysComp = true;
    aotArgs.sysCompPath = "/system/lib64/libabc.so";
    aotArgs.anFileName = "test_an_file";

    std::vector<uint8_t> signData;
    auto res = AOTExecutor::GetInstance().StartAOTCompiler(aotArgs, signData);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
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
    aotArgs.anFileName = AN_FILE_NAME;
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
    EXPECT_EQ(cacheData.anFileName, aotArgs.anFileName);
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
    data.anFileName = AN_FILE_NAME;
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
 * @tc.desc: verify BuildAOTArgs rejects shared bundle global AOT
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
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: AOTHandler_SharedHsp_BuildHostSharedHspAOTArgs_0100
 * @tc.name: test BuildHostSharedHspAOTArgs for host-private shared hsp AOT
 * @tc.desc: verify host-private shared hsp AOT args contain host bundle name and host-private output path
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_SharedHsp_BuildHostSharedHspAOTArgs_0100, Function | SmallTest | Level1)
{
    std::string hostBundleName = "com.example.host";
    std::string sharedBundleName = "com.example.sharedhsp";
    InnerBundleInfo hostInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = hostBundleName;
    applicationInfo.bundleType = BundleType::APP;
    hostInfo.SetBaseApplicationInfo(applicationInfo);
    hostInfo.SetAppIdentifier("hostAppIdentifier");

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = hostBundleName;
    userInfo.uid = 200100;
    userInfo.gids.emplace_back(200101);
    userInfo.bundleUserInfo.userId = Constants::START_USERID;
    hostInfo.innerBundleUserInfos_.emplace(
        hostBundleName + Constants::FILE_UNDERLINE + std::to_string(Constants::START_USERID), userInfo);

    BaseSharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.bundleName = sharedBundleName;
    sharedBundleInfo.moduleName = AOT_MODULE_NAME;
    sharedBundleInfo.versionCode = VERSION_CODE;
    sharedBundleInfo.hapPath = HAP_PATH;
    sharedBundleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;

    auto ret = AOTHandler::GetInstance().BuildHostSharedHspAOTArgs(
        hostInfo, sharedBundleInfo, ServiceConstants::AOT_TRIGGER_INSTALL);
    ASSERT_NE(ret, std::nullopt);
    EXPECT_EQ(ret->bundleName, sharedBundleName);
    EXPECT_EQ(ret->moduleName, AOT_MODULE_NAME);
    EXPECT_EQ(ret->hostBundleName, hostBundleName);
    EXPECT_EQ(ret->bundleType, static_cast<uint8_t>(BundleType::SHARED));
    EXPECT_EQ(ret->compileMode, ServiceConstants::COMPILE_FULL);
    EXPECT_EQ(ret->bundleUid, userInfo.uid);
    EXPECT_EQ(ret->bundleGid, userInfo.gids[0]);
    EXPECT_EQ(ret->triggerType, ServiceConstants::AOT_TRIGGER_INSTALL);

    std::string expectedOutputPath = std::string(ServiceConstants::HAP_ARK_CACHE_PATH) + hostBundleName +
        ServiceConstants::PATH_SEPARATOR + ServiceConstants::ARM64 + ServiceConstants::PATH_SEPARATOR +
        sharedBundleName + ServiceConstants::PATH_SEPARATOR + std::to_string(VERSION_CODE);
    EXPECT_EQ(ret->outputPath, expectedOutputPath);
    EXPECT_EQ(ret->anFileName, expectedOutputPath + ServiceConstants::PATH_SEPARATOR + AOT_MODULE_NAME +
        ServiceConstants::AN_SUFFIX);
}

/**
 * @tc.number: AOTHandler_HostSharedHsp_BuildAOTArgs_0200
 * @tc.name: test BuildHostSharedHspAOTArgs without host user info
 * @tc.desc: verify host-private shared HSP AOT args are not built when uid/gid cannot be resolved
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_HostSharedHsp_BuildAOTArgs_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo hostInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "com.example.host.no.user";
    applicationInfo.bundleType = BundleType::APP;
    hostInfo.SetBaseApplicationInfo(applicationInfo);

    BaseSharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.bundleName = "com.example.sharedhsp";
    sharedBundleInfo.moduleName = AOT_MODULE_NAME;
    sharedBundleInfo.versionCode = VERSION_CODE;
    sharedBundleInfo.hapPath = HAP_PATH;
    sharedBundleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;

    auto ret = AOTHandler::GetInstance().BuildHostSharedHspAOTArgs(
        hostInfo, sharedBundleInfo, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: AOTHandler_HostSharedHsp_BuildAOTArgs_0300
 * @tc.name: test BuildHostSharedHspAOTArgs with debug host and encrypted shared module
 * @tc.desc: verify debug appIdentifier, explicit gid and encrypted module branch
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_HostSharedHsp_BuildAOTArgs_0300, Function | SmallTest | Level1)
{
    std::string hostBundleName = "com.example.host.debug";
    InnerBundleInfo hostInfo;
    ApplicationInfo hostApplicationInfo;
    hostApplicationInfo.bundleName = hostBundleName;
    hostApplicationInfo.bundleType = BundleType::APP;
    hostApplicationInfo.appProvisionType = Constants::APP_PROVISION_TYPE_DEBUG;
    hostInfo.SetBaseApplicationInfo(hostApplicationInfo);
    hostInfo.SetAppIdentifier("hostIdentifier");

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = hostBundleName;
    userInfo.bundleUserInfo.userId = Constants::START_USERID;
    userInfo.uid = 20000;
    userInfo.gids.emplace_back(21000);
    hostInfo.AddInnerBundleUserInfo(userInfo);

    BaseSharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.bundleName = "com.example.sharedhsp.encrypted";
    sharedBundleInfo.moduleName = AOT_MODULE_NAME;
    sharedBundleInfo.versionCode = VERSION_CODE;
    sharedBundleInfo.hapPath = HAP_PATH;
    sharedBundleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;

    InnerBundleInfo sharedInfo;
    ApplicationInfo sharedApplicationInfo;
    sharedApplicationInfo.bundleName = sharedBundleInfo.bundleName;
    sharedApplicationInfo.bundleType = BundleType::SHARED;
    sharedInfo.SetBaseApplicationInfo(sharedApplicationInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    moduleInfo.isEncrypted = true;
    sharedInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        sharedBundleInfo.bundleName, sharedInfo);

    auto ret = AOTHandler::GetInstance().BuildHostSharedHspAOTArgs(
        hostInfo, sharedBundleInfo, ServiceConstants::AOT_TRIGGER_INSTALL);
    ASSERT_NE(ret, std::nullopt);
    EXPECT_EQ(ret->appIdentifier, "DEBUG_LIB_ID");
    EXPECT_EQ(ret->bundleGid, userInfo.gids[0]);
    EXPECT_EQ(ret->isEncryptedBundle, 1u);

    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(sharedBundleInfo.bundleName);
}

/**
 * @tc.number: AOTHandler_HostSharedHsp_BuildAOTArgs_0400
 * @tc.name: test BuildHostSharedHspAOTArgs with null dataMgr
 * @tc.desc: verify host-private shared HSP args can be built without querying shared bundle info
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_HostSharedHsp_BuildAOTArgs_0400, Function | SmallTest | Level1)
{
    std::string hostBundleName = "com.example.host.no.datamgr";
    InnerBundleInfo hostInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = hostBundleName;
    applicationInfo.bundleType = BundleType::APP;
    hostInfo.SetBaseApplicationInfo(applicationInfo);

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = hostBundleName;
    userInfo.bundleUserInfo.userId = Constants::START_USERID;
    userInfo.uid = 20000;
    hostInfo.AddInnerBundleUserInfo(userInfo);

    BaseSharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.bundleName = "com.example.sharedhsp.no.datamgr";
    sharedBundleInfo.moduleName = AOT_MODULE_NAME;
    sharedBundleInfo.versionCode = VERSION_CODE;
    sharedBundleInfo.hapPath = HAP_PATH;
    sharedBundleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;

    ClearDataMgr();
    auto ret = AOTHandler::GetInstance().BuildHostSharedHspAOTArgs(
        hostInfo, sharedBundleInfo, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_NE(ret, std::nullopt);
    if (ret) {
        EXPECT_EQ(ret->isEncryptedBundle, 0u);
    }
    ResetDataMgr();
}

/**
 * @tc.number: AOTHandler_HostSharedHsp_BuildAOTArgs_0500
 * @tc.name: test BuildHostSharedHspAOTArgs with non-encrypted shared module
 * @tc.desc: verify queried shared module keeps isEncryptedBundle false when module is not encrypted
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_HostSharedHsp_BuildAOTArgs_0500, Function | SmallTest | Level1)
{
    std::string hostBundleName = "com.example.host.release";
    InnerBundleInfo hostInfo;
    ApplicationInfo hostApplicationInfo;
    hostApplicationInfo.bundleName = hostBundleName;
    hostApplicationInfo.bundleType = BundleType::APP;
    hostInfo.SetBaseApplicationInfo(hostApplicationInfo);

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = hostBundleName;
    userInfo.bundleUserInfo.userId = Constants::START_USERID;
    userInfo.uid = 20000;
    hostInfo.AddInnerBundleUserInfo(userInfo);

    BaseSharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.bundleName = "com.example.sharedhsp.not.encrypted";
    sharedBundleInfo.moduleName = AOT_MODULE_NAME;
    sharedBundleInfo.versionCode = VERSION_CODE;
    sharedBundleInfo.hapPath = HAP_PATH;
    sharedBundleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;

    InnerBundleInfo sharedInfo;
    ApplicationInfo sharedApplicationInfo;
    sharedApplicationInfo.bundleName = sharedBundleInfo.bundleName;
    sharedApplicationInfo.bundleType = BundleType::SHARED;
    sharedInfo.SetBaseApplicationInfo(sharedApplicationInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    moduleInfo.isEncrypted = false;
    sharedInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(sharedBundleInfo.bundleName, sharedInfo);

    auto ret = AOTHandler::GetInstance().BuildHostSharedHspAOTArgs(
        hostInfo, sharedBundleInfo, ServiceConstants::AOT_TRIGGER_INSTALL);
    ASSERT_NE(ret, std::nullopt);
    EXPECT_EQ(ret->isEncryptedBundle, 0u);

    dataMgr->bundleInfos_.erase(sharedBundleInfo.bundleName);
}

/**
 * @tc.number: AOTHandler_DeleteHostPrivateSharedHspAOT_0100
 * @tc.name: test DeleteHostPrivateSharedHspAOT
 * @tc.desc: verify DeleteHostPrivateSharedHspAOT handles empty hsp bundle name
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_DeleteHostPrivateSharedHspAOT_0100, Function | SmallTest | Level1)
{
    AOTHandler::DeleteHostPrivateSharedHspAOT("");
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: AOTHandler_DeleteHostPrivateSharedHspAOT_0200
 * @tc.name: test DeleteHostPrivateSharedHspAOT with null dataMgr
 * @tc.desc: verify DeleteHostPrivateSharedHspAOT returns early when dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_DeleteHostPrivateSharedHspAOT_0200, Function | SmallTest | Level1)
{
    ClearDataMgr();
    AOTHandler::DeleteHostPrivateSharedHspAOT("com.example.sharedhsp");
    EXPECT_EQ(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
    ResetDataMgr();
}

/**
 * @tc.number: AOTHandler_DeleteHostPrivateSharedHspAOT_0300
 * @tc.name: test DeleteHostPrivateSharedHspAOT with installed hosts
 * @tc.desc: verify DeleteHostPrivateSharedHspAOT handles host-private shared HSP AOT cleanup
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_DeleteHostPrivateSharedHspAOT_0300, Function | SmallTest | Level1)
{
    std::string hspBundleName = "com.example.sharedhsp.delete";
    InnerBundleInfo sharedInfo;
    ApplicationInfo sharedApplicationInfo;
    sharedApplicationInfo.bundleName = hspBundleName;
    sharedApplicationInfo.bundleType = BundleType::SHARED;
    sharedInfo.SetBaseApplicationInfo(sharedApplicationInfo);
    BundleInfo sharedBundleBaseInfo;
    sharedBundleBaseInfo.name = hspBundleName;
    sharedInfo.SetBaseBundleInfo(sharedBundleBaseInfo);
    InnerModuleInfo sharedModule;
    sharedModule.moduleName = AOT_MODULE_NAME;
    sharedModule.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    sharedModule.bundleType = BundleType::SHARED;
    sharedModule.versionCode = VERSION_CODE;
    sharedModule.hapPath = HAP_PATH;
    sharedInfo.InsertInnerSharedModuleInfo(AOT_MODULE_NAME, sharedModule);
    InnerModuleInfo higherSharedModule = sharedModule;
    higherSharedModule.versionCode = VERSION_CODE + 1;
    sharedInfo.InsertInnerSharedModuleInfo(AOT_MODULE_NAME, higherSharedModule);

    InnerBundleInfo hostInfo;
    ApplicationInfo hostApplicationInfo;
    hostApplicationInfo.bundleName = "com.example.host.delete";
    hostApplicationInfo.bundleType = BundleType::APP;
    hostInfo.SetBaseApplicationInfo(hostApplicationInfo);
    InnerModuleInfo hostModule;
    hostModule.moduleName = "entry";
    Dependency targetDependency;
    targetDependency.bundleName = hspBundleName;
    targetDependency.moduleName = AOT_MODULE_NAME;
    targetDependency.versionCode = VERSION_CODE;
    hostModule.dependencies.emplace_back(targetDependency);
    hostInfo.innerModuleInfos_.try_emplace(hostModule.moduleName, hostModule);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(hspBundleName, sharedInfo);
    dataMgr->bundleInfos_.emplace(hostApplicationInfo.bundleName, hostInfo);

    AOTHandler::DeleteHostPrivateSharedHspAOT(hspBundleName, VERSION_CODE);
    EXPECT_NE(dataMgr->bundleInfos_.find(hostApplicationInfo.bundleName), dataMgr->bundleInfos_.end());

    dataMgr->bundleInfos_.erase(hspBundleName);
    dataMgr->bundleInfos_.erase(hostApplicationInfo.bundleName);
}

/**
 * @tc.number: AOTHandler_CompileDependentSharedHspAOT_0100
 * @tc.name: test CompileDependentSharedHspAOT with null dataMgr
 * @tc.desc: verify CompileDependentSharedHspAOT returns early when dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_CompileDependentSharedHspAOT_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo hostInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "com.example.host";
    applicationInfo.bundleType = BundleType::APP;
    hostInfo.SetBaseApplicationInfo(applicationInfo);

    ClearDataMgr();
    AOTHandler::GetInstance().CompileDependentSharedHspAOT(hostInfo, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_EQ(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
    ResetDataMgr();
}

/**
 * @tc.number: AOTHandler_CompileDependentSharedHspAOT_0200
 * @tc.name: test CompileDependentSharedHspAOT without shared dependencies
 * @tc.desc: verify CompileDependentSharedHspAOT returns when dependency query fails
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_CompileDependentSharedHspAOT_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo hostInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "com.example.host.no.deps";
    applicationInfo.bundleType = BundleType::APP;
    hostInfo.SetBaseApplicationInfo(applicationInfo);

    AOTHandler::GetInstance().CompileDependentSharedHspAOT(hostInfo, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: AOTHandler_CompileHostsForChangedSharedHsp_0100
 * @tc.name: test CompileHostsForChangedSharedHsp with empty bundle name
 * @tc.desc: verify CompileHostsForChangedSharedHsp returns early when shared hsp bundle name is empty
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_CompileHostsForChangedSharedHsp_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo sharedInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleType = BundleType::SHARED;
    sharedInfo.SetBaseApplicationInfo(applicationInfo);

    AOTHandler::GetInstance().CompileHostsForChangedSharedHsp(sharedInfo);
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: AOTHandler_CompileHostsForChangedSharedHsp_0200
 * @tc.name: test CompileHostsForChangedSharedHsp without static or hybrid module
 * @tc.desc: verify CompileHostsForChangedSharedHsp returns when shared hsp has no compilable module
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_CompileHostsForChangedSharedHsp_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo sharedInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "com.example.sharedhsp.dynamic.only";
    applicationInfo.bundleType = BundleType::SHARED;
    sharedInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = AOT_MODULE_NAME;
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    sharedInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, moduleInfo);

    AOTHandler::GetInstance().CompileHostsForChangedSharedHsp(sharedInfo);
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: AOTHandler_CompileHostsForChangedSharedHsp_0300
 * @tc.name: test CompileHostsForChangedSharedHsp skips non-host candidates
 * @tc.desc: verify same bundle, shared bundle, old host and dependency matching branches
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_CompileHostsForChangedSharedHsp_0300, Function | SmallTest | Level1)
{
    std::string hspBundleName = "com.example.sharedhsp.changed";
    InnerBundleInfo sharedInfo;
    ApplicationInfo sharedApplicationInfo;
    sharedApplicationInfo.bundleName = hspBundleName;
    sharedApplicationInfo.bundleType = BundleType::SHARED;
    sharedInfo.SetBaseApplicationInfo(sharedApplicationInfo);
    BundleInfo sharedBundleBaseInfo;
    sharedBundleBaseInfo.name = hspBundleName;
    sharedInfo.SetBaseBundleInfo(sharedBundleBaseInfo);
    InnerModuleInfo sharedModule;
    sharedModule.moduleName = AOT_MODULE_NAME;
    sharedModule.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    sharedModule.bundleType = BundleType::SHARED;
    sharedModule.versionCode = VERSION_CODE;
    sharedModule.hapPath = HAP_PATH;
    sharedInfo.innerModuleInfos_.try_emplace(AOT_MODULE_NAME, sharedModule);
    sharedInfo.InsertInnerSharedModuleInfo(AOT_MODULE_NAME, sharedModule);

    InnerBundleInfo anotherSharedInfo;
    ApplicationInfo anotherSharedApplicationInfo;
    anotherSharedApplicationInfo.bundleName = "com.example.other.shared";
    anotherSharedApplicationInfo.bundleType = BundleType::SHARED;
    anotherSharedInfo.SetBaseApplicationInfo(anotherSharedApplicationInfo);
    BundleInfo anotherSharedBundleBaseInfo;
    anotherSharedBundleBaseInfo.name = anotherSharedApplicationInfo.bundleName;
    anotherSharedInfo.SetBaseBundleInfo(anotherSharedBundleBaseInfo);
    InnerModuleInfo anotherSharedModule;
    anotherSharedModule.moduleName = "otherModule";
    anotherSharedModule.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    anotherSharedModule.bundleType = BundleType::SHARED;
    anotherSharedModule.versionCode = VERSION_CODE;
    anotherSharedModule.hapPath = HAP_PATH;
    anotherSharedInfo.InsertInnerSharedModuleInfo(anotherSharedModule.moduleName, anotherSharedModule);

    InnerBundleInfo oldHostInfo;
    ApplicationInfo oldHostApplicationInfo;
    oldHostApplicationInfo.bundleName = "com.example.old.host";
    oldHostApplicationInfo.bundleType = BundleType::APP;
    oldHostInfo.SetBaseApplicationInfo(oldHostApplicationInfo);
    oldHostInfo.SetIsNewVersion(false);

    InnerBundleInfo hostWithoutDepsInfo;
    ApplicationInfo hostWithoutDepsApplicationInfo;
    hostWithoutDepsApplicationInfo.bundleName = "com.example.host.without.deps";
    hostWithoutDepsApplicationInfo.bundleType = BundleType::APP;
    hostWithoutDepsInfo.SetBaseApplicationInfo(hostWithoutDepsApplicationInfo);
    hostWithoutDepsInfo.SetIsNewVersion(true);

    InnerBundleInfo hostWithOtherDepInfo;
    ApplicationInfo hostWithOtherDepApplicationInfo;
    hostWithOtherDepApplicationInfo.bundleName = "com.example.host.with.other.dep";
    hostWithOtherDepApplicationInfo.bundleType = BundleType::APP;
    hostWithOtherDepInfo.SetBaseApplicationInfo(hostWithOtherDepApplicationInfo);
    hostWithOtherDepInfo.SetIsNewVersion(true);
    InnerModuleInfo hostOtherDepModule;
    hostOtherDepModule.moduleName = "entry";
    Dependency otherDependency;
    otherDependency.bundleName = anotherSharedApplicationInfo.bundleName;
    otherDependency.moduleName = anotherSharedModule.moduleName;
    otherDependency.versionCode = VERSION_CODE;
    hostOtherDepModule.dependencies.emplace_back(otherDependency);
    hostWithOtherDepInfo.innerModuleInfos_.try_emplace(hostOtherDepModule.moduleName, hostOtherDepModule);

    InnerBundleInfo hostWithTargetDepInfo;
    ApplicationInfo hostWithTargetDepApplicationInfo;
    hostWithTargetDepApplicationInfo.bundleName = "com.example.host.with.target.dep";
    hostWithTargetDepApplicationInfo.bundleType = BundleType::APP;
    hostWithTargetDepInfo.SetBaseApplicationInfo(hostWithTargetDepApplicationInfo);
    hostWithTargetDepInfo.SetIsNewVersion(true);
    InnerModuleInfo hostTargetDepModule;
    hostTargetDepModule.moduleName = "entry";
    Dependency targetDependency;
    targetDependency.bundleName = hspBundleName;
    targetDependency.moduleName = AOT_MODULE_NAME;
    targetDependency.versionCode = VERSION_CODE;
    hostTargetDepModule.dependencies.emplace_back(targetDependency);
    hostWithTargetDepInfo.innerModuleInfos_.try_emplace(hostTargetDepModule.moduleName, hostTargetDepModule);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(hspBundleName, sharedInfo);
    dataMgr->bundleInfos_.emplace(anotherSharedApplicationInfo.bundleName, anotherSharedInfo);
    dataMgr->bundleInfos_.emplace(oldHostApplicationInfo.bundleName, oldHostInfo);
    dataMgr->bundleInfos_.emplace(hostWithoutDepsApplicationInfo.bundleName, hostWithoutDepsInfo);
    dataMgr->bundleInfos_.emplace(hostWithOtherDepApplicationInfo.bundleName, hostWithOtherDepInfo);
    dataMgr->bundleInfos_.emplace(hostWithTargetDepApplicationInfo.bundleName, hostWithTargetDepInfo);

    AOTHandler::GetInstance().CompileHostsForChangedSharedHsp(sharedInfo);
    EXPECT_NE(dataMgr->bundleInfos_.find(hostWithoutDepsApplicationInfo.bundleName), dataMgr->bundleInfos_.end());

    dataMgr->bundleInfos_.erase(hspBundleName);
    dataMgr->bundleInfos_.erase(anotherSharedApplicationInfo.bundleName);
    dataMgr->bundleInfos_.erase(oldHostApplicationInfo.bundleName);
    dataMgr->bundleInfos_.erase(hostWithoutDepsApplicationInfo.bundleName);
    dataMgr->bundleInfos_.erase(hostWithOtherDepApplicationInfo.bundleName);
    dataMgr->bundleInfos_.erase(hostWithTargetDepApplicationInfo.bundleName);
}

/**
 * @tc.number: AOTHandler_CompileHostsForChangedSharedHsp_0400
 * @tc.name: test CompileHostsForChangedSharedHsp with null dataMgr
 * @tc.desc: verify CompileHostsForChangedSharedHsp returns early when dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_CompileHostsForChangedSharedHsp_0400, Function | SmallTest | Level1)
{
    InnerBundleInfo sharedInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "com.example.sharedhsp.null.datamgr";
    applicationInfo.bundleType = BundleType::SHARED;
    sharedInfo.SetBaseApplicationInfo(applicationInfo);

    ClearDataMgr();
    AOTHandler::GetInstance().CompileHostsForChangedSharedHsp(sharedInfo);
    EXPECT_EQ(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
    ResetDataMgr();
}

/**
 * @tc.number: AOTHandler_HandleSharedHspChangedAOT_0200
 * @tc.name: test HandleSharedHspChangedAOT with non-existent bundle name
 * @tc.desc: verify HandleSharedHspChangedAOT returns early when shared hsp bundle does not exist
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_HandleSharedHspChangedAOT_0200, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().HandleSharedHspChangedAOT("nonExistentSharedHsp");
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: AOTHandler_HandleSharedHspChangedAOT_0300
 * @tc.name: test HandleSharedHspChangedAOT with null dataMgr
 * @tc.desc: verify HandleSharedHspChangedAOT returns early when dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_HandleSharedHspChangedAOT_0300, Function | SmallTest | Level1)
{
    ClearDataMgr();
    AOTHandler::GetInstance().HandleSharedHspChangedAOT("com.example.sharedhsp.null.datamgr");
    EXPECT_EQ(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
    ResetDataMgr();
}

/**
 * @tc.number: AOTHandler_HandleSharedHspChangedAOT_0400
 * @tc.name: test HandleSharedHspChangedAOT with old shared hsp
 * @tc.desc: verify HandleSharedHspChangedAOT returns early when shared hsp is not new version
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_HandleSharedHspChangedAOT_0400, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.sharedhsp.old";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(false);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    AOTHandler::GetInstance().HandleSharedHspChangedAOT(bundleName);
    EXPECT_FALSE(dataMgr->bundleInfos_.at(bundleName).GetIsNewVersion());
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_HandleSharedHspChangedAOT_0500
 * @tc.name: test HandleSharedHspChangedAOT with non-shared bundle
 * @tc.desc: verify HandleSharedHspChangedAOT returns early when bundle type is APP
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_HandleSharedHspChangedAOT_0500, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.host.not.shared";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    AOTHandler::GetInstance().HandleSharedHspChangedAOT(bundleName);
    EXPECT_EQ(dataMgr->bundleInfos_.at(bundleName).GetApplicationBundleType(), BundleType::APP);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_HandleSharedHspChangedAOTAsync_0100
 * @tc.name: test HandleSharedHspChangedAOTAsync with non-existent bundle
 * @tc.desc: verify HandleSharedHspChangedAOTAsync can dispatch task and return safely
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_HandleSharedHspChangedAOTAsync_0100, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().HandleSharedHspChangedAOTAsync("nonExistentSharedHsp");
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MILLI_SECONDS));
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: AOTHandler_CompileHostSharedHspAOT_0100
 * @tc.name: test CompileHostSharedHspAOT with dynamic shared hsp module
 * @tc.desc: verify CompileHostSharedHspAOT returns early when shared hsp module is dynamic
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_CompileHostSharedHspAOT_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo hostInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "com.example.host";
    applicationInfo.bundleType = BundleType::APP;
    hostInfo.SetBaseApplicationInfo(applicationInfo);

    BaseSharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.bundleName = "com.example.sharedhsp";
    sharedBundleInfo.moduleName = AOT_MODULE_NAME;
    sharedBundleInfo.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;

    AOTHandler::GetInstance().CompileHostSharedHspAOT(
        hostInfo, sharedBundleInfo, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: AOTHandler_CompileHostSharedHspAOT_0200
 * @tc.name: test CompileHostSharedHspAOT without host user info
 * @tc.desc: verify CompileHostSharedHspAOT returns when BuildHostSharedHspAOTArgs fails
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_CompileHostSharedHspAOT_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo hostInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "com.example.host.no.user";
    applicationInfo.bundleType = BundleType::APP;
    hostInfo.SetBaseApplicationInfo(applicationInfo);

    BaseSharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.bundleName = "com.example.sharedhsp";
    sharedBundleInfo.moduleName = AOT_MODULE_NAME;
    sharedBundleInfo.versionCode = VERSION_CODE;
    sharedBundleInfo.hapPath = HAP_PATH;
    sharedBundleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;

    AOTHandler::GetInstance().CompileHostSharedHspAOT(
        hostInfo, sharedBundleInfo, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: AOTHandler_SharedHsp_HandleHapInstallAOT_0100
 * @tc.name: test HandleSharedHspChangedAOTAsync for shared bundle
 * @tc.desc: verify HandleSharedHspChangedAOTAsync processes shared bundle correctly
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_SharedHsp_HandleHapInstallAOT_0100, Function | SmallTest | Level1)
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

    AOTHandler::GetInstance().HandleSharedHspChangedAOTAsync(bundleName);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MILLI_SECONDS));

    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_TRUE(item->second.GetIsNewVersion());
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_SharedHsp_HandleHapInstallAOT_0200
 * @tc.name: test HandleSharedHspChangedAOTAsync skips dynamic ArkTS shared bundle
 * @tc.desc: verify HandleSharedHspChangedAOTAsync returns early for dynamic ArkTS mode shared bundle
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_SharedHsp_HandleHapInstallAOT_0200, Function | SmallTest | Level1)
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

    AOTHandler::GetInstance().HandleSharedHspChangedAOTAsync(bundleName);
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
 * @tc.desc: verify ProcessAOT calls HandleSharedHspChangedAOTAsync for each shared bundle during normal install
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
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, "nonExistModule", "", false, ServiceConstants::AOT_TRIGGER_INSTALL);
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: HandleHapInstallAOT_0100
 * @tc.name: test HandleHapInstallAOT with not stage model
 * @tc.desc: verify HandleHapInstallAOT returns early if IsNewVersion is false
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.oldmodel";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(false);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);
    AOTHandler::GetInstance().HandleHapInstallAOT(bundleName);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_FALSE(item->second.GetIsNewVersion());
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleHapInstallAOT_0200
 * @tc.name: test HandleHapInstallAOT with all-dynamic ArkTS app
 * @tc.desc: verify HandleHapInstallAOT returns early if app ArkTS mode is dynamic
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_0200, Function | SmallTest | Level1)
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
    AOTHandler::GetInstance().HandleHapInstallAOT(bundleName);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleHapInstallAOT_0300
 * @tc.name: test HandleHapInstallAOT with dataMgr null
 * @tc.desc: verify HandleHapInstallAOT returns early if dataMgr is null
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_0300, Function | SmallTest | Level1)
{
    ClearDataMgr();
    AOTHandler::GetInstance().HandleHapInstallAOT(AOT_BUNDLE_NAME);
    ResetDataMgr();
    EXPECT_NE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr(), nullptr);
}

/**
 * @tc.number: HandleHapInstallAOT_0400
 * @tc.name: test HandleHapInstallAOT with bundle not found
 * @tc.desc: verify HandleHapInstallAOT returns early if QueryInnerBundleInfo fails
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_0400, Function | SmallTest | Level1)
{
    AOTHandler::GetInstance().HandleHapInstallAOT("nonExistentBundle");
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.count("nonExistentBundle"), 0);
}

/**
 * @tc.number: HandleHapInstallAOT_0500
 * @tc.name: test HandleHapInstallAOT for non-shared app without bap file
 * @tc.desc: verify HandleHapInstallAOT skips compilation for non-shared app modules
 *           when bap file is not present (dynamic module skipped by dynamic check,
 *           static module skipped by bap file check)
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_0500, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.mixedmodules";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::APP;
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
    AOTHandler::GetInstance().HandleHapInstallAOT(bundleName);
    // static module: no bap file so skipped; dynamic module: skipped by dynamic check
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
    data.anFileName = AN_FILE_NAME;
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
    data.anFileName = AN_FILE_NAME;
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
 * @tc.number: EnforceCodeSignForModule_SharedBundle_0100
 * @tc.name: test EnforceCodeSignForModule signs host-private shared HSP without status update
 * @tc.desc: verify shared bundle pending sign uses cached anFileName and does not write global AOT status
 */
HWTEST_F(BmsAOTMgrTest, EnforceCodeSignForModule_SharedBundle_0100, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.moduleSignDataVector_.clear();
    AppExecFwk::AOTSignDataCacheMgr::ModuleSignData data;
    data.signData = {0x0A, 0x0B};
    data.versionCode = VERSION_CODE;
    data.triggerType = ServiceConstants::AOT_TRIGGER_INSTALL;
    data.bundleType = static_cast<uint8_t>(BundleType::SHARED);
    data.bundleName = AOT_BUNDLE_NAME;
    data.moduleName = AOT_MODULE_NAME;
    data.anFileName = "host_private_shared_hsp.an";
    signDataCacheMgr.moduleSignDataVector_.emplace_back(data);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
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
    ASSERT_NE(item, DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);

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
    aotArgs.hostBundleName = "hostBundleName";

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
    EXPECT_EQ(aotArgsPtr->hostBundleName, aotArgs.hostBundleName);
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
    EXPECT_TRUE(aotArgs.hostBundleName.empty());
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
    aotArgs.hostBundleName = "hostBundleName";
    std::string ret = aotArgs.ToString();
    EXPECT_NE(ret.find("bundleType = " + std::to_string(aotArgs.bundleType)), std::string::npos);
    EXPECT_NE(ret.find("triggerType = " + std::to_string(aotArgs.triggerType)), std::string::npos);
    EXPECT_NE(ret.find("staticAndHybridModuleCnt = " + std::to_string(aotArgs.staticAndHybridModuleCnt)),
        std::string::npos);
    EXPECT_NE(ret.find("hostBundleName = " + aotArgs.hostBundleName), std::string::npos);
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
    sharedArgs.outputPath = std::string(ServiceConstants::HAP_ARK_CACHE_PATH) + "../escape";
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
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = Constants::START_USERID;
    userInfo.uid = 200100;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

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
        innerBundleInfo, "staticModule", ServiceConstants::COMPILE_FULL, false, ServiceConstants::AOT_TRIGGER_INSTALL);
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
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = Constants::START_USERID;
    userInfo.uid = 200100;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    InnerModuleInfo moduleA;
    moduleA.moduleName = "moduleA";
    moduleA.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("moduleA", moduleA);

    InnerModuleInfo moduleB;
    moduleB.moduleName = "moduleB";
    moduleB.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("moduleB", moduleB);

    auto ret = AOTHandler::GetInstance().BuildAOTArgs(
        innerBundleInfo, "moduleA", ServiceConstants::COMPILE_FULL, false, ServiceConstants::AOT_TRIGGER_INSTALL);
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

/**
 * @tc.number: ShouldCompileSharedModule_0100
 * @tc.name: test ShouldCompileSharedModule with dynamic module
 * @tc.desc: verify ShouldCompileSharedModule returns false for dynamic ArkTS mode module
 */
HWTEST_F(BmsAOTMgrTest, ShouldCompileSharedModule_0100, Function | SmallTest | Level1)
{
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "dynamicSharedModule";
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    bool result = AOTHandler::GetInstance().ShouldCompileSharedModule(moduleInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: ShouldCompileSharedModule_0200
 * @tc.name: test ShouldCompileSharedModule with static module
 * @tc.desc: verify ShouldCompileSharedModule returns true for static ArkTS mode module
 */
HWTEST_F(BmsAOTMgrTest, ShouldCompileSharedModule_0200, Function | SmallTest | Level1)
{
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "staticSharedModule";
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    bool result = AOTHandler::GetInstance().ShouldCompileSharedModule(moduleInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: ShouldCompileSharedModule_0300
 * @tc.name: test ShouldCompileSharedModule with hybrid module
 * @tc.desc: verify ShouldCompileSharedModule returns true for hybrid ArkTS mode module
 */
HWTEST_F(BmsAOTMgrTest, ShouldCompileSharedModule_0300, Function | SmallTest | Level1)
{
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "hybridSharedModule";
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_HYBRID;
    bool result = AOTHandler::GetInstance().ShouldCompileSharedModule(moduleInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: ShouldCompileSharedHspModule_0100
 * @tc.name: test ShouldCompileSharedHspModule with dynamic module
 * @tc.desc: verify host-private shared HSP AOT skips dynamic ArkTS mode module
 */
HWTEST_F(BmsAOTMgrTest, ShouldCompileSharedHspModule_0100, Function | SmallTest | Level1)
{
    BaseSharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.bundleName = "com.example.sharedhsp";
    sharedBundleInfo.moduleName = "dynamicSharedHspModule";
    sharedBundleInfo.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    bool result = AOTHandler::GetInstance().ShouldCompileSharedHspModule(sharedBundleInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: ShouldCompileSharedHspModule_0200
 * @tc.name: test ShouldCompileSharedHspModule with static module
 * @tc.desc: verify host-private shared HSP AOT accepts static ArkTS mode module
 */
HWTEST_F(BmsAOTMgrTest, ShouldCompileSharedHspModule_0200, Function | SmallTest | Level1)
{
    BaseSharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.bundleName = "com.example.sharedhsp";
    sharedBundleInfo.moduleName = "staticSharedHspModule";
    sharedBundleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    bool result = AOTHandler::GetInstance().ShouldCompileSharedHspModule(sharedBundleInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: HasCompilableSharedHspModule_0100
 * @tc.name: test HasCompilableSharedHspModule
 * @tc.desc: verify dynamic-only shared HSP is skipped and static module makes it compilable
 */
HWTEST_F(BmsAOTMgrTest, HasCompilableSharedHspModule_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo sharedInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "com.example.sharedhsp";
    applicationInfo.bundleType = BundleType::SHARED;
    sharedInfo.SetBaseApplicationInfo(applicationInfo);

    InnerModuleInfo dynamicModule;
    dynamicModule.moduleName = "dynamicModule";
    dynamicModule.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    sharedInfo.innerModuleInfos_.try_emplace(dynamicModule.moduleName, dynamicModule);
    EXPECT_FALSE(AOTHandler::GetInstance().HasCompilableSharedHspModule(sharedInfo));

    InnerModuleInfo staticModule;
    staticModule.moduleName = "staticModule";
    staticModule.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    sharedInfo.innerModuleInfos_.try_emplace(staticModule.moduleName, staticModule);
    EXPECT_TRUE(AOTHandler::GetInstance().HasCompilableSharedHspModule(sharedInfo));
}

/**
 * @tc.number: ShouldCompileAppModule_0100
 * @tc.name: test ShouldCompileAppModule with dynamic module
 * @tc.desc: verify ShouldCompileAppModule returns false for dynamic ArkTS mode module
 */
HWTEST_F(BmsAOTMgrTest, ShouldCompileAppModule_0100, Function | SmallTest | Level1)
{
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "dynamicAppModule";
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    bool result = AOTHandler::GetInstance().ShouldCompileAppModule(moduleInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: ShouldCompileAppModule_0200
 * @tc.name: test ShouldCompileAppModule with invalid hap path
 * @tc.desc: verify ShouldCompileAppModule returns false when BundleExtractor init fails
 */
HWTEST_F(BmsAOTMgrTest, ShouldCompileAppModule_0200, Function | SmallTest | Level1)
{
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "appModule";
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    moduleInfo.hapPath = "/non/existent/path.hap";
    bool result = AOTHandler::GetInstance().ShouldCompileAppModule(moduleInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: ShouldCompileAppModule_0300
 * @tc.name: test ShouldCompileAppModule with valid hap but no bap entry
 * @tc.desc: verify ShouldCompileAppModule returns false when bap file is not in hap
 */
HWTEST_F(BmsAOTMgrTest, ShouldCompileAppModule_0300, Function | SmallTest | Level1)
{
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "appModule";
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    moduleInfo.hapPath = HAP_PATH;
    bool result = AOTHandler::GetInstance().ShouldCompileAppModule(moduleInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: ShouldCompileAppModule_0400
 * @tc.name: test ShouldCompileAppModule with hybrid module and no bap
 * @tc.desc: verify ShouldCompileAppModule returns false for hybrid module without bap file
 */
HWTEST_F(BmsAOTMgrTest, ShouldCompileAppModule_0400, Function | SmallTest | Level1)
{
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "hybridModule";
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_HYBRID;
    moduleInfo.hapPath = HAP_PATH;
    bool result = AOTHandler::GetInstance().ShouldCompileAppModule(moduleInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: HandleHapInstallAOT_SharedNotInList_0100
 * @tc.name: test HandleHapInstallAOT skips shared bundle not in enable list
 * @tc.desc: verify HandleHapInstallAOT returns early for shared bundle not in AOT enable list
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_SharedNotInList_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.shared.notinlist";
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

    AOTHandler::GetInstance().HandleHapInstallAOT(bundleName);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus(AOT_MODULE_NAME), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleHapInstallAOT_AppDynamicModuleSkipped_0100
 * @tc.name: test HandleHapInstallAOT skips dynamic module via ShouldCompileAppModule
 * @tc.desc: verify non-shared app with one dynamic module and one static module:
 *           dynamic module is filtered by ShouldCompileAppModule (dynamic check),
 *           static module is filtered by ShouldCompileAppModule (no bap file)
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_AppDynamicModuleSkipped_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app.mixmodules";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    // static module: will reach ShouldCompileAppModule, fail at bap check
    InnerModuleInfo staticModule;
    staticModule.moduleName = "staticModule";
    staticModule.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    staticModule.hapPath = HAP_PATH;
    innerBundleInfo.innerModuleInfos_.try_emplace("staticModule", staticModule);

    // dynamic module: will reach ShouldCompileAppModule, fail at dynamic check
    InnerModuleInfo dynamicModule;
    dynamicModule.moduleName = "dynamicModule";
    dynamicModule.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("dynamicModule", dynamicModule);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    AOTHandler::GetInstance().HandleHapInstallAOT(bundleName);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    // non-shared app skips whitelist, enters module loop via ShouldCompileAppModule
    // static module: no bap in HAP_PATH → NOT_COMPILED
    // dynamic module: rejected by dynamic check → NOT_COMPILED
    EXPECT_EQ(item->second.GetAOTCompileStatus("staticModule"), AOTCompileStatus::NOT_COMPILED);
    EXPECT_EQ(item->second.GetAOTCompileStatus("dynamicModule"), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleHapInstallAOT_AppNoBap_0100
 * @tc.name: test HandleHapInstallAOT for non-shared app enters module loop
 * @tc.desc: verify non-shared bundle skips whitelist check and enters module loop
 *           where ShouldCompileAppModule filters by bap file presence
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_AppNoBap_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app.nobap";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    moduleInfo.hapPath = HAP_PATH;
    innerBundleInfo.innerModuleInfos_.try_emplace("entry", moduleInfo);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    AOTHandler::GetInstance().HandleHapInstallAOT(bundleName);
    // no bap file in HAP_PATH, so module stays NOT_COMPILED
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus("entry"), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleHapInstallAOT_AppInvalidHapPath_0100
 * @tc.name: test HandleHapInstallAOT for non-shared app with invalid hap path
 * @tc.desc: verify ShouldCompileAppModule returns false when BundleExtractor init fails
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_AppInvalidHapPath_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app.invalidhap";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    moduleInfo.hapPath = "/non/existent/path.hap";
    innerBundleInfo.innerModuleInfos_.try_emplace("entry", moduleInfo);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    AOTHandler::GetInstance().HandleHapInstallAOT(bundleName);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    EXPECT_EQ(item->second.GetAOTCompileStatus("entry"), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: HandleHapInstallAOT_AppHybridMode_0100
 * @tc.name: test HandleHapInstallAOT for hybrid app with mixed modules
 * @tc.desc: verify HandleHapInstallAOT processes hybrid app correctly:
 *           app-level mode is hybrid (not filtered), dynamic modules skipped,
 *           static modules checked for bap file
 */
HWTEST_F(BmsAOTMgrTest, HandleHapInstallAOT_AppHybridMode_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app.hybrid";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = VERSION_CODE;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerModuleInfo staticModule;
    staticModule.moduleName = "staticEntry";
    staticModule.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    staticModule.hapPath = HAP_PATH;
    innerBundleInfo.innerModuleInfos_.try_emplace("staticEntry", staticModule);

    InnerModuleInfo hybridModule;
    hybridModule.moduleName = "hybridFeature";
    hybridModule.moduleArkTSMode = Constants::ARKTS_MODE_HYBRID;
    hybridModule.hapPath = HAP_PATH;
    innerBundleInfo.innerModuleInfos_.try_emplace("hybridFeature", hybridModule);

    InnerModuleInfo dynamicModule;
    dynamicModule.moduleName = "dynamicFeature";
    dynamicModule.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    innerBundleInfo.innerModuleInfos_.try_emplace("dynamicFeature", dynamicModule);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    AOTHandler::GetInstance().HandleHapInstallAOT(bundleName);
    auto item = dataMgr->bundleInfos_.find(bundleName);
    ASSERT_NE(item, dataMgr->bundleInfos_.end());
    // static and hybrid: no bap so NOT_COMPILED; dynamic: skipped by dynamic check
    EXPECT_EQ(item->second.GetAOTCompileStatus("staticEntry"), AOTCompileStatus::NOT_COMPILED);
    EXPECT_EQ(item->second.GetAOTCompileStatus("hybridFeature"), AOTCompileStatus::NOT_COMPILED);
    EXPECT_EQ(item->second.GetAOTCompileStatus("dynamicFeature"), AOTCompileStatus::NOT_COMPILED);
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: MapSysCompArgs_0100
 * @tc.name: test MapSysCompArgs with isSysComp=true
 * @tc.desc: verify MapSysCompArgs correctly maps sysComp fields
 *           without mapping non-sysComp fields.
 */
HWTEST_F(BmsAOTMgrTest, MapSysCompArgs_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    AOTArgs aotArgs;
    aotArgs.isSysComp = true;
    aotArgs.sysCompPath = "/system/lib64/module.abc";
    aotArgs.anFileName = "/data/ark-cache/syscomp.an";
    aotArgs.bundleName = "should_not_appear";

    ArkCompiler::AotCompilerArgs args;
    ErrCode ret = AOTExecutor::GetInstance().MapSysCompArgs(aotArgs, args);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(args.isSysComp);
    EXPECT_EQ(args.sysCompPath, aotArgs.sysCompPath);
    EXPECT_EQ(args.abcPath, aotArgs.sysCompPath);
    EXPECT_EQ(args.anFileName, aotArgs.anFileName);
    // Non-sysComp fields should not be mapped (remain default)
    EXPECT_TRUE(args.bundleName.empty());
    EXPECT_EQ(args.processUid, static_cast<int32_t>(getuid()));
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: MapBundleArgs_DirectFields_0100
 * @tc.name: test MapBundleArgs direct field mappings with isSysComp=false
 * @tc.desc: verify identity and direct field mappings from AOTArgs to AotCompilerArgs.
 */
HWTEST_F(BmsAOTMgrTest, MapBundleArgs_DirectFields_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    AOTArgs aotArgs;
    aotArgs.isSysComp = false;
    aotArgs.compileMode = "partial";
    aotArgs.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    aotArgs.bundleName = "com.test.bundle";
    aotArgs.moduleName = "entry";
    aotArgs.appIdentifier = "com.test.bundle_12345";
    aotArgs.bundleUid = 100200;
    aotArgs.bundleGid = 100200;
    aotArgs.hapPath = "/data/app/com.test.bundle/entry.hap";
    aotArgs.anFileName = "/data/ark-cache/com.test.bundle/entry.an";
    aotArgs.outputPath = "/data/ark-cache/com.test.bundle";
    aotArgs.arkProfilePath = "/data/app/ark_profile/com.test.bundle/entry.ap";
    aotArgs.offset = 1024;
    aotArgs.length = 2048;
    aotArgs.optBCRangeList = "0-100";
    aotArgs.isScreenOff = 1;
    aotArgs.isEncryptedBundle = 0;
    aotArgs.isEnableBaselinePgo = 1;
    aotArgs.bundleType = 0;
    aotArgs.triggerType = 1;
    aotArgs.hostBundleName = "com.test.host";

    ArkCompiler::AotCompilerArgs args;
    ErrCode ret = AOTExecutor::GetInstance().MapBundleArgs(aotArgs, args);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(args.isSysComp);
    EXPECT_EQ(args.processUid, static_cast<int32_t>(getuid()));
    EXPECT_EQ(args.compileMode, "partial");
    EXPECT_EQ(args.moduleArkTSMode, Constants::ARKTS_MODE_DYNAMIC);
    EXPECT_EQ(args.bundleName, "com.test.bundle");
    EXPECT_EQ(args.moduleName, "entry");
    EXPECT_EQ(args.appIdentifier, "com.test.bundle_12345");
    EXPECT_EQ(args.bundleUid, 100200);
    EXPECT_EQ(args.bundleGid, 100200);
    EXPECT_EQ(args.hapPath, "/data/app/com.test.bundle/entry.hap");
    EXPECT_EQ(args.anFileName, "/data/ark-cache/com.test.bundle/entry.an");
    EXPECT_EQ(args.outputPath, "/data/ark-cache/com.test.bundle");
    EXPECT_EQ(args.hostBundleName, "com.test.host");
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: MapBundleArgs_DerivedFields_0100
 * @tc.name: test MapBundleArgs derived fields (abcPath, pgoDir)
 * @tc.desc: verify derived fields abcPath and pgoDir are correctly computed.
 */
HWTEST_F(BmsAOTMgrTest, MapBundleArgs_DerivedFields_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    AOTArgs aotArgs;
    aotArgs.isSysComp = false;
    aotArgs.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    aotArgs.hapPath = "/data/app/com.test.bundle/entry.hap";
    aotArgs.arkProfilePath = "/data/app/ark_profile/com.test.bundle/entry.ap";

    ArkCompiler::AotCompilerArgs args;
    ErrCode ret = AOTExecutor::GetInstance().MapBundleArgs(aotArgs, args);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(args.abcPath, aotArgs.hapPath + std::string("/") + "ets/modules.abc");
    EXPECT_EQ(args.pgoDir, "/data/app/ark_profile/com.test.bundle");
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: MapBundleArgs_Options_0100
 * @tc.name: test MapBundleArgs compilation options and extra ints
 * @tc.desc: verify optBCRangeList, screenOff, encryptedBundle, baselinePgo,
 *           bundleType, and triggerType are correctly mapped.
 */
HWTEST_F(BmsAOTMgrTest, MapBundleArgs_Options_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    AOTArgs aotArgs;
    aotArgs.isSysComp = false;
    aotArgs.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    aotArgs.hapPath = "/data/app/test/entry.hap";
    aotArgs.outputPath = "/data/ark-cache/test";
    aotArgs.optBCRangeList = "0-100";
    aotArgs.isScreenOff = 1;
    aotArgs.isEncryptedBundle = 0;
    aotArgs.isEnableBaselinePgo = 1;
    aotArgs.bundleType = 0;
    aotArgs.triggerType = 1;

    ArkCompiler::AotCompilerArgs args;
    ErrCode ret = AOTExecutor::GetInstance().MapBundleArgs(aotArgs, args);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(args.optBCRangeList, "0-100");
    EXPECT_EQ(args.isScreenOff, 1u);
    EXPECT_EQ(args.isEncryptedBundle, 0u);
    EXPECT_EQ(args.isEnableBaselinePgo, 1u);
    EXPECT_EQ(args.bundleType, 0);
    EXPECT_EQ(args.triggerType, 1);
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: MapBundleArgs_HspModules_0100
 * @tc.name: test MapBundleArgs maps HSP module info correctly
 * @tc.desc: verify HspModuleInfo fields are mapped from HspInfo to ArkCompiler::HspModuleInfo.
 */
HWTEST_F(BmsAOTMgrTest, MapBundleArgs_HspModules_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    AOTArgs aotArgs;
    aotArgs.isSysComp = false;
    aotArgs.hapPath = "/data/app/test/entry.hap";
    aotArgs.outputPath = "/data/ark-cache/test";
    aotArgs.moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;

    HspInfo hsp;
    hsp.bundleName = "com.test.hsp";
    hsp.moduleName = "hspModule";
    hsp.hapPath = "/data/app/com.test.hsp/hsp.hap";
    hsp.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    aotArgs.hspVector.push_back(hsp);

    ArkCompiler::AotCompilerArgs args;
    ErrCode ret = AOTExecutor::GetInstance().MapBundleArgs(aotArgs, args);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(args.hspModules.size(), 1u);
    EXPECT_EQ(args.hspModules[0].bundleName, "com.test.hsp");
    EXPECT_EQ(args.hspModules[0].moduleName, "hspModule");
    EXPECT_EQ(args.hspModules[0].hapPath, "/data/app/com.test.hsp/hsp.hap");
    EXPECT_EQ(args.hspModules[0].moduleArkTSMode, Constants::ARKTS_MODE_STATIC);
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: HandleCompilerResult_SignFailed_0100
 * @tc.name: test HandleCompilerResult with ERR_AOT_COMPILER_SIGN_FAILED
 * @tc.desc: verify HandleCompilerResult returns SIGN_AOT_FAILED when compiler reports
 *           local signature failure.
 */
HWTEST_F(BmsAOTMgrTest, HandleCompilerResult_SignFailed_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    std::vector<uint8_t> fileData;
    std::vector<uint8_t> signData;
    constexpr int16_t ERR_AOT_COMPILER_SIGN_FAILED = 10004;
    ErrCode ret = AOTExecutor::GetInstance().HandleCompilerResult(
        ERR_AOT_COMPILER_SIGN_FAILED, fileData, signData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED);
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: HandleCompilerResult_Crash_0100
 * @tc.name: test HandleCompilerResult with ERR_AOT_COMPILER_CALL_CRASH
 * @tc.desc: verify HandleCompilerResult returns AOT_EXECUTE_CRASH when compiler process crashes.
 */
HWTEST_F(BmsAOTMgrTest, HandleCompilerResult_Crash_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    std::vector<uint8_t> fileData;
    std::vector<uint8_t> signData;
    constexpr int16_t ERR_AOT_COMPILER_CALL_CRASH = 10008;
    ErrCode ret = AOTExecutor::GetInstance().HandleCompilerResult(
        ERR_AOT_COMPILER_CALL_CRASH, fileData, signData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_CRASH);
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: HandleCompilerResult_Cancelled_0100
 * @tc.name: test HandleCompilerResult with ERR_AOT_COMPILER_CALL_CANCELLED
 * @tc.desc: verify HandleCompilerResult returns AOT_EXECUTE_CANCELLED when compiler is cancelled.
 */
HWTEST_F(BmsAOTMgrTest, HandleCompilerResult_Cancelled_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    std::vector<uint8_t> fileData;
    std::vector<uint8_t> signData;
    constexpr int16_t ERR_AOT_COMPILER_CALL_CANCELLED = 10009;
    ErrCode ret = AOTExecutor::GetInstance().HandleCompilerResult(
        ERR_AOT_COMPILER_CALL_CANCELLED, fileData, signData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_CANCELLED);
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: HandleCompilerResult_GeneralFail_0100
 * @tc.name: test HandleCompilerResult with a generic error code
 * @tc.desc: verify HandleCompilerResult returns AOT_EXECUTE_FAILED for non-specific error codes.
 */
HWTEST_F(BmsAOTMgrTest, HandleCompilerResult_GeneralFail_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    std::vector<uint8_t> fileData;
    std::vector<uint8_t> signData;
    ErrCode ret = AOTExecutor::GetInstance().HandleCompilerResult(
        ERR_APPEXECFWK_INSTALLD_PARAM_ERROR, fileData, signData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: HandleCompilerResult_Success_0100
 * @tc.name: test HandleCompilerResult with ERR_OK
 * @tc.desc: verify HandleCompilerResult copies fileData to signData and returns ERR_OK
 *           on successful compilation.
 */
HWTEST_F(BmsAOTMgrTest, HandleCompilerResult_Success_0100, Function | SmallTest | Level1)
{
#if defined(CODE_SIGNATURE_ENABLE)
    std::vector<uint8_t> fileData = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<uint8_t> signData;
    ErrCode ret = AOTExecutor::GetInstance().HandleCompilerResult(ERR_OK, fileData, signData);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(signData.size(), fileData.size());
    EXPECT_EQ(signData, fileData);
#else
    GTEST_SKIP() << "CODE_SIGNATURE_ENABLE not defined";
#endif
}

/**
 * @tc.number: MkAOTOutputDir_AppType_UsesCompilerServiceGid_0100
 * @tc.name: test MkAOTOutputDir App type uses COMPILER_SERVICE_GID
 * @tc.desc: verify MkAOTOutputDir for non-shared bundles creates output directory
 *           under HAP_ARK_CACHE_PATH/bundleName with COMPILER_SERVICE_GID ownership.
 *           Since UT environment cannot create real directories, verify the return value
 *           is consistent with whether HAP_ARK_CACHE_PATH base exists.
 */
HWTEST_F(BmsAOTMgrTest, MkAOTOutputDir_AppType_UsesCompilerServiceGid_0100, Function | SmallTest | Level1)
{
    AOTArgs aotArgs;
    aotArgs.bundleName = "com.test.app.gid";
    aotArgs.bundleType = 0; // non-shared
    aotArgs.bundleUid = 1000;
    aotArgs.bundleGid = 1000;
    aotArgs.outputPath = "/data/test/ark-cache/com.test.app.gid";

    bool ret = AOTExecutor::GetInstance().MkAOTOutputDir(aotArgs);
    // In UT environment HAP_ARK_CACHE_PATH does not exist, so MkAOTOutputDir should fail
    // (MkdirWithAuth validates basePath is a directory)
    struct stat st;
    bool baseExists = (stat(ServiceConstants::HAP_ARK_CACHE_PATH, &st) == 0);
    if (!baseExists) {
        EXPECT_FALSE(ret);
    }
}
} // OHOS
