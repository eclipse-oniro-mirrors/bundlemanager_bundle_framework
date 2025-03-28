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
    hspInfo.codeLanguage = Constants::CODE_LANGUAGE_1_2;
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
    EXPECT_EQ(sourceHspInfo.codeLanguage, targetHspInfo.codeLanguage);
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0200, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0300, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0400, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0500, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0600, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0700, Function | SmallTest | Level0)
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
 * @tc.number: AOTExecutor_0800
 * @tc.name: test AOTExecutor
 * @tc.desc: 1. system running normally
 *           2. verify function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_0800, Function | SmallTest | Level0)
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
    aotArgs.codeLanguage = Constants::CODE_LANGUAGE_1_2;

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
    EXPECT_EQ(aotArgsPtr->codeLanguage, aotArgs.codeLanguage);
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
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
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
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: AOTHandler_2400
 * @tc.name: test AOTHandler
 * @tc.desc: test BuildAOTArgs function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2400, Function | SmallTest | Level0)
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
    auto ret = AOTHandler::GetInstance().BuildAOTArgs(innerBundleInfo, AOT_MODULE_NAME, "");
    EXPECT_NE(ret, std::nullopt);
}

/**
 * @tc.number: AOTHandler_2500
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleInstall function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2500, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    newInfo.SetIsNewVersion(true);
    infos.emplace("", newInfo);
    system::SetParameter(INSTALL_COMPILE_MODE, "on");
    AOTHandler::GetInstance().HandleInstall(infos);
    EXPECT_EQ(infos.empty(), false);
}

/**
 * @tc.number: AOTHandler_2600
 * @tc.name: test AOTHandler
 * @tc.desc: test CopyApWithBundle function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_2600, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_2700, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_2800, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_2900, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_3000, Function | SmallTest | Level0)
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
 * @tc.number: AOTHandler_3000
 * @tc.name: test AOTHandler
 * @tc.desc: test ClearArkAp function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = AOT_BUNDLE_NAME;
    BundleInfo bundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace(AOT_BUNDLE_NAME, innerBundleInfo);
    ClearDataMgr();
    std::string curAOTVersion = AOTHandler::GetInstance().GetCurAOTVersion();
    EXPECT_EQ(curAOTVersion.empty(), false);
    std::string oldAOTVersion;
    (void)AOTHandler::GetInstance().GetOldAOTVersion(oldAOTVersion);
    EXPECT_EQ(oldAOTVersion, "");
    AOTHandler::GetInstance().ClearArkAp(curAOTVersion, oldAOTVersion);
    ResetDataMgr();
}

/**
 * @tc.number: AOTExecutor_1200
 * @tc.name: test GetSubjectInfo
 * @tc.desc: test GetSubjectInfo function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1200, Function | SmallTest | Level0)
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
 * @tc.name: test MapArgs
 * @tc.desc: test MapArgs function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1300, Function | SmallTest | Level0)
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
    AOTExecutor::GetInstance().MapArgs(aotArgs, argsMap);
    EXPECT_EQ(argsMap.empty(), false);
}

/**
 * @tc.number: AOTExecutor_1400
 * @tc.name: test PendSignAOT
 * @tc.desc: test PendSignAOT function running with exception parameter
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1400, Function | SmallTest | Level0)
{
    std::string anFileName = "anFileName";
    std::vector<uint8_t> signData(HAP_PATH.begin(), HAP_PATH.end());
    ErrCode ret = AOTExecutor::GetInstance().PendSignAOT(anFileName, signData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0100
 * @tc.name: test AOTSignDataCacheMgr
 * @tc.desc: test AddPendSignData function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0100, Function | SmallTest | Level0)
{
    std::optional<AOTArgs> aotArgs;
    AOTArgs aotArg;
    aotArg.bundleName = "bundleName";
    aotArg.moduleName = "moduleName";
    aotArgs = aotArg;
    int32_t versionCode = 1;
    std::vector<uint8_t> pendSignData(HAP_PATH.begin(), HAP_PATH.end());
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    AOTSignDataCacheMgr::GetInstance().AddPendSignData(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(AOTSignDataCacheMgr::GetInstance().pendingSignData_.empty(), false);
    AOTSignDataCacheMgr::GetInstance().pendingSignData_.clear();
}

/**
 * @tc.number: AOTSignDataCacheMgr_0200
 * @tc.name: test AOTSignDataCacheMgr
 * @tc.desc: test AddPendSignData function running with exception parameter
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0200, Function | SmallTest | Level0)
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
    signDataCacheMgr.AddPendSignData(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(signDataCacheMgr.pendingSignData_.empty(), true);
    signDataCacheMgr.isLocked_ = true;
    signDataCacheMgr.AddPendSignData(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(signDataCacheMgr.pendingSignData_.empty(), true);
    ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    signDataCacheMgr.AddPendSignData(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(signDataCacheMgr.pendingSignData_.empty(), true);
    signDataCacheMgr.isLocked_ = false;
    signDataCacheMgr.AddPendSignData(*aotArgs, versionCode, pendSignData, ret);
    EXPECT_EQ(signDataCacheMgr.pendingSignData_.empty(), true);
    ret = ERR_OK;
    signDataCacheMgr.AddPendSignData(*aotArgs, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.pendingSignData_.empty(), true);
    ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    signDataCacheMgr.AddPendSignData(*aotArgs, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.pendingSignData_.empty(), true);
    ret = ERR_OK;
    signDataCacheMgr.isLocked_ = true;
    signDataCacheMgr.AddPendSignData(*aotArgs, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.pendingSignData_.empty(), true);
    ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    signDataCacheMgr.AddPendSignData(*aotArgs2, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.pendingSignData_.empty(), true);
    signDataCacheMgr.AddPendSignData(*aotArgs3, versionCode, pendSignData2, ret);
    EXPECT_EQ(signDataCacheMgr.pendingSignData_.empty(), true);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0300
 * @tc.name: test RegisterScreenUnlockListener and UnregisterScreenUnlockEvent
 * @tc.desc: test RegisterScreenUnlockListener function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0300, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0400, Function | SmallTest | Level0)
{
    AOTSignDataCacheMgr& signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.HandleUnlockEvent();
    EXPECT_EQ(signDataCacheMgr.isLocked_, false);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0500
 * @tc.name: test ExecutePendSign
 * @tc.desc: test ExecutePendSign function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0500, Function | SmallTest | Level0)
{
    AOTSignDataCacheMgr& signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    ErrCode ret = ERR_OK;
    ret = signDataCacheMgr.ExecutePendSign();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AOTExecutor_1500
 * @tc.name: test DecToHex
 * @tc.desc: test DecToHex function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1500, Function | SmallTest | Level0)
{
    std::string result = AOTExecutor::GetInstance().DecToHex(50);
    EXPECT_EQ(result, "0x32");
}

/**
 * @tc.number: AOTExecutor_1600
 * @tc.name: test CheckArgs
 * @tc.desc: test CheckArgs function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1600, Function | SmallTest | Level0)
{
    AOTArgs aotArgs;
    bool result = AOTExecutor::GetInstance().CheckArgs(aotArgs);
    EXPECT_FALSE(result);
    aotArgs.compileMode = "partial";
    aotArgs.hapPath = "hapPath";
    aotArgs.outputPath = "outputPath";
    result = AOTExecutor::GetInstance().CheckArgs(aotArgs);
    EXPECT_FALSE(result);
    aotArgs.arkProfilePath = "arkProfilePath";
    result = AOTExecutor::GetInstance().CheckArgs(aotArgs);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: AOTExecutor_1700
 * @tc.name: test GetAbcFileInfo
 * @tc.desc: test GetAbcFileInfo function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1700, Function | SmallTest | Level0)
{
    std::string hapPath = "";
    uint32_t offset = OFFSET;
    uint32_t length = LENGTH;
    bool result = AOTExecutor::GetInstance().GetAbcFileInfo(hapPath, Constants::CODE_LANGUAGE_1_1, offset, length);
    EXPECT_FALSE(result);
    hapPath = HAP_PATH;
    result = AOTExecutor::GetInstance().GetAbcFileInfo(hapPath, Constants::CODE_LANGUAGE_1_1, offset, length);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: AOTExecutor_1800
 * @tc.name: test PrepareArgs
 * @tc.desc: test PrepareArgs function return value
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1800, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_1900, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTExecutor_2000, Function | SmallTest | Level0)
{
    AOTExecutor::GetInstance().ResetState();
    EXPECT_FALSE(AOTExecutor::GetInstance().state_.running);
}

/**
 * @tc.number: AOTExecutor_2100
 * @tc.name: test GetAbcRelativePath
 * @tc.desc: system running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTExecutor_2100, Function | SmallTest | Level0)
{
    EXPECT_EQ(AOTExecutor::GetInstance().GetAbcRelativePath(Constants::CODE_LANGUAGE_1_1), ABC_RELATIVE_PATH);
    EXPECT_EQ(AOTExecutor::GetInstance().GetAbcRelativePath(Constants::CODE_LANGUAGE_1_2), STATIC_ABC_RELATIVE_PATH);
    EXPECT_EQ(AOTExecutor::GetInstance().GetAbcRelativePath(Constants::EMPTY_STRING), Constants::EMPTY_STRING);
}

/**
 * @tc.number: AOTHandler_3200
 * @tc.name: test MkApDestDirIfNotExist
 * @tc.desc: test MkApDestDirIfNotExist function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3200, Function | SmallTest | Level0)
{
    ErrCode ret = AOTHandler::GetInstance().MkApDestDirIfNotExist();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AOTHandler_3300
 * @tc.name: test AOTHandler
 * @tc.desc: test GetSouceAp function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3300, Function | SmallTest | Level0)
{
    std::string bundleName = "bundleName";
    std::string arkProfilePath;
    int32_t userId = 100;
    arkProfilePath.append(ServiceConstants::ARK_PROFILE_PATH).append(std::to_string(userId))
        .append(ServiceConstants::PATH_SEPARATOR).append(bundleName).append(ServiceConstants::PATH_SEPARATOR);
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_3400, Function | SmallTest | Level0)
{
    bool result = AOTHandler::GetInstance().IsSupportARM64();
    EXPECT_TRUE(result);
}

/**
 * @tc.number: AOTHandler_3500
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileWithSingleHap function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3500, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    std::string bundleName = "bundleName";
    std::string compileMode;
    ErrCode ret = AOTHandler::GetInstance().HandleCompileWithSingleHap(info, bundleName, compileMode, true);
    EXPECT_EQ(ret, ERR_APPEXECFWK_AOT_ARGS_EMPTY);
}

/**
 * @tc.number: AOTHandler_3600
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleCompileModules function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3600, Function | SmallTest | Level0)
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
 * @tc.desc: test ClearArkCacheDir function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3700, Function | SmallTest | Level0)
{
    AOTHandler::GetInstance().ClearArkCacheDir();
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<std::string> bundleNames = dataMgr->GetAllBundleName();
    std::for_each(bundleNames.cbegin(), bundleNames.cend(), [dataMgr](const auto &bundleName) {
        std::string removeDir = ServiceConstants::ARK_CACHE_PATH + bundleName;
        ASSERT_NE(AppExecFwk::InstalldClient::GetInstance(), nullptr);
        ErrCode ret = AppExecFwk::InstalldClient::GetInstance()->RemoveDir(removeDir);
        EXPECT_EQ(ret, ERR_OK);
    });
}

/**
 * @tc.number: AOTHandler_3800
 * @tc.name: test AOTHandler
 * @tc.desc: test HandleOTACompile function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_3800, Function | SmallTest | Level0)
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
HWTEST_F(BmsAOTMgrTest, AOTHandler_3900, Function | SmallTest | Level0)
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
 * @tc.number: AOTHandler_4000
 * @tc.name: test AOTHandler
 * @tc.desc: test DeleteArkAp function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4000, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    AOTHandler::GetInstance().DeleteArkAp(bundleInfo, 0);
    EXPECT_NE(AppExecFwk::InstalldClient::GetInstance()->installdProxy_, nullptr);
}

/**
 * @tc.number: AOTHandler_4100
 * @tc.name: test AOTHandler
 * @tc.desc: test GetCurAOTVersion function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4100, Function | SmallTest | Level0)
{
    std::string result = AOTHandler::GetInstance().GetCurAOTVersion();
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.number: AOTHandler_4200
 * @tc.name: test AOTHandler
 * @tc.desc: test GetOldAOTVersion function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4200, Function | SmallTest | Level0)
{
    std::string oldAOTVersion = "";
    bool result = AOTHandler::GetInstance().GetOldAOTVersion(oldAOTVersion);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: AOTHandler_4300
 * @tc.name: test AOTHandler
 * @tc.desc: test SaveAOTVersion function running
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4300, Function | SmallTest | Level0)
{
    std::string curAOTVersion = "2.5";
    AOTHandler::GetInstance().SaveAOTVersion(curAOTVersion);
    bool result = AOTHandler::GetInstance().GetOldAOTVersion(curAOTVersion);
    EXPECT_FALSE(result);
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
 * @tc.number: AOTHandler_4800
 * @tc.name: Test GetOldAOTVersion
 * @tc.desc: 1.GetOldAOTVersion
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4800, Function | SmallTest | Level1)
{
    std::string oldAOTVersion;
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBmsParam();
    auto result = AOTHandler::GetInstance().GetOldAOTVersion(oldAOTVersion);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: AOTHandler_4900
 * @tc.name: Test GetOldAOTVersion
 * @tc.desc: 1.GetOldAOTVersion
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_4900, Function | SmallTest | Level1)
{
    std::string oldAOTVersion;
    BmsParam bmsParam;
    bmsParam.SaveBmsParam(AOT_VERSION, AOT_BUNDLE_NAME);
    auto result = AOTHandler::GetInstance().GetOldAOTVersion(oldAOTVersion);
    EXPECT_TRUE(result);
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
 * @tc.number: AOTHandler_5300
 * @tc.name: Test SaveAOTVersion
 * @tc.desc: 1.SaveAOTVersion
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_5300, Function | SmallTest | Level1)
{
    OHOS::AppExecFwk::BmsParam bmsParam;
    AOTHandler::GetInstance().SaveAOTVersion(AOT_MODULE_NAME);
    std::string value;
    bmsParam.GetBmsParam(AOT_VERSION, value);
    EXPECT_EQ(value, AOT_MODULE_NAME);
}

/**
 * @tc.number: AOTHandler_5400
 * @tc.name: Test SaveAOTVersion
 * @tc.desc: 1.SaveAOTVersion
 */
HWTEST_F(BmsAOTMgrTest, AOTHandler_5400, Function | SmallTest | Level1)
{
    OHOS::AppExecFwk::BmsParam bmsParam;
    AOTHandler::GetInstance().SaveAOTVersion(STRING_EMPTY);
    std::string value;
    bmsParam.GetBmsParam(AOT_VERSION, value);
    EXPECT_NE(value, STRING_EMPTY);
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
 * @tc.name: test ExecutePendSign
 * @tc.desc: test ExecutePendSign function running normally
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0600, Function | SmallTest | Level0)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    std::optional<AOTArgs> aotArgs;
    AOTArgs aotArg;
    aotArg.bundleName = "bundleName";
    aotArg.moduleName = "moduleName";
    aotArgs = aotArg;
    int32_t versionCode = 1;
    std::vector<uint8_t> pendSignData(HAP_PATH.begin(), HAP_PATH.end());
    ErrCode ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    AOTSignDataCacheMgr::GetInstance().AddPendSignData(*aotArgs, versionCode, pendSignData, ret);
    ret = signDataCacheMgr.ExecutePendSign();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0700
 * @tc.name: Test HandleUnlockEvent
 * @tc.desc: 1.HandleUnlockEvent
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0700, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    signDataCacheMgr.isLocked_ = true;
    std::string key = "key";
    AppExecFwk::AOTSignDataCacheMgr::PendingData data;
    std::unordered_map<std::string, AppExecFwk::AOTSignDataCacheMgr::PendingData> datas;
    datas.emplace(key, data);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    signDataCacheMgr.pendingSignData_.emplace(key, datas);
    signDataCacheMgr.HandleUnlockEvent();
    EXPECT_FALSE(signDataCacheMgr.isLocked_);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = dataMgr;
}

/**
 * @tc.number: AOTSignDataCacheMgr_0800
 * @tc.name: Test ExecutePendSign
 * @tc.desc: 1.ExecutePendSign
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0800, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    std::string key = "key";
    AppExecFwk::AOTSignDataCacheMgr::PendingData data;
    std::unordered_map<std::string, AppExecFwk::AOTSignDataCacheMgr::PendingData> datas;
    datas.emplace(key, data);
    signDataCacheMgr.pendingSignData_[key]= datas;
    SetPendSignAOTCode(ERR_OK);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    auto ret = signDataCacheMgr.ExecutePendSign();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AOTSignDataCacheMgr_0900
 * @tc.name: Test ExecutePendSign
 * @tc.desc: 1.ExecutePendSign
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_0900, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    std::string key = "key";
    AppExecFwk::AOTSignDataCacheMgr::PendingData data;
    std::unordered_map<std::string, AppExecFwk::AOTSignDataCacheMgr::PendingData> datas;
    datas.emplace(key, data);
    signDataCacheMgr.pendingSignData_[key] = datas;
    SetPendSignAOTCode(ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    auto ret = signDataCacheMgr.ExecutePendSign();
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED);
}

/**
 * @tc.number: AOTSignDataCacheMgr_1000
 * @tc.name: Test ExecutePendSign
 * @tc.desc: 1.ExecutePendSign
 */
HWTEST_F(BmsAOTMgrTest, AOTSignDataCacheMgr_1000, Function | SmallTest | Level1)
{
    AOTSignDataCacheMgr &signDataCacheMgr = AOTSignDataCacheMgr::GetInstance();
    std::string key = "key";
    AppExecFwk::AOTSignDataCacheMgr::PendingData data;
    std::unordered_map<std::string, AppExecFwk::AOTSignDataCacheMgr::PendingData> datas;
    datas.emplace(key, data);
    signDataCacheMgr.pendingSignData_[key] = datas;
    SetPendSignAOTCode(ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    InstalldClient::GetInstance()->installdProxy_ = new (std::nothrow) MockInstalldProxy(nullptr);
    auto ret = signDataCacheMgr.ExecutePendSign();
    EXPECT_EQ(ret, ERR_OK);
    InstalldClient::GetInstance()->installdProxy_ = nullptr;
    InstalldClient::GetInstance()->GetInstalldProxy();
}
} // OHOS
