/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>

#include "bms_key_event_mgr.h"
#include "bms_param.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "parameters.h"

#include "appexecfwk_errors.h"
#include "message_parcel.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int32_t USERID = 100;
const std::string CLEANUP_MODE_PARAM = "ohos.boot.cleanup.mode";
const std::string BOPD_MODE_PARAM = "ohos.boot.bopd.mode";
const std::string REGISTER_READY_PARAM = "bootevent.bms.register.ready";
const std::string MAIN_BUNDLES_READY_PARAM = "bootevent.bms.main.bundles.ready";
}  // namespace

class BmsCleanupModeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool IsCleanupModeEnabled() const;

    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsCleanupModeTest::bundleMgrService_ = nullptr;

void BmsCleanupModeTest::SetUpTestCase()
{
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    // Init BmsParam (mock bms_param.cpp in-memory map) for the AC-4.x flag read/write cases.
    bundleMgrService_->InitBmsParam();
}

void BmsCleanupModeTest::TearDownTestCase()
{
    bundleMgrService_ = nullptr;
    DelayedSingleton<BundleMgrService>::DestroyInstance();
}

void BmsCleanupModeTest::SetUp()
{
    // Reset the cleanup-mode param before each case to avoid cross-case pollution.
    OHOS::system::SetParameter(CLEANUP_MODE_PARAM, "");
}

void BmsCleanupModeTest::TearDown()
{
    OHOS::system::SetParameter(CLEANUP_MODE_PARAM, "");
    OHOS::system::SetParameter(REGISTER_READY_PARAM, "false");
    // Clear the bmsCleanRecovery flag so the mock BmsParam static map does not leak across cases.
    auto bmsPara = bundleMgrService_ != nullptr ? bundleMgrService_->GetBmsParam() : nullptr;
    if (bmsPara != nullptr) {
        bmsPara->DeleteBmsParam("bmsCleanRecovery");
    }
}

bool BmsCleanupModeTest::IsCleanupModeEnabled() const
{
    auto dataMgr = bundleMgrService_ != nullptr ? bundleMgrService_->GetDataMgr() : nullptr;
    if (dataMgr == nullptr) {
        return false;
    }
    return dataMgr->IsCleanupModeEnabled();
}

/**
 * @tc.number: BmsCleanupModeTest_0001
 * @tc.name: IsCleanupModeEnabled returns true when ohos.boot.cleanup.mode is "true"
 * @tc.desc: 1. set ohos.boot.cleanup.mode to "true"
 *           2. verify IsCleanupModeEnabled returns true
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0001, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(CLEANUP_MODE_PARAM, "true");
    EXPECT_TRUE(IsCleanupModeEnabled()) << "cleanup mode should be enabled when param is true";
}

/**
 * @tc.number: BmsCleanupModeTest_0002
 * @tc.name: IsCleanupModeEnabled returns false for invalid/empty values
 * @tc.desc: 1. set ohos.boot.cleanup.mode to invalid/empty values
 *           2. verify IsCleanupModeEnabled returns false
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0002, Function | SmallTest | Level0)
{
    const std::vector<std::string> disabledModes = {"", "false", "0", "1", "TRUE", "True", "invalid"};
    for (const auto &mode : disabledModes) {
        OHOS::system::SetParameter(CLEANUP_MODE_PARAM, mode);
        EXPECT_FALSE(IsCleanupModeEnabled()) << "mode " << mode << " should be disabled";
    }
}

/**
 * @tc.number: BmsCleanupModeTest_0003
 * @tc.name: IsCleanupModeEnabled is independent of ohos.boot.bopd.mode
 * @tc.desc: 1. set bopd mode enabled but cleanup mode empty -> cleanup disabled
 *           2. set cleanup mode true but bopd mode empty -> cleanup enabled
 *           3. both set -> cleanup follows its own param
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0003, Function | SmallTest | Level0)
{
    // bopd set, cleanup not set -> cleanup still false (the two params are independent).
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "0x2");
    OHOS::system::SetParameter(CLEANUP_MODE_PARAM, "");
    EXPECT_FALSE(IsCleanupModeEnabled());

    // cleanup set, bopd not set -> cleanup true.
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "");
    OHOS::system::SetParameter(CLEANUP_MODE_PARAM, "true");
    EXPECT_TRUE(IsCleanupModeEnabled());

    // both set -> cleanup still follows its own param (true).
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "0x2");
    OHOS::system::SetParameter(CLEANUP_MODE_PARAM, "true");
    EXPECT_TRUE(IsCleanupModeEnabled());

    // Restore the bopd param to avoid polluting other test suites.
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "");
}

/**
 * @tc.number: BmsCleanupModeTest_0004
 * @tc.name: ProcessRegisterReady sets bootevent.bms.register.ready to true
 * @tc.desc: 1. call BmsKeyEventMgr::ProcessRegisterReady
 *           2. verify bootevent.bms.register.ready == "true"
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0004, Function | SmallTest | Level0)
{
    BmsKeyEventMgr::ProcessRegisterReady();
    EXPECT_EQ(OHOS::system::GetParameter(REGISTER_READY_PARAM, ""), "true");
}

/**
 * @tc.number: BmsCleanupModeTest_0005
 * @tc.name: ProcessRegisterReady is idempotent
 * @tc.desc: 1. call ProcessRegisterReady twice
 *           2. verify no crash and register.ready stays "true"
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0005, Function | SmallTest | Level0)
{
    BmsKeyEventMgr::ProcessRegisterReady();
    BmsKeyEventMgr::ProcessRegisterReady();
    EXPECT_EQ(OHOS::system::GetParameter(REGISTER_READY_PARAM, ""), "true");
}

/**
 * @tc.number: BmsCleanupModeTest_0006
 * @tc.name: ProcessRegisterReady writes register.ready only, not main.bundles.ready
 * @tc.desc: 1. capture current main.bundles.ready value (do NOT modify it: avoid touching a key boot param)
 *           2. call ProcessRegisterReady
 *           3. verify register.ready == "true" and main.bundles.ready unchanged
 * bootevent.bms.main.bundles.ready is watched by init/startup_init; this case never writes it and only asserts
 * the value is unchanged across the call.
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0006, Function | SmallTest | Level0)
{
    const std::string prior = OHOS::system::GetParameter(MAIN_BUNDLES_READY_PARAM, "");
    BmsKeyEventMgr::ProcessRegisterReady();
    EXPECT_EQ(OHOS::system::GetParameter(REGISTER_READY_PARAM, ""), "true");
    EXPECT_EQ(OHOS::system::GetParameter(MAIN_BUNDLES_READY_PARAM, ""), prior)
        << "ProcessRegisterReady must not touch main.bundles.ready";
}

namespace {
const std::string CLEANUP_RECOVERY_FLAG_KEY = "bmsCleanRecovery";
}

/**
 * @tc.number: BmsCleanupModeTest_0007
 * @tc.name: IsCleanupRecoveryFlagSet returns true when bmsCleanRecovery="true"
 * @tc.desc: 1. seed bms_param bmsCleanRecovery="true" via mock BmsParam
 *           2. call BMSEventHandler::IsCleanupRecoveryFlagSet
 *           3. verify returns true
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0007, Function | SmallTest | Level0)
{
    auto bmsPara = bundleMgrService_->GetBmsParam();
    ASSERT_NE(bmsPara, nullptr);
    EXPECT_TRUE(bmsPara->SaveBmsParam(CLEANUP_RECOVERY_FLAG_KEY, "true"));

    auto handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    EXPECT_TRUE(handler->IsCleanupRecoveryFlagSet()) << "flag should be set when bmsCleanRecovery=true";
}

/**
 * @tc.number: BmsCleanupModeTest_0008
 * @tc.name: IsCleanupRecoveryFlagSet returns false for absent row or non-"true" value
 * @tc.desc: 1. no bmsCleanRecovery row -> false
 *           2. bmsCleanRecovery="false" -> false (only "true" matches)
 *           3. bmsCleanRecovery="" rejected by SaveBmsParam (empty value) -> still absent -> false
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0008, Function | SmallTest | Level0)
{
    auto bmsPara = bundleMgrService_->GetBmsParam();
    ASSERT_NE(bmsPara, nullptr);
    auto handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);

    // No row -> false.
    bmsPara->DeleteBmsParam(CLEANUP_RECOVERY_FLAG_KEY);
    EXPECT_FALSE(handler->IsCleanupRecoveryFlagSet()) << "absent flag should be false";

    // Value not "true" -> false (only an exact VALUE_TRUE match counts).
    EXPECT_TRUE(bmsPara->SaveBmsParam(CLEANUP_RECOVERY_FLAG_KEY, "false"));
    EXPECT_FALSE(handler->IsCleanupRecoveryFlagSet()) << "value 'false' should not match";

    // Empty value is rejected by SaveBmsParam, so the row is not written -> still false.
    EXPECT_FALSE(bmsPara->SaveBmsParam(CLEANUP_RECOVERY_FLAG_KEY, ""));
    EXPECT_FALSE(handler->IsCleanupRecoveryFlagSet()) << "empty value rejected, flag stays false";
}

/**
 * @tc.number: BmsCleanupModeTest_0009
 * @tc.name: ClearCleanupRecoveryFlag deletes the bmsCleanRecovery row
 * @tc.desc: 1. seed bmsCleanRecovery="true"
 *           2. call BMSEventHandler::ClearCleanupRecoveryFlag
 *           3. verify GetBmsParam returns false (row gone) and IsCleanupRecoveryFlagSet returns false
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0009, Function | SmallTest | Level0)
{
    auto bmsPara = bundleMgrService_->GetBmsParam();
    ASSERT_NE(bmsPara, nullptr);
    EXPECT_TRUE(bmsPara->SaveBmsParam(CLEANUP_RECOVERY_FLAG_KEY, "true"));

    auto handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    EXPECT_TRUE(handler->IsCleanupRecoveryFlagSet());

    handler->ClearCleanupRecoveryFlag();

    std::string value;
    EXPECT_FALSE(bmsPara->GetBmsParam(CLEANUP_RECOVERY_FLAG_KEY, value)) << "row should be deleted";
    EXPECT_FALSE(handler->IsCleanupRecoveryFlagSet()) << "flag should be false after clear";
}

/**
 * @tc.number: BmsCleanupModeTest_0010
 * @tc.name: cleanupRecoveryFlagSet_ member defaults to false
 * @tc.desc: 1. construct a fresh BMSEventHandler
 *           2. verify cleanupRecoveryFlagSet_ == false (no stale state carried into the OTA block)
 * The OTA block assigns cleanupRecoveryFlagSet_ from IsCleanupRecoveryFlagSet() before OnBundleRebootStart and
 * resets it after; the default false ensures a non-cleanup boot never forces the same-version updateBundle.
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0010, Function | SmallTest | Level0)
{
    auto handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    EXPECT_FALSE(handler->cleanupRecoveryFlagSet_) << "member must default to false";
}

/**
 * @tc.number: BmsCleanupModeTest_0011
 * @tc.name: OnExtension sa_cleanup is refused when cleanup mode is disabled
 * @tc.desc: 1. keep ohos.boot.cleanup.mode empty
 *           2. call OnExtension("sa_cleanup")
 *           3. verify returns ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR (the cleanup gate blocks)
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0011, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(CLEANUP_MODE_PARAM, "");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = bundleMgrService_->OnExtension("sa_cleanup", data, reply);
    EXPECT_EQ(result, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR)
        << "OnClean must be refused when cleanup mode is disabled";
}

/**
 * @tc.number: BmsCleanupModeTest_0012
 * @tc.name: OnExtension sa_cleanup is refused when BOPD mode is on but cleanup mode is off (independence)
 * @tc.desc: 1. set ohos.boot.bopd.mode to a valid value but keep ohos.boot.cleanup.mode empty
 *           2. call OnExtension("sa_cleanup")
 *           3. verify returns ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR — the gate uses cleanup mode, not BOPD mode;
 *              BOPD mode alone does not authorize the cleanup action (cleanup mode is independent)
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0012, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "0x2");
    OHOS::system::SetParameter(CLEANUP_MODE_PARAM, "");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = bundleMgrService_->OnExtension("sa_cleanup", data, reply);
    EXPECT_EQ(result, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR)
        << "BOPD mode alone must not pass the cleanup gate; cleanup mode is independent";
    OHOS::system::SetParameter(BOPD_MODE_PARAM, "");
}

/**
 * @tc.number: BmsCleanupModeTest_0013
 * @tc.name: OnExtension sa_cleanup passes the gate when cleanup mode is enabled
 * @tc.desc: 1. set ohos.boot.cleanup.mode to "true"
 *           2. call OnExtension("sa_cleanup")
 *           3. verify the gate passes (result is NOT ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
 *              OnClean may fail for other reasons (e.g. mirror path unavailable in the test environment) but the
 *              cleanup-mode gate itself must not block
 */
HWTEST_F(BmsCleanupModeTest, BmsCleanupModeTest_0013, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(CLEANUP_MODE_PARAM, "true");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = bundleMgrService_->OnExtension("sa_cleanup", data, reply);
    EXPECT_NE(result, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR)
        << "gate should pass when cleanup mode is enabled";
}
