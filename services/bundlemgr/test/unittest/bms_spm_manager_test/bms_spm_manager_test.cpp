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

#include <gtest/gtest.h>

#include "access_token_error.h"
#include "appexecfwk_errors.h"
#include "bundle_data_mgr.h"
#include "bundle_install_checker.h"
#include "bundle_permission_mgr.h"
#include "bundle_spm_manager.h"
#include "default_permission.h"
#include "hap_token_info.h"
#include "installd_client.h"
#include "inner_bundle_info.h"
#include "parcel.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

// Counting stub accessors defined in test/mock/src/installd_client.cpp.
namespace OHOS {
namespace AppExecFwk {
void ResetClearSessionProvisionCacheCountForTest();
int32_t GetClearSessionProvisionCacheCountForTest();
} // namespace AppExecFwk
} // namespace OHOS

namespace OHOS {
extern int32_t g_testVerifyPermission;
extern int32_t g_deleteAccessTokenIdCount;
extern bool g_deleteAccessTokenIdReserved;
extern int32_t g_initHapTokenRet;
extern int32_t g_updateHapTokenRet;
extern int32_t g_deleteAccessTokenIdRet;
extern bool g_updateHapTokenDataRefresh;
extern bool g_updateHapTokenIsDebugGrant;
extern bool g_updateHapTokenNeedInit;
// Test knobs for the CreateBundlePolicy branches (mock bundle_permission_mgr).
extern bool g_defaultPermissionRet;
extern AppExecFwk::DefaultPermission g_mockDefaultPermission;
extern bool g_matchSignatureRet;
// SPM facade mock resetter defined in test/mock/src/bundle_permission_mgr.cpp.
void ResetSpmFacadeMockValues();

// SPM control variables defined in test/mock/src/accesstoken_kit.cpp.
namespace Security {
namespace AccessToken {
extern int32_t g_spmFinishInstallRet;
extern std::vector<int32_t> g_spmFinishInstallRetSeq;
extern int32_t g_spmFinishInstallCallCount;
extern bool g_spmFinishInstallLastPersistent;
extern unsigned int g_spmGetHapTokenIDRet;
extern std::string g_lastDeleteIdentityBundleName;
void ResetSpmKitMockValuesForTest();
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

namespace {
const std::string BUNDLE_NAME = "com.ohos.spm.test";
const std::string PERMISSION_NAME = "ohos.permission.TEST_PERMISSION";
const std::string SPM_ENABLE_PARAM = "persist.bms.spm.enable";
constexpr int32_t TEST_USERID = 100;
constexpr int32_t TEST_TOKENID = 12345;
constexpr int32_t TEST_SESSION_ID = 56789;
} // namespace

namespace OHOS {

class BmsSpmManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        // Pin the switch to OFF for this binary regardless of the device state:
        // a leftover persist.bms.spm.enable=true (e.g. from a previous
        // BmsSpmManagerOnTest run on the same integration host) would flip
        // IsEnabled() to true for the whole process (function-local static
        // cache) and route every OFF-mode assertion below into the SPM ON
        // branches. Note: this target compiles against the real SDK
        // parameters.h (its include path wins over the mock parameter/
        // subdirectory), which has no RemoveParameter — the explicit "false"
        // reset works for both headers.
        OHOS::system::SetParameter(SPM_ENABLE_PARAM, "false");
    };
    static void TearDownTestCase() {};
    void SetUp() override
    {
        OHOS::ResetSpmFacadeMockValues();
        ResetClearSessionProvisionCacheCountForTest();
        OHOS::Security::AccessToken::ResetSpmKitMockValuesForTest();
    };
    void TearDown() override {};
};

/**
 * @tc.number: BmsSpmManagerTest.IsEnabled_0001
 * @tc.name: IsEnabled
 * @tc.desc: SPM OFF stage: the switch is hard-coded to false.
 */
HWTEST_F(BmsSpmManagerTest, IsEnabled_0001, Function | MediumTest | Level1)
{
    EXPECT_FALSE(BundleSpmManager::IsEnabled());
}

/**
 * @tc.number: BmsSpmManagerTest.CreateDeferred_0001
 * @tc.name: CreateDeferred
 * @tc.desc: Deferred session keeps session id 0, inactive, without verify results.
 */
HWTEST_F(BmsSpmManagerTest, CreateDeferred_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.GetSessionId(), 0);
    EXPECT_FALSE(session.IsActive());
    std::vector<Security::Verify::HapVerifyResult> results;
    EXPECT_FALSE(session.GetHapVerifyResults(results));
}

/**
 * @tc.number: BmsSpmManagerTest.CheckSignAndInitSession_0001
 * @tc.name: CheckSignAndInitSession with empty paths
 * @tc.desc: Empty bundle paths fail sign verification and return an empty session
 *           with the raw error code passed through.
 */
HWTEST_F(BmsSpmManagerTest, CheckSignAndInitSession_0001, Function | MediumTest | Level1)
{
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    EXPECT_EQ(session.GetSessionId(), 0);
    std::vector<Security::Verify::HapVerifyResult> results;
    EXPECT_FALSE(session.GetHapVerifyResults(results));
}

/**
 * @tc.number: BmsSpmManagerTest.CheckSignAndInitSession_0002
 * @tc.name: CheckSignAndInitSession with invalid path
 * @tc.desc: A non-existent hap path fails sign verification; the raw error code is
 *           passed through via outErrCode and the session stays empty.
 */
HWTEST_F(BmsSpmManagerTest, CheckSignAndInitSession_0002, Function | MediumTest | Level1)
{
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {"/data/local/tmp/not_exist.hap"}, false, checker, errCode, true, false);
    EXPECT_NE(errCode, ERR_OK);
    EXPECT_EQ(session.GetSessionId(), 0);
}

/**
 * @tc.number: BmsSpmManagerTest.CheckPermissionInfo_0001
 * @tc.name: CheckPermissionInfo
 * @tc.desc: SPM OFF: permission pre-check is a no-op success.
 */
HWTEST_F(BmsSpmManagerTest, CheckPermissionInfo_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.CheckPermissionInfo(Security::AccessToken::InstallTypeEnum::TYPE_INSTALL,
        checkResult), ERR_OK);
    EXPECT_EQ(session.CheckPermissionInfo(Security::AccessToken::InstallTypeEnum::TYPE_REPLACE,
        checkResult), ERR_OK);
    EXPECT_EQ(session.CheckPermissionInfo(Security::AccessToken::InstallTypeEnum::TYPE_MERGE,
        checkResult), ERR_OK);
}

/**
 * @tc.number: BmsSpmManagerTest.Commit_0001
 * @tc.name: Commit and Rollback
 * @tc.desc: SPM OFF: commit/rollback are no-op successes and trigger no IPC.
 */
HWTEST_F(BmsSpmManagerTest, Commit_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.Commit({}), ERR_OK);
    EXPECT_EQ(session.Rollback(), ERR_OK);
    // AC-8: commit/rollback under SPM OFF must not reach installd via IPC.
    EXPECT_EQ(GetClearSessionProvisionCacheCountForTest(), 0);
}

/**
 * @tc.number: BmsSpmManagerTest.FillCreateDirParam_0001
 * @tc.name: FillCreateDirParam
 * @tc.desc: Only the session id (0 under SPM OFF) is set; existing fields are kept.
 */
HWTEST_F(BmsSpmManagerTest, FillCreateDirParam_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    CreateDirParam param;
    param.bundleName = BUNDLE_NAME;
    param.userId = TEST_USERID;
    param.uid = 12450;
    session.FillCreateDirParam(param);
    EXPECT_EQ(param.sessionId, 0);
    EXPECT_EQ(param.bundleName, BUNDLE_NAME);
    EXPECT_EQ(param.userId, TEST_USERID);
    EXPECT_EQ(param.uid, 12450);
}

/**
 * @tc.number: BmsSpmManagerTest.FillCodeSignatureParam_0001
 * @tc.name: FillCodeSignatureParam
 * @tc.desc: Only the session id is set; fields filled by ProcessCodeSignatureParam
 *           at the installer side are untouched.
 */
HWTEST_F(BmsSpmManagerTest, FillCodeSignatureParam_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    Security::Verify::HapVerifyResult verifyResult;
    CodeSignatureParam param;
    param.bundleName = BUNDLE_NAME;
    param.isEnterpriseBundle = true;
    session.FillCodeSignatureParam(verifyResult, param);
    EXPECT_EQ(param.sessionId, 0);
    EXPECT_EQ(param.bundleName, BUNDLE_NAME);
    EXPECT_TRUE(param.isEnterpriseBundle);
}

/**
 * @tc.number: BmsSpmManagerTest.FillInstallHnpParam_0001
 * @tc.name: FillInstallHnpParam
 * @tc.desc: Only the session id is set on the hnp install param.
 */
HWTEST_F(BmsSpmManagerTest, FillInstallHnpParam_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    InstallHnpParam param;
    param.hapPath = "/data/local/tmp/test.hap";
    session.FillInstallHnpParam(param);
    EXPECT_EQ(param.sessionId, 0);
    EXPECT_EQ(param.hapPath, "/data/local/tmp/test.hap");
}

/**
 * @tc.number: BmsSpmManagerTest.FillVerifyBinParam_0001
 * @tc.name: FillVerifyBinParam
 * @tc.desc: Only the session id is set on the verify bin param.
 */
HWTEST_F(BmsSpmManagerTest, FillVerifyBinParam_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    VerifyBinParam param;
    param.bundleName = BUNDLE_NAME;
    param.userId = TEST_USERID;
    session.FillVerifyBinParam(param);
    EXPECT_EQ(param.sessionId, 0);
    EXPECT_EQ(param.bundleName, BUNDLE_NAME);
    EXPECT_EQ(param.userId, TEST_USERID);
}

/**
 * @tc.number: BmsSpmManagerTest.DeleteToken_0001
 * @tc.name: DeleteToken NONE
 * @tc.desc: NONE maps to DeleteAccessTokenId(tokenId, false) under SPM OFF.
 */
HWTEST_F(BmsSpmManagerTest, DeleteToken_0001, Function | MediumTest | Level1)
{
    EXPECT_EQ(OHOS::g_deleteAccessTokenIdCount, 0);
    int32_t ret = BundleSpmManager::DeleteToken(TEST_TOKENID, BUNDLE_NAME,
        BundleSpmManager::TokenDeleteType::NONE);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(OHOS::g_deleteAccessTokenIdCount, 1);
    EXPECT_FALSE(OHOS::g_deleteAccessTokenIdReserved);
}

/**
 * @tc.number: BmsSpmManagerTest.DeleteToken_0002
 * @tc.name: DeleteToken RESERVED_IDENTITY
 * @tc.desc: RESERVED_IDENTITY maps to DeleteAccessTokenId(tokenId, true).
 */
HWTEST_F(BmsSpmManagerTest, DeleteToken_0002, Function | MediumTest | Level1)
{
    EXPECT_EQ(OHOS::g_deleteAccessTokenIdCount, 0);
    int32_t ret = BundleSpmManager::DeleteToken(TEST_TOKENID, BUNDLE_NAME,
        BundleSpmManager::TokenDeleteType::RESERVED_IDENTITY);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(OHOS::g_deleteAccessTokenIdCount, 1);
    EXPECT_TRUE(OHOS::g_deleteAccessTokenIdReserved);
}

/**
 * @tc.number: BmsSpmManagerTest.DeleteToken_0003
 * @tc.name: DeleteToken RESERVED_DATA
 * @tc.desc: RESERVED_DATA keeps the token alive: no deletion is invoked under SPM OFF.
 */
HWTEST_F(BmsSpmManagerTest, DeleteToken_0003, Function | MediumTest | Level1)
{
    EXPECT_EQ(OHOS::g_deleteAccessTokenIdCount, 0);
    int32_t ret = BundleSpmManager::DeleteToken(TEST_TOKENID, BUNDLE_NAME,
        BundleSpmManager::TokenDeleteType::RESERVED_DATA);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(OHOS::g_deleteAccessTokenIdCount, 0);
}

/**
 * @tc.number: BmsSpmManagerTest.VerifyPermission_0001
 * @tc.name: VerifyPermission
 * @tc.desc: SPM OFF: the facade passes through BundlePermissionMgr::VerifyPermission
 *           with the identical return value.
 */
HWTEST_F(BmsSpmManagerTest, VerifyPermission_0001, Function | MediumTest | Level1)
{
    OHOS::g_testVerifyPermission = -1;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    int32_t facadeRet = session.VerifyPermission(BUNDLE_NAME, PERMISSION_NAME, TEST_USERID);
    int32_t directRet = BundlePermissionMgr::VerifyPermission(
        BUNDLE_NAME, PERMISSION_NAME, TEST_USERID);
    EXPECT_EQ(facadeRet, directRet);
    EXPECT_EQ(facadeRet, -1);

    OHOS::g_testVerifyPermission = 0;
    facadeRet = session.VerifyPermission(BUNDLE_NAME, PERMISSION_NAME, TEST_USERID);
    directRet = BundlePermissionMgr::VerifyPermission(BUNDLE_NAME, PERMISSION_NAME, TEST_USERID);
    EXPECT_EQ(facadeRet, directRet);
    EXPECT_EQ(facadeRet, ERR_OK);
}

/**
 * @tc.number: BmsSpmManagerTest.DeliverySignProfile_0001
 * @tc.name: DeliverySignProfile
 * @tc.desc: SPM OFF: the facade is a passthrough of InstalldClient::DeliverySignProfile,
 *           including the parameter-error path.
 */
HWTEST_F(BmsSpmManagerTest, DeliverySignProfile_0001, Function | MediumTest | Level1)
{
    unsigned char profileBlock[] = "testProfileBlock";
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    ErrCode facadeRet = session.DeliverySignProfile("", sizeof(profileBlock), profileBlock);
    ErrCode directRet = InstalldClient::GetInstance()->DeliverySignProfile(
        "", sizeof(profileBlock), profileBlock);
    EXPECT_EQ(facadeRet, directRet);
    EXPECT_EQ(facadeRet, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: BmsSpmManagerTest.InitToken_0001
 * @tc.name: InitToken with a zero token id
 * @tc.desc: Zero token id takes the InitHapToken branch; with the mock returning
 *           success and no data mgr the facade returns ERR_OK.
 */
HWTEST_F(BmsSpmManagerTest, InitToken_0001, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult,
        "", nullptr, false), ERR_OK);
}

/**
 * @tc.number: BmsSpmManagerTest.InitToken_0002
 * @tc.name: InitToken with a non-zero token id
 * @tc.desc: Non-zero token id (keep-data recovery) takes the UpdateHapToken branch.
 */
HWTEST_F(BmsSpmManagerTest, InitToken_0002, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult,
        "", nullptr, false), ERR_OK);
}

/**
 * @tc.number: BmsSpmManagerTest.UpdateToken_0001
 * @tc.name: UpdateToken
 * @tc.desc: SPM OFF: token update passes through with ERR_OK on the success mock.
 */
HWTEST_F(BmsSpmManagerTest, UpdateToken_0001, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult,
        "", false, false), ERR_OK);
}

/**
 * @tc.number: BmsSpmManagerTest.Move_0001
 * @tc.name: Move semantics
 * @tc.desc: Moving a session keeps its SPM OFF state; the moved-from session stays
 *           empty and safe to destroy.
 */
HWTEST_F(BmsSpmManagerTest, Move_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    auto moved = std::move(session);
    EXPECT_EQ(moved.GetSessionId(), 0);
    EXPECT_FALSE(moved.IsActive());
    std::vector<Security::Verify::HapVerifyResult> results;
    EXPECT_FALSE(moved.GetHapVerifyResults(results));
}

// ---- Error code conservation cases (AC-19): the facade passes the raw return
// code of the underlying API through on every failure path. ----

/**
 * @tc.number: BmsSpmManagerTest.InitToken_0003
 * @tc.name: InitToken new-token failure passthrough
 * @tc.desc: When InitHapToken fails, InitToken returns the identical raw code.
 */
HWTEST_F(BmsSpmManagerTest, InitToken_0003, Function | MediumTest | Level1)
{
    OHOS::g_initHapTokenRet = -1;
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult,
        "", nullptr, false), -1);
}

/**
 * @tc.number: BmsSpmManagerTest.InitToken_0004
 * @tc.name: InitToken keep-data recovery failure passthrough
 * @tc.desc: When the recovery UpdateHapToken fails, InitToken returns the identical
 *           raw code.
 */
HWTEST_F(BmsSpmManagerTest, InitToken_0004, Function | MediumTest | Level1)
{
    OHOS::g_updateHapTokenRet = -2;
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult,
        "", nullptr, false), -2);
}

/**
 * @tc.number: BmsSpmManagerTest.UpdateToken_0002
 * @tc.name: UpdateToken failure passthrough
 * @tc.desc: When UpdateHapToken fails, UpdateToken returns the identical raw code.
 */
HWTEST_F(BmsSpmManagerTest, UpdateToken_0002, Function | MediumTest | Level1)
{
    OHOS::g_updateHapTokenRet = -3;
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult,
        "", false, false), -3);
}

/**
 * @tc.number: BmsSpmManagerTest.DeleteToken_0004
 * @tc.name: DeleteToken failure passthrough
 * @tc.desc: When DeleteAccessTokenId fails, DeleteToken returns the identical raw code.
 */
HWTEST_F(BmsSpmManagerTest, DeleteToken_0004, Function | MediumTest | Level1)
{
    OHOS::g_deleteAccessTokenIdRet = -4;
    EXPECT_EQ(BundleSpmManager::DeleteToken(TEST_TOKENID, BUNDLE_NAME,
        BundleSpmManager::TokenDeleteType::NONE), -4);
    EXPECT_EQ(OHOS::g_deleteAccessTokenIdCount, 1);
}

/**
 * @tc.number: BmsSpmManagerTest.UpdateToken_0003
 * @tc.name: UpdateToken argument passthrough
 * @tc.desc: AC-7: the facade forwards dataRefresh/isDebugGrant to the underlying
 *           UpdateHapToken and keeps the needInit default (true).
 */
HWTEST_F(BmsSpmManagerTest, UpdateToken_0003, Function | MediumTest | Level1)
{
    OHOS::g_updateHapTokenDataRefresh = false;
    OHOS::g_updateHapTokenIsDebugGrant = true;
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult,
        "", true, false), ERR_OK);
    EXPECT_TRUE(OHOS::g_updateHapTokenDataRefresh);
    EXPECT_FALSE(OHOS::g_updateHapTokenIsDebugGrant);
    EXPECT_TRUE(OHOS::g_updateHapTokenNeedInit);
}

// ---- Parcel round-trip cases (AC-13): session id default 0 and a non-zero value
// survive Marshalling -> ReadFromParcel on all four extended IPC params. ----

HWTEST_F(BmsSpmManagerTest, ParcelRoundTrip_CodeSignatureParam_0001, Function | MediumTest | Level1)
{
    CodeSignatureParam param;
    param.bundleName = BUNDLE_NAME;
    param.modulePath = "/data/app/module";
    EXPECT_EQ(param.sessionId, 0);
    Parcel parcel;
    ASSERT_TRUE(param.Marshalling(parcel));
    CodeSignatureParam out;
    ASSERT_TRUE(out.ReadFromParcel(parcel));
    EXPECT_EQ(out.sessionId, 0);
    EXPECT_EQ(out.bundleName, BUNDLE_NAME);
    EXPECT_EQ(out.modulePath, "/data/app/module");

    param.sessionId = TEST_SESSION_ID;
    Parcel parcel2;
    ASSERT_TRUE(param.Marshalling(parcel2));
    CodeSignatureParam out2;
    ASSERT_TRUE(out2.ReadFromParcel(parcel2));
    EXPECT_EQ(out2.sessionId, TEST_SESSION_ID);
}

HWTEST_F(BmsSpmManagerTest, ParcelRoundTrip_CreateDirParam_0001, Function | MediumTest | Level1)
{
    CreateDirParam param;
    param.bundleName = BUNDLE_NAME;
    param.userId = TEST_USERID;
    param.uid = 12450;
    EXPECT_EQ(param.sessionId, 0);
    Parcel parcel;
    ASSERT_TRUE(param.Marshalling(parcel));
    CreateDirParam out;
    ASSERT_TRUE(out.ReadFromParcel(parcel));
    EXPECT_EQ(out.sessionId, 0);
    EXPECT_EQ(out.bundleName, BUNDLE_NAME);
    EXPECT_EQ(out.userId, TEST_USERID);
    EXPECT_EQ(out.uid, 12450);

    param.sessionId = TEST_SESSION_ID;
    Parcel parcel2;
    ASSERT_TRUE(param.Marshalling(parcel2));
    CreateDirParam out2;
    ASSERT_TRUE(out2.ReadFromParcel(parcel2));
    EXPECT_EQ(out2.sessionId, TEST_SESSION_ID);
}

HWTEST_F(BmsSpmManagerTest, ParcelRoundTrip_InstallHnpParam_0001, Function | MediumTest | Level1)
{
    InstallHnpParam param;
    param.hapPath = "/data/local/tmp/test.hap";
    param.hnpPaths = {"typeA/pkgA"};
    EXPECT_EQ(param.sessionId, 0);
    Parcel parcel;
    ASSERT_TRUE(param.Marshalling(parcel));
    InstallHnpParam out;
    ASSERT_TRUE(out.ReadFromParcel(parcel));
    EXPECT_EQ(out.sessionId, 0);
    EXPECT_EQ(out.hapPath, "/data/local/tmp/test.hap");
    ASSERT_EQ(out.hnpPaths.size(), 1);
    EXPECT_EQ(out.hnpPaths[0], "typeA/pkgA");

    param.sessionId = TEST_SESSION_ID;
    Parcel parcel2;
    ASSERT_TRUE(param.Marshalling(parcel2));
    InstallHnpParam out2;
    ASSERT_TRUE(out2.ReadFromParcel(parcel2));
    EXPECT_EQ(out2.sessionId, TEST_SESSION_ID);
}

HWTEST_F(BmsSpmManagerTest, ParcelRoundTrip_VerifyBinParam_0001, Function | MediumTest | Level1)
{
    VerifyBinParam param;
    param.bundleName = BUNDLE_NAME;
    param.userId = TEST_USERID;
    param.binFilePaths = {"/data/app/so/libtest.so"};
    param.isDebug = true;
    EXPECT_EQ(param.sessionId, 0);
    Parcel parcel;
    ASSERT_TRUE(param.Marshalling(parcel));
    VerifyBinParam out;
    ASSERT_TRUE(out.ReadFromParcel(parcel));
    EXPECT_EQ(out.sessionId, 0);
    EXPECT_EQ(out.bundleName, BUNDLE_NAME);
    EXPECT_EQ(out.userId, TEST_USERID);
    ASSERT_EQ(out.binFilePaths.size(), 1);
    EXPECT_TRUE(out.isDebug);

    param.sessionId = TEST_SESSION_ID;
    Parcel parcel2;
    ASSERT_TRUE(param.Marshalling(parcel2));
    VerifyBinParam out2;
    ASSERT_TRUE(out2.ReadFromParcel(parcel2));
    EXPECT_EQ(out2.sessionId, TEST_SESSION_ID);
}

// Remaining acceptance items deferred to the integration environment (no local build):
// - AC-2 success-path equality needs real signed haps (test_bundle resources).
// - AC-5 uid allocation branch needs a data manager instance (no BundleDataMgr mock here).
// - AC-14 ERR_OK shell body runs only with foundation uid; the permission-gate case is
//   covered by BmsInstallDaemonHostImplTest.InstalldHostImplTest_3100.

/**
 * @tc.number: BmsSpmManagerTest.IsRecoverableSpmError_0002
 * @tc.name: IsRecoverableSpmError is disabled under SPM OFF
 * @tc.desc: The switch gate makes the recovery detection always false under SPM
 *           OFF, so the SPM OFF error-code contract is never affected even when
 *           a legacy AT path happens to return the same numeric codes.
 */
HWTEST_F(BmsSpmManagerTest, IsRecoverableSpmError_0002, Function | MediumTest | Level1)
{
    EXPECT_FALSE(BundleSpmManager::IsRecoverableSpmError(
        Security::AccessToken::AccessTokenError::ERR_UID_NOT_EXIST));
    EXPECT_FALSE(BundleSpmManager::IsRecoverableSpmError(
        Security::AccessToken::AccessTokenError::ERR_BUNDLE_ALREADY_EXIST));
    EXPECT_FALSE(BundleSpmManager::IsRecoverableSpmError(-1));
    // The wrapper follows the gate: nothing is wrapped under SPM OFF.
    EXPECT_EQ(BundleSpmManager::WrapRecoverableSpmErrorCode(
        Security::AccessToken::AccessTokenError::ERR_UID_NOT_EXIST),
        Security::AccessToken::AccessTokenError::ERR_UID_NOT_EXIST);
}

// ===== BundleSpmManager::FinishHapInstall (production logic, relocated from
// BundlePermissionMgr so it stays real in mock-linked test targets) =====

/**
 * @tc.number: BmsSpmManagerTest.FinishHapInstall_ZeroSession_0001
 * @tc.name: A zero session id short-circuits without AT or cache activity
 * @tc.desc: Legacy (SPM OFF / no session) callers pass session id 0: the call
 *           returns ERR_OK immediately and neither FinishInstall nor the
 *           installd provision-cache clear is invoked.
 */
HWTEST_F(BmsSpmManagerTest, FinishHapInstall_ZeroSession_0001, Function | SmallTest | Level1)
{
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(BundleSpmManager::FinishHapInstall(0, true, modulePathMap), ERR_OK);
    EXPECT_EQ(Security::AccessToken::g_spmFinishInstallCallCount, 0);
    EXPECT_EQ(GetClearSessionProvisionCacheCountForTest(), 0);
}

/**
 * @tc.number: BmsSpmManagerTest.FinishHapInstall_Success_0001
 * @tc.name: A successful finish clears the installd provision cache
 * @tc.desc: FinishInstall succeeds: ERR_OK is returned, the isPersistent flag
 *           is propagated, and the session provision cache in the installd
 *           process is cleared exactly once.
 */
HWTEST_F(BmsSpmManagerTest, FinishHapInstall_Success_0001, Function | SmallTest | Level1)
{
    Security::AccessToken::g_spmFinishInstallRet = 0;
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(BundleSpmManager::FinishHapInstall(56789, true, modulePathMap), ERR_OK);
    EXPECT_EQ(Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_TRUE(Security::AccessToken::g_spmFinishInstallLastPersistent);
    EXPECT_EQ(GetClearSessionProvisionCacheCountForTest(), 1);
}

/**
 * @tc.number: BmsSpmManagerTest.FinishHapInstall_TransientRetrySucceeds_0001
 * @tc.name: A write-parcel failure is retried once and may succeed
 * @tc.desc: The first FinishInstall fails with ERR_WRITE_PARCEL_FAILED (the
 *           request provably never reached the AT side) and the retry
 *           succeeds: ERR_OK is returned after exactly two AT calls and the
 *           installd cache is cleared once (by the successful retry).
 *           Ambiguous codes (SERVICE_ABNORMAL / READ_PARCEL_FAILED) are NOT
 *           retried — see FinishHapInstall_AmbiguousNoRetry_0001.
 */
HWTEST_F(BmsSpmManagerTest, FinishHapInstall_TransientRetrySucceeds_0001, Function | SmallTest | Level1)
{
    Security::AccessToken::g_spmFinishInstallRetSeq = {
        Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED, 0};
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(BundleSpmManager::FinishHapInstall(56789, false, modulePathMap), ERR_OK);
    EXPECT_EQ(Security::AccessToken::g_spmFinishInstallCallCount, 2);
    EXPECT_FALSE(Security::AccessToken::g_spmFinishInstallLastPersistent);
    EXPECT_EQ(GetClearSessionProvisionCacheCountForTest(), 1);
}

/**
 * @tc.number: BmsSpmManagerTest.FinishHapInstall_TransientRetryStillFails_0001
 * @tc.name: A still-failing retry propagates the error without cache cleanup
 * @tc.desc: Both the first FinishInstall and its retry fail with the safe
 *           retryable code: the last error is returned, the cache is NOT
 *           cleared (the session is not finished on the AT side), and no
 *           further retries.
 */
HWTEST_F(BmsSpmManagerTest, FinishHapInstall_TransientRetryStillFails_0001, Function | SmallTest | Level1)
{
    Security::AccessToken::g_spmFinishInstallRetSeq = {
        Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED,
        Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED};
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(BundleSpmManager::FinishHapInstall(56789, true, modulePathMap),
        Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED);
    EXPECT_EQ(Security::AccessToken::g_spmFinishInstallCallCount, 2);
    EXPECT_EQ(GetClearSessionProvisionCacheCountForTest(), 0);
}

/**
 * @tc.number: BmsSpmManagerTest.FinishHapInstall_AmbiguousNoRetry_0001
 * @tc.name: Ambiguous failures are NOT retried
 * @tc.desc: SERVICE_ABNORMAL and READ_PARCEL_FAILED may mean the AT side
 *           already finished the session — a blind retry could double-apply
 *           or hit a finished session. Both codes are returned as-is after
 *           exactly one AT call.
 */
HWTEST_F(BmsSpmManagerTest, FinishHapInstall_AmbiguousNoRetry_0001, Function | SmallTest | Level1)
{
    Security::AccessToken::g_spmFinishInstallRet =
        Security::AccessToken::AccessTokenError::ERR_SERVICE_ABNORMAL;
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(BundleSpmManager::FinishHapInstall(56789, true, modulePathMap),
        Security::AccessToken::AccessTokenError::ERR_SERVICE_ABNORMAL);
    EXPECT_EQ(Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_EQ(GetClearSessionProvisionCacheCountForTest(), 0);

    Security::AccessToken::g_spmFinishInstallRet =
        Security::AccessToken::AccessTokenError::ERR_READ_PARCEL_FAILED;
    Security::AccessToken::g_spmFinishInstallCallCount = 0;
    EXPECT_EQ(BundleSpmManager::FinishHapInstall(56789, true, modulePathMap),
        Security::AccessToken::AccessTokenError::ERR_READ_PARCEL_FAILED);
    EXPECT_EQ(Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_EQ(GetClearSessionProvisionCacheCountForTest(), 0);
}

/**
 * @tc.number: BmsSpmManagerTest.FinishHapInstall_NonTransientNoRetry_0001
 * @tc.name: A non-transient failure is returned without any retry
 * @tc.desc: A business error (not in the transient set) is returned as-is
 *           after exactly one AT call; the installd cache stays untouched.
 */
HWTEST_F(BmsSpmManagerTest, FinishHapInstall_NonTransientNoRetry_0001, Function | SmallTest | Level1)
{
    Security::AccessToken::g_spmFinishInstallRet = -5;  // not a transient IPC error
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(BundleSpmManager::FinishHapInstall(56789, true, modulePathMap), -5);
    EXPECT_EQ(Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_EQ(GetClearSessionProvisionCacheCountForTest(), 0);
}

// ===== BundleSpmManager::CreateBundlePolicy =====

/**
 * @tc.number: BmsSpmManagerTest.CreateBundlePolicy_NoDefaultPermission_0001
 * @tc.name: No default permission configured yields an empty policy
 * @tc.desc: GetDefaultPermission reports no configuration for the bundle:
 *           the pre-authorization list stays empty while dlpType and the
 *           debug-grant flag are still carried.
 */
HWTEST_F(BmsSpmManagerTest, CreateBundlePolicy_NoDefaultPermission_0001, Function | SmallTest | Level1)
{
    g_defaultPermissionRet = false;
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);

    auto policy = BundleSpmManager::CreateBundlePolicy(info, 1, true);
    EXPECT_TRUE(policy.preAuthorizationInfo.empty());
    EXPECT_EQ(policy.dlpType, Security::AccessToken::DlpType(1));
    EXPECT_TRUE(policy.isDebugGrant);
}

/**
 * @tc.number: BmsSpmManagerTest.CreateBundlePolicy_FullPreAuthorization_0001
 * @tc.name: A matched default permission is fully pre-authorized
 * @tc.desc: The matched default permission's grant list is carried into the
 *           policy verbatim (permissionName/userCancelable) — the full set is
 *           pre-authorized regardless of what this particular profile
 *           requests (full-set grant decision).
 */
HWTEST_F(BmsSpmManagerTest, CreateBundlePolicy_FullPreAuthorization_0001, Function | SmallTest | Level1)
{
    DefaultPermission defaultPermission;
    defaultPermission.bundleName = BUNDLE_NAME;
    PermissionInfo first;
    first.name = "ohos.permission.TEST_A";
    first.userCancellable = true;
    defaultPermission.grantPermission.emplace_back(first);
    PermissionInfo second;
    second.name = "ohos.permission.TEST_B";
    second.userCancellable = false;
    defaultPermission.grantPermission.emplace_back(second);
    g_mockDefaultPermission = defaultPermission;

    InnerBundleInfo info;  // requests nothing: the policy still gets the full set
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);

    auto policy = BundleSpmManager::CreateBundlePolicy(info, 2, false);
    ASSERT_EQ(policy.preAuthorizationInfo.size(), static_cast<size_t>(2));
    EXPECT_EQ(policy.preAuthorizationInfo[0].permissionName, "ohos.permission.TEST_A");
    EXPECT_TRUE(policy.preAuthorizationInfo[0].userCancelable);
    EXPECT_EQ(policy.preAuthorizationInfo[1].permissionName, "ohos.permission.TEST_B");
    EXPECT_FALSE(policy.preAuthorizationInfo[1].userCancelable);
    EXPECT_EQ(policy.dlpType, Security::AccessToken::DlpType(2));
    EXPECT_FALSE(policy.isDebugGrant);
}

#ifdef USE_PRE_BUNDLE_PROFILE
/**
 * @tc.number: BmsSpmManagerTest.CreateBundlePolicy_SignatureMismatch_0001
 * @tc.name: A signature mismatch yields an empty pre-authorization list
 * @tc.desc: Under USE_PRE_BUNDLE_PROFILE a default permission whose
 *           signatures do not match the bundle is not pre-authorized.
 *           (Not compiled in this target: it does not define the macro.)
 */
HWTEST_F(BmsSpmManagerTest, CreateBundlePolicy_SignatureMismatch_0001, Function | SmallTest | Level1)
{
    g_matchSignatureRet = false;
    DefaultPermission defaultPermission;
    defaultPermission.bundleName = BUNDLE_NAME;
    PermissionInfo granted;
    granted.name = "ohos.permission.TEST_A";
    defaultPermission.grantPermission.emplace_back(granted);
    g_mockDefaultPermission = defaultPermission;

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);

    auto policy = BundleSpmManager::CreateBundlePolicy(info, 0, false);
    EXPECT_TRUE(policy.preAuthorizationInfo.empty());
}
#endif

// ===== BundleSpmManager singleton / module-uninstall / recovery (SPM OFF) =====
// Under SPM OFF: GetInstance is state-independent; OnModuleUninstalled is a
// documented no-op; both recovery helpers short-circuit to false before any
// AT call. ParseTrustedBundleInfo has no SPM OFF surface (the ON-only
// trusted-bundle parsing runs behind CheckSignAndInitSession's AT branch).

/**
 * @tc.number: BmsSpmManagerTest.GetInstance_0001
 * @tc.name: GetInstance returns the same non-null singleton
 */
HWTEST_F(BmsSpmManagerTest, GetInstance_0001, Function | SmallTest | Level1)
{
    auto &first = BundleSpmManager::GetInstance();
    auto &second = BundleSpmManager::GetInstance();
    EXPECT_EQ(&first, &second);
}

/**
 * @tc.number: BmsSpmManagerTest.OnModuleUninstalled_Off_NoOp_0001
 * @tc.name: OnModuleUninstalled is a no-op under SPM OFF
 * @tc.desc: The module-uninstall re-sign flow is SPM-ON-only; under OFF it
 *           returns ERR_OK without touching the AT side.
 */
HWTEST_F(BmsSpmManagerTest, OnModuleUninstalled_Off_NoOp_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);

    EXPECT_EQ(BundleSpmManager::OnModuleUninstalled(info, TEST_USERID), ERR_OK);
    EXPECT_EQ(Security::AccessToken::g_spmFinishInstallCallCount, 0);
}

/**
 * @tc.number: BmsSpmManagerTest.TryRecoverUidError_Off_False_0001
 * @tc.name: The uid recovery is disabled under SPM OFF
 */
HWTEST_F(BmsSpmManagerTest, TryRecoverUidError_Off_False_0001, Function | SmallTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    EXPECT_FALSE(BundleSpmManager::TryRecoverUidError(BUNDLE_NAME, dataMgr.get()));
}

/**
 * @tc.number: BmsSpmManagerTest.TryRecoverAlreadyExistError_Off_False_0001
 * @tc.name: The leftover-identity recovery is disabled under SPM OFF
 */
HWTEST_F(BmsSpmManagerTest, TryRecoverAlreadyExistError_Off_False_0001, Function | SmallTest | Level1)
{
    EXPECT_FALSE(BundleSpmManager::TryRecoverAlreadyExistError(BUNDLE_NAME));
}

/**
 * @tc.number: ConvertHapVerifyResultCode_0100
 * @tc.name: errorCode 0 + ret success returns ERR_OK
 * @tc.desc: Both the AT call and the per-hap verification succeeded:
 *           errorCode == 0 and ret == RET_SUCCESS -> ERR_OK.
 */
HWTEST_F(BmsSpmManagerTest, ConvertHapVerifyResultCode_0100, Function | SmallTest | Level1)
{
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(
        Security::Verify::HapVerifyResultCode::VERIFY_SUCCESS,
        Security::AccessToken::AccessTokenKitRet::RET_SUCCESS),
        ERR_OK);
}

/**
 * @tc.number: ConvertHapVerifyResultCode_0200
 * @tc.name: errorCode 0 + AT-level ret maps to pre-SPM BMS codes
 * @tc.desc: errorCode == 0 (no per-hap result, AT call itself failed):
 *           the AT-level ret is mapped to the pre-SPM BMS error codes —
 *           PARAM_INVALID→PARAM_ERROR, CHECK_MULTIPLE_HAP→INCOMPATIBLE_SIGNATURE,
 *           ALREADY_EXIST→passthrough (recovery chain), others→SIGNATURE_FAILURE.
 */
HWTEST_F(BmsSpmManagerTest, ConvertHapVerifyResultCode_0200, Function | SmallTest | Level1)
{
    using ATE = Security::AccessToken::AccessTokenError;
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(
        Security::Verify::HapVerifyResultCode::VERIFY_SUCCESS, ATE::ERR_PARAM_INVALID),
        ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(
        Security::Verify::HapVerifyResultCode::VERIFY_SUCCESS, ATE::ERR_CHECK_MULTIPLE_HAP_FAILED),
        ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(
        Security::Verify::HapVerifyResultCode::VERIFY_SUCCESS, ATE::ERR_BUNDLE_ALREADY_EXIST),
        ATE::ERR_BUNDLE_ALREADY_EXIST);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(
        Security::Verify::HapVerifyResultCode::VERIFY_SUCCESS, ATE::ERR_HAP_SIGN_VERIFY_FAILED),
        ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(
        Security::Verify::HapVerifyResultCode::VERIFY_SUCCESS, ATE::ERR_SESSION_NOT_EXIST),
        ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(
        Security::Verify::HapVerifyResultCode::VERIFY_SUCCESS, ATE::ERR_HAP_PROVISION_INVALID),
        ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(
        Security::Verify::HapVerifyResultCode::VERIFY_SUCCESS, ATE::ERR_SERVICE_ABNORMAL),
        ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
}

/**
 * @tc.number: ConvertHapVerifyResultCode_0300
 * @tc.name: Each known HapVerifyResultCode maps to its registered BMS code
 * @tc.desc: All 17 non-success HapVerifyResultCode values (excluding
 *           VERIFY_SUCCESS) map through the shared HAP_VERIFY_ERR_MAP —
 *           the same mapping the OFF-path verification uses.
 */
HWTEST_F(BmsSpmManagerTest, ConvertHapVerifyResultCode_0300, Function | SmallTest | Level1)
{
    using VR = Security::Verify::HapVerifyResultCode;
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::FILE_PATH_INVALID),
        ERR_APPEXECFWK_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::OPEN_FILE_ERROR),
        ERR_APPEXECFWK_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE_FILE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::SIGNATURE_NOT_FOUND),
        ERR_APPEXECFWK_INSTALL_FAILED_NO_BUNDLE_SIGNATURE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::VERIFY_APP_PKCS7_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_APP_PKCS7_FAIL);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::PROFILE_PARSE_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::APP_SOURCE_NOT_TRUSTED),
        ERR_APPEXECFWK_INSTALL_FAILED_APP_SOURCE_NOT_TRUESTED);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::GET_DIGEST_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_BAD_DIGEST);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::VERIFY_INTEGRITY_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_INTEGRITY_VERIFICATION_FAILURE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::FILE_SIZE_TOO_LARGE),
        ERR_APPEXECFWK_INSTALL_FAILED_FILE_SIZE_TOO_LARGE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::GET_PUBLICKEY_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_BAD_PUBLICKEY);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::GET_SIGNATURE_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::NO_PROFILE_BLOCK_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_NO_PROFILE_BLOCK_FAIL);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::VERIFY_SIGNATURE_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::VERIFY_SOURCE_INIT_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_SOURCE_INIT_FAIL);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::DEVICE_UNAUTHORIZED),
        ERR_APPEXECFWK_INSTALL_FAILED_DEVICE_UNAUTHORIZED);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::CERTIFICATE_EXPIRED),
        ERR_APPEXECFWK_INSTALL_FAILED_CERTIFICATE_EXPIRED);
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(VR::VERIFY_ENTERPRISE_RESIGN_FAIL),
        ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_ENTERPRISE_RESIGN_FAIL);
}

/**
 * @tc.number: ConvertHapVerifyResultCode_0400
 * @tc.name: Unknown errorCode and unknown ret both fold into signature failure
 * @tc.desc: verifyResultCode not in HAP_VERIFY_ERR_MAP_KEY and ret is an
 *           arbitrary positive/negative number — generic signature failure.
 */
HWTEST_F(BmsSpmManagerTest, ConvertHapVerifyResultCode_0400, Function | SmallTest | Level1)
{
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(99999),
        ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    // A small negative like -1 is NOT unknown: HapVerifyResultCode::FILE_PATH_INVALID
    // is -1 (covered by the _0300 mapping above) — use an out-of-range negative here.
    EXPECT_EQ(BundleVerifyMgr::ConvertHapVerifyResultCode(-99999),
        ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
}

/**
 * @tc.number: BmsSpmManagerTest.CheckNewInstallIdentity_0001
 * @tc.name: The identity plan is inert under SPM OFF
 * @tc.desc: Even with an AT-side token visible to the query, the SPM OFF
 *           contract keeps the plan at zero: no reuse path, no AT touch.
 */
HWTEST_F(BmsSpmManagerTest, CheckNewInstallIdentity_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmGetHapTokenIDRet = 101;
    auto plan = BundleSpmManager::CheckNewInstallIdentity(TEST_USERID, BUNDLE_NAME,
        Constants::INITIAL_APP_INDEX, nullptr);
    EXPECT_EQ(plan.reuseTokenId, 0);
    EXPECT_FALSE(plan.keepDataReinstall);
    OHOS::Security::AccessToken::g_spmGetHapTokenIDRet = 0;
}

/**
 * @tc.number: BmsSpmManagerTest.HasAtIdentity_0001
 * @tc.name: HasAtIdentity is always false under SPM OFF
 * @tc.desc: The update-flow branch selector must not query the AT side under
 *           SPM OFF (the legacy UpdateHapToken flow stays untouched).
 */
HWTEST_F(BmsSpmManagerTest, HasAtIdentity_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmGetHapTokenIDRet = 101;
    EXPECT_FALSE(BundleSpmManager::HasAtIdentity(TEST_USERID, BUNDLE_NAME,
        Constants::INITIAL_APP_INDEX));
    OHOS::Security::AccessToken::g_spmGetHapTokenIDRet = 0;
}
} // namespace OHOS
