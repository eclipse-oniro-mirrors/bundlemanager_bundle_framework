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
#include "bundle_install_checker.h"
#include "bundle_permission_mgr.h"
#include "bundle_spm_manager.h"
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
// Control variables defined in test/mock/src/bundle_permission_mgr.cpp.
void ResetSpmFacadeMockValues();
extern int32_t g_testVerifyPermission;
extern int32_t g_deleteAccessTokenIdCount;
extern bool g_deleteAccessTokenIdReserved;
extern int32_t g_initHapTokenRet;
extern int32_t g_updateHapTokenRet;
extern int32_t g_deleteAccessTokenIdRet;
extern bool g_updateHapTokenDataRefresh;
extern bool g_updateHapTokenIsDebugGrant;
extern bool g_updateHapTokenNeedInit;
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

} // namespace OHOS
