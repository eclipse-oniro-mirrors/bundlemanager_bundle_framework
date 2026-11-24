/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#define private public
#include "status_receiver_proxy.h"
#undef private

#include "appexecfwk_errors.h"
#include "status_receiver_interface.h"
#include "ipc_object_stub.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class BmsStatusReceiverProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    sptr<StatusReceiverProxy> receiver_ = nullptr;
};

void BmsStatusReceiverProxyTest::SetUpTestCase() {}

void BmsStatusReceiverProxyTest::TearDownTestCase() {}

void BmsStatusReceiverProxyTest::SetUp()
{
    auto stub = new (std::nothrow) IPCObjectStub(u"testStatusReceiver");
    receiver_ = new (std::nothrow) StatusReceiverProxy(stub);
}

void BmsStatusReceiverProxyTest::TearDown() {}

/**
 * @tc.name: TransformResult_ERR_OK_0100
 * @tc.desc: Test TransformResult with ERR_OK → SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_ERR_OK_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_OK, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::SUCCESS);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[SUCCESS]"));
}

/**
 * @tc.name: TransformResult_InstallInternalError_0100
 * @tc.desc: Test TransformResult with ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_InstallInternalError_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_INSTALL_INTERNAL_ERROR]"));
}

/**
 * @tc.name: TransformResult_AlternateModuleInvalid_0100
 * @tc.desc: Test the alternate module content error uses the existing install result code.
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_AlternateModuleInvalid_0100, Function | SmallTest | Level0)
{
    receiver_->TransformResult(ERR_APPEXECFWK_INSTALL_ALTERNATE_MODULE_INVALID);
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALL_PARAM_ERROR);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[MSG_ERR_INSTALL_ALTERNATE_MODULE_INVALID]"));
}

/**
 * @tc.name: TransformResult_ParseUnexpected_0100
 * @tc.desc: Test TransformResult with ERR_APPEXECFWK_PARSE_UNEXPECTED
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_ParseUnexpected_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_APPEXECFWK_PARSE_UNEXPECTED, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALL_PARSE_UNEXPECTED);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_INSTALL_PARSE_UNEXPECTED]"));
}

/**
 * @tc.name: TransformResult_UninstallParamError_0100
 * @tc.desc: Test TransformResult with ERR_APPEXECFWK_UNINSTALL_PARAM_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_UninstallParamError_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_APPEXECFWK_UNINSTALL_PARAM_ERROR, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_UNINSTALL_PARAM_ERROR);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_UNINSTALL_PARAM_ERROR]"));
}

/**
 * @tc.name: TransformResult_OverlayInternalError_0100
 * @tc.desc: Test TransformResult with ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_OverlayInternalError_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR]"));
}

/**
 * @tc.name: TransformResult_NativeInstallFailed_0100
 * @tc.desc: Test TransformResult with ERR_APPEXECFWK_NATIVE_INSTALL_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_NativeInstallFailed_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_APPEXECFWK_NATIVE_INSTALL_FAILED, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALL_NATIVE_FAILED);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[MSG_ERR_NATIVE_INSTALL_FAILED]"));
}

/**
 * @tc.name: TransformResult_InstallBopdModeDisabled_0100
 * @tc.desc: Test TransformResult with ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_InstallBopdModeDisabled_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_APPEXECFWK_INSTALL_BOPD_MODE_DISABLED, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALL_CODE_APP_CONTROLLED_FAILED);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[MSG_ERR_INSTALL_CODE_APP_CONTROLLED_FAILED]"));
}

/**
 * @tc.name: TransformResult_UnknownErrorCode_0100
 * @tc.desc: Test TransformResult with an unknown error code → ERR_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_UnknownErrorCode_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(99999999, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_UNKNOWN);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_UNKNOWN]"));
}

/**
 * @tc.name: TransformResult_InstalldCodeWithErrno_0100
 * @tc.desc: Test TransformResult with installd error code that has errno embedded.
 *           ExtractInstalldBusinessErrCode should strip the errno part.
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_InstalldCodeWithErrno_0100, Function | SmallTest | Level0)
{
    int32_t codeWithErrno = ERR_APPEXECFWK_INSTALLD_PARAM_ERROR + 5;
    receiver_->OnFinished(codeWithErrno, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALLD_PARAM_ERROR);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_INSTALLD_PARAM_ERROR]"));
}

/**
 * @tc.name: TransformResult_InstalldCodeWithLargeErrno_0100
 * @tc.desc: Test TransformResult with installd error code at max errno boundary (199).
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_InstalldCodeWithLargeErrno_0100, Function | SmallTest | Level0)
{
    int32_t codeWithErrno = ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED + 199;
    receiver_->OnFinished(codeWithErrno, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALLD_CREATE_DIR_FAILED);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_INSTALLD_CREATE_DIR_FAILED]"));
}

/**
 * @tc.name: TransformResult_InstalldCodeNotInMap_0100
 * @tc.desc: Test TransformResult with installd error code that is not in the map → ERR_UNKNOWN.
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_InstalldCodeNotInMap_0100, Function | SmallTest | Level0)
{
    int32_t unmappedInstalldCode = APPEXECFWK_INSTALLD_ERR_OFFSET + 100 * ERRNO_MAX_SIZE;
    receiver_->OnFinished(unmappedInstalldCode, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_UNKNOWN);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_UNKNOWN]"));
}

/**
 * @tc.name: TransformResult_CodeBelowInstalldOffset_0100
 * @tc.desc: Test TransformResult with a regular (non-installd) error code.
 *           ExtractInstalldBusinessErrCode should return it unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_CodeBelowInstalldOffset_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_APPEXECFWK_INSTALL_ALREADY_EXIST, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALL_ALREADY_EXIST);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_INSTALL_ALREADY_EXIST]"));
}

/**
 * @tc.name: TransformResult_ResultMsgOverride_0100
 * @tc.desc: Test that OnFinished does not override resultMsg_ when non-empty resultMsg is passed.
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_ResultMsgOverride_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_OK, "custom message");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::SUCCESS);
    EXPECT_EQ(receiver_->resultMsg_, std::string("custom message"));
}

/**
 * @tc.name: TransformResult_MultipleCalls_0100
 * @tc.desc: Test that TransformResult correctly updates state on successive calls.
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_MultipleCalls_0100, Function | SmallTest | Level0)
{
    receiver_->OnFinished(ERR_OK, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::SUCCESS);

    receiver_->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_INSTALL_INTERNAL_ERROR]"));

    receiver_->OnFinished(99999999, "");
    EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_UNKNOWN);
    EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_UNKNOWN]"));
}

/**
 * @tc.name: TransformResult_DedupSoErrors_0100
 * @tc.desc: Test TransformResult maps every dedup so install error
 *           (CONFIG_UNAVAILABLE / NO_MATCH / LINK_FAILED / VERSION_MISMATCH)
 *           to the converged client code ERR_INSTALL_DEDUP_SO_LINK_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(BmsStatusReceiverProxyTest, TransformResult_DedupSoErrors_0100, Function | SmallTest | Level0)
{
    const int32_t dedupSoErrors[] = {
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_CONFIG_UNAVAILABLE,
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_NO_MATCH,
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED,
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_VERSION_MISMATCH,
    };
    for (int32_t dedupSoError : dedupSoErrors) {
        receiver_->OnFinished(dedupSoError, "");
        EXPECT_EQ(receiver_->resultCode_, IStatusReceiver::ERR_INSTALL_DEDUP_SO_LINK_FAILED);
        EXPECT_EQ(receiver_->resultMsg_, std::string("[ERR_INSTALL_DEDUP_SO_LINK_FAILED]"));
    }
}
}  // namespace
