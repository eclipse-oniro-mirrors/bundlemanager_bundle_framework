/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define protected public
#include "bundle_command.h"
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class BmCommandQuickFixTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::string cmd_ = "quickfix";
};

void BmCommandQuickFixTest::SetUpTestCase()
{}

void BmCommandQuickFixTest::TearDownTestCase()
{}

void BmCommandQuickFixTest::SetUp()
{
    // reset optind to 0
    optind = 0;
}

void BmCommandQuickFixTest::TearDown()
{}

/**
 * @tc.name: Bm_Command_QuickFix_0100
 * @tc.desc: "bm quickfix" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_0100, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "error: parameter is not enough.\n" + HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_0200
 * @tc.desc: "bm quickfix --invalid" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_0200, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--invalid",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "error: unknown option.\n" + HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Help_0100
 * @tc.desc: "bm quickfix -h" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Help_0100, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-h",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Help_0200
 * @tc.desc: "bm quickfix --help" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Help_0200, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--help",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Apply_0100
 * @tc.desc: "bm quickfix -a" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Apply_0100, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-a",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "error: option [--apply] is incorrect.\n" + HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Apply_0200
 * @tc.desc: "bm quickfix --apply" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Apply_0200, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--apply",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "error: option [--apply] is incorrect.\n" + HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Apply_0300
 * @tc.desc: "bm quickfix --apply --invalidKey" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Apply_0300, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--apply",
        (char *)"--invalidKey",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "error: option [--apply] is incorrect.\n" + HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Apply_0400
 * @tc.desc: "bm quickfix --apply --invalidKey invalidValue" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Apply_0400, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--apply",
        (char *)"--invalidKey",
        (char *)"invalidValue",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "error: parameter is not enough.\n" + HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Apply_0500
 * @tc.desc: "bm quickfix --apply -f <file-path>" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Apply_0500, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--apply",
        (char *)"-f",
        (char *)"/data/storage/el1/aa.hqf",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "check file path failed.\n");
}

/**
 * @tc.name: Bm_Command_QuickFix_Apply_0600
 * @tc.desc: "bm quickfix --apply --file-path <file-path> <file-path>" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Apply_0600, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--apply",
        (char *)"--file-path",
        (char *)"/data/storage/el1/aa.hqf",
        (char *)"/data/storage/el2/bb.hqf",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "check file path failed.\n");
}

/**
 * @tc.name: Bm_Command_QuickFix_Apply_0700
 * @tc.desc: "bm quickfix --apply --file-path <bundle-direction>" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Apply_0700, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--apply",
        (char *)"--file-path",
        (char *)"/data/storage/el1",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "check file path failed.\n");
}

/**
 * @tc.name: Bm_Command_QuickFix_Query_0100
 * @tc.desc: "bm quickfix -q" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Query_0100, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-q",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "error: option [--query] is incorrect.\n" + HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Query_0200
 * @tc.desc: "bm quickfix --query" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Query_0200, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--query",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "error: option [--query] is incorrect.\n" + HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Query_0300
 * @tc.desc: "bm quickfix -q --invalidKey" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Query_0300, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-q",
        (char *)"--invalidKey",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "error: option [--query] is incorrect.\n" + HELP_MSG_QUICK_FIX);
}

/**
 * @tc.name: Bm_Command_QuickFix_Query_0400
 * @tc.desc: "bm quickfix --query --invalidKey invalidValue" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Query_0400, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--query",
        (char *)"--invalidKey",
        (char *)"invalidValue",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "bundle name is empty.\n");
}

/**
 * @tc.name: Bm_Command_QuickFix_Query_0500
 * @tc.desc: "bm quickfix --query -b <bundle-name>" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Query_0500, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--query",
        (char *)"-b",
        (char *)"bundleName1",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "Get quick fix info failed with errno 8.\n");
}

/**
 * @tc.name: Bm_Command_QuickFix_Query_0600
 * @tc.desc: "bm quickfix --query --bundle-name <bundle-name>" test.
 * @tc.type: FUNC
 * @tc.require: issueI5OCZV
 */
HWTEST_F(BmCommandQuickFixTest, Bm_Command_QuickFix_Query_0600, TestSize.Level1)
{
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--query",
        (char *)"--bundle-name",
        (char *)"bundleName1",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    BundleManagerShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "Get quick fix info failed with errno 8.\n");
}
} // namespace AAFwk
} // namespace OHOS
