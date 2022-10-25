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

#include <cstdio>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bundle_install_checker.h"
#include "directory_ex.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string HAP = "hap";
const std::string HAP_ONE = "hap1";
const std::string HAP_TWO = "hap2";
const std::string HAP_THREE = "hap3";
const std::string HAP_FOUR = "hap4";
const std::string HAP_FIVE = "hap5";
const std::string ARM = "arm";
const std::string ARM_SO_PATH = "/lib/arm/arm.so";
const std::string ARM_AN_PATH = "/an/arm/arm.so";
const std::string X86 = "x86";
const std::string X86_SO_PATH = "/lib/x86/x86.so";
const std::string X86_AN_PATH = "/an/x86/x86.so";
}  // namespace

class BmsBundleInstallCheckerTest : public testing::Test {
public:
    BmsBundleInstallCheckerTest();
    ~BmsBundleInstallCheckerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleInstallCheckerTest::BmsBundleInstallCheckerTest()
{}

BmsBundleInstallCheckerTest::~BmsBundleInstallCheckerTest()
{}

void BmsBundleInstallCheckerTest::SetUpTestCase()
{
}

void BmsBundleInstallCheckerTest::TearDownTestCase()
{}

void BmsBundleInstallCheckerTest::SetUp()
{}

void BmsBundleInstallCheckerTest::TearDown()
{}

/**
 * @tc.number: CheckMultiNativeFile_0100
 * @tc.name: test the start function of BundleInstallChecker
 * @tc.desc: 1. BundleInstallChecker
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMultiNativeFile_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(HAP, innerBundleInfo);

    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.SetArkNativeFileAbi(ARM);
    innerBundleInfo1.SetArkNativeFilePath(ARM_AN_PATH);
    innerBundleInfo1.SetCpuAbi(ARM);
    innerBundleInfo1.SetNativeLibraryPath(ARM_SO_PATH);
    infos.emplace(HAP_ONE, innerBundleInfo1);

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.SetArkNativeFileAbi(ARM);
    innerBundleInfo2.SetArkNativeFilePath(ARM_AN_PATH);
    innerBundleInfo2.SetCpuAbi(ARM);
    innerBundleInfo2.SetNativeLibraryPath(ARM_SO_PATH);
    infos.emplace(HAP_TWO, innerBundleInfo2);
    ErrCode ret = bundleInstallChecker.CheckMultiNativeFile(infos);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleInfo innerBundleInfo3;
    infos.emplace(HAP_THREE, innerBundleInfo3);
    ret = bundleInstallChecker.CheckMultiNativeFile(infos);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleInfo innerBundleInfo4;
    innerBundleInfo4.SetArkNativeFileAbi(X86);
    innerBundleInfo4.SetArkNativeFilePath(X86_AN_PATH);
    infos.emplace(HAP_FOUR, innerBundleInfo4);
    ret = bundleInstallChecker.CheckMultiNativeFile(infos);
    EXPECT_NE(ret, ERR_OK);

    InnerBundleInfo innerBundleInfo5;
    innerBundleInfo5.SetCpuAbi(X86);
    innerBundleInfo5.SetNativeLibraryPath(X86_SO_PATH);
    infos.emplace(HAP_FIVE, innerBundleInfo5);
    ret = bundleInstallChecker.CheckMultiNativeFile(infos);
    EXPECT_NE(ret, ERR_OK);
}
} // OHOS
