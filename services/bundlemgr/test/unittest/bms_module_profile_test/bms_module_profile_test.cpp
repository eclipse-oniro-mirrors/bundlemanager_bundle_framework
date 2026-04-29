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
#define protected public

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <map>

#include "module_profile.h"
#include "inner_bundle_info.h"
#include "bundle_service_constants.h"
#include "appexecfwk_errors.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::ServiceConstants;

namespace OHOS {
namespace {

const std::string CPU_ABI = "armeabi-v7a";
const std::string MODULE_PACKAGE = "module_package";
const std::string NORMAL_DIR = "libs/subA";
const std::string LONG_DIR(4097, 'x');
const std::string PATH_TRAVERSAL_DIR = "libs/../etc";

class BmsModuleProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsModuleProfileTest::SetUpTestCase()
{}

void BmsModuleProfileTest::TearDownTestCase()
{}

void BmsModuleProfileTest::SetUp()
{}

void BmsModuleProfileTest::TearDown()
{}

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_001
 * @tc.name: Test ProcessLibrarySupportDirectory with empty map
 * @tc.desc: When librarySupportDirectoryMap is empty, should return ERR_OK
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_001, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    innerBundleInfo.SetCpuAbi(CPU_ABI);

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_002
 * @tc.name: Test ProcessLibrarySupportDirectory with empty cpuAbi
 * @tc.desc: When cpuAbi is empty, should return ERR_OK
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_002, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    librarySupportDirectoryMap[CPU_ABI] = {NORMAL_DIR};
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    // cpuAbi is empty by default

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_003
 * @tc.name: Test ProcessLibrarySupportDirectory when cpuAbi not in map
 * @tc.desc: When cpuAbi is not found in map, should return ERR_OK
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_003, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    librarySupportDirectoryMap["otherCpuAbi"] = {NORMAL_DIR};
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    innerBundleInfo.SetCpuAbi(CPU_ABI);

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_004
 * @tc.name: Test ProcessLibrarySupportDirectory when dirs size > 1024
 * @tc.desc: When dirs size exceeds 1024, should return ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_004, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    std::vector<std::string> dirs(1025, NORMAL_DIR);
    librarySupportDirectoryMap[CPU_ABI] = dirs;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    innerBundleInfo.SetCpuAbi(CPU_ABI);

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR);
}

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_005
 * @tc.name: Test ProcessLibrarySupportDirectory when single dir length > 4096
 * @tc.desc: The dir exceeding length should be filtered, remaining dirs should be set
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_005, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    librarySupportDirectoryMap[CPU_ABI] = {NORMAL_DIR, LONG_DIR, "libs/subB"};
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    innerBundleInfo.SetCpuAbi(CPU_ABI);

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &result = innerBundleInfo.innerModuleInfos_[MODULE_PACKAGE].librarySupportDirectory;
    EXPECT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], NORMAL_DIR);
    EXPECT_EQ(result[1], "libs/subB");
}

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_006
 * @tc.name: Test ProcessLibrarySupportDirectory when single dir contains path traversal ".."
 * @tc.desc: The dir containing ".." should be filtered, remaining dirs should be set
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_006, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    librarySupportDirectoryMap[CPU_ABI] = {NORMAL_DIR, PATH_TRAVERSAL_DIR, "libs/subC"};
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    innerBundleInfo.SetCpuAbi(CPU_ABI);

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &result = innerBundleInfo.innerModuleInfos_[MODULE_PACKAGE].librarySupportDirectory;
    EXPECT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], NORMAL_DIR);
    EXPECT_EQ(result[1], "libs/subC");
}

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_007
 * @tc.name: Test ProcessLibrarySupportDirectory with mixed dirs (normal + too long + path traversal)
 * @tc.desc: Normal dirs should be set, too long and path traversal should be filtered
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_007, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    librarySupportDirectoryMap[CPU_ABI] = {NORMAL_DIR, LONG_DIR, PATH_TRAVERSAL_DIR, "libs/subD"};
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    innerBundleInfo.SetCpuAbi(CPU_ABI);

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &result = innerBundleInfo.innerModuleInfos_[MODULE_PACKAGE].librarySupportDirectory;
    EXPECT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], NORMAL_DIR);
    EXPECT_EQ(result[1], "libs/subD");
}

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_008
 * @tc.name: Test ProcessLibrarySupportDirectory when all dirs are filtered (too long/path traversal)
 * @tc.desc: Empty vector should be set
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_008, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    librarySupportDirectoryMap[CPU_ABI] = {LONG_DIR, PATH_TRAVERSAL_DIR};
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    innerBundleInfo.SetCpuAbi(CPU_ABI);

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &result = innerBundleInfo.innerModuleInfos_[MODULE_PACKAGE].librarySupportDirectory;
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_009
 * @tc.name: Test ProcessLibrarySupportDirectory when all dirs are normal
 * @tc.desc: All dirs should be set correctly
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_009, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    librarySupportDirectoryMap[CPU_ABI] = {"libs/subA", "libs/subB", "libs/subC"};
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    innerBundleInfo.SetCpuAbi(CPU_ABI);

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &result = innerBundleInfo.innerModuleInfos_[MODULE_PACKAGE].librarySupportDirectory;
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "libs/subA");
    EXPECT_EQ(result[1], "libs/subB");
    EXPECT_EQ(result[2], "libs/subC");
}

}  // namespace
}  // namespace OHOS