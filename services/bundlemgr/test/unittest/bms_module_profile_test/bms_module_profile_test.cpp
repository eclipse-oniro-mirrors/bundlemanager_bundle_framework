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
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include "parcel.h"

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
 * @tc.name: Test ProcessLibrarySupportDirectory when dirs size > 2048
 * @tc.desc: When dirs size exceeds 1024, should return ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_004, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    std::vector<std::string> dirs(2049, NORMAL_DIR);
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

/**
 * @tc.number: BmsModuleProfileTest_ProcessLibrarySupportDirectory_010
 * @tc.name: Test ProcessLibrarySupportDirectory when currentPackage not in innerModuleInfos
 * @tc.desc: When currentPackage does not match any module, should return ERR_OK without updating module
 */
HWTEST_F(BmsModuleProfileTest, ProcessLibrarySupportDirectory_010, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<std::string>> librarySupportDirectoryMap;
    librarySupportDirectoryMap[CPU_ABI] = {NORMAL_DIR};
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage("unknown_package");
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    innerBundleInfo.SetCpuAbi(CPU_ABI);

    ErrCode ret = ProcessLibrarySupportDirectory(librarySupportDirectoryMap, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(innerBundleInfo.innerModuleInfos_.at(MODULE_PACKAGE).librarySupportDirectory.empty());
}

std::string BuildModuleJsonWithNativeChildProcessPreloadSoList(
    const std::vector<std::string> &nativeChildProcessPreloadSoList)
{
    std::ostringstream json;
    json << "{" <<
        "\"app\":{" <<
        "\"bundleName\":\"com.example.demoapp\"," <<
        "\"icon\":\"$media:icon\"," <<
        "\"label\":\"DemoApp\"," <<
        "\"versionCode\":1," <<
        "\"versionName\":\"1.0.0\"," <<
        "\"minAPIVersion\":9," <<
        "\"targetAPIVersion\":9";
    if (!nativeChildProcessPreloadSoList.empty()) {
        json << ",\"nativeChildProcessPreloadSoList\":[";
        for (size_t i = 0; i < nativeChildProcessPreloadSoList.size(); ++i) {
            if (i != 0) {
                json << ",";
            }
            json << "\"" << nativeChildProcessPreloadSoList[i] << "\"";
        }
        json << "]";
    }
    json << "}," <<
        "\"module\":{" <<
        "\"name\":\"entry\"," <<
        "\"type\":\"entry\"," <<
        "\"deviceTypes\":[\"phone\"]," <<
        "\"deliveryWithInstall\":true" <<
        "}" <<
        "}";
    return json.str();
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_001
 * @tc.name: Test nativeChildProcessPreloadSoList parsing with configured list
 * @tc.desc: When app.json declares nativeChildProcessPreloadSoList, parsed ApplicationInfo
 *           should keep same order and values
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_001, Function | SmallTest | Level0)
{
    const std::vector<std::string> expected = {"libfoo.so", "libbar.so", "libbaz.so"};
    std::ostringstream source;
    source << BuildModuleJsonWithNativeChildProcessPreloadSoList(expected);

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &actual = innerBundleInfo.GetBaseApplicationInfo().nativeChildProcessPreloadSoList;
    EXPECT_EQ(actual, expected);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_002
 * @tc.name: Test nativeChildProcessPreloadSoList default value when field absent
 * @tc.desc: When app.json does not declare nativeChildProcessPreloadSoList, ApplicationInfo
 *           should default to empty list
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_002, Function | SmallTest | Level0)
{
    std::ostringstream source;
    source << BuildModuleJsonWithNativeChildProcessPreloadSoList({});

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &actual = innerBundleInfo.GetBaseApplicationInfo().nativeChildProcessPreloadSoList;
    EXPECT_TRUE(actual.empty());
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_003
 * @tc.name: Test nativeChildProcessPreloadSoList rejects explicit empty array
 * @tc.desc: When app.json set nativeChildProcessPreloadSoList to [], install should be rejected
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_003, Function | SmallTest | Level0)
{
    std::ostringstream source;
    source << "{" <<
        "\"app\":{" <<
        "\"bundleName\":\"com.example.demoapp\"," <<
        "\"icon\":\"$media:icon\"," <<
        "\"label\":\"DemoApp\"," <<
        "\"versionCode\":1," <<
        "\"versionName\":\"1.0.0\"," <<
        "\"minAPIVersion\":9," <<
        "\"targetAPIVersion\":9," <<
        "\"nativeChildProcessPreloadSoList\":[]" <<
        "}," <<
        "\"module\":{" <<
        "\"name\":\"entry\"," <<
        "\"type\":\"entry\"," <<
        "\"deviceTypes\":[\"phone\"]," <<
        "\"deliveryWithInstall\":true" <<
        "}" <<
        "}";

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_004
 * @tc.name: Test nativeChildProcessPreloadSoList IPC marshalling/unmarshalling round-trip
 * @tc.desc: When ApplicationInfo with nativeChildProcessPreloadSoList is marshalled then unmarshalled,
 *           the field should keep same values and order (IPC transfer)
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_004, Function | SmallTest | Level0)
{
    const std::vector<std::string> expected = {"libfoo.so", "libbar.so", "libbaz.so"};
    ApplicationInfo appInfo;
    appInfo.bundleName = "com.example.demoapp";
    appInfo.nativeChildProcessPreloadSoList = expected;

    Parcel parcel;
    ASSERT_TRUE(appInfo.Marshalling(parcel));

    ApplicationInfo *restored = ApplicationInfo::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->nativeChildProcessPreloadSoList, expected);
    delete restored;
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_005
 * @tc.name: Test nativeChildProcessPreloadSoList empty default after IPC round-trip
 * @tc.desc: When ApplicationInfo does not declare nativeChildProcessPreloadSoList, unmarshalled
 *           ApplicationInfo should keep empty list (backward compatible)
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_005, Function | SmallTest | Level0)
{
    ApplicationInfo appInfo;
    appInfo.bundleName = "com.example.demoapp";

    Parcel parcel;
    ASSERT_TRUE(appInfo.Marshalling(parcel));

    ApplicationInfo *restored = ApplicationInfo::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_TRUE(restored->nativeChildProcessPreloadSoList.empty());
    delete restored;
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_006
 * @tc.name: Test nativeChildProcessPreloadSoList persisted in InnerBundleInfo ToString json
 * @tc.desc: When InnerBundleInfo contains nativeChildProcessPreloadSoList, ToString output
 *           should include the new field with correct values (RDB persistence)
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_006, Function | SmallTest | Level0)
{
    const std::vector<std::string> expected = {"libfoo.so", "libbar.so"};
    ApplicationInfo appInfo;
    appInfo.bundleName = "com.example.demoapp";
    appInfo.nativeChildProcessPreloadSoList = expected;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);

    std::string jsonStr = innerBundleInfo.ToString();
    ASSERT_FALSE(jsonStr.empty());
    EXPECT_NE(jsonStr.find("nativeChildProcessPreloadSoList"), std::string::npos);
    EXPECT_NE(jsonStr.find("libfoo.so"), std::string::npos);
    EXPECT_NE(jsonStr.find("libbar.so"), std::string::npos);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_007
 * @tc.name: Test nativeChildProcessPreloadSoList Getter/Setter of InnerBundleInfo
 * @tc.desc: GetNativeChildProcessPreloadSoList should return what SetNativeChildProcessPreloadSoList set
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_007, Function | SmallTest | Level0)
{
    const std::vector<std::string> expected = {"libfoo.so", "libbar.so"};
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetNativeChildProcessPreloadSoList(expected);
    EXPECT_EQ(innerBundleInfo.GetNativeChildProcessPreloadSoList(), expected);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_008
 * @tc.name: Test nativeChildProcessPreloadSoList rejects over-limit array size
 * @tc.desc: When app.json declares 129 elements, install should be rejected
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_008, Function | SmallTest | Level0)
{
    const std::vector<std::string> overLimit(129, "libfoo.so");
    std::ostringstream source;
    source << BuildModuleJsonWithNativeChildProcessPreloadSoList(overLimit);

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_009
 * @tc.name: Test nativeChildProcessPreloadSoList accepts array size equal to upper limit
 * @tc.desc: When app.json declares 128 elements, install should succeed and all elements are kept
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_009, Function | SmallTest | Level0)
{
    std::vector<std::string> expected;
    for (int32_t i = 0; i < 128; ++i) {
        expected.emplace_back("libfoo" + std::to_string(i) + ".so");
    }
    std::ostringstream source;
    source << BuildModuleJsonWithNativeChildProcessPreloadSoList(expected);

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &actual = innerBundleInfo.GetBaseApplicationInfo().nativeChildProcessPreloadSoList;
    EXPECT_EQ(actual.size(), 128);
    EXPECT_EQ(actual, expected);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_010
 * @tc.name: Test nativeChildProcessPreloadSoList rejects over-limit element length
 * @tc.desc: When one element length is 129, install should be rejected
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_010, Function | SmallTest | Level0)
{
    const std::vector<std::string> overLimit = {std::string(129, 'x')};
    std::ostringstream source;
    source << BuildModuleJsonWithNativeChildProcessPreloadSoList(overLimit);

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_011
 * @tc.name: Test nativeChildProcessPreloadSoList accepts element length equal to upper limit
 * @tc.desc: When one element length is 128, install should succeed and the element is kept intact
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_011, Function | SmallTest | Level0)
{
    const std::vector<std::string> expected = {std::string(128, 'x')};
    std::ostringstream source;
    source << BuildModuleJsonWithNativeChildProcessPreloadSoList(expected);

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &actual = innerBundleInfo.GetBaseApplicationInfo().nativeChildProcessPreloadSoList;
    ASSERT_EQ(actual.size(), 1);
    EXPECT_EQ(actual[0], expected[0]);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_012
 * @tc.name: Test nativeChildProcessPreloadSoList accepts array size equal to lower limit
 * @tc.desc: When app.json declares a single element, install should succeed
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_012, Function | SmallTest | Level0)
{
    const std::vector<std::string> expected = {"libfoo.so"};
    std::ostringstream source;
    source << BuildModuleJsonWithNativeChildProcessPreloadSoList(expected);

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    const auto &actual = innerBundleInfo.GetBaseApplicationInfo().nativeChildProcessPreloadSoList;
    EXPECT_EQ(actual, expected);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_013
 * @tc.name: Test nativeChildProcessPreloadSoList rejects duplicated elements
 * @tc.desc: When app.json declares duplicated so names, install should be rejected (uniqueItems)
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_013, Function | SmallTest | Level0)
{
    const std::vector<std::string> duplicated = {"libfoo.so", "libfoo.so"};
    std::ostringstream source;
    source << BuildModuleJsonWithNativeChildProcessPreloadSoList(duplicated);

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);
}

/**
 * @tc.number: BmsModuleProfileTest_NativeChildProcessPreloadSoList_014
 * @tc.name: Test nativeChildProcessPreloadSoList rejects relative path traversal name
 * @tc.desc: When app.json declares "../libevil.so", install should be rejected (path traversal)
 */
HWTEST_F(BmsModuleProfileTest, NativeChildProcessPreloadSoList_014, Function | SmallTest | Level0)
{
    const std::vector<std::string> traversal = {"../libevil.so"};
    std::ostringstream source;
    source << BuildModuleJsonWithNativeChildProcessPreloadSoList(traversal);

    ModuleProfile moduleProfile;
    BundleExtractor bundleExtractor("");
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = moduleProfile.TransformTo(source, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);
}

/**
 * @tc.name: AllowAutoControlIntent_Parse
 * @tc.desc: Parse explicit and absent application declarations from a Stage profile.
 */
HWTEST_F(BmsModuleProfileTest, AllowAutoControlIntent_Parse, Function | SmallTest | Level1)
{
    const nlohmann::json profile = {
        {"app", {{"bundleName", "com.example.automation"}, {"icon", "$media:app_icon"},
            {"label", "$string:app_name"}, {"versionCode", 1},
            {"versionName", "1.0"}, {"minAPIVersion", 26}, {"targetAPIVersion", 26}}},
        {"module", {{"name", "entry"}, {"type", "entry"}, {"deviceTypes", {"default"}},
            {"deliveryWithInstall", true}, {"installationFree", false}}}
    };
    for (int i = 0; i < 3; ++i) {
        auto input = profile;
        if (i < 2) {
            input["app"]["allowAutoControlIntent"] = (i == 0);
        }
        std::ostringstream stream;
        stream << input.dump();
        InnerBundleInfo info;
        BundleExtractor extractor("");
        ASSERT_EQ(ModuleProfile().TransformTo(stream, extractor, info), ERR_OK);
        EXPECT_EQ(info.GetBaseApplicationInfo().allowAutoControlIntent, i == 0);
    }
}

/**
 * @tc.name: AllowAutoControlIntent_InvalidType
 * @tc.desc: Reject non-boolean declarations without coercing them into permission to control.
 */
HWTEST_F(BmsModuleProfileTest, AllowAutoControlIntent_InvalidType, Function | SmallTest | Level1)
{
    const std::vector<nlohmann::json> invalidValues = {
        "true", 1, nullptr, nlohmann::json::array(), nlohmann::json::object()
    };
    for (const auto &value : invalidValues) {
        nlohmann::json input = {
            {"app", {{"bundleName", "com.example.automation"}, {"icon", "$media:app_icon"},
                {"label", "$string:app_name"}, {"versionCode", 1},
                {"versionName", "1.0"}, {"minAPIVersion", 26}, {"targetAPIVersion", 26},
                {"allowAutoControlIntent", value}}},
            {"module", {{"name", "entry"}, {"type", "entry"}, {"deviceTypes", {"default"}},
                {"deliveryWithInstall", true}, {"installationFree", false}}}
        };
        std::ostringstream stream;
        stream << input.dump();
        InnerBundleInfo info;
        BundleExtractor extractor("");
        EXPECT_EQ(ModuleProfile().TransformTo(stream, extractor, info),
            ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR) << value.dump();
    }
}

/**
 * @tc.name: SharedUID_Parse
 * @tc.desc: Parse explicit and absent sharedUID declarations from a Stage profile.
 */
HWTEST_F(BmsModuleProfileTest, SharedUID_Parse, Function | SmallTest | Level1)
{
    const nlohmann::json profile = {
        {"app", {{"bundleName", "com.example.automation"}, {"icon", "$media:app_icon"},
            {"label", "$string:app_name"}, {"versionCode", 1},
            {"versionName", "1.0"}, {"minAPIVersion", 26}, {"targetAPIVersion", 26}}},
        {"module", {{"name", "entry"}, {"type", "entry"}, {"deviceTypes", {"default"}},
            {"deliveryWithInstall", true}, {"installationFree", false}}}
    };
    for (int i = 0; i < 3; ++i) {
        auto input = profile;
        if (i < 2) {
            input["app"]["sharedUID"] = (i == 0);
        }
        std::ostringstream stream;
        stream << input.dump();
        InnerBundleInfo info;
        BundleExtractor extractor("");
        ASSERT_EQ(ModuleProfile().TransformTo(stream, extractor, info), ERR_OK);
        EXPECT_EQ(info.GetBaseApplicationInfo().sharedUID, i == 0);
    }
}

/**
 * @tc.name: SharedUID_InvalidType
 * @tc.desc: Reject non-boolean sharedUID declarations instead of coercing a shared identity.
 */
HWTEST_F(BmsModuleProfileTest, SharedUID_InvalidType, Function | SmallTest | Level1)
{
    const std::vector<nlohmann::json> invalidValues = {
        "true", 1, nullptr, nlohmann::json::array(), nlohmann::json::object()
    };
    for (const auto &value : invalidValues) {
        nlohmann::json input = {
            {"app", {{"bundleName", "com.example.automation"}, {"icon", "$media:app_icon"},
                {"label", "$string:app_name"}, {"versionCode", 1},
                {"versionName", "1.0"}, {"minAPIVersion", 26}, {"targetAPIVersion", 26},
                {"sharedUID", value}}},
            {"module", {{"name", "entry"}, {"type", "entry"}, {"deviceTypes", {"default"}},
                {"deliveryWithInstall", true}, {"installationFree", false}}}
        };
        std::ostringstream stream;
        stream << input.dump();
        InnerBundleInfo info;
        BundleExtractor extractor("");
        EXPECT_EQ(ModuleProfile().TransformTo(stream, extractor, info),
            ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR) << value.dump();
    }
}

/**
 * @tc.name: SharedUID_Update_Propagation
 * @tc.desc: Updating an app replaces the stored sharedUID with the incoming one.
 */
HWTEST_F(BmsModuleProfileTest, SharedUID_Update_Propagation, Function | SmallTest | Level1)
{
    InnerBundleInfo installed;
    installed.baseApplicationInfo_->sharedUID = true;
    InnerBundleInfo incoming;
    incoming.baseApplicationInfo_->sharedUID = false;
    installed.UpdateBaseApplicationInfo(incoming);
    EXPECT_FALSE(installed.GetBaseApplicationInfo().sharedUID);
}
}  // namespace
}  // namespace OHOS