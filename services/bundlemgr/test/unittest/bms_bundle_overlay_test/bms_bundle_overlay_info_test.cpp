/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "appexecfwk_errors.h"
#include "json_util.h"
#include "overlay_bundle_info.h"
#include "overlay_module_info.h"
#include "string_ex.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string TEST_BUNDLE_OVERLAY_BUNDLE_NAME = "testBundleName";
const std::string TEST_BUNDLE_OVERLAY_BUNDLE_DIR = "testBundleDir";
const int32_t TEST_BUNDLE_OVERLAY_BUNDLE_STATE = 0;
const int32_t TEST_BUNDLE_OVERLAY_BUNDLE_PRIORITY = 50;
const std::string TEST_MODULE_OVERLAY_BUNDLE_NAME = "testBundleName";
const std::string TEST_MODULE_OVERLAY_MODULE_NAME = "testModuleName";
const std::string TEST_MODULE_OVERLAY_HAP_PATH = "testHapPath";
const std::string TEST_MODULE_TARGET_MODULE_NAME = "testTargetModuleName";
const int32_t TEST_MODULE_OVERLAY_PRIORITY = 50;
const int32_t TEST_MODULE_OVERLAY_STATE = 0;

const nlohmann::json OVERLAY_BUNDLE_INFO_JSON = R"(
{
    "bundleName": "testBundleName",
    "bundleDir": "testBundleDir",
    "state": 0,
    "priority": 50
})"_json;

const nlohmann::json OVERLAY_MODULE_INFO_JSON = R"(
{
    "bundleName": "testBundleName",
    "moduleName": "testModuleName",
    "targetModuleName": "testTargetModuleName",
    "hapPath": "testHapPath",
    "priority": 50,
    "state": 0
})"_json;
} // namespace

class BmsBundleOverlayInfoTest : public testing::Test {
public:
    BmsBundleOverlayInfoTest();
    ~BmsBundleOverlayInfoTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void CheckOverlayBundleInfo(const OverlayBundleInfo &info);
    void CheckOverlayModuleInfo(const OverlayModuleInfo &info);
};

BmsBundleOverlayInfoTest::BmsBundleOverlayInfoTest()
{}

BmsBundleOverlayInfoTest::~BmsBundleOverlayInfoTest()
{}

void BmsBundleOverlayInfoTest::SetUpTestCase()
{}

void BmsBundleOverlayInfoTest::TearDownTestCase()
{}

void BmsBundleOverlayInfoTest::SetUp()
{}

void BmsBundleOverlayInfoTest::TearDown()
{}

void BmsBundleOverlayInfoTest::CheckOverlayBundleInfo(const OverlayBundleInfo &info)
{
    EXPECT_EQ(info.bundleName, TEST_BUNDLE_OVERLAY_BUNDLE_NAME);
    EXPECT_EQ(info.bundleDir, TEST_BUNDLE_OVERLAY_BUNDLE_DIR);
    EXPECT_EQ(info.state, TEST_BUNDLE_OVERLAY_BUNDLE_STATE);
    EXPECT_EQ(info.priority, TEST_BUNDLE_OVERLAY_BUNDLE_PRIORITY);
}

void BmsBundleOverlayInfoTest::CheckOverlayModuleInfo(const OverlayModuleInfo &info)
{
    EXPECT_EQ(info.bundleName, TEST_MODULE_OVERLAY_BUNDLE_NAME);
    EXPECT_EQ(info.moduleName, TEST_MODULE_OVERLAY_MODULE_NAME);
    EXPECT_EQ(info.hapPath, TEST_MODULE_OVERLAY_HAP_PATH);
    EXPECT_EQ(info.targetModuleName, TEST_MODULE_TARGET_MODULE_NAME);
    EXPECT_EQ(info.state, TEST_MODULE_OVERLAY_STATE);
    EXPECT_EQ(info.priority, TEST_MODULE_OVERLAY_PRIORITY);
}

/**
 * @tc.number: OverlayInfoTest_0100
 * @tc.name: test ReadFromParcel interface in OverlayBundleInfo.
 * @tc.desc: 1.construct parcel.
 *           2.calling ReadFromParcel interface by using input parameter parcel.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_0100, Function | SmallTest | Level0)
{
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(TEST_BUNDLE_OVERLAY_BUNDLE_NAME));
    parcel.WriteString16(Str8ToStr16(TEST_BUNDLE_OVERLAY_BUNDLE_DIR));
    parcel.WriteInt32(TEST_BUNDLE_OVERLAY_BUNDLE_STATE);
    parcel.WriteInt32(TEST_BUNDLE_OVERLAY_BUNDLE_PRIORITY);

    OverlayBundleInfo overlayBundleInfo;
    overlayBundleInfo.ReadFromParcel(parcel);
    CheckOverlayBundleInfo(overlayBundleInfo);
}

/**
 * @tc.number: OverlayInfoTest_0200
 * @tc.name: test Marshalling interface in OverlayBundleInfo.
 * @tc.desc: 1.construct OverlayBundleInfo instance.
 *           2.calling Marshalling interface by using the constructed OverlayBundleInfo instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_0200, Function | SmallTest | Level0)
{
    OverlayBundleInfo overlayBundleInfo;
    overlayBundleInfo.bundleName = TEST_BUNDLE_OVERLAY_BUNDLE_NAME;
    overlayBundleInfo.bundleDir = TEST_BUNDLE_OVERLAY_BUNDLE_DIR;
    overlayBundleInfo.state = TEST_BUNDLE_OVERLAY_BUNDLE_STATE;
    overlayBundleInfo.priority = TEST_BUNDLE_OVERLAY_BUNDLE_PRIORITY;

    Parcel parcel;
    overlayBundleInfo.Marshalling(parcel);
    OverlayBundleInfo otherOverlayBundleInfo;
    otherOverlayBundleInfo.ReadFromParcel(parcel);
    CheckOverlayBundleInfo(otherOverlayBundleInfo);
}

/**
 * @tc.number: OverlayInfoTest_0300
 * @tc.name: test Unmarshalling interface in OverlayBundleInfo.
 * @tc.desc: 1.construct parcel.
 *           2.calling Unmarshalling interface by using input parameter parcel.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_0300, Function | SmallTest | Level0)
{
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(TEST_BUNDLE_OVERLAY_BUNDLE_NAME));
    parcel.WriteString16(Str8ToStr16(TEST_BUNDLE_OVERLAY_BUNDLE_DIR));
    parcel.WriteInt32(TEST_BUNDLE_OVERLAY_BUNDLE_STATE);
    parcel.WriteInt32(TEST_BUNDLE_OVERLAY_BUNDLE_PRIORITY);


    OverlayBundleInfo overlayBundleInfo;
    OverlayBundleInfo *info = overlayBundleInfo.Unmarshalling(parcel);
    CheckOverlayBundleInfo(*info);
    delete info;
}

/**
 * @tc.number: OverlayInfoTest_0400
 * @tc.name: test to_json interface in OverlayBundleInfo.
 * @tc.desc: 1.construct OverlayBundleInfo instance.
 *           2.calling to_json interface by using the constructed OverlayBundleInfo instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_0400, Function | SmallTest | Level0)
{
    OverlayBundleInfo overlayBundleInfo;
    overlayBundleInfo.bundleName = TEST_BUNDLE_OVERLAY_BUNDLE_NAME;
    overlayBundleInfo.bundleDir = TEST_BUNDLE_OVERLAY_BUNDLE_DIR;
    overlayBundleInfo.state = TEST_BUNDLE_OVERLAY_BUNDLE_STATE;
    overlayBundleInfo.priority = TEST_BUNDLE_OVERLAY_BUNDLE_PRIORITY;

    nlohmann::json jsonObject;
    to_json(jsonObject, overlayBundleInfo);
    std::string str1 = jsonObject.dump(Constants::DUMP_INDENT);
    std::string str2 = OVERLAY_BUNDLE_INFO_JSON.dump(Constants::DUMP_INDENT);
    EXPECT_EQ(str1, str2);
}

/**
 * @tc.number: OverlayInfoTest_0500
 * @tc.name: test from_json interface in OverlayBundleInfo.
 * @tc.desc: 1.construct OverlayBundleInfo instance.
 *           2.calling from_json interface by using the constructed OverlayBundleInfo instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_0500, Function | SmallTest | Level0)
{
    OverlayBundleInfo overlayBundleInfo;
    from_json(OVERLAY_BUNDLE_INFO_JSON, overlayBundleInfo);

    CheckOverlayBundleInfo(overlayBundleInfo);
}

/**
 * @tc.number: OverlayInfoTest_0600
 * @tc.name: test ReadFromParcel interface in OverlayModuleInfo.
 * @tc.desc: 1.construct parcel.
 *           2.calling ReadFromParcel interface by using input parameter parcel.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_0600, Function | SmallTest | Level0)
{
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(TEST_MODULE_OVERLAY_BUNDLE_NAME));
    parcel.WriteString16(Str8ToStr16(TEST_MODULE_OVERLAY_MODULE_NAME));
    parcel.WriteString16(Str8ToStr16(TEST_MODULE_TARGET_MODULE_NAME));
    parcel.WriteString16(Str8ToStr16(TEST_MODULE_OVERLAY_HAP_PATH));
    parcel.WriteInt32(TEST_MODULE_OVERLAY_PRIORITY);
    parcel.WriteInt32(TEST_MODULE_OVERLAY_STATE);

    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.ReadFromParcel(parcel);
    CheckOverlayModuleInfo(overlayModuleInfo);
}

/**
 * @tc.number: OverlayInfoTest_0700
 * @tc.name: test Marshalling interface in OverlayModuleInfo.
 * @tc.desc: 1.construct OverlayBundleInfo instance.
 *           2.calling Marshalling interface by using the constructed OverlayModuleInfo instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_0700, Function | SmallTest | Level0)
{
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.bundleName = TEST_MODULE_OVERLAY_BUNDLE_NAME;
    overlayModuleInfo.moduleName = TEST_MODULE_OVERLAY_MODULE_NAME;
    overlayModuleInfo.hapPath = TEST_MODULE_OVERLAY_HAP_PATH;
    overlayModuleInfo.targetModuleName = TEST_MODULE_TARGET_MODULE_NAME;
    overlayModuleInfo.state = TEST_MODULE_OVERLAY_STATE;
    overlayModuleInfo.priority = TEST_MODULE_OVERLAY_PRIORITY;

    Parcel parcel;
    overlayModuleInfo.Marshalling(parcel);
    OverlayModuleInfo otherOverlayModuleInfo;
    otherOverlayModuleInfo.ReadFromParcel(parcel);
    CheckOverlayModuleInfo(otherOverlayModuleInfo);
}

/**
 * @tc.number: OverlayInfoTest_0800
 * @tc.name: test Unmarshalling interface in OverlayModuleInfo.
 * @tc.desc: 1.construct parcel.
 *           2.calling Unmarshalling interface by using input parameter parcel.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_0800, Function | SmallTest | Level0)
{
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(TEST_MODULE_OVERLAY_BUNDLE_NAME));
    parcel.WriteString16(Str8ToStr16(TEST_MODULE_OVERLAY_MODULE_NAME));
    parcel.WriteString16(Str8ToStr16(TEST_MODULE_TARGET_MODULE_NAME));
    parcel.WriteString16(Str8ToStr16(TEST_MODULE_OVERLAY_HAP_PATH));
    parcel.WriteInt32(TEST_MODULE_OVERLAY_PRIORITY);
    parcel.WriteInt32(TEST_MODULE_OVERLAY_STATE);

    OverlayModuleInfo overlayModuleInfo;
    OverlayModuleInfo *info = overlayModuleInfo.Unmarshalling(parcel);
    CheckOverlayModuleInfo(*info);
    delete info;
}

/**
 * @tc.number: OverlayInfoTest_0900
 * @tc.name: test to_json interface in OverlayModuleInfo.
 * @tc.desc: 1.construct OverlayBundleInfo instance.
 *           2.calling to_json interface by using the constructed OverlayModuleInfo instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_0900, Function | SmallTest | Level0)
{
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.bundleName = TEST_MODULE_OVERLAY_BUNDLE_NAME;
    overlayModuleInfo.moduleName = TEST_MODULE_OVERLAY_MODULE_NAME;
    overlayModuleInfo.hapPath = TEST_MODULE_OVERLAY_HAP_PATH;
    overlayModuleInfo.targetModuleName = TEST_MODULE_TARGET_MODULE_NAME;
    overlayModuleInfo.state = TEST_MODULE_OVERLAY_STATE;
    overlayModuleInfo.priority = TEST_MODULE_OVERLAY_PRIORITY;

    nlohmann::json jsonObject;
    to_json(jsonObject, overlayModuleInfo);
    std::string str1 = jsonObject.dump(Constants::DUMP_INDENT);
    std::string str2 = OVERLAY_MODULE_INFO_JSON.dump(Constants::DUMP_INDENT);
    EXPECT_EQ(str1, str2);
}

/**
 * @tc.number: OverlayInfoTest_1000
 * @tc.name: test from_json interface in OverlayModuleInfo.
 * @tc.desc: 1.construct OverlayBundleInfo instance.
 *           2.calling from_json interface by using the constructed OverlayModuleInfo instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayInfoTest, OverlayInfoTest_1000, Function | SmallTest | Level0)
{
    OverlayModuleInfo overlayModuleInfo;
    from_json(OVERLAY_MODULE_INFO_JSON, overlayModuleInfo);

    CheckOverlayModuleInfo(overlayModuleInfo);
}
} // OHOS