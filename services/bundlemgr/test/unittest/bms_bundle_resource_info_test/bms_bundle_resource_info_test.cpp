/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <fstream>
#include <future>
#include <gtest/gtest.h>

#include "bundle_resource_info.h"

#include "string_ex.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BmsBundleResourceInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsBundleResourceInfoTest::SetUpTestCase()
{}

void BmsBundleResourceInfoTest::TearDownTestCase()
{}

void BmsBundleResourceInfoTest::SetUp()
{}

void BmsBundleResourceInfoTest::TearDown()
{}

/**
 * @tc.number: ReadFromParcel_0100
 * @tc.name: test the ReadFromParcel
 * @tc.desc: 1. system running normally
 *           2. test ReadFromParcel
 */
HWTEST_F(BmsBundleResourceInfoTest, ReadFromParcel_0100, Function | MediumTest | Level1)
{
    BundleResourceInfo bundleResourceInfo;
    Parcel parcel;
    parcel.WriteInt32(1);
    std::string element = "testElement";
    auto res = bundleResourceInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: ReadFromParcel_0200
 * @tc.name: test the ReadFromParcel
 * @tc.desc: 1. system running normally
 *           2. test ReadFromParcel
 */
HWTEST_F(BmsBundleResourceInfoTest, ReadFromParcel_0200, Function | MediumTest | Level1)
{
    BundleResourceInfo bundleResourceInfo;
    Parcel parcel;
    std::string bundleName = "bundleName";
    parcel.WriteString16(Str8ToStr16(bundleName));
    parcel.WriteInt32(1);

    auto res = bundleResourceInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(res);
    EXPECT_EQ(bundleResourceInfo.bundleName, bundleName);
}

/**
 * @tc.number: ReadFromParcel_0300
 * @tc.name: test the ReadFromParcel
 * @tc.desc: 1. system running normally
 *           2. test ReadFromParcel
 */
HWTEST_F(BmsBundleResourceInfoTest, ReadFromParcel_0300, Function | MediumTest | Level1)
{
    BundleResourceInfo bundleResourceInfo;
    Parcel parcel;
    std::string bundleName = "bundleName";
    parcel.WriteString16(Str8ToStr16(bundleName));
    std::string label = "label";
    parcel.WriteString16(Str8ToStr16(label));
    parcel.WriteInt32(1);

    auto res = bundleResourceInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(res);
    EXPECT_EQ(bundleResourceInfo.bundleName, bundleName);
    EXPECT_EQ(bundleResourceInfo.label, label);
}

/**
 * @tc.number: ReadFromParcel_0400
 * @tc.name: test the ReadFromParcel
 * @tc.desc: 1. system running normally
 *           2. test ReadFromParcel
 */
HWTEST_F(BmsBundleResourceInfoTest, ReadFromParcel_0400, Function | MediumTest | Level2)
{
    BundleResourceInfo bundleResourceInfo;
    Parcel parcel;
    std::string bundleName = "bundleName";
    parcel.WriteString16(Str8ToStr16(bundleName));
    std::string label = "label";
    parcel.WriteString16(Str8ToStr16(label));
    std::string icon = "icon";
    parcel.WriteString16(Str8ToStr16(icon));
    parcel.WriteString16(Str8ToStr16(icon));

    auto res = bundleResourceInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(res);
    EXPECT_EQ(bundleResourceInfo.bundleName, bundleName);
    EXPECT_EQ(bundleResourceInfo.label, label);
    EXPECT_EQ(bundleResourceInfo.icon, icon);
}

/**
 * @tc.number: ReadFromParcel_0500
 * @tc.name: test the ReadFromParcel
 * @tc.desc: 1. system running normally
 *           2. test ReadFromParcel
 */
HWTEST_F(BmsBundleResourceInfoTest, ReadFromParcel_0500, Function | MediumTest | Level1)
{
    BundleResourceInfo bundleResourceInfo;
    Parcel parcel;
    std::string bundleName = "bundleName";
    parcel.WriteString16(Str8ToStr16(bundleName));
    std::string label = "label";
    parcel.WriteString16(Str8ToStr16(label));
    std::string icon = "icon";
    parcel.WriteString16(Str8ToStr16(icon));
    parcel.WriteInt32(0);
    parcel.WriteInt32(0);
    int32_t appIndex = 1;
    parcel.WriteInt32(appIndex);

    auto res = bundleResourceInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(res);
    EXPECT_EQ(bundleResourceInfo.bundleName, bundleName);
    EXPECT_EQ(bundleResourceInfo.label, label);
    EXPECT_EQ(bundleResourceInfo.icon, icon);
    EXPECT_EQ(bundleResourceInfo.appIndex, appIndex);
}

/**
 * @tc.number: Marshalling_0100
 * @tc.name: test the Marshalling
 * @tc.desc: 1. system running normally
 *           2. test Marshalling
 */
HWTEST_F(BmsBundleResourceInfoTest, Marshalling_0100, Function | MediumTest | Level1)
{
    BundleResourceInfo bundleResourceInfo;
    Parcel parcel;
    parcel.WriteInt32(1);
    std::string element = "testElement";
    auto res = bundleResourceInfo.Marshalling(parcel);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: UnMarshalling_0100
 * @tc.name: test the UnMarshalling
 * @tc.desc: 1. system running normally
 *           2. test UnMarshalling
 */
HWTEST_F(BmsBundleResourceInfoTest, UnMarshalling_0100, Function | MediumTest | Level1)
{
    BundleResourceInfo bundleResourceInfo;
    Parcel parcel;
    parcel.WriteInt32(1);
    std::string element = "testElement";
    auto res = bundleResourceInfo.Unmarshalling(parcel);
    ASSERT_EQ(res, nullptr);
}

/**
 * @tc.number: UnMarshalling_0200
 * @tc.name: test the UnMarshalling
 * @tc.desc: 1. system running normally
 *           2. test UnMarshalling
 */
HWTEST_F(BmsBundleResourceInfoTest, UnMarshalling_0200, Function | MediumTest | Level1)
{
    Parcel parcel;
    std::string bundleName = "bundleName";
    parcel.WriteString16(Str8ToStr16(bundleName));
    parcel.WriteInt32(1);
    auto res = BundleResourceInfo::Unmarshalling(parcel);
    ASSERT_EQ(res, nullptr);
}
/**
 * @tc.number: UnMarshalling_0300
 * @tc.name: test the UnMarshalling
 * @tc.desc: 1. system running normally
 *           2. test UnMarshalling
 */
HWTEST_F(BmsBundleResourceInfoTest, UnMarshalling_0300, Function | MediumTest | Level1)
{
    Parcel parcel;
    std::string bundleName = "bundleName";
    parcel.WriteString16(Str8ToStr16(bundleName));
    std::string label = "label";
    parcel.WriteString16(Str8ToStr16(label));
    parcel.WriteInt32(1);

    auto res = BundleResourceInfo::Unmarshalling(parcel);
    ASSERT_EQ(res, nullptr);
}

/**
 * @tc.number: UnMarshalling_0400
 * @tc.name: test the UnMarshalling
 * @tc.desc: 1. system running normally
 *           2. test UnMarshalling
 */
HWTEST_F(BmsBundleResourceInfoTest, UnMarshalling_0400, Function | MediumTest | Level2)
{
    Parcel parcel;
    std::string bundleName = "bundleName";
    parcel.WriteString16(Str8ToStr16(bundleName));
    std::string label = "label";
    parcel.WriteString16(Str8ToStr16(label));
    std::string icon = "icon";
    parcel.WriteString16(Str8ToStr16(icon));
    parcel.WriteString16(Str8ToStr16(icon));

    auto res = BundleResourceInfo::Unmarshalling(parcel);
    ASSERT_EQ(res, nullptr);
}

/**
 * @tc.number: UnMarshalling_0500
 * @tc.name: test the UnMarshalling
 * @tc.desc: 1. system running normally
 *           2. test UnMarshalling
 */
HWTEST_F(BmsBundleResourceInfoTest, UnMarshalling_0500, Function | MediumTest | Level1)
{
    Parcel parcel;
    std::string bundleName = "bundleName";
    parcel.WriteString16(Str8ToStr16(bundleName));
    std::string label = "label";
    parcel.WriteString16(Str8ToStr16(label));
    std::string icon = "icon";
    parcel.WriteString16(Str8ToStr16(icon));
    parcel.WriteInt32(0);
    parcel.WriteInt32(0);
    int32_t appIndex = 1;
    parcel.WriteInt32(appIndex);

    auto bundleResourceInfo = BundleResourceInfo::Unmarshalling(parcel);
    ASSERT_NE(bundleResourceInfo, nullptr);
    if (bundleResourceInfo != nullptr) {
        EXPECT_EQ(bundleResourceInfo->bundleName, bundleName);
        EXPECT_EQ(bundleResourceInfo->label, label);
        EXPECT_EQ(bundleResourceInfo->icon, icon);
        EXPECT_EQ(bundleResourceInfo->appIndex, appIndex);
        delete bundleResourceInfo;
        bundleResourceInfo = nullptr;
    }
}
}
}