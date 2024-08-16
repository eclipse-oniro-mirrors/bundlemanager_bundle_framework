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
}
}