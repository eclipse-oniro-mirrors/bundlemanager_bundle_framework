/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "bundle_info.h"

#include "json_util.h"
#include "parcel_macro.h"
#include "string_ex.h"
#include <cstdint>

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BundleInfoTest : public testing::Test {
public:
    BundleInfoTest() = default;
    ~BundleInfoTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleInfoTest::SetUpTestCase()
{}

void BundleInfoTest::TearDownTestCase()
{}

void BundleInfoTest::SetUp()
{}

void BundleInfoTest::TearDown()
{}

/**
 * @tc.number: Bundle_Info_Test_0100
 * @tc.name: test the Unmarshalling of SimpleAppInfo
 * @tc.desc: 1. Unmarshalling
 */
HWTEST_F(BundleInfoTest, Bundle_Info_Test_0100, Function | SmallTest | Level0)
{
    Parcel parcel;
    auto ret = SimpleAppInfo::Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}
} // AppExecFwk
} // OHOS
