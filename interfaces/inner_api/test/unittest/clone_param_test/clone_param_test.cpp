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

#include "clone_param.h"

#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "parcel.h"

#define private public
#include "bundle_resource_proxy.h"
#undef private
#include "bundle_resource_interface.h"
#include "iremote_stub.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class CloneParamTest : public testing::Test {
public:
    CloneParamTest() = default;
    ~CloneParamTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void CloneParamTest::SetUpTestCase()
{}

void CloneParamTest::TearDownTestCase()
{}

void CloneParamTest::SetUp()
{}

void CloneParamTest::TearDown()
{}

/**
 * @tc.number: Clone_Prame_Test_0100
 * @tc.name: test the CloneParamTestFinished
 * @tc.desc: 1. CloneParamTestFinished
 */
HWTEST_F(CloneParamTest, Clone_Prame_Test_0100, Function | SmallTest | Level0)
{
    MessageParcel parcel;
    DestroyAppCloneParam cloneParam;
    
    parcel.WriteInt32(100);
    parcel.WriteUint32(2);

    std::u16string u16str1 = u"key1";
    std::u16string u16str11 = u"val1";
    std::u16string u16str2 = u"key2";
    std::u16string u16str22 = u"val12";
    parcel.WriteString16(u16str1);
    parcel.WriteString16(u16str11);
    parcel.WriteString16(u16str2);
    parcel.WriteString16(u16str22);

    auto info = cloneParam.Unmarshalling(parcel);
    EXPECT_NE(info, nullptr);
    if (info != nullptr) {
        delete info;
    }
}

/**
 * @tc.number: Clone_Prame_Test_0200
 * @tc.name: test the CloneParamTestFinished
 * @tc.desc: 1. CloneParamTestFinished
 */
HWTEST_F(CloneParamTest, Clone_Prame_Test_0200, Function | SmallTest | Level0)
{
    MessageParcel parcel;
    DestroyAppCloneParam cloneParam;
    MessageParcel readParcel;

    parcel.WriteInt32(100);
    parcel.WriteUint32(2);
    std::u16string u16str1 = u"key1";
    std::u16string u16str11 = u"val1";
    std::u16string u16str2 = u"key2";
    std::u16string u16str22 = u"val12";
    parcel.WriteString16(u16str1);
    parcel.WriteString16(u16str11);
    parcel.WriteString16(u16str2);
    parcel.WriteString16(u16str22);

    auto info = cloneParam.Unmarshalling(parcel);
    EXPECT_NE(info, nullptr);
    if (info != nullptr) {
        auto ret = info->Marshalling(readParcel);
        EXPECT_EQ(ret, true);
        delete info;
    }
}

/**
 * @tc.number: Clone_Prame_Test_0300
 * @tc.name: test the CloneParamTestFinished
 * @tc.desc: 1. CloneParamTestFinished
 */
HWTEST_F(CloneParamTest, Clone_Prame_Test_0300, Function | SmallTest | Level0)
{
    MessageParcel parcel;
    DestroyAppCloneParam cloneParam;
    auto ret = cloneParam.Unmarshalling(parcel);
    EXPECT_EQ(ret, nullptr);
}

} // AppExecFwk
} // OHOS