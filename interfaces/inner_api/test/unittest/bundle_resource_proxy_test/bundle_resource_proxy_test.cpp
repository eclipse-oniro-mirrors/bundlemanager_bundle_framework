/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "bundle_resource_proxy.h"
#include "bundle_resource_interface.h"
#include "iremote_stub.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

constexpr int32_t MAX_PARCEL_CAPACITY = 100 * 1024 * 1024; // 100M

ErrCode WriteVectorToParcel(std::vector<BundleResourceInfo> &parcelVector, MessageParcel &reply)
{
    Parcel tempParcel;
    (void)tempParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    if (!tempParcel.WriteInt32(parcelVector.size())) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    for (auto &parcel : parcelVector) {
        if (!tempParcel.WriteParcelable(&parcel)) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRawData(
        reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}

class MockStub : public IRemoteStub<IBundleResource> {
public:
    MockStub() = default;
    virtual ~MockStub() = default;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        if (code == static_cast<uint32_t>(BundleResourceInterfaceCode::GET_BUNDLE_RESOURCE_INFO)) {
            GTEST_LOG_(INFO) << "OnRemoteRequest, GET_BUNDLE_RESOURCE_INFO";
            reply.WriteInt32(ERR_OK);
        
            BundleResourceInfo info;
            reply.WriteUint32(sizeof(info));
            reply.WriteRawData(&info, sizeof(info));
        } else {
            GTEST_LOG_(INFO) << "OnRemoteRequest, GET_ALL_BUNDLE_RESOURCE_INFO";
            reply.WriteInt32(ERR_OK);
        
            std::vector<BundleResourceInfo> infoVector;
            BundleResourceInfo item;
            infoVector.push_back(item);
            infoVector.push_back(item);
            infoVector.push_back(item);
            WriteVectorToParcel(infoVector, reply);
        }
        return 0;
    }
};

class BundleResourceProxyTest : public testing::Test {
public:
    BundleResourceProxyTest() = default;
    ~BundleResourceProxyTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
};

void BundleResourceProxyTest::SetUpTestCase()
{}

void BundleResourceProxyTest::TearDownTestCase()
{
}

void BundleResourceProxyTest::SetUp()
{}

void BundleResourceProxyTest::TearDown()
{
}

HWTEST_F(BundleResourceProxyTest, GetVectorParcelInfo_0100, Function | SmallTest | Level0)
{
    GTEST_LOG_(INFO) << "GetVectorParcelInfo_0100 start";
    sptr<MockStub> stub = new MockStub();
    sptr<BundleResourceProxy> proxy = new BundleResourceProxy(stub->AsObject());
    std::vector<BundleResourceInfo> info;
    ErrCode ret = proxy->GetAllBundleResourceInfo(0, info);
    GTEST_LOG_(INFO) << "GetVectorParcelInfo_0100 end, " << ret;
    ASSERT_EQ(info.size(), 3);
    ASSERT_EQ(ret, ERR_OK);
}

}
}