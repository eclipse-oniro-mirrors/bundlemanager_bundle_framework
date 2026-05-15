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

#include <gtest/gtest.h>
#include "default_app_host.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace {
constexpr int32_t TEST_USER_ID = 100;
}

class TestDefaultAppHost : public DefaultAppHost {
public:
    ErrCode retIsDefault_ = ERR_OK;
    ErrCode retGetDefault_ = ERR_OK;
    ErrCode retSetDefault_ = ERR_OK;
    ErrCode retResetDefault_ = ERR_OK;
    ErrCode retSetAppClone_ = ERR_OK;
    ErrCode retSetCustom_ = ERR_OK;

    ErrCode IsDefaultApplication(const std::string &type, bool &isDefaultApp) override
    {
        isDefaultApp = true;
        return retIsDefault_;
    }
    ErrCode GetDefaultApplication(int32_t userId, const std::string &type, BundleInfo &bundleInfo) override
    {
        bundleInfo.name = "com.test.default";
        return retGetDefault_;
    }
    ErrCode SetDefaultApplication(int32_t userId, const std::string &type, const Want &want) override
    {
        return retSetDefault_;
    }
    ErrCode ResetDefaultApplication(int32_t userId, const std::string &type) override
    {
        return retResetDefault_;
    }
    ErrCode SetDefaultApplicationForAppClone(const int32_t userId, const int32_t appIndex,
        const std::string &type, const Want &want) override
    {
        return retSetAppClone_;
    }
    ErrCode SetDefaultApplicationForCustom(const int32_t userId, const std::string &type,
        const Want &want) override
    {
        return retSetCustom_;
    }
};

class BmsDefaultAppHostTest : public testing::Test {
public:
    void SetUp() override { host_ = std::make_unique<TestDefaultAppHost>(); }
    void TearDown() override { host_.reset(); }
protected:
    std::unique_ptr<TestDefaultAppHost> host_;
};

void WriteInterfaceToken(MessageParcel &data)
{
    data.WriteInterfaceToken(DefaultAppHost::GetDescriptor());
}

// === OnRemoteRequest ===

TEST_F(BmsDefaultAppHostTest, OnRemoteRequest_DescriptorMismatch)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"wrong.descriptor");
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(DefaultAppInterfaceCode::IS_DEFAULT_APPLICATION), data, reply, option);
    EXPECT_EQ(ret, OBJECT_NULL);
}

TEST_F(BmsDefaultAppHostTest, OnRemoteRequest_UnknownCode)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(99, data, reply, option);
    EXPECT_NE(ret, NO_ERROR);
}

// === HandleIsDefaultApplication ===

TEST_F(BmsDefaultAppHostTest, HandleIsDefaultApplication_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteString("browser");
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(DefaultAppInterfaceCode::IS_DEFAULT_APPLICATION), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    ErrCode errCode = reply.ReadInt32();
    EXPECT_EQ(errCode, ERR_OK);
    bool isDefault = reply.ReadBool();
    EXPECT_TRUE(isDefault);
}

TEST_F(BmsDefaultAppHostTest, HandleIsDefaultApplication_HostError)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteString("browser");
    MessageParcel reply;
    MessageOption option;
    host_->retIsDefault_ = ERR_BUNDLE_MANAGER_INVALID_TYPE;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(DefaultAppInterfaceCode::IS_DEFAULT_APPLICATION), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    ErrCode errCode = reply.ReadInt32();
    EXPECT_EQ(errCode, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

// === HandleGetDefaultApplication ===

TEST_F(BmsDefaultAppHostTest, HandleGetDefaultApplication_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteInt32(TEST_USER_ID);
    data.WriteString("browser");
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(DefaultAppInterfaceCode::GET_DEFAULT_APPLICATION), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}

// === HandleSetDefaultApplication ===

TEST_F(BmsDefaultAppHostTest, HandleSetDefaultApplication_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteInt32(TEST_USER_ID);
    data.WriteString("browser");
    Want want;
    data.WriteParcelable(&want);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}

TEST_F(BmsDefaultAppHostTest, HandleSetDefaultApplication_NullWant)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteInt32(TEST_USER_ID);
    data.WriteString("browser");
    // Don't write a Want parcelable - ReadParcelable will return nullptr
    data.WriteInt32(0); // write nothing valid for Want
    MessageParcel reply;
    MessageOption option;
    // This should fail because ReadParcelable<Want> returns null
    ErrCode ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION), data, reply, option);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// === HandleResetDefaultApplication ===

TEST_F(BmsDefaultAppHostTest, HandleResetDefaultApplication_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteInt32(TEST_USER_ID);
    data.WriteString("browser");
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(DefaultAppInterfaceCode::RESET_DEFAULT_APPLICATION), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}

// === HandleSetDefaultApplicationForAppClone ===

TEST_F(BmsDefaultAppHostTest, HandleSetDefaultApplicationForAppClone_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteInt32(TEST_USER_ID);
    data.WriteInt32(1);
    data.WriteString("browser");
    Want want;
    data.WriteParcelable(&want);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION_FOR_APP_CLONE), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}

// === HandleSetDefaultApplicationForCustom ===

TEST_F(BmsDefaultAppHostTest, HandleSetDefaultApplicationForCustom_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteInt32(TEST_USER_ID);
    data.WriteString("browser");
    Want want;
    data.WriteParcelable(&want);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION_FOR_CUSTOM), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}
