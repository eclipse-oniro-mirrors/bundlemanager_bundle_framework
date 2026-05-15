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
#include "default_app_proxy.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

class MockDefaultAppRemote : public IRemoteObject {
public:
    MockDefaultAppRemote() : IRemoteObject(u"ohos.bundleManager.defaultApp") {}
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        called_ = true;
        lastCode_ = code;
        if (shouldFail_) {
            return -1;
        }
        reply.WriteInt32(replyErr_);
        if (replyErr_ == ERR_OK) {
            if (code == static_cast<uint32_t>(DefaultAppInterfaceCode::IS_DEFAULT_APPLICATION)) {
                reply.WriteBool(true);
            } else if (code == static_cast<uint32_t>(DefaultAppInterfaceCode::GET_DEFAULT_APPLICATION)) {
                BundleInfo info;
                info.name = "com.test.default";
                reply.WriteParcelable(&info);
            }
            // SET/RESET methods just return int32 already written
        }
        return 0;
    }
    sptr<IRemoteBroker> AsInterface() override { return nullptr; }
    int32_t GetObjectRefCount() override { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }

    bool called_ = false;
    uint32_t lastCode_ = 0;
    bool shouldFail_ = false;
    int32_t replyErr_ = ERR_OK;
};

class BmsDefaultAppProxyTest : public testing::Test {
public:
    void SetUp() override
    {
        remote_ = new MockDefaultAppRemote();
        proxy_ = std::make_unique<DefaultAppProxy>(remote_);
    }
    void TearDown() override { proxy_.reset(); }
protected:
    sptr<MockDefaultAppRemote> remote_;
    std::unique_ptr<DefaultAppProxy> proxy_;
};

// === IsDefaultApplication ===

TEST_F(BmsDefaultAppProxyTest, IsDefaultApplication_Success)
{
    bool isDefault = false;
    ErrCode ret = proxy_->IsDefaultApplication("browser", isDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isDefault);
}

TEST_F(BmsDefaultAppProxyTest, IsDefaultApplication_SendRequestFailed)
{
    remote_->shouldFail_ = true;
    bool isDefault = false;
    ErrCode ret = proxy_->IsDefaultApplication("browser", isDefault);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

TEST_F(BmsDefaultAppProxyTest, IsDefaultApplication_HostError)
{
    remote_->replyErr_ = ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    bool isDefault = false;
    ErrCode ret = proxy_->IsDefaultApplication("browser", isDefault);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

// === GetDefaultApplication ===

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplication_EmptyType)
{
    BundleInfo info;
    ErrCode ret = proxy_->GetDefaultApplication(100, "", info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplication_Success)
{
    BundleInfo info;
    ErrCode ret = proxy_->GetDefaultApplication(100, "browser", info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.name, "com.test.default");
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplication_SendRequestFailed)
{
    remote_->shouldFail_ = true;
    BundleInfo info;
    ErrCode ret = proxy_->GetDefaultApplication(100, "browser", info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// === SetDefaultApplication ===

TEST_F(BmsDefaultAppProxyTest, SetDefaultApplication_Success)
{
    Want want;
    ErrCode ret = proxy_->SetDefaultApplication(100, "browser", want);
    EXPECT_EQ(ret, ERR_OK);
}

TEST_F(BmsDefaultAppProxyTest, SetDefaultApplication_SendRequestFailed)
{
    remote_->shouldFail_ = true;
    Want want;
    ErrCode ret = proxy_->SetDefaultApplication(100, "browser", want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// === ResetDefaultApplication ===

TEST_F(BmsDefaultAppProxyTest, ResetDefaultApplication_EmptyType)
{
    ErrCode ret = proxy_->ResetDefaultApplication(100, "");
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
}

TEST_F(BmsDefaultAppProxyTest, ResetDefaultApplication_Success)
{
    ErrCode ret = proxy_->ResetDefaultApplication(100, "browser");
    EXPECT_EQ(ret, ERR_OK);
}

TEST_F(BmsDefaultAppProxyTest, ResetDefaultApplication_SendRequestFailed)
{
    remote_->shouldFail_ = true;
    ErrCode ret = proxy_->ResetDefaultApplication(100, "browser");
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// === SetDefaultApplicationForAppClone ===

TEST_F(BmsDefaultAppProxyTest, SetDefaultApplicationForAppClone_Success)
{
    Want want;
    ErrCode ret = proxy_->SetDefaultApplicationForAppClone(100, 1, "browser", want);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(
        remote_->lastCode_,
        static_cast<uint32_t>(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION_FOR_APP_CLONE));
}

TEST_F(BmsDefaultAppProxyTest, SetDefaultApplicationForAppClone_SendRequestFailed)
{
    remote_->shouldFail_ = true;
    Want want;
    ErrCode ret = proxy_->SetDefaultApplicationForAppClone(100, 1, "browser", want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// === SetDefaultApplicationForCustom ===

TEST_F(BmsDefaultAppProxyTest, SetDefaultApplicationForCustom_Success)
{
    Want want;
    ErrCode ret = proxy_->SetDefaultApplicationForCustom(100, "browser", want);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(remote_->lastCode_, static_cast<uint32_t>(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION_FOR_CUSTOM));
}

TEST_F(BmsDefaultAppProxyTest, SetDefaultApplicationForCustom_SendRequestFailed)
{
    remote_->shouldFail_ = true;
    Want want;
    ErrCode ret = proxy_->SetDefaultApplicationForCustom(100, "browser", want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// === Null remote ===

TEST_F(BmsDefaultAppProxyTest, NullRemote)
{
    auto nullProxy = std::make_unique<DefaultAppProxy>(nullptr);
    bool isDefault = false;
    ErrCode ret = nullProxy->IsDefaultApplication("browser", isDefault);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}
