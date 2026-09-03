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
#include <cstdint>
#include <vector>
#include "default_app_proxy.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ability_info.h"
#include "appexecfwk_errors.h"
#include "default_app_interface.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace {
constexpr int32_t MAX_PARCEL_CAPACITY = 100 * 1024 * 1024; // 100M, mirrors MAX_IPC_ALLOWED_CAPACITY
const int32_t TEST_USER_ID = 100;
// A reply count far larger than the payload can actually hold; the proxy must reject the
// malformed candidate buffer instead of masking the verify failure as ERR_OK.
constexpr int32_t LIAR_CLAIMED_COUNT = 10000;
}

// Build the same reply wire format the host's WriteVectorToParcel emits: int32 count,
// then each AbilityInfo parcelable, then uint32 total data size, then the raw buffer.
static ErrCode WriteAbilityVectorToReply(std::vector<AbilityInfo>& parcelVector, MessageParcel& reply)
{
    Parcel tempParcel;
    (void)tempParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    if (!tempParcel.WriteInt32(static_cast<int32_t>(parcelVector.size()))) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (auto &parcel : parcelVector) {
        if (!tempParcel.WriteParcelable(&parcel)) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteUint32(static_cast<uint32_t>(dataSize))) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteRawData(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

// Malformed reply: the count claims there are "claimedCount" entries but only one AbilityInfo is
// actually serialized, so dataSize reflects a single entry. The proxy's container check must catch
// readSize > GetReadableBytes() and return a parcel error instead of looping into short reads.
static ErrCode WriteLiarCountToReply(int32_t claimedCount, MessageParcel& reply)
{
    Parcel tempParcel;
    (void)tempParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    if (!tempParcel.WriteInt32(claimedCount)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    AbilityInfo info;
    info.bundleName = "com.test.browser";
    info.name = "MainAbility";
    if (!tempParcel.WriteParcelable(&info)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteUint32(static_cast<uint32_t>(dataSize))) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteRawData(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

// Generic malformed-reply builder: writes an arbitrary byte stream as the vector buffer,
// so the proxy's ParseVectorFromBuffer parses exactly those bytes as a Parcel. The first
// int32 in rawBuffer becomes infoSize; the remainder (if any) is the (truncated) payload.
static ErrCode WriteRawBufferToReply(const std::vector<uint8_t>& rawBuffer, MessageParcel& reply)
{
    uint32_t dataSize = static_cast<uint32_t>(rawBuffer.size());
    if (!reply.WriteUint32(dataSize)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteRawData(rawBuffer.data(), dataSize)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

class MockDefaultAppRemote : public IRemoteObject {
public:
    // reply modes driven by replyMode_ set by the test before invoking the proxy.
    enum ReplyMode {
        MODE_EMPTY_VECTOR,    // ERR_OK + zero-data reply (empty candidate list)
        MODE_ONE_ITEM,        // ERR_OK + one AbilityInfo round-trips back
        MODE_ERR_FAILED,      // a non-OK ret, no vector payload
        MODE_HUGE_ASHMEM,     // ERR_OK + a dataSize above the 100MB IPC limit (ashmem path)
        MODE_LIAR_COUNT,      // ERR_OK + count claims N but payload only has 1 entry (malformed)
        MODE_NEGATIVE_COUNT,  // ERR_OK + buffer whose first int32 is -1 (infoSize < 0)
        MODE_HUGE_COUNT,      // ERR_OK + buffer whose first int32 is INT32_MAX (infoSize > max_size)
        MODE_CORRUPT_ELEMENT, // ERR_OK + count 1 but the trailing bytes are not a valid AbilityInfo
        MODE_ZERO_COUNT,      // ERR_OK + buffer whose first int32 is 0 (zero-element success path)
    };

    MockDefaultAppRemote() : IRemoteObject(u"ohos.bundleManager.defaultApp") {}
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        called_ = true;
        lastCode_ = code;
        if (shouldFail_) {
            return -1;
        }
        reply.WriteInt32(replyErr_);
        if (replyErr_ != ERR_OK) {
            return 0;
        }
        return WriteBody(code, reply);
    }

    // Writes the ERR_OK payload for a request code. Kept flat so the mock stays within the
    // 50-line / depth-4 limits the code checker enforces on the whole method set.
    int WriteBody(uint32_t code, MessageParcel &reply)
    {
        if (code == static_cast<uint32_t>(DefaultAppInterfaceCode::IS_DEFAULT_APPLICATION)) {
            reply.WriteBool(true);
        } else if (code == static_cast<uint32_t>(DefaultAppInterfaceCode::GET_DEFAULT_APPLICATION)) {
            BundleInfo info;
            info.name = "com.test.default";
            reply.WriteParcelable(&info);
        } else if (code == static_cast<uint32_t>(DefaultAppInterfaceCode::GET_DEFAULT_APPLICATION_CANDIDATES)) {
            return WriteCandidatesReply(reply);
        }
        return 0;
    }

    // Builds the candidate-list reply for every GET_DEFAULT_APPLICATION_CANDIDATES reply mode.
    int WriteCandidatesReply(MessageParcel &reply)
    {
        if (replyMode_ == MODE_HUGE_ASHMEM) {
            // dataSize over the 100MB limit forces the proxy onto the ashmem branch; the
            // remote does not provision a real Ashmem, so the proxy must surface a parcel
            // error rather than crash.
            if (!reply.WriteUint32(MAX_PARCEL_CAPACITY + 1)) {
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
            return 0;
        }
        if (replyMode_ == MODE_LIAR_COUNT) {
            // claim LIAR_CLAIMED_COUNT entries but serialise only one: the proxy must reject
            // this rather than mask the verify failure as ERR_OK (the CONTAINER_SECURITY_VERIFY bug).
            return WriteLiarCountToReply(LIAR_CLAIMED_COUNT, reply);
        }
        std::vector<AbilityInfo> vector;
        if (replyMode_ == MODE_ONE_ITEM) {
            AbilityInfo info;
            info.bundleName = "com.test.browser";
            info.name = "MainAbility";
            vector.emplace_back(info);
        }
        if (replyMode_ == MODE_NEGATIVE_COUNT || replyMode_ == MODE_HUGE_COUNT ||
            replyMode_ == MODE_CORRUPT_ELEMENT || replyMode_ == MODE_ZERO_COUNT) {
            return WriteRawCountBuffer(reply);
        }
        return WriteAbilityVectorToReply(vector, reply);
    }

    // Builds a raw buffer whose first int32 drives a ParseVectorFromBuffer branch:
    //   NEGATIVE_COUNT  -> infoSize = -1            (infoSize < 0)
    //   HUGE_COUNT      -> infoSize = INT32_MAX     (infoSize > max_size, see proxy test notes)
    //   CORRUPT_ELEMENT -> infoSize = 1 + junk      (ReadParcelable returns nullptr)
    //   ZERO_COUNT      -> infoSize = 0             (loop skipped, success)
    int WriteRawCountBuffer(MessageParcel &reply)
    {
        Parcel tempParcel;
        (void)tempParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
        int32_t infoSize = 0;
        if (replyMode_ == MODE_NEGATIVE_COUNT) {
            infoSize = -1;
        } else if (replyMode_ == MODE_HUGE_COUNT) {
            infoSize = INT32_MAX;
        } else if (replyMode_ == MODE_CORRUPT_ELEMENT) {
            infoSize = 1;
        }
        if (!tempParcel.WriteInt32(infoSize)) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        // For CORRUPT_ELEMENT append a couple of junk bytes so the buffer is non-empty
        // after the count but far too short to form a valid AbilityInfo: ReadParcelable
        // fails fast and returns nullptr.
        if (replyMode_ == MODE_CORRUPT_ELEMENT) {
            if (!tempParcel.WriteInt32(0xDEADBEEF)) {
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
        }
        const uint8_t *base = reinterpret_cast<const uint8_t *>(tempParcel.GetData());
        std::vector<uint8_t> rawBuffer(base, base + tempParcel.GetDataSize());
        return WriteRawBufferToReply(rawBuffer, reply);
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
    ReplyMode replyMode_ = MODE_EMPTY_VECTOR;
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

// === GetDefaultApplicationCandidates ===

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_EmptyType)
{
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "", 0, infos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_TYPE);
    EXPECT_FALSE(remote_->called_);
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_EmptyVector)
{
    remote_->replyMode_ = MockDefaultAppRemote::MODE_EMPTY_VECTOR;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(infos.empty());
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_OneItem)
{
    remote_->replyMode_ = MockDefaultAppRemote::MODE_ONE_ITEM;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(infos.size(), static_cast<size_t>(1));
    EXPECT_EQ(infos[0].bundleName, "com.test.browser");
    EXPECT_EQ(infos[0].name, "MainAbility");
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_ErrReply)
{
    remote_->replyErr_ = ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    EXPECT_TRUE(infos.empty());
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_SendRequestFailed)
{
    remote_->shouldFail_ = true;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_AshmemFailure)
{
    remote_->replyMode_ = MockDefaultAppRemote::MODE_HUGE_ASHMEM;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_LiarCount)
{
    remote_->replyMode_ = MockDefaultAppRemote::MODE_LIAR_COUNT;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
    EXPECT_TRUE(infos.empty());
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_NegativeCount)
{
    remote_->replyMode_ = MockDefaultAppRemote::MODE_NEGATIVE_COUNT;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
    EXPECT_TRUE(infos.empty());
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_HugeCount)
{
    remote_->replyMode_ = MockDefaultAppRemote::MODE_HUGE_COUNT;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
    EXPECT_TRUE(infos.empty());
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_CorruptElement)
{
    remote_->replyMode_ = MockDefaultAppRemote::MODE_CORRUPT_ELEMENT;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
    EXPECT_TRUE(infos.empty());
}

TEST_F(BmsDefaultAppProxyTest, GetDefaultApplicationCandidates_ZeroCount)
{
    remote_->replyMode_ = MockDefaultAppRemote::MODE_ZERO_COUNT;
    std::vector<AbilityInfo> infos;
    ErrCode ret = proxy_->GetDefaultApplicationCandidates(TEST_USER_ID, "BROWSER", 0, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(infos.empty());
}

// === Null remote ===

TEST_F(BmsDefaultAppProxyTest, NullRemote)
{
    auto nullProxy = std::make_unique<DefaultAppProxy>(nullptr);
    bool isDefault = false;
    ErrCode ret = nullProxy->IsDefaultApplication("browser", isDefault);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}
