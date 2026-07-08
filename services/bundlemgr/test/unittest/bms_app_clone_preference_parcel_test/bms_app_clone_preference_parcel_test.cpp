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

#include "parcel.h"

#include "app_clone_preference.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace testing;
using namespace testing::ext;

// Allocator that always fails — injected into a Parcel via SetAllocator to force WriteInt32 to
// return false, exercising the FIRST false branch of Marshalling (mode write failure).
class NullAllocator : public OHOS::Allocator {
public:
    void *Alloc(size_t size) override { return nullptr; }
    void *Realloc(void *data, size_t newSize) override { return nullptr; }
    void Dealloc(void *data) override {}
};

// Allocator that succeeds on the first Realloc (real heap allocation) and fails on every
// subsequent call. Combined with pre-filling the Parcel so that the second WriteInt32 in
// Marshalling needs a Realloc, this exercises the SECOND false branch (appIndex write failure)
// independently from the first. Memory handed back to the Parcel is freed via Dealloc.
class FailOnSecondRealloc : public OHOS::Allocator {
public:
    void *Alloc(size_t size) override { return nullptr; }
    void *Realloc(void *data, size_t newSize) override
    {
        if (calls_ >= 1) {
            return nullptr;
        }
        calls_++;
        return ::malloc(newSize);
    }
    void Dealloc(void *data) override { ::free(data); }

private:
    int calls_ = 0;
};

class BmsAppClonePreferenceParcelTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

// -------------------- Default-constructed state --------------------

// Default-constructed AppClonePreference must be a valid ALWAYS_ASK record so it can be sent
// over IPC without explicit initialization. Verifies the defaults that Unmarshalling relies on
// for the "no explicit value" case and that Marshalling can round-trip a default-constructed obj.
HWTEST_F(BmsAppClonePreferenceParcelTest, DefaultConstructor_001, TestSize.Level1)
{
    AppClonePreference pref;
    EXPECT_EQ(pref.mode, AppClonePreferenceMode::ALWAYS_ASK);
    EXPECT_EQ(pref.appIndex, 0);
    Parcel parcel;
    ASSERT_TRUE(pref.Marshalling(parcel));
    auto *restored = AppClonePreference::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->mode, AppClonePreferenceMode::ALWAYS_ASK);
    EXPECT_EQ(restored->appIndex, 0);
    delete restored;
}

// -------------------- Marshalling happy paths --------------------

HWTEST_F(BmsAppClonePreferenceParcelTest, Marshalling_AlwaysAsk_Roundtrip_001, TestSize.Level1)
{
    AppClonePreference original;
    original.mode = AppClonePreferenceMode::ALWAYS_ASK;
    original.appIndex = 0;
    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    auto *restored = AppClonePreference::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->mode, AppClonePreferenceMode::ALWAYS_ASK);
    EXPECT_EQ(restored->appIndex, 0);
    delete restored;
}

HWTEST_F(BmsAppClonePreferenceParcelTest, Marshalling_Main_Roundtrip_001, TestSize.Level1)
{
    AppClonePreference original;
    original.mode = AppClonePreferenceMode::MAIN_APP;
    original.appIndex = 0;
    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    auto *restored = AppClonePreference::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->mode, AppClonePreferenceMode::MAIN_APP);
    EXPECT_EQ(restored->appIndex, 0);
    delete restored;
}

HWTEST_F(BmsAppClonePreferenceParcelTest, Marshalling_Clone_Roundtrip_001, TestSize.Level1)
{
    AppClonePreference original;
    original.mode = AppClonePreferenceMode::CLONE_APP;
    original.appIndex = 3;
    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    auto *restored = AppClonePreference::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(restored->appIndex, 3);
    delete restored;
}

HWTEST_F(BmsAppClonePreferenceParcelTest, Marshalling_Clone_BoundaryMin_001, TestSize.Level1)
{
    AppClonePreference original;
    original.mode = AppClonePreferenceMode::CLONE_APP;
    original.appIndex = 1;
    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));
    auto *restored = AppClonePreference::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->appIndex, 1);
    delete restored;
}

HWTEST_F(BmsAppClonePreferenceParcelTest, Marshalling_Clone_BoundaryMax_001, TestSize.Level1)
{
    AppClonePreference original;
    original.mode = AppClonePreferenceMode::CLONE_APP;
    original.appIndex = 5;
    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));
    auto *restored = AppClonePreference::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->appIndex, 5);
    delete restored;
}

HWTEST_F(BmsAppClonePreferenceParcelTest, Marshalling_AllEnumValues_001, TestSize.Level1)
{
    const std::vector<std::pair<AppClonePreferenceMode, int32_t>> cases = {
        {AppClonePreferenceMode::ALWAYS_ASK, 0},
        {AppClonePreferenceMode::MAIN_APP, 0},
        {AppClonePreferenceMode::CLONE_APP, 1},
        {AppClonePreferenceMode::CLONE_APP, 2},
        {AppClonePreferenceMode::CLONE_APP, 3},
        {AppClonePreferenceMode::CLONE_APP, 4},
        {AppClonePreferenceMode::CLONE_APP, 5},
    };
    for (const auto &c : cases) {
        AppClonePreference original;
        original.mode = c.first;
        original.appIndex = c.second;
        Parcel parcel;
        ASSERT_TRUE(original.Marshalling(parcel));
        auto *restored = AppClonePreference::Unmarshalling(parcel);
        ASSERT_NE(restored, nullptr);
        EXPECT_EQ(restored->mode, c.first);
        EXPECT_EQ(restored->appIndex, c.second);
        delete restored;
    }
}

// -------------------- Marshalling failure branches --------------------

// Force the FIRST WriteInt32 (mode) to fail by making every Realloc return nullptr. Verifies
// the early-false branch of Marshalling regardless of which valid mode is set on the input.
HWTEST_F(BmsAppClonePreferenceParcelTest, Marshalling_WriteMode_Fails_001, TestSize.Level1)
{
    AppClonePreference original;
    original.mode = AppClonePreferenceMode::MAIN_APP;
    Parcel parcel;
    parcel.SetAllocator(new NullAllocator());
    EXPECT_FALSE(original.Marshalling(parcel));
    // Re-run with a different mode to confirm the failure is allocator-driven, not mode-driven.
    Parcel parcel2;
    parcel2.SetAllocator(new NullAllocator());
    original.mode = AppClonePreferenceMode::CLONE_APP;
    original.appIndex = 2;
    EXPECT_FALSE(original.Marshalling(parcel2));
}

// Force the SECOND WriteInt32 (appIndex) to fail. The Parcel is pre-filled with 60 bytes so
// that after the first Realloc (64-byte buffer) the first Marshalling WriteInt32 fits in the
// remaining 4 bytes (no Realloc needed), but the second WriteInt32 needs a Realloc that
// FailOnSecondRealloc will reject.
HWTEST_F(BmsAppClonePreferenceParcelTest, Marshalling_WriteAppIndex_Fails_001, TestSize.Level1)
{
    AppClonePreference original;
    original.mode = AppClonePreferenceMode::MAIN_APP;
    Parcel parcel;
    parcel.SetAllocator(new FailOnSecondRealloc());
    uint8_t pad[60] = {0};
    ASSERT_TRUE(parcel.WriteUnpadBuffer(pad, sizeof(pad)));
    EXPECT_FALSE(original.Marshalling(parcel));
}

// -------------------- Unmarshalling failure branches --------------------

// Unmarshalling from an empty parcel — the first ReadInt32 (mode) fails → returns nullptr.
// Verified with both a completely empty parcel and a parcel holding an unrelated byte that
// still cannot satisfy a 4-byte ReadInt32.
HWTEST_F(BmsAppClonePreferenceParcelTest, Unmarshalling_EmptyParcel_001, TestSize.Level1)
{
    Parcel parcel;
    auto *result = AppClonePreference::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
    Parcel parcel2;
    uint8_t oneByte = 0xAB;
    ASSERT_TRUE(parcel2.WriteUint8(oneByte));  // 1 byte — not enough for ReadInt32
    auto *result2 = AppClonePreference::Unmarshalling(parcel2);
    EXPECT_EQ(result2, nullptr);
}

// Type is valid but appIndex ReadInt32 fails (parcel exhausted after the first int).
HWTEST_F(BmsAppClonePreferenceParcelTest, Unmarshalling_TypeValid_NoAppIndex_001, TestSize.Level1)
{
    Parcel parcel;
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(AppClonePreferenceMode::MAIN_APP)));
    // Note: no appIndex written — ReadInt32 will fail.
    auto *result = AppClonePreference::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
    // Same shape with a different valid type — the second ReadInt32 still fails.
    Parcel parcel2;
    ASSERT_TRUE(parcel2.WriteInt32(static_cast<int32_t>(AppClonePreferenceMode::ALWAYS_ASK)));
    auto *result2 = AppClonePreference::Unmarshalling(parcel2);
    EXPECT_EQ(result2, nullptr);
}

// Unmarshalling rejects any type outside the [ALWAYS_ASK=0, CLONE_APP=2] range. The range check
// fires after both ReadInt32 calls succeed, so appIndex is always present in the parcel.
HWTEST_F(BmsAppClonePreferenceParcelTest, Unmarshalling_OutOfRangeType_Rejected_001, TestSize.Level1)
{
    const std::vector<int32_t> outOfRangeTypes = {99, 3, -1};
    for (int32_t rawType : outOfRangeTypes) {
        Parcel parcel;
        ASSERT_TRUE(parcel.WriteInt32(rawType));
        ASSERT_TRUE(parcel.WriteInt32(0));
        auto *restored = AppClonePreference::Unmarshalling(parcel);
        EXPECT_EQ(restored, nullptr) << "rawType=" << rawType << " should be rejected";
    }
}

// Boundary: CLONE_APP (max valid type) accepted.
HWTEST_F(BmsAppClonePreferenceParcelTest, Unmarshalling_MaxValidType_Accepted_001, TestSize.Level1)
{
    Parcel parcel;
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(AppClonePreferenceMode::CLONE_APP)));
    ASSERT_TRUE(parcel.WriteInt32(3));
    auto *restored = AppClonePreference::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(restored->appIndex, 3);
    delete restored;
}

// Boundary: ALWAYS_ASK (min valid type) accepted.
HWTEST_F(BmsAppClonePreferenceParcelTest, Unmarshalling_MinValidType_Accepted_001, TestSize.Level1)
{
    Parcel parcel;
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(AppClonePreferenceMode::ALWAYS_ASK)));
    ASSERT_TRUE(parcel.WriteInt32(0));
    auto *restored = AppClonePreference::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->mode, AppClonePreferenceMode::ALWAYS_ASK);
    EXPECT_EQ(restored->appIndex, 0);
    delete restored;
}
