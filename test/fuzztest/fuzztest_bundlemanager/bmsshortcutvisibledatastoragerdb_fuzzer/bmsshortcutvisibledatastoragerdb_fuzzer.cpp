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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bundle_distributed_manager.h"
#include "bmsshortcutvisibledatastoragerdb_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "shortcut_visible_data_storage_rdb.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {

// UTF-8 encoding constants
// Byte sequence length constants
constexpr uint8_t UTF8_TWO_BYTE_SEQUENCE_LENGTH = 2;    // 2-byte UTF-8 sequence length
constexpr uint8_t UTF8_THREE_BYTE_SEQUENCE_LENGTH = 3;  // 3-byte UTF-8 sequence length
constexpr uint8_t UTF8_FOUR_BYTE_SEQUENCE_LENGTH = 4;   // 4-byte UTF-8 sequence length

// Byte offset constants for checking sequence completeness
constexpr uint8_t UTF8_TWO_BYTE_OFFSET = 1;    // Offset for 2-byte sequence (need i+1)
constexpr uint8_t UTF8_THREE_BYTE_OFFSET = 2;  // Offset for 3-byte sequence (need i+2)
constexpr uint8_t UTF8_FOUR_BYTE_OFFSET = 3;   // Offset for 4-byte sequence (need i+3)

// UTF-8 byte range boundary constants
constexpr uint8_t UTF8_TWO_BYTE_INVALID_MAX = 0xC1;    // Invalid 2-byte start (non-shortest form)

constexpr uint8_t UTF8_THREE_BYTE_START_E0 = 0xE0;      // 3-byte sequence start 0xE0
constexpr uint8_t UTF8_THREE_BYTE_START_ED = 0xED;      // 3-byte sequence start 0xED
constexpr uint8_t UTF8_THREE_BYTE_E0_SECOND_MIN = 0xA0; // Minimum second byte for 0xE0
constexpr uint8_t UTF8_THREE_BYTE_ED_SECOND_MAX = 0x9F; // Maximum second byte for 0xED (exclude surrogate)

constexpr uint8_t UTF8_FOUR_BYTE_MAX_VALID = 0xF4;     // Maximum valid 4-byte start
constexpr uint8_t UTF8_FOUR_BYTE_START_F0 = 0xF0;       // 4-byte sequence start 0xF0
constexpr uint8_t UTF8_FOUR_BYTE_START_F4 = 0xF4;       // 4-byte sequence start 0xF4
constexpr uint8_t UTF8_FOUR_BYTE_F0_SECOND_MIN = 0x90;  // Minimum second byte for 0xF0 (U+10000 boundary)
constexpr uint8_t UTF8_FOUR_BYTE_F4_SECOND_MAX = 0x8F;  // Maximum second byte for 0xF4 (U+10FFFF boundary)

constexpr uint8_t UTF8_CONTINUATION_BYTE_MASK = 0xC0;   // Mask for checking continuation byte format
constexpr uint8_t UTF8_CONTINUATION_BYTE_PATTERN = 0x80; // Expected pattern for continuation byte (10xxxxxx)

bool IsContinuationByte(unsigned char c)
{
    return (c & UTF8_CONTINUATION_BYTE_MASK) == UTF8_CONTINUATION_BYTE_PATTERN;
}

bool ValidateTwoByteSequence(const std::string &str, size_t &i, size_t len)
{
    if (i + UTF8_TWO_BYTE_OFFSET >= len) {
        return false;
    }
    unsigned char c = static_cast<unsigned char>(str[i]);
    if (c <= UTF8_TWO_BYTE_INVALID_MAX) {
        return false;
    }
    unsigned char c2 = static_cast<unsigned char>(str[i + UTF8_TWO_BYTE_OFFSET]);
    if (!IsContinuationByte(c2)) {
        return false;
    }
    i += UTF8_TWO_BYTE_SEQUENCE_LENGTH;
    return true;
}

bool ValidateThreeByteSequence(const std::string &str, size_t &i, size_t len)
{
    if (i + UTF8_THREE_BYTE_OFFSET >= len) {
        return false;
    }
    unsigned char c = static_cast<unsigned char>(str[i]);
    unsigned char c2 = static_cast<unsigned char>(str[i + UTF8_TWO_BYTE_OFFSET]);
    unsigned char c3 = static_cast<unsigned char>(str[i + UTF8_THREE_BYTE_OFFSET]);

    if (!IsContinuationByte(c2) || !IsContinuationByte(c3)) {
        return false;
    }

    if (c == UTF8_THREE_BYTE_START_E0 && c2 < UTF8_THREE_BYTE_E0_SECOND_MIN) {
        return false;
    }

    if (c == UTF8_THREE_BYTE_START_ED && c2 > UTF8_THREE_BYTE_ED_SECOND_MAX) {
        return false;
    }

    i += UTF8_THREE_BYTE_SEQUENCE_LENGTH;
    return true;
}

bool ValidateFourByteSequence(const std::string &str, size_t &i, size_t len)
{
    if (i + UTF8_FOUR_BYTE_OFFSET >= len) {
        return false;
    }
    unsigned char c = static_cast<unsigned char>(str[i]);
    if (c > UTF8_FOUR_BYTE_MAX_VALID) {
        return false;
    }

    unsigned char c2 = static_cast<unsigned char>(str[i + UTF8_TWO_BYTE_OFFSET]);
    unsigned char c3 = static_cast<unsigned char>(str[i + UTF8_THREE_BYTE_OFFSET]);
    unsigned char c4 = static_cast<unsigned char>(str[i + UTF8_FOUR_BYTE_OFFSET]);

    if (!IsContinuationByte(c2) || !IsContinuationByte(c3) || !IsContinuationByte(c4)) {
        return false;
    }

    if (c == UTF8_FOUR_BYTE_START_F0 && c2 < UTF8_FOUR_BYTE_F0_SECOND_MIN) {
        return false;
    }

    if (c == UTF8_FOUR_BYTE_START_F4 && c2 > UTF8_FOUR_BYTE_F4_SECOND_MAX) {
        return false;
    }

    i += UTF8_FOUR_BYTE_SEQUENCE_LENGTH;
    return true;
}

bool IsValidUtf8(const std::string &str)
{
    size_t i = 0;
    size_t len = str.size();
    while (i < len) {
        unsigned char c = static_cast<unsigned char>(str[i]);
        if (c <= 0x7F) {
            i += 1;
            continue;
        }
        if ((c & 0xE0) == 0xC0) {
            if (!ValidateTwoByteSequence(str, i, len)) {
                return false;
            }
            continue;
        }
        if ((c & 0xF0) == 0xE0) {
            if (!ValidateThreeByteSequence(str, i, len)) {
                return false;
            }
            continue;
        }
        if ((c & 0xF8) == 0xF0) {
            if (!ValidateFourByteSequence(str, i, len)) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

bool IsValidShortcutInfo(const ShortcutInfo &shortcutInfo)
{
    if (!IsValidUtf8(shortcutInfo.id) ||
        !IsValidUtf8(shortcutInfo.bundleName) ||
        !IsValidUtf8(shortcutInfo.moduleName) ||
        !IsValidUtf8(shortcutInfo.hostAbility) ||
        !IsValidUtf8(shortcutInfo.icon) ||
        !IsValidUtf8(shortcutInfo.label) ||
        !IsValidUtf8(shortcutInfo.disableMessage)) {
        return false;
    }
    if (shortcutInfo.intents.empty()) {
        return true;
    }
    for (const auto& item : shortcutInfo.intents) {
        if (!IsValidUtf8(item.targetBundle) ||
            !IsValidUtf8(item.targetModule) ||
            !IsValidUtf8(item.targetClass)) {
            return false;
        }
        if (item.parameters.empty()) {
            continue;
        }
        for (const auto& param : item.parameters) {
            if (!IsValidUtf8(param.first) ||
                !IsValidUtf8(param.second)) {
                return false;
            }
        }
    }
    return true;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    ShortcutVisibleDataStorageRdb shortcutVisibleDataStorageRdb;
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string shortcutId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = GenerateRandomUser(fdp);
    ShortcutInfo shortcutInfo;
    GenerateDynamicShortcutInfo(fdp, shortcutId, bundleName, appIndex, shortcutInfo);
    if (!IsValidShortcutInfo(shortcutInfo)) {
        return false;
    }
    shortcutVisibleDataStorageRdb.SaveStorageShortcutVisibleInfo(
        bundleName, shortcutId, appIndex, userId, shortcutInfo);
    shortcutVisibleDataStorageRdb.DeleteShortcutVisibleInfo(bundleName, userId, appIndex);

    shortcutVisibleDataStorageRdb.rdbDataManager_ = nullptr;
    shortcutVisibleDataStorageRdb.SaveStorageShortcutVisibleInfo(
        bundleName, shortcutId, appIndex, userId, shortcutInfo);
    shortcutVisibleDataStorageRdb.DeleteShortcutVisibleInfo(bundleName, userId, appIndex);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}