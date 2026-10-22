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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_UNITTEST_BMS_PRE_COMPRESS_TEST_MOCK_ZSTD_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_UNITTEST_BMS_PRE_COMPRESS_TEST_MOCK_ZSTD_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "zstd_abi.h"

namespace OHOS {
namespace AppExecFwk {
namespace MockZstd {
// the zstd error code the mock reports for corrupted input, (size_t)-ZSTD_error_corruption_detected
constexpr size_t MOCK_ERROR_CORRUPTION = static_cast<size_t>(-20);
constexpr size_t MOCK_DEFAULT_IN_SIZE = 13;
constexpr size_t MOCK_DEFAULT_OUT_SIZE = 7;
constexpr size_t MOCK_MAX_BLOCK_SIZE = 128 * 1024;

/**
 * @brief Build deterministic content of the given size.
 */
std::vector<uint8_t> MakeContent(size_t size, uint8_t seed);

/**
 * @brief Build a zstd frame (RFC 8878) that stores the content in raw blocks.
 * @param withContentSize Whether the frame header carries the Frame_Content_Size field.
 * @param blockSize Indicates the max size of each raw block.
 */
std::vector<uint8_t> BuildRawFrame(const std::vector<uint8_t> &content, bool withContentSize,
    size_t blockSize = MOCK_MAX_BLOCK_SIZE);

/**
 * @brief Build a zstd frame whose only block uses the reserved block type.
 */
std::vector<uint8_t> BuildReservedBlockFrame();

// the libzstd entries, decoding zstd frames made of raw blocks with the libzstd streaming contract:
// 0 is returned once a frame is fully decoded, a positive hint while more input is needed
ZstdDStream *CreateDStream();
ZstdDStream *CreateDStreamFailed();
size_t FreeDStream(ZstdDStream *zds);
size_t DecompressStream(ZstdDStream *zds, ZstdOutBuffer *output, ZstdInBuffer *input);
size_t DStreamInSize();
size_t DStreamOutSize();
unsigned long long GetFrameContentSize(const void *src, size_t srcSize);
unsigned IsError(size_t code);
const char *GetErrorName(size_t code);

/**
 * @brief Set the buffer sizes reported by DStreamInSize and DStreamOutSize.
 */
void SetStreamSizes(size_t inSize, size_t outSize);

/**
 * @brief The number of streams created and not freed yet.
 */
int32_t GetLiveStreamCount();

/**
 * @brief The address of the mock entry exported as the libzstd symbol, nullptr for an unknown symbol.
 */
void *GetSymbol(const std::string &symbolName);

/**
 * @brief The libzstd symbols ZstdWrapper resolves, in resolving order.
 */
const std::vector<std::string> &GetSymbolNames();
}  // namespace MockZstd
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_UNITTEST_BMS_PRE_COMPRESS_TEST_MOCK_ZSTD_H
