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

#include "mock_zstd.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <iterator>
#include <map>
#include <new>

namespace OHOS {
namespace AppExecFwk {
namespace MockZstd {
namespace {
constexpr uint8_t MAGIC_BYTES[] = { 0x28, 0xB5, 0x2F, 0xFD };
constexpr size_t MAGIC_SIZE = sizeof(MAGIC_BYTES);
constexpr size_t FHD_SIZE = 1;
constexpr size_t BLOCK_HEADER_SIZE = 3;
constexpr size_t CHECKSUM_SIZE = 4;
constexpr size_t MAX_FRAME_HEADER_SIZE = 18;
constexpr size_t FOUR_BYTES_FCS_FIELD_SIZE = 4;
constexpr size_t TWO_BYTES_FCS_FIELD_SIZE = 2;
constexpr uint64_t TWO_BYTES_FCS_OFFSET = 256;
constexpr size_t DID_FIELD_SIZES[] = { 0, 1, 2, 4 };
constexpr size_t FCS_FIELD_SIZES[] = { 0, 2, 4, 8 };
// Frame_Content_Size_flag 2 (4 bytes field) with Single_Segment_flag
constexpr uint8_t FHD_FOUR_BYTES_FCS_SINGLE_SEGMENT = 0xA0;
constexpr uint8_t FHD_NO_FCS = 0x00;
// Window_Descriptor of a 128 KB window, used when the frame is not single segment
constexpr uint8_t WINDOW_DESCRIPTOR_128K = 0x38;
constexpr uint8_t FHD_SINGLE_SEGMENT_BIT = 0x20;
constexpr uint8_t FHD_RESERVED_BIT = 0x08;
constexpr uint8_t FHD_CHECKSUM_BIT = 0x04;
constexpr uint8_t FHD_DID_MASK = 0x03;
constexpr uint8_t FHD_FCS_SHIFT = 6;
constexpr uint32_t BLOCK_TYPE_RAW = 0;
constexpr uint32_t BLOCK_TYPE_RESERVED = 3;
constexpr uint32_t BLOCK_TYPE_SHIFT = 1;
constexpr uint32_t BLOCK_TYPE_MASK = 0x3;
constexpr uint32_t BLOCK_SIZE_SHIFT = 3;
constexpr uint32_t LAST_BLOCK_BIT = 0x1;
constexpr uint32_t BITS_PER_BYTE = 8;
constexpr uint64_t BYTE_MASK = 0xFF;
constexpr uint32_t CONTENT_MULTIPLIER = 31;
// libzstd reports error codes as (size_t)-errorCode, every code above (size_t)-ZSTD_error_maxCode is an error
constexpr size_t ERROR_MAX_CODE = static_cast<size_t>(-120);
constexpr const char* CORRUPTION_ERROR_NAME = "Data corruption detected";
constexpr const char* NO_ERROR_NAME = "No error detected";

std::atomic<size_t> g_inSize { MOCK_DEFAULT_IN_SIZE };
std::atomic<size_t> g_outSize { MOCK_DEFAULT_OUT_SIZE };
std::atomic<int32_t> g_liveStreams { 0 };

enum class Stage {
    FRAME_HEADER,
    BLOCK_HEADER,
    BLOCK_DATA,
    CHECKSUM,
    FRAME_DONE,
};

struct MockDStream {
    Stage stage = Stage::FRAME_HEADER;
    uint8_t header[MAX_FRAME_HEADER_SIZE] = {};
    size_t headerLen = 0;
    size_t headerNeed = MAGIC_SIZE + FHD_SIZE;
    bool headerParsed = false;
    bool hasChecksum = false;
    uint8_t blockHeader[BLOCK_HEADER_SIZE] = {};
    size_t blockHeaderLen = 0;
    size_t blockRemaining = 0;
    bool lastBlock = false;
    size_t checksumLen = 0;
};

void AppendLittleEndian(std::vector<uint8_t> &out, uint64_t value, size_t bytes)
{
    for (size_t i = 0; i < bytes; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (i * BITS_PER_BYTE)) & BYTE_MASK));
    }
}

uint64_t ReadLittleEndian(const uint8_t *data, size_t bytes)
{
    uint64_t value = 0;
    for (size_t i = 0; i < bytes; ++i) {
        value |= static_cast<uint64_t>(data[i]) << (i * BITS_PER_BYTE);
    }
    return value;
}

bool IsMagicValid(const uint8_t *data)
{
    return std::memcmp(data, MAGIC_BYTES, MAGIC_SIZE) == 0;
}

size_t GetFcsFieldSize(uint8_t fhd)
{
    size_t fcsSize = FCS_FIELD_SIZES[fhd >> FHD_FCS_SHIFT];
    if ((fcsSize == 0) && ((fhd & FHD_SINGLE_SEGMENT_BIT) != 0)) {
        fcsSize = 1;
    }
    return fcsSize;
}

size_t GetFrameHeaderSize(uint8_t fhd)
{
    size_t windowDescriptorSize = ((fhd & FHD_SINGLE_SEGMENT_BIT) != 0) ? 0 : 1;
    return MAGIC_SIZE + FHD_SIZE + windowDescriptorSize + DID_FIELD_SIZES[fhd & FHD_DID_MASK] +
        GetFcsFieldSize(fhd);
}

unsigned long long ParseContentSize(const uint8_t *header)
{
    uint8_t fhd = header[MAGIC_SIZE];
    size_t fcsSize = GetFcsFieldSize(fhd);
    if (fcsSize == 0) {
        return ZSTD_CONTENT_SIZE_UNKNOWN;
    }
    uint64_t contentSize = ReadLittleEndian(header + GetFrameHeaderSize(fhd) - fcsSize, fcsSize);
    if (fcsSize == TWO_BYTES_FCS_FIELD_SIZE) {
        contentSize += TWO_BYTES_FCS_OFFSET;
    }
    return contentSize;
}

// every step returns true when decoding goes on, or false with the value to return in ret
bool StepFrameHeader(MockDStream &stream, ZstdInBuffer &input, size_t &ret)
{
    const uint8_t *src = static_cast<const uint8_t *>(input.src);
    while ((stream.headerLen < stream.headerNeed) && (input.pos < input.size)) {
        stream.header[stream.headerLen++] = src[input.pos++];
    }
    if (stream.headerLen < stream.headerNeed) {
        ret = stream.headerNeed - stream.headerLen;
        return false;
    }
    if (!stream.headerParsed) {
        uint8_t fhd = stream.header[MAGIC_SIZE];
        if (!IsMagicValid(stream.header) || ((fhd & FHD_RESERVED_BIT) != 0)) {
            ret = MOCK_ERROR_CORRUPTION;
            return false;
        }
        stream.headerParsed = true;
        stream.hasChecksum = (fhd & FHD_CHECKSUM_BIT) != 0;
        stream.headerNeed = GetFrameHeaderSize(fhd);
        return true;
    }
    stream.stage = Stage::BLOCK_HEADER;
    stream.blockHeaderLen = 0;
    return true;
}

bool StepBlockHeader(MockDStream &stream, ZstdInBuffer &input, size_t &ret)
{
    const uint8_t *src = static_cast<const uint8_t *>(input.src);
    while ((stream.blockHeaderLen < BLOCK_HEADER_SIZE) && (input.pos < input.size)) {
        stream.blockHeader[stream.blockHeaderLen++] = src[input.pos++];
    }
    if (stream.blockHeaderLen < BLOCK_HEADER_SIZE) {
        ret = BLOCK_HEADER_SIZE - stream.blockHeaderLen;
        return false;
    }
    uint32_t blockHeader = static_cast<uint32_t>(ReadLittleEndian(stream.blockHeader, BLOCK_HEADER_SIZE));
    uint32_t blockType = (blockHeader >> BLOCK_TYPE_SHIFT) & BLOCK_TYPE_MASK;
    stream.lastBlock = (blockHeader & LAST_BLOCK_BIT) != 0;
    stream.blockRemaining = blockHeader >> BLOCK_SIZE_SHIFT;
    // only raw blocks are supported by the mock, any other block type is reported as corruption
    if ((blockType != BLOCK_TYPE_RAW) || (stream.blockRemaining > MOCK_MAX_BLOCK_SIZE)) {
        ret = MOCK_ERROR_CORRUPTION;
        return false;
    }
    stream.stage = Stage::BLOCK_DATA;
    return true;
}

bool FinishBlock(MockDStream &stream, size_t &ret)
{
    if (!stream.lastBlock) {
        stream.stage = Stage::BLOCK_HEADER;
        stream.blockHeaderLen = 0;
        return true;
    }
    if (stream.hasChecksum) {
        stream.stage = Stage::CHECKSUM;
        stream.checksumLen = 0;
        return true;
    }
    stream.stage = Stage::FRAME_DONE;
    ret = 0;
    return false;
}

bool StepBlockData(MockDStream &stream, ZstdOutBuffer &output, ZstdInBuffer &input, size_t &ret)
{
    size_t len = std::min({ stream.blockRemaining, input.size - input.pos, output.size - output.pos });
    if (len > 0) {
        std::memcpy(static_cast<uint8_t *>(output.dst) + output.pos,
            static_cast<const uint8_t *>(input.src) + input.pos, len);
        input.pos += len;
        output.pos += len;
        stream.blockRemaining -= len;
    }
    if (stream.blockRemaining > 0) {
        ret = stream.blockRemaining;
        return false;
    }
    return FinishBlock(stream, ret);
}

bool StepChecksum(MockDStream &stream, ZstdInBuffer &input, size_t &ret)
{
    size_t len = std::min(CHECKSUM_SIZE - stream.checksumLen, input.size - input.pos);
    input.pos += len;
    stream.checksumLen += len;
    if (stream.checksumLen < CHECKSUM_SIZE) {
        ret = CHECKSUM_SIZE - stream.checksumLen;
        return false;
    }
    stream.stage = Stage::FRAME_DONE;
    ret = 0;
    return false;
}
}  // namespace

std::vector<uint8_t> MakeContent(size_t size, uint8_t seed)
{
    std::vector<uint8_t> content(size);
    for (size_t i = 0; i < size; ++i) {
        content[i] = static_cast<uint8_t>((i * CONTENT_MULTIPLIER + seed) & BYTE_MASK);
    }
    return content;
}

std::vector<uint8_t> BuildRawFrame(const std::vector<uint8_t> &content, bool withContentSize, size_t blockSize)
{
    std::vector<uint8_t> frame(std::begin(MAGIC_BYTES), std::end(MAGIC_BYTES));
    if (withContentSize) {
        frame.push_back(FHD_FOUR_BYTES_FCS_SINGLE_SEGMENT);
        AppendLittleEndian(frame, content.size(), FOUR_BYTES_FCS_FIELD_SIZE);
    } else {
        frame.push_back(FHD_NO_FCS);
        frame.push_back(WINDOW_DESCRIPTOR_128K);
    }
    size_t maxBlockSize = std::max<size_t>(1, std::min(blockSize, MOCK_MAX_BLOCK_SIZE));
    size_t offset = 0;
    do {
        size_t len = std::min(maxBlockSize, content.size() - offset);
        bool isLastBlock = (offset + len) == content.size();
        uint32_t blockHeader = (static_cast<uint32_t>(len) << BLOCK_SIZE_SHIFT) |
            (BLOCK_TYPE_RAW << BLOCK_TYPE_SHIFT) | (isLastBlock ? LAST_BLOCK_BIT : 0);
        AppendLittleEndian(frame, blockHeader, BLOCK_HEADER_SIZE);
        auto begin = content.begin() + static_cast<std::ptrdiff_t>(offset);
        frame.insert(frame.end(), begin, begin + static_cast<std::ptrdiff_t>(len));
        offset += len;
    } while (offset < content.size());
    return frame;
}

std::vector<uint8_t> BuildReservedBlockFrame()
{
    std::vector<uint8_t> frame(std::begin(MAGIC_BYTES), std::end(MAGIC_BYTES));
    frame.push_back(FHD_NO_FCS);
    frame.push_back(WINDOW_DESCRIPTOR_128K);
    AppendLittleEndian(frame, (BLOCK_TYPE_RESERVED << BLOCK_TYPE_SHIFT) | LAST_BLOCK_BIT, BLOCK_HEADER_SIZE);
    return frame;
}

ZstdDStream *CreateDStream()
{
    MockDStream *stream = new (std::nothrow) MockDStream();
    if (stream != nullptr) {
        ++g_liveStreams;
    }
    return reinterpret_cast<ZstdDStream *>(stream);
}

ZstdDStream *CreateDStreamFailed()
{
    return nullptr;
}

size_t FreeDStream(ZstdDStream *zds)
{
    if (zds != nullptr) {
        delete reinterpret_cast<MockDStream *>(zds);
        --g_liveStreams;
    }
    return 0;
}

size_t DecompressStream(ZstdDStream *zds, ZstdOutBuffer *output, ZstdInBuffer *input)
{
    MockDStream *stream = reinterpret_cast<MockDStream *>(zds);
    if ((stream == nullptr) || (output == nullptr) || (input == nullptr)) {
        return MOCK_ERROR_CORRUPTION;
    }
    if (stream->stage == Stage::FRAME_DONE) {
        if (input->pos >= input->size) {
            return 0;
        }
        // like libzstd, decoding stops at the end of a frame and the next call starts the next frame
        *stream = MockDStream();
    }
    size_t ret = 0;
    bool goOn = true;
    while (goOn) {
        switch (stream->stage) {
            case Stage::FRAME_HEADER:
                goOn = StepFrameHeader(*stream, *input, ret);
                break;
            case Stage::BLOCK_HEADER:
                goOn = StepBlockHeader(*stream, *input, ret);
                break;
            case Stage::BLOCK_DATA:
                goOn = StepBlockData(*stream, *output, *input, ret);
                break;
            case Stage::CHECKSUM:
                goOn = StepChecksum(*stream, *input, ret);
                break;
            default:
                goOn = false;
                ret = 0;
                break;
        }
    }
    return ret;
}

size_t DStreamInSize()
{
    return g_inSize.load();
}

size_t DStreamOutSize()
{
    return g_outSize.load();
}

unsigned long long GetFrameContentSize(const void *src, size_t srcSize)
{
    const uint8_t *data = static_cast<const uint8_t *>(src);
    if ((data == nullptr) || (srcSize < MAGIC_SIZE + FHD_SIZE) || !IsMagicValid(data)) {
        return ZSTD_CONTENT_SIZE_ERROR;
    }
    uint8_t fhd = data[MAGIC_SIZE];
    if (((fhd & FHD_RESERVED_BIT) != 0) || (srcSize < GetFrameHeaderSize(fhd))) {
        return ZSTD_CONTENT_SIZE_ERROR;
    }
    return ParseContentSize(data);
}

unsigned IsError(size_t code)
{
    return (code > ERROR_MAX_CODE) ? 1 : 0;
}

const char *GetErrorName(size_t code)
{
    return (IsError(code) != 0) ? CORRUPTION_ERROR_NAME : NO_ERROR_NAME;
}

void SetStreamSizes(size_t inSize, size_t outSize)
{
    g_inSize.store(inSize);
    g_outSize.store(outSize);
}

int32_t GetLiveStreamCount()
{
    return g_liveStreams.load();
}

void *GetSymbol(const std::string &symbolName)
{
    static const std::map<std::string, void *> symbols = {
        { "ZSTD_createDStream", reinterpret_cast<void *>(&CreateDStream) },
        { "ZSTD_freeDStream", reinterpret_cast<void *>(&FreeDStream) },
        { "ZSTD_decompressStream", reinterpret_cast<void *>(&DecompressStream) },
        { "ZSTD_DStreamInSize", reinterpret_cast<void *>(&DStreamInSize) },
        { "ZSTD_DStreamOutSize", reinterpret_cast<void *>(&DStreamOutSize) },
        { "ZSTD_getFrameContentSize", reinterpret_cast<void *>(&GetFrameContentSize) },
        { "ZSTD_isError", reinterpret_cast<void *>(&IsError) },
        { "ZSTD_getErrorName", reinterpret_cast<void *>(&GetErrorName) },
    };
    auto iter = symbols.find(symbolName);
    return (iter == symbols.end()) ? nullptr : iter->second;
}

const std::vector<std::string> &GetSymbolNames()
{
    static const std::vector<std::string> symbolNames = {
        "ZSTD_createDStream",
        "ZSTD_freeDStream",
        "ZSTD_decompressStream",
        "ZSTD_DStreamInSize",
        "ZSTD_DStreamOutSize",
        "ZSTD_getFrameContentSize",
        "ZSTD_isError",
        "ZSTD_getErrorName",
    };
    return symbolNames;
}
}  // namespace MockZstd
}  // namespace AppExecFwk
}  // namespace OHOS
