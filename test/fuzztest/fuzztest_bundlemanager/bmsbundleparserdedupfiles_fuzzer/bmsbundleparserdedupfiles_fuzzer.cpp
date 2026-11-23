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

#define private public
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include "bmsbundleparserdedupfiles_fuzzer.h"
#include "bundle_parser.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr const char* DEDUP_FILES_ENTRY_NAME = "dedupfiles.json";
constexpr const char* FUZZ_TEMP_FILE = "/data/local/tmp/bms_fuzz_dedup_files.hap";
// max_len=1000 by project.xml; 512 still fits a valid manifest entry + raw bytes
constexpr size_t DEDUP_PAYLOAD_MAX_LENGTH = 512;
// zip constants of the minimal STORED container (zip_file.h packed layouts)
constexpr uint32_t FUZZ_ZIP_LOCAL_HEADER_SIGNATURE = 0x04034b50;
constexpr uint32_t FUZZ_ZIP_CENTRAL_DIR_SIGNATURE = 0x02014b50;
constexpr uint32_t FUZZ_ZIP_EOCD_SIGNATURE = 0x06054b50;
constexpr uint16_t FUZZ_ZIP_VERSION = 20;  // 2.0
constexpr uint16_t FUZZ_ZIP_METHOD_STORED = 0;
constexpr uint16_t FUZZ_ZIP_MODIFIED_TIME = 0;
constexpr uint16_t FUZZ_ZIP_MODIFIED_DATE = 0x21;  // 1980-01-01
constexpr size_t FUZZ_ZIP_LOCAL_HEADER_SIZE = 30;
constexpr size_t FUZZ_ZIP_CENTRAL_DIR_ENTRY_SIZE = 46;
constexpr size_t FUZZ_ZIP_EOCD_SIZE = 22;
}

void AppendU16(std::string &out, const uint16_t value)
{
    out.push_back(static_cast<char>(value & 0x00ff));
    out.push_back(static_cast<char>((value >> 8) & 0x00ff));
}

void AppendU32(std::string &out, const uint32_t value)
{
    out.push_back(static_cast<char>(value & 0x000000ff));
    out.push_back(static_cast<char>((value >> 8) & 0x000000ff));
    out.push_back(static_cast<char>((value >> 16) & 0x000000ff));
    out.push_back(static_cast<char>((value >> 24) & 0x000000ff));
}

// self-contained CRC-32 (reflected polynomial 0xEDB88320), no zlib needed
uint32_t DedupCrc32(const char *data, const size_t size)
{
    uint32_t crc = 0xffffffff;
    for (size_t i = 0; i < size; ++i) {
        crc ^= static_cast<uint8_t>(data[i]);
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = (crc & 1) ? 0xEDB88320 : 0;
            crc = (crc >> 1) ^ mask;
        }
    }
    return crc ^ 0xffffffff;
}

// Minimal STORED zip consumed by BundleExtractor::Init: local header + entry +
// central dir entry + EOCD, byte-compatible with the packed zip_file.h layouts
std::string BuildStoredDedupZip(const std::string &payload)
{
    const uint16_t nameSize = static_cast<uint16_t>(strlen(DEDUP_FILES_ENTRY_NAME));
    const uint32_t entrySize = static_cast<uint32_t>(payload.size());
    const uint32_t crc = DedupCrc32(payload.data(), payload.size());

    std::string zip;
    zip.reserve(FUZZ_ZIP_LOCAL_HEADER_SIZE + nameSize + payload.size() +
        FUZZ_ZIP_CENTRAL_DIR_ENTRY_SIZE + nameSize + FUZZ_ZIP_EOCD_SIZE);

    // local file header (LocalHeader, 30 bytes)
    AppendU32(zip, FUZZ_ZIP_LOCAL_HEADER_SIGNATURE);
    AppendU16(zip, FUZZ_ZIP_VERSION);       // version needed
    AppendU16(zip, 0);                      // flags: no data descriptor, sizes are in the header
    AppendU16(zip, FUZZ_ZIP_METHOD_STORED);
    AppendU16(zip, FUZZ_ZIP_MODIFIED_TIME);
    AppendU16(zip, FUZZ_ZIP_MODIFIED_DATE);
    AppendU32(zip, crc);
    AppendU32(zip, entrySize);              // compressed size
    AppendU32(zip, entrySize);              // uncompressed size
    AppendU16(zip, nameSize);
    AppendU16(zip, 0);                      // extra field size
    zip.append(DEDUP_FILES_ENTRY_NAME);
    zip.append(payload);

    // central directory entry (CentralDirEntry, 46 bytes)
    const uint32_t centralDirOffset = static_cast<uint32_t>(zip.size());
    AppendU32(zip, FUZZ_ZIP_CENTRAL_DIR_SIGNATURE);
    AppendU16(zip, FUZZ_ZIP_VERSION);       // version made by
    AppendU16(zip, FUZZ_ZIP_VERSION);       // version needed
    AppendU16(zip, 0);                      // flags
    AppendU16(zip, FUZZ_ZIP_METHOD_STORED);
    AppendU16(zip, FUZZ_ZIP_MODIFIED_TIME);
    AppendU16(zip, FUZZ_ZIP_MODIFIED_DATE);
    AppendU32(zip, crc);
    AppendU32(zip, entrySize);              // compressed size
    AppendU32(zip, entrySize);              // uncompressed size
    AppendU16(zip, nameSize);
    AppendU16(zip, 0);                      // extra field size
    AppendU16(zip, 0);                      // file comment size
    AppendU16(zip, 0);                      // disk number start
    AppendU16(zip, 0);                      // internal file attributes
    AppendU32(zip, 0);                      // external file attributes
    AppendU32(zip, 0);                      // relative offset of the local header
    zip.append(DEDUP_FILES_ENTRY_NAME);
    const uint32_t centralDirSize = static_cast<uint32_t>(zip.size() - centralDirOffset);

    // end of central directory record (EndDir, 22 bytes), trailing, no comment
    AppendU32(zip, FUZZ_ZIP_EOCD_SIGNATURE);
    AppendU16(zip, 0);                      // number of this disk
    AppendU16(zip, 0);                      // disk with the start of the central directory
    AppendU16(zip, 1);                      // entries on this disk
    AppendU16(zip, 1);                      // total entries
    AppendU32(zip, centralDirSize);
    AppendU32(zip, centralDirOffset);
    AppendU16(zip, 0);                      // comment length
    return zip;
}

void WriteFuzzDataToFile(const std::string& filePath, const std::string& content)
{
    std::ofstream ofs(filePath, std::ios::binary | std::ios::trunc);
    if (ofs.is_open()) {
        ofs << content;
        ofs.close();
    }
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, const size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    BundleParser parser;
    DedupSoInfoList dedupSoInfoList;

    // form 1: wrapped as the dedupfiles.json entry of a STORED zip
    const std::string payload = fdp.ConsumeRandomLengthString(DEDUP_PAYLOAD_MAX_LENGTH);
    WriteFuzzDataToFile(FUZZ_TEMP_FILE, BuildStoredDedupZip(payload));
    parser.ParseDedupFiles(FUZZ_TEMP_FILE, "fuzzBundle", dedupSoInfoList);

    // form 2: raw bytes as-is, covering the empty/corrupted/non-zip paths
    WriteFuzzDataToFile(FUZZ_TEMP_FILE, fdp.ConsumeRemainingBytesAsString());
    parser.ParseDedupFiles(FUZZ_TEMP_FILE, "fuzzBundle", dedupSoInfoList);
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
