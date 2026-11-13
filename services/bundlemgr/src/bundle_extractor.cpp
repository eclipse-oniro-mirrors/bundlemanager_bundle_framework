/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "bundle_extractor.h"

#include <set>
#include <sstream>

#include "app_log_wrapper.h"
#include "bundle_service_constants.h"
#include "mem_mgr_client.h"
#include "nlohmann/json.hpp"

namespace {
constexpr const char* AP_PATH = "ap/";

// Constants for inode calculation (in KB)
static constexpr uint8_t BLOCK_SIZE_KB = 4;  // 4KB per block
static constexpr uint16_t DIRECT_BLOCKS = 923;  // Direct blocks
static constexpr uint16_t SINGLE_INDIRECT_BLOCKS = 1018;  // Blocks in single indirect
static constexpr uint16_t SINGLE_INDIRECT_SIZE = SINGLE_INDIRECT_BLOCKS * BLOCK_SIZE_KB;  // 1018 * 4 KB
// Threshold 1: 923 * 4KB
static constexpr uint16_t THRESHOLD_1 = DIRECT_BLOCKS * BLOCK_SIZE_KB;  // 3692 KB
// Threshold 2: 923 * 4 + 2 * 1018 * 4 KB
static constexpr uint16_t THRESHOLD_2 = THRESHOLD_1 + 2 * SINGLE_INDIRECT_SIZE;  // 3692 + 8144 = 11836 KB
// Threshold 3: 923 * 4 + 2 * 1018 * 4 + 2 * 1018 * 1018 * 4 KB
static constexpr uint32_t DOUBLE_INDIRECT_SIZE = 2 * SINGLE_INDIRECT_BLOCKS * SINGLE_INDIRECT_BLOCKS * BLOCK_SIZE_KB;
static constexpr uint32_t THRESHOLD_3 = THRESHOLD_2 + DOUBLE_INDIRECT_SIZE;  // 11836 + 8290592 = 8302428 KB
// Base inode counts
static constexpr uint8_t BASE_INODES_SMALL = 1;      // < THRESHOLD_1
static constexpr uint8_t BASE_INODES_MEDIUM = 3;     // < THRESHOLD_2
static constexpr uint16_t BASE_INODES_HUGE = 2042;    // >= THRESHOLD_3 (1+2+2+2*1018+1)
}  // namespace

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_PROFILE_NAME = "config.json";
constexpr const char* MODULE_PROFILE_NAME = "module.json";
constexpr const char* BUNDLE_PACKFILE_NAME = "pack.info";
constexpr const char* DEDUP_FILES_NAME = "dedupfiles.json";
constexpr const char* DEDUP_REMOVED_SO_FILES_KEY = "removedSoFiles";
constexpr const char* DEDUP_ORIGINAL_PATH_KEY = "originalPathInHap";
constexpr const char* MERGE_ABC_PATH = "ets/modules.abc";
// The profile is decompressed into the memory and parsed by json, so the extracted size of the
// profile must be limited to a part of the available memory to avoid the OOM caused by a
// malicious package(zip bomb).
constexpr double MAX_AVAILABLE_MEMORY_RATIO = 0.9;
constexpr uint64_t KILOBYTE = 1024;
}
BundleExtractor::BundleExtractor(const std::string &source, bool parallel) : BaseExtractor(source, parallel)
{
    APP_LOGD("BundleExtractor is created");
}

BundleExtractor::~BundleExtractor()
{
    APP_LOGD("destroyed");
}

bool BundleExtractor::ExtractProfile(std::ostream &dest) const
{
    if (IsNewVersion()) {
        APP_LOGD("profile is module.json");
        return ExtractByName(MODULE_PROFILE_NAME, dest);
    }
    APP_LOGD("profile is config.json");
    return ExtractByName(BUNDLE_PROFILE_NAME, dest);
}

bool BundleExtractor::ExtractPackFile(std::ostream &dest) const
{
    APP_LOGD("start to parse pack.info");
    return ExtractByName(BUNDLE_PACKFILE_NAME, dest);
}

bool BundleExtractor::ExtractModuleProfile(std::ostream &dest) const
{
    if (IsNewVersion()) {
        APP_LOGD("profile is module.json");
        return ExtractByName(MODULE_PROFILE_NAME, dest);
    }
    APP_LOGW("profile is config.json");
    return false;
}

uint32_t BundleExtractor::GetProfileUncompressedSize() const
{
    const char *profileName = IsNewVersion() ? MODULE_PROFILE_NAME : BUNDLE_PROFILE_NAME;
    ZipEntry zipEntry;
    if (!zipFile_.GetEntry(profileName, zipEntry)) {
        APP_LOGE("profile %{public}s is not found", profileName);
        return 0;
    }
    return zipEntry.uncompressedSize;
}

uint32_t BundleExtractor::GetMaxProfileUncompressedSize()
{
    // the available memory obtained from memmgr is in unit of KB
    int32_t availableMemoryKb = 0;
    if ((Memory::MemMgrClient::GetInstance().GetAvailableMemory(availableMemoryKb) != ERR_OK) ||
        (availableMemoryKb <= 0)) {
        // the profile size is not limited when the available memory cannot be obtained
        APP_LOGW("get the available memory from memmgr failed");
        return 0;
    }

    return static_cast<uint32_t>(availableMemoryKb * MAX_AVAILABLE_MEMORY_RATIO);
}

bool BundleExtractor::IsProfileSizeAllowed() const
{
    // the max allowed size is in unit of KB
    auto maxProfileSizeKb = GetMaxProfileUncompressedSize();
    if (maxProfileSizeKb == 0) {
        // the check is skipped when the available memory cannot be obtained
        return true;
    }

    // the declared size in the zip header is in unit of byte, convert it to KB for the comparison
    auto profileUncompressedSizeKb = static_cast<uint32_t>((GetProfileUncompressedSize() + KILOBYTE - 1) / KILOBYTE);
    if (profileUncompressedSizeKb > maxProfileSizeKb) {
        APP_LOGE("profile uncompressed size(%{public}u KB) exceeds the max allowed size(%{public}u KB)",
            profileUncompressedSizeKb, maxProfileSizeKb);
        return false;
    }

    return true;
}

uint32_t BundleExtractor::GetDedupFilesUncompressedSize() const
{
    ZipEntry zipEntry;
    if (!zipFile_.GetEntry(DEDUP_FILES_NAME, zipEntry)) {
        APP_LOGE("dedupfiles.json is not found");
        return 0;
    }
    return zipEntry.uncompressedSize;
}

bool BundleExtractor::IsDedupFilesSizeAllowed(uint32_t maxSize) const
{
    // a HAP without dedupfiles.json keeps the normal install flow
    uint32_t dedupFilesSize = GetDedupFilesUncompressedSize();
    if (dedupFilesSize == 0) {
        return true;
    }
    if (dedupFilesSize > maxSize) {
        APP_LOGE("dedupfiles.json uncompressed size(%{public}u bytes) exceeds the max allowed size"
            "(%{public}u bytes)", dedupFilesSize, maxSize);
        return false;
    }

    return true;
}

bool BundleExtractor::IsDedupFilesDepthAllowed(const std::string &content)
{
    // reject before the DOM building (nlohmann keeps consuming); brackets in strings never count
    int32_t depth = 0;
    bool inString = false;
    bool escaped = false;
    for (const char ch : content) {
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                inString = false;
            }
            continue;
        }
        if (ch == '"') {
            inString = true;
        } else if (ch == '{' || ch == '[') {
            ++depth;
            if (depth >= MAX_DEDUP_FILES_DEPTH) {
                return false;
            }
        } else if (ch == '}' || ch == ']') {
            --depth;
        }
    }
    return true;
}

bool BundleExtractor::GetDedupSoAbiPrefixes(std::set<std::string> &abis) const
{
    abis.clear();
    // no manifest: not a dedup package, the abi derivation stays off
    if (!HasEntry(DEDUP_FILES_NAME)) {
        return false;
    }
    // loose probe: any failure only disables the derivation, ParseDedupFiles stays the gate
    if (GetDedupFilesUncompressedSize() > MAX_DEDUP_FILES_SIZE) {
        // WARN, not an install-grade ERROR: query paths must not error on the same manifest
        APP_LOGW("dedupfiles.json uncompressed size exceeds limit, skip abi derivation");
        return false;
    }
    std::stringstream dedupFilesStream;
    if (!ExtractByName(DEDUP_FILES_NAME, dedupFilesStream)) {
        APP_LOGW("extract dedupfiles.json failed, skip abi derivation");
        return false;
    }
    // re-check the real extracted size before the .str() copy: a lying header stays bounded
    uint64_t extractedSize = static_cast<uint64_t>(dedupFilesStream.tellp());
    if (extractedSize > MAX_DEDUP_FILES_SIZE) {
        APP_LOGW("dedupfiles.json extracted size exceeds limit, skip abi derivation");
        return false;
    }
    // loose: the depth scan only skips the derivation here
    if (!IsDedupFilesDepthAllowed(dedupFilesStream.str())) {
        APP_LOGW("dedupfiles.json nesting depth exceeds limit, skip abi derivation");
        return false;
    }
    nlohmann::json jsonBuf = nlohmann::json::parse(dedupFilesStream, nullptr, false, true);
    if (jsonBuf.is_discarded() || !jsonBuf.is_object() ||
        !jsonBuf.contains(DEDUP_REMOVED_SO_FILES_KEY) ||
        !jsonBuf[DEDUP_REMOVED_SO_FILES_KEY].is_array()) {
        APP_LOGW("invalid dedupfiles.json structure, skip abi derivation");
        return false;
    }
    const std::string libsPrefix = ServiceConstants::LIBS;
    for (const auto &item : jsonBuf[DEDUP_REMOVED_SO_FILES_KEY]) {
        // loose: malformed entries are left to the strict parser
        if (!item.is_object() || !item.contains(DEDUP_ORIGINAL_PATH_KEY) ||
            !item[DEDUP_ORIGINAL_PATH_KEY].is_string()) {
            continue;
        }
        const std::string originalPath = item[DEDUP_ORIGINAL_PATH_KEY].get<std::string>();
        // collect only the libs/<abi>/ prefixes; the strict parser rejects the rest
        if (originalPath.size() <= libsPrefix.size() ||
            originalPath.compare(0, libsPrefix.size(), libsPrefix) != 0) {
            continue;
        }
        const size_t abiEnd = originalPath.find(ServiceConstants::PATH_SEPARATOR, libsPrefix.size());
        if (abiEnd == std::string::npos || abiEnd == libsPrefix.size()) {
            continue;
        }
        abis.insert(originalPath.substr(libsPrefix.size(), abiEnd - libsPrefix.size()));
    }
    APP_LOGD("probe dedupfiles.json abi prefixes, size %{public}zu", abis.size());
    return !abis.empty();
}

void BundleExtractor::IsHapCompress(bool &isAbcCompressed) const
{
    ZipEntry zipEntry;
    if (!zipFile_.GetEntry(MERGE_ABC_PATH, zipEntry)) {
        APP_LOGE("GetEntry failed entryName: %{public}s", MERGE_ABC_PATH);
        return;
    }
    if (zipEntry.compressionMethod != 0) {
        isAbcCompressed = true;
    }
}

uint32_t BundleExtractor::CalculateRequiredInodes(uint64_t fileSizeKb)
{
    if (fileSizeKb < THRESHOLD_1) {
        // Case 1: fileSize < 923*4KB, inode count = 1
        return BASE_INODES_SMALL;
    } else if (fileSizeKb < THRESHOLD_2) {
        // Case 2: fileSize < 923*4+2*1018*4 KB, inode count = 1+2 = 3
        return BASE_INODES_MEDIUM;
    } else if (fileSizeKb < THRESHOLD_3) {
        // Case 3: fileSize < 923*4+2*1018*4+2*1018*1018*4 KB
        // inode count = 1+2+ceil((fileSize-923*4-2*1018*4)/(1018*4))
        uint64_t remainingSize = fileSizeKb - THRESHOLD_2;
        uint32_t additionalInodes = static_cast<uint32_t>((remainingSize + SINGLE_INDIRECT_SIZE - 1) /
            SINGLE_INDIRECT_SIZE);
        return BASE_INODES_MEDIUM + additionalInodes;
    } else {
        // Case 4: Other scenarios
        // inode count = 1+2+2+2*1018+1+ceil((fileSize-923*4-2*1018*4-2*1018*1018*4)/(1018*4))
        uint64_t remainingSize = fileSizeKb - THRESHOLD_3;
        uint32_t additionalInodes = static_cast<uint32_t>((remainingSize + SINGLE_INDIRECT_SIZE - 1) /
            SINGLE_INDIRECT_SIZE);
        return BASE_INODES_HUGE + additionalInodes;
    }
}

BundleParallelExtractor::BundleParallelExtractor(const std::string &source) : BundleExtractor(source, true)
{
    APP_LOGD("BundleParallelExtractor is created");
}

BundleParallelExtractor::~BundleParallelExtractor()
{
    APP_LOGD("BundleParallelExtractor is destroyed");
}

bool BundleParallelExtractor::ExtractByName(const std::string &fileName, std::ostream &dest) const
{
    if (!initial_) {
        APP_LOGE("extractor is not initial");
        return false;
    }
    if (!zipFile_.ExtractFileParallel(fileName, dest)) {
        APP_LOGE("extractor is not ExtractFile");
        return false;
    }
    return true;
}

uint32_t BundleExtractor::GetExtractedFileInodes(bool isCompressNativeLibrary, bool hasArkNativeFile,
    const std::vector<HnpPackage> &hnpPackages) const
{
    if (!initial_) {
        APP_LOGE("extractor is not initial");
        return 0;
    }

    uint32_t totalInodes = 0;

    const auto &entryMap = zipFile_.GetAllEntries();

    // Calculate inodes for each file that will be extracted
    for (const auto &entry : entryMap) {
        const std::string &fileName = entry.second.fileName;
        uint64_t uncompressedSize = entry.second.uncompressedSize;

        // Convert bytes to KB (round up)
        uint64_t fileSizeKb = (uncompressedSize + 1023) / 1024;

        bool shouldExtract = false;

        // 1. SO files: libs/{cpuAbi}/*.so - only if isCompressNativeLibrary
        if (fileName.find(ServiceConstants::LIBS) == 0) {
            shouldExtract = isCompressNativeLibrary;
        } else if (fileName.find(ServiceConstants::AN) == 0) {
            // 2. AN/AI files: an/{cpuAbi}/*.an and *.ai - only if hasArkNativeFile
            shouldExtract = hasArkNativeFile;
        } else if (fileName.find(AP_PATH) == 0) {
            // 3. AP files: ap/*.ap
            shouldExtract = true;
        } else if (fileName.find(ServiceConstants::RES_FILE_PATH) == 0) {
            // 4. Resource files: resources/resfile/* - always extract
            shouldExtract = true;
        } else if (fileName.find(ServiceConstants::HNPS) == 0) {
            // 5. HNP files: hnp/{cpuAbi}/* - only if HNP packages exist
            shouldExtract = !hnpPackages.empty();
        }

        if (shouldExtract) {
            // Calculate inodes for this individual file and add to total
            totalInodes += CalculateRequiredInodes(fileSizeKb);
        }
    }

    APP_LOGD("GetExtractedFileInodes: total inodes=%{public}u", totalInodes);
    return totalInodes;
}

}  // namespace AppExecFwk
}  // namespace OHOS
