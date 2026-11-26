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

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_PROFILE_NAME = "config.json";
constexpr const char* MODULE_PROFILE_NAME = "module.json";
constexpr const char* BUNDLE_PACKFILE_NAME = "pack.info";
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
    if (!zipFile_.GetEntry(ServiceConstants::DEDUP_FILES_NAME, zipEntry)) {
        // a HAP without dedupfiles.json keeps the normal flow and the loose
        // probe lands here on plain HAPs too: stay quiet
        APP_LOGD("dedupfiles.json is not found");
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

bool BundleExtractor::IsDedupFilesDepthAllowed(std::istream &content)
{
    // reject before the DOM building (nlohmann keeps consuming); brackets in
    // strings never count; stream through the payload so a size-capped 16MB
    // manifest is never doubled into a transient .str() copy. The scan
    // consumes the get position, so rewind for the DOM parse reading the same
    // stream right after
    int32_t depth = 0;
    bool inString = false;
    bool escaped = false;
    char ch = 0;
    while (content.get(ch)) {
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
            if (depth >= ServiceConstants::MAX_DEDUP_FILES_DEPTH) {
                content.clear();
                content.seekg(0, std::ios::beg);
                return false;
            }
        } else if (ch == '}' || ch == ']') {
            --depth;
        }
    }
    content.clear();
    content.seekg(0, std::ios::beg);
    return true;
}

bool BundleExtractor::IsDedupFilesDepthAllowed(const std::string &content)
{
    // the string form feeds the streamed state machine; kept for the direct
    // unit-level callers of the depth scan
    std::istringstream stream(content);
    return IsDedupFilesDepthAllowed(stream);
}

bool BundleExtractor::GetDedupSoAbiPrefixes(std::set<std::string> &abis) const
{
    abis.clear();
    // no manifest: not a dedup package, the abi derivation stays off
    if (!HasEntry(ServiceConstants::DEDUP_FILES_NAME)) {
        return false;
    }
    // loose probe: any failure only disables the derivation, ParseDedupFiles stays the gate
    if (GetDedupFilesUncompressedSize() > ServiceConstants::MAX_DEDUP_FILES_SIZE) {
        // WARN, not an install-grade ERROR: query paths must not error on the same manifest
        APP_LOGW("dedupfiles.json uncompressed size exceeds limit, skip abi derivation");
        return false;
    }
    std::stringstream dedupFilesStream;
    if (!ExtractByName(ServiceConstants::DEDUP_FILES_NAME, dedupFilesStream,
        ServiceConstants::MAX_DEDUP_FILES_SIZE)) {
        APP_LOGW("extract dedupfiles.json failed, skip abi derivation");
        return false;
    }
    // re-check the real extracted size before the scan and DOM: a lying header stays bounded
    uint64_t extractedSize = static_cast<uint64_t>(dedupFilesStream.tellp());
    if (extractedSize > ServiceConstants::MAX_DEDUP_FILES_SIZE) {
        APP_LOGW("dedupfiles.json extracted size exceeds limit, skip abi derivation");
        return false;
    }
    // loose: the depth scan only skips the derivation here
    if (!IsDedupFilesDepthAllowed(dedupFilesStream)) {
        APP_LOGW("dedupfiles.json nesting depth exceeds limit, skip abi derivation");
        return false;
    }
    nlohmann::json jsonBuf = nlohmann::json::parse(dedupFilesStream, nullptr, false, true);
    if (jsonBuf.is_discarded() || !jsonBuf.is_object() ||
        !jsonBuf.contains(ServiceConstants::DEDUP_REMOVED_SO_FILES_KEY) ||
        !jsonBuf[ServiceConstants::DEDUP_REMOVED_SO_FILES_KEY].is_array()) {
        APP_LOGW("invalid dedupfiles.json structure, skip abi derivation");
        return false;
    }
    const std::string libsPrefix = ServiceConstants::LIBS;
    for (const auto &item : jsonBuf[ServiceConstants::DEDUP_REMOVED_SO_FILES_KEY]) {
        // loose: malformed entries are left to the strict parser
        if (!item.is_object() || !item.contains(ServiceConstants::DEDUP_ORIGINAL_PATH_KEY) ||
            !item[ServiceConstants::DEDUP_ORIGINAL_PATH_KEY].is_string()) {
            continue;
        }
        const std::string originalPath = item[ServiceConstants::DEDUP_ORIGINAL_PATH_KEY].get<std::string>();
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

BundleParallelExtractor::BundleParallelExtractor(const std::string &source) : BundleExtractor(source, true)
{
    APP_LOGD("BundleParallelExtractor is created");
}

BundleParallelExtractor::~BundleParallelExtractor()
{
    APP_LOGD("BundleParallelExtractor is destroyed");
}

bool BundleParallelExtractor::ExtractByName(const std::string &fileName, std::ostream &dest,
    size_t maxUncompressedSize) const
{
    if (!initial_) {
        APP_LOGE("extractor is not initial");
        return false;
    }
    if (!zipFile_.ExtractFileParallel(fileName, dest, maxUncompressedSize)) {
        APP_LOGE("extractor is not ExtractFile");
        return false;
    }
    return true;
}

}  // namespace AppExecFwk
}  // namespace OHOS
