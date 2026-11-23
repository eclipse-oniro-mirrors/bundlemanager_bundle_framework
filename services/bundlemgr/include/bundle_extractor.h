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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_EXTRACTOR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_EXTRACTOR_H

#include <istream>
#include <set>
#include <vector>

#include "application_info.h"
#include "base_extractor.h"

namespace OHOS {
namespace AppExecFwk {

class BundleExtractor : public BaseExtractor {
public:
    explicit BundleExtractor(const std::string &source, bool parallel = false);
    virtual ~BundleExtractor() override;
    /**
     * @brief Extract the config.json of a hap to dest stream.
     * @param dest Indicates the obtained std::ostream object.
     * @return Returns true if the Profile is successfully extracted; returns false otherwise.
     */
    bool ExtractProfile(std::ostream &dest) const;
    /**
     * @brief Extract the pack.info of a hap to dest stream.
     * @param dest Indicates the obtained std::ostream object.
     * @return Returns true if the file is successfully extracted; returns false otherwise.
     */
    bool ExtractPackFile(std::ostream &dest) const;
    /**
     * @brief Extract the module.json of a hap to dest stream.
     * @param dest Indicates the obtained std::ostream object.
     * @return Returns true if the Profile is successfully extracted; returns false otherwise.
     */
    bool ExtractModuleProfile(std::ostream &dest) const;
    /**
     * @brief Check whether the declared size of the profile is allowed to be extracted, so that
     *        an oversized profile will not exhaust the memory.
     * @return Returns true if the profile size is within the limit; returns false otherwise.
     */
    bool IsProfileSizeAllowed() const;

    /**
     * @brief Check whether the declared size of dedupfiles.json is allowed to be extracted, so
     *        that an oversized dedup manifest will not exhaust the memory during install.
     * @param maxSize The max allowed uncompressed size in bytes.
     * @return Returns true if the dedup files size is within the limit; returns false otherwise.
     */
    bool IsDedupFilesSizeAllowed(uint32_t maxSize) const;

    /**
     * @brief Check whether the bracket nesting depth of the extracted dedupfiles.json
     *        payload stays within the bound; brackets inside quoted strings never
     *        count.
     * @param content Indicates the extracted dedupfiles.json payload.
     * @return Returns true if the depth stays within the limit; false otherwise.
     */
    static bool IsDedupFilesDepthAllowed(const std::string &content);
    /**
     * @brief Streamed variant for an extracted payload stream: scans the stream
     *        without materializing a full string copy of a size-capped manifest
     *        (a .str() copy would double the transient memory), and always
     *        leaves the stream rewound to the beginning for the DOM parse
     *        reading the same stream right after.
     * @param content Indicates the extracted dedupfiles.json payload stream.
     * @return Returns true if the depth stays within the limit; false otherwise.
     */
    static bool IsDedupFilesDepthAllowed(std::istream &content);

    /**
     * @brief Loosely probe the ABI directory prefixes (libs/<abi>/) declared by the
     *        originalPathInHap entries of dedupfiles.json, so the profile parsing can
     *        derive the target so path for a fully deduplicated hap whose libs/<abi>/
     *        dir entries are also stripped.
     * @param abis Indicates the collected ABI directory names.
     * @return Returns true if at least one prefix was collected; false otherwise —
     *         the derivation stays off, ParseDedupFiles keeps the fail-closed gate.
     */
    bool GetDedupSoAbiPrefixes(std::set<std::string> &abis) const;

    void IsHapCompress(bool &isAbcCompressed) const;

    /**
     * @brief Calculate the required inode count for a file based on its size.
     * @param fileSizeKb File size in KB.
     * @return Returns the required inode count.
     */
    static uint32_t CalculateRequiredInodes(uint64_t fileSizeKb);

    /**
     * @brief Calculate the total inode count for files that will be extracted from the HAP.
     * @param isCompressNativeLibrary Whether native libs are compressed.
     * @param hasArkNativeFile Whether Ark Native files exist.
     * @param hnpPackages HNP packages info.
     * @return Returns total inode count if successful; returns 0 otherwise.
     */
    uint32_t GetExtractedFileInodes(bool isCompressNativeLibrary, bool hasArkNativeFile,
        const std::vector<HnpPackage> &hnpPackages) const;

private:
    /**
     * @brief Get the declared uncompressed size of the profile(module.json/config.json) in the hap.
     * @return Returns the declared uncompressed size; returns 0 if the profile is not found.
     */
    uint32_t GetProfileUncompressedSize() const;

    /**
     * @brief Get the declared uncompressed size of dedupfiles.json in the hap.
     * @return Returns the declared size; returns 0 if the entry is not found.
     */
    uint32_t GetDedupFilesUncompressedSize() const;

    /**
     * @brief Get the max allowed uncompressed size of the profile according to the available memory.
     * @return Returns the max allowed size in KB, which is a part of the available memory;
     *         returns 0 if the available memory cannot be obtained.
     */
    static uint32_t GetMaxProfileUncompressedSize();
};

class BundleParallelExtractor : public BundleExtractor {
public:
    explicit BundleParallelExtractor(const std::string &source);
    virtual ~BundleParallelExtractor() override;
    virtual bool ExtractByName(const std::string &fileName, std::ostream &dest,
        size_t maxUncompressedSize = 0) const override;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_EXTRACTOR_H
