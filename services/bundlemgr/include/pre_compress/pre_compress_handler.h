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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_COMPRESS_PRE_COMPRESS_HANDLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_COMPRESS_PRE_COMPRESS_HANDLER_H

#include <string>
#include <unordered_map>
#include <vector>

#include "appexecfwk_errors.h"

namespace OHOS {
namespace AppExecFwk {
class InnerBundleInfo;

class PreCompressHandler final {
public:
    /**
     * @brief Whether a path names a compressed preinstall archive, that is a .hap or
     *        .hsp with the archive suffix appended, e.g. entry.hap.zst.
     */
    static bool IsCompressedArchive(const std::string &path);

    /**
     * @brief Collect the compressed archives directly under a preinstall directory.
     * @param currentBundlePath Indicates the preinstall directory to scan.
     * @param archiveList Indicates the archives found, appended.
     * @return Returns ERR_OK on success; returns error code if the dir cannot be opened or holds a plain .hap/.hsp.
     */
    static ErrCode GetCompressedArchivesFromBundlePath(
        const std::string &currentBundlePath, std::vector<std::string> &archiveList);

    /**
     * @brief Turn compressed preload paths into plain hap paths, expanding every
     *        archive into a temp dir.
     * @param inPaths Indicates the preload directory and/or package paths.
     * @param outPaths Indicates the resulting hap paths.
     * @param toDeletePaths The created temp dir is appended, for the caller to clean up.
     * @param sourceMap Maps each decompressed path back to its original archive path.
     * @return Returns ERR_OK if every archive was expanded; returns error code otherwise.
     */
    static ErrCode PrepareCompressedPaths(const std::vector<std::string> &inPaths,
        std::vector<std::string> &outPaths, std::vector<std::string> &toDeletePaths,
        std::unordered_map<std::string, std::string> &sourceMap);

    /**
     * @brief Turn a preinstall scan path into plain hap paths ready for parsing,
     *        expanding any compressed archive it holds into a temp dir.
     * @param scanPath Indicates a preinstall directory or a single package path.
     * @param isCompressed Whether the configuration marks scanPath as compressed.
     * @param realPaths Indicates the resulting hap paths, decompressed ones included.
     * @param tempDirs The created temp dirs are appended, the caller must delete them
     *        once it is done with realPaths.
     * @param sourceMap Maps each decompressed path back to the archive under the image.
     * @return Returns true if at least one hap path was produced.
     */
    static bool PrepareScanPaths(const std::string &scanPath, bool isCompressed,
        std::vector<std::string> &realPaths, std::vector<std::string> &tempDirs,
        std::unordered_map<std::string, std::string> &sourceMap);

    /**
     * @brief Re-key parsed infos from the temp paths the archives were expanded into
     *        back onto the archives under the image.
     * @param sourceMap Maps each decompressed path back to its original archive path.
     * @param infos Indicates the parsed infos to re-key, in place.
     */
    static void RekeyInfosToSource(const std::unordered_map<std::string, std::string> &sourceMap,
        std::unordered_map<std::string, InnerBundleInfo> &infos);

    /**
     * @brief Copy the ag_config.json beside the archives into the temp dir they were expanded into.
     * @param sourceMap Maps each decompressed path back to its original archive path.
     * @param stagedPath Indicates the staged copy, left empty if the preload dir has no ag_config.json.
     * @return Returns ERR_OK if the file is staged or absent; returns error code if the copy failed.
     */
    static ErrCode StageAgConfigFile(const std::unordered_map<std::string, std::string> &sourceMap,
        std::string &stagedPath);
};

class ScopedDecompressedHap final {
public:
    explicit ScopedDecompressedHap(const std::string &path);
    ~ScopedDecompressedHap();

    ScopedDecompressedHap(const ScopedDecompressedHap &) = delete;
    ScopedDecompressedHap &operator=(const ScopedDecompressedHap &) = delete;
    ScopedDecompressedHap(ScopedDecompressedHap &&) = delete;
    ScopedDecompressedHap &operator=(ScopedDecompressedHap &&) = delete;

    /**
     * @brief Whether the hap is usable. False only when decompression failed.
     */
    bool IsValid() const
    {
        return valid_;
    }
    /**
     * @brief The plain hap path to operate on. Empty when IsValid() is false.
     */
    const std::string &GetHapPath() const
    {
        return hapPath_;
    }

private:
    bool valid_ = false;
    std::string hapPath_;
    std::vector<std::string> toDeletePaths_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_COMPRESS_PRE_COMPRESS_HANDLER_H
