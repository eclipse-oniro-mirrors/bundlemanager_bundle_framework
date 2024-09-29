/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_OPERATOR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_OPERATOR_H

#include <mutex>
#include <string>
#include <vector>

#include "aot/aot_args.h"
#include "appexecfwk_errors.h"
#include "bundle_extractor.h"
#include "code_sign_helper.h"
#include "installd/installd_constants.h"
#include "ipc/check_encryption_param.h"
#include "ipc/code_signature_param.h"
#include "ipc/extract_param.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
using EnforceMetadataProcessForApp = int32_t (*)(const std::unordered_map<std::string, std::string> &,
    uint32_t, bool &, const int32_t, const bool &);

class InstalldOperator {
public:
    /**
     * @brief Check whether a file exist.
     * @param path Indicates the file path to be checked.
     * @return Returns true if the file exist; returns false otherwise.
     */
    static bool IsExistFile(const std::string &path);
    /**
     * @brief Check whether an AP file exists in the current directory of the file.
     * @param path Indicates the file path to be checked.
     * @return Returns true if the file exist; returns false otherwise.
     */
    static bool IsExistApFile(const std::string &path);
    /**
     * @brief Check whether a directory exist.
     * @param path Indicates the directory path to be checked.
     * @return Returns true if the directory exist; returns false otherwise.
     */
    static bool IsExistDir(const std::string &path);
    /**
     * @brief Check whether a directory is empty.
     * @param dir Indicates the directory path to be checked.
     * @return Returns true if the directory is empty; returns false otherwise.
     */
    static bool IsDirEmpty(const std::string &dir);
    /**
     * @brief Make a new directory including the parent path if not exist.
     * @param path Indicates the directory path to be checked.
     * @param isReadByOthers Indicates the directory whether read by other users.
     * @return Returns true if the directory make successfully; returns false otherwise.
     */
    static bool MkRecursiveDir(const std::string &path, bool isReadByOthers);
    /**
     * @brief Delete a directory.
     * @param path Indicates the directory path to be deleted.
     * @return Returns true if the directory deleted successfully; returns false otherwise.
     */
    static bool DeleteDir(const std::string &path);
    /**
     * @brief Extract the files of a compressed package to a specific directory.
     * @param srcModulePath Indicates the package file path.
     * @param targetSoPath so files decompression path.
     * @param cpuAbi cpuAbi.
     * @return Returns true if the package extracted successfully; returns false otherwise.
     */
    static bool ExtractFiles(const std::string &sourcePath, const std::string &targetSoPath,
        const std::string &cpuAbi);

    static bool IsNativeSo(const std::string &entryName, const std::string &cpuAbi);

    static bool ExtractFiles(const ExtractParam &extractParam);
    static bool ExtractFiles(const std::string hnpPackageInfo, const ExtractParam &extractParam);
    static void ExtractTargetFile(
        const BundleExtractor &extractor,
        const std::string &entryName,
        const std::string &targetPath,
        const std::string &cpuAbi,
        const ExtractFileType &extractFileType = ExtractFileType::SO);
    static void ExtractTargetHnpFile(
        const BundleExtractor &extractor,
        const std::string &entryName,
        const std::string &targetPath,
        const ExtractFileType &extractFileType = ExtractFileType::SO);
    static bool ProcessBundleInstallNative(
        const std::string &userId,
        const std::string &hnpRootPath,
        const std::string &hapPath,
        const std::string &cpuAbi,
        const std::string &packageName);
    static bool ProcessBundleUnInstallNative(const std::string &userId, const std::string &bundleName);

    static bool DeterminePrefix(const ExtractFileType &extractFileType, const std::string &cpuAbi,
        std::string &prefix);

    static bool DetermineSuffix(const ExtractFileType &extractFileType, std::vector<std::string> &suffixes);

    static bool IsNativeFile(
        const std::string &entryName, const ExtractParam &extractParam);

    /**
     * @brief Rename a directory from old path to new path.
     * @param oldPath Indicates the old path name.
     * @param newPath Indicates the new path name.
     * @return Returns true if the directory renamed successfully; returns false otherwise.
     */
    static bool RenameDir(const std::string &oldPath, const std::string &newPath);
    /**
     * @brief Change the owner and group ID of a file or directory.
     * @param filePath Indicates the file or directory path.
     * @param uid Indicates the uid.
     * @param uid Indicates the gid.
     * @return Returns true if changed successfully; returns false otherwise.
     */
    static bool ChangeFileAttr(const std::string &filePath, const int uid, const int gid);
    /**
     * @brief Rename a file from old path to new path.
     * @param oldPath Indicates the old path name.
     * @param newPath Indicates the new path name.
     * @return Returns true if the file renamed successfully; returns false otherwise.
     */
    static bool RenameFile(const std::string &oldPath, const std::string &newPath);
    /**
     * @brief Check whether a path is valid under a root path.
     * @param rootDir Indicates the root path name.
     * @param path Indicates the path to be checked.
     * @return Returns true if the path is valid successfully; returns false otherwise.
     */
    static bool IsValidPath(const std::string &rootDir, const std::string &path);
    /**
     * @brief Check whether a path is valid code path.
     * @param codePath Indicates the path to be checked.
     * @return Returns true if the file renamed successfully; returns false otherwise.
     */
    static bool IsValidCodePath(const std::string &codePath);
    /**
     * @brief Get the parent directory path of a file.
     * @param codePath Indicates the file path.
     * @return Returns the parent directory if get successfully; returns empty string otherwise.
     */
    static std::string GetPathDir(const std::string &path);
    /**
     * @brief Delete files in a directory.
     * @param path Indicates the directory path of the files to be deleted.
     * @return Returns true if the files deleted successfully; returns false otherwise.
     */
    static bool DeleteFiles(const std::string &dataPath);
    /**
     * @brief Delete files in a directory except the directories to be kept.
     * @param dataPath Indicates the directory path of the files to be deleted.
     * @param dirsToKeep Indicates the directories to be kept.
     * @return Returns true if the files deleted successfully; returns false otherwise
     */
    static bool DeleteFilesExceptDirs(const std::string &dataPath, const std::vector<std::string> &dirsToKeep);
    /**
     * @brief Make a directory and change the owner and group ID of it.
     * @param path Indicates the directory path to be made.
     * @param isReadByOthers Indicates the directory whether read by other users.
     * @param uid Indicates the uid.
     * @param uid Indicates the gid.
     * @return Returns true if directory made successfully; returns false otherwise.
     */
    static bool MkOwnerDir(const std::string &path, bool isReadByOthers, const int uid, const int gid);
    /**
     * @brief Make a directory and change the owner and group ID of it.
     * @param path Indicates the directory path to be made.
     * @param mode Indicates the directory mode.
     * @param uid Indicates the uid.
     * @param uid Indicates the gid.
     * @return Returns true if directory made successfully; returns false otherwise.
     */
    static bool MkOwnerDir(const std::string &path,  int mode, const int uid, const int gid);
    /**
     * @brief Get disk usage for dir.
     * @param dir Indicates the directory.
     * @param size Indicates the disk size.
     * @return Returns true if successfully; returns false otherwise.
     */
    static int64_t GetDiskUsage(const std::string &dir, bool isRealPath = false);
    /**
     * @brief Traverse all cache directories.
     * @param currentPath Indicates the current path.
     * @param cacheDirs Indicates the cache directories.
     * @return Returns true if successfully; returns false otherwise.
     */
    static void TraverseCacheDirectory(const std::string &currentPath, std::vector<std::string> &cacheDirs);
    /**
     * @brief Get disk usage from path.
     * @param path Indicates the current path.
     * @return Returns disk size.
     */
    static int64_t GetDiskUsageFromPath(const std::vector<std::string> &path);

    static bool InitialiseQuotaMounts();

    static int64_t GetDiskUsageFromQuota(const int32_t uid);

    static bool ScanDir(
        const std::string &dirPath, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths);

    static bool ScanSoFiles(const std::string &newSoPath, const std::string &originPath,
        const std::string &currentPath, std::vector<std::string> &paths);

    static bool CopyFile(const std::string &sourceFile, const std::string &destinationFile);

    static bool CopyFileFast(const std::string &sourcePath, const std::string &destPath);

    static bool ChangeDirOwnerRecursively(const std::string &path, const int uid, const int gid);

    static bool IsDiffFiles(const std::string &entryName,
        const std::string &targetPath, const std::string &cpuAbi);

    static bool ExtractDiffFiles(const std::string &filePath, const std::string &targetPath,
        const std::string &cpuAbi);

    static bool ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
        const std::string &newSoPath, int32_t uid);

    static bool ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &fileVec);

    static bool CopyFiles(const std::string &sourceDir, const std::string &destinationDir);

    static bool GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
        std::vector<std::string> &fileNames);

    static bool GetAtomicServiceBundleDataDir(const std::string &bundleName,
        const int32_t userId, std::vector<std::string> &allPathNames);

#if defined(CODE_SIGNATURE_ENABLE)
    static bool PrepareEntryMap(const CodeSignatureParam &codeSignatureParam,
        const std::vector<std::string> &soEntryFiles, Security::CodeSign::EntryMap &entryMap);
    static ErrCode PerformCodeSignatureCheck(const CodeSignatureParam &codeSignatureParam,
        const Security::CodeSign::EntryMap &entryMap);
#endif

    static bool VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam);

#if defined(CODE_ENCRYPTION_ENABLE)
    static bool EnforceEncryption(std::unordered_map<std::string, std::string> &entryMap, int32_t bundleId,
        bool &isEncryption, InstallBundleType installBundleType, bool isCompressNativeLibrary);
#endif

    static bool CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption);

    static bool CheckHapEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption);

    static bool MoveFiles(const std::string &srcDir, const std::string &desDir, bool isDesDirNeedCreated = false);

    static bool MoveFileOrDir(const std::string &srcPath, const std::string &destPath, mode_t mode);

    static bool MoveFile(const std::string &srcPath, const std::string &destPath);

    static bool ExtractDriverSoFiles(const std::string &srcPath,
        const std::unordered_multimap<std::string, std::string> &dirMap);

    static bool CopyDriverSoFiles(const BundleExtractor &extractor, const std::string &originalDir,
        const std::string &destinedDir);

#if defined(CODE_ENCRYPTION_ENABLE)
    static ErrCode ExtractSoFilesToTmpHapPath(const std::string &hapPath, const std::string &cpuAbi,
        const std::string &tmpSoPath, int32_t uid);

    static ErrCode ExtractSoFilesToTmpSoPath(const std::string &hapPath, const std::string &realSoFilesPath,
        const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid);

    static ErrCode DecryptSoFile(const std::string &hapPath, const std::string &tmpHapPath, int32_t uid,
        uint32_t fileSize, uint32_t offset);

    static ErrCode RemoveEncryptedKey(int32_t uid, const std::vector<std::string> &soList);

    static int32_t CallIoctl(int32_t flag, int32_t associatedFlag, int32_t uid, int32_t &fd);
#endif

    static bool GenerateKeyIdAndSetPolicy(int32_t uid, const std::string &bundleName,
        const int32_t userId, std::string &keyId);

    static bool DeleteKeyId(const std::string &keyId);

private:
    static bool ObtainNativeSoFile(const BundleExtractor &extractor, const std::string &cpuAbi,
        std::vector<std::string> &soEntryFiles);

    static bool ProcessApplyDiffPatchPath(const std::string &oldSoPath, const std::string &diffFilePath,
        const std::string &newSoPath, std::vector<std::string> &oldSoFileNames,
        std::vector<std::string> &diffFileNames);
    static bool ExtractResourceFiles(const ExtractParam &extractParam, const BundleExtractor &extractor);
    static bool CheckPathIsSame(const std::string &path, int32_t mode, const int32_t uid, const int32_t gid,
        bool &isPathExist);
#if defined(CODE_ENCRYPTION_ENABLE)
    static std::mutex encryptionMutex_;
    static void *encryptionHandle_;
    static EnforceMetadataProcessForApp enforceMetadataProcessForApp_;
    static bool OpenEncryptionHandle();
#endif
    static void FsyncResFile(const std::string &path, const ExtractFileType &extractFileType);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_OPERATOR_H
