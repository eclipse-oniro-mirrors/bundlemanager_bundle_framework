/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include <openssl/sha.h>
#include <mutex>
#include <string>
#include <vector>
#include <sys/quota.h>

#include "aot/aot_args.h"
#include "appexecfwk_errors.h"
#include "bundle_extractor.h"
#include "code_sign_helper.h"
#include "installd/installd_constants.h"
#include "interfaces/hap_verify.h"
#include "ipc/check_encryption_param.h"
#include "ipc/code_signature_param.h"
#include "ipc/encryption_param.h"
#include "ipc/extract_param.h"
#include "ipc/install_hnp_param.h"
#include "ipc/skills_package_param.h"
#include "nocopyable.h"
#include "skills_installer/skills_package_info.h"

namespace OHOS {
namespace AppExecFwk {
using EnforceMetadataProcessForApp = int32_t (*)(const std::unordered_map<std::string, std::string> &,
    const CodeCryptoHapInfo &, bool &);

struct SessionProvisionInfo {
    std::string bundleName;
    std::string apl;
    int32_t distributionType = 0;
    int32_t provisionType = 0;
    bool isEnterpriseResigned = false;
    std::string appIdentifier;
    uint32_t profileBlockLength = 0;
    std::shared_ptr<unsigned char[]> profileBlock;
};

class InstalldOperator {
public:
    /**
     * @brief Check link file and unlink.
     * @param path Indicates the file path to be checked.
     * @return Returns true if the file is link and unlink succeed; returns false otherwise.
     */
    static bool CheckAndDeleteLinkFile(const std::string &path);
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

    static bool DeleteDirFast(const std::string &path);

    static bool DeleteDirFlexible(const std::string &path, const bool async);

    static bool DeleteUninstallTmpDir(const std::string &path);
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
    static bool ExtractFiles(const std::map<std::string, std::string> &hnpPackageMap,
        const ExtractParam &extractParam);
    static bool ExtractTargetFile(
        const BundleExtractor &extractor,
        const std::string &entryName,
        const ExtractParam &param);
    static void ExtractTargetHnpFile(
        const BundleExtractor &extractor,
        const std::string &entryName,
        const std::string &targetPath,
        const ExtractFileType &extractFileType = ExtractFileType::SO);
    static bool ProcessBundleInstallNative(const InstallHnpParam &installHnpParam);
    static bool ProcessBundleUnInstallNative(const std::string &userId, const std::string &bundleName);

    /**
     * @brief Extract skills package with validation.
     * @param param Contains bundleName, moduleName, hspPath and skillNameList.
     * @param skillInfoList Output parameter containing skill extraction results with description.
     * @return Returns ERR_OK if extracted successfully; returns error code otherwise.
     */
    static ErrCode ExtractSkillsPackage(const SkillsPackageParam &param,
        std::vector<SkillsPackageInfo> &skillInfoList);

    /**
     * @brief Parse SKILL.md to extract name and description.
     * @param skillMdPath Path to SKILL.md file.
     * @param name Output parameter for skill name.
     * @param description Output parameter for skill description.
     * @return Returns ERR_OK if parsed successfully; returns error code otherwise.
     */
    static ErrCode ParseSkillMd(const std::string &skillMdPath,
        std::string &name, std::string &description);

    /**
     * @brief Extract a single skill folder from HSP file.
     * @param extractor Reference to initialized BundleExtractor.
     * @param skillName Skill name.
     * @param targetPath Target extraction path.
     * @return Returns true if extraction successful; returns false otherwise.
     */
    static bool ExtractSkillFromHsp(
        const BundleExtractor &extractor,
        const std::string &skillName,
        const std::string &targetPath);

    /**
     * @brief Validate skill name by parsing SKILL.md.
     * @param skillName Expected skill name.
     * @param extractedPath Path to extracted SKILL.md file.
     * @return Returns true if validation passed; returns false otherwise.
     */
    static bool ValidateSkillName(
        const std::string &skillName,
        const std::string &extractedPath);

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
     * @param timeoutMs Indicates the timeout time.
     * @return Returns disk size.
     */
    static int64_t GetDiskUsageFromPath(const std::vector<std::string> &path, int64_t timeoutMs = -1);

    static bool InitialiseQuotaMounts();

    static int64_t GetDiskUsageFromQuota(const int32_t uid);

    static int64_t GetBundleInodeCount(int32_t uid);

    static bool ScanDir(
        const std::string &dirPath, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths);

    static bool ScanSoFiles(const std::string &newSoPath, const std::string &originPath,
        const std::string &currentPath, std::vector<std::string> &paths);

    static bool CopyFile(const std::string &sourceFile, const std::string &destinationFile);

    static bool CopyFileFast(const std::string &sourcePath, const std::string &destPath);

    static bool ChangeDirOwnerRecursively(const std::string &path, const int uid, const int gid);

    static bool ChangeDirModeRecursively(const std::string &path, mode_t fileMode, mode_t dirMode);

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

    static bool EndsWith(const std::string &sourceString, const std::string &targetSuffix);

#if defined(CODE_SIGNATURE_ENABLE)
    static bool PrepareEntryMap(const CodeSignatureParam &codeSignatureParam,
        const std::vector<std::string> &soEntryFiles, Security::CodeSign::EntryMap &entryMap);
    static ErrCode PerformCodeSignatureCheck(const CodeSignatureParam &codeSignatureParam,
        const Security::CodeSign::EntryMap &entryMap);
#endif

    static ErrCode VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam);

#if defined(CODE_ENCRYPTION_ENABLE)
    static ErrCode EnforceEncryption(std::unordered_map<std::string, std::string> &entryMap,
        const CodeCryptoHapInfo &hapInfo, bool &isEncryption);
#endif

    static ErrCode CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption);

    static ErrCode CheckHapEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption);

    static bool MoveFiles(const std::string &srcDir, const std::string &desDir, bool isDesDirNeedCreated = false);

    static bool MoveFileOrDir(const std::string &srcPath, const std::string &destPath, mode_t mode);

    static bool MoveFile(const std::string &srcPath, const std::string &destPath);

    static bool ExtractDriverSoFiles(const std::string &srcPath,
        const std::unordered_multimap<std::string, std::string> &dirMap);

    static bool CopyDriverSoFiles(const std::string &originalDir, const std::string &destinedDir);

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
    static int32_t MigrateData(const std::vector<std::string> &sourcePaths, const std::string &destinationPath);

    static bool GenerateKeyIdAndSetPolicy(const EncryptionParam &encryptionParam, std::string &keyId);

    static bool DeleteKeyId(const EncryptionParam &encryptionParam);

    /**
     * @brief Add file Delete dfx
     * @param path Indicates the directory path to add dfx.
     * @return
     */
    static void AddDeleteDfx(const std::string &path);

   /**
     * @brief Rmv file Delete dfx
     * @param path Indicates the directory path to add dfx.
     * @return
     */
    static void RmvDeleteDfx(const std::string &path);

    static bool ClearDir(const std::string &dir);

    static bool RestoreconPath(const std::string &path);

    static ErrCode SetBinFileLabel(const std::string &binFilePath);

    static bool CheckElfFile(const std::string &filePath);

    static std::string Sha256File(const std::string& filePath);
 
    static ErrCode HashSoFile(const std::string& soPath,
        uint32_t catchSoNum,
        uint64_t catchSoMaxSize,
        std::vector<std::string> &soName,
        std::vector<std::string> &soHash);

    static bool WriteCertToFile(const std::string &certFilePath, const std::string &certContent);

    static bool IsFileNameValid(const std::string &fileName);

    static bool ResetBmsDBSecurity();

    /**
     * @brief Copy directory Recursively from source dir to destination dir.
     * @param sourceDir Indicates the source dir.
     * @param destinationDir Indicates the destination dir.
     * @return Returns true if successfully; returns false otherwise.
     */
    static bool CopyDir(const std::string &sourceDir, const std::string &destinationDir);

    static bool FsyncFile(const std::string &path);

    static bool FsyncNpapiPluginFile(const std::string &path);

    static ErrCode DeleteCertAndRemoveKey(const std::string &path);

    static bool IsValidBundleName(const std::string &bundleName);

    static bool IsValidUserId(const int32_t userId);

    static bool IsValidUid(const int32_t uid);

    static bool IsValidAppIndex(const int32_t appIndex);

    static bool IsValidApl(const std::string &apl);

    static bool IsValidPathByBundleDirScene(const BundleDirScene &scene, const std::string &path);

    static bool IsValidAppIdentifier(const std::string &appIdentifier);

    static bool IsValidUuid(const std::string &uuid);

    static bool ObtainSignInfoForPlugin(
        const std::string &filePath, std::string &appIdentifier, std::string &pluginId);

    /**
     * @brief Recursively find largest files/directories up to 6 levels, then drill down to largest file.
     * @param dirPaths Indicates the vector of directory paths to scan.
     * @param timeout Indicates the maximum scan time in seconds.
     *                  If <= 0, use 3 seconds. If > 180, use 180 seconds (max 3 minutes).
     * @param resultPathsWithSize Output parameter containing vector of (path, size) pairs for all found items
     *                            during 6-level recursion, plus the final largest file path from deep drilling.
     * @return Returns true if successfully; returns false otherwise.
     */
    static bool GetLargestFilesRecursive(const std::vector<std::string> &dirPaths,
        const int32_t timeout, std::vector<std::pair<std::string, uint64_t>> &resultPathsWithSize);

    /**
     * @brief Get all bundle data directory paths based on bundleName, appIndex and userId.
     * @param bundleName Indicates the bundle name.
     * @param appIndex Indicates the app index.
     * @param userId Indicates the user ID.
     * @param dataDirPaths Output parameter containing vector of data directory paths.
     * @return Returns true if successfully; returns false otherwise.
     */
    static bool GetBundleDataDirPaths(const std::string &bundleName, const int32_t appIndex,
        const int32_t userId, std::vector<std::string> &dataDirPaths);

    /**
     * @brief Anonymize a file path by replacing every other character in directory and file names with '*'.
     * @param path Indicates the file path to be anonymized.
     * @return Returns the anonymized path string.
     */
    static std::string AnonymizePath(const std::string &path);

    static bool IsValidPathByCreateBundleDirScene(
        const BundleDirScene &scene, const std::string &bundleName, const std::string &path);

    static bool IsValidPathByMkDirScene(
        const BundleDirScene &scene, const std::string& bundleName, const std::string &path);

    static bool IsValidPathByRenameModuleDir(
        const std::string &oldPath, const std::string &newPath, const std::string &bundleName, BundleDirScene scene);

    static bool IsValidPathByMoveFileScene(const std::string &oldPath, const std::string &newPath,
        const BundleDirScene &scene, const std::string &bundleName);
    static bool IsValidPathByCopyFileScene(
        const std::string &oldPath, const std::string &newPath, const BundleDirScene &scene);
    static bool IsValidPathByRemoveDirScene(const std::string &dir, const std::string &bundleName,
        const BundleDirScene &scene);
    static bool IsValidPathByMoveHapToCodeDir(const std::string &originPath, const std::string &targetPath);
    static bool IsValidPathByExtractDiffFiles(const std::string &filePath, const std::string &targetPath);
    static bool IsValidPathByApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
        const std::string &newSoPath);
    static bool IsValidPathByExtractEncryptedSoFiles(
        const std::string &hapPath, const std::string &realSoFilesPath, const std::string &tmpSoPath);
    static bool IsValidPathByExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
        const std::string &targetSoPath);
    static bool IsValidCertPath(const std::string &certPath);
    static bool IsValidPathByCopyDirScene(const std::string &sourceDir, const std::string &destinationDir,
        const std::string &bundleName, const BundleDirScene &scene);
    static bool IsValidPathByClearDirScene(const std::string &dir, const BundleDirScene &scene);
    static bool IsValidPathByGetNativeLibraryFileNames(const std::string &filePath);
    static bool IsValidPathByRestoreconPathScene(const std::string &bundleName, const std::string &path,
        const BundleDirScene &scene);
    static bool IsValidPathByCopyFilesScene(const std::string &sourceDir, const std::string &destinationDir,
        const std::string &bundleName, const BundleDirScene &scene);
    static bool IsValidPathByMoveFilesScene(const std::string &srcDir, const std::string &desDir,
        const std::string &bundleName, const BundleDirScene &scene);
    static bool IsValidPathByGetDiskUsageFromPathScene(
        const std::string &path, const std::string &bundleName, const BundleDirScene &scene);
    static bool IsValidPathByGetFileStatScene(const std::string &file, const BundleDirScene &scene);
    static bool IsValidPathByHashFiles(const std::string &file);
    static bool IsValidPathByMigrateData(
        const std::vector<std::string> &sourcePaths, const std::string &destinationPath, bool &isInvalidsourcePath);
    static bool IsValidPathByCleanBundleDirsScene(const std::string &dir, const std::string &bundleName,
        const BundleDirScene &scene);
    static bool IsValidPathByDeleteUninstallTmpDirs(const std::string &dir);
private:
    static bool ObtainNativeSoFile(const BundleExtractor &extractor, const std::string &cpuAbi,
        std::vector<std::string> &soEntryFiles);

    static bool ProcessApplyDiffPatchPath(const std::string &oldSoPath, const std::string &diffFilePath,
        const std::string &newSoPath, std::vector<std::string> &oldSoFileNames,
        std::vector<std::string> &diffFileNames);
    static bool ExtractResourceFiles(const ExtractParam &extractParam, const BundleExtractor &extractor);
    static bool CheckPathIsSame(const std::string &path, int32_t mode, const int32_t uid, const int32_t gid,
        bool &isPathExist);
    static bool IsPathNeedChown(const std::string &path, int32_t mode, bool isPathExist);
    static bool SetKeyIdPolicy(const EncryptionParam &encryptionParam, const std::string &keyId);
    static bool GenerateKeyId(const EncryptionParam &encryptionParam, std::string &keyId);
    static bool MatchPathTemplate(const std::string &path, const std::string &pattern);
#if defined(CODE_ENCRYPTION_ENABLE)
    static std::mutex encryptionMutex_;
    static void *encryptionHandle_;
    static EnforceMetadataProcessForApp enforceMetadataProcessForApp_;
    static bool OpenEncryptionHandle();
#endif
    static std::string GetSameLevelTmpPath(const std::string &path);

    struct OwnershipInfo {
        int32_t uid { 0 };
        int32_t gid { 0 };
        int32_t mode { 0 };
    };
    static int32_t InnerMigrateData(
        const std::string &sourcePaths, const std::string &destinationPath, const OwnershipInfo &info);
    static int32_t MigrateDataCopyFile(
        const std::string &sourceFile, const std::string &destinationFile, const OwnershipInfo &info);
    static int32_t MigrateDataCopyDir(
        const std::string &sourcePaths, const std::string &destinationPath, const OwnershipInfo &info);
    static int32_t MigrateDataCheckPrmissions(
        std::vector<std::string> &realSourcePaths, const std::string &destinationPath, OwnershipInfo &info);
    static int32_t UpdateFileProperties(const std::string &newFile, const OwnershipInfo &info);
    static int32_t ForceCreateDirectory(const std::string &path, const OwnershipInfo &info);
    static int32_t MigrateDataCreateAhead(
        const std::string &sourcePaths, std::string &destinationPath, const OwnershipInfo &info);
    static bool ReadCert(const std::string &path, std::vector<unsigned char> &certData);
    static std::optional<struct dqblk> GetQuotaData(int32_t uid);
    static bool CheckDeviceMode(char *buf);
    static bool CheckEfuseStatus(char *buf);
    static bool IsRdDevice();
    static bool ParsePluginId(const std::string &appServiceCapabilities, std::vector<std::string> &pluginIds);
    static ErrCode HapVerify(const std::string &filePath, Security::Verify::HapVerifyResult &hapVerifyResult);

    /**
     * @brief Get top 3 largest files or directories in the given path.
     * @param dirPath Indicates the directory path to scan.
     * @param largestPathsWithSize Output parameter containing vector of (path, size) pairs for top 3 largest items.
     * @return Returns true if successfully; returns false otherwise.
     * @note Internal overload with cache parameter is used by GetLargestFilesRecursive for performance.
     */
    static bool GetLargestFiles(const std::string &dirPath,
        std::vector<std::pair<std::string, uint64_t>> &largestPathsWithSize);

    /**
     * @brief Get top 3 largest items (files or directories) from the given paths.
     * @param dirPaths Indicates the vector of file or directory paths to scan.
     *                Files use their size directly, directories calculate total size.
     * @param largestDirsWithSize Output parameter containing vector of (path, size) pairs for top 3 largest items.
     * @return Returns true if successfully; returns false otherwise.
     */
    static bool GetLargestDirs(const std::vector<std::string> &dirPaths,
        std::vector<std::pair<std::string, uint64_t>> &largestDirsWithSize);
    static bool IsContainsPathPart(const std::string &path, const std::string &pathPart);
    static bool IsContainsBundleName(const std::string &path, const std::string &bundleName);
    static bool IsValidPathByMkDirSceneNeedBundleName(
        const BundleDirScene &scene, const std::string &bundleName, const std::string &path);
    static bool IsValidPathByMkDirSceneNoBundleName(const BundleDirScene &scene, const std::string &path);
    static bool IsValidSourcePathByMoveFileScene(
        const std::string &sourcePath, const BundleDirScene &scene, const std::string &bundleName);
    static bool IsValidTargetPathByMoveFileScene(
        const std::string &targetPath, const BundleDirScene &scene, const std::string &bundleName);
    static bool IsValidSourcePathByCopyVerifyFile(const std::string &sourcePath);
    static bool IsValidSourcePathByCopyFileScene(const std::string &sourcePath, const BundleDirScene &scene);
    static bool IsValidTargetPathByCopyFileScene(const std::string &targetPath, const BundleDirScene &scene);
    static bool IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        const std::string &dir, const std::string &bundleName, const BundleDirScene &scene);
    static bool IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        const std::string &dir, const std::string &bundleName, const BundleDirScene &scene);
    static bool IsValidPathByRemoveDirSceneNoBundleName(const std::string &dir, const BundleDirScene &scene);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_OPERATOR_H
