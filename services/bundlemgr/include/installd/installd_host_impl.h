/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_HOST_IMPL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_HOST_IMPL_H

#include "bundle_constants.h"
#include "code_sign_helper.h"
#include "ipc/installd_host.h"
#include "installd/installd_operator.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
class InstalldHostImpl : public InstalldHost {
public:
    InstalldHostImpl();
    virtual ~InstalldHostImpl();
    /**
     * @brief Create a bundle code directory.
     * @param bundleDir Indicates the bundle code directory path that to be created.
     * @return Returns ERR_OK if the bundle directory created successfully; returns error code otherwise.
     */
    virtual ErrCode CreateBundleDir(const std::string &bundleDir) override;
    /**
     * @brief Extract the files of a HAP module to the code directory.
     * @param srcModulePath Indicates the HAP file path.
     * @param targetPath normal files decompression path.
     * @param targetSoPath so files decompression path.
     * @param cpuAbi cpuAbi.
     * @return Returns ERR_OK if the HAP file extracted successfully; returns error code otherwise.
     */
    virtual ErrCode ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
        const std::string &targetSoPath, const std::string &cpuAbi) override;
    /**
     * @brief Extract the files.
     * @param extractParam Indicates the extractParam.
     * @return Returns ERR_OK if the HAP file extracted successfully; returns error code otherwise.
     */
    virtual ErrCode ExtractFiles(const ExtractParam &extractParam) override;

    /**
     * @brief Extract the hnpFiles.
     * @param hnpPackageMap Indicates the hnpPackageInfo.
     * @param extractParam Indicates the extractParam.
     * @return Returns ERR_OK if the HAP file extracted successfully; returns error code otherwise.
     */
    virtual ErrCode ExtractHnpFiles(const std::map<std::string, std::string> &hnpPackageMap,
        const ExtractParam &extractParam) override;

    virtual ErrCode ProcessBundleInstallNative(const InstallHnpParam &installHnpParam) override;

    virtual ErrCode ProcessBundleUnInstallNative(const std::string &userId, const std::string &bundleName) override;

    virtual ErrCode ExecuteAOT(const AOTArgs &aotArgs, std::vector<uint8_t> &pendSignData) override;

    virtual ErrCode PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData) override;

    virtual ErrCode StopAOT() override;

    virtual ErrCode DeleteUninstallTmpDirs(const std::vector<std::string> &dirs) override;
    /**
     * @brief Rename the module directory from temporaily path to the real path.
     * @param oldPath Indicates the old path name.
     * @param newPath Indicates the new path name.
     * @return Returns ERR_OK if the module directory renamed successfully; returns error code otherwise.
     */
    virtual ErrCode RenameModuleDir(const std::string &oldPath, const std::string &newPath) override;
    /**
     * @brief Create a bundle data directory.
     * @param createDirParam Indicates param to be set to the directory.
     * @return Returns ERR_OK if the bundle data directory created successfully; returns error code otherwise.
     */
    virtual ErrCode CreateBundleDataDir(const CreateDirParam &createDirParam) override;

    virtual ErrCode CreateBundleDataDirWithVector(const std::vector<CreateDirParam> &createDirParams) override;
    /**
     * @brief Remove a bundle data directory.
     * @param bundleName Indicates the bundleName data directory path that to be created.
     * @param userid Indicates userid to be set to the directory.
     * @return Returns ERR_OK if the bundle data directory created successfully; returns error code otherwise.
     */
    virtual ErrCode RemoveBundleDataDir(const std::string &bundleName, const int32_t userId,
        bool isAtomicService = false, const bool async = false) override;
    /**
     * @brief Remove a module data directory.
     * @param ModuleDir Indicates the module data directory path that to be created.
     * @param userid Indicates userid to be set to the directory.
     * @return Returns ERR_OK if the data directories created successfully; returns error code otherwise.
     */
    virtual ErrCode RemoveModuleDataDir(const std::string &ModuleDir, const int userid) override;
    /**
     * @brief Remove a directory.
     * @param dir Indicates the directory path that to be removed.
     * @return Returns ERR_OK if the  directory removed successfully; returns error code otherwise.
     */
    virtual ErrCode RemoveDir(const std::string &dir, bool async = false) override;
    /**
     * @brief Get disk usage for dir.
     * @param dir Indicates the directory.
     * @param isRealPath Indicates isRealPath.
     * * @param statSize Indicates size of dir.
     * @return Returns true if successfully; returns false otherwise.
     */
    virtual ErrCode GetDiskUsage(const std::string &dir, int64_t &statSize, bool isRealPath = false) override;
    /**
     * @brief Get disk usage for dir.
     * @param path Indicates the directory vector.
     * * @param statSize Indicates size of path.
     * @return Returns true if successfully; returns false otherwise.
     */
    virtual ErrCode GetDiskUsageFromPath(const std::vector<std::string> &path, int64_t &statSize) override;
    /**
     * @brief Clean all files in a bundle data directory.
     * @param bundleDir Indicates the data directory path that to be cleaned.
     * @return Returns ERR_OK if the data directory cleaned successfully; returns error code otherwise.
     */
    virtual ErrCode CleanBundleDataDir(const std::string &bundleDir) override;

    virtual ErrCode CleanBundleDirs(const std::vector<std::string> &dirs, bool keepParent) override;
    /**
     * @brief Clean a bundle data directory.
     * @param bundleName Indicates the bundleName data directory path that to be cleaned.
     * @param userid Indicates userid to be set to the directory.
     * @param appIndex Indicates app index to be set to the directory.
     * @return Returns ERR_OK if the bundle data directory cleaned successfully; returns error code otherwise.
     */
    virtual ErrCode CleanBundleDataDirByName(const std::string &bundleName, const int userid,
        const int appIndex = 0, const bool isAtomicService = false) override;
    /**
     * @brief Get bundle Stats.
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user Id.
     * @param bundleStats Indicates the bundle Stats.
     * @return Returns ERR_OK if get stats successfully; returns error code otherwise.
     */
    virtual ErrCode GetBundleStats(const std::string &bundleName, const int32_t userId,
        std::vector<int64_t> &bundleStats, const std::unordered_set<int32_t> &uids,
        const int32_t appIndex = 0, const uint32_t statFlag = 0,
        const std::vector<std::string> &moduleNameList = {}) override;

    virtual ErrCode BatchGetBundleStats(const std::vector<std::string> &bundleNames, const int32_t userId,
        const std::unordered_map<std::string, std::unordered_set<int32_t>> &uidMap,
        std::vector<BundleStorageStats> &bundleStats) override;

    virtual ErrCode GetAllBundleStats(const int32_t userId,
        std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids) override;
    /**
     * @brief Set dir apl.
     * @param dir Indicates the data dir.
     * @param bundleName Indicates the bundle name.
     * @param apl Indicates the apl type.
     * @param isPreInstallApp Indicates the bundle install type.
     * @param debug Indicates the bundle debug mode.
     * @param uid Indicates the uid.
     * @return Returns ERR_OK if set apl successfully; returns error code otherwise.
     */
    virtual ErrCode SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
        bool isPreInstallApp, bool debug, int32_t uid) override;

    virtual ErrCode SetDirsApl(const CreateDirParam &createDirParam, bool isExtensionDir) override;

    virtual ErrCode SetFileConForce(const std::vector<std::string> &paths,
        const CreateDirParam &createDirParam) override;

    virtual ErrCode StopSetFileCon(const CreateDirParam &createDirParam, int32_t reason) override;

    /**
     * @brief Set dir apl.
     * @param dir Indicates the data dir.
     * @return Returns ERR_OK if set apl successfully; returns error code otherwise.
     */
    virtual ErrCode SetArkStartupCacheApl(const std::string &dir) override;

    std::string GetAppDataPath(const std::string &bundleName, const std::string &el,
        const int32_t userId, const int32_t appIndex);

    /**
     * @brief Get all cache file path.
     * @param dir Indicates the data dir.
     * @param cachesPath Indicates the cache file path.
     * @return Returns ERR_OK if get cache file path successfully; returns error code otherwise.
     */
    virtual ErrCode GetBundleCachePath(const std::string &dir, std::vector<std::string> &cachePath) override;

    virtual ErrCode ScanDir(
        const std::string &dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths) override;

    virtual ErrCode MoveFile(const std::string &oldPath, const std::string &newPath) override;

    virtual ErrCode RenameFile(const std::string &oldPath, const std::string &newPath) override;

    virtual ErrCode CopyFile(const std::string &oldPath, const std::string &newPath,
        const std::string &signatureFilePath = "") override;

    virtual ErrCode Mkdir(
        const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid) override;

    virtual ErrCode GetFileStat(const std::string &file, FileStat &fileStat) override;

    virtual ErrCode ChangeFileStat(const std::string &file, FileStat &fileStat) override;

    virtual ErrCode ExtractDiffFiles(const std::string &filePath, const std::string &targetPath,
        const std::string &cpuAbi) override;

    virtual ErrCode ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
        const std::string &newSoPath, int32_t uid) override;

    virtual ErrCode IsExistDir(const std::string &dir, bool &isExist) override;

    virtual ErrCode IsExistFile(const std::string &path, bool &isExist) override;

    virtual ErrCode IsExistApFile(const std::string &path, bool &isExist) override;

    virtual ErrCode IsDirEmpty(const std::string &dir, bool &isDirEmpty) override;

    virtual ErrCode ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &dirVec) override;

    virtual ErrCode CopyFiles(const std::string &sourceDir, const std::string &destinationDir) override;

    virtual ErrCode GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
        std::vector<std::string> &fileNames) override;

    virtual ErrCode VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam) override;

    virtual ErrCode CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption) override;

    virtual ErrCode MoveFiles(const std::string &srcDir, const std::string &desDir) override;

    virtual ErrCode ExtractDriverSoFiles(const std::string &srcPath,
        const std::unordered_multimap<std::string, std::string> &dirMap) override;

    virtual ErrCode ExtractEncryptedSoFiles(const std::string &hapPath, const std::string &realSoFilesPath,
        const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid) override;

#if defined(CODE_SIGNATURE_ENABLE)
    ErrCode PrepareEntryMap(const CodeSignatureParam &codeSignatureParam, Security::CodeSign::EntryMap &entryMap);
#endif

    virtual ErrCode VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam) override;

    virtual ErrCode DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
        const unsigned char *profileBlock) override;

    virtual ErrCode RemoveSignProfile(const std::string &bundleName) override;

    virtual ErrCode AddCertAndEnableKey(const std::string &certPath, const std::string &certContent) override;

    virtual ErrCode SetEncryptionPolicy(const EncryptionParam &encryptionParam, std::string &keyId) override;

    virtual ErrCode DeleteEncryptionKeyId(const EncryptionParam &encryptionParam) override;

    virtual ErrCode RemoveExtensionDir(int32_t userId, const std::vector<std::string> &extensionBundleDirs) override;

    virtual ErrCode IsExistExtensionDir(int32_t userId, const std::string &extensionBundleDir, bool &isExist) override;

    virtual ErrCode CreateExtensionDataDir(const CreateDirParam &createDirParam) override;

    virtual ErrCode GetExtensionSandboxTypeList(std::vector<std::string> &typeList) override;

    virtual ErrCode AddUserDirDeleteDfx(int32_t userId) override;

    virtual ErrCode MoveHapToCodeDir(const std::string &originPath, const std::string &targetPath) override;

    virtual ErrCode CreateDataGroupDirs(const std::vector<CreateDirParam> &params) override;

    virtual ErrCode MigrateData(
        const std::vector<std::string> &sourcePaths, const std::string &destinationPath) override;

    virtual ErrCode DeleteDataGroupDirs(const std::vector<std::string> &uuidList, int32_t userId) override;

    virtual ErrCode ClearDir(const std::string &dir) override;

    virtual ErrCode RestoreconPath(const std::string &path) override;

    virtual ErrCode ResetBmsDBSecurity() override;
    virtual ErrCode HashSoFile(const std::string& soPath, uint32_t catchSoNum, uint64_t catchSoMaxSize,
        std::vector<std::string> &soName, std::vector<std::string> &soHash) override;
    virtual ErrCode HashFiles(const std::vector<std::string> &files, std::vector<std::string> &filesHash) override;

    virtual ErrCode CopyDir(const std::string &sourceDir, const std::string &destinationDir) override;

    virtual ErrCode DeleteCertAndRemoveKey(const std::vector<std::string> &certPaths) override;

private:
    static std::string GetGroupDirPath(const std::string &el, int32_t userId, const std::string &uuid);
    std::string GetExtensionConfigPath() const;
    /**
     * @brief Create /data/app/el2/userid/sharefiles/ bundle data directory.
     * @param createDirParam Indicates param to be set to the directory.
     * @return Returns ERR_OK if the bundle data directory created successfully; returns error code otherwise.
     */
    ErrCode CreateSharefilesDataDirEl2(const CreateDirParam &createDirParam);
    void LoadNeedCreateSandbox(const nlohmann::json &object, std::vector<std::string> &typeList);
    bool LoadExtensionNeedCreateSandbox(const nlohmann::json &object, std::string extensionTypeName);
    bool ReadFileIntoJson(const std::string &filePath, nlohmann::json &jsonBuf);
    ErrCode CreateExtensionDir(const CreateDirParam &createDirParam, const std::string& parentDir,
        int32_t mode, int32_t gid, bool isLog = false);
    ErrCode RemoveExtensionDir(int32_t userId, const std::string &extensionBundleDir);
    std::string GetBundleDataDir(const std::string &el, const int userid) const;
    bool CheckPathValid(const std::string &path, const std::string &prefix);
    ErrCode SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
        unsigned int hapFlags, int32_t uid);
    unsigned int GetHapFlags(const bool isPreInstallApp, const bool debug, const bool isDlpSandbox,
        const int32_t dlpType, const bool isExtensionDir);
    ErrCode InnerRemoveAtomicServiceBundleDataDir(
        const std::string &bundleName, const int32_t userId, const bool async);
    ErrCode InnerRemoveBundleDataDir(const std::string &bundleName, const int32_t userId, const bool async);
    ErrCode AclSetDir(bool debug, const std::string &dir, bool setAccess, bool setDefault);
    ErrCode AclSetExtensionDirs(bool debug, const std::string &parentDir,
        const std::vector<std::string> &extensionDirs, bool setAccess, bool setDefault);
    int64_t GetAppCacheSize(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex, const std::vector<std::string> &moduleNames = {});
    ErrCode CreateDataGroupDir(const CreateDirParam &param);
    ErrCode DeleteEl5DataGroupDirs(const std::vector<std::string> &uuidList, int32_t userId);
    ErrCode CreateBundleDataDirWithEl(const CreateDirParam &createDirParam);
    ErrCode CreateCommonDataDir(const CreateDirParam &createDirParam, const std::string &el);
    ErrCode CreateEl2DataDir(const CreateDirParam &createDirParam);
    void InnerCleanBundleDataDirByName(std::string &suffixName, const int userid, const int appIndex = 0);
    ErrCode ResetBmsDBSecurityByPath(const std::string &parentPath, const std::string &fileFlag);
    ErrCode ResetSecurityByPath(const FileStat &fileStat, const std::string &targetPath);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_HOST_IMPL_H