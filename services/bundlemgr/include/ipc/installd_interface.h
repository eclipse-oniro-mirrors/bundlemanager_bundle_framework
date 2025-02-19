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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_INSTALLD_INTERFACE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_INSTALLD_INTERFACE_H

#include <string>
#include <vector>

#include "iremote_broker.h"

#include "aot/aot_args.h"
#include "appexecfwk_errors.h"
#include "ipc/check_encryption_param.h"
#include "ipc/code_signature_param.h"
#include "ipc/create_dir_param.h"
#include "ipc/encryption_param.h"
#include "ipc/extract_param.h"
#include "ipc/file_stat.h"
#include "installd/installd_constants.h"

namespace OHOS {
namespace AppExecFwk {
class IInstalld : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.Installd");
    /**
     * @brief Create a bundle code directory.
     * @param bundleDir Indicates the bundle code directory path that to be created.
     * @return Returns ERR_OK if the bundle directory created successfully; returns error code otherwise.
     */
    virtual ErrCode CreateBundleDir(const std::string &bundleDir)
    {
        return ERR_OK;
    }
    /**
     * @brief Extract the files of a HAP module to the code directory.
     * @param srcModulePath Indicates the HAP file path.
     * @param targetPath normal files decompression path.
     * @param targetSoPath so files decompression path.
     * @param cpuAbi cpuAbi.
     * @return Returns ERR_OK if the HAP file extracted successfully; returns error code otherwise.
     */
    virtual ErrCode ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
        const std::string &targetSoPath, const std::string &cpuAbi)
    {
        return ERR_OK;
    }
    /**
     * @brief Extract the files.
     * @param extractParam Indicates the extractParam.
     * @return Returns ERR_OK if the HAP file extracted successfully; returns error code otherwise.
     */
    virtual ErrCode ExtractFiles(const ExtractParam &extractParam)
    {
        return ERR_OK;
    }

    /**
     * @brief Extract the hnpFiles.
     * @param hnpPackageInfo Indicates the hnpPackageInfo.
     * @param extractParam Indicates the extractParam.
     * @return Returns ERR_OK if the HAP file extracted successfully; returns error code otherwise.
     */
    virtual ErrCode ExtractHnpFiles(const std::string &hnpPackageInfo, const ExtractParam &extractParam)
    {
        return ERR_OK;
    }

    virtual ErrCode ProcessBundleInstallNative(const std::string &userId, const std::string &hnpRootPath,
        const std::string &hapPath, const std::string &cpuAbi, const std::string &packageName)
    {
        return ERR_OK;
    }

    virtual ErrCode ProcessBundleUnInstallNative(const std::string &userId, const std::string &bundleName)
    {
        return ERR_OK;
    }

    virtual ErrCode ExecuteAOT(const AOTArgs &aotArgs, std::vector<uint8_t> &pendSignData)
    {
        return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    }

    virtual ErrCode PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData)
    {
        return ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED;
    }

    virtual ErrCode StopAOT()
    {
        return ERR_APPEXECFWK_INSTALLD_STOP_AOT_FAILED;
    }

    virtual ErrCode DeleteUninstallTmpDirs(const std::vector<std::string> &dirs)
    {
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    /**
     * @brief Rename the module directory from temporaily path to the real path.
     * @param oldPath Indicates the old path name.
     * @param newPath Indicates the new path name.
     * @return Returns ERR_OK if the module directory renamed successfully; returns error code otherwise.
     */
    virtual ErrCode RenameModuleDir(const std::string &oldDir, const std::string &newDir)
    {
        return ERR_OK;
    }
    /**
     * @brief Create a bundle data directory.
     * @param createDirParam Indicates param to be set to the directory.
     * @return Returns ERR_OK if the bundle data directory created successfully; returns error code otherwise.
     */
    virtual ErrCode CreateBundleDataDir(const CreateDirParam &createDirParam)
    {
        return ERR_OK;
    }

    virtual ErrCode CreateBundleDataDirWithVector(const std::vector<CreateDirParam> &createDirParams)
    {
        return ERR_OK;
    }
    /**
     * @brief Remove a bundle data directory.
     * @param bundleDir Indicates the bundle data directory path that to be created.
     * @param userid Indicates userid to be set to the directory.
     * @return Returns ERR_OK if the bundle data directory created successfully; returns error code otherwise.
     */
    virtual ErrCode RemoveBundleDataDir(const std::string &bundleDir, const int32_t userId,
        bool isAtomicService = false, const bool async = false)
    {
        return ERR_OK;
    }
    /**
     * @brief Remove a module and it's abilities data directory.
     * @param ModuleDir Indicates the module data directory path that to be created.
     * @param userid Indicates userid to be set to the directory.
     * @return Returns ERR_OK if the data directories created successfully; returns error code otherwise.
     */
    virtual ErrCode RemoveModuleDataDir(const std::string &ModuleDir, const int userid)
    {
        return ERR_OK;
    }
    /**
     * @brief Remove a directory.
     * @param dir Indicates the directory path that to be removed.
     * @return Returns ERR_OK if the  directory removed successfully; returns error code otherwise.
     */
    virtual ErrCode RemoveDir(const std::string &dir)
    {
        return ERR_OK;
    }
    /**
     * @brief Get disk usage for dir.
     * @param dir Indicates the directory.
     * @param isRealPath Indicates isRealPath.
     * @param statSize Indicates size of dir.
     * @return Returns true if successfully; returns false otherwise.
     */
    virtual ErrCode GetDiskUsage(const std::string &dir, int64_t &statSize, bool isRealPath = false)
    {
        return ERR_OK;
    }
    /**
     * @brief Get disk usage for dir.
     * @param path Indicates the directory vector.\
     * @param statSize Indicates size of path.
     * @return Returns true if successfully; returns false otherwise.
     */
    virtual ErrCode GetDiskUsageFromPath(const std::vector<std::string> &path, int64_t &statSize)
    {
        return ERR_OK;
    }
    /**
     * @brief Clean all files in a bundle data directory.
     * @param bundleDir Indicates the data directory path that to be cleaned.
     * @return Returns ERR_OK if the data directory cleaned successfully; returns error code otherwise.
     */
    virtual ErrCode CleanBundleDataDir(const std::string &bundleDir)
    {
        return ERR_OK;
    }
    /**
     * @brief Clean a bundle data directory.
     * @param bundleName Indicates the bundleName data directory path that to be cleaned.
     * @param userid Indicates userid to be set to the directory.
     * @param appIndex Indicates userid to be set to the directory.
     * @return Returns ERR_OK if the bundle data directory cleaned successfully; returns error code otherwise.
     */
    virtual ErrCode CleanBundleDataDirByName(const std::string &bundleName, const int userid, const int appIndex = 0)
    {
        return ERR_OK;
    }
    /**
     * @brief Get bundle Stats.
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user Id.
     * @param bundleStats Indicates the bundle Stats.
     * @return Returns ERR_OK if get stats successfully; returns error code otherwise.
     */
    virtual ErrCode GetBundleStats(const std::string &bundleName, const int32_t userId,
        std::vector<int64_t> &bundleStats, const int32_t uid, const int32_t appIndex = 0,
        const uint32_t statFlag = 0, const std::vector<std::string> &moduleNameList = {})
    {
        return ERR_OK;
    }

    virtual ErrCode GetAllBundleStats(const int32_t userId,
        std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids)
    {
        return ERR_OK;
    }
    /**
     * @brief Set dir apl.
     * @param dir Indicates the data dir.
     * @param bundleName Indicates the bundle name.
     * @param apl Indicates the apl type.
     * @param isPreInstallApp Indicates the bundle install type.
     * @param debug Indicates the bundle debug mode.
     * @return Returns ERR_OK if set apl successfully; returns error code otherwise.
     */
    virtual ErrCode SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
        bool isPreInstallApp, bool debug)
    {
        return ERR_OK;
    }
    /**
     * @brief Get all cache file path.
     * @param dir Indicates the data dir.
     * @param cachesPath Indicates the cache file path.
     * @return Returns ERR_OK if get cache file path successfully; returns error code otherwise.
     */
    virtual ErrCode GetBundleCachePath(const std::string &dir, std::vector<std::string> &cachePath)
    {
        return ERR_OK;
    }
    /**
     * @brief Scan dir by scanMode and resultMode. this interface has higher permissions to scan.
     * @param dir Indicates the directory to be scanned.
     * @param scanMode Indicates the scan mode.
     *                 Scan all subfiles and subfolders in the directory in SUB_FILE_ALL mode
     *                 Scan all subfolders in the directory in SUB_FILE_DIR mode
     *                 Scan all subfiles in the directory in SUB_FILE_FILE mode
     * @param resultMode Indicates the result mode.
     *                 Get absolute path in ABSOLUTE_PATH mode
     *                 Get relative path in RELATIVE_PATH mode
     * @return Returns ERR_OK if scan dir successfully; returns error code otherwise.
     */
    virtual ErrCode ScanDir(
        const std::string &dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
    {
        return ERR_OK;
    }

    /**
     * @brief Move file from oldPath to newPath.
     * @param oldPath Indicates oldPath.
     * @param newPath Indicates newPath.
     * @return Returns ERR_OK if move file successfully; returns error code otherwise.
     */
    virtual ErrCode MoveFile(const std::string &oldPath, const std::string &newPath)
    {
        return ERR_OK;
    }

    /**
     * @brief Copy file from oldPath to newPath.
     * @param oldPath Indicates oldPath.
     * @param newPath Indicates newPath.
     * @return Returns ERR_OK if copy file successfully; returns error code otherwise.
     */
    virtual ErrCode CopyFile(const std::string &oldPath, const std::string &newPath,
        const std::string &signatureFilePath)
    {
        return ERR_OK;
    }

    /**
     * @brief Create directory recursively.
     * @param dir Indicates dir which will be created.
     * @param mode Indicates dir mode.
     * @param uid Indicates dir uid.
     * @param gid Indicates dir gid.
     * @return Returns ERR_OK if create directory successfully; returns error code otherwise.
     */
    virtual ErrCode Mkdir(
        const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid)
    {
        return ERR_OK;
    }

    /**
     * @brief Get file stat.
     * @param file Indicates file.
     * @param fileStat Indicates fileStat.
     * @return Returns ERR_OK if get file stat successfully; returns error code otherwise.
     */
    virtual ErrCode GetFileStat(const std::string &file, FileStat &fileStat)
    {
        return ERR_OK;
    }

    virtual ErrCode ExtractDiffFiles(const std::string &filePath, const std::string &targetPath,
        const std::string &cpuAbi)
    {
        return ERR_OK;
    }

    virtual ErrCode ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, int32_t uid)
    {
        return ERR_OK;
    }

    virtual ErrCode IsExistDir(const std::string &dir, bool &isExist)
    {
        return ERR_OK;
    }

    virtual ErrCode IsExistFile(const std::string &path, bool &isExist)
    {
        return ERR_OK;
    }

    virtual ErrCode IsExistApFile(const std::string &path, bool &isExist)
    {
        return ERR_OK;
    }

    virtual ErrCode IsDirEmpty(const std::string &dir, bool &isDirEmpty)
    {
        return ERR_OK;
    }

    virtual ErrCode ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &dirVec)
    {
        return ERR_OK;
    }

    virtual ErrCode CopyFiles(const std::string &sourceDir, const std::string &destinationDir)
    {
        return ERR_OK;
    }

    virtual ErrCode GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
        std::vector<std::string> &fileNames)
    {
        return ERR_OK;
    }

    virtual ErrCode VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam)
    {
        return ERR_OK;
    }

    virtual ErrCode CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
    {
        return ERR_OK;
    }

    virtual ErrCode MoveFiles(const std::string &srcDir, const std::string &desDir)
    {
        return ERR_OK;
    }

    virtual ErrCode ExtractDriverSoFiles(const std::string &srcPath,
        const std::unordered_multimap<std::string, std::string> &dirMap)
    {
        return ERR_OK;
    }

    virtual ErrCode ExtractEncryptedSoFiles(const std::string &hapPath, const std::string &realSoFilesPath,
        const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid)
    {
        return ERR_OK;
    }

    virtual ErrCode VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam)
    {
        return ERR_OK;
    }

    virtual ErrCode DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
        const unsigned char *profileBlock)
    {
        return ERR_OK;
    }

    virtual ErrCode RemoveSignProfile(const std::string &bundleName)
    {
        return ERR_OK;
    }

    virtual ErrCode SetEncryptionPolicy(const EncryptionParam &encryptionParam, std::string &keyId)
    {
        return ERR_OK;
    }

    virtual ErrCode DeleteEncryptionKeyId(const EncryptionParam &encryptionParam)
    {
        return ERR_OK;
    }

    virtual ErrCode RemoveExtensionDir(int32_t userId, const std::vector<std::string> &extensionBundleDirs)
    {
        return ERR_OK;
    }

    virtual ErrCode IsExistExtensionDir(int32_t userId, const std::string &extensionBundleDir, bool &isExist)
    {
        return ERR_OK;
    }

    virtual ErrCode CreateExtensionDataDir(const CreateDirParam &createDirParam)
    {
        return ERR_OK;
    }

    virtual ErrCode GetExtensionSandboxTypeList(std::vector<std::string> &typeList)
    {
        return ERR_OK;
    }

    virtual ErrCode AddUserDirDeleteDfx(int32_t userId)
    {
        return ERR_OK;
    }

    virtual ErrCode MoveHapToCodeDir(const std::string &originPath, const std::string &targetPath)
    {
        return ERR_OK;
    }

    virtual ErrCode CreateDataGroupDirs(const std::vector<CreateDirParam> &params)
    {
        return ERR_OK;
    }

    virtual ErrCode DeleteDataGroupDirs(const std::vector<std::string> &uuidList, int32_t userId)
    {
        return ERR_OK;
    }

    virtual ErrCode BackUpFirstBootLog()
    {
        return ERR_OK;
    }
};

#define INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(parcel, token)                        \
    do {                                                                            \
        bool ret = parcel.WriteInterfaceToken((token));                             \
        if (!ret) {                                                                 \
            APP_LOGE("write interface token failed");             \
            return ERR_APPEXECFWK_PARCEL_ERROR;                                     \
        }                                                                           \
    } while (0)

#define INSTALLD_PARCEL_WRITE(parcel, type, value)                                  \
    do {                                                                            \
        bool ret = parcel.Write##type((value));                                     \
        if (!ret) {                                                                 \
            APP_LOGE("write parameter failed");                   \
            return ERR_APPEXECFWK_PARCEL_ERROR;                                     \
        }                                                                           \
    } while (0)
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_INSTALLD_INTERFACE_H