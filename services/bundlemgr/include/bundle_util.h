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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_UTIL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_UTIL_H

#include <mutex>
#include <string>
#include <vector>

#include "appexecfwk_errors.h"
#include "application_info.h"

namespace OHOS {
namespace AppExecFwk {
enum class DirType {
    STREAM_INSTALL_DIR = 0,
    QUICK_FIX_DIR = 1,
    SIG_FILE_DIR = 2,
    ABC_FILE_DIR = 3,
    PGO_FILE_DIR = 4,
    EXT_RESOURCE_FILE_DIR = 5,
    UNKNOWN
};

class BundleUtil {
public:
    /**
     * @brief Check whether a file is valid HAP file.
     * @param bundlePath Indicates the HAP file path.
     * @return Returns ERR_OK if the file checked successfully; returns error code otherwise.
     */
    static ErrCode CheckFilePath(const std::string &bundlePath, std::string &realPath);
    /**
     * @brief Check whether an array of files are valid HAP files.
     * @param bundlePaths Indicates the HAP file paths.
     * @param realPaths Indicates the real paths of HAP files.
     * @return Returns ERR_OK if the file checked successfully; returns error code otherwise.
     */
    static ErrCode CheckFilePath(const std::vector<std::string> &bundlePaths, std::vector<std::string> &realPaths);
    /**
     * @brief Check whether a file is the specific type file.
     * @param fileName Indicates the file path.
     * @param extensionName Indicates the type to be checked.
     * @return Returns true if the file type checked successfully; returns false otherwise.
     */
    static bool CheckFileType(const std::string &fileName, const std::string &extensionName);
    /**
     * @brief Check whether a file name is valid.
     * @param fileName Indicates the file path.
     * @return Returns true if the file name checked successfully; returns false otherwise.
     */
    static bool CheckFileName(const std::string &fileName);
    /**
     * @brief Check whether a Hap size is valid.
     * @param fileName Indicates the file path.
     * @return Returns true if the file size checked successfully; returns false otherwise.
     */
    static bool CheckFileSize(const std::string &bundlePath, const int64_t fileSize);
    /**
     * @brief Check whether the disk path memory is available for installing the hap.
     * @param bundlePath Indicates the file path.
     * @param diskPath Indicates disk path in the system.
     * @return Returns true if the file size checked successfully; returns false otherwise.
     */
    static bool CheckSystemSize(const std::string &bundlePath, const std::string &diskPath);

    static bool CheckSystemFreeSize(const std::string &path, int64_t size);

    /**
     * @brief Insufficient disk space reported
     * @param path Indicates the file path.
     * @param fileName Indicates the file path.
    */
    static bool CheckSystemSizeAndHisysEvent(const std::string &path, const std::string &fileName);
    /**
     * @brief to obtain the hap paths of the input bundle path.
     * @param currentBundlePath Indicates the current bundle path.
     * @param hapFileList Indicates the hap paths.
     * @return Returns true if the hap path obtained successfully; returns false otherwise.
     */
    static bool GetHapFilesFromBundlePath(const std::string& currentBundlePath, std::vector<std::string>& hapFileList);
    /**
     * @brief to obtain the current time.
     * @return Returns current time.
     */
    static int64_t GetCurrentTime();
    /**
     * @brief to obtain the current time in ms.
     * @return Returns current time.
     */
    static int64_t GetCurrentTimeMs();
    /**
     * @brief to obtain the current time in ns.
     * @return Returns current time.
     */
    static int64_t GetCurrentTimeNs();
    /**
     * @brief key combination of deviceId and bundleName.
     * @param deviceId Indicates the deviceId.
     * @param bundleName Indicates the bundle name.
     * @param key Indicates the key.
     */
    static void DeviceAndNameToKey(
        const std::string &deviceId, const std::string &bundleName, std::string &key);
    /**
     * @brief The key is parsed into deviceId and bundleName.
     * @param key Indicates the key.
     * @param deviceId Indicates the deviceId.
     * @param bundleName Indicates the bundle name.
     * @return Returns result.
     */
    static bool KeyToDeviceAndName(
        const std::string &key, std::string &deviceId, std::string &bundleName);
    /**
     * @brief get userId by callinguid.
     * @return Returns userId.
     */
    static int32_t GetUserIdByCallingUid();
    /**
     * @brief get userId by uid.
     * @param uid Indicates uid.
     * @return Returns userId.
     */
    static int32_t GetUserIdByUid(int32_t uid);
    /**
     * @brief Is file exist.
     * @param path Indicates path.
     * @return Returns result.
     */
    static bool IsExistFile(const std::string &path);
    /**
     * @brief Is file exist.
     * @param path Indicates path.
     * @return Returns result.
     */
    static bool IsExistFileNoLog(const std::string &path);
    /**
     * @brief Is dir exist.
     * @param path Indicates path.
     * @return Returns result.
     */
    static bool IsExistDir(const std::string &path);
    /**
     * @brief Is dir exist.
     * @param path Indicates path.
     * @return Returns result.
     */
    static bool IsExistDirNoLog(const std::string &path);

    static bool IsPathInformationConsistent(const std::string &path, int32_t uid, int32_t gid);

    /**
     * @brief Rename file from oldPath to newPath.
     * @param oldPath Indicates oldPath.
     * @param newPath Indicates newPath.
     * @return Returns result.
     */
    static bool RenameFile(const std::string &oldPath, const std::string &newPath);
    /**
     * @brief Copy file from oldPath to newPath.
     * @param oldPath Indicates oldPath.
     * @param newPath Indicates newPath.
     * @return Returns result.
     */
    static bool CopyFile(
        const std::string &oldPath, const std::string &newPath);

    static bool CopyFileFast(const std::string &sourcePath, const std::string &destPath);
    /**
     * @brief Delete all dir or file.
     * @param path Indicates sourceStr.
     * @return Returns result.
     */
    static bool DeleteDir(const std::string &path);
    static bool IsUtd(const std::string &param);
    static bool IsSpecificUtd(const std::string &param);
    static std::vector<std::string> GetUtdVectorByMimeType(const std::string &mimeType);
    static std::string GetBoolStrVal(bool val);
    static void MakeFsConfig(const std::string &bundleName, int32_t bundleId, const std::string &configPath);
    static void RemoveFsConfig(const std::string &bundleName, const std::string &configPath);
    static std::string CreateInstallTempDir(uint32_t installerId, const DirType &type);
    static std::string CreateSharedBundleTempDir(uint32_t installerId, uint32_t index);
    static int32_t CreateFileDescriptor(const std::string &bundlePath, long long offset);
    static int32_t CreateFileDescriptorForReadOnly(const std::string &bundlePath, long long offset);
    static void CloseFileDescriptor(std::vector<int32_t> &fdVec);
    static Resource GetResource(const std::string &bundleName, const std::string &moduleName, uint32_t resId);
    static bool CreateDir(const std::string &dir);
    static bool RevertToRealPath(const std::string &sandBoxPath, const std::string &bundleName, std::string &realPath);
    static bool StartWith(const std::string &source, const std::string &suffix);
    static bool EndWith(const std::string &source, const std::string &suffix);
    static int64_t GetFileSize(const std::string &filePath);
    static int64_t CalculateFileSize(const std::string &bundlePath);
    static std::string CreateTempDir(const std::string &tempDir);
    static std::string CopyFileToSecurityDir(const std::string &filePath, const DirType &dirType,
        std::vector<std::string> &toDeletePaths, bool rename = false);
    static void DeleteTempDirs(const std::vector<std::string> &tempDirs);
    static std::string GenerateUuid();
    static std::string GetHexHash(const std::string &s);
    static void RecursiveHash(std::string& s);
    static std::string ExtractGroupIdByDevelopId(const std::string &developerId);
    static std::string ToString(const std::vector<std::string> &vector);
    static std::string GetNoDisablingConfigPath();
    static std::string GenerateUuidByKey(const std::string &key);
private:
    static std::mutex g_mutex;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_UTIL_H
