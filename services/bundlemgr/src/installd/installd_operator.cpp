/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "installd/installd_operator.h"

#include <algorithm>
#if defined(CODE_SIGNATURE_ENABLE)
#include "code_sign_utils.h"
#endif
#if defined(CODE_ENCRYPTION_ENABLE)
#include <sys/ioctl.h>
#include "code_crypto_metadata_process.h"
#include "linux/code_decrypt.h"
#endif
#include <cerrno>
#include <cstdio>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <string.h>
#include <sys/mman.h>
#include <sys/quota.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_util.h"
#include "directory_ex.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static const char LIB_DIFF_PATCH_SHARED_SO_PATH[] = "system/lib/libdiff_patch_shared.z.so";
static const char LIB64_DIFF_PATCH_SHARED_SO_PATH[] = "system/lib64/libdiff_patch_shared.z.so";
static const char APPLY_PATCH_FUNCTION_NAME[] = "ApplyPatch";
static std::string PREFIX_RESOURCE_PATH = "/resources/rawfile/";
static std::string PREFIX_TARGET_PATH = "/print_service/";
static const std::string SO_SUFFIX_REGEX = "\\.so\\.[0-9][0-9]*$";
static constexpr int32_t INSTALLS_UID = 3060;
static constexpr int32_t MODE_BASE = 07777;
static const std::string PROC_MOUNTS_PATH = "/proc/mounts";
static const std::string QUOTA_DEVICE_DATA_PATH = "/data";
#if defined(CODE_SIGNATURE_ENABLE)
using namespace OHOS::Security::CodeSign;
#endif
#if defined(CODE_ENCRYPTION_ENABLE)
static std::string CODE_DECRYPT = "/dev/code_decrypt";
static int32_t INVALID_RETURN_VALUE = -1;
static int32_t INVALID_FILE_DESCRIPTOR = -1;
#endif
std::recursive_mutex mMountsLock;
static std::map<std::string, std::string> mQuotaReverseMounts;
using ApplyPatch = int32_t (*)(const std::string, const std::string, const std::string);

static std::string HandleScanResult(
    const std::string &dir, const std::string &subName, ResultMode resultMode)
{
    if (resultMode == ResultMode::RELATIVE_PATH) {
        return subName;
    }

    return dir + Constants::PATH_SEPARATOR + subName;
}

static bool StartsWith(const std::string &sourceString, const std::string &targetPrefix)
{
    return sourceString.find(targetPrefix) == 0;
}

static bool EndsWith(const std::string &sourceString, const std::string &targetSuffix)
{
    if (sourceString.length() < targetSuffix.length()) {
        return false;
    }
    if (sourceString.rfind(targetSuffix) == (sourceString.length() - targetSuffix.length())) {
        return true;
    }
    if (targetSuffix == Constants::SO_SUFFIX) {
        std::regex soRegex(SO_SUFFIX_REGEX);
        return std::regex_search(sourceString, soRegex);
    }
    return false;
}
} // namespace

bool InstalldOperator::IsExistFile(const std::string &path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        APP_LOGE("fail to stat errno:%{public}d", errno);
        return false;
    }
    return S_ISREG(buf.st_mode);
}

bool InstalldOperator::IsExistApFile(const std::string &path)
{
    std::string realPath;
    std::filesystem::path apFilePath(path);
    std::string apDir = apFilePath.parent_path().string();
    if (path.empty() || !PathToRealPath(apDir, realPath)) {
        return false;
    }

    std::error_code errorCode;
    std::filesystem::directory_iterator iter(realPath, errorCode);

    if (errorCode) {
        APP_LOGE("Error occurred while opening apDir: %{public}s", errorCode.message().c_str());
        return false;
    }
    for (const auto& entry : iter) {
        if (entry.path().extension() == Constants::AP_SUFFIX) {
            return true;
        }
    }
    return false;
}

bool InstalldOperator::IsExistDir(const std::string &path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        return false;
    }
    return S_ISDIR(buf.st_mode);
}

bool InstalldOperator::IsDirEmpty(const std::string &dir)
{
    return OHOS::IsEmptyFolder(dir);
}

bool InstalldOperator::MkRecursiveDir(const std::string &path, bool isReadByOthers)
{
    if (!OHOS::ForceCreateDirectory(path)) {
        APP_LOGE("mkdir failed");
        return false;
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH;
    mode |= (isReadByOthers ? S_IROTH : 0);
    return OHOS::ChangeModeDirectory(path, mode);
}

bool InstalldOperator::DeleteDir(const std::string &path)
{
    APP_LOGD("start to delete dir %{public}s", path.c_str());
    if (IsExistFile(path)) {
        return OHOS::RemoveFile(path);
    }
    if (IsExistDir(path)) {
        return OHOS::ForceRemoveDirectory(path);
    }
    return true;
}

bool InstalldOperator::ExtractFiles(const std::string &sourcePath, const std::string &targetSoPath,
    const std::string &cpuAbi)
{
    APP_LOGD("InstalldOperator::ExtractFiles start");
    if (targetSoPath.empty()) {
        return true;
    }

    BundleExtractor extractor(sourcePath);
    if (!extractor.Init()) {
        return false;
    }

    std::vector<std::string> soEntryFiles;
    if (!ObtainNativeSoFile(extractor, cpuAbi, soEntryFiles)) {
        APP_LOGE("ExtractFiles obtain native so file entryName failed");
        return false;
    }

    for_each(soEntryFiles.begin(), soEntryFiles.end(), [&extractor, &targetSoPath, &cpuAbi](const auto &entry) {
        ExtractTargetFile(extractor, entry, targetSoPath, cpuAbi);
    });

    APP_LOGD("InstalldOperator::ExtractFiles end");
    return true;
}

bool InstalldOperator::ExtractFiles(const ExtractParam &extractParam)
{
    APP_LOGD("InstalldOperator::ExtractFiles start");
    BundleExtractor extractor(extractParam.srcPath);
    if (!extractor.Init()) {
        APP_LOGE("extractor init failed");
        return false;
    }

    if (extractParam.extractFileType == ExtractFileType::RESOURCE) {
        return ExtractResourceFiles(extractParam, extractor);
    }

    if ((extractParam.extractFileType == ExtractFileType::AP) &&
        !extractor.IsDirExist(Constants::AP)) {
        APP_LOGD("hap has no ap files and does not need to be extracted.");
        return true;
    }

    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames) || entryNames.empty()) {
        APP_LOGE("get entryNames failed");
        return false;
    }

    for (const auto &entryName : entryNames) {
        if (strcmp(entryName.c_str(), ".") == 0 ||
            strcmp(entryName.c_str(), "..") == 0) {
            continue;
        }
        if (entryName.back() == Constants::PATH_SEPARATOR[0]) {
            continue;
        }
        // handle native file
        if (IsNativeFile(entryName, extractParam)) {
            ExtractTargetFile(extractor, entryName, extractParam.targetPath,
                extractParam.cpuAbi, extractParam.extractFileType);
            continue;
        }
    }

    APP_LOGD("InstalldOperator::ExtractFiles end");
    return true;
}

bool InstalldOperator::IsNativeFile(
    const std::string &entryName, const ExtractParam &extractParam)
{
    APP_LOGD("IsNativeFile, entryName : %{public}s", entryName.c_str());
    if (extractParam.targetPath.empty()) {
        APP_LOGD("current hap not include so");
        return false;
    }
    std::string prefix;
    std::vector<std::string> suffixes;
    if (!DeterminePrefix(extractParam.extractFileType, extractParam.cpuAbi, prefix) ||
        !DetermineSuffix(extractParam.extractFileType, suffixes)) {
        APP_LOGE("determine prefix or suffix failed");
        return false;
    }

    if (!StartsWith(entryName, prefix)) {
        APP_LOGD("entryName not start with %{public}s", prefix.c_str());
        return false;
    }

    bool checkSuffix = false;
    for (const auto &suffix : suffixes) {
        if (EndsWith(entryName, suffix)) {
            checkSuffix = true;
            break;
        }
    }

    if (!checkSuffix && extractParam.extractFileType != ExtractFileType::RES_FILE) {
        APP_LOGD("file type error.");
        return false;
    }

    APP_LOGD("find native file, prefix: %{public}s, entryName: %{public}s",
        prefix.c_str(), entryName.c_str());
    return true;
}

bool InstalldOperator::IsNativeSo(const std::string &entryName, const std::string &cpuAbi)
{
    APP_LOGD("IsNativeSo, entryName : %{public}s", entryName.c_str());
    std::string prefix = Constants::LIBS + cpuAbi + Constants::PATH_SEPARATOR;
    if (!StartsWith(entryName, prefix)) {
        APP_LOGD("entryName not start with %{public}s", prefix.c_str());
        return false;
    }
    if (!EndsWith(entryName, Constants::SO_SUFFIX)) {
        APP_LOGD("file name not so format.");
        return false;
    }
    APP_LOGD("find native so, entryName : %{public}s", entryName.c_str());
    return true;
}

bool InstalldOperator::IsDiffFiles(const std::string &entryName,
    const std::string &targetPath, const std::string &cpuAbi)
{
    APP_LOGD("IsDiffFiles, entryName : %{public}s", entryName.c_str());
    if (targetPath.empty()) {
        APP_LOGD("current hap not include diff");
        return false;
    }
    std::string prefix = Constants::LIBS + cpuAbi + Constants::PATH_SEPARATOR;
    if (!StartsWith(entryName, prefix)) {
        APP_LOGD("entryName not start with %{public}s", prefix.c_str());
        return false;
    }
    if (!EndsWith(entryName, Constants::DIFF_SUFFIX)) {
        APP_LOGD("file name not diff format.");
        return false;
    }
    APP_LOGD("find native diff, entryName : %{public}s", entryName.c_str());
    return true;
}

void InstalldOperator::ExtractTargetFile(const BundleExtractor &extractor, const std::string &entryName,
    const std::string &targetPath, const std::string &cpuAbi, const ExtractFileType &extractFileType)
{
    // create dir if not exist
    if (!IsExistDir(targetPath)) {
        if (!MkRecursiveDir(targetPath, true)) {
            APP_LOGE("create targetPath %{public}s failed", targetPath.c_str());
            return;
        }
    }

    std::string prefix;
    if (!DeterminePrefix(extractFileType, cpuAbi, prefix)) {
        APP_LOGE("determine prefix failed");
        return;
    }
    std::string targetName = entryName.substr(prefix.length());
    std::string path = targetPath;
    if (path.back() != Constants::FILE_SEPARATOR_CHAR) {
        path += Constants::FILE_SEPARATOR_CHAR;
    }
    path += targetName;
    if (targetName.find(Constants::PATH_SEPARATOR) != std::string::npos) {
        std::string dir = GetPathDir(path);
        if (!IsExistDir(dir) && !MkRecursiveDir(dir, true)) {
            APP_LOGE("create dir %{public}s failed", dir.c_str());
            return;
        }
    }
    bool ret = extractor.ExtractFile(entryName, path);
    if (!ret) {
        APP_LOGE("extract file failed, entryName : %{public}s", entryName.c_str());
        return;
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (extractFileType == ExtractFileType::AP) {
        struct stat buf = {};
        if (stat(targetPath.c_str(), &buf) != 0) {
            APP_LOGE("fail to stat errno:%{public}d", errno);
            return;
        }
        ChangeFileAttr(path, buf.st_uid, buf.st_gid);
        mode = (buf.st_uid == buf.st_gid) ? (S_IRUSR | S_IWUSR) : (S_IRUSR | S_IWUSR | S_IRGRP);
    }
    if (!OHOS::ChangeModeFile(path, mode)) {
        APP_LOGE("ChangeModeFile %{public}s failed, errno: %{public}d", path.c_str(), errno);
        return;
    }
    APP_LOGD("extract file success, path : %{public}s", path.c_str());
}

bool InstalldOperator::DeterminePrefix(const ExtractFileType &extractFileType, const std::string &cpuAbi,
    std::string &prefix)
{
    switch (extractFileType) {
        case ExtractFileType::SO: {
            prefix = Constants::LIBS + cpuAbi + Constants::PATH_SEPARATOR;
            break;
        }
        case ExtractFileType::AN: {
            prefix = Constants::AN + cpuAbi + Constants::PATH_SEPARATOR;
            break;
        }
        case ExtractFileType::AP: {
            prefix = Constants::AP;
            break;
        }
        case ExtractFileType::RES_FILE: {
            prefix = Constants::RES_FILE_PATH;
            break;
        }
        default: {
            return false;
        }
    }
    return true;
}

bool InstalldOperator::DetermineSuffix(const ExtractFileType &extractFileType, std::vector<std::string> &suffixes)
{
    switch (extractFileType) {
        case ExtractFileType::SO: {
            suffixes.emplace_back(Constants::SO_SUFFIX);
            break;
        }
        case ExtractFileType::AN: {
            suffixes.emplace_back(Constants::AN_SUFFIX);
            suffixes.emplace_back(Constants::AI_SUFFIX);
            break;
        }
        case ExtractFileType::AP: {
            suffixes.emplace_back(Constants::AP_SUFFIX);
            break;
        }
        case ExtractFileType::RES_FILE: {
            break;
        }
        default: {
            return false;
        }
    }
    return true;
}

bool InstalldOperator::RenameDir(const std::string &oldPath, const std::string &newPath)
{
    if (oldPath.empty() || oldPath.size() > PATH_MAX) {
        APP_LOGE("oldpath error");
        return false;
    }
    if (access(oldPath.c_str(), F_OK) != 0 && access(newPath.c_str(), F_OK) == 0) {
        APP_LOGE("fail to access file errno:%{public}d", errno);
        return true;
    }
    std::string realOldPath;
    realOldPath.reserve(PATH_MAX);
    realOldPath.resize(PATH_MAX - 1);
    if (realpath(oldPath.c_str(), &(realOldPath[0])) == nullptr) {
        APP_LOGE("realOldPath %{public}s, errno:%{public}d", realOldPath.c_str(), errno);
        return false;
    }

    if (!(IsValidCodePath(realOldPath) && IsValidCodePath(newPath))) {
        APP_LOGE("IsValidCodePath failed");
        return false;
    }
    return RenameFile(realOldPath, newPath);
}

std::string InstalldOperator::GetPathDir(const std::string &path)
{
    std::size_t pos = path.rfind(Constants::PATH_SEPARATOR);
    if (pos == std::string::npos) {
        return std::string();
    }
    return path.substr(0, pos + 1);
}

bool InstalldOperator::ChangeDirOwnerRecursively(const std::string &path, const int uid, const int gid)
{
    std::string subPath;
    bool ret = true;
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        APP_LOGD("fail to opendir:%{public}s, errno:%{public}d", path.c_str(), errno);
        return false;
    }

    while (true) {
        struct dirent *ptr = readdir(dir);
        if (ptr == nullptr) {
            APP_LOGD("fail to readdir errno:%{public}d", errno);
            break;
        }

        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }

        subPath = OHOS::IncludeTrailingPathDelimiter(path) + std::string(ptr->d_name);
        if (ptr->d_type == DT_DIR) {
            ret = ChangeDirOwnerRecursively(subPath, uid, gid);
            continue;
        }

        if (access(subPath.c_str(), F_OK) == 0) {
            if (!ChangeFileAttr(subPath, uid, gid)) {
                APP_LOGD("Failed to ChangeFileAttr %{public}s, uid=%{public}d", subPath.c_str(), uid);
                closedir(dir);
                return false;
            }
        }
    }

    closedir(dir);
    std::string currentPath = OHOS::ExcludeTrailingPathDelimiter(path);
    if (access(currentPath.c_str(), F_OK) == 0) {
        if (!ChangeFileAttr(currentPath, uid, gid)) {
            APP_LOGD("Failed to ChangeFileAttr %{public}s, uid=%{public}d", currentPath.c_str(), uid);
            return false;
        }
    }

    return ret;
}

void InstalldOperator::ChangeDirProperties(const std::string &path, int32_t uid, int32_t gid)
{
    struct stat s;
    if ((stat(path.c_str(), &s) == 0) && (((s.st_mode & S_ISGID) != S_ISGID) ||
        (static_cast<int32_t>(s.st_uid) != uid) || (static_cast<int32_t>(s.st_gid) != gid))) {
        APP_LOGI("dir :%{private}s need change mode, uid:%{public}d, gid:%{public}d", path.c_str(), uid, gid);
        if (chown(path.c_str(), INSTALLS_UID, INSTALLS_UID) != 0) {
            APP_LOGW("fail to change %{private}s ownership, errno:%{public}d", path.c_str(), errno);
        }
        if (chmod(path.c_str(), s.st_mode | S_ISGID) != 0) {
            APP_LOGW("chmod path:%{private}s failed, errno:%{public}d",
                path.c_str(), errno);
        }
        if (chown(path.c_str(), uid, gid) != 0) {
            APP_LOGW("fail to change %{private}s ownership, uid=%{public}d, errno:%{public}d",
                path.c_str(), uid, errno);
        }
    }
}

bool InstalldOperator::ChangeDirPropertiesRecursively(const std::string &path, int32_t uid, int32_t gid)
{
    std::string subPath;
    bool ret = true;
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        APP_LOGE("fail to opendir:%{private}s, errno:%{public}d", path.c_str(), errno);
        return false;
    }
    struct dirent *ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        subPath = OHOS::IncludeTrailingPathDelimiter(path) + std::string(ptr->d_name);
        struct stat s;
        if ((stat(subPath.c_str(), &s) == 0)) {
            if ((ptr->d_type == DT_DIR) && (((s.st_mode & S_ISGID) != S_ISGID) ||
                (static_cast<int32_t>(s.st_uid) != uid) || (static_cast<int32_t>(s.st_gid) != gid))) {
                APP_LOGI("dir :%{private}s need change mode, uid:%{public}d, gid:%{public}d,",
                    subPath.c_str(), uid, gid);
                if ((chown(subPath.c_str(), INSTALLS_UID, INSTALLS_UID) == 0) &&
                    (chmod(subPath.c_str(), s.st_mode | S_ISGID) == 0) &&
                    (chown(subPath.c_str(), uid, gid) == 0)) {
                    APP_LOGI("change %{private}s ownership success", subPath.c_str(), errno);
                } else {
                    APP_LOGE("chmod and chown path:%{public}s failed, errno:%{public}d", subPath.c_str(), errno);
                }
            }
            if ((ptr->d_type != DT_DIR) && ((static_cast<int32_t>(s.st_uid) != uid) ||
                (static_cast<int32_t>(s.st_gid) != gid))) {
                APP_LOGI("file: %{private}s need change uid %{public}d gid:%{public}d", subPath.c_str(), uid, gid);
                if (chown(subPath.c_str(), uid, gid) != 0) {
                    APP_LOGE("fail to change %{public}s ownership, uid=%{public}d, errno:%{public}d",
                        subPath.c_str(), uid, errno);
                }
            }
        }

        if (ptr->d_type == DT_DIR) {
            ret = ChangeDirPropertiesRecursively(subPath, uid, gid);
        }
    }
    closedir(dir);
    return ret;
}

bool InstalldOperator::ChangeFileAttr(const std::string &filePath, const int uid, const int gid)
{
    APP_LOGD("begin to change %{public}s file attribute", filePath.c_str());
    if (chown(filePath.c_str(), uid, gid) != 0) {
        APP_LOGE("fail to change %{public}s ownership, uid=%{public}d, errno:%{public}d",
            filePath.c_str(), uid, errno);
        return false;
    }
    APP_LOGD("change %{public}s file attribute successfully", filePath.c_str());
    return true;
}

bool InstalldOperator::RenameFile(const std::string &oldPath, const std::string &newPath)
{
    if (oldPath.empty() || newPath.empty()) {
        return false;
    }
    if (!DeleteDir(newPath)) {
        return false;
    }
    return rename(oldPath.c_str(), newPath.c_str()) == 0;
}

bool InstalldOperator::IsValidPath(const std::string &rootDir, const std::string &path)
{
    if (rootDir.find(Constants::PATH_SEPARATOR) != 0 ||
        rootDir.rfind(Constants::PATH_SEPARATOR) != (rootDir.size() - 1) || rootDir.find("..") != std::string::npos) {
        return false;
    }
    if (path.find("..") != std::string::npos) {
        return false;
    }
    return path.compare(0, rootDir.size(), rootDir) == 0;
}

bool InstalldOperator::IsValidCodePath(const std::string &codePath)
{
    if (codePath.empty()) {
        return false;
    }
    return IsValidPath(Constants::BUNDLE_BASE_CODE_DIR + Constants::PATH_SEPARATOR, codePath);
}

bool InstalldOperator::DeleteFiles(const std::string &dataPath)
{
    APP_LOGD("InstalldOperator::DeleteFiles start");
    std::string subPath;
    bool ret = true;
    DIR *dir = opendir(dataPath.c_str());
    if (dir == nullptr) {
        APP_LOGE("fail to opendir:%{public}s, errno:%{public}d", dataPath.c_str(), errno);
        return false;
    }
    while (true) {
        struct dirent *ptr = readdir(dir);
        if (ptr == nullptr) {
            APP_LOGE("fail to readdir errno:%{public}d", errno);
            break;
        }
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        subPath = OHOS::IncludeTrailingPathDelimiter(dataPath) + std::string(ptr->d_name);
        if (ptr->d_type == DT_DIR) {
            ret = OHOS::ForceRemoveDirectory(subPath);
        } else {
            if (access(subPath.c_str(), F_OK) == 0) {
                ret = OHOS::RemoveFile(subPath);
            }
        }
    }
    closedir(dir);
    return ret;
}

bool InstalldOperator::DeleteFilesExceptDirs(const std::string &dataPath, const std::vector<std::string> &dirsToKeep)
{
    APP_LOGD("InstalldOperator::DeleteFilesExceptBundleDataDirs start");
    std::string filePath;
    DIR *dir = opendir(dataPath.c_str());
    if (dir == nullptr) {
        APP_LOGE("fail to opendir:%{public}s, errno:%{public}d", dataPath.c_str(), errno);
        return false;
    }
    bool ret = true;
    while (true) {
        struct dirent *ptr = readdir(dir);
        if (ptr == nullptr) {
            APP_LOGE("fail to readdir errno:%{public}d", errno);
            break;
        }
        std::string dirName = Constants::PATH_SEPARATOR + std::string(ptr->d_name);
        if (std::find(dirsToKeep.begin(), dirsToKeep.end(), dirName) != dirsToKeep.end()) {
            continue;
        }
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        filePath = OHOS::IncludeTrailingPathDelimiter(dataPath) + std::string(ptr->d_name);
        if (ptr->d_type == DT_DIR) {
            ret = OHOS::ForceRemoveDirectory(filePath);
        } else {
            if (access(filePath.c_str(), F_OK) == 0) {
                ret = OHOS::RemoveFile(filePath);
            }
        }
    }
    closedir(dir);
    return ret;
}

bool InstalldOperator::MkOwnerDir(const std::string &path, bool isReadByOthers, const int uid, const int gid)
{
    if (!MkRecursiveDir(path, isReadByOthers)) {
        return false;
    }
    return ChangeFileAttr(path, uid, gid);
}

bool InstalldOperator::CheckPathIsSame(const std::string &path, int32_t mode, const int32_t uid, const int32_t gid,
    bool &isPathExist)
{
    struct stat s;
    if (stat(path.c_str(), &s) != 0) {
        APP_LOGD("path :%{public}s is not exist, need create, errno:%{public}d", path.c_str(), errno);
        isPathExist = false;
        return false;
    }
    isPathExist = true;
    if (((s.st_mode & MODE_BASE) == mode) && (static_cast<int32_t>(s.st_uid) == uid)
        && (static_cast<int32_t>(s.st_gid) == gid)) {
        APP_LOGD("path :%{public}s mode uid and gid are same, no need to create again", path.c_str());
        return true;
    }
    APP_LOGW("path:%{public}s exist, but mode uid or gid are not same, need to create again", path.c_str());
    return false;
}

bool InstalldOperator::MkOwnerDir(const std::string &path, int mode, const int uid, const int gid)
{
    bool isPathExist = false;
    if (CheckPathIsSame(path, mode, uid, gid, isPathExist)) {
        return true;
    }
    if (isPathExist) {
        if (chown(path.c_str(), INSTALLS_UID, INSTALLS_UID) != 0) {
            APP_LOGW("fail to change %{public}s ownership, errno:%{public}d", path.c_str(), errno);
        }
    }
    if (!OHOS::ForceCreateDirectory(path)) {
        APP_LOGE("mkdir failed, errno: %{public}d", errno);
        return false;
    }
    // only modify parent dir mode
    if (chmod(path.c_str(), mode) != 0) {
        APP_LOGE("chmod path:%{public}s mode:%{public}d failed, errno:%{public}d", path.c_str(), mode, errno);
        return false;
    }
    if (!ChangeDirOwnerRecursively(path, uid, gid)) {
        APP_LOGE("ChangeDirOwnerRecursively failed, errno: %{public}d", errno);
        return false;
    }
    return true;
}

int64_t InstalldOperator::GetDiskUsage(const std::string &dir, bool isRealPath)
{
    if (dir.empty() || (dir.size() > Constants::PATH_MAX_SIZE)) {
        APP_LOGE("GetDiskUsage dir path invalid");
        return 0;
    }
    std::string filePath = dir;
    if (!isRealPath && !PathToRealPath(dir, filePath)) {
        APP_LOGE("file is not real path, file path: %{public}s", dir.c_str());
        return 0;
    }
    DIR *dirPtr = opendir(filePath.c_str());
    if (dirPtr == nullptr) {
        APP_LOGE("GetDiskUsage open file dir:%{public}s is failure, errno:%{public}d", filePath.c_str(), errno);
        return 0;
    }
    if (filePath.back() != Constants::FILE_SEPARATOR_CHAR) {
        filePath.push_back(Constants::FILE_SEPARATOR_CHAR);
    }
    struct dirent *entry = nullptr;
    int64_t size = 0;
    while ((entry = readdir(dirPtr)) != nullptr) {
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }
        std::string path = filePath + entry->d_name;
        if (entry->d_type == DT_DIR) {
            size += GetDiskUsage(path, true);
            continue;
        }
        struct stat fileInfo = {0};
        if (stat(path.c_str(), &fileInfo) != 0) {
            APP_LOGE("call stat error %{public}s, errno:%{public}d", path.c_str(), errno);
            fileInfo.st_size = 0;
        }
        size += fileInfo.st_size;
    }
    closedir(dirPtr);
    return size;
}

void InstalldOperator::TraverseCacheDirectory(const std::string &currentPath, std::vector<std::string> &cacheDirs)
{
    if (currentPath.empty() || (currentPath.size() > Constants::PATH_MAX_SIZE)) {
        APP_LOGE("TraverseCacheDirectory current path invaild");
        return;
    }
    std::string filePath = "";
    if (!PathToRealPath(currentPath, filePath)) {
        APP_LOGE("file is not real path, file path: %{public}s", currentPath.c_str());
        return;
    }
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
        APP_LOGE("fail to opendir:%{public}s, errno:%{public}d", filePath.c_str(), errno);
        return;
    }
    if (filePath.back() != Constants::FILE_SEPARATOR_CHAR) {
        filePath.push_back(Constants::FILE_SEPARATOR_CHAR);
    }
    struct dirent *ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        if (ptr->d_type == DT_DIR && strcmp(ptr->d_name, Constants::CACHE_DIR) == 0) {
            std::string currentDir = filePath + std::string(ptr->d_name);
            cacheDirs.emplace_back(currentDir);
            continue;
        }
        if (ptr->d_type == DT_DIR) {
            std::string currentDir = filePath + std::string(ptr->d_name);
            TraverseCacheDirectory(currentDir, cacheDirs);
        }
    }
    closedir(dir);
}

int64_t InstalldOperator::GetDiskUsageFromPath(const std::vector<std::string> &path)
{
    int64_t fileSize = 0;
    for (auto &st : path) {
        fileSize += GetDiskUsage(st);
    }
    return fileSize;
}

bool InstalldOperator::InitialiseQuotaMounts()
{
    mQuotaReverseMounts.clear();
    std::ifstream mountsFile(PROC_MOUNTS_PATH);

    if (!mountsFile.is_open()) {
        APP_LOGE("Failed to open mounts file errno:%{public}d", errno);
        return false;
    }
    std::string line;

    while (std::getline(mountsFile, line)) {
        std::string device;
        std::string mountPoint;
        std::string fsType;
        std::istringstream lineStream(line);

        if (!(lineStream >> device >> mountPoint >> fsType)) {
            APP_LOGW("Failed to parse mounts file line: %{public}s", line.c_str());
            continue;
        }

        if (mountPoint == QUOTA_DEVICE_DATA_PATH) {
            struct dqblk dq;
            if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), device.c_str(), 0, reinterpret_cast<char*>(&dq)) == 0) {
                mQuotaReverseMounts[mountPoint] = device;
                APP_LOGD("InitialiseQuotaMounts, mountPoint: %{public}s, device: %{public}s", mountPoint.c_str(),
                    device.c_str());
            } else {
                APP_LOGW("InitialiseQuotaMounts, Failed to get quotactl, errno: %{public}d", errno);
            }
        }
    }
    return true;
}

int64_t InstalldOperator::GetDiskUsageFromQuota(const int32_t uid)
{
    std::lock_guard<std::recursive_mutex> lock(mMountsLock);
    std::string device = "";
    if (mQuotaReverseMounts.find(QUOTA_DEVICE_DATA_PATH) == mQuotaReverseMounts.end()) {
        if (!InitialiseQuotaMounts()) {
            APP_LOGE("Failed to initialise quota mounts");
            return 0;
        }
    }
    device = mQuotaReverseMounts[QUOTA_DEVICE_DATA_PATH];
    if (device.empty()) {
        APP_LOGW("skip when device no quotas present");
        return 0;
    }
    struct dqblk dq;
    if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), device.c_str(), uid, reinterpret_cast<char*>(&dq)) != 0) {
        APP_LOGE("Failed to get quotactl, errno: %{public}d", errno);
        return 0;
    }
    APP_LOGD("get disk usage from quota, uid: %{public}d, usage: %{public}llu",
        uid, static_cast<unsigned long long>(dq.dqb_curspace));
    return dq.dqb_curspace;
}

bool InstalldOperator::ScanDir(
    const std::string &dirPath, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
{
    if (dirPath.empty() || (dirPath.size() > Constants::PATH_MAX_SIZE)) {
        APP_LOGE("Scan dir path invaild");
        return false;
    }

    std::string realPath = "";
    if (!PathToRealPath(dirPath, realPath)) {
        APP_LOGE("file(%{public}s) is not real path", dirPath.c_str());
        return false;
    }

    DIR* dir = opendir(realPath.c_str());
    if (dir == nullptr) {
        APP_LOGE("Scan open dir(%{public}s) fail, errno:%{public}d", realPath.c_str(), errno);
        return false;
    }

    struct dirent *ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }

        std::string subName(ptr->d_name);
        if (scanMode == ScanMode::SUB_FILE_DIR) {
            if (ptr->d_type == DT_DIR) {
                paths.emplace_back(HandleScanResult(dirPath, subName, resultMode));
            }

            continue;
        }

        if (scanMode == ScanMode::SUB_FILE_FILE) {
            if (ptr->d_type == DT_REG) {
                paths.emplace_back(HandleScanResult(dirPath, subName, resultMode));
            }

            continue;
        }

        paths.emplace_back(HandleScanResult(dirPath, subName, resultMode));
    }

    closedir(dir);
    return true;
}

bool InstalldOperator::ScanSoFiles(const std::string &newSoPath, const std::string &originPath,
    const std::string &currentPath, std::vector<std::string> &paths)
{
    if (currentPath.empty() || (currentPath.size() > Constants::PATH_MAX_SIZE)) {
        APP_LOGE("ScanSoFiles current path invalid");
        return false;
    }
    std::string filePath = "";
    if (!PathToRealPath(currentPath, filePath)) {
        APP_LOGE("file is not real path, file path: %{public}s", currentPath.c_str());
        return false;
    }
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
        APP_LOGE("ScanSoFiles open dir(%{public}s) fail, errno:%{public}d", filePath.c_str(), errno);
        return false;
    }
    if (filePath.back() != Constants::FILE_SEPARATOR_CHAR) {
        filePath.push_back(Constants::FILE_SEPARATOR_CHAR);
    }
    struct dirent *ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        if (ptr->d_type == DT_DIR) {
            std::string currentDir = filePath + std::string(ptr->d_name);
            if (!ScanSoFiles(newSoPath, originPath, currentDir, paths)) {
                closedir(dir);
                return false;
            }
        }
        if (ptr->d_type == DT_REG) {
            std::string currentFile = filePath + std::string(ptr->d_name);
            std::string prefixPath = originPath;
            if (prefixPath.back() != Constants::FILE_SEPARATOR_CHAR) {
                prefixPath.push_back(Constants::FILE_SEPARATOR_CHAR);
            }
            std::string relativePath = currentFile.substr(prefixPath.size());
            paths.emplace_back(relativePath);
            std::string subNewSoPath = GetPathDir(newSoPath + Constants::PATH_SEPARATOR + relativePath);
            if (!IsExistDir(subNewSoPath) && !MkRecursiveDir(subNewSoPath, true)) {
                APP_LOGE("ScanSoFiles create subNewSoPath (%{public}s) failed", filePath.c_str());
                closedir(dir);
                return false;
            }
        }
    }
    closedir(dir);
    return true;
}

bool InstalldOperator::CopyFile(
    const std::string &sourceFile, const std::string &destinationFile)
{
    if (sourceFile.empty() || destinationFile.empty()) {
        APP_LOGE("Copy file failed due to sourceFile or destinationFile is empty");
        return false;
    }

    std::ifstream in(sourceFile);
    if (!in.is_open()) {
        APP_LOGE("Copy file failed due to open sourceFile %{private}s failed errno:%{public}d",
            sourceFile.c_str(), errno);
        return false;
    }

    std::ofstream out(destinationFile);
    if (!out.is_open()) {
        APP_LOGE("Copy file failed due to open destinationFile %{private}s failed errno:%{public}d",
            destinationFile.c_str(), errno);
        in.close();
        return false;
    }

    out << in.rdbuf();
    in.close();
    out.close();
    return true;
}

bool InstalldOperator::CopyFileFast(const std::string &sourcePath, const std::string &destPath)
{
    APP_LOGD("begin");
    return BundleUtil::CopyFileFast(sourcePath, destPath);
}

bool InstalldOperator::ExtractDiffFiles(const std::string &filePath, const std::string &targetPath,
    const std::string &cpuAbi)
{
    BundleExtractor extractor(filePath);
    if (!extractor.Init()) {
        return false;
    }
    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames)) {
        return false;
    }
    for (const auto &entryName : entryNames) {
        if (strcmp(entryName.c_str(), ".") == 0 ||
            strcmp(entryName.c_str(), "..") == 0) {
            continue;
        }
        if (entryName.back() == Constants::PATH_SEPARATOR[0]) {
            continue;
        }
        // handle diff file
        if (IsDiffFiles(entryName, targetPath, cpuAbi)) {
            ExtractTargetFile(extractor, entryName, targetPath, cpuAbi);
        }
    }
    return true;
}

bool InstalldOperator::OpenHandle(void **handle)
{
    APP_LOGI("InstalldOperator::OpenHandle start");
    if (handle == nullptr) {
        APP_LOGE("InstalldOperator::OpenHandle error handle is nullptr.");
        return false;
    }
    *handle = dlopen(LIB64_DIFF_PATCH_SHARED_SO_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (*handle == nullptr) {
        APP_LOGW("ApplyDiffPatch failed to open libdiff_patch_shared.z.so, err:%{public}s", dlerror());
        *handle = dlopen(LIB_DIFF_PATCH_SHARED_SO_PATH, RTLD_NOW | RTLD_GLOBAL);
    }
    if (*handle == nullptr) {
        APP_LOGE("ApplyDiffPatch failed to open libdiff_patch_shared.z.so, err:%{public}s", dlerror());
        return false;
    }
    APP_LOGI("InstalldOperator::OpenHandle end");
    return true;
}

void InstalldOperator::CloseHandle(void **handle)
{
    APP_LOGI("InstalldOperator::CloseHandle start");
    if ((handle != nullptr) && (*handle != nullptr)) {
        dlclose(*handle);
        *handle = nullptr;
        APP_LOGD("InstalldOperator::CloseHandle, err:%{public}s", dlerror());
    }
    APP_LOGI("InstalldOperator::CloseHandle end");
}

bool InstalldOperator::ProcessApplyDiffPatchPath(
    const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, std::vector<std::string> &oldSoFileNames, std::vector<std::string> &diffFileNames)
{
    APP_LOGI("ProcessApplyDiffPatchPath oldSoPath: %{public}s, diffFilePath: %{public}s, newSoPath: %{public}s",
        oldSoPath.c_str(), diffFilePath.c_str(), newSoPath.c_str());
    if (oldSoPath.empty() || diffFilePath.empty() || newSoPath.empty()) {
        return false;
    }
    if (!IsExistDir(oldSoPath) || !IsExistDir(diffFilePath)) {
        APP_LOGE("ProcessApplyDiffPatchPath oldSoPath or diffFilePath not exist");
        return false;
    }

    if (!ScanSoFiles(newSoPath, oldSoPath, oldSoPath, oldSoFileNames)) {
        APP_LOGE("ProcessApplyDiffPatchPath ScanSoFiles oldSoPath failed");
        return false;
    }

    if (!ScanSoFiles(newSoPath, diffFilePath, diffFilePath, diffFileNames)) {
        APP_LOGE("ProcessApplyDiffPatchPath ScanSoFiles diffFilePath failed");
        return false;
    }

    if (oldSoFileNames.empty() || diffFileNames.empty()) {
        APP_LOGE("ProcessApplyDiffPatchPath so or diff files empty");
        return false;
    }

    if (!IsExistDir(newSoPath)) {
        APP_LOGD("ProcessApplyDiffPatchPath create newSoPath");
        if (!MkRecursiveDir(newSoPath, true)) {
            APP_LOGE("ProcessApplyDiffPatchPath create newSo dir (%{public}s) failed", newSoPath.c_str());
            return false;
        }
    }
    APP_LOGI("ProcessApplyDiffPatchPath end");
    return true;
}

bool InstalldOperator::ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, int32_t uid)
{
    APP_LOGI("ApplyDiffPatch start");
    std::vector<std::string> oldSoFileNames;
    std::vector<std::string> diffFileNames;
    if (InstalldOperator::IsDirEmpty(oldSoPath) || InstalldOperator::IsDirEmpty(diffFilePath)) {
        APP_LOGD("oldSoPath or diffFilePath is empty, not require ApplyPatch");
        return true;
    }
    if (!ProcessApplyDiffPatchPath(oldSoPath, diffFilePath, newSoPath, oldSoFileNames, diffFileNames)) {
        APP_LOGE("ApplyDiffPatch ProcessApplyDiffPatchPath failed");
        return false;
    }
    std::string realOldSoPath;
    std::string realDiffFilePath;
    std::string realNewSoPath;
    if (!PathToRealPath(oldSoPath, realOldSoPath) || !PathToRealPath(diffFilePath, realDiffFilePath) ||
        !PathToRealPath(newSoPath, realNewSoPath)) {
        APP_LOGE("ApplyDiffPatch Path is not real path");
        return false;
    }
    void *handle = nullptr;
    if (!OpenHandle(&handle)) {
        return false;
    }
    auto applyPatch = reinterpret_cast<ApplyPatch>(dlsym(handle, APPLY_PATCH_FUNCTION_NAME));
    if (applyPatch == nullptr) {
        APP_LOGE("ApplyDiffPatch failed to get applyPatch err:%{public}s", dlerror());
        CloseHandle(&handle);
        return false;
    }
    std::vector<std::string> newSoList;
    for (const auto &diffFileName : diffFileNames) {
        std::string soFileName = diffFileName.substr(0, diffFileName.rfind(Constants::DIFF_SUFFIX));
        APP_LOGD("ApplyDiffPatch soName: %{public}s, diffName: %{public}s", soFileName.c_str(), diffFileName.c_str());
        if (find(oldSoFileNames.begin(), oldSoFileNames.end(), soFileName) != oldSoFileNames.end()) {
            int32_t ret = applyPatch(realDiffFilePath + Constants::PATH_SEPARATOR + diffFileName,
                                     realOldSoPath + Constants::PATH_SEPARATOR + soFileName,
                                     realNewSoPath + Constants::PATH_SEPARATOR + soFileName);
            if (ret != ERR_OK) {
                APP_LOGE("ApplyDiffPatch failed, applyPatch errcode: %{public}d", ret);
                for (const auto &file : newSoList) {
                    DeleteDir(file);
                }
                CloseHandle(&handle);
                return false;
            }
            newSoList.emplace_back(realNewSoPath + Constants::PATH_SEPARATOR + soFileName);
        }
    }
    CloseHandle(&handle);
#if defined(CODE_ENCRYPTION_ENABLE)
    RemoveEncryptedKey(uid, newSoList);
#endif
    APP_LOGI("ApplyDiffPatch end");
    return true;
}

bool InstalldOperator::ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &fileVec)
{
    if (dir.empty()) {
        APP_LOGE("ObtainQuickFixFileDir dir path invaild");
        return false;
    }

    std::string realPath = "";
    if (!PathToRealPath(dir, realPath)) {
        APP_LOGE("dir(%{public}s) is not real path", dir.c_str());
        return false;
    }

    DIR* directory = opendir(realPath.c_str());
    if (directory == nullptr) {
        APP_LOGE("ObtainQuickFixFileDir open dir(%{public}s) fail, errno:%{public}d", realPath.c_str(), errno);
        return false;
    }

    struct dirent *ptr = nullptr;
    while ((ptr = readdir(directory)) != nullptr) {
        std::string currentName(ptr->d_name);
        if (currentName.compare(".") == 0 || currentName.compare("..") == 0) {
            continue;
        }

        std::string curPath = dir + Constants::PATH_SEPARATOR + currentName;
        struct stat s;
        if (stat(curPath.c_str(), &s) == 0) {
            // directory
            if (s.st_mode & S_IFDIR) {
                ObtainQuickFixFileDir(curPath, fileVec);
            }

            // file
            if ((s.st_mode & S_IFREG) &&
                (currentName.find(Constants::QUICK_FIX_FILE_SUFFIX) != std::string::npos)) {
                    fileVec.emplace_back(dir);
                }
        }
    }
    closedir(directory);
    return true;
}

bool InstalldOperator::CopyFiles(const std::string &sourceDir, const std::string &destinationDir)
{
    APP_LOGD("sourceDir is %{public}s, destinationDir is %{public}s", sourceDir.c_str(), destinationDir.c_str());
    if (sourceDir.empty() || destinationDir.empty()) {
        APP_LOGE("Copy file failed due to sourceDir or destinationDir is empty");
        return false;
    }

    std::string realPath = "";
    if (!PathToRealPath(sourceDir, realPath)) {
        APP_LOGE("sourceDir(%{public}s) is not real path", sourceDir.c_str());
        return false;
    }

    DIR* directory = opendir(realPath.c_str());
    if (directory == nullptr) {
        APP_LOGE("CopyFiles open dir(%{public}s) fail, errno:%{public}d", realPath.c_str(), errno);
        return false;
    }

    struct dirent *ptr = nullptr;
    while ((ptr = readdir(directory)) != nullptr) {
        std::string currentName(ptr->d_name);
        if (currentName.compare(".") == 0 || currentName.compare("..") == 0) {
            continue;
        }

        std::string curPath = sourceDir + Constants::PATH_SEPARATOR + currentName;
        struct stat s;
        if ((stat(curPath.c_str(), &s) == 0) && (s.st_mode & S_IFREG)) {
            std::string innerDesStr = destinationDir + Constants::PATH_SEPARATOR + currentName;
            if (CopyFile(curPath, innerDesStr)) {
                ChangeFileAttr(innerDesStr, Constants::FOUNDATION_UID, Constants::BMS_GID);
            }
        }
    }
    closedir(directory);
    return true;
}

bool InstalldOperator::GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
    std::vector<std::string> &fileNames)
{
    BundleExtractor extractor(filePath);
    if (!extractor.Init()) {
        return false;
    }
    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames)) {
        return false;
    }
    std::string prefix = Constants::LIBS + cpuAbi + Constants::PATH_SEPARATOR;
    for (const auto &entryName : entryNames) {
        if (StartsWith(entryName, prefix) && EndsWith(entryName, Constants::SO_SUFFIX)) {
            fileNames.push_back(entryName.substr(prefix.length(), entryName.length()));
        }
    }
    APP_LOGD("InstalldOperator::GetNativeLibraryFileNames end");
    return true;
}

#if defined(CODE_SIGNATURE_ENABLE)
bool InstalldOperator::PrepareEntryMap(const CodeSignatureParam &codeSignatureParam,
    const std::vector<std::string> &soEntryFiles, Security::CodeSign::EntryMap &entryMap)
{
    if (codeSignatureParam.targetSoPath.empty()) {
        return false;
    }
    const std::string prefix = Constants::LIBS + codeSignatureParam.cpuAbi + Constants::PATH_SEPARATOR;
    for_each(soEntryFiles.begin(), soEntryFiles.end(),
        [&entryMap, &prefix, &codeSignatureParam](const auto &entry) {
        std::string fileName = entry.substr(prefix.length());
        std::string path = codeSignatureParam.targetSoPath;
        if (path.back() != Constants::FILE_SEPARATOR_CHAR) {
            path += Constants::FILE_SEPARATOR_CHAR;
        }
        entryMap.emplace(entry, path + fileName);
        APP_LOGD("VerifyCode the targetSoPath is %{public}s", (path + fileName).c_str());
    });
    return true;
}

ErrCode InstalldOperator::PerformCodeSignatureCheck(const CodeSignatureParam &codeSignatureParam,
    const Security::CodeSign::EntryMap &entryMap)
{
    ErrCode ret = ERR_OK;
    if (codeSignatureParam.isCompileSdkOpenHarmony &&
        !Security::CodeSign::CodeSignUtils::IsSupportOHCodeSign()) {
        APP_LOGD("code signature is not supported");
        return ret;
    }
    if (codeSignatureParam.signatureFileDir.empty()) {
        std::shared_ptr<CodeSignHelper> codeSignHelper = std::make_shared<CodeSignHelper>();
        Security::CodeSign::FileType fileType = codeSignatureParam.isPreInstalledBundle ?
            FILE_ENTRY_ONLY : FILE_ENTRY_ADD;
        if (codeSignatureParam.isEnterpriseBundle) {
            APP_LOGD("Verify code signature for enterprise bundle");
            ret = codeSignHelper->EnforceCodeSignForAppWithOwnerId(codeSignatureParam.appIdentifier,
                codeSignatureParam.modulePath, entryMap, fileType);
        } else {
            APP_LOGD("Verify code signature for non-enterprise bundle");
            ret = codeSignHelper->EnforceCodeSignForApp(codeSignatureParam.modulePath, entryMap, fileType);
        }
        APP_LOGI("Verify code signature for hap %{public}s", codeSignatureParam.modulePath.c_str());
    } else {
        ret = CodeSignUtils::EnforceCodeSignForApp(entryMap, codeSignatureParam.signatureFileDir);
    }
    return ret;
}
#endif

bool InstalldOperator::VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam)
{
    BundleExtractor extractor(codeSignatureParam.modulePath);
    if (!extractor.Init()) {
        return false;
    }

    std::vector<std::string> soEntryFiles;
    if (!ObtainNativeSoFile(extractor, codeSignatureParam.cpuAbi, soEntryFiles)) {
        return false;
    }

    if (soEntryFiles.empty()) {
        return true;
    }

#if defined(CODE_SIGNATURE_ENABLE)
    Security::CodeSign::EntryMap entryMap;
    if (!PrepareEntryMap(codeSignatureParam, soEntryFiles, entryMap)) {
        return false;
    }

    ErrCode ret = PerformCodeSignatureCheck(codeSignatureParam, entryMap);
    if (ret == VerifyErrCode::CS_CODE_SIGN_NOT_EXISTS) {
        APP_LOGW("no code sign file in the bundle");
        return true;
    }
    if (ret != ERR_OK) {
        APP_LOGE("VerifyCode failed due to %{public}d", ret);
        return false;
    }
#endif
    return true;
}

bool InstalldOperator::CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    APP_LOGD("process check encryption of src path %{public}s", checkEncryptionParam.modulePath.c_str());
    if (checkEncryptionParam.cpuAbi.empty() && checkEncryptionParam.targetSoPath.empty()) {
        return CheckHapEncryption(checkEncryptionParam, isEncryption);
    }
    const std::string cpuAbi = checkEncryptionParam.cpuAbi;
    const int32_t bundleId = checkEncryptionParam.bundleId;
    InstallBundleType installBundleType = checkEncryptionParam.installBundleType;
    const bool isCompressNativeLibrary = checkEncryptionParam.isCompressNativeLibrary;
    APP_LOGD("CheckEncryption: bundleId %{public}d, installBundleType %{public}d, isCompressNativeLibrary %{public}d",
        bundleId, installBundleType, isCompressNativeLibrary);

    BundleExtractor extractor(checkEncryptionParam.modulePath);
    if (!extractor.Init()) {
        return false;
    }

    std::vector<std::string> soEntryFiles;
    if (!ObtainNativeSoFile(extractor, cpuAbi, soEntryFiles)) {
        APP_LOGE("ObtainNativeSoFile failed");
        return false;
    }

    if (soEntryFiles.empty()) {
        APP_LOGD("no so file in installation file %{public}s", checkEncryptionParam.modulePath.c_str());
        return true;
    }

#if defined(CODE_ENCRYPTION_ENABLE)
    const std::string targetSoPath = checkEncryptionParam.targetSoPath;
    Security::CodeCrypto::EntryMap entryMap;
    entryMap.emplace(Constants::CODE_SIGNATURE_HAP, checkEncryptionParam.modulePath);
    if (!targetSoPath.empty()) {
        const std::string prefix = Constants::LIBS + cpuAbi + Constants::PATH_SEPARATOR;
        std::for_each(soEntryFiles.begin(), soEntryFiles.end(), [&entryMap, &prefix, &targetSoPath](const auto &entry) {
            std::string fileName = entry.substr(prefix.length());
            std::string path = targetSoPath;
            if (path.back() != Constants::FILE_SEPARATOR_CHAR) {
                path += Constants::FILE_SEPARATOR_CHAR;
            }
            entryMap.emplace(entry, path + fileName);
            APP_LOGD("CheckEncryption the targetSoPath is %{public}s", (path + fileName).c_str());
        });
    }
    ErrCode ret = Security::CodeCrypto::CodeCryptoUtils::EnforceMetadataProcessForApp(entryMap, bundleId,
        isEncryption, static_cast<Security::CodeCrypto::CodeCryptoUtils::InstallBundleType>(installBundleType),
        isCompressNativeLibrary);
    if (ret != ERR_OK) {
        APP_LOGE("CheckEncryption failed due to %{public}d", ret);
        return false;
    }
#endif
    return true;
}

bool InstalldOperator::CheckHapEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    const std::string hapPath = checkEncryptionParam.modulePath;
    const int32_t bundleId = checkEncryptionParam.bundleId;
    InstallBundleType installBundleType = checkEncryptionParam.installBundleType;
    const bool isCompressNativeLibrary = checkEncryptionParam.isCompressNativeLibrary;
    APP_LOGD("CheckHapEncryption the hapPath is %{public}s, installBundleType is %{public}d, "
        "bundleId is %{public}d, isCompressNativeLibrary is %{public}d", hapPath.c_str(),
        installBundleType, bundleId, isCompressNativeLibrary);
#if defined(CODE_ENCRYPTION_ENABLE)
    Security::CodeCrypto::EntryMap entryMap;
    entryMap.emplace(Constants::CODE_SIGNATURE_HAP, hapPath);
    ErrCode ret = Security::CodeCrypto::CodeCryptoUtils::EnforceMetadataProcessForApp(entryMap, bundleId,
        isEncryption, static_cast<Security::CodeCrypto::CodeCryptoUtils::InstallBundleType>(installBundleType),
        isCompressNativeLibrary);
    if (ret != ERR_OK) {
        APP_LOGE("CheckEncryption failed due to %{public}d", ret);
        return false;
    }
#endif
    return true;
}

bool InstalldOperator::ObtainNativeSoFile(const BundleExtractor &extractor, const std::string &cpuAbi,
    std::vector<std::string> &soEntryFiles)
{
    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames)) {
        APP_LOGE("GetZipFileNames failed");
        return false;
    }
    if (entryNames.empty()) {
        APP_LOGE("entryNames is empty");
        return false;
    }

    for (const auto &entryName : entryNames) {
        if (strcmp(entryName.c_str(), ".") == 0 ||
            strcmp(entryName.c_str(), "..") == 0) {
            continue;
        }
        if (entryName.back() == Constants::PATH_SEPARATOR[0]) {
            continue;
        }
        // save native so file entryName in the hap
        if (IsNativeSo(entryName, cpuAbi)) {
            soEntryFiles.emplace_back(entryName);
            continue;
        }
    }

    if (soEntryFiles.empty()) {
        APP_LOGD("no so file in installation file");
    }
    return true;
}

bool InstalldOperator::MoveFiles(const std::string &srcDir, const std::string &desDir, bool isDesDirNeedCreated)
{
    APP_LOGD("srcDir is %{public}s, desDir is %{public}s", srcDir.c_str(), desDir.c_str());
    if (isDesDirNeedCreated && !MkRecursiveDir(desDir, true)) {
        APP_LOGE("create desDir failed");
        return false;
    }

    if (srcDir.empty() || desDir.empty()) {
        APP_LOGE("move file failed due to srcDir or desDir is empty");
        return false;
    }

    std::string realPath = "";
    if (!PathToRealPath(srcDir, realPath)) {
        APP_LOGE("srcDir(%{public}s) is not real path", srcDir.c_str());
        return false;
    }

    std::string realDesDir = "";
    if (!PathToRealPath(desDir, realDesDir)) {
        APP_LOGE("desDir(%{public}s) is not real path", desDir.c_str());
        return false;
    }

    DIR* directory = opendir(realPath.c_str());
    if (directory == nullptr) {
        APP_LOGE("MoveFiles open dir(%{public}s) fail, errno:%{public}d", realPath.c_str(), errno);
        return false;
    }

    struct dirent *ptr = nullptr;
    while ((ptr = readdir(directory)) != nullptr) {
        std::string currentName(ptr->d_name);
        if (currentName.compare(".") == 0 || currentName.compare("..") == 0) {
            continue;
        }

        std::string curPath = realPath + Constants::PATH_SEPARATOR + currentName;
        std::string innerDesStr = realDesDir + Constants::PATH_SEPARATOR + currentName;
        struct stat s;
        if (stat(curPath.c_str(), &s) != 0) {
            APP_LOGD("MoveFiles stat %{public}s failed, errno:%{public}d", curPath.c_str(), errno);
            continue;
        }
        if (!MoveFileOrDir(curPath, innerDesStr, s.st_mode)) {
            closedir(directory);
            return false;
        }
    }
    closedir(directory);
    return true;
}

bool InstalldOperator::MoveFileOrDir(const std::string &srcPath, const std::string &destPath, mode_t mode)
{
    if (mode & S_IFREG) {
        APP_LOGD("srcPath(%{public}s) is a file", srcPath.c_str());
        return MoveFile(srcPath, destPath);
    } else if (mode & S_IFDIR) {
        APP_LOGD("srcPath(%{public}s) is a dir", srcPath.c_str());
        return MoveFiles(srcPath, destPath, true);
    }
    return true;
}

bool InstalldOperator::MoveFile(const std::string &srcPath, const std::string &destPath)
{
    APP_LOGD("srcPath is %{public}s, destPath is %{public}s", srcPath.c_str(), destPath.c_str());
    if (!RenameFile(srcPath, destPath)) {
        APP_LOGE("move file from srcPath(%{public}s) to destPath(%{public}s) failed", srcPath.c_str(),
            destPath.c_str());
        return false;
    }
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!OHOS::ChangeModeFile(destPath, mode)) {
        APP_LOGE("change mode failed");
        return false;
    }
    return true;
}

bool InstalldOperator::ExtractResourceFiles(const ExtractParam &extractParam, const BundleExtractor &extractor)
{
    APP_LOGD("ExtractResourceFiles begin");
    std::string targetDir = extractParam.targetPath;
    if (!MkRecursiveDir(targetDir, true)) {
        APP_LOGE("create targetDir failed");
        return false;
    }
    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames)) {
        APP_LOGE("GetZipFileNames failed");
        return false;
    }
    for (const auto &entryName : entryNames) {
        if (StartsWith(entryName, Constants::LIBS)
            || StartsWith(entryName, Constants::AN)
            || StartsWith(entryName, Constants::AP)) {
            continue;
        }
        const std::string relativeDir = GetPathDir(entryName);
        if (!relativeDir.empty()) {
            if (!MkRecursiveDir(targetDir + relativeDir, true)) {
                APP_LOGE("MkRecursiveDir failed");
                return false;
            }
        }
        std::string filePath = targetDir + entryName;
        if (!extractor.ExtractFile(entryName, filePath)) {
            APP_LOGE("ExtractFile failed");
            continue;
        }
        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        if (!OHOS::ChangeModeFile(filePath, mode)) {
            APP_LOGE("change mode failed");
            return false;
        }
    }
    APP_LOGD("ExtractResourceFiles success");
    return true;
}

bool InstalldOperator::ExtractDriverSoFiles(const std::string &srcPath,
    const std::unordered_multimap<std::string, std::string> &dirMap)
{
    APP_LOGD("ExtractDriverSoFiles start with src(%{public}s)", srcPath.c_str());
    if (srcPath.empty() || dirMap.empty()) {
        APP_LOGE("ExtractDriverSoFiles parameters are invalid");
        return false;
    }
    BundleExtractor extractor(srcPath);
    if (!extractor.Init()) {
        APP_LOGE("extractor init failed");
        return false;
    }

    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames)) {
        APP_LOGE("GetZipFileNames failed");
        return false;
    }

    for (auto &[originalDir, destinedDir] : dirMap) {
        if ((originalDir.compare(".") == 0) || (originalDir.compare("..") == 0)) {
            APP_LOGE("the originalDir %{public}s is not existed in the hap", originalDir.c_str());
            return false;
        }
        if (!BundleUtil::StartWith(originalDir, PREFIX_RESOURCE_PATH) ||
            !BundleUtil::StartWith(destinedDir, PREFIX_TARGET_PATH)) {
            APP_LOGE("the originalDir %{public}s and destined dir %{public}s are invalid", originalDir.c_str(),
                destinedDir.c_str());
            return false;
        }
        std::string innerOriginalDir = originalDir;
        if (innerOriginalDir.front() == Constants::PATH_SEPARATOR[0]) {
            innerOriginalDir = innerOriginalDir.substr(1);
        }
        if (find(entryNames.cbegin(), entryNames.cend(), innerOriginalDir) == entryNames.cend()) {
            APP_LOGE("the innerOriginalDir %{public}s is not existed in the hap", innerOriginalDir.c_str());
            return false;
        }
        std::string systemServiceDir = Constants::SYSTEM_SERVICE_DIR;
        if (!CopyDriverSoFiles(extractor, innerOriginalDir, systemServiceDir + destinedDir)) {
            APP_LOGE("CopyDriverSoFiles failed");
            return false;
        }
    }
    APP_LOGD("ExtractDriverSoFiles end");
    return true;
}

bool InstalldOperator::CopyDriverSoFiles(const BundleExtractor &extractor, const std::string &originalDir,
    const std::string &destinedDir)
{
    APP_LOGD("CopyDriverSoFiles beign");
    auto pos = destinedDir.rfind(Constants::PATH_SEPARATOR);
    if ((pos == std::string::npos) || (pos == destinedDir.length() -1)) {
        APP_LOGE("destinedDir(%{public}s) is invalid path", destinedDir.c_str());
        return false;
    }
    std::string desDir = destinedDir.substr(0, pos);
    std::string realDesDir;
    if (!PathToRealPath(desDir, realDesDir)) {
        APP_LOGE("desDir(%{public}s) is not real path", desDir.c_str());
        return false;
    }
    std::string realDestinedDir = realDesDir + destinedDir.substr(pos);
    APP_LOGD("realDestinedDir is %{public}s", realDestinedDir.c_str());
    if (!extractor.ExtractFile(originalDir, realDestinedDir)) {
        APP_LOGE("ExtractFile failed");
        return false;
    }

    struct stat buf = {};
    if (stat(realDesDir.c_str(), &buf) != 0) {
        APP_LOGE("failed to obtain the stat status of realDesDir %{public}s, errno:%{public}d",
            realDesDir.c_str(), errno);
        return false;
    }
    ChangeFileAttr(realDestinedDir, buf.st_uid, buf.st_gid);
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!OHOS::ChangeModeFile(realDestinedDir, mode)) {
        return false;
    }
    APP_LOGD("CopyDriverSoFiles end");
    return true;
}

#if defined(CODE_ENCRYPTION_ENABLE)
ErrCode InstalldOperator::ExtractSoFilesToTmpHapPath(const std::string &hapPath, const std::string &cpuAbi,
    const std::string &tmpSoPath, int32_t uid)
{
    APP_LOGD("start to obtain decoded so files from hapPath %{public}s", hapPath.c_str());
    BundleExtractor extractor(hapPath);
    if (!extractor.Init()) {
        APP_LOGE("init bundle extractor failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    /* obtain the so list in the hap */
    std::vector<std::string> soEntryFiles;
    if (!ObtainNativeSoFile(extractor, cpuAbi, soEntryFiles)) {
        APP_LOGE("ExtractFiles obtain native so file entryName failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    std::string innerTmpSoPath = tmpSoPath;
    if (innerTmpSoPath.back() != Constants::PATH_SEPARATOR[0]) {
        innerTmpSoPath += Constants::PATH_SEPARATOR;
    }

    /* create innerTmpSoPath */
    if (!IsExistDir(innerTmpSoPath)) {
        if (!MkRecursiveDir(innerTmpSoPath, true)) {
            APP_LOGE("create innerTmpSoPath %{public}s failed", innerTmpSoPath.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }

    for (const auto &entry : soEntryFiles) {
        APP_LOGD("entryName is %{public}s", entry.c_str());
        auto pos = entry.rfind(Constants::PATH_SEPARATOR[0]);
        if (pos == std::string::npos) {
            APP_LOGW("invalid so entry %{public}s", entry.c_str());
            continue;
        }
        std::string soFileName = entry.substr(pos + 1);
        if (soFileName.empty()) {
            APP_LOGW("invalid so entry %{public}s", entry.c_str());
            continue;
        }
        APP_LOGD("so file is %{public}s", soFileName.c_str());
        uint32_t offset = 0;
        uint32_t length = 0;
        if (!extractor.GetFileInfo(entry, offset, length) || length == 0) {
            APP_LOGW("GetFileInfo failed or invalid so file");
            continue;
        }
        APP_LOGD("so file %{public}s has offset %{public}d and file size %{public}d", entry.c_str(), offset, length);

        /* mmap so to ram and write so file to temp path */
        ErrCode res = ERR_OK;
        if ((res = DecryptSoFile(hapPath, innerTmpSoPath + soFileName, uid, length, offset)) != ERR_OK) {
            APP_LOGE("decrypt file failed, srcPath is %{public}s and destPath is %{public}s", hapPath.c_str(),
                (innerTmpSoPath + soFileName).c_str());
            return res;
        }
    }

    return ERR_OK;
}

ErrCode InstalldOperator::ExtractSoFilesToTmpSoPath(const std::string &hapPath, const std::string &realSoFilesPath,
    const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid)
{
    APP_LOGD("start to obtain decoded so files from so path");
    if (realSoFilesPath.empty()) {
        APP_LOGE("real so file path is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
    }
    BundleExtractor extractor(hapPath);
    if (!extractor.Init()) {
        APP_LOGE("init bundle extractor failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    /* obtain the so list in the hap */
    std::vector<std::string> soEntryFiles;
    if (!ObtainNativeSoFile(extractor, cpuAbi, soEntryFiles)) {
        APP_LOGE("ExtractFiles obtain native so file entryName failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    std::string innerTmpSoPath = tmpSoPath;
    if (innerTmpSoPath.back() != Constants::PATH_SEPARATOR[0]) {
        innerTmpSoPath += Constants::PATH_SEPARATOR;
    }
    // create innerTmpSoPath
    if (!IsExistDir(innerTmpSoPath)) {
        if (!MkRecursiveDir(innerTmpSoPath, true)) {
            APP_LOGE("create innerTmpSoPath %{public}s failed", innerTmpSoPath.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }

    for (const auto &entry : soEntryFiles) {
        auto pos = entry.rfind(Constants::PATH_SEPARATOR[0]);
        if (pos == std::string::npos) {
            APP_LOGW("invalid so entry %{public}s", entry.c_str());
            continue;
        }
        std::string soFileName = entry.substr(pos + 1);
        if (soFileName.empty()) {
            APP_LOGW("invalid so entry %{public}s", entry.c_str());
            continue;
        }

        std::string soPath = realSoFilesPath + soFileName;
        APP_LOGD("real path of the so file %{public}s is %{public}s", soFileName.c_str(), soPath.c_str());

        if (IsExistFile(soPath)) {
            /* mmap so file to ram and write to innerTmpSoPath */
            ErrCode res = ERR_OK;
            APP_LOGD("tmp so path is %{public}s", (innerTmpSoPath + soFileName).c_str());
            if ((res = DecryptSoFile(soPath, innerTmpSoPath + soFileName, uid, 0, 0)) != ERR_OK) {
                APP_LOGE("decrypt file failed, srcPath is %{public}s and destPath is %{public}s", soPath.c_str(),
                    (innerTmpSoPath + soFileName).c_str());
                return res;
            }
        } else {
            APP_LOGW("so file %{public}s is not existed", soPath.c_str());
        }
    }
    return ERR_OK;
}

ErrCode InstalldOperator::DecryptSoFile(const std::string &filePath, const std::string &tmpPath, int32_t uid,
    uint32_t fileSize, uint32_t offset)
{
    APP_LOGD("src file is %{public}s, temp path is %{public}s, bundle uid is %{public}d", filePath.c_str(),
        tmpPath.c_str(), uid);
    ErrCode result = ERR_BUNDLEMANAGER_QUICK_FIX_DECRYPTO_SO_FAILED;

    /* call CallIoctl */
    int32_t dev_fd = INVALID_FILE_DESCRIPTOR;
    auto ret = CallIoctl(CODE_DECRYPT_CMD_SET_KEY, CODE_DECRYPT_CMD_SET_ASSOCIATE_KEY, uid, dev_fd);
    if (ret != 0) {
        APP_LOGE("CallIoctl failed");
        return result;
    }

    /* mmap hap or so file to ram */
    std::string newfilePath;
    if (!PathToRealPath(filePath, newfilePath)) {
        APP_LOGE("file is not real path, file path: %{public}s", filePath.c_str());
        return result;
    }
    auto fd = open(newfilePath.c_str(), O_RDONLY);
    if (fd < 0) {
        APP_LOGE("open hap failed errno:%{public}d", errno);
        close(dev_fd);
        return result;
    }
    struct stat st;
    if (fstat(fd, &st) == INVALID_RETURN_VALUE) {
        APP_LOGE("obtain hap file status faield errno:%{public}d", errno);
        close(dev_fd);
        close(fd);
        return result;
    }
    off_t innerFileSize = fileSize;
    if (fileSize == 0) {
        innerFileSize = st.st_size;
    }
    void *addr = mmap(NULL, innerFileSize, PROT_READ, MAP_PRIVATE, fd, offset);
    if (addr == MAP_FAILED) {
        APP_LOGE("mmap hap file status faield errno:%{public}d", errno);
        close(dev_fd);
        close(fd);
        return result;
    }

    /* write hap file to the temp path */
    auto outPutFd = BundleUtil::CreateFileDescriptor(tmpPath, 0);
    if (outPutFd < 0) {
        APP_LOGE("create fd for tmp hap file failed");
        close(dev_fd);
        close(fd);
        munmap(addr, innerFileSize);
        return result;
    }
    if (write(outPutFd, addr, innerFileSize) != INVALID_RETURN_VALUE) {
        result = ERR_OK;
        APP_LOGD("write hap to temp path successfully");
    }
    close(dev_fd);
    close(fd);
    close(outPutFd);
    munmap(addr, innerFileSize);
    return result;
}

ErrCode InstalldOperator::RemoveEncryptedKey(int32_t uid, const std::vector<std::string> &soList)
{
    if (uid == Constants::INVALID_UID) {
        APP_LOGD("invalid uid and no need to remove encrypted key");
        return ERR_OK;
    }
    if (soList.empty()) {
        APP_LOGD("no new so generated and no need to remove encrypted key");
        return ERR_OK;
    }
    ErrCode result = ERR_BUNDLEMANAGER_QUICK_FIX_DECRYPTO_SO_FAILED;

    /* call CallIoctl */
    int32_t dev_fd = INVALID_FILE_DESCRIPTOR;
    auto ret = CallIoctl(CODE_DECRYPT_CMD_REMOVE_KEY, CODE_DECRYPT_CMD_REMOVE_KEY, uid, dev_fd);
    if (ret == 0) {
        APP_LOGD("ioctl successfully");
        result = ERR_OK;
    }
    close(dev_fd);
    return result;
}

int32_t InstalldOperator::CallIoctl(int32_t flag, int32_t associatedFlag, int32_t uid, int32_t &fd)
{
    int32_t installdUid = static_cast<int32_t>(getuid());
    int32_t bundleUid = uid;
    APP_LOGD("current process uid is %{public}d and bundle uid is %{public}d", installdUid, bundleUid);

    /* open CODE_DECRYPT */
    std::string newCodeDecrypt;
    if (!PathToRealPath(CODE_DECRYPT, newCodeDecrypt)) {
        APP_LOGE("file is not real path, file path: %{public}s", CODE_DECRYPT.c_str());
        return INVALID_RETURN_VALUE;
    }
    fd = open(newCodeDecrypt.c_str(), O_RDONLY);
    if (fd < 0) {
        APP_LOGE("call open failed errno:%{public}d", errno);
        return INVALID_RETURN_VALUE;
    }

    /* build ioctl args to set key or remove key*/
    struct code_decrypt_arg firstArg;
    firstArg.arg1_len = sizeof(bundleUid);
    firstArg.arg1 = reinterpret_cast<void *>(&bundleUid);
    auto ret = ioctl(fd, flag, &firstArg);
    if (ret != 0) {
        APP_LOGE("call ioctl failed errno:%{public}d", errno);
        close(fd);
    }

    struct code_decrypt_arg secondArg;
    secondArg.arg1_len = sizeof(installdUid);
    secondArg.arg1 = reinterpret_cast<void *>(&installdUid);
    if (associatedFlag == CODE_DECRYPT_CMD_SET_ASSOCIATE_KEY) {
        secondArg.arg2_len = sizeof(bundleUid);
        secondArg.arg2 = reinterpret_cast<void *>(&bundleUid);
    }
    ret = ioctl(fd, associatedFlag, &secondArg);
    if (ret != 0) {
        APP_LOGE("call ioctl failed errno:%{public}d", errno);
        close(fd);
    }
    return ret;
}
#endif

ErrCode InstalldOperator::MigrateData(const std::vector<std::string> &sourcePaths,
    const std::string &destinationPath)
{
    APP_LOGD("migrate data start");
    ErrCode ret = ERR_OK;
    std::vector<std::string> realSourcePaths;
    bool existValidPath = false;
    for (const auto &sourcePath : sourcePaths) {
        std::string realPath;
        if (!PathToRealPath(sourcePath, realPath)) {
            APP_LOGW("file(%{private}s) is not real path", sourcePath.c_str());
            ret = ERR_BUNDLE_MANAGER_MIGRATE_DATA_SOURCE_PATH_INVALID;
            continue;
        }
        realSourcePaths.push_back(realPath);
        existValidPath = true;
    }
    // all sourcePaths are invalid, need return error
    if (!existValidPath) {
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_SOURCE_PATH_INVALID;
    }
    std::string destPath;
    if (!PathToRealPath(destinationPath, destPath)) {
        APP_LOGE("file(%{private}s) is not real path", destinationPath.c_str());
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_DESTINATION_PATH_INVALID;
    }
    for (const auto &sourcePath : realSourcePaths) {
        if (!InnerMigrateData(sourcePath, destPath)) {
            APP_LOGW("file(%{private}s) migrate data failed, errno:%{public}d", sourcePath.c_str(), errno);
            ret = ERR_BUNDLE_MANAGER_MIGRATE_DATA_OTHER_REASON_FAILED;
        }
    }
    APP_LOGD("migrate data end");
    return ret;
}

bool InstalldOperator::InnerMigrateData(const std::string &sourcePaths, const std::string &destinationPath)
{
    struct stat buf = {};
    if (stat(sourcePaths.c_str(), &buf) != 0) {
        APP_LOGE("fail to stat errno:%{public}d", errno);
        return false;
    }
    if (!S_ISDIR(buf.st_mode)) {
        std::string fileName = sourcePaths;
        auto pos = sourcePaths.rfind(Constants::PATH_SEPARATOR);
        if (pos != std::string::npos) {
            fileName = sourcePaths.substr(pos + 1);
        }
        std::string destPath = OHOS::IncludeTrailingPathDelimiter(destinationPath) + fileName;
        return CopyFile(sourcePaths, destPath);
    }
    // create dir if not exist
    if (!IsExistDir(destinationPath)) {
        if (!MkRecursiveDir(destinationPath, true)) {
            APP_LOGE("create targetPath %{public}s failed", destinationPath.c_str());
            return false;
        }
    }
    DIR *dir = opendir(sourcePaths.c_str());
    if (dir == nullptr) {
        APP_LOGE("fail to opendir:%{private}s, errno:%{public}d", sourcePaths.c_str(), errno);
        return false;
    }
    bool ret = true;
    struct dirent *ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        std::string subPath = OHOS::IncludeTrailingPathDelimiter(sourcePaths) + std::string(ptr->d_name);
        std::string destPath = OHOS::IncludeTrailingPathDelimiter(destinationPath) + std::string(ptr->d_name);
        if (ptr->d_type == DT_DIR) {
            ret = InnerMigrateData(subPath, destPath);
            continue;
        }
        if (!CopyFile(subPath, destPath)) {
            APP_LOGE("migrate data source:%{private}s to destination %{public}s failed",
                subPath.c_str(), destPath.c_str());
            ret = false;
        }
    }
    closedir(dir);
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS