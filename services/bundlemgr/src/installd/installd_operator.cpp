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

#include "installd/installd_operator.h"

#include <algorithm>
#include <cstdio>
#include <dirent.h>
#include <dlfcn.h>
#include <fstream>
#include <map>
#include <sstream>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "directory_ex.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static const char LIB_DIFF_PATCH_SHARED_SO_PATH[] = "system/lib/libdiff_patch_shared.z.so";
static const char LIB64_DIFF_PATCH_SHARED_SO_PATH[] = "system/lib64/libdiff_patch_shared.z.so";
static const char APPLY_PATCH_FUNCTION_NAME[] = "ApplyPatch";
using ApplyPatch = int32_t (*)(const std::string, const std::string, const std::string);

static std::string HandleScanResult(
    const std::string &dir, const std::string &subName, ResultMode resultMode)
{
    if (resultMode == ResultMode::RELATIVE_PATH) {
        return subName;
    }

    return dir + Constants::PATH_SEPARATOR + subName;
}
}

bool InstalldOperator::IsExistFile(const std::string &path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        return false;
    }
    return S_ISREG(buf.st_mode);
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
    if (IsExistFile(path)) {
        return OHOS::RemoveFile(path);
    }
    if (IsExistDir(path)) {
        return OHOS::ForceRemoveDirectory(path);
    }
    return true;
}

bool InstalldOperator::ExtractFiles(const std::string &sourcePath, const std::string &targetPath,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    APP_LOGD("InstalldOperator::ExtractFiles start");
    BundleExtractor extractor(sourcePath);
    if (!extractor.Init()) {
        return false;
    }
    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames)) {
        return false;
    }
    if (entryNames.empty()) {
        return false;
    }

    std::string targetDir = targetPath;
    if (targetPath.back() != Constants::PATH_SEPARATOR[0]) {
        targetDir = targetPath + Constants::PATH_SEPARATOR;
    }
    for (const auto &entryName : entryNames) {
        if (strcmp(entryName.c_str(), ".") == 0 ||
            strcmp(entryName.c_str(), "..") == 0) {
            continue;
        }
        if (entryName.back() == Constants::PATH_SEPARATOR[0]) {
            continue;
        }
        // handle native so
        if (IsNativeSo(entryName, targetSoPath, cpuAbi)) {
            ExtractTargetFile(extractor, entryName, targetSoPath, cpuAbi);
            continue;
        }
        if (system::GetBoolParameter(Constants::COMPRESS_PROPERTY, false)) {
            continue;
        }
        const std::string dir = GetPathDir(entryName);
        std::string filePath = targetDir + dir;
        if (!dir.empty()) {
            if (!MkRecursiveDir(filePath, true)) {
                return false;
            }
        }
        filePath = targetDir + entryName;
        if (!extractor.ExtractFile(entryName, filePath)) {
            return false;
        }
        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        if (!OHOS::ChangeModeFile(filePath, mode)) {
            APP_LOGE("change mode failed");
        }
        filePath.clear();
    }
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
    std::vector<std::string> suffixs;
    switch (extractParam.extractFileType) {
        case ExtractFileType::SO: {
            prefix = Constants::LIBS + extractParam.cpuAbi + Constants::PATH_SEPARATOR;
            suffixs.emplace_back(Constants::SO_SUFFIX);
            break;
        }
        case ExtractFileType::AN: {
            prefix = Constants::AN + extractParam.cpuAbi + Constants::PATH_SEPARATOR;
            suffixs.emplace_back(Constants::AN_SUFFIX);
            suffixs.emplace_back(Constants::AI_SUFFIX);
            break;
        }
        case ExtractFileType::AP: {
            prefix = Constants::AP;
            suffixs.emplace_back(Constants::AP_SUFFIX);
            break;
        }
        default: {
            return false;
        }
    }

    if (entryName.find(prefix) == std::string::npos) {
        APP_LOGD("entryName not start with %{public}s", prefix.c_str());
        return false;
    }

    bool checkSuffix = false;
    for (const auto &suffix : suffixs) {
        if (entryName.find(suffix) != std::string::npos) {
            checkSuffix = true;
            break;
        }
    }

    if (!checkSuffix) {
        APP_LOGD("file type error.");
        return false;
    }

    APP_LOGD("find native file, prefix: %{public}s, entryName: %{public}s",
        prefix.c_str(), entryName.c_str());
    return true;
}

bool InstalldOperator::IsNativeSo(const std::string &entryName,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    APP_LOGD("IsNativeSo, entryName : %{public}s", entryName.c_str());
    if (targetSoPath.empty()) {
        APP_LOGD("current hap not include so");
        return false;
    }
    std::string prefix = Constants::LIBS + cpuAbi + Constants::PATH_SEPARATOR;
    if (entryName.find(prefix) == std::string::npos) {
        APP_LOGD("entryName not start with %{public}s", prefix.c_str());
        return false;
    }
    if (entryName.find(Constants::SO_SUFFIX) == std::string::npos) {
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
    if (entryName.find(prefix) == std::string::npos) {
        APP_LOGD("entryName not start with %{public}s", prefix.c_str());
        return false;
    }
    if (entryName.find(Constants::DIFF_SUFFIX) == std::string::npos) {
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
            APP_LOGE("create targetPath %{private}s failed", targetPath.c_str());
            return;
        }
    }

    std::string prefix;
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
        default: {
            return;
        }
    }
    std::string targetName = entryName.substr(prefix.length());
    std::string path = targetPath;
    if (path.back() != Constants::FILE_SEPARATOR_CHAR) {
        path += Constants::FILE_SEPARATOR_CHAR;
    }
    path += targetName;
    bool ret = extractor.ExtractFile(entryName, path);
    if (!ret) {
        APP_LOGE("extract file failed, entryName : %{public}s", entryName.c_str());
        return;
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (extractFileType == ExtractFileType::AP) {
        struct stat buf = {};
        if (stat(targetPath.c_str(), &buf) != 0) {
            return;
        }
        ChangeFileAttr(path, buf.st_uid, buf.st_gid);
        mode = (buf.st_uid == buf.st_gid) ? (S_IRUSR | S_IWUSR) : (S_IRUSR | S_IWUSR | S_IRGRP);
    }
    if (!OHOS::ChangeModeFile(path, mode)) {
        return;
    }
    APP_LOGD("extract file success, path : %{private}s", path.c_str());
}

bool InstalldOperator::RenameDir(const std::string &oldPath, const std::string &newPath)
{
    if (oldPath.empty() || oldPath.size() > PATH_MAX) {
        APP_LOGE("oldpath error");
        return false;
    }
    if (access(oldPath.c_str(), F_OK) != 0 && access(newPath.c_str(), F_OK) == 0) {
        return true;
    }
    std::string realOldPath;
    realOldPath.reserve(PATH_MAX);
    realOldPath.resize(PATH_MAX - 1);
    if (realpath(oldPath.c_str(), &(realOldPath[0])) == nullptr) {
        APP_LOGE("realOldPath %{private}s", realOldPath.c_str());
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
        return false;
    }

    while (true) {
        struct dirent *ptr = readdir(dir);
        if (ptr == nullptr) {
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
                APP_LOGE("Failed to ChangeFileAttr %{public}s", subPath.c_str());
                closedir(dir);
                return false;
            }
        }
    }

    closedir(dir);
    std::string currentPath = OHOS::ExcludeTrailingPathDelimiter(path);
    if (access(currentPath.c_str(), F_OK) == 0) {
        if (!ChangeFileAttr(currentPath, uid, gid)) {
            APP_LOGE("Failed to ChangeFileAttr %{public}s", currentPath.c_str());
            return false;
        }
    }

    return ret;
}

bool InstalldOperator::ChangeFileAttr(const std::string &filePath, const int uid, const int gid)
{
    APP_LOGD("begin to change %{private}s file attribute", filePath.c_str());
    if (chown(filePath.c_str(), uid, gid) != 0) {
        APP_LOGE("fail to change %{private}s ownership", filePath.c_str());
        return false;
    }
    APP_LOGD("change %{private}s file attribute successfully", filePath.c_str());
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
        return false;
    }
    while (true) {
        struct dirent *ptr = readdir(dir);
        if (ptr == nullptr) {
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

bool InstalldOperator::MkOwnerDir(const std::string &path, bool isReadByOthers, const int uid, const int gid)
{
    if (!MkRecursiveDir(path, isReadByOthers)) {
        return false;
    }
    return ChangeFileAttr(path, uid, gid);
}

bool InstalldOperator::MkOwnerDir(const std::string &path, int mode, const int uid, const int gid)
{
    if (!OHOS::ForceCreateDirectory(path)) {
        APP_LOGE("mkdir failed");
        return false;
    }
    if (!OHOS::ChangeModeDirectory(path, mode)) {
        return false;
    }
    return ChangeDirOwnerRecursively(path, uid, gid);
}

int64_t InstalldOperator::GetDiskUsage(const std::string &dir)
{
    if (dir.empty() || (dir.size() > Constants::PATH_MAX_SIZE)) {
        APP_LOGE("GetDiskUsage dir path invaild");
        return 0;
    }
    std::string filePath = "";
    if (!PathToRealPath(dir, filePath)) {
        APP_LOGE("file is not real path, file path: %{private}s", dir.c_str());
        return 0;
    }
    DIR *dirPtr = opendir(filePath.c_str());
    if (dirPtr == nullptr) {
        APP_LOGE("GetDiskUsage open file dir:%{private}s is failure", filePath.c_str());
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
        std::string realPath = "";
        if (!PathToRealPath(path, realPath)) {
            APP_LOGE("file is not real path %{private}s", path.c_str());
            continue;
        }
        struct stat fileInfo = {0};
        if (stat(realPath.c_str(), &fileInfo) != 0) {
            APP_LOGE("call stat error %{private}s", realPath.c_str());
            fileInfo.st_size = 0;
        }
        size += fileInfo.st_size;
        if (entry->d_type == DT_DIR) {
            size += GetDiskUsage(realPath);
        }
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
        APP_LOGE("file is not real path, file path: %{private}s", currentPath.c_str());
        return;
    }
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
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
        APP_LOGE("Scan open dir(%{public}s) fail", realPath.c_str());
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

bool InstalldOperator::CopyFile(
    const std::string &sourceFile, const std::string &destinationFile)
{
    if (sourceFile.empty() || destinationFile.empty()) {
        APP_LOGE("Copy file failed due to sourceFile or destinationFile is empty");
        return false;
    }

    std::ifstream in(sourceFile);
    if (!in.is_open()) {
        APP_LOGE("Copy file failed due to open sourceFile failed");
        return false;
    }

    std::ofstream out(destinationFile);
    if (!out.is_open()) {
        APP_LOGE("Copy file failed due to open destinationFile failed");
        in.close();
        return false;
    }

    out << in.rdbuf();
    in.close();
    out.close();
    return true;
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
    if (IsExistDir(Constants::SYSTEM_LIB64)) {
        *handle = dlopen(LIB64_DIFF_PATCH_SHARED_SO_PATH, RTLD_NOW | RTLD_GLOBAL);
    } else {
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
    APP_LOGI("ProcessApplyDiffPatchPath oldSoPath: %{private}s, diffFilePath: %{private}s, newSoPath: %{public}s",
        oldSoPath.c_str(), diffFilePath.c_str(), newSoPath.c_str());
    if (oldSoPath.empty() || diffFilePath.empty() || newSoPath.empty()) {
        return false;
    }
    if (!IsExistDir(oldSoPath) || !IsExistDir(diffFilePath)) {
        APP_LOGE("ProcessApplyDiffPatchPath oldSoPath or diffFilePath not exist");
        return false;
    }

    if (!ScanDir(oldSoPath, ScanMode::SUB_FILE_FILE, ResultMode::RELATIVE_PATH, oldSoFileNames)) {
        APP_LOGE("ProcessApplyDiffPatchPath ScanDir oldSoPath failed");
        return false;
    }

    if (!ScanDir(diffFilePath, ScanMode::SUB_FILE_FILE, ResultMode::RELATIVE_PATH, diffFileNames)) {
        APP_LOGE("ProcessApplyDiffPatchPath ScanDir diffFilePath failed");
        return false;
    }

    if (oldSoFileNames.empty() || diffFileNames.empty()) {
        APP_LOGE("ProcessApplyDiffPatchPath so or diff files empty");
        return false;
    }

    if (!IsExistDir(newSoPath)) {
        APP_LOGD("ProcessApplyDiffPatchPath create newSoPath");
        if (!MkRecursiveDir(newSoPath, true)) {
            APP_LOGE("ProcessApplyDiffPatchPath create newSo dir (%{private}s) failed", newSoPath.c_str());
            return false;
        }
    }
    APP_LOGI("ProcessApplyDiffPatchPath end");
    return true;
}

bool InstalldOperator::ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath)
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
        APP_LOGE("ObtainQuickFixFileDir open dir(%{public}s) fail", realPath.c_str());
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
        APP_LOGE("CopyFiles open dir(%{public}s) fail", realPath.c_str());
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
}  // namespace AppExecFwk
}  // namespace OHOS