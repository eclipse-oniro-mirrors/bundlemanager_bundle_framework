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

#include "bundle_util.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <set>
#include <sstream>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <thread>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#ifdef CONFIG_POLOCY_ENABLE
#include "config_policy_utils.h"
#endif
#include "directory_ex.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "parameter.h"
#include "string_ex.h"
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
#include "type_descriptor.h"
#include "utd_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string::size_type EXPECT_SPLIT_SIZE = 2;
const size_t ORIGIN_STRING_LENGTH = 32;
constexpr char UUID_SEPARATOR = '-';
const std::vector<int32_t> SEPARATOR_POSITIONS { 8, 13, 18, 23};
const int64_t HALF_GB = 1024 * 1024 * 512; // 0.5GB
const int64_t SPACE_NEED_DOUBLE = 2;
const uint32_t UUID_LENGTH_MAX = 512;
static std::string g_deviceUdid;
static std::mutex g_mutex;
// hmdfs and sharefs config
constexpr const char* BUNDLE_ID_FILE = "appid";
// single max hap size
constexpr int64_t ONE_GB = 1024 * 1024 * 1024;
constexpr int64_t MAX_HAP_SIZE = ONE_GB * 4;  // 4GB
constexpr const char* ABC_FILE_PATH = "abc_files";
constexpr const char* PGO_FILE_PATH = "pgo_files";
const std::string EMPTY_STRING = "";
#ifdef CONFIG_POLOCY_ENABLE
    const char* NO_DISABLING_CONFIG_PATH = "/etc/ability_runtime/resident_process_in_extreme_memory.json";
#endif
const char* NO_DISABLING_CONFIG_PATH_DEFAULT =
    "/system/etc/ability_runtime/resident_process_in_extreme_memory.json";
}

std::mutex BundleUtil::g_mutex;

ErrCode BundleUtil::CheckFilePath(const std::string &bundlePath, std::string &realPath)
{
    if (!CheckFileName(bundlePath)) {
        APP_LOGE("bundle file path invalid");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    if (!CheckFileType(bundlePath, ServiceConstants::INSTALL_FILE_SUFFIX) &&
        !CheckFileType(bundlePath, ServiceConstants::HSP_FILE_SUFFIX) &&
        !CheckFileType(bundlePath, ServiceConstants::QUICK_FIX_FILE_SUFFIX) &&
        !CheckFileType(bundlePath, ServiceConstants::CODE_SIGNATURE_FILE_SUFFIX)) {
        APP_LOGE("file is not hap, hsp, hqf or sig");
        return ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME;
    }
    if (!PathToRealPath(bundlePath, realPath)) {
        APP_LOGE("file is not real path");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    if (access(realPath.c_str(), F_OK) != 0) {
        APP_LOGE("not access the bundle file path: %{public}s, errno:%{public}d", realPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALL_INVALID_BUNDLE_FILE;
    }
    if (!CheckFileSize(realPath, MAX_HAP_SIZE)) {
        APP_LOGE("file size larger than max hap size Max size is: %{public}" PRId64, MAX_HAP_SIZE);
        return ERR_APPEXECFWK_INSTALL_INVALID_HAP_SIZE;
    }
    return ERR_OK;
}

ErrCode BundleUtil::CheckFilePath(const std::vector<std::string> &bundlePaths, std::vector<std::string> &realPaths)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    // there are three cases for bundlePaths:
    // 1. one bundle direction in the bundlePaths, some hap files under this bundle direction.
    // 2. one hap direction in the bundlePaths.
    // 3. some hap file directions in the bundlePaths.
    APP_LOGD("check file path");
    if (bundlePaths.empty()) {
        APP_LOGE("bundle file paths invalid");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    ErrCode ret = ERR_OK;

    if (bundlePaths.size() == 1) {
        struct stat s;
        std::string bundlePath = bundlePaths.front();
        if (stat(bundlePath.c_str(), &s) == 0) {
            std::string realPath = "";
            // it is a direction
            if ((s.st_mode & S_IFDIR) && !GetHapFilesFromBundlePath(bundlePath, realPaths)) {
                APP_LOGE("GetHapFilesFromBundlePath failed with bundlePath:%{public}s", bundlePaths.front().c_str());
                return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
            }
            // it is a file
            if ((s.st_mode & S_IFREG) && (ret = CheckFilePath(bundlePaths.front(), realPath)) == ERR_OK) {
                realPaths.emplace_back(realPath);
            }
            return ret;
        } else {
            APP_LOGE("bundlePath not existed with :%{public}s", bundlePaths.front().c_str());
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
    } else {
        for (const std::string& bundlePath : bundlePaths) {
            std::string realPath = "";
            ret = CheckFilePath(bundlePath, realPath);
            if (ret != ERR_OK) {
                return ret;
            }
            realPaths.emplace_back(realPath);
        }
    }
    APP_LOGD("finish check file path");
    return ret;
}

bool BundleUtil::CheckFileType(const std::string &fileName, const std::string &extensionName)
{
    APP_LOGD("path is %{public}s, support suffix is %{public}s", fileName.c_str(), extensionName.c_str());
    if (!CheckFileName(fileName)) {
        return false;
    }

    auto position = fileName.rfind('.');
    if (position == std::string::npos) {
        APP_LOGE("filename no extension name");
        return false;
    }

    std::string suffixStr = fileName.substr(position);
    return LowerStr(suffixStr) == extensionName;
}

bool BundleUtil::CheckFileName(const std::string &fileName)
{
    if (fileName.empty()) {
        APP_LOGE("the file name is empty");
        return false;
    }
    if (fileName.size() > ServiceConstants::PATH_MAX_SIZE) {
        APP_LOGE("bundle file path length %{public}zu too long", fileName.size());
        return false;
    }
    return true;
}

bool BundleUtil::CheckFileSize(const std::string &bundlePath, const int64_t fileSize)
{
    APP_LOGD("fileSize is %{public}" PRId64, fileSize);
    struct stat fileInfo = { 0 };
    if (stat(bundlePath.c_str(), &fileInfo) != 0) {
        APP_LOGE("call stat error:%{public}d", errno);
        return false;
    }
    if (fileInfo.st_size > fileSize) {
        return false;
    }
    return true;
}

bool BundleUtil::CheckSystemSize(const std::string &bundlePath, const std::string &diskPath)
{
    struct statfs diskInfo = { 0 };
    if (statfs(diskPath.c_str(), &diskInfo) != 0) {
        APP_LOGE("call statfs error:%{public}d", errno);
        return false;
    }
    int64_t freeSize = diskInfo.f_bavail * diskInfo.f_bsize;
    APP_LOGD("left free size in the disk path is %{public}" PRId64, freeSize);
    struct stat fileInfo = { 0 };
    if (stat(bundlePath.c_str(), &fileInfo) != 0) {
        APP_LOGE("call stat error:%{public}d", errno);
        return false;
    }
    if (std::max(fileInfo.st_size * SPACE_NEED_DOUBLE, HALF_GB) > freeSize) {
        return false;
    }
    return true;
}

bool BundleUtil::GetHapFilesFromBundlePath(const std::string& currentBundlePath, std::vector<std::string>& hapFileList)
{
    APP_LOGD("GetHapFilesFromBundlePath with path is %{public}s", currentBundlePath.c_str());
    if (currentBundlePath.empty()) {
        return false;
    }
    DIR* dir = opendir(currentBundlePath.c_str());
    if (dir == nullptr) {
        char errMsg[256] = {0};
        strerror_r(errno, errMsg, sizeof(errMsg));
        APP_LOGE("GetHapFilesFromBundlePath open bundle dir:%{public}s failed due to %{public}s, errno:%{public}d",
            currentBundlePath.c_str(), errMsg, errno);
        return false;
    }
    std::string bundlePath = currentBundlePath;
    if (bundlePath.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
        bundlePath.append(ServiceConstants::PATH_SEPARATOR);
    }
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        const std::string hapFilePath = bundlePath + entry->d_name;
        std::string realPath = "";
        if (CheckFilePath(hapFilePath, realPath) != ERR_OK) {
            APP_LOGE("find invalid hap path %{public}s", hapFilePath.c_str());
            closedir(dir);
            return false;
        }
        hapFileList.emplace_back(realPath);
        APP_LOGD("find hap path %{public}s", realPath.c_str());

        if (!hapFileList.empty() && (hapFileList.size() > ServiceConstants::MAX_HAP_NUMBER)) {
            APP_LOGE("reach the max hap number 128, stop to add more.");
            closedir(dir);
            return false;
        }
    }
    closedir(dir);
    return true;
}

int64_t BundleUtil::GetCurrentTime()
{
    int64_t time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
    APP_LOGD("the current time in seconds is %{public}" PRId64, time);
    return time;
}

int64_t BundleUtil::GetCurrentTimeMs()
{
    int64_t time =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
    APP_LOGD("the current time in milliseconds is %{public}" PRId64, time);
    return time;
}

int64_t BundleUtil::GetCurrentTimeNs()
{
    int64_t time =
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
    APP_LOGD("the current time in nanoseconds is %{public}" PRId64, time);
    return time;
}

void BundleUtil::DeviceAndNameToKey(
    const std::string &deviceId, const std::string &bundleName, std::string &key)
{
    key.append(deviceId);
    key.append(Constants::FILE_UNDERLINE);
    key.append(bundleName);
    APP_LOGD("bundleName = %{public}s", bundleName.c_str());
}

bool BundleUtil::KeyToDeviceAndName(
    const std::string &key, std::string &deviceId, std::string &bundleName)
{
    bool ret = false;
    std::vector<std::string> splitStrs;
    OHOS::SplitStr(key, Constants::FILE_UNDERLINE, splitStrs);
    // the expect split size should be 2.
    // key rule is <deviceId>_<bundleName>
    if (splitStrs.size() == EXPECT_SPLIT_SIZE) {
        deviceId = splitStrs[0];
        bundleName = splitStrs[1];
        ret = true;
    }
    APP_LOGD("bundleName = %{public}s", bundleName.c_str());
    return ret;
}

int32_t BundleUtil::GetUserIdByCallingUid()
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    APP_LOGD("get calling uid(%{public}d)", uid);
    return GetUserIdByUid(uid);
}

int32_t BundleUtil::GetUserIdByUid(int32_t uid)
{
    if (uid <= Constants::INVALID_UID) {
        APP_LOGE("uid illegal: %{public}d", uid);
        return Constants::INVALID_USERID;
    }

    return uid / Constants::BASE_USER_RANGE;
}

void BundleUtil::MakeFsConfig(const std::string &bundleName, int32_t bundleId, const std::string &configPath)
{
    std::string bundleDir = configPath + ServiceConstants::PATH_SEPARATOR + bundleName;
    if (access(bundleDir.c_str(), F_OK) != 0) {
        APP_LOGD("fail to access error:%{public}d", errno);
        if (mkdir(bundleDir.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
            APP_LOGE("make bundle dir error:%{public}d", errno);
            return;
        }
    }

    std::string realBundleDir;
    if (!PathToRealPath(bundleDir, realBundleDir)) {
        APP_LOGE("bundleIdFile is not real path");
        return;
    }

    realBundleDir += (ServiceConstants::PATH_SEPARATOR + BUNDLE_ID_FILE);

    int32_t bundleIdFd = open(realBundleDir.c_str(), O_WRONLY | O_TRUNC);
    if (bundleIdFd > 0) {
        std::string bundleIdStr = std::to_string(bundleId);
        if (write(bundleIdFd, bundleIdStr.c_str(), bundleIdStr.size()) < 0) {
            APP_LOGE("write bundleId error:%{public}d", errno);
        }
    }
    close(bundleIdFd);
}

void BundleUtil::RemoveFsConfig(const std::string &bundleName, const std::string &configPath)
{
    std::string bundleDir = configPath + ServiceConstants::PATH_SEPARATOR + bundleName;
    std::string realBundleDir;
    if (!PathToRealPath(bundleDir, realBundleDir)) {
        APP_LOGE("bundleDir is not real path");
        return;
    }
    if (rmdir(realBundleDir.c_str()) != 0) {
        APP_LOGE("remove hmdfs bundle dir error:%{public}d", errno);
    }
}

std::string BundleUtil::CreateTempDir(const std::string &tempDir)
{
    if (!OHOS::ForceCreateDirectory(tempDir)) {
        APP_LOGE("mkdir %{public}s failed", tempDir.c_str());
        return "";
    }
    if (chown(tempDir.c_str(), Constants::FOUNDATION_UID, ServiceConstants::BMS_GID) != 0) {
        APP_LOGE("fail to change %{public}s ownership errno:%{public}d", tempDir.c_str(), errno);
        return "";
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (!OHOS::ChangeModeFile(tempDir, mode)) {
        APP_LOGE("change mode failed, temp install dir : %{public}s", tempDir.c_str());
        return "";
    }
    return tempDir;
}

std::string BundleUtil::CreateInstallTempDir(uint32_t installerId, const DirType &type)
{
    std::time_t curTime = std::time(0);
    std::string tempDir = ServiceConstants::HAP_COPY_PATH;
    if (type == DirType::STREAM_INSTALL_DIR) {
        tempDir += ServiceConstants::PATH_SEPARATOR + ServiceConstants::STREAM_INSTALL_PATH;
    } else if (type == DirType::QUICK_FIX_DIR) {
        tempDir += ServiceConstants::PATH_SEPARATOR + ServiceConstants::QUICK_FIX_PATH;
    } else if (type == DirType::SIG_FILE_DIR) {
        tempDir += ServiceConstants::PATH_SEPARATOR + ServiceConstants::SIGNATURE_FILE_PATH;
    } else if (type == DirType::PGO_FILE_DIR) {
        tempDir += ServiceConstants::PATH_SEPARATOR + PGO_FILE_PATH;
    } else if (type == DirType::ABC_FILE_DIR) {
        tempDir += ServiceConstants::PATH_SEPARATOR + ABC_FILE_PATH;
    } else if (type == DirType::EXT_RESOURCE_FILE_DIR) {
        tempDir += ServiceConstants::PATH_SEPARATOR + ServiceConstants::EXT_RESOURCE_FILE_PATH;
    } else {
        return "";
    }

    if (CreateTempDir(tempDir).empty()) {
        APP_LOGE("create tempDir failed");
        return "";
    }

    tempDir += ServiceConstants::PATH_SEPARATOR + std::to_string(curTime) +
        std::to_string(installerId) + ServiceConstants::PATH_SEPARATOR;
    return CreateTempDir(tempDir);
}

std::string BundleUtil::CreateSharedBundleTempDir(uint32_t installerId, uint32_t index)
{
    std::time_t curTime = std::time(0);
    std::string tempDir = ServiceConstants::HAP_COPY_PATH;
    tempDir += ServiceConstants::PATH_SEPARATOR + ServiceConstants::STREAM_INSTALL_PATH;
    tempDir += ServiceConstants::PATH_SEPARATOR + std::to_string(curTime) + std::to_string(installerId)
        + Constants::FILE_UNDERLINE + std::to_string(index)+ ServiceConstants::PATH_SEPARATOR;
    return CreateTempDir(tempDir);
}

int32_t BundleUtil::CreateFileDescriptor(const std::string &bundlePath, long long offset)
{
    int fd = -1;
    if (bundlePath.length() > ServiceConstants::PATH_MAX_SIZE) {
        APP_LOGE("the length of the bundlePath exceeds maximum limitation");
        return fd;
    }
    if ((fd = open(bundlePath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)) < 0) {
        APP_LOGE("open bundlePath %{public}s failed errno:%{public}d", bundlePath.c_str(), errno);
        return fd;
    }
    if (offset > 0) {
        lseek(fd, offset, SEEK_SET);
    }
    return fd;
}

int32_t BundleUtil::CreateFileDescriptorForReadOnly(const std::string &bundlePath, long long offset)
{
    int fd = -1;
    if (bundlePath.length() > ServiceConstants::PATH_MAX_SIZE) {
        APP_LOGE("the length of the bundlePath exceeds maximum limitation");
        return fd;
    }
    std::string realPath;
    if (!PathToRealPath(bundlePath, realPath)) {
        APP_LOGE("file is not real path");
        return fd;
    }

    if ((fd = open(realPath.c_str(), O_RDONLY)) < 0) {
        APP_LOGE("open bundlePath %{public}s failed errno:%{public}d", realPath.c_str(), errno);
        return fd;
    }
    if (offset > 0) {
        lseek(fd, offset, SEEK_SET);
    }
    return fd;
}

void BundleUtil::CloseFileDescriptor(std::vector<int32_t> &fdVec)
{
    for_each(fdVec.begin(), fdVec.end(), [](const auto &fd) {
        if (fd > 0) {
            close(fd);
        }
    });
    fdVec.clear();
}

bool BundleUtil::IsExistFile(const std::string &path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        APP_LOGE("fail stat errno:%{public}d", errno);
        return false;
    }

    return S_ISREG(buf.st_mode);
}

bool BundleUtil::IsExistDir(const std::string &path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        APP_LOGE("fail stat errno:%{public}d", errno);
        return false;
    }

    return S_ISDIR(buf.st_mode);
}

int64_t BundleUtil::CalculateFileSize(const std::string &bundlePath)
{
    struct stat fileInfo = { 0 };
    if (stat(bundlePath.c_str(), &fileInfo) != 0) {
        APP_LOGE("call stat error:%{public}d", errno);
        return 0;
    }

    return static_cast<int64_t>(fileInfo.st_size);
}

bool BundleUtil::RenameFile(const std::string &oldPath, const std::string &newPath)
{
    if (oldPath.empty() || newPath.empty()) {
        APP_LOGE("oldPath or newPath is empty");
        return false;
    }

    if (!DeleteDir(newPath)) {
        APP_LOGE("delete newPath failed");
        return false;
    }

    return rename(oldPath.c_str(), newPath.c_str()) == 0;
}

bool BundleUtil::DeleteDir(const std::string &path)
{
    if (IsExistFile(path)) {
        return OHOS::RemoveFile(path);
    }

    if (IsExistDir(path)) {
        return OHOS::ForceRemoveDirectory(path);
    }

    return true;
}

bool BundleUtil::IsUtd(const std::string &param)
{
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
    bool isUtd = false;
    auto ret = UDMF::UtdClient::GetInstance().IsUtd(param, isUtd);
    return ret == ERR_OK && isUtd;
#else
    return false;
#endif
}

std::string BundleUtil::GetBoolStrVal(bool val)
{
    return val ? "true" : "false";
}

bool BundleUtil::CopyFile(
    const std::string &sourceFile, const std::string &destinationFile)
{
    if (sourceFile.empty() || destinationFile.empty()) {
        APP_LOGE("Copy file failed due to sourceFile or destinationFile is empty");
        return false;
    }

    std::ifstream in(sourceFile);
    if (!in.is_open()) {
        APP_LOGE("Copy file failed due to open sourceFile failed errno:%{public}d", errno);
        return false;
    }

    std::ofstream out(destinationFile);
    if (!out.is_open()) {
        APP_LOGE("Copy file failed due to open destinationFile failed errno:%{public}d", errno);
        in.close();
        return false;
    }

    out << in.rdbuf();
    in.close();
    out.close();
    return true;
}

bool BundleUtil::CopyFileFast(const std::string &sourcePath, const std::string &destPath)
{
    APP_LOGI("sourcePath : %{public}s, destPath : %{public}s", sourcePath.c_str(), destPath.c_str());
    if (sourcePath.empty() || destPath.empty()) {
        APP_LOGE("invalid path");
        return false;
    }

    int32_t sourceFd = open(sourcePath.c_str(), O_RDONLY);
    if (sourceFd == -1) {
        APP_LOGE("sourcePath open failed, errno : %{public}d", errno);
        return CopyFile(sourcePath, destPath);
    }

    struct stat sourceStat;
    if (fstat(sourceFd, &sourceStat) == -1) {
        APP_LOGE("fstat failed, errno : %{public}d", errno);
        close(sourceFd);
        return CopyFile(sourcePath, destPath);
    }
    if (sourceStat.st_size < 0) {
        APP_LOGE("invalid st_size");
        close(sourceFd);
        return CopyFile(sourcePath, destPath);
    }

    int32_t destFd = open(
        destPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (destFd == -1) {
        APP_LOGE("destPath open failed, errno : %{public}d", errno);
        close(sourceFd);
        return CopyFile(sourcePath, destPath);
    }

    size_t buffer = 524288; // 0.5M
    size_t transferCount = 0;
    ssize_t singleTransfer = 0;
    while ((singleTransfer = sendfile(destFd, sourceFd, nullptr, buffer)) > 0) {
        transferCount += static_cast<size_t>(singleTransfer);
    }

    if (singleTransfer == -1 || transferCount != static_cast<size_t>(sourceStat.st_size)) {
        APP_LOGE("sendfile failed, errno : %{public}d, send count : %{public}zu , file size : %{public}zu",
            errno, transferCount, static_cast<size_t>(sourceStat.st_size));
        close(sourceFd);
        close(destFd);
        return CopyFile(sourcePath, destPath);
    }

    close(sourceFd);
    close(destFd);
    APP_LOGD("sendfile success");
    return true;
}

Resource BundleUtil::GetResource(const std::string &bundleName, const std::string &moduleName, int32_t resId)
{
    Resource resource;
    resource.bundleName = bundleName;
    resource.moduleName = moduleName;
    resource.id = resId;
    return resource;
}

bool BundleUtil::CreateDir(const std::string &dir)
{
    if (dir.empty()) {
        APP_LOGE("path is empty");
        return false;
    }

    if (IsExistFile(dir)) {
        return true;
    }

    if (!OHOS::ForceCreateDirectory(dir)) {
        APP_LOGE("mkdir %{public}s failed", dir.c_str());
        return false;
    }

    if (chown(dir.c_str(), Constants::FOUNDATION_UID, ServiceConstants::BMS_GID) != 0) {
        APP_LOGE("fail change %{public}s ownership, errno:%{public}d", dir.c_str(), errno);
        return false;
    }

    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (!OHOS::ChangeModeFile(dir, mode)) {
        APP_LOGE("change mode failed, temp install dir : %{public}s", dir.c_str());
        return false;
    }
    return true;
}

bool BundleUtil::RevertToRealPath(const std::string &sandBoxPath, const std::string &bundleName, std::string &realPath)
{
    if (sandBoxPath.empty() || bundleName.empty() ||
        sandBoxPath.find(ServiceConstants::SANDBOX_DATA_PATH) == std::string::npos) {
        APP_LOGE("input sandboxPath or bundleName invalid");
        return false;
    }

    realPath = sandBoxPath;
    std::string relaDataPath = ServiceConstants::REAL_DATA_PATH + ServiceConstants::PATH_SEPARATOR
        + std::to_string(BundleUtil::GetUserIdByCallingUid()) + ServiceConstants::BASE + bundleName;
    realPath.replace(realPath.find(ServiceConstants::SANDBOX_DATA_PATH),
        std::string(ServiceConstants::SANDBOX_DATA_PATH).size(), relaDataPath);
    return true;
}

bool BundleUtil::StartWith(const std::string &source, const std::string &prefix)
{
    if (source.empty() || prefix.empty()) {
        return false;
    }

    return source.find(prefix) == 0;
}

bool BundleUtil::EndWith(const std::string &source, const std::string &suffix)
{
    if (source.empty() || suffix.empty()) {
        return false;
    }

    auto position = source.rfind(suffix);
    if (position == std::string::npos) {
        return false;
    }

    std::string suffixStr = source.substr(position);
    return suffixStr == suffix;
}

int64_t BundleUtil::GetFileSize(const std::string &filePath)
{
    struct stat fileInfo = { 0 };
    if (stat(filePath.c_str(), &fileInfo) != 0) {
        APP_LOGE("call stat error:%{public}d", errno);
        return 0;
    }
    return fileInfo.st_size;
}

std::string BundleUtil::CopyFileToSecurityDir(const std::string &filePath, const DirType &dirType,
    std::vector<std::string> &toDeletePaths)
{
    APP_LOGD("the original dir is %{public}s", filePath.c_str());
    std::string destination = "";
    std::string subStr = "";
    destination.append(ServiceConstants::HAP_COPY_PATH).append(ServiceConstants::PATH_SEPARATOR);
    if (dirType == DirType::STREAM_INSTALL_DIR) {
        subStr = ServiceConstants::STREAM_INSTALL_PATH;
        destination.append(ServiceConstants::SECURITY_STREAM_INSTALL_PATH);
        mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
        if (InstalldClient::GetInstance()->Mkdir(
            destination, mode, Constants::FOUNDATION_UID, ServiceConstants::BMS_GID) != ERR_OK) {
            APP_LOGW("installd mkdir %{private}s failed", destination.c_str());
        }
    }
    if (dirType == DirType::SIG_FILE_DIR) {
        subStr = ServiceConstants::SIGNATURE_FILE_PATH;
        destination.append(ServiceConstants::SECURITY_SIGNATURE_FILE_PATH);
    }
    destination.append(ServiceConstants::PATH_SEPARATOR).append(std::to_string(GetCurrentTimeNs()));
    destination = CreateTempDir(destination);
    auto pos = filePath.find(subStr);
    if (pos == std::string::npos) { // this circumstance could not be considered laterly
        auto lastPathSeperator = filePath.rfind(ServiceConstants::PATH_SEPARATOR);
        if ((lastPathSeperator != std::string::npos) && (lastPathSeperator != filePath.length() - 1)) {
            toDeletePaths.emplace_back(destination);
            destination.append(filePath.substr(lastPathSeperator));
        }
    } else {
        auto secondLastPathSep = filePath.find(ServiceConstants::PATH_SEPARATOR, pos);
        if ((secondLastPathSep == std::string::npos) || (secondLastPathSep == filePath.length() - 1)) {
            return "";
        }
        auto thirdLastPathSep =
            filePath.find(ServiceConstants::PATH_SEPARATOR, secondLastPathSep + 1);
        if ((thirdLastPathSep == std::string::npos) || (thirdLastPathSep == filePath.length() - 1)) {
            return "";
        }
        toDeletePaths.emplace_back(destination);
        std::string innerSubstr =
            filePath.substr(secondLastPathSep, thirdLastPathSep - secondLastPathSep + 1);
        destination = CreateTempDir(destination.append(innerSubstr));
        destination.append(filePath.substr(thirdLastPathSep + 1));
    }
    APP_LOGD("the destination dir is %{public}s", destination.c_str());
    if (destination.empty()) {
        return "";
    }
    if (!CopyFileFast(filePath, destination)) {
        APP_LOGE("copy file from %{public}s to %{public}s failed", filePath.c_str(), destination.c_str());
        return "";
    }
    return destination;
}

void BundleUtil::DeleteTempDirs(const std::vector<std::string> &tempDirs)
{
    for (const auto &tempDir : tempDirs) {
        APP_LOGD("the temp hap dir %{public}s needs to be deleted", tempDir.c_str());
        BundleUtil::DeleteDir(tempDir);
    }
}

std::string BundleUtil::GetHexHash(const std::string &s)
{
    std::hash<std::string> hasher;
    size_t hash = hasher(s);

    std::stringstream ss;
    ss << std::hex << hash;

    std::string hash_str = ss.str();
    return hash_str;
}

void BundleUtil::RecursiveHash(std::string& s)
{
    if (s.size() >= ORIGIN_STRING_LENGTH) {
        s = s.substr(s.size() - ORIGIN_STRING_LENGTH);
        return;
    }
    std::string hash = GetHexHash(s);
    s += hash;
    RecursiveHash(s);
}

std::string BundleUtil::GenerateUuid()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    auto currentTime = std::chrono::system_clock::now();
    auto timestampNanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(currentTime.time_since_epoch()).count();

    // convert nanosecond timestamps to string
    std::string s = std::to_string(timestampNanoseconds);
    std::string timeStr = GetHexHash(s);

    char deviceId[UUID_LENGTH_MAX] = { 0 };
    auto ret = GetDevUdid(deviceId, UUID_LENGTH_MAX);
    std::string deviceUdid;
    std::string deviceStr;
    if (ret != 0) {
        APP_LOGW("GetDevUdid failed");
    } else {
        deviceUdid = std::string{ deviceId };
        deviceStr = GetHexHash(deviceUdid);
    }

    std::string uuid = timeStr + deviceStr;
    RecursiveHash(uuid);

    for (int32_t index : SEPARATOR_POSITIONS) {
        uuid.insert(index, 1, UUID_SEPARATOR);
    }
    return uuid;
}

std::string BundleUtil::GenerateUuidByKey(const std::string &key)
{
    std::string keyHash = GetHexHash(key);

    char deviceId[UUID_LENGTH_MAX] = { 0 };
    auto ret = GetDevUdid(deviceId, UUID_LENGTH_MAX);
    std::string deviceUdid;
    std::string deviceStr;
    if (ret != 0) {
        APP_LOGW("GetDevUdid failed");
    } else {
        deviceUdid = std::string{ deviceId };
        deviceStr = GetHexHash(deviceUdid);
    }

    std::string uuid = keyHash + deviceStr;
    RecursiveHash(uuid);

    for (int32_t index : SEPARATOR_POSITIONS) {
        uuid.insert(index, 1, UUID_SEPARATOR);
    }
    return uuid;
}

std::string BundleUtil::ExtractGroupIdByDevelopId(const std::string &developerId)
{
    std::string::size_type dot_position = developerId.find('.');
    if (dot_position == std::string::npos) {
        // If cannot find '.' , the input string is developerId, return developerId
        return developerId;
    }
    if (dot_position == 0) {
        // if'.' In the first place, then groupId is empty, return developerId
        return developerId.substr(1);
    }
    // If '.' If it is not the first place, there is a groupId, and the groupId is returned
    return developerId.substr(0, dot_position);
}

std::string BundleUtil::ToString(const std::vector<std::string> &vector)
{
    std::string ret;
    for (const std::string &item : vector) {
        ret.append(item).append(",");
    }
    return ret;
}

std::string BundleUtil::GetNoDisablingConfigPath()
{
#ifdef CONFIG_POLOCY_ENABLE
    char buf[MAX_PATH_LEN] = { 0 };
    char *configPath = GetOneCfgFile(NO_DISABLING_CONFIG_PATH, buf, MAX_PATH_LEN);
    if (configPath == nullptr || configPath[0] == '\0' || strlen(configPath) > MAX_PATH_LEN) {
        return NO_DISABLING_CONFIG_PATH_DEFAULT;
    }
    return configPath;
#else
    return NO_DISABLING_CONFIG_PATH_DEFAULT;
#endif
}
}  // namespace AppExecFwk
}  // namespace OHOS
