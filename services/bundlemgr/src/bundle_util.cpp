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

#include "bundle_util.h"

#include <cinttypes>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <random>
#include <sstream>
#include <sys/sendfile.h>
#include <sys/statfs.h>
#include <vector>

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
constexpr int64_t HALF_GB = 1024 * 1024 * 512; // 0.5GB
constexpr int8_t SPACE_NEED_DOUBLE = 2;
static std::string g_deviceUdid;
// hmdfs and sharefs config
constexpr const char* BUNDLE_ID_FILE = "appid";
// single max hap size
constexpr int64_t ONE_GB = 1024 * 1024 * 1024;
constexpr int64_t MAX_HAP_SIZE = ONE_GB * 4;  // 4GB
constexpr const char* ABC_FILE_PATH = "abc_files";
constexpr const char* PGO_FILE_PATH = "pgo_files";
#ifdef CONFIG_POLOCY_ENABLE
const char* NO_DISABLING_CONFIG_PATH = "/etc/ability_runtime/resident_process_in_extreme_memory.json";
#endif
const char* NO_DISABLING_CONFIG_PATH_DEFAULT =
    "/system/etc/ability_runtime/resident_process_in_extreme_memory.json";
const std::string EMPTY_STRING = "";
constexpr int64_t DISK_REMAINING_SIZE_LIMIT = 1024 * 1024 * 10; // 10M
constexpr uint32_t RANDOM_NUMBER_LENGTH = 255;
constexpr uint32_t SANDBOX_PATH_INDEX = 0;
constexpr uint32_t ID_INVALID = 0;
constexpr const char* COLON = ":";
constexpr const char* DEFAULT_START_WINDOW_BACKGROUND_IMAGE_FIT_VALUE = "Cover";
constexpr const char* APP_INSTALL_PREFIX = "+app_install+";
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
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
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
            APP_LOGE("bundlePath not existed with :%{public}s errno %{public}d", bundlePaths.front().c_str(), errno);
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
    int64_t freeSize = static_cast<int64_t>(diskInfo.f_bavail * diskInfo.f_bsize);
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

bool BundleUtil::CheckSystemFreeSize(const std::string &path, int64_t size)
{
    struct statfs diskInfo = { 0 };
    if (statfs(path.c_str(), &diskInfo) != 0) {
        APP_LOGE("call statfs error:%{public}d", errno);
        return false;
    }
    int64_t freeSize = static_cast<int64_t>(diskInfo.f_bavail * diskInfo.f_bsize);
    return freeSize >= size;
}

bool BundleUtil::CheckSystemSizeAndHisysEvent(const std::string &path, const std::string &fileName)
{
    struct statfs diskInfo = { 0 };
    if (statfs(path.c_str(), &diskInfo) != 0) {
        APP_LOGE("call statfs error:%{public}d", errno);
        return false;
    }
    int64_t freeSize = static_cast<int64_t>(diskInfo.f_bavail * diskInfo.f_bsize);
    return freeSize < DISK_REMAINING_SIZE_LIMIT;
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
            continue;
        }
        hapFileList.emplace_back(realPath);
        APP_LOGD("find hap path %{public}s", realPath.c_str());

        if (!hapFileList.empty() && (hapFileList.size() > ServiceConstants::MAX_HAP_NUMBER)) {
            APP_LOGE("reach the max hap number 128, stop to add more");
            closedir(dir);
            return false;
        }
    }
    APP_LOGI("hap number: %{public}zu", hapFileList.size());
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
    MakeFsConfig(bundleName, configPath, std::to_string(bundleId), std::string(BUNDLE_ID_FILE));
}

void BundleUtil::MakeFsConfig(const std::string &bundleName, const std::string &configPath,
    const std::string labelValue, const std::string labelPath)
{
    std::string bundleDir = configPath + ServiceConstants::PATH_SEPARATOR + bundleName;
    if (access(bundleDir.c_str(), F_OK) != 0) {
        APP_LOGD("fail to access error:%{public}d", errno);
        if (mkdir(bundleDir.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
            APP_LOGE("make bundle dir error:%{public}d", errno);
            return;
        }
    }
    std::string finalLabelValue = labelValue;
    if (labelPath == Constants::APP_PROVISION_TYPE_FILE_NAME) {
        finalLabelValue = finalLabelValue ==
            Constants::APP_PROVISION_TYPE_DEBUG ? Constants::DEBUG_TYPE_VALUE : Constants::RELEASE_TYPE_VALUE;
    }
    std::string realBundleDir;
    if (!PathToRealPath(bundleDir, realBundleDir)) {
        APP_LOGE("bundleIdFile is not real path");
        return;
    }

    realBundleDir += std::string(ServiceConstants::PATH_SEPARATOR) + labelPath;
    int32_t bundleIdFd = open(realBundleDir.c_str(), O_WRONLY | O_TRUNC);
    if (bundleIdFd > 0) {
        if (write(bundleIdFd, finalLabelValue.c_str(), finalLabelValue.size()) < 0) {
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
    std::string pathseparator = ServiceConstants::PATH_SEPARATOR;
    if (type == DirType::STREAM_INSTALL_DIR) {
        tempDir += pathseparator + ServiceConstants::STREAM_INSTALL_PATH;
    } else if (type == DirType::QUICK_FIX_DIR) {
        tempDir += pathseparator + ServiceConstants::QUICK_FIX_PATH;
    } else if (type == DirType::SIG_FILE_DIR) {
        tempDir += pathseparator + ServiceConstants::SIGNATURE_FILE_PATH;
    } else if (type == DirType::PGO_FILE_DIR) {
        tempDir += pathseparator + PGO_FILE_PATH;
    } else if (type == DirType::ABC_FILE_DIR) {
        tempDir += pathseparator + ABC_FILE_PATH;
    } else if (type == DirType::EXT_RESOURCE_FILE_DIR) {
        tempDir += pathseparator + ServiceConstants::EXT_RESOURCE_FILE_PATH;
    } else if (type == DirType::EXT_PROFILE_DIR) {
        tempDir += pathseparator + ServiceConstants::EXT_PROFILE;
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
    tempDir += std::string(ServiceConstants::PATH_SEPARATOR) + ServiceConstants::STREAM_INSTALL_PATH;
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
        APP_LOGD("fail stat errno:%{public}d", errno);
        return false;
    }

    return S_ISREG(buf.st_mode);
}

bool BundleUtil::IsExistFileNoLog(const std::string &path)
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

bool BundleUtil::IsExistDirNoLog(const std::string &path)
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

bool BundleUtil::IsPathInformationConsistent(const std::string &path, int32_t uid, int32_t gid)
{
    if (path.empty()) {
        return false;
    }
    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        return false;
    }
    if ((static_cast<int32_t>(buf.st_uid) != uid) || ((static_cast<int32_t>(buf.st_gid) != gid))) {
        APP_LOGE("path uid or gid is not same");
        return false;
    }
    return true;
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

    if (rename(oldPath.c_str(), newPath.c_str()) != 0) {
        APP_LOGE("rename failed, errno:%{public}d", errno);
        return false;
    }
    return true;
}

bool BundleUtil::DeleteDir(const std::string &path)
{
    if (IsExistFile(path)) {
        return OHOS::RemoveFile(path);
    }

    if (IsExistDir(path)) {
        return OHOS::ForceRemoveDirectoryBMS(path);
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

bool BundleUtil::IsSpecificUtd(const std::string &param)
{
    if (!IsUtd(param)) {
        return false;
    }
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
    std::shared_ptr<UDMF::TypeDescriptor> typeDescriptor;
    auto ret = UDMF::UtdClient::GetInstance().GetTypeDescriptor(param, typeDescriptor);
    if (ret != ERR_OK || typeDescriptor == nullptr) {
        return false;
    }
    std::vector<std::string> mimeTypes = typeDescriptor->GetMimeTypes();
    std::vector<std::string> filenameExtensions = typeDescriptor->GetFilenameExtensions();
    return !mimeTypes.empty() || !filenameExtensions.empty();
#else
    return false;
#endif
}

std::vector<std::string> BundleUtil::GetUtdVectorByMimeType(const std::string &mimeType)
{
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
    std::vector<std::string> utdVector;
    auto ret = UDMF::UtdClient::GetInstance().GetUniformDataTypesByMIMEType(mimeType, utdVector);
    if (ret != ERR_OK || utdVector.empty()) {
        return {};
    }
    return utdVector;
#else
    return {};
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

bool BundleUtil::CopyFileFast(const std::string &sourcePath, const std::string &destPath, const bool needFsync)
{
    APP_LOGI("sourcePath : %{private}s, destPath : %{private}s", sourcePath.c_str(), destPath.c_str());
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
    if (needFsync) {
        (void)fsync(destFd);
    }
    close(destFd);
    APP_LOGD("sendfile success");
    return true;
}

Resource BundleUtil::GetResource(const std::string &bundleName, const std::string &moduleName, uint32_t resId)
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
        (sandBoxPath.find(ServiceConstants::SANDBOX_DATA_PATH) == std::string::npos &&
        sandBoxPath.find(ServiceConstants::APP_INSTALL_SANDBOX_PATH) == std::string::npos)) {
        APP_LOGE("input sandboxPath or bundleName invalid");
        return false;
    }

    realPath = sandBoxPath;
    if (sandBoxPath.find(ServiceConstants::SANDBOX_DATA_PATH) == 0) {
        std::string relaDataPath = std::string(ServiceConstants::REAL_DATA_PATH) + ServiceConstants::PATH_SEPARATOR
            + std::to_string(BundleUtil::GetUserIdByCallingUid()) + ServiceConstants::BASE + bundleName;
        realPath.replace(realPath.find(ServiceConstants::SANDBOX_DATA_PATH),
            std::string(ServiceConstants::SANDBOX_DATA_PATH).size(), relaDataPath);
    } else if (sandBoxPath.find(ServiceConstants::APP_INSTALL_SANDBOX_PATH) == 0) {
        std::string relaDataPath = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
            ServiceConstants::GALLERY_DOWNLOAD_PATH + std::to_string(BundleUtil::GetUserIdByCallingUid());
        realPath.replace(realPath.find(ServiceConstants::APP_INSTALL_SANDBOX_PATH),
            std::string(ServiceConstants::APP_INSTALL_SANDBOX_PATH).size(), relaDataPath);
    } else {
        APP_LOGE("input sandboxPath invalid");
        return false;
    }
    return true;
}

bool BundleUtil::IsSandBoxPath(const std::string &path)
{
    if (path.empty()) {
        return false;
    }
    return path.find(ServiceConstants::SANDBOX_DATA_PATH) == SANDBOX_PATH_INDEX;
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
    std::vector<std::string> &toDeletePaths, bool rename)
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
    destination.append(ServiceConstants::PATH_SEPARATOR);
    destination.append(GetAppInstallPrefix(filePath, rename));
    destination.append(std::to_string(GetCurrentTimeNs()));
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
    if (rename) {
        APP_LOGD("rename file from %{public}s to %{public}s", filePath.c_str(), destination.c_str());
        if (!RenameFile(filePath, destination)) {
            APP_LOGE("rename file from %{private}s to %{private}s failed", filePath.c_str(), destination.c_str());
            return "";
        }
    } else {
        if (!CopyFileFast(filePath, destination)) {
            APP_LOGE("copy file from %{private}s to %{private}s failed", filePath.c_str(), destination.c_str());
            return "";
        }
    }
    return destination;
}

std::string BundleUtil::GetAppInstallPrefix(const std::string &filePath, bool rename)
{
    // get ${bundleName} and ${userId} from
    // /data/service/el1/public/bms/bundle_manager_service/app_install/${userId}/${bundleName}/${fileName}.hap
    if (!rename) {
        return "";
    }
    std::string prefix = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::GALLERY_DOWNLOAD_PATH;
    if (filePath.find(prefix) != 0) {
        return "";
    }
    // ${userId}/${bundleName}/${fileName}.hap
    std::string tempStr = filePath.substr(prefix.length());
    auto pos = tempStr.rfind(ServiceConstants::PATH_SEPARATOR);
    if (pos == std::string::npos) {
        return "";
    }
    // ${userId}/${bundleName}
    tempStr = tempStr.substr(0, pos);
    pos = tempStr.rfind(ServiceConstants::PATH_SEPARATOR);
    if (pos == std::string::npos) {
        return "";
    }
    if (pos != tempStr.find(ServiceConstants::PATH_SEPARATOR)) {
        return "";
    }
    std::string bundleName = tempStr.substr(pos + 1);
    std::string userId = tempStr.substr(0, pos);
    if (bundleName.empty() || userId.empty()) {
        return "";
    }
    // +app_install+${bundleName}+${userId}+
    std::string newPrefix = std::string(APP_INSTALL_PREFIX) + bundleName + ServiceConstants::PLUS_SIGN + userId +
        ServiceConstants::PLUS_SIGN;
    APP_LOGI("newPrefix is %{public}s", newPrefix.c_str());
    return newPrefix;
}

void BundleUtil::RestoreAppInstallHaps()
{
    std::string securityPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
        ServiceConstants::SECURITY_STREAM_INSTALL_PATH + ServiceConstants::PATH_SEPARATOR;
    DIR* dir = opendir(securityPath.c_str());
    if (dir == nullptr) {
        APP_LOGE("open security dir failed errno:%{public}d", errno);
        return;
    }
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (entry->d_type != DT_DIR) {
            continue;
        }
        std::string dirName = std::string(entry->d_name);
        if (dirName.find(APP_INSTALL_PREFIX) != 0) {
            continue;
        }
        // parse bundleName and userId from +app_install+${bundleName}+${userId}+${fileName}
        std::string temp = dirName.substr(strlen(APP_INSTALL_PREFIX));
        auto pos = temp.find(ServiceConstants::PLUS_SIGN);
        if (pos == std::string::npos) {
            continue;
        }
        std::string bundleName = temp.substr(0, pos);
        temp = temp.substr(pos + 1);
        pos = temp.find(ServiceConstants::PLUS_SIGN);
        if (pos == std::string::npos) {
            continue;
        }
        std::string userId = temp.substr(0, pos);
        RestoreHaps(securityPath + dirName + ServiceConstants::PATH_SEPARATOR, bundleName, userId);
    }
    closedir(dir);
}

void BundleUtil::RestoreHaps(const std::string &sourcePath, const std::string &bundleName, const std::string &userId)
{
    if (sourcePath.empty() || bundleName.empty() || userId.empty()) {
        return;
    }
    if (OHOS::IsEmptyFolder(sourcePath)) {
        return;
    }
    std::string destPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::GALLERY_DOWNLOAD_PATH +
        userId + ServiceConstants::PATH_SEPARATOR + bundleName + ServiceConstants::PATH_SEPARATOR;
    struct stat buf = {};
    if (stat(destPath.c_str(), &buf) != 0 || !S_ISDIR(buf.st_mode)) {
        APP_LOGE("app install bundlename dir not exist");
        return;
    }
    DIR* dir = opendir(sourcePath.c_str());
    if (dir == nullptr) {
        APP_LOGE("open security dir failed errno:%{public}d", errno);
        return;
    }
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        std::string fileName = std::string(entry->d_name);
        std::string sourceFile = sourcePath + fileName;
        std::string destFile = destPath + fileName;
        APP_LOGI("restore file from %{public}s to %{public}s", sourceFile.c_str(), destFile.c_str());
        if (!RenameFile(sourceFile, destFile)) {
            APP_LOGE("restore file from %{public}s to %{public}s failed", sourceFile.c_str(), destFile.c_str());
        }
    }
    closedir(dir);
    if (OHOS::IsEmptyFolder(sourcePath)) {
        BundleUtil::DeleteDir(sourcePath);
    }
}

void BundleUtil::DeleteTempDirs(const std::vector<std::string> &tempDirs)
{
    for (const auto &tempDir : tempDirs) {
        APP_LOGD("the temp hap dir %{public}s needs to be deleted", tempDir.c_str());
        BundleUtil::DeleteDir(tempDir);
    }
}

std::vector<uint8_t> BundleUtil::GenerateRandomNumbers(uint8_t size, uint8_t lRange, uint8_t rRange)
{
    std::vector<uint8_t> rangeV;
    if (size == 0 || size > RANDOM_NUMBER_LENGTH) {
        return rangeV;
    }
    rangeV.resize(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> distributionNum(lRange, rRange);

    std::generate(rangeV.begin(), rangeV.end(), [&]() { return distributionNum(gen); });
    return rangeV;
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
    if (configPath == nullptr || configPath[0] == '\0') {
        APP_LOGE("BundleUtil GetOneCfgFile failed");
        return NO_DISABLING_CONFIG_PATH_DEFAULT;
    }
    if (strlen(configPath) > MAX_PATH_LEN) {
        APP_LOGE("length exceeds");
        return NO_DISABLING_CONFIG_PATH_DEFAULT;
    }
    return configPath;
#else
    return NO_DISABLING_CONFIG_PATH_DEFAULT;
#endif
}

uint32_t BundleUtil::ExtractNumberFromString(nlohmann::json &jsonObject, const std::string &key)
{
    std::string str;
    if (jsonObject.find(key) == jsonObject.end()) {
        APP_LOGE("not find key");
        return ID_INVALID;
    }
    if (!jsonObject.at(key).is_string()) {
        APP_LOGE("key is not string");
        return ID_INVALID;
    }
    str = jsonObject.at(key).get<std::string>();
    if (str.empty() || str.length() > Constants::MAX_JSON_STRING_LENGTH) {
        APP_LOGE("exceeding the maximum string length");
        return ID_INVALID;
    }
    size_t index = str.find(COLON);
    if ((index == std::string::npos) || (index == str.length() - 1)) {
        APP_LOGE("not find colon or format error");
        return ID_INVALID;
    }
    std::string numberStr = str.substr(index + 1);
    if (numberStr.empty()) {
        APP_LOGE("number string is empty");
        return ID_INVALID;
    }
    uint32_t data = 0;
    if (!StrToUint32(numberStr, data)) {
        APP_LOGE("conversion failure");
        return ID_INVALID;
    }
    return data;
}

bool BundleUtil::StrToUint32(const std::string &str, uint32_t &value)
{
    if (str.empty() || !isdigit(str.front())) {
        APP_LOGE("str is empty!");
        return false;
    }
    char* end = nullptr;
    errno = 0;
    auto addr = str.c_str();
    auto result = strtoul(addr, &end, 10); /* 10 means decimal */
    if ((end == addr) || (end[0] != '\0') || (errno == ERANGE) ||
        (result > UINT32_MAX)) {
        APP_LOGE("the result was incorrect!");
        return false;
    }
    value = static_cast<uint32_t>(result);
    return true;
}

std::string BundleUtil::ExtractStringFromJson(nlohmann::json &jsonObject, const std::string &key)
{
    std::string str = DEFAULT_START_WINDOW_BACKGROUND_IMAGE_FIT_VALUE;
    if (jsonObject.find(key) == jsonObject.end()) {
        APP_LOGW("the default value is Cover");
        return str;
    }
    if (!jsonObject.at(key).is_string()) {
        APP_LOGE("key is not string");
        return str;
    }
    str = jsonObject.at(key).get<std::string>();
    if (str.empty() || str.length() > Constants::MAX_JSON_STRING_LENGTH) {
        APP_LOGE("exceeding the maximum string length");
        return DEFAULT_START_WINDOW_BACKGROUND_IMAGE_FIT_VALUE;
    }
    return str;
}

std::unordered_map<std::string, std::string> BundleUtil::ParseMapFromJson(const std::string &jsonStr)
{
    std::unordered_map<std::string, std::string> result;
    if (jsonStr.empty()) {
        APP_LOGD("jsonStr is empty");
        return result;
    }
    APP_LOGD("ParseMapFromJson from %{public}s", jsonStr.c_str());
    nlohmann::json jsonBuf = nlohmann::json::parse(jsonStr, nullptr, false);
    if (jsonBuf.is_discarded()) {
        APP_LOGE("json file discarded");
        return result;
    }
    if (!jsonBuf.is_object()) {
        APP_LOGE("jsonBuf is not object");
        return result;
    }
    for (const auto& [key, value] : jsonBuf.items()) {
        result[key] = value.is_string() ? value.get<std::string>() : value.dump();
    }
    return result;
}

void BundleUtil::SetBit(const uint8_t pos, uint8_t &num)
{
    num |= (1U << pos);
}

void BundleUtil::ResetBit(const uint8_t pos, uint8_t &num)
{
    num &= ~(1U << pos);
}

bool BundleUtil::GetBitValue(const uint8_t num, const uint8_t pos)
{
    return (num & (1U << pos)) != 0;
}

std::unordered_set<std::string> BundleUtil::ParseAppStartupBundleNames(const std::string &confFilePath)
{
    std::unordered_set<std::string> bundleNames;
    std::ifstream file(confFilePath);
    
    if (!file.is_open()) {
        APP_LOGE("fail to open %{public}s file, errno:%{public}d",
            confFilePath.c_str(), errno);
        return bundleNames;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        // Remove leading and trailing whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        // Find the end of bundle name (before' ' or '#')
        size_t endPos = line.find_first_of("# \t");
        if (endPos == std::string::npos) {
            endPos = line.length();
        }
        
        std::string bundleName = line.substr(0, endPos);
        if (!bundleName.empty()) {
            bundleNames.insert(bundleName);
        }
    }
    return bundleNames;
}
}  // namespace AppExecFwk
}  // namespace OHOS
