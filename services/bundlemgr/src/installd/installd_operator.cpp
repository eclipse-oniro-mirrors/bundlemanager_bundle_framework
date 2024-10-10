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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/quota.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "app_log_tag_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "directory_ex.h"
#include "el5_filekey_manager_kit.h"
#include "parameters.h"
#include "securec.h"
#include "hnp_api.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* PREFIX_RESOURCE_PATH = "/resources/rawfile/";
constexpr const char* PREFIX_TARGET_PATH = "/print_service/";
constexpr const char* HQF_DIR_PREFIX = "patch_";
#if defined(CODE_ENCRYPTION_ENABLE)
static const char LIB_CODE_CRYPTO_SO_PATH[] = "system/lib/libcode_crypto_metadata_process_utils.z.so";
static const char LIB64_CODE_CRYPTO_SO_PATH[] = "system/lib64/libcode_crypto_metadata_process_utils.z.so";
static const char CODE_CRYPTO_FUNCTION_NAME[] = "_ZN4OHOS8Security10CodeCrypto15CodeCryptoUtils28"
    "EnforceMetadataProcessForAppERKNSt3__h13unordered_mapINS3_12basic_stringIcNS3_11char_traitsIcEENS3_"
    "9allocatorIcEEEESA_NS3_4hashISA_EENS3_8equal_toISA_EENS8_INS3_4pairIKSA_SA_EEEEEEjRbNS2_17InstallBundleTypeERKb";
#endif
static constexpr int32_t INSTALLS_UID = 3060;
static constexpr int32_t MODE_BASE = 07777;
static constexpr int32_t KEY_ID_STEP = 2;
constexpr const char* PROC_MOUNTS_PATH = "/proc/mounts";
constexpr const char* QUOTA_DEVICE_DATA_PATH = "/data";
constexpr const char* CACHE_DIR = "cache";
constexpr const char* BUNDLE_BASE_CODE_DIR = "/data/app/el1/bundle";
constexpr const char* AP_PATH = "ap/";
constexpr const char* AI_SUFFIX = ".ai";
constexpr const char* DIFF_SUFFIX = ".diff";
constexpr const char* BUNDLE_BACKUP_KEEP_DIR = "/.backup";
constexpr const char* ATOMIC_SERVICE_PATH = "+auid-";
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

    return dir + ServiceConstants::PATH_SEPARATOR + subName;
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
    return false;
}
} // namespace

#define FSCRYPT_KEY_DESCRIPTOR_SIZE 8
#define HMFS_IOCTL_MAGIC 0xf5
#define HMFS_IOC_SET_ASDP_ENCRYPTION_POLICY _IOW(HMFS_IOCTL_MAGIC, 84, struct fscrypt_asdp_policy)
#define FORCE_PROTECT 0x0

struct fscrypt_asdp_policy {
    char version;
    char asdp_class;
    char flags;
    char reserved;
    char app_key2_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
} __attribute__((__packed__));

bool InstalldOperator::IsExistFile(const std::string &path)
{
    if (path.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "path is empty");
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLD, "stat fail %{public}d", errno);
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
        LOG_E(BMS_TAG_INSTALLD, "Error occurred while opening apDir: %{public}s", errorCode.message().c_str());
        return false;
    }
    for (const auto& entry : iter) {
        if (entry.path().extension() == ServiceConstants::AP_SUFFIX) {
            return true;
        }
    }
    return false;
}

bool InstalldOperator::IsExistDir(const std::string &path)
{
    if (path.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "path is empty");
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
        LOG_E(BMS_TAG_INSTALLD, "mkdir failed");
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
        LOG_NOFUNC_I(BMS_TAG_COMMON, "del %{public}s", path.c_str());
        return OHOS::ForceRemoveDirectory(path);
    }
    return true;
}

bool InstalldOperator::ExtractFiles(const std::string &sourcePath, const std::string &targetSoPath,
    const std::string &cpuAbi)
{
    LOG_D(BMS_TAG_INSTALLD, "InstalldOperator::ExtractFiles start");
    if (targetSoPath.empty()) {
        LOG_D(BMS_TAG_INSTALLD, "targetSoPath is empty");
        return true;
    }

    BundleExtractor extractor(sourcePath);
    if (!extractor.Init()) {
        return false;
    }

    std::vector<std::string> soEntryFiles;
    if (!ObtainNativeSoFile(extractor, cpuAbi, soEntryFiles)) {
        LOG_E(BMS_TAG_INSTALLD, "ExtractFiles obtain native so file entryName failed");
        return false;
    }

    for_each(soEntryFiles.begin(), soEntryFiles.end(), [&extractor, &targetSoPath, &cpuAbi](const auto &entry) {
        ExtractTargetFile(extractor, entry, targetSoPath, cpuAbi);
    });

    LOG_D(BMS_TAG_INSTALLD, "InstalldOperator::ExtractFiles end");
    return true;
}

bool InstalldOperator::ExtractFiles(const ExtractParam &extractParam)
{
    LOG_D(BMS_TAG_INSTALLD, "InstalldOperator::ExtractFiles start");
    BundleExtractor extractor(extractParam.srcPath);
    if (!extractor.Init()) {
        LOG_E(BMS_TAG_INSTALLD, "extractor init failed");
        return false;
    }

    if (extractParam.extractFileType == ExtractFileType::RESOURCE) {
        return ExtractResourceFiles(extractParam, extractor);
    }

    if ((extractParam.extractFileType == ExtractFileType::AP) &&
        !extractor.IsDirExist(AP_PATH)) {
        LOG_D(BMS_TAG_INSTALLD, "hap has no ap files and does not need to be extracted");
        return true;
    }

    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames) || entryNames.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "get entryNames failed");
        return false;
    }

    for (const auto &entryName : entryNames) {
        if (strcmp(entryName.c_str(), ".") == 0 ||
            strcmp(entryName.c_str(), "..") == 0) {
            continue;
        }
        if (entryName.back() == ServiceConstants::PATH_SEPARATOR[0]) {
            continue;
        }
        // handle native file
        if (IsNativeFile(entryName, extractParam)) {
            ExtractTargetFile(extractor, entryName, extractParam.targetPath,
                extractParam.cpuAbi, extractParam.extractFileType);
            continue;
        }
    }

    LOG_D(BMS_TAG_INSTALLD, "InstalldOperator::ExtractFiles end");
    return true;
}

bool InstalldOperator::ExtractFiles(const std::string hnpPackageInfo, const ExtractParam &extractParam)
{
    std::map<std::string, std::string> hnpPackageInfoMap;
    std::stringstream hnpPackageInfoString(hnpPackageInfo);
    std::string keyValue;
    while (getline(hnpPackageInfoString, keyValue, '}')) {
        size_t pos = keyValue.find(":");
        if (pos != std::string::npos) {
            std::string key = keyValue.substr(1, pos - 1);
            std::string value = keyValue.substr(pos + 1);
            hnpPackageInfoMap[key] = value;
        }
    }

    BundleExtractor extractor(extractParam.srcPath);
    if (!extractor.Init()) {
        LOG_E(BMS_TAG_INSTALLD, "extractor init failed");
        return false;
    }

    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames) || entryNames.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "get entryNames failed");
        return false;
    }
    std::string targetPathAndName = "";
    for (const auto &entryName : entryNames) {
        if (strcmp(entryName.c_str(), ".") == 0 ||
            strcmp(entryName.c_str(), "..") == 0) {
                continue;
        }
        if (entryName.back() == ServiceConstants::PATH_SEPARATOR[0]) {
            continue;
        }
        // handle native file
        if (IsNativeFile(entryName, extractParam)) {
            std::string prefix;

            if (!DeterminePrefix(extractParam.extractFileType, extractParam.cpuAbi, prefix)) {
                LOG_E(BMS_TAG_INSTALLD, "determine prefix failed");
                return false;
            }
            
            std::string targetName = entryName.substr(prefix.length());
            if (hnpPackageInfoMap.find(targetName) == hnpPackageInfoMap.end()) {
                LOG_E(BMS_TAG_INSTALLD, "illegal native bundle");
                continue;
            }
            targetPathAndName = extractParam.targetPath + hnpPackageInfoMap[targetName]
                                + ServiceConstants::PATH_SEPARATOR + targetName;
            ExtractTargetHnpFile(extractor, entryName, targetPathAndName, extractParam.extractFileType);
            hnpPackageInfoMap.erase(targetName);
            continue;
        }
    }

    if (hnpPackageInfoMap.size() > 0) {
        return false;
    }
    LOG_D(BMS_TAG_INSTALLD, "InstalldOperator::ExtractFiles end");
    return true;
}
bool InstalldOperator::IsNativeFile(
    const std::string &entryName, const ExtractParam &extractParam)
{
    LOG_D(BMS_TAG_INSTALLD, "IsNativeFile, entryName : %{public}s", entryName.c_str());
    if (extractParam.targetPath.empty()) {
        LOG_D(BMS_TAG_INSTALLD, "current hap not include so");
        return false;
    }
    std::string prefix;
    std::vector<std::string> suffixes;
    if (!DeterminePrefix(extractParam.extractFileType, extractParam.cpuAbi, prefix) ||
        !DetermineSuffix(extractParam.extractFileType, suffixes)) {
        LOG_E(BMS_TAG_INSTALLD, "determine prefix or suffix failed");
        return false;
    }

    if (!StartsWith(entryName, prefix)) {
        LOG_D(BMS_TAG_INSTALLD, "entryName not start with %{public}s", prefix.c_str());
        return false;
    }

    bool checkSuffix = false;
    for (const auto &suffix : suffixes) {
        if (EndsWith(entryName, suffix)) {
            checkSuffix = true;
            break;
        }
    }

    if (!checkSuffix && extractParam.extractFileType != ExtractFileType::RES_FILE
        && extractParam.extractFileType != ExtractFileType::SO
        && extractParam.extractFileType != ExtractFileType::HNPS_FILE) {
        LOG_D(BMS_TAG_INSTALLD, "file type error");
        return false;
    }

    LOG_D(BMS_TAG_INSTALLD, "find native file, prefix: %{public}s, entryName: %{public}s",
        prefix.c_str(), entryName.c_str());
    return true;
}

bool InstalldOperator::IsNativeSo(const std::string &entryName, const std::string &cpuAbi)
{
    LOG_D(BMS_TAG_INSTALLD, "IsNativeSo, entryName : %{public}s", entryName.c_str());
    std::string prefix = ServiceConstants::LIBS + cpuAbi + ServiceConstants::PATH_SEPARATOR;
    if (!StartsWith(entryName, prefix)) {
        LOG_D(BMS_TAG_INSTALLD, "entryName not start with %{public}s", prefix.c_str());
        return false;
    }
    LOG_D(BMS_TAG_INSTALLD, "find native so, entryName : %{public}s", entryName.c_str());
    return true;
}

bool InstalldOperator::IsDiffFiles(const std::string &entryName,
    const std::string &targetPath, const std::string &cpuAbi)
{
    LOG_D(BMS_TAG_INSTALLD, "IsDiffFiles, entryName : %{public}s", entryName.c_str());
    if (targetPath.empty()) {
        LOG_D(BMS_TAG_INSTALLD, "current hap not include diff");
        return false;
    }
    std::string prefix = ServiceConstants::LIBS + cpuAbi + ServiceConstants::PATH_SEPARATOR;
    if (!StartsWith(entryName, prefix)) {
        LOG_D(BMS_TAG_INSTALLD, "entryName not start with %{public}s", prefix.c_str());
        return false;
    }
    if (!EndsWith(entryName, DIFF_SUFFIX)) {
        LOG_D(BMS_TAG_INSTALLD, "file name not diff format");
        return false;
    }
    LOG_D(BMS_TAG_INSTALLD, "find native diff, entryName : %{public}s", entryName.c_str());
    return true;
}

void InstalldOperator::ExtractTargetHnpFile(const BundleExtractor &extractor, const std::string &entryName,
    const std::string &targetPath, const ExtractFileType &extractFileType)
{
    std::string path = targetPath;
    std::string dir = GetPathDir(path);
    if (!IsExistDir(dir) && !MkRecursiveDir(dir, true)) {
        LOG_E(BMS_TAG_INSTALLD, "create dir %{public}s failed", dir.c_str());
        return;
    }
    bool ret = extractor.ExtractFile(entryName, path);
    if (!ret) {
        LOG_E(BMS_TAG_INSTALLD, "extract file failed, entryName : %{public}s", entryName.c_str());
        return;
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (extractFileType == ExtractFileType::AP) {
        struct stat buf = {};
        if (stat(targetPath.c_str(), &buf) != 0) {
            LOG_E(BMS_TAG_INSTALLD, "fail to stat errno:%{public}d", errno);
            return;
        }
        ChangeFileAttr(path, buf.st_uid, buf.st_gid);
        mode = (buf.st_uid == buf.st_gid) ? (S_IRUSR | S_IWUSR) : (S_IRUSR | S_IWUSR | S_IRGRP);
    }
    if (!OHOS::ChangeModeFile(path, mode)) {
        LOG_E(BMS_TAG_INSTALLD, "ChangeModeFile %{public}s failed, errno: %{public}d", path.c_str(), errno);
        return;
    }
    LOG_D(BMS_TAG_INSTALLD, "extract file success, path : %{public}s", path.c_str());
}

bool InstalldOperator::ProcessBundleInstallNative(const std::string &userId, const std::string &hnpRootPath,
    const std::string &hapPath, const std::string &cpuAbi, const std::string &packageName)
{
    struct HapInfo hapInfo;
    int res = strcpy_s(hapInfo.packageName, packageName.length() + 1, packageName.c_str());
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "failed to strcpy_s packageName");
    }
    res = strcpy_s(hapInfo.hapPath, hapPath.length() + 1, hapPath.c_str());
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "failed to strcpy_s hapPath");
    }
    res = strcpy_s(hapInfo.abi, cpuAbi.length() + 1, cpuAbi.c_str());
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "failed to strcpy_s cpuAbi");
    }
    int ret = NativeInstallHnp(userId.c_str(), hnpRootPath.c_str(), &hapInfo, 1);
    LOG_D(BMS_TAG_INSTALLD, "NativeInstallHnp ret: %{public}d", ret);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLD, "Native package installation failed with error code: %{public}d", ret);
        return false;
    }
    return true;
}

bool InstalldOperator::ProcessBundleUnInstallNative(const std::string &userId, const std::string &packageName)
{
    int ret = NativeUnInstallHnp(userId.c_str(), packageName.c_str());
    LOG_D(BMS_TAG_INSTALLD, "NativeUnInstallHnp ret: %{public}d", ret);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLD, "Native package uninstallation failed with error code: %{public}d", ret);
        return false;
    }
    return true;
}

void InstalldOperator::ExtractTargetFile(const BundleExtractor &extractor, const std::string &entryName,
    const std::string &targetPath, const std::string &cpuAbi, const ExtractFileType &extractFileType)
{
    // create dir if not exist
    if (!IsExistDir(targetPath)) {
        if (!MkRecursiveDir(targetPath, true)) {
            LOG_E(BMS_TAG_INSTALLD, "create targetPath %{public}s failed", targetPath.c_str());
            return;
        }
    }

    std::string prefix;
    if (!DeterminePrefix(extractFileType, cpuAbi, prefix)) {
        LOG_E(BMS_TAG_INSTALLD, "determine prefix failed");
        return;
    }
    std::string targetName = entryName.substr(prefix.length());
    std::string path = targetPath;
    if (path.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
        path += ServiceConstants::FILE_SEPARATOR_CHAR;
    }
    path += targetName;
    if (targetName.find(ServiceConstants::PATH_SEPARATOR) != std::string::npos) {
        std::string dir = GetPathDir(path);
        if (!IsExistDir(dir) && !MkRecursiveDir(dir, true)) {
            LOG_E(BMS_TAG_INSTALLD, "create dir %{public}s failed", dir.c_str());
            return;
        }
    }
    bool ret = extractor.ExtractFile(entryName, path);
    if (!ret) {
        LOG_E(BMS_TAG_INSTALLD, "extract file failed, entryName : %{public}s", entryName.c_str());
        return;
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (extractFileType == ExtractFileType::AP) {
        struct stat buf = {};
        if (stat(targetPath.c_str(), &buf) != 0) {
            LOG_E(BMS_TAG_INSTALLD, "fail to stat errno:%{public}d", errno);
            return;
        }
        ChangeFileAttr(path, buf.st_uid, buf.st_gid);
        mode = (buf.st_uid == buf.st_gid) ? (S_IRUSR | S_IWUSR) : (S_IRUSR | S_IWUSR | S_IRGRP);
    }
    if (!OHOS::ChangeModeFile(path, mode)) {
        LOG_E(BMS_TAG_INSTALLD, "ChangeModeFile %{public}s failed, errno: %{public}d", path.c_str(), errno);
        return;
    }
    FsyncResFile(path, extractFileType);
    LOG_D(BMS_TAG_INSTALLD, "extract file success, path : %{public}s", path.c_str());
}

void InstalldOperator::FsyncResFile(const std::string &path, const ExtractFileType &extractFileType)
{
    if (extractFileType == ExtractFileType::RES_FILE) {
        int32_t fileFd = open(path.c_str(), O_RDONLY);
        if (fileFd < 0) {
            LOG_E(BMS_TAG_INSTALLER, "open %{public}s failed", path.c_str());
            return;
        }
        if (fsync(fileFd) != 0) {
            LOG_E(BMS_TAG_INSTALLER, "fsync %{public}s failed", path.c_str());
        }
        close(fileFd);
    }
}

bool InstalldOperator::DeterminePrefix(const ExtractFileType &extractFileType, const std::string &cpuAbi,
    std::string &prefix)
{
    switch (extractFileType) {
        case ExtractFileType::SO: {
            prefix = ServiceConstants::LIBS + cpuAbi + ServiceConstants::PATH_SEPARATOR;
            break;
        }
        case ExtractFileType::AN: {
            prefix = ServiceConstants::AN + cpuAbi + ServiceConstants::PATH_SEPARATOR;
            break;
        }
        case ExtractFileType::AP: {
            prefix = AP_PATH;
            break;
        }
        case ExtractFileType::RES_FILE: {
            prefix = ServiceConstants::RES_FILE_PATH;
            break;
        }
        case ExtractFileType::HNPS_FILE: {
            prefix = ServiceConstants::HNPS + cpuAbi + ServiceConstants::PATH_SEPARATOR;
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
            break;
        }
        case ExtractFileType::AN: {
            suffixes.emplace_back(ServiceConstants::AN_SUFFIX);
            suffixes.emplace_back(AI_SUFFIX);
            break;
        }
        case ExtractFileType::AP: {
            suffixes.emplace_back(ServiceConstants::AP_SUFFIX);
            break;
        }
        case ExtractFileType::RES_FILE: {
            break;
        }
        case ExtractFileType::HNPS_FILE: {
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
        LOG_E(BMS_TAG_INSTALLD, "oldpath error");
        return false;
    }
    if (access(oldPath.c_str(), F_OK) != 0 && access(newPath.c_str(), F_OK) == 0) {
        LOG_E(BMS_TAG_INSTALLD, "fail to access file errno:%{public}d", errno);
        return true;
    }
    std::string realOldPath;
    realOldPath.reserve(PATH_MAX);
    realOldPath.resize(PATH_MAX - 1);
    if (realpath(oldPath.c_str(), &(realOldPath[0])) == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLD, "realOldPath:%{public}s errno:%{public}d", realOldPath.c_str(), errno);
        return false;
    }

    if (!(IsValidCodePath(realOldPath) && IsValidCodePath(newPath))) {
        LOG_E(BMS_TAG_INSTALLD, "IsValidCodePath failed");
        return false;
    }
    return RenameFile(realOldPath, newPath);
}

std::string InstalldOperator::GetPathDir(const std::string &path)
{
    std::size_t pos = path.rfind(ServiceConstants::PATH_SEPARATOR);
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
        LOG_D(BMS_TAG_INSTALLD, "fail to opendir:%{public}s, errno:%{public}d", path.c_str(), errno);
        return false;
    }

    while (true) {
        struct dirent *ptr = readdir(dir);
        if (ptr == nullptr) {
            LOG_D(BMS_TAG_INSTALLD, "fail to readdir errno:%{public}d", errno);
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
                LOG_D(BMS_TAG_INSTALLD, "Failed to ChangeFileAttr %{public}s, uid=%{public}d", subPath.c_str(), uid);
                closedir(dir);
                return false;
            }
        }
    }

    closedir(dir);
    std::string currentPath = OHOS::ExcludeTrailingPathDelimiter(path);
    if (access(currentPath.c_str(), F_OK) == 0) {
        if (!ChangeFileAttr(currentPath, uid, gid)) {
            LOG_D(BMS_TAG_INSTALLD, "Failed to ChangeFileAttr %{public}s, uid=%{public}d", currentPath.c_str(), uid);
            return false;
        }
    }

    return ret;
}

bool InstalldOperator::ChangeFileAttr(const std::string &filePath, const int uid, const int gid)
{
    LOG_D(BMS_TAG_INSTALLD, "begin to change %{public}s file attribute", filePath.c_str());
    if (chown(filePath.c_str(), uid, gid) != 0) {
        LOG_E(BMS_TAG_INSTALLD, "fail to change %{public}s ownership, uid=%{public}d, errno:%{public}d",
            filePath.c_str(), uid, errno);
        return false;
    }
    LOG_D(BMS_TAG_INSTALLD, "change %{public}s file attribute successfully", filePath.c_str());
    return true;
}

bool InstalldOperator::RenameFile(const std::string &oldPath, const std::string &newPath)
{
    if (oldPath.empty() || newPath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "old path or new path is empty");
        return false;
    }
    if (!DeleteDir(newPath)) {
        return false;
    }
    return rename(oldPath.c_str(), newPath.c_str()) == 0;
}

bool InstalldOperator::IsValidPath(const std::string &rootDir, const std::string &path)
{
    if (rootDir.find(ServiceConstants::PATH_SEPARATOR) != 0 ||
        rootDir.rfind(ServiceConstants::PATH_SEPARATOR) != (rootDir.size() - 1) ||
        rootDir.find("..") != std::string::npos) {
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
        LOG_E(BMS_TAG_INSTALLD, "code path is empty");
        return false;
    }
    return IsValidPath(BUNDLE_BASE_CODE_DIR + ServiceConstants::PATH_SEPARATOR, codePath);
}

bool InstalldOperator::DeleteFiles(const std::string &dataPath)
{
    LOG_D(BMS_TAG_INSTALLD, "InstalldOperator::DeleteFiles start");
    std::string subPath;
    bool ret = true;
    DIR *dir = opendir(dataPath.c_str());
    if (dir == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "fail to opendir:%{public}s, errno:%{public}d", dataPath.c_str(), errno);
        return false;
    }
    while (true) {
        struct dirent *ptr = readdir(dir);
        if (ptr == nullptr) {
            LOG_E(BMS_TAG_INSTALLD, "fail to readdir errno:%{public}d", errno);
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
    LOG_D(BMS_TAG_INSTALLD, "InstalldOperator::DeleteFilesExceptBundleDataDirs start");
    std::string filePath;
    DIR *dir = opendir(dataPath.c_str());
    if (dir == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "fail to opendir:%{public}s, errno:%{public}d", dataPath.c_str(), errno);
        return false;
    }
    bool ret = true;
    while (true) {
        struct dirent *ptr = readdir(dir);
        if (ptr == nullptr) {
            LOG_E(BMS_TAG_INSTALLD, "fail to readdir errno:%{public}d", errno);
            break;
        }
        std::string dirName = ServiceConstants::PATH_SEPARATOR + std::string(ptr->d_name);
        if (std::find(dirsToKeep.begin(), dirsToKeep.end(), dirName) != dirsToKeep.end() ||
            std::string(BUNDLE_BACKUP_KEEP_DIR) == dirName) {
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
        LOG_D(BMS_TAG_INSTALLD, "path :%{public}s is not exist, need create, errno:%{public}d", path.c_str(), errno);
        isPathExist = false;
        return false;
    }
    isPathExist = true;
    if (((s.st_mode & MODE_BASE) == mode) && (static_cast<int32_t>(s.st_uid) == uid)
        && (static_cast<int32_t>(s.st_gid) == gid)) {
        LOG_D(BMS_TAG_INSTALLD, "path :%{public}s mode uid and gid are same, no need to create again", path.c_str());
        return true;
    }
    LOG_NOFUNC_W(BMS_TAG_INSTALLD, "path:%{public}s exist, but mode uid or gid are not same, need to create again",
        path.c_str());
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
            LOG_W(BMS_TAG_INSTALLD, "fail to change %{public}s ownership, errno:%{public}d", path.c_str(), errno);
        }
    }
    if (!OHOS::ForceCreateDirectory(path)) {
        LOG_E(BMS_TAG_INSTALLD, "mkdir failed, errno: %{public}d", errno);
        return false;
    }
    // only modify parent dir mode
    if (chmod(path.c_str(), mode) != 0) {
        LOG_E(BMS_TAG_INSTALLD, "chmod path:%{public}s mode:%{public}d failed, errno:%{public}d",
            path.c_str(), mode, errno);
        return false;
    }
    if (!ChangeDirOwnerRecursively(path, uid, gid)) {
        LOG_E(BMS_TAG_INSTALLD, "ChangeDirOwnerRecursively failed, errno: %{public}d", errno);
        return false;
    }
    return true;
}

int64_t InstalldOperator::GetDiskUsage(const std::string &dir, bool isRealPath)
{
    if (dir.empty() || (dir.size() > ServiceConstants::PATH_MAX_SIZE)) {
        LOG_E(BMS_TAG_INSTALLD, "GetDiskUsage dir path invalid");
        return 0;
    }
    std::string filePath = dir;
    if (!isRealPath && !PathToRealPath(dir, filePath)) {
        LOG_E(BMS_TAG_INSTALLD, "file is not real path, file path: %{public}s", dir.c_str());
        return 0;
    }
    DIR *dirPtr = opendir(filePath.c_str());
    if (dirPtr == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "GetDiskUsage open file dir:%{public}s is failure, errno:%{public}d",
            filePath.c_str(), errno);
        return 0;
    }
    if (filePath.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
        filePath.push_back(ServiceConstants::FILE_SEPARATOR_CHAR);
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
            LOG_E(BMS_TAG_INSTALLD, "call stat error %{public}s, errno:%{public}d", path.c_str(), errno);
            fileInfo.st_size = 0;
        }
        size += fileInfo.st_size;
    }
    closedir(dirPtr);
    return size;
}

void InstalldOperator::TraverseCacheDirectory(const std::string &currentPath, std::vector<std::string> &cacheDirs)
{
    if (currentPath.empty() || (currentPath.size() > ServiceConstants::PATH_MAX_SIZE)) {
        LOG_E(BMS_TAG_INSTALLD, "TraverseCacheDirectory current path invaild");
        return;
    }
    std::string filePath = "";
    if (!PathToRealPath(currentPath, filePath)) {
        LOG_E(BMS_TAG_INSTALLD, "file is not real path, file path: %{public}s", currentPath.c_str());
        return;
    }
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "fail to opendir:%{public}s, errno:%{public}d", filePath.c_str(), errno);
        return;
    }
    if (filePath.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
        filePath.push_back(ServiceConstants::FILE_SEPARATOR_CHAR);
    }
    struct dirent *ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        if (ptr->d_type == DT_DIR && strcmp(ptr->d_name, CACHE_DIR) == 0) {
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
        LOG_E(BMS_TAG_INSTALLD, "Failed to open mounts file errno:%{public}d", errno);
        return false;
    }
    std::string line;

    while (std::getline(mountsFile, line)) {
        std::string device;
        std::string mountPoint;
        std::string fsType;
        std::istringstream lineStream(line);

        if (!(lineStream >> device >> mountPoint >> fsType)) {
            LOG_W(BMS_TAG_INSTALLD, "Failed to parse mounts file line: %{public}s", line.c_str());
            continue;
        }

        if (mountPoint == QUOTA_DEVICE_DATA_PATH) {
            struct dqblk dq;
            if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), device.c_str(), 0, reinterpret_cast<char*>(&dq)) == 0) {
                mQuotaReverseMounts[mountPoint] = device;
                LOG_D(BMS_TAG_INSTALLD, "InitialiseQuotaMounts, mountPoint: %{public}s, device: %{public}s",
                    mountPoint.c_str(), device.c_str());
            } else {
                LOG_W(BMS_TAG_INSTALLD, "InitialiseQuotaMounts, Failed to get quotactl, errno: %{public}d", errno);
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
            LOG_E(BMS_TAG_INSTALLD, "Failed to initialise quota mounts");
            return 0;
        }
    }
    device = mQuotaReverseMounts[QUOTA_DEVICE_DATA_PATH];
    if (device.empty()) {
        LOG_W(BMS_TAG_INSTALLD, "skip when device no quotas present");
        return 0;
    }
    struct dqblk dq;
    if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), device.c_str(), uid, reinterpret_cast<char*>(&dq)) != 0) {
        LOG_E(BMS_TAG_INSTALLD, "Failed to get quotactl, errno: %{public}d", errno);
        return 0;
    }
    LOG_D(BMS_TAG_INSTALLD, "get disk usage from quota, uid: %{public}d, usage: %{public}llu",
        uid, static_cast<unsigned long long>(dq.dqb_curspace));
    return dq.dqb_curspace;
}

bool InstalldOperator::ScanDir(
    const std::string &dirPath, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
{
    if (dirPath.empty() || (dirPath.size() > ServiceConstants::PATH_MAX_SIZE)) {
        LOG_E(BMS_TAG_INSTALLD, "Scan dir path invaild");
        return false;
    }

    std::string realPath = "";
    if (!PathToRealPath(dirPath, realPath)) {
        LOG_E(BMS_TAG_INSTALLD, "file(%{public}s) is not real path", dirPath.c_str());
        return false;
    }

    DIR* dir = opendir(realPath.c_str());
    if (dir == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "Scan open dir(%{public}s) fail, errno:%{public}d", realPath.c_str(), errno);
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
    if (currentPath.empty() || (currentPath.size() > ServiceConstants::PATH_MAX_SIZE)) {
        LOG_E(BMS_TAG_INSTALLD, "ScanSoFiles current path invalid");
        return false;
    }
    std::string filePath = "";
    if (!PathToRealPath(currentPath, filePath)) {
        LOG_E(BMS_TAG_INSTALLD, "file is not real path, file path: %{public}s", currentPath.c_str());
        return false;
    }
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "ScanSoFiles open dir(%{public}s) fail, errno:%{public}d", filePath.c_str(), errno);
        return false;
    }
    if (filePath.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
        filePath.push_back(ServiceConstants::FILE_SEPARATOR_CHAR);
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
            if (prefixPath.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
                prefixPath.push_back(ServiceConstants::FILE_SEPARATOR_CHAR);
            }
            std::string relativePath = currentFile.substr(prefixPath.size());
            paths.emplace_back(relativePath);
            std::string subNewSoPath = GetPathDir(newSoPath + ServiceConstants::PATH_SEPARATOR + relativePath);
            if (!IsExistDir(subNewSoPath) && !MkRecursiveDir(subNewSoPath, true)) {
                LOG_E(BMS_TAG_INSTALLD, "ScanSoFiles create subNewSoPath (%{public}s) failed", filePath.c_str());
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
        LOG_E(BMS_TAG_INSTALLD, "Copy file failed due to sourceFile or destinationFile is empty");
        return false;
    }

    std::ifstream in(sourceFile);
    if (!in.is_open()) {
        LOG_E(BMS_TAG_INSTALLD, "Copy file failed due to open sourceFile failed errno:%{public}d", errno);
        return false;
    }

    std::ofstream out(destinationFile);
    if (!out.is_open()) {
        LOG_E(BMS_TAG_INSTALLD, "Copy file failed due to open destinationFile failed errno:%{public}d", errno);
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
    LOG_D(BMS_TAG_INSTALLD, "begin");
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
        if (entryName.back() == ServiceConstants::PATH_SEPARATOR[0]) {
            continue;
        }
        // handle diff file
        if (IsDiffFiles(entryName, targetPath, cpuAbi)) {
            ExtractTargetFile(extractor, entryName, targetPath, cpuAbi);
        }
    }
    return true;
}

bool InstalldOperator::ProcessApplyDiffPatchPath(
    const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, std::vector<std::string> &oldSoFileNames, std::vector<std::string> &diffFileNames)
{
    LOG_I(BMS_TAG_INSTALLD, "oldSoPath: %{public}s, diffFilePath: %{public}s, newSoPath: %{public}s",
        oldSoPath.c_str(), diffFilePath.c_str(), newSoPath.c_str());
    if (oldSoPath.empty() || diffFilePath.empty() || newSoPath.empty()) {
        return false;
    }
    if (!IsExistDir(oldSoPath) || !IsExistDir(diffFilePath)) {
        LOG_E(BMS_TAG_INSTALLD, "oldSoPath or diffFilePath not exist");
        return false;
    }

    if (!ScanSoFiles(newSoPath, oldSoPath, oldSoPath, oldSoFileNames)) {
        LOG_E(BMS_TAG_INSTALLD, "ScanSoFiles oldSoPath failed");
        return false;
    }

    if (!ScanSoFiles(newSoPath, diffFilePath, diffFilePath, diffFileNames)) {
        LOG_E(BMS_TAG_INSTALLD, "ScanSoFiles diffFilePath failed");
        return false;
    }

    if (oldSoFileNames.empty() || diffFileNames.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "so or diff files empty");
        return false;
    }

    if (!IsExistDir(newSoPath)) {
        LOG_D(BMS_TAG_INSTALLD, "ProcessApplyDiffPatchPath create newSoPath");
        if (!MkRecursiveDir(newSoPath, true)) {
            LOG_E(BMS_TAG_INSTALLD, "ProcessApplyDiffPatchPath create newSo dir (%{public}s) failed",
                newSoPath.c_str());
            return false;
        }
    }
    LOG_I(BMS_TAG_INSTALLD, "ProcessApplyDiffPatchPath end");
    return true;
}

bool InstalldOperator::ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, int32_t uid)
{
    LOG_I(BMS_TAG_INSTALLD, "ApplyDiffPatch no need to process");
    return true;
}

bool InstalldOperator::ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &fileVec)
{
    if (dir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "ObtainQuickFixFileDir dir path invaild");
        return false;
    }

    std::string realPath = "";
    if (!PathToRealPath(dir, realPath)) {
        LOG_E(BMS_TAG_INSTALLD, "dir(%{public}s) is not real path", dir.c_str());
        return false;
    }

    DIR* directory = opendir(realPath.c_str());
    if (directory == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "ObtainQuickFixFileDir open dir(%{public}s) fail, errno:%{public}d",
            realPath.c_str(), errno);
        return false;
    }

    struct dirent *ptr = nullptr;
    bool isBundleCodeDir = dir.compare(Constants::BUNDLE_CODE_DIR) == 0;
    while ((ptr = readdir(directory)) != nullptr) {
        std::string currentName(ptr->d_name);
        if (currentName.compare(".") == 0 || currentName.compare("..") == 0) {
            continue;
        }

        std::string curPath = dir + ServiceConstants::PATH_SEPARATOR + currentName;
        struct stat s;
        if (stat(curPath.c_str(), &s) == 0) {
            // directory
            if ((s.st_mode & S_IFDIR) && (isBundleCodeDir || BundleUtil::StartWith(currentName, HQF_DIR_PREFIX))) {
                ObtainQuickFixFileDir(curPath, fileVec);
            }

            // file
            if ((s.st_mode & S_IFREG) &&
                (currentName.find(ServiceConstants::QUICK_FIX_FILE_SUFFIX) != std::string::npos)) {
                    fileVec.emplace_back(dir);
                }
        }
    }
    closedir(directory);
    return true;
}

bool InstalldOperator::CopyFiles(const std::string &sourceDir, const std::string &destinationDir)
{
    LOG_D(BMS_TAG_INSTALLD, "sourceDir is %{public}s, destinationDir is %{public}s",
        sourceDir.c_str(), destinationDir.c_str());
    if (sourceDir.empty() || destinationDir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Copy file failed due to sourceDir or destinationDir is empty");
        return false;
    }

    std::string realPath = "";
    if (!PathToRealPath(sourceDir, realPath)) {
        LOG_E(BMS_TAG_INSTALLD, "sourceDir(%{public}s) is not real path", sourceDir.c_str());
        return false;
    }

    DIR* directory = opendir(realPath.c_str());
    if (directory == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "CopyFiles open dir(%{public}s) fail, errno:%{public}d", realPath.c_str(), errno);
        return false;
    }

    struct dirent *ptr = nullptr;
    while ((ptr = readdir(directory)) != nullptr) {
        std::string currentName(ptr->d_name);
        if (currentName.compare(".") == 0 || currentName.compare("..") == 0) {
            continue;
        }

        std::string curPath = sourceDir + ServiceConstants::PATH_SEPARATOR + currentName;
        struct stat s;
        if ((stat(curPath.c_str(), &s) == 0) && (s.st_mode & S_IFREG)) {
            std::string innerDesStr = destinationDir + ServiceConstants::PATH_SEPARATOR + currentName;
            if (CopyFile(curPath, innerDesStr)) {
                ChangeFileAttr(innerDesStr, Constants::FOUNDATION_UID, ServiceConstants::BMS_GID);
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
    std::string prefix = ServiceConstants::LIBS + cpuAbi + ServiceConstants::PATH_SEPARATOR;
    for (const auto &entryName : entryNames) {
        if (StartsWith(entryName, prefix)) {
            fileNames.push_back(entryName.substr(prefix.length(), entryName.length()));
        }
    }
    LOG_D(BMS_TAG_INSTALLD, "InstalldOperator::GetNativeLibraryFileNames end");
    return true;
}

#if defined(CODE_SIGNATURE_ENABLE)
bool InstalldOperator::PrepareEntryMap(const CodeSignatureParam &codeSignatureParam,
    const std::vector<std::string> &soEntryFiles, Security::CodeSign::EntryMap &entryMap)
{
    if (codeSignatureParam.targetSoPath.empty()) {
        return false;
    }
    const std::string prefix = ServiceConstants::LIBS + codeSignatureParam.cpuAbi + ServiceConstants::PATH_SEPARATOR;
    for_each(soEntryFiles.begin(), soEntryFiles.end(),
        [&entryMap, &prefix, &codeSignatureParam](const auto &entry) {
        std::string fileName = entry.substr(prefix.length());
        std::string path = codeSignatureParam.targetSoPath;
        if (path.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
            path += ServiceConstants::FILE_SEPARATOR_CHAR;
        }
        entryMap.emplace(entry, path + fileName);
        LOG_D(BMS_TAG_INSTALLD, "VerifyCode the targetSoPath is %{public}s", (path + fileName).c_str());
    });
    return true;
}

ErrCode InstalldOperator::PerformCodeSignatureCheck(const CodeSignatureParam &codeSignatureParam,
    const Security::CodeSign::EntryMap &entryMap)
{
    ErrCode ret = ERR_OK;
    if (codeSignatureParam.isCompileSdkOpenHarmony &&
        !Security::CodeSign::CodeSignUtils::IsSupportOHCodeSign()) {
        LOG_D(BMS_TAG_INSTALLD, "code signature is not supported");
        return ret;
    }
    if (codeSignatureParam.signatureFileDir.empty()) {
        std::shared_ptr<CodeSignHelper> codeSignHelper = std::make_shared<CodeSignHelper>();
        Security::CodeSign::FileType fileType = codeSignatureParam.isPreInstalledBundle ?
            FILE_ENTRY_ONLY : FILE_ENTRY_ADD;
        if (codeSignatureParam.isEnterpriseBundle) {
            LOG_D(BMS_TAG_INSTALLD, "Verify code signature for enterprise bundle");
            ret = codeSignHelper->EnforceCodeSignForAppWithOwnerId(codeSignatureParam.appIdentifier,
                codeSignatureParam.modulePath, entryMap, fileType);
        } else {
            LOG_D(BMS_TAG_INSTALLD, "Verify code signature for non-enterprise bundle");
            ret = codeSignHelper->EnforceCodeSignForApp(codeSignatureParam.modulePath, entryMap, fileType);
        }
        LOG_I(BMS_TAG_INSTALLD, "Verify code signature %{public}s", codeSignatureParam.modulePath.c_str());
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
        LOG_D(BMS_TAG_INSTALLD, "soEntryFiles is empty");
        return true;
    }

#if defined(CODE_SIGNATURE_ENABLE)
    Security::CodeSign::EntryMap entryMap;
    if (!PrepareEntryMap(codeSignatureParam, soEntryFiles, entryMap)) {
        return false;
    }

    ErrCode ret = PerformCodeSignatureCheck(codeSignatureParam, entryMap);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "VerifyCode failed due to %{public}d", ret);
        return false;
    }
#endif
    return true;
}

bool InstalldOperator::CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    if (checkEncryptionParam.cpuAbi.empty() && checkEncryptionParam.targetSoPath.empty()) {
        return CheckHapEncryption(checkEncryptionParam, isEncryption);
    }
    const std::string cpuAbi = checkEncryptionParam.cpuAbi;
    const int32_t bundleId = checkEncryptionParam.bundleId;
    InstallBundleType installBundleType = checkEncryptionParam.installBundleType;
    const bool isCompressNativeLibrary = checkEncryptionParam.isCompressNativeLibrary;
    LOG_D(BMS_TAG_INSTALLD,
        "bundleId %{public}d, installBundleType %{public}d, isCompressNativeLibrary %{public}d, path %{public}s",
        bundleId, installBundleType, isCompressNativeLibrary, checkEncryptionParam.modulePath.c_str());

    BundleExtractor extractor(checkEncryptionParam.modulePath);
    if (!extractor.Init()) {
        return false;
    }

    std::vector<std::string> soEntryFiles;
    if (!ObtainNativeSoFile(extractor, cpuAbi, soEntryFiles)) {
        LOG_E(BMS_TAG_INSTALLD, "ObtainNativeSoFile failed");
        return false;
    }

    if (soEntryFiles.empty()) {
        LOG_D(BMS_TAG_INSTALLD, "no so file in installation file %{public}s", checkEncryptionParam.modulePath.c_str());
        return true;
    }

#if defined(CODE_ENCRYPTION_ENABLE)
    const std::string targetSoPath = checkEncryptionParam.targetSoPath;
    std::unordered_map<std::string, std::string> entryMap;
    entryMap.emplace(ServiceConstants::CODE_SIGNATURE_HAP, checkEncryptionParam.modulePath);
    if (!targetSoPath.empty()) {
        const std::string prefix = ServiceConstants::LIBS + cpuAbi + ServiceConstants::PATH_SEPARATOR;
        std::for_each(soEntryFiles.begin(), soEntryFiles.end(), [&entryMap, &prefix, &targetSoPath](const auto &entry) {
            std::string fileName = entry.substr(prefix.length());
            std::string path = targetSoPath;
            if (path.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
                path += ServiceConstants::FILE_SEPARATOR_CHAR;
            }
            entryMap.emplace(entry, path + fileName);
            LOG_D(BMS_TAG_INSTALLD, "CheckEncryption the targetSoPath is %{public}s", (path + fileName).c_str());
        });
    }
    if (!EnforceEncryption(entryMap, bundleId, isEncryption, installBundleType, isCompressNativeLibrary)) {
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
    LOG_D(BMS_TAG_INSTALLD, "CheckHapEncryption the hapPath is %{public}s, installBundleType is %{public}d, "
        "bundleId is %{public}d, isCompressNativeLibrary is %{public}d", hapPath.c_str(),
        installBundleType, bundleId, isCompressNativeLibrary);
#if defined(CODE_ENCRYPTION_ENABLE)
    std::unordered_map<std::string, std::string> entryMap;
    entryMap.emplace(ServiceConstants::CODE_SIGNATURE_HAP, hapPath);
    if (!EnforceEncryption(entryMap, bundleId, isEncryption, installBundleType, isCompressNativeLibrary)) {
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
        LOG_E(BMS_TAG_INSTALLD, "GetZipFileNames failed");
        return false;
    }
    if (entryNames.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "entryNames is empty");
        return false;
    }

    for (const auto &entryName : entryNames) {
        if (strcmp(entryName.c_str(), ".") == 0 ||
            strcmp(entryName.c_str(), "..") == 0) {
            continue;
        }
        if (entryName.back() == ServiceConstants::PATH_SEPARATOR[0]) {
            continue;
        }
        // save native so file entryName in the hap
        if (IsNativeSo(entryName, cpuAbi)) {
            soEntryFiles.emplace_back(entryName);
            continue;
        }
    }

    if (soEntryFiles.empty()) {
        LOG_D(BMS_TAG_INSTALLD, "no so file in installation file");
    }
    return true;
}

bool InstalldOperator::MoveFiles(const std::string &srcDir, const std::string &desDir, bool isDesDirNeedCreated)
{
    LOG_D(BMS_TAG_INSTALLD, "srcDir is %{public}s, desDir is %{public}s", srcDir.c_str(), desDir.c_str());
    if (isDesDirNeedCreated && !MkRecursiveDir(desDir, true)) {
        LOG_E(BMS_TAG_INSTALLD, "create desDir failed");
        return false;
    }

    if (srcDir.empty() || desDir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "move file failed due to srcDir or desDir is empty");
        return false;
    }

    std::string realPath = "";
    if (!PathToRealPath(srcDir, realPath)) {
        LOG_E(BMS_TAG_INSTALLD, "srcDir(%{public}s) is not real path", srcDir.c_str());
        return false;
    }

    std::string realDesDir = "";
    if (!PathToRealPath(desDir, realDesDir)) {
        LOG_E(BMS_TAG_INSTALLD, "desDir(%{public}s) is not real path", desDir.c_str());
        return false;
    }

    DIR* directory = opendir(realPath.c_str());
    if (directory == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "MoveFiles open dir(%{public}s) fail, errno:%{public}d", realPath.c_str(), errno);
        return false;
    }

    struct dirent *ptr = nullptr;
    while ((ptr = readdir(directory)) != nullptr) {
        std::string currentName(ptr->d_name);
        if (currentName.compare(".") == 0 || currentName.compare("..") == 0) {
            continue;
        }

        std::string curPath = realPath + ServiceConstants::PATH_SEPARATOR + currentName;
        std::string innerDesStr = realDesDir + ServiceConstants::PATH_SEPARATOR + currentName;
        struct stat s;
        if (stat(curPath.c_str(), &s) != 0) {
            LOG_D(BMS_TAG_INSTALLD, "MoveFiles stat %{public}s failed, errno:%{public}d", curPath.c_str(), errno);
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
        LOG_D(BMS_TAG_INSTALLD, "srcPath(%{public}s) is a file", srcPath.c_str());
        return MoveFile(srcPath, destPath);
    } else if (mode & S_IFDIR) {
        LOG_D(BMS_TAG_INSTALLD, "srcPath(%{public}s) is a dir", srcPath.c_str());
        return MoveFiles(srcPath, destPath, true);
    }
    return true;
}

bool InstalldOperator::MoveFile(const std::string &srcPath, const std::string &destPath)
{
    LOG_D(BMS_TAG_INSTALLD, "srcPath is %{public}s, destPath is %{public}s", srcPath.c_str(), destPath.c_str());
    if (!RenameFile(srcPath, destPath)) {
        LOG_E(BMS_TAG_INSTALLD, "move file from srcPath(%{public}s) to destPath(%{public}s) failed", srcPath.c_str(),
            destPath.c_str());
        return false;
    }
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!OHOS::ChangeModeFile(destPath, mode)) {
        LOG_E(BMS_TAG_INSTALLD, "change mode failed");
        return false;
    }
    return true;
}

bool InstalldOperator::ExtractResourceFiles(const ExtractParam &extractParam, const BundleExtractor &extractor)
{
    LOG_D(BMS_TAG_INSTALLD, "ExtractResourceFiles begin");
    std::string targetDir = extractParam.targetPath;
    if (!MkRecursiveDir(targetDir, true)) {
        LOG_E(BMS_TAG_INSTALLD, "create targetDir failed");
        return false;
    }
    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames)) {
        LOG_E(BMS_TAG_INSTALLD, "GetZipFileNames failed");
        return false;
    }
    for (const auto &entryName : entryNames) {
        if (StartsWith(entryName, ServiceConstants::LIBS)
            || StartsWith(entryName, ServiceConstants::AN)
            || StartsWith(entryName, AP_PATH)) {
            continue;
        }
        const std::string relativeDir = GetPathDir(entryName);
        if (!relativeDir.empty()) {
            if (!MkRecursiveDir(targetDir + relativeDir, true)) {
                LOG_E(BMS_TAG_INSTALLD, "MkRecursiveDir failed");
                return false;
            }
        }
        std::string filePath = targetDir + entryName;
        if (!extractor.ExtractFile(entryName, filePath)) {
            LOG_E(BMS_TAG_INSTALLD, "ExtractFile failed");
            continue;
        }
        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        if (!OHOS::ChangeModeFile(filePath, mode)) {
            LOG_E(BMS_TAG_INSTALLD, "change mode failed");
            return false;
        }
    }
    LOG_D(BMS_TAG_INSTALLD, "ExtractResourceFiles success");
    return true;
}

bool InstalldOperator::ExtractDriverSoFiles(const std::string &srcPath,
    const std::unordered_multimap<std::string, std::string> &dirMap)
{
    LOG_D(BMS_TAG_INSTALLD, "ExtractDriverSoFiles start with src(%{public}s)", srcPath.c_str());
    if (srcPath.empty() || dirMap.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "ExtractDriverSoFiles parameters are invalid");
        return false;
    }
    BundleExtractor extractor(srcPath);
    if (!extractor.Init()) {
        LOG_E(BMS_TAG_INSTALLD, "extractor init failed");
        return false;
    }

    std::vector<std::string> entryNames;
    if (!extractor.GetZipFileNames(entryNames)) {
        LOG_E(BMS_TAG_INSTALLD, "GetZipFileNames failed");
        return false;
    }

    for (auto &[originalDir, destinedDir] : dirMap) {
        if ((originalDir.compare(".") == 0) || (originalDir.compare("..") == 0)) {
            LOG_E(BMS_TAG_INSTALLD, "the originalDir %{public}s is not existed in the hap", originalDir.c_str());
            return false;
        }
        if (!BundleUtil::StartWith(originalDir, PREFIX_RESOURCE_PATH) ||
            !BundleUtil::StartWith(destinedDir, PREFIX_TARGET_PATH)) {
            LOG_E(BMS_TAG_INSTALLD, "the originalDir %{public}s and destined dir %{public}s are invalid",
                originalDir.c_str(), destinedDir.c_str());
            return false;
        }
        std::string innerOriginalDir = originalDir;
        if (innerOriginalDir.front() == ServiceConstants::PATH_SEPARATOR[0]) {
            innerOriginalDir = innerOriginalDir.substr(1);
        }
        if (find(entryNames.cbegin(), entryNames.cend(), innerOriginalDir) == entryNames.cend()) {
            LOG_E(BMS_TAG_INSTALLD, "the innerOriginalDir %{public}s is not existed in the hap",
                innerOriginalDir.c_str());
            return false;
        }
        std::string systemServiceDir = ServiceConstants::SYSTEM_SERVICE_DIR;
        if (!CopyDriverSoFiles(extractor, innerOriginalDir, systemServiceDir + destinedDir)) {
            LOG_E(BMS_TAG_INSTALLD, "CopyDriverSoFiles failed");
            return false;
        }
    }
    LOG_D(BMS_TAG_INSTALLD, "ExtractDriverSoFiles end");
    return true;
}

bool InstalldOperator::CopyDriverSoFiles(const BundleExtractor &extractor, const std::string &originalDir,
    const std::string &destinedDir)
{
    LOG_D(BMS_TAG_INSTALLD, "CopyDriverSoFiles beign");
    auto pos = destinedDir.rfind(ServiceConstants::PATH_SEPARATOR);
    if ((pos == std::string::npos) || (pos == destinedDir.length() -1)) {
        LOG_E(BMS_TAG_INSTALLD, "destinedDir(%{public}s) is invalid path", destinedDir.c_str());
        return false;
    }
    std::string desDir = destinedDir.substr(0, pos);
    std::string realDesDir;
    if (!PathToRealPath(desDir, realDesDir)) {
        LOG_E(BMS_TAG_INSTALLD, "desDir(%{public}s) is not real path", desDir.c_str());
        return false;
    }
    std::string realDestinedDir = realDesDir + destinedDir.substr(pos);
    LOG_D(BMS_TAG_INSTALLD, "realDestinedDir is %{public}s", realDestinedDir.c_str());
    if (!extractor.ExtractFile(originalDir, realDestinedDir)) {
        LOG_E(BMS_TAG_INSTALLD, "ExtractFile failed");
        return false;
    }

    struct stat buf = {};
    if (stat(realDesDir.c_str(), &buf) != 0) {
        LOG_E(BMS_TAG_INSTALLD, "failed to obtain the stat status of realDesDir %{public}s, errno:%{public}d",
            realDesDir.c_str(), errno);
        return false;
    }
    ChangeFileAttr(realDestinedDir, buf.st_uid, buf.st_gid);
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!OHOS::ChangeModeFile(realDestinedDir, mode)) {
        return false;
    }
    LOG_D(BMS_TAG_INSTALLD, "CopyDriverSoFiles end");
    return true;
}

#if defined(CODE_ENCRYPTION_ENABLE)
ErrCode InstalldOperator::ExtractSoFilesToTmpHapPath(const std::string &hapPath, const std::string &cpuAbi,
    const std::string &tmpSoPath, int32_t uid)
{
    LOG_D(BMS_TAG_INSTALLD, "start to obtain decoded so files from hapPath %{public}s", hapPath.c_str());
    BundleExtractor extractor(hapPath);
    if (!extractor.Init()) {
        LOG_E(BMS_TAG_INSTALLD, "init bundle extractor failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    /* obtain the so list in the hap */
    std::vector<std::string> soEntryFiles;
    if (!ObtainNativeSoFile(extractor, cpuAbi, soEntryFiles)) {
        LOG_E(BMS_TAG_INSTALLD, "ExtractFiles obtain native so file entryName failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    std::string innerTmpSoPath = tmpSoPath;
    if (innerTmpSoPath.back() != ServiceConstants::PATH_SEPARATOR[0]) {
        innerTmpSoPath += ServiceConstants::PATH_SEPARATOR;
    }

    /* create innerTmpSoPath */
    if (!IsExistDir(innerTmpSoPath)) {
        if (!MkRecursiveDir(innerTmpSoPath, true)) {
            LOG_E(BMS_TAG_INSTALLD, "create innerTmpSoPath %{public}s failed", innerTmpSoPath.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }

    for (const auto &entry : soEntryFiles) {
        LOG_D(BMS_TAG_INSTALLD, "entryName is %{public}s", entry.c_str());
        auto pos = entry.rfind(ServiceConstants::PATH_SEPARATOR[0]);
        if (pos == std::string::npos) {
            LOG_W(BMS_TAG_INSTALLD, "invalid so entry %{public}s", entry.c_str());
            continue;
        }
        std::string soFileName = entry.substr(pos + 1);
        if (soFileName.empty()) {
            LOG_W(BMS_TAG_INSTALLD, "invalid so entry %{public}s", entry.c_str());
            continue;
        }
        LOG_D(BMS_TAG_INSTALLD, "so file is %{public}s", soFileName.c_str());
        uint32_t offset = 0;
        uint32_t length = 0;
        if (!extractor.GetFileInfo(entry, offset, length) || length == 0) {
            LOG_W(BMS_TAG_INSTALLD, "GetFileInfo failed or invalid so file");
            continue;
        }
        LOG_D(BMS_TAG_INSTALLD, "so file %{public}s has offset %{public}d and file size %{public}d",
            entry.c_str(), offset, length);

        /* mmap so to ram and write so file to temp path */
        ErrCode res = ERR_OK;
        if ((res = DecryptSoFile(hapPath, innerTmpSoPath + soFileName, uid, length, offset)) != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "decrypt file failed, srcPath is %{public}s and destPath is %{public}s",
                hapPath.c_str(), (innerTmpSoPath + soFileName).c_str());
            return res;
        }
    }

    return ERR_OK;
}

ErrCode InstalldOperator::ExtractSoFilesToTmpSoPath(const std::string &hapPath, const std::string &realSoFilesPath,
    const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid)
{
    LOG_D(BMS_TAG_INSTALLD, "start to obtain decoded so files from so path");
    if (realSoFilesPath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "real so file path is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
    }
    BundleExtractor extractor(hapPath);
    if (!extractor.Init()) {
        LOG_E(BMS_TAG_INSTALLD, "init bundle extractor failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    /* obtain the so list in the hap */
    std::vector<std::string> soEntryFiles;
    if (!ObtainNativeSoFile(extractor, cpuAbi, soEntryFiles)) {
        LOG_E(BMS_TAG_INSTALLD, "ExtractFiles obtain native so file entryName failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    std::string innerTmpSoPath = tmpSoPath;
    if (innerTmpSoPath.back() != ServiceConstants::PATH_SEPARATOR[0]) {
        innerTmpSoPath += ServiceConstants::PATH_SEPARATOR;
    }
    // create innerTmpSoPath
    if (!IsExistDir(innerTmpSoPath)) {
        if (!MkRecursiveDir(innerTmpSoPath, true)) {
            LOG_E(BMS_TAG_INSTALLD, "create innerTmpSoPath %{public}s failed", innerTmpSoPath.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }

    for (const auto &entry : soEntryFiles) {
        auto pos = entry.rfind(ServiceConstants::PATH_SEPARATOR[0]);
        if (pos == std::string::npos) {
            LOG_W(BMS_TAG_INSTALLD, "invalid so entry %{public}s", entry.c_str());
            continue;
        }
        std::string soFileName = entry.substr(pos + 1);
        if (soFileName.empty()) {
            LOG_W(BMS_TAG_INSTALLD, "invalid so entry %{public}s", entry.c_str());
            continue;
        }

        std::string soPath = realSoFilesPath + soFileName;
        LOG_D(BMS_TAG_INSTALLD, "real path of the so file %{public}s is %{public}s",
            soFileName.c_str(), soPath.c_str());

        if (IsExistFile(soPath)) {
            /* mmap so file to ram and write to innerTmpSoPath */
            ErrCode res = ERR_OK;
            LOG_D(BMS_TAG_INSTALLD, "tmp so path is %{public}s", (innerTmpSoPath + soFileName).c_str());
            if ((res = DecryptSoFile(soPath, innerTmpSoPath + soFileName, uid, 0, 0)) != ERR_OK) {
                LOG_E(BMS_TAG_INSTALLD, "decrypt file failed, srcPath is %{public}s and destPath is %{public}s",
                    soPath.c_str(), (innerTmpSoPath + soFileName).c_str());
                return res;
            }
        } else {
            LOG_W(BMS_TAG_INSTALLD, "so file %{public}s is not existed", soPath.c_str());
        }
    }
    return ERR_OK;
}

ErrCode InstalldOperator::DecryptSoFile(const std::string &filePath, const std::string &tmpPath, int32_t uid,
    uint32_t fileSize, uint32_t offset)
{
    LOG_D(BMS_TAG_INSTALLD, "src file is %{public}s, temp path is %{public}s, bundle uid is %{public}d",
        filePath.c_str(), tmpPath.c_str(), uid);
    ErrCode result = ERR_BUNDLEMANAGER_QUICK_FIX_DECRYPTO_SO_FAILED;

    /* call CallIoctl */
    int32_t dev_fd = INVALID_FILE_DESCRIPTOR;
    auto ret = CallIoctl(CODE_DECRYPT_CMD_SET_KEY, CODE_DECRYPT_CMD_SET_ASSOCIATE_KEY, uid, dev_fd);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLD, "CallIoctl failed");
        return result;
    }

    /* mmap hap or so file to ram */
    std::string newfilePath;
    if (!PathToRealPath(filePath, newfilePath)) {
        LOG_E(BMS_TAG_INSTALLD, "file is not real path, file path: %{public}s", filePath.c_str());
        return result;
    }
    auto fd = open(newfilePath.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_E(BMS_TAG_INSTALLD, "open hap failed errno:%{public}d", errno);
        close(dev_fd);
        return result;
    }
    struct stat st;
    if (fstat(fd, &st) == INVALID_RETURN_VALUE) {
        LOG_E(BMS_TAG_INSTALLD, "obtain hap file status faield errno:%{public}d", errno);
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
        LOG_E(BMS_TAG_INSTALLD, "mmap hap file status faield errno:%{public}d", errno);
        close(dev_fd);
        close(fd);
        return result;
    }

    /* write hap file to the temp path */
    auto outPutFd = BundleUtil::CreateFileDescriptor(tmpPath, 0);
    if (outPutFd < 0) {
        LOG_E(BMS_TAG_INSTALLD, "create fd for tmp hap file failed");
        close(dev_fd);
        close(fd);
        munmap(addr, innerFileSize);
        return result;
    }
    if (write(outPutFd, addr, innerFileSize) != INVALID_RETURN_VALUE) {
        result = ERR_OK;
        LOG_D(BMS_TAG_INSTALLD, "write hap to temp path successfully");
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
        LOG_D(BMS_TAG_INSTALLD, "invalid uid and no need to remove encrypted key");
        return ERR_OK;
    }
    if (soList.empty()) {
        LOG_D(BMS_TAG_INSTALLD, "no new so generated and no need to remove encrypted key");
        return ERR_OK;
    }
    ErrCode result = ERR_BUNDLEMANAGER_QUICK_FIX_DECRYPTO_SO_FAILED;

    /* call CallIoctl */
    int32_t dev_fd = INVALID_FILE_DESCRIPTOR;
    auto ret = CallIoctl(CODE_DECRYPT_CMD_REMOVE_KEY, CODE_DECRYPT_CMD_REMOVE_KEY, uid, dev_fd);
    if (ret == 0) {
        LOG_D(BMS_TAG_INSTALLD, "ioctl successfully");
        result = ERR_OK;
    }
    close(dev_fd);
    return result;
}

int32_t InstalldOperator::CallIoctl(int32_t flag, int32_t associatedFlag, int32_t uid, int32_t &fd)
{
    int32_t installdUid = static_cast<int32_t>(getuid());
    int32_t bundleUid = uid;
    LOG_D(BMS_TAG_INSTALLD, "current process uid is %{public}d and bundle uid is %{public}d", installdUid, bundleUid);

    /* open CODE_DECRYPT */
    std::string newCodeDecrypt;
    if (!PathToRealPath(CODE_DECRYPT, newCodeDecrypt)) {
        LOG_E(BMS_TAG_INSTALLD, "file is not real path, file path: %{public}s", CODE_DECRYPT.c_str());
        return INVALID_RETURN_VALUE;
    }
    fd = open(newCodeDecrypt.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_E(BMS_TAG_INSTALLD, "call open failed errno:%{public}d", errno);
        return INVALID_RETURN_VALUE;
    }

    /* build ioctl args to set key or remove key*/
    struct code_decrypt_arg firstArg;
    firstArg.arg1_len = sizeof(bundleUid);
    firstArg.arg1 = reinterpret_cast<void *>(&bundleUid);
    auto ret = ioctl(fd, flag, &firstArg);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLD, "call ioctl failed errno:%{public}d", errno);
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
        LOG_E(BMS_TAG_INSTALLD, "call ioctl failed errno:%{public}d", errno);
        close(fd);
    }
    return ret;
}
#endif

bool InstalldOperator::GenerateKeyIdAndSetPolicy(int32_t uid, const std::string &bundleName,
    const int32_t userId, std::string &keyId)
{
    LOG_D(BMS_TAG_INSTALLD, "GenerateKeyId uid is %{public}d, bundleName is %{public}s, userId is %{public}d",
        uid, bundleName.c_str(), userId);
    auto ret = Security::AccessToken::El5FilekeyManagerKit::GenerateAppKey(
        static_cast<uint32_t>(uid), bundleName, keyId);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLD, "Call GenerateAppKey failed ret = %{public}d", ret);
        return false;
    }
    if (keyId.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "keyId is empty");
        return false;
    }
    struct fscrypt_asdp_policy policy;
    policy.version = 0;
    policy.asdp_class = FORCE_PROTECT;
    // keyId length = KEY_ID_STEP * FSCRYPT_KEY_DESCRIPTOR_SIZE
    for (uint32_t i = 0; i < keyId.size(); i += KEY_ID_STEP) {
        if (i / KEY_ID_STEP >= FSCRYPT_KEY_DESCRIPTOR_SIZE) {
            break;
        }
        std::string byteString = keyId.substr(i, KEY_ID_STEP);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        policy.app_key2_descriptor[i / KEY_ID_STEP] = byte;
    }

    std::vector<std::string> dirs;
    dirs.emplace_back(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH + ServiceConstants::PATH_SEPARATOR +
        std::to_string(userId) + ServiceConstants::BASE + bundleName);
    dirs.emplace_back(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH + ServiceConstants::PATH_SEPARATOR +
        std::to_string(userId) + ServiceConstants::DATABASE + bundleName);
    for (const auto &dir : dirs) {
        auto fd = open(dir.c_str(), O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            LOG_E(BMS_TAG_INSTALLD, "open filePath failed");
            return false;
        }
        // call ioctl to set e policy
        auto result = ioctl(fd, HMFS_IOC_SET_ASDP_ENCRYPTION_POLICY, &policy);
        if (result != 0) {
            LOG_E(BMS_TAG_INSTALLD, "ioctl failed result:%{public}d", result);
            close(fd);
            return false;
        }
        close(fd);
    }
    LOG_I(BMS_TAG_INSTALLD, "GenerateKeyIdAndSetPolicy success for %{public}s", bundleName.c_str());
    return true;
}

bool InstalldOperator::DeleteKeyId(const std::string &keyId)
{
    LOG_D(BMS_TAG_INSTALLD, "DeleteKeyId keyId is %{public}s", keyId.c_str());
    auto ret = Security::AccessToken::El5FilekeyManagerKit::DeleteAppKey(keyId);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLD, "Call DeleteAppKey failed ret = %{public}d", ret);
        return false;
    }
    return true;
}

bool InstalldOperator::GetAtomicServiceBundleDataDir(const std::string &bundleName,
    const int32_t userId, std::vector<std::string> &allPathNames)
{
    std::string baseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[0] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::BASE;
    DIR *dir = opendir(baseDir.c_str());
    if (dir == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "fail to opendir:%{public}s, errno:%{public}d", baseDir.c_str(), errno);
        return false;
    }
    struct dirent *ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (ptr->d_type == DT_DIR) {
            std::string pathName(ptr->d_name);
            if (pathName.find(ATOMIC_SERVICE_PATH) != 0) {
                continue;
            }
            auto pos = pathName.rfind(bundleName);
            if ((pos != std::string::npos) && (pos == (pathName.size() - bundleName.size()))) {
                allPathNames.emplace_back(pathName);
            }
        }
    }
    closedir(dir);
    return !allPathNames.empty();
}

#if defined(CODE_ENCRYPTION_ENABLE)
std::mutex InstalldOperator::encryptionMutex_;
void *InstalldOperator::encryptionHandle_ = nullptr;
EnforceMetadataProcessForApp InstalldOperator::enforceMetadataProcessForApp_ = nullptr;

bool InstalldOperator::OpenEncryptionHandle()
{
    std::lock_guard<std::mutex> lock(encryptionMutex_);
    if (encryptionHandle_ != nullptr && enforceMetadataProcessForApp_ != nullptr) {
        LOG_NOFUNC_I(BMS_TAG_INSTALLD, "encrypt handle opened");
        return true;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "OpenEncryption start");
    encryptionHandle_ = dlopen(LIB64_CODE_CRYPTO_SO_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (encryptionHandle_ == nullptr) {
        LOG_W(BMS_TAG_INSTALLD, "open encrypt lib64 failed %{public}s", dlerror());
        encryptionHandle_ = dlopen(LIB_CODE_CRYPTO_SO_PATH, RTLD_NOW | RTLD_GLOBAL);
    }
    if (encryptionHandle_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "open encrypt lib failed %{public}s", dlerror());
        return false;
    }
    enforceMetadataProcessForApp_ =
        reinterpret_cast<EnforceMetadataProcessForApp>(dlsym(encryptionHandle_, CODE_CRYPTO_FUNCTION_NAME));
    if (enforceMetadataProcessForApp_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "dlsym encrypt err:%{public}s", dlerror());
        dlclose(encryptionHandle_);
        encryptionHandle_ = nullptr;
        return false;
    }
    return true;
}

bool InstalldOperator::EnforceEncryption(std::unordered_map<std::string, std::string> &entryMap, int32_t bundleId,
    bool &isEncryption, InstallBundleType installBundleType, bool isCompressNativeLibrary)
{
    if (!OpenEncryptionHandle()) {
        return false;
    }
    ErrCode ret = enforceMetadataProcessForApp_(entryMap, bundleId,
        isEncryption, static_cast<int32_t>(installBundleType), isCompressNativeLibrary);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CheckEncryption failed due to %{public}d", ret);
        return false;
    }
    return true;
}
#endif
}  // namespace AppExecFwk
}  // namespace OHOS
