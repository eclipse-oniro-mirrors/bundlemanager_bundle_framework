/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "verify_manager_host_impl.h"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "verify_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string SEPARATOR = "/";
const std::string ABCS_DIR = "abcs";
const std::string ABCS_TEMP_DIR = "temp/";
const std::string DATA_STORAGE_BUNDLE = "/data/storage/el1/bundle/";
const std::string DATA_STORAGE_EL1_BASE = "/data/storage/el1/base/";
const std::string DATA_STORAGE_EL1_DATABASE  = "/data/storage/el1/database/";
const std::string DATA_STORAGE_EL2_BASE = "/data/storage/el2/base/";
const std::string DATA_STORAGE_EL2_DATABASE = "/data/storage/el2/database/";
const std::string DATA_STORAGE_EL3_BASE = "/data/storage/el3/base/";
const std::string DATA_STORAGE_EL3_DATABASE = "/data/storage/el3/database/";
const std::string DATA_STORAGE_EL4_BASE = "/data/storage/el4/base/";
const std::string DATA_STORAGE_EL4_DATABASE = "/data/storage/el4/database/";
constexpr const char* ABC_FILE_SUFFIX = ".abc";

bool IsValidPath(const std::string &path)
{
    if (path.empty()) {
        return false;
    }
    if (path.find("..") != std::string::npos) {
        return false;
    }
    return true;
}

std::string GetRootDir(const std::string &bundleName)
{
    std::string rootDir;
    rootDir.append(Constants::BUNDLE_CODE_DIR).append(ServiceConstants::PATH_SEPARATOR)
        .append(bundleName).append(ServiceConstants::PATH_SEPARATOR)
        .append(ABCS_DIR).append(ServiceConstants::PATH_SEPARATOR);
    return rootDir;
}

std::string GetTempRootDir(const std::string &bundleName)
{
    std::string tempRootDir;
    tempRootDir.append(Constants::BUNDLE_CODE_DIR).append(ServiceConstants::PATH_SEPARATOR)
        .append(bundleName).append(ServiceConstants::PATH_SEPARATOR).append(ABCS_DIR)
        .append(ServiceConstants::PATH_SEPARATOR).append(ABCS_TEMP_DIR);
    return tempRootDir;
}

bool GetDataDir(const std::string &path, std::string &suffix, std::string &el, std::string &baseType)
{
    if (BundleUtil::StartWith(path, DATA_STORAGE_EL1_BASE)) {
        suffix = path.substr(DATA_STORAGE_EL1_BASE.size());
        el = ServiceConstants::DIR_EL1;
        baseType = ServiceConstants::BASE;
        return true;
    }

    if (BundleUtil::StartWith(path, DATA_STORAGE_EL1_DATABASE)) {
        suffix = path.substr(DATA_STORAGE_EL1_DATABASE.size());
        el = ServiceConstants::DIR_EL1;
        baseType = ServiceConstants::DATABASE;
        return true;
    }

    if (BundleUtil::StartWith(path, DATA_STORAGE_EL2_BASE)) {
        suffix = path.substr(DATA_STORAGE_EL2_BASE.size());
        el = ServiceConstants::DIR_EL2;
        baseType = ServiceConstants::BASE;
        return true;
    }

    if (BundleUtil::StartWith(path, DATA_STORAGE_EL2_DATABASE)) {
        suffix = path.substr(DATA_STORAGE_EL2_DATABASE.size());
        el = ServiceConstants::DIR_EL2;
        baseType = ServiceConstants::DATABASE;
        return true;
    }

    if (BundleUtil::StartWith(path, DATA_STORAGE_EL3_BASE)) {
        suffix = path.substr(DATA_STORAGE_EL3_BASE.size());
        el = ServiceConstants::DIR_EL3;
        baseType = ServiceConstants::BASE;
        return true;
    }

    if (BundleUtil::StartWith(path, DATA_STORAGE_EL3_DATABASE)) {
        suffix = path.substr(DATA_STORAGE_EL3_DATABASE.size());
        el = ServiceConstants::DIR_EL3;
        baseType = ServiceConstants::DATABASE;
        return true;
    }

    if (BundleUtil::StartWith(path, DATA_STORAGE_EL4_BASE)) {
        suffix = path.substr(DATA_STORAGE_EL4_BASE.size());
        el = ServiceConstants::DIR_EL4;
        baseType = ServiceConstants::BASE;
        return true;
    }

    if (BundleUtil::StartWith(path, DATA_STORAGE_EL4_DATABASE)) {
        suffix = path.substr(DATA_STORAGE_EL4_DATABASE.size());
        el = ServiceConstants::DIR_EL4;
        baseType = ServiceConstants::DATABASE;
        return true;
    }

    return false;
}
}

VerifyManagerHostImpl::VerifyManagerHostImpl()
{
    APP_LOGI("create VerifyManagerHostImpl");
}

VerifyManagerHostImpl::~VerifyManagerHostImpl()
{
    APP_LOGI("destroy VerifyManagerHostImpl");
}

ErrCode VerifyManagerHostImpl::Verify(const std::vector<std::string> &abcPaths)
{
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_TWELVE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_RUN_DYN_CODE)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_VERIFY_PERMISSION_DENIED;
    }

    std::string bundleName;
    int32_t userId = BundleUtil::GetUserIdByCallingUid();
    if (!GetCallingBundleName(bundleName) || bundleName.empty()) {
        APP_LOGE("GetCallingBundleName failed");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    auto &mtx = GetBundleMutex(bundleName);
    std::lock_guard lock {mtx};
    if (!CheckFileParam(abcPaths)) {
        APP_LOGE("CheckFile failed");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    if (!CopyFilesToTempDir(bundleName, userId, abcPaths)) {
        APP_LOGE("Copy failed");
        RemoveTempFiles(bundleName);
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    ErrCode ret = InnerVerify(bundleName, abcPaths);
    RemoveTempFiles(bundleName);
    return ret;
}

bool VerifyManagerHostImpl::GetCallingBundleName(std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("verify failed, dataMgr is null");
        return false;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    InnerBundleInfo innerBundleInfo;
    if (dataMgr->GetInnerBundleInfoByUid(callingUid, innerBundleInfo) != ERR_OK) {
        APP_LOGE("verify failed, callingUid is %{public}d", callingUid);
        return false;
    }

    bundleName = innerBundleInfo.GetBundleName();
    return true;
}

bool VerifyManagerHostImpl::CopyFilesToTempDir(
    const std::string &bundleName,
    int32_t userId,
    const std::vector<std::string> &abcPaths)
{
    std::string tempRootDir = GetTempRootDir(bundleName);
    ErrCode result = MkdirIfNotExist(tempRootDir);
    if (result != ERR_OK) {
        APP_LOGE("mkdir tempRootDir %{public}s faild %{public}d", tempRootDir.c_str(), result);
        return false;
    }

    for (size_t i = 0; i < abcPaths.size(); ++i) {
        std::string tempCopyPath = tempRootDir + abcPaths[i];
        std::string realPath = GetRealPath(bundleName, userId, abcPaths[i]);
        if (realPath.empty()) {
            APP_LOGE("abcPath %{public}s is illegal", abcPaths[i].c_str());
            return false;
        }

        APP_LOGD("realPath is %{public}s", realPath.c_str());
        std::string fileDir;
        if (!GetFileDir(tempCopyPath, fileDir)) {
            APP_LOGE("GetFileDir failed %{public}s", realPath.c_str());
            return false;
        }

        result = MkdirIfNotExist(fileDir);
        if (result != ERR_OK) {
            APP_LOGE("mkdir fileDir %{public}s faild %{public}d", fileDir.c_str(), result);
            return false;
        }

        result = InstalldClient::GetInstance()->CopyFile(realPath, tempCopyPath, "");
        if (result != ERR_OK) {
            APP_LOGE("CopyFile tempDir %{public}s faild %{public}d", realPath.c_str(), result);
            return false;
        }
    }

    return true;
}

std::string VerifyManagerHostImpl::GetRealPath(
    const std::string &bundleName, int32_t userId, const std::string &relativePath)
{
    auto path = relativePath;
    if (!BundleUtil::StartWith(path, ServiceConstants::PATH_SEPARATOR)) {
        path = ServiceConstants::PATH_SEPARATOR + path;
    }

    std::string filePath;
    if (BundleUtil::StartWith(path, DATA_STORAGE_BUNDLE)) {
        auto suffix = path.substr(DATA_STORAGE_BUNDLE.size());
        filePath.append(Constants::BUNDLE_CODE_DIR).append(ServiceConstants::PATH_SEPARATOR)
            .append(bundleName).append(ServiceConstants::PATH_SEPARATOR).append(suffix);
        return filePath;
    }

    std::string suffix;
    std::string el;
    std::string baseType;
    if (!GetDataDir(path, suffix, el, baseType)) {
        APP_LOGW("The path %{public}s is illegal", path.c_str());
        return filePath;
    }

    filePath.append(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR).append(el)
            .append(ServiceConstants::PATH_SEPARATOR).append(std::to_string(userId)).append(baseType)
            .append(bundleName).append(ServiceConstants::PATH_SEPARATOR).append(suffix);
    return filePath;
}

ErrCode VerifyManagerHostImpl::InnerVerify(
    const std::string &bundleName,
    const std::vector<std::string> &abcPaths)
{
    if (!VerifyAbc(GetTempRootDir(bundleName), abcPaths)) {
        APP_LOGE("verify abc failed");
        return ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED;
    }

    if (!MoveAbc(bundleName, abcPaths)) {
        APP_LOGE("move abc failed");
        return ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED;
    }

    APP_LOGI("verify abc success");
    return ERR_OK;
}

bool VerifyManagerHostImpl::CheckFileParam(const std::vector<std::string> &abcPaths)
{
    if (abcPaths.empty()) {
        APP_LOGE("CheckFile abcPath failed due to abcPaths is empty");
        return false;
    }

    for (const auto &abcPath : abcPaths) {
        if (!IsValidPath(abcPath)) {
            APP_LOGE("CheckFile abcPath(%{public}s) failed due to invalid path", abcPath.c_str());
            return false;
        }
        if (!BundleUtil::CheckFileType(abcPath, ABC_FILE_SUFFIX)) {
            APP_LOGE("CheckFile abcPath(%{public}s) failed due to not abc suffix", abcPath.c_str());
            return false;
        }
    }

    return true;
}

bool VerifyManagerHostImpl::VerifyAbc(
    const std::string &rootDir, const std::vector<std::string> &names)
{
    std::vector<std::string> paths;
    paths.reserve(names.size());
    for (const auto &name : names) {
        paths.emplace_back(rootDir + name);
    }

    return VerifyAbc(paths);
}

bool VerifyManagerHostImpl::VerifyAbc(const std::vector<std::string> &abcPaths)
{
    APP_LOGD("current process pid: %{public}d, ppid: %{public}d", getpid(), getppid());
    pid_t pid = fork();
    if (pid < 0) {
        APP_LOGE("fork child process failed");
        return false;
    } else if (pid == 0) {
        APP_LOGD("child process pid: %{public}d, ppid: %{public}d", getpid(), getppid());
        for (const auto &abcPath : abcPaths) {
            if (!BundleUtil::IsExistFile(abcPath)) {
                APP_LOGE("abcPath is not exist: %{public}s", abcPath.c_str());
                _exit(1);
            }

            if (!VerifyUtil::VerifyAbc(abcPath)) {
                APP_LOGE("verify abc failed");
                _exit(1);
            }
        }
        APP_LOGI("verify abc successfully");
        _exit(0);
    } else {
        int status;
        pid_t childPid = waitpid(pid, &status, 0);
        if (childPid == -1) {
            APP_LOGE("waitpid failed");
            return false;
        }
        if (WIFEXITED(status)) {
            int exitStatus = WEXITSTATUS(status);
            if (exitStatus != 0) {
                APP_LOGE("verify abc failed");
                return false;
            }
        } else {
            APP_LOGE("child process did not exit normally");
            return false;
        }
    }
    APP_LOGD("end process pid: %{public}d, ppid: %{public}d", getpid(), getppid());
    return true;
}

void VerifyManagerHostImpl::RemoveTempFiles(const std::string &bundleName)
{
    APP_LOGI("RemoveTempFiles");
    auto tempRootDir = GetTempRootDir(bundleName);
    InstalldClient::GetInstance()->RemoveDir(tempRootDir);
}

void VerifyManagerHostImpl::RemoveTempFiles(const std::vector<std::string> &paths)
{
    APP_LOGI("RemoveTempFiles");
    for (const auto &path : paths) {
        if (!BundleUtil::DeleteDir(path)) {
            APP_LOGW("RemoveFile %{private}s failed", path.c_str());
        }
    }
}

bool VerifyManagerHostImpl::GetFileName(const std::string &sourcePath, std::string &fileName)
{
    size_t pos = sourcePath.find_last_of(SEPARATOR);
    if (pos == std::string::npos) {
        APP_LOGE("invalid sourcePath");
        return false;
    }

    fileName = sourcePath.substr(pos + 1);
    return !fileName.empty();
}

bool VerifyManagerHostImpl::GetFileDir(const std::string &sourcePath, std::string &fileDir)
{
    size_t pos = sourcePath.find_last_of(SEPARATOR);
    if (pos == std::string::npos) {
        APP_LOGE("invalid sourcePath");
        return false;
    }

    fileDir = sourcePath.substr(0, pos);
    return !fileDir.empty();
}

ErrCode VerifyManagerHostImpl::MkdirIfNotExist(const std::string &dir)
{
    bool isDirExist = false;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(dir, isDirExist);
    if (result != ERR_OK) {
        APP_LOGE("Check if dir exist failed %{public}d", result);
        return result;
    }

    if (!isDirExist) {
        result = InstalldClient::GetInstance()->CreateBundleDir(dir);
        if (result != ERR_OK) {
            APP_LOGE("Create dir failed %{public}d", result);
            return result;
        }
    }
    return result;
}

bool VerifyManagerHostImpl::MoveAbc(
    const std::string &bundleName,
    const std::vector<std::string> &abcPaths)
{
    auto rootDir = GetRootDir(bundleName);
    auto tempRootDir = GetTempRootDir(bundleName);
    std::vector<std::string> hasMovePaths;
    ErrCode result = ERR_OK;
    for (size_t i = 0; i < abcPaths.size(); ++i) {
        std::string tempPath = tempRootDir + abcPaths[i];
        std::string targetPath = rootDir + abcPaths[i];
        std::string fileDir;
        if (!GetFileDir(targetPath, fileDir)) {
            APP_LOGE("GetFileDir failed %{public}s", targetPath.c_str());
            Rollback(hasMovePaths);
            return false;
        }

        result = MkdirIfNotExist(fileDir);
        if (result != ERR_OK) {
            APP_LOGE("mkdir fileDir %{public}s faild %{public}d", fileDir.c_str(), result);
            Rollback(hasMovePaths);
            return false;
        }

        result = InstalldClient::GetInstance()->MoveFile(tempPath, targetPath);
        if (result != ERR_OK) {
            APP_LOGE("move file to real path failed %{public}d", result);
            Rollback(hasMovePaths);
            return false;
        }

        hasMovePaths.emplace_back(targetPath);
    }

    return true;
}

void VerifyManagerHostImpl::Rollback(
    const std::string &rootDir, const std::vector<std::string> &names)
{
    std::vector<std::string> paths;
    for (const auto &name : names) {
        paths.emplace_back(rootDir + name);
    }

    Rollback(paths);
}

void VerifyManagerHostImpl::Rollback(const std::vector<std::string> &paths)
{
    for (const auto &abcPath : paths) {
        auto result = BundleUtil::DeleteDir(abcPath);
        if (result != ERR_OK) {
            APP_LOGE("move file to real path failed %{public}d", result);
        }
    }
}

ErrCode VerifyManagerHostImpl::DeleteAbc(const std::string &path)
{
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_TWELVE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_RUN_DYN_CODE)) {
        APP_LOGE("DeleteAbc failed due to permission denied");
        return ERR_BUNDLE_MANAGER_VERIFY_PERMISSION_DENIED;
    }
    if (!IsValidPath(path)) {
        APP_LOGE("DeleteAbc failed due to invalid path");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }
    if (!BundleUtil::CheckFileType(path, ABC_FILE_SUFFIX)) {
        APP_LOGE("DeleteAbc failed due to not abc file");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DeleteAbc failed due to dataMgr is null");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_FAILED;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    InnerBundleInfo innerBundleInfo;
    if (dataMgr->GetInnerBundleInfoByUid(callingUid, innerBundleInfo) != ERR_OK) {
        APP_LOGE("DeleteAbc failed due to get callingUid failed");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_FAILED;
    }

    auto &mtx = GetBundleMutex(innerBundleInfo.GetBundleName());
    std::lock_guard lock {mtx};
    std::string realPath;
    realPath.append(Constants::BUNDLE_CODE_DIR).append(ServiceConstants::PATH_SEPARATOR)
        .append(innerBundleInfo.GetBundleName()).append(ServiceConstants::PATH_SEPARATOR)
        .append(ABCS_DIR).append(ServiceConstants::PATH_SEPARATOR).append(path);
    bool isExist = false;
    auto result = InstalldClient::GetInstance()->IsExistFile(realPath, isExist);
    if (result != ERR_OK) {
        APP_LOGE("DeleteAbc %{public}s failed due to call IsExistFile failed %{public}d",
            realPath.c_str(), result);
        return ERR_BUNDLE_MANAGER_DELETE_ABC_FAILED;
    }
    if (!isExist) {
        APP_LOGE("DeleteAbc failed due to path %{public}s is not exist", realPath.c_str());
        return ERR_BUNDLE_MANAGER_DELETE_ABC_FAILED;
    }
    result = InstalldClient::GetInstance()->RemoveDir(realPath);
    if (result != ERR_OK) {
        APP_LOGE("DeleteAbc failed due to remove path %{public}s failed %{public}d",
            realPath.c_str(), result);
        return ERR_BUNDLE_MANAGER_DELETE_ABC_FAILED;
    }
    return ERR_OK;
}

std::mutex &VerifyManagerHostImpl::GetBundleMutex(const std::string &bundleName)
{
    bundleMutex_.lock_shared();
    auto it = bundleMutexMap_.find(bundleName);
    if (it == bundleMutexMap_.end()) {
        bundleMutex_.unlock_shared();
        std::unique_lock lock {bundleMutex_};
        return bundleMutexMap_[bundleName];
    }
    bundleMutex_.unlock_shared();
    return it->second;
}
} // AppExecFwk
} // namespace OHOS
