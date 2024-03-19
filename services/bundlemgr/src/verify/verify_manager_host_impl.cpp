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

bool IsFileNameValid(const std::string &fileName)
{
    if (fileName.find("..") != std::string::npos
        || fileName.find("/") != std::string::npos
        || fileName.find("\\") != std::string::npos
        || fileName.find("%") != std::string::npos) {
        return false;
    }
    return true;
}

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
}
VerifyManagerHostImpl::VerifyManagerHostImpl()
{
    APP_LOGI("create VerifyManagerHostImpl.");
}

VerifyManagerHostImpl::~VerifyManagerHostImpl()
{
    APP_LOGI("destroy VerifyManagerHostImpl.");
}

ErrCode VerifyManagerHostImpl::Verify(const std::vector<std::string> &abcPaths,
    const std::vector<std::string> &abcNames, bool flag)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_RUN_DYN_CODE)) {
        APP_LOGE("verify permission failed.");
        return ERR_BUNDLE_MANAGER_VERIFY_PERMISSION_DENIED;
    }

    if (!CheckFileParam(abcPaths, abcNames)) {
        APP_LOGE("CheckFile failed.");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    ErrCode ret = InnerVerify(abcPaths, abcNames, flag);
    RemoveTempFiles(abcPaths);
    return ret;
}

ErrCode VerifyManagerHostImpl::InnerVerify(const std::vector<std::string> &abcPaths,
    const std::vector<std::string> &abcNames, bool flag)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("verify failed, dataMgr is null");
        return ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    InnerBundleInfo innerBundleInfo;
    if (dataMgr->GetInnerBundleInfoByUid(callingUid, innerBundleInfo) != ERR_OK) {
        APP_LOGE("verify failed, callingUid is %{public}d", callingUid);
        return ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED;
    }

    std::string rootDir;
    rootDir.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
        .append(innerBundleInfo.GetBundleName()).append(Constants::PATH_SEPARATOR)
        .append(ABCS_DIR).append(Constants::PATH_SEPARATOR);
    if (!MoveAbc(abcPaths, abcNames, rootDir)) {
        APP_LOGE("move abc failed.");
        return ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED;
    }

    if (!VerifyAbc(rootDir, abcNames)) {
        APP_LOGE("verify abc failed.");
        Rollback(rootDir, abcNames);
        return ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED;
    }

    APP_LOGI("verify abc success.");
    return ERR_OK;
}

bool VerifyManagerHostImpl::CheckFileParam(
    const std::vector<std::string> &abcPaths, const std::vector<std::string> &abcNames)
{
    if (abcPaths.empty() || abcNames.empty()) {
        APP_LOGE("CheckFile abcPath failed due to abcPaths or abcNames is empty");
        return false;
    }

    for (const auto &abcPath : abcPaths) {
        if (!IsValidPath(abcPath)) {
            APP_LOGE("CheckFile abcPath(%{public}s) failed due to invalid path", abcPath.c_str());
            return false;
        }
        if (!BundleUtil::CheckFileType(abcPath, Constants::ABC_FILE_SUFFIX)) {
            APP_LOGE("CheckFile abcPath(%{public}s) failed due to not abc suffix.", abcPath.c_str());
            return false;
        }
        if (!BundleUtil::StartWith(abcPath, Constants::HAP_COPY_PATH)) {
            APP_LOGE("CheckFile abcPath(%{public}s) failed due to prefix error.", abcPath.c_str());
            return false;
        }
    }

    for (const auto abcName : abcNames) {
        if (!IsValidPath(abcName)) {
            APP_LOGE("CheckFile abcName(%{public}s) failed due to invalid path", abcName.c_str());
            return false;
        }
        if (!BundleUtil::CheckFileType(abcName, Constants::ABC_FILE_SUFFIX)) {
            APP_LOGE("CheckFile abcName(%{public}s) failed due to not abc suffix.", abcName.c_str());
            return false;
        }
    }

    return true;
}

bool VerifyManagerHostImpl::VerifyAbc(
    const std::string &rootDir, const std::vector<std::string> &names)
{
    std::vector<std::string> paths;
    for (const auto &name : names) {
        paths.emplace_back(rootDir + name);
    }

    return VerifyAbc(paths);
}

bool VerifyManagerHostImpl::VerifyAbc(const std::vector<std::string> &abcPaths)
{
    for (const auto &abcPath : abcPaths) {
        if (!BundleUtil::IsExistFile(abcPath)) {
            APP_LOGE("abcPath is not exist: %{public}s.", abcPath.c_str());
            return false;
        }

        if (!VerifyUtil::VerifyAbc(abcPath)) {
            APP_LOGE("verify abc failed.");
            return false;
        }
    }

    return true;
}

void VerifyManagerHostImpl::RemoveTempFiles(const std::vector<std::string> &paths)
{
    APP_LOGI("RemoveTempFiles.");
    for (const auto &path : paths) {
        if (!BundleUtil::DeleteDir(path)) {
            APP_LOGW("RemoveFile %{private}s failed.", path.c_str());
        }
    }
}

bool VerifyManagerHostImpl::GetFileName(const std::string &sourcePath, std::string &fileName)
{
    size_t pos = sourcePath.find_last_of(SEPARATOR);
    if (pos == std::string::npos) {
        APP_LOGE("invalid sourcePath.");
        return false;
    }

    fileName = sourcePath.substr(pos + 1);
    return !fileName.empty();
}

bool VerifyManagerHostImpl::GetFileDir(const std::string &sourcePath, std::string &fileDir)
{
    size_t pos = sourcePath.find_last_of(SEPARATOR);
    if (pos == std::string::npos) {
        APP_LOGE("invalid sourcePath.");
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

bool VerifyManagerHostImpl::MoveAbc(const std::vector<std::string> &abcPaths,
    const std::vector<std::string> &abcNames, const std::string &rootDir)
{
    if (abcPaths.size() != abcNames.size()) {
        APP_LOGE("The number %{public}zu of abcPaths is different from that of abcNames",
            abcPaths.size());
        return false;
    }

    std::vector<std::string> hasMovePaths;
    ErrCode result = ERR_OK;
    for (size_t i = 0; i < abcPaths.size(); ++i) {
        std::string targetPath = rootDir + abcNames[i];
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

        result = InstalldClient::GetInstance()->MoveFile(abcPaths[i], targetPath);
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
        std::string targetPath;
        auto result = InstalldClient::GetInstance()->MoveFile(abcPath, targetPath);
        if (result != ERR_OK) {
            APP_LOGE("move file to real path failed %{public}d", result);
        }
    }
}

ErrCode VerifyManagerHostImpl::CreateFd(const std::string &fileName, int32_t &fd, std::string &path)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_RUN_DYN_CODE)) {
        APP_LOGE("verify install permission failed.");
        return ERR_BUNDLE_MANAGER_VERIFY_PERMISSION_DENIED;
    }

    if (!BundleUtil::CheckFileType(fileName, Constants::ABC_FILE_SUFFIX)) {
        APP_LOGE("not abc file.");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    if (!IsFileNameValid(fileName)) {
        APP_LOGE("invalid fileName");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    std::string tmpDir = BundleUtil::CreateInstallTempDir(++id_, DirType::ABC_FILE_DIR);
    if (tmpDir.empty()) {
        APP_LOGE("create tmp dir failed.");
        return ERR_BUNDLE_MANAGER_VERIFY_CREATE_TARGET_DIR_FAILED;
    }

    path = tmpDir + fileName;
    if ((fd = BundleUtil::CreateFileDescriptor(path, 0)) < 0) {
        APP_LOGE("create file descriptor failed.");
        BundleUtil::DeleteDir(tmpDir);
        return ERR_BUNDLE_MANAGER_VERIFY_CREATE_FD_FAILED;
    }
    return ERR_OK;
}

ErrCode VerifyManagerHostImpl::DeleteAbc(const std::string &path)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_RUN_DYN_CODE)) {
        APP_LOGE("DeleteAbc failed due to permission denied.");
        return ERR_BUNDLE_MANAGER_VERIFY_PERMISSION_DENIED;
    }
    if (!IsValidPath(path)) {
        APP_LOGE("DeleteAbc failed due to invalid path");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }
    if (!BundleUtil::CheckFileType(path, Constants::ABC_FILE_SUFFIX)) {
        APP_LOGE("DeleteAbc failed due to not abc file.");
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
    std::string realPath;
    realPath.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
        .append(innerBundleInfo.GetBundleName()).append(Constants::PATH_SEPARATOR)
        .append(ABCS_DIR).append(Constants::PATH_SEPARATOR).append(path);
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
} // AppExecFwk
} // namespace OHOS
