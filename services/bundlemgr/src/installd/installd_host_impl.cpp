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

#include "installd/installd_host_impl.h"

#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "common_profile.h"
#include "directory_ex.h"
#ifdef WITH_SELINUX
#include "hap_restorecon.h"
#endif // WITH_SELINUX
#include "installd/installd_operator.h"
#include "installd/installd_permission_mgr.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string ARK_CACHE_PATH = "/data/local/ark-cache/";
const std::string ARK_PROFILE_PATH = "/data/local/ark-profile/";
}

InstalldHostImpl::InstalldHostImpl()
{
    APP_LOGI("installd service instance is created");
}

InstalldHostImpl::~InstalldHostImpl()
{
    APP_LOGI("installd service instance is destroyed");
}

ErrCode InstalldHostImpl::CreateBundleDir(const std::string &bundleDir)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleDir.empty()) {
        APP_LOGE("Calling the function CreateBundleDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (InstalldOperator::IsExistDir(bundleDir)) {
        APP_LOGW("bundleDir %{public}s is exist", bundleDir.c_str());
        OHOS::ForceRemoveDirectory(bundleDir);
    }
    if (!InstalldOperator::MkRecursiveDir(bundleDir, true)) {
        APP_LOGE("create bundle dir %{public}s failed", bundleDir.c_str());
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    APP_LOGD("ExtractModuleFiles extract original src %{public}s and target src %{public}s",
        srcModulePath.c_str(), targetPath.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (srcModulePath.empty() || targetPath.empty()) {
        APP_LOGE("Calling the function ExtractModuleFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::MkRecursiveDir(targetPath, true)) {
        APP_LOGE("create target dir %{private}s failed", targetPath.c_str());
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    if (!InstalldOperator::ExtractFiles(srcModulePath, targetPath, targetSoPath, cpuAbi)) {
        APP_LOGE("extract %{private}s to %{private}s failed", srcModulePath.c_str(), targetPath.c_str());
        InstalldOperator::DeleteDir(targetPath);
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractFiles(const ExtractParam &extractParam)
{
    APP_LOGD("ExtractFiles extractParam %{public}s", extractParam.ToString().c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (extractParam.srcPath.empty() || extractParam.targetPath.empty()) {
        APP_LOGE("Calling the function ExtractFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (!InstalldOperator::ExtractFiles(extractParam)) {
        APP_LOGE("extract failed");
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }

    return ERR_OK;
}

ErrCode InstalldHostImpl::RenameModuleDir(const std::string &oldPath, const std::string &newPath)
{
    APP_LOGD("rename %{private}s to %{private}s", oldPath.c_str(), newPath.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (oldPath.empty() || newPath.empty()) {
        APP_LOGE("Calling the function RenameModuleDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::RenameDir(oldPath, newPath)) {
        APP_LOGE("rename module dir %{private}s to %{private}s failed", oldPath.c_str(), newPath.c_str());
        return ERR_APPEXECFWK_INSTALLD_RNAME_DIR_FAILED;
    }
    return ERR_OK;
}

static void CreateBackupExtHomeDir(const std::string &bundleName, const int userid, const int uid)
{
    // Setup BackupExtensionAbility's home directory in a harmless way
    std::string bundleBackupDir = Constants::BUNDLE_BACKUP_HOME_PATH + bundleName;
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::MkOwnerDir(bundleBackupDir, S_IRWXU | S_IRWXG | S_ISGID, uid, Constants::BACKU_HOME_GID)) {
        static std::once_flag logOnce;
        std::call_once(logOnce, []() {
            APP_LOGW("CreateBundledatadir MkOwnerDir(backup's home dir) failed");
        });
    }
}

static void CreateShareDir(const std::string &bundleName, const int userid, const int uid, const int gid)
{
    std::string bundleShareDir = Constants::SHARE_FILE_PATH + bundleName;
    bundleShareDir = bundleShareDir.replace(bundleShareDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::MkOwnerDir(bundleShareDir, S_IRWXU | S_IRWXG | S_ISGID, uid, gid)) {
        static std::once_flag logOnce;
        std::call_once(logOnce, []() {
            APP_LOGW("CreateBundledatadir MkOwnerDir(share's home dir) failed");
        });
    }
}

ErrCode InstalldHostImpl::CreateBundleDataDir(const std::string &bundleName,
    const int userid, const int uid, const int gid, const std::string &apl)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty() || userid < 0 || uid < 0 || gid < 0) {
        APP_LOGE("Calling the function CreateBundleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    for (const auto &el : Constants::BUNDLE_EL) {
        std::string bundleDataDir = GetBundleDataDir(el, userid) + Constants::BASE;
        if (access(bundleDataDir.c_str(), F_OK) != 0) {
            APP_LOGW("CreateBundleDataDir base directory does not existed.");
            return ERR_OK;
        }
        bundleDataDir += bundleName;
        if (!InstalldOperator::MkOwnerDir(bundleDataDir, S_IRWXU, uid, gid)) {
            APP_LOGE("CreateBundledatadir MkOwnerDir failed");
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        if (el == Constants::BUNDLE_EL[1]) {
            for (const auto &dir : Constants::BUNDLE_DATA_DIR) {
                if (!InstalldOperator::MkOwnerDir(bundleDataDir + dir, S_IRWXU, uid, gid)) {
                    APP_LOGE("CreateBundledatadir MkOwnerDir el2 failed");
                    return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
                }
            }
        }
        ErrCode ret = SetDirApl(bundleDataDir, bundleName, apl);
        if (ret != ERR_OK) {
            APP_LOGE("CreateBundleDataDir SetDirApl failed");
            return ret;
        }
        std::string databaseDir = GetBundleDataDir(el, userid) + Constants::DATABASE + bundleName;
        if (!InstalldOperator::MkOwnerDir(
            databaseDir, S_IRWXU | S_IRWXG | S_ISGID, uid, Constants::DATABASE_DIR_GID)) {
            APP_LOGE("CreateBundle databaseDir MkOwnerDir failed");
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        ret = SetDirApl(databaseDir, bundleName, apl);
        if (ret != ERR_OK) {
            APP_LOGE("CreateBundleDataDir SetDirApl failed");
            return ret;
        }
    }
    std::string distributedfile = Constants::DISTRIBUTED_FILE;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::MkOwnerDir(distributedfile + bundleName,
        S_IRWXU | S_IRWXG | S_ISGID, uid, Constants::DFS_GID)) {
        APP_LOGE("Failed to mk dir for distributedfile");
    }

    distributedfile = Constants::DISTRIBUTED_FILE_NON_ACCOUNT;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::MkOwnerDir(distributedfile + bundleName,
        S_IRWXU | S_IRWXG | S_ISGID, uid, Constants::DFS_GID)) {
        APP_LOGE("Failed to mk dir for non account distributedfile");
    }
    
    CreateBackupExtHomeDir(bundleName, userid, uid);
    CreateShareDir(bundleName, userid, uid, gid);
    return ERR_OK;
}

static ErrCode RemoveShareDir(const std::string &bundleName, const int userid)
{
    std::string shareFileDir = Constants::SHARE_FILE_PATH + bundleName;
    shareFileDir = shareFileDir.replace(shareFileDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(shareFileDir)) {
        APP_LOGE("remove dir %{public}s failed", shareFileDir.c_str());
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveBundleDataDir(const std::string &bundleName, const int userid)
{
    APP_LOGD("InstalldHostImpl::RemoveBundleDataDir bundleName:%{public}s", bundleName.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty() || userid < 0) {
        APP_LOGE("Calling the function CreateBundleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    for (const auto &el : Constants::BUNDLE_EL) {
        std::string bundleDataDir = GetBundleDataDir(el, userid) + Constants::BASE + bundleName;
        if (!InstalldOperator::DeleteDir(bundleDataDir)) {
            APP_LOGE("remove dir %{public}s failed", bundleDataDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }
        std::string databaseDir = GetBundleDataDir(el, userid) + Constants::DATABASE + bundleName;
        if (!InstalldOperator::DeleteDir(databaseDir)) {
            APP_LOGE("remove dir %{public}s failed", databaseDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }
    }
    if (RemoveShareDir(bundleName, userid) != ERR_OK) {
        APP_LOGE("failed to remove share dir");
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveModuleDataDir(const std::string &ModuleDir, const int userid)
{
    APP_LOGD("InstalldHostImpl::RemoveModuleDataDir ModuleDir:%{public}s", ModuleDir.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (ModuleDir.empty() || userid < 0) {
        APP_LOGE("Calling the function CreateModuleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    for (const auto &el : Constants::BUNDLE_EL) {
        std::string moduleDataDir = GetBundleDataDir(el, userid) + Constants::BASE + ModuleDir;
        if (!InstalldOperator::DeleteDir(moduleDataDir)) {
            APP_LOGE("remove dir %{public}s failed", moduleDataDir.c_str());
        }
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveDir(const std::string &dir)
{
    APP_LOGD("InstalldHostImpl::RemoveDir:%{public}s", dir.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dir.empty()) {
        APP_LOGE("Calling the function RemoveDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::DeleteDir(dir)) {
        APP_LOGE("remove dir %{public}s failed", dir.c_str());
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CleanBundleDataDir(const std::string &dataDir)
{
    APP_LOGD("InstalldHostImpl::CleanBundleDataDir start");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dataDir.empty()) {
        APP_LOGE("Calling the function CleanBundleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (!InstalldOperator::DeleteFiles(dataDir)) {
        APP_LOGE("CleanBundleDataDir delete files failed");
        return ERR_APPEXECFWK_INSTALLD_CLEAN_DIR_FAILED;
    }
    return ERR_OK;
}

std::string InstalldHostImpl::GetBundleDataDir(const std::string &el, const int userid) const
{
    std::string dataDir = Constants::BUNDLE_APP_DATA_BASE_DIR +
                          el +
                          Constants::PATH_SEPARATOR +
                          std::to_string(userid);
    return dataDir;
}

ErrCode InstalldHostImpl::GetBundleStats(
    const std::string &bundleName, const int32_t userId, std::vector<int64_t> &bundleStats)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    std::vector<std::string> bundlePath;
    bundlePath.push_back(Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName); // bundle code
    bundlePath.push_back(ARK_CACHE_PATH + bundleName); // ark cache file
    // ark profile
    bundlePath.push_back(ARK_PROFILE_PATH + std::to_string(userId) + Constants::PATH_SEPARATOR + bundleName);
    int64_t fileSize = InstalldOperator::GetDiskUsageFromPath(bundlePath);
    bundlePath.clear();
    std::vector<std::string> cachePath;
    int64_t allBundleLocalSize = 0;
    for (const auto &el : Constants::BUNDLE_EL) {
        std::string filePath = Constants::BUNDLE_APP_DATA_BASE_DIR + el + Constants::PATH_SEPARATOR +
            std::to_string(userId) + Constants::BASE + bundleName;
        allBundleLocalSize += InstalldOperator::GetDiskUsage(filePath);
        if (el == Constants::BUNDLE_EL[1]) {
            for (const auto &dataDir : Constants::BUNDLE_DATA_DIR) {
                bundlePath.push_back(filePath + dataDir);
            }
        } else {
            bundlePath.push_back(filePath);
        }
        InstalldOperator::TraverseCacheDirectory(filePath, cachePath);
    }
    int64_t bundleLocalSize = InstalldOperator::GetDiskUsageFromPath(bundlePath);
    int64_t systemFolderSize = allBundleLocalSize - bundleLocalSize;
    // index 0 : bundle data size
    bundleStats.push_back(fileSize + systemFolderSize);
    int64_t cacheSize = InstalldOperator::GetDiskUsageFromPath(cachePath);
    bundleLocalSize -= cacheSize;
    // index 1 : local bundle data size
    bundleStats.push_back(bundleLocalSize);

    // index 2 : distributed data size
    std::string distributedfilePath = Constants::DISTRIBUTED_FILE;
    distributedfilePath = distributedfilePath.replace(distributedfilePath.find("%"), 1, std::to_string(userId)) +
        bundleName;
    int64_t distributedFileSize = InstalldOperator::GetDiskUsage(distributedfilePath);
    bundleStats.push_back(distributedFileSize);

    // index 3 : database size
    std::vector<std::string> dataBasePath;
    for (const auto &el : Constants::BUNDLE_EL) {
        std::string filePath = Constants::BUNDLE_APP_DATA_BASE_DIR + el + Constants::PATH_SEPARATOR +
            std::to_string(userId) + Constants::DATABASE + bundleName;
        dataBasePath.push_back(filePath);
    }
    int64_t databaseFileSize = InstalldOperator::GetDiskUsageFromPath(dataBasePath);
    bundleStats.push_back(databaseFileSize);

    // index 4 : cache size
    bundleStats.push_back(cacheSize);
    return ERR_OK;
}

ErrCode InstalldHostImpl::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl)
{
#ifdef WITH_SELINUX
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dir.empty() || bundleName.empty()) {
        APP_LOGE("Calling the function SetDirApl with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    std::string aplLevel = Profile::AVAILABLELEVEL_NORMAL;
    if (!apl.empty()) {
        aplLevel = apl;
    }
    HapContext hapContext;
    int ret = hapContext.HapFileRestorecon(dir, aplLevel, bundleName, SELINUX_HAP_RESTORECON_RECURSE);
    if (ret != 0) {
        APP_LOGE("HapFileRestorecon path: %{private}s failed, ret:%{public}d", dir.c_str(), ret);
    }
    return ret;
#else
    return ERR_OK;
#endif // WITH_SELINUX
}

ErrCode InstalldHostImpl::GetBundleCachePath(const std::string &dir, std::vector<std::string> &cachePath)
{
    APP_LOGD("InstalldHostImpl::GetBundleCachePath start");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dir.empty()) {
        APP_LOGE("Calling the function GetBundleCachePath with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    InstalldOperator::TraverseCacheDirectory(dir, cachePath);
    return ERR_OK;
}

ErrCode InstalldHostImpl::ScanDir(
    const std::string &dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
{
    APP_LOGD("InstalldHostImpl::Scan start %{public}s", dir.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dir.empty()) {
        APP_LOGE("Calling the function Scan with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    InstalldOperator::ScanDir(dir, scanMode, resultMode, paths);
    return ERR_OK;
}

ErrCode InstalldHostImpl::MoveFile(const std::string &oldPath, const std::string &newPath)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::RenameFile(oldPath, newPath)) {
        APP_LOGE("Move file %{public}s to %{public}s failed",
            oldPath.c_str(), newPath.c_str());
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!OHOS::ChangeModeFile(newPath, mode)) {
        APP_LOGE("change mode failed");
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CopyFile(const std::string &oldPath, const std::string &newPath)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::CopyFile(oldPath, newPath)) {
        APP_LOGE("Copy file %{public}s to %{public}s failed",
            oldPath.c_str(), newPath.c_str());
        return ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED;
    }
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!OHOS::ChangeModeFile(newPath, mode)) {
        APP_LOGE("change mode failed");
        return ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::Mkdir(
    const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    APP_LOGD("Mkdir start %{public}s", dir.c_str());
    if (dir.empty()) {
        APP_LOGE("Calling the function Mkdir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (!InstalldOperator::MkOwnerDir(dir, mode, uid, gid)) {
        APP_LOGE("Mkdir %{public}s failed", dir.c_str());
        return ERR_APPEXECFWK_INSTALLD_MKDIR_FAILED;
    }

    return ERR_OK;
}

ErrCode InstalldHostImpl::GetFileStat(const std::string &file, FileStat &fileStat)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    APP_LOGD("GetFileStat start %{public}s", file.c_str());
    struct stat s;
    if (stat(file.c_str(), &s) != 0) {
        APP_LOGE("Stat file(%{public}s) failed", file.c_str());
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    fileStat.uid = static_cast<int32_t>(s.st_uid);
    fileStat.gid = static_cast<int32_t>(s.st_gid);
    fileStat.lastModifyTime = static_cast<int64_t>(s.st_mtime);
    fileStat.isDir = s.st_mode & S_IFDIR;
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractDiffFiles(const std::string &filePath, const std::string &targetPath,
    const std::string &cpuAbi)
{
    if (filePath.empty() || targetPath.empty()) {
        APP_LOGE("Calling the function ExtractDiffFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::ExtractDiffFiles(filePath, targetPath, cpuAbi)) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath)
{
    if (oldSoPath.empty() || diffFilePath.empty() || newSoPath.empty()) {
        APP_LOGE("Calling the function ExtractDiffFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath)) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_APPLY_DIFF_PATCH_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistDir(const std::string &dir, bool &isExist)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    isExist = InstalldOperator::IsExistDir(dir);
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsDirEmpty(const std::string &dir, bool &isDirEmpty)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    isDirEmpty = InstalldOperator::IsDirEmpty(dir);
    return ERR_OK;
}

ErrCode InstalldHostImpl::ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &dirVec)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    InstalldOperator::ObtainQuickFixFileDir(dir, dirVec);
    return ERR_OK;
}

ErrCode InstalldHostImpl::CopyFiles(const std::string &sourceDir, const std::string &destinationDir)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    InstalldOperator::CopyFiles(sourceDir, destinationDir);
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
