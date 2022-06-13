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
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
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
    if (srcModulePath.empty() || targetPath.empty()) {
        APP_LOGE("Calling the function ExtractModuleFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::MkRecursiveDir(targetPath, true)) {
        APP_LOGE("create target dir %{public}s failed", targetPath.c_str());
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    if (!InstalldOperator::ExtractFiles(srcModulePath, targetPath, targetSoPath, cpuAbi)) {
        APP_LOGE("extract %{public}s to %{public}s failed", srcModulePath.c_str(), targetPath.c_str());
        InstalldOperator::DeleteDir(targetPath);
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RenameModuleDir(const std::string &oldPath, const std::string &newPath)
{
    APP_LOGD("rename %{public}s to %{public}s", oldPath.c_str(), newPath.c_str());
    if (oldPath.empty() || newPath.empty()) {
        APP_LOGE("Calling the function RenameModuleDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::RenameDir(oldPath, newPath)) {
        APP_LOGE("rename module dir %{public}s to %{public}s failed", oldPath.c_str(), newPath.c_str());
        return ERR_APPEXECFWK_INSTALLD_RNAME_DIR_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateBundleDataDir(const std::string &bundleDataDir,
    const int userid, const int uid, const int gid, const std::string &apl, bool onlyOneUser)
{
    if (bundleDataDir.empty() || uid < 0 || gid < 0) {
        APP_LOGE("Calling the function CreateBundleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    std::string bundleName = strrchr(bundleDataDir.c_str(), Constants::FILE_SEPARATOR_CHAR);
    if (onlyOneUser) {
        std::string createDir;
        if (bundleDataDir.back() != Constants::PATH_SEPARATOR[0]) {
            createDir = bundleDataDir + Constants::PATH_SEPARATOR;
        } else {
            createDir = bundleDataDir;
        }
        if (!InstalldOperator::MkOwnerDir(createDir + Constants::DATA_DIR, true, uid, gid)) {
            APP_LOGE("CreateBundleDataDir MkOwnerDir DATA_DIR failed");
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }

        if (!InstalldOperator::MkOwnerDir(createDir + Constants::DATA_BASE_DIR,
                                          S_IRWXU | S_IRWXG | S_ISGID,
                                          uid,
                                          Constants::DATABASE_DIR_GID)) {
            APP_LOGE("CreateBundleDataDir MkOwnerDir DATA_BASE_DIR failed");
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }

        if (!InstalldOperator::MkOwnerDir(createDir + Constants::CACHE_DIR, true, uid, gid)) {
            APP_LOGE("CreateBundleDataDir MkOwnerDir CACHE_DIR failed");
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }

        if (!InstalldOperator::MkOwnerDir(createDir + Constants::SHARED_PREFERENCE_DIR, true, uid, gid)) {
            APP_LOGE("CreateBundleDataDir MkOwnerDir SHARED_PREFERENCE_DIR failed");
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
    }

    if (CreateNewBundleDataDir(bundleName, userid, uid, gid, apl) != ERR_OK) {
        APP_LOGE("CreateNewBundleDataDir MkOwnerDir failed");
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateNewBundleDataDir(
    const std::string &bundleName, const int userid, const int uid, const int gid, const std::string &apl)
{
    if (bundleName.empty() || userid < 0 || uid < 0 || gid < 0) {
        APP_LOGE("Calling the function CreateBundleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    for (const auto &el : Constants::BUNDLE_EL) {
        std::string bundleDataDir = GetBundleDataDir(el, userid) + Constants::BASE + bundleName;
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
    if (system::GetBoolParameter(Constants::DISTRIBUTED_FILE_PROPERTY, false)) {
        std::string distributedfile = Constants::DISTRIBUTED_FILE;
        distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(userid));
        if (!InstalldOperator::MkOwnerDir(distributedfile + bundleName, S_IRWXU | S_IRWXG | S_ISGID, uid, gid)) {
            APP_LOGE("Failed to mk dir for distributedfile");
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }

        distributedfile = Constants::DISTRIBUTED_FILE_NON_ACCOUNT;
        distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(userid));
        if (!InstalldOperator::MkOwnerDir(distributedfile + bundleName,
            S_IRWXU | S_IRWXG | S_ISGID, uid, Constants::DFS_GID)) {
            APP_LOGE("Failed to mk dir for non account distributedfile");
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveBundleDataDir(const std::string &bundleName, const int userid)
{
    APP_LOGD("InstalldHostImpl::RemoveBundleDataDir bundleName:%{public}s", bundleName.c_str());
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
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateModuleDataDir(
    const std::string &ModuleDir, const std::vector<std::string> &abilityDirs, const int uid, const int gid)
{
    if (ModuleDir.empty() || uid < 0 || gid < 0) {
        APP_LOGE("Calling the function CreateModuleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    std::string createDir;
    if (ModuleDir.back() != Constants::PATH_SEPARATOR[0]) {
        createDir = ModuleDir + Constants::PATH_SEPARATOR;
    } else {
        createDir = ModuleDir;
    }

    if (!InstalldOperator::MkOwnerDir(createDir + Constants::SHARED_DIR, true, uid, gid)) {
        APP_LOGE("CreateModuleDataDir MkOwnerDir %{public}s failed", Constants::SHARED_DIR.c_str());
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }

    for (auto &abilityDir : abilityDirs) {
        std::string dataDir = createDir + abilityDir + Constants::PATH_SEPARATOR + Constants::DATA_DIR;
        if (!InstalldOperator::MkOwnerDir(dataDir, true, uid, gid)) {
            APP_LOGE("CreateModuleDataDir MkOwnerDir %{public}s failed", dataDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        std::string cacheDir = createDir + abilityDir + Constants::PATH_SEPARATOR + Constants::CACHE_DIR;
        if (!InstalldOperator::MkOwnerDir(cacheDir, true, uid, gid)) {
            APP_LOGE("CreateModuleDataDir MkOwnerDir %{public}s failed", cacheDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        std::string dataBaseDir = createDir + abilityDir + Constants::PATH_SEPARATOR + Constants::DATA_BASE_DIR;
        if (!InstalldOperator::MkOwnerDir(dataBaseDir, true, uid, gid)) {
            APP_LOGE("CreateModuleDataDir MkOwnerDir %{public}s failed", dataBaseDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        std::string sharedDir = createDir + abilityDir + Constants::PATH_SEPARATOR + Constants::SHARED_PREFERENCE_DIR;
        if (!InstalldOperator::MkOwnerDir(sharedDir, true, uid, gid)) {
            APP_LOGE("CreateModuleDataDir MkOwnerDir %{public}s failed", sharedDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveModuleDataDir(const std::string &ModuleDir, const int userid)
{
    APP_LOGD("InstalldHostImpl::RemoveModuleDataDir ModuleDir:%{public}s", ModuleDir.c_str());
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
                          Constants::FILE_SEPARATOR_CHAR +
                          std::to_string(userid);
    return dataDir;
}

ErrCode InstalldHostImpl::GetBundleStats(
    const std::string &bundleName, const int32_t userId, std::vector<int64_t> &bundleStats)
{
    if (bundleName.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    std::string path = Constants::BUNDLE_CODE_DIR + Constants::FILE_SEPARATOR_CHAR + bundleName;
    int64_t fileSize = InstalldOperator::GetDiskUsage(path);
    std::vector<std::string> bundlePath;
    std::vector<std::string> cachePath;
    int64_t allBundleLocalSize = 0;
    for (const auto &el : Constants::BUNDLE_EL) {
        std::string filePath = Constants::BUNDLE_APP_DATA_BASE_DIR + el + Constants::FILE_SEPARATOR_CHAR +
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
    for (auto &el : Constants::BUNDLE_EL) {
        std::string filePath = Constants::BUNDLE_APP_DATA_BASE_DIR + el + Constants::FILE_SEPARATOR_CHAR +
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
        APP_LOGE("HapFileRestorecon path: %{public}s failed, ret:%{public}d", dir.c_str(), ret);
    }
    return ret;
#else
    return ERR_OK;
#endif // WITH_SELINUX
}

ErrCode InstalldHostImpl::GetBundleCachePath(const std::string &dir, std::vector<std::string> &cachePath)
{
    APP_LOGD("InstalldHostImpl::GetBundleCachePath start");
    if (dir.empty()) {
        APP_LOGE("Calling the function GetBundleCachePathl with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    InstalldOperator::TraverseCacheDirectory(dir, cachePath);
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
