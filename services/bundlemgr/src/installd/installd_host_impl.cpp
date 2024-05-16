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

#include "aot/aot_executor.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#if defined(CODE_SIGNATURE_ENABLE)
#include "byte_buffer.h"
#include "code_sign_utils.h"
#endif
#include "common_profile.h"
#include "directory_ex.h"
#ifdef WITH_SELINUX
#include "hap_restorecon.h"
#ifndef SELINUX_HAP_DEBUGGABLE
#define SELINUX_HAP_DEBUGGABLE 2
#endif
#endif // WITH_SELINUX
#include "installd/installd_operator.h"
#include "installd/installd_permission_mgr.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string ARK_CACHE_PATH = "/data/local/ark-cache/";
const std::string ARK_PROFILE_PATH = "/data/local/ark-profile/";
const std::vector<std::string> BUNDLE_DATA_DIR = {
    "/cache",
    "/files",
    "/temp",
    "/preferences",
    "/haps"
};
const std::string CLOUD_FILE_PATH = "/data/service/el2/%/hmdfs/cloud/data/";
const std::string BUNDLE_BACKUP_HOME_PATH_EL2 = "/data/service/el2/%/backup/bundles/";
const std::string DISTRIBUTED_FILE = "/data/service/el2/%/hmdfs/account/data/";
const std::string SHARE_FILE_PATH = "/data/service/el2/%/share/";
const std::string BUNDLE_BACKUP_HOME_PATH_EL1 = "/data/service/el1/%/backup/bundles/";
const std::string DISTRIBUTED_FILE_NON_ACCOUNT = "/data/service/el2/%/hmdfs/non_account/data/";
enum class DirType {
    DIR_EL1,
    DIR_EL2,
};
#if defined(CODE_SIGNATURE_ENABLE)
using namespace OHOS::Security::CodeSign;
#endif
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
        APP_LOGE("create bundle dir %{public}s failed, errno:%{public}d", bundleDir.c_str(), errno);
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
        APP_LOGE("create target dir %{public}s failed, errno:%{public}d", targetPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    if (!InstalldOperator::ExtractFiles(srcModulePath, targetSoPath, cpuAbi)) {
        APP_LOGE("extract %{public}s to %{public}s failed errno:%{public}d",
            srcModulePath.c_str(), targetPath.c_str(), errno);
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
        APP_LOGE("extract failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }

    return ERR_OK;
}

ErrCode InstalldHostImpl::ExecuteAOT(const AOTArgs &aotArgs)
{
    APP_LOGD("begin to execute AOT, args : %{public}s", aotArgs.ToString().c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode ret = ERR_OK;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret);
    APP_LOGD("execute AOT ret : %{public}d", ret);
    return ret;
}

ErrCode InstalldHostImpl::StopAOT()
{
    APP_LOGI("StopAOT begin");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    return AOTExecutor::GetInstance().StopAOT();
}

ErrCode InstalldHostImpl::RenameModuleDir(const std::string &oldPath, const std::string &newPath)
{
    APP_LOGD("rename %{public}s to %{public}s", oldPath.c_str(), newPath.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (oldPath.empty() || newPath.empty()) {
        APP_LOGE("Calling the function RenameModuleDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::RenameDir(oldPath, newPath)) {
        APP_LOGE("rename module dir %{public}s to %{public}s failed errno:%{public}d",
            oldPath.c_str(), newPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_RNAME_DIR_FAILED;
    }
    return ERR_OK;
}

static void GetBackupExtDirByType(std::string &bundleBackupDir, const std::string &bundleName, const DirType dirType)
{
    switch (dirType) {
        case DirType::DIR_EL1:
            bundleBackupDir = BUNDLE_BACKUP_HOME_PATH_EL1 + bundleName;
            break;
        case DirType::DIR_EL2:
            bundleBackupDir = BUNDLE_BACKUP_HOME_PATH_EL2 + bundleName;
            break;
        default:
            break;
    }
}

static void CreateBackupExtHomeDir(const std::string &bundleName, const int32_t userid, const int32_t uid,
    std::string &bundleBackupDir, const DirType dirType)
{
    GetBackupExtDirByType(bundleBackupDir, bundleName, dirType);
    APP_LOGD("CreateBackupExtHomeDir begin, type %{public}d, path %{public}s.", dirType, bundleBackupDir.c_str());
    if (bundleBackupDir.empty()) {
        APP_LOGW("CreateBackupExtHomeDir backup dir empty, type  %{public}d.", dirType);
        return;
    }
    // Setup BackupExtensionAbility's home directory in a harmless way
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::MkOwnerDir(bundleBackupDir, S_IRWXU | S_IRWXG | S_ISGID, uid, Constants::BACKU_HOME_GID)) {
        static std::once_flag logOnce;
        std::call_once(logOnce, []() {
            APP_LOGW("CreateBackupExtHomeDir MkOwnerDir(backup's home dir) failed errno:%{public}d", errno);
        });
    }
}

static void CreateShareDir(const std::string &bundleName, const int32_t userid, const int32_t uid, const int32_t gid)
{
    std::string bundleShareDir = SHARE_FILE_PATH + bundleName;
    bundleShareDir = bundleShareDir.replace(bundleShareDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::MkOwnerDir(bundleShareDir, S_IRWXU | S_IRWXG | S_ISGID, uid, gid)) {
        static std::once_flag logOnce;
        std::call_once(logOnce, []() {
            APP_LOGW("CreateShareDir MkOwnerDir(share's home dir) failed errno:%{public}d", errno);
        });
    }
}

static void CreateCloudDir(const std::string &bundleName, const int32_t userid, const int32_t uid, const int32_t gid)
{
    std::string bundleCloudDir = CLOUD_FILE_PATH + bundleName;
    bundleCloudDir = bundleCloudDir.replace(bundleCloudDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::MkOwnerDir(bundleCloudDir, S_IRWXU | S_IRWXG | S_ISGID, uid, gid)) {
        static std::once_flag logOnce;
        std::call_once(logOnce, []() {
            APP_LOGW("CreateCloudDir MkOwnerDir(cloud's home dir) failed errno:%{public}d", errno);
        });
    }
}
ErrCode InstalldHostImpl::CreateBundleDataDirWithVector(const std::vector<CreateDirParam> &createDirParams)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode res = ERR_OK;
    for (const auto &item : createDirParams) {
        auto result = CreateBundleDataDir(item);
        if (result != ERR_OK) {
            APP_LOGE("CreateBundleDataDir failed in %{public}s, errCode is %{public}d",
                item.bundleName.c_str(), result);
            res = result;
        }
    }
    return res;
}

ErrCode InstalldHostImpl::ChmodBundleDataDir(const CreateDirParam &createDirParam)
{
    APP_LOGI("start bundleName:%{public}s", createDirParam.bundleName.c_str());
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        // data/app/el<>/<userId>/database/<bundleName>
        std::string databaseDir = GetBundleDataDir(el, createDirParam.userId) + Constants::DATABASE
            + createDirParam.bundleName;
        InstalldOperator::ChangeDirProperties(databaseDir, createDirParam.uid, Constants::DATABASE_DIR_GID);
        InstalldOperator::ChangeDirPropertiesRecursively(databaseDir, createDirParam.uid, Constants::DATABASE_DIR_GID);
    }
    std::string userId = std::to_string(createDirParam.userId);

    // /data/service/el2/%/hmdfs/account/data/
    std::string distributedfile = DISTRIBUTED_FILE + createDirParam.bundleName;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, userId);
    InstalldOperator::ChangeDirProperties(distributedfile, createDirParam.uid, Constants::DFS_GID);
    InstalldOperator::ChangeDirPropertiesRecursively(distributedfile, createDirParam.uid, Constants::DFS_GID);
    // /data/service/el2/%/hmdfs/non_account/data/
    distributedfile = DISTRIBUTED_FILE_NON_ACCOUNT + createDirParam.bundleName;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, userId);
    InstalldOperator::ChangeDirProperties(distributedfile, createDirParam.uid, Constants::DFS_GID);
    InstalldOperator::ChangeDirPropertiesRecursively(distributedfile, createDirParam.uid, Constants::DFS_GID);

    // /data/service/el1/%/backup/bundles/
    std::string bundleBackupDir = BUNDLE_BACKUP_HOME_PATH_EL1 + createDirParam.bundleName;
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, userId);
    InstalldOperator::ChangeDirProperties(bundleBackupDir, createDirParam.uid, Constants::BACKU_HOME_GID);
    InstalldOperator::ChangeDirPropertiesRecursively(bundleBackupDir, createDirParam.uid, Constants::BACKU_HOME_GID);
    // /data/service/el2/%/backup/bundles/
    bundleBackupDir = BUNDLE_BACKUP_HOME_PATH_EL2 + createDirParam.bundleName;
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, userId);
    InstalldOperator::ChangeDirProperties(bundleBackupDir, createDirParam.uid, Constants::BACKU_HOME_GID);
    InstalldOperator::ChangeDirPropertiesRecursively(bundleBackupDir, createDirParam.uid, Constants::BACKU_HOME_GID);

    // /data/service/el2/%/share/
    std::string bundleShareDir = SHARE_FILE_PATH + createDirParam.bundleName;
    bundleShareDir = bundleShareDir.replace(bundleShareDir.find("%"), 1, userId);
    InstalldOperator::ChangeDirProperties(bundleShareDir, createDirParam.uid, createDirParam.gid);
    InstalldOperator::ChangeDirPropertiesRecursively(bundleShareDir, createDirParam.uid, createDirParam.gid);

    // /data/service/el2/%/hmdfs/cloud/data/
    std::string bundleCloudDir = CLOUD_FILE_PATH + createDirParam.bundleName;
    bundleCloudDir = bundleCloudDir.replace(bundleCloudDir.find("%"), 1, userId);
    InstalldOperator::ChangeDirProperties(bundleCloudDir, createDirParam.uid, Constants::DFS_GID);
    InstalldOperator::ChangeDirPropertiesRecursively(bundleCloudDir, createDirParam.uid, Constants::DFS_GID);
    APP_LOGI("end bundleName:%{public}s", createDirParam.bundleName.c_str());
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateBundleDataDir(const CreateDirParam &createDirParam)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (createDirParam.bundleName.empty() || createDirParam.userId < 0 ||
        createDirParam.uid < 0 || createDirParam.gid < 0) {
        APP_LOGE("Calling the function CreateBundleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (createDirParam.createDirFlag == CreateDirFlag::FIX_DIR_AND_FILES_PROPERTIES) {
        return ChmodBundleDataDir(createDirParam);
    }
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        if ((createDirParam.createDirFlag == CreateDirFlag::CREATE_DIR_UNLOCKED) &&
            (el == ServiceConstants::BUNDLE_EL[0])) {
            continue;
        }

        std::string bundleDataDir = GetBundleDataDir(el, createDirParam.userId) + Constants::BASE;
        if (access(bundleDataDir.c_str(), F_OK) != 0) {
            APP_LOGW("Base directory %{public}s does not existed, bundleName:%{public}s",
                bundleDataDir.c_str(), createDirParam.bundleName.c_str());
            return ERR_OK;
        }
        bundleDataDir += createDirParam.bundleName;
        if (!InstalldOperator::MkOwnerDir(bundleDataDir, S_IRWXU, createDirParam.uid, createDirParam.gid)) {
            APP_LOGE("CreateBundledatadir MkOwnerDir failed errno:%{public}d", errno);
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            for (const auto &dir : BUNDLE_DATA_DIR) {
                if (!InstalldOperator::MkOwnerDir(bundleDataDir + dir, S_IRWXU,
                    createDirParam.uid, createDirParam.gid)) {
                    APP_LOGE("CreateBundledatadir MkOwnerDir el2 failed errno:%{public}d", errno);
                    return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
                }
            }
            std::string logDir = GetBundleDataDir(el, createDirParam.userId) +
                Constants::LOG + createDirParam.bundleName;
            if (!InstalldOperator::MkOwnerDir(
                logDir, S_IRWXU | S_IRWXG, createDirParam.uid, Constants::LOG_DIR_GID)) {
                APP_LOGE("create log dir failed errno:%{public}d", errno);
                return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
            }
        }
        ErrCode ret = SetDirApl(bundleDataDir, createDirParam.bundleName, createDirParam.apl,
            createDirParam.isPreInstallApp, createDirParam.debug);
        if (ret != ERR_OK) {
            APP_LOGE("CreateBundleDataDir SetDirApl failed");
            return ret;
        }
        std::string databaseDir = GetBundleDataDir(el, createDirParam.userId) + Constants::DATABASE
            + createDirParam.bundleName;
        if (!InstalldOperator::MkOwnerDir(
            databaseDir, S_IRWXU | S_IRWXG | S_ISGID, createDirParam.uid, Constants::DATABASE_DIR_GID)) {
            APP_LOGE("CreateBundle databaseDir MkOwnerDir failed errno:%{public}d", errno);
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        ret = SetDirApl(databaseDir, createDirParam.bundleName, createDirParam.apl,
            createDirParam.isPreInstallApp, createDirParam.debug);
        if (ret != ERR_OK) {
            APP_LOGE("CreateBundleDataDir SetDirApl failed");
            return ret;
        }
    }
    std::string distributedfile = DISTRIBUTED_FILE;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(createDirParam.userId));
    if (!InstalldOperator::MkOwnerDir(distributedfile + createDirParam.bundleName,
        S_IRWXU | S_IRWXG | S_ISGID, createDirParam.uid, Constants::DFS_GID)) {
        APP_LOGE("Failed to mk dir for distributedfile errno:%{public}d", errno);
    }

    distributedfile = DISTRIBUTED_FILE_NON_ACCOUNT;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(createDirParam.userId));
    if (!InstalldOperator::MkOwnerDir(distributedfile + createDirParam.bundleName,
        S_IRWXU | S_IRWXG | S_ISGID, createDirParam.uid, Constants::DFS_GID)) {
        APP_LOGE("Failed to mk dir for non account distributedfile errno:%{public}d", errno);
    }

    std::string bundleBackupDir;
    CreateBackupExtHomeDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, bundleBackupDir,
        DirType::DIR_EL2);
    ErrCode ret = SetDirApl(bundleBackupDir, createDirParam.bundleName, createDirParam.apl,
        createDirParam.isPreInstallApp, createDirParam.debug);
    if (ret != ERR_OK) {
        APP_LOGE("CreateBackupExtHomeDir DIR_EL2 SetDirApl failed, errno is %{public}d", ret);
    }

    CreateBackupExtHomeDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, bundleBackupDir,
        DirType::DIR_EL1);
    ret = SetDirApl(bundleBackupDir, createDirParam.bundleName, createDirParam.apl,
        createDirParam.isPreInstallApp, createDirParam.debug);
    if (ret != ERR_OK) {
        APP_LOGE("CreateBackupExtHomeDir DIR_EL1 SetDirApl failed, errno is %{public}d", ret);
    }

    CreateShareDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, createDirParam.gid);
    CreateCloudDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, Constants::DFS_GID);
    return ERR_OK;
}

static ErrCode RemoveBackupExtHomeDir(const std::string &bundleName, const int userid, DirType dirType)
{
    std::string bundleBackupDir;
    GetBackupExtDirByType(bundleBackupDir, bundleName, dirType);
    APP_LOGD("RemoveBackupExtHomeDir begin, type %{public}d, path %{public}s.", dirType, bundleBackupDir.c_str());
    if (bundleBackupDir.empty()) {
        APP_LOGW("RemoveBackupExtHomeDir backup dir empty, type  %{public}d.", dirType);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(bundleBackupDir)) {
        APP_LOGE("remove dir %{public}s failed, errno is %{public}d", bundleBackupDir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

static void CleanBackupExtHomeDir(const std::string &bundleName, const int userid, DirType dirType)
{
    std::string bundleBackupDir;
    GetBackupExtDirByType(bundleBackupDir, bundleName, dirType);
    APP_LOGD("CleanBackupExtHomeDir begin, type %{public}d, path %{public}s.", dirType, bundleBackupDir.c_str());
    if (bundleBackupDir.empty()) {
        APP_LOGW("CleanBackupExtHomeDir backup dir empty, type %{public}d.", dirType);
        return;
    }
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(bundleBackupDir)) {
        APP_LOGW("clean dir %{public}s failed, errno is %{public}d", bundleBackupDir.c_str(), errno);
    }
}

static ErrCode RemoveDistributedDir(const std::string &bundleName, const int userid)
{
    std::string distributedFile = DISTRIBUTED_FILE + bundleName;
    distributedFile = distributedFile.replace(distributedFile.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(distributedFile)) {
        APP_LOGE("remove dir %{public}s failed, errno is %{public}d", distributedFile.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    std::string fileNonAccount = DISTRIBUTED_FILE_NON_ACCOUNT + bundleName;
    fileNonAccount = fileNonAccount.replace(fileNonAccount.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(fileNonAccount)) {
        APP_LOGE("remove dir %{public}s failed, errno is %{public}d", fileNonAccount.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

static void CleanDistributedDir(const std::string &bundleName, const int userid)
{
    std::string distributedFile = DISTRIBUTED_FILE + bundleName;
    distributedFile = distributedFile.replace(distributedFile.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(distributedFile)) {
        APP_LOGW("clean dir %{public}s failed, errno is %{public}d", distributedFile.c_str(), errno);
    }
    std::string fileNonAccount = DISTRIBUTED_FILE_NON_ACCOUNT + bundleName;
    fileNonAccount = fileNonAccount.replace(fileNonAccount.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(fileNonAccount)) {
        APP_LOGW("clean dir %{public}s failed, errno is %{public}d", fileNonAccount.c_str(), errno);
    }
}

static ErrCode RemoveShareDir(const std::string &bundleName, const int userid)
{
    std::string shareFileDir = SHARE_FILE_PATH + bundleName;
    shareFileDir = shareFileDir.replace(shareFileDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(shareFileDir)) {
        APP_LOGE("remove dir %{public}s failed errno:%{public}d", shareFileDir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

static void CleanShareDir(const std::string &bundleName, const int userid)
{
    std::string shareFileDir = SHARE_FILE_PATH + bundleName;
    shareFileDir = shareFileDir.replace(shareFileDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(shareFileDir)) {
        APP_LOGW("clean dir %{public}s failed errno:%{public}d", shareFileDir.c_str(), errno);
    }
}

static ErrCode RemoveCloudDir(const std::string &bundleName, const int userid)
{
    std::string cloudFileDir = CLOUD_FILE_PATH + bundleName;
    cloudFileDir = cloudFileDir.replace(cloudFileDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(cloudFileDir)) {
        APP_LOGE("remove dir %{public}s failed errno:%{public}d", cloudFileDir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

static void CleanCloudDir(const std::string &bundleName, const int userid)
{
    std::string cloudFileDir = CLOUD_FILE_PATH + bundleName;
    cloudFileDir = cloudFileDir.replace(cloudFileDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(cloudFileDir)) {
        APP_LOGW("clean dir %{public}s failed errno:%{public}d", cloudFileDir.c_str(), errno);
    }
}

static void CleanBundleDataForEl2(const std::string &bundleName, const int userid)
{
    std::string dataDir = Constants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userid);
    std::string databaseDir = dataDir + Constants::DATABASE + bundleName;
    if (!InstalldOperator::DeleteFiles(databaseDir)) {
        APP_LOGW("clean dir %{public}s failed errno:%{public}d", databaseDir.c_str(), errno);
    }
    std::string logDir = dataDir + Constants::LOG + bundleName;
    if (!InstalldOperator::DeleteFiles(logDir)) {
        APP_LOGW("clean dir %{public}s failed errno:%{public}d", logDir.c_str(), errno);
    }
    std::string bundleDataDir = dataDir + Constants::BASE + bundleName;
    for (const auto &dir : BUNDLE_DATA_DIR) {
        std::string subDir = bundleDataDir + dir;
        if (!InstalldOperator::DeleteFiles(subDir)) {
            APP_LOGW("clean dir %{public}s failed errno:%{public}d", subDir.c_str(), errno);
        }
    }
    if (!InstalldOperator::DeleteFilesExceptDirs(bundleDataDir, BUNDLE_DATA_DIR)) {
        APP_LOGW("clean dir %{public}s failed errno:%{public}d", bundleDataDir.c_str(), errno);
    }
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
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        std::string bundleDataDir = GetBundleDataDir(el, userid) + Constants::BASE + bundleName;
        if (!InstalldOperator::DeleteDir(bundleDataDir)) {
            APP_LOGE("remove dir %{public}s failed errno:%{public}d", bundleDataDir.c_str(), errno);
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }
        std::string databaseDir = GetBundleDataDir(el, userid) + Constants::DATABASE + bundleName;
        if (!InstalldOperator::DeleteDir(databaseDir)) {
            APP_LOGE("remove dir %{public}s failed errno:%{public}d", databaseDir.c_str(), errno);
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            std::string logDir = GetBundleDataDir(el, userid) + Constants::LOG + bundleName;
            if (!InstalldOperator::DeleteDir(logDir)) {
                APP_LOGE("remove dir %{public}s failed errno:%{public}d", logDir.c_str(), errno);
                return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
            }
        }
    }
    if (RemoveShareDir(bundleName, userid) != ERR_OK) {
        APP_LOGE("failed to remove share dir");
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    if (RemoveCloudDir(bundleName, userid) != ERR_OK) {
        APP_LOGE("failed to remove cloud dir");
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    if (RemoveBackupExtHomeDir(bundleName, userid, DirType::DIR_EL2) != ERR_OK ||
        RemoveBackupExtHomeDir(bundleName, userid, DirType::DIR_EL1) != ERR_OK) {
        APP_LOGE("failed to remove backup ext home dir");
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    if (RemoveDistributedDir(bundleName, userid) != ERR_OK) {
        APP_LOGE("failed to remove distributed file dir");
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

    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        std::string moduleDataDir = GetBundleDataDir(el, userid) + Constants::BASE + ModuleDir;
        if (!InstalldOperator::DeleteDir(moduleDataDir)) {
            APP_LOGE("remove dir %{public}s failed errno:%{public}d", moduleDataDir.c_str(), errno);
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
        APP_LOGE("remove dir %{public}s failed errno:%{public}d", dir.c_str(), errno);
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
        APP_LOGE("CleanBundleDataDir delete files failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_CLEAN_DIR_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CleanBundleDataDirByName(const std::string &bundleName, const int userid)
{
    APP_LOGD("InstalldHostImpl::CleanBundleDataDirByName bundleName:%{public}s", bundleName.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty() || userid < 0) {
        APP_LOGE("Calling the function CleanBundleDataDirByName with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            CleanBundleDataForEl2(bundleName, userid);
            continue;
        }
        std::string bundleDataDir = GetBundleDataDir(el, userid) + Constants::BASE + bundleName;
        if (!InstalldOperator::DeleteFiles(bundleDataDir)) {
            APP_LOGW("clean dir %{public}s failed errno:%{public}d", bundleDataDir.c_str(), errno);
        }
        std::string databaseDir = GetBundleDataDir(el, userid) + Constants::DATABASE + bundleName;
        if (!InstalldOperator::DeleteFiles(databaseDir)) {
            APP_LOGW("clean dir %{public}s failed errno:%{public}d", databaseDir.c_str(), errno);
        }
    }
    CleanShareDir(bundleName, userid);
    CleanCloudDir(bundleName, userid);
    CleanBackupExtHomeDir(bundleName, userid, DirType::DIR_EL2);
    CleanBackupExtHomeDir(bundleName, userid, DirType::DIR_EL1);
    CleanDistributedDir(bundleName, userid);
    return ERR_OK;
}

std::string InstalldHostImpl::GetBundleDataDir(const std::string &el, const int userid) const
{
    std::string dataDir = Constants::BUNDLE_APP_DATA_BASE_DIR +
                          el +
                          ServiceConstants::PATH_SEPARATOR +
                          std::to_string(userid);
    return dataDir;
}

ErrCode InstalldHostImpl::GetBundleStats(
    const std::string &bundleName, const int32_t userId, std::vector<int64_t> &bundleStats, const int32_t uid)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    std::vector<std::string> bundlePath;
    bundlePath.push_back(Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR + bundleName); // bundle code
    bundlePath.push_back(ARK_CACHE_PATH + bundleName); // ark cache file
    // ark profile
    bundlePath.push_back(ARK_PROFILE_PATH + std::to_string(userId) + ServiceConstants::PATH_SEPARATOR + bundleName);
    int64_t fileSize = InstalldOperator::GetDiskUsageFromPath(bundlePath);
    bundlePath.clear();
    std::vector<std::string> cachePath;
    int64_t allBundleLocalSize = 0;
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        std::string filePath = Constants::BUNDLE_APP_DATA_BASE_DIR + el + ServiceConstants::PATH_SEPARATOR +
            std::to_string(userId) + Constants::BASE + bundleName;
        allBundleLocalSize += InstalldOperator::GetDiskUsage(filePath);
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            for (const auto &dataDir : BUNDLE_DATA_DIR) {
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
    int64_t bundleDataSize = InstalldOperator::GetDiskUsageFromQuota(uid);
    // index 1 : local bundle data size
    bundleStats.push_back(bundleDataSize);
    bundleStats.push_back(0);
    bundleStats.push_back(0);
    int64_t cacheSize = InstalldOperator::GetDiskUsageFromPath(cachePath);
    // index 4 : cache size
    bundleStats.push_back(cacheSize);
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetAllBundleStats(const std::vector<std::string> &bundleNames, const int32_t userId,
    std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleNames.empty() || bundleNames.size() != uids.size()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    int64_t totalFileSize = 0;
    int64_t totalDataSize = 0;
    for (size_t index = 0; index < bundleNames.size(); ++index) {
        const auto &bundleName = bundleNames[index];
        const auto &uid = uids[index];
        std::vector<std::string> bundlePath;
        bundlePath.push_back(Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR + bundleName); // bundle code
        bundlePath.push_back(ARK_CACHE_PATH + bundleName); // ark cache file
        // ark profile
        bundlePath.push_back(ARK_PROFILE_PATH + std::to_string(userId) + ServiceConstants::PATH_SEPARATOR + bundleName);
        int64_t fileSize = InstalldOperator::GetDiskUsageFromPath(bundlePath);
        // index 0 : bundle data size
        totalFileSize += fileSize;
        int64_t bundleDataSize = InstalldOperator::GetDiskUsageFromQuota(uid);
        // index 1 : local bundle data size
        totalDataSize += bundleDataSize;
    }
    bundleStats.push_back(totalFileSize);
    bundleStats.push_back(totalDataSize);
    bundleStats.push_back(0);
    bundleStats.push_back(0);
    bundleStats.push_back(0);
    return ERR_OK;
}

ErrCode InstalldHostImpl::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
    bool isPreInstallApp, bool debug)
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
    HapFileInfo hapFileInfo;
    hapFileInfo.pathNameOrig.push_back(dir);
    hapFileInfo.apl = apl;
    hapFileInfo.packageName = bundleName;
    hapFileInfo.flags = SELINUX_HAP_RESTORECON_RECURSE;
    hapFileInfo.hapFlags = isPreInstallApp ? SELINUX_HAP_RESTORECON_PREINSTALLED_APP : 0;
    hapFileInfo.hapFlags |= debug ? SELINUX_HAP_DEBUGGABLE : 0;
    HapContext hapContext;
    int ret = hapContext.HapFileRestorecon(hapFileInfo);
    if (ret != 0) {
        APP_LOGE("HapFileRestorecon path: %{public}s failed, apl: %{public}s, errcode:%{public}d",
            dir.c_str(), apl.c_str(), ret);
        return ERR_APPEXECFWK_INSTALLD_SET_SELINUX_LABEL_FAILED;
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
    if (!InstalldOperator::MoveFile(oldPath, newPath)) {
        APP_LOGE("Move file %{public}s to %{public}s failed errno:%{public}d",
            oldPath.c_str(), newPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CopyFile(const std::string &oldPath, const std::string &newPath,
    const std::string &signatureFilePath)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::CopyFileFast(oldPath, newPath)) {
        APP_LOGE("Copy file %{public}s to %{public}s failed errno:%{public}d",
            oldPath.c_str(), newPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED;
    }
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!OHOS::ChangeModeFile(newPath, mode)) {
        APP_LOGE("change mode failed");
        return ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED;
    }

    if (signatureFilePath.empty()) {
        APP_LOGD("signature file path is empty and no need to process code signature");
        return ERR_OK;
    }

#if defined(CODE_SIGNATURE_ENABLE)
    Security::CodeSign::EntryMap entryMap = {{ Constants::CODE_SIGNATURE_HAP, newPath }};
    ErrCode ret = Security::CodeSign::CodeSignUtils::EnforceCodeSignForApp(entryMap, signatureFilePath);
    if (ret != ERR_OK) {
        APP_LOGE("hap or hsp code signature failed due to %{public}d", ret);
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
#endif
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
        APP_LOGE("Mkdir %{public}s failed errno:%{public}d", dir.c_str(), errno);
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
    fileStat.mode = static_cast<int32_t>(s.st_mode);
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
        APP_LOGE("fail to ExtractDiffFiles errno:%{public}d", errno);
        return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, int32_t uid)
{
    if (oldSoPath.empty() || diffFilePath.empty() || newSoPath.empty()) {
        APP_LOGE("Calling the function ExtractDiffFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, uid)) {
        APP_LOGE("fail to ApplyDiffPatch errno:%{public}d", errno);
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

ErrCode InstalldHostImpl::IsExistFile(const std::string &path, bool &isExist)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    isExist = InstalldOperator::IsExistFile(path);
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistApFile(const std::string &path, bool &isExist)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    isExist = InstalldOperator::IsExistApFile(path);
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

ErrCode InstalldHostImpl::GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
    std::vector<std::string> &fileNames)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (filePath.empty()) {
        APP_LOGE("Calling the function ExtractDiffFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    InstalldOperator::GetNativeLibraryFileNames(filePath, cpuAbi, fileNames);
    return ERR_OK;
}

ErrCode InstalldHostImpl::VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam)
{
    APP_LOGD("start to process the code signature for so files");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    APP_LOGD("code sign param is %{public}s", codeSignatureParam.ToString().c_str());
    if (codeSignatureParam.modulePath.empty()) {
        APP_LOGE("Calling the function VerifyCodeSignature with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::VerifyCodeSignature(codeSignatureParam)) {
        APP_LOGE("verify code signature failed");
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    APP_LOGD("start to process check encryption");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (checkEncryptionParam.modulePath.empty()) {
        APP_LOGE("Calling the function CheckEncryption with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::CheckEncryption(checkEncryptionParam, isEncryption)) {
        APP_LOGE("check encryption failed");
        return ERR_APPEXECFWK_INSTALL_CHECK_ENCRYPTION_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::MoveFiles(const std::string &srcDir, const std::string &desDir)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (srcDir.empty() || desDir.empty()) {
        APP_LOGE("Calling the function MoveFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::MoveFiles(srcDir, desDir)) {
        APP_LOGE("move files failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractDriverSoFiles(const std::string &srcPath,
    const std::unordered_multimap<std::string, std::string> &dirMap)
{
    APP_LOGD("start to copy driver so files");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dirMap.empty()) {
        APP_LOGE("Calling the function ExtractDriverSoFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (!InstalldOperator::ExtractDriverSoFiles(srcPath, dirMap)) {
        APP_LOGE("copy driver so files failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractEncryptedSoFiles(const std::string &hapPath, const std::string &realSoFilesPath,
    const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid)
{
    APP_LOGD("start to obtain decoded so files");
#if defined(CODE_ENCRYPTION_ENABLE)
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (hapPath.empty() || tmpSoPath.empty()) {
        APP_LOGE("hapPath %{public}s or tmpSoPath %{public}s is empty", hapPath.c_str(), tmpSoPath.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
    }

    if (!CheckPathValid(hapPath, Constants::BUNDLE_CODE_DIR) ||
        !CheckPathValid(realSoFilesPath, Constants::BUNDLE_CODE_DIR) ||
        !CheckPathValid(tmpSoPath, Constants::HAP_COPY_PATH)) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
    }
    if (realSoFilesPath.empty()) {
        /* obtain the decoded so files from hapPath*/
        return InstalldOperator::ExtractSoFilesToTmpHapPath(hapPath, cpuAbi, tmpSoPath, uid);
    } else {
        /* obtain the decoded so files from realSoFilesPath*/
        return InstalldOperator::ExtractSoFilesToTmpSoPath(hapPath, realSoFilesPath, cpuAbi, tmpSoPath, uid);
    }
#else
    APP_LOGD("code encryption is not supported");
    return ERR_BUNDLEMANAGER_QUICK_FIX_NOT_SUPPORT_CODE_ENCRYPTION;
#endif
}

#if defined(CODE_SIGNATURE_ENABLE)
ErrCode InstalldHostImpl::PrepareEntryMap(const CodeSignatureParam &codeSignatureParam,
    Security::CodeSign::EntryMap &entryMap)
{
    APP_LOGD("PrepareEntryMap target so path is %{public}s", codeSignatureParam.targetSoPath.c_str());
    if (codeSignatureParam.modulePath.empty()) {
        APP_LOGE("real path of the installed hap is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (codeSignatureParam.targetSoPath.empty()) {
        APP_LOGW("target so path is empty");
        return ERR_OK;
    }
    std::vector<std::string> fileNames;
    if (!InstalldOperator::GetNativeLibraryFileNames(
        codeSignatureParam.modulePath, codeSignatureParam.cpuAbi, fileNames)) {
        APP_LOGE("get native library file names failed");
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
    const std::string prefix = ServiceConstants::LIBS + codeSignatureParam.cpuAbi + ServiceConstants::PATH_SEPARATOR;
    for (const auto &fileName : fileNames) {
        std::string entryName = prefix + fileName;
        std::string path = codeSignatureParam.targetSoPath;
        if (path.back() != Constants::FILE_SEPARATOR_CHAR) {
            path += Constants::FILE_SEPARATOR_CHAR;
        }
        entryMap.emplace(entryName, path + fileName);
        APP_LOGD("entryMap add soEntry %{public}s: %{public}s", entryName.c_str(), (path + fileName).c_str());
    }
    return ERR_OK;
}
#endif

ErrCode InstalldHostImpl::VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam)
{
    APP_LOGD("code sign param is %{public}s", codeSignatureParam.ToString().c_str());
#if defined(CODE_SIGNATURE_ENABLE)
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode ret = ERR_OK;
    if (codeSignatureParam.isCompileSdkOpenHarmony && !Security::CodeSign::CodeSignUtils::IsSupportOHCodeSign()) {
        APP_LOGD("code signature is not supported");
        return ret;
    }
    Security::CodeSign::EntryMap entryMap;
    if ((ret = PrepareEntryMap(codeSignatureParam, entryMap)) != ERR_OK) {
        APP_LOGE("prepare entry map failed");
        return ret;
    }
    if (codeSignatureParam.signatureFileDir.empty()) {
        std::shared_ptr<CodeSignHelper> codeSignHelper = std::make_shared<CodeSignHelper>();
        Security::CodeSign::FileType fileType = codeSignatureParam.isPreInstalledBundle ?
            FILE_ENTRY_ONLY : FILE_ALL;
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
        APP_LOGD("Verify code signature with: %{public}s", codeSignatureParam.signatureFileDir.c_str());
        ret = Security::CodeSign::CodeSignUtils::EnforceCodeSignForApp(entryMap, codeSignatureParam.signatureFileDir);
    }
    if (ret == VerifyErrCode::CS_CODE_SIGN_NOT_EXISTS) {
        APP_LOGW("no code sign file in the bundle");
        return ERR_OK;
    }
    if (ret != ERR_OK) {
        APP_LOGE("hap or hsp code signature failed due to %{public}d", ret);
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
#else
    APP_LOGW("code signature feature is not supported");
#endif
    return ERR_OK;
}

ErrCode InstalldHostImpl::DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
    const unsigned char *profileBlock)
{
    APP_LOGD("start to delivery sign profile");
#if defined(CODE_SIGNATURE_ENABLE)
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (bundleName.empty() || profileBlock == nullptr || profileBlockLength == 0) {
        APP_LOGE("Calling the function DeliverySignProfile with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    APP_LOGD("delivery profile of bundle %{public}s and profile size is %{public}d", bundleName.c_str(),
        profileBlockLength);
    Security::CodeSign::ByteBuffer byteBuffer;
    byteBuffer.CopyFrom(reinterpret_cast<const uint8_t *>(profileBlock), profileBlockLength);
    ErrCode ret = Security::CodeSign::CodeSignUtils::EnableKeyInProfile(bundleName, byteBuffer);
    if (ret != ERR_OK) {
        APP_LOGE("delivery code sign profile failed due to error %{public}d", ret);
        return ERR_BUNDLE_MANAGER_CODE_SIGNATURE_DELIVERY_FILE_FAILED;
    }
#else
    APP_LOGW("code signature feature is not supported");
#endif
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveSignProfile(const std::string &bundleName)
{
    APP_LOGD("start to remove sign profile");
#if defined(CODE_SIGNATURE_ENABLE)
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (bundleName.empty()) {
        APP_LOGE("Calling the function RemoveSignProfile with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    ErrCode ret = Security::CodeSign::CodeSignUtils::RemoveKeyInProfile(bundleName);
    if (ret != ERR_OK) {
        APP_LOGE("remove code sign profile failed due to error %{public}d", ret);
        return ERR_BUNDLE_MANAGER_CODE_SIGNATURE_REMOVE_FILE_FAILED;
    }
#else
    APP_LOGW("code signature feature is not supported");
#endif
    return ERR_OK;
}

bool InstalldHostImpl::CheckPathValid(const std::string &path, const std::string &prefix)
{
    if (path.empty()) {
        return true;
    }
    if (path.find(Constants::RELATIVE_PATH) != std::string::npos) {
        APP_LOGE("path(%{public}s) contain relevant path", path.c_str());
        return false;
    }
    if (path.find(prefix) == std::string::npos) {
        APP_LOGE("prefix(%{public}s) cannot be found", prefix.c_str());
        return false;
    }
    return true;
}

ErrCode InstalldHostImpl::SetEncryptionPolicy(int32_t uid, const std::string &bundleName,
    const int32_t userId, std::string &keyId)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty()) {
        APP_LOGE("Calling the function SetEncryptionPolicy with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::GenerateKeyIdAndSetPolicy(uid, bundleName, userId, keyId)) {
        APP_LOGE("EncryptionPaths fail");
        return ERR_APPEXECFWK_INSTALLD_GENERATE_KEY_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::DeleteEncryptionKeyId(const std::string &keyId)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        APP_LOGE("installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (keyId.empty()) {
        APP_LOGE("Calling the function DeleteEncryptionKeyId with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::DeleteKeyId(keyId)) {
        APP_LOGE("EncryptionPaths fail");
        return ERR_APPEXECFWK_INSTALLD_DELETE_KEY_FAILED;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
