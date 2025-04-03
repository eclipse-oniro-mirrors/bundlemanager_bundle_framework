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

#include "installd/installd_host_impl.h"

#include <cinttypes>
#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "aot/aot_executor.h"
#include "app_log_tag_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#if defined(CODE_SIGNATURE_ENABLE)
#include "byte_buffer.h"
#include "code_sign_utils.h"
#endif
#include "common_profile.h"
#ifdef CONFIG_POLOCY_ENABLE
#include "config_policy_utils.h"
#endif
#include "directory_ex.h"
#ifdef WITH_SELINUX
#include "hap_restorecon.h"
#include "selinux/selinux.h"
#ifndef SELINUX_HAP_DEBUGGABLE
#define SELINUX_HAP_DEBUGGABLE 2
#endif
#endif // WITH_SELINUX
#include "hitrace_meter.h"
#include "installd/installd_operator.h"
#include "installd/installd_permission_mgr.h"
#include "parameters.h"
#include "inner_bundle_clone_common.h"
#include "storage_acl.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::vector<std::string> BUNDLE_DATA_DIR = {
    "/cache",
    "/files",
    "/temp",
    "/preferences",
    "/haps"
};
constexpr const char* CLOUD_FILE_PATH = "/data/service/el2/%/hmdfs/cloud/data/";
constexpr const char* BUNDLE_BACKUP_HOME_PATH_EL2 = "/data/service/el2/%/backup/bundles/";
constexpr const char* DISTRIBUTED_FILE = "/data/service/el2/%/hmdfs/account/data/";
constexpr const char* SHARE_FILE_PATH = "/data/service/el2/%/share/";
constexpr const char* SHAREFILES_DATA_PATH_EL2 = "/data/app/el2/%/sharefiles/";
constexpr const char* BUNDLE_BACKUP_HOME_PATH_EL1 = "/data/service/el1/%/backup/bundles/";
constexpr const char* DISTRIBUTED_FILE_NON_ACCOUNT = "/data/service/el2/%/hmdfs/non_account/data/";
constexpr const char* BUNDLE_BACKUP_HOME_PATH_EL2_NEW = "/data/app/el2/%/base/";
constexpr const char* BUNDLE_BACKUP_HOME_PATH_EL1_NEW = "/data/app/el1/%/base/";
constexpr const char* BUNDLE_BACKUP_INNER_DIR = "/.backup";
constexpr const char* EXTENSION_CONFIG_DEFAULT_PATH = "/system/etc/ams_extension_config.json";
#ifdef CONFIG_POLOCY_ENABLE
constexpr const char* EXTENSION_CONFIG_FILE_PATH = "/etc/ams_extension_config.json";
#endif
constexpr const char* EXTENSION_CONFIG_NAME = "ams_extension_config";
constexpr const char* EXTENSION_TYPE_NAME = "extension_type_name";
constexpr const char* EXTENSION_SERVICE_NEED_CREATE_SANDBOX = "need_create_sandbox";
constexpr const char* SHELL_ENTRY_TXT = "g:2000:rwx";
constexpr uint64_t VECTOR_SIZE_MAX = 200;
constexpr int32_t INSTALLS_UID = 3060;
constexpr const char* LOG_PATH = "/log/";
constexpr const char* FIRST_BOOT_LOG_BACK_UP_PATH = "/log/bms/firstboot/";
enum class DirType : uint8_t {
    DIR_EL1,
    DIR_EL2,
};
#if defined(CODE_SIGNATURE_ENABLE)
using namespace OHOS::Security::CodeSign;
#endif
}

InstalldHostImpl::InstalldHostImpl()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd service created");
}

InstalldHostImpl::~InstalldHostImpl()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd service destroyed");
}

ErrCode InstalldHostImpl::CreateBundleDir(const std::string &bundleDir)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleDir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function CreateBundleDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (InstalldOperator::IsExistDir(bundleDir)) {
        LOG_W(BMS_TAG_INSTALLD, "bundleDir %{public}s is exist", bundleDir.c_str());
        OHOS::ForceRemoveDirectoryBMS(bundleDir);
    }
    if (!InstalldOperator::MkRecursiveDir(bundleDir, true)) {
        LOG_E(BMS_TAG_INSTALLD, "create bundle dir %{public}s failed, errno:%{public}d", bundleDir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    InstalldOperator::RmvDeleteDfx(bundleDir);
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    LOG_D(BMS_TAG_INSTALLD, "ExtractModuleFiles extract original src %{public}s and target src %{public}s",
        srcModulePath.c_str(), targetPath.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (srcModulePath.empty() || targetPath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function ExtractModuleFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::MkRecursiveDir(targetPath, true)) {
        LOG_E(BMS_TAG_INSTALLD, "create target dir %{public}s failed, errno:%{public}d", targetPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    if (!InstalldOperator::ExtractFiles(srcModulePath, targetSoPath, cpuAbi)) {
        LOG_E(BMS_TAG_INSTALLD, "extract %{public}s to %{public}s failed errno:%{public}d",
            srcModulePath.c_str(), targetPath.c_str(), errno);
        InstalldOperator::DeleteDir(targetPath);
        return ERR_APPEXECFWK_INSTALLD_EXTRACT_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractFiles(const ExtractParam &extractParam)
{
    LOG_D(BMS_TAG_INSTALLD, "ExtractFiles extractParam %{public}s", extractParam.ToString().c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (extractParam.srcPath.empty() || extractParam.targetPath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function ExtractFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (!InstalldOperator::ExtractFiles(extractParam)) {
        LOG_E(BMS_TAG_INSTALLD, "extract failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_EXTRACT_FAILED;
    }

    return ERR_OK;
}


ErrCode InstalldHostImpl::ExtractHnpFiles(const std::string &hnpPackageInfo, const ExtractParam &extractParam)
{
    LOG_D(BMS_TAG_INSTALLD, "ExtractHnpFiles hnpPackageInfo %{public}s", hnpPackageInfo.c_str());
    LOG_D(BMS_TAG_INSTALLD, "ExtractHnpFiles extractParam %{public}s", extractParam.ToString().c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (extractParam.srcPath.empty() || extractParam.targetPath.empty() || hnpPackageInfo.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function ExtractFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (!InstalldOperator::ExtractFiles(hnpPackageInfo, extractParam)) {
        LOG_E(BMS_TAG_INSTALLD, "extract failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_NATIVE_HNP_EXTRACT_FAILED;
    }

    return ERR_OK;
}

ErrCode InstalldHostImpl::ProcessBundleInstallNative(const std::string &userId, const std::string &hnpRootPath,
    const std::string &hapPath, const std::string &cpuAbi, const std::string &packageName)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::ProcessBundleInstallNative(userId, hnpRootPath, hapPath, cpuAbi, packageName)) {
        return ERR_APPEXECFWK_NATIVE_INSTALL_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ProcessBundleUnInstallNative(const std::string &userId, const std::string &packageName)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::ProcessBundleUnInstallNative(userId, packageName)) {
        return ERR_APPEXECFWK_NATIVE_UNINSTALL_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExecuteAOT(const AOTArgs &aotArgs, std::vector<uint8_t> &pendSignData)
{
    LOG_D(BMS_TAG_INSTALLD, "begin to execute AOT, args : %{public}s", aotArgs.ToString().c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode ret = ERR_OK;
    AOTExecutor::GetInstance().ExecuteAOT(aotArgs, ret, pendSignData);
    LOG_D(BMS_TAG_INSTALLD, "execute AOT ret : %{public}d", ret);
    return ret;
}

ErrCode InstalldHostImpl::PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData)
{
    LOG_D(BMS_TAG_INSTALLD, "begin to pend sign AOT, anFileName : %{public}s", anFileName.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode ret = AOTExecutor::GetInstance().PendSignAOT(anFileName, signData);
    LOG_D(BMS_TAG_INSTALLD, "pend sign AOT ret : %{public}d", ret);
    return ret;
}

ErrCode InstalldHostImpl::StopAOT()
{
    LOG_I(BMS_TAG_INSTALLD, "StopAOT begin");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "verify permission failed");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    return AOTExecutor::GetInstance().StopAOT();
}

ErrCode InstalldHostImpl::DeleteUninstallTmpDirs(const std::vector<std::string> &dirs)
{
    LOG_I(BMS_TAG_INSTALLD, "DeleteUninstallTmpDirs begin");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "verify permission failed");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode ret = ERR_OK;
    for (const std::string &dir : dirs) {
        if (!InstalldOperator::DeleteUninstallTmpDir(dir)) {
            ret = ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }
    }
    return ret;
}

ErrCode InstalldHostImpl::RenameModuleDir(const std::string &oldPath, const std::string &newPath)
{
    LOG_D(BMS_TAG_INSTALLD, "rename %{public}s to %{public}s", oldPath.c_str(), newPath.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (oldPath.empty() || newPath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function RenameModuleDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::RenameDir(oldPath, newPath)) {
        LOG_D(BMS_TAG_INSTALLD, "rename module dir %{public}s to %{public}s failed errno:%{public}d",
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

static void GetNewBackupExtDirByType(std::string &bundleBackupDir,
    const std::string &bundleName, const DirType dirType)
{
    switch (dirType) {
        case DirType::DIR_EL1:
            bundleBackupDir = BUNDLE_BACKUP_HOME_PATH_EL1_NEW + bundleName + BUNDLE_BACKUP_INNER_DIR;
            break;
        case DirType::DIR_EL2:
            bundleBackupDir = BUNDLE_BACKUP_HOME_PATH_EL2_NEW + bundleName + BUNDLE_BACKUP_INNER_DIR;
            break;
        default:
            break;
    }
}

static void CreateBackupExtHomeDir(const std::string &bundleName, const int32_t userid, const int32_t uid,
    std::string &bundleBackupDir, const DirType dirType)
{
    GetBackupExtDirByType(bundleBackupDir, bundleName, dirType);
    LOG_D(BMS_TAG_INSTALLD, "CreateBackupExtHomeDir begin, type %{public}d, path %{public}s",
        static_cast<int32_t>(dirType), bundleBackupDir.c_str());
    if (bundleBackupDir.empty()) {
        LOG_W(BMS_TAG_INSTALLD, "CreateBackupExtHomeDir backup dir empty, type  %{public}d",
            static_cast<int32_t>(dirType));
        return;
    }
    // Setup BackupExtensionAbility's home directory in a harmless way
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::MkOwnerDir(
        bundleBackupDir, S_IRWXU | S_IRWXG | S_ISGID, uid, ServiceConstants::BACKU_HOME_GID)) {
        static std::once_flag logOnce;
        std::call_once(logOnce, []() {
            LOG_W(BMS_TAG_INSTALLD, "CreateBackupExtHomeDir MkOwnerDir(backup's home dir) failed errno:%{public}d",
                errno);
        });
    }
}

static void CreateNewBackupExtHomeDir(const std::string &bundleName, const int32_t userid, const int32_t uid,
    std::string &bundleBackupDir, const DirType dirType)
{
    GetNewBackupExtDirByType(bundleBackupDir, bundleName, dirType);
    LOG_D(BMS_TAG_INSTALLD, "CreateNewBackupExtHomeDir begin, type %{public}d, path %{public}s",
        static_cast<int32_t>(dirType), bundleBackupDir.c_str());
    if (bundleBackupDir.empty()) {
        LOG_W(BMS_TAG_INSTALLD, "CreateNewBackupExtHomeDir backup dir empty, type  %{public}d",
            static_cast<int32_t>(dirType));
        return;
    }
    // Setup BackupExtensionAbility's home directory in a harmless way
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::MkOwnerDir(
        bundleBackupDir, S_IRWXU | S_IRWXG | S_ISGID, uid, ServiceConstants::BACKU_HOME_GID)) {
        static std::once_flag logOnce;
        std::call_once(logOnce, []() {
            LOG_W(BMS_TAG_INSTALLD, "CreateNewBackupExtHomeDir MkOwnerDir(backup's home dir) failed errno:%{public}d",
                errno);
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
            LOG_W(BMS_TAG_INSTALLD, "CreateShareDir MkOwnerDir(share's home dir) failed errno:%{public}d", errno);
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
            LOG_W(BMS_TAG_INSTALLD, "CreateCloudDir MkOwnerDir(cloud's home dir) failed errno:%{public}d", errno);
        });
    }
}

/**
 * @brief Create bundle data dir(BUNDLE_DATA_DIR) in /data/app/el2/userid/sharefiles/
 * @return ErrCode
 */
ErrCode InstalldHostImpl::CreateSharefilesDataDirEl2(const CreateDirParam &createDirParam)
{
    std::string bundleName = createDirParam.bundleName;
    LOG_D(BMS_TAG_INSTALLD, "begin for %{public}s", bundleName.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_W(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode res = ERR_OK;
    FileStat fileStat;
    int32_t uid = createDirParam.uid;
    int32_t gid = createDirParam.gid;
    std::string shareFilesDataDir = SHAREFILES_DATA_PATH_EL2;
    shareFilesDataDir.replace(shareFilesDataDir.find("%"), 1, std::to_string(createDirParam.userId));
    // check /data/app/el2/userid/sharefiles exist or not
    if (access(shareFilesDataDir.c_str(), F_OK) != 0) {
        LOG_W(BMS_TAG_INSTALLD, "No %{public}s, bundleName:%{public}s",
            shareFilesDataDir.c_str(), bundleName.c_str());
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    std::string bundleShareFilesDataDir = shareFilesDataDir + bundleName;
    if (!InstalldOperator::MkOwnerDir(bundleShareFilesDataDir, S_IRWXU, uid, gid)) {
        LOG_W(BMS_TAG_INSTALLD, "MkOwnerDir %{public}s failed: %{public}d",
            bundleShareFilesDataDir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    for (const auto &dir : BUNDLE_DATA_DIR) {
        std::string childBundleDataDir = bundleShareFilesDataDir + dir;
        if (!InstalldOperator::MkOwnerDir(childBundleDataDir, S_IRWXU, uid, gid)) {
            LOG_W(BMS_TAG_INSTALLD, "MkOwnerDir [%{public}s] failed: %{public}d",
                childBundleDataDir.c_str(), errno);
        }
    }
    unsigned int hapFlags = GetHapFlags(createDirParam.isPreInstallApp, createDirParam.debug,
        createDirParam.isDlpSandbox);
    res = SetDirApl(bundleShareFilesDataDir, bundleName, createDirParam.apl, hapFlags);
    if (res != ERR_OK) {
        LOG_W(BMS_TAG_INSTALLD, "SetDirApl failed: %{public}s, errno: %{public}d",
            bundleShareFilesDataDir.c_str(), res);
        return res;
    }
    LOG_D(BMS_TAG_INSTALLD, "succeed for %{public}s", bundleName.c_str());
    return res;
}

ErrCode InstalldHostImpl::CreateBundleDataDirWithVector(const std::vector<CreateDirParam> &createDirParams)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    LOG_I(BMS_TAG_INSTALLD, "begin");
    ErrCode res = ERR_OK;
    for (const auto &item : createDirParams) {
        ErrCode result = ERR_OK;
        if (item.dataDirEl == DataDirEl::NONE) {
            result = CreateBundleDataDir(item);
        } else {
            result = CreateBundleDataDirWithEl(item);
        }
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundleDataDir failed in %{public}s, errCode is %{public}d",
                item.bundleName.c_str(), result);
            res = result;
        }
    }
    LOG_I(BMS_TAG_INSTALLD, "end");
    return res;
}

ErrCode InstalldHostImpl::AddUserDirDeleteDfx(int32_t userId)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    std::vector<std::string> elPath(ServiceConstants::BUNDLE_EL);
    elPath.push_back(ServiceConstants::DIR_EL5);
    for (const auto &el : elPath) {
        std::string bundleDataDir = GetBundleDataDir(el, userId) + ServiceConstants::BASE;
        if (access(bundleDataDir.c_str(), F_OK) != 0) {
            LOG_W(BMS_TAG_INSTALLD, "Base directory %{public}s does not existed, userId:%{public}d",
                bundleDataDir.c_str(), userId);
            return ERR_OK;
        }
        InstalldOperator::AddDeleteDfx(bundleDataDir);
        std::string databaseParentDir = GetBundleDataDir(el, userId) + ServiceConstants::DATABASE;
        if (access(databaseParentDir.c_str(), F_OK) != 0) {
            LOG_W(BMS_TAG_INSTALLD, "DataBase directory %{public}s does not existed, userId:%{public}d",
                databaseParentDir.c_str(), userId);
            return ERR_OK;
        }
        InstalldOperator::AddDeleteDfx(databaseParentDir);
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::AclSetDir(bool debug, const std::string &dir, bool setAccess, bool setDefault)
{
    if (!debug) {
        return ERR_OK;
    }
    if (setAccess) {
        int status = StorageDaemon::AclSetAccess(dir, SHELL_ENTRY_TXT);
        LOG_I(BMS_TAG_INSTALLD, "AclSetAccess: %{public}d, %{private}s", status, dir.c_str());
    }
    if (setDefault) {
        int status = StorageDaemon::AclSetDefault(dir, SHELL_ENTRY_TXT);
        LOG_I(BMS_TAG_INSTALLD, "AclSetDefault: %{public}d, %{private}s", status, dir.c_str());
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::AclSetExtensionDirs(bool debug, const std::string &parentDir,
    const std::vector<std::string> &extensionDirs, bool setAccess, bool setDefault)
{
    if (!debug) {
        return ERR_OK;
    }
    if (extensionDirs.empty()) {
        return ERR_OK;
    }
    for (const auto &extension : extensionDirs) {
        std::string extensionDir = parentDir + extension;
        AclSetDir(debug, extensionDir, setAccess, setDefault);
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateBundleDataDir(const CreateDirParam &createDirParam)
{
    const std::string bundleName = createDirParam.bundleName;
    const int32_t userId = createDirParam.userId;
    LOG_I(BMS_TAG_INSTALLD, "CreateBundleDataDir %{public}s begin, %{public}d",
        bundleName.c_str(), userId);
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (createDirParam.bundleName.empty() || createDirParam.userId < 0 ||
        createDirParam.uid < 0 || createDirParam.gid < 0) {
        LOG_E(BMS_TAG_INSTALLD, "CreateBundleDataDir invalid param, bundleName %{public}s "
            "userId %{public}d uid %{public}d gid %{public}d", createDirParam.bundleName.c_str(),
            createDirParam.userId, createDirParam.uid, createDirParam.gid);
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    unsigned int hapFlags = GetHapFlags(createDirParam.isPreInstallApp, createDirParam.debug,
        createDirParam.isDlpSandbox);
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        if ((createDirParam.createDirFlag == CreateDirFlag::CREATE_DIR_UNLOCKED) &&
            (el == ServiceConstants::BUNDLE_EL[0])) {
            continue;
        }
        std::string bundleDataDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::BASE;
        if (access(bundleDataDir.c_str(), F_OK) != 0) {
            LOG_W(BMS_TAG_INSTALLD, "Base directory %{public}s does not existed, bundleName:%{public}s",
                bundleDataDir.c_str(), createDirParam.bundleName.c_str());
            return ERR_OK;
        }
        // create base extension dir
        int mode = createDirParam.debug ? (S_IRWXU | S_IRWXG | S_IRWXO) : S_IRWXU;
        if (CreateExtensionDir(createDirParam, bundleDataDir, mode, createDirParam.gid) != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", bundleDataDir.c_str());
        }
        AclSetExtensionDirs(createDirParam.debug, bundleDataDir, createDirParam.extensionDirs, true, true);
        bundleDataDir += createDirParam.bundleName;
        if (!InstalldOperator::MkOwnerDir(bundleDataDir, mode, createDirParam.uid, createDirParam.gid)) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundledatadir MkOwnerDir failed errno:%{public}d", errno);
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        AclSetDir(createDirParam.debug, bundleDataDir, true, true);
        InstalldOperator::RmvDeleteDfx(bundleDataDir);
        if (el == ServiceConstants::BUNDLE_EL[0]) {
            std::string el1ShaderCachePath = std::string(ServiceConstants::NEW_SHADER_CACHE_PATH);
            el1ShaderCachePath = el1ShaderCachePath.replace(el1ShaderCachePath.find("%"), 1,
                std::to_string(createDirParam.userId));
            if (access(el1ShaderCachePath.c_str(), F_OK) == 0) {
                el1ShaderCachePath = el1ShaderCachePath + createDirParam.bundleName;
                if (!InstalldOperator::MkOwnerDir(el1ShaderCachePath, ServiceConstants::NEW_SHADRE_CACHE_MODE,
                    createDirParam.uid, ServiceConstants::NEW_SHADRE_CACHE_GID)) {
                        LOG_W(BMS_TAG_INSTALLER, "fail to Mkdir el1ShaderCachePath, errno: %{public}d", errno);
                }
            }
        }
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            for (const auto &dir : BUNDLE_DATA_DIR) {
                if (!InstalldOperator::MkOwnerDir(bundleDataDir + dir, mode,
                    createDirParam.uid, createDirParam.gid)) {
                    LOG_E(BMS_TAG_INSTALLD, "CreateBundledatadir MkOwnerDir el2 failed errno:%{public}d",
                        errno);
                    return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
                }
            }
            std::string logParentDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::LOG;
            std::string logDir = logParentDir + createDirParam.bundleName;
            if (!InstalldOperator::MkOwnerDir(
                logDir, S_IRWXU | S_IRWXG, createDirParam.uid, ServiceConstants::LOG_DIR_GID)) {
                LOG_E(BMS_TAG_INSTALLD, "create log dir failed errno:%{public}d", errno);
                return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
            }
            // create log extension dir
            if (CreateExtensionDir(createDirParam, logParentDir, S_IRWXU | S_IRWXG,
                ServiceConstants::LOG_DIR_GID, true) != ERR_OK) {
                LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", logParentDir.c_str());
            }
            CreateSharefilesDataDirEl2(createDirParam);
        }
        ErrCode ret = SetDirApl(bundleDataDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundleDataDir SetDirApl failed");
            return ret;
        }

        std::string databaseParentDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::DATABASE;
        std::string databaseDir = databaseParentDir + createDirParam.bundleName;
        mode = createDirParam.debug ? (S_IRWXU | S_IRWXG | S_ISGID | S_IROTH | S_IXOTH) : (S_IRWXU | S_IRWXG | S_ISGID);
        if (!InstalldOperator::MkOwnerDir(
            databaseDir, mode, createDirParam.uid, ServiceConstants::DATABASE_DIR_GID)) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundle databaseDir MkOwnerDir failed errno:%{public}d", errno);
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        AclSetDir(createDirParam.debug, databaseDir, false, true);
        InstalldOperator::RmvDeleteDfx(databaseDir);
        ret = SetDirApl(databaseDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundleDataDir SetDirApl failed");
            return ret;
        }
        // create database extension dir
        if (CreateExtensionDir(createDirParam, databaseParentDir, mode,
            ServiceConstants::DATABASE_DIR_GID) != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", databaseParentDir.c_str());
        }
        AclSetExtensionDirs(createDirParam.debug, databaseParentDir, createDirParam.extensionDirs, false, true);
    }
    std::string distributedfile = DISTRIBUTED_FILE;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(createDirParam.userId));
    if (!InstalldOperator::MkOwnerDir(distributedfile + createDirParam.bundleName,
        S_IRWXU | S_IRWXG | S_ISGID, createDirParam.uid, ServiceConstants::DFS_GID)) {
        LOG_E(BMS_TAG_INSTALLD, "Failed to mk dir for distributedfile errno:%{public}d", errno);
    }

    distributedfile = DISTRIBUTED_FILE_NON_ACCOUNT;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(createDirParam.userId));
    if (!InstalldOperator::MkOwnerDir(distributedfile + createDirParam.bundleName,
        S_IRWXU | S_IRWXG | S_ISGID, createDirParam.uid, ServiceConstants::DFS_GID)) {
        LOG_E(BMS_TAG_INSTALLD, "Failed to mk dir for non account distributedfile errno:%{public}d", errno);
    }

    std::string bundleBackupDir;
    CreateBackupExtHomeDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, bundleBackupDir,
        DirType::DIR_EL2);
    ErrCode ret = SetDirApl(bundleBackupDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CreateBackupExtHomeDir DIR_EL2 SetDirApl failed, errno is %{public}d", ret);
    }

    CreateBackupExtHomeDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, bundleBackupDir,
        DirType::DIR_EL1);
    ret = SetDirApl(bundleBackupDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CreateBackupExtHomeDir DIR_EL1 SetDirApl failed, errno is %{public}d", ret);
    }

    std::string newBundleBackupDir;
    CreateNewBackupExtHomeDir(createDirParam.bundleName,
        createDirParam.userId, createDirParam.uid, newBundleBackupDir, DirType::DIR_EL2);
    ret = SetDirApl(newBundleBackupDir, createDirParam.bundleName, createDirParam.apl,
        createDirParam.isPreInstallApp, createDirParam.debug);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CreateNewBackupExtHomeDir DIR_EL2 SetDirApl failed, errno is %{public}d", ret);
    }

    CreateNewBackupExtHomeDir(createDirParam.bundleName,
        createDirParam.userId, createDirParam.uid, newBundleBackupDir, DirType::DIR_EL1);
    ret = SetDirApl(newBundleBackupDir, createDirParam.bundleName, createDirParam.apl,
        createDirParam.isPreInstallApp, createDirParam.debug);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CreateNewBackupExtHomeDir DIR_EL1 SetDirApl failed: %{public}d", ret);
    }

    CreateShareDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, createDirParam.gid);
    CreateCloudDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, ServiceConstants::DFS_GID);
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateBundleDataDirWithEl(const CreateDirParam &createDirParam)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_I(BMS_TAG_INSTALLD, "%{public}s begin, %{public}d, el %{public}" PRIu8 "",
        createDirParam.bundleName.c_str(), createDirParam.userId, static_cast<uint8_t>(createDirParam.dataDirEl));
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (createDirParam.bundleName.empty() || createDirParam.userId < 0 ||
        createDirParam.uid < 0 || createDirParam.gid < 0) {
        LOG_E(BMS_TAG_INSTALLD, "invalid param, bundleName %{public}s userId %{public}d uid %{public}d gid %{public}d",
            createDirParam.bundleName.c_str(), createDirParam.userId, createDirParam.uid, createDirParam.gid);
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (createDirParam.dataDirEl == DataDirEl::NONE || createDirParam.dataDirEl == DataDirEl::EL1 ||
        createDirParam.dataDirEl == DataDirEl::EL5) {
        LOG_E(BMS_TAG_INSTALLD, "invalid el: %{public}d", static_cast<uint8_t>(createDirParam.dataDirEl));
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    uint32_t index = static_cast<uint32_t>(createDirParam.dataDirEl) - 1;
    if (index >= ServiceConstants::BUNDLE_EL.size()) {
        LOG_E(BMS_TAG_INSTALLD, "invalid dataDirEl %{public}d", index);
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    std::string el = ServiceConstants::BUNDLE_EL[index];
    std::string bundleDataDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::BASE;
    if (access(bundleDataDir.c_str(), F_OK) != 0) {
        LOG_W(BMS_TAG_INSTALLD, "Base directory %{public}s does not existed, bundleName:%{public}s",
            bundleDataDir.c_str(), createDirParam.bundleName.c_str());
        return ERR_OK;
    }
    ErrCode ret = ERR_OK;
    // create common dirs for all el: ${bundleName} and ${extension} under base and database
    ret = CreateCommonDataDir(createDirParam, el);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CreateCommonDataDir failed %{public}d", ret);
        return ret;
    }
    // create dirs unique to el2
    if (createDirParam.dataDirEl == DataDirEl::EL2) {
        ret = CreateEl2DataDir(createDirParam);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "CreateEl2DataDir failed %{public}d", ret);
            return ret;
        }
    }
    return ret;
}

ErrCode InstalldHostImpl::CreateCommonDataDir(const CreateDirParam &createDirParam, const std::string &el)
{
    if (createDirParam.dataDirEl == DataDirEl::NONE || createDirParam.dataDirEl == DataDirEl::EL5) {
        LOG_I(BMS_TAG_INSTALLD, "el not support: %{public}" PRIu8 "", static_cast<uint8_t>(createDirParam.dataDirEl));
        return ERR_OK;
    }
    unsigned int hapFlags = GetHapFlags(createDirParam.isPreInstallApp, createDirParam.debug,
        createDirParam.isDlpSandbox);
    std::string bundleDataDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::BASE;
    int mode = createDirParam.debug ? (S_IRWXU | S_IRWXG | S_IRWXO) : S_IRWXU;

    // create base extension dir: /data/app/${elx}/${userId}/base/${extensionDir}
    if (CreateExtensionDir(createDirParam, bundleDataDir, mode, createDirParam.gid) != ERR_OK) {
        LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", bundleDataDir.c_str());
    }
    AclSetExtensionDirs(createDirParam.debug, bundleDataDir, createDirParam.extensionDirs, true, true);

    // create base bundleName dir: /data/app/${elx}/${userId}/base/${bundleName}
    bundleDataDir += createDirParam.bundleName;
    if (!InstalldOperator::MkOwnerDir(bundleDataDir, mode, createDirParam.uid, createDirParam.gid)) {
        LOG_E(BMS_TAG_INSTALLD, "CreateBundledatadir MkOwnerDir failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    AclSetDir(createDirParam.debug, bundleDataDir, true, true);
    InstalldOperator::RmvDeleteDfx(bundleDataDir);
    ErrCode ret = SetDirApl(bundleDataDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CreateBundleDataDir SetDirApl failed");
        return ret;
    }

    // create database bundleName dir: /data/app/${elx}/${userId}/database/${bundleName}
    std::string databaseParentDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::DATABASE;
    std::string databaseDir = databaseParentDir + createDirParam.bundleName;
    mode = createDirParam.debug ? (S_IRWXU | S_IRWXG | S_ISGID | S_IROTH | S_IXOTH) : (S_IRWXU | S_IRWXG | S_ISGID);
    if (!InstalldOperator::MkOwnerDir(
        databaseDir, mode, createDirParam.uid, ServiceConstants::DATABASE_DIR_GID)) {
        LOG_E(BMS_TAG_INSTALLD, "CreateBundle databaseDir MkOwnerDir failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    AclSetDir(createDirParam.debug, databaseDir, false, true);
    InstalldOperator::RmvDeleteDfx(databaseDir);
    ret = SetDirApl(databaseDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CreateBundleDataDir SetDirApl failed");
        return ret;
    }

    // create database extension dir: /data/app/${elx}/${userId}/database/${extensionDir}
    if (CreateExtensionDir(createDirParam, databaseParentDir, mode,
        ServiceConstants::DATABASE_DIR_GID) != ERR_OK) {
        LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", databaseParentDir.c_str());
    }
    AclSetExtensionDirs(createDirParam.debug, databaseParentDir, createDirParam.extensionDirs, false, true);
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateEl2DataDir(const CreateDirParam &createDirParam)
{
    std::string el = ServiceConstants::DIR_EL2;
    std::string bundleDataDir = GetBundleDataDir(el, createDirParam.userId) +
        ServiceConstants::BASE + createDirParam.bundleName;
    int mode = createDirParam.debug ? (S_IRWXU | S_IRWXG | S_IRWXO) : S_IRWXU;

    // create el2 sub dir: /data/app/el2/${userId}/base/${bundleName}/cache|files|temp|preferences|haps
    for (const auto &dir : BUNDLE_DATA_DIR) {
        if (!InstalldOperator::MkOwnerDir(bundleDataDir + dir, mode,
            createDirParam.uid, createDirParam.gid)) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundledatadir MkOwnerDir el2 failed errno:%{public}d", errno);
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
    }

    // create log dir: /data/app/el2/${userId}/log/${bundleName}
    std::string logParentDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::LOG;
    std::string logDir = logParentDir + createDirParam.bundleName;
    if (!InstalldOperator::MkOwnerDir(
        logDir, S_IRWXU | S_IRWXG, createDirParam.uid, ServiceConstants::LOG_DIR_GID)) {
        LOG_E(BMS_TAG_INSTALLD, "create log dir failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }

    // create log extension dir: /data/app/el2/${userId}/log/${extensionDir}
    if (CreateExtensionDir(createDirParam, logParentDir, S_IRWXU | S_IRWXG,
        ServiceConstants::LOG_DIR_GID, true) != ERR_OK) {
        LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", logParentDir.c_str());
    }

    // create sharefiles dir: /data/app/el2/${userId}/sharefiles/${bundleName}
    CreateSharefilesDataDirEl2(createDirParam);

    // /data/service/el2/${userId}/hmdfs/account/data/${bundleName}
    std::string distributedfile = DISTRIBUTED_FILE;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(createDirParam.userId));
    if (!InstalldOperator::MkOwnerDir(distributedfile + createDirParam.bundleName,
        S_IRWXU | S_IRWXG | S_ISGID, createDirParam.uid, ServiceConstants::DFS_GID)) {
        LOG_E(BMS_TAG_INSTALLD, "Failed to mk dir for distributedfile errno:%{public}d", errno);
    }

    // /data/service/el2/${userId}/hmdfs/non_account/data/${bundleName}
    distributedfile = DISTRIBUTED_FILE_NON_ACCOUNT;
    distributedfile = distributedfile.replace(distributedfile.find("%"), 1, std::to_string(createDirParam.userId));
    if (!InstalldOperator::MkOwnerDir(distributedfile + createDirParam.bundleName,
        S_IRWXU | S_IRWXG | S_ISGID, createDirParam.uid, ServiceConstants::DFS_GID)) {
        LOG_E(BMS_TAG_INSTALLD, "Failed to mk dir for non account distributedfile errno:%{public}d", errno);
    }

    // /data/service/el2/${userId}/backup/bundles/${bundleName}
    std::string bundleBackupDir;
    CreateBackupExtHomeDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, bundleBackupDir,
        DirType::DIR_EL2);
    unsigned int hapFlags = GetHapFlags(createDirParam.isPreInstallApp, createDirParam.debug,
        createDirParam.isDlpSandbox);
    ErrCode ret = SetDirApl(bundleBackupDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CreateBackupExtHomeDir DIR_EL2 SetDirApl failed, errno is %{public}d", ret);
    }

    // /data/app/el2/${userId}/base/${bundleName}/.backup
    std::string newBundleBackupDir;
    CreateNewBackupExtHomeDir(createDirParam.bundleName,
        createDirParam.userId, createDirParam.uid, newBundleBackupDir, DirType::DIR_EL2);
    ret = SetDirApl(newBundleBackupDir, createDirParam.bundleName, createDirParam.apl,
        createDirParam.isPreInstallApp, createDirParam.debug);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CreateNewBackupExtHomeDir DIR_EL2 SetDirApl failed, errno is %{public}d", ret);
    }

    // /data/service/el2/${userId}/share/${bundleName}
    CreateShareDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, createDirParam.gid);

    // /data/service/el2/${userId}/hmdfs/cloud/data/${bundleName}
    CreateCloudDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, ServiceConstants::DFS_GID);
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateExtensionDir(const CreateDirParam &createDirParam, const std::string& parentDir,
    int32_t mode, int32_t gid, bool isLog)
{
    if (createDirParam.extensionDirs.empty()) {
        return ERR_OK;
    }
    unsigned int hapFlags = GetHapFlags(createDirParam.isPreInstallApp, createDirParam.debug,
        createDirParam.isDlpSandbox);
    LOG_I(BMS_TAG_INSTALLD, "CreateExtensionDir parent dir %{public}s for bundle %{public}s",
        parentDir.c_str(), createDirParam.bundleName.c_str());
    for (const auto &item : createDirParam.extensionDirs) {
        std::string extensionDir = parentDir + item;
        LOG_I(BMS_TAG_INSTALLD, "begin to create extension dir %{public}s", extensionDir.c_str());
        if (!InstalldOperator::MkOwnerDir(
            extensionDir, mode, createDirParam.uid, gid)) {
            LOG_E(BMS_TAG_INSTALLD, "CreateExtension dir %{public}s error %{public}s",
                extensionDir.c_str(), strerror(errno));
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        InstalldOperator::RmvDeleteDfx(extensionDir);
        if (isLog) {
            continue;
        }
        auto ret = SetDirApl(extensionDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "dir %{public}s SetDirApl failed", extensionDir.c_str());
            return ret;
        }
    }
    return ERR_OK;
}

static ErrCode RemoveBackupExtHomeDir(const std::string &bundleName, const int userid, DirType dirType)
{
    std::string bundleBackupDir;
    GetBackupExtDirByType(bundleBackupDir, bundleName, dirType);
    LOG_D(BMS_TAG_INSTALLD, "RemoveBackupExtHomeDir begin, type %{public}d, path %{public}s",
        static_cast<int32_t>(dirType), bundleBackupDir.c_str());
    if (bundleBackupDir.empty()) {
        LOG_W(BMS_TAG_INSTALLD, "RemoveBackupExtHomeDir backup dir empty, type  %{public}d",
            static_cast<int32_t>(dirType));
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(bundleBackupDir)) {
        LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed, errno is %{public}d", bundleBackupDir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

static ErrCode RemoveNewBackupExtHomeDir(const std::string &bundleName, const int userid, DirType dirType)
{
    std::string bundleBackupDir;
    GetNewBackupExtDirByType(bundleBackupDir, bundleName, dirType);
    LOG_D(BMS_TAG_INSTALLD, "RemoveNewBackupExtHomeDir begin, type %{public}d, path %{public}s",
        static_cast<int32_t>(dirType), bundleBackupDir.c_str());
    if (bundleBackupDir.empty()) {
        LOG_W(BMS_TAG_INSTALLD, "RemoveNewBackupExtHomeDir backup dir empty, type  %{public}d",
            static_cast<int32_t>(dirType));
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(bundleBackupDir)) {
        LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed, errno is %{public}d", bundleBackupDir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

static void CleanBackupExtHomeDir(const std::string &bundleName, const int userid, DirType dirType)
{
    std::string bundleBackupDir;
    GetBackupExtDirByType(bundleBackupDir, bundleName, dirType);
    LOG_D(BMS_TAG_INSTALLD, "CleanBackupExtHomeDir begin, type %{public}d, path %{public}s",
        static_cast<int32_t>(dirType), bundleBackupDir.c_str());
    if (bundleBackupDir.empty()) {
        LOG_W(BMS_TAG_INSTALLD, "CleanBackupExtHomeDir backup dir empty, type %{public}d",
            static_cast<int32_t>(dirType));
        return;
    }
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(bundleBackupDir)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed, errno is %{public}d", bundleBackupDir.c_str(), errno);
    }
}

static void CleanNewBackupExtHomeDir(const std::string &bundleName, const int userid, DirType dirType)
{
    std::string bundleBackupDir;
    GetNewBackupExtDirByType(bundleBackupDir, bundleName, dirType);
    LOG_D(BMS_TAG_INSTALLD, "CleanNewBackupExtHomeDir begin, type %{public}d, path %{public}s",
        static_cast<int32_t>(dirType), bundleBackupDir.c_str());
    if (bundleBackupDir.empty()) {
        LOG_W(BMS_TAG_INSTALLD, "CleanNewBackupExtHomeDir backup dir empty, type %{public}d",
            static_cast<int32_t>(dirType));
        return;
    }
    bundleBackupDir = bundleBackupDir.replace(bundleBackupDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(bundleBackupDir)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed, errno is %{public}d", bundleBackupDir.c_str(), errno);
    }
}

static ErrCode RemoveDistributedDir(const std::string &bundleName, const int userid)
{
    std::string distributedFile = DISTRIBUTED_FILE + bundleName;
    distributedFile = distributedFile.replace(distributedFile.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(distributedFile)) {
        LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed, errno is %{public}d", distributedFile.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    std::string fileNonAccount = DISTRIBUTED_FILE_NON_ACCOUNT + bundleName;
    fileNonAccount = fileNonAccount.replace(fileNonAccount.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(fileNonAccount)) {
        LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed, errno is %{public}d", fileNonAccount.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

static void CleanDistributedDir(const std::string &bundleName, const int userid)
{
    std::string distributedFile = DISTRIBUTED_FILE + bundleName;
    distributedFile = distributedFile.replace(distributedFile.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(distributedFile)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed, errno is %{public}d", distributedFile.c_str(), errno);
    }
    std::string fileNonAccount = DISTRIBUTED_FILE_NON_ACCOUNT + bundleName;
    fileNonAccount = fileNonAccount.replace(fileNonAccount.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(fileNonAccount)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed, errno is %{public}d", fileNonAccount.c_str(), errno);
    }
}

static ErrCode RemoveShareDir(const std::string &bundleName, const int userid)
{
    std::string shareFileDir = SHARE_FILE_PATH + bundleName;
    shareFileDir = shareFileDir.replace(shareFileDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(shareFileDir)) {
        LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", shareFileDir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

static void CleanShareDir(const std::string &bundleName, const int userid)
{
    std::string shareFileDir = SHARE_FILE_PATH + bundleName;
    shareFileDir = shareFileDir.replace(shareFileDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(shareFileDir)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed errno:%{public}d", shareFileDir.c_str(), errno);
    }
}

static ErrCode RemoveCloudDir(const std::string &bundleName, const int userid)
{
    std::string cloudFileDir = CLOUD_FILE_PATH + bundleName;
    cloudFileDir = cloudFileDir.replace(cloudFileDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteDir(cloudFileDir)) {
        LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", cloudFileDir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

static void CleanCloudDir(const std::string &bundleName, const int userid)
{
    std::string cloudFileDir = CLOUD_FILE_PATH + bundleName;
    cloudFileDir = cloudFileDir.replace(cloudFileDir.find("%"), 1, std::to_string(userid));
    if (!InstalldOperator::DeleteFiles(cloudFileDir)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed errno:%{public}d", cloudFileDir.c_str(), errno);
    }
}

static void CleanBundleDataSubDirs(const std::string &bundleDataDir)
{
    for (const auto &dir : BUNDLE_DATA_DIR) {
        std::string subDir = bundleDataDir + dir;
        if (!InstalldOperator::DeleteFiles(subDir)) {
            LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed: %{public}d", subDir.c_str(), errno);
        }
    }
    if (!InstalldOperator::DeleteFilesExceptDirs(bundleDataDir, BUNDLE_DATA_DIR)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed errno:%{public}d", bundleDataDir.c_str(), errno);
    }
}

static void CleanBundleDataForEl2(const std::string &bundleName, const int userid, const int appIndex)
{
    std::string suffixName = bundleName;
    if (appIndex > 0) {
        suffixName = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
    }
    std::string dataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userid);
    std::string databaseDir = dataDir + ServiceConstants::DATABASE + suffixName;
    if (!InstalldOperator::DeleteFiles(databaseDir)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed errno:%{public}d", databaseDir.c_str(), errno);
    }
    std::string logDir = dataDir + ServiceConstants::LOG + suffixName;
    if (!InstalldOperator::DeleteFiles(logDir)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed errno:%{public}d", logDir.c_str(), errno);
    }
    std::string bundleDataDir = dataDir + ServiceConstants::BASE + suffixName;
    CleanBundleDataSubDirs(bundleDataDir);

    // add data sharefiles bundle dir to be cleaned
    std::string dataShareFilesBundleDir = dataDir + ServiceConstants::SHAREFILES + suffixName;
    CleanBundleDataSubDirs(dataShareFilesBundleDir);
}

ErrCode InstalldHostImpl::RemoveBundleDataDir(const std::string &bundleName, const int32_t userId,
    bool isAtomicService, const bool async)
{
    LOG_D(BMS_TAG_INSTALLD, "InstalldHostImpl::RemoveBundleDataDir bundleName:%{public}s", bundleName.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty() || userId < 0) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function CreateBundleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (isAtomicService) {
        LOG_I(BMS_TAG_INSTALLD, "bundleName:%{public}s is atomic service, need process", bundleName.c_str());
        return InnerRemoveAtomicServiceBundleDataDir(bundleName, userId, async);
    }

    ErrCode result = InnerRemoveBundleDataDir(bundleName, userId, async);
    if (result != ERR_OK) {
        return InnerRemoveBundleDataDir(bundleName, userId, async);
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveModuleDataDir(const std::string &ModuleDir, const int userid)
{
    LOG_D(BMS_TAG_INSTALLD, "InstalldHostImpl::RemoveModuleDataDir ModuleDir:%{public}s", ModuleDir.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (ModuleDir.empty() || userid < 0) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function CreateModuleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        std::string moduleDataDir = GetBundleDataDir(el, userid) + ServiceConstants::BASE + ModuleDir;
        if (!InstalldOperator::DeleteDir(moduleDataDir)) {
            LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", moduleDataDir.c_str(), errno);
        }
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveDir(const std::string &dir)
{
    LOG_D(BMS_TAG_INSTALLD, "InstalldHostImpl::RemoveDir:%{public}s", dir.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function RemoveDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::DeleteDir(dir)) {
        LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", dir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetDiskUsage(const std::string &dir, int64_t &statSize, bool isRealPath)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    statSize = InstalldOperator::GetDiskUsage(dir, isRealPath);
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetDiskUsageFromPath(const std::vector<std::string> &path, int64_t &statSize)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    statSize = InstalldOperator::GetDiskUsageFromPath(path);
    return ERR_OK;
}

ErrCode InstalldHostImpl::CleanBundleDataDir(const std::string &dataDir)
{
    LOG_D(BMS_TAG_INSTALLD, "InstalldHostImpl::CleanBundleDataDir start");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dataDir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function CleanBundleDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (!InstalldOperator::DeleteFiles(dataDir)) {
        LOG_E(BMS_TAG_INSTALLD, "CleanBundleDataDir delete files failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_CLEAN_DIR_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CleanBundleDataDirByName(const std::string &bundleName, const int userid, const int appIndex)
{
    LOG_D(BMS_TAG_INSTALLD,
        "InstalldHostImpl::CleanBundleDataDirByName bundleName:%{public}s,userid:%{public}d,appIndex:%{public}d",
        bundleName.c_str(), userid, appIndex);
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty() || userid < 0 || appIndex < 0 || appIndex > Constants::INITIAL_SANDBOX_APP_INDEX) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function CleanBundleDataDirByName with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    std::string suffixName = bundleName;
    std::vector<std::string> elPath(ServiceConstants::BUNDLE_EL);
    elPath.push_back(ServiceConstants::DIR_EL5);
    for (const auto &el : elPath) {
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            CleanBundleDataForEl2(bundleName, userid, appIndex);
            continue;
        }
        if (appIndex > 0) {
            suffixName = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
        }
        std::string bundleDataDir = GetBundleDataDir(el, userid) + ServiceConstants::BASE + suffixName;
        if (!InstalldOperator::DeleteFiles(bundleDataDir)) {
            LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed errno:%{public}d", bundleDataDir.c_str(), errno);
        }
        std::string databaseDir = GetBundleDataDir(el, userid) + ServiceConstants::DATABASE + suffixName;
        if (!InstalldOperator::DeleteFiles(databaseDir)) {
            LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed errno:%{public}d", databaseDir.c_str(), errno);
        }
    }
    CleanShareDir(bundleName, userid);
    CleanCloudDir(bundleName, userid);
    CleanBackupExtHomeDir(bundleName, userid, DirType::DIR_EL2);
    CleanBackupExtHomeDir(bundleName, userid, DirType::DIR_EL1);
    CleanNewBackupExtHomeDir(bundleName, userid, DirType::DIR_EL2);
    CleanNewBackupExtHomeDir(bundleName, userid, DirType::DIR_EL1);
    CleanDistributedDir(bundleName, userid);
    return ERR_OK;
}

std::string InstalldHostImpl::GetBundleDataDir(const std::string &el, const int userid) const
{
    std::string dataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR +
                          el +
                          ServiceConstants::PATH_SEPARATOR +
                          std::to_string(userid);
    return dataDir;
}

std::string InstalldHostImpl::GetAppDataPath(const std::string &bundleName, const std::string &el,
    const int32_t userId, const int32_t appIndex)
{
    if (appIndex == 0) {
        return ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + el + ServiceConstants::PATH_SEPARATOR +
            std::to_string(userId) + ServiceConstants::BASE + bundleName;
    } else {
        std::string innerDataDir = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
        return ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + el + ServiceConstants::PATH_SEPARATOR +
            std::to_string(userId) + ServiceConstants::BASE + innerDataDir;
    }
}

int64_t InstalldHostImpl::GetAppCacheSize(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex, const std::vector<std::string> &moduleNameList)
{
    std::string bundleNameDir = bundleName;
    if (appIndex > 0) {
        bundleNameDir = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
    }
    std::vector<std::string> cachePaths;
    std::vector<std::string> elPath(ServiceConstants::BUNDLE_EL);
    elPath.push_back(ServiceConstants::DIR_EL5);
    for (const auto &el : elPath) {
        cachePaths.push_back(std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + el +
            ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::BASE +
            bundleNameDir + ServiceConstants::PATH_SEPARATOR + Constants::CACHE_DIR);
        if (ServiceConstants::BUNDLE_EL[1] == el) {
            cachePaths.push_back(std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + el +
                ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES +
                bundleNameDir + ServiceConstants::PATH_SEPARATOR + Constants::CACHE_DIR);
        }
        for (const auto &moduleName : moduleNameList) {
            std::string moduleCachePath = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + el +
                ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::BASE + bundleNameDir +
                ServiceConstants::HAPS + moduleName + ServiceConstants::PATH_SEPARATOR + Constants::CACHE_DIR;
            cachePaths.push_back(moduleCachePath);

            if (ServiceConstants::BUNDLE_EL[1] == el) {
                moduleCachePath = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + el +
                    ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES +
                    bundleNameDir + ServiceConstants::HAPS + moduleName + ServiceConstants::PATH_SEPARATOR +
                    Constants::CACHE_DIR;
                cachePaths.push_back(moduleCachePath);
            }
        }
    }
    return InstalldOperator::GetDiskUsageFromPath(cachePaths);
}

ErrCode InstalldHostImpl::GetBundleStats(const std::string &bundleName, const int32_t userId,
    std::vector<int64_t> &bundleStats, const int32_t uid, const int32_t appIndex,
    const uint32_t statFlag, const std::vector<std::string> &moduleNameList)
{
    LOG_D(BMS_TAG_INSTALLD,
        "bundleName = %{public}s, userId = %{public}d, uid = %{public}d, appIndex = %{public}d",
        bundleName.c_str(), userId, uid, appIndex);
    LOG_D(BMS_TAG_INSTALLD,
        "statFlag = %{public}d", statFlag);
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    bundleStats = {0, 0, 0, 0, 0};
    std::vector<std::string> bundlePath;
    bundlePath.push_back(std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName);
    int64_t appDataSize = 0;
    int64_t bundleDataSize = 0;
    int64_t bundleCacheSize = 0;
    if ((statFlag & OHOS::AppExecFwk::Constants::NoGetBundleStatsFlag::GET_BUNDLE_WITHOUT_INSTALL_SIZE) !=
        OHOS::AppExecFwk::Constants::NoGetBundleStatsFlag::GET_BUNDLE_WITHOUT_INSTALL_SIZE) {
        appDataSize = appIndex == 0 ? InstalldOperator::GetDiskUsageFromPath(bundlePath) : 0;
    }
    if ((statFlag & OHOS::AppExecFwk::Constants::NoGetBundleStatsFlag::GET_BUNDLE_WITHOUT_DATA_SIZE) !=
        OHOS::AppExecFwk::Constants::NoGetBundleStatsFlag::GET_BUNDLE_WITHOUT_DATA_SIZE) {
        bundleDataSize = InstalldOperator::GetDiskUsageFromQuota(uid);
    }
    if ((statFlag & OHOS::AppExecFwk::Constants::GET_BUNDLE_WITHOUT_CACHE_SIZE) !=
        OHOS::AppExecFwk::Constants::NoGetBundleStatsFlag::GET_BUNDLE_WITHOUT_CACHE_SIZE) {
        bundleCacheSize = GetAppCacheSize(bundleName, userId, appIndex, moduleNameList);
    }
    // index 0 : bundle data size
    bundleStats[0] = appDataSize;
    // index 1 : local bundle data size
    bundleStats[1] = bundleDataSize;
    // index 4 : cache size
    bundleStats[4] = bundleCacheSize;
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetAllBundleStats(const int32_t userId,
    std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (uids.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    int64_t totalFileSize = InstalldOperator::GetDiskUsageFromQuota(INSTALLS_UID);
    int64_t totalDataSize = 0;
    for (size_t index = 0; index < uids.size(); ++index) {
        const auto &uid = uids[index];
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

unsigned int InstalldHostImpl::GetHapFlags(const bool isPreInstallApp, const bool debug, const bool isDlpSandbox)
{
    unsigned int hapFlags = 0;
#ifdef WITH_SELINUX
    hapFlags = isPreInstallApp ? SELINUX_HAP_RESTORECON_PREINSTALLED_APP : 0;
    hapFlags |= debug ? SELINUX_HAP_DEBUGGABLE : 0;
    hapFlags |= isDlpSandbox ? SELINUX_HAP_DLP : 0;
#endif
    return hapFlags;
}

ErrCode InstalldHostImpl::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
    bool isPreInstallApp, bool debug)
{
    unsigned int hapFlags = GetHapFlags(isPreInstallApp, debug, false);
    return SetDirApl(dir, bundleName, apl, hapFlags);
}

ErrCode InstalldHostImpl::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
    unsigned int hapFlags)
{
#ifdef WITH_SELINUX
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dir.empty() || bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function SetDirApl with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    HapFileInfo hapFileInfo;
    hapFileInfo.pathNameOrig.push_back(dir);
    hapFileInfo.apl = apl;
    hapFileInfo.packageName = bundleName;
    hapFileInfo.flags = SELINUX_HAP_RESTORECON_RECURSE;
    hapFileInfo.hapFlags = hapFlags;
    HapContext hapContext;
    int ret = hapContext.HapFileRestorecon(hapFileInfo);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLD, "HapFileRestorecon path: %{public}s failed, apl: %{public}s, errcode:%{public}d",
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
    LOG_D(BMS_TAG_INSTALLD, "InstalldHostImpl::GetBundleCachePath start");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function GetBundleCachePath with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    InstalldOperator::TraverseCacheDirectory(dir, cachePath);
    return ERR_OK;
}

ErrCode InstalldHostImpl::ScanDir(
    const std::string &dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
{
    LOG_D(BMS_TAG_INSTALLD, "InstalldHostImpl::Scan start %{public}s", dir.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function Scan with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    InstalldOperator::ScanDir(dir, scanMode, resultMode, paths);
    return ERR_OK;
}

ErrCode InstalldHostImpl::MoveFile(const std::string &oldPath, const std::string &newPath)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::MoveFile(oldPath, newPath)) {
        LOG_E(BMS_TAG_INSTALLD, "Move file %{public}s to %{public}s failed errno:%{public}d",
            oldPath.c_str(), newPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CopyFile(const std::string &oldPath, const std::string &newPath,
    const std::string &signatureFilePath)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::CopyFileFast(oldPath, newPath)) {
        LOG_E(BMS_TAG_INSTALLD, "Copy file %{private}s to %{private}s failed errno:%{public}d",
            oldPath.c_str(), newPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED;
    }
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!OHOS::ChangeModeFile(newPath, mode)) {
        LOG_E(BMS_TAG_INSTALLD, "change mode failed");
        return ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED;
    }

    if (signatureFilePath.empty()) {
        LOG_D(BMS_TAG_INSTALLD, "signature file path is empty and no need to process code signature");
        return ERR_OK;
    }

#if defined(CODE_SIGNATURE_ENABLE)
    Security::CodeSign::EntryMap entryMap = {{ ServiceConstants::CODE_SIGNATURE_HAP, newPath }};
    ErrCode ret = Security::CodeSign::CodeSignUtils::EnforceCodeSignForApp(entryMap, signatureFilePath);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "hap or hsp code signature failed due to %{public}d", ret);
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
#endif
    return ERR_OK;
}

ErrCode InstalldHostImpl::Mkdir(
    const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    LOG_D(BMS_TAG_INSTALLD, "Mkdir start %{public}s", dir.c_str());
    if (dir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function Mkdir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (!InstalldOperator::MkOwnerDir(dir, mode, uid, gid)) {
        LOG_E(BMS_TAG_INSTALLD, "Mkdir %{public}s failed errno:%{public}d", dir.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_MKDIR_FAILED;
    }
    if (dir.find(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) == 0) {
        InstalldOperator::RmvDeleteDfx(dir);
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetFileStat(const std::string &file, FileStat &fileStat)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    LOG_D(BMS_TAG_INSTALLD, "GetFileStat start %{public}s", file.c_str());
    struct stat s;
    if (stat(file.c_str(), &s) != 0) {
        LOG_E(BMS_TAG_INSTALLD, "Stat file(%{public}s) failed", file.c_str());
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
        LOG_E(BMS_TAG_INSTALLD, "Calling the function ExtractDiffFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::ExtractDiffFiles(filePath, targetPath, cpuAbi)) {
        LOG_E(BMS_TAG_INSTALLD, "fail to ExtractDiffFiles errno:%{public}d", errno);
        return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, int32_t uid)
{
    if (oldSoPath.empty() || diffFilePath.empty() || newSoPath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function ExtractDiffFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, uid)) {
        LOG_E(BMS_TAG_INSTALLD, "fail to ApplyDiffPatch errno:%{public}d", errno);
        return ERR_BUNDLEMANAGER_QUICK_FIX_APPLY_DIFF_PATCH_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistDir(const std::string &dir, bool &isExist)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    isExist = InstalldOperator::IsExistDir(dir);
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistFile(const std::string &path, bool &isExist)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    isExist = InstalldOperator::IsExistFile(path);
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistApFile(const std::string &path, bool &isExist)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    isExist = InstalldOperator::IsExistApFile(path);
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsDirEmpty(const std::string &dir, bool &isDirEmpty)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    isDirEmpty = InstalldOperator::IsDirEmpty(dir);
    return ERR_OK;
}

ErrCode InstalldHostImpl::ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &dirVec)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    InstalldOperator::ObtainQuickFixFileDir(dir, dirVec);
    return ERR_OK;
}

ErrCode InstalldHostImpl::CopyFiles(const std::string &sourceDir, const std::string &destinationDir)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    InstalldOperator::CopyFiles(sourceDir, destinationDir);
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
    std::vector<std::string> &fileNames)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (filePath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function ExtractDiffFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    InstalldOperator::GetNativeLibraryFileNames(filePath, cpuAbi, fileNames);
    return ERR_OK;
}

ErrCode InstalldHostImpl::VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam)
{
    LOG_D(BMS_TAG_INSTALLD, "start to process the code signature for so files");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    LOG_D(BMS_TAG_INSTALLD, "code sign param is %{public}s", codeSignatureParam.ToString().c_str());
    if (codeSignatureParam.modulePath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function VerifyCodeSignature with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    ErrCode ret = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "verify code signature failed: %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    LOG_D(BMS_TAG_INSTALLD, "start to process check encryption");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (checkEncryptionParam.modulePath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function CheckEncryption with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    auto ret = InstalldOperator::CheckEncryption(checkEncryptionParam, isEncryption);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "check encryption failed due to %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::MoveFiles(const std::string &srcDir, const std::string &desDir)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (srcDir.empty() || desDir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function MoveFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::MoveFiles(srcDir, desDir)) {
        LOG_E(BMS_TAG_INSTALLD, "move files failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractDriverSoFiles(const std::string &srcPath,
    const std::unordered_multimap<std::string, std::string> &dirMap)
{
    LOG_D(BMS_TAG_INSTALLD, "start to copy driver so files");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (dirMap.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function ExtractDriverSoFiles with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (!InstalldOperator::ExtractDriverSoFiles(srcPath, dirMap)) {
        LOG_E(BMS_TAG_INSTALLD, "copy driver so files failed errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractEncryptedSoFiles(const std::string &hapPath, const std::string &realSoFilesPath,
    const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid)
{
    LOG_D(BMS_TAG_INSTALLD, "start to obtain decoded so files");
#if defined(CODE_ENCRYPTION_ENABLE)
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (hapPath.empty() || tmpSoPath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "hapPath %{public}s or tmpSoPath %{public}s is empty",
            hapPath.c_str(), tmpSoPath.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
    }

    if (!CheckPathValid(hapPath, Constants::BUNDLE_CODE_DIR) ||
        !CheckPathValid(realSoFilesPath, Constants::BUNDLE_CODE_DIR) ||
        !CheckPathValid(tmpSoPath, ServiceConstants::HAP_COPY_PATH)) {
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
    LOG_D(BMS_TAG_INSTALLD, "code encryption is not supported");
    return ERR_BUNDLEMANAGER_QUICK_FIX_NOT_SUPPORT_CODE_ENCRYPTION;
#endif
}

#if defined(CODE_SIGNATURE_ENABLE)
ErrCode InstalldHostImpl::PrepareEntryMap(const CodeSignatureParam &codeSignatureParam,
    Security::CodeSign::EntryMap &entryMap)
{
    LOG_D(BMS_TAG_INSTALLD, "PrepareEntryMap target so path is %{public}s", codeSignatureParam.targetSoPath.c_str());
    if (codeSignatureParam.modulePath.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "real path of the installed hap is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (codeSignatureParam.targetSoPath.empty()) {
        LOG_W(BMS_TAG_INSTALLD, "target so path is empty");
        return ERR_OK;
    }
    std::vector<std::string> fileNames;
    if (!InstalldOperator::GetNativeLibraryFileNames(
        codeSignatureParam.modulePath, codeSignatureParam.cpuAbi, fileNames)) {
        LOG_E(BMS_TAG_INSTALLD, "get native library file names failed");
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
    const std::string prefix = ServiceConstants::LIBS + codeSignatureParam.cpuAbi + ServiceConstants::PATH_SEPARATOR;
    for (const auto &fileName : fileNames) {
        std::string entryName = prefix + fileName;
        std::string path = codeSignatureParam.targetSoPath;
        if (path.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
            path += ServiceConstants::FILE_SEPARATOR_CHAR;
        }
        entryMap.emplace(entryName, path + fileName);
        LOG_D(BMS_TAG_INSTALLD, "entryMap add soEntry %{public}s: %{public}s",
            entryName.c_str(), (path + fileName).c_str());
    }
    return ERR_OK;
}
#endif

ErrCode InstalldHostImpl::VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam)
{
    LOG_D(BMS_TAG_INSTALLD, "code sign param is %{public}s", codeSignatureParam.ToString().c_str());
#if defined(CODE_SIGNATURE_ENABLE)
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode ret = ERR_OK;
    if (codeSignatureParam.isCompileSdkOpenHarmony && !Security::CodeSign::CodeSignUtils::IsSupportOHCodeSign()) {
        LOG_D(BMS_TAG_INSTALLD, "code signature is not supported");
        return ret;
    }
    Security::CodeSign::EntryMap entryMap;
    if ((ret = PrepareEntryMap(codeSignatureParam, entryMap)) != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "prepare entry map failed");
        return ret;
    }
    uint32_t codeSignFlag = 0;
    if (!codeSignatureParam.isCompressNativeLibrary) {
        codeSignFlag |= Security::CodeSign::CodeSignInfoFlag::IS_UNCOMPRESSED_NATIVE_LIBS;
    }
    if (codeSignatureParam.signatureFileDir.empty()) {
        std::shared_ptr<CodeSignHelper> codeSignHelper = std::make_shared<CodeSignHelper>();
        Security::CodeSign::FileType fileType = codeSignatureParam.isPreInstalledBundle ?
            FILE_ENTRY_ONLY : FILE_ALL;
        if (codeSignatureParam.isEnterpriseBundle) {
            LOG_D(BMS_TAG_INSTALLD, "Verify code signature for enterprise bundle");
            ret = codeSignHelper->EnforceCodeSignForAppWithOwnerId(codeSignatureParam.appIdentifier,
                codeSignatureParam.modulePath, entryMap, fileType, codeSignFlag);
        } else if (codeSignatureParam.isInternaltestingBundle) {
            LOG_D(BMS_TAG_INSTALLD, "Verify code signature for internaltesting bundle");
            ret = codeSignHelper->EnforceCodeSignForAppWithOwnerId(codeSignatureParam.appIdentifier,
                codeSignatureParam.modulePath, entryMap, fileType, codeSignFlag);
        } else {
            LOG_D(BMS_TAG_INSTALLD, "Verify code signature for non-enterprise bundle");
            ret = codeSignHelper->EnforceCodeSignForApp(
                codeSignatureParam.modulePath, entryMap, fileType, codeSignFlag);
        }
        LOG_I(BMS_TAG_INSTALLD, "Verify code signature %{public}s", codeSignatureParam.modulePath.c_str());
    } else {
        LOG_D(BMS_TAG_INSTALLD, "Verify code signature with: %{public}s", codeSignatureParam.signatureFileDir.c_str());
        ret = Security::CodeSign::CodeSignUtils::EnforceCodeSignForApp(entryMap, codeSignatureParam.signatureFileDir);
    }
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "hap or hsp code signature failed due to %{public}d", ret);
        if (CODE_SIGNATURE_ERR_MAP.find(ret) != CODE_SIGNATURE_ERR_MAP.end()) {
            return CODE_SIGNATURE_ERR_MAP.at(ret);
        }
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
#else
    LOG_W(BMS_TAG_INSTALLD, "code signature feature is not supported");
#endif
    return ERR_OK;
}

ErrCode InstalldHostImpl::DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
    const unsigned char *profileBlock)
{
#if defined(CODE_SIGNATURE_ENABLE)
    LOG_I(BMS_TAG_INSTALLD, "start");
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (bundleName.empty() || profileBlock == nullptr || profileBlockLength == 0) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function DeliverySignProfile with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    LOG_D(BMS_TAG_INSTALLD, "delivery profile of bundle %{public}s and profile size is %{public}d", bundleName.c_str(),
        profileBlockLength);
    Security::CodeSign::ByteBuffer byteBuffer;
    byteBuffer.CopyFrom(reinterpret_cast<const uint8_t *>(profileBlock), profileBlockLength);
    ErrCode ret = Security::CodeSign::CodeSignUtils::EnableKeyInProfile(bundleName, byteBuffer);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "delivery code sign profile failed due to error %{public}d", ret);
        return ERR_BUNDLE_MANAGER_CODE_SIGNATURE_DELIVERY_FILE_FAILED;
    }
    LOG_I(BMS_TAG_INSTALLD, "end");
#else
    LOG_W(BMS_TAG_INSTALLD, "code signature feature is not supported");
#endif
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveSignProfile(const std::string &bundleName)
{
    LOG_D(BMS_TAG_INSTALLD, "start to remove sign profile");
#if defined(CODE_SIGNATURE_ENABLE)
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    if (bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function RemoveSignProfile with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    ErrCode ret = Security::CodeSign::CodeSignUtils::RemoveKeyInProfile(bundleName);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "remove code sign profile failed due to error %{public}d", ret);
        return ERR_BUNDLE_MANAGER_CODE_SIGNATURE_REMOVE_FILE_FAILED;
    }
#else
    LOG_W(BMS_TAG_INSTALLD, "code signature feature is not supported");
#endif
    return ERR_OK;
}

bool InstalldHostImpl::CheckPathValid(const std::string &path, const std::string &prefix)
{
    if (path.empty()) {
        return true;
    }
    if (path.find(ServiceConstants::RELATIVE_PATH) != std::string::npos) {
        LOG_E(BMS_TAG_INSTALLD, "path(%{public}s) contain relevant path", path.c_str());
        return false;
    }
    if (path.find(prefix) == std::string::npos) {
        LOG_E(BMS_TAG_INSTALLD, "prefix(%{public}s) cannot be found", prefix.c_str());
        return false;
    }
    return true;
}

ErrCode InstalldHostImpl::SetEncryptionPolicy(const EncryptionParam &encryptionParam, std::string &keyId)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "permission denied");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (encryptionParam.bundleName.empty() && encryptionParam.groupId.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::GenerateKeyIdAndSetPolicy(encryptionParam, keyId)) {
        LOG_E(BMS_TAG_INSTALLD, "EncryptionPaths fail");
        return ERR_APPEXECFWK_INSTALLD_GENERATE_KEY_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::DeleteEncryptionKeyId(const EncryptionParam &encryptionParam)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "permission denied");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (encryptionParam.bundleName.empty() && encryptionParam.groupId.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::DeleteKeyId(encryptionParam)) {
        LOG_E(BMS_TAG_INSTALLD, "EncryptionPaths fail");
        return ERR_APPEXECFWK_INSTALLD_DELETE_KEY_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveExtensionDir(int32_t userId, const std::vector<std::string> &extensionBundleDirs)
{
    LOG_I(BMS_TAG_INSTALLD, "RemoveExtensionDir userId: %{public}d, extensionBundleDir size: %{public}zu",
        userId, extensionBundleDirs.size());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (extensionBundleDirs.empty() || userId < 0) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function RemoveExtensionDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    for (const std::string &extensionBundleDir : extensionBundleDirs) {
        if (extensionBundleDir.empty()) {
            LOG_E(BMS_TAG_INSTALLD, "RemoveExtensionDir failed for param invalid");
            return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
        }
        auto ret = RemoveExtensionDir(userId, extensionBundleDir);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "remove dir failed: %{public}s", extensionBundleDir.c_str());
            return ret;
        }
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveExtensionDir(int32_t userId, const std::string &extensionBundleDir)
{
    LOG_I(BMS_TAG_INSTALLD, "begin RemoveExtensionDir dir %{public}s", extensionBundleDir.c_str());
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        const std::string bundleDataDir = GetBundleDataDir(el, userId);
        std::string baseDir = bundleDataDir + ServiceConstants::BASE + extensionBundleDir;
        if (!InstalldOperator::DeleteDir(baseDir)) {
            LOG_E(BMS_TAG_INSTALLD, "remove base dir %{public}s failed errno:%{public}d", baseDir.c_str(), errno);
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }

        std::string databaseDir = bundleDataDir + ServiceConstants::DATABASE + extensionBundleDir;
        if (!InstalldOperator::DeleteDir(databaseDir)) {
            LOG_E(BMS_TAG_INSTALLD, "remove database dir %{public}s failed errno:%{public}d",
                databaseDir.c_str(), errno);
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }

        if (el == ServiceConstants::BUNDLE_EL[1]) {
            std::string logDir = bundleDataDir + ServiceConstants::LOG + extensionBundleDir;
            if (!InstalldOperator::DeleteDir(logDir)) {
                LOG_E(BMS_TAG_INSTALLD, "remove log dir %{public}s failed errno:%{public}d", logDir.c_str(), errno);
                return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
            }
        }
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistExtensionDir(int32_t userId, const std::string &extensionBundleDir, bool &isExist)
{
    LOG_I(BMS_TAG_INSTALLD, "IsExistExtensionDir called, userId %{public}d dir %{public}s",
        userId, extensionBundleDir.c_str());
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        const std::string bundleDataDir = GetBundleDataDir(el, userId);
        std::string baseDir = bundleDataDir + ServiceConstants::BASE + extensionBundleDir;
        if (!InstalldOperator::IsExistDir(baseDir)) {
            LOG_I(BMS_TAG_INSTALLD, "dir %{public}s is not existed", baseDir.c_str());
            isExist = false;
            return ERR_OK;
        }

        std::string databaseDir = bundleDataDir + ServiceConstants::DATABASE + extensionBundleDir;
        if (!InstalldOperator::IsExistDir(databaseDir)) {
            LOG_I(BMS_TAG_INSTALLD, "dir %{public}s is not existed", databaseDir.c_str());
            isExist = false;
            return ERR_OK;
        }

        if (el == ServiceConstants::BUNDLE_EL[1]) {
            std::string logDir = bundleDataDir + ServiceConstants::LOG + extensionBundleDir;
            if (!InstalldOperator::IsExistDir(logDir)) {
                LOG_I(BMS_TAG_INSTALLD, "dir %{public}s is not existed", logDir.c_str());
                isExist = false;
                return ERR_OK;
            }
        }
    }
    isExist = true;
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateExtensionDataDir(const CreateDirParam &createDirParam)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (createDirParam.bundleName.empty() || createDirParam.userId < 0 ||
        createDirParam.uid < 0 || createDirParam.gid < 0 || createDirParam.extensionDirs.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function CreateExtensionDataDir with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    LOG_I(BMS_TAG_INSTALLD, "begin to create extension dir for bundle %{public}s, which has %{public}zu extension dir",
        createDirParam.bundleName.c_str(), createDirParam.extensionDirs.size());
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        if ((createDirParam.createDirFlag == CreateDirFlag::CREATE_DIR_UNLOCKED) &&
            (el == ServiceConstants::BUNDLE_EL[0])) {
            continue;
        }

        std::string bundleDataDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::BASE;
        if (access(bundleDataDir.c_str(), F_OK) != 0) {
            LOG_W(BMS_TAG_INSTALLD, "Base directory %{public}s does not existed, bundleName:%{public}s",
                bundleDataDir.c_str(), createDirParam.bundleName.c_str());
            return ERR_OK;
        }
        int mode = createDirParam.debug ? (S_IRWXU | S_IRWXG | S_IRWXO) : S_IRWXU;
        if (CreateExtensionDir(createDirParam, bundleDataDir, mode, createDirParam.gid) != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", bundleDataDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        AclSetExtensionDirs(createDirParam.debug, bundleDataDir, createDirParam.extensionDirs, true, true);
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            std::string logParentDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::LOG;
            if (CreateExtensionDir(createDirParam, logParentDir, S_IRWXU | S_IRWXG,
                ServiceConstants::LOG_DIR_GID, true) != ERR_OK) {
                LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", logParentDir.c_str());
            }
        }
        mode = createDirParam.debug ? (S_IRWXU | S_IRWXG | S_ISGID | S_IROTH | S_IXOTH) : (S_IRWXU | S_IRWXG | S_ISGID);
        std::string databaseParentDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::DATABASE;
        if (CreateExtensionDir(createDirParam, databaseParentDir, mode,
            ServiceConstants::DATABASE_DIR_GID) != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", databaseParentDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        AclSetExtensionDirs(createDirParam.debug, databaseParentDir, createDirParam.extensionDirs, false, true);
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetExtensionSandboxTypeList(std::vector<std::string> &typeList)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    nlohmann::json jsonBuf;
    std::string extensionConfigPath = GetExtensionConfigPath();
    if (!ReadFileIntoJson(extensionConfigPath, jsonBuf)) {
        LOG_I(BMS_TAG_INSTALLD, "Parse file %{public}s failed", extensionConfigPath.c_str());
        return ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL;
    }
    LoadNeedCreateSandbox(jsonBuf, typeList);
    return ERR_OK;
}

std::string InstalldHostImpl::GetExtensionConfigPath() const
{
#ifdef CONFIG_POLOCY_ENABLE
    char buf[MAX_PATH_LEN] = { 0 };
    char *configPath = GetOneCfgFile(EXTENSION_CONFIG_FILE_PATH, buf, MAX_PATH_LEN);
    if (configPath == nullptr || configPath[0] == '\0') {
        LOG_E(BMS_TAG_INSTALLD, "GetOneCfgFile failed");
        return EXTENSION_CONFIG_DEFAULT_PATH;
    }
    if (strlen(configPath) > MAX_PATH_LEN) {
        LOG_E(BMS_TAG_INSTALLD, "configPath length exceeds");
        return EXTENSION_CONFIG_DEFAULT_PATH;
    }
    return configPath;
#else
    return EXTENSION_CONFIG_DEFAULT_PATH;
#endif
}

void InstalldHostImpl::LoadNeedCreateSandbox(const nlohmann::json &object, std::vector<std::string> &typeList)
{
    if (!object.contains(EXTENSION_CONFIG_NAME) || !object.at(EXTENSION_CONFIG_NAME).is_array()) {
        LOG_E(BMS_TAG_INSTALLD, "Extension config not existed");
        return;
    }

    for (auto &item : object.at(EXTENSION_CONFIG_NAME).items()) {
        const nlohmann::json& jsonObject = item.value();
        if (!jsonObject.contains(EXTENSION_TYPE_NAME) || !jsonObject.at(EXTENSION_TYPE_NAME).is_string()) {
            continue;
        }
        std::string extensionType = jsonObject.at(EXTENSION_TYPE_NAME).get<std::string>();
        if (LoadExtensionNeedCreateSandbox(jsonObject, extensionType)) {
            typeList.emplace_back(extensionType);
        }
    }
}

bool InstalldHostImpl::LoadExtensionNeedCreateSandbox(const nlohmann::json &object, std::string extensionTypeName)
{
    if (!object.contains(EXTENSION_SERVICE_NEED_CREATE_SANDBOX) ||
        !object.at(EXTENSION_SERVICE_NEED_CREATE_SANDBOX).is_boolean()) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLD, "need create sandbox config not existed");
        return false;
    }
    return object.at(EXTENSION_SERVICE_NEED_CREATE_SANDBOX).get<bool>();
}

bool InstalldHostImpl::ReadFileIntoJson(const std::string &filePath, nlohmann::json &jsonBuf)
{
    if (filePath.length() > PATH_MAX) {
        LOG_E(BMS_TAG_INSTALLD, "path length(%{public}u) longer than max length(%{public}d)",
            static_cast<unsigned int>(filePath.length()), PATH_MAX);
        return false;
    }
    std::string realPath;
    realPath.reserve(PATH_MAX);
    realPath.resize(PATH_MAX - 1);
    if (realpath(filePath.c_str(), &(realPath[0])) == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "transform real path: %{public}s  error: %{public}d", filePath.c_str(), errno);
        return false;
    }
    if (access(filePath.c_str(), F_OK) != 0) {
        LOG_D(BMS_TAG_INSTALLD, "access file %{public}s failed, error: %{public}s", filePath.c_str(), strerror(errno));
        return false;
    }

    std::fstream in;
    char errBuf[256];
    errBuf[0] = '\0';
    in.open(filePath, std::ios_base::in);
    if (!in.is_open()) {
        strerror_r(errno, errBuf, sizeof(errBuf));
        LOG_E(BMS_TAG_INSTALLD, "the file cannot be open due to  %{public}s, errno:%{public}d", errBuf, errno);
        return false;
    }

    in.seekg(0, std::ios::end);
    int64_t size = in.tellg();
    if (size <= 0) {
        LOG_E(BMS_TAG_INSTALLD, "the file is an empty file, errno:%{public}d", errno);
        in.close();
        return false;
    }

    in.seekg(0, std::ios::beg);
    jsonBuf = nlohmann::json::parse(in, nullptr, false);
    in.close();
    if (jsonBuf.is_discarded()) {
        LOG_E(BMS_TAG_INSTALLD, "bad profile file");
        return false;
    }

    return true;
}

ErrCode InstalldHostImpl::InnerRemoveAtomicServiceBundleDataDir(
    const std::string &bundleName, const int32_t userId, const bool async)
{
    LOG_D(BMS_TAG_INSTALLD, "process atomic service bundleName:%{public}s", bundleName.c_str());
    std::vector<std::string> pathName;
    if (!InstalldOperator::GetAtomicServiceBundleDataDir(bundleName, userId, pathName)) {
        LOG_W(BMS_TAG_INSTALLD, "atomic bundle %{public}s no other path", bundleName.c_str());
    }
    pathName.emplace_back(bundleName);
    LOG_I(BMS_TAG_INSTALLD, "bundle %{public}s need delete path size:%{public}zu", bundleName.c_str(), pathName.size());
    ErrCode result = ERR_OK;
    for (const auto &name : pathName) {
        ErrCode tmpResult = InnerRemoveBundleDataDir(name, userId, async);
        if (tmpResult != ERR_OK) {
            result = tmpResult;
        }
    }
    return result;
}

ErrCode InstalldHostImpl::InnerRemoveBundleDataDir(
    const std::string &bundleName, const int32_t userId, const bool async)
{
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        std::string dataDir = GetBundleDataDir(el, userId);
        std::string bundleDataDir = dataDir + ServiceConstants::BASE + bundleName;
        if (!InstalldOperator::DeleteDirFlexible(bundleDataDir, async)) {
            LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", bundleDataDir.c_str(), errno);
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }
        std::string databaseDir = dataDir + ServiceConstants::DATABASE + bundleName;
        if (!InstalldOperator::DeleteDirFlexible(databaseDir, async)) {
            LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", databaseDir.c_str(), errno);
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            std::string logDir = dataDir + ServiceConstants::LOG + bundleName;
            if (!InstalldOperator::DeleteDir(logDir)) {
                LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", logDir.c_str(), errno);
                return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
            }

            // remove SHAREFILES_DATA_PATH_EL2
            std::string shareFilesDataDir = dataDir + ServiceConstants::SHAREFILES + bundleName;
            if (!InstalldOperator::DeleteDir(shareFilesDataDir)) {
                LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed: %{public}d", shareFilesDataDir.c_str(), errno);
                return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
            }
        }
    }
    if (RemoveShareDir(bundleName, userId) != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "failed to remove share dir");
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    if (RemoveCloudDir(bundleName, userId) != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "failed to remove cloud dir");
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    if (RemoveBackupExtHomeDir(bundleName, userId, DirType::DIR_EL2) != ERR_OK ||
        RemoveBackupExtHomeDir(bundleName, userId, DirType::DIR_EL1) != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "failed to remove backup ext home dir");
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    if (RemoveNewBackupExtHomeDir(bundleName, userId, DirType::DIR_EL2) != ERR_OK ||
        RemoveNewBackupExtHomeDir(bundleName, userId, DirType::DIR_EL1) != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "failed to remove new backup ext home dir");
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    if (RemoveDistributedDir(bundleName, userId) != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "failed to remove distributed file dir");
        return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::MigrateData(const std::vector<std::string> &sourcePaths, const std::string &destinationPath)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (sourcePaths.size() > VECTOR_SIZE_MAX) {
        LOG_E(BMS_TAG_INSTALLD, "source paths size out of range");
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_SOURCE_PATH_INVALID;
    }
    auto checkPath = [](const auto &path) { return path.find(ServiceConstants::RELATIVE_PATH) != std::string::npos; };
    if (sourcePaths.empty() || std::any_of(sourcePaths.begin(), sourcePaths.end(), checkPath)) {
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_SOURCE_PATH_INVALID;
    }
    if (destinationPath.empty() || checkPath(destinationPath)) {
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_DESTINATION_PATH_INVALID;
    }
    return InstalldOperator::MigrateData(sourcePaths, destinationPath);
}

ErrCode InstalldHostImpl::MoveHapToCodeDir(const std::string &originPath, const std::string &targetPath)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (!InstalldOperator::MoveFile(originPath, targetPath)) {
        LOG_E(BMS_TAG_INSTALLD, "move file %{public}s to %{public}s failed errno:%{public}d",
            originPath.c_str(), targetPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!OHOS::ChangeModeFile(targetPath, mode)) {
        LOG_E(BMS_TAG_INSTALLD, "change mode failed");
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }
    if (!InstalldOperator::ChangeFileAttr(targetPath, INSTALLS_UID, INSTALLS_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "ChangeAttr %{public}s failed errno:%{public}d", targetPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }

#ifdef WITH_SELINUX
    const char *context = "u:object_r:data_app_el1_file:s0";
    if (lsetfilecon(targetPath.c_str(), context) < 0) {
        LOG_E(BMS_TAG_INSTALLD, "setcon %{public}s failed errno:%{public}d", targetPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    }
#endif
    return ERR_OK;
}

std::string InstalldHostImpl::GetGroupDirPath(const std::string &el, int32_t userId, const std::string &uuid)
{
    return ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + el + ServiceConstants::PATH_SEPARATOR + std::to_string(userId)
        + ServiceConstants::DATA_GROUP_PATH + uuid;
}

ErrCode InstalldHostImpl::CreateDataGroupDirs(const std::vector<CreateDirParam> &params)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "permission denied");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode result = ERR_OK;
    for (const CreateDirParam &param : params) {
        if (CreateDataGroupDir(param) != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "create group dir %{private}s failed", param.uuid.c_str());
            result = ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
    }
    return result;
}

ErrCode InstalldHostImpl::CreateDataGroupDir(const CreateDirParam &param)
{
    if (param.uuid.empty() || param.userId < 0 ||
        param.uid < 0 || param.gid < 0) {
        LOG_E(BMS_TAG_INSTALLD, "invalid param, uuid %{private}s "
            "-u %{public}d uid %{public}d gid %{public}d", param.uuid.c_str(),
            param.userId, param.uid, param.gid);
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    // create el2~el4 group dirs
    ErrCode result = ERR_OK;
    const std::vector<std::string> elList { "el2", "el3", "el4" };
    for (const auto &el : elList) {
        std::string userDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR +
            el + ServiceConstants::PATH_SEPARATOR + std::to_string(param.userId);
        if (access(userDir.c_str(), F_OK) != 0) {
            LOG_W(BMS_TAG_INSTALLD, "user directory %{public}s does not existed", userDir.c_str());
            result = ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
            continue;
        }
        std::string groupDir = userDir + ServiceConstants::DATA_GROUP_PATH + param.uuid;
        if (!InstalldOperator::MkOwnerDir(
            groupDir, ServiceConstants::DATA_GROUP_DIR_MODE, param.uid, param.gid)) {
            LOG_E(BMS_TAG_INSTALLD, "create group dir failed error %{public}s", strerror(errno));
            result = ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
            continue;
        }
    }
    return result;
}

ErrCode InstalldHostImpl::DeleteDataGroupDirs(const std::vector<std::string> &uuidList, int32_t userId)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "permission denied");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (uuidList.empty() || userId < 0) {
        LOG_E(BMS_TAG_INSTALLD, "invalid param, uuidList size %{public}zu "
            "-u %{public}d", uuidList.size(), userId);
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    // remove el2~el4 group dirs
    ErrCode result = ERR_OK;
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        if (el == ServiceConstants::BUNDLE_EL[0]) {
            continue;
        }
        for (const std::string &uuid : uuidList) {
            std::string groupDir = GetGroupDirPath(el, userId, uuid);
            if (!InstalldOperator::DeleteDir(groupDir)) {
                LOG_E(BMS_TAG_INSTALLD, "remove dir %{private}s failed, errno is %{public}d", groupDir.c_str(), errno);
                result = ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
            }
        }
    }

    auto el5Res = DeleteEl5DataGroupDirs(uuidList, userId);
    if (el5Res != ERR_OK) {
        LOG_W(BMS_TAG_INSTALLD, "el5 group directory del failed, res %{public}d", el5Res);
        result = el5Res;
    }
    return result;
}

ErrCode InstalldHostImpl::DeleteEl5DataGroupDirs(const std::vector<std::string> &uuidList, int32_t userId)
{
    ErrCode result = ERR_OK;
    for (const std::string &uuid : uuidList) {
        std::string groupDir = GetGroupDirPath(ServiceConstants::DIR_EL5, userId, uuid);
        if (access(groupDir.c_str(), F_OK) != 0) {
            LOG_D(BMS_TAG_INSTALLD, "group directory %{private}s does not existed", groupDir.c_str());
            continue;
        }
        // delete dir
        if (!InstalldOperator::DeleteDir(groupDir)) {
            LOG_E(BMS_TAG_INSTALLD, "remove dir %{private}s failed, errno is %{public}d", groupDir.c_str(), errno);
            result = ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
            continue;
        }
        // delete key id
        EncryptionParam encryptionParam("", uuid, 0, userId, EncryptionDirType::GROUP);
        if (!InstalldOperator::DeleteKeyId(encryptionParam)) {
            LOG_E(BMS_TAG_INSTALLD, "delete keyId fail");
            result = ERR_APPEXECFWK_INSTALLD_DELETE_KEY_FAILED;
        }
    }
    return result;
}
 
ErrCode InstalldHostImpl::BackUpFirstBootLog()
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "permission denied");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    std::string realLogPath;
    if (!PathToRealPath(LOG_PATH, realLogPath)) {
        LOG_E(BMS_TAG_INSTALLER, "not real path: %{public}s", LOG_PATH);
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    if (!InstalldOperator::IsExistDir(realLogPath)) {
        APP_LOGE("No /log path");
        return ERR_APPEXECFWK_INSTALLD_LOG_PATH_NOT_EXIST;
    }
    std::vector<std::string> logFiles = InstalldOperator::GetFirstBootLogFile();
    if (logFiles.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "no log found");
        return ERR_APPEXECFWK_INSTALLD_NO_LOG_FILE_FOUND;
    }
    InstalldOperator::DeleteDir(FIRST_BOOT_LOG_BACK_UP_PATH);
    if (!InstalldOperator::MkOwnerDir(FIRST_BOOT_LOG_BACK_UP_PATH,
        S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, INSTALLS_UID, INSTALLS_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "make %{public}s failed", FIRST_BOOT_LOG_BACK_UP_PATH);
        return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
    }
    for (const auto& file : logFiles) {
        std::string realFilePath;
        if (!PathToRealPath(file, realFilePath)) {
            LOG_E(BMS_TAG_INSTALLER, "not real path: %{public}s", file.c_str());
            continue;
        }
        std::string filename = InstalldOperator::GetFileName(file);
        LOG_D(BMS_TAG_INSTALLD, "FilePath:%{public}s, filename:%{public}s", file.c_str(), filename.c_str());
        std::string desFile = std::string(FIRST_BOOT_LOG_BACK_UP_PATH) + "/" + filename;
        if (!InstalldOperator::CopyFileFast(file, desFile)) {
            LOG_E(BMS_TAG_INSTALLD, "copy file error No: %{public}d:%{public}s", errno, strerror(errno));
        }
    }

    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
