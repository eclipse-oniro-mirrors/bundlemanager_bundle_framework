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

#include <cinttypes>
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
#ifndef SELINUX_HAP_DEBUGGABLE
#define SELINUX_HAP_DEBUGGABLE 2
#endif
#endif // WITH_SELINUX
#include "installd/installd_operator.h"
#include "installd/installd_permission_mgr.h"
#include "parameters.h"
#include "inner_bundle_clone_common.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ARK_CACHE_PATH = "/data/local/ark-cache/";
constexpr const char* ARK_PROFILE_PATH = "/data/local/ark-profile/";
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
        OHOS::ForceRemoveDirectory(bundleDir);
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
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
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
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
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
ErrCode InstalldHostImpl::CreateBundleDataDirWithVector(const std::vector<CreateDirParam> &createDirParams)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    ErrCode res = ERR_OK;
    for (const auto &item : createDirParams) {
        auto result = CreateBundleDataDir(item);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundleDataDir failed in %{public}s, errCode is %{public}d",
                item.bundleName.c_str(), result);
            res = result;
        }
    }
    return res;
}

ErrCode InstalldHostImpl::AddUserDirDeleteDfx(int32_t userId)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    std::vector<std::string> elPath(ServiceConstants::BUNDLE_EL);
    elPath.push_back("el5");
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

ErrCode InstalldHostImpl::CreateBundleDataDir(const CreateDirParam &createDirParam)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (createDirParam.bundleName.empty() || createDirParam.userId < 0 ||
        createDirParam.uid < 0 || createDirParam.gid < 0) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function CreateBundleDataDir with invalid param, bundleName %{public}s "
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
        if (CreateExtensionDir(createDirParam, bundleDataDir, S_IRWXU, createDirParam.gid) != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", bundleDataDir.c_str());
        }
        bundleDataDir += createDirParam.bundleName;
        if (!InstalldOperator::MkOwnerDir(bundleDataDir, S_IRWXU, createDirParam.uid, createDirParam.gid)) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundledatadir MkOwnerDir failed errno:%{public}d", errno);
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        InstalldOperator::RmvDeleteDfx(bundleDataDir);
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            for (const auto &dir : BUNDLE_DATA_DIR) {
                if (!InstalldOperator::MkOwnerDir(bundleDataDir + dir, S_IRWXU,
                    createDirParam.uid, createDirParam.gid)) {
                    LOG_E(BMS_TAG_INSTALLD, "CreateBundledatadir MkOwnerDir el2 failed errno:%{public}d", errno);
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
        }
        ErrCode ret = SetDirApl(bundleDataDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundleDataDir SetDirApl failed");
            return ret;
        }
        std::string databaseParentDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::DATABASE;
        std::string databaseDir = databaseParentDir + createDirParam.bundleName;
        if (!InstalldOperator::MkOwnerDir(
            databaseDir, S_IRWXU | S_IRWXG | S_ISGID, createDirParam.uid, ServiceConstants::DATABASE_DIR_GID)) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundle databaseDir MkOwnerDir failed errno:%{public}d", errno);
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        InstalldOperator::RmvDeleteDfx(databaseDir);
        ret = SetDirApl(databaseDir, createDirParam.bundleName, createDirParam.apl, hapFlags);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "CreateBundleDataDir SetDirApl failed");
            return ret;
        }
        // create database extension dir
        if (CreateExtensionDir(createDirParam, databaseParentDir, S_IRWXU | S_IRWXG | S_ISGID,
            ServiceConstants::DATABASE_DIR_GID) != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", databaseParentDir.c_str());
        }
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
        LOG_E(BMS_TAG_INSTALLD, "CreateNewBackupExtHomeDir DIR_EL1 SetDirApl failed, errno is %{public}d", ret);
    }

    CreateShareDir(createDirParam.bundleName, createDirParam.userId, createDirParam.uid, createDirParam.gid);
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
    for (const auto &dir : BUNDLE_DATA_DIR) {
        std::string subDir = bundleDataDir + dir;
        if (!InstalldOperator::DeleteFiles(subDir)) {
            LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed errno:%{public}d", subDir.c_str(), errno);
        }
    }
    if (!InstalldOperator::DeleteFilesExceptDirs(bundleDataDir, BUNDLE_DATA_DIR)) {
        LOG_W(BMS_TAG_INSTALLD, "clean dir %{public}s failed errno:%{public}d", bundleDataDir.c_str(), errno);
    }
}

ErrCode InstalldHostImpl::RemoveBundleDataDir(const std::string &bundleName, const int32_t userId,
    bool isAtomicService)
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
        return InnerRemoveAtomicServiceBundleDataDir(bundleName, userId);
    }

    ErrCode result = InnerRemoveBundleDataDir(bundleName, userId);
    if (result != ERR_OK) {
        return InnerRemoveBundleDataDir(bundleName, userId);
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

int64_t InstalldHostImpl::GetDiskUsage(const std::string &dir, bool isRealPath)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    return InstalldOperator::GetDiskUsage(dir, isRealPath);
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
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
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

int64_t InstalldHostImpl::HandleAppDataSizeStats(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex, std::vector<std::string> &cachePath)
{
    std::vector<std::string> bundlePath;
    bundlePath.push_back(std::string(Constants::BUNDLE_CODE_DIR) +
        ServiceConstants::PATH_SEPARATOR + bundleName); // bundle code
    bundlePath.push_back(ARK_CACHE_PATH + bundleName); // ark cache file
    // ark profile
    bundlePath.push_back(ARK_PROFILE_PATH + std::to_string(userId) + ServiceConstants::PATH_SEPARATOR + bundleName);
    int64_t fileSize = InstalldOperator::GetDiskUsageFromPath(bundlePath);
    bundlePath.clear();
    int64_t allBundleLocalSize = 0;
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        std::string filePath = GetAppDataPath(bundleName, el, userId, appIndex);
        LOG_D(BMS_TAG_INSTALLD, "filePath = %{public}s", filePath.c_str());
        if (appIndex > 0) {
            InstalldOperator::TraverseCacheDirectory(filePath, cachePath);
            continue;
        }
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
    LOG_D(BMS_TAG_INSTALLD,
        "GetBundleStats, allBundleLocalSize = %{public}" PRId64 ", bundleLocalSize = %{public}" PRId64,
        allBundleLocalSize, bundleLocalSize);
    int64_t systemFolderSize = allBundleLocalSize - bundleLocalSize;
    if (appIndex == 0) {
        return fileSize + systemFolderSize;
    }
    return 0;
}

ErrCode InstalldHostImpl::GetBundleStats(const std::string &bundleName, const int32_t userId,
    std::vector<int64_t> &bundleStats, const int32_t uid, const int32_t appIndex)
{
    LOG_D(BMS_TAG_INSTALLD,
        "GetBundleStats, bundleName = %{public}s, userId = %{public}d, uid = %{public}d, appIndex = %{public}d",
        bundleName.c_str(), userId, uid, appIndex);
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    std::vector<std::string> cachePath;
    int64_t appDataSize = HandleAppDataSizeStats(bundleName, userId, appIndex, cachePath);
    LOG_D(BMS_TAG_INSTALLD, "cachePath.size() = %{public}zu", cachePath.size());
    // index 0 : bundle data size
    bundleStats.push_back(appDataSize);
    // index 1 : local bundle data size
    int64_t bundleDataSize = InstalldOperator::GetDiskUsageFromQuota(uid);
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
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
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
        bundlePath.push_back(std::string(Constants::BUNDLE_CODE_DIR) +
            ServiceConstants::PATH_SEPARATOR + bundleName); // bundle code
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
        LOG_E(BMS_TAG_INSTALLD, "Copy file %{public}s to %{public}s failed errno:%{public}d",
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
    if (!InstalldOperator::VerifyCodeSignature(codeSignatureParam)) {
        LOG_E(BMS_TAG_INSTALLD, "verify code signature failed");
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
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
    if (!InstalldOperator::CheckEncryption(checkEncryptionParam, isEncryption)) {
        LOG_E(BMS_TAG_INSTALLD, "check encryption failed");
        return ERR_APPEXECFWK_INSTALL_CHECK_ENCRYPTION_FAILED;
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
    if (codeSignatureParam.signatureFileDir.empty()) {
        std::shared_ptr<CodeSignHelper> codeSignHelper = std::make_shared<CodeSignHelper>();
        Security::CodeSign::FileType fileType = codeSignatureParam.isPreInstalledBundle ?
            FILE_ENTRY_ONLY : FILE_ALL;
        if (codeSignatureParam.isEnterpriseBundle) {
            LOG_D(BMS_TAG_INSTALLD, "Verify code signature for enterprise bundle");
            ret = codeSignHelper->EnforceCodeSignForAppWithOwnerId(codeSignatureParam.appIdentifier,
                codeSignatureParam.modulePath, entryMap, fileType);
        } else if (codeSignatureParam.isInternaltestingBundle) {
            LOG_D(BMS_TAG_INSTALLD, "Verify code signature for internaltesting bundle");
            ret = codeSignHelper->EnforceCodeSignForAppWithOwnerId(codeSignatureParam.appIdentifier,
                codeSignatureParam.modulePath, entryMap, fileType);
        } else {
            LOG_D(BMS_TAG_INSTALLD, "Verify code signature for non-enterprise bundle");
            ret = codeSignHelper->EnforceCodeSignForApp(codeSignatureParam.modulePath, entryMap, fileType);
        }
        LOG_I(BMS_TAG_INSTALLD, "Verify code signature %{public}s", codeSignatureParam.modulePath.c_str());
    } else {
        LOG_D(BMS_TAG_INSTALLD, "Verify code signature with: %{public}s", codeSignatureParam.signatureFileDir.c_str());
        ret = Security::CodeSign::CodeSignUtils::EnforceCodeSignForApp(entryMap, codeSignatureParam.signatureFileDir);
    }
    if (ret == VerifyErrCode::CS_CODE_SIGN_NOT_EXISTS) {
        LOG_W(BMS_TAG_INSTALLD, "no code sign file in the bundle");
        return ERR_OK;
    }
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "hap or hsp code signature failed due to %{public}d", ret);
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
    LOG_D(BMS_TAG_INSTALLD, "start to delivery sign profile");
#if defined(CODE_SIGNATURE_ENABLE)
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

ErrCode InstalldHostImpl::SetEncryptionPolicy(int32_t uid, const std::string &bundleName,
    const int32_t userId, std::string &keyId)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function SetEncryptionPolicy with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::GenerateKeyIdAndSetPolicy(uid, bundleName, userId, keyId)) {
        LOG_E(BMS_TAG_INSTALLD, "EncryptionPaths fail");
        return ERR_APPEXECFWK_INSTALLD_GENERATE_KEY_FAILED;
    }
    return ERR_OK;
}

ErrCode InstalldHostImpl::DeleteEncryptionKeyId(const std::string &bundleName, const int32_t userId)
{
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "Calling the function DeleteEncryptionKeyId with invalid param");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!InstalldOperator::DeleteKeyId(bundleName, userId)) {
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
        if (CreateExtensionDir(createDirParam, bundleDataDir, S_IRWXU, createDirParam.gid) != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", bundleDataDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            std::string logParentDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::LOG;
            if (CreateExtensionDir(createDirParam, logParentDir, S_IRWXU | S_IRWXG,
                ServiceConstants::LOG_DIR_GID, true) != ERR_OK) {
                LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", logParentDir.c_str());
            }
        }

        std::string databaseParentDir = GetBundleDataDir(el, createDirParam.userId) + ServiceConstants::DATABASE;
        if (CreateExtensionDir(createDirParam, databaseParentDir, S_IRWXU | S_IRWXG | S_ISGID,
            ServiceConstants::DATABASE_DIR_GID) != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLD, "create extension dir failed, parent dir %{public}s", databaseParentDir.c_str());
            return ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED;
        }
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
    if (configPath == nullptr || configPath[0] == '\0' || strlen(configPath) > MAX_PATH_LEN) {
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
        LOG_E(BMS_TAG_INSTALLD, "transform real path error: %{public}d", errno);
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

ErrCode InstalldHostImpl::InnerRemoveAtomicServiceBundleDataDir(const std::string &bundleName, const int32_t userId)
{
    LOG_I(BMS_TAG_INSTALLD, "process atomic service bundleName:%{public}s", bundleName.c_str());
    std::vector<std::string> pathName;
    if (!InstalldOperator::GetAtomicServiceBundleDataDir(bundleName, userId, pathName)) {
        LOG_W(BMS_TAG_INSTALLD, "atomic bundle %{public}s no other path", bundleName.c_str());
    }
    pathName.emplace_back(bundleName);
    LOG_I(BMS_TAG_INSTALLD, "bundle %{public}s need delete path size:%{public}zu", bundleName.c_str(), pathName.size());
    ErrCode result = ERR_OK;
    for (const auto &name : pathName) {
        ErrCode tmpResult = InnerRemoveBundleDataDir(name, userId);
        if (tmpResult != ERR_OK) {
            result = tmpResult;
        }
    }
    return result;
}

ErrCode InstalldHostImpl::InnerRemoveBundleDataDir(const std::string &bundleName, const int32_t userId)
{
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        std::string bundleDataDir = GetBundleDataDir(el, userId) + ServiceConstants::BASE + bundleName;
        if (!InstalldOperator::DeleteDir(bundleDataDir)) {
            LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", bundleDataDir.c_str(), errno);
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }
        std::string databaseDir = GetBundleDataDir(el, userId) + ServiceConstants::DATABASE + bundleName;
        if (!InstalldOperator::DeleteDir(databaseDir)) {
            LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", databaseDir.c_str(), errno);
            return ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED;
        }
        if (el == ServiceConstants::BUNDLE_EL[1]) {
            std::string logDir = GetBundleDataDir(el, userId) + ServiceConstants::LOG + bundleName;
            if (!InstalldOperator::DeleteDir(logDir)) {
                LOG_E(BMS_TAG_INSTALLD, "remove dir %{public}s failed errno:%{public}d", logDir.c_str(), errno);
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
}  // namespace AppExecFwk
}  // namespace OHOS
