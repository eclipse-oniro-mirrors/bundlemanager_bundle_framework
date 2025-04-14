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

#include "ipc/installd_proxy.h"

#include "app_log_tag_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int16_t WAIT_TIME = 3000;
constexpr int16_t MAX_VEC_SIZE = 1000;
constexpr int16_t MAX_STRING_SIZE = 1024;
}

InstalldProxy::InstalldProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IInstalld>(object)
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd proxy instance created");
}

InstalldProxy::~InstalldProxy()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd proxy instance destroyed");
}

ErrCode InstalldProxy::CreateBundleDir(const std::string &bundleDir)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleDir));

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::CREATE_BUNDLE_DIR, data, reply, option);
}

ErrCode InstalldProxy::ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(srcModulePath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(targetPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(targetSoPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(cpuAbi));

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::EXTRACT_MODULE_FILES, data, reply, option);
}

ErrCode InstalldProxy::ExtractFiles(const ExtractParam &extractParam)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&extractParam)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable extractParam failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::EXTRACT_FILES, data, reply, option);
}

ErrCode InstalldProxy::ExtractHnpFiles(const std::string &hnpPackageInfo, const ExtractParam &extractParam)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(hnpPackageInfo));
    if (!data.WriteParcelable(&extractParam)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable extractParam failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::EXTRACT_HNP_FILES, data, reply, option);
}

ErrCode InstalldProxy::ProcessBundleInstallNative(const std::string &userId, const std::string &hnpRootPath,
    const std::string &hapPath, const std::string &cpuAbi, const std::string &packageName)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(userId));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(hnpRootPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(hapPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(cpuAbi));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(packageName));

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::INSTALL_NATIVE, data, reply, option);
}

ErrCode InstalldProxy::ProcessBundleUnInstallNative(const std::string &userId, const std::string &packageName)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(userId));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(packageName));

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::UNINSTALL_NATIVE, data, reply, option);
}

ErrCode InstalldProxy::ExecuteAOT(const AOTArgs &aotArgs, std::vector<uint8_t> &pendSignData)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&aotArgs)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable aotArgs failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    ErrCode ret = TransactInstalldCmd(InstalldInterfaceCode::EXECUTE_AOT, data, reply, option);
    if (ret == ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd ExecuteAOT failed when AOTSign disable");
        if (!reply.ReadUInt8Vector(&pendSignData)) {
            LOG_E(BMS_TAG_INSTALLD, "ReadUInt8Vector ExecuteAOT failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ret;
}

ErrCode InstalldProxy::PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(anFileName));
    if (!data.WriteUInt8Vector(signData)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable PendSignAOT failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::PEND_SIGN_AOT, data, reply, option);
}

ErrCode InstalldProxy::StopAOT()
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::STOP_AOT, data, reply, option);
}

ErrCode InstalldProxy::DeleteUninstallTmpDirs(const std::vector<std::string> &dirs)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, Uint32, dirs.size());
    for (const std::string &dir : dirs) {
        INSTALLD_PARCEL_WRITE(data, String, dir);
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::DELETE_UNINSTALL_TMP_DIRS, data, reply, option);
}

ErrCode InstalldProxy::RenameModuleDir(const std::string &oldPath, const std::string &newPath)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(oldPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(newPath));

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::RENAME_MODULE_DIR, data, reply, option);
}

ErrCode InstalldProxy::CreateBundleDataDir(const CreateDirParam &createDirParam)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&createDirParam)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable createDirParam failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::CREATE_BUNDLE_DATA_DIR, data, reply, option);
}

ErrCode InstalldProxy::CreateBundleDataDirWithVector(const std::vector<CreateDirParam> &createDirParams)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (createDirParams.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "createDirParams size is empty");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    INSTALLD_PARCEL_WRITE(data, Uint32, createDirParams.size());
    for (const auto &createDirParam : createDirParams) {
        if (!data.WriteParcelable(&createDirParam)) {
            LOG_E(BMS_TAG_INSTALLD, "WriteParcelable createDirParam failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::CREATE_BUNDLE_DATA_DIR_WITH_VECTOR, data, reply, option);
}

ErrCode InstalldProxy::RemoveBundleDataDir(
    const std::string &bundleName, const int userId, bool isAtomicService, const bool async)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, Int32, userId);
    INSTALLD_PARCEL_WRITE(data, Bool, isAtomicService);
    INSTALLD_PARCEL_WRITE(data, Bool, async);

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::REMOVE_BUNDLE_DATA_DIR, data, reply, option);
}

ErrCode InstalldProxy::RemoveModuleDataDir(const std::string &ModuleName, const int userid)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(ModuleName));
    INSTALLD_PARCEL_WRITE(data, Int32, userid);

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::REMOVE_MODULE_DATA_DIR, data, reply, option);
}

ErrCode InstalldProxy::RemoveDir(const std::string &dir)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(dir));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    return TransactInstalldCmd(InstalldInterfaceCode::REMOVE_DIR, data, reply, option);
}

ErrCode InstalldProxy::GetDiskUsage(const std::string &dir, int64_t &statSize, bool isRealPath)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(dir));
    INSTALLD_PARCEL_WRITE(data, Bool, isRealPath);

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC, WAIT_TIME);
    ErrCode ret = TransactInstalldCmd(InstalldInterfaceCode::GET_DISK_USAGE, data, reply, option);
    if (ret == ERR_OK) {
        statSize = reply.ReadInt64();
    }
    return ret;
}

ErrCode InstalldProxy::GetDiskUsageFromPath(const std::vector<std::string> &path, int64_t &statSize)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (path.size() > Constants::MAX_CACHE_DIR_SIZE) {
        LOG_E(BMS_TAG_INSTALLD, "cache path size invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    if (!data.WriteUint32(path.size())) {
        LOG_E(BMS_TAG_INSTALLD, "failed: write path count fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (size_t i = 0; i < path.size(); i++) {
        if (!data.WriteString(path[i])) {
            LOG_E(BMS_TAG_INSTALLD, "WriteParcelable path:[%{public}s] failed",
                path[i].c_str());
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC, WAIT_TIME);
    ErrCode ret = TransactInstalldCmd(InstalldInterfaceCode::GET_DISK_USAGE_FROM_PATH, data, reply, option);
    if (ret == ERR_OK) {
        statSize = reply.ReadInt64();
    }
    return ret;
}

ErrCode InstalldProxy::CleanBundleDataDir(const std::string &bundleDir)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleDir));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC, WAIT_TIME);
    return TransactInstalldCmd(InstalldInterfaceCode::CLEAN_BUNDLE_DATA_DIR, data, reply, option);
}

ErrCode InstalldProxy::CleanBundleDataDirByName(const std::string &bundleName, const int userid, const int appIndex)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, Int32, userid);
    INSTALLD_PARCEL_WRITE(data, Int32, appIndex);
    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::CLEAN_BUNDLE_DATA_DIR_BY_NAME, data, reply, option);
}

ErrCode InstalldProxy::GetBundleStats(const std::string &bundleName, const int32_t userId,
    std::vector<int64_t> &bundleStats, const int32_t uid, const int32_t appIndex,
    const uint32_t statFlag, const std::vector<std::string> &moduleNameList)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, Int32, userId);
    INSTALLD_PARCEL_WRITE(data, Int32, uid);
    INSTALLD_PARCEL_WRITE(data, Int32, appIndex);
    INSTALLD_PARCEL_WRITE(data, Uint32, statFlag);
    if (!data.WriteInt32(moduleNameList.size())) {
        LOG_E(BMS_TAG_INSTALLD, "GetBundleStats failed: write module name count fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (size_t i = 0; i < moduleNameList.size(); i++) {
        if (!data.WriteString(moduleNameList[i])) {
            LOG_E(BMS_TAG_INSTALLD, "WriteParcelable moduleNames:[%{public}s] failed",
                moduleNameList[i].c_str());
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::GET_BUNDLE_STATS, data, reply, option);
    if (ret == ERR_OK) {
        if (reply.ReadInt64Vector(&bundleStats)) {
            return ERR_OK;
        } else {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ret;
}

ErrCode InstalldProxy::GetAllBundleStats(const int32_t userId,
    std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, Int32, userId);
    uint32_t uidSize = uids.size();
    INSTALLD_PARCEL_WRITE(data, Uint32, uidSize);
    for (const auto &uid : uids) {
        INSTALLD_PARCEL_WRITE(data, Int32, uid);
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::GET_ALL_BUNDLE_STATS, data, reply, option);
    if (ret == ERR_OK) {
        if (!reply.ReadInt64Vector(&bundleStats)) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        return ERR_OK;
    }
    return ret;
}

ErrCode InstalldProxy::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
    bool isPreInstallApp, bool debug)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(dir));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(apl));
    INSTALLD_PARCEL_WRITE(data, Bool, isPreInstallApp);
    INSTALLD_PARCEL_WRITE(data, Bool, debug);

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    return TransactInstalldCmd(InstalldInterfaceCode::SET_DIR_APL, data, reply, option);
}

ErrCode InstalldProxy::GetBundleCachePath(const std::string &dir, std::vector<std::string> &cachePath)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(dir));
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::GET_BUNDLE_CACHE_PATH, data, reply, option);
    if (ret == ERR_OK) {
        if (reply.ReadStringVector(&cachePath)) {
            return ERR_OK;
        } else {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ret;
}

ErrCode InstalldProxy::ScanDir(
    const std::string &dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(dir));
    INSTALLD_PARCEL_WRITE(data, Int32, static_cast<int32_t>(scanMode));
    INSTALLD_PARCEL_WRITE(data, Int32, static_cast<int32_t>(resultMode));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::SCAN_DIR, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }

    if (!reply.ReadStringVector(&paths)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode InstalldProxy::MoveFile(const std::string &oldPath, const std::string &newPath)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(oldPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(newPath));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    return TransactInstalldCmd(InstalldInterfaceCode::MOVE_FILE, data, reply, option);
}

ErrCode InstalldProxy::CopyFile(const std::string &oldPath, const std::string &newPath,
    const std::string &signatureFilePath)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(oldPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(newPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(signatureFilePath));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    return TransactInstalldCmd(InstalldInterfaceCode::COPY_FILE, data, reply, option);
}

ErrCode InstalldProxy::Mkdir(
    const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(dir));
    INSTALLD_PARCEL_WRITE(data, Int32, mode);
    INSTALLD_PARCEL_WRITE(data, Int32, uid);
    INSTALLD_PARCEL_WRITE(data, Int32, gid);

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    return TransactInstalldCmd(InstalldInterfaceCode::MKDIR, data, reply, option);
}

ErrCode InstalldProxy::GetFileStat(const std::string &file, FileStat &fileStat)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(file));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::GET_FILE_STAT, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }

    std::unique_ptr<FileStat> info(reply.ReadParcelable<FileStat>());
    if (info == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    fileStat = *info;
    return ERR_OK;
}

ErrCode InstalldProxy::ExtractDiffFiles(const std::string &filePath, const std::string &targetPath,
    const std::string &cpuAbi)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(filePath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(targetPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(cpuAbi));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    return TransactInstalldCmd(InstalldInterfaceCode::EXTRACT_DIFF_FILES, data, reply, option);
}

ErrCode InstalldProxy::ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, int32_t uid)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(oldSoPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(diffFilePath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(newSoPath));
    INSTALLD_PARCEL_WRITE(data, Int32, uid);

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    return TransactInstalldCmd(InstalldInterfaceCode::APPLY_DIFF_PATCH, data, reply, option);
}

ErrCode InstalldProxy::IsExistDir(const std::string &dir, bool &isExist)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(dir));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::IS_EXIST_DIR, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    isExist = reply.ReadBool();
    return ERR_OK;
}

ErrCode InstalldProxy::IsExistFile(const std::string &path, bool &isExist)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(path));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::IS_EXIST_FILE, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    isExist = reply.ReadBool();
    return ERR_OK;
}

ErrCode InstalldProxy::IsExistApFile(const std::string &path, bool &isExist)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(path));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::IS_EXIST_AP_FILE, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    isExist = reply.ReadBool();
    return ERR_OK;
}

ErrCode InstalldProxy::IsDirEmpty(const std::string &dir, bool &isDirEmpty)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(dir));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::IS_DIR_EMPTY, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    isDirEmpty = reply.ReadBool();
    return ERR_OK;
}

ErrCode InstalldProxy::ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &dirVec)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(dir));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::OBTAIN_QUICK_FIX_DIR, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    if (!reply.ReadStringVector(&dirVec)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::CopyFiles(const std::string &sourceDir, const std::string &destinationDir)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(sourceDir));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(destinationDir));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::COPY_FILES, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
    std::vector<std::string> &fileNames)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(filePath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(cpuAbi));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::GET_NATIVE_LIBRARY_FILE_NAMES, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    if (!reply.ReadStringVector(&fileNames)) {
        LOG_E(BMS_TAG_INSTALLD, "ReadStringVector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&codeSignatureParam)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable codeSignatureParam failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::VERIFY_CODE_SIGNATURE, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&checkEncryptionParam)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable checkEncryptionParam failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::CHECK_ENCRYPTION, data, reply, option);
    isEncryption = reply.ReadBool();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "CheckEncryption failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::MoveFiles(const std::string &srcDir, const std::string &desDir)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(srcDir));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(desDir));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::MOVE_FILES, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::ExtractDriverSoFiles(const std::string &srcPath,
    const std::unordered_multimap<std::string, std::string> &dirMap)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(srcPath));
    INSTALLD_PARCEL_WRITE(data, Int32, static_cast<int32_t>(dirMap.size()));
    for (auto &[orignialDir, destinedDir] : dirMap) {
        INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(orignialDir));
        INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(destinedDir));
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::EXTRACT_DRIVER_SO_FILE, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::ExtractEncryptedSoFiles(const std::string &hapPath, const std::string &realSoFilesPath,
    const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(hapPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(realSoFilesPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(cpuAbi));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(tmpSoPath));
    INSTALLD_PARCEL_WRITE(data, Int32, uid);

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::EXTRACT_CODED_SO_FILE, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&codeSignatureParam)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable codeSignatureParam failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::VERIFY_CODE_SIGNATURE_FOR_HAP, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
    const unsigned char *profileBlock)
{
    if (profileBlockLength == 0 || profileBlockLength > Constants::MAX_PARCEL_CAPACITY || profileBlock == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "invalid params");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    MessageParcel data;
    (void)data.SetMaxCapacity(Constants::MAX_PARCEL_CAPACITY);
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, Int32, profileBlockLength);
    if (!data.WriteRawData(profileBlock, profileBlockLength)) {
        LOG_E(BMS_TAG_INSTALLD, "Failed to write raw data");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::DELIVERY_SIGN_PROFILE, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::RemoveSignProfile(const std::string &bundleName)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::REMOVE_SIGN_PROFILE, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::SetEncryptionPolicy(const EncryptionParam &encryptionParam, std::string &keyId)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&encryptionParam)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable encryptionParam failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::SET_ENCRYPTION_DIR, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    keyId = reply.ReadString();
    return ERR_OK;
}

ErrCode InstalldProxy::DeleteEncryptionKeyId(const EncryptionParam &encryptionParam)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&encryptionParam)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable encryptionParam failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::DELETE_ENCRYPTION_KEY_ID, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::RemoveExtensionDir(int32_t userId, const std::vector<std::string> &extensionBundleDirs)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, Int32, userId);
    const auto size = extensionBundleDirs.size();
    if (size > MAX_VEC_SIZE) {
        APP_LOGE("fail to RemoveExtensionDir due to extensionBundleDirs size %{public}zu is too big", size);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    INSTALLD_PARCEL_WRITE(data, Int32, size);
    for (size_t i = 0; i < size; i++) {
        if (extensionBundleDirs[i].size() > MAX_STRING_SIZE) {
            APP_LOGE("extensionBundleDirs %{public}zu is too long", i);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        if (!data.WriteString(extensionBundleDirs[i])) {
            APP_LOGE("fail to RemoveExtensionDir due to write extensionBundleDirs %{public}zu fail", i);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::REMOVE_EXTENSION_DIR, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::IsExistExtensionDir(int32_t userId, const std::string &extensionBundleDir, bool &isExist)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, Int32, userId);
    if (extensionBundleDir.size() > MAX_STRING_SIZE) {
        APP_LOGE("extensionBundleDir is too long");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(extensionBundleDir));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::IS_EXIST_EXTENSION_DIR, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    isExist = reply.ReadBool();
    return ERR_OK;
}

ErrCode InstalldProxy::GetExtensionSandboxTypeList(std::vector<std::string> &typeList)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::GET_EXTENSION_SANDBOX_TYPE_LIST, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    if (!reply.ReadStringVector(&typeList)) {
        APP_LOGE("fail to GetExtensionSandboxTypeList from reply");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::AddUserDirDeleteDfx(int32_t userId)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, Int32, userId);
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::ADD_USER_DIR_DELETE_DFX, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::CreateExtensionDataDir(const CreateDirParam &createDirParam)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&createDirParam)) {
        LOG_E(BMS_TAG_INSTALLD, "WriteParcelable createDirParam failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::CREATE_EXTENSION_DATA_DIR, data, reply, option);
}

ErrCode InstalldProxy::MoveHapToCodeDir(const std::string &originPath, const std::string &targetPath)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(originPath));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(targetPath));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    return TransactInstalldCmd(InstalldInterfaceCode::MOVE_HAP_TO_CODE_DIR, data, reply, option);
}

ErrCode InstalldProxy::MigrateData(const std::vector<std::string> &sourcePaths, const std::string &destinationPath)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, Int32, static_cast<int32_t>(sourcePaths.size()));
    for (auto &path : sourcePaths) {
        INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(path));
    }
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(destinationPath));
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::MIGRATE_DATA, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLD, "TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::CreateDataGroupDirs(const std::vector<CreateDirParam> &params)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (params.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "params is empty");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    INSTALLD_PARCEL_WRITE(data, Uint32, params.size());
    for (const auto &param : params) {
        if (!data.WriteParcelable(&param)) {
            LOG_E(BMS_TAG_INSTALLD, "WriteParcelable param failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::CREATE_DATA_GROUP_DIRS, data, reply, option);
}

ErrCode InstalldProxy::DeleteDataGroupDirs(const std::vector<std::string> &uuidList, int32_t userId)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, Uint32, uuidList.size());
    for (const std::string &dir : uuidList) {
        INSTALLD_PARCEL_WRITE(data, String, dir);
    }
    INSTALLD_PARCEL_WRITE(data, Int32, userId);

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::DELETE_DATA_GROUP_DIRS, data, reply, option);
}

ErrCode InstalldProxy::BackUpFirstBootLog()
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::BACK_UP_FIRST_BOOT_LOG, data, reply, option);
}

ErrCode InstalldProxy::TransactInstalldCmd(InstalldInterfaceCode code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "fail to send %{public}u cmd to service due to remote object is null",
            (unsigned int)(code));
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    if (remote->SendRequest(static_cast<uint32_t>(code), data, reply, option) != OHOS::NO_ERROR) {
        LOG_E(BMS_TAG_INSTALLD, "fail to send %{public}u request to service due to transact error",
            (unsigned int)(code));
        return ERR_APPEXECFWK_INSTALLD_SERVICE_DIED;
    }
    return reply.ReadInt32();
}
}  // namespace AppExecFwk
}  // namespace OHOS