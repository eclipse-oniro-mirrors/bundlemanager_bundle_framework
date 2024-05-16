/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "ipc_types.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t WAIT_TIME = 3000;
}

InstalldProxy::InstalldProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IInstalld>(object)
{
    APP_LOGI("installd proxy instance is created");
}

InstalldProxy::~InstalldProxy()
{
    APP_LOGI("installd proxy instance is destroyed");
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
        APP_LOGE("WriteParcelable extractParam failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::EXTRACT_FILES, data, reply, option);
}

ErrCode InstalldProxy::ExecuteAOT(const AOTArgs &aotArgs)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&aotArgs)) {
        APP_LOGE("WriteParcelable aotArgs failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::EXECUTE_AOT, data, reply, option);
}

ErrCode InstalldProxy::StopAOT()
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::STOP_AOT, data, reply, option);
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
        APP_LOGE("WriteParcelable createDirParam failed.");
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
        APP_LOGE("createDirParams size is empty.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    INSTALLD_PARCEL_WRITE(data, Uint32, createDirParams.size());
    for (const auto &createDirParam : createDirParams) {
        if (!data.WriteParcelable(&createDirParam)) {
            APP_LOGE("WriteParcelable createDirParam failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::CREATE_BUNDLE_DATA_DIR_WITH_VECTOR, data, reply, option);
}

ErrCode InstalldProxy::RemoveBundleDataDir(const std::string &bundleName, const int userid)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, Int32, userid);

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

ErrCode InstalldProxy::CleanBundleDataDir(const std::string &bundleDir)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleDir));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC, WAIT_TIME);
    return TransactInstalldCmd(InstalldInterfaceCode::CLEAN_BUNDLE_DATA_DIR, data, reply, option);
}

ErrCode InstalldProxy::CleanBundleDataDirByName(const std::string &bundleName, const int userid)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, Int32, userid);
    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::CLEAN_BUNDLE_DATA_DIR_BY_NAME, data, reply, option);
}

ErrCode InstalldProxy::GetBundleStats(
    const std::string &bundleName, const int32_t userId, std::vector<int64_t> &bundleStats, const int32_t uid)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, Int32, userId);
    INSTALLD_PARCEL_WRITE(data, Int32, uid);
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

ErrCode InstalldProxy::GetAllBundleStats(const std::vector<std::string> &bundleNames, const int32_t userId,
    std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids)
{
    uint32_t bundleNamesSize = bundleNames.size();
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, Uint32, bundleNamesSize);
    for (const auto &bundleName : bundleNames) {
        INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    }
    INSTALLD_PARCEL_WRITE(data, Int32, userId);
    for (const auto &uid : uids) {
        INSTALLD_PARCEL_WRITE(data, Int32, uid);
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::GET_ALL_BUNDLE_STATS, data, reply, option);
    if (ret == ERR_OK) {
        if (reply.ReadInt64Vector(&bundleStats)) {
            return ERR_OK;
        } else {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
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
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }

    std::unique_ptr<FileStat> info(reply.ReadParcelable<FileStat>());
    if (info == nullptr) {
        APP_LOGE("readParcelableInfo failed");
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
        APP_LOGE("TransactInstalldCmd failed");
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
        APP_LOGE("TransactInstalldCmd failed");
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
        APP_LOGE("TransactInstalldCmd failed");
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
        APP_LOGE("TransactInstalldCmd failed");
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
        APP_LOGE("TransactInstalldCmd failed");
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
        APP_LOGE("TransactInstalldCmd failed");
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
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    if (!reply.ReadStringVector(&fileNames)) {
        APP_LOGE("ReadStringVector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&codeSignatureParam)) {
        APP_LOGE("WriteParcelable codeSignatureParam failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::VERIFY_CODE_SIGNATURE, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&checkEncryptionParam)) {
        APP_LOGE("WriteParcelable checkEncryptionParam failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::CHECK_ENCRYPTION, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    isEncryption = reply.ReadBool();
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
        APP_LOGE("TransactInstalldCmd failed");
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
        APP_LOGE("TransactInstalldCmd failed");
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
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    if (!data.WriteParcelable(&codeSignatureParam)) {
        APP_LOGE("WriteParcelable codeSignatureParam failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::VERIFY_CODE_SIGNATURE_FOR_HAP, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
    const unsigned char *profileBlock)
{
    if (profileBlockLength == 0 || profileBlockLength > Constants::MAX_PARCEL_CAPACITY || profileBlock == nullptr) {
        APP_LOGE("invalid params");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    MessageParcel data;
    (void)data.SetMaxCapacity(Constants::MAX_PARCEL_CAPACITY);
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, Int32, profileBlockLength);
    if (!data.WriteRawData(profileBlock, profileBlockLength)) {
        APP_LOGE("Failed to write raw data");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::DELIVERY_SIGN_PROFILE, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
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
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::SetEncryptionPolicy(int32_t uid, const std::string &bundleName,
    const int32_t userId, std::string &keyId)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, Int32, uid);
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    INSTALLD_PARCEL_WRITE(data, Int32, userId);

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

ErrCode InstalldProxy::DeleteEncryptionKeyId(const std::string &keyId)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(keyId));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    auto ret = TransactInstalldCmd(InstalldInterfaceCode::DELETE_ENCRYPTION_KEY_ID, data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("TransactInstalldCmd failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode InstalldProxy::TransactInstalldCmd(InstalldInterfaceCode code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail to send %{public}u cmd to service due to remote object is null", code);
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    if (remote->SendRequest(static_cast<uint32_t>(code), data, reply, option) != OHOS::NO_ERROR) {
        APP_LOGE("fail to send %{public}u request to service due to transact error", code);
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }
    return reply.ReadInt32();
}
}  // namespace AppExecFwk
}  // namespace OHOS