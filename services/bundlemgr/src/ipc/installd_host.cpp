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

#include "ipc/installd_host.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_framework_services_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "parcel_macro.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t UNLOAD_TIME = 3 * 60 * 1000; // 3 min for installd to unload
const std::string UNLOAD_TASK_NAME = "UnloadInstalldTask";
const std::string UNLOAD_QUEUE_NAME = "UnloadInstalldQueue";
}

InstalldHost::InstalldHost()
{
    Init();
    InitEventHandler();
    APP_LOGI("installd host instance is created");
}

InstalldHost::~InstalldHost()
{
    APP_LOGI("installd host instance is destroyed");
}

void InstalldHost::Init()
{
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::CREATE_BUNDLE_DIR),
        &InstalldHost::HandleCreateBundleDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_MODULE_FILES),
        &InstalldHost::HandleExtractModuleFiles);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::RENAME_MODULE_DIR),
        &InstalldHost::HandleRenameModuleDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::CREATE_BUNDLE_DATA_DIR),
        &InstalldHost::HandleCreateBundleDataDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_BUNDLE_DATA_DIR),
        &InstalldHost::HandleRemoveBundleDataDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_MODULE_DATA_DIR),
        &InstalldHost::HandleRemoveModuleDataDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::CLEAN_BUNDLE_DATA_DIR),
        &InstalldHost::HandleCleanBundleDataDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::CLEAN_BUNDLE_DATA_DIR_BY_NAME),
        &InstalldHost::HandleCleanBundleDataDirByName);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::SET_DIR_APL), &InstalldHost::HandleSetDirApl);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_DIR), &InstalldHost::HandleRemoveDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::GET_BUNDLE_STATS),
        &InstalldHost::HandleGetBundleStats);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::GET_ALL_BUNDLE_STATS),
        &InstalldHost::HandleGetAllBundleStats);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::GET_BUNDLE_CACHE_PATH),
        &InstalldHost::HandleGetBundleCachePath);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::SCAN_DIR), &InstalldHost::HandleScanDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::MOVE_FILE), &InstalldHost::HandleMoveFile);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::COPY_FILE), &InstalldHost::HandleCopyFile);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::MKDIR), &InstalldHost::HandleMkdir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::GET_FILE_STAT), &InstalldHost::HandleGetFileStat);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_DIFF_FILES),
        &InstalldHost::HandleExtractDiffFiles);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::APPLY_DIFF_PATCH),
        &InstalldHost::HandleApplyDiffPatch);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_DIR), &InstalldHost::HandleIsExistDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::IS_DIR_EMPTY), &InstalldHost::HandleIsDirEmpty);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::OBTAIN_QUICK_FIX_DIR),
        &InstalldHost::HandObtainQuickFixFileDir);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::COPY_FILES), &InstalldHost::HandCopyFiles);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_FILES), &InstalldHost::HandleExtractFiles);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::GET_NATIVE_LIBRARY_FILE_NAMES),
        &InstalldHost::HandGetNativeLibraryFileNames);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::EXECUTE_AOT), &InstalldHost::HandleExecuteAOT);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_FILE), &InstalldHost::HandleIsExistFile);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_AP_FILE),
        &InstalldHost::HandleIsExistApFile);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::VERIFY_CODE_SIGNATURE),
        &InstalldHost::HandVerifyCodeSignature);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::CHECK_ENCRYPTION),
        &InstalldHost::HandleCheckEncryption);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::MOVE_FILES), &InstalldHost::HandMoveFiles);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_DRIVER_SO_FILE),
        &InstalldHost::HandExtractDriverSoFiles);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_CODED_SO_FILE),
        &InstalldHost::HandExtractEncryptedSoFiles);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::VERIFY_CODE_SIGNATURE_FOR_HAP),
        &InstalldHost::HandVerifyCodeSignatureForHap);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::DELIVERY_SIGN_PROFILE),
        &InstalldHost::HandDeliverySignProfile);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_SIGN_PROFILE),
        &InstalldHost::HandRemoveSignProfile);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::CREATE_BUNDLE_DATA_DIR_WITH_VECTOR),
        &InstalldHost::HandleCreateBundleDataDirWithVector);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::STOP_AOT), &InstalldHost::HandleStopAOT);
    funcMap_.emplace(static_cast<uint32_t>(InstalldInterfaceCode::MIGRATE_DATA),
        &InstalldHost::HandleMigrateData);
}

int InstalldHost::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGD(
        "installd host receives message from client, code = %{public}d, flags = %{public}d", code, option.GetFlags());
    RemoveCloseInstalldTask();
    std::u16string descripter = InstalldHost::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        APP_LOGE("installd host fail to write reply message due to the reply is nullptr");
        return OHOS::ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool result = true;
    APP_LOGD("funcMap_ size is %{public}d", static_cast<int32_t>(funcMap_.size()));
    if (funcMap_.find(code) != funcMap_.end() && funcMap_[code] != nullptr) {
        result = (this->*funcMap_[code])(data, reply);
    } else {
        APP_LOGW("installd host receives unknown code, code = %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    APP_LOGD("installd host finish to process message from client");
    AddCloseInstalldTask();
    return result ? NO_ERROR : OHOS::ERR_APPEXECFWK_PARCEL_ERROR;
}

void InstalldHost::InitEventHandler()
{
    std::lock_guard<std::mutex> lock(unloadTaskMutex_);
    runner_ = EventRunner::Create(UNLOAD_QUEUE_NAME);
    if (runner_ == nullptr) {
        APP_LOGE("init event runner failed");
        return;
    }
    handler_ = std::make_shared<EventHandler>(runner_);
    handler_->PostTask([]() { BundleMemoryGuard memoryGuard; },
        AppExecFwk::EventQueue::Priority::IMMEDIATE);
}

bool InstalldHost::HandleCreateBundleDir(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleDir = Str16ToStr8(data.ReadString16());
    APP_LOGI("bundleName %{public}s", bundleDir.c_str());
    ErrCode result = CreateBundleDir(bundleDir);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleExtractModuleFiles(MessageParcel &data, MessageParcel &reply)
{
    std::string srcModulePath = Str16ToStr8(data.ReadString16());
    std::string targetPath = Str16ToStr8(data.ReadString16());
    std::string targetSoPath = Str16ToStr8(data.ReadString16());
    std::string cpuAbi = Str16ToStr8(data.ReadString16());
    APP_LOGI("extract module %{public}s", targetPath.c_str());
    ErrCode result = ExtractModuleFiles(srcModulePath, targetPath, targetSoPath, cpuAbi);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleExtractFiles(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<ExtractParam> info(data.ReadParcelable<ExtractParam>());
    if (info == nullptr) {
        APP_LOGE("readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    ErrCode result = ExtractFiles(*info);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleExecuteAOT(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AOTArgs> aotArgs(data.ReadParcelable<AOTArgs>());
    if (aotArgs == nullptr) {
        APP_LOGE("readParcelableInfo failed");
        return false;
    }

    ErrCode result = ExecuteAOT(*aotArgs);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleStopAOT(MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = StopAOT();
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleRenameModuleDir(MessageParcel &data, MessageParcel &reply)
{
    std::string oldPath = Str16ToStr8(data.ReadString16());
    std::string newPath = Str16ToStr8(data.ReadString16());
    ErrCode result = RenameModuleDir(oldPath, newPath);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleCreateBundleDataDir(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<CreateDirParam> info(data.ReadParcelable<CreateDirParam>());
    if (info == nullptr) {
        APP_LOGE("readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }
    ErrCode result = CreateBundleDataDir(*info);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleCreateBundleDataDirWithVector(MessageParcel &data, MessageParcel &reply)
{
    auto createDirParamSize = data.ReadInt32();
    if (createDirParamSize == 0 || createDirParamSize > Constants::MAX_PARCEL_CAPACITY) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, ERR_APPEXECFWK_PARCEL_ERROR);
        return false;
    }
    std::vector<CreateDirParam> createDirParams;
    for (int32_t index = 0; index < createDirParamSize; ++index) {
        std::unique_ptr<CreateDirParam> info(data.ReadParcelable<CreateDirParam>());
        if (info == nullptr) {
            APP_LOGE("readParcelableInfo failed");
            return false;
        }
        createDirParams.emplace_back(*info);
    }

    ErrCode result = CreateBundleDataDirWithVector(createDirParams);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleRemoveBundleDataDir(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int userid = data.ReadInt32();
    ErrCode result = RemoveBundleDataDir(bundleName, userid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleRemoveModuleDataDir(MessageParcel &data, MessageParcel &reply)
{
    std::string moduleNmae = Str16ToStr8(data.ReadString16());
    int userid = data.ReadInt32();
    ErrCode result = RemoveModuleDataDir(moduleNmae, userid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleRemoveDir(MessageParcel &data, MessageParcel &reply)
{
    std::string removedDir = Str16ToStr8(data.ReadString16());
    ErrCode result = RemoveDir(removedDir);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleCleanBundleDataDir(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleDir = Str16ToStr8(data.ReadString16());
    ErrCode result = CleanBundleDataDir(bundleDir);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleCleanBundleDataDirByName(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int userid = data.ReadInt32();
    ErrCode result = CleanBundleDataDirByName(bundleName, userid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleGetBundleStats(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t userId = data.ReadInt32();
    int32_t uid = data.ReadInt32();
    std::vector<int64_t> bundleStats;
    ErrCode result = GetBundleStats(bundleName, userId, bundleStats, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteInt64Vector(bundleStats)) {
        APP_LOGE("HandleGetBundleStats write failed");
        return false;
    }
    return true;
}

bool InstalldHost::HandleGetAllBundleStats(MessageParcel &data, MessageParcel &reply)
{
    auto bundleNamesSize = data.ReadInt32();
    if (bundleNamesSize == 0 || bundleNamesSize > Constants::MAX_PARCEL_CAPACITY) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, ERR_APPEXECFWK_PARCEL_ERROR);
        return false;
    }
    std::vector<std::string> bundleNames;
    std::vector<int32_t> uids;
    for (int32_t index = 0; index < bundleNamesSize; ++index) {
        std::string bundleName = Str16ToStr8(data.ReadString16());
        bundleNames.emplace_back(bundleName);
    }
    int32_t userId = data.ReadInt32();
    for (int32_t index = 0; index < bundleNamesSize; ++index) {
        int32_t uid = data.ReadInt32();
        uids.emplace_back(uid);
    }
    std::vector<int64_t> bundleStats;
    ErrCode result = GetAllBundleStats(bundleNames, userId, bundleStats, uids);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteInt64Vector(bundleStats)) {
        APP_LOGE("HandleGetAllBundleStats write failed");
        return false;
    }
    return true;
}

bool InstalldHost::HandleSetDirApl(MessageParcel &data, MessageParcel &reply)
{
    std::string dataDir = Str16ToStr8(data.ReadString16());
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::string apl = Str16ToStr8(data.ReadString16());
    bool isPreInstallApp = data.ReadBool();
    bool debug = data.ReadBool();
    ErrCode result = SetDirApl(dataDir, bundleName, apl, isPreInstallApp, debug);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleGetBundleCachePath(MessageParcel &data, MessageParcel &reply)
{
    std::string dir = Str16ToStr8(data.ReadString16());
    std::vector<std::string> cachePath;
    ErrCode result = GetBundleCachePath(dir, cachePath);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteStringVector(cachePath)) {
        APP_LOGE("fail to GetBundleCachePath from reply");
        return false;
    }
    return true;
}

bool InstalldHost::HandleScanDir(MessageParcel &data, MessageParcel &reply)
{
    std::string dir = Str16ToStr8(data.ReadString16());
    ScanMode scanMode = static_cast<ScanMode>(data.ReadInt32());
    ResultMode resultMode = static_cast<ResultMode>(data.ReadInt32());
    std::vector<std::string> paths;
    ErrCode result = ScanDir(dir, scanMode, resultMode, paths);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteStringVector(paths)) {
        APP_LOGE("fail to Scan from reply");
        return false;
    }

    return true;
}

bool InstalldHost::HandleMoveFile(MessageParcel &data, MessageParcel &reply)
{
    std::string oldPath = Str16ToStr8(data.ReadString16());
    std::string newPath = Str16ToStr8(data.ReadString16());
    ErrCode result = MoveFile(oldPath, newPath);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleCopyFile(MessageParcel &data, MessageParcel &reply)
{
    std::string oldPath = Str16ToStr8(data.ReadString16());
    std::string newPath = Str16ToStr8(data.ReadString16());
    std::string signatureFilePath = Str16ToStr8(data.ReadString16());

    ErrCode result = CopyFile(oldPath, newPath, signatureFilePath);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleMkdir(MessageParcel &data, MessageParcel &reply)
{
    std::string dir = Str16ToStr8(data.ReadString16());
    int32_t mode = data.ReadInt32();
    int32_t uid = data.ReadInt32();
    int32_t gid = data.ReadInt32();
    ErrCode result = Mkdir(dir, mode, uid, gid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleGetFileStat(MessageParcel &data, MessageParcel &reply)
{
    std::string file = Str16ToStr8(data.ReadString16());
    FileStat fileStat;
    ErrCode result = GetFileStat(file, fileStat);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteParcelable(&fileStat)) {
        APP_LOGE("fail to GetFileStat from reply");
        return false;
    }

    return true;
}

bool InstalldHost::HandleExtractDiffFiles(MessageParcel &data, MessageParcel &reply)
{
    std::string filePath = Str16ToStr8(data.ReadString16());
    std::string targetPath = Str16ToStr8(data.ReadString16());
    std::string cpuAbi = Str16ToStr8(data.ReadString16());
    ErrCode result = ExtractDiffFiles(filePath, targetPath, cpuAbi);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleApplyDiffPatch(MessageParcel &data, MessageParcel &reply)
{
    std::string oldSoPath = Str16ToStr8(data.ReadString16());
    std::string diffFilePath = Str16ToStr8(data.ReadString16());
    std::string newSoPath = Str16ToStr8(data.ReadString16());
    int32_t uid = data.ReadInt32();

    ErrCode result = ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleIsExistDir(MessageParcel &data, MessageParcel &reply)
{
    std::string path = Str16ToStr8(data.ReadString16());
    bool isExist = false;
    ErrCode result = IsExistDir(path, isExist);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteBool(isExist)) {
        APP_LOGE("fail to IsExistDir from reply");
        return false;
    }
    return true;
}

bool InstalldHost::HandleIsExistFile(MessageParcel &data, MessageParcel &reply)
{
    std::string path = Str16ToStr8(data.ReadString16());
    bool isExist = false;
    ErrCode result = IsExistFile(path, isExist);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteBool(isExist)) {
        APP_LOGE("fail to IsExistFile from reply");
        return false;
    }
    return true;
}

bool InstalldHost::HandleIsExistApFile(MessageParcel &data, MessageParcel &reply)
{
    std::string path = Str16ToStr8(data.ReadString16());
    bool isExist = false;
    ErrCode result = IsExistApFile(path, isExist);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteBool(isExist)) {
        APP_LOGE("fail to IsExistApFile from reply");
        return false;
    }
    return true;
}

bool InstalldHost::HandleIsDirEmpty(MessageParcel &data, MessageParcel &reply)
{
    std::string dir = Str16ToStr8(data.ReadString16());
    bool isDirEmpty = false;
    ErrCode result = IsDirEmpty(dir, isDirEmpty);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteBool(isDirEmpty)) {
        APP_LOGE("write isDirEmpty failed");
        return false;
    }
    return true;
}

bool InstalldHost::HandObtainQuickFixFileDir(MessageParcel &data, MessageParcel &reply)
{
    std::string dir = Str16ToStr8(data.ReadString16());
    std::vector<std::string> dirVec;
    ErrCode result = ObtainQuickFixFileDir(dir, dirVec);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if ((result == ERR_OK) && !reply.WriteStringVector(dirVec)) {
        APP_LOGE("fail to obtain quick fix file dir from reply");
        return false;
    }
    return true;
}

bool InstalldHost::HandCopyFiles(MessageParcel &data, MessageParcel &reply)
{
    std::string sourceDir = Str16ToStr8(data.ReadString16());
    std::string destinationDir = Str16ToStr8(data.ReadString16());

    ErrCode result = CopyFiles(sourceDir, destinationDir);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandGetNativeLibraryFileNames(MessageParcel &data, MessageParcel &reply)
{
    std::string filePath = Str16ToStr8(data.ReadString16());
    std::string cupAbi = Str16ToStr8(data.ReadString16());
    std::vector<std::string> fileNames;
    ErrCode result = GetNativeLibraryFileNames(filePath, cupAbi, fileNames);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if ((result == ERR_OK) && !reply.WriteStringVector(fileNames)) {
        APP_LOGE("fail to obtain fileNames from reply");
        return false;
    }
    return true;
}

bool InstalldHost::HandVerifyCodeSignature(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<CodeSignatureParam> info(data.ReadParcelable<CodeSignatureParam>());
    if (info == nullptr) {
        APP_LOGE("readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    ErrCode result = VerifyCodeSignature(*info);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleCheckEncryption(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<CheckEncryptionParam> info(data.ReadParcelable<CheckEncryptionParam>());
    if (info == nullptr) {
        APP_LOGE("readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    bool isEncryption = false;
    ErrCode result = CheckEncryption(*info, isEncryption);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteBool(isEncryption)) {
        APP_LOGE("write isEncryption failed");
        return false;
    }
    return true;
}

bool InstalldHost::HandMoveFiles(MessageParcel &data, MessageParcel &reply)
{
    std::string srcDir = Str16ToStr8(data.ReadString16());
    std::string desDir = Str16ToStr8(data.ReadString16());

    ErrCode result = MoveFiles(srcDir, desDir);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}


bool InstalldHost::HandExtractDriverSoFiles(MessageParcel &data, MessageParcel &reply)
{
    std::string srcPath = Str16ToStr8(data.ReadString16());
    int32_t size = data.ReadInt32();
    std::unordered_multimap<std::string, std::string> dirMap;
    CONTAINER_SECURITY_VERIFY(data, size, &dirMap);
    for (int32_t index = 0; index < size; ++index) {
        std::string originalDir = Str16ToStr8(data.ReadString16());
        std::string destinedDir = Str16ToStr8(data.ReadString16());
        dirMap.emplace(originalDir, destinedDir);
    }

    ErrCode result = ExtractDriverSoFiles(srcPath, dirMap);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandExtractEncryptedSoFiles(MessageParcel &data, MessageParcel &reply)
{
    std::string hapPath = Str16ToStr8(data.ReadString16());
    std::string realSoFilesPath = Str16ToStr8(data.ReadString16());
    std::string cpuAbi = Str16ToStr8(data.ReadString16());
    std::string tmpSoPath = Str16ToStr8(data.ReadString16());
    int32_t uid = data.ReadInt32();

    ErrCode result = ExtractEncryptedSoFiles(hapPath, realSoFilesPath, cpuAbi, tmpSoPath, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandVerifyCodeSignatureForHap(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<CodeSignatureParam> info(data.ReadParcelable<CodeSignatureParam>());
    if (info == nullptr) {
        APP_LOGE("readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    ErrCode result = VerifyCodeSignatureForHap(*info);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandDeliverySignProfile(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t profileBlockLength = data.ReadInt32();
    if (profileBlockLength == 0 || profileBlockLength > Constants::MAX_PARCEL_CAPACITY) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, ERR_APPEXECFWK_PARCEL_ERROR);
        return false;
    }
    auto dataInfo = data.ReadRawData(profileBlockLength);
    if (!dataInfo) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, ERR_APPEXECFWK_PARCEL_ERROR);
        return false;
    }
    const unsigned char *profileBlock = reinterpret_cast<const unsigned char *>(dataInfo);
    if (profileBlock == nullptr) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, ERR_APPEXECFWK_PARCEL_ERROR);
        return false;
    }
    ErrCode result = DeliverySignProfile(bundleName, profileBlockLength, profileBlock);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandRemoveSignProfile(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = Str16ToStr8(data.ReadString16());

    ErrCode result = RemoveSignProfile(bundleName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleMigrateData(MessageParcel &data, MessageParcel &reply)
{
    int32_t size = data.ReadInt32();
    std::vector<std::string> sourcePaths;
    CONTAINER_SECURITY_VERIFY(data, size, &sourcePaths);
    for (int32_t index = 0; index < size; ++index) {
        std::string path = Str16ToStr8(data.ReadString16());
        sourcePaths.emplace_back(path);
    }
    std::string destinationPath = Str16ToStr8(data.ReadString16());
    ErrCode result = MigrateData(sourcePaths, destinationPath);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

void InstalldHost::RemoveCloseInstalldTask()
{
    std::lock_guard<std::mutex> lock(unloadTaskMutex_);
    handler_->RemoveTask(UNLOAD_TASK_NAME);
}

void InstalldHost::AddCloseInstalldTask()
{
    std::lock_guard<std::mutex> lock(unloadTaskMutex_);
    auto task = [] {
        BundleMemoryGuard memoryGuard;
        if (!SystemAbilityHelper::UnloadSystemAbility(INSTALLD_SERVICE_ID)) {
            APP_LOGE("fail to unload to system ability manager");
            return;
        }
        APP_LOGI("unload Installd successfully");
    };
    handler_->PostTask(task, UNLOAD_TASK_NAME, UNLOAD_TIME);
    APP_LOGD("send unload task successfully");
}
}  // namespace AppExecFwk
}  // namespace OHOS
