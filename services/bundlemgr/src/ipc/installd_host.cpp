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

#include "app_log_tag_wrapper.h"
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
constexpr int32_t MAX_BATCH_QUERY_BUNDLE_SIZE = 1000;
const std::string UNLOAD_TASK_NAME = "UnloadInstalldTask";
const std::string UNLOAD_QUEUE_NAME = "UnloadInstalldQueue";
}

InstalldHost::InstalldHost()
{
    InitEventHandler();
    LOG_I(BMS_TAG_INSTALLD, "installd host instance is created");
}

InstalldHost::~InstalldHost()
{
    LOG_I(BMS_TAG_INSTALLD, "installd host instance is destroyed");
}

int InstalldHost::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    LOG_D(BMS_TAG_INSTALLD, "installd host receives message from client, code = %{public}d, flags = %{public}d",
        code, option.GetFlags());
    RemoveCloseInstalldTask();
    std::u16string descripter = InstalldHost::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        LOG_E(BMS_TAG_INSTALLD, "installd host fail to write reply message due to the reply is nullptr");
        return OHOS::ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool result = true;
    switch (code) {
        case static_cast<uint32_t>(InstalldInterfaceCode::CREATE_BUNDLE_DIR):
            result = this->HandleCreateBundleDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_MODULE_FILES):
            result = this->HandleExtractModuleFiles(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::RENAME_MODULE_DIR):
            result = this->HandleRenameModuleDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::CREATE_BUNDLE_DATA_DIR):
            result = this->HandleCreateBundleDataDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_BUNDLE_DATA_DIR):
            result = this->HandleRemoveBundleDataDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_MODULE_DATA_DIR):
            result = this->HandleRemoveModuleDataDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::CLEAN_BUNDLE_DATA_DIR):
            result = this->HandleCleanBundleDataDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::CLEAN_BUNDLE_DATA_DIR_BY_NAME):
            result = this->HandleCleanBundleDataDirByName(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::SET_DIR_APL):
            result = this->HandleSetDirApl(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_DIR):
            result = this->HandleRemoveDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::GET_BUNDLE_STATS):
            result = this->HandleGetBundleStats(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::GET_ALL_BUNDLE_STATS):
            result = this->HandleGetAllBundleStats(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::GET_BUNDLE_CACHE_PATH):
            result = this->HandleGetBundleCachePath(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::SCAN_DIR):
            result = this->HandleScanDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::MOVE_FILE):
            result = this->HandleMoveFile(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::COPY_FILE):
            result = this->HandleCopyFile(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::MOVE_HAP_TO_CODE_DIR):
            result = this->HandleMoveHapToCodeDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::MKDIR):
            result = this->HandleMkdir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::GET_FILE_STAT):
            result = this->HandleGetFileStat(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_DIFF_FILES):
            result = this->HandleExtractDiffFiles(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::APPLY_DIFF_PATCH):
            result = this->HandleApplyDiffPatch(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_DIR):
            result = this->HandleIsExistDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::IS_DIR_EMPTY):
            result = this->HandleIsDirEmpty(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::OBTAIN_QUICK_FIX_DIR):
            result = this->HandObtainQuickFixFileDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::COPY_FILES):
            result = this->HandCopyFiles(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_FILES):
            result = this->HandleExtractFiles(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_HNP_FILES):
            result = this->HandleExtractHnpFiles(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::INSTALL_NATIVE):
            result = this->HandleProcessBundleInstallNative(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::UNINSTALL_NATIVE):
            result = this->HandleProcessBundleUnInstallNative(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::GET_NATIVE_LIBRARY_FILE_NAMES):
            result = this->HandGetNativeLibraryFileNames(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::EXECUTE_AOT):
            result = this->HandleExecuteAOT(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::PEND_SIGN_AOT):
            result = this->HandlePendSignAOT(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_FILE):
            result = this->HandleIsExistFile(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_AP_FILE):
            result = this->HandleIsExistApFile(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::VERIFY_CODE_SIGNATURE):
            result = this->HandVerifyCodeSignature(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::CHECK_ENCRYPTION):
            result = this->HandleCheckEncryption(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::MOVE_FILES):
            result = this->HandMoveFiles(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_DRIVER_SO_FILE):
            result = this->HandExtractDriverSoFiles(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::EXTRACT_CODED_SO_FILE):
            result = this->HandExtractEncryptedSoFiles(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::VERIFY_CODE_SIGNATURE_FOR_HAP):
            result = this->HandVerifyCodeSignatureForHap(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::DELIVERY_SIGN_PROFILE):
            result = this->HandDeliverySignProfile(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_SIGN_PROFILE):
            result = this->HandRemoveSignProfile(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::CREATE_BUNDLE_DATA_DIR_WITH_VECTOR):
            result = this->HandleCreateBundleDataDirWithVector(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::STOP_AOT):
            result = this->HandleStopAOT(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::SET_ENCRYPTION_DIR):
            result = this->HandleSetEncryptionDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::DELETE_ENCRYPTION_KEY_ID):
            result = this->HandleDeleteEncryptionKeyId(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::REMOVE_EXTENSION_DIR):
            result = this->HandleRemoveExtensionDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::IS_EXIST_EXTENSION_DIR):
            result = this->HandleIsExistExtensionDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::CREATE_EXTENSION_DATA_DIR):
            result = this->HandleCreateExtensionDataDir(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::GET_DISK_USAGE):
            result = this->HandleGetDiskUsage(data, reply);
            break;
        case static_cast<uint32_t>(InstalldInterfaceCode::GET_EXTENSION_SANDBOX_TYPE_LIST):
            result = this->HandleGetExtensionSandboxTypeList(data, reply);
            break;
        default :
            LOG_W(BMS_TAG_INSTALLD, "installd host receives unknown code, code = %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    LOG_D(BMS_TAG_INSTALLD, "installd host finish to process message from client");
    AddCloseInstalldTask();
    return result ? NO_ERROR : OHOS::ERR_APPEXECFWK_PARCEL_ERROR;
}

void InstalldHost::InitEventHandler()
{
    std::lock_guard<std::mutex> lock(unloadTaskMutex_);
    runner_ = EventRunner::Create(UNLOAD_QUEUE_NAME);
    if (runner_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "init event runner failed");
        return;
    }
    handler_ = std::make_shared<EventHandler>(runner_);
    handler_->PostTask([]() { BundleMemoryGuard memoryGuard; },
        AppExecFwk::EventQueue::Priority::IMMEDIATE);
}

bool InstalldHost::HandleCreateBundleDir(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleDir = Str16ToStr8(data.ReadString16());
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "HandleCreateBundleDir %{public}s", bundleDir.c_str());
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
    LOG_I(BMS_TAG_INSTALLD, "extract module %{public}s", targetPath.c_str());
    ErrCode result = ExtractModuleFiles(srcModulePath, targetPath, targetSoPath, cpuAbi);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleExtractFiles(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<ExtractParam> info(data.ReadParcelable<ExtractParam>());
    if (info == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    ErrCode result = ExtractFiles(*info);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleExtractHnpFiles(MessageParcel &data, MessageParcel &reply)
{
    std::string hnpPackageInfo = Str16ToStr8(data.ReadString16());
    std::unique_ptr<ExtractParam> info(data.ReadParcelable<ExtractParam>());
    if (info == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    ErrCode result = ExtractHnpFiles(hnpPackageInfo, *info);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleProcessBundleInstallNative(MessageParcel &data, MessageParcel &reply)
{
    std::string userId = Str16ToStr8(data.ReadString16());
    std::string hnpRootPath = Str16ToStr8(data.ReadString16());
    std::string hapPath = Str16ToStr8(data.ReadString16());
    std::string cpuAbi = Str16ToStr8(data.ReadString16());
    std::string packageName = Str16ToStr8(data.ReadString16());

    ErrCode result = ProcessBundleInstallNative(userId, hnpRootPath, hapPath, cpuAbi, packageName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleProcessBundleUnInstallNative(MessageParcel &data, MessageParcel &reply)
{
    std::string userId = Str16ToStr8(data.ReadString16());
    std::string packageName = Str16ToStr8(data.ReadString16());

    ErrCode result = ProcessBundleUnInstallNative(userId, packageName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleExecuteAOT(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AOTArgs> aotArgs(data.ReadParcelable<AOTArgs>());
    if (aotArgs == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
        return false;
    }

    std::vector<uint8_t> pendSignData;
    ErrCode result = ExecuteAOT(*aotArgs, pendSignData);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (result == ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE) {
        if (!reply.WriteUInt8Vector(pendSignData)) {
            LOG_E(BMS_TAG_INSTALLD, "WriteParcelable ExecuteAOT failed");
            return false;
        }
    }
    return true;
}

bool InstalldHost::HandlePendSignAOT(MessageParcel &data, MessageParcel &reply)
{
    std::string anFileName = Str16ToStr8(data.ReadString16());
    std::vector<uint8_t> signData;
    if (!data.ReadUInt8Vector(&signData)) {
        LOG_E(BMS_TAG_INSTALLD, "ReadUInt8Vector PendSignAOT failed");
        return false;
    }
    ErrCode result = PendSignAOT(anFileName, signData);
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
        LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
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
            LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
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
    int32_t userId = data.ReadInt32();
    bool isAtomicService = data.ReadBool();
    ErrCode result = RemoveBundleDataDir(bundleName, userId, isAtomicService);
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

bool InstalldHost::HandleGetDiskUsage(MessageParcel &data, MessageParcel &reply)
{
    std::string dir = Str16ToStr8(data.ReadString16());
    bool isRealPath = data.ReadBool();

    ErrCode result = GetDiskUsage(dir, isRealPath);
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
    int appIndex = data.ReadInt32();
    ErrCode result = CleanBundleDataDirByName(bundleName, userid, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleGetBundleStats(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t userId = data.ReadInt32();
    int32_t uid = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    uint32_t statFlag = data.ReadUint32();
    std::vector<std::string> moduleNameList;
    if (!data.ReadStringVector(&moduleNameList)) {
        return false;
    }
    std::vector<int64_t> bundleStats;
    ErrCode result = GetBundleStats(bundleName, userId, bundleStats, uid, appIndex, statFlag, moduleNameList);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteInt64Vector(bundleStats)) {
        LOG_E(BMS_TAG_INSTALLD, "HandleGetBundleStats write failed");
        return false;
    }
    return true;
}

bool InstalldHost::HandleGetAllBundleStats(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = data.ReadInt32();
    auto uidSize = data.ReadInt32();
    if (uidSize == 0) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, ERR_APPEXECFWK_PARCEL_ERROR);
        return false;
    }
    std::vector<int32_t> uids;
    for (int32_t index = 0; index < uidSize; ++index) {
        int32_t uid = data.ReadInt32();
        uids.emplace_back(uid);
    }
    std::vector<int64_t> bundleStats;
    ErrCode result = GetAllBundleStats(userId, bundleStats, uids);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteInt64Vector(bundleStats)) {
        LOG_E(BMS_TAG_INSTALLD, "HandleGetAllBundleStats write failed");
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
        LOG_E(BMS_TAG_INSTALLD, "fail to GetBundleCachePath from reply");
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
        LOG_E(BMS_TAG_INSTALLD, "fail to Scan from reply");
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
        LOG_E(BMS_TAG_INSTALLD, "fail to GetFileStat from reply");
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
        LOG_E(BMS_TAG_INSTALLD, "fail to IsExistDir from reply");
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
        LOG_E(BMS_TAG_INSTALLD, "fail to IsExistFile from reply");
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
        LOG_E(BMS_TAG_INSTALLD, "fail to IsExistApFile from reply");
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
        LOG_E(BMS_TAG_INSTALLD, "write isDirEmpty failed");
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
        LOG_E(BMS_TAG_INSTALLD, "fail to obtain quick fix file dir from reply");
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
        LOG_E(BMS_TAG_INSTALLD, "fail to obtain fileNames from reply");
        return false;
    }
    return true;
}

bool InstalldHost::HandVerifyCodeSignature(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<CodeSignatureParam> info(data.ReadParcelable<CodeSignatureParam>());
    if (info == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
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
        LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }

    bool isEncryption = false;
    ErrCode result = CheckEncryption(*info, isEncryption);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteBool(isEncryption)) {
        LOG_E(BMS_TAG_INSTALLD, "write isEncryption failed");
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
        LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
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
        LOG_E(BMS_TAG_INSTALLD, "readRawData failed");
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

bool InstalldHost::HandleSetEncryptionDir(MessageParcel &data, MessageParcel &reply)
{
    int32_t uid = data.ReadInt32();
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t userId = data.ReadInt32();
    std::string keyId = "";

    ErrCode result = SetEncryptionPolicy(uid, bundleName, userId, keyId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteString(keyId)) {
        APP_LOGE("write keyId failed");
        return false;
    }
    return true;
}

bool InstalldHost::HandleDeleteEncryptionKeyId(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t userId = data.ReadInt32();

    ErrCode result = DeleteEncryptionKeyId(bundleName, userId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleRemoveExtensionDir(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = data.ReadInt32();
    int32_t extensionBundleDirSize = data.ReadInt32();
    if (extensionBundleDirSize <= 0 || extensionBundleDirSize > MAX_BATCH_QUERY_BUNDLE_SIZE) {
        APP_LOGE("extensionBundleDirs count is error");
        return false;
    }
    std::vector<std::string> extensionBundleDirs;
    for (int32_t i = 0; i < extensionBundleDirSize; i++) {
        std::string extensionBundleDir = data.ReadString();
        if (extensionBundleDir.empty()) {
            APP_LOGE("extensionBundleDirs %{public}d is empty", i);
            return false;
        }
        extensionBundleDirs.push_back(extensionBundleDir);
    }
    ErrCode result = RemoveExtensionDir(userId, extensionBundleDirs);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleIsExistExtensionDir(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = data.ReadInt32();
    std::string extensionBundleDir = Str16ToStr8(data.ReadString16());

    bool isExist = false;
    ErrCode result = IsExistExtensionDir(userId, extensionBundleDir, isExist);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (!reply.WriteBool(isExist)) {
        LOG_E(BMS_TAG_INSTALLD, "fail to write bool from reply");
        return false;
    }
    return true;
}

bool InstalldHost::HandleGetExtensionSandboxTypeList(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> typeList;
    ErrCode result = GetExtensionSandboxTypeList(typeList);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    if (result == ERR_OK) {
        if (!reply.WriteStringVector(typeList)) {
            APP_LOGE("write failed");
            return false;
        }
    }
    return true;
}

bool InstalldHost::HandleCreateExtensionDataDir(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<CreateDirParam> info(data.ReadParcelable<CreateDirParam>());
    if (info == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "readParcelableInfo failed");
        return ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR;
    }
    ErrCode result = CreateExtensionDataDir(*info);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}

bool InstalldHost::HandleMoveHapToCodeDir(MessageParcel &data, MessageParcel &reply)
{
    std::string originPath = Str16ToStr8(data.ReadString16());
    std::string targetPath = Str16ToStr8(data.ReadString16());

    ErrCode result = MoveHapToCodeDir(originPath, targetPath);
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
            LOG_E(BMS_TAG_INSTALLD, "fail to unload to system ability manager");
            return;
        }
        LOG_NOFUNC_I(BMS_TAG_INSTALLD, "unload Installd successfully");
    };
    handler_->PostTask(task, UNLOAD_TASK_NAME, UNLOAD_TIME);
    LOG_D(BMS_TAG_INSTALLD, "send unload task successfully");
}
}  // namespace AppExecFwk
}  // namespace OHOS
