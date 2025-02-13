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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_INSTALLD_HOST_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_INSTALLD_HOST_H

#include <mutex>
#include <string>

#include "event_handler.h"
#include "event_runner.h"
#include "iremote_stub.h"
#include "ipc/installd_interface.h"

namespace OHOS {
namespace AppExecFwk {
class InstalldHost : public IRemoteStub<IInstalld> {
public:
    InstalldHost();
    virtual ~InstalldHost() override;

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    /**
     * @brief Handles the CreateBundleDir function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleCreateBundleDir(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the ExtractModuleFiles function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleExtractModuleFiles(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the HandleExtractFiles function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleExtractFiles(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the HandleExtractHnpFiles function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleExtractHnpFiles(MessageParcel &data, MessageParcel &reply);

    bool HandleProcessBundleInstallNative(MessageParcel &data, MessageParcel &reply);
    bool HandleProcessBundleUnInstallNative(MessageParcel &data, MessageParcel &reply);

    bool HandleExecuteAOT(MessageParcel &data, MessageParcel &reply);

    bool HandlePendSignAOT(MessageParcel &data, MessageParcel &reply);

    bool HandleStopAOT(MessageParcel &data, MessageParcel &reply);

    bool HandleDeleteUninstallTmpDirs(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the RenameModuleDir function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleRenameModuleDir(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the CreateBundleDataDir function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleCreateBundleDataDir(MessageParcel &data, MessageParcel &reply);

    bool HandleCreateBundleDataDirWithVector(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the RemoveBundleDataDir function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleRemoveBundleDataDir(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the RemoveModuleDataDir function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleRemoveModuleDataDir(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the RemoveDir function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleRemoveDir(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the GetDiskUsage function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleGetDiskUsage(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the GetDiskUsage function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleGetDiskUsageFromPath(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the CleanBundleDataDir function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleCleanBundleDataDir(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the CleanBundleDataDirByName function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleCleanBundleDataDirByName(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief Handles the CleanBundleDataDir function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleGetBundleStats(MessageParcel &data, MessageParcel &reply);

    bool HandleGetAllBundleStats(MessageParcel &data, MessageParcel &reply);
    
    /**
     * @brief Handles the set dir apl function called from a IInstalld proxy object.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleSetDirApl(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief Handles the all GetBundleCachePath function.
     * @param data Indicates the data to be read.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleGetBundleCachePath(MessageParcel &data, MessageParcel &reply);

    bool HandleScanDir(MessageParcel &data, MessageParcel &reply);

    bool HandleMoveFile(MessageParcel &data, MessageParcel &reply);

    bool HandleCopyFile(MessageParcel &data, MessageParcel &reply);

    bool HandleMkdir(MessageParcel &data, MessageParcel &reply);

    bool HandleGetFileStat(MessageParcel &data, MessageParcel &reply);

    bool HandleExtractDiffFiles(MessageParcel &data, MessageParcel &reply);

    bool HandleApplyDiffPatch(MessageParcel &data, MessageParcel &reply);

    bool HandleIsExistDir(MessageParcel &data, MessageParcel &reply);

    bool HandleIsExistFile(MessageParcel &data, MessageParcel &reply);

    bool HandleIsExistApFile(MessageParcel &data, MessageParcel &reply);

    bool HandleIsDirEmpty(MessageParcel &data, MessageParcel &reply);

    bool HandObtainQuickFixFileDir(MessageParcel &data, MessageParcel &reply);

    bool HandCopyFiles(MessageParcel &data, MessageParcel &reply);

    bool HandGetNativeLibraryFileNames(MessageParcel &data, MessageParcel &reply);

    bool HandVerifyCodeSignature(MessageParcel &data, MessageParcel &reply);

    bool HandleCheckEncryption(MessageParcel &data, MessageParcel &reply);

    bool HandMoveFiles(MessageParcel &data, MessageParcel &reply);

    bool HandExtractDriverSoFiles(MessageParcel &data, MessageParcel &reply);

    bool HandExtractEncryptedSoFiles(MessageParcel &data, MessageParcel &reply);

    bool HandVerifyCodeSignatureForHap(MessageParcel &data, MessageParcel &reply);

    bool HandDeliverySignProfile(MessageParcel &data, MessageParcel &reply);

    bool HandRemoveSignProfile(MessageParcel &data, MessageParcel &reply);

    bool HandleSetEncryptionDir(MessageParcel &data, MessageParcel &reply);

    bool HandleDeleteEncryptionKeyId(MessageParcel &data, MessageParcel &reply);

    bool HandleRemoveExtensionDir(MessageParcel &data, MessageParcel &reply);

    bool HandleIsExistExtensionDir(MessageParcel &data, MessageParcel &reply);

    bool HandleCreateExtensionDataDir(MessageParcel &data, MessageParcel &reply);

    bool HandleGetExtensionSandboxTypeList(MessageParcel &data, MessageParcel &reply);

    bool HandleMoveHapToCodeDir(MessageParcel &data, MessageParcel &reply);

    void AddCloseInstalldTask();

    void RemoveCloseInstalldTask();

    void InitEventHandler();

    std::mutex unloadTaskMutex_;
    std::shared_ptr<EventHandler> handler_ = nullptr;
    std::shared_ptr<EventRunner> runner_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_INSTALLD_HOST_H