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

#include "bundle_installer_proxy.h"

#include <cerrno>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_file_util.h"
#include "directory_ex.h"
#include "hitrace_meter.h"
#include "ipc_types.h"
#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* SEPARATOR = "/";
constexpr const char* ENTERPRISE_MANIFEST = "ohos.bms.param.enterpriseManifest";
const std::unordered_map<int32_t, int32_t> IPC_ERR_MAP = {
    {29201, ERR_APPEXECFWK_IPC_REPLY_ERROR},
    {29202, ERR_APPEXECFWK_IPC_REMOTE_FROZEN_ERROR},
    {29189, ERR_APPEXECFWK_IPC_REMOTE_DEAD_ERROR}
};
} // namespace

BundleInstallerProxy::BundleInstallerProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IBundleInstaller>(object)
{
    LOG_D(BMS_TAG_INSTALLER, "create bundle installer proxy instance");
}

BundleInstallerProxy::~BundleInstallerProxy()
{
    LOG_D(BMS_TAG_INSTALLER, "destroy bundle installer proxy instance");
}

bool BundleInstallerProxy::Install(
    const std::string &bundlePath, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    PARCEL_WRITE_INTERFACE_TOKEN(data, GetDescriptor());
    PARCEL_WRITE(data, String16, Str8ToStr16(bundlePath));
    PARCEL_WRITE(data, Parcelable, &installParam);

    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "fail to install, for statusReceiver is nullptr");
        return false;
    }
    if (!data.WriteRemoteObject(statusReceiver->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write parcel failed");
        return false;
    }

    return SendInstallRequest(BundleInstallerInterfaceCode::INSTALL, data, reply, option);
}

bool BundleInstallerProxy::Install(const std::vector<std::string> &bundleFilePaths, const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    PARCEL_WRITE_INTERFACE_TOKEN(data, GetDescriptor());
    auto size = bundleFilePaths.size();
    PARCEL_WRITE(data, Int32, size);
    for (uint32_t i = 0; i < size; ++i) {
        PARCEL_WRITE(data, String16, Str8ToStr16(bundleFilePaths[i]));
    }
    PARCEL_WRITE(data, Parcelable, &installParam);

    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "fail to install, for statusReceiver is nullptr");
        return false;
    }
    if (!data.WriteRemoteObject(statusReceiver->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write parcel failed");
        return false;
    }

    return SendInstallRequest(BundleInstallerInterfaceCode::INSTALL_MULTIPLE_HAPS, data, reply,
        option);
}

bool BundleInstallerProxy::Recover(const std::string &bundleName,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    PARCEL_WRITE_INTERFACE_TOKEN(data, GetDescriptor());
    PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    PARCEL_WRITE(data, Parcelable, &installParam);

    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "fail to install, for statusReceiver is nullptr");
        return false;
    }
    if (!data.WriteRemoteObject(statusReceiver->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write parcel failed");
        return false;
    }

    return SendInstallRequest(BundleInstallerInterfaceCode::RECOVER, data, reply,
        option);
}

bool BundleInstallerProxy::Uninstall(
    const std::string &bundleName, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    PARCEL_WRITE_INTERFACE_TOKEN(data, GetDescriptor());
    PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    PARCEL_WRITE(data, Parcelable, &installParam);
    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "fail to uninstall, for statusReceiver is nullptr");
        return false;
    }
    if (!data.WriteRemoteObject(statusReceiver->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write parcel failed");
        return false;
    }

    return SendInstallRequest(BundleInstallerInterfaceCode::UNINSTALL, data, reply, option);
}

bool BundleInstallerProxy::Uninstall(const std::string &bundleName, const std::string &modulePackage,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    PARCEL_WRITE_INTERFACE_TOKEN(data, GetDescriptor());
    PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    PARCEL_WRITE(data, String16, Str8ToStr16(modulePackage));
    PARCEL_WRITE(data, Parcelable, &installParam);
    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "fail to uninstall, for statusReceiver is nullptr");
        return false;
    }
    if (!data.WriteRemoteObject(statusReceiver->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write parcel failed");
        return false;
    }

    return SendInstallRequest(BundleInstallerInterfaceCode::UNINSTALL_MODULE, data, reply, option);
}

bool BundleInstallerProxy::Uninstall(const UninstallParam &uninstallParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    PARCEL_WRITE_INTERFACE_TOKEN(data, GetDescriptor());
    PARCEL_WRITE(data, Parcelable, &uninstallParam);
    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "fail to uninstall, for statusReceiver is nullptr");
        return false;
    }
    if (!data.WriteRemoteObject(statusReceiver->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write parcel failed");
        return false;
    }
    return SendInstallRequest(BundleInstallerInterfaceCode::UNINSTALL_BY_UNINSTALL_PARAM, data, reply, option);
}

ErrCode BundleInstallerProxy::InstallSandboxApp(const std::string &bundleName, int32_t dlpType, int32_t userId,
    int32_t &appIndex)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallSandboxApp due to write MessageParcel fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(bundleName))) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallSandboxApp due to write bundleName fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(dlpType)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallSandboxApp due to write appIndex fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallSandboxApp due to write userId fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }

    auto ret =
        SendInstallRequest(BundleInstallerInterfaceCode::INSTALL_SANDBOX_APP, data, reply, option);
    if (!ret) {
        LOG_E(BMS_TAG_INSTALLER, "install sandbox app failed due to send request fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_SEND_REQUEST_ERROR;
    }

    auto res = reply.ReadInt32();
    if (res == ERR_OK) {
        appIndex = reply.ReadInt32();
    }
    return res;
}

ErrCode BundleInstallerProxy::UninstallSandboxApp(const std::string &bundleName, int32_t appIndex, int32_t userId)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallSandboxApp due to write MessageParcel fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(bundleName))) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallSandboxApp due to write bundleName fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallSandboxApp due to write appIndex fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallSandboxApp due to write userId fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }

    auto ret =
        SendInstallRequest(BundleInstallerInterfaceCode::UNINSTALL_SANDBOX_APP, data, reply, option);
    if (!ret) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall sandbox app failed due to send request fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_SEND_REQUEST_ERROR;
    }
    return reply.ReadInt32();
}

ErrCode BundleInstallerProxy::InstallPlugin(const std::string &hostBundleName,
    const std::vector<std::string> &pluginFilePaths, const InstallPluginParam &installPluginParam)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    for (auto &path : pluginFilePaths) {
        if (access(path.c_str(), F_OK) != 0) {
            APP_LOGE("can not access the plugin file path: %{public}s, errno:%{public}d", path.c_str(), errno);
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
    }
    
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallPlugin due to write MessageParcel fail");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(hostBundleName)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallPlugin due to write hostBundleName fail");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(pluginFilePaths)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallPlugin due to write pluginFilePaths fail");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&installPluginParam)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallPlugin due to write installParam fail");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_WRITE_PARCEL_ERROR;
    }

    ErrCode ret =
        SendInstallRequestWithErrCode(BundleInstallerInterfaceCode::INSTALL_PLUGIN_APP, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "InstallPlugin failed due to send request fail");
        return ret;
    }
    return reply.ReadInt32();
}

ErrCode BundleInstallerProxy::UninstallPlugin(const std::string &hostBundleName, const std::string &pluginBundleName,
    const InstallPluginParam &installPluginParam)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_INSTALLER, "failed to UninstallPlugin due to write MessageParcel fail");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(hostBundleName))) {
        LOG_E(BMS_TAG_INSTALLER, "failed to UninstallPlugin due to write hostBundleName fail");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(pluginBundleName))) {
        LOG_E(BMS_TAG_INSTALLER, "failed to UninstallPlugin due to write pluginBundleName fail");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&installPluginParam)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to UninstallPlugin due to write installParam fail");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_WRITE_PARCEL_ERROR;
    }
    ErrCode ret =
        SendInstallRequestWithErrCode(BundleInstallerInterfaceCode::UNINSTALL_PLUGIN_APP, data, reply, option);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "UninstallPlugin failed due to send request fail");
        return ret;
    }
    return reply.ReadInt32();
}

sptr<IBundleStreamInstaller> BundleInstallerProxy::CreateStreamInstaller(const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver, const std::vector<std::string> &originHapPaths)
{
    LOG_D(BMS_TAG_INSTALLER, "create stream installer begin");
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "fail to install, for receiver is nullptr");
        return nullptr;
    }

    bool ret = data.WriteInterfaceToken(GetDescriptor());
    if (!ret) {
        LOG_E(BMS_TAG_INSTALLER, "fail to write interface token into the parcel");
        statusReceiver->OnFinished(ERR_APPEXECFWK_PARCEL_ERROR, "");
        return nullptr;
    }
    ret = data.WriteParcelable(&installParam);
    if (!ret) {
        LOG_E(BMS_TAG_INSTALLER, "fail to write parameter into the parcel");
        statusReceiver->OnFinished(ERR_APPEXECFWK_PARCEL_ERROR, "");
        return nullptr;
    }
    if (!data.WriteRemoteObject(statusReceiver->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write parcel failed");
        statusReceiver->OnFinished(ERR_APPEXECFWK_PARCEL_ERROR, "");
        return nullptr;
    }
    if (!data.WriteStringVector(originHapPaths)) {
        LOG_E(BMS_TAG_INSTALLER, "write parcel failed");
        statusReceiver->OnFinished(ERR_APPEXECFWK_PARCEL_ERROR, "");
        return nullptr;
    }
    bool res = SendInstallRequest(BundleInstallerInterfaceCode::CREATE_STREAM_INSTALLER, data, reply, option);
    if (!res) {
        LOG_E(BMS_TAG_INSTALLER, "CreateStreamInstaller failed due to send request fail");
        statusReceiver->OnFinished(ERR_APPEXECFWK_PARCEL_ERROR, "");
        return nullptr;
    }
    if (!reply.ReadBool()) {
        LOG_E(BMS_TAG_INSTALLER, "CreateStreamInstaller failed");
        return nullptr;
    }
    uint32_t streamInstallerId = reply.ReadUint32();
    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "CreateStreamInstaller create nullptr remote object");
        return nullptr;
    }
    sptr<IBundleStreamInstaller> streamInstaller = iface_cast<IBundleStreamInstaller>(object);
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "CreateStreamInstaller failed");
        return streamInstaller;
    }
    streamInstaller->SetInstallerId(streamInstallerId);
    LOG_D(BMS_TAG_INSTALLER, "create stream installer successfully");
    return streamInstaller;
}

bool BundleInstallerProxy::DestoryBundleStreamInstaller(uint32_t streamInstallerId)
{
    LOG_D(BMS_TAG_INSTALLER, "destory stream installer begin");
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    PARCEL_WRITE_INTERFACE_TOKEN(data, GetDescriptor());
    PARCEL_WRITE(data, Uint32, streamInstallerId);
    bool res = SendInstallRequest(BundleInstallerInterfaceCode::DESTORY_STREAM_INSTALLER, data, reply, option);
    if (!res) {
        LOG_E(BMS_TAG_INSTALLER, "CreateStreamInstaller failed due to send request fail");
        return false;
    }
    LOG_D(BMS_TAG_INSTALLER, "destory stream installer successfully");
    return true;
}

bool BundleInstallerProxy::UninstallAndRecover(const std::string &bundleName, const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel reply;
    MessageParcel data;
    MessageOption option(MessageOption::TF_SYNC);

    PARCEL_WRITE_INTERFACE_TOKEN(data, GetDescriptor());
    PARCEL_WRITE(data, String16, Str8ToStr16(bundleName));
    PARCEL_WRITE(data, Parcelable, &installParam);
    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "fail to uninstall quick fix, for statusReceiver is nullptr");
        return false;
    }
    if (!data.WriteRemoteObject(statusReceiver->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write parcel failed");
        return false;
    }

    return SendInstallRequest(BundleInstallerInterfaceCode::UNINSTALL_AND_RECOVER, data, reply, option);
}

ErrCode BundleInstallerProxy::StreamInstall(const std::vector<std::string> &bundleFilePaths,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    LOG_D(BMS_TAG_INSTALLER, "stream install start");
    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "stream install failed due to nullptr status receiver");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    std::vector<std::string> realPaths;
    if (!bundleFilePaths.empty() && !BundleFileUtil::CheckFilePath(bundleFilePaths, realPaths)) {
        LOG_E(BMS_TAG_INSTALLER, "stream install failed due to check file failed");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }

    sptr<IBundleStreamInstaller> streamInstaller = CreateStreamInstaller(installParam, statusReceiver, realPaths);
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "stream install failed due to nullptr stream installer");
        return ERR_OK;
    }
    ErrCode res = ERR_OK;
    // copy hap or hsp file to bms service
    if (!installParam.IsRenameInstall()) {
        for (const auto &path : realPaths) {
            res = WriteHapFileToStream(streamInstaller, path);
            if (res != ERR_OK) {
                DestoryBundleStreamInstaller(streamInstaller->GetInstallerId());
                LOG_E(BMS_TAG_INSTALLER, "WriteHapFileToStream failed due to %{public}d", res);
                return res;
            }
        }
    }
    // copy sig file to bms service
    if (!realPaths.empty() && !installParam.verifyCodeParams.empty() &&
        (realPaths.size() != installParam.verifyCodeParams.size())) {
        DestoryBundleStreamInstaller(streamInstaller->GetInstallerId());
        LOG_E(BMS_TAG_INSTALLER, "size of hapFiles is not same with size of verifyCodeParams");
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID;
    }
    if ((res = CopySignatureFileToService(streamInstaller, installParam)) != ERR_OK) {
        DestoryBundleStreamInstaller(streamInstaller->GetInstallerId());
        LOG_E(BMS_TAG_INSTALLER, "CopySignatureFileToService failed due to %{public}d", res);
        return res;
    }
    // copy pgo file to bms service
    res = CopyPgoFileToService(streamInstaller, installParam);
    if (res != ERR_OK) {
        LOG_W(BMS_TAG_INSTALLER, "CopyPgoFileToService failed due to %{public}d", res);
    }

    // copy ext profile file to bms service
    res = CopyExtProfileFileToService(streamInstaller, installParam);
    if (res != ERR_OK) {
        LOG_W(BMS_TAG_INSTALLER, "CopyExtProfileFileToService failed due to %{public}d", res);
    }

    // write shared bundles
    size_t size = installParam.sharedBundleDirPaths.size();
    for (uint32_t i = 0; i < size; ++i) {
        realPaths.clear();
        std::vector<std::string> sharedBundleDir = {installParam.sharedBundleDirPaths[i]};
        if (!BundleFileUtil::CheckFilePath(sharedBundleDir, realPaths)) {
            LOG_E(BMS_TAG_INSTALLER, "stream install failed due to check shared package files failed");
            DestoryBundleStreamInstaller(streamInstaller->GetInstallerId());
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
        for (const auto &path : realPaths) {
            res = WriteSharedFileToStream(streamInstaller, path, i);
            if (res != ERR_OK) {
                DestoryBundleStreamInstaller(streamInstaller->GetInstallerId());
                LOG_E(BMS_TAG_INSTALLER, "WriteSharedFileToStream(sharedBundleDirPaths) failed due to %{public}d", res);
                return res;
            }
        }
    }

    // start install haps
    if (!streamInstaller->Install()) {
        LOG_E(BMS_TAG_INSTALLER, "stream install failed");
        DestoryBundleStreamInstaller(streamInstaller->GetInstallerId());
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_FAILED_STREAM_INSTALL, "");
        return ERR_APPEXECFWK_INSTALL_FAILED_STREAM_INSTALL;
    }
    LOG_D(BMS_TAG_INSTALLER, "stream install end");
    return ERR_OK;
}

ErrCode BundleInstallerProxy::WriteFile(const std::string &path, int32_t outputFd)
{
    LOG_D(BMS_TAG_INSTALLER, "write file stream to service terminal start");
    std::string realPath;
    if (!PathToRealPath(path, realPath)) {
        LOG_E(BMS_TAG_INSTALLER, "file is not real path, file path: %{private}s", path.c_str());
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    int32_t inputFd = open(realPath.c_str(), O_RDONLY);
    if (inputFd < 0) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to open the hap file, errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }

    struct stat sourceStat;
    if (fstat(inputFd, &sourceStat) == -1) {
        LOG_E(BMS_TAG_INSTALLER, "fstat failed, errno : %{public}d", errno);
        close(inputFd);
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }
    if (sourceStat.st_size < 0) {
        LOG_E(BMS_TAG_INSTALLER, "invalid st_size");
        close(inputFd);
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }

    size_t buffer = 524288; // 0.5M
    size_t transferCount = 0;
    ssize_t singleTransfer = 0;
    while ((singleTransfer = sendfile(outputFd, inputFd, nullptr, buffer)) > 0) {
        transferCount += static_cast<size_t>(singleTransfer);
    }

    if (singleTransfer == -1 || transferCount != static_cast<size_t>(sourceStat.st_size)) {
        LOG_E(BMS_TAG_INSTALLER, "errno: %{public}d, send count: %{public}zu, file size: %{public}zu",
            errno, transferCount, static_cast<size_t>(sourceStat.st_size));
        close(inputFd);
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }

    close(inputFd);
    fsync(outputFd);

    LOG_D(BMS_TAG_INSTALLER, "write file stream to service terminal end");
    return ERR_OK;
}

ErrCode BundleInstallerProxy::WriteHapFileToStream(sptr<IBundleStreamInstaller> &streamInstaller,
    const std::string &path)
{
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to nullptr stream installer");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    std::string fileName;
    ErrCode ret = ERR_OK;
    ret = GetFileNameByFilePath(path, fileName);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "invalid file path");
        return ret;
    }
    LOG_D(BMS_TAG_INSTALLER, "write file stream of hap path %{public}s", path.c_str());

    int32_t outputFd = streamInstaller->CreateStream(fileName);
    if (outputFd < 0) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to invalid file descriptor");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }

    ret = WriteFile(path, outputFd);
    close(outputFd);

    return ret;
}

ErrCode BundleInstallerProxy::WriteSignatureFileToStream(sptr<IBundleStreamInstaller> &streamInstaller,
    const std::string &path, const std::string &moduleName)
{
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to nullptr stream installer");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    std::string fileName;
    ErrCode ret = ERR_OK;
    ret = GetFileNameByFilePath(path, fileName);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "invalid file path");
        return ret;
    }
    LOG_D(BMS_TAG_INSTALLER, "write file stream of signature path %{public}s", path.c_str());

    int32_t outputFd = streamInstaller->CreateSignatureFileStream(moduleName, fileName);
    if (outputFd < 0) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to invalid file descriptor");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }

    ret = WriteFile(path, outputFd);
    close(outputFd);

    return ret;
}

ErrCode BundleInstallerProxy::WriteSharedFileToStream(sptr<IBundleStreamInstaller> &streamInstaller,
    const std::string &path, uint32_t index)
{
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to nullptr stream installer");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    std::string hspName;
    ErrCode ret = ERR_OK;
    ret = GetFileNameByFilePath(path, hspName);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "invalid file path");
        return ret;
    }

    LOG_D(BMS_TAG_INSTALLER, "write file stream of shared path %{public}s", path.c_str());
    int32_t outputFd = streamInstaller->CreateSharedBundleStream(hspName, index);
    if (outputFd < 0) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to invalid file descriptor");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }

    ret = WriteFile(path, outputFd);
    close(outputFd);

    return ret;
}

ErrCode BundleInstallerProxy::WritePgoFileToStream(sptr<IBundleStreamInstaller> &streamInstaller,
    const std::string &path, const std::string &moduleName)
{
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to nullptr stream installer");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    std::string fileName;
    ErrCode ret = ERR_OK;
    ret = GetFileNameByFilePath(path, fileName);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "invalid file path");
        return ret;
    }
    LOG_D(BMS_TAG_INSTALLER, "write file stream of pgo path %{public}s", path.c_str());
    
    int32_t outputFd = streamInstaller->CreatePgoFileStream(moduleName, fileName);
    if (outputFd < 0) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to invalid file descriptor");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }

    ret = WriteFile(path, outputFd);
    close(outputFd);

    return ret;
}

ErrCode BundleInstallerProxy::CopySignatureFileToService(sptr<IBundleStreamInstaller> &streamInstaller,
    const InstallParam &installParam)
{
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "copy file failed due to nullptr stream installer");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    if (installParam.verifyCodeParams.empty()) {
        return ERR_OK;
    }
    for (const auto &param : installParam.verifyCodeParams) {
        std::string realPath;
        if (param.first.empty() || !BundleFileUtil::CheckFilePath(param.second, realPath)) {
            LOG_E(BMS_TAG_INSTALLER, "CheckFilePath signature file dir %{public}s failed", param.second.c_str());
            DestoryBundleStreamInstaller(streamInstaller->GetInstallerId());
            return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID;
        }
        ErrCode res = WriteSignatureFileToStream(streamInstaller, realPath, param.first);
        if (res != ERR_OK) {
            DestoryBundleStreamInstaller(streamInstaller->GetInstallerId());
            LOG_E(BMS_TAG_INSTALLER, "WriteSignatureFileToStream failed due to %{public}d", res);
            return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID;
        }
    }

    return ERR_OK;
}

ErrCode BundleInstallerProxy::CopyPgoFileToService(sptr<IBundleStreamInstaller> &streamInstaller,
    const InstallParam &installParam)
{
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "copy file failed due to nullptr stream installer");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (installParam.pgoParams.empty()) {
        return ERR_OK;
    }
    for (const auto &param : installParam.pgoParams) {
        std::string realPath;
        if (param.first.empty() || !BundleFileUtil::CheckFilePath(param.second, realPath)) {
            LOG_W(BMS_TAG_INSTALLER, "CheckFilePath pgo file path %{public}s failed", param.second.c_str());
            continue;
        }
        ErrCode res = WritePgoFileToStream(streamInstaller, realPath, param.first);
        if (res != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLER, "WritePgoFileToStream failed due to %{public}d", res);
            continue;
        }
    }

    return ERR_OK;
}

ErrCode BundleInstallerProxy::WriteExtProfileFileToStream(sptr<IBundleStreamInstaller> streamInstaller,
    const std::string &path)
{
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to nullptr stream installer");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    std::string fileName;
    ErrCode ret = ERR_OK;
    ret = GetFileNameByFilePath(path, fileName);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "invalid file path");
        return ret;
    }
    LOG_D(BMS_TAG_INSTALLER, "write file stream of hap path %{public}s", path.c_str());

    int32_t outputFd = streamInstaller->CreateExtProfileFileStream(fileName);
    if (outputFd < 0) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to invalid file descriptor");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }

    ret = WriteFile(path, outputFd);
    close(outputFd);

    return ret;
}

ErrCode BundleInstallerProxy::CopyExtProfileFileToService(sptr<IBundleStreamInstaller> streamInstaller,
    const InstallParam &installParam)
{
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "copy file failed due to nullptr stream installer");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    auto iter = installParam.parameters.find(ENTERPRISE_MANIFEST);
    if ((iter == installParam.parameters.end()) || (iter->second.empty())) {
        return ERR_OK;
    }
    
    std::string realPath;
    if (!BundleFileUtil::CheckFilePath(iter->second, realPath)) {
        LOG_W(BMS_TAG_INSTALLER, "CheckFilePath ext profile file path %{public}s failed", iter->second.c_str());
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    ErrCode res = WriteExtProfileFileToStream(streamInstaller, realPath);
    if (res != ERR_OK) {
        LOG_W(BMS_TAG_INSTALLER, "WriteExtProfileFileToStream failed due to %{public}d", res);
        return res;
    }

    return ERR_OK;
}

ErrCode BundleInstallerProxy::GetFileNameByFilePath(const std::string &filePath, std::string &fileName)
{
    size_t pos = filePath.find_last_of(SEPARATOR);
    if (pos == std::string::npos) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to invalid file path");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    fileName = filePath.substr(pos + 1);
    if (fileName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "write file to stream failed due to invalid file path");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    return ERR_OK;
}

bool BundleInstallerProxy::SendInstallRequest(
    BundleInstallerInterfaceCode code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "fail to uninstall, for Remote() is nullptr");
        return false;
    }

    int32_t ret = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (ret != NO_ERROR) {
        LOG_E(BMS_TAG_INSTALLER, "fail to sendRequest, for transact is failed and error code is: %{public}d", ret);
        return false;
    }
    return true;
}

ErrCode BundleInstallerProxy::SendInstallRequestWithErrCode(
    BundleInstallerInterfaceCode code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "Remote() is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    int32_t ret = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (ret != NO_ERROR) {
        LOG_E(BMS_TAG_INSTALLER, "fail to sendRequest, for transact is failed and error code is: %{public}d", ret);
        auto it = IPC_ERR_MAP.find(ret);
        if (it != IPC_ERR_MAP.end()) {
            return it->second;
        }
        return ret;
    }
    return ERR_OK;
}

ErrCode BundleInstallerProxy::InstallCloneApp(const std::string &bundleName, int32_t userId, int32_t& appIndex)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallCloneApp due to write MessageParcel fail");
        return ERR_APPEXECFWK_CLONE_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(bundleName))) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallCloneApp due to write bundleName fail");
        return ERR_APPEXECFWK_CLONE_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallCloneApp due to write userId fail");
        return ERR_APPEXECFWK_CLONE_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to InstallCloneApp due to write appIndex fail");
        return ERR_APPEXECFWK_CLONE_INSTALL_WRITE_PARCEL_ERROR;
    }

    auto ret =
        SendInstallRequest(BundleInstallerInterfaceCode::INSTALL_CLONE_APP, data, reply, option);
    if (!ret) {
        LOG_E(BMS_TAG_INSTALLER, "install clone app failed due to send request fail");
        return ERR_APPEXECFWK_CLONE_INSTALL_SEND_REQUEST_ERROR;
    }

    auto res = reply.ReadInt32();
    if (res == ERR_OK) {
        appIndex = reply.ReadInt32();
    }
    return res;
}

ErrCode BundleInstallerProxy::UninstallCloneApp(const std::string &bundleName, int32_t userId, int32_t appIndex,
                                                const DestroyAppCloneParam &destroyAppCloneParam)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_INSTALLER, "failed to UninstallCloneApp due to write MessageParcel fail");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(bundleName))) {
        LOG_E(BMS_TAG_INSTALLER, "failed to UninstallCloneApp due to write bundleName fail");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to UninstallCloneApp due to write userId fail");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to UninstallCloneApp due to write appIndex fail");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_WRITE_PARCEL_ERROR;
    }

    PARCEL_WRITE(data, Parcelable, &destroyAppCloneParam);

    auto ret =
        SendInstallRequest(BundleInstallerInterfaceCode::UNINSTALL_CLONE_APP, data, reply, option);
    if (!ret) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall clone app failed due to send request fail");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_SEND_REQUEST_ERROR;
    }
    return reply.ReadInt32();
}

ErrCode BundleInstallerProxy::InstallExisted(const std::string &bundleName, int32_t userId)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_INSTALLER, "failed to write descriptor");
        return ERR_APPEXECFWK_INSTALL_EXISTED_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(bundleName))) {
        LOG_E(BMS_TAG_INSTALLER, "failed to write bundleName");
        return ERR_APPEXECFWK_INSTALL_EXISTED_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "failed to write userId");
        return ERR_APPEXECFWK_INSTALL_EXISTED_WRITE_PARCEL_ERROR;
    }

    auto ret =
        SendInstallRequest(BundleInstallerInterfaceCode::INSTALL_EXISTED, data, reply, option);
    if (!ret) {
        LOG_E(BMS_TAG_INSTALLER, "installExisted failed due to send request fail");
        return ERR_APPEXECFWK_INSTALL_EXISTED_WRITE_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}
}  // namespace AppExecFwk
}  // namespace OHOS
