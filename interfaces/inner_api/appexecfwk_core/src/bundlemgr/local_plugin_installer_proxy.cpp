/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "local_plugin_installer_proxy.h"

#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_file_util.h"
#include "directory_ex.h"
#include "hitrace_meter.h"
#include "local_plugin_stream_installer_proxy.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *LOCAL_PLUGIN_FILE_SUFFIX = ".hsp";
constexpr char FILE_SEPARATOR_CHAR = '/';

bool IsValidLocalPluginInputFile(const std::string &path)
{
    return BundleFileUtil::CheckFileType(path, LOCAL_PLUGIN_FILE_SUFFIX);
}

ErrCode GetFileNameByFilePath(const std::string &filePath, std::string &fileName)
{
    auto pos = filePath.rfind(FILE_SEPARATOR_CHAR);
    fileName = (pos == std::string::npos) ? filePath : filePath.substr(pos + 1);
    return fileName.empty() ? ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID : ERR_OK;
}

ErrCode GetInputPathStat(const std::string &path, struct stat &pathStat)
{
    if (stat(path.c_str(), &pathStat) != 0) {
        APP_LOGE("stat %{public}s failed, errno:%{public}d", path.c_str(), errno);
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    return ERR_OK;
}

ErrCode AddLocalPluginFileToStreamPaths(const std::string &path, const struct stat &pathStat,
    std::vector<std::string> &streamPaths)
{
    if (!S_ISREG(pathStat.st_mode)) {
        APP_LOGE("path is not a regular file: %{public}s", path.c_str());
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    if (!IsValidLocalPluginInputFile(path)) {
        APP_LOGE("local plugin only supports hsp file: %{public}s", path.c_str());
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    streamPaths.emplace_back(path);
    return ERR_OK;
}

ErrCode CollectDirectoryStreamPaths(const std::string &dirPath, std::vector<std::string> &streamPaths)
{
    DIR *dir = opendir(dirPath.c_str());
    if (dir == nullptr) {
        APP_LOGE("open %{public}s failed, errno:%{public}d", dirPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }

    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        std::string filePath = dirPath + FILE_SEPARATOR_CHAR + entry->d_name;
        struct stat entryStat;
        ErrCode ret = GetInputPathStat(filePath, entryStat);
        if (ret != ERR_OK) {
            closedir(dir);
            return ret;
        }
        ret = AddLocalPluginFileToStreamPaths(filePath, entryStat, streamPaths);
        if (ret != ERR_OK) {
            closedir(dir);
            return ret;
        }
    }
    closedir(dir);
    return ERR_OK;
}

ErrCode CollectInstallStreamPaths(const std::vector<std::string> &pluginFilePaths,
    std::vector<std::string> &streamPaths)
{
    if (pluginFilePaths.empty()) {
        APP_LOGE("pluginFilePaths is empty");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    if (pluginFilePaths.size() == 1) {
        struct stat pathStat;
        ErrCode ret = GetInputPathStat(pluginFilePaths.front(), pathStat);
        if (ret != ERR_OK) {
            return ret;
        }
        if (S_ISDIR(pathStat.st_mode)) {
            return CollectDirectoryStreamPaths(pluginFilePaths.front(), streamPaths);
        }
        return AddLocalPluginFileToStreamPaths(pluginFilePaths.front(), pathStat, streamPaths);
    }

    for (const auto &path : pluginFilePaths) {
        struct stat pathStat;
        ErrCode ret = GetInputPathStat(path, pathStat);
        if (ret != ERR_OK) {
            return ret;
        }

        if (S_ISDIR(pathStat.st_mode)) {
            APP_LOGE("directory path is only supported as a single install input: %{public}s", path.c_str());
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
        ret = AddLocalPluginFileToStreamPaths(path, pathStat, streamPaths);
        if (ret != ERR_OK) {
            return ret;
        }
    }
    return ERR_OK;
}

ErrCode WriteInputFileToLocalPluginStream(const std::string &path, int32_t outputFd)
{
    std::string inputPath = path;
    std::string realPath;
    if (PathToRealPath(path, realPath)) {
        inputPath = realPath;
    } else {
        APP_LOGW("file path has no real path, fallback to original path: %{public}s", path.c_str());
    }

    int32_t inputFd = open(inputPath.c_str(), O_RDONLY | O_UNCACHE);
    if (inputFd < 0) {
        APP_LOGE("open %{public}s failed, errno:%{public}d", inputPath.c_str(), errno);
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    fdsan_exchange_owner_tag(inputFd, 0, LOG_DOMAIN);
    struct stat sourceStat;
    if (fstat(inputFd, &sourceStat) == -1 || sourceStat.st_size < 0) {
        APP_LOGE("fstat failed, errno:%{public}d", errno);
        fdsan_close_with_tag(inputFd, LOG_DOMAIN);
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }

    size_t buffer = 524288;
    size_t transferCount = 0;
    ssize_t singleTransfer = 0;
    errno = 0;
    while ((singleTransfer = sendfile(outputFd, inputFd, nullptr, buffer)) > 0) {
        transferCount += static_cast<size_t>(singleTransfer);
    }

    if (singleTransfer == -1 || transferCount != static_cast<size_t>(sourceStat.st_size)) {
        APP_LOGE("errno:%{public}d, singleTransfer:%{public}zd, send count:%{public}zu, file size:%{public}zu",
            errno, singleTransfer, transferCount, static_cast<size_t>(sourceStat.st_size));
        fdsan_close_with_tag(inputFd, LOG_DOMAIN);
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }

    fdsan_close_with_tag(inputFd, LOG_DOMAIN);
    fsync(outputFd);
    return ERR_OK;
}
}  // namespace

LocalPluginInstallerProxy::LocalPluginInstallerProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<ILocalPluginInstaller>(object)
{}

LocalPluginInstallerProxy::~LocalPluginInstallerProxy() = default;

ErrCode LocalPluginInstallerProxy::Install(const std::vector<std::string> &pluginFilePaths,
    const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (statusReceiver == nullptr) {
        APP_LOGE("fail to install local plugin due to nullptr statusReceiver");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    std::vector<std::string> streamPaths;
    ErrCode ret = CollectInstallStreamPaths(pluginFilePaths, streamPaths);
    if (ret != ERR_OK) {
        return ret;
    }

    sptr<ILocalPluginStreamInstaller> pluginStreamInstaller = CreateLocalPluginStreamInstaller(statusReceiver);
    if (pluginStreamInstaller == nullptr) {
        if (statusReceiver != nullptr) {
            APP_LOGE("local plugin stream install failed, errcode pass through onFinished");
            return ERR_OK;
        } else {
            return ERR_APPEXECFWK_NULL_PTR;
        }
    }
    for (const auto &path : streamPaths) {
        ret = WriteFileToLocalPluginStream(pluginStreamInstaller, path);
        if (ret != ERR_OK) {
            DestroyLocalPluginStreamInstaller(pluginStreamInstaller->GetLocalPluginInstallerId());
            return ret;
        }
    }
    if (!pluginStreamInstaller->CommitLocalPluginInstall()) {
        DestroyLocalPluginStreamInstaller(pluginStreamInstaller->GetLocalPluginInstallerId());
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, "");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode LocalPluginInstallerProxy::Uninstall(const std::string &pluginBundleName,
    const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (statusReceiver == nullptr) {
        return ERR_APPEXECFWK_NULL_PTR;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor()) || !data.WriteString16(Str8ToStr16(pluginBundleName)) ||
        !data.WriteRemoteObject(statusReceiver->AsObject())) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = SendRequest(LocalPluginInstallerInterfaceCode::UNINSTALL, data, reply);
    if (ret != ERR_OK) {
        return ret;
    }
    return reply.ReadInt32();
}

ErrCode LocalPluginInstallerProxy::Uninstall(const std::string &bundleName, const std::string &pluginBundleName,
    int32_t userId)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor()) ||
        !data.WriteString16(Str8ToStr16(bundleName)) ||
        !data.WriteString16(Str8ToStr16(pluginBundleName)) ||
        !data.WriteInt32(userId)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = SendRequest(LocalPluginInstallerInterfaceCode::INTERNAL_UNINSTALL, data, reply);
    if (ret != ERR_OK) {
        return ret;
    }
    return reply.ReadInt32();
}

sptr<ILocalPluginStreamInstaller> LocalPluginInstallerProxy::CreateLocalPluginStreamInstaller(
    const sptr<IStatusReceiver> &statusReceiver)
{
    if (statusReceiver == nullptr) {
        return nullptr;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor()) || !data.WriteRemoteObject(statusReceiver->AsObject())) {
        statusReceiver->OnFinished(ERR_APPEXECFWK_PARCEL_ERROR, "");
        return nullptr;
    }
    auto ret = SendRequest(LocalPluginInstallerInterfaceCode::CREATE_LOCAL_PLUGIN_STREAM_INSTALLER, data, reply);
    if (ret != ERR_OK) {
        statusReceiver->OnFinished(ret == ERR_APPEXECFWK_NULL_PTR ? ret : ERR_APPEXECFWK_PARCEL_ERROR, "");
        return nullptr;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("CreateLocalPluginStreamInstaller failed");
        return nullptr;
    }
    uint32_t installerId = reply.ReadUint32();
    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("CreateLocalPluginStreamInstaller create nullptr remote object");
        statusReceiver->OnFinished(ERR_APPEXECFWK_PARCEL_ERROR, "");
        return nullptr;
    }
    sptr<ILocalPluginStreamInstaller> pluginStreamInstaller = iface_cast<ILocalPluginStreamInstaller>(object);
    if (pluginStreamInstaller == nullptr) {
        APP_LOGE("CreateLocalPluginStreamInstaller failed");
        statusReceiver->OnFinished(ERR_APPEXECFWK_NULL_PTR, "");
        return nullptr;
    }
    pluginStreamInstaller->SetLocalPluginInstallerId(installerId);
    return pluginStreamInstaller;
}

bool LocalPluginInstallerProxy::DestroyLocalPluginStreamInstaller(uint32_t installerId)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor()) || !data.WriteUint32(installerId)) {
        return false;
    }
    auto ret = SendRequest(LocalPluginInstallerInterfaceCode::DESTROY_LOCAL_PLUGIN_STREAM_INSTALLER, data, reply);
    if (ret != ERR_OK) {
        return false;
    }
    return reply.ReadBool();
}

ErrCode LocalPluginInstallerProxy::SendRequest(
    LocalPluginInstallerInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    auto remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("remote is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    auto ret = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (ret != ERR_NONE) {
        APP_LOGE("send request failed, code:%{public}u ret:%{public}d", static_cast<uint32_t>(code), ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode LocalPluginInstallerProxy::WriteFileToLocalPluginStream(
    const sptr<ILocalPluginStreamInstaller> &pluginStreamInstaller, const std::string &path)
{
    if (pluginStreamInstaller == nullptr) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    std::string fileName;
    ErrCode ret = GetFileNameByFilePath(path, fileName);
    if (ret != ERR_OK) {
        return ret;
    }
    int32_t outputFd = pluginStreamInstaller->CreatePluginFileStream(fileName);
    if (outputFd < 0) {
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    ret = WriteInputFileToLocalPluginStream(path, outputFd);
    close(outputFd);
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS
