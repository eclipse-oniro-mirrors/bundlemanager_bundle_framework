/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "extend_resource_manager_proxy.h"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_file_util.h"
#include "directory_ex.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string SEPARATOR = "/";
const int32_t DEFAULT_BUFFER_SIZE = 65536;
}
ExtendResourceManagerProxy::ExtendResourceManagerProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IExtendResourceManager>(object)
{
    APP_LOGI_NOFUNC("create ExtendResourceManagerProxy");
}

ExtendResourceManagerProxy::~ExtendResourceManagerProxy()
{
    APP_LOGI_NOFUNC("destroy ExtendResourceManagerProxy");
}

ErrCode ExtendResourceManagerProxy::AddExtResource(
    const std::string &bundleName, const std::vector<std::string> &filePaths)
{
    APP_LOGD("begin to AddExtResource");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to AddExtResource due to bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (filePaths.empty()) {
        APP_LOGE("fail to AddExtResource due to filePaths is empty");
        return ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to AddExtResource due to WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to AddExtResource due to write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(filePaths)) {
        APP_LOGE("fail to AddExtResource due to write filePaths failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(ExtendResourceManagerInterfaceCode::ADD_EXT_RESOURCE, data, reply)) {
        APP_LOGE("fail to AddExtResource from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

ErrCode ExtendResourceManagerProxy::RemoveExtResource(
    const std::string &bundleName, const std::vector<std::string> &moduleNames)
{
    APP_LOGD("begin to RemoveExtResource");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to RemoveExtResource due to bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (moduleNames.empty()) {
        APP_LOGE("fail to RemoveExtResource due to moduleNames is empty");
        return ERR_EXT_RESOURCE_MANAGER_REMOVE_EXT_RESOURCE_FAILED;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to RemoveExtResource due to WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to RemoveExtResource due to write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(moduleNames)) {
        APP_LOGE("fail to RemoveExtResource due to write moduleNames failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(ExtendResourceManagerInterfaceCode::REMOVE_EXT_RESOURCE, data, reply)) {
        APP_LOGE("fail to RemoveExtResource from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

ErrCode ExtendResourceManagerProxy::GetExtResource(
    const std::string &bundleName, std::vector<std::string> &moduleNames)
{
    APP_LOGD("begin to GetExtResource");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to GetExtResource due to bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetExtResource due to WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetExtResource due to write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(ExtendResourceManagerInterfaceCode::GET_EXT_RESOURCE, data, reply)) {
        APP_LOGE("fail to GetExtResource from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("fail to GetExtResource from server");
        return ret;
    }
    if (!reply.ReadStringVector(&moduleNames)) {
        APP_LOGE("read moduleNames failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerProxy::EnableDynamicIcon(
    const std::string &bundleName, const std::string &moduleName)
{
    APP_LOGD("begin to EnableDynamicIcon");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to EnableDynamicIcon due to bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (moduleName.empty()) {
        APP_LOGE("fail to EnableDynamicIcon due to moduleName is empty");
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to EnableDynamicIcon due to WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to EnableDynamicIcon due to write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to EnableDynamicIcon due to write moduleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(ExtendResourceManagerInterfaceCode::ENABLE_DYNAMIC_ICON, data, reply)) {
        APP_LOGE("fail to EnableDynamicIcon from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

ErrCode ExtendResourceManagerProxy::DisableDynamicIcon(const std::string &bundleName)
{
    APP_LOGD("begin to DisableDynamicIcon");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to DisableDynamicIcon due to bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to DisableDynamicIcon due to WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to DisableDynamicIcon due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(ExtendResourceManagerInterfaceCode::DISABLE_DYNAMIC_ICON, data, reply)) {
        APP_LOGE("fail to DisableDynamicIcon from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

ErrCode ExtendResourceManagerProxy::GetDynamicIcon(
    const std::string &bundleName, std::string &moduleName)
{
    APP_LOGD("begin to GetDynamicIcon");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to GetDynamicIcon due to bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetDynamicIcon due to WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetDynamicIcon due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(ExtendResourceManagerInterfaceCode::GET_DYNAMIC_ICON, data, reply)) {
        APP_LOGE("fail to GetDynamicIcon from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("GetDynamicIcon failed: %{public}d", ret);
        return ret;
    }

    moduleName = reply.ReadString();
    return ERR_OK;
}

ErrCode ExtendResourceManagerProxy::CreateFd(
    const std::string &fileName, int32_t &fd, std::string &path)
{
    APP_LOGD("begin to create fd");
    if (fileName.empty()) {
        APP_LOGE("fileName is empty");
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(fileName)) {
        APP_LOGE("write fileName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendRequest(ExtendResourceManagerInterfaceCode::CREATE_FD, data, reply)) {
        APP_LOGE("send request failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("reply return false");
        return ret;
    }
    fd = reply.ReadFileDescriptor();
    if (fd < 0) {
        APP_LOGE("invalid fd");
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    path = reply.ReadString();
    if (path.empty()) {
        APP_LOGE("invalid path");
        close(fd);
        return ERR_EXT_RESOURCE_MANAGER_INVALID_TARGET_DIR;
    }
    APP_LOGD("create fd success");
    return ERR_OK;
}

ErrCode ExtendResourceManagerProxy::CopyFiles(
    const std::vector<std::string> &sourceFiles, std::vector<std::string> &destFiles)
{
    APP_LOGD("begin to copy files");
    if (sourceFiles.empty()) {
        APP_LOGE("sourceFiles empty");
        return ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED;
    }
    std::vector<std::string> filePaths;
    if (!BundleFileUtil::CheckFilePath(sourceFiles, filePaths)) {
        APP_LOGE("CopyFiles CheckFilePath failed");
        return ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED;
    }
    for (const std::string &sourcePath : filePaths) {
        size_t pos = sourcePath.find_last_of(SEPARATOR);
        if (pos == std::string::npos) {
            APP_LOGE("invalid sourcePath");
            return ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED;
        }
        std::string fileName = sourcePath.substr(pos + 1);
        APP_LOGD("sourcePath : %{private}s, fileName : %{private}s", sourcePath.c_str(), fileName.c_str());
        int32_t sourceFd = open(sourcePath.c_str(), O_RDONLY);
        if (sourceFd < 0) {
            APP_LOGE("open file failed, errno:%{public}d", errno);
            return ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED;
        }
        int32_t destFd = -1;
        std::string destPath;
        auto ret = CreateFd(fileName, destFd, destPath);
        if ((ret != ERR_OK) || (destFd < 0) || (destPath.empty())) {
            APP_LOGE("create fd failed");
            close(sourceFd);
            return ret;
        }
        char buffer[DEFAULT_BUFFER_SIZE] = {0};
        int offset = -1;
        while ((offset = read(sourceFd, buffer, sizeof(buffer))) > 0) {
            if (write(destFd, buffer, offset) < 0) {
                APP_LOGE("write file to the temp dir failed, errno %{public}d", errno);
                close(sourceFd);
                close(destFd);
                return ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED;
            }
        }
        destFiles.emplace_back(destPath);
        close(sourceFd);
        fsync(destFd);
        close(destFd);
    }
    APP_LOGD("copy files success");
    return ERR_OK;
}

bool ExtendResourceManagerProxy::SendRequest(
    ExtendResourceManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("failed to send request %{public}d due to remote object null", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error %{public}d in transact %{public}d", result, code);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS