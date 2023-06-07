/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "quick_fix_manager_proxy.h"

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

QuickFixManagerProxy::QuickFixManagerProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IQuickFixManager>(object)
{
    APP_LOGI("create QuickFixManagerProxy.");
}

QuickFixManagerProxy::~QuickFixManagerProxy()
{
    APP_LOGI("destroy QuickFixManagerProxy.");
}

ErrCode QuickFixManagerProxy::DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    APP_LOGI("begin to call DeployQuickFix.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleFilePaths.empty() || (statusCallback == nullptr)) {
        APP_LOGE("DeployQuickFix failed due to params error.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(bundleFilePaths)) {
        APP_LOGE("write bundleFilePaths failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteObject<IRemoteObject>(statusCallback->AsObject())) {
        APP_LOGE("write parcel failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(IQuickFixManager::Message::DEPLOY_QUICK_FIX, data, reply)) {
        APP_LOGE("SendRequest failed.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_SEND_REQUEST_FAILED;
    }

    return reply.ReadInt32();
}

ErrCode QuickFixManagerProxy::SwitchQuickFix(const std::string &bundleName, bool enable,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    APP_LOGI("begin to call SwitchQuickFix.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleName.empty() || (statusCallback == nullptr)) {
        APP_LOGE("SwitchQuickFix failed due to params error.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(enable)) {
        APP_LOGE("write enable failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteObject<IRemoteObject>(statusCallback->AsObject())) {
        APP_LOGE("write parcel failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(IQuickFixManager::Message::SWITCH_QUICK_FIX, data, reply)) {
        APP_LOGE("SendRequest failed.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_SEND_REQUEST_FAILED;
    }

    return reply.ReadInt32();
}

ErrCode QuickFixManagerProxy::DeleteQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    APP_LOGI("begin to call DeleteQuickFix.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleName.empty() || (statusCallback == nullptr)) {
        APP_LOGE("DeleteQuickFix failed due to params error.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteObject<IRemoteObject>(statusCallback->AsObject())) {
        APP_LOGE("write parcel failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(IQuickFixManager::Message::DELETE_QUICK_FIX, data, reply)) {
        APP_LOGE("SendRequest failed.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_SEND_REQUEST_FAILED;
    }

    return reply.ReadInt32();
}

ErrCode QuickFixManagerProxy::CreateFd(const std::string &fileName, int32_t &fd, std::string &path)
{
    APP_LOGD("begin to create fd.");
    if (fileName.empty()) {
        APP_LOGE("fileName is empty.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interface token failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(fileName)) {
        APP_LOGE("write fileName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendRequest(IQuickFixManager::Message::CREATE_FD, data, reply)) {
        APP_LOGE("send request failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("reply return false.");
        return ret;
    }
    fd = reply.ReadFileDescriptor();
    if (fd < 0) {
        APP_LOGE("invalid fd.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_CREATE_FD_FAILED;
    }
    path = reply.ReadString();
    if (path.empty()) {
        APP_LOGE("invalid path.");
        close(fd);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_TARGET_DIR;
    }
    APP_LOGD("create fd success.");
    return ERR_OK;
}

ErrCode QuickFixManagerProxy::CopyFiles(
    const std::vector<std::string> &sourceFiles, std::vector<std::string> &destFiles)
{
    APP_LOGD("begin to copy files.");
    if (sourceFiles.empty()) {
        APP_LOGE("sourceFiles empty.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    std::vector<std::string> hqfFilePaths;
    if (!BundleFileUtil::CheckFilePath(sourceFiles, hqfFilePaths)) {
        APP_LOGE("CopyFiles CheckFilePath failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    for (const std::string &sourcePath : hqfFilePaths) {
        size_t pos = sourcePath.find_last_of(SEPARATOR);
        if (pos == std::string::npos) {
            APP_LOGE("invalid sourcePath.");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
        }
        std::string fileName = sourcePath.substr(pos + 1);
        APP_LOGD("sourcePath : %{private}s, fileName : %{private}s", sourcePath.c_str(), fileName.c_str());
        int32_t sourceFd = open(sourcePath.c_str(), O_RDONLY);
        if (sourceFd < 0) {
            APP_LOGE("open file failed.");
            return ERR_BUNDLEMANAGER_QUICK_FIX_OPEN_SOURCE_FILE_FAILED;
        }
        int32_t destFd = -1;
        std::string destPath;
        auto ret = CreateFd(fileName, destFd, destPath);
        if ((ret != ERR_OK) || (destFd < 0) || (destPath.empty())) {
            APP_LOGE("create fd failed.");
            close(sourceFd);
            return ret;
        }
        char buffer[DEFAULT_BUFFER_SIZE] = {0};
        int offset = -1;
        while ((offset = read(sourceFd, buffer, sizeof(buffer))) > 0) {
            if (write(destFd, buffer, offset) < 0) {
                close(sourceFd);
                close(destFd);
                return ERR_BUNDLEMANAGER_QUICK_FIX_WRITE_FILE_FAILED;
            }
        }
        destFiles.emplace_back(destPath);
        close(sourceFd);
        fsync(destFd);
        close(destFd);
    }
    APP_LOGD("copy files success.");
    return ERR_OK;
}

bool QuickFixManagerProxy::SendRequest(IQuickFixManager::Message code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("failed to send request %{public}d due to remote object null.", code);
        return false;
    }
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error code %{public}d in transact %{public}d", result, code);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS