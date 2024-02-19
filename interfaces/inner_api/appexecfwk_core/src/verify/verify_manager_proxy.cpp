/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "verify_manager_proxy.h"

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

VerifyManagerProxy::VerifyManagerProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IVerifyManager>(object)
{
    APP_LOGI("create VerifyManagerProxy.");
}

VerifyManagerProxy::~VerifyManagerProxy()
{
    APP_LOGI("destroy VerifyManagerProxy.");
}

ErrCode VerifyManagerProxy::Verify(const std::vector<std::string> &abcPaths,
    const std::vector<std::string> &abcNames, bool flag)
{
    APP_LOGI("begin to call Verify.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (abcPaths.empty()) {
        APP_LOGE("Verify failed due to params error.");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(abcPaths)) {
        APP_LOGE("write abcPaths failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(abcNames)) {
        APP_LOGE("write abcNames failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(flag)) {
        APP_LOGE("write flag failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(VerifyManagerInterfaceCode::VERIFY, data, reply)) {
        APP_LOGE("SendRequest failed.");
        return ERR_BUNDLE_MANAGER_VERIFY_SEND_REQUEST_FAILED;
    }

    return reply.ReadInt32();
}

ErrCode VerifyManagerProxy::RemoveFiles(const std::vector<std::string> &abcPaths)
{
    APP_LOGI("RemoveFiles.");
    std::vector<std::string> realPaths;
    if (!BundleFileUtil::CheckFilePath(abcPaths, realPaths)) {
        APP_LOGE("RemoveFiles CheckFilePath failed");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    for (const auto &path : realPaths) {
        if (!BundleFileUtil::DeleteDir(path)) {
            APP_LOGW("RemoveFile %{private}s failed, errno:%{public}d", path.c_str(), errno);
        }
    }

    return ERR_OK;
}

ErrCode VerifyManagerProxy::CreateFd(const std::string &fileName, int32_t &fd, std::string &path)
{
    APP_LOGD("begin to create fd.");
    if (fileName.empty()) {
        APP_LOGE("fileName is empty.");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
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
    if (!SendRequest(VerifyManagerInterfaceCode::CREATE_FD, data, reply)) {
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
        return ERR_BUNDLE_MANAGER_VERIFY_CREATE_FD_FAILED;
    }
    path = reply.ReadString();
    if (path.empty()) {
        APP_LOGE("invalid path.");
        close(fd);
        return ERR_BUNDLE_MANAGER_VERIFY_INVALID_TARGET_DIR;
    }
    APP_LOGD("create fd success.");
    return ERR_OK;
}

ErrCode VerifyManagerProxy::CopyFiles(
    const std::vector<std::string> &sourceFiles, std::vector<std::string> &destFiles)
{
    APP_LOGD("begin to copy files.");
    if (sourceFiles.empty()) {
        APP_LOGE("sourceFiles empty.");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }
    std::vector<std::string> filePaths;
    if (!BundleFileUtil::CheckFilePath(sourceFiles, filePaths)) {
        APP_LOGE("CopyFiles CheckFilePath failed");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }
    for (const std::string &sourcePath : filePaths) {
        size_t pos = sourcePath.find_last_of(SEPARATOR);
        if (pos == std::string::npos) {
            APP_LOGE("invalid sourcePath.");
            return ERR_BUNDLE_MANAGER_VERIFY_INVALID_PATH;
        }
        std::string fileName = sourcePath.substr(pos + 1);
        APP_LOGD("sourcePath : %{private}s, fileName : %{private}s", sourcePath.c_str(), fileName.c_str());
        int32_t sourceFd = open(sourcePath.c_str(), O_RDONLY);
        if (sourceFd < 0) {
            APP_LOGE("open file failed, errno:%{public}d", errno);
            return ERR_BUNDLE_MANAGER_VERIFY_OPEN_SOURCE_FILE_FAILED;
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
                APP_LOGE("write file to the temp dir failed, errno %{public}d", errno);
                close(sourceFd);
                close(destFd);
                return ERR_BUNDLE_MANAGER_VERIFY_WRITE_FILE_FAILED;
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

ErrCode VerifyManagerProxy::DeleteAbc(const std::string &path)
{
    APP_LOGI("begin to call DeleteAbc.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (path.empty()) {
        APP_LOGE("DeleteAbc failed due to params error.");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }
    if (!data.WriteString(path)) {
        APP_LOGE("write path failed.");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(VerifyManagerInterfaceCode::DELETE_ABC, data, reply)) {
        APP_LOGE("SendRequest failed.");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_SEND_REQUEST_FAILED;
    }

    return reply.ReadInt32();
}

bool VerifyManagerProxy::SendRequest(
    VerifyManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("failed to send request %{public}d due to remote object null.", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error code %{public}d in transact %{public}d", result, code);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS