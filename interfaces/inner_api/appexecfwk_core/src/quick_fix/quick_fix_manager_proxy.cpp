/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

#include "app_log_tag_wrapper.h"
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
    LOG_I(BMS_TAG_DEFAULT, "create QuickFixManagerProxy");
}

QuickFixManagerProxy::~QuickFixManagerProxy()
{
    LOG_I(BMS_TAG_DEFAULT, "destroy QuickFixManagerProxy");
}

ErrCode QuickFixManagerProxy::DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
    const sptr<IQuickFixStatusCallback> &statusCallback, bool isDebug, const std::string &inputTargetPath,
    bool isReplace)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to call DeployQuickFix");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleFilePaths.empty() || (statusCallback == nullptr)) {
        LOG_E(BMS_TAG_DEFAULT, "DeployQuickFix failed due to params error");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    std::string targetPath = inputTargetPath;
    if (targetPath.find(".") != std::string::npos ||
        targetPath.find("..") != std::string::npos ||
        targetPath.find("/") != std::string::npos) {
        LOG_E(BMS_TAG_DEFAULT, "input targetPath is invalid");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(bundleFilePaths)) {
        LOG_E(BMS_TAG_DEFAULT, "write bundleFilePaths failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isDebug)) {
        LOG_E(BMS_TAG_DEFAULT, "write isDebug failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetPath)) {
        LOG_E(BMS_TAG_DEFAULT, "write targetPath failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isReplace)) {
        LOG_E(BMS_TAG_DEFAULT, "write isReplace failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(statusCallback->AsObject())) {
        LOG_E(BMS_TAG_DEFAULT, "write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(QuickFixManagerInterfaceCode::DEPLOY_QUICK_FIX, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_SEND_REQUEST_FAILED;
    }

    return reply.ReadInt32();
}

ErrCode QuickFixManagerProxy::SwitchQuickFix(const std::string &bundleName, bool enable,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to call SwitchQuickFix");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleName.empty() || (statusCallback == nullptr)) {
        LOG_E(BMS_TAG_DEFAULT, "SwitchQuickFix failed due to params error");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(enable)) {
        LOG_E(BMS_TAG_DEFAULT, "write enable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(statusCallback->AsObject())) {
        LOG_E(BMS_TAG_DEFAULT, "write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(QuickFixManagerInterfaceCode::SWITCH_QUICK_FIX, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_SEND_REQUEST_FAILED;
    }

    return reply.ReadInt32();
}

ErrCode QuickFixManagerProxy::DeleteQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to call DeleteQuickFix");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleName.empty() || (statusCallback == nullptr)) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteQuickFix failed due to params error");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(statusCallback->AsObject())) {
        LOG_E(BMS_TAG_DEFAULT, "write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(QuickFixManagerInterfaceCode::DELETE_QUICK_FIX, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_SEND_REQUEST_FAILED;
    }

    return reply.ReadInt32();
}

ErrCode QuickFixManagerProxy::CreateFd(const std::string &fileName, int32_t &fd, std::string &path)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to create fd");
    if (fileName.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "fileName is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(fileName)) {
        LOG_E(BMS_TAG_DEFAULT, "write fileName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendRequest(QuickFixManagerInterfaceCode::CREATE_FD, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "send request failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "reply return false");
        return ret;
    }
    fd = reply.ReadFileDescriptor();
    if (fd < 0) {
        LOG_E(BMS_TAG_DEFAULT, "invalid fd");
        return ERR_BUNDLEMANAGER_QUICK_FIX_CREATE_FD_FAILED;
    }
    path = reply.ReadString();
    if (path.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "invalid path");
        close(fd);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_TARGET_DIR;
    }
    LOG_D(BMS_TAG_DEFAULT, "create fd success");
    return ERR_OK;
}

ErrCode QuickFixManagerProxy::CopyFiles(
    const std::vector<std::string> &sourceFiles, std::vector<std::string> &destFiles)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to copy files");
    if (sourceFiles.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "sourceFiles empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    std::vector<std::string> hqfFilePaths;
    if (!BundleFileUtil::CheckFilePath(sourceFiles, hqfFilePaths)) {
        LOG_E(BMS_TAG_DEFAULT, "CopyFiles CheckFilePath failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    for (const std::string &sourcePath : hqfFilePaths) {
        size_t pos = sourcePath.find_last_of(SEPARATOR);
        if (pos == std::string::npos) {
            LOG_E(BMS_TAG_DEFAULT, "invalid sourcePath");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
        }
        std::string fileName = sourcePath.substr(pos + 1);
        LOG_D(BMS_TAG_DEFAULT, "sourcePath:%{private}s fileName:%{private}s", sourcePath.c_str(), fileName.c_str());
        int32_t sourceFd = open(sourcePath.c_str(), O_RDONLY);
        if (sourceFd < 0) {
            LOG_E(BMS_TAG_DEFAULT, "open file failed, errno:%{public}d", errno);
            return ERR_BUNDLEMANAGER_QUICK_FIX_OPEN_SOURCE_FILE_FAILED;
        }
        int32_t destFd = -1;
        std::string destPath;
        auto ret = CreateFd(fileName, destFd, destPath);
        if ((ret != ERR_OK) || (destFd < 0) || (destPath.empty())) {
            LOG_E(BMS_TAG_DEFAULT, "create fd failed");
            close(sourceFd);
            return ret;
        }
        char buffer[DEFAULT_BUFFER_SIZE] = {0};
        int offset = -1;
        while ((offset = read(sourceFd, buffer, sizeof(buffer))) > 0) {
            if (write(destFd, buffer, offset) < 0) {
                LOG_E(BMS_TAG_DEFAULT, "write file to the temp dir failed, errno %{public}d", errno);
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
    LOG_D(BMS_TAG_DEFAULT, "copy files success");
    return ERR_OK;
}

bool QuickFixManagerProxy::SendRequest(QuickFixManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "failed to send request %{public}hhu due to remote object null", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        LOG_E(BMS_TAG_DEFAULT, "receive error code %{public}d in transact %{public}hhu", result, code);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS