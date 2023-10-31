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

#include "bundle_stream_installer_proxy.h"

#include <unistd.h>

#include "app_log_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
BundleStreamInstallerProxy::BundleStreamInstallerProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IBundleStreamInstaller>(object)
{
    APP_LOGD("create bundle stream installer proxy instance");
}

BundleStreamInstallerProxy:: ~BundleStreamInstallerProxy()
{
    APP_LOGD("destory bundle stream installer proxy instance");
}

int32_t BundleStreamInstallerProxy::CreateStream(const std::string &fileName)
{
    APP_LOGD("bundle stream installer proxy create stream begin");
    int32_t fd = Constants::DEFAULT_STREAM_FD;
    if (fileName.empty()) {
        APP_LOGE("BundleStreamInstallerProxy create stream faile due to empty fileName");
        return fd;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(BundleStreamInstallerProxy::GetDescriptor())) {
        APP_LOGE("fail to CreateStream due to write interface token fail");
        return fd;
    }
    if (!data.WriteString(fileName)) {
        APP_LOGE("fail to CreateStream due to write fileName fail");
        return fd;
    }

    MessageParcel reply;
    if (!SendStreamInstallRequest(BundleStreamInstallerInterfaceCode::CREATE_STREAM, data, reply)) {
        APP_LOGE("fail to SendStreamInstallRequest");
        return fd;
    }

    int32_t sharedFd = reply.ReadFileDescriptor();
    if (sharedFd < 0) {
        APP_LOGE("fail to CreateStream");
        return fd;
    }

    fd = dup(sharedFd);
    close(sharedFd);

    APP_LOGD("bundle stream installer proxy create stream end");
    return fd;
}

int32_t BundleStreamInstallerProxy::CreateSignatureFileStream(const std::string &moduleName,
    const std::string &fileName)
{
    APP_LOGD("bundle stream installer proxy create signature file stream begin");
    int32_t fd = Constants::DEFAULT_STREAM_FD;
    if (moduleName.empty() || fileName.empty()) {
        APP_LOGE("BundleStreamInstallerProxy create stream faile due to empty fileName or moduleName");
        return fd;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(BundleStreamInstallerProxy::GetDescriptor())) {
        APP_LOGE("fail to CreateSignatureFileStream due to write interface token fail");
        return fd;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to CreateSignatureFileStream due to write moduleName fail");
        return fd;
    }
    if (!data.WriteString(fileName)) {
        APP_LOGE("fail to CreateSignatureFileStream due to write fileName fail");
        return fd;
    }
    MessageParcel reply;
    if (!SendStreamInstallRequest(BundleStreamInstallerInterfaceCode::CREATE_SIGNATURE_FILE_STREAM, data, reply)) {
        APP_LOGE("fail to SendStreamInstallRequest");
        return fd;
    }

    int32_t sharedFd = reply.ReadFileDescriptor();
    if (sharedFd < 0) {
        APP_LOGE("fail to CreateSignatureFileStream");
        return fd;
    }

    fd = dup(sharedFd);
    close(sharedFd);

    APP_LOGD("bundle stream installer proxy create stream end");
    return fd;
}

int32_t BundleStreamInstallerProxy::CreateSharedBundleStream(const std::string &hspName, uint32_t index)
{
    APP_LOGD("bundle stream installer proxy create shared bundle stream begin");
    int32_t fd = Constants::DEFAULT_STREAM_FD;
    if (hspName.empty()) {
        APP_LOGE("BundleStreamInstallerProxy create shared bundle stream faile due to empty hspName");
        return fd;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(BundleStreamInstallerProxy::GetDescriptor())) {
        APP_LOGE("fail to CreateSharedBundleStream due to write interface token fail");
        return fd;
    }
    if (!data.WriteString(hspName)) {
        APP_LOGE("fail to CreateSharedBundleStream due to write hspName fail");
        return fd;
    }
    if (!data.WriteUint32(index)) {
        APP_LOGE("fail to CreateSharedBundleStream due to write sharedBundleIdx fail");
        return fd;
    }

    MessageParcel reply;
    if (!SendStreamInstallRequest(BundleStreamInstallerInterfaceCode::CREATE_SHARED_BUNDLE_STREAM, data, reply)) {
        APP_LOGE("fail to SendStreamInstallRequest");
        return fd;
    }

    int32_t sharedFd = reply.ReadFileDescriptor();
    if (sharedFd < 0) {
        APP_LOGE("fail to CreateSharedBundleStream");
        return fd;
    }

    fd = dup(sharedFd);
    close(sharedFd);

    APP_LOGD("bundle stream installer proxy create shared bundle stream end");
    return fd;
}

int32_t BundleStreamInstallerProxy::CreatePgoFileStream(const std::string &moduleName,
    const std::string &fileName)
{
    APP_LOGD("create pgo file stream begin");
    int32_t fd = Constants::DEFAULT_STREAM_FD;
    if (moduleName.empty() || fileName.empty()) {
        APP_LOGE("create stream faile due to empty fileName or moduleName");
        return fd;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(BundleStreamInstallerProxy::GetDescriptor())) {
        APP_LOGE("fail to CreatePgoFileStream due to write interface token fail");
        return fd;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to CreatePgoFileStream due to write moduleName fail");
        return fd;
    }
    if (!data.WriteString(fileName)) {
        APP_LOGE("fail to CreatePgoFileStream due to write fileName fail");
        return fd;
    }
    MessageParcel reply;
    if (!SendStreamInstallRequest(BundleStreamInstallerInterfaceCode::CREATE_PGO_FILE_STREAM, data, reply)) {
        APP_LOGE("fail to SendStreamInstallRequest");
        return fd;
    }

    int32_t sharedFd = reply.ReadFileDescriptor();
    if (sharedFd < 0) {
        APP_LOGE("fail to CreatePgoFileStream");
        return fd;
    }

    fd = dup(sharedFd);
    close(sharedFd);

    APP_LOGD("create pgo file stream end");
    return fd;
}

bool BundleStreamInstallerProxy::Install()
{
    APP_LOGD("bundle stream installer proxy install begin");
    MessageParcel data;
    if (!data.WriteInterfaceToken(BundleStreamInstallerProxy::GetDescriptor())) {
        APP_LOGE("fail to Install due to write interface token fail");
        return false;
    }

    MessageParcel reply;
    bool res = SendStreamInstallRequest(BundleStreamInstallerInterfaceCode::STREAM_INSTALL, data, reply);
    if (!res) {
        APP_LOGE("fail to SendStreamInstallRequest");
        return res;
    }
    APP_LOGD("bundle stream installer proxy install end");
    return true;
}

uint32_t BundleStreamInstallerProxy::GetInstallerId() const
{
    return installerId_;
}

void BundleStreamInstallerProxy::SetInstallerId(uint32_t installerId)
{
    installerId_ = installerId;
}

bool BundleStreamInstallerProxy::SendStreamInstallRequest(BundleStreamInstallerInterfaceCode code, MessageParcel& data,
    MessageParcel& reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail to send request, for remote is nullptr");
        return false;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (ret != NO_ERROR) {
        APP_LOGE("fail to sendRequest, for transact is failed and error code is: %{public}d", ret);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS