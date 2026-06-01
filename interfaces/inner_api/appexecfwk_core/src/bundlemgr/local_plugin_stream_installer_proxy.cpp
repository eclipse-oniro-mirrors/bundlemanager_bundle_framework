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

#include "local_plugin_stream_installer_proxy.h"

#include <unistd.h>

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
LocalPluginStreamInstallerProxy::LocalPluginStreamInstallerProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<ILocalPluginStreamInstaller>(object)
{}

LocalPluginStreamInstallerProxy::~LocalPluginStreamInstallerProxy() = default;

int32_t LocalPluginStreamInstallerProxy::CreatePluginFileStream(const std::string &fileName)
{
    int32_t fd = Constants::DEFAULT_STREAM_FD;
    if (fileName.empty()) {
        APP_LOGE("CreatePluginFileStream failed due to empty fileName");
        return fd;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor()) || !data.WriteString(fileName)) {
        APP_LOGE("CreatePluginFileStream write parcel failed");
        return fd;
    }

    MessageParcel reply;
    if (!SendRequest(LocalPluginStreamInstallerInterfaceCode::CREATE_PLUGIN_FILE_STREAM, data, reply)) {
        APP_LOGE("CreatePluginFileStream send request failed");
        return fd;
    }

    int32_t sharedFd = reply.ReadFileDescriptor();
    if (sharedFd < 0) {
        APP_LOGE("CreatePluginFileStream failed due to invalid sharedFd");
        return fd;
    }

    fd = dup(sharedFd);
    close(sharedFd);
    return fd;
}

bool LocalPluginStreamInstallerProxy::CommitLocalPluginInstall()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("CommitLocalPluginInstall write parcel failed");
        return false;
    }

    MessageParcel reply;
    if (!SendRequest(LocalPluginStreamInstallerInterfaceCode::COMMIT_LOCAL_PLUGIN_INSTALL, data, reply)) {
        APP_LOGE("CommitLocalPluginInstall send request failed");
        return false;
    }
    return reply.ReadBool();
}

uint32_t LocalPluginStreamInstallerProxy::GetLocalPluginInstallerId() const
{
    return installerId_;
}

void LocalPluginStreamInstallerProxy::SetLocalPluginInstallerId(uint32_t installerId)
{
    installerId_ = installerId;
}

bool LocalPluginStreamInstallerProxy::SendRequest(
    LocalPluginStreamInstallerInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    auto remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("remote is nullptr");
        return false;
    }

    MessageOption option(MessageOption::TF_SYNC);
    auto ret = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    return ret == ERR_NONE;
}
}  // namespace AppExecFwk
}  // namespace OHOS