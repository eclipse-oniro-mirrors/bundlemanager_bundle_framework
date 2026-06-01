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

#include "local_plugin_stream_installer_host.h"

#include "app_log_tag_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
LocalPluginStreamInstallerHost::LocalPluginStreamInstallerHost()
{
    LOG_D(BMS_TAG_INSTALLER, "create local plugin stream installer host instance");
    Init();
}

int LocalPluginStreamInstallerHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    LOG_D(BMS_TAG_INSTALLER, "local plugin stream installer host onReceived message, code:%{public}u", code);
    std::u16string descriptor = GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        LOG_W(BMS_TAG_INSTALLER, "invalid interface token");
        return OBJECT_NULL;
    }

    if (funcMap_.find(code) == funcMap_.end()) {
        LOG_W(BMS_TAG_INSTALLER, "unknown code");
        return IRemoteStub<ILocalPluginStreamInstaller>::OnRemoteRequest(code, data, reply, option);
    }

    return funcMap_[code](data, reply);
}

ErrCode LocalPluginStreamInstallerHost::HandleCreatePluginFileStream(MessageParcel &data, MessageParcel &reply)
{
    int32_t fd = CreatePluginFileStream(data.ReadString());
    if (!reply.WriteFileDescriptor(fd)) {
        LOG_E(BMS_TAG_INSTALLER, "write fd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode LocalPluginStreamInstallerHost::HandleCommitLocalPluginInstall(MessageParcel &data, MessageParcel &reply)
{
    if (!CommitLocalPluginInstall()) {
        reply.WriteBool(false);
        LOG_E(BMS_TAG_INSTALLER, "local plugin stream install failed");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    reply.WriteBool(true);
    return ERR_OK;
}

void LocalPluginStreamInstallerHost::Init()
{
    funcMap_.emplace(static_cast<uint32_t>(LocalPluginStreamInstallerInterfaceCode::CREATE_PLUGIN_FILE_STREAM),
        [this](MessageParcel &data, MessageParcel &reply) -> ErrCode {
            return this->HandleCreatePluginFileStream(data, reply);
        });
    funcMap_.emplace(static_cast<uint32_t>(LocalPluginStreamInstallerInterfaceCode::COMMIT_LOCAL_PLUGIN_INSTALL),
        [this](MessageParcel &data, MessageParcel &reply) -> ErrCode {
            return this->HandleCommitLocalPluginInstall(data, reply);
        });
}
}  // namespace AppExecFwk
}  // namespace OHOS