/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "bundle_stream_installer_host.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
BundleStreamInstallerHost::BundleStreamInstallerHost()
{
    LOG_D(BMS_TAG_INSTALLER, "create bundle stream installer host instance");
    init();
}

int BundleStreamInstallerHost::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    LOG_D(BMS_TAG_INSTALLER, "bundle stream installer host onReceived message, the message code is %{public}u", code);
    std::u16string descriptor = BundleStreamInstallerHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        LOG_W(BMS_TAG_INSTALLER, "[OnRemoteRequest] fail: invalid interface token");
        return OBJECT_NULL;
    }

    if (funcMap_.find(code) == funcMap_.end()) {
        LOG_W(BMS_TAG_INSTALLER, "[OnRemoteRequest] fail: unknown code");
        return IRemoteStub<IBundleStreamInstaller>::OnRemoteRequest(code, data, reply, option);
    }

    return funcMap_[code](data, reply);
}

ErrCode BundleStreamInstallerHost::HandleCreateStream(MessageParcel &data, MessageParcel &reply)
{
    std::string fileName = data.ReadString();
    int32_t fd = CreateStream(fileName);
    if (!reply.WriteFileDescriptor(fd)) {
        LOG_E(BMS_TAG_INSTALLER, "write fd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleStreamInstallerHost::HandleCreateSignatureFileStream(MessageParcel &data, MessageParcel &reply)
{
    std::string moduleName = data.ReadString();
    std::string fileName = data.ReadString();
    int32_t fd = CreateSignatureFileStream(moduleName, fileName);
    if (!reply.WriteFileDescriptor(fd)) {
        LOG_E(BMS_TAG_INSTALLER, "write fd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleStreamInstallerHost::HandleCreateSharedBundleStream(MessageParcel &data, MessageParcel &reply)
{
    std::string hspName = data.ReadString();
    uint32_t sharedBundleIdx = data.ReadUint32();
    int32_t fd = CreateSharedBundleStream(hspName, sharedBundleIdx);
    if (!reply.WriteFileDescriptor(fd)) {
        LOG_E(BMS_TAG_INSTALLER, "write fd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleStreamInstallerHost::HandleCreatePgoFileStream(MessageParcel &data, MessageParcel &reply)
{
    std::string moduleName = data.ReadString();
    std::string fileName = data.ReadString();
    int32_t fd = CreatePgoFileStream(moduleName, fileName);
    if (!reply.WriteFileDescriptor(fd)) {
        LOG_E(BMS_TAG_INSTALLER, "write fd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleStreamInstallerHost::HandleInstall(MessageParcel &data, MessageParcel &reply)
{
    if (!Install()) {
        reply.WriteBool(false);
        LOG_E(BMS_TAG_INSTALLER, "stream install failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    reply.WriteBool(true);
    return ERR_OK;
}

void BundleStreamInstallerHost::init()
{
    funcMap_.emplace(static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::CREATE_STREAM),
        [this](MessageParcel &data, MessageParcel &reply)->ErrCode {
            return this->HandleCreateStream(data, reply);
        });
    funcMap_.emplace(static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::CREATE_SHARED_BUNDLE_STREAM),
        [this](MessageParcel &data, MessageParcel &reply)->ErrCode {
            return this->HandleCreateSharedBundleStream(data, reply);
        });
    funcMap_.emplace(static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::STREAM_INSTALL),
        [this](MessageParcel &data, MessageParcel &reply)->ErrCode {
            return this->HandleInstall(data, reply);
        });
    funcMap_.emplace(static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::CREATE_SIGNATURE_FILE_STREAM),
        [this](MessageParcel &data, MessageParcel &reply)->ErrCode {
            return this->HandleCreateSignatureFileStream(data, reply);
        });
    funcMap_.emplace(static_cast<uint32_t>(BundleStreamInstallerInterfaceCode::CREATE_PGO_FILE_STREAM),
        [this](MessageParcel &data, MessageParcel &reply)->ErrCode {
            return this->HandleCreatePgoFileStream(data, reply);
        });
}
} // AppExecFwk
} // OHOS