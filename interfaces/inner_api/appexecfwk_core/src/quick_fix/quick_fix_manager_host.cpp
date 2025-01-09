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

#include "quick_fix_manager_host.h"

#include <fcntl.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "app_log_tag_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixManagerHost::QuickFixManagerHost()
{
    LOG_I(BMS_TAG_DEFAULT, "create QuickFixManagerHost");
}

QuickFixManagerHost::~QuickFixManagerHost()
{
    LOG_I(BMS_TAG_DEFAULT, "destroy QuickFixManagerHost");
}

int QuickFixManagerHost::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    BundleMemoryGuard memoryGuard;
    LOG_I(BMS_TAG_DEFAULT, "QuickFixManagerHost OnRemoteRequest, message code : %{public}u", code);
    std::u16string descriptor = QuickFixManagerHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        LOG_E(BMS_TAG_DEFAULT, "descriptor invalid");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(QuickFixManagerInterfaceCode::DEPLOY_QUICK_FIX):
            return HandleDeployQuickFix(data, reply);
        case static_cast<uint32_t>(QuickFixManagerInterfaceCode::SWITCH_QUICK_FIX):
            return HandleSwitchQuickFix(data, reply);
        case static_cast<uint32_t>(QuickFixManagerInterfaceCode::DELETE_QUICK_FIX):
            return HandleDeleteQuickFix(data, reply);
        case static_cast<uint32_t>(QuickFixManagerInterfaceCode::CREATE_FD):
            return HandleCreateFd(data, reply);
        default:
            LOG_W(BMS_TAG_DEFAULT, "QuickFixManagerHost receive unknown code, code = %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

ErrCode QuickFixManagerHost::HandleDeployQuickFix(MessageParcel& data, MessageParcel& reply)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to HandleDeployQuickFix");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::vector<std::string> bundleFilePaths;
    if (!data.ReadStringVector(&bundleFilePaths)) {
        LOG_E(BMS_TAG_DEFAULT, "read bundleFilePaths failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isDebug = data.ReadBool();
    std::string targetPath = data.ReadString();
    bool isReplace = data.ReadBool();
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "read statusCallback failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IQuickFixStatusCallback> statusCallback = iface_cast<IQuickFixStatusCallback>(object);

    auto ret = DeployQuickFix(bundleFilePaths, statusCallback, isDebug, targetPath, isReplace);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixManagerHost::HandleSwitchQuickFix(MessageParcel& data, MessageParcel& reply)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to HandleSwitchQuickFix");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    bool enable = data.ReadBool();
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "read statusCallback failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IQuickFixStatusCallback> statusCallback = iface_cast<IQuickFixStatusCallback>(object);

    auto ret = SwitchQuickFix(bundleName, enable, statusCallback);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixManagerHost::HandleDeleteQuickFix(MessageParcel& data, MessageParcel& reply)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to HandleDeleteQuickFix");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "read statusCallback failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IQuickFixStatusCallback> statusCallback = iface_cast<IQuickFixStatusCallback>(object);

    auto ret = DeleteQuickFix(bundleName, statusCallback);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixManagerHost::HandleCreateFd(MessageParcel& data, MessageParcel& reply)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to HandleCreateFd");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string fileName = data.ReadString();
    int32_t fd = -1;
    std::string path;
    auto ret = CreateFd(fileName, fd, path);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        close(fd);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteFileDescriptor(fd)) {
            LOG_E(BMS_TAG_DEFAULT, "write fd failed");
            close(fd);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        if (!reply.WriteString(path)) {
            LOG_E(BMS_TAG_DEFAULT, "write path failed");
            close(fd);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    close(fd);
    return ERR_OK;
}
} // AppExecFwk
} // namespace OHOS
