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

#include "quick_fix_manager_host.h"

#include <fcntl.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixManagerHost::QuickFixManagerHost()
{
    APP_LOGI("create QuickFixManagerHost.");
}

QuickFixManagerHost::~QuickFixManagerHost()
{
    APP_LOGI("destroy QuickFixManagerHost.");
}

int QuickFixManagerHost::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    APP_LOGI("QuickFixManagerHost OnRemoteRequest, message code : %{public}u", code);
    std::u16string descriptor = QuickFixManagerHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGE("descriptor invalid.");
        return OBJECT_NULL;
    }

    switch (code) {
        case IQuickFixManager::Message::DEPLOY_QUICK_FIX:
            return HandleDeployQuickFix(data, reply);
        case IQuickFixManager::Message::SWITCH_QUICK_FIX:
            return HandleSwitchQuickFix(data, reply);
        case IQuickFixManager::Message::DELETE_QUICK_FIX:
            return HandleDeleteQuickFix(data, reply);
        case IQuickFixManager::Message::CREATE_FD:
            return HandleCreateFd(data, reply);
        default:
            APP_LOGW("QuickFixManagerHost receive unknown code, code = %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

ErrCode QuickFixManagerHost::HandleDeployQuickFix(MessageParcel& data, MessageParcel& reply)
{
    APP_LOGI("begin to HandleDeployQuickFix.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::vector<std::string> bundleFilePaths;
    if (!data.ReadStringVector(&bundleFilePaths)) {
        APP_LOGE("read bundleFilePaths failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    if (object == nullptr) {
        APP_LOGE("read statusCallback failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IQuickFixStatusCallback> statusCallback = iface_cast<IQuickFixStatusCallback>(object);

    auto ret = DeployQuickFix(bundleFilePaths, statusCallback);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixManagerHost::HandleSwitchQuickFix(MessageParcel& data, MessageParcel& reply)
{
    APP_LOGI("begin to HandleSwitchQuickFix.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    bool enable = data.ReadBool();
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    if (object == nullptr) {
        APP_LOGE("read statusCallback failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IQuickFixStatusCallback> statusCallback = iface_cast<IQuickFixStatusCallback>(object);

    auto ret = SwitchQuickFix(bundleName, enable, statusCallback);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixManagerHost::HandleDeleteQuickFix(MessageParcel& data, MessageParcel& reply)
{
    APP_LOGI("begin to HandleDeleteQuickFix.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    if (object == nullptr) {
        APP_LOGE("read statusCallback failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IQuickFixStatusCallback> statusCallback = iface_cast<IQuickFixStatusCallback>(object);

    auto ret = DeleteQuickFix(bundleName, statusCallback);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixManagerHost::HandleCreateFd(MessageParcel& data, MessageParcel& reply)
{
    APP_LOGD("begin to HandleCreateFd.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string fileName = data.ReadString();
    int32_t fd = -1;
    std::string path;
    auto ret = CreateFd(fileName, fd, path);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed.");
        close(fd);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteFileDescriptor(fd)) {
            APP_LOGE("write fd failed.");
            close(fd);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        if (!reply.WriteString(path)) {
            APP_LOGE("write path failed.");
            close(fd);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    close(fd);
    return ERR_OK;
}
} // AppExecFwk
} // namespace OHOS
