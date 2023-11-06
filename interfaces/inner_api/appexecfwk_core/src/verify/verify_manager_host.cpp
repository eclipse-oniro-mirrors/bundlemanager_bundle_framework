/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "verify_manager_host.h"

#include <fcntl.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
VerifyManagerHost::VerifyManagerHost()
{
    APP_LOGI("create VerifyManagerHost.");
}

VerifyManagerHost::~VerifyManagerHost()
{
    APP_LOGI("destroy VerifyManagerHost.");
}

int VerifyManagerHost::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGI("VerifyManagerHost OnRemoteRequest, message code : %{public}u", code);
    std::u16string descriptor = VerifyManagerHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGE("descriptor invalid.");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(VerifyManagerInterfaceCode::VERIFY):
            return HandleVerify(data, reply);
        case static_cast<uint32_t>(VerifyManagerInterfaceCode::CREATE_FD):
            return HandleCreateFd(data, reply);
        default:
            APP_LOGW("VerifyManagerHost receive unknown code, code = %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

ErrCode VerifyManagerHost::HandleVerify(MessageParcel& data, MessageParcel& reply)
{
    APP_LOGI("begin to HandleVerify.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::vector<std::string> abcPaths;
    if (!data.ReadStringVector(&abcPaths)) {
        APP_LOGE("read abcPaths failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    bool flag = data.ReadBool();
    auto ret = Verify(abcPaths, flag);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode VerifyManagerHost::HandleCreateFd(MessageParcel& data, MessageParcel& reply)
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
