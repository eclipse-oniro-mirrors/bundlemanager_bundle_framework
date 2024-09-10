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

VerifyManagerProxy::VerifyManagerProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IVerifyManager>(object)
{
    APP_LOGI("create VerifyManagerProxy");
}

VerifyManagerProxy::~VerifyManagerProxy()
{
    APP_LOGI("destroy VerifyManagerProxy");
}

ErrCode VerifyManagerProxy::Verify(const std::vector<std::string> &abcPaths)
{
    APP_LOGI("begin to call Verify");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (abcPaths.empty()) {
        APP_LOGE("Verify failed due to params error");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(abcPaths)) {
        APP_LOGE("write abcPaths failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(VerifyManagerInterfaceCode::VERIFY, data, reply)) {
        APP_LOGE("SendRequest failed");
        return ERR_BUNDLE_MANAGER_VERIFY_SEND_REQUEST_FAILED;
    }

    return reply.ReadInt32();
}

ErrCode VerifyManagerProxy::RemoveFiles(const std::vector<std::string> &abcPaths)
{
    APP_LOGI("RemoveFiles");
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

ErrCode VerifyManagerProxy::DeleteAbc(const std::string &path)
{
    APP_LOGI("begin to call DeleteAbc");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (path.empty()) {
        APP_LOGE("DeleteAbc failed due to params error");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }
    if (!data.WriteString(path)) {
        APP_LOGE("write path failed");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(VerifyManagerInterfaceCode::DELETE_ABC, data, reply)) {
        APP_LOGE("SendRequest failed");
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
        APP_LOGE("send request %{public}d failed due to remote object null", code);
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