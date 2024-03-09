/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dynamic_icon_manager_proxy.h"

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
DynamicIconManagerProxy::DynamicIconManagerProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IDynamicIconManager>(object)
{
    APP_LOGI("create DynamicIconManagerProxy.");
}

DynamicIconManagerProxy::~DynamicIconManagerProxy()
{
    APP_LOGI("destroy DynamicIconManagerProxy.");
}

ErrCode DynamicIconManagerProxy::EnableDynamicIcon(const std::string &bundleName,
    const std::string &dynamicIconKey, const std::string &filePath)
{
    APP_LOGD("begin to EnableDynamicIcon");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty() || dynamicIconKey.empty() || filePath.empty()) {
        APP_LOGE("fail to EnableDynamicIcon due to param is empty.");
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to EnableDynamicIcon due to WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to EnableDynamicIcon due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(dynamicIconKey)) {
        APP_LOGE("fail to EnableDynamicIcon due to write dynamicIconKey fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(filePath)) {
        APP_LOGE("fail to EnableDynamicIcon due to write filePath fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(DynamicIconManagerInterfaceCode::ENABLE_DYNAMIC_ICON, data, reply)) {
        APP_LOGE("fail to EnableDynamicIcon from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

ErrCode DynamicIconManagerProxy::DisableDynamicIcon(const std::string &bundleName)
{
    APP_LOGD("begin to DisableDynamicIcon");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to DisableDynamicIcon due to param is empty.");
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to DisableDynamicIcon due to WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to DisableDynamicIcon due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(DynamicIconManagerInterfaceCode::DISABLE_DYNAMIC_ICON, data, reply)) {
        APP_LOGE("fail to DisableDynamicIcon from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

ErrCode DynamicIconManagerProxy::GetDynamicIcon(
    const std::string &bundleName, std::string &dynamicIconKey)
{
    APP_LOGD("begin to GetDynamicIcon");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to GetDynamicIcon due to param is empty.");
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetDynamicIcon due to WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetDynamicIcon due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(DynamicIconManagerInterfaceCode::GET_DYNAMIC_ICON, data, reply)) {
        APP_LOGE("fail to GetDynamicIcon from server.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("fail to GetDynamicIcon from server %{public}d", ret);
        return ret;
    }

    dynamicIconKey = reply.ReadString();
    return ERR_OK;
}

ErrCode DynamicIconManagerProxy::CreateFd(const std::string &fileName, int32_t &fd, std::string &path)
{
    APP_LOGD("begin to create fd.");
    if (fileName.empty()) {
        APP_LOGE("fileName is empty.");
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_PARAM_ERROR;
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
    if (!SendRequest(DynamicIconManagerInterfaceCode::CREATE_FD, data, reply)) {
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
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_CREATE_FD_FAILED;
    }
    path = reply.ReadString();
    if (path.empty()) {
        APP_LOGE("invalid path.");
        close(fd);
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_INVALID_TARGET_DIR;
    }
    APP_LOGD("create fd success.");
    return ERR_OK;
}

ErrCode DynamicIconManagerProxy::CopyFiles(
    const std::string &sourceFile, std::string &destFiles)
{
    return ERR_OK;
}

bool DynamicIconManagerProxy::SendRequest(
    DynamicIconManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply)
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