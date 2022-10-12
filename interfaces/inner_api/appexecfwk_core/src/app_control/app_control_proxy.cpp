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

#include "app_control_proxy.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
AppControlProxy::AppControlProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IAppControlMgr>(object)
{
    APP_LOGD("create AppControlProxy.");
}

AppControlProxy::~AppControlProxy()
{
    APP_LOGD("destroy AppControlProxy.");
}

ErrCode AppControlProxy::AddAppInstallControlRule(const std::vector<std::string> &appIds,
    const AppInstallControlRuleType controlRuleType, int32_t userId)
{
    APP_LOGD("begin to call AddAppInstallControlRule.");
    if (appIds.empty()) {
        APP_LOGE("AddAppInstallControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteStringVector(appIds, data)) {
        APP_LOGE("write appIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        APP_LOGE("write controlRuleType failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(IAppControlMgr::Message::ADD_APP_INSTALL_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
    const std::vector<std::string> &appIds, int32_t userId)
{
    APP_LOGD("begin to call DeleteAppInstallControlRule.");
    if (appIds.empty()) {
        APP_LOGE("DeleteAppInstallControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        APP_LOGE("write controlRuleType failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteStringVector(appIds, data)) {
        APP_LOGE("write appIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(IAppControlMgr::Message::DELETE_APP_INSTALL_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppInstallControlRule(
    const AppInstallControlRuleType controlRuleType, int32_t userId)
{
    APP_LOGD("begin to call DeleteAppInstallControlRule.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        APP_LOGE("write controlRuleType failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(IAppControlMgr::Message::CLEAN_APP_INSTALL_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::GetAppInstallControlRule(
    const AppInstallControlRuleType controlRuleType, int32_t userId, std::vector<std::string> &appIds)
{
    APP_LOGD("begin to call GetAppInstallControlRule.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        APP_LOGE("write controlRuleType failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfos(IAppControlMgr::Message::GET_APP_INSTALL_CONTROL_RULE, data, appIds);
}

ErrCode AppControlProxy::AddAppRunningControlRule(
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    APP_LOGD("begin to call AddAppRunningControlRule.");
    if (controlRules.empty()) {
        APP_LOGE("AddAppRunningControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        APP_LOGE("write AppRunningControlRule failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(IAppControlMgr::Message::ADD_APP_RUNNING_CONTROL_RULE, data, reply);
}
ErrCode AppControlProxy::DeleteAppRunningControlRule(
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    APP_LOGD("begin to call delete AppRunningControlRules.");
    if (controlRules.empty()) {
        APP_LOGE("DeleteAppRunningControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        APP_LOGE("write AppRunningControlRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(IAppControlMgr::Message::DELETE_APP_RUNNING_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppRunningControlRule(int32_t userId)
{
    APP_LOGD("begin to call delete appRunningControlRuleType.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(IAppControlMgr::Message::CLEAN_APP_RUNNING_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::GetAppRunningControlRule(int32_t userId, std::vector<std::string> &appIds)
{
    APP_LOGD("begin to call GetAppInstallControlRule.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfos(IAppControlMgr::Message::GET_APP_RUNNING_CONTROL_RULE, data, appIds);
}

ErrCode AppControlProxy::GetAppRunningControlRule(
    const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRuleResult)
{
    APP_LOGD("begin to call GetAppRunningControlRuleResult.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetMediaData due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfo<AppRunningControlRuleResult>(
        IAppControlMgr::Message::GET_APP_RUNNING_CONTROL_RULE_RESULT, data, controlRuleResult);
}

ErrCode AppControlProxy::SetDisposedStatus(const std::string &appId, const Want &want)
{
    APP_LOGD("proxy begin to SetDisposedStatus.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        APP_LOGE("write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("write want failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(IAppControlMgr::Message::SET_DISPOSED_STATUS, data, reply);
    if (ret != ERR_OK) {
        APP_LOGE("SendRequest failed.");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::DeleteDisposedStatus(const std::string &appId)
{
    APP_LOGD("proxy begin to DeleteDisposedStatus.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        APP_LOGE("write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode ret = SendRequest(IAppControlMgr::Message::DELETE_DISPOSED_STATUS, data, reply);
    if (ret != ERR_OK) {
        APP_LOGE("SendRequest failed.");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::GetDisposedStatus(const std::string &appId, Want &want)
{
    APP_LOGD("proxy begin to GetDisposedStatus.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        APP_LOGE("write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = GetParcelableInfo<Want>(IAppControlMgr::Message::GET_DISPOSED_STATUS, data, want);
    if (ret != ERR_OK) {
        APP_LOGE("host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

bool AppControlProxy::WriteStringVector(const std::vector<std::string> &stringVector, MessageParcel &data)
{
    if (!data.WriteInt32(stringVector.size())) {
        APP_LOGE("write ParcelableVector failed");
        return false;
    }

    for (auto &string : stringVector) {
        if (!data.WriteString(string)) {
            APP_LOGE("write string failed");
            return false;
        }
    }
    return true;
}

template<typename T>
bool AppControlProxy::WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data)
{
    data.SetDataCapacity(Constants::CAPACITY_SIZE);
    if (!data.WriteInt32(parcelableVector.size())) {
        APP_LOGE("write ParcelableVector failed");
        return false;
    }

    for (const auto &parcelable : parcelableVector) {
        if (!data.WriteParcelable(&parcelable)) {
            APP_LOGE("write ParcelableVector failed");
            return false;
        }
    }
    return true;
}

template<typename T>
ErrCode AppControlProxy::GetParcelableInfo(IAppControlMgr::Message code, MessageParcel& data, T& parcelableInfo)
{
    MessageParcel reply;
    int32_t ret = SendRequest(code, data, reply);
    if (ret != NO_ERROR) {
        APP_LOGE("get return error=%{public}d from host", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != NO_ERROR) {
        return ret;
    }
    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (info == nullptr) {
        APP_LOGE("ReadParcelable failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    parcelableInfo = *info;
    APP_LOGI("GetParcelableInfo success.");
    return NO_ERROR;
}

int32_t AppControlProxy::GetParcelableInfos(
    IAppControlMgr::Message code, MessageParcel &data, std::vector<std::string> &stringVector)
{
    MessageParcel reply;
    int32_t ret = SendRequest(code, data, reply);
    if (ret != NO_ERROR) {
        return ret;
    }

    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; i++) {
        stringVector.emplace_back(reply.ReadString());
    }
    APP_LOGD("Read string vector success");
    return NO_ERROR;
}

int32_t AppControlProxy::SendRequest(IAppControlMgr::Message code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("failed to send request %{public}d due to remote object null.", code);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error code %{public}d in transact %{public}d", result, code);
    }
    return result;
}
} // AppExecFwk
} // OHOS