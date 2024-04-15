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

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "ipc_types.h"
#include "parcel_macro.h"

namespace OHOS {
namespace AppExecFwk {
AppControlProxy::AppControlProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IAppControlMgr>(object)
{
    LOG_D(BMS_TAG_APP_CONTROL, "create AppControlProxy.");
}

AppControlProxy::~AppControlProxy()
{
    LOG_D(BMS_TAG_APP_CONTROL, "destroy AppControlProxy.");
}

ErrCode AppControlProxy::AddAppInstallControlRule(const std::vector<std::string> &appIds,
    const AppInstallControlRuleType controlRuleType, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call AddAppInstallControlRule.");
    if (appIds.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "AddAppInstallControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteStringVector(appIds, data)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write appIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        LOG_E(BMS_TAG_APP_CONTROL, "write controlRuleType failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::ADD_APP_INSTALL_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
    const std::vector<std::string> &appIds, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call DeleteAppInstallControlRule.");
    if (appIds.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "DeleteAppInstallControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        LOG_E(BMS_TAG_APP_CONTROL, "write controlRuleType failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteStringVector(appIds, data)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write appIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::DELETE_APP_INSTALL_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppInstallControlRule(
    const AppInstallControlRuleType controlRuleType, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call DeleteAppInstallControlRule.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        LOG_E(BMS_TAG_APP_CONTROL, "write controlRuleType failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::CLEAN_APP_INSTALL_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::GetAppInstallControlRule(
    const AppInstallControlRuleType controlRuleType, int32_t userId, std::vector<std::string> &appIds)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call GetAppInstallControlRule.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        LOG_E(BMS_TAG_APP_CONTROL, "write controlRuleType failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfos(AppControlManagerInterfaceCode::GET_APP_INSTALL_CONTROL_RULE, data, appIds);
}

ErrCode AppControlProxy::AddAppRunningControlRule(
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call AddAppRunningControlRule.");
    if (controlRules.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "AddAppRunningControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write AppRunningControlRule failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::ADD_APP_RUNNING_CONTROL_RULE, data, reply);
}
ErrCode AppControlProxy::DeleteAppRunningControlRule(
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call delete AppRunningControlRules.");
    if (controlRules.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "DeleteAppRunningControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write AppRunningControlRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::DELETE_APP_RUNNING_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppRunningControlRule(int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call delete appRunningControlRuleType.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::CLEAN_APP_RUNNING_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::GetAppRunningControlRule(int32_t userId, std::vector<std::string> &appIds)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call GetAppInstallControlRule.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfos(AppControlManagerInterfaceCode::GET_APP_RUNNING_CONTROL_RULE, data, appIds);
}

ErrCode AppControlProxy::GetAppRunningControlRule(
    const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRuleResult)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call GetAppRunningControlRuleResult.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_APP_CONTROL, "fail to GetMediaData due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfo<AppRunningControlRuleResult>(
        AppControlManagerInterfaceCode::GET_APP_RUNNING_CONTROL_RULE_RESULT, data, controlRuleResult);
}

ErrCode AppControlProxy::ConfirmAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId)
{
    if (callerBundleName.empty() || targetBundleName.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "ConfirmAppJumpControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(callerBundleName)) {
        LOG_E(BMS_TAG_APP_CONTROL, "fail to write callerBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetBundleName)) {
        LOG_E(BMS_TAG_APP_CONTROL, "fail to write targetBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::CONFIRM_APP_JUMP_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
{
    if (controlRules.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "DeleteAppJumpControlRule failed due to params error.");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write AppJumpControlRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::ADD_APP_JUMP_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write AppJumpControlRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(callerBundleName)) {
        LOG_E(BMS_TAG_APP_CONTROL, "fail to write callerBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE_BY_CALLER, data, reply);
}

ErrCode AppControlProxy::DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetBundleName)) {
        LOG_E(BMS_TAG_APP_CONTROL, "fail to write targetBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE_BY_TARGET, data, reply);
}

ErrCode AppControlProxy::GetAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId, AppJumpControlRule &controlRule)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(callerBundleName)) {
        LOG_E(BMS_TAG_APP_CONTROL, "fail to write callerBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetBundleName)) {
        LOG_E(BMS_TAG_APP_CONTROL, "fail to write targetBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfo<AppJumpControlRule>(
        AppControlManagerInterfaceCode::GET_APP_JUMP_CONTROL_RULE, data, controlRule);
}

ErrCode AppControlProxy::SetDisposedStatus(
    const std::string &appId, const Want &want, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "proxy begin to SetDisposedStatus.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write want failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(AppControlManagerInterfaceCode::SET_DISPOSED_STATUS, data, reply);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "SendRequest failed.");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::DeleteDisposedStatus(const std::string &appId, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "proxy begin to DeleteDisposedStatus.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(AppControlManagerInterfaceCode::DELETE_DISPOSED_STATUS, data, reply);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "SendRequest failed.");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::GetDisposedStatus(const std::string &appId, Want &want, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "proxy begin to GetDisposedStatus.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = GetParcelableInfo<Want>(AppControlManagerInterfaceCode::GET_DISPOSED_STATUS, data, want);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::SetDisposedRule(
    const std::string &appId, DisposedRule &disposedRule, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "proxy begin to SetDisposedRule.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&disposedRule)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write disposedRule failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(AppControlManagerInterfaceCode::SET_DISPOSED_RULE, data, reply);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "SendRequest failed.");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::GetDisposedRule(const std::string &appId, DisposedRule &rule, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "proxy begin to GetDisposedRule.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write appId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = GetParcelableInfo<DisposedRule>(AppControlManagerInterfaceCode::GET_DISPOSED_RULE, data, rule);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::GetAbilityRunningControlRule(
    const std::string &bundleName, int32_t userId, std::vector<DisposedRule> &rules)
{
    LOG_D(BMS_TAG_APP_CONTROL, "begin to call GetAbilityRunningControlRule.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_APP_CONTROL, "WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_APP_CONTROL, "write userId failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfos(AppControlManagerInterfaceCode::GET_ABILITY_RUNNING_CONTROL_RULE, data, rules);
}

bool AppControlProxy::WriteStringVector(const std::vector<std::string> &stringVector, MessageParcel &data)
{
    if (!data.WriteInt32(stringVector.size())) {
        LOG_E(BMS_TAG_APP_CONTROL, "write ParcelableVector failed");
        return false;
    }

    for (auto &string : stringVector) {
        if (!data.WriteString(string)) {
            LOG_E(BMS_TAG_APP_CONTROL, "write string failed");
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
        LOG_E(BMS_TAG_APP_CONTROL, "write ParcelableVector failed");
        return false;
    }

    for (const auto &parcelable : parcelableVector) {
        if (!data.WriteParcelable(&parcelable)) {
            LOG_E(BMS_TAG_APP_CONTROL, "write ParcelableVector failed");
            return false;
        }
    }
    return true;
}

template<typename T>
ErrCode AppControlProxy::GetParcelableInfo(AppControlManagerInterfaceCode code, MessageParcel& data, T& parcelableInfo)
{
    MessageParcel reply;
    int32_t ret = SendRequest(code, data, reply);
    if (ret != NO_ERROR) {
        LOG_E(BMS_TAG_APP_CONTROL, "get return error=%{public}d from host", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != NO_ERROR) {
        return ret;
    }
    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (info == nullptr) {
        LOG_E(BMS_TAG_APP_CONTROL, "ReadParcelable failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    parcelableInfo = *info;
    LOG_D(BMS_TAG_APP_CONTROL, "GetParcelableInfo success.");
    return NO_ERROR;
}

int32_t AppControlProxy::GetParcelableInfos(
    AppControlManagerInterfaceCode code, MessageParcel &data, std::vector<std::string> &stringVector)
{
    MessageParcel reply;
    int32_t ret = SendRequest(code, data, reply);
    if (ret != NO_ERROR) {
        return ret;
    }

    int32_t infoSize = reply.ReadInt32();
    CONTAINER_SECURITY_VERIFY(reply, infoSize, &stringVector);
    for (int32_t i = 0; i < infoSize; i++) {
        stringVector.emplace_back(reply.ReadString());
    }
    LOG_D(BMS_TAG_APP_CONTROL, "Read string vector success");
    return NO_ERROR;
}

template<typename T>
bool AppControlProxy::GetParcelableInfos(
    AppControlManagerInterfaceCode code, MessageParcel &data, std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    if (!SendRequest(code, data, reply)) {
        return false;
    }

    if (!reply.ReadBool()) {
        LOG_E(BMS_TAG_APP_CONTROL, "readParcelableInfo failed");
        return false;
    }

    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (info == nullptr) {
            LOG_E(BMS_TAG_APP_CONTROL, "Read Parcelable infos failed");
            return false;
        }
        parcelableInfos.emplace_back(*info);
    }
    LOG_D(BMS_TAG_APP_CONTROL, "get parcelable infos success");
    return true;
}

int32_t AppControlProxy::SendRequest(AppControlManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_APP_CONTROL, "failed to send request %{public}d due to remote object null.", code);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        LOG_E(BMS_TAG_APP_CONTROL, "receive error code %{public}d in transact %{public}d", result, code);
    }
    return result;
}
} // AppExecFwk
} // OHOS