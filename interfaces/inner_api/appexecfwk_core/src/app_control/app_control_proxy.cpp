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
    LOG_D(BMS_TAG_DEFAULT, "create AppControlProxy");
}

AppControlProxy::~AppControlProxy()
{
    LOG_D(BMS_TAG_DEFAULT, "destroy AppControlProxy");
}

ErrCode AppControlProxy::AddAppInstallControlRule(const std::vector<std::string> &appIds,
    const AppInstallControlRuleType controlRuleType, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call AddAppInstallControlRule");
    if (appIds.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "AddAppInstallControlRule failed due to params error");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteStringVector(appIds, data)) {
        LOG_E(BMS_TAG_DEFAULT, "write appIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        LOG_E(BMS_TAG_DEFAULT, "write controlRuleType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::ADD_APP_INSTALL_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
    const std::vector<std::string> &appIds, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call DeleteAppInstallControlRule");
    if (appIds.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteAppInstallControlRule failed due to params error");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        LOG_E(BMS_TAG_DEFAULT, "write controlRuleType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteStringVector(appIds, data)) {
        LOG_E(BMS_TAG_DEFAULT, "write appIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::DELETE_APP_INSTALL_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppInstallControlRule(
    const AppInstallControlRuleType controlRuleType, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call DeleteAppInstallControlRule");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        LOG_E(BMS_TAG_DEFAULT, "write controlRuleType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::CLEAN_APP_INSTALL_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::GetAppInstallControlRule(
    const AppInstallControlRuleType controlRuleType, int32_t userId, std::vector<std::string> &appIds)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call GetAppInstallControlRule");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(controlRuleType))) {
        LOG_E(BMS_TAG_DEFAULT, "write controlRuleType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfos(AppControlManagerInterfaceCode::GET_APP_INSTALL_CONTROL_RULE, data, appIds);
}

ErrCode AppControlProxy::AddAppRunningControlRule(
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call AddAppRunningControlRule");
    if (controlRules.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "AddAppRunningControlRule failed due to params error");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        LOG_E(BMS_TAG_DEFAULT, "write AppRunningControlRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::ADD_APP_RUNNING_CONTROL_RULE, data, reply);
}
ErrCode AppControlProxy::DeleteAppRunningControlRule(
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call delete AppRunningControlRules");
    if (controlRules.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteAppRunningControlRule failed due to params error");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        LOG_E(BMS_TAG_DEFAULT, "write AppRunningControlRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::DELETE_APP_RUNNING_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppRunningControlRule(int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call delete appRunningControlRuleType");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::CLEAN_APP_RUNNING_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::GetAppRunningControlRule(int32_t userId, std::vector<std::string> &appIds)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call GetAppInstallControlRule");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfos(AppControlManagerInterfaceCode::GET_APP_RUNNING_CONTROL_RULE, data, appIds);
}

ErrCode AppControlProxy::GetAppRunningControlRule(
    const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRuleResult)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call GetAppRunningControlRuleResult");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to GetMediaData due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfo<AppRunningControlRuleResult>(
        AppControlManagerInterfaceCode::GET_APP_RUNNING_CONTROL_RULE_RESULT, data, controlRuleResult);
}

ErrCode AppControlProxy::ConfirmAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId)
{
    if (callerBundleName.empty() || targetBundleName.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "ConfirmAppJumpControlRule failed due to params error");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(callerBundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to write callerBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetBundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to write targetBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::CONFIRM_APP_JUMP_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
{
    if (controlRules.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteAppJumpControlRule failed due to params error");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        LOG_E(BMS_TAG_DEFAULT, "write AppJumpControlRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::ADD_APP_JUMP_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector(controlRules, data)) {
        LOG_E(BMS_TAG_DEFAULT, "write AppJumpControlRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE, data, reply);
}

ErrCode AppControlProxy::DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(callerBundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to write callerBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE_BY_CALLER, data, reply);
}

ErrCode AppControlProxy::DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetBundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to write targetBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
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
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(callerBundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to write callerBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetBundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to write targetBundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfo<AppJumpControlRule>(
        AppControlManagerInterfaceCode::GET_APP_JUMP_CONTROL_RULE, data, controlRule);
}

ErrCode AppControlProxy::SetDisposedStatus(
    const std::string &appId, const Want &want, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "proxy begin to SetDisposedStatus");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_DEFAULT, "write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_DEFAULT, "write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(AppControlManagerInterfaceCode::SET_DISPOSED_STATUS, data, reply);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::DeleteDisposedStatus(const std::string &appId, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "proxy begin to DeleteDisposedStatus");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_DEFAULT, "write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(AppControlManagerInterfaceCode::DELETE_DISPOSED_STATUS, data, reply);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::GetDisposedStatus(const std::string &appId, Want &want, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "proxy begin to GetDisposedStatus");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_DEFAULT, "write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = GetParcelableInfo<Want>(AppControlManagerInterfaceCode::GET_DISPOSED_STATUS, data, want);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::SetDisposedRule(
    const std::string &appId, DisposedRule &disposedRule, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(TAG_SET_DISPOSED_RULE(BMS_PROXY), "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(TAG_SET_DISPOSED_RULE(BMS_PROXY), "write appId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&disposedRule)) {
        LOG_E(TAG_SET_DISPOSED_RULE(BMS_PROXY), "write disposedRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(TAG_SET_DISPOSED_RULE(BMS_PROXY), "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(AppControlManagerInterfaceCode::SET_DISPOSED_RULE, data, reply);
    if (ret != ERR_OK) {
        LOG_E(TAG_SET_DISPOSED_RULE(BMS_PROXY), "SendRequest failed");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(TAG_SET_DISPOSED_RULE(BMS_PROXY), "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::GetDisposedRule(const std::string &appId, DisposedRule &rule, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "proxy begin to GetDisposedRule");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_DEFAULT, "write appId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = GetParcelableInfo<DisposedRule>(AppControlManagerInterfaceCode::GET_DISPOSED_RULE, data, rule);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::GetAbilityRunningControlRule(
    const std::string &bundleName, int32_t userId, std::vector<DisposedRule> &rules)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call GetAbilityRunningControlRule");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfos(AppControlManagerInterfaceCode::GET_ABILITY_RUNNING_CONTROL_RULE, data, rules);
}

ErrCode AppControlProxy::SetDisposedRuleForCloneApp(
    const std::string &appId, DisposedRule &disposedRule, int32_t appIndex, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "proxy begin to SetDisposedRuleForCloneApp");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_DEFAULT, "write appId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&disposedRule)) {
        LOG_E(BMS_TAG_DEFAULT, "write disposedRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_DEFAULT, "write appIndex appIndex");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(AppControlManagerInterfaceCode::SET_DISPOSED_RULE_FOR_CLONE_APP, data, reply);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::GetDisposedRuleForCloneApp(const std::string &appId, DisposedRule &rule,
    int32_t appIndex, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "proxy begin to GetDisposedRuleForCloneApp");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_DEFAULT, "write appId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_DEFAULT, "write appIndex failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = GetParcelableInfo<DisposedRule>(AppControlManagerInterfaceCode::GET_DISPOSED_RULE_FOR_CLONE_APP,
        data, rule);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlProxy::DeleteDisposedRuleForCloneApp(const std::string &appId, int32_t appIndex, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "proxy begin to DeleteDisposedRuleForCloneApp");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        LOG_E(BMS_TAG_DEFAULT, "write appId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_DEFAULT, "write appIndex failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(AppControlManagerInterfaceCode::DELETE_DISPOSED_RULE_FOR_CLONE_APP, data, reply);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "host return error : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

bool AppControlProxy::WriteStringVector(const std::vector<std::string> &stringVector, MessageParcel &data)
{
    if (!data.WriteInt32(stringVector.size())) {
        LOG_E(BMS_TAG_DEFAULT, "write ParcelableVector failed");
        return false;
    }

    for (auto &string : stringVector) {
        if (!data.WriteString(string)) {
            LOG_E(BMS_TAG_DEFAULT, "write string failed");
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
        LOG_E(BMS_TAG_DEFAULT, "write ParcelableVector failed");
        return false;
    }

    for (const auto &parcelable : parcelableVector) {
        if (!data.WriteParcelable(&parcelable)) {
            LOG_E(BMS_TAG_DEFAULT, "write ParcelableVector failed");
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
        LOG_E(BMS_TAG_DEFAULT, "get return error=%{public}d from host", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != NO_ERROR) {
        return ret;
    }
    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (info == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "ReadParcelable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    parcelableInfo = *info;
    LOG_D(BMS_TAG_DEFAULT, "GetParcelableInfo success");
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
    LOG_D(BMS_TAG_DEFAULT, "Read string vector success");
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
        LOG_E(BMS_TAG_DEFAULT, "readParcelableInfo failed");
        return false;
    }

    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (info == nullptr) {
            LOG_E(BMS_TAG_DEFAULT, "Read Parcelable infos failed");
            return false;
        }
        parcelableInfos.emplace_back(*info);
    }
    LOG_D(BMS_TAG_DEFAULT, "get parcelable infos success");
    return true;
}

int32_t AppControlProxy::SendRequest(AppControlManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "failed to send request %{public}d due to remote object null", code);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        LOG_E(BMS_TAG_DEFAULT, "receive error code %{public}d in transact %{public}d", result, code);
    }
    return result;
}
} // AppExecFwk
} // OHOS