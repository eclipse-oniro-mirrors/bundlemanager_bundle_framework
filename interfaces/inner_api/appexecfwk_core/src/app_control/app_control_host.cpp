/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "app_control_host.h"

#include "securec.h"
#include "string_ex.h"

#include "app_control_constants.h"
#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "disposed_rule.h"
#include "ipc_types.h"
#include "parcel_macro.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int16_t MAX_VECTOR_NUM = 1000;
constexpr size_t MAX_IPC_ALLOWED_CAPACITY = 100 * 1024 * 1024; // max ipc size 100MB
bool GetData(size_t size, const void *data, void *&buffer)
{
    if (data == nullptr) {
        APP_LOGE("failed due to null data");
        return false;
    }
    if ((size == 0) || size > Constants::MAX_PARCEL_CAPACITY) {
        APP_LOGE("failed due to wrong size");
        return false;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        APP_LOGE("failed due to malloc buffer failed");
        return false;
    }
    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        APP_LOGE("failed due to memcpy_s failed");
        return false;
    }
    return true;
}
}
AppControlHost::AppControlHost()
{
    LOG_D(BMS_TAG_DEFAULT, "create AppControlHost");
}

AppControlHost::~AppControlHost()
{
    LOG_D(BMS_TAG_DEFAULT, "destroy AppControlHost");
}

int AppControlHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGD("AppControlHost OnRemoteRequest, message code : %{public}u", code);
    std::u16string descriptor = AppControlHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        LOG_E(BMS_TAG_DEFAULT, "descriptor invalid");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::ADD_APP_INSTALL_CONTROL_RULE):
            return HandleAddAppInstallControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_INSTALL_CONTROL_RULE):
            return HandleDeleteAppInstallControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::CLEAN_APP_INSTALL_CONTROL_RULE):
            return HandleCleanAppInstallControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_APP_INSTALL_CONTROL_RULE):
            return HandleGetAppInstallControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::ADD_APP_RUNNING_CONTROL_RULE):
            return HandleAddAppRunningControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_RUNNING_CONTROL_RULE):
            return HandleDeleteAppRunningControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::CLEAN_APP_RUNNING_CONTROL_RULE):
            return HandleCleanAppRunningControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_APP_RUNNING_CONTROL_RULE):
            return HandleGetAppRunningControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_APP_RUNNING_CONTROL_RULE_RESULT):
            return HandleGetAppRunningControlRuleResult(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::CONFIRM_APP_JUMP_CONTROL_RULE):
            return HandleConfirmAppJumpControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::ADD_APP_JUMP_CONTROL_RULE):
            return HandleAddAppJumpControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE):
            return HandleDeleteAppJumpControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE_BY_CALLER):
            return HandleDeleteRuleByCallerBundleName(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_APP_JUMP_CONTROL_RULE_BY_TARGET):
            return HandleDeleteRuleByTargetBundleName(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_APP_JUMP_CONTROL_RULE):
            return HandleGetAppJumpControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_DISPOSED_STATUS):
            return HandleSetDisposedStatus(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_DISPOSED_STATUS):
            return HandleGetDisposedStatus(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_DISPOSED_STATUS):
            return HandleDeleteDisposedStatus(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_DISPOSED_RULE):
            return HandleSetDisposedRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_DISPOSED_RULES):
            return HandleSetDisposedRules(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_DISPOSED_RULES):
            return HandleDeleteDisposedRules(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_DISPOSED_RULE):
            return HandleGetDisposedRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_ABILITY_RUNNING_CONTROL_RULE):
            return HandleGetAbilityRunningControlRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_DISPOSED_RULE_FOR_CLONE_APP):
            return HandleGetDisposedRuleForCloneApp(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_DISPOSED_RULE_FOR_CLONE_APP):
            return HandleSetDisposedRuleForCloneApp(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_DISPOSED_RULE_FOR_CLONE_APP):
            return HandleDeleteDisposedRuleForCloneApp(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::SET_UNINSTALL_DISPOSED_RULE):
            return HandleSetUninstallDisposedRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_UNINSTALL_DISPOSED_RULE):
            return HandleGetUninstallDisposedRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::DELETE_UNINSTALL_DISPOSED_RULE):
            return HandleDeleteUninstallDisposedRule(data, reply);
        case static_cast<uint32_t>(AppControlManagerInterfaceCode::GET_DISPOSED_RULES):
            return HandleGetDisposedRules(data, reply);
        default:
            LOG_W(BMS_TAG_DEFAULT, "AppControlHost receive unknown code, code = %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

ErrCode AppControlHost::HandleAddAppInstallControlRule(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> appIds;
    int32_t appIdSize = data.ReadInt32();
    if (appIdSize > AppControlConstants::LIST_MAX_SIZE || appIdSize < 0) {
        LOG_E(BMS_TAG_DEFAULT, "HandleAddAppInstallControlRule parameter is invalid");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    appIds.reserve(appIdSize);
    for (int32_t i = 0; i < appIdSize; i++) {
        appIds.emplace_back(data.ReadString());
    }
    AppInstallControlRuleType controlRuleType = static_cast<AppInstallControlRuleType>(data.ReadInt32());
    int32_t userId = data.ReadInt32();
    int32_t ret = AddAppInstallControlRule(appIds, controlRuleType, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleAddAppInstallControlRule failed");
    }
    return ret;
}

ErrCode AppControlHost::HandleDeleteAppInstallControlRule(MessageParcel& data, MessageParcel& reply)
{
    AppInstallControlRuleType controlRuleType = static_cast<AppInstallControlRuleType>(data.ReadInt32());
    std::vector<std::string> appIds;
    int32_t appIdSize = data.ReadInt32();
    if (appIdSize > AppControlConstants::LIST_MAX_SIZE || appIdSize < 0) {
        LOG_E(BMS_TAG_DEFAULT, "HandleDeleteAppInstallControlRule parameter is invalid");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    appIds.reserve(appIdSize);
    for (int32_t i = 0; i < appIdSize; i++) {
        appIds.emplace_back(data.ReadString());
    }
    int32_t userId = data.ReadInt32();
    int32_t ret = DeleteAppInstallControlRule(controlRuleType, appIds, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleDeleteAppInstallControlRule failed");
    }
    return ret;
}

ErrCode AppControlHost::HandleCleanAppInstallControlRule(MessageParcel& data, MessageParcel& reply)
{
    AppInstallControlRuleType controlRuleType = static_cast<AppInstallControlRuleType>(data.ReadInt32());
    int32_t userId = data.ReadInt32();
    int32_t ret = DeleteAppInstallControlRule(controlRuleType, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleCleanAppInstallControlRule failed");
    }
    return ret;
}

ErrCode AppControlHost::HandleGetAppInstallControlRule(MessageParcel& data, MessageParcel& reply)
{
    AppInstallControlRuleType controlRuleType = static_cast<AppInstallControlRuleType>(data.ReadInt32());
    int32_t userId = data.ReadInt32();
    std::vector<std::string> appIds;
    int32_t ret = GetAppInstallControlRule(controlRuleType, userId, appIds);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleGetAppInstallControlRule failed");
        return ret;
    }
    if (!WriteStringVector(appIds, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "write appIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleAddAppRunningControlRule(MessageParcel& data, MessageParcel& reply)
{
    std::vector<AppRunningControlRule> controlRules;
    auto ret = ReadParcelableVector(data, controlRules);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "AddAppRunningControlRule read controlRuleParam failed");
        return ret;
    }
    int32_t userId = data.ReadInt32();
    return AddAppRunningControlRule(controlRules, userId);
}

ErrCode AppControlHost::HandleDeleteAppRunningControlRule(MessageParcel& data, MessageParcel& reply)
{
    std::vector<AppRunningControlRule> controlRules;
    auto ret = ReadParcelableVector(data, controlRules);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteAppRunningControlRule read controlRuleParam failed");
        return ret;
    }
    int32_t userId = data.ReadInt32();
    return DeleteAppRunningControlRule(controlRules, userId);
}

ErrCode AppControlHost::HandleCleanAppRunningControlRule(MessageParcel& data, MessageParcel& reply)
{
    int32_t userId = data.ReadInt32();
    int32_t ret = DeleteAppRunningControlRule(userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleCleanAppInstallControlRule failed");
    }
    return ret;
}

ErrCode AppControlHost::HandleGetAppRunningControlRule(MessageParcel& data, MessageParcel& reply)
{
    int32_t userId = data.ReadInt32();
    std::vector<std::string> appIds;
    bool allowRunning;
    int32_t ret = GetAppRunningControlRule(userId, appIds, allowRunning);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleGetAppRunningControlRule failed");
        return ret;
    }
    if (!WriteStringVector(appIds, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "write appIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteBool(allowRunning)) {
        LOG_E(BMS_TAG_DEFAULT, "write allowRunning failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleGetAppRunningControlRuleResult(MessageParcel& data, MessageParcel& reply)
{
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    AppRunningControlRuleResult ruleResult;
    int32_t ret = GetAppRunningControlRule(bundleName, userId, ruleResult);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleGetAppRunningControlRuleResult failed");
    }
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteParcelable(&ruleResult)) {
        LOG_E(BMS_TAG_DEFAULT, "write AppRunningControlRuleResult failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleConfirmAppJumpControlRule(MessageParcel& data, MessageParcel& reply)
{
    std::string callerBundleName = data.ReadString();
    std::string targetBundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t ret = ConfirmAppJumpControlRule(callerBundleName, targetBundleName, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleConfirmAppJumpControlRule failed");
    }
    return ret;
}

ErrCode AppControlHost::HandleAddAppJumpControlRule(MessageParcel& data, MessageParcel& reply)
{
    std::vector<AppJumpControlRule> controlRules;
    auto ret = ReadParcelableVector(data, controlRules);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleAddAppJumpControlRule read controlRuleParam failed");
        return ret;
    }
    int32_t userId = data.ReadInt32();
    return AddAppJumpControlRule(controlRules, userId);
}

ErrCode AppControlHost::HandleDeleteAppJumpControlRule(MessageParcel& data, MessageParcel& reply)
{
    std::vector<AppJumpControlRule> controlRules;
    auto ret = ReadParcelableVector(data, controlRules);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleDeleteAppJumpControlRule read controlRuleParam failed");
        return ret;
    }
    int32_t userId = data.ReadInt32();
    return DeleteAppJumpControlRule(controlRules, userId);
}

ErrCode AppControlHost::HandleDeleteRuleByCallerBundleName(MessageParcel& data, MessageParcel& reply)
{
    std::string callerBundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t ret = DeleteRuleByCallerBundleName(callerBundleName, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleDeleteRuleByCallerBundleName failed");
    }
    return ret;
}

ErrCode AppControlHost::HandleDeleteRuleByTargetBundleName(MessageParcel& data, MessageParcel& reply)
{
    std::string targetBundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t ret = DeleteRuleByTargetBundleName(targetBundleName, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleDeleteRuleByTargetBundleName failed");
    }
    return ret;
}

ErrCode AppControlHost::HandleGetAppJumpControlRule(MessageParcel& data, MessageParcel& reply)
{
    std::string callerBundleName = data.ReadString();
    std::string targetBundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    AppJumpControlRule rule;
    int32_t ret = GetAppJumpControlRule(callerBundleName, targetBundleName, userId, rule);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleGetAppJumpControlRule failed");
    }
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteParcelable(&rule)) {
        LOG_E(BMS_TAG_DEFAULT, "write AppJumpControlRule failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleSetDisposedStatus(MessageParcel& data, MessageParcel& reply)
{
    std::string appId = data.ReadString();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    int32_t userId = data.ReadInt32();
    if (want == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = SetDisposedStatus(appId, *want, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleDeleteDisposedStatus(MessageParcel& data, MessageParcel &reply)
{
    std::string appId = data.ReadString();
    int32_t userId = data.ReadInt32();
    ErrCode ret = DeleteDisposedStatus(appId, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleGetDisposedStatus(MessageParcel& data, MessageParcel &reply)
{
    std::string appId = data.ReadString();
    int32_t userId = data.ReadInt32();
    Want want;
    ErrCode ret = GetDisposedStatus(appId, want, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&want)) {
            LOG_E(BMS_TAG_DEFAULT, "write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleGetDisposedRule(MessageParcel& data, MessageParcel &reply)
{
    std::string appId = data.ReadString();
    int32_t userId = data.ReadInt32();
    DisposedRule rule;
    ErrCode ret = GetDisposedRule(appId, rule, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&rule)) {
            LOG_E(BMS_TAG_DEFAULT, "write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleGetDisposedRules(MessageParcel& data, MessageParcel &reply)
{
    int32_t userId = data.ReadInt32();
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    ErrCode ret = GetDisposedRules(userId, disposedRuleConfigurations);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (WriteVectorToParcel(disposedRuleConfigurations, reply) != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleSetDisposedRule(MessageParcel& data, MessageParcel& reply)
{
    std::string appId = data.ReadString();
    std::unique_ptr<DisposedRule> disposedRule(data.ReadParcelable<DisposedRule>());
    int32_t userId = data.ReadInt32();
    if (disposedRule == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "ReadParcelable<disposedRule> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = SetDisposedRule(appId, *disposedRule, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleSetDisposedRules(MessageParcel& data, MessageParcel& reply)
{
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    auto ret = GetVectorParcelInfo(data, disposedRuleConfigurations);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "HandleSetDisposedRules read DisposedRuleConfiguration failed");
        return ret;
    }
    if (disposedRuleConfigurations.empty() || disposedRuleConfigurations.size() > MAX_VECTOR_NUM) {
        LOG_E(BMS_TAG_DEFAULT, "disposedRuleConfiguration count is error");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    int32_t userId = data.ReadInt32();
    ret = SetDisposedRules(disposedRuleConfigurations, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleDeleteDisposedRules(MessageParcel& data, MessageParcel& reply)
{
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    auto ret = GetVectorParcelInfo(data, disposedRuleConfigurations);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "read DisposedRuleConfiguration failed");
        return ret;
    }
    if (disposedRuleConfigurations.empty() || disposedRuleConfigurations.size() > MAX_VECTOR_NUM) {
        LOG_E(BMS_TAG_DEFAULT, "disposedRuleConfiguration count is error");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    int32_t userId = data.ReadInt32();
    ret = DeleteDisposedRules(disposedRuleConfigurations, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleGetAbilityRunningControlRule(MessageParcel& data, MessageParcel& reply)
{
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    std::vector<DisposedRule> rules;
    ErrCode ret = GetAbilityRunningControlRule(bundleName, userId, rules, appIndex);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteParcelableVector(rules, reply)) {
            LOG_E(BMS_TAG_DEFAULT, "write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleGetDisposedRuleForCloneApp(MessageParcel& data, MessageParcel &reply)
{
    std::string appId = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    DisposedRule rule;
    ErrCode ret = GetDisposedRuleForCloneApp(appId, rule, appIndex, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&rule)) {
            LOG_E(BMS_TAG_DEFAULT, "write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleSetDisposedRuleForCloneApp(MessageParcel& data, MessageParcel& reply)
{
    std::string appId = data.ReadString();
    std::unique_ptr<DisposedRule> disposedRule(data.ReadParcelable<DisposedRule>());
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    if (disposedRule == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "ReadParcelable<disposedRule> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = SetDisposedRuleForCloneApp(appId, *disposedRule, appIndex, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleDeleteDisposedRuleForCloneApp(MessageParcel& data, MessageParcel& reply)
{
    std::string appId = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    ErrCode ret = DeleteDisposedRuleForCloneApp(appId, appIndex, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

bool AppControlHost::WriteStringVector(const std::vector<std::string> &stringVector, MessageParcel &reply)
{
    if (!reply.WriteInt32(stringVector.size())) {
        LOG_E(BMS_TAG_DEFAULT, "write ParcelableVector failed");
        return false;
    }

    for (auto &string : stringVector) {
        if (!reply.WriteString(string)) {
            LOG_E(BMS_TAG_DEFAULT, "write string failed");
            return false;
        }
    }
    return true;
}

template<typename T>
bool AppControlHost::WriteParcelableVector(std::vector<T> &parcelableVector, MessageParcel &reply)
{
    if (!reply.WriteInt32(parcelableVector.size())) {
        LOG_E(BMS_TAG_DEFAULT, "write ParcelableVector failed");
        return false;
    }

    for (auto &parcelable : parcelableVector) {
        if (!reply.WriteParcelable(&parcelable)) {
            LOG_E(BMS_TAG_DEFAULT, "write ParcelableVector failed");
            return false;
        }
    }
    return true;
}

template<typename T>
ErrCode AppControlHost::ReadParcelableVector(MessageParcel &data, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = data.ReadInt32();
    if (infoSize > AppControlConstants::LIST_MAX_SIZE) {
        LOG_E(BMS_TAG_DEFAULT, "elements num exceeds the limit %{public}d", AppControlConstants::LIST_MAX_SIZE);
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(data.ReadParcelable<T>());
        if (info == nullptr) {
            LOG_E(BMS_TAG_DEFAULT, "read parcelable infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfos.emplace_back(*info);
    }
    LOG_D(BMS_TAG_DEFAULT, "read parcelable infos success");
    return ERR_OK;
}

ErrCode AppControlHost::HandleGetUninstallDisposedRule(MessageParcel& data, MessageParcel& reply)
{
    std::string appIdentifier = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    UninstallDisposedRule rule;
    ErrCode ret = GetUninstallDisposedRule(appIdentifier, appIndex, userId, rule);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&rule)) {
            LOG_E(BMS_TAG_DEFAULT, "write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleSetUninstallDisposedRule(MessageParcel& data, MessageParcel& reply)
{
    std::string appIdentifier = data.ReadString();
    std::unique_ptr<UninstallDisposedRule> uninstallDisposedRule(data.ReadParcelable<UninstallDisposedRule>());
    if (uninstallDisposedRule == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "ReadParcelable<uninstalldisposedRule> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    ErrCode ret = SetUninstallDisposedRule(appIdentifier, *uninstallDisposedRule, appIndex, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlHost::HandleDeleteUninstallDisposedRule(MessageParcel& data, MessageParcel& reply)
{
    std::string appIdentifier = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    ErrCode ret = DeleteUninstallDisposedRule(appIdentifier, appIndex, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT, "write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

template<typename T>
ErrCode AppControlHost::GetVectorParcelInfo(MessageParcel &data, std::vector<T> &parcelInfos)
{
    size_t dataSize = data.ReadUint32();
    if (dataSize == 0) {
        APP_LOGW("Parcel no data");
        return ERR_OK;
    }

    void *buffer = nullptr;
    if (dataSize > MAX_IPC_ALLOWED_CAPACITY) {
        APP_LOGE("dataSize is too large");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    } else {
        if (!GetData(dataSize, data.ReadRawData(dataSize), buffer)) {
            APP_LOGE("GetData failed dataSize: %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        APP_LOGE("Fail to ParseFrom");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t infoSize = tempParcel.ReadInt32();
    CONTAINER_SECURITY_VERIFY(tempParcel, infoSize, &parcelInfos);
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(tempParcel.ReadParcelable<T>());
        if (info == nullptr) {
            APP_LOGE("Read Parcelable infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelInfos.emplace_back(*info);
    }

    return ERR_OK;
}

template<typename T>
ErrCode AppControlHost::WriteVectorToParcel(std::vector<T> &parcelVector, MessageParcel &reply)
{
    MessageParcel tempParcel;
    (void)tempParcel.SetMaxCapacity(Constants::MAX_PARCEL_CAPACITY);
    if (!tempParcel.WriteInt32(static_cast<int32_t>(parcelVector.size()))) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    for (auto &parcel : parcelVector) {
        if (!tempParcel.WriteParcelable(&parcel)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    std::vector<T>().swap(parcelVector);

    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteUint32(dataSize)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (dataSize > MAX_IPC_ALLOWED_CAPACITY) {
        APP_LOGE("datasize is too large");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    if (!reply.WriteRawData(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        APP_LOGE("write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS
