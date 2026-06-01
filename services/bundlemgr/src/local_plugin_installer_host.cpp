/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "local_plugin_installer_host.h"

#include "app_log_tag_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "local_plugin_stream_installer_host_impl.h"
#include "parameters.h"
#include "plugin/plugin_installer.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* GET_MANAGER_FAIL = "fail to get bundle installer manager";
}  // namespace

LocalPluginInstallerHost::LocalPluginInstallerHost()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "create local plugin installer host instance");
}

LocalPluginInstallerHost::~LocalPluginInstallerHost()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "destroy local plugin installer host instance");
}

void LocalPluginInstallerHost::Init()
{
    manager_ = std::make_shared<BundleInstallerManager>();
}

int LocalPluginInstallerHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    LOG_D(BMS_TAG_INSTALLER, "local plugin installer host onReceived message, the message code is %{public}u", code);
    std::u16string descripter = GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        LOG_E(BMS_TAG_INSTALLER, "descripter is not matched");
        return OBJECT_NULL;
    }

    ErrCode errCode = ERR_OK;
    switch (code) {
        case static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::UNINSTALL):
            errCode = HandleUninstallMessage(data, reply);
            break;
        case static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::INTERNAL_UNINSTALL):
            errCode = HandleInternalUninstallMessage(data, reply);
            break;
        case static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::CREATE_LOCAL_PLUGIN_STREAM_INSTALLER):
            errCode = HandleCreateLocalPluginStreamInstallerMessage(data, reply);
            break;
        case static_cast<uint32_t>(LocalPluginInstallerInterfaceCode::DESTROY_LOCAL_PLUGIN_STREAM_INSTALLER):
            errCode = HandleDestroyLocalPluginStreamInstallerMessage(data, reply);
            break;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return errCode;
}

ErrCode LocalPluginInstallerHost::HandleUninstallMessage(MessageParcel &data, MessageParcel &reply)
{
    LOG_D(BMS_TAG_INSTALLER, "handle uninstall local plugin message");
    std::string pluginBundleName = Str16ToStr8(data.ReadString16());
    auto object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "read statusReceiver failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto statusReceiver = iface_cast<IStatusReceiver>(object);
    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver is nullptr");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    ErrCode ret = Uninstall(pluginBundleName, statusReceiver);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write uninstall result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode LocalPluginInstallerHost::HandleInternalUninstallMessage(MessageParcel &data, MessageParcel &reply)
{
    LOG_D(BMS_TAG_INSTALLER, "handle internal uninstall local plugin message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::string pluginBundleName = Str16ToStr8(data.ReadString16());
    int32_t userId = data.ReadInt32();

    ErrCode ret = Uninstall(bundleName, pluginBundleName, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write internal uninstall result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode LocalPluginInstallerHost::HandleCreateLocalPluginStreamInstallerMessage(
    MessageParcel &data, MessageParcel &reply)
{
    LOG_D(BMS_TAG_INSTALLER, "handle create local plugin stream installer message");
    auto object = data.ReadRemoteObject();
    if (object == nullptr) {
        reply.WriteBool(false);
        LOG_E(BMS_TAG_INSTALLER, "read statusReceiver failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto statusReceiver = iface_cast<IStatusReceiver>(object);
    if (statusReceiver == nullptr) {
        reply.WriteBool(false);
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver is nullptr");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    auto pluginStreamInstaller = CreateLocalPluginStreamInstaller(statusReceiver);
    if (pluginStreamInstaller == nullptr) {
        if (!reply.WriteBool(false)) {
            LOG_E(BMS_TAG_INSTALLER, "write result failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        return ERR_OK;
    }

    if (!reply.WriteBool(true)) {
        LOG_E(BMS_TAG_INSTALLER, "write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteUint32(pluginStreamInstaller->GetLocalPluginInstallerId())) {
        LOG_E(BMS_TAG_INSTALLER, "write stream installer id failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteRemoteObject(pluginStreamInstaller->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write stream installer remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    std::lock_guard<std::mutex> lock(localPluginStreamInstallMutex_);
    localPluginStreamInstallers_.emplace_back(pluginStreamInstaller);
    return ERR_OK;
}

ErrCode LocalPluginInstallerHost::HandleDestroyLocalPluginStreamInstallerMessage(
    MessageParcel &data, MessageParcel &reply)
{
    LOG_D(BMS_TAG_INSTALLER, "handle destroy local plugin stream installer message");
    bool ret = DestroyLocalPluginStreamInstaller(data.ReadUint32());
    if (!reply.WriteBool(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write destroy result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode LocalPluginInstallerHost::Install(const std::vector<std::string> &pluginFilePaths,
    const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    std::string hostBundleName;
    InstallPluginParam installPluginParam;
    int32_t uid = IPCSkeleton::GetCallingUid();
    ErrCode ret = GetBundleNameAndUserId(uid, hostBundleName, installPluginParam);
    if (ret != ERR_OK) {
        return ret;
    }
    return InstallByLocalPluginStream(hostBundleName, pluginFilePaths, installPluginParam, statusReceiver);
}

ErrCode LocalPluginInstallerHost::InstallByLocalPluginStream(const std::string &hostBundleName,
    const std::vector<std::string> &pluginFilePaths, const InstallPluginParam &installPluginParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    if (pluginFilePaths.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "install local plugin failed due to empty pluginFilePaths");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_FILEPATH_INVALID;
    }
    if (!CheckInstallerManager(statusReceiver)) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    ErrCode ret = CheckOperationCondition();
    if (ret != ERR_OK) {
        return ret;
    }
    manager_->CreateInstallLocalPluginTask(hostBundleName, pluginFilePaths, installPluginParam, statusReceiver);
    return ERR_OK;
}

ErrCode LocalPluginInstallerHost::Uninstall(const std::string &pluginBundleName,
    const sptr<IStatusReceiver> &statusReceiver)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (pluginBundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall local plugin failed due to empty pluginBundleName");
        return ERR_APPEXECFWK_PLUGIN_NOT_FOUND;
    }
    if (!CheckInstallerManager(statusReceiver)) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_SUPPORT_LOCAL_PLUGIN)) {
        LOG_E(BMS_TAG_INSTALLER, "local plugin operation permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "null dataMgr");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    std::string hostBundleName;
    auto ret = dataMgr->GetNameForUid(uid, hostBundleName);
    if (ret != ERR_OK || hostBundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "GetNameForUid failed, uid:%{public}d, ret:%{public}d", uid, ret);
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    InstallPluginParam installPluginParam;
    installPluginParam.userId = BundleUtil::GetUserIdByUid(uid);
    manager_->CreateUninstallLocalPluginTask(hostBundleName, pluginBundleName, installPluginParam, statusReceiver);
    return ERR_OK;
}

ErrCode LocalPluginInstallerHost::Uninstall(const std::string &bundleName,
    const std::string &pluginBundleName, int32_t userId)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_UNINSTALL_PLUGIN)) {
        LOG_E(BMS_TAG_INSTALLER, "internal uninstall local plugin permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }

    InstallPluginParam installPluginParam;
    installPluginParam.userId = userId;
    std::shared_ptr<PluginInstaller> pluginInstaller = std::make_shared<PluginInstaller>();
    if (pluginInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "pluginInstaller is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    return pluginInstaller->UninstallLocalPlugin(bundleName, pluginBundleName, installPluginParam, true);
}

sptr<ILocalPluginStreamInstaller> LocalPluginInstallerHost::CreateLocalPluginStreamInstaller(
    const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckInstallerManager(statusReceiver)) {
        return nullptr;
    }
    ErrCode ret = CheckOperationCondition();
    if (ret != ERR_OK) {
        statusReceiver->OnFinished(ret, "");
        return nullptr;
    }

    std::string hostBundleName;
    InstallPluginParam installPluginParam;
    int32_t uid = IPCSkeleton::GetCallingUid();
    ret = GetBundleNameAndUserId(uid, hostBundleName, installPluginParam);
    if (ret != ERR_OK) {
        statusReceiver->OnFinished(ret, "");
        return nullptr;
    }
    sptr<LocalPluginStreamInstallerHostImpl> pluginStreamInstaller(
        new (std::nothrow) LocalPluginStreamInstallerHostImpl(++localPluginStreamInstallerIds_, uid));
    if (pluginStreamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "create local plugin stream installer failed");
        statusReceiver->OnFinished(ERR_APPEXECFWK_NULL_PTR, "");
        return nullptr;
    }
    bool res = pluginStreamInstaller->Init(installPluginParam, statusReceiver, hostBundleName);
    if (!res) {
        LOG_E(BMS_TAG_INSTALLER, "local plugin stream installer init failed");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, "");
        return nullptr;
    }
    return pluginStreamInstaller;
}

ErrCode LocalPluginInstallerHost::GetBundleNameAndUserId(int32_t uid, std::string &hostBundleName,
    InstallPluginParam &installPluginParam) const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "null dataMgr");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    auto ret = dataMgr->GetNameForUid(uid, hostBundleName);
    if (ret != ERR_OK || hostBundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "GetNameForUid failed, uid:%{public}d, ret:%{public}d", uid, ret);
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    installPluginParam.userId = BundleUtil::GetUserIdByUid(uid);
    return ERR_OK;
}

bool LocalPluginInstallerHost::DestroyLocalPluginStreamInstaller(uint32_t installerId)
{
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_SUPPORT_LOCAL_PLUGIN)) {
        LOG_E(BMS_TAG_INSTALLER, "destroy local plugin stream installer permission denied");
        return false;
    }

    std::lock_guard<std::mutex> lock(localPluginStreamInstallMutex_);
    for (auto it = localPluginStreamInstallers_.begin(); it != localPluginStreamInstallers_.end();) {
        if ((*it)->GetLocalPluginInstallerId() == installerId) {
            (*it)->UnInit();
            it = localPluginStreamInstallers_.erase(it);
        } else {
            ++it;
        }
    }
    return true;
}

bool LocalPluginInstallerHost::CheckInstallerManager(const sptr<IStatusReceiver> &statusReceiver) const
{
    if (statusReceiver == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "the receiver is nullptr");
        return false;
    }
    if (manager_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "the bundle installer manager is nullptr");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, GET_MANAGER_FAIL);
        return false;
    }
    return true;
}

ErrCode LocalPluginInstallerHost::CheckOperationCondition() const
{
    if (!OHOS::system::GetBoolParameter(ServiceConstants::IS_SUPPORT_LOCAL_PLUGIN, false)) {
        LOG_E(BMS_TAG_INSTALLER, "current device not support local plugin");
        return ERR_APPEXECFWK_DEVICE_NOT_SUPPORT_PLUGIN;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_SUPPORT_LOCAL_PLUGIN)) {
        LOG_E(BMS_TAG_INSTALLER, "local plugin operation permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS