/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "bundle_installer_host.h"

#ifdef ABILITY_RUNTIME_ENABLE
#include "ability_manager_client.h"
#endif
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_manager.h"
#endif
#include "app_log_tag_wrapper.h"
#include "bundle_clone_installer.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_hitrace_chain.h"
#include "bundle_memory_guard.h"
#include "bundle_mgr_service.h"
#include "bundle_multiuser_installer.h"
#include "bundle_permission_mgr.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "plugin_installer.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* GET_MANAGER_FAIL = "fail to get bundle installer manager";
constexpr const char* BMS_PARA_BUNDLE_NAME = "ohos.bms.param.bundleName";
constexpr const char* BMS_PARA_IS_KEEP_DATA = "ohos.bms.param.isKeepData";
constexpr const char* BMS_PARA_USER_ID = "ohos.bms.param.userId";
constexpr const char* BMS_PARA_APP_INDEX = "ohos.bms.param.appIndex";
constexpr bool IS_KEEP_DATA = false;
int32_t INVALID_APP_INDEX = 0;
int32_t LOWER_DLP_TYPE_BOUND = 0;
int32_t UPPER_DLP_TYPE_BOUND = 3;
}  // namespace

BundleInstallerHost::BundleInstallerHost()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "create bundle installer host instance");
}

BundleInstallerHost::~BundleInstallerHost()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "destroy bundle installer host instance");
}

void BundleInstallerHost::Init()
{
    LOG_D(BMS_TAG_INSTALLER, "begin to init");
    manager_ = std::make_shared<BundleInstallerManager>();
    LOG_D(BMS_TAG_INSTALLER, "init successfully");
}

int BundleInstallerHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    LOG_D(BMS_TAG_INSTALLER, "bundle installer host onReceived message, the message code is %{public}u", code);
    std::u16string descripter = GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        LOG_E(BMS_TAG_INSTALLER, "fail to write reply message in bundle mgr host due to the reply is nullptr");
        return OBJECT_NULL;
    }
    switch (code) {
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::INSTALL):
            HandleInstallMessage(data);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::INSTALL_MULTIPLE_HAPS):
            HandleInstallMultipleHapsMessage(data);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::UNINSTALL):
            HandleUninstallMessage(data);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::UNINSTALL_MODULE):
            HandleUninstallModuleMessage(data);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::UNINSTALL_BY_UNINSTALL_PARAM):
            HandleUninstallByUninstallParam(data);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::RECOVER):
            HandleRecoverMessage(data);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::INSTALL_SANDBOX_APP):
            HandleInstallSandboxApp(data, reply);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::UNINSTALL_SANDBOX_APP):
            HandleUninstallSandboxApp(data, reply);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::CREATE_STREAM_INSTALLER):
            HandleCreateStreamInstaller(data, reply);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::DESTORY_STREAM_INSTALLER):
            HandleDestoryBundleStreamInstaller(data, reply);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::UNINSTALL_AND_RECOVER):
            HandleUninstallAndRecoverMessage(data);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::INSTALL_CLONE_APP):
            HandleInstallCloneApp(data, reply);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::UNINSTALL_CLONE_APP):
            HandleUninstallCloneApp(data, reply);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::INSTALL_EXISTED):
            HandleInstallExisted(data, reply);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::INSTALL_PLUGIN_APP):
            HandleInstallPlugin(data, reply);
            break;
        case static_cast<uint32_t>(BundleInstallerInterfaceCode::UNINSTALL_PLUGIN_APP):
            HandleUninstallPlugin(data, reply);
            break;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}

void BundleInstallerHost::HandleInstallMessage(MessageParcel &data)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("Install", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle install message");
    std::string bundlePath = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    installParam->withCopyHaps = true;
    Install(bundlePath, *installParam, statusReceiver);
    LOG_D(BMS_TAG_INSTALLER, "handle install message finished");
}

void BundleInstallerHost::HandleRecoverMessage(MessageParcel &data)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("Recover", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle install message by bundleName");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);

    installParam->preinstallSourceFlag = ApplicationInfoFlag::FLAG_RECOVER_INSTALLED;
    Recover(bundleName, *installParam, statusReceiver);
    LOG_D(BMS_TAG_INSTALLER, "handle install message by bundleName finished");
}

void BundleInstallerHost::HandleInstallMultipleHapsMessage(MessageParcel &data)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("Install", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle install multiple haps message");
    int32_t size = data.ReadInt32();
    if (size > ServiceConstants::MAX_HAP_NUMBER) {
        LOG_E(BMS_TAG_INSTALLER, "bundle path size is greater than the max hap number 128");
        return;
    }
    std::vector<std::string> pathVec;
    for (int i = 0; i < size; ++i) {
        pathVec.emplace_back(Str16ToStr8(data.ReadString16()));
    }
    if (size == 0 || pathVec.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "inputted bundlepath vector is empty");
        return;
    }
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    installParam->withCopyHaps = true;
    Install(pathVec, *installParam, statusReceiver);
    LOG_D(BMS_TAG_INSTALLER, "handle install multiple haps finished");
}

void BundleInstallerHost::HandleUninstallMessage(MessageParcel &data)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("Uninstall", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle uninstall message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);

    Uninstall(bundleName, *installParam, statusReceiver);
    LOG_D(BMS_TAG_INSTALLER, "handle uninstall message finished");
}

void BundleInstallerHost::HandleUninstallModuleMessage(MessageParcel &data)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("Uninstall", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle uninstall module message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::string modulePackage = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    Uninstall(bundleName, modulePackage, *installParam, statusReceiver);
    LOG_D(BMS_TAG_INSTALLER, "handle uninstall message finished");
}

void BundleInstallerHost::HandleUninstallByUninstallParam(MessageParcel &data)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("Uninstall", HITRACE_FLAG_INCLUDE_ASYNC);
    std::unique_ptr<UninstallParam> uninstallParam(data.ReadParcelable<UninstallParam>());
    if (uninstallParam == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<UninstallParam failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    Uninstall(*uninstallParam, statusReceiver);
}

void BundleInstallerHost::HandleInstallSandboxApp(MessageParcel &data, MessageParcel &reply)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("InstallSandboxApp", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle install sandbox app message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t dplType = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX;
    auto ret = InstallSandboxApp(bundleName, dplType, userId, appIndex);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write failed");
    }
    if (ret == ERR_OK && !reply.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_INSTALLER, "write failed");
    }
    LOG_D(BMS_TAG_INSTALLER, "handle install sandbox app message finished");
}

void BundleInstallerHost::HandleUninstallSandboxApp(MessageParcel &data, MessageParcel &reply)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("UninstallSandbox", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle install sandbox app message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t appIndex = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    auto ret = UninstallSandboxApp(bundleName, appIndex, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write failed");
    }
    LOG_D(BMS_TAG_INSTALLER, "handle install sandbox app message finished");
}

void BundleInstallerHost::HandleInstallPlugin(MessageParcel &data, MessageParcel &reply)
{
    LOG_D(BMS_TAG_INSTALLER, "handle install plugin application");
    std::string hostBundleName = data.ReadString();
    std::vector<std::string> pluginFilePaths;
    if (!data.ReadStringVector(&pluginFilePaths)) {
        reply.WriteInt32(ERR_APPEXECFWK_PLUGIN_INSTALL_READ_PARCEL_ERROR);
        LOG_E(BMS_TAG_INSTALLER, "read pluginFilePaths failed");
        return;
    }
    std::unique_ptr<InstallPluginParam> installPluginParam(data.ReadParcelable<InstallPluginParam>());
    if (installPluginParam == nullptr) {
        reply.WriteInt32(ERR_APPEXECFWK_PLUGIN_INSTALL_READ_PARCEL_ERROR);
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<installPluginParam> failed");
        return;
    }
    auto ret = InstallPlugin(hostBundleName, pluginFilePaths, *installPluginParam);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write failed");
    }
    LOG_D(BMS_TAG_INSTALLER, "handle install plugin application finished");
}

void BundleInstallerHost::HandleUninstallPlugin(MessageParcel &data, MessageParcel &reply)
{
    LOG_D(BMS_TAG_INSTALLER, "handle uninstall plugin application");
    std::string hostBundleName = Str16ToStr8(data.ReadString16());
    std::string pluginBundleName = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallPluginParam> installPluginParam(data.ReadParcelable<InstallPluginParam>());
    if (installPluginParam == nullptr) {
        reply.WriteInt32(ERR_APPEXECFWK_PLUGIN_INSTALL_READ_PARCEL_ERROR);
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<installPluginParam> failed");
        return;
    }
    auto ret = UninstallPlugin(hostBundleName, pluginBundleName, *installPluginParam);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write failed");
    }
    LOG_D(BMS_TAG_INSTALLER, "handle uninstall plugin application finished");
}

void BundleInstallerHost::HandleCreateStreamInstaller(MessageParcel &data, MessageParcel &reply)
{
    LOG_D(BMS_TAG_INSTALLER, "handle create stream installer message begin");
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        reply.WriteBool(false);
        LOG_E(BMS_TAG_INSTALLER, "read receiver failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    if (statusReceiver == nullptr) {
        reply.WriteBool(false);
        LOG_E(BMS_TAG_INSTALLER, "cast remote object to status receiver error");
        return;
    }
    std::vector<std::string> originHapPaths;
    if (!data.ReadStringVector(&originHapPaths)) {
        reply.WriteBool(false);
        LOG_E(BMS_TAG_INSTALLER, "read originPaths failed");
        return;
    }

    sptr<IBundleStreamInstaller> streamInstaller = CreateStreamInstaller(*installParam, statusReceiver, originHapPaths);
    if (streamInstaller == nullptr) {
        if (!reply.WriteBool(false)) {
            LOG_E(BMS_TAG_INSTALLER, "write result failed");
        }
        return;
    }
    if (!reply.WriteBool(true)) {
        LOG_E(BMS_TAG_INSTALLER, "write result failed");
        return;
    }
    if (!reply.WriteUint32(streamInstaller->GetInstallerId())) {
        LOG_E(BMS_TAG_INSTALLER, "write stream installe id failed");
        return;
    }
    if (!reply.WriteRemoteObject(streamInstaller->AsObject())) {
        LOG_E(BMS_TAG_INSTALLER, "write stream installer remote object failed");
        return;
    }

    std::lock_guard<std::mutex> lock(streamInstallMutex_);
    streamInstallers_.emplace_back(streamInstaller);
    LOG_D(BMS_TAG_INSTALLER, "handle create stream installer message finish");
}

void BundleInstallerHost::HandleDestoryBundleStreamInstaller(MessageParcel &data, MessageParcel &reply)
{
    LOG_D(BMS_TAG_INSTALLER, "handle destory stream installer message begin");
    uint32_t installerId = data.ReadUint32();
    DestoryBundleStreamInstaller(installerId);
    LOG_D(BMS_TAG_INSTALLER, "handle destoy stream installer message finish");
}

void BundleInstallerHost::HandleUninstallAndRecoverMessage(MessageParcel &data)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("UninstallAndRecover", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle UninstallAndRecover message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    installParam->preinstallSourceFlag = ApplicationInfoFlag::FLAG_RECOVER_INSTALLED;
    UninstallAndRecover(bundleName, *installParam, statusReceiver);
    LOG_D(BMS_TAG_INSTALLER, "handle UninstallAndRecover message finished");
}

bool BundleInstallerHost::Install(
    const std::string &bundleFilePath, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    if (!BundlePermissionMgr::CheckUserFromShell(installParam.userId)) {
        LOG_E(BMS_TAG_INSTALLER, "check shell user fail");
        statusReceiver->OnFinished(ERR_APPEXECFWK_USER_NOT_INSTALL_HAP, "can not specify user in shell");
        return false;
    }
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_INTERNALTESTING_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "install permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return false;
    }

    manager_->CreateInstallTask(bundleFilePath, installParam, statusReceiver);
    return true;
}

bool BundleInstallerHost::Install(const std::vector<std::string> &bundleFilePaths, const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    if (!BundlePermissionMgr::CheckUserFromShell(installParam.userId)) {
        LOG_E(BMS_TAG_INSTALLER, "check shell user fail");
        statusReceiver->OnFinished(ERR_APPEXECFWK_USER_NOT_INSTALL_HAP, "can not specify user in shell");
        return false;
    }
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_INTERNALTESTING_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "install permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return false;
    }

    manager_->CreateInstallTask(bundleFilePaths, installParam, statusReceiver);
    return true;
}

bool BundleInstallerHost::Recover(
    const std::string &bundleName, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::VerifyRecoverPermission()) {
        LOG_E(BMS_TAG_INSTALLER, "Recover permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return false;
    }
    manager_->CreateRecoverTask(bundleName, CheckInstallParam(installParam), statusReceiver);
    return true;
}

bool BundleInstallerHost::Uninstall(
    const std::string &bundleName, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    if (!BundlePermissionMgr::CheckUserFromShell(installParam.userId)) {
        LOG_E(BMS_TAG_INSTALLER, "check shell user fail");
        statusReceiver->OnFinished(ERR_APPEXECFWK_USER_NOT_INSTALL_HAP, "can not specify user in shell");
        return false;
    }
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::VerifyUninstallPermission()) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_UNINSTALL_PERMISSION_DENIED, "");
        return false;
    }
    if (installParam.IsForcedUninstall() && IPCSkeleton::GetCallingUid() != Constants::EDC_UID) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PREINSTALL_BUNDLE_ONLY_ALLOW_FORCE_UNINSTALLED_BY_EDC,
            "Only edc can force uninstall");
        return false;
    }
    if (installParam.IsVerifyUninstallRule() &&
        CheckUninstallDisposedRule(bundleName, installParam.userId, Constants::MAIN_APP_INDEX,
                                   installParam.isKeepData)) {
        LOG_W(BMS_TAG_INSTALLER, "CheckUninstallDisposedRule failed");
        statusReceiver->OnFinished(ERR_APPEXECFWK_UNINSTALL_DISPOSED_RULE_FAILED, "");
        return false;
    }
    manager_->CreateUninstallTask(bundleName, CheckInstallParam(installParam), statusReceiver);
    return true;
}

bool BundleInstallerHost::Uninstall(const std::string &bundleName, const std::string &modulePackage,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    if (!BundlePermissionMgr::CheckUserFromShell(installParam.userId)) {
        LOG_E(BMS_TAG_INSTALLER, "check shell user fail");
        statusReceiver->OnFinished(ERR_APPEXECFWK_USER_NOT_INSTALL_HAP, "can not specify user in shell");
        return false;
    }
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::VerifyUninstallPermission()) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_UNINSTALL_PERMISSION_DENIED, "");
        return false;
    }
    if (installParam.IsVerifyUninstallRule() &&
        CheckUninstallDisposedRule(
            bundleName, installParam.userId, Constants::MAIN_APP_INDEX, installParam.isKeepData, modulePackage)) {
        LOG_W(BMS_TAG_INSTALLER, "CheckUninstallDisposedRule failed");
        statusReceiver->OnFinished(ERR_APPEXECFWK_UNINSTALL_DISPOSED_RULE_FAILED, "");
        return false;
    }
    manager_->CreateUninstallTask(
        bundleName, modulePackage, CheckInstallParam(installParam), statusReceiver);
    return true;
}

bool BundleInstallerHost::Uninstall(const UninstallParam &uninstallParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::VerifyUninstallPermission()) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_UNINSTALL_PERMISSION_DENIED, "");
        return false;
    }
    manager_->CreateUninstallTask(uninstallParam, statusReceiver);
    return true;
}

bool BundleInstallerHost::InstallByBundleName(const std::string &bundleName,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_INTERNALTESTING_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "install permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return false;
    }

    manager_->CreateInstallByBundleNameTask(bundleName, CheckInstallParam(installParam), statusReceiver);
    return true;
}

ErrCode BundleInstallerHost::InstallSandboxApp(const std::string &bundleName, int32_t dplType, int32_t userId,
    int32_t &appIndex)
{
    if (bundleName.empty() || dplType <= LOWER_DLP_TYPE_BOUND || dplType >= UPPER_DLP_TYPE_BOUND) {
        LOG_E(BMS_TAG_INSTALLER, "install sandbox failed due to error parameters");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "vnon-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_SANDBOX_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "InstallSandboxApp permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    auto helper = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    if (helper == nullptr) {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    auto res = helper->InstallSandboxApp(bundleName, dplType, userId, appIndex);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "install sandbox failed due to error code : %{public}d", res);
    }
    return res;
}

ErrCode BundleInstallerHost::UninstallSandboxApp(const std::string &bundleName, int32_t appIndex, int32_t userId)
{
    // check bundle name
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall sandbox failed due to empty bundleName");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    // check appIndex
    if (appIndex <= INVALID_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        LOG_E(BMS_TAG_INSTALLER, "the appIndex %{public}d is invalid", appIndex);
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_UNINSTALL_SANDBOX_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "UninstallSandboxApp permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    auto helper = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    if (helper == nullptr) {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    auto res = helper->UninstallSandboxApp(bundleName, appIndex, userId);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall sandbox failed due to error code : %{public}d", res);
    }
    return res;
}

ErrCode BundleInstallerHost::InstallPlugin(const std::string &hostBundleName,
    const std::vector<std::string> &pluginFilePaths, const InstallPluginParam &installPluginParam)
{
    if (hostBundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "install plugin failed due to empty hostBundleName");
        return ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND;
    }
    if (pluginFilePaths.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "install plugin failed due to empty pluginFilePaths");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_FILEPATH_INVALID;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!OHOS::system::GetBoolParameter(ServiceConstants::IS_SUPPORT_PLUGIN, false)) {
        LOG_E(BMS_TAG_INSTALLER, "current device not support plugin");
        return ERR_APPEXECFWK_DEVICE_NOT_SUPPORT_PLUGIN;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_PLUGIN)) {
        LOG_E(BMS_TAG_INSTALLER, "InstallPlugin permission denied");
        return ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED;
    }
    std::shared_ptr<PluginInstaller> pluginInstaller = std::make_shared<PluginInstaller>();
    auto ret = pluginInstaller->InstallPlugin(hostBundleName, pluginFilePaths, installPluginParam);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "install plugin failed due to error code : %{public}d", ret);
    }
    return ret;
}

ErrCode BundleInstallerHost::UninstallPlugin(const std::string &hostBundleName, const std::string &pluginBundleName,
    const InstallPluginParam &installPluginParam)
{
    if (hostBundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall plugin failed due to empty hostBundleName");
        return ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND;
    }
    if (pluginBundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall plugin failed due to empty pluginBundleName");
        return ERR_APPEXECFWK_PLUGIN_NOT_FOUND;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_UNINSTALL_PLUGIN)) {
        LOG_E(BMS_TAG_INSTALLER, "UninstallPlugin permission denied");
        return ERR_APPEXECFWK_UNINSTALL_PERMISSION_DENIED;
    }
    std::shared_ptr<PluginInstaller> pluginInstaller = std::make_shared<PluginInstaller>();
    auto ret = pluginInstaller->UninstallPlugin(hostBundleName, pluginBundleName, installPluginParam);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall plugin failed due to error code : %{public}d", ret);
    }
    return ret;
}

ErrCode BundleInstallerHost::StreamInstall(const std::vector<std::string> &bundleFilePaths,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    return ERR_OK;
}

sptr<IBundleStreamInstaller> BundleInstallerHost::CreateStreamInstaller(const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver, const std::vector<std::string> &originHapPaths)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return nullptr;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return nullptr;
    }
    InstallParam verifiedInstallParam = installParam;
    if (!IsPermissionVaild(installParam, verifiedInstallParam)) {
        LOG_E(BMS_TAG_INSTALLER, "install permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return nullptr;
    }
    auto uid = IPCSkeleton::GetCallingUid();
    sptr<BundleStreamInstallerHostImpl> streamInstaller(new (std::nothrow) BundleStreamInstallerHostImpl(
        ++streamInstallerIds_, uid));
    if (streamInstaller == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "streamInstaller is nullptr, uid : %{public}d", uid);
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, "");
        return nullptr;
    }
    bool res = streamInstaller->Init(verifiedInstallParam, statusReceiver, originHapPaths);
    if (!res) {
        LOG_E(BMS_TAG_INSTALLER, "stream installer init failed");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, "");
        return nullptr;
    }
    return streamInstaller;
}

bool BundleInstallerHost::IsPermissionVaild(const InstallParam &installParam, InstallParam &verifiedInstallParam)
{
    verifiedInstallParam.isCallByShell = BundlePermissionMgr::IsShellTokenType();
    verifiedInstallParam.installBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    verifiedInstallParam.installEnterpriseBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    verifiedInstallParam.installEtpNormalBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    verifiedInstallParam.installEtpMdmBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    verifiedInstallParam.installInternaltestingBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_INTERNALTESTING_BUNDLE)
            ? PermissionStatus::HAVE_PERMISSION_STATUS
            : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    verifiedInstallParam.installUpdateSelfBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_SELF_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    return (verifiedInstallParam.installBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        verifiedInstallParam.installEnterpriseBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        verifiedInstallParam.installEtpNormalBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        verifiedInstallParam.installEtpMdmBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        verifiedInstallParam.installUpdateSelfBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_QUICK_FIX_BUNDLE));
}

bool BundleInstallerHost::DestoryBundleStreamInstaller(uint32_t streamInstallerId)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_INTERNALTESTING_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_QUICK_FIX_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "install permission denied");
        return false;
    }
    std::lock_guard<std::mutex> lock(streamInstallMutex_);
    for (auto it = streamInstallers_.begin(); it != streamInstallers_.end();) {
        if ((*it)->GetInstallerId() == streamInstallerId) {
            (*it)->UnInit();
            it = streamInstallers_.erase(it);
        } else {
            it++;
        }
    }
    return true;
}

bool BundleInstallerHost::CheckBundleInstallerManager(const sptr<IStatusReceiver> &statusReceiver) const
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

InstallParam BundleInstallerHost::CheckInstallParam(const InstallParam &installParam)
{
    if (installParam.userId == Constants::UNSPECIFIED_USERID) {
        LOG_I(BMS_TAG_INSTALLER, "installParam userId is unspecified and get calling userId by callingUid");
        InstallParam callInstallParam = installParam;
        callInstallParam.userId = BundleUtil::GetUserIdByCallingUid();
        return callInstallParam;
    }

    return installParam;
}

bool BundleInstallerHost::UpdateBundleForSelf(const std::vector<std::string> &bundleFilePaths,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_SELF_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "install permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return false;
    }
    manager_->CreateInstallTask(bundleFilePaths, installParam, statusReceiver);
    return true;
}

bool BundleInstallerHost::UninstallAndRecover(const std::string &bundleName, const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        LOG_E(BMS_TAG_INSTALLER, "statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_INSTALL_BUNDLE,
        ServiceConstants::PERMISSION_UNINSTALL_BUNDLE})) {
        LOG_E(BMS_TAG_INSTALLER, "install permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return false;
    }
    if (installParam.IsForcedUninstall() && IPCSkeleton::GetCallingUid() != Constants::EDC_UID) {
        LOG_E(BMS_TAG_INSTALLER, "uninstall permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PREINSTALL_BUNDLE_ONLY_ALLOW_FORCE_UNINSTALLED_BY_EDC,
            "Only edc can force uninstall");
        return false;
    }
    manager_->CreateUninstallAndRecoverTask(bundleName, CheckInstallParam(installParam), statusReceiver);
    return true;
}

void BundleInstallerHost::AddTask(const ThreadPoolTask &task, const std::string &taskName)
{
    manager_->AddTask(task, taskName);
}

int32_t BundleInstallerHost::GetThreadsNum()
{
    return manager_->GetThreadsNum();
}

size_t BundleInstallerHost::GetCurTaskNum()
{
    return manager_->GetCurTaskNum();
}

ErrCode BundleInstallerHost::InstallCloneApp(const std::string &bundleName, int32_t userId, int32_t& appIndex)
{
    if (OHOS::system::GetBoolParameter(ServiceConstants::IS_APP_CLONE_DISABLE, false)) {
        LOG_E(BMS_TAG_INSTALLER, "the enterprise device does not support the creation of an appClone instance.");
        return ERR_APPEXECFWK_CLONE_INSTALL_APP_NOT_SUPPORTED_MULTI_TYPE;
    }
    LOG_D(BMS_TAG_INSTALLER, "params[bundleName: %{public}s, user_id: %{public}d, appIndex: %{public}d]",
        bundleName.c_str(), userId, appIndex);
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "install clone app failed due to error parameters");
        return ERR_APPEXECFWK_CLONE_INSTALL_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api bundleName: %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_CLONE_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "InstallCloneApp permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    std::shared_ptr<BundleCloneInstaller> installer = std::make_shared<BundleCloneInstaller>();
    return installer->InstallCloneApp(bundleName, userId, appIndex);
}

void BundleInstallerHost::HandleInstallCloneApp(MessageParcel &data, MessageParcel &reply)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("Install", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle install clone app message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();

    LOG_I(BMS_TAG_INSTALLER, "receive Install CLone App Request");

    auto ret = InstallCloneApp(bundleName, userId, appIndex);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write failed");
    }

    if (ret == ERR_OK && !reply.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_INSTALLER, "write failed");
    }
    LOG_D(BMS_TAG_INSTALLER, "handle install clone app message finished");
}

ErrCode BundleInstallerHost::UninstallCloneApp(const std::string &bundleName, int32_t userId, int32_t appIndex,
                                               const DestroyAppCloneParam &destroyAppCloneParam)
{
    LOG_D(BMS_TAG_INSTALLER, "params[bundleName: %{public}s, user_id: %{public}d, appIndex: %{public}d]",
        bundleName.c_str(), userId, appIndex);
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "install clone app failed due to empty bundleName");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api, bundleName: %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_UNINSTALL_CLONE_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "UninstallCloneApp permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    if (appIndex < ServiceConstants::CLONE_APP_INDEX_MIN || appIndex > ServiceConstants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("Add Clone Bundle Fail, appIndex: %{public}d not in valid range", appIndex);
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX;
    }
    if (destroyAppCloneParam.IsVerifyUninstallRule() &&
        CheckUninstallDisposedRule(bundleName, userId, appIndex, IS_KEEP_DATA)) {
        LOG_W(BMS_TAG_INSTALLER, "CheckUninstallDisposedRule failed");
        return ERR_APPEXECFWK_UNINSTALL_DISPOSED_RULE_FAILED;
    }
    std::shared_ptr<BundleCloneInstaller> installer = std::make_shared<BundleCloneInstaller>();
    return installer->UninstallCloneApp(bundleName, userId, appIndex, false);
}

void BundleInstallerHost::HandleUninstallCloneApp(MessageParcel &data, MessageParcel &reply)
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("UninstallCloneApp", HITRACE_FLAG_INCLUDE_ASYNC);
    LOG_D(BMS_TAG_INSTALLER, "handle uninstall clone app message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    std::unique_ptr<DestroyAppCloneParam> destroyAppCloneParam(data.ReadParcelable<DestroyAppCloneParam>());
    if (destroyAppCloneParam == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "ReadParcelable<DestroyAppCloneParam> failed");
        return;
    }

    LOG_I(BMS_TAG_INSTALLER, "receive Uninstall CLone App Request");

    auto ret = UninstallCloneApp(bundleName, userId, appIndex, *destroyAppCloneParam);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write failed");
    }
    LOG_D(BMS_TAG_INSTALLER, "handle uninstall clone app message finished");
}

ErrCode BundleInstallerHost::InstallExisted(const std::string &bundleName, int32_t userId)
{
    LOG_D(BMS_TAG_INSTALLER, "params[bundleName: %{public}s, user_id: %{public}d]",
        bundleName.c_str(), userId);
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "install existed app failed due to error parameters");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_INSTALLER, "non-system app calling system api bundleName: %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE)) {
        LOG_E(BMS_TAG_INSTALLER, "InstallExisted permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    std::shared_ptr<BundleMultiUserInstaller> installer = std::make_shared<BundleMultiUserInstaller>();
    return installer->InstallExistedApp(bundleName, userId);
}

void BundleInstallerHost::HandleInstallExisted(MessageParcel &data, MessageParcel &reply)
{
    LOG_D(BMS_TAG_INSTALLER, "handle install existed app message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t userId = data.ReadInt32();

    LOG_I(BMS_TAG_INSTALLER, "receive InstallExisted Request -n %{public}s -u %{public}d",
        bundleName.c_str(), userId);

    auto ret = InstallExisted(bundleName, userId);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "write failed");
    }
    LOG_D(BMS_TAG_INSTALLER, "handle installExisted message finished");
}

bool BundleInstallerHost::CheckUninstallDisposedRule(
    const std::string &bundleName, int32_t userId, int32_t appIndex, bool isKeepData, const std::string &modulePackage)
{
#if defined (BUNDLE_FRAMEWORK_APP_CONTROL) && defined (ABILITY_RUNTIME_ENABLE)
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "null dataMgr");
        return false;
    }

    InnerBundleInfo bundleInfo;
    bool isBundleExist = dataMgr->FetchInnerBundleInfo(bundleName, bundleInfo);
    if (!isBundleExist) {
        LOG_E(BMS_TAG_INSTALLER, "the bundle: %{public}s is not install", bundleName.c_str());
        return false;
    }
    if (!modulePackage.empty() && !bundleInfo.IsOnlyModule(modulePackage)) {
        return false;
    }
    std::string appId = bundleInfo.GetAppIdentifier();
    if (appId.empty()) {
        appId = bundleInfo.GetAppId();
    }

    if (userId == Constants::UNSPECIFIED_USERID) {
        LOG_I(BMS_TAG_INSTALLER, "installParam userId is unspecified and get calling userId by callingUid");
        userId = BundleUtil::GetUserIdByCallingUid();
    }

    UninstallDisposedRule rule;
    auto ret = DelayedSingleton<AppControlManager>::GetInstance()
                   ->GetUninstallDisposedRule(appId, appIndex, userId, rule);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "GetUninstallDisposedRule failed code:%{public}d", ret);
        return false;
    }

    if (rule.want == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "null rule.want");
        return false;
    }
    rule.want->SetParam(BMS_PARA_BUNDLE_NAME, bundleName);
    rule.want->SetParam(BMS_PARA_USER_ID, userId);
    rule.want->SetParam(BMS_PARA_APP_INDEX, appIndex);
    rule.want->SetParam(BMS_PARA_IS_KEEP_DATA, isKeepData);

    if (rule.uninstallComponentType == UninstallComponentType::EXTENSION) {
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(
            *rule.want, nullptr, userId, AppExecFwk::ExtensionAbilityType::SERVICE);
        IPCSkeleton::SetCallingIdentity(identity);
        if (err != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLER, "start extension ability failed code:%{public}d", err);
        }
    } else {
        LOG_E(BMS_TAG_INSTALLER, "uninstallComponentType wrong type:%{public}d", rule.uninstallComponentType);
    }

    return true;
#else
    LOG_I(BMS_TAG_INSTALLER, "BUNDLE_FRAMEWORK_APP_CONTROL or ABILITY_RUNTIME_ENABLE is false");
    return false;
#endif
}
}  // namespace AppExecFwk
}  // namespace OHOS