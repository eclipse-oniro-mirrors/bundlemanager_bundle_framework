/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "bundle_permission_mgr.h"
#include "bundle_sandbox_app_helper.h"
#include "bundle_util.h"
#include "ffrt.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string GET_MANAGER_FAIL = "fail to get bundle installer manager";
int32_t INVALID_APP_INDEX = 0;
int32_t LOWER_DLP_TYPE_BOUND = 0;
int32_t UPPER_DLP_TYPE_BOUND = 3;
}  // namespace

BundleInstallerHost::BundleInstallerHost()
{
    APP_LOGI("create bundle installer host instance");
}

BundleInstallerHost::~BundleInstallerHost()
{
    APP_LOGI("destroy bundle installer host instance");
}

bool BundleInstallerHost::Init()
{
    APP_LOGD("begin to init");
    manager_ = std::make_shared<BundleInstallerManager>();
    APP_LOGD("init successfully");
    return true;
}

int BundleInstallerHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGD("bundle installer host onReceived message, the message code is %{public}u", code);

    std::u16string descripter = GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        APP_LOGE("fail to write reply message in bundle mgr host due to the reply is nullptr");
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
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}

void BundleInstallerHost::HandleInstallMessage(MessageParcel &data)
{
    APP_LOGD("handle install message");
    std::string bundlePath = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        APP_LOGE("ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    installParam->withCopyHaps = true;
    Install(bundlePath, *installParam, statusReceiver);
    APP_LOGD("handle install message finished");
}

void BundleInstallerHost::HandleRecoverMessage(MessageParcel &data)
{
    APP_LOGD("handle install message by bundleName");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        APP_LOGE("ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);

    Recover(bundleName, *installParam, statusReceiver);
    APP_LOGD("handle install message by bundleName finished");
}

void BundleInstallerHost::HandleInstallMultipleHapsMessage(MessageParcel &data)
{
    APP_LOGD("handle install multiple haps message");
    int32_t size = data.ReadInt32();
    if (size > Constants::MAX_HAP_NUMBER) {
        APP_LOGE("bundle path size is greater than the max hap number 128");
        return;
    }
    std::vector<std::string> pathVec;
    for (int i = 0; i < size; ++i) {
        pathVec.emplace_back(Str16ToStr8(data.ReadString16()));
    }
    if (size == 0 || pathVec.empty()) {
        APP_LOGE("inputted bundlepath vector is empty");
        return;
    }
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        APP_LOGE("ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    installParam->withCopyHaps = true;
    Install(pathVec, *installParam, statusReceiver);
    APP_LOGD("handle install multiple haps finished");
}

void BundleInstallerHost::HandleUninstallMessage(MessageParcel &data)
{
    APP_LOGD("handle uninstall message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        APP_LOGE("ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);

    Uninstall(bundleName, *installParam, statusReceiver);
    APP_LOGD("handle uninstall message finished");
}

void BundleInstallerHost::HandleUninstallModuleMessage(MessageParcel &data)
{
    APP_LOGD("handle uninstall module message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::string modulePackage = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        APP_LOGE("ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    Uninstall(bundleName, modulePackage, *installParam, statusReceiver);
    APP_LOGD("handle uninstall message finished");
}

void BundleInstallerHost::HandleUninstallByUninstallParam(MessageParcel &data)
{
    std::unique_ptr<UninstallParam> uninstallParam(data.ReadParcelable<UninstallParam>());
    if (uninstallParam == nullptr) {
        APP_LOGE("ReadParcelable<UninstallParam failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    Uninstall(*uninstallParam, statusReceiver);
}

void BundleInstallerHost::HandleInstallSandboxApp(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("handle install sandbox app message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t dplType = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = Constants::INITIAL_APP_INDEX;
    auto ret = InstallSandboxApp(bundleName, dplType, userId, appIndex);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
    }
    if (ret == ERR_OK && !reply.WriteInt32(appIndex)) {
        APP_LOGE("write failed");
    }
    APP_LOGD("handle install sandbox app message finished");
}

void BundleInstallerHost::HandleUninstallSandboxApp(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("handle install sandbox app message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t appIndex = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    auto ret = UninstallSandboxApp(bundleName, appIndex, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
    }
    APP_LOGD("handle install sandbox app message finished");
}

void BundleInstallerHost::HandleCreateStreamInstaller(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("handle create stream installer message begin");
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        APP_LOGE("ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        reply.WriteBool(false);
        APP_LOGE("read receiver failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    if (statusReceiver == nullptr) {
        reply.WriteBool(false);
        APP_LOGE("cast remote object to status receiver error");
        return;
    }

    sptr<IBundleStreamInstaller> streamInstaller = CreateStreamInstaller(*installParam, statusReceiver);
    if (streamInstaller == nullptr) {
        if (!reply.WriteBool(false)) {
            APP_LOGE("write result failed");
        }
        return;
    }
    if (!reply.WriteBool(true)) {
        APP_LOGE("write result failed");
        return;
    }
    if (!reply.WriteUint32(streamInstaller->GetInstallerId())) {
        APP_LOGE("write stream installe id failed");
        return;
    }
    if (!reply.WriteRemoteObject(streamInstaller->AsObject())) {
        APP_LOGE("write stream installer remote object failed");
        return;
    }

    std::lock_guard<std::mutex> lock(streamInstallMutex_);
    streamInstallers_.emplace_back(streamInstaller);
    APP_LOGD("handle create stream installer message finish");
}

void BundleInstallerHost::HandleDestoryBundleStreamInstaller(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("handle destory stream installer message begin");
    uint32_t installeId = data.ReadUint32();
    DestoryBundleStreamInstaller(installeId);
    APP_LOGD("handle destoy stream installer message finish");
}

void BundleInstallerHost::HandleUninstallAndRecoverMessage(MessageParcel &data)
{
    APP_LOGD("handle UninstallAndRecover message");
    std::string bundleName = Str16ToStr8(data.ReadString16());
    std::unique_ptr<InstallParam> installParam(data.ReadParcelable<InstallParam>());
    if (installParam == nullptr) {
        APP_LOGE("ReadParcelable<InstallParam> failed");
        return;
    }
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return;
    }
    sptr<IStatusReceiver> statusReceiver = iface_cast<IStatusReceiver>(object);
    UninstallAndRecover(bundleName, *installParam, statusReceiver);
    APP_LOGD("handle UninstallAndRecover message finished");
}

bool BundleInstallerHost::Install(
    const std::string &bundleFilePath, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        APP_LOGE("statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE)) {
        APP_LOGE("install permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return false;
    }

    manager_->CreateInstallTask(bundleFilePath, installParam, statusReceiver);
    return true;
}

bool BundleInstallerHost::Install(const std::vector<std::string> &bundleFilePaths, const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        APP_LOGE("statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE)) {
        APP_LOGE("install permission denied");
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
        APP_LOGE("statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::VerifyRecoverPermission()) {
        APP_LOGE("Recover permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return false;
    }
    manager_->CreateRecoverTask(bundleName, CheckInstallParam(installParam), statusReceiver);
    return true;
}

bool BundleInstallerHost::Uninstall(
    const std::string &bundleName, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        APP_LOGE("statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::VerifyUninstallPermission()) {
        APP_LOGE("uninstall permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_UNINSTALL_PERMISSION_DENIED, "");
        return false;
    }
    manager_->CreateUninstallTask(bundleName, CheckInstallParam(installParam), statusReceiver);
    return true;
}

bool BundleInstallerHost::Uninstall(const std::string &bundleName, const std::string &modulePackage,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        APP_LOGE("statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::VerifyUninstallPermission()) {
        APP_LOGE("uninstall permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_UNINSTALL_PERMISSION_DENIED, "");
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
        APP_LOGE("statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::VerifyUninstallPermission()) {
        APP_LOGE("uninstall permission denied");
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
        APP_LOGE("statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE)) {
        APP_LOGE("install permission denied");
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
        APP_LOGE("install sandbox failed due to error parameters");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("vnon-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_SANDBOX_BUNDLE)) {
        APP_LOGE("InstallSandboxApp permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    auto helper = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    if (helper == nullptr) {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    auto res = helper->InstallSandboxApp(bundleName, dplType, userId, appIndex);
    if (res != ERR_OK) {
        APP_LOGE("install sandbox failed due to error code : %{public}d", res);
    }
    return res;
}

ErrCode BundleInstallerHost::UninstallSandboxApp(const std::string &bundleName, int32_t appIndex, int32_t userId)
{
    // check bundle name
    if (bundleName.empty()) {
        APP_LOGE("uninstall sandbox failed due to empty bundleName");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    // check appIndex
    if (appIndex <= INVALID_APP_INDEX || appIndex > Constants::MAX_APP_INDEX) {
        APP_LOGE("the appIndex %{public}d is invalid", appIndex);
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_UNINSTALL_SANDBOX_BUNDLE)) {
        APP_LOGE("UninstallSandboxApp permission denied");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    auto helper = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    if (helper == nullptr) {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    auto res = helper->UninstallSandboxApp(bundleName, appIndex, userId);
    if (res != ERR_OK) {
        APP_LOGE("uninstall sandbox failed due to error code : %{public}d", res);
    }
    return res;
}

ErrCode BundleInstallerHost::StreamInstall(const std::vector<std::string> &bundleFilePaths,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    return ERR_OK;
}

sptr<IBundleStreamInstaller> BundleInstallerHost::CreateStreamInstaller(const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    if (!CheckBundleInstallerManager(statusReceiver)) {
        APP_LOGE("statusReceiver invalid");
        return nullptr;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return nullptr;
    }
    InstallParam verifiedInstallParam = installParam;
    if (!IsPermissionVaild(installParam, verifiedInstallParam)) {
        APP_LOGE("install permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
        return nullptr;
    }
    auto uid = IPCSkeleton::GetCallingUid();
    sptr<BundleStreamInstallerHostImpl> streamInstaller(new (std::nothrow) BundleStreamInstallerHostImpl(
        ++streamInstallerIds_, uid));
    if (streamInstaller == nullptr) {
        APP_LOGE("streamInstaller is nullptr, uid : %{public}d", uid);
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, "");
        return nullptr;
    }
    bool res = streamInstaller->Init(verifiedInstallParam, statusReceiver);
    if (!res) {
        APP_LOGE("stream installer init failed");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, "");
        return nullptr;
    }
    return streamInstaller;
}

bool BundleInstallerHost::IsPermissionVaild(const InstallParam &installParam, InstallParam &verifiedInstallParam)
{
    verifiedInstallParam.isCallByShell = BundlePermissionMgr::IsNativeTokenType();
    verifiedInstallParam.installBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    verifiedInstallParam.installEnterpriseBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    verifiedInstallParam.installEtpNormalBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    verifiedInstallParam.installEtpMdmBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    verifiedInstallParam.installUpdateSelfBundlePermissionStatus =
        BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_SELF_BUNDLE) ?
        PermissionStatus::HAVE_PERMISSION_STATUS : PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    return (verifiedInstallParam.installBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        verifiedInstallParam.installEnterpriseBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        verifiedInstallParam.installEtpNormalBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        verifiedInstallParam.installEtpMdmBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        verifiedInstallParam.installUpdateSelfBundlePermissionStatus == PermissionStatus::HAVE_PERMISSION_STATUS ||
        BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_QUICK_FIX_BUNDLE));
}

bool BundleInstallerHost::DestoryBundleStreamInstaller(uint32_t streamInstallerId)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_QUICK_FIX_BUNDLE)) {
        APP_LOGE("install permission denied");
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
        APP_LOGE("the receiver is nullptr");
        return false;
    }
    if (manager_ == nullptr) {
        APP_LOGE("the bundle installer manager is nullptr");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, GET_MANAGER_FAIL);
        return false;
    }
    return true;
}

InstallParam BundleInstallerHost::CheckInstallParam(const InstallParam &installParam)
{
    if (installParam.userId == Constants::UNSPECIFIED_USERID) {
        APP_LOGI("installParam userId is unspecified and get calling userId by callingUid");
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
        APP_LOGE("statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_SELF_BUNDLE)) {
        APP_LOGE("install permission denied");
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
        APP_LOGE("statusReceiver invalid");
        return false;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        statusReceiver->OnFinished(ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, "");
        return false;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_INSTALL_BUNDLE,
        Constants::PERMISSION_UNINSTALL_BUNDLE})) {
        APP_LOGE("install permission denied");
        statusReceiver->OnFinished(ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED, "");
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
}  // namespace AppExecFwk
}  // namespace OHOS