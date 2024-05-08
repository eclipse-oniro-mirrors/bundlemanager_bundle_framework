/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "bundle_connect_ability_mgr.h"

#include <thread>

#include "ability_manager_client.h"
#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_memory_guard.h"
#include "bundle_mgr_service.h"
#include "ffrt_inner.h"
#include "free_install_params.h"
#include "hitrace_meter.h"
#include "json_util.h"
#include "parcel.h"
#include "scope_guard.h"
#include "service_center_connection.h"
#include "service_center_status_callback.h"
#include "string_ex.h"
#include "system_ability_load_callback_stub.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string PARAM_FREEINSTALL_APPID = "ohos.freeinstall.params.callingAppId";
const std::string PARAM_FREEINSTALL_BUNDLENAMES = "ohos.freeinstall.params.callingBundleNames";
const std::string PARAM_FREEINSTALL_TARGET_APP_DIST_TYPE = "send_to_erms_targetAppDistType";
const std::string PARAM_FREEINSTALL_EMBEDDED = "send_to_erms_embedded";
const std::string PARAM_FREEINSTALL_TARGET_APP_PROVISION_TYPE = "send_to_erms_targetAppProvisionType";
const std::string PARAM_FREEINSTALL_UID = "ohos.freeinstall.params.callingUid";
const std::string DISCONNECT_DELAY_TASK = "DisconnectDelayTask";
const std::string DEFAULT_VERSION = "1";
const std::string CONNECT_ABILITY_QUEUE = "ConnectAbilityQueue";
constexpr uint32_t CALLING_TYPE_HARMONY = 2;
constexpr uint32_t BIT_ZERO_COMPATIBLE = 0;
constexpr uint32_t BIT_ONE_FRONT_MODE = 0;
constexpr uint32_t BIT_ONE_BACKGROUND_MODE = 1;
constexpr uint32_t BIT_TWO_CUSTOM = 0;
constexpr uint32_t BIT_THREE_ZERO = 0;
constexpr uint32_t BIT_FOUR_AZ_DEVICE = 0;
constexpr uint32_t BIT_FIVE_SAME_BUNDLE_NAME = 0;
constexpr uint32_t BIT_SIX_SAME_BUNDLE = 0;
constexpr uint32_t BIT_ONE = 2;
constexpr uint32_t BIT_TWO = 4;
constexpr uint32_t BIT_THREE = 8;
constexpr uint32_t BIT_FOUR = 16;
constexpr uint32_t BIT_FIVE = 32;
constexpr uint32_t BIT_SIX = 64;
constexpr uint32_t DISCONNECT_DELAY = 20000;
constexpr uint32_t OUT_TIME = 30000;
const std::u16string ATOMIC_SERVICE_STATUS_CALLBACK_TOKEN = u"ohos.IAtomicServiceStatusCallback";
const std::u16string SERVICE_CENTER_TOKEN = u"abilitydispatcherhm.openapi.hapinstall.IHapInstall";
constexpr uint32_t FREE_INSTALL_DONE = 0;
constexpr uint32_t TYPE_HARMONEY_INVALID = 0;
constexpr uint32_t TYPE_HARMONEY_APP = 1;
constexpr uint32_t TYPE_HARMONEY_SERVICE = 2;
constexpr uint32_t DEFAULT_VALUE = -1;
constexpr uint32_t DEFAULT_EMBEDDED_VALUE = 0;
constexpr int32_t DMS_UID = 5522;
// sa id
constexpr int32_t DOWNLOAD_SERVICE_SA_ID = 3706;
// replace want int ecological rule
constexpr const char* PARAM_REPLACE_WANT = "ohos.extra.param.key.replace_want";

void SendSysEvent(int32_t resultCode, const AAFwk::Want &want, int32_t userId)
{
    EventInfo sysEventInfo;
    ElementName element = want.GetElement();
    sysEventInfo.bundleName = element.GetBundleName();
    sysEventInfo.moduleName = element.GetModuleName();
    sysEventInfo.abilityName = element.GetAbilityName();
    sysEventInfo.isFreeInstallMode = true;
    sysEventInfo.userId = userId;
    sysEventInfo.errCode = resultCode;
    EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, sysEventInfo);
}
}

BundleConnectAbilityMgr::BundleConnectAbilityMgr()
{
    LOG_D(BMS_TAG_FREE_INSTALL, "create BundleConnectAbilityMgr");
    serialQueue_ = std::make_shared<SerialQueue>(CONNECT_ABILITY_QUEUE);
}

BundleConnectAbilityMgr::~BundleConnectAbilityMgr()
{
    LOG_D(BMS_TAG_FREE_INSTALL, "destroy BundleConnectAbilityMgr");
}

bool BundleConnectAbilityMgr::ProcessPreloadCheck(const TargetAbilityInfo &targetAbilityInfo)
{
    LOG_D(BMS_TAG_FREE_INSTALL, "ProcessPreloadCheck");
    auto preloadCheckFunc = [this, targetAbilityInfo]() {
        BundleMemoryGuard memoryGuard;
        int32_t flag = ServiceCenterFunction::CONNECT_PRELOAD_INSTALL;
        this->ProcessPreloadRequestToServiceCenter(flag, targetAbilityInfo);
    };
    ffrt::submit(preloadCheckFunc);
    return true;
}

void BundleConnectAbilityMgr::ProcessPreloadRequestToServiceCenter(int32_t flag,
    const TargetAbilityInfo &targetAbilityInfo)
{
    LOG_D(BMS_TAG_FREE_INSTALL, "ProcessPreloadRequestToServiceCenter");
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<BundleDataMgr> bundleDataMgr_ = bms->GetDataMgr();
    if (bundleDataMgr_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetDataMgr failed, bundleDataMgr_ is nullptr");
        return;
    }
    std::string bundleName;
    std::string abilityName;
    if (!(bundleDataMgr_->QueryAppGalleryAbilityName(bundleName, abilityName))) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Fail to query ServiceCenter ability and bundle name");
        return;
    }
    auto task = [ owner = weak_from_this() ] {
        auto mgr = owner.lock();
        if (mgr == nullptr) {
            LOG_E(BMS_TAG_FREE_INSTALL, "BundleConnectAbilityMgr is nullptr");
            return;
        }
        mgr->LoadDownloadService();
    };
    std::thread loadServiceThread(task);
    loadServiceThread.detach();
    Want serviceCenterWant;
    serviceCenterWant.SetElementName(bundleName, abilityName);
    bool isConnectSuccess = ConnectAbility(serviceCenterWant, nullptr);
    if (!isConnectSuccess) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Fail to connect ServiceCenter");
        return;
    } else {
        PreloadRequest(flag, targetAbilityInfo);
        return;
    }
}

void BundleConnectAbilityMgr::PreloadRequest(int32_t flag, const TargetAbilityInfo &targetAbilityInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(SERVICE_CENTER_TOKEN)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "failed to WriteInterfaceToken");
        return;
    }
    const std::string dataString = GetJsonStrFromInfo(targetAbilityInfo);
    LOG_I(BMS_TAG_FREE_INSTALL, "TargetAbilityInfo to JsonString : %{public}s", dataString.c_str());
    if (!data.WriteString16(Str8ToStr16(dataString))) {
        LOG_E(BMS_TAG_FREE_INSTALL, "%{public}s failed to WriteParcelable targetAbilityInfo", __func__);
        return;
    }
    serviceCenterRemoteObject_ = serviceCenterConnection_->GetRemoteObject();
    if (serviceCenterRemoteObject_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "%{public}s failed to get remote object", __func__);
        return;
    }
    int32_t result = serviceCenterRemoteObject_->SendRequest(flag, data, reply, option);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Failed to sendRequest, result = %{public}d", result);
    }
    LOG_D(BMS_TAG_FREE_INSTALL, "sendRequest to service center success.");
}

int32_t BundleConnectAbilityMgr::GetPreloadFlag()
{
    int32_t flagZero = BIT_ZERO_COMPATIBLE;
    int32_t flagOne = BIT_ONE_BACKGROUND_MODE * BIT_ONE;
    int32_t flagTwo = BIT_TWO_CUSTOM * BIT_TWO;
    int32_t flagThree = BIT_THREE_ZERO * BIT_THREE;
    int32_t flagFour = BIT_FOUR_AZ_DEVICE * BIT_FOUR;
    int32_t flagFive = BIT_FIVE_SAME_BUNDLE_NAME * BIT_FIVE;
    int32_t flagSix = BIT_SIX_SAME_BUNDLE * BIT_SIX;
    return flagZero + flagOne + flagTwo + flagThree + flagFour + flagFive + flagSix;
}

bool BundleConnectAbilityMgr::GetPreloadList(const std::string &bundleName, const std::string &moduleName,
    int32_t userId, sptr<TargetAbilityInfo> &targetAbilityInfo)
{
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<BundleDataMgr> bundleDataMgr_ = bms->GetDataMgr();
    if (bundleDataMgr_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetDataMgr failed, bundleDataMgr_ is nullptr");
        return false;
    }
    InnerBundleInfo innerBundleInfo;
    int32_t flag = ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE;
    auto ret = bundleDataMgr_->GetInnerBundleInfoWithBundleFlagsAndLock(bundleName, flag, innerBundleInfo, userId);
    if (!ret) {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetInnerBundleInfoWithBundleFlagsAndLock failed.");
        return false;
    }
    if (innerBundleInfo.GetBaseApplicationInfo().bundleType != BundleType::ATOMIC_SERVICE) {
        return false;
    }
    if (moduleName.empty()) {
        LOG_E(BMS_TAG_FREE_INSTALL, "moduleName is empty.");
        return false;
    }
    std::set<std::string> preloadModuleNames;
    auto moduleInfoMap = innerBundleInfo.GetInnerModuleInfos();
    if (moduleInfoMap.find(moduleName) == moduleInfoMap.end()) {
        LOG_E(BMS_TAG_FREE_INSTALL, "get moduleInfo from innerBundleInfo failed.");
        return false;
    }
    auto preloadItems = moduleInfoMap[moduleName].preloads;
    if (preloadItems.empty()) {
        return false;
    }
    for (const auto &item : preloadItems) {
        preloadModuleNames.insert(item);
    }
    for (const auto &it : moduleInfoMap) {
        auto iter = preloadModuleNames.find(it.first);
        if (iter != preloadModuleNames.end()) {
            preloadModuleNames.erase(iter);
        }
    }
    if (preloadModuleNames.empty()) {
        LOG_D(BMS_TAG_FREE_INSTALL, "All preload modules exist locally.");
        return false;
    }
    targetAbilityInfo->targetInfo.callingAppIds.emplace_back(innerBundleInfo.GetBaseBundleInfo().appId);
    for (const auto &item : preloadModuleNames) {
        targetAbilityInfo->targetInfo.preloadModuleNames.emplace_back(item);
    }
    return true;
}

bool BundleConnectAbilityMgr::ProcessPreload(const Want &want)
{
    LOG_D(BMS_TAG_FREE_INSTALL, "BundleConnectAbilityMgr::ProcessPreload is called.");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string moduleName = want.GetElement().GetModuleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    int32_t uid = want.GetIntParam("uid", 0);
    int32_t userId = uid / Constants::BASE_USER_RANGE;
    sptr<TargetAbilityInfo> targetAbilityInfo = new(std::nothrow) TargetAbilityInfo();
    if (targetAbilityInfo == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetAbilityInfo is nullptr");
        return false;
    }
    sptr<TargetInfo> targetInfo = new(std::nothrow) TargetInfo();
    if (targetInfo == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetInfo is nullptr");
        return false;
    }
    sptr<TargetExtSetting> targetExtSetting = new(std::nothrow) TargetExtSetting();
    if (targetExtSetting == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetExtSetting is nullptr");
        return false;
    }
    targetAbilityInfo->targetInfo = *targetInfo;
    targetAbilityInfo->targetExtSetting = *targetExtSetting;
    targetAbilityInfo->version = DEFAULT_VERSION;

    if (!GetPreloadList(bundleName, moduleName, userId, targetAbilityInfo)) {
        LOG_I(BMS_TAG_FREE_INSTALL, "the module have no preload module.");
        return false;
    }
    targetAbilityInfo->targetInfo.transactId = std::to_string(this->GetTransactId());
    targetAbilityInfo->targetInfo.bundleName = bundleName;
    targetAbilityInfo->targetInfo.moduleName = moduleName;
    targetAbilityInfo->targetInfo.abilityName = abilityName;
    targetAbilityInfo->targetInfo.action = want.GetAction();
    targetAbilityInfo->targetInfo.uri = want.GetUriString();
    targetAbilityInfo->targetInfo.type = want.GetType();
    targetAbilityInfo->targetInfo.flags = GetPreloadFlag();
    targetAbilityInfo->targetInfo.callingUid = uid;
    targetAbilityInfo->targetInfo.callingAppType = CALLING_TYPE_HARMONY;
    targetAbilityInfo->targetInfo.callingBundleNames.emplace_back(bundleName);
    if (!ProcessPreloadCheck(*targetAbilityInfo)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "ProcessPreloadCheck failed.");
        return false;
    }
    return true;
}

bool BundleConnectAbilityMgr::SilentInstall(TargetAbilityInfo &targetAbilityInfo, const Want &want,
    const FreeInstallParams &freeInstallParams, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_I(BMS_TAG_FREE_INSTALL, "SilentInstall");
    if (!CheckIsOnDemandLoad(targetAbilityInfo)) {
        ErmsCallerInfo callerInfo;
        GetEcologicalCallerInfo(want, callerInfo, userId);
        BmsExperienceRule rule;
        bool ret = CheckEcologicalRule(want, callerInfo, rule);
        if (!ret) {
            LOG_E(BMS_TAG_FREE_INSTALL, "check ecological rule failed, skip.");
        } else if (rule.isAllow) {
            LOG_I(BMS_TAG_FREE_INSTALL, "ecological rule is allow, keep going.");
        } else if (rule.replaceWant != nullptr) {
            LOG_I(BMS_TAG_FREE_INSTALL, "ecological rule is replace want.");
            targetAbilityInfo.targetExtSetting.extValues.emplace(PARAM_REPLACE_WANT,
                rule.replaceWant->ToUri());
        } else {
            LOG_W(BMS_TAG_FREE_INSTALL, "ecological rule is not allowed, return.");
            CallAbilityManager(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId, freeInstallParams.callback);
            return false;
        }
    }

    auto silentInstallFunc = [this, targetAbilityInfo, want, userId, freeInstallParams]() {
        BundleMemoryGuard memoryGuard;
        int32_t flag = ServiceCenterFunction::CONNECT_SILENT_INSTALL;
        this->SendRequestToServiceCenter(flag, targetAbilityInfo, want, userId, freeInstallParams);
    };
    ffrt::submit(silentInstallFunc, {}, {}, ffrt::task_attr().qos(ffrt::qos_deadline_request));
    return true;
}

bool BundleConnectAbilityMgr::UpgradeCheck(const TargetAbilityInfo &targetAbilityInfo, const Want &want,
    const FreeInstallParams &freeInstallParams, int32_t userId)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "UpgradeCheck");
    auto upgradeCheckFunc = [this, targetAbilityInfo, want, userId, freeInstallParams]() {
        BundleMemoryGuard memoryGuard;
        int32_t flag = ServiceCenterFunction::CONNECT_UPGRADE_CHECK;
        this->SendRequestToServiceCenter(flag, targetAbilityInfo, want, userId, freeInstallParams);
    };
    ffrt::submit(upgradeCheckFunc);
    return true;
}

bool BundleConnectAbilityMgr::UpgradeInstall(const TargetAbilityInfo &targetAbilityInfo, const Want &want,
    const FreeInstallParams &freeInstallParams, int32_t userId)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "UpgradeInstall");
    auto upgradeInstallFunc = [this, targetAbilityInfo, want, userId, freeInstallParams]() {
        BundleMemoryGuard memoryGuard;
        int32_t flag = ServiceCenterFunction::CONNECT_UPGRADE_INSTALL;
        this->SendRequestToServiceCenter(flag, targetAbilityInfo, want, userId, freeInstallParams);
    };
    ffrt::submit(upgradeInstallFunc);
    return true;
}

bool BundleConnectAbilityMgr::SendRequestToServiceCenter(int32_t flag, const TargetAbilityInfo &targetAbilityInfo,
    const Want &want, int32_t userId, const FreeInstallParams &freeInstallParams)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "SendRequestToServiceCenter");
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<BundleDataMgr> bundleDataMgr_ = bms->GetDataMgr();
    if (bundleDataMgr_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetDataMgr failed, bundleDataMgr_ is nullptr");
        CallAbilityManager(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId, freeInstallParams.callback);
        return false;
    }
    std::string bundleName;
    std::string abilityName;
    if (!(bundleDataMgr_->QueryAppGalleryAbilityName(bundleName, abilityName))) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Fail to query ServiceCenter ability and bundle name");
        CallAbilityManager(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId, freeInstallParams.callback);
        return false;
    }
    Want serviceCenterWant;
    serviceCenterWant.SetElementName(bundleName, abilityName);
    auto task = [ owner = weak_from_this() ] {
        auto mgr = owner.lock();
        if (mgr == nullptr) {
            LOG_E(BMS_TAG_FREE_INSTALL, "BundleConnectAbilityMgr is nullptr");
            return;
        }
        mgr->LoadDownloadService();
    };
    std::thread loadServiceThread(task);
    loadServiceThread.detach();
    bool isConnectSuccess = ConnectAbility(serviceCenterWant, nullptr);
    if (!isConnectSuccess) {
        if (freeInstallParams.serviceCenterFunction == ServiceCenterFunction::CONNECT_UPGRADE_INSTALL) {
            LOG_E(BMS_TAG_FREE_INSTALL, "Fail to connect ServiceCenter, but freeinstall upgrade return ok");
            CallAbilityManager(ServiceCenterResultCode::FREE_INSTALL_OK, want, userId, freeInstallParams.callback);
        } else {
            LOG_E(BMS_TAG_FREE_INSTALL, "Fail to connect ServiceCenter");
            CallAbilityManager(FreeInstallErrorCode::CONNECT_ERROR, want, userId, freeInstallParams.callback);
        }
        SendSysEvent(FreeInstallErrorCode::CONNECT_ERROR, want, userId);
        return false;
    } else {
        SendRequest(flag, targetAbilityInfo, want, userId, freeInstallParams);
        return true;
    }
}

void BundleConnectAbilityMgr::LoadDownloadService() const
{
    LOG_I(BMS_TAG_FREE_INSTALL, "LoadDownloadService start");
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Failed to get SystemAbilityManager");
        return;
    }
    sptr<SystemAbilityLoadCallbackStub> loadCallback = new (std::nothrow) SystemAbilityLoadCallbackStub();
    if (loadCallback == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Create load callback failed");
        return;
    }
    auto ret = systemAbilityMgr->LoadSystemAbility(DOWNLOAD_SERVICE_SA_ID, loadCallback);
    if (ret != 0) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Load system ability %{public}d failed with %{public}d.",
            DOWNLOAD_SERVICE_SA_ID, ret);
        return;
    }
    LOG_I(BMS_TAG_FREE_INSTALL, "LoadDownloadService end");
}

void BundleConnectAbilityMgr::DisconnectAbility()
{
    if (serviceCenterConnection_ != nullptr) {
        LOG_I(BMS_TAG_FREE_INSTALL, "DisconnectAbility");
        int result = AbilityManagerClient::GetInstance()->DisconnectAbility(serviceCenterConnection_);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_FREE_INSTALL, "disconnect fail, resultCode: %{public}d", result);
        }
    }
}

void BundleConnectAbilityMgr::WaitFromConnecting(std::unique_lock<std::mutex> &lock)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "ConnectAbility await start CONNECTING");
    while (connectState_ == ServiceCenterConnectState::CONNECTING) {
        cv_.wait(lock);
    }
    LOG_I(BMS_TAG_FREE_INSTALL, "ConnectAbility await end CONNECTING");
}

void BundleConnectAbilityMgr::WaitFromConnected(std::unique_lock<std::mutex> &lock)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "ConnectAbility await start CONNECTED");
    while (connectState_ != ServiceCenterConnectState::CONNECTED) {
        if (connectState_ == ServiceCenterConnectState::DISCONNECTED) {
            break;
        }
        cv_.wait(lock);
    }
    LOG_I(BMS_TAG_FREE_INSTALL, "ConnectAbility await end CONNECTED");
}

bool BundleConnectAbilityMgr::ConnectAbility(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "ConnectAbility start target bundle = %{public}s", want.GetBundle().c_str());
    std::unique_lock<std::mutex> lock(mutex_);
    serialQueue_->CancelDelayTask(DISCONNECT_DELAY_TASK);
    if (connectState_ == ServiceCenterConnectState::CONNECTING) {
        WaitFromConnecting(lock);
    } else if (connectState_ == ServiceCenterConnectState::DISCONNECTED) {
        connectState_ = ServiceCenterConnectState::CONNECTING;
        serviceCenterConnection_ = new (std::nothrow) ServiceCenterConnection(connectState_,
            cv_, weak_from_this());
        if (serviceCenterConnection_ == nullptr) {
            LOG_E(BMS_TAG_FREE_INSTALL, "ServiceCenterConnection is nullptr");
            connectState_ = ServiceCenterConnectState::DISCONNECTED;
            cv_.notify_all();
            return false;
        }
        LOG_I(BMS_TAG_FREE_INSTALL, "ConnectAbility start");
        int result = AbilityManagerClient::GetInstance()->ConnectAbility(want, serviceCenterConnection_, callerToken);
        if (result == ERR_OK) {
            if (connectState_ != ServiceCenterConnectState::CONNECTED) {
                WaitFromConnected(lock);
            }
            serviceCenterRemoteObject_ = serviceCenterConnection_->GetRemoteObject();
        } else {
            LOG_E(BMS_TAG_FREE_INSTALL, "ConnectAbility fail result = %{public}d", result);
        }
    }

    LOG_I(BMS_TAG_FREE_INSTALL, "ConnectAbility end");
    if (connectState_ == ServiceCenterConnectState::CONNECTED) {
        return true;
    } else {
        LOG_E(BMS_TAG_FREE_INSTALL, "ConnectAbility fail");
        connectState_ = ServiceCenterConnectState::DISCONNECTED;
        return false;
    }
}

void BundleConnectAbilityMgr::DisconnectDelay()
{
    auto disconnectFunc = [connect = shared_from_this()]() {
        LOG_I(BMS_TAG_FREE_INSTALL, "disconnectFunc Disconnect Ability");
        BundleMemoryGuard memoryGuard;
        if (connect) {
            connect->DisconnectAbility();
        }
    };
    serialQueue_->ScheduleDelayTask(DISCONNECT_DELAY_TASK, DISCONNECT_DELAY, disconnectFunc);
}

void BundleConnectAbilityMgr::SendCallBack(
    int32_t resultCode, const AAFwk::Want &want, int32_t userId, const std::string &transactId)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "SendCallBack");
    sptr<IRemoteObject> amsCallBack = GetAbilityManagerServiceCallBack(transactId);
    if (amsCallBack == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Abilitity manager callback is null");
        return;
    }

    std::unique_lock<std::mutex> lock(mapMutex_);
    if (freeInstallParamsMap_[transactId].serviceCenterFunction == ServiceCenterFunction::CONNECT_UPGRADE_INSTALL &&
        resultCode != ServiceCenterResultCode::FREE_INSTALL_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "SendCallBack, freeinstall upgrade return ok");
        resultCode = ServiceCenterResultCode::FREE_INSTALL_OK;
    }
    freeInstallParamsMap_.erase(transactId);
    LOG_I(BMS_TAG_FREE_INSTALL, "erase map size = %{public}zu, transactId = %{public}s",
        freeInstallParamsMap_.size(), transactId.c_str());
    if (freeInstallParamsMap_.size() == 0) {
        if (connectState_ == ServiceCenterConnectState::CONNECTED) {
            LOG_I(BMS_TAG_FREE_INSTALL, "DisconnectDelay");
            DisconnectDelay();
        }
    }
    lock.unlock();

    MessageParcel data;
    if (!data.WriteInterfaceToken(ATOMIC_SERVICE_STATUS_CALLBACK_TOKEN)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write interface token failed");
        return;
    }
    if (!data.WriteInt32(resultCode)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write result code failed");
        return;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write want failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write userId failed");
        return;
    }
    MessageParcel reply;
    MessageOption option;

    if (amsCallBack->SendRequest(FREE_INSTALL_DONE, data, reply, option) != ERR_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "BundleConnectAbilityMgr::SendCallBack SendRequest failed");
    }
}

void BundleConnectAbilityMgr::SendCallBack(const std::string &transactId, const FreeInstallParams &freeInstallParams)
{
    if (freeInstallParams.callback == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "freeInstallParams.callback is null");
        return;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(ATOMIC_SERVICE_STATUS_CALLBACK_TOKEN)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write interface token failed");
        return;
    }
    if (!data.WriteInt32(FreeInstallErrorCode::SERVICE_CENTER_CRASH)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write result code error");
        return;
    }
    if (!data.WriteParcelable(&(freeInstallParams.want))) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write want failed");
        return;
    }
    if (!data.WriteInt32(freeInstallParams.userId)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write userId error");
        return;
    }
    MessageParcel reply;
    MessageOption option;
    if (freeInstallParams.callback->SendRequest(FREE_INSTALL_DONE, data, reply, option) != ERR_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "BundleConnectAbilityMgr::SendCallBack SendRequest failed");
    }
}

void BundleConnectAbilityMgr::DeathRecipientSendCallback()
{
    LOG_I(BMS_TAG_FREE_INSTALL, "DeathRecipientSendCallback start");
    std::unique_lock<std::mutex> lock(mapMutex_);
    LOG_I(BMS_TAG_FREE_INSTALL, "freeInstallParamsMap size = %{public}zu", freeInstallParamsMap_.size());
    for (auto &it : freeInstallParamsMap_) {
        SendCallBack(it.first, it.second);
    }
    freeInstallParamsMap_.clear();
    lock.unlock();

    connectState_ = ServiceCenterConnectState::DISCONNECTED;
    serviceCenterRemoteObject_ = nullptr;
    cv_.notify_all();

    LOG_I(BMS_TAG_FREE_INSTALL, "DeathRecipientSendCallback end");
}

void BundleConnectAbilityMgr::OnServiceCenterCall(std::string installResultStr)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "OnServiceCenterCall start, installResultStr = %{public}s", installResultStr.c_str());
    InstallResult installResult;
    if (!ParseInfoFromJsonStr(installResultStr.c_str(), installResult)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Parse info from json fail");
        return;
    }
    LOG_I(BMS_TAG_FREE_INSTALL, "OnServiceCenterCall, retCode = %{public}d", installResult.result.retCode);
    FreeInstallParams freeInstallParams;
    std::unique_lock<std::mutex> lock(mapMutex_);
    auto node = freeInstallParamsMap_.find(installResult.result.transactId);
    if (node == freeInstallParamsMap_.end()) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Can not find node in %{public}s function", __func__);
        return;
    }
    serialQueue_->CancelDelayTask(installResult.result.transactId);
    freeInstallParams = node->second;
    lock.unlock();
    if (installResult.result.retCode == ServiceCenterResultCode::FREE_INSTALL_DOWNLOADING) {
        LOG_I(BMS_TAG_FREE_INSTALL, "ServiceCenter is downloading, downloadSize = %{public}d, totalSize = %{public}d",
            installResult.progress.downloadSize, installResult.progress.totalSize);
        return;
    }
    LOG_I(BMS_TAG_FREE_INSTALL, "serviceCenterFunction = %{public}d", freeInstallParams.serviceCenterFunction);
    if (freeInstallParams.serviceCenterFunction == ServiceCenterFunction::CONNECT_UPGRADE_INSTALL &&
        installResult.result.retCode != ServiceCenterResultCode::FREE_INSTALL_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "freeinstall upgrade return ok");
        installResult.result.retCode = ServiceCenterResultCode::FREE_INSTALL_OK;
    }
    SendCallBack(installResult.result.retCode, freeInstallParams.want, freeInstallParams.userId,
        installResult.result.transactId);
    LOG_I(BMS_TAG_FREE_INSTALL, "OnServiceCenterCall end");
}

void BundleConnectAbilityMgr::OnDelayedHeartbeat(std::string installResultStr)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "OnDelayedHeartbeat start, installResultStr = %{public}s", installResultStr.c_str());
    InstallResult installResult;
    if (!ParseInfoFromJsonStr(installResultStr.c_str(), installResult)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Parse info from json fail");
        return;
    }
    LOG_I(BMS_TAG_FREE_INSTALL, "OnDelayedHeartbeat, retCode = %{public}d", installResult.result.retCode);
    FreeInstallParams freeInstallParams;
    std::unique_lock<std::mutex> lock(mapMutex_);
    auto node = freeInstallParamsMap_.find(installResult.result.transactId);
    if (node == freeInstallParamsMap_.end()) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Can not find node in %{public}s function", __func__);
        return;
    }
    serialQueue_->CancelDelayTask(installResult.result.transactId);
    lock.unlock();
    OutTimeMonitor(installResult.result.transactId);
    LOG_I(BMS_TAG_FREE_INSTALL, "OnDelayedHeartbeat end");
}

void BundleConnectAbilityMgr::OutTimeMonitor(std::string transactId)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "BundleConnectAbilityMgr::OutTimeMonitor");
    FreeInstallParams freeInstallParams;
    std::unique_lock<std::mutex> lock(mapMutex_);
    auto node = freeInstallParamsMap_.find(transactId);
    if (node == freeInstallParamsMap_.end()) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Can not find node in %{public}s function", __func__);
        return;
    }
    freeInstallParams = node->second;
    lock.unlock();
    auto RegisterEventListenerFunc = [this, freeInstallParams, transactId]() {
        LOG_I(BMS_TAG_FREE_INSTALL, "RegisterEventListenerFunc");
        BundleMemoryGuard memoryGuard;
        this->SendCallBack(FreeInstallErrorCode::SERVICE_CENTER_TIMEOUT,
            freeInstallParams.want, freeInstallParams.userId, transactId);
    };
    serialQueue_->ScheduleDelayTask(transactId, OUT_TIME, RegisterEventListenerFunc);
}

void BundleConnectAbilityMgr::SendRequest(int32_t flag, const TargetAbilityInfo &targetAbilityInfo, const Want &want,
    int32_t userId, const FreeInstallParams &freeInstallParams)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(SERVICE_CENTER_TOKEN)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "failed to WriteInterfaceToken");
        CallAbilityManager(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId, freeInstallParams.callback);
        SendSysEvent(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId);
        return;
    }
    const std::string dataString = GetJsonStrFromInfo(targetAbilityInfo);
    LOG_I(BMS_TAG_FREE_INSTALL, "TargetAbilityInfo to JsonString : %{public}s", dataString.c_str());
    if (!data.WriteString16(Str8ToStr16(dataString))) {
        LOG_E(BMS_TAG_FREE_INSTALL, "%{public}s failed to WriteParcelable targetAbilityInfo", __func__);
        CallAbilityManager(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId, freeInstallParams.callback);
        SendSysEvent(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId);
        return;
    }
    sptr<ServiceCenterStatusCallback> callback = new(std::nothrow) ServiceCenterStatusCallback(weak_from_this());
    if (callback == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "callback is nullptr");
        return;
    }
    if (!data.WriteRemoteObject(callback)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "%{public}s failed to WriteRemoteObject callbcak", __func__);
        CallAbilityManager(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId, freeInstallParams.callback);
        SendSysEvent(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId);
        return;
    }
    serviceCenterRemoteObject_ = serviceCenterConnection_->GetRemoteObject();
    if (serviceCenterRemoteObject_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "%{public}s failed to get remote object", __func__);
        CallAbilityManager(FreeInstallErrorCode::CONNECT_ERROR, want, userId, freeInstallParams.callback);
        SendSysEvent(FreeInstallErrorCode::CONNECT_ERROR, want, userId);
        return;
    }
    std::unique_lock<std::mutex> lock(mapMutex_);
    auto emplaceResult = freeInstallParamsMap_.emplace(targetAbilityInfo.targetInfo.transactId, freeInstallParams);
    LOG_I(BMS_TAG_FREE_INSTALL, "emplace map size = %{public}zu, transactId = %{public}s",
        freeInstallParamsMap_.size(), targetAbilityInfo.targetInfo.transactId.c_str());
    if (!emplaceResult.second) {
        LOG_E(BMS_TAG_FREE_INSTALL, "freeInstallParamsMap emplace error");
        CallAbilityManager(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId, freeInstallParams.callback);
        return;
    }
    lock.unlock();
    int32_t result = serviceCenterRemoteObject_->SendRequest(flag, data, reply, option);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Failed to sendRequest, result = %{public}d", result);
        SendCallBack(FreeInstallErrorCode::CONNECT_ERROR, want, userId, targetAbilityInfo.targetInfo.transactId);
        SendSysEvent(FreeInstallErrorCode::CONNECT_ERROR, want, userId);
        return;
    }
    OutTimeMonitor(targetAbilityInfo.targetInfo.transactId);
}

bool BundleConnectAbilityMgr::SendRequest(int32_t code, MessageParcel &data, MessageParcel &reply)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "BundleConnectAbilityMgr::SendRequest to service center");
    serviceCenterRemoteObject_ = serviceCenterConnection_->GetRemoteObject();
    if (serviceCenterRemoteObject_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "failed to get remote object");
        return false;
    }
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t result = serviceCenterRemoteObject_->SendRequest(code, data, reply, option);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "failed to send request code:%{public}d", code);
        return false;
    }
    return true;
}

sptr<IRemoteObject> BundleConnectAbilityMgr::GetAbilityManagerServiceCallBack(std::string transactId)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "GetAbilityManagerServiceCallBack");
    FreeInstallParams freeInstallParams;
    std::unique_lock<std::mutex> lock(mapMutex_);
    auto node = freeInstallParamsMap_.find(transactId);
    if (node == freeInstallParamsMap_.end()) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Can not find node transactId = %{public}s", transactId.c_str());
        return nullptr;
    }
    freeInstallParams = node->second;
    lock.unlock();
    return freeInstallParams.callback;
}

void BundleConnectAbilityMgr::GetCallingInfo(int32_t userId, int32_t callingUid,
    std::vector<std::string> &bundleNames, std::vector<std::string> &callingAppIds)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "enter");
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<BundleDataMgr> bundleDataMgr_ = bms->GetDataMgr();
    if (bundleDataMgr_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetDataMgr failed, bundleDataMgr_ is nullptr");
        return;
    }
    std::string bundleName;
    if (bundleDataMgr_->GetBundleNameForUid(callingUid, bundleName)) {
        bundleNames.emplace_back(bundleName);
    } else {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetBundleNameForUid failed");
    }
    BundleInfo bundleInfo;
    if (bundleDataMgr_->GetBundleInfo(bundleName, GET_BUNDLE_DEFAULT, bundleInfo, userId)) {
        callingAppIds.emplace_back(bundleInfo.appId);
    } else {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetBundleInfo failed");
    }
}

bool ExistBundleNameInCallingBundles(const std::string &bundleName, const std::vector<std::string> &callingBundleNames)
{
    for (const auto &bundleNameItem : callingBundleNames) {
        if (bundleNameItem == bundleName) {
            return true;
        }
    }
    return false;
}

int32_t GetTargetInfoFlag(const Want &want, const std::string &deviceId, const std::string &bundleName,
    const std::vector<std::string> &callingBundleNames)
{
    // make int from bits.
    int32_t flagZero = BIT_ZERO_COMPATIBLE;
    int32_t flagOne = 0;
    if ((want.GetFlags() & Want::FLAG_INSTALL_WITH_BACKGROUND_MODE) == 0) {
        flagOne = BIT_ONE_FRONT_MODE * BIT_ONE;
    } else {
        flagOne = BIT_ONE_BACKGROUND_MODE * BIT_ONE;
    }
    int32_t flagTwo = BIT_TWO_CUSTOM * BIT_TWO;
    int32_t flagThree = !deviceId.empty() * BIT_THREE;
    int32_t flagFour = BIT_FOUR_AZ_DEVICE * BIT_FOUR;
    int32_t flagFive = !ExistBundleNameInCallingBundles(bundleName, callingBundleNames) * BIT_FIVE;
    int32_t flagSix = BIT_SIX_SAME_BUNDLE * BIT_SIX;
    return flagZero + flagOne + flagTwo + flagThree + flagFour + flagFive + flagSix;
}

void BundleConnectAbilityMgr::GetTargetAbilityInfo(const Want &want, int32_t userId,
    const InnerBundleInfo &innerBundleInfo, sptr<TargetAbilityInfo> &targetAbilityInfo)
{
    if (targetAbilityInfo == nullptr) {
        return;
    }
    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string moduleName = element.GetModuleName();
    if (!GetModuleName(innerBundleInfo, want, moduleName)) {
        LOG_W(BMS_TAG_FREE_INSTALL, "GetModuleName failed");
    }
    std::string abilityName = element.GetAbilityName();
    std::string deviceId = element.GetDeviceID();
    std::vector<std::string> callingBundleNames;
    std::vector<std::string> callingAppids;
    auto wantParams = want.GetParams();
    std::map<std::string, std::string> extValues;
    for (auto it : wantParams.GetParams()) {
        int typeId = WantParams::GetDataType(it.second);
        auto info = wantParams.GetParam(it.first);
        std::string value = wantParams.GetStringByType(info, typeId);
        extValues.emplace(it.first, value);
    }
    auto callingUid = want.GetIntParam(PARAM_FREEINSTALL_UID, IPCSkeleton::GetCallingUid());

    targetAbilityInfo->targetExtSetting.extValues = extValues;
    targetAbilityInfo->targetInfo.transactId = std::to_string(this->GetTransactId());
    targetAbilityInfo->targetInfo.bundleName = bundleName;
    targetAbilityInfo->targetInfo.moduleName = moduleName;
    targetAbilityInfo->targetInfo.abilityName = abilityName;
    targetAbilityInfo->targetInfo.action = want.GetAction();
    targetAbilityInfo->targetInfo.uri = want.GetUriString();
    targetAbilityInfo->targetInfo.type = want.GetType();
    targetAbilityInfo->targetInfo.callingUid = callingUid;
    targetAbilityInfo->targetInfo.callingAppType = CALLING_TYPE_HARMONY;
    if (callingUid == DMS_UID) {
        callingAppids.push_back(want.GetStringParam(PARAM_FREEINSTALL_APPID));
        callingBundleNames = want.GetStringArrayParam(PARAM_FREEINSTALL_BUNDLENAMES);
    } else {
        this->GetCallingInfo(userId, callingUid, callingBundleNames, callingAppids);
    }
    targetAbilityInfo->targetInfo.callingBundleNames = callingBundleNames;
    targetAbilityInfo->targetInfo.flags = GetTargetInfoFlag(want, deviceId, bundleName, callingBundleNames);
    targetAbilityInfo->targetInfo.reasonFlag = static_cast<int32_t>(innerBundleInfo.GetModuleUpgradeFlag(moduleName));
    targetAbilityInfo->targetInfo.embedded = want.GetIntParam(PARAM_FREEINSTALL_EMBEDDED, DEFAULT_EMBEDDED_VALUE);
    targetAbilityInfo->targetInfo.callingAppIds = callingAppids;
}

void BundleConnectAbilityMgr::CallAbilityManager(
    int32_t resultCode, const Want &want, int32_t userId, const sptr<IRemoteObject> &callBack)
{
    if (callBack == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "callBack is nullptr");
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(ATOMIC_SERVICE_STATUS_CALLBACK_TOKEN)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write interface token failed");
        return;
    }
    if (!data.WriteInt32(resultCode)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write result code failed");
        return;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write want failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Write userId failed");
        return;
    }

    if (callBack->SendRequest(FREE_INSTALL_DONE, data, reply, option) != ERR_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "BundleConnectAbilityMgr::CallAbilityManager SendRequest failed");
    }
}

bool BundleConnectAbilityMgr::CheckIsModuleNeedUpdate(
    InnerBundleInfo &innerBundleInfo, const Want &want, int32_t userId, const sptr<IRemoteObject> &callBack)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "CheckIsModuleNeedUpdate called");
    std::string moduleName = want.GetModuleName();
    if (!GetModuleName(innerBundleInfo, want, moduleName)) {
        LOG_W(BMS_TAG_FREE_INSTALL, "GetModuleName failed");
    }
    if (innerBundleInfo.GetModuleUpgradeFlag(moduleName) != 0) {
        sptr<TargetAbilityInfo> targetAbilityInfo = new(std::nothrow) TargetAbilityInfo();
        if (targetAbilityInfo == nullptr) {
            LOG_E(BMS_TAG_FREE_INSTALL, "targetAbilityInfo is nullptr");
            return false;
        }
        sptr<TargetInfo> targetInfo = new(std::nothrow) TargetInfo();
        if (targetInfo == nullptr) {
            LOG_E(BMS_TAG_FREE_INSTALL, "targetInfo is nullptr");
            return false;
        }
        sptr<TargetExtSetting> targetExtSetting = new(std::nothrow) TargetExtSetting();
        if (targetExtSetting == nullptr) {
            LOG_E(BMS_TAG_FREE_INSTALL, "targetExtSetting is nullptr");
            return false;
        }
        targetAbilityInfo->targetInfo = *targetInfo;
        targetAbilityInfo->targetExtSetting = *targetExtSetting;
        targetAbilityInfo->version = DEFAULT_VERSION;
        this->GetTargetAbilityInfo(want, userId, innerBundleInfo, targetAbilityInfo);
        if (targetAbilityInfo->targetInfo.moduleName.empty()) {
            targetAbilityInfo->targetInfo.moduleName = moduleName;
        }
        sptr<FreeInstallParams> freeInstallParams = new(std::nothrow) FreeInstallParams();
        if (freeInstallParams == nullptr) {
            LOG_E(BMS_TAG_FREE_INSTALL, "freeInstallParams is nullptr");
            return false;
        }
        freeInstallParams->callback = callBack;
        freeInstallParams->want = want;
        freeInstallParams->userId = userId;
        freeInstallParams->serviceCenterFunction = ServiceCenterFunction::CONNECT_UPGRADE_INSTALL;
        this->UpgradeInstall(*targetAbilityInfo, want, *freeInstallParams, userId);
        return true;
    }
    LOG_I(BMS_TAG_FREE_INSTALL, "Module is not need update");
    return false;
}

bool BundleConnectAbilityMgr::IsObtainAbilityInfo(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, const sptr<IRemoteObject> &callBack, InnerBundleInfo &innerBundleInfo)
{
    LOG_D(BMS_TAG_FREE_INSTALL, "IsObtainAbilityInfo");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string moduleName = want.GetElement().GetModuleName();
    if (bundleName == "") {
        CallAbilityManager(FreeInstallErrorCode::UNDEFINED_ERROR, want, userId, callBack);
        LOG_E(BMS_TAG_FREE_INSTALL, "bundle name or ability name is null");
        return false;
    }
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<BundleDataMgr> bundleDataMgr_ = bms->GetDataMgr();
    if (bundleDataMgr_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetDataMgr failed, bundleDataMgr_ is nullptr");
        return false;
    }
    bool innerBundleInfoResult = bundleDataMgr_->GetInnerBundleInfoWithBundleFlagsAndLock(bundleName,
        flags, innerBundleInfo, userId);
    if (!innerBundleInfoResult) {
        APP_LOGE("GetInnerBundleInfoWithBundleFlagsAndLock failed.");
        return false;
    }
    if (abilityName.empty()) {
        Want launchWant;
        auto launchWantResult = bundleDataMgr_->GetLaunchWantForBundle(bundleName, launchWant, userId);
        if (launchWantResult == ERR_OK) {
            (const_cast<Want &>(want)).SetModuleName(launchWant.GetModuleName());
        }
        return CheckIsModuleNeedUpdateWrap(innerBundleInfo, want, userId, callBack);
    }
    bool abilityInfoResult = bundleDataMgr_->QueryAbilityInfo(want, flags, userId, abilityInfo);
    if (!abilityInfoResult) {
        std::vector<ExtensionAbilityInfo> extensionInfos;
        abilityInfoResult = bundleDataMgr_->QueryExtensionAbilityInfos(want, flags, userId, extensionInfos);
        if (abilityInfoResult && moduleName.empty()) {
            moduleName = extensionInfos[0].moduleName;
        }
    } else {
        if (moduleName.empty()) {
            moduleName = abilityInfo.moduleName;
        }
    }
    if (abilityInfoResult) {
        return CheckIsModuleNeedUpdateWrap(innerBundleInfo, want, userId, callBack);
    }
    return false;
}

bool BundleConnectAbilityMgr::CheckIsModuleNeedUpdateWrap(InnerBundleInfo &innerBundleInfo, const Want &want,
    int32_t userId, const sptr<IRemoteObject> &callBack)
{
    bool isModuleNeedUpdate = CheckIsModuleNeedUpdate(innerBundleInfo, want, userId, callBack);
    if (!isModuleNeedUpdate) {
        CallAbilityManager(ServiceCenterResultCode::FREE_INSTALL_OK, want, userId, callBack);
    }
    return true;
}

bool BundleConnectAbilityMgr::QueryAbilityInfo(const Want &want, int32_t flags,
    int32_t userId, AbilityInfo &abilityInfo, const sptr<IRemoteObject> &callBack)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_FREE_INSTALL, "QueryAbilityInfo");
    InnerBundleInfo innerBundleInfo;
    if (IsObtainAbilityInfo(want, flags, userId, abilityInfo, callBack, innerBundleInfo)) {
        return true;
    }
    sptr<TargetAbilityInfo> targetAbilityInfo = new(std::nothrow) TargetAbilityInfo();
    if (targetAbilityInfo == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetAbilityInfo is nullptr");
        return false;
    }
    sptr<TargetInfo> targetInfo = new(std::nothrow) TargetInfo();
    if (targetInfo == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetInfo is nullptr");
        return false;
    }
    sptr<TargetExtSetting> targetExtSetting = new(std::nothrow) TargetExtSetting();
    if (targetExtSetting == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetExtSetting is nullptr");
        return false;
    }
    targetAbilityInfo->targetInfo = *targetInfo;
    targetAbilityInfo->targetExtSetting = *targetExtSetting;
    targetAbilityInfo->version = DEFAULT_VERSION;
    this->GetTargetAbilityInfo(want, userId, innerBundleInfo, targetAbilityInfo);
    sptr<FreeInstallParams> freeInstallParams = new(std::nothrow) FreeInstallParams();
    if (freeInstallParams == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "freeInstallParams is nullptr");
        return false;
    }
    freeInstallParams->callback = callBack;
    freeInstallParams->want = want;
    freeInstallParams->userId = userId;
    freeInstallParams->serviceCenterFunction = ServiceCenterFunction::CONNECT_SILENT_INSTALL;

    this->SilentInstall(*targetAbilityInfo, want, *freeInstallParams, userId);
    return false;
}

bool BundleConnectAbilityMgr::SilentInstall(const Want &want, int32_t userId, const sptr<IRemoteObject> &callBack)
{
    LOG_D(BMS_TAG_FREE_INSTALL, "SilentInstall");
    sptr<TargetAbilityInfo> targetAbilityInfo = new(std::nothrow) TargetAbilityInfo();
    if (targetAbilityInfo == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetAbilityInfo is nullptr");
        return false;
    }
    sptr<TargetInfo> targetInfo = new(std::nothrow) TargetInfo();
    if (targetInfo == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetInfo is nullptr");
        return false;
    }
    sptr<TargetExtSetting> targetExtSetting = new(std::nothrow) TargetExtSetting();
    if (targetExtSetting == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetExtSetting is nullptr");
        return false;
    }

    targetAbilityInfo->targetInfo = *targetInfo;
    targetAbilityInfo->targetExtSetting = *targetExtSetting;
    targetAbilityInfo->version = DEFAULT_VERSION;
    InnerBundleInfo innerBundleInfo;
    GetTargetAbilityInfo(want, userId, innerBundleInfo, targetAbilityInfo);
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::vector<std::string> callingBundleNames;
    std::vector<std::string> callingAppids;
    GetCallingInfo(userId, callingUid, callingBundleNames, callingAppids);
    targetAbilityInfo->targetInfo.callingUid = callingUid;
    targetAbilityInfo->targetInfo.callingBundleNames = callingBundleNames;
    targetAbilityInfo->targetInfo.callingAppIds = callingAppids;
    sptr<FreeInstallParams> freeInstallParams = new(std::nothrow) FreeInstallParams();
    if (freeInstallParams == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "freeInstallParams is nullptr");
        return false;
    }

    freeInstallParams->callback = callBack;
    freeInstallParams->want = want;
    freeInstallParams->userId = userId;
    freeInstallParams->serviceCenterFunction = ServiceCenterFunction::CONNECT_SILENT_INSTALL;
    SilentInstall(*targetAbilityInfo, want, *freeInstallParams, userId);
    return true;
}

void BundleConnectAbilityMgr::UpgradeAtomicService(const Want &want, int32_t userId)
{
    LOG_I(BMS_TAG_FREE_INSTALL, "UpgradeAtomicService");
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<BundleDataMgr> bundleDataMgr_ = bms->GetDataMgr();
    if (bundleDataMgr_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetDataMgr failed, bundleDataMgr_ is nullptr");
        return;
    }
    std::string bundleName = want.GetElement().GetBundleName();
    InnerBundleInfo innerBundleInfo;
    bundleDataMgr_->GetInnerBundleInfoWithBundleFlagsAndLock(bundleName, want.GetFlags(), innerBundleInfo, userId);
    if (!innerBundleInfo.GetEntryInstallationFree()) {
        LOG_I(BMS_TAG_FREE_INSTALL, "bundleName:%{public}s is atomic application", bundleName.c_str());
        return;
    }
    LOG_I(BMS_TAG_FREE_INSTALL, "bundleName:%{public}s is atomic service", bundleName.c_str());
    sptr<TargetAbilityInfo> targetAbilityInfo = new(std::nothrow) TargetAbilityInfo();
    if (targetAbilityInfo == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetAbilityInfo is nullptr");
        return;
    }
    sptr<TargetInfo> targetInfo = new(std::nothrow) TargetInfo();
    if (targetInfo == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetInfo is nullptr");
        return;
    }
    sptr<TargetExtSetting> targetExtSetting = new(std::nothrow) TargetExtSetting();
    if (targetExtSetting == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "targetExtSetting is nullptr");
        return;
    }
    targetAbilityInfo->targetInfo = *targetInfo;
    targetAbilityInfo->targetExtSetting = *targetExtSetting;
    targetAbilityInfo->version = DEFAULT_VERSION;
    this->GetTargetAbilityInfo(want, userId, innerBundleInfo, targetAbilityInfo);
    if (!GetModuleName(innerBundleInfo, want, targetAbilityInfo->targetInfo.moduleName)) {
        LOG_W(BMS_TAG_FREE_INSTALL, "GetModuleName failed");
    }

    sptr<FreeInstallParams> freeInstallParams = new(std::nothrow) FreeInstallParams();
    if (freeInstallParams == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "freeInstallParams is nullptr");
        return;
    }
    freeInstallParams->want = want;
    freeInstallParams->userId = userId;
    freeInstallParams->serviceCenterFunction = ServiceCenterFunction::CONNECT_UPGRADE_CHECK;
    this->UpgradeCheck(*targetAbilityInfo, want, *freeInstallParams, userId);
}

bool BundleConnectAbilityMgr::CheckEcologicalRule(const Want &want, ErmsCallerInfo &callerInfo, BmsExperienceRule &rule)
{
    sptr<BmsEcologicalRuleMgrServiceClient> instance_ =
        BmsEcologicalRuleMgrServiceClient::GetInstance();
    if (instance_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Failed to get instance from erms.");
        return false;
    }
    int ret = instance_->QueryFreeInstallExperience(want, callerInfo, rule);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Failed to query free install experience from erms.");
        return false;
    }
    return true;
}

void BundleConnectAbilityMgr::GetEcologicalCallerInfo(const Want &want, ErmsCallerInfo &callerInfo, int32_t userId)
{
    callerInfo.packageName = want.GetStringParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME);
    callerInfo.uid = want.GetIntParam(PARAM_FREEINSTALL_UID, IPCSkeleton::GetCallingUid());
    callerInfo.pid = want.GetIntParam(Want::PARAM_RESV_CALLER_PID, DEFAULT_VALUE);
    callerInfo.targetAppType = TYPE_HARMONEY_SERVICE;
    callerInfo.callerAppType = TYPE_HARMONEY_INVALID;
    callerInfo.targetAppDistType = want.GetStringParam(PARAM_FREEINSTALL_TARGET_APP_DIST_TYPE);
    callerInfo.embedded = want.GetIntParam(PARAM_FREEINSTALL_EMBEDDED, DEFAULT_EMBEDDED_VALUE);
    callerInfo.targetAppProvisionType = want.GetStringParam(PARAM_FREEINSTALL_TARGET_APP_PROVISION_TYPE);
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<BundleDataMgr> bundleDataMgr_ = bms->GetDataMgr();
    if (bundleDataMgr_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetDataMgr failed, bundleDataMgr_ is nullptr");
        return;
    }
    std::string callerBundleName;
    ErrCode err = bundleDataMgr_->GetNameForUid(callerInfo.uid, callerBundleName);
    if (err != ERR_OK) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Get callerBundleName failed.");
        return;
    }
    AppExecFwk::ApplicationInfo callerAppInfo;
    bool getCallerResult = bundleDataMgr_->GetApplicationInfo(callerBundleName,
        AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, callerAppInfo);
    if (!getCallerResult) {
        LOG_E(BMS_TAG_FREE_INSTALL, "Get callerAppInfo failed.");
        return;
    }
    callerInfo.callerAppProvisionType = callerAppInfo.appProvisionType;
    InnerBundleInfo info;
    bool getInnerBundleInfoRes = bundleDataMgr_->GetInnerBundleInfoWithBundleFlagsAndLock(callerBundleName,
        AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, info, userId);
    if (!getInnerBundleInfoRes) {
        APP_LOGW("Get callerInnerBundleInfo failed.");
        return;
    }
    callerInfo.callerModelType = BmsCallerInfo::MODEL_FA;
    if (info.GetIsNewVersion()) {
        callerInfo.callerModelType = BmsCallerInfo::MODEL_STAGE;
    }
    if (callerAppInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE) {
        LOG_D(BMS_TAG_FREE_INSTALL, "the caller type is atomic service");
        callerInfo.callerAppType = TYPE_HARMONEY_SERVICE;
    } else if (callerAppInfo.bundleType == AppExecFwk::BundleType::APP) {
        LOG_D(BMS_TAG_FREE_INSTALL, "the caller type is app");
        callerInfo.callerAppType = TYPE_HARMONEY_APP;
    } else {
        LOG_D(BMS_TAG_FREE_INSTALL, "the caller type is invalid type");
    }
}

bool BundleConnectAbilityMgr::CheckIsOnDemandLoad(const TargetAbilityInfo &targetAbilityInfo) const
{
    if (targetAbilityInfo.targetInfo.callingBundleNames.empty()) {
        LOG_D(BMS_TAG_FREE_INSTALL, "callingBundleNames in targetAbilityInfo is empty.");
        return false;
    }
    if (targetAbilityInfo.targetInfo.callingBundleNames[0] != targetAbilityInfo.targetInfo.bundleName) {
        LOG_D(BMS_TAG_FREE_INSTALL, "callingBundleName is different with target bundleName.");
        return false;
    }
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bms == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "BundleMgrService GetInstance failed");
        return false;
    }
    std::shared_ptr<BundleDataMgr> bundleDataMgr_ = bms->GetDataMgr();
    if (bundleDataMgr_ == nullptr) {
        LOG_E(BMS_TAG_FREE_INSTALL, "GetDataMgr failed, bundleDataMgr_ is nullptr");
        return false;
    }
    BundleInfo bundleInfo;
    if (bundleDataMgr_->GetBundleInfo(
        targetAbilityInfo.targetInfo.bundleName, GET_BUNDLE_DEFAULT, bundleInfo, Constants::ANY_USERID)) {
        return bundleInfo.applicationInfo.bundleType == BundleType::ATOMIC_SERVICE;
    }
    return false;
}

bool BundleConnectAbilityMgr::GetModuleName(const InnerBundleInfo &innerBundleInfo,
    const Want &want, std::string &moduleName) const
{
    if (!moduleName.empty()) {
        return true;
    }
    auto baseAbilitiesInfo = innerBundleInfo.GetInnerAbilityInfos();
    ElementName element = want.GetElement();
    std::string abilityName = element.GetAbilityName();
    for (const auto& info : baseAbilitiesInfo) {
        if (info.second.name == abilityName) {
            moduleName = info.second.moduleName;
            return true;
        }
    }
    LOG_E(BMS_TAG_FREE_INSTALL, "GetModuleName failed, ability(%{public}s) is not existed in bundle(%{public}s)",
        abilityName.c_str(), innerBundleInfo.GetBundleName().c_str());
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
