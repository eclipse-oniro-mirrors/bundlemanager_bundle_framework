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

#include "bundle_distributed_manager.h"

#include "app_log_wrapper.h"
#include "ability_manager_client.h"
#include "bundle_manager_callback.h"
#include "bundle_memory_guard.h"
#include "bundle_mgr_service.h"
#include "free_install_params.h"
#include "json_util.h"
#include "scope_guard.h"
#include "syscap_interface.h"

#ifdef BMS_DEVICE_INFO_MANAGER_ENABLE
#include "distributed_device_profile_client.h"
#endif // BMS_DEVICE_INFO_MANAGER_ENABLE

namespace OHOS {
namespace AppExecFwk {
using namespace ffrt;
namespace {
const int32_t CHECK_ABILITY_ENABLE_INSTALL = 1;
const uint32_t OUT_TIME = 3000;
const std::string DISTRIBUTED_MANAGER_QUEUE = "DistributedManagerQueue";
const std::u16string DMS_BUNDLE_MANAGER_CALLBACK_TOKEN = u"ohos.DistributedSchedule.IDmsBundleManagerCallback";
const std::u16string SERVICE_CENTER_TOKEN = u"abilitydispatcherhm.openapi.hapinstall.IHapInstall";
// syscap
constexpr const char* CHARACTER_OS_SYSCAP = "ossyscap";
constexpr const char* CHARACTER_PRIVATE_SYSCAP = "privatesyscap";
}

BundleDistributedManager::BundleDistributedManager()
{
    APP_LOGD("create BundleDistributedManager");
    serialQueue_ = std::make_shared<SerialQueue>(DISTRIBUTED_MANAGER_QUEUE);
}

BundleDistributedManager::~BundleDistributedManager()
{
    APP_LOGD("destroy BundleDistributedManager");
}

bool BundleDistributedManager::ConvertTargetAbilityInfo(const Want &want, TargetAbilityInfo &targetAbilityInfo)
{
    auto elementName = want.GetElement();
    std::string bundleName = elementName.GetBundleName();
    std::string moduleName = elementName.GetModuleName();
    std::string abilityName = elementName.GetAbilityName();
    APP_LOGI("ConvertTargetAbilityInfo: %{public}s, %{public}s, %{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    AppExecFwk::TargetInfo targetInfo;
    targetInfo.transactId = std::to_string(this->GetTransactId());
    targetInfo.bundleName = bundleName;
    targetInfo.moduleName = moduleName;
    targetInfo.abilityName = abilityName;
    targetAbilityInfo.targetInfo = targetInfo;
    return true;
}

int32_t BundleDistributedManager::ComparePcIdString(const Want &want, const RpcIdResult &rpcIdResult)
{
#ifdef BMS_DEVICE_INFO_MANAGER_ENABLE
    DistributedDeviceProfile::DeviceProfile profile;
    int32_t result = DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(
        want.GetElement().GetDeviceID(), profile);
    if (result != 0) {
        APP_LOGE("GetDeviceProfile failed result:%{public}d", result);
        return ErrorCode::GET_DEVICE_PROFILE_FAILED;
    }
    std::string jsonData = profile.GetOsSysCap();
    APP_LOGI("CharacteristicProfileJson:%{public}s", jsonData.c_str());
    nlohmann::json jsonObject = nlohmann::json::parse(jsonData, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("jsonObject is_discarded");
        return ErrorCode::DECODE_SYS_CAP_FAILED;
    }
    std::vector<int> values = jsonObject[CHARACTER_OS_SYSCAP].get<std::vector<int>>();
    std::string pcId;
    for (int value : values) {
        pcId = pcId + std::to_string(value) + ",";
    }
    std::string capabilities = jsonObject[CHARACTER_PRIVATE_SYSCAP];
    if (capabilities.empty()) {
        pcId.resize(pcId.length() - 1);
    } else {
        pcId = pcId + capabilities;
    }
    APP_LOGD("sysCap pcId:%{public}s", pcId.c_str());
    for (auto &rpcId : rpcIdResult.abilityInfo.rpcId) {
        APP_LOGD("sysCap rpcId:%{public}s", rpcId.c_str());
        CompareError compareError = {{0}, 0, 0};
        int32_t ret = ComparePcidString(pcId.c_str(), rpcId.c_str(), &compareError);
        if (ret != 0) {
            APP_LOGE("ComparePcIdString failed errCode:%{public}d", ret);
            return ErrorCode::COMPARE_PC_ID_FAILED;
        }
    }
    return ErrorCode::NO_ERROR;
#else
    APP_LOGW("BMS_DEVICE_INFO_MANAGER_ENABLE is false");
    return ErrorCode::ERR_BMS_DEVICE_INFO_MANAGER_ENABLE_DISABLED;
#endif
}

bool BundleDistributedManager::CheckAbilityEnableInstall(
    const Want &want, int32_t missionId, int32_t userId, const sptr<IRemoteObject> &callback)
{
    APP_LOGI("BundleDistributedManager::CheckAbilityEnableInstall");
    AppExecFwk::TargetAbilityInfo targetAbilityInfo;
    if (!ConvertTargetAbilityInfo(want, targetAbilityInfo)) {
        return false;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("fail to get data mgr");
        return false;
    }
    ApplicationInfo applicationInfo;
    if (!dataMgr->GetApplicationInfo(
        targetAbilityInfo.targetInfo.bundleName, 0, userId, applicationInfo)) {
        APP_LOGE("fail to get bundleName:%{public}s application", targetAbilityInfo.targetInfo.bundleName.c_str());
        return false;
    }
    sptr<QueryRpcIdParams> queryRpcIdParams = new(std::nothrow) QueryRpcIdParams();
    if (queryRpcIdParams == nullptr) {
        APP_LOGE("queryRpcIdParams is nullptr");
        return false;
    }
    queryRpcIdParams->missionId = missionId;
    queryRpcIdParams->callback = callback;
    queryRpcIdParams->want = want;
    queryRpcIdParams->versionCode = applicationInfo.versionCode;
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto ret = queryAbilityParamsMap_.emplace(targetAbilityInfo.targetInfo.transactId, *queryRpcIdParams);
        if (!ret.second) {
            APP_LOGE("BundleDistributedManager::QueryAbilityInfo map emplace error");
            return false;
        }
    }
    auto queryRpcIdByAbilityFunc = [this, targetAbilityInfo]() {
        BundleMemoryGuard memoryGuard;
        auto res = this->QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
        if (!res) {
            SendCallbackRequest(ErrorCode::WAITING_TIMEOUT, targetAbilityInfo.targetInfo.transactId);
        }
    };
    ffrt::submit(queryRpcIdByAbilityFunc);
    return true;
}

bool BundleDistributedManager::QueryRpcIdByAbilityToServiceCenter(const TargetAbilityInfo &targetAbilityInfo)
{
    APP_LOGI("QueryRpcIdByAbilityToServiceCenter");
    auto connectAbility = DelayedSingleton<BundleMgrService>::GetInstance()->GetConnectAbility();
    if (connectAbility == nullptr) {
        APP_LOGE("fail to connect ServiceCenter");
        return false;
    }
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<BundleDataMgr> bundleDataMgr_ = bms->GetDataMgr();
    if (bundleDataMgr_ == nullptr) {
        APP_LOGE("GetDataMgr failed, bundleDataMgr_ is nullptr");
        SendCallbackRequest(ErrorCode::WAITING_TIMEOUT, targetAbilityInfo.targetInfo.transactId);
        return true;
    }
    std::string bundleName;
    std::string abilityName;
    if (!(bundleDataMgr_->QueryAppGalleryAbilityName(bundleName, abilityName))) {
        APP_LOGE("Fail to query ServiceCenter ability and bundle name");
        SendCallbackRequest(ErrorCode::CONNECT_FAILED, targetAbilityInfo.targetInfo.transactId);
        return true;
    }
    Want serviceCenterWant;
    serviceCenterWant.SetElementName(bundleName, abilityName);
    bool ret = connectAbility->ConnectAbility(serviceCenterWant, nullptr);
    if (!ret) {
        APP_LOGE("fail to connect ServiceCenter");
        SendCallbackRequest(ErrorCode::CONNECT_FAILED, targetAbilityInfo.targetInfo.transactId);
        return true;
    }
    const std::string targetInfo = GetJsonStrFromInfo(targetAbilityInfo);
    APP_LOGI("queryRpcId param :%{public}s", targetInfo.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(SERVICE_CENTER_TOKEN)) {
        APP_LOGE("failed to sendCallback due to write MessageParcel fail");
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(targetInfo))) {
        APP_LOGE("WriteString16 failed");
        return false;
    }
    sptr<BundleManagerCallback> bundleManagerCallback = new(std::nothrow) BundleManagerCallback(weak_from_this());
    if (bundleManagerCallback == nullptr) {
        APP_LOGE("bundleManagerCallback is nullptr");
        return false;
    }
    if (!data.WriteRemoteObject(bundleManagerCallback)) {
        APP_LOGE("failed to write remote object");
        return false;
    }
    ret = connectAbility->SendRequest(ServiceCenterFunction::CONNECT_QUERY_RPCID, data, reply);
    if (!ret) {
        APP_LOGE("send request to serviceCenter failed");
        SendCallbackRequest(ErrorCode::SEND_REQUEST_FAILED, targetAbilityInfo.targetInfo.transactId);
        return true;
    }
    OutTimeMonitor(targetAbilityInfo.targetInfo.transactId);
    return true;
}

void BundleDistributedManager::OutTimeMonitor(const std::string transactId)
{
    APP_LOGI("BundleDistributedManager::OutTimeMonitor");
    auto registerEventListenerFunc = [this, transactId]() {
        BundleMemoryGuard memoryGuard;
        APP_LOGI("RegisterEventListenerFunc transactId:%{public}s", transactId.c_str());
        this->SendCallbackRequest(ErrorCode::WAITING_TIMEOUT, transactId);
    };
    serialQueue_->ScheduleDelayTask(transactId, OUT_TIME, registerEventListenerFunc);
}

void BundleDistributedManager::OnQueryRpcIdFinished(const std::string &queryRpcIdResult)
{
    RpcIdResult rpcIdResult;
    APP_LOGI("queryRpcIdResult:%{public}s", queryRpcIdResult.c_str());
    if (!ParseInfoFromJsonStr(queryRpcIdResult.c_str(), rpcIdResult)) {
        APP_LOGE("Parse info from json fail");
        return;
    }
    Want want;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto queryAbilityParams = queryAbilityParamsMap_.find(rpcIdResult.transactId);
        if (queryAbilityParams == queryAbilityParamsMap_.end()) {
            APP_LOGE("Can not find node in %{public}s function", __func__);
            return;
        }
        want = queryAbilityParams->second.want;
    }
    serialQueue_->CancelDelayTask(rpcIdResult.transactId);
    if (rpcIdResult.retCode != 0) {
        APP_LOGE("query RpcId fail%{public}d", rpcIdResult.retCode);
        SendCallbackRequest(rpcIdResult.retCode, rpcIdResult.transactId);
        return;
    }
    int32_t ret = ComparePcIdString(want, rpcIdResult);
    if (ret != 0) {
        APP_LOGE("Compare pcId fail%{public}d", ret);
    }
    SendCallbackRequest(ret, rpcIdResult.transactId);
}

void BundleDistributedManager::SendCallbackRequest(int32_t resultCode, const std::string &transactId)
{
    APP_LOGI("sendCallbackRequest resultCode:%{public}d, transactId:%{public}s", resultCode, transactId.c_str());
    QueryRpcIdParams queryRpcIdParams;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto queryAbilityParams = queryAbilityParamsMap_.find(transactId);
        if (queryAbilityParams == queryAbilityParamsMap_.end()) {
            APP_LOGE("Can not find transactId:%{public}s in queryAbilityParamsMap", transactId.c_str());
            return;
        }
        queryRpcIdParams = queryAbilityParams->second;
    }
    SendCallback(resultCode, queryRpcIdParams);

    uint32_t mapSize;
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        queryAbilityParamsMap_.erase(transactId);
        mapSize = queryAbilityParamsMap_.size();
    }

    if (mapSize == 0) {
        auto connectAbility = DelayedSingleton<BundleMgrService>::GetInstance()->GetConnectAbility();
        if (connectAbility == nullptr) {
            APP_LOGW("fail to connect ServiceCenter");
            return;
        }
        connectAbility->DisconnectAbility();
    }
}

void BundleDistributedManager::SendCallback(int32_t resultCode, const QueryRpcIdParams &queryRpcIdParams)
{
    auto remoteObject = queryRpcIdParams.callback;
    if (remoteObject == nullptr) {
        APP_LOGW("sendCallbackRequest remoteObject is invalid");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_BUNDLE_MANAGER_CALLBACK_TOKEN)) {
        APP_LOGE("failed to sendCallback due to write MessageParcel fail");
        return;
    }
    if (!data.WriteInt32(resultCode)) {
        APP_LOGE("fail to sendCallback due to write resultCode fail");
        return;
    }
    if (!data.WriteUint32(queryRpcIdParams.versionCode)) {
        APP_LOGE("fail to sendCallback due to write versionCode fail");
        return;
    }
    if (!data.WriteInt32(queryRpcIdParams.missionId)) {
        APP_LOGE("fail to sendCallback due to write missionId fail");
        return;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remoteObject->SendRequest(CHECK_ABILITY_ENABLE_INSTALL, data, reply, option);
    if (result != 0) {
        APP_LOGE("failed to send request code:%{public}d", result);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
