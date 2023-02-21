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

#include "bundle_distributed_manager.h"

#include "app_log_wrapper.h"
#include "ability_manager_client.h"
#include "bundle_manager_callback.h"
#include "bundle_mgr_service.h"
#include "distributed_device_profile_client.h"
#include "free_install_params.h"
#include "json_util.h"
#include "scope_guard.h"
#include "syscap_interface.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t CHECK_ABILITY_ENABLE_INSTALL = 1;
const uint32_t OUT_TIME = 3000;
const std::string DISTRIBUTED_MANAGER_THREAD = "DistributedManagerThread";
const std::string SERVICE_CENTER_BUNDLE_NAME = "com.ohos.hag.famanager";
const std::string SERVICE_CENTER_ABILITY_NAME = "HapInstallServiceAbility";
const std::u16string DMS_BUNDLE_MANAGER_CALLBACK_TOKEN = u"ohos.DistributedSchedule.IDmsBundleManagerCallback";
}

void BundleDistributedManager::Init()
{
    runner_ = EventRunner::Create(DISTRIBUTED_MANAGER_THREAD);
    if (runner_ == nullptr) {
        APP_LOGE("Create runner failed");
        return;
    }

    handler_ = std::make_shared<AppExecFwk::EventHandler>(runner_);
    if (handler_ == nullptr) {
        APP_LOGE("Create handler failed");
    }
}

BundleDistributedManager::BundleDistributedManager()
{
    Init();
}

BundleDistributedManager::~BundleDistributedManager()
{
    if (handler_ != nullptr) {
        handler_.reset();
    }
    if (runner_ != nullptr) {
        runner_.reset();
    }
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
    DeviceProfile::ServiceCharacteristicProfile profile;
    profile.SetServiceId(Constants::SYSCAP_SERVICE_ID);
    profile.SetServiceType(Constants::SYSCAP_SERVICE_TYPE);
    int32_t result = DeviceProfile::DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(
        want.GetElement().GetDeviceID(), Constants::SYSCAP_SERVICE_ID, profile);
    if (result != 0) {
        APP_LOGE("GetDeviceProfile failed result:%{public}d", result);
        return ErrorCode::GET_DEVICE_PROFILE_FAILED;
    }
    std::string jsonData = profile.GetCharacteristicProfileJson();
    APP_LOGI("CharacteristicProfileJson:%{public}s", jsonData.c_str());
    nlohmann::json jsonObject = nlohmann::json::parse(jsonData, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("jsonObject is_discarded");
        return ErrorCode::DECODE_SYS_CAP_FAILED;
    }
    std::vector<int> values = jsonObject[Constants::CHARACTER_OS_SYSCAP].get<std::vector<int>>();
    std::string pcId;
    for (int value : values) {
        pcId = pcId + std::to_string(value) + ",";
    }
    std::string capabilities = jsonObject[Constants::CHARACTER_PRIVATE_SYSCAP];
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
}

bool BundleDistributedManager::CheckAbilityEnableInstall(
    const Want &want, int32_t missionId, int32_t userId, const sptr<IRemoteObject> &callback)
{
    APP_LOGI("BundleDistributedManager::CheckAbilityEnableInstall");
    if (handler_ == nullptr) {
        APP_LOGE("handler_ is nullptr");
        return false;
    }
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
    auto ret = queryAbilityParamsMap_.emplace(targetAbilityInfo.targetInfo.transactId, *queryRpcIdParams);
    if (!ret.second) {
        APP_LOGE("BundleDistributedManager::QueryAbilityInfo map emplace error");
        return false;
    }
    auto queryRpcIdByAbilityFunc = [this, targetAbilityInfo]() {
        this->QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
    };
    handler_->PostTask(queryRpcIdByAbilityFunc, targetAbilityInfo.targetInfo.transactId.c_str());
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
    Want serviceCenterWant;
    serviceCenterWant.SetElementName(SERVICE_CENTER_BUNDLE_NAME, SERVICE_CENTER_ABILITY_NAME);
    bool ret = connectAbility->ConnectAbility(serviceCenterWant, nullptr);
    if (!ret) {
        APP_LOGE("fail to connect ServiceCenter");
        SendCallbackRequest(ErrorCode::CONNECT_FAILED, targetAbilityInfo.targetInfo.transactId);
        return false;
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
        return false;
    }
    OutTimeMonitor(targetAbilityInfo.targetInfo.transactId);
    return true;
}

void BundleDistributedManager::OutTimeMonitor(const std::string transactId)
{
    APP_LOGI("BundleDistributedManager::OutTimeMonitor");
    if (handler_ == nullptr) {
        APP_LOGE("OutTimeMonitor, handler is nullptr");
        return;
    }
    auto registerEventListenerFunc = [this, transactId]() {
        APP_LOGI("RegisterEventListenerFunc transactId:%{public}s", transactId.c_str());
        this->SendCallbackRequest(ErrorCode::WAITING_TIMEOUT, transactId);
    };
    handler_->PostTask(registerEventListenerFunc, transactId, OUT_TIME, AppExecFwk::EventQueue::Priority::LOW);
}

void BundleDistributedManager::OnQueryRpcIdFinished(const std::string &queryRpcIdResult)
{
    RpcIdResult rpcIdResult;
    APP_LOGI("queryRpcIdResult:%{public}s", queryRpcIdResult.c_str());
    if (!ParseInfoFromJsonStr(queryRpcIdResult.c_str(), rpcIdResult)) {
        APP_LOGE("Parse info from json fail");
        return;
    }
    auto queryAbilityParams = queryAbilityParamsMap_.find(rpcIdResult.transactId);
    if (queryAbilityParams == queryAbilityParamsMap_.end()) {
        APP_LOGE("Can not find node in %{public}s function", __func__);
        return;
    }
    if (handler_ != nullptr) {
        handler_->RemoveTask(rpcIdResult.transactId);
    }
    int32_t ret = ComparePcIdString(queryAbilityParams->second.want, rpcIdResult);
    if (ret != 0) {
        APP_LOGE("Compare pcId fail%{public}d", ret);
        SendCallbackRequest(ret, rpcIdResult.transactId);
    } else {
        SendCallbackRequest(rpcIdResult.retCode, rpcIdResult.transactId);
    }
}

void BundleDistributedManager::SendCallbackRequest(int32_t resultCode, const std::string &transactId)
{
    APP_LOGI("sendCallbackRequest resultCode:%{public}d, transactId:%{public}s", resultCode, transactId.c_str());
    auto queryAbilityParams = queryAbilityParamsMap_.find(transactId);
    if (queryAbilityParams == queryAbilityParamsMap_.end()) {
        APP_LOGE("Can not find transactId:%{public}s in queryAbilityParamsMap", transactId.c_str());
        return;
    }
    SendCallback(resultCode, queryAbilityParams->second);
    queryAbilityParamsMap_.erase(transactId);
    if (queryAbilityParamsMap_.size() == 0) {
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
