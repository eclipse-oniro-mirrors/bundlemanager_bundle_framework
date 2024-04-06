/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "app_log_wrapper.h"
#include "bms_ecological_rule_mgr_service_client.h"
#include "iremote_broker.h"
#include "iservice_registry.h"
#include <cinttypes>
namespace OHOS {
namespace AppExecFwk {

using namespace std::chrono;

static inline const std::u16string ERMS_INTERFACE_TOKEN =
    u"ohos.cloud.ecologicalrulemgrservice.IEcologicalRuleMgrService";

std::mutex BmsEcologicalRuleMgrServiceClient::instanceLock_;
sptr<BmsEcologicalRuleMgrServiceClient> BmsEcologicalRuleMgrServiceClient::instance_;
sptr<IBmsEcologicalRuleMgrService> BmsEcologicalRuleMgrServiceClient::bmsEcologicalRuleMgrServiceProxy_;
sptr<BmsEcologicalRuleMgrServiceDeathRecipient> BmsEcologicalRuleMgrServiceClient::deathRecipient_;

std::string BmsEcologicalRuleMgrServiceClient::ERMS_ORIGINAL_TARGET = "ecological_experience_original_target";

inline int64_t GetCurrentTimeMicro()
{
    return duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
}

BmsEcologicalRuleMgrServiceClient::~BmsEcologicalRuleMgrServiceClient()
{
    if (bmsEcologicalRuleMgrServiceProxy_ != nullptr) {
        auto remoteObj = bmsEcologicalRuleMgrServiceProxy_->AsObject();
        if (remoteObj != nullptr) {
            remoteObj->RemoveDeathRecipient(deathRecipient_);
        }
    }
}

sptr<BmsEcologicalRuleMgrServiceClient> BmsEcologicalRuleMgrServiceClient::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = (new (std::nothrow)  BmsEcologicalRuleMgrServiceClient);
        }
    }
    return instance_;
}

sptr<IBmsEcologicalRuleMgrService> BmsEcologicalRuleMgrServiceClient::ConnectService()
{
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        APP_LOGE("GetSystemAbilityManager error");
        return nullptr;
    }

    auto systemAbility = samgr->CheckSystemAbility(6105);
    if (systemAbility == nullptr) {
        APP_LOGE("CheckSystemAbility error, ECOLOGICALRULEMANAGERSERVICE_ID = 6105");
        return nullptr;
    }

    deathRecipient_ = (new (std::nothrow)   BmsEcologicalRuleMgrServiceDeathRecipient());
    systemAbility->AddDeathRecipient(deathRecipient_);

    return iface_cast<IBmsEcologicalRuleMgrService>(systemAbility);
}

bool BmsEcologicalRuleMgrServiceClient::CheckConnectService()
{
    if (bmsEcologicalRuleMgrServiceProxy_ == nullptr) {
        APP_LOGW("redo ConnectService");
        bmsEcologicalRuleMgrServiceProxy_ = ConnectService();
    }
    if (bmsEcologicalRuleMgrServiceProxy_ == nullptr) {
        APP_LOGE("Connect SA Failed");
        return false;
    }
    return true;
}

void BmsEcologicalRuleMgrServiceClient::OnRemoteSaDied(const wptr<IRemoteObject> &object)
{
    bmsEcologicalRuleMgrServiceProxy_ = ConnectService();
}

int32_t BmsEcologicalRuleMgrServiceClient::QueryFreeInstallExperience(const OHOS::AAFwk::Want &want,
    const BmsCallerInfo &callerInfo, BmsExperienceRule &rule)
{
    int64_t start = GetCurrentTimeMicro();
    APP_LOGD("QueryFreeInstallExperience want = %{public}s, callerInfo = %{public}s", want.ToString().c_str(),
        callerInfo.ToString().c_str());
    if (callerInfo.packageName.find_first_not_of(' ') == std::string::npos) {
        rule.isAllow = true;
        APP_LOGD("callerInfo packageName is empty, allow = true");
        return OHOS::AppExecFwk::IBmsEcologicalRuleMgrService::ErrCode::ERR_OK;
    }

    if (!CheckConnectService()) {
        APP_LOGW("check Connect SA Failed");
        return OHOS::AppExecFwk::IBmsEcologicalRuleMgrService::ErrCode::ERR_FAILED;
    }
    int32_t res = bmsEcologicalRuleMgrServiceProxy_->QueryFreeInstallExperience(want, callerInfo, rule);
    if (rule.replaceWant != nullptr) {
        rule.replaceWant->SetParam(ERMS_ORIGINAL_TARGET, want.ToString());
        APP_LOGD("QueryFreeInstallExperience  isAllow = %{public}d, replaceWant = %{public}s", rule.isAllow,
            (*(rule.replaceWant)).ToString().c_str());
    }
    int64_t cost = GetCurrentTimeMicro() - start;
    APP_LOGD("[ERMS-DFX] QueryFreeInstallExperience interface cost %{public}" PRId64"  mirco seconds.", cost);
    return res;
}

void BmsEcologicalRuleMgrServiceDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    BmsEcologicalRuleMgrServiceClient::GetInstance()->OnRemoteSaDied(object);
}

BmsEcologicalRuleMgrServiceProxy::BmsEcologicalRuleMgrServiceProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IBmsEcologicalRuleMgrService>(object)
{}

int32_t BmsEcologicalRuleMgrServiceProxy::QueryFreeInstallExperience(const Want &want, const BmsCallerInfo &callerInfo,
    BmsExperienceRule &rule)
{
    APP_LOGI("QueryFreeInstallExperience called");
    MessageParcel data;

    if (!data.WriteInterfaceToken(ERMS_INTERFACE_TOKEN)) {
        APP_LOGE("write token failed");
        return ERR_FAILED;
    }

    if (!data.WriteParcelable(&want)) {
        APP_LOGE("write want failed");
        return ERR_FAILED;
    }

    if (!data.WriteParcelable(&callerInfo)) {
        APP_LOGE("write callerInfo failed");
        return ERR_FAILED;
    }

    MessageOption option = { MessageOption::TF_SYNC };
    MessageParcel reply;

    auto remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("get Remote failed");
        return ERR_FAILED;
    }

    int32_t ret = remote->SendRequest(QUERY_FREE_INSTALL_EXPERIENCE_CMD, data, reply, option);
    if (ret != ERR_NONE) {
        APP_LOGE("SendRequest error, ret = %{public}d", ret);
        return ERR_FAILED;
    }

    std::unique_ptr<BmsExperienceRule> sptrRule(reply.ReadParcelable<BmsExperienceRule>());
    if (sptrRule == nullptr) {
        APP_LOGE("readParcelable sptrRule error");
        return ERR_FAILED;
    }

    rule = *sptrRule;
    APP_LOGI("QueryFreeInstallExperience end");
    return ERR_OK;
}

template <typename T>
bool BmsEcologicalRuleMgrServiceProxy::ReadParcelableVector(std::vector<T> &parcelableVector, MessageParcel &reply)
{
    int32_t infoSize = reply.ReadInt32();
    parcelableVector.clear();
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (info == nullptr) {
            APP_LOGE("read Parcelable infos failed");
            return false;
        }
        parcelableVector.emplace_back(*info);
    }
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
