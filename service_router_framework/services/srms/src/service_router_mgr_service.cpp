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

#include "service_router_mgr_service.h"

#include <memory>
#include <string>

#include "ability_manager_client.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "service_router_data_mgr.h"
#include "string_ex.h"
#include "sr_samgr_helper.h"
#include "system_ability_definition.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string NAME_SERVICE_ROUTER_MGR_SERVICE = "ServiceRouterMgrService";
const std::string TASK_NAME = "ServiceRouterUnloadTask";
const int64_t UNLOAD_DELAY_TIME = 90000;
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<ServiceRouterMgrService>::GetInstance().get());

ServiceRouterMgrService::ServiceRouterMgrService() : SystemAbility(SERVICE_ROUTER_MGR_SERVICE_ID, true)
{
    APP_LOGD("SRMS instance create");
}

ServiceRouterMgrService::~ServiceRouterMgrService()
{
    APP_LOGD("SRMS instance destroy");
}

void ServiceRouterMgrService::OnStart()
{
    APP_LOGI("SRMS starting...");
    Init();
    bool ret = Publish(this);
    if (!ret) {
        APP_LOGE("Publish SRMS failed!");
        return;
    }
    DelayUnloadTask();
    APP_LOGI("SRMS start success.");
}

void ServiceRouterMgrService::OnStop()
{
    APP_LOGI("Stop SRMS.");
}

void ServiceRouterMgrService::Init()
{
    LoadAllBundleInfos();
    InitEventRunnerAndHandler();
    SubscribeCommonEvent();
}

void ServiceRouterMgrService::DelayUnloadTask()
{
    if (handler_ == nullptr) {
        APP_LOGI("DelayUnloadTask, handler_ is nullptr");
        return;
    }
    
    std::lock_guard<std::mutex> lock(delayTaskMutex_);
    handler_->RemoveTask(TASK_NAME);
    auto task = [this]() {
        APP_LOGE("UnloadSA start.");
        sptr<ISystemAbilityManager> saManager =
            OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (saManager == nullptr) {
            APP_LOGE("UnloadSA, GetSystemAbilityManager is null.");
            return;
        }
        int32_t result = saManager->UnloadSystemAbility(OHOS::SERVICE_ROUTER_MGR_SERVICE_ID);
        if (result != ERR_OK) {
            APP_LOGE("UnloadSA, UnloadSystemAbility result: %{public}d", result);
            return;
        }
        APP_LOGI("UnloadSA success.");
    };
    handler_->PostTask(task, TASK_NAME, UNLOAD_DELAY_TIME);
}

bool ServiceRouterMgrService::LoadAllBundleInfos()
{
    APP_LOGD("LoadAllBundleInfos start");
    ServiceRouterDataMgr::GetInstance().LoadAllBundleInfos();
    APP_LOGD("LoadAllBundleInfos end");
    return true;
}

bool ServiceRouterMgrService::InitEventRunnerAndHandler()
{
    std::lock_guard<std::mutex> lock(mutex_);
    runner_ = EventRunner::Create(NAME_SERVICE_ROUTER_MGR_SERVICE);
    if (runner_ == nullptr) {
        APP_LOGE("%{public}s fail, Failed to init due to create runner error", __func__);
        return false;
    }
    handler_ = std::make_shared<EventHandler>(runner_);
    if (handler_ == nullptr) {
        APP_LOGE("%{public}s fail, Failed to init due to create handler error", __func__);
        return false;
    }
    return true;
}

bool ServiceRouterMgrService::ServiceRouterMgrService::SubscribeCommonEvent()
{
    if (eventSubscriber_ != nullptr) {
        APP_LOGI("subscribeCommonEvent already subscribed.");
        return true;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    eventSubscriber_ = std::make_shared<SrCommonEventSubscriber>(subscribeInfo);
    eventSubscriber_->SetEventHandler(handler_);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(eventSubscriber_)) {
        APP_LOGE("subscribeCommonEvent subscribed failure.");
        return false;
    };
    APP_LOGI("subscribeCommonEvent subscribed success.");
    return true;
}

int32_t ServiceRouterMgrService::QueryBusinessAbilityInfos(const BusinessAbilityFilter &filter,
    std::vector< BusinessAbilityInfo> &businessAbilityInfos)
{
    APP_LOGD("%{public}s coldStart:", __func__);
    DelayUnloadTask();
    return ServiceRouterDataMgr::GetInstance().QueryBusinessAbilityInfos(filter, businessAbilityInfos);
}

int32_t ServiceRouterMgrService::QueryPurposeInfos(const Want &want, const std::string purposeName,
    std::vector<PurposeInfo> &purposeInfos)
{
    APP_LOGD("%{public}s coldStart:", __func__);
    DelayUnloadTask();
    return ServiceRouterDataMgr::GetInstance().QueryPurposeInfos(want, purposeName, purposeInfos);
}

int32_t ServiceRouterMgrService::StartUIExtensionAbility(const Want &want, const sptr<SessionInfo> &sessionInfo,
    int32_t userId, ExtensionAbilityType extensionType)
{
    APP_LOGD("StartUIExtensionAbility start:");
    DelayUnloadTask();
    return IN_PROCESS_CALL(AbilityManagerClient::GetInstance()->
        StartUIExtensionAbility(want, sessionInfo, userId, extensionType));
}

int32_t ServiceRouterMgrService::ConnectUIExtensionAbility(const Want &want, const sptr<IAbilityConnection> &connect,
    const sptr<SessionInfo> &sessionInfo, int32_t userId)
{
    APP_LOGD("ConnectUIExtensionAbility start:");
    DelayUnloadTask();
    return IN_PROCESS_CALL(AbilityManagerClient::GetInstance()->
        ConnectUIExtensionAbility(want, connect, sessionInfo, userId));
}
}  // namespace AppExecFwk
}  // namespace OHOS