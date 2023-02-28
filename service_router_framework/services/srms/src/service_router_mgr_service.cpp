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

#include <memory>
#include <string>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "if_system_ability_manager.h"
#include "service_router_data_mgr.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "service_router_mgr_service.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "sr_samgr_helper.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
const std::string NAME_SERVICE_ROUTER_MGR_SERVICE = "ServiceRouterMgrService";

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<ServiceRouterMgrService>::GetInstance().get());

ServiceRouterMgrService::ServiceRouterMgrService() : SystemAbility(SERVICE_ROUTER_MGR_SERVICE_ID, true)
{
    APP_LOGI("SRMS instance create");
}

ServiceRouterMgrService::~ServiceRouterMgrService()
{
    APP_LOGI("SRMS instance destroy");
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
    APP_LOGI("SRMS start success.");
}

void ServiceRouterMgrService::OnStop()
{
    APP_LOGI("Stop SRMS.");
}

void ServiceRouterMgrService::Init()
{
    APP_LOGI("Init start");
    initEventRunnerAndHandler();
    LoadAllBundleInfos();
    subscribeCommonEvent();
}

bool ServiceRouterMgrService::LoadAllBundleInfos()
{
    if (handler_ == nullptr) {
        APP_LOGE("%{public}s fail, handler_ is null", __func__);
        return false;
    }
    auto task = []() {
        APP_LOGI("LoadAllBundleInfos start");
        ServiceRouterDataMgr::GetInstance().LoadAllBundleInfos();
        APP_LOGI("LoadAllBundleInfos end");
    };
    handler_->PostTask(task);
    return true;
}

bool ServiceRouterMgrService::initEventRunnerAndHandler()
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

bool ServiceRouterMgrService::ServiceRouterMgrService::subscribeCommonEvent()
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

bool ServiceRouterMgrService::subscribeBundleEvent()
{
    bundleEventCallback_ = new (std::nothrow) SrBundleEventCallback(handler_);
    if (bundleEventCallback_ == nullptr) {
        APP_LOGE("%{public}s fail, allocate BundleEventCallbackHost failed!", __func__);
        return false;
    }
    sptr<IBundleMgr> iBundleMgr = SrSamgrHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("%{public}s fail, getBundleMgr failed!", __func__);
        return false;
    }
    bool ret = iBundleMgr->RegisterBundleEventCallback(bundleEventCallback_);
    if (!ret) {
        APP_LOGE("%{public}s fail, RegisterBundleEventCallback failed!", __func__);
    }
    return ret;
}

int32_t ServiceRouterMgrService::QueryServiceInfos(const Want &want, const ExtensionServiceType &serviceType,
    std::vector<ServiceInfo> &serviceInfos)
{
    APP_LOGI("%{public}s coldStart:", __func__);
    return ServiceRouterDataMgr::GetInstance().QueryServiceInfos(want, serviceType, serviceInfos);
}

int32_t ServiceRouterMgrService::QueryIntentInfos(const Want &want, const std::string intentName,
    std::vector<IntentInfo> &intentInfos)
{
    APP_LOGI("%{public}s coldStart:", __func__);
    return ServiceRouterDataMgr::GetInstance().QueryIntentInfos(want, intentName, intentInfos);
}
}  // namespace AAFwk
}  // namespace OHOS