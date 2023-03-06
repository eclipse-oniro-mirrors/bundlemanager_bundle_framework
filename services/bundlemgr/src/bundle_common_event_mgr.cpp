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

#include "bundle_common_event_mgr.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_util.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
BundleCommonEventMgr::BundleCommonEventMgr()
{
    APP_LOGI("enter BundleCommonEventMgr");
    Init();
}

void BundleCommonEventMgr::Init()
{
    commonEventMap_ = {
        { NotifyType::INSTALL, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED },
        { NotifyType::UNINSTALL_BUNDLE, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED },
        { NotifyType::UNINSTALL_MODULE, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED },
        { NotifyType::UPDATE, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED },
        { NotifyType::ABILITY_ENABLE, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED },
        { NotifyType::APPLICATION_ENABLE, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED },
        { NotifyType::BUNDLE_DATA_CLEARED, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED },
        { NotifyType::BUNDLE_CACHE_CLEARED, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CACHE_CLEARED },
    };
}

void BundleCommonEventMgr::NotifyBundleStatus(const NotifyBundleEvents &installResult,
    const std::shared_ptr<BundleDataMgr> &dataMgr)
{
    APP_LOGD("notify type %{public}d with %{public}d for %{public}s-%{public}s in %{public}s",
        static_cast<int32_t>(installResult.type), installResult.resultCode, installResult.modulePackage.c_str(),
        installResult.abilityName.c_str(), installResult.bundleName.c_str());

    std::string eventData = GetCommonEventData(installResult.type);
    APP_LOGD("will send event data %{public}s", eventData.c_str());
    OHOS::AAFwk::Want want;
    want.SetAction(eventData);
    ElementName element;
    element.SetBundleName(installResult.bundleName);
    element.SetAbilityName(installResult.abilityName);
    want.SetElement(element);
    want.SetParam(Constants::UID, installResult.uid);
    want.SetParam(Constants::USER_ID, BundleUtil::GetUserIdByUid(installResult.uid));
    want.SetParam(Constants::ABILITY_NAME, installResult.abilityName);
    want.SetParam(Constants::ACCESS_TOKEN_ID, static_cast<int32_t>(installResult.accessTokenId));
    want.SetParam(Constants::IS_AGING_UNINSTALL, installResult.isAgingUninstall);
    EventFwk::CommonEventData commonData { want };
    // trigger BundleEventCallback first
    if (dataMgr != nullptr) {
        dataMgr->NotifyBundleEventCallback(commonData);
    }

    uint8_t installType = ((installResult.type == NotifyType::UNINSTALL_BUNDLE) ||
            (installResult.type == NotifyType::UNINSTALL_MODULE)) ?
            static_cast<uint8_t>(InstallType::UNINSTALL_CALLBACK) :
            static_cast<uint8_t>(InstallType::INSTALL_CALLBACK);

    // trigger the status callback for status listenning
    if (dataMgr != nullptr) {
        auto &callbackMutex = dataMgr->GetStatusCallbackMutex();
        std::shared_lock<std::shared_mutex> lock(callbackMutex);
        auto callbackList = dataMgr->GetCallBackList();
        for (const auto& callback : callbackList) {
            if (callback->GetBundleName() == installResult.bundleName) {
                // if the msg needed, it could convert in the proxy node
                callback->OnBundleStateChanged(installType, installResult.resultCode, Constants::EMPTY_STRING,
                    installResult.bundleName);
            }
        }
    }

    if (installResult.resultCode != ERR_OK) {
        return;
    }
    EventFwk::CommonEventManager::PublishCommonEvent(commonData);
}

ErrCode BundleCommonEventMgr::NotifySandboxAppStatus(const InnerBundleInfo &info, int32_t uid, int32_t userId,
    const SandboxInstallType &type)
{
    OHOS::AAFwk::Want want;
    if (type == SandboxInstallType::INSTALL) {
        want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_ADDED);
    } else if (type == SandboxInstallType::UNINSTALL) {
        want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    } else {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_UNKNOWN_INSTALL_TYPE;
    }
    ElementName element;
    element.SetBundleName(info.GetBundleName());
    element.SetAbilityName(info.GetMainAbility());
    want.SetElement(element);
    want.SetParam(Constants::UID, uid);
    want.SetParam(Constants::USER_ID, userId);
    want.SetParam(Constants::ABILITY_NAME, info.GetMainAbility());
    want.SetParam(Constants::SANDBOX_APP_INDEX, info.GetAppIndex());
    want.SetParam(Constants::ACCESS_TOKEN_ID, static_cast<int32_t>(info.GetAccessTokenId(userId)));
    EventFwk::CommonEventData commonData { want };
    EventFwk::CommonEventManager::PublishCommonEvent(commonData);
    return ERR_OK;
}

std::string BundleCommonEventMgr::GetCommonEventData(const NotifyType &type)
{
    auto iter = commonEventMap_.find(type);
    if (iter == commonEventMap_.end()) {
        APP_LOGW("event type error");
        return EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED;
    }
    return iter->second;
}
} // AppExecFwk
} // OHOS