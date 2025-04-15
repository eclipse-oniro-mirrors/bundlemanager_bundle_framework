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

#include "account_helper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_common_event.h"
#include "bundle_util.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ACCESS_TOKEN_ID = "accessTokenId";
constexpr const char* IS_AGING_UNINSTALL = "isAgingUninstall";
constexpr const char* APP_ID = "appId";
constexpr const char* IS_MODULE_UPDATE = "isModuleUpdate";
constexpr const char* IS_ENABLE_DYNAMIC_ICON = "isEnableDynamicIcon";
constexpr const char* BUNDLE_RESOURCES_CHANGED = "usual.event.BUNDLE_RESOURCES_CHANGED";
constexpr const char* APP_IDENTIFIER = "appIdentifier";
constexpr const char* APP_DISTRIBUTION_TYPE = "appDistributionType";
constexpr const char* BUNDLE_TYPE = "bundleType";
constexpr const char* ATOMIC_SERVICE_MODULE_UPGRADE = "atomicServiceModuleUpgrade";
constexpr const char* UID = "uid";
constexpr const char* SANDBOX_APP_INDEX = "sandbox_app_index";
constexpr const char* BUNDLE_RESOURCE_CHANGE_TYPE = "bundleResourceChangeType";
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* TYPE = "type";
constexpr const char* RESULT_CODE = "resultCode";
constexpr const char* IS_APP_UPDATE = "isAppUpdate";
constexpr const char* PERMISSION_GET_DISPOSED_STATUS = "ohos.permission.GET_DISPOSED_APP_STATUS";
constexpr const char* ASSET_ACCESS_GROUPS = "assetAccessGroups";
constexpr const char* DEVELOPERID = "developerId";
constexpr const char* CHANGE_DEFAULT_APPLICATION = "ohos.permission.CHANGE_DEFAULT_APPLICATION";
constexpr const char* UTD_IDS = "utdIds";
}

BundleCommonEventMgr::BundleCommonEventMgr()
{
    APP_LOGI_NOFUNC("enter BundleCommonEventMgr");
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
        { NotifyType::UNINSTALL_STATE, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED },
        { NotifyType::APPLICATION_ENABLE, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED },
        { NotifyType::BUNDLE_DATA_CLEARED, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED },
        { NotifyType::BUNDLE_CACHE_CLEARED, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CACHE_CLEARED },
        { NotifyType::OVERLAY_INSTALL, OVERLAY_ADD_ACTION},
        { NotifyType::OVERLAY_UPDATE, OVERLAY_CHANGED_ACTION},
        { NotifyType::DISPOSED_RULE_ADDED, DISPOSED_RULE_ADDED},
        { NotifyType::DISPOSED_RULE_DELETED, DISPOSED_RULE_DELETED},
        { NotifyType::START_INSTALL, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_INSTALLATION_STARTED },
    };
}

void BundleCommonEventMgr::NotifyBundleStatus(const NotifyBundleEvents &installResult,
    const std::shared_ptr<BundleDataMgr> &dataMgr)
{
    APP_LOGD("notify type %{public}d with %{public}d for %{public}s-%{public}s in %{public}s",
        static_cast<int32_t>(installResult.type), installResult.resultCode, installResult.modulePackage.c_str(),
        installResult.abilityName.c_str(), installResult.bundleName.c_str());
    OHOS::AAFwk::Want want;
    SetNotifyWant(want, installResult);
    EventFwk::CommonEventData commonData { want };
    // trigger BundleEventCallback first
    if (dataMgr != nullptr && !(want.GetAction() == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED &&
        installResult.resultCode != ERR_OK)) {
        LOG_I(BMS_TAG_DEFAULT, "eventBack begin");
        dataMgr->NotifyBundleEventCallback(commonData);
        LOG_I(BMS_TAG_DEFAULT, "eventBack end");
    }

    uint8_t installType = ((installResult.type == NotifyType::UNINSTALL_BUNDLE) ||
            (installResult.type == NotifyType::UNINSTALL_MODULE)) ?
            static_cast<uint8_t>(InstallType::UNINSTALL_CALLBACK) :
            static_cast<uint8_t>(InstallType::INSTALL_CALLBACK);
    int32_t bundleUserId = BundleUtil::GetUserIdByUid(installResult.uid);
    int32_t publishUserId = (bundleUserId == Constants::DEFAULT_USERID) ?
        AccountHelper::GetCurrentActiveUserId() : bundleUserId;

    // trigger the status callback for status listening
    if ((dataMgr != nullptr) && (installResult.type != NotifyType::START_INSTALL)) {
        auto &callbackMutex = dataMgr->GetStatusCallbackMutex();
        std::shared_lock<std::shared_mutex> lock(callbackMutex);
        auto callbackList = dataMgr->GetCallBackList();
        for (const auto& callback : callbackList) {
            int32_t callbackUserId = callback->GetUserId();
            if (callbackUserId != Constants::UNSPECIFIED_USERID && callbackUserId != publishUserId) {
                LOG_W(BMS_TAG_DEFAULT, "not callback userId %{public}d incorrect", callbackUserId);
                continue;
            }
            if (callback->GetBundleName() == installResult.bundleName) {
                // if the msg needed, it could convert in the proxy node
                callback->OnBundleStateChanged(installType, installResult.resultCode, Constants::EMPTY_STRING,
                    installResult.bundleName);
            }
        }
    }

    if (installResult.resultCode != ERR_OK || installResult.isBmsExtensionUninstalled) {
        APP_LOGI("install ret: %{public}d, extension: %{public}d",
            installResult.resultCode, installResult.isBmsExtensionUninstalled);
        return;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!EventFwk::CommonEventManager::PublishCommonEventAsUser(commonData, publishUserId)) {
        APP_LOGE("PublishCommonEventAsUser failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
}

void BundleCommonEventMgr::SetNotifyWant(OHOS::AAFwk::Want& want, const NotifyBundleEvents &installResult)
{
    std::string eventData = GetCommonEventData(installResult.type);
    APP_LOGD("will send event data %{public}s", eventData.c_str());
    want.SetAction(eventData);
    ElementName element;
    element.SetBundleName(installResult.bundleName);
    element.SetModuleName(installResult.modulePackage);
    element.SetAbilityName(installResult.abilityName);
    want.SetElement(element);
    want.SetParam(Constants::BUNDLE_NAME, installResult.bundleName);
    want.SetParam(Constants::UID, installResult.uid);
    want.SetParam(Constants::USER_ID, BundleUtil::GetUserIdByUid(installResult.uid));
    want.SetParam(Constants::ABILITY_NAME, installResult.abilityName);
    want.SetParam(ACCESS_TOKEN_ID, static_cast<int32_t>(installResult.accessTokenId));
    want.SetParam(IS_AGING_UNINSTALL, installResult.isAgingUninstall);
    want.SetParam(APP_ID, installResult.appId);
    want.SetParam(IS_MODULE_UPDATE, installResult.isModuleUpdate);
    want.SetParam(APP_IDENTIFIER, installResult.appIdentifier);
    want.SetParam(APP_DISTRIBUTION_TYPE, installResult.appDistributionType);
    want.SetParam(BUNDLE_TYPE, installResult.bundleType);
    want.SetParam(ATOMIC_SERVICE_MODULE_UPGRADE, installResult.atomicServiceModuleUpgrade);
    want.SetParam(APP_INDEX, installResult.appIndex);
    want.SetParam(TYPE, static_cast<int32_t>(installResult.type));
    want.SetParam(RESULT_CODE, installResult.resultCode);
    want.SetParam(IS_APP_UPDATE, installResult.isAppUpdate);
    if (want.GetAction() == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED
        && !installResult.assetAccessGroups.empty()) {
        want.SetParam(ASSET_ACCESS_GROUPS, installResult.assetAccessGroups);
        want.SetParam(DEVELOPERID, installResult.developerId);
    }
}

ErrCode BundleCommonEventMgr::NotifySandboxAppStatus(const InnerBundleInfo &info, int32_t uid, int32_t userId,
    const SandboxInstallType &type)
{
    OHOS::AAFwk::Want want;
    if (type == SandboxInstallType::INSTALL) {
        want.SetAction(COMMON_EVENT_SANDBOX_PACKAGE_ADDED);
    } else if (type == SandboxInstallType::UNINSTALL) {
        want.SetAction(COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    } else {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_UNKNOWN_INSTALL_TYPE;
    }
    ElementName element;
    element.SetBundleName(info.GetBundleName());
    element.SetAbilityName(info.GetMainAbility());
    want.SetElement(element);
    want.SetParam(UID, uid);
    want.SetParam(Constants::USER_ID, userId);
    want.SetParam(Constants::ABILITY_NAME, info.GetMainAbility());
    want.SetParam(SANDBOX_APP_INDEX, info.GetAppIndex());
    want.SetParam(ACCESS_TOKEN_ID, static_cast<int32_t>(info.GetAccessTokenId(userId)));
    want.SetParam(APP_ID, info.GetAppId());
    EventFwk::CommonEventData commonData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> permissionVec { Constants::LISTEN_BUNDLE_CHANGE };
    publishInfo.SetSubscriberPermissions(permissionVec);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        APP_LOGE("PublishCommonEvent failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
    return ERR_OK;
}

void BundleCommonEventMgr::NotifyOverlayModuleStateStatus(const std::string &bundleName,
    const std::string &moduleName, bool isEnabled, int32_t userId, int32_t uid)
{
    OHOS::AAFwk::Want want;
    want.SetAction(OVERLAY_STATE_CHANGED);
    ElementName element;
    element.SetBundleName(bundleName);
    element.SetModuleName(moduleName);
    want.SetElement(element);
    want.SetParam(UID, uid);
    want.SetParam(Constants::USER_ID, userId);
    want.SetParam(Constants::OVERLAY_STATE, isEnabled);
    EventFwk::CommonEventData commonData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> permissionVec { Constants::LISTEN_BUNDLE_CHANGE };
    publishInfo.SetSubscriberPermissions(permissionVec);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        APP_LOGE("PublishCommonEvent failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
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

void BundleCommonEventMgr::NotifySetDiposedRule(
    const std::string &appId, int32_t userId, const std::string &data, int32_t appIndex)
{
    OHOS::AAFwk::Want want;
    want.SetAction(DISPOSED_RULE_ADDED);
    want.SetParam(Constants::USER_ID, userId);
    want.SetParam(APP_ID, appId);
    want.SetParam(APP_INDEX, appIndex);
    EventFwk::CommonEventData commonData { want };
    commonData.SetData(data);
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> permissionVec { PERMISSION_GET_DISPOSED_STATUS };
    publishInfo.SetSubscriberPermissions(permissionVec);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        APP_LOGE("PublishCommonEvent failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
}

void BundleCommonEventMgr::NotifyDeleteDiposedRule(const std::string &appId, int32_t userId, int32_t appIndex)
{
    OHOS::AAFwk::Want want;
    want.SetAction(DISPOSED_RULE_DELETED);
    want.SetParam(Constants::USER_ID, userId);
    want.SetParam(APP_ID, appId);
    want.SetParam(APP_INDEX, appIndex);
    EventFwk::CommonEventData commonData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> permissionVec { PERMISSION_GET_DISPOSED_STATUS };
    publishInfo.SetSubscriberPermissions(permissionVec);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        APP_LOGE("PublishCommonEvent failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
}

void BundleCommonEventMgr::NotifyDynamicIconEvent(
    const std::string &bundleName, bool isEnableDynamicIcon, int32_t userId, int32_t appIndex)
{
    APP_LOGI("NotifyDynamicIconEvent bundleName: %{public}s, %{public}d",
        bundleName.c_str(), isEnableDynamicIcon);
    OHOS::AAFwk::Want want;
    want.SetAction(DYNAMIC_ICON_CHANGED);
    ElementName element;
    element.SetBundleName(bundleName);
    want.SetElement(element);
    want.SetParam(IS_ENABLE_DYNAMIC_ICON, isEnableDynamicIcon);
    if ((userId != Constants::UNSPECIFIED_USERID) || (appIndex != Constants::DEFAULT_APP_INDEX)) {
        want.SetParam(Constants::USER_ID, userId);
        want.SetParam(Constants::APP_INDEX, appIndex);
    }
    EventFwk::CommonEventData commonData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        APP_LOGE("PublishCommonEvent failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
}

void BundleCommonEventMgr::NotifyBundleResourcesChanged(const int32_t userId, const uint32_t type)
{
    OHOS::AAFwk::Want want;
    want.SetAction(BUNDLE_RESOURCES_CHANGED);
    want.SetParam(Constants::USER_ID, userId);
    want.SetParam(BUNDLE_RESOURCE_CHANGE_TYPE, static_cast<int32_t>(type));
    EventFwk::CommonEventData commonData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> permissionVec { ServiceConstants::PERMISSION_GET_BUNDLE_RESOURCES };
    publishInfo.SetSubscriberPermissions(permissionVec);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        APP_LOGE("PublishCommonEvent failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
}

void BundleCommonEventMgr::NotifyDefaultAppChanged(const int32_t userId, std::vector<std::string> &utdIdVec)
{
    OHOS::AAFwk::Want want;
    want.SetAction(DEFAULT_APPLICATION_CHANGED);
    want.SetParam(Constants::USER_ID, userId);
    want.SetParam(UTD_IDS, utdIdVec);
    EventFwk::CommonEventData commonData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> permissionVec { CHANGE_DEFAULT_APPLICATION };
    publishInfo.SetSubscriberPermissions(permissionVec);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        APP_LOGE("Publish defaultApp changed event failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
}

void BundleCommonEventMgr::NotifyPluginEvents(const NotifyBundleEvents &event,
    const std::shared_ptr<BundleDataMgr> &dataMgr)
{
    OHOS::AAFwk::Want want;
    std::string eventData = GetCommonEventData(event.type);
    want.SetAction(eventData);
    ElementName element;
    element.SetBundleName(event.bundleName);
    element.SetModuleName(event.modulePackage);
    want.SetElement(element);
    want.SetParam(Constants::BUNDLE_NAME, event.bundleName);
    want.SetParam(BUNDLE_TYPE, event.bundleType);
    want.SetParam(Constants::UID, event.uid);
    EventFwk::CommonEventData commonData { want };
    if (dataMgr != nullptr) {
        LOG_I(BMS_TAG_DEFAULT, "pluginEventBack begin");
        dataMgr->NotifyPluginEventCallback(commonData);
        LOG_I(BMS_TAG_DEFAULT, "pluginEventBack end");
    }
}
} // AppExecFwk
} // OHOS