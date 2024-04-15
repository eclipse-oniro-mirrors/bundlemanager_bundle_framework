/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "launcher_service.h"

#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service_death_recipient.h"
#include "common_event_subscribe_info.h"
#include "common_event_support.h"
#include "hitrace_meter.h"
#include "matching_skills.h"
#include "operation_builder.h"

namespace OHOS {
namespace AppExecFwk {
OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> LauncherService::bundleMgr_ = nullptr;
OHOS::sptr<IRemoteObject::DeathRecipient> LauncherService::deathRecipient_(
    new (std::nothrow) LauncherServiceDeathRecipient());
std::mutex LauncherService::bundleMgrMutex_;
const char* EMPTY_STRING = "";

void LauncherService::LauncherServiceDeathRecipient::OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject>& remote)
{
    APP_LOGD("BundleManagerService dead.");
    std::lock_guard<std::mutex> lock(bundleMgrMutex_);
    bundleMgr_ = nullptr;
};

LauncherService::LauncherService()
{
    init();
}

void LauncherService::init()
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    bundleMonitor_ = std::make_shared<BundleMonitor>(subscribeInfo);
}

LauncherService::~LauncherService()
{
    APP_LOGD("destroy LauncherService");
    if (bundleMgr_ != nullptr && deathRecipient_ != nullptr) {
        bundleMgr_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
}

OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> LauncherService::GetBundleMgr()
{
    if (bundleMgr_ == nullptr) {
        std::lock_guard<std::mutex> lock(bundleMgrMutex_);
        if (bundleMgr_ == nullptr) {
            auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
            if (systemAbilityManager == nullptr) {
                APP_LOGE("GetBundleMgr GetSystemAbilityManager is null");
                return nullptr;
            }
            auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
            if (bundleMgrSa == nullptr) {
                APP_LOGE("GetBundleMgr GetSystemAbility is null");
                return nullptr;
            }
            auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
            if (bundleMgr == nullptr) {
                APP_LOGE("GetBundleMgr iface_cast get null");
                return nullptr;
            }
            bundleMgr_ = bundleMgr;
            bundleMgr_->AsObject()->AddDeathRecipient(deathRecipient_);
        }
    }
    return bundleMgr_;
}

bool LauncherService::RegisterCallback(const sptr<IBundleStatusCallback> &callback)
{
    APP_LOGD("RegisterCallback called");
    if (bundleMonitor_ == nullptr) {
        APP_LOGE("failed to register callback, bundleMonitor is null");
        return false;
    }

    // check permission
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    if (!iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        return false;
    }
    if (!iBundleMgr->VerifyCallingPermission(Constants::LISTEN_BUNDLE_CHANGE)) {
        APP_LOGE("register bundle status callback failed due to lack of permission");
        return false;
    }
    return bundleMonitor_->Subscribe(callback);
}

bool LauncherService::UnRegisterCallback()
{
    APP_LOGD("UnRegisterCallback called");
    if (bundleMonitor_ == nullptr) {
        APP_LOGE("failed to unregister callback, bundleMonitor is null");
        return false;
    }

    // check permission
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    if (!iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        return false;
    }
    if (!iBundleMgr->VerifyCallingPermission(Constants::LISTEN_BUNDLE_CHANGE)) {
        APP_LOGE("register bundle status callback failed due to lack of permission");
        return false;
    }
    return bundleMonitor_->UnSubscribe();
}

bool LauncherService::GetAbilityList(
    const std::string &bundleName, const int userId, std::vector<LauncherAbilityInfo> &launcherAbilityInfos)
{
    APP_LOGD("GetAbilityList called");
    auto iBundleMgr = GetBundleMgr();
    if ((iBundleMgr == nullptr) || (bundleName.empty())) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    if (!iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        return false;
    }
    std::vector<std::string> entities;
    entities.push_back(Want::ENTITY_HOME);
    Want want;
    want.SetAction(Want::ACTION_HOME);
    want.AddEntity(Want::ENTITY_HOME);
    ElementName elementName;
    elementName.SetBundleName(bundleName);
    want.SetElement(elementName);
    std::vector<AbilityInfo> abilityInfos;
    if (!iBundleMgr->QueryAllAbilityInfos(want, userId, abilityInfos)) {
        APP_LOGE("Query ability info failed");
        return false;
    }

    for (auto &ability : abilityInfos) {
        if (ability.bundleName != bundleName || !ability.enabled) {
            continue;
        }

        LauncherAbilityInfo info;
        info.applicationInfo = ability.applicationInfo;
        info.labelId = ability.labelId;
        info.iconId = ability.iconId;
        ElementName abilityElementName;
        abilityElementName.SetBundleName(ability.bundleName);
        abilityElementName.SetModuleName(ability.moduleName);
        abilityElementName.SetAbilityName(ability.name);
        abilityElementName.SetDeviceID(ability.deviceId);
        info.elementName = abilityElementName;
        info.userId = userId;
        info.installTime = ability.installTime;
        launcherAbilityInfos.emplace_back(info);
    }

    return true;
}

bool LauncherService::GetAllLauncherAbilityInfos(int32_t userId, std::vector<LauncherAbilityInfo> &launcherAbilityInfos)
{
    APP_LOGI("start");
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    if (!iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        return false;
    }
    Want want;
    want.SetAction(Want::ACTION_HOME);
    want.AddEntity(Want::ENTITY_HOME);

    std::vector<AbilityInfo> abilityInfos;
    if (!iBundleMgr->QueryAllAbilityInfos(want, userId, abilityInfos)) {
        APP_LOGE("Query ability info failed");
        return false;
    }

    for (const auto& ability : abilityInfos) {
        if (ability.applicationInfo.isLauncherApp || !ability.enabled) {
            continue;
        }

        if (ability.applicationInfo.hideDesktopIcon) {
            APP_LOGD("Bundle(%{public}s) hide desktop icon", ability.bundleName.c_str());
            continue;
        }

        LauncherAbilityInfo info;
        info.installTime = ability.installTime;
        info.applicationInfo = ability.applicationInfo;
        info.labelId = ability.labelId;
        info.iconId = ability.iconId;
        info.userId = userId;
        ElementName elementName;
        elementName.SetBundleName(ability.bundleName);
        elementName.SetModuleName(ability.moduleName);
        elementName.SetAbilityName(ability.name);
        elementName.SetDeviceID(ability.deviceId);
        info.elementName = elementName;
        launcherAbilityInfos.emplace_back(info);
    }

    if (launcherAbilityInfos.empty()) {
        APP_LOGW("success, but launcherAbilityInfos is empty");
    } else {
        APP_LOGI("success");
    }

    return true;
}

ErrCode LauncherService::GetShortcutInfos(
    const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfos)
{
    APP_LOGD("GetShortcutInfos called");
    if (bundleName.empty()) {
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    std::vector<ShortcutInfo> infos;
    if (!iBundleMgr->GetShortcutInfos(bundleName, infos)) {
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (infos.size() == 0) {
        return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST;
    }

    for (ShortcutInfo shortcutInfo : infos) {
        if (bundleName == shortcutInfo.bundleName) {
            shortcutInfos.emplace_back(shortcutInfo);
        }
    }
    return ERR_OK;
}

void LauncherService::InitWant(Want &want, const std::string &bundleName)
{
    want.SetAction(Want::ACTION_HOME);
    want.AddEntity(Want::ENTITY_HOME);
    if (!bundleName.empty()) {
        ElementName elementName;
        elementName.SetBundleName(bundleName);
        want.SetElement(elementName);
    }
}

void LauncherService::ConvertAbilityToLauncherAbility(const AbilityInfo &ability, LauncherAbilityInfo &launcherAbility,
    const int32_t userId)
{
    launcherAbility.applicationInfo = ability.applicationInfo;
    launcherAbility.labelId = ability.labelId;
    launcherAbility.iconId = ability.iconId;
    ElementName elementName;
    elementName.SetBundleName(ability.bundleName);
    elementName.SetModuleName(ability.moduleName);
    elementName.SetAbilityName(ability.name);
    elementName.SetDeviceID(ability.deviceId);
    launcherAbility.elementName = elementName;
    launcherAbility.userId = userId;
    launcherAbility.installTime = ability.installTime;
}

ErrCode LauncherService::GetLauncherAbilityByBundleName(const std::string &bundleName, const int32_t userId,
    std::vector<LauncherAbilityInfo> &launcherAbilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("GetLauncherAbilityByBundleName called");
    if (bundleName.empty()) {
        APP_LOGE("no bundleName %{public}s found", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }

    Want want;
    InitWant(want, bundleName);
    std::vector<AbilityInfo> abilityInfos;
    ErrCode err = iBundleMgr->QueryLauncherAbilityInfos(want, userId, abilityInfos);
    if (err != ERR_OK) {
        APP_LOGE("QueryLauncherAbilityInfos failed");
        return err;
    }
    for (const auto &ability : abilityInfos) {
        if (ability.bundleName != bundleName || !ability.enabled) {
            continue;
        }
        LauncherAbilityInfo info;
        ConvertAbilityToLauncherAbility(ability, info, userId);
        launcherAbilityInfos.push_back(info);
    }
    return ERR_OK;
}

ErrCode LauncherService::GetAllLauncherAbility(const int32_t userId,
    std::vector<LauncherAbilityInfo> &launcherAbilityInfos)
{
    APP_LOGD("GetAllLauncherAbility called");
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }

    Want want;
    InitWant(want, EMPTY_STRING);
    std::vector<AbilityInfo> abilityInfos;
    ErrCode err = iBundleMgr->QueryLauncherAbilityInfos(want, userId, abilityInfos);
    if (err != ERR_OK) {
        APP_LOGE("QueryLauncherAbilityInfos failed");
        return err;
    }
    for (const auto &ability : abilityInfos) {
        if (!ability.enabled || ability.applicationInfo.hideDesktopIcon) {
            continue;
        }
        LauncherAbilityInfo info;
        ConvertAbilityToLauncherAbility(ability, info, userId);
        launcherAbilityInfos.push_back(info);
    }
    return ERR_OK;
}

ErrCode LauncherService::GetShortcutInfoV9(
    const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfos)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    std::vector<ShortcutInfo> infos;
    ErrCode errCode = iBundleMgr->GetShortcutInfoV9(bundleName, infos);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (infos.empty()) {
        APP_LOGD("ShortcutInfo is not exist for this bundle");
        return ERR_OK;
    }

    for (ShortcutInfo shortcutInfo : infos) {
        if (bundleName == shortcutInfo.bundleName) {
            shortcutInfos.emplace_back(shortcutInfo);
        }
    }
    return ERR_OK;
}

void LauncherService::OnDeath()
{
    APP_LOGD("BundleManagerService dead.");
    std::lock_guard<std::mutex> lock(bundleMgrMutex_);
    bundleMgr_ = nullptr;
}
}  // namespace AppExecFwk
}  // namespace OHOS