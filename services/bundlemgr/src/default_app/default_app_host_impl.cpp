/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "default_app_host_impl.h"

#include "app_log_tag_wrapper.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "event_report.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
ErrCode DefaultAppHostImpl::IsDefaultApplication(const std::string& type, bool& isDefaultApp)
{
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    return DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
}

ErrCode DefaultAppHostImpl::GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    return DefaultAppMgr::GetInstance().GetDefaultApplication(userId, type, bundleInfo);
}

ErrCode DefaultAppHostImpl::SetDefaultApplication(int32_t userId, const std::string& type, const Want& want)
{
    return InnerSetDefaultApplication(userId, Constants::DEFAULT_APP_INDEX, type, want);
}

ErrCode DefaultAppHostImpl::SetDefaultApplicationForAppClone(const int32_t userId, const int32_t appIndex,
    const std::string& type, const Want& want)
{
    if (!BundlePermissionMgr::VerifyAcrossUserPermission(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (appIndex <= Constants::MAIN_APP_INDEX || appIndex > Constants::CLONE_APP_INDEX_MAX) {
        LOG_E(BMS_TAG_DEFAULT, "Invalid appIndex:%{public}d", appIndex);
        return ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE;
    }
    return InnerSetDefaultApplication(userId, appIndex, type, want);
}

ErrCode DefaultAppHostImpl::InnerSetDefaultApplication(int32_t userId, const int32_t appIndex,
    const std::string& type, const Want& want)
{
    LOG_D(BMS_TAG_DEFAULT, "SetDefaultApplication userId:%{public}d type:%{public}s", userId, type.c_str());
    const ElementName& elementName = want.GetElement();
    const std::string& bundleName = elementName.GetBundleName();
    const std::string& moduleName = elementName.GetModuleName();
    const std::string& abilityName = elementName.GetAbilityName();
    LOG_D(BMS_TAG_DEFAULT, "ElementName bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    // case1 : ElementName is empty.
    bool isEmpty = bundleName.empty() && moduleName.empty() && abilityName.empty();
    if (isEmpty) {
        LOG_D(BMS_TAG_DEFAULT, "ElementName is empty");
        Element element;
        ErrCode result = DefaultAppMgr::GetInstance().SetDefaultApplication(userId, type, element);
        if (result == ERR_OK) {
            EventReport::SendDefaultAppEvent(DefaultAppActionType::SET, userId, appIndex, GetCallerName(),
                want.ToString(), type);
        }
        return result;
    }
    // case2 : ElementName is valid ability or valid extension.
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!dataMgr->HasUserId(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "userId not exist");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    Element element;
    bool ret = dataMgr->GetElement(userId, appIndex, elementName, element);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "GetElement failed");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    ErrCode result = DefaultAppMgr::GetInstance().SetDefaultApplication(userId, type, element);
    if (result == ERR_OK) {
        EventReport::SendDefaultAppEvent(DefaultAppActionType::SET, userId, appIndex,
            GetCallerName(), want.ToString(), type);
    }
    return result;
}

ErrCode DefaultAppHostImpl::ResetDefaultApplication(int32_t userId, const std::string& type)
{
    ErrCode result = DefaultAppMgr::GetInstance().ResetDefaultApplication(userId, type);
    if (result == ERR_OK) {
        EventReport::SendDefaultAppEvent(DefaultAppActionType::RESET, userId,
            Constants::DEFAULT_APP_INDEX, GetCallerName(), Constants::EMPTY_STRING, type);
    }
    return result;
}

std::string DefaultAppHostImpl::GetCallerName()
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return std::to_string(uid);
    }
    std::string callerName;
    auto ret = dataMgr->GetNameForUid(uid, callerName);
    if (ret != ERR_OK) {
        callerName = std::to_string(uid);
    }
    return callerName;
}
}
}
