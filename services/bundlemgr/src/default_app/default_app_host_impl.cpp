/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_promise.h"
#include "bundle_util.h"
#include "element.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "status_receiver_host.h"

namespace OHOS {
namespace AppExecFwk {
ErrCode DefaultAppHostImpl::IsDefaultApplication(const std::string& type, bool& isDefaultApp)
{
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    return DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
}

ErrCode DefaultAppHostImpl::GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    return DefaultAppMgr::GetInstance().GetDefaultApplication(userId, type, bundleInfo);
}

ErrCode DefaultAppHostImpl::SetDefaultApplication(int32_t userId, const std::string& type, const Want& want)
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
        return DefaultAppMgr::GetInstance().SetDefaultApplication(userId, type, element);
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
    bool ret = dataMgr->GetElement(userId, elementName, element);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "GetElement failed");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    return DefaultAppMgr::GetInstance().SetDefaultApplication(userId, type, element);
}

ErrCode DefaultAppHostImpl::ResetDefaultApplication(int32_t userId, const std::string& type)
{
    return DefaultAppMgr::GetInstance().ResetDefaultApplication(userId, type);
}
}
}
