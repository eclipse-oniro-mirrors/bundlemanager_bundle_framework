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

#include "default_app_host_impl.h"

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
    APP_LOGD("begin to call IsDefaultApplication, userId : %{public}d, type : %{public}s", userId, type.c_str());
    return DefaultAppMgr::GetInstance().IsDefaultApplication(userId, type, isDefaultApp);
}

ErrCode DefaultAppHostImpl::GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo)
{
    APP_LOGD("begin to GetDefaultApplication, userId : %{public}d, type : %{public}s", userId, type.c_str());
    return DefaultAppMgr::GetInstance().GetDefaultApplication(userId, type, bundleInfo);
}

ErrCode DefaultAppHostImpl::SetDefaultApplication(int32_t userId, const std::string& type, const Want& want)
{
    APP_LOGD("begin to SetDefaultApplication, userId : %{public}d, type : %{public}s", userId, type.c_str());
    const ElementName& elementName = want.GetElement();
    const std::string& bundleName = elementName.GetBundleName();
    const std::string& moduleName = elementName.GetModuleName();
    const std::string& abilityName = elementName.GetAbilityName();
    APP_LOGD("ElementName, bundleName : %{public}s, moduleName : %{public}s, abilityName : %{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    // case1 : ElementName is empty.
    bool isEmpty = bundleName.empty() && moduleName.empty() && abilityName.empty();
    if (isEmpty) {
        APP_LOGD("ElementName is empty.");
        Element element;
        return DefaultAppMgr::GetInstance().SetDefaultApplication(userId, type, element);
    }
    // case2 : ElementName is valid ability or valid extension.
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (!dataMgr->HasUserId(userId)) {
        APP_LOGE("userId not exist.");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    Element element;
    bool ret = dataMgr->GetElement(userId, elementName, element);
    if (!ret) {
        APP_LOGE("GetElement failed.");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    return DefaultAppMgr::GetInstance().SetDefaultApplication(userId, type, element);
}

ErrCode DefaultAppHostImpl::ResetDefaultApplication(int32_t userId, const std::string& type)
{
    APP_LOGD("begin to ResetDefaultApplication, userId : %{public}d, type : %{public}s", userId, type.c_str());
    return DefaultAppMgr::GetInstance().ResetDefaultApplication(userId, type);
}
}
}
