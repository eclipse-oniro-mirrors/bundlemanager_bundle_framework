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
bool DefaultAppHostImpl::IsDefaultApplication(const std::string& type)
{
    APP_LOGI("begin to call IsDefaultApplication.");
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    return defaultAppMgr_->IsDefaultApplication(userId, type);
}

bool DefaultAppHostImpl::GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo)
{
    APP_LOGI("begin to GetDefaultApplication.");
    return defaultAppMgr_->GetDefaultApplication(userId, type, bundleInfo);
}

bool DefaultAppHostImpl::SetDefaultApplication(int32_t userId, const std::string& type, const Want& want)
{
    APP_LOGI("begin to SetDefaultApplication.");
    // case1 : ElementName is empty.
    ElementName elementName =  want.GetElement();
    bool isEmpty = elementName.GetBundleName().empty() && elementName.GetModuleName().empty()
        && elementName.GetAbilityName().empty();
    if (isEmpty) {
        APP_LOGI("ElementName is empty.");
        Element element;
        return defaultAppMgr_->SetDefaultApplication(userId, type, element);
    }
    // case2 : ElementName is valid ability or valid extension.
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    Element element;
    bool ret = dataMgr->GetElement(userId, elementName, element);
    if (!ret) {
        APP_LOGE("GetElement failed.");
        return false;
    }
    return defaultAppMgr_->SetDefaultApplication(userId, type, element);
}

bool DefaultAppHostImpl::ResetDefaultApplication(int32_t userId, const std::string& type)
{
    APP_LOGI("begin to ResetDefaultApplication.");
    return defaultAppMgr_->ResetDefaultApplication(userId, type);
}
}
}
