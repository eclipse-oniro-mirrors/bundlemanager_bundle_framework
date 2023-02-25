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

#include "app_log_wrapper.h"
#include "sr_bundle_event_callback.h"
#include "service_router_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
void SrBundleEventCallback::OnReceiveEvent(const EventFwk::CommonEventData eventData)
{
    // env check
    if (eventHandler_ == nullptr) {
        APP_LOGE("%{public}s failed, eventHandler_ is nullptr", __func__);
        return;
    }
    const AAFwk::Want& want = eventData.GetWant();
    // action contains the change type of haps.
    std::string action = want.GetAction();
    std::string bundleName = want.GetElement().GetBundleName();
    int userId = want.GetIntParam("userId", 0);
    // verify data
    if (action.empty() || bundleName.empty()) {
        APP_LOGE("%{public}s failed, empty action/bundleName", __func__);
        return;
    }
    if (eventHandler_ == nullptr) {
        APP_LOGE("%{public}s fail, invalid event handler.", __func__);
        return;
    }
    APP_LOGI("%{public}s, action:%{public}s.", __func__, action.c_str());

    wptr<SrBundleEventCallback> weakThis = this;
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        // install or update
        auto task = [weakThis, bundleName, userId]() {
            APP_LOGI("%{public}s, bundle changed, bundleName: %{public}s", __func__, bundleName.c_str());
            sptr<SrBundleEventCallback> sharedThis = weakThis.promote();
            if (sharedThis) {
                ServiceRouterDataMgr::GetInstance().DeleteBundleInfo(bundleName);
            }
        };
        eventHandler_->PostTask(task);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        // uninstall module/bundle
        auto task = [weakThis, bundleName, userId]() {
            APP_LOGI("%{public}s, bundle removed, bundleName: %{public}s", __func__, bundleName.c_str());
            sptr<SrBundleEventCallback> sharedThis = weakThis.promote();
            if (sharedThis) {
                ServiceRouterDataMgr::GetInstance().LoadBundleInfo(bundleName);
            }
        };
        eventHandler_->PostTask(task);
    }
}

} // namespace AppExecFwk
} // namespace OHOS