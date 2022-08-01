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

#include "quick_fixer.h"

#include <cinttypes>

#include "app_log_wrapper.h"
#include "quick_fix_async_mgr.h"
#include "quick_fix_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixer::QuickFixer(const int64_t quickFixerId, const std::shared_ptr<EventHandler> &handler,
    const sptr<IQuickFixStatusCallback> &statusCallback) : quickFixerId_(quickFixerId), handler_(handler),
    statusCallback_(statusCallback) {}

void QuickFixer::DeployQuickFix(const std::vector<std::string> &bundleFilePaths)
{
    APP_LOGI("DeployQuickFix start");
    if (bundleFilePaths.empty()) {
        APP_LOGE("DeployQuickFix wrong parms");
        return;
    }
    if (statusCallback_ == nullptr) {
        APP_LOGE("DeployQuickFix failed due to nullptr statusCallback");
        return;
    }
    auto res = DelayedSingleton<QuickFixDataMgr>::GetInstance()->DeployQuickFix(bundleFilePaths);
    if (res != ERR_OK) {
        APP_LOGE("DeployQuickFix failed");
    }

    SendRemoveEvent();
}

void QuickFixer::SwitchQuickFix(const std::string &bundleName)
{
    APP_LOGI("SwitchQuickFix start");
    if (bundleName.empty()) {
        APP_LOGE("SwitchQuickFix wrong parms");
        return;
    }
    if (statusCallback_ == nullptr) {
        APP_LOGE("SwitchQuickFix failed due to nullptr statusCallback");
        return;
    }
    auto res = DelayedSingleton<QuickFixDataMgr>::GetInstance()->SwitchQuickFix(bundleName);
    if (res != ERR_OK) {
        APP_LOGE("SwitchQuickFix failed");
    }

    SendRemoveEvent();
}

void QuickFixer::DeleteQuickFix(const std::string &bundleName)
{
    APP_LOGI("DeleteQuickFix start");
    if (bundleName.empty()) {
        APP_LOGE("DeleteQuickFix wrong parms");
        return;
    }
    if (statusCallback_ == nullptr) {
        APP_LOGE("DeleteQuickFix failed due to nullptr statusCallback");
        return;
    }
    auto res =  DelayedSingleton<QuickFixDataMgr>::GetInstance()->DeleteQuickFix(bundleName);
    if (res != ERR_OK) {
        APP_LOGE("DeleteQuickFix failed");
    }

    SendRemoveEvent();
}

void QuickFixer::SendRemoveEvent() const
{
    if (auto handler = handler_.lock()) {
        APP_LOGD("SendRemoveEvent begin");
        handler->SendEvent(InnerEvent::Get(QuickFixAsyncMgr::MessageId::REMOVE_QUICK_FIXER, quickFixerId_));
        return;
    }
    APP_LOGE("fail to remove %{public}" PRId64 " quickFixer due to handler is expired", quickFixerId_);
}
} // AppExecFwk
} // OHOS