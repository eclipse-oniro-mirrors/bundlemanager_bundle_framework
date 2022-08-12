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
#include "quick_fix_deleter.h"
#include "quick_fix_deployer.h"
#include "quick_fix_switcher.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixer::QuickFixer(const int64_t quickFixerId, const std::shared_ptr<EventHandler> &handler,
    const sptr<IQuickFixStatusCallback> &statusCallback) : quickFixerId_(quickFixerId), handler_(handler),
    statusCallback_(statusCallback)
{
    APP_LOGI("enter QuickFixer");
}

void QuickFixer::DeployQuickFix(const std::vector<std::string> &bundleFilePaths)
{
    APP_LOGI("DeployQuickFix start");
    if (statusCallback_ == nullptr) {
        APP_LOGE("DeployQuickFix failed due to nullptr statusCallback");
    }

    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    std::shared_ptr<IQuickFix> deployer = std::make_shared<QuickFixDeployer>(bundleFilePaths, quickFixDataMgr);
    deployer->Execute();

    // callback operation
    SendRemoveEvent();
}

void QuickFixer::SwitchQuickFix(const std::string &bundleName, bool enable)
{
    APP_LOGI("SwitchQuickFix start");
    if (statusCallback_ == nullptr) {
        APP_LOGE("SwitchQuickFix failed due to nullptr statusCallback");
    }

    std::shared_ptr<IQuickFix> switcher = std::make_shared<QuickFixSwitcher>(bundleName, enable);
    switcher->Execute();

    // callback operation
    SendRemoveEvent();
}

void QuickFixer::DeleteQuickFix(const std::string &bundleName)
{
    APP_LOGI("DeleteQuickFix start");
    if (statusCallback_ == nullptr) {
        APP_LOGE("DeleteQuickFix failed due to nullptr statusCallback");
    }

    std::shared_ptr<IQuickFix> deleter = std::make_shared<QuickFixDeleter>(bundleName);
    deleter->Execute();

    // callback operation
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