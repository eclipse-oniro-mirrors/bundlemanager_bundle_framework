/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "bundle_death_recipient.h"

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "status_receiver_interface.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const char* STRING_FAIL = "[BUNDLER_MANAGER_SERVICE_UNAVAILABLE]";
}
BundleDeathRecipient::BundleDeathRecipient(const sptr<StatusReceiverHost> &statusReceiver,
    const sptr<QuickFixStatusCallbackHost> &callback) : statusReceiver_(statusReceiver), quickFixCallback_(callback)
{
}

BundleDeathRecipient::~BundleDeathRecipient()
{
    statusReceiver_ = nullptr;
    quickFixCallback_ = nullptr;
}

void BundleDeathRecipient::OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject> &remote)
{
    APP_LOGE("BundleManagerService is died");
    if (statusReceiver_ != nullptr) {
        APP_LOGD("call installer callback");
        statusReceiver_->OnFinished(IStatusReceiver::ERR_FAILED_SERVICE_DIED, STRING_FAIL);
    }
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    if (quickFixCallback_ != nullptr) {
        APP_LOGD("call quickFix callback");
        std::shared_ptr<QuickFixResult> deployRes = std::make_shared<DeployQuickFixResult>();
        deployRes->SetResCode(ERR_APPEXECFWK_FAILED_SERVICE_DIED);
        quickFixCallback_->OnPatchDeployed(deployRes);
    }
#endif
    return;
}
} // namespace AppExecFwk
} // namespace OHOS