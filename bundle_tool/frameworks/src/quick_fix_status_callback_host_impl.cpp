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

#include "quick_fix_status_callback_host_impl.h"

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t WAITTING_TIME = 5;
} // namespace

QuickFixStatusCallbackHostlmpl::QuickFixStatusCallbackHostlmpl()
{
    APP_LOGI("create status callback instance");
}

QuickFixStatusCallbackHostlmpl::~QuickFixStatusCallbackHostlmpl()
{
    APP_LOGI("destroy status callback instance");
}

void QuickFixStatusCallbackHostlmpl::OnPatchDeployed(const DeployQuickFixResult &result)
{
    APP_LOGD("on Patch deployed bundleName is %{public}s", result.bundleName.c_str());
    APP_LOGD("on Patch deployed bundle version code is %{public}u", result.bundleVersionCode);
    APP_LOGD("on Patch deployed patch version code is %{public}u", result.patchVersionCode);
    APP_LOGD("on Patch deployed isSoContained is %{public}d", result.isSoContained);
    APP_LOGD("on Patch deployed patch type is %{public}d", static_cast<int32_t>(result.type));
    for (const auto &name : result.moduleNames) {
        APP_LOGD("on Patch deployed moduleName is %{public}s", name.c_str());
    }
    APP_LOGD("on Patch deployed errcode is %{public}d", result.resultCode);
    resultPromise_.set_value(result.resultCode);
}

void QuickFixStatusCallbackHostlmpl::OnPatchSwitched(const SwitchQuickFixResult &result)
{
    APP_LOGD("on Patch switched bundleName is %{public}s", result.bundleName.c_str());
    resultPromise_.set_value(result.resultCode);
}

void QuickFixStatusCallbackHostlmpl::OnPatchDeleted(const DeleteQuickFixResult &result)
{
    APP_LOGD("on Patch deleted bundleName is %{public}s", result.bundleName.c_str());
    resultPromise_.set_value(result.resultCode);
}

int32_t QuickFixStatusCallbackHostlmpl::GetResultCode() const
{
    auto future = resultPromise_.get_future();
    if (future.wait_for(std::chrono::seconds(WAITTING_TIME)) == std::future_status::ready) {
        int32_t resultCode = future.get();
        return resultCode;
    }
    return ERR_APPEXECFWK_OPERATION_TIME_OUT;
}
}  // namespace AppExecFwk
}  // namespace OHOS