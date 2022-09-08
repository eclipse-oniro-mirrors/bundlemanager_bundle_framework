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

#include "quick_fix_switch_state.h"

#include "app_log_wrapper.h"
#include "quick_fix_boot_scanner.h"
#include "quick_fix_delete_state.h"
#include "quick_fix_switcher.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixSwitchState::QuickFixSwitchState(const std::string &bundleName, bool enable)
    : bundleName_(bundleName), enable_(enable)
{
    APP_LOGI("create QuickFixSwitchState");
}

ErrCode QuickFixSwitchState::Process()
{
    APP_LOGD("start to process switch-status bundle %{public}s", bundleName_.c_str());
    std::unique_ptr<QuickFixSwitcher> switcher = std::make_unique<QuickFixSwitcher>(bundleName_, enable_);
    auto res = switcher->Execute();
    if (res != ERR_OK) {
        APP_LOGE("switch quick fix info failed due to %{public}d", res);
        return res;
    }

    std::shared_ptr<QuickFixDeleteState> deleteState = std::make_shared<QuickFixDeleteState>(bundleName_);
    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    if (scanner == nullptr) {
        APP_LOGE("scanner is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    scanner->SetQuickFixState(deleteState);
    return scanner->ProcessState();
}
} // AppExecFwk
} // OHOS