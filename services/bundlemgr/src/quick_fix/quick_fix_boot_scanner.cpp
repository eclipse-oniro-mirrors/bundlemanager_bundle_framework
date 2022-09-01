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

#include "quick_fix_boot_scanner.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "inner_app_quick_fix.h"
#include "quick_fix_delete_state.h"
#include "quick_fix_deploy_state.h"
#include "quick_fix_switch_state.h"

namespace OHOS {
namespace AppExecFwk {
void QuickFixBootScanner::ProcessQuickFixBootUp()
{
    APP_LOGI("start to process quick fix boot up");
    quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    if (quickFixDataMgr_ == nullptr) {
        APP_LOGE("quickFixDataMgr_ is nullptr");
        return;
    }

    std::map<std::string, InnerAppQuickFix> quickFixInfoMap;
    auto ret = quickFixDataMgr_->QueryAllInnerAppQuickFix(quickFixInfoMap);
    if (!ret || quickFixInfoMap.empty()) {
        APP_LOGW("no quick fix info in db");
        return;
    }

    for (const auto &quickFixInfo : quickFixInfoMap) {
        auto quickFixStatus = quickFixInfo.second.GetQuickFixMark().status;
        APP_LOGD("quick fix scan bundle %{public}s, status is %{public}d", quickFixInfo.first.c_str(), quickFixStatus);
        if ((quickFixStatus == QuickFixStatus::DEFAULT_STATUS) || (quickFixStatus == QuickFixStatus::DELETE_END) ||
            (quickFixStatus == QuickFixStatus::SWITCH_END) || (quickFixStatus== QuickFixStatus::DELETE_START)) {
            state_ = std::make_shared<QuickFixDeleteState>(quickFixInfo.first);
        }
        if (quickFixStatus == QuickFixStatus::DEPLOY_START) {
            state_ = std::make_shared<QuickFixDeployState>(quickFixInfo.second);
        }
        if ((quickFixStatus == QuickFixStatus::DEPLOY_END) || (quickFixStatus == QuickFixStatus::SWITCH_ENABLE_START)) {
            state_ = std::make_shared<QuickFixSwitchState>(quickFixInfo.first, true);
        }
        if (quickFixStatus == QuickFixStatus::SWITCH_DISABLE_START) {
            state_ = std::make_shared<QuickFixSwitchState>(quickFixInfo.first, false);
        }
        auto ret = ProcessState();
        if (ret != ERR_OK) {
            APP_LOGE("quick fix info %{public}s is processed failed", quickFixInfo.first.c_str());
        }
        state_.reset();
    }
    APP_LOGI("process quick fix boot up completely");
}

void QuickFixBootScanner::SetQuickFixState(const std::shared_ptr<QuickFixState> &state)
{
    state_.reset();
    state_ = state;
}

ErrCode QuickFixBootScanner::ProcessState()
{
    if (state_ == nullptr) {
        APP_LOGE("state_ is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    return state_->Process();
}
} // AppExecFwk
} // OHOS