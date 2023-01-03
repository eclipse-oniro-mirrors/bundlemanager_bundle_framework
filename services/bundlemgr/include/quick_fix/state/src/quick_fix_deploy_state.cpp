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

#include "quick_fix_deploy_state.h"

#include "app_log_wrapper.h"
#include "quick_fix_boot_scanner.h"
#include "quick_fix_deployer.h"
#include "quick_fix_switch_state.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDeployState::QuickFixDeployState(const InnerAppQuickFix &innerQuickFixInfo)
    : innerQuickFixInfo_(innerQuickFixInfo)
{
    APP_LOGI("create QuickFixDeployState");
}

ErrCode QuickFixDeployState::Process()
{
    const std::string bundleName = innerQuickFixInfo_.GetAppQuickFix().bundleName;
    APP_LOGD("start to process deploy-status bundle %{public}s", bundleName.c_str());
    std::vector<std::string> bundlePaths;
    std::unique_ptr<QuickFixDeployer> deployer = std::make_unique<QuickFixDeployer>(bundlePaths);
    InnerAppQuickFix oldInnerAppQuickFix;
    auto res = deployer->ToDeployEndStatus(innerQuickFixInfo_, oldInnerAppQuickFix);
    if (res != ERR_OK) {
        APP_LOGE("deploy quick fix failed due to %{public}d", res);
        return res;
    }

    std::shared_ptr<QuickFixSwitchState> switchState = std::make_shared<QuickFixSwitchState>(bundleName, true);

    auto scanner = DelayedSingleton<QuickFixBootScanner>::GetInstance();
    if (scanner == nullptr) {
        APP_LOGE("scanner is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    scanner->SetQuickFixState(switchState);
    return scanner->ProcessState();
}
} // AppExecFwk
} // OHOS