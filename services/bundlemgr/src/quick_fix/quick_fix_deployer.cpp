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

#include "quick_fix_deployer.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDeployer::QuickFixDeployer(const std::vector<std::string> &pacthPaths) : patchPaths_(pacthPaths)
{
    APP_LOGI("enter QuickFixSwitcher");
}

ErrCode QuickFixDeployer::Execute()
{
    APP_LOGI("start execute");
    return DeployQuickFix();
}

ErrCode QuickFixDeployer::DeployQuickFix()
{
    if (patchPaths_.empty()) {
        APP_LOGE("DeployQuickFix wrong parms");
        return ERR_APPEXECFWK_QUICK_FIX_PARAM_ERROR;
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS