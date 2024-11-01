/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "app_log_tag_wrapper.h"
#include "quick_fix_deleter.h"
#include "quick_fix_deployer.h"
#include "quick_fix_switcher.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixer::QuickFixer(const sptr<IQuickFixStatusCallback> &statusCallback) : statusCallback_(statusCallback)
{
    LOG_I(BMS_TAG_DEFAULT, "enter QuickFixer");
}

void QuickFixer::DeployQuickFix(const std::vector<std::string> &bundleFilePaths, bool isDebug,
    const std::string &targetPath)
{
    LOG_I(BMS_TAG_DEFAULT, "DeployQuickFix start");

    std::unique_ptr<QuickFixDeployer> deployer = std::make_unique<QuickFixDeployer>(
        bundleFilePaths, isDebug, targetPath);
    auto ret = deployer->Execute();

    // callback operation
    DeployQuickFixResult result = deployer->GetDeployQuickFixResult();
    result.resultCode = ret;
    std::shared_ptr<QuickFixResult> deployRes = std::make_shared<DeployQuickFixResult>(result);
    if (statusCallback_ != nullptr) {
        statusCallback_->OnPatchDeployed(deployRes);
    } else {
        LOG_E(BMS_TAG_DEFAULT, "DeployQuickFix failed due to nullptr statusCallback");
    }
}

void QuickFixer::SwitchQuickFix(const std::string &bundleName, bool enable)
{
    LOG_I(BMS_TAG_DEFAULT, "SwitchQuickFix start");
    if (statusCallback_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "SwitchQuickFix failed due to nullptr statusCallback");
    }

    std::unique_ptr<IQuickFix> switcher = std::make_unique<QuickFixSwitcher>(bundleName, enable);
    auto ret = switcher->Execute();

    // callback operation
    SwitchQuickFixResult result;
    result.resultCode = ret;
    result.bundleName = bundleName;
    std::shared_ptr<QuickFixResult> switchRes = std::make_shared<SwitchQuickFixResult>(result);
    if (statusCallback_ != nullptr) {
        statusCallback_->OnPatchSwitched(switchRes);
    }
}

void QuickFixer::DeleteQuickFix(const std::string &bundleName)
{
    LOG_I(BMS_TAG_DEFAULT, "DeleteQuickFix start");
    if (statusCallback_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteQuickFix failed due to nullptr statusCallback");
    }

    std::unique_ptr<IQuickFix> deleter = std::make_unique<QuickFixDeleter>(bundleName);
    auto ret = deleter->Execute();

    // callback operation
    DeleteQuickFixResult result;
    result.resultCode = ret;
    result.bundleName = bundleName;
    std::shared_ptr<QuickFixResult> deleteRes = std::make_shared<DeleteQuickFixResult>(result);
    if (statusCallback_ != nullptr) {
        statusCallback_->OnPatchDeleted(deleteRes);
    }
}
} // AppExecFwk
} // OHOS