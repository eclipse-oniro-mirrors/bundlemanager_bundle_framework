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

#include "quick_fix_mgr.h"

#include <cinttypes>

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "bundle_memory_guard.h"
#include "datetime_ex.h"
#include "ffrt.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixMgr::QuickFixMgr()
{
    LOG_I(BMS_TAG_DEFAULT, "create quick fixer async manager instance");
}

QuickFixMgr::~QuickFixMgr()
{
    LOG_I(BMS_TAG_DEFAULT, "destory quick fixer async manager instance");
}

ErrCode QuickFixMgr::DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
    const sptr<IQuickFixStatusCallback> &statusCallback, bool isDebug, const std::string &targetPath)
{
    LOG_I(BMS_TAG_DEFAULT, "DeployQuickFix begin");
    auto quickFixer = CreateQuickFixer(statusCallback);
    if (quickFixer == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DeployQuickFix failed due to nullptr quick fixer");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    auto task = [quickFixer, bundleFilePaths, isDebug, targetPath] {
        BundleMemoryGuard memoryGuard;
        quickFixer->DeployQuickFix(bundleFilePaths, isDebug, targetPath);
    };

    ffrt::submit(task);
    return ERR_OK;
}

ErrCode QuickFixMgr::SwitchQuickFix(const std::string &bundleName, bool enable,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    LOG_I(BMS_TAG_DEFAULT, "SwitchQuickFix begin");
    auto quickFixer = CreateQuickFixer(statusCallback);
    if (quickFixer == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "SwitchQuickFix failed due to nullptr quick fixer");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    auto task = [quickFixer, bundleName, enable] {
        BundleMemoryGuard memoryGuard;
        quickFixer->SwitchQuickFix(bundleName, enable);
    };

    ffrt::submit(task);
    return ERR_OK;
}

ErrCode QuickFixMgr::DeleteQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    LOG_I(BMS_TAG_DEFAULT, "DeleteQuickFix begin");
    auto quickFixer = CreateQuickFixer(statusCallback);
    if (quickFixer == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteQuickFix failed due to nullptr quick fixer");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    auto task = [quickFixer, bundleName] {
        BundleMemoryGuard memoryGuard;
        quickFixer->DeleteQuickFix(bundleName);
    };

    ffrt::submit(task);
    return ERR_OK;
}

std::shared_ptr<QuickFixer> QuickFixMgr::CreateQuickFixer(const sptr<IQuickFixStatusCallback> &statusCallback)
{
    return std::make_shared<QuickFixer>(statusCallback);
}
} // AppExecFwk
} // OHOS