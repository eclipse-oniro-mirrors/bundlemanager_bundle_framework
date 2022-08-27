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

#include "quick_fix_mgr.h"

#include <cinttypes>

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "datetime_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string ADD_QUICK_FIXER_FAILED = "fail to add quick fixer";
} // namespace
QuickFixMgr::QuickFixMgr(const std::shared_ptr<EventRunner> &runner) : EventHandler(runner)
{
    APP_LOGI("create quick fixer async manager instance");
}

QuickFixMgr::~QuickFixMgr()
{
    APP_LOGI("destory quick fixer async manager instance");
}

void QuickFixMgr::ProcessEvent(const InnerEvent::Pointer &event)
{
    APP_LOGD("process event : %{public}u", event->GetInnerEventId());
    if (event->GetInnerEventId() == REMOVE_QUICK_FIXER) {
        RemoveQuickFixer(event->GetParam());
        return;
    }
    APP_LOGW("the eventId is not supported");
}

ErrCode QuickFixMgr::DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    APP_LOGI("DeployQuickFix begin");
    auto quickFixer = CreateQuickFixer(statusCallback);
    if (quickFixer == nullptr) {
        APP_LOGE("DeployQuickFix failed due to nullptr quick fixer");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    auto task = [quickFixer, bundleFilePaths] {
        quickFixer->DeployQuickFix(bundleFilePaths);
    };

    ThreadPool &installersPool = DelayedSingleton<BundleMgrService>::GetInstance()->GetThreadPool();
    installersPool.AddTask(task);
    return ERR_OK;
}

ErrCode QuickFixMgr::SwitchQuickFix(const std::string &bundleName, bool enable,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    APP_LOGI("SwitchQuickFix begin");
    auto quickFixer = CreateQuickFixer(statusCallback);
    if (quickFixer == nullptr) {
        APP_LOGE("SwitchQuickFix failed due to nullptr quick fixer");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    auto task = [quickFixer, bundleName, enable] {
        quickFixer->SwitchQuickFix(bundleName, enable);
    };

    ThreadPool &installersPool = DelayedSingleton<BundleMgrService>::GetInstance()->GetThreadPool();
    installersPool.AddTask(task);
    return ERR_OK;
}

ErrCode QuickFixMgr::DeleteQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    APP_LOGI("DeleteQuickFix begin");
    auto quickFixer = CreateQuickFixer(statusCallback);
    if (quickFixer == nullptr) {
        APP_LOGE("DeleteQuickFix failed due to nullptr quick fixer");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    auto task = [quickFixer, bundleName] {
        quickFixer->DeleteQuickFix(bundleName);
    };

    ThreadPool &installersPool = DelayedSingleton<BundleMgrService>::GetInstance()->GetThreadPool();
    installersPool.AddTask(task);
    return ERR_OK;
}

std::shared_ptr<QuickFixer> QuickFixMgr::CreateQuickFixer(const sptr<IQuickFixStatusCallback> &statusCallback)
{
    int64_t quickFixerId = GetMicroTickCount();
    auto fixer = std::make_shared<QuickFixer>(quickFixerId, shared_from_this(), statusCallback);
    bool isSuccess = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto result = quickFixer_.try_emplace(quickFixerId, fixer);
        isSuccess = result.second;
    }

    if (!isSuccess) {
        APP_LOGE("fail to add bundle quickFixer");
        fixer.reset();
        return fixer;
    }
    APP_LOGD("add the specific %{public}" PRId64 " quickFixer", quickFixerId);
    return fixer;
}

void QuickFixMgr::RemoveQuickFixer(const int64_t fixerId)
{
    APP_LOGD("start to remove quick fixer the specific %{public}" PRId64 " quickFixer", fixerId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (quickFixer_.erase(fixerId) > 0) {
        APP_LOGD("erase the specific %{public}" PRId64 " quickFixer", fixerId);
    }
}
} // AppExecFwk
} // OHOS