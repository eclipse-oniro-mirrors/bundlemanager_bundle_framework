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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_QUICK_FIX_MANAGER_HOST_IMPL_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_QUICK_FIX_MANAGER_HOST_IMPL_H

#include <atomic>

#include "quick_fix_mgr.h"
#include "quick_fix_manager_host.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixManagerHostImpl : public QuickFixManagerHost {
public:
    QuickFixManagerHostImpl();
    virtual ~QuickFixManagerHostImpl();

    virtual ErrCode DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
        const sptr<IQuickFixStatusCallback> &statusCallback) override;

    virtual ErrCode SwitchQuickFix(const std::string &bundleName, bool enable,
        const sptr<IQuickFixStatusCallback> &statusCallback) override;

    virtual ErrCode DeleteQuickFix(const std::string &bundleName,
        const sptr<IQuickFixStatusCallback> &statusCallback) override;

    virtual ErrCode CreateFd(const std::string &fileName, int32_t &fd, std::string &path) override;

private:
    bool GetQuickFixMgr();
    bool IsFileNameValid(const std::string &fileName) const;

    std::shared_ptr<QuickFixMgr> quickFixMgr_ = nullptr;
    std::atomic<uint32_t> id_ = 0;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_QUICK_FIX_MANAGER_HOST_IMPL_H
