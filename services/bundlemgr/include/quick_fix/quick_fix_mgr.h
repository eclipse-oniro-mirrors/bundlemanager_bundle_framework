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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_ASYNC_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_ASYNC_MGR_H

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "nocopyable.h"
#include "quick_fixer.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixMgr : public EventHandler {
public:
    explicit QuickFixMgr(const std::shared_ptr<EventRunner> &runner);
    virtual ~QuickFixMgr() override;

    virtual void ProcessEvent(const InnerEvent::Pointer &event) override;
    ErrCode DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
        const sptr<IQuickFixStatusCallback> &statusCallback);
    ErrCode SwitchQuickFix(const std::string &bundleName, bool enable,
        const sptr<IQuickFixStatusCallback> &statusCallback);
    ErrCode DeleteQuickFix(const std::string &bundleName,
        const sptr<IQuickFixStatusCallback> &statusCallback);

    enum MessageId : uint32_t {
        REMOVE_QUICK_FIXER = 1,
    };

private:
    std::shared_ptr<QuickFixer> CreateQuickFixer(const sptr<IQuickFixStatusCallback> &statusCallback);
    void RemoveQuickFixer(const int64_t fixerId);

    std::mutex mutex_;
    // map key will use timestamp.
    std::unordered_map<int64_t, std::shared_ptr<QuickFixer>> quickFixer_;

    DISALLOW_COPY_AND_MOVE(QuickFixMgr);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_ASYNC_MGR_H
