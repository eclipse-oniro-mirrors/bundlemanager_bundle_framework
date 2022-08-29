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

#ifndef FOUNDATION_BUNDLEMANAGER_STANDARD_SERVICE_MOCK_QUICK_FIX_CALLBACK_H
#define FOUNDATION_BUNDLEMANAGER_STANDARD_SERVICE_MOCK_QUICK_FIX_CALLBACK_H

#include <future>

#include "quick_fix_status_callback_host.h"

namespace OHOS {
namespace AppExecFwk {
class MockQuickFixCallback : public QuickFixStatusCallbackHost {
public:
    MockQuickFixCallback() = default;
    virtual ~MockQuickFixCallback() = default;

    virtual void OnPatchDeployed(const std::shared_ptr<QuickFixResult> &result) override;
    virtual void OnPatchSwitched(const std::shared_ptr<QuickFixResult> &result) override;
    virtual void OnPatchDeleted(const std::shared_ptr<QuickFixResult> &result) override;

    std::shared_ptr<QuickFixResult> GetResCode() const;

private:
    mutable std::promise<std::shared_ptr<QuickFixResult>> promise_;

    DISALLOW_COPY_AND_MOVE(MockQuickFixCallback);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // FOUNDATION_BUNDLEMANAGER_STANDARD_SERVICE_MOCK_QUICK_FIX_CALLBACK_H