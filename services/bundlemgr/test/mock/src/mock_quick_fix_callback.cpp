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

#include "mock_quick_fix_callback.h"

namespace OHOS {
namespace AppExecFwk {
void MockQuickFixCallback::OnPatchDeployed(const std::shared_ptr<QuickFixResult> &result)
{
    promise_.set_value(result);
}

void MockQuickFixCallback::OnPatchSwitched(const std::shared_ptr<QuickFixResult> &result)
{
    promise_.set_value(result);
}

void MockQuickFixCallback::OnPatchDeleted(const std::shared_ptr<QuickFixResult> &result)
{
    promise_.set_value(result);
}

std::shared_ptr<QuickFixResult> MockQuickFixCallback::GetResCode() const
{
    auto future = promise_.get_future();
    future.wait();
    auto quickFixRes = future.get();
    return std::shared_ptr<QuickFixResult>(std::move(quickFixRes));
}
} // AppExecFwk
} // OHOS