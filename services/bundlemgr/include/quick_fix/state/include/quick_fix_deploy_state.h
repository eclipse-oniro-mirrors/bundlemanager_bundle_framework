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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_DEPLOY_STATE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_DEPLOY_STATE_H

#include "inner_app_quick_fix.h"
#include "quick_fix_state.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixDeployState final : public QuickFixState {
public:
    explicit QuickFixDeployState(const InnerAppQuickFix &innerQuickFixInfo);
    virtual ~QuickFixDeployState() = default;

    virtual ErrCode Process() override;
private:
    InnerAppQuickFix innerQuickFixInfo_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_DEPLOY_STATE_H