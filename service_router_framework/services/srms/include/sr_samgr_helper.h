/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_SERVICE_ROUTER_SERVICES_SRMS_INCLUDE_SR_SAMGR_HELPER_H
#define FOUNDATION_SERVICE_ROUTER_SERVICES_SRMS_INCLUDE_SR_SAMGR_HELPER_H

#include <singleton.h>
#include "bundle_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

/**
 * @class SystemAbilityManager Helper
 * Bms helpler.
 */
class SrSamgrHelper final : public DelayedRefSingleton<SrSamgrHelper> {
    DECLARE_DELAYED_REF_SINGLETON(SrSamgrHelper)

public:
    DISALLOW_COPY_AND_MOVE(SrSamgrHelper);

    /**
     * @brief Acquire a bundle manager, if it not existed,
     * @return returns the bundle manager ipc object, or nullptr for failed.
     */
    sptr<IBundleMgr> GetBundleMgr();

private:
    std::mutex bundleMgrMutex_;
    sptr<IBundleMgr> iBundleMgr_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // FOUNDATION_SERVICE_ROUTER_SERVICES_SRMS_INCLUDE_SR_SAMGR_HELPER_H
