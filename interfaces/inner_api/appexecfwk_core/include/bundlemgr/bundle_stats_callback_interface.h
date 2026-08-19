/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_STATS_CALLBACK_INTERFACE_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_STATS_CALLBACK_INTERFACE_H

#include <vector>

#include "errors.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {
class IBundleStatsCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.BundleStatsCallback");

    /**
     * @brief Called when get bundle stats finished.
     * @param errCode Indicates the result of the get bundle stats progress.
     * @param bundleStats Indicates the bundle stats vector.
     *                     index 0 : app data size;
     *                     index 1 : bundle data size;
     *                     index 4 : cache size.
     */
    virtual void OnGetBundleStatsFinished(int32_t errCode, const std::vector<int64_t> &bundleStats) = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_STATS_CALLBACK_INTERFACE_H
