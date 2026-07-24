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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_CLONE_FOR_ACCOUNT_UTIL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_CLONE_FOR_ACCOUNT_UTIL_H

#include <cstdint>
#include <string>

#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @brief Utility class for Car device mode.
 * Provides methods to handle Car-specific scenarios, such as falling back to
 * an enabled clone app when the main app is disabled.
 */
class CloneForAccountUtil {
public:
    /**
     * @brief Finds any enabled clone appIndex when the main app is disabled.
     * @param innerBundleInfo Indicates the InnerBundleInfo of the bundle.
     * @param responseUserId Indicates the resolved response user ID.
     * @return Returns an enabled clone appIndex (> Constants::MAIN_APP_INDEX)
     *         on success, or Constants::MAIN_APP_INDEX if the main app is enabled
     *         or no enabled clone exists.
     */
    static int32_t GetEnabledCloneAppIndex(const InnerBundleInfo &innerBundleInfo,
        int32_t responseUserId);

private:
    CloneForAccountUtil() = default;
    ~CloneForAccountUtil() = default;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_CLONE_FOR_ACCOUNT_UTIL_H