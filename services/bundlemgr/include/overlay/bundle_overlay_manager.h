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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_OVERLAY_MANAGER_CHECKER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_OVERLAY_MANAGER_CHECKER_H

#include "appexecfwk_errors.h"
#include "inner_bundle_info.h"
#include "bundle_mgr_service.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class BundleOverlayManager : public DelayedSingleton<BundleOverlayManager> {
public:
    bool IsExistedNonOverlayHap(const std::string &bundleName);

    bool GetInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info);

    ErrCode GetAllOverlayModuleInfo(const std::string &bundleName, std::vector<OverlayModuleInfo> &overlayModuleInfo,
        int32_t userId);

    ErrCode GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
        OverlayModuleInfo &overlayModuleInfo, int32_t userId);

    ErrCode GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
        std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t userId);

    ErrCode GetOverlayModuleInfoForTarget(const std::string &targetBundleName, const std::string &targetModuleName,
        std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId);

    ErrCode SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName, bool isEnabled,
        int32_t userId);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_OVERLAY_MANAGER_CHECKER_H