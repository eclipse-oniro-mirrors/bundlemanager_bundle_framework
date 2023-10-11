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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_OVERLAY_INSTALL_CHECKER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_OVERLAY_INSTALL_CHECKER_H

#include <map>
#include <string>

#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class BundleOverlayInstallChecker final {
public:
    BundleOverlayInstallChecker() = default;
    virtual ~BundleOverlayInstallChecker() = default;

    ErrCode CheckOverlayInstallation(std::unordered_map<std::string, InnerBundleInfo> &newInfos, int32_t userId,
        int32_t &overlayType);
    ErrCode CheckInternalBundle(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InnerBundleInfo &innerBundleInfo) const;
    ErrCode CheckExternalBundle(const InnerBundleInfo &innerBundleInfo, int32_t userId) const;
    ErrCode CheckTargetBundle(const std::string &targetBundleName, const std::string &targetModuleName,
        const std::string &fingerprint, int32_t userId) const;
    ErrCode CheckOverlayUpdate(const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo, int32_t userId) const;

private:
    ErrCode CheckHapType(const InnerBundleInfo &info) const;
    ErrCode CheckBundleType(const InnerBundleInfo &info) const;
    ErrCode CheckTargetPriority(int32_t priority) const;
    ErrCode CheckVersionCode(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InnerBundleInfo &info) const;
    ErrCode CheckTargetModule(const std::string &bundleName, const std::string &targetModuleName) const;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_OVERLAY_INSTALL_CHECKER_H