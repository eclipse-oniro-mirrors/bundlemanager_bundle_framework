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

#ifndef FOUNDATION_BUNDLE_MANAGER_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_CHECKER_H
#define FOUNDATION_BUNDLE_MANAGER_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_CHECKER_H

#include <string>
#include <unordered_map>
#include <vector>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_verify_mgr.h"
#include "quick_fix/app_quick_fix.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixChecker {
public:
    ErrCode CheckMultipleHqfsSignInfo(
        const std::vector<std::string> &bundlePaths,
        std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);

    ErrCode CheckAppQuickFixInfos(const std::unordered_map<std::string, AppQuickFix> &infos);

    ErrCode CheckMultiNativeSo(
        std::unordered_map<std::string, AppQuickFix> &infos);

    ErrCode CheckPatchWithInstalledBundle(const AppQuickFix &appQuickFix, const BundleInfo &bundleInfo,
        const Security::Verify::ProvisionInfo &provisionInfo);

    ErrCode CheckHotReloadWithInstalledBundle(const AppQuickFix &appQuickFix, const BundleInfo &bundleInfo);

    ErrCode CheckSignatureInfo(const BundleInfo &bundleInfo,
        const Security::Verify::ProvisionInfo &provisionInfo);

private:
    ErrCode CheckCommonWithInstalledBundle(const AppQuickFix &appQuickFix, const BundleInfo &bundleInfo);

    ErrCode CheckModuleNameExist(const BundleInfo &bundleInfo,
        const std::unordered_map<std::string, AppQuickFix> &infos);

    std::string GetAppDistributionType(const Security::Verify::AppDistType &type);

    std::string GetAppProvisionType(const Security::Verify::ProvisionType &type);

    ErrCode CheckPatchNativeSoWithInstalledBundle(
        const BundleInfo &bundleInfo, const AppqfInfo &qfInfo);

    static size_t QUICK_FIX_MAP_SIZE;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLE_MANAGER_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_CHECKER_H
