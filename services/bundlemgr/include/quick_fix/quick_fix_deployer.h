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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_DEPLOYER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_DEPLOYER_H

#include "quick_fix_checker.h"
#include "quick_fix_data_mgr.h"
#include "quick_fix_interface.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixDeployer final : public IQuickFix {
public:
    QuickFixDeployer(const std::vector<std::string> &bundleFilePaths,
        std::shared_ptr<QuickFixDataMgr> &quickFixDataMgr);

    virtual ~QuickFixDeployer() = default;

    virtual ErrCode Execute() override;

private:
    ErrCode DeployQuickFix();

    ErrCode ToDeployStartStatus(const std::vector<std::string> &bundleFilePaths,
        InnerAppQuickFix &newInnerAppQuickFix, InnerAppQuickFix &oldInnerAppQuickFix);

    ErrCode ToDeployEndStatus(InnerAppQuickFix &newInnerAppQuickFix,
        const InnerAppQuickFix &oldInnerAppQuickFix);

    ErrCode ParseAndCheckAppQuickFixInfos(
        const std::vector<std::string> &bundleFilePaths,
        std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
        std::unordered_map<std::string, AppQuickFix> &infos);

    ErrCode ToInnerAppQuickFix(const std::unordered_map<std::string, AppQuickFix> infos,
        const InnerAppQuickFix &oldInnerAppQuickFix, InnerAppQuickFix &newInnerAppQuickFix);

    ErrCode GetBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo);

    ErrCode CheckWithInstalledBundle(
        const AppQuickFix &appQuickFix,
        const BundleInfo &bundleInfo,
        const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes);

    ErrCode CheckPatchVersionCode(
        const AppQuickFix &newAppQuickFix,
        const AppQuickFix &oldAppQuickFix);

    ErrCode SaveAppQuickFix(const InnerAppQuickFix &innerAppQuickFix);

    ErrCode ExtractDiffFiles(
        const std::string &targetPath,
        const AppqfInfo &appQfInfo);

    ErrCode ApplyDiffPatch(
        const std::string &bundleName,
        const std::string &libraryPath,
        const std::string &diffFilePath,
        const std::string &newSoPath);

    ErrCode MoveHqfFiles(InnerAppQuickFix &innerAppQuickFix, const std::string &targetPath);

    std::vector<std::string> patchPaths_;
    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_ = nullptr;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_DEPLOYER_H