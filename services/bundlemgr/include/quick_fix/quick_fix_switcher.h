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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_SWITCHER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_SWITCHER_H

#include "bundle_data_mgr.h"
#include "quick_fix_data_mgr.h"
#include "quick_fix_interface.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixSwitcher final : public IQuickFix {
public:
    QuickFixSwitcher(const std::string &bundleName, bool enable);
    virtual ~QuickFixSwitcher() = default;

    virtual ErrCode Execute() override;
    ErrCode DisableQuickFix(InnerBundleInfo &innerBundleInfo);

private:
    ErrCode SwitchQuickFix();
    ErrCode EnableQuickFix(const std::string &bundleName);
    ErrCode DisableQuickFix(const std::string &bundleName);
    ErrCode InnerSwitchQuickFix(InnerBundleInfo &innerBundleInfo,
        const InnerAppQuickFix &innerAppQuickFix, bool enable);
    ErrCode InnerSwitchQuickFix(const std::string &bundleName, const InnerAppQuickFix &innerAppQuickFix, bool enable);
    ErrCode CreateInnerAppqf(const InnerBundleInfo &innerBundleInfo, bool enable, InnerAppQuickFix &innerAppQuickFix);
    ErrCode GetDataMgr();
    ErrCode GetQuickFixDataMgr();

    std::string bundleName_;
    bool enable_ = false;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_ = nullptr;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_SWITCHER_H