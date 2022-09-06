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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_DELETER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_DELETER_H

#include "bundle_data_mgr.h"
#include "quick_fix_data_mgr.h"
#include "quick_fix_interface.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixDeleter final : public IQuickFix {
public:
    explicit QuickFixDeleter(const std::string &bundleName);
    virtual ~QuickFixDeleter() = default;

    virtual ErrCode Execute() override;

private:
    ErrCode DeleteQuickFix();
    ErrCode ToDeletePatchDir(const InnerAppQuickFix &innerAppQuickFix);
    ErrCode InnerDeletePatchDir(const AppqfInfo &appqfInfo, const std::string &bundleName);
    ErrCode GetQuickFixDataMgr();
    ErrCode GetDataMgr();
    ErrCode RemoveDeployingInfo(const std::string &bundleName);

    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_ = nullptr;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    std::string bundleName_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_DELETER_H