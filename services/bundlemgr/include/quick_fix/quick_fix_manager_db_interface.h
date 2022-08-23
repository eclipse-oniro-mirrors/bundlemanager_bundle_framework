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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_QUICK_FIX_MANAGER_DB_INTERFACE_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_QUICK_FIX_MANAGER_DB_INTERFACE_H

#include <map>
#include <string>
#include "inner_app_quick_fix.h"

namespace OHOS {
namespace AppExecFwk {
class IQuickFixManagerDb {
public:
    IQuickFixManagerDb() = default;
    virtual ~IQuickFixManagerDb() = default;

    virtual bool QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes) = 0;

    virtual bool QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix) = 0;

    virtual bool SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix) = 0;

    virtual bool DeleteInnerAppQuickFix(const std::string &bundleName) = 0;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_QUICK_FIX_MANAGER_DB_INTERFACE_H
