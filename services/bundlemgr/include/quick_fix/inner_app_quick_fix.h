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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_INNER_APP_QUICK_FIX_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_INNER_APP_QUICK_FIX_H

#include "app_quick_fix.h"
#include "appqf_info.h"
#include "hqf_info.h"

#include "nlohmann/json.hpp"
#include "nocopyable.h"
#include <string>

namespace OHOS {
namespace AppExecFwk {
enum QuickFixStatus : int32_t {
    UNKNOWN_STATUS = 0,
    DEPLOY_START,
    DEPLOY_END,
    SWITCH_START,
    SWITCH_END,
    DELETE_START,
    DELETE_END
};

struct QuickFixMark {
    std::string bundleName;
    std::string moduleName;
    int32_t status = QuickFixStatus::UNKNOWN_STATUS;
};

class InnerAppQuickFix {
public:
    InnerAppQuickFix();
    ~InnerAppQuickFix();

    void SetAppQuickFix(const AppQuickFix &appQuickFix);

    AppQuickFix GetAppQuickFix() const;

    bool AddHqfInfo(const InnerAppQuickFix &newInfo);

    bool RemoveHqfInfo(const std::string &bundleName);

    bool SwitchQuickFix();

    bool SetQuickFixMark(const QuickFixMark &mark);
    
    QuickFixMark GetQuickFixMark() const;

    std::string ToString() const;

    void ToJson(nlohmann::json &jsonObject) const;

    int32_t FromJson(const nlohmann::json &jsonObject);

private:
    AppQuickFix appQuickFix_;
    QuickFixMark quickFixMark_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_INNER_APP_QUICK_FIX_H