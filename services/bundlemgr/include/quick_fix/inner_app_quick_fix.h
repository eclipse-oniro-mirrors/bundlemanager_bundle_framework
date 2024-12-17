/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <string>

#include "nlohmann/json_fwd.hpp"
#include "nocopyable.h"

#include "app_quick_fix.h"
#include "appqf_info.h"
#include "hqf_info.h"

namespace OHOS {
namespace AppExecFwk {
enum QuickFixStatus : uint8_t {
    DEFAULT_STATUS = 0,
    DEPLOY_START,
    DEPLOY_END,
    SWITCH_ENABLE_START,
    SWITCH_DISABLE_START,
    SWITCH_END,
    DELETE_START,
    DELETE_END
};

struct QuickFixMark {
    int32_t status = QuickFixStatus::DEFAULT_STATUS;
    std::string bundleName;
};

class InnerAppQuickFix {
public:
    InnerAppQuickFix();
    InnerAppQuickFix(const AppQuickFix &appQuickFix, const QuickFixMark &mark);
    ~InnerAppQuickFix();

    void SetAppQuickFix(const AppQuickFix &appQuickFix);

    AppQuickFix GetAppQuickFix() const;

    bool AddHqfInfo(const AppQuickFix &newInfo);

    bool RemoveHqfInfo(const std::string &moduleName);

    void SwitchQuickFix();

    void SetQuickFixMark(const QuickFixMark &mark);

    QuickFixMark GetQuickFixMark() const;

    std::string ToString() const;

    void ToJson(nlohmann::json &jsonObject) const;

    int32_t FromJson(const nlohmann::json &jsonObject);

private:
    AppQuickFix appQuickFix_;
    QuickFixMark quickFixMark_;
};
void to_json(nlohmann::json &jsonObject, const QuickFixMark &quickFixMark);
void from_json(const nlohmann::json &jsonObject, QuickFixMark &quickFixMark);
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_INNER_APP_QUICK_FIX_H