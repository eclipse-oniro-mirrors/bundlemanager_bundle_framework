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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PATCH_PARSER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PATCH_PARSER_H

#include <set>
#include <string>
#include <unordered_map>

#include "appexecfwk_errors.h"
#include "quick_fix/app_quick_fix.h"

namespace OHOS {
namespace AppExecFwk {
class PatchParser {
public:
    ErrCode ParsePatchInfo(const std::string &pathName, AppQuickFix &appQuickFix) const;

    ErrCode ParsePatchInfo(const std::vector<std::string> &filePaths,
        std::unordered_map<std::string, AppQuickFix> &appQuickFixes) const;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PATCH_PARSER_H