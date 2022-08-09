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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PATCH_PROFILE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PATCH_PROFILE_H

#include "appexecfwk_errors.h"
#include "quick_fix/app_quick_fix.h"
#include "quick_fix/appqf_info.h"
#include "quick_fix/patch_extractor.h"

namespace OHOS {
namespace AppExecFwk {
class PatchProfile {
public:
    ErrCode TransformTo(
        const std::ostringstream &source, const PatchExtractor &patchExtractor, AppQuickFix &appQuickFix);
private:
    bool DefaultNativeSo(const PatchExtractor &patchExtractor, bool isSystemLib64Exist, AppqfInfo &appqfInfo);
    bool ParseNativeSo(const PatchExtractor &patchExtractor, AppqfInfo &appqfInfo);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PATCH_PROFILE_H