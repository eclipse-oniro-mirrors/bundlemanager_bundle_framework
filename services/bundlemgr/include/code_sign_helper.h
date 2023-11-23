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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_CODE_SIGN_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_CODE_SIGN_HELPER_H

#include <string>

#ifdef CODE_SIGNATURE_ENABLE
#include "code_sign_utils.h"
#endif

namespace OHOS {
namespace AppExecFwk {
#ifdef CODE_SIGNATURE_ENABLE
class CodeSignHelper : public Security::CodeSign::CodeSignUtils {
#else
class CodeSignHelper {
#endif
public:
    CodeSignHelper();

    ~CodeSignHelper();

    bool IsHapChecked() const;

    void SetHapChecked(bool checked);

private:
    bool isHapChecked = false;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_CODE_SIGN_HELPER_H
