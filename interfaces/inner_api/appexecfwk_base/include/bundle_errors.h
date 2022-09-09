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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_ERRORS_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_ERRORS_H

#include "errors.h"

namespace OHOS {
namespace AppExecFwk {
constexpr ErrCode PERMISSION_DENIED_ERROR = 201;
constexpr ErrCode PARAM_CHECK_ERROR = 401;
constexpr ErrCode SYSTEM_ABILITY_NOT_FOUND = 801;
constexpr ErrCode BUNDLE_NOT_EXIST = 17700001;
constexpr ErrCode ABILITY_NOT_EXIST = 17700003;
constexpr ErrCode INVALID_USER_ID = 17700004;
constexpr ErrCode INTERNAL_ERROR = 17700101;
constexpr ErrCode OUT_OF_MEMORY_ERROR = 17700102;
}
}
#endif