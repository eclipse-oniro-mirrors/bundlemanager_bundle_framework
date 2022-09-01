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

#ifndef COMMON_FUNC_H
#define COMMON_FUNC_H

#include <vector>

#include "app_log_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;

void ConvertWantInfo(napi_env env, napi_value objWantInfo, const Want &want);

std::string GetStringFromNAPI(napi_env env, napi_value value);

void ParseString(napi_env env, napi_value value, std::string& result);

void ParseElementName(napi_env env, napi_value args, Want &want);
}
}
#endif