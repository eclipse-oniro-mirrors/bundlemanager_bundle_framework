/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef BUSINESS_ERROR_MAP_H
#define BUSINESS_ERROR_MAP_H
#include <unordered_map>

namespace OHOS {
namespace AppExecFwk {
namespace BussinessErrorNS {
constexpr const char* ERR_MSG_BUSINESS_ERROR = "BusinessError $: ";
constexpr const char* ERR_MSG_PARAM_NUMBER_ERROR =
    "BusinessError 401: Parameter error. The number of parameters is incorrect.";
constexpr const char* ERR_MSG_ENUM_ERROR =
    "Parameter error. The value of $ is not a valid enum $.";
}
class BusinessErrorMap {
public:
    static void GetErrMap(std::unordered_map<int32_t, const char*>& errMap);
};
}
}
#endif
