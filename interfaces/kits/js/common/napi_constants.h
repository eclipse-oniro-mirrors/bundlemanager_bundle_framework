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
#ifndef NAPI_CONSTANTS_H
#define NAPI_CONSTANTS_H

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr uint8_t ARGS_SIZE_ZERO = 0;
constexpr uint8_t ARGS_SIZE_ONE = 1;
constexpr uint8_t ARGS_SIZE_TWO = 2;
constexpr uint8_t ARGS_SIZE_THREE = 3;
constexpr uint8_t ARGS_SIZE_FOUR = 4;
constexpr uint8_t ARGS_SIZE_FIVE = 5;

constexpr uint8_t ARGS_POS_ZERO = 0;
constexpr uint8_t ARGS_POS_ONE = 1;
constexpr uint8_t ARGS_POS_TWO = 2;
constexpr uint8_t ARGS_POS_THREE = 3;
constexpr uint8_t ARGS_POS_FOUR = 4;

constexpr uint8_t NAPI_RETURN_ONE = 1;
constexpr uint8_t CALLBACK_PARAM_SIZE = 2;

constexpr const char* TYPE_NUMBER = "number";
constexpr const char* TYPE_STRING = "string";
constexpr const char* TYPE_OBJECT = "object";
constexpr const char* TYPE_BOOLEAN = "boolean";
constexpr const char* TYPE_FUNCTION = "function";
constexpr const char* TYPE_ARRAY = "array";
}
}
}
#endif