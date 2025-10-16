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

#include <cstddef>
#include <cstdint>
#include <set>
#include <fuzzer/FuzzedDataProvider.h>
#include "json_util.h"
#include "bmsbmsjsonutil_fuzzer.h"
#include "bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    nlohmann::json jsonObject;
    auto jsonObjectEnd = jsonObject.end();
    std::string key = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string datas = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bool isNecessary = fdp.ConsumeBool();
    bool data1 = fdp.ConsumeBool();
    int32_t parseResult = fdp.ConsumeIntegral<int32_t>();
    int32_t parseResult1 = fdp.ConsumeIntegral<int32_t>();
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, key, datas, isNecessary, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, key, datas, isNecessary, parseResult1);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject, jsonObjectEnd, key, data1, isNecessary, parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject, jsonObjectEnd, key, data1, isNecessary, parseResult1);
    nlohmann::json value;
    BMSJsonUtil::CheckArrayValueType(value, ArrayType::NUMBER);
    BMSJsonUtil::CheckArrayValueType(value, ArrayType::STRING);
    BMSJsonUtil::CheckArrayValueType(value, ArrayType::NOT_ARRAY);
    BMSJsonUtil::CheckMapValueType(value, JsonType::BOOLEAN, ArrayType::NUMBER);
    BMSJsonUtil::CheckMapValueType(value, JsonType::NUMBER, ArrayType::NUMBER);
    BMSJsonUtil::CheckMapValueType(value, JsonType::STRING, ArrayType::NUMBER);
    BMSJsonUtil::CheckMapValueType(value, JsonType::ARRAY, ArrayType::NUMBER);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}