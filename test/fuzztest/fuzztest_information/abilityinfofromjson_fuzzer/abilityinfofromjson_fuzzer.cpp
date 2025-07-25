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

#include <cstddef>
#include <cstdint>

#include "ability_info.h"
#include "json_serializer.h"
#include "nlohmann/json.hpp"

#include "abilityinfofromjson_fuzzer.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const char NAME[] = "name";
constexpr size_t SIZE_TWO = 2;
}
    bool FuzzAbilityInFromJson(const uint8_t* data, size_t size)
    {
        if ((size < SIZE_TWO) || (size % SIZE_TWO != 0)) {
            return false;
        }
        nlohmann::json infoJson;
        std::string name (reinterpret_cast<const char*>(data), size);
        infoJson[NAME] = name;
        AbilityInfo abilityInfo = infoJson;
        return !abilityInfo.name.empty();
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::FuzzAbilityInFromJson(data, size);
    return 0;
}