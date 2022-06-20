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

#ifndef FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_DEFAULT_APP_DATA
#define FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_DEFAULT_APP_DATA

#include <map>

#include "element.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
struct DefaultAppData {
    std::map<std::string, Element> infos;

    std::string ToString() const;
    void ToJson(nlohmann::json& jsonObject) const;
    int32_t FromJson(const nlohmann::json& jsonObject);
    bool ParseDefaultApplicationConfig(const nlohmann::json& jsonObject);
};

void to_json(nlohmann::json &jsonObject, const Element& element);
void from_json(const nlohmann::json& jsonObject, Element& element);
}
}
#endif
