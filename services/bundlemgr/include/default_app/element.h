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

#ifndef FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_ELEMENT
#define FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_ELEMENT

#include <string>

namespace OHOS {
namespace AppExecFwk {
struct Element {
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string extensionName;
    std::string type;

    bool operator==(const Element& other)
    {
        if (this->bundleName == other.bundleName && this->moduleName == other.moduleName
            && this->abilityName == other.abilityName && this->extensionName == other.extensionName) {
            return true;
        }
        return false;
    }
};
}
}
#endif
