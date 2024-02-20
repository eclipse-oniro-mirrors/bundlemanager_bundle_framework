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

#include "resource_info.h"

#include "nlohmann/json.hpp"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string SEPARATOR = "/";
}

ResourceInfo::ResourceInfo()
{}

ResourceInfo::~ResourceInfo()
{}

std::string ResourceInfo::GetKey() const
{
    std::string key = bundleName_;
    /**
    * if moduleName and abilityName both empty, it represents bundle resource,
    * otherwise it represents launcher ability resource.
    */
    if (!abilityName_.empty()) {
        key = moduleName_.empty() ? key : (key + SEPARATOR + moduleName_);
        key = abilityName_.empty() ? key : (key + SEPARATOR + abilityName_);
    }
    return key;
}

void ResourceInfo::ParseKey(const std::string &key)
{
    auto firstPos = key.find_first_of(SEPARATOR);
    if (firstPos == std::string::npos) {
        bundleName_ = key;
        moduleName_ = std::string();
        abilityName_ = std::string();
        return;
    }
    bundleName_ = key.substr(0, firstPos);
    auto lastPos = key.find_last_of(SEPARATOR);
    abilityName_ = key.substr(lastPos + 1);
    if (firstPos != lastPos) {
        moduleName_ = key.substr(firstPos + 1, lastPos - firstPos - 1);
        return;
    }
    moduleName_ = std::string();
}
} // AppExecFwk
} // OHOS
