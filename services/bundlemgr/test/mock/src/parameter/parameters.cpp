/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "parameters.h"

#include <map>
#include <mutex>

namespace OHOS {
namespace system {
std::map<std::string, std::string> paramMap;
std::mutex mutex;

std::string GetDeviceType()
{
    return "default";
}

bool GetBoolParameter(const std::string& key, bool def)
{
#ifndef GET_BOOL_PARAMETER_TRUE
    return false;
#else
    return true;
#endif
}

template<typename T>
T GetIntParameter(const std::string& key, T def)
{
    std::lock_guard<std::mutex> lock(mutex);
    try {
        auto item = paramMap.find(key);
        if (item == paramMap.end()) {
            return def;
        }
        return std::stoi(item->second);
    } catch (...) {
        return def;
    }
}

std::string GetParameter(const std::string& key, const std::string& def)
{
    std::lock_guard<std::mutex> lock(mutex);
    auto item = paramMap.find(key);
    if (item == paramMap.end()) {
        return def;
    }
    return item->second;
}

bool SetParameter(const std::string& key, const std::string& val)
{
    std::lock_guard<std::mutex> lock(mutex);
    paramMap[key] = val;
    return true;
}

template int32_t GetIntParameter(const std::string& key, int32_t def);
} // system
} // OHOS