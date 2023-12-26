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

#include "bundle_resource_param.h"

#include "app_log_wrapper.h"
#include "parameter.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t MAX_LEN = 128;
const std::string SYSTEM_LANGUAGE = "persist.global.locale";
const std::string SYSTEM_COLOR_MODE = "persist.ace.darkmode";
const std::string DEFAULT_LANGUAGE = "zh-Hans";
const std::string DEFAULT_COLOR_MODE_LIGHT = "light";
}

std::string BundleResourceParam::GetSystemLanguage()
{
    std::string language = GetSystemParam(SYSTEM_LANGUAGE);
    return language.empty() ? DEFAULT_LANGUAGE : language;
}

std::string BundleResourceParam::GetSystemColorMode()
{
    std::string mode = GetSystemParam(SYSTEM_COLOR_MODE);
    return mode.empty() ? DEFAULT_COLOR_MODE_LIGHT : mode;
}

std::string BundleResourceParam::GetSystemParam(const std::string &key)
{
    char value[MAX_LEN] = {0};
    int32_t ret = GetParameter(key.c_str(), "", value, MAX_LEN);
    if (ret <= 0) {
        APP_LOGE("GetParameter:%{public}s failed!", key.c_str());
        return "";
    }
    return std::string(value);
}
} // AppExecFwk
} // OHOS
